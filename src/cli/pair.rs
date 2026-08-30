//! `herdr pair` — put a phone on this machine by scanning a QR.
//!
//! The problem this solves is the first screen of the app: it asks for a host, a user and
//! an ed25519 private key pasted from the clipboard, which means generating a key on a
//! computer before the app is usable at all. This command replaces that with one scan.
//!
//! WHAT IT DOES NOT DO: it never generates, transports or sees a private key. The phone
//! makes its own keypair and sends only the public half; this command appends that to
//! `~/.ssh/authorized_keys`. The QR carries a single-use token plus public facts, so a
//! photograph of it is worthless once redeemed.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::pair_qr::{open_qr_with, PairingQrFile};
use crate::pairing;

/// How long a pairing window stays open. Long enough to walk to another room and find the
/// app; short enough that an unattended terminal is not a standing invitation.
const DEFAULT_TTL: Duration = Duration::from_secs(300);
const SSH_READY_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn run_pair_command(args: &[String]) -> std::io::Result<i32> {
    let mut lan = false;
    let mut ttl = DEFAULT_TTL;
    let mut port: u16 = 0; // 0 = let the OS choose
    let mut open_qr = false;
    let mut qr_file: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" | "help" => {
                print_help();
                return Ok(0);
            }
            "--lan" => lan = true,
            "--open" => open_qr = true,
            "--qr-file" => {
                i += 1;
                match args.get(i).filter(|value| !value.is_empty()) {
                    Some(path) => qr_file = Some(PathBuf::from(path)),
                    None => {
                        eprintln!("--qr-file takes a file path");
                        return Ok(2);
                    }
                }
            }
            "--ttl" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(secs) if secs > 0 && secs <= 3600 => ttl = Duration::from_secs(secs),
                    _ => {
                        eprintln!("--ttl takes seconds, 1..3600");
                        return Ok(2);
                    }
                }
            }
            "--port" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u16>().ok()) {
                    Some(p) => port = p,
                    None => {
                        eprintln!("--port takes a port number");
                        return Ok(2);
                    }
                }
            }
            other => {
                eprintln!("unknown option {other:?}");
                print_help();
                return Ok(2);
            }
        }
        i += 1;
    }

    // Decide where to listen BEFORE anything else. Every refusal here is a refusal to put
    // a pre-authentication endpoint somewhere it should not be, so it happens before a
    // token exists, before a socket is opened, and before anything is printed.
    let lan_addr = if lan {
        match crate::platform::private_lan_ipv4() {
            Ok(address) => address,
            Err(err) => {
                eprintln!("herdr pair: {err}");
                return Ok(1);
            }
        }
    } else {
        None
    };
    let tailscale_result = pairing::detect_tailscale_address();
    let tailscale = match tailscale_result {
        Ok(address) => Some(address),
        Err(pairing::TailscaleDetectionError::InvalidOutput) => {
            eprintln!(
                "herdr pair: {}",
                pairing::TailscaleDetectionError::InvalidOutput
            );
            return Ok(1);
        }
        Err(_err) if lan && lan_addr.is_some() => None,
        Err(err) if lan => {
            eprintln!(
                "herdr pair: no RFC1918 private LAN address was found. Tailscale was also unavailable: {err}"
            );
            return Ok(1);
        }
        Err(err) => {
            eprintln!("herdr pair: {err}");
            return Ok(1);
        }
    };
    let bind_ip = match pairing::choose_bind_address(tailscale, lan_addr) {
        Ok(addr) => addr,
        Err(refusal) => {
            eprintln!("herdr pair: {refusal}");
            return Ok(1);
        }
    };

    // A pairing succeeds only if the app can SSH to the machine afterwards and pin the
    // key it sees. Prove both facts before minting or exposing a code. The old path emitted
    // `fp: ""` and an "UNKNOWN" label, even though Herdrup correctly refuses that payload.
    let fingerprint = match ssh_readiness(bind_ip) {
        Ok(fingerprint) => fingerprint,
        Err(SshReadinessError::NotListening { address, cause }) => {
            eprintln!(
                "herdr pair: SSH is not accepting connections at {address}: {cause}. {}",
                crate::platform::ssh_pairing_setup_hint()
            );
            return Ok(1);
        }
        Err(SshReadinessError::MissingHostKey { address }) => {
            eprintln!(
                "herdr pair: SSH is reachable at {address}, but its host-key fingerprint could not be read. Pairing stopped because Herdrup requires a pinned host identity. {}",
                crate::platform::ssh_pairing_setup_hint()
            );
            return Ok(1);
        }
    };

    let listener = match std::net::TcpListener::bind((bind_ip, port)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("herdr pair: could not bind {bind_ip}: {err}");
            return Ok(1);
        }
    };
    let local = listener.local_addr()?;

    let token = pairing::PairingToken::generate()?;
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into());
    let payload = pairing::PairingPayload {
        v: pairing::PAIRING_PAYLOAD_VERSION,
        host: bind_ip.to_string(),
        port: local.port(),
        user: user.clone(),
        token: token.as_str().to_string(),
        fp: fingerprint.clone(),
    };

    let qr = match pairing::render_qr_terminal(&payload.to_json()) {
        Ok(qr) => qr,
        Err(err) => {
            eprintln!("herdr pair: {err}");
            return Ok(1);
        }
    };
    let svg = if open_qr || qr_file.is_some() {
        match pairing::render_qr_svg(&payload.to_json()) {
            Ok(svg) => Some(svg),
            Err(err) => {
                eprintln!("herdr pair: {err}");
                return Ok(1);
            }
        }
    } else {
        None
    };
    let qr_artifact = match svg.as_deref() {
        Some(svg) => match PairingQrFile::create(svg, qr_file.as_deref()) {
            Ok(file) => Some(file),
            Err(err) => {
                eprintln!("herdr pair: could not write the QR image: {err}");
                return Ok(1);
            }
        },
        None => None,
    };
    let open_warning = if open_qr {
        qr_artifact
            .as_ref()
            .and_then(|file| open_qr_with(file.path(), crate::platform::open_path))
    } else {
        None
    };

    let mut out = std::io::stdout().lock();
    writeln!(out)?;
    writeln!(out, "{qr}")?;
    writeln!(out, "  Scan this in herdrup to connect this machine.")?;
    writeln!(out)?;
    writeln!(out, "  address    {}:{}", bind_ip, local.port())?;
    writeln!(out, "  user       {user}")?;
    writeln!(out, "  host key   {fingerprint}")?;
    if let Some(file) = &qr_artifact {
        writeln!(out, "  QR image   {}", file.path().display())?;
    }
    if let Some(warning) = &open_warning {
        writeln!(out, "  warning    {warning}")?;
    }
    writeln!(
        out,
        "  network    {}",
        if tailscale.is_some() {
            "Tailscale"
        } else {
            "private LAN (--lan)"
        }
    )?;
    writeln!(out, "  expires    in {}s", ttl.as_secs())?;
    writeln!(out)?;
    writeln!(
        out,
        "  The QR carries a single-use code, never a key. Your phone"
    )?;
    writeln!(
        out,
        "  generates its own keypair and sends only the public half."
    )?;
    writeln!(out)?;
    out.flush()?;

    let keys = pairing::authorized_keys_path(&home_dir());
    let outcome =
        pairing::serve_one_pairing(&listener, token, &keys, Instant::now() + ttl, |event| {
            eprintln!("  {event}")
        })?;

    match outcome {
        pairing::PairingOutcome::Paired { added } => {
            println!();
            if added {
                println!("  Paired. The phone's key was added to {}.", keys.display());
            } else {
                println!("  Paired. That key was already authorized; nothing changed.");
            }
            println!(
                "  To revoke it later, remove the line marked {:?} from that file.",
                pairing::AUTHORIZED_KEYS_MARKER
            );
            Ok(0)
        }
        pairing::PairingOutcome::TimedOut => {
            println!();
            println!("  Pairing window closed — nobody scanned it. Run herdr pair again.");
            Ok(1)
        }
        pairing::PairingOutcome::GaveUp => {
            println!();
            println!("  Too many failed attempts; stopping. Run herdr pair again for a new code.");
            Ok(1)
        }
    }
}

fn home_dir() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/root"))
}

#[derive(Debug, PartialEq, Eq)]
enum SshReadinessError {
    NotListening { address: SocketAddr, cause: String },
    MissingHostKey { address: SocketAddr },
}

fn ssh_readiness(bind_ip: Ipv4Addr) -> Result<String, SshReadinessError> {
    ssh_readiness_with(
        bind_ip,
        |address, timeout| {
            TcpStream::connect_timeout(&address, timeout)
                .map(drop)
                .map_err(|err| err.to_string())
        },
        pairing::ssh_host_key_fingerprint,
    )
}

fn ssh_readiness_with(
    bind_ip: Ipv4Addr,
    connect: impl FnOnce(SocketAddr, Duration) -> Result<(), String>,
    fingerprint: impl FnOnce() -> Option<String>,
) -> Result<String, SshReadinessError> {
    let address = SocketAddr::from((bind_ip, 22));
    connect(address, SSH_READY_TIMEOUT)
        .map_err(|cause| SshReadinessError::NotListening { address, cause })?;
    fingerprint().ok_or(SshReadinessError::MissingHostKey { address })
}

/// Render the SAME help clap builds for `herdr pair --help`, taken from `spec.rs`.
///
/// `--help` never reaches this function: because `pair` IS registered in the spec,
/// `write_requested_help` resolves it and prints clap's long help directly. This path
/// serves `herdr pair help` and the unknown-option case. Rendering the spec rather than
/// a second hand-written string is what keeps those two from drifting apart.
///
/// (`accounts` is the counter-example: absent from the spec, so `write_requested_help`
/// returns false — `path.len() == 1` — and its own `print_help` runs. That works, but it
/// costs the command its place in shell completions and in the root usage list, both of
/// which are generated from the spec.)
fn print_help() {
    let mut root = super::spec::command();
    root.build();
    if let Some(pair) = root.find_subcommand_mut("pair") {
        let _ = pair.print_help();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_must_listen_before_the_fingerprint_is_read() {
        let fingerprint_called = std::cell::Cell::new(false);
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |_address, _timeout| Err("connection refused".into()),
            || {
                fingerprint_called.set(true);
                Some("SHA256:should-not-be-read".into())
            },
        );
        assert!(matches!(
            result,
            Err(SshReadinessError::NotListening { .. })
        ));
        assert!(!fingerprint_called.get());
    }

    #[test]
    fn ssh_without_a_fingerprint_is_refused() {
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |_address, timeout| {
                assert_eq!(timeout, SSH_READY_TIMEOUT);
                Ok(())
            },
            || None,
        );
        assert_eq!(
            result,
            Err(SshReadinessError::MissingHostKey {
                address: "100.64.1.2:22".parse().expect("socket address")
            })
        );
    }

    #[test]
    fn ssh_readiness_returns_the_exact_fingerprint() {
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |address, _timeout| {
                assert_eq!(address, "100.64.1.2:22".parse().expect("socket address"));
                Ok(())
            },
            || Some("SHA256:exact".into()),
        );
        assert_eq!(result, Ok("SHA256:exact".into()));
    }

    #[test]
    fn qr_file_requires_a_path_before_any_network_work() {
        let exit = run_pair_command(&["--qr-file".into()]).expect("command result");
        assert_eq!(exit, 2);
    }
}
