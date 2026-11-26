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

use std::io::{IsTerminal as _, Write as _};
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
    let mut list = false;
    let mut revoke: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" | "help" => {
                print_help();
                return Ok(0);
            }
            "--lan" => lan = true,
            "--open" => open_qr = true,
            "--list" => list = true,
            "--revoke" => {
                i += 1;
                match args.get(i).filter(|value| !value.trim().is_empty()) {
                    Some(target) => revoke = Some(target.clone()),
                    None => {
                        eprintln!("--revoke takes a fingerprint (SHA256:…) or a label");
                        return Ok(2);
                    }
                }
            }
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

    if list || revoke.is_some() {
        if list && revoke.is_some() {
            eprintln!("herdr pair: --list and --revoke are separate commands");
            return Ok(2);
        }
        if cfg!(not(unix)) {
            eprintln!("herdr pair: {}", pairing::PAIR_KEYS_UNSUPPORTED);
            return Ok(1);
        }
        let path = pairing::authorized_keys_path(&pairing::home_dir());
        return Ok(match revoke {
            Some(target) => match revoke_paired_key(&path, &target) {
                Ok(removed) => {
                    for key in removed {
                        println!("revoked {}", key_row(&key));
                    }
                    0
                }
                Err(err) => {
                    eprintln!("herdr pair: {err}");
                    1
                }
            },
            None => match pairing::list_paired_keys(&path) {
                Ok(keys) if keys.is_empty() => {
                    println!("no paired device keys in {}", path.display());
                    0
                }
                Ok(keys) => {
                    for key in keys {
                        println!("{}", key_row(&key));
                    }
                    0
                }
                Err(err) => {
                    eprintln!("herdr pair: could not read {}: {err}", path.display());
                    1
                }
            },
        });
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
        Err(SshReadinessError::MissingHostKey { address, failure }) => {
            eprintln!(
                "herdr pair: SSH is reachable at {address}, but its host-key fingerprint could not be read ({failure}). Pairing stopped because Herdrup requires a pinned host identity. {}",
                crate::platform::ssh_pairing_setup_hint()
            );
            return Ok(1);
        }
    };
    let Some(user) = pair_user_from_env(cfg!(windows), |name| std::env::var_os(name)) else {
        eprintln!(
            "herdr pair: could not tell which account the phone should sign in as: USER, LOGNAME, USERNAME, USERPROFILE and HOME are all unset. Set USERNAME to your Windows account name, then run `herdr pair` again."
        );
        return Ok(1);
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
    let app_link = payload.app_link();
    writeln!(
        out,
        "{}",
        app_link_line(&app_link, std::io::stdout().is_terminal())
    )?;
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

    let keys = pairing::authorized_keys_path(&pairing::home_dir());
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

/// The account the phone signs in as. Unix keeps its historical `root` default; Windows
/// has no `root` account, so a guess there would only fail later at SSH authentication.
fn pair_user_from_env(
    is_windows: bool,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<String> {
    super::login_user_from_env(env).or_else(|| (!is_windows).then(|| "root".to_string()))
}

#[derive(Debug, PartialEq, Eq)]
enum SshReadinessError {
    NotListening {
        address: SocketAddr,
        cause: String,
    },
    MissingHostKey {
        address: SocketAddr,
        failure: pairing::HostKeyLookupFailure,
    },
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
    fingerprint: impl FnOnce() -> Result<String, pairing::HostKeyLookupFailure>,
) -> Result<String, SshReadinessError> {
    let address = SocketAddr::from((bind_ip, 22));
    connect(address, SSH_READY_TIMEOUT)
        .map_err(|cause| SshReadinessError::NotListening { address, cause })?;
    fingerprint().map_err(|failure| SshReadinessError::MissingHostKey { address, failure })
}

/// The "open on this computer" line under the QR. On a terminal the URL is wrapped in an
/// OSC 8 hyperlink so one click opens it; the URL itself is always the visible text, so it
/// can still be copied where OSC 8 is unsupported or stdout is not a terminal.
fn app_link_line(link: &str, tty: bool) -> String {
    if tty {
        format!("  Or open   \x1b]8;;{link}\x1b\\{link}\x1b]8;;\x1b\\   (this computer)")
    } else {
        format!("  Or open   {link}   (this computer)")
    }
}

fn key_row(key: &pairing::PairedKey) -> String {
    if key.label.is_empty() {
        key.fingerprint.clone()
    } else {
        format!("{}  {}", key.fingerprint, key.label)
    }
}

/// Remove the herdr-pair key named by a fingerprint (`SHA256:…`) or an exact label. A
/// label held by several different keys is refused, listing them, so one name never
/// revokes more than the user meant.
fn revoke_paired_key(
    path: &std::path::Path,
    target: &str,
) -> Result<Vec<pairing::PairedKey>, String> {
    let keys = pairing::list_paired_keys(path)
        .map_err(|err| format!("could not read {}: {err}", path.display()))?;
    let fingerprint = if target.starts_with("SHA256:") {
        target.to_string()
    } else {
        let matches: Vec<&pairing::PairedKey> =
            keys.iter().filter(|key| key.label == target).collect();
        let mut fingerprints: Vec<&str> =
            matches.iter().map(|key| key.fingerprint.as_str()).collect();
        fingerprints.sort_unstable();
        fingerprints.dedup();
        match fingerprints.as_slice() {
            [] => return Err(format!("no paired device key is labelled {target:?}")),
            [one] => (*one).to_string(),
            _ => {
                let rows: Vec<String> = matches
                    .iter()
                    .map(|key| format!("  {}", key_row(key)))
                    .collect();
                return Err(format!(
                    "{} keys are labelled {target:?}; revoke one by fingerprint:\n{}",
                    fingerprints.len(),
                    rows.join("\n")
                ));
            }
        }
    };
    let removed = pairing::remove_paired_keys(path, &fingerprint)
        .map_err(|err| format!("could not rewrite {}: {err}", path.display()))?;
    if removed.is_empty() {
        return Err(format!(
            "no paired device key has fingerprint {fingerprint}"
        ));
    }
    Ok(removed)
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
    fn app_link_line_wraps_osc8_only_on_a_tty() {
        let link = "herdrup://pair#eyJ2IjoxfQ";
        let plain = app_link_line(link, false);
        assert_eq!(plain, format!("  Or open   {link}   (this computer)"));
        assert!(!plain.contains('\x1b'));

        let tty = app_link_line(link, true);
        assert_eq!(
            tty,
            format!("  Or open   \x1b]8;;{link}\x1b\\{link}\x1b]8;;\x1b\\   (this computer)")
        );
    }

    #[test]
    fn ssh_must_listen_before_the_fingerprint_is_read() {
        let fingerprint_called = std::cell::Cell::new(false);
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |_address, _timeout| Err("connection refused".into()),
            || {
                fingerprint_called.set(true);
                Ok("SHA256:should-not-be-read".into())
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
            || Err(missing_key_failure()),
        );
        assert_eq!(
            result,
            Err(SshReadinessError::MissingHostKey {
                address: "100.64.1.2:22".parse().expect("socket address"),
                failure: missing_key_failure(),
            })
        );
    }

    fn missing_key_failure() -> pairing::HostKeyLookupFailure {
        pairing::HostKeyLookupFailure {
            tried: vec![(
                PathBuf::from("/etc/ssh/ssh_host_ed25519_key.pub"),
                "not found".into(),
            )],
        }
    }

    #[test]
    fn ssh_readiness_returns_the_exact_fingerprint() {
        let result = ssh_readiness_with(
            "100.64.1.2".parse().expect("address"),
            |address, _timeout| {
                assert_eq!(address, "100.64.1.2:22".parse().expect("socket address"));
                Ok(())
            },
            || Ok("SHA256:exact".into()),
        );
        assert_eq!(result, Ok("SHA256:exact".into()));
    }

    #[test]
    fn pair_user_defaults_to_root_only_on_unix() {
        assert_eq!(pair_user_from_env(false, |_| None), Some("root".into()));
        assert_eq!(pair_user_from_env(true, |_| None), None);
    }

    #[test]
    fn pair_user_prefers_the_environment_over_the_default() {
        let only_username = |name: &str| (name == "USERNAME").then(|| "warez".into());
        for is_windows in [false, true] {
            assert_eq!(
                pair_user_from_env(is_windows, only_username),
                Some("warez".into())
            );
        }
    }

    #[test]
    fn qr_file_requires_a_path_before_any_network_work() {
        let exit = run_pair_command(&["--qr-file".into()]).expect("command result");
        assert_eq!(exit, 2);
    }

    /// Off Unix the device-key commands refuse before touching any path.
    #[cfg(not(unix))]
    #[test]
    fn list_and_revoke_are_refused_off_unix() {
        assert_eq!(run_pair_command(&["--list".into()]).unwrap(), 1);
        assert_eq!(
            run_pair_command(&["--revoke".into(), "iPhone".into()]).unwrap(),
            1
        );
    }

    fn ed25519_key(byte: u8) -> String {
        use base64::Engine as _;
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[byte; 32]);
        format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        )
    }

    #[test]
    fn revoking_by_a_shared_label_is_refused_and_lists_the_keys() {
        let dir = std::env::temp_dir().join(format!("herdr-pair-revoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = pairing::authorized_keys_path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (own, a, b, c) = (
            ed25519_key(1),
            ed25519_key(2),
            ed25519_key(3),
            ed25519_key(5),
        );
        let original = format!(
            "{own} iPhone\n{a} herdr-pair:iPhone\n{b} herdr-pair:iPhone\n{c} herdr-pair:iPad\n"
        );
        std::fs::write(&path, &original).unwrap();
        let fingerprint =
            |key: &str| pairing::key_fingerprint(key.split(' ').nth(1).unwrap()).unwrap();

        let err = revoke_paired_key(&path, "iPhone").unwrap_err();
        assert!(err.starts_with("2 keys are labelled \"iPhone\""), "{err}");
        assert!(
            err.contains(&fingerprint(&a)) && err.contains(&fingerprint(&b)),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(revoke_paired_key(&path, "Nope").is_err());
        assert!(
            revoke_paired_key(&path, &fingerprint(&own)).is_err(),
            "not a herdr-pair line"
        );

        let removed = revoke_paired_key(&path, "iPad").unwrap();
        assert_eq!(removed[0].fingerprint, fingerprint(&c));
        let removed = revoke_paired_key(&path, &fingerprint(&a)).unwrap();
        assert_eq!(removed[0].label, "iPhone");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{own} iPhone\n{b} herdr-pair:iPhone\n")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
