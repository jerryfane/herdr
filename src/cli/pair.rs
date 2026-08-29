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
use std::time::{Duration, Instant};

use crate::pairing;

/// How long a pairing window stays open. Long enough to walk to another room and find the
/// app; short enough that an unattended terminal is not a standing invitation.
const DEFAULT_TTL: Duration = Duration::from_secs(300);

pub(super) fn run_pair_command(args: &[String]) -> std::io::Result<i32> {
    let mut lan = false;
    let mut ttl = DEFAULT_TTL;
    let mut port: u16 = 0; // 0 = let the OS choose

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" | "help" => {
                print_help();
                return Ok(0);
            }
            "--lan" => lan = true,
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
    let tailscale = pairing::detect_tailscale_address();
    // Resolve --lan BEFORE consulting the bind policy, and report ITS failure with ITS own
    // cause. The original defect was here: an unresolvable LAN address fell through as
    // `None`, indistinguishable from "no Tailscale", so a macOS user was told Tailscale was
    // missing when the real problem was that we could not enumerate their interfaces.
    // Tailscale still wins when available, so this cannot downgrade the chosen path.
    let mut lan_choice = None;
    if lan && tailscale.is_none() {
        match pairing::choose_lan_address(crate::platform::local_ipv4_addresses()) {
            Ok(found) => lan_choice = Some(found),
            Err(refusal) => {
                eprintln!("herdr pair: {refusal}");
                return Ok(1);
            }
        }
    }
    let bind_ip =
        match pairing::choose_bind_address(tailscale, lan_choice.as_ref().map(|c| c.address)) {
            Ok(addr) => addr,
            Err(refusal) => {
                eprintln!("herdr pair: {refusal}");
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
    // Without the fingerprint the app has to trust-on-first-use whatever answers, so say
    // plainly when we cannot supply it rather than letting the weaker path pass unnoticed.
    let fingerprint = pairing::ssh_host_key_fingerprint();

    let payload = pairing::PairingPayload {
        v: pairing::PAIRING_PAYLOAD_VERSION,
        host: bind_ip.to_string(),
        port: local.port(),
        user: user.clone(),
        token: token.as_str().to_string(),
        fp: fingerprint.clone().unwrap_or_default(),
    };

    let qr = match pairing::render_qr_terminal(&payload.to_json()) {
        Ok(qr) => qr,
        Err(err) => {
            eprintln!("herdr pair: {err}");
            return Ok(1);
        }
    };

    let mut out = std::io::stdout().lock();
    writeln!(out)?;
    writeln!(out, "{qr}")?;
    writeln!(out, "  Scan this in herdrup to connect this machine.")?;
    writeln!(out)?;
    writeln!(out, "  address    {}:{}", bind_ip, local.port())?;
    writeln!(out, "  user       {user}")?;
    match &fingerprint {
        Some(fp) => writeln!(out, "  host key   {fp}")?,
        None => writeln!(
            out,
            "  host key   UNKNOWN — could not read this machine's SSH host key, so the \
             app will trust the first key it is offered"
        )?,
    }
    writeln!(
        out,
        "  network    {}",
        match (&tailscale, &lan_choice) {
            (Some(_), _) => "Tailscale".to_string(),
            // Name the interface: on a machine with docker bridges or several NICs the
            // address alone does not tell the user whether the right one was picked, and
            // this address is the one they are about to scan.
            (None, Some(choice)) => format!("private LAN via {} (--lan)", choice.interface),
            (None, None) => "private LAN (--lan)".to_string(),
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
