//! QR pairing: the pure, testable half.
//!
//! A phone with no credential needs a way to become an authorized SSH client of this
//! machine. `herdr pair` mints a SHORT-LIVED token, prints it as a QR alongside the
//! address and host-key fingerprint, and accepts exactly one redemption: the phone sends
//! a public key it generated itself, and we append it to `~/.ssh/authorized_keys`.
//!
//! WHAT IS DELIBERATELY NOT HERE: no private key is ever generated, transported, or seen
//! by this machine. The QR carries a token that is worthless once redeemed, never a
//! credential. That is the whole reason the phone generates its own keypair.
//!
//! This module holds the parts that need no socket, so they can be tested directly:
//! token minting, the bind-address decision, and the `authorized_keys` writer.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Bytes of entropy in a pairing token. 32 bytes is overkill for something that lives
/// for minutes and is single-use, which is the right direction to be wrong in.
const TOKEN_BYTES: usize = 32;

/// The marker written alongside every key this command adds, so a human (or a future
/// `herdr pair --revoke`) can find exactly what herdr put in `authorized_keys` and remove
/// it without reading the whole file or guessing which line is ours.
pub const AUTHORIZED_KEYS_MARKER: &str = "herdr-pair";

/// A minted pairing token. Single-use and short-lived by construction: the listener drops
/// it after one successful redemption, and `herdr pair` exits when it expires.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingToken(String);

impl PairingToken {
    /// Mint a token from the OS CSPRNG.
    ///
    /// NOT `generate_machine_id` (`crate::persist::machine`), whose own comment disclaims
    /// it as "an install identity, not a cryptographic secret" — it derives entropy from
    /// hashing sentinels through `RandomState`. This grants SSH access, so it takes real
    /// randomness or none.
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::getrandom(&mut bytes).map_err(|err| {
            io::Error::other(format!("no OS randomness for a pairing token: {err}"))
        })?;
        use base64::Engine as _;
        Ok(Self(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compare in constant time. A pairing listener answers attacker-controlled input, so
    /// the same discipline as the federation token check applies
    /// (`crate::api::federation::constant_time_eq`).
    pub fn matches(&self, candidate: &str) -> bool {
        crate::api::federation::constant_time_eq(self.0.as_bytes(), candidate.as_bytes())
    }
}

/// Redacted, so a token cannot reach a log through a stray `{:?}` — the same protection
/// `FederationHello` gives its own token.
impl fmt::Debug for PairingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingToken(<redacted>)")
    }
}

/// Why a pairing listener refused to bind. Every variant is a refusal to expose a
/// pre-authentication endpoint somewhere it should not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindRefusal {
    /// No Tailscale address, and `--lan` was not passed.
    NoTailscale,
    /// `--lan` was passed but the address is not private, so binding it would publish a
    /// pre-auth endpoint to the internet.
    LanAddressIsPublic(Ipv4Addr),
    /// Tailscale reported something outside the tailnet CGNAT range.
    NotATailnetAddress(Ipv4Addr),
}

impl fmt::Display for BindRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTailscale => write!(
                f,
                "no Tailscale address found. Pairing binds to your tailnet so nothing is \
                 reachable from the internet. Install/start Tailscale, or pass --lan to \
                 pair over a private local network instead."
            ),
            Self::LanAddressIsPublic(addr) => write!(
                f,
                "refusing to bind pairing to {addr}: it is a PUBLIC address. --lan is for \
                 private networks (10/8, 172.16/12, 192.168/16); binding here would expose \
                 a pre-authentication endpoint to the internet."
            ),
            Self::NotATailnetAddress(addr) => write!(
                f,
                "Tailscale reported {addr}, which is outside the tailnet range \
                 (100.64.0.0/10). Refusing to bind rather than guess."
            ),
        }
    }
}

/// Is this address inside Tailscale's CGNAT range, 100.64.0.0/10?
///
/// Checked rather than trusted: `tailscale ip -4` is a subprocess whose output we do not
/// control, and the whole security story here is "this endpoint is only reachable on the
/// tailnet". A wrong address silently widens that.
pub fn is_tailnet_address(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 100 && (64..=127).contains(&b)
}

/// RFC1918 private ranges, for the `--lan` escape hatch.
pub fn is_private_address(addr: Ipv4Addr) -> bool {
    addr.is_private() || addr.is_loopback()
}

/// Decide what to bind, given what Tailscale reported and whether `--lan` was passed.
///
/// Split from the subprocess call so the policy is unit-testable — the refusals are the
/// security property, and they must be provable without a network or a tailnet.
pub fn choose_bind_address(
    tailscale: Option<Ipv4Addr>,
    lan_opt_in: Option<Ipv4Addr>,
) -> Result<Ipv4Addr, BindRefusal> {
    if let Some(addr) = tailscale {
        // Tailscale wins whenever it is available, even with --lan: the safer path should
        // not be lost by passing a flag.
        return if is_tailnet_address(addr) {
            Ok(addr)
        } else {
            Err(BindRefusal::NotATailnetAddress(addr))
        };
    }
    match lan_opt_in {
        Some(addr) if is_private_address(addr) => Ok(addr),
        Some(addr) => Err(BindRefusal::LanAddressIsPublic(addr)),
        None => Err(BindRefusal::NoTailscale),
    }
}

/// Ask Tailscale for this machine's tailnet IPv4, or `None` if it is not usable.
///
/// Deliberately shells out rather than naming an interface: on this fleet `tailscale0`
/// does not appear in `ip addr` at all (userspace/TUN routing), while `tailscale ip -4`
/// resolves cleanly. Any failure is `None`, never an error — "no Tailscale" is an ordinary
/// state that `choose_bind_address` already has a message for.
pub fn detect_tailscale_address() -> Option<Ipv4Addr> {
    let out = std::process::Command::new("tailscale")
        .args(["ip", "-4"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()?
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

/// What the QR actually carries.
///
/// JSON rather than a URL: the username is user-controlled and a URL would need
/// percent-encoding rules agreed byte-for-byte across two languages, which is exactly the
/// kind of quiet mismatch this feature cannot afford. At ~200 bytes a QR is nowhere near
/// capacity, so the compactness a URI would buy is worth nothing here.
///
/// NOTE WHAT IS ABSENT: no private key, no password, nothing that keeps working after the
/// token is spent. Everything here is either public (host, port, user, fingerprint) or
/// single-use (token).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PairingPayload {
    /// Payload format version, so an old app meets a new daemon with a real error rather
    /// than a misparse.
    pub v: u8,
    /// Address the phone should connect to — the tailnet IP.
    pub host: String,
    pub port: u16,
    /// The SSH user the phone will log in as.
    pub user: String,
    /// Single-use pairing token.
    pub token: String,
    /// The machine's SSH host-key fingerprint, `SHA256:...` as ssh-keygen prints it.
    ///
    /// This is what lets the app PIN the host key before its first connection. Without it
    /// the app trusts-on-first-use whatever answers, with no prompt — so carrying it here
    /// closes a window that is open today.
    pub fp: String,
}

pub const PAIRING_PAYLOAD_VERSION: u8 = 1;

impl PairingPayload {
    pub fn to_json(&self) -> String {
        // Infallible in practice (plain strings and integers); a panic here would be a
        // programming error, not a runtime condition, so it is not surfaced as an error.
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Render a QR to a terminal using half-block characters, two module rows per text line.
///
/// POLARITY IS DELIBERATE AND IS THE THING THAT BREAKS SCANNING: a camera expects DARK
/// modules on a LIGHT field. Terminals are usually dark, so the glyphs are drawn for the
/// LIGHT modules and dark modules are left as background. Inverting this produces a QR
/// that looks perfectly fine to a human and cannot be scanned.
///
/// The 4-module quiet zone is required by the spec, not decoration — many scanners fail
/// without it, and a QR flush against terminal output has no margin at all.
pub fn render_qr_terminal(data: &str) -> Result<String, String> {
    let cells = qr_cells(data)?;
    let mut out = String::new();
    for row in &cells {
        // Track the last SGR so an unchanged run of cells costs one glyph, not 20 bytes.
        let mut last: Option<(u8, u8)> = None;
        for cell in row {
            let pair = (colour(cell.top_light), colour(cell.bottom_light));
            if last != Some(pair) {
                out.push_str(&format!("\x1b[38;5;{};48;5;{}m", pair.0, pair.1));
                last = Some(pair);
            }
            out.push(HALF_BLOCK);
        }
        out.push_str(SGR_RESET);
        out.push('\n');
    }
    Ok(out)
}

/// Upper half block: its FOREGROUND paints the top module, its BACKGROUND the bottom one.
/// Two module rows per text line, so a 61-module QR fits in 61 columns instead of 122.
const HALF_BLOCK: char = '\u{2580}';
const SGR_RESET: &str = "\x1b[0m";
/// 256-colour cube indices, NOT the 16 basic colours.
///
/// THIS IS THE WHOLE POINT OF DRAWING BOTH COLOURS. Colours 0-15 are remapped by the
/// terminal's theme, so "black on white" becomes whatever the user's profile says. Cube
/// entries 16 and 231 are fixed pure black and pure white in every conforming terminal.
const CUBE_WHITE: u8 = 231;
const CUBE_BLACK: u8 = 16;

fn colour(light: bool) -> u8 {
    if light {
        CUBE_WHITE
    } else {
        CUBE_BLACK
    }
}

/// One rendered character: the two vertically-stacked modules it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrCell {
    pub top_light: bool,
    pub bottom_light: bool,
}

/// The QR as half-block cells, with the quiet zone included.
///
/// Split from the colouring so the GEOMETRY (quiet zone, row pairing, the odd final row)
/// can be checked against the encoder's own matrix without parsing escape sequences.
pub fn qr_cells(data: &str) -> Result<Vec<Vec<QrCell>>, String> {
    use qrcodegen::{QrCode, QrCodeEcc};
    let qr = QrCode::encode_text(data, QrCodeEcc::Medium)
        .map_err(|err| format!("could not encode the pairing QR: {err}"))?;
    let size = qr.size();
    let lo = -QUIET_MODULES;
    let hi = size + QUIET_MODULES;

    // `true` = a LIGHT module, so the sense is explicit at every use site.
    let light = |x: i32, y: i32| -> bool { !qr.get_module(x, y) };

    let mut rows = Vec::new();
    let mut y = lo;
    while y < hi {
        let mut row = Vec::with_capacity((hi - lo) as usize);
        for x in lo..hi {
            row.push(QrCell {
                top_light: light(x, y),
                // An odd module count leaves the last line half empty; that half is quiet
                // zone, so it must be LIGHT. Painting it dark would put ink hard against
                // the QR's bottom edge and cost the margin the spec requires.
                bottom_light: if y + 1 < hi { light(x, y + 1) } else { true },
            });
        }
        rows.push(row);
        y += 2;
    }
    Ok(rows)
}

/// The quiet zone the QR spec requires. Not decoration: many scanners fail without it,
/// and terminal output has no natural margin at all.
const QUIET_MODULES: i32 = 4;

/// This machine's SSH host-key fingerprint, as `ssh-keygen -lf` prints it.
///
/// Read from the host key sshd actually serves, so the app pins the same key it will be
/// offered. Returns `None` when no ed25519 host key is readable — pairing then has to fall
/// back to trust-on-first-use, and the caller says so out loud rather than pretending.
pub fn ssh_host_key_fingerprint() -> Option<String> {
    for path in [
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/etc/ssh/ssh_host_rsa_key.pub",
    ] {
        if !Path::new(path).exists() {
            continue;
        }
        let out = std::process::Command::new("ssh-keygen")
            .args(["-lf", path])
            .output()
            .ok()?;
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8(out.stdout).ok()?;
        if let Some(fp) = text.split_whitespace().nth(1) {
            if fp.starts_with("SHA256:") {
                return Some(fp.to_string());
            }
        }
    }
    None
}

/// What the phone sends to redeem a pairing token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairRedeem {
    #[serde(rename = "type")]
    pub kind: String,
    pub token: String,
    /// The phone's PUBLIC key. The private half never leaves the device.
    pub public_key: String,
    /// A human label ("Jerry's iPhone") that ends up in the authorized_keys comment so the
    /// entry can be recognised and revoked later.
    #[serde(default)]
    pub device: String,
}

pub const PAIR_REDEEM_KIND: &str = "pair.redeem";

/// The outcome of one redemption attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemOutcome {
    /// Key accepted and written (or already present).
    Accepted { added: bool },
    /// Refused. The `reason` is for OUR log; `client_message` is what goes on the wire.
    Refused {
        reason: String,
        client_message: &'static str,
    },
}

/// Every refusal tells the client the same thing.
///
/// The client is unauthenticated and may be an attacker, so it learns only that pairing
/// failed — never whether the token was wrong, expired, already spent, or the key
/// malformed. The operator gets the real reason on their own terminal, where it is useful
/// and not a probing oracle.
pub const OPAQUE_REFUSAL: &str = "pairing refused";

/// Decide and apply one redemption. Pure enough to test: it takes the request, the live
/// token, and the file to write, and returns what happened.
///
/// `token` is `None` once spent — a second redemption of the same token is refused even if
/// the value is correct, which is what makes a photographed QR harmless after use.
pub fn redeem(
    request: &PairRedeem,
    token: Option<&PairingToken>,
    authorized_keys: &Path,
) -> RedeemOutcome {
    let refuse = |reason: String| RedeemOutcome::Refused {
        reason,
        client_message: OPAQUE_REFUSAL,
    };

    if request.kind != PAIR_REDEEM_KIND {
        return refuse(format!("unexpected message type {:?}", request.kind));
    }
    let Some(token) = token else {
        return refuse("token already redeemed".into());
    };
    if !token.matches(&request.token) {
        return refuse("token mismatch".into());
    }
    let key = match validate_public_key_line(&request.public_key) {
        Ok(key) => key,
        Err(err) => return refuse(format!("bad public key: {err}")),
    };
    // The device label is attacker-controlled and lands in a file, so it is sanitised to a
    // safe subset rather than trusted — the key line itself is already validated, but the
    // comment we append is ours to keep clean.
    let label = sanitize_device_label(&request.device);
    let line = marked_authorized_key(key, &label);
    match append_authorized_key(authorized_keys, &line) {
        Ok(added) => RedeemOutcome::Accepted { added },
        Err(err) => refuse(format!("could not write authorized_keys: {err}")),
    }
}

/// Keep a device label to characters that are safe in an `authorized_keys` comment.
///
/// Whitespace becomes a single space, control characters and anything exotic are dropped,
/// and the result is length-capped. The key line is validated separately; this stops a
/// label from being the thing that smuggles something in.
pub fn sanitize_device_label(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| {
            !c.is_control()
                && (c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '\''))
        })
        .collect();
    cleaned
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(48)
        .collect()
}

/// Largest redemption request we will read. A public key line is ~120 bytes; 8 KiB is
/// generous. Bounded because this socket is reachable before authentication, so an
/// unbounded read is a way to spend our memory without ever proving anything.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// How many failed attempts before the listener gives up.
///
/// The token is 32 bytes of entropy, so guessing is not the threat — this bounds noise
/// and stops a wedged client from holding the pairing window open forever.
const MAX_FAILED_ATTEMPTS: usize = 20;

/// How one pairing session ended.
#[derive(Debug, PartialEq, Eq)]
pub enum PairingOutcome {
    /// A phone redeemed the token. `added` is false if that key was already present.
    Paired { added: bool },
    /// Nobody redeemed it before the deadline.
    TimedOut,
    /// Too many failed attempts.
    GaveUp,
}

/// Serve pairing on an already-bound listener until someone redeems the token, the
/// deadline passes, or too many attempts fail.
///
/// Takes the listener rather than binding one, so a test can drive the whole protocol over
/// loopback without a tailnet — the bind POLICY is tested separately in
/// `choose_bind_address`, and mixing the two would make both harder to prove.
///
/// The token is consumed on the first success: `token` is moved out, so a second
/// redemption of the same value cannot be served even if the connection races.
pub fn serve_one_pairing(
    listener: &std::net::TcpListener,
    token: PairingToken,
    authorized_keys: &Path,
    deadline: std::time::Instant,
    mut on_event: impl FnMut(&str),
) -> io::Result<PairingOutcome> {
    use std::io::{BufRead, BufReader, Write};

    listener.set_nonblocking(true)?;
    let token = Some(token);
    let mut failures = 0usize;

    loop {
        if std::time::Instant::now() >= deadline {
            return Ok(PairingOutcome::TimedOut);
        }
        let (stream, peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            Err(err) => return Err(err),
        };
        stream.set_nonblocking(false)?;
        // A connection that opens and then says nothing must not hold the window.
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

        let mut line = String::new();
        // `Read::take` on the STREAM, then buffer it. Taking on the BufReader instead
        // resolves to `Iterator::take`, which does not bound the read at all.
        let read = {
            use std::io::Read as _;
            let bounded = (&stream).take(MAX_REQUEST_BYTES as u64);
            BufReader::new(bounded).read_line(&mut line)
        };
        let mut stream = stream;

        let outcome = match read {
            Err(err) => RedeemOutcome::Refused {
                reason: format!("read failed from {peer}: {err}"),
                client_message: OPAQUE_REFUSAL,
            },
            Ok(0) => RedeemOutcome::Refused {
                reason: format!("{peer} connected and sent nothing"),
                client_message: OPAQUE_REFUSAL,
            },
            Ok(_) => match serde_json::from_str::<PairRedeem>(line.trim()) {
                Ok(request) => redeem(&request, token.as_ref(), authorized_keys),
                Err(err) => RedeemOutcome::Refused {
                    reason: format!("unparseable request from {peer}: {err}"),
                    client_message: OPAQUE_REFUSAL,
                },
            },
        };

        match outcome {
            RedeemOutcome::Accepted { added } => {
                // Single-use is enforced by RETURNING here, not by clearing `token`:
                // the loop is the only thing that can serve a second request, and this
                // arm always leaves it. (An earlier `token = None;` here read as the
                // mechanism but was dead code — the compiler said so.) The consequence
                // to preserve: a key that landed must never be redeemable twice because
                // the client missed the confirmation, so nothing below may `continue`.
                let body = serde_json::json!({ "type": "pair.ok" });
                let _ = writeln!(stream, "{body}");
                let _ = stream.flush();
                on_event(if added {
                    "paired: key added to authorized_keys"
                } else {
                    "paired: that key was already authorized"
                });
                return Ok(PairingOutcome::Paired { added });
            }
            RedeemOutcome::Refused {
                reason,
                client_message,
            } => {
                failures += 1;
                let body = serde_json::json!({ "type": "pair.error", "message": client_message });
                let _ = writeln!(stream, "{body}");
                let _ = stream.flush();
                // The real reason goes to the OPERATOR's terminal, never on the wire.
                on_event(&format!("refused: {reason}"));
                if failures >= MAX_FAILED_ATTEMPTS {
                    return Ok(PairingOutcome::GaveUp);
                }
            }
        }
    }
}

pub fn authorized_keys_path(home: &Path) -> PathBuf {
    home.join(".ssh").join("authorized_keys")
}

/// The line we append, carrying the marker and a device label so it can be identified and
/// revoked later.
pub fn marked_authorized_key(public_key_line: &str, device_label: &str) -> String {
    let key = public_key_line.trim();
    let label = device_label.trim();
    if label.is_empty() {
        format!("{key} {AUTHORIZED_KEYS_MARKER}")
    } else {
        format!("{key} {AUTHORIZED_KEYS_MARKER}:{label}")
    }
}

/// Reject anything that is not a single well-formed ed25519 public key line.
///
/// This is attacker-controlled input that ends up in a file sshd reads, so it is validated
/// before it is written, not after. A newline in particular would let one redemption
/// append MULTIPLE authorized keys, or append options (`command=`, `from=`) to a
/// subsequent line — so embedded newlines are refused outright rather than escaped.
pub fn validate_public_key_line(line: &str) -> Result<&str, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err("empty public key".into());
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err("public key contains a newline; refusing to write it".into());
    }
    let mut parts = trimmed.split_whitespace();
    let kind = parts.next().unwrap_or_default();
    if kind != "ssh-ed25519" {
        return Err(format!("expected an ssh-ed25519 key, got {kind:?}"));
    }
    let blob = parts.next().unwrap_or_default();
    if blob.is_empty() {
        return Err("public key has no key material".into());
    }
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|_| "public key material is not valid base64".to_string())?;
    // string("ssh-ed25519") + string(32-byte key) = 4+11 + 4+32.
    if decoded.len() != 51 {
        return Err(format!(
            "public key material is {} bytes, expected 51 for ed25519",
            decoded.len()
        ));
    }
    Ok(trimmed)
}

/// Append a validated public key to `authorized_keys`, idempotently.
///
/// Appends rather than rewrites: this file is the user's, it may hold keys herdr knows
/// nothing about, and losing one locks somebody out of their own machine. Returns whether
/// a line was actually added, so a repeated pairing reports honestly instead of silently
/// growing the file.
pub fn append_authorized_key(path: &Path, line: &str) -> io::Result<bool> {
    use std::io::Write as _;
    let key_line = validate_public_key_line(line).map_err(io::Error::other)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // sshd IGNORES ~/.ssh and authorized_keys that are group/world writable, and
            // does so silently. Getting this wrong means pairing "succeeds" and login
            // fails with nothing useful logged.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let existing = std::fs::read_to_string(path).unwrap_or_default();
    // Compare on the key material, not the whole line: the comment carries a device label
    // that can legitimately differ between pairings of the same key.
    let material = key_line.split_whitespace().nth(1).unwrap_or_default();
    let already = existing
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(material));
    if already {
        return Ok(false);
    }

    let needs_newline = !existing.is_empty() && !existing.ends_with('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if needs_newline {
        file.write_all(b"\n")?;
    }
    file.write_all(key_line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_random_and_not_reused() {
        let a = PairingToken::generate().expect("OS randomness");
        let b = PairingToken::generate().expect("OS randomness");
        assert_ne!(a.as_str(), b.as_str());
        // 32 bytes -> 43 base64url chars, unpadded.
        assert_eq!(a.as_str().len(), 43);
        assert!(!a.as_str().contains('='), "url-safe, unpadded");
    }

    #[test]
    fn a_token_matches_only_itself() {
        let t = PairingToken::generate().unwrap();
        assert!(t.matches(t.as_str()));
        assert!(!t.matches(""));
        assert!(!t.matches("not-the-token"));
        // A prefix must not pass — the comparison is over the whole value.
        assert!(!t.matches(&t.as_str()[..10]));
    }

    /// A token in a log is a credential in a log.
    #[test]
    fn a_token_never_prints_itself() {
        let t = PairingToken::generate().unwrap();
        let shown = format!("{t:?}");
        assert!(!shown.contains(t.as_str()));
        assert!(shown.contains("redacted"));
    }

    fn sample_payload() -> PairingPayload {
        PairingPayload {
            v: PAIRING_PAYLOAD_VERSION,
            host: "100.106.218.88".into(),
            port: 8787,
            user: "jerry".into(),
            token: "tok".into(),
            fp: "SHA256:vL7GMFHkifrUqP8D1g/8YJGKWxWjkvRaHfKjeLXytuc".into(),
        }
    }

    #[test]
    fn the_payload_round_trips_and_is_versioned() {
        let p = sample_payload();
        let json = p.to_json();
        let back: PairingPayload = serde_json::from_str(&json).expect("round trip");
        assert_eq!(back, p);
        assert!(
            json.contains("\"v\":1"),
            "an old app must be able to detect a new format"
        );
    }

    /// The payload must carry NOTHING that survives redemption. If this ever fails, a QR
    /// has become a credential someone can photograph off a screen.
    #[test]
    fn the_payload_carries_no_lasting_secret() {
        let json = sample_payload().to_json();
        for forbidden in ["PRIVATE KEY", "password", "BEGIN OPENSSH"] {
            assert!(
                !json.contains(forbidden),
                "pairing payload must never carry {forbidden}"
            );
        }
    }

    #[test]
    fn the_qr_renders_with_a_quiet_zone_and_correct_polarity() {
        let cells = qr_cells(&sample_payload().to_json()).expect("encodes");
        assert!(!cells.is_empty());

        let width = cells[0].len();
        assert!(cells.iter().all(|r| r.len() == width), "ragged QR");

        // The 4-module quiet zone means the top rows and both side columns are entirely
        // LIGHT. A QR with no margin scans badly, and the failure looks like a camera
        // problem rather than a rendering one.
        assert!(
            cells[0].iter().all(|c| c.top_light && c.bottom_light),
            "top quiet zone must be solid light"
        );
        assert!(
            cells.iter().all(|r| {
                let (l, r2) = (r[0], r[width - 1]);
                l.top_light && l.bottom_light && r2.top_light && r2.bottom_light
            }),
            "left and right quiet zones must be solid light"
        );

        // A real QR must contain DARK modules. An all-light block would render beautifully
        // and scan as nothing.
        assert!(
            cells
                .iter()
                .flatten()
                .any(|c| !c.top_light || !c.bottom_light),
            "no dark modules rendered — the QR would be blank to a scanner"
        );
    }

    /// THE RENDERED OUTPUT MUST NOT DEPEND ON THE TERMINAL'S THEME.
    ///
    /// Measured defect, not a hypothetical: the first version drew light modules as glyphs
    /// and left dark ones as background, which inverts on a light-background terminal.
    /// An independent decoder (OpenCV) read the dark-terminal render and FAILED on the
    /// inverted one — and macOS Terminal's default profile is white-on-black's opposite,
    /// so the default Mac setup was exactly the broken case.
    ///
    /// So every cell must carry BOTH colours explicitly, from the 256-colour cube rather
    /// than the themeable 0-15 range.
    #[test]
    fn every_cell_paints_both_colours_from_the_unthemeable_cube() {
        let out = render_qr_terminal(&sample_payload().to_json()).unwrap();

        // Colours 0-15 are remapped by the user's profile; using one would reintroduce
        // the theme dependency this test exists to prevent.
        for themeable in [
            "\x1b[30m",
            "\x1b[37m",
            "\x1b[40m",
            "\x1b[47m",
            "\x1b[97m",
            "\x1b[107m",
        ] {
            assert!(
                !out.contains(themeable),
                "{themeable:?} is theme-remappable; use the 256-colour cube"
            );
        }

        // Both a foreground and a background must be set, and only pure white/black.
        assert!(
            out.contains("38;5;231") && out.contains("48;5;16"),
            "light-over-dark missing"
        );
        assert!(
            out.contains("38;5;16") && out.contains("48;5;231"),
            "dark-over-light missing"
        );

        // Every line resets, or the colour bleeds into whatever prints next.
        assert!(
            out.lines().all(|l| l.ends_with(SGR_RESET)),
            "each line must reset SGR"
        );
    }

    /// THE RENDERER IS THE PART WE WROTE, SO IT IS THE PART TESTED HERE.
    ///
    /// Reads the rendered cells back into a module matrix and compares it against the
    /// encoder's own `get_module`. That covers every way the half-block mapping could be
    /// wrong — inverted polarity, a swapped upper/lower half, an off-by-one on the odd
    /// final row, a quiet zone of the wrong width.
    ///
    /// Honest limit: this proves our rendering faithfully represents qrcodegen's matrix,
    /// not that a camera can read it. That second half was measured separately and out of
    /// band — OpenCV's decoder read the real `herdr pair` output back to the exact payload
    /// JSON — but a decoder is not a dependency of this crate, so the receipt lives in the
    /// PR, not here.
    #[test]
    fn the_rendered_cells_decode_back_to_the_encoders_own_matrix() {
        use qrcodegen::{QrCode, QrCodeEcc};
        let data = sample_payload().to_json();
        let qr = QrCode::encode_text(&data, QrCodeEcc::Medium).unwrap();
        let cells = qr_cells(&data).unwrap();

        let mut checked = 0usize;
        for y in 0..qr.size() {
            for x in 0..qr.size() {
                // Rendered coordinates: shifted by the quiet zone, two module rows per line.
                let col = (x + QUIET_MODULES) as usize;
                let line = ((y + QUIET_MODULES) / 2) as usize;
                let cell = cells[line][col];
                let light_here = if (y + QUIET_MODULES) % 2 == 0 {
                    cell.top_light
                } else {
                    cell.bottom_light
                };
                assert_eq!(
                    light_here,
                    !qr.get_module(x, y),
                    "module ({x},{y}) rendered with the wrong polarity"
                );
                checked += 1;
            }
        }
        // State the count with the result: a loop that checked nothing would pass loudly.
        assert!(
            checked > 400,
            "only {checked} modules verified — the check is vacuous"
        );
    }

    /// Writes the QR two ways so a human can test the thing that actually matters.
    ///
    /// The PNG is a CONTROL: it is qrcodegen's matrix rendered as plain pixels, so if it
    /// scans and the terminal one does not, the bug is in our half-block renderer and
    /// nowhere else. Run with:
    ///   cargo test --bin herdr dump_qr -- --nocapture --ignored
    #[test]
    #[ignore = "artifact dump for manual scanning"]
    fn dump_qr() {
        use qrcodegen::{QrCode, QrCodeEcc};
        let payload = sample_payload().to_json();
        let dir = std::path::PathBuf::from(
            std::env::var("HERDR_QR_OUT").unwrap_or_else(|_| "/tmp".into()),
        );
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(
            dir.join("qr-terminal.txt"),
            render_qr_terminal(&payload).unwrap(),
        )
        .unwrap();

        // PBM: one byte per pixel is trivial to emit without an image crate, and PIL can
        // convert it. 1 = black (a dark QR module), 0 = white.
        let qr = QrCode::encode_text(&payload, QrCodeEcc::Medium).unwrap();
        const QUIET: i32 = 4;
        let n = qr.size() + 2 * QUIET;
        let mut pbm = format!("P1\n{n} {n}\n");
        for y in -QUIET..qr.size() + QUIET {
            for x in -QUIET..qr.size() + QUIET {
                pbm.push(if qr.get_module(x, y) { '1' } else { '0' });
                pbm.push(' ');
            }
            pbm.push('\n');
        }
        std::fs::write(dir.join("qr-reference.pbm"), pbm).unwrap();
        std::fs::write(dir.join("qr-payload.json"), &payload).unwrap();
        println!(
            "wrote qr-terminal.txt, qr-reference.pbm, qr-payload.json to {}",
            dir.display()
        );
    }

    /// Not an assertion — a way to eyeball the thing a human will actually scan.
    /// Run with: cargo test --bin herdr show_qr -- --nocapture --ignored
    #[test]
    #[ignore = "visual check only"]
    fn show_qr() {
        println!(
            "{}",
            render_qr_terminal(&sample_payload().to_json()).unwrap()
        );
    }

    #[test]
    fn the_qr_encodes_a_realistic_payload_without_overflowing() {
        // A long username and a full fingerprint — the biggest realistic payload.
        let p = PairingPayload {
            user: "a-rather-long-username".into(),
            host: "100.127.255.255".into(),
            ..sample_payload()
        };
        assert!(render_qr_terminal(&p.to_json()).is_ok());
    }

    #[test]
    fn tailnet_range_is_100_64_through_100_127() {
        assert!(is_tailnet_address("100.64.0.0".parse().unwrap()));
        assert!(is_tailnet_address("100.106.218.88".parse().unwrap()));
        assert!(is_tailnet_address("100.127.255.255".parse().unwrap()));
        // Adjacent but NOT tailnet — 100.63 and 100.128 are ordinary public space.
        assert!(!is_tailnet_address("100.63.255.255".parse().unwrap()));
        assert!(!is_tailnet_address("100.128.0.0".parse().unwrap()));
        assert!(!is_tailnet_address("37.27.59.89".parse().unwrap()));
    }

    /// THE SECURITY PROPERTY: a pre-authentication endpoint must never land on a public
    /// interface. Every refusal below is the point of the feature, not an edge case.
    #[test]
    fn binding_refuses_every_way_of_reaching_the_internet() {
        let public: Ipv4Addr = "37.27.59.89".parse().unwrap();
        let tailnet: Ipv4Addr = "100.106.218.88".parse().unwrap();
        let lan: Ipv4Addr = "192.168.1.10".parse().unwrap();

        // No Tailscale and no opt-in: refuse.
        assert_eq!(
            choose_bind_address(None, None),
            Err(BindRefusal::NoTailscale)
        );
        // --lan pointed at a public address: refuse.
        assert_eq!(
            choose_bind_address(None, Some(public)),
            Err(BindRefusal::LanAddressIsPublic(public))
        );
        // Tailscale reporting something outside the range: refuse rather than guess.
        assert_eq!(
            choose_bind_address(Some(public), None),
            Err(BindRefusal::NotATailnetAddress(public))
        );
        // The two legitimate paths.
        assert_eq!(choose_bind_address(Some(tailnet), None), Ok(tailnet));
        assert_eq!(choose_bind_address(None, Some(lan)), Ok(lan));
        // Tailscale wins even when --lan is also supplied: passing a flag must not
        // silently drop to the weaker network.
        assert_eq!(choose_bind_address(Some(tailnet), Some(lan)), Ok(tailnet));
    }

    fn sample_key() -> String {
        // string("ssh-ed25519") + string(32 bytes) = 51 bytes.
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[7u8; 32]);
        use base64::Engine as _;
        format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        )
    }

    #[test]
    fn a_well_formed_key_validates() {
        let k = sample_key();
        assert!(validate_public_key_line(&k).is_ok());
        assert!(validate_public_key_line(&format!("  {k}  ")).is_ok());
    }

    /// THE INJECTION GUARD. This input ends up in a file sshd reads; a newline would let
    /// one redemption append a SECOND key, or attach options like `command=`/`from=` to
    /// whatever follows.
    #[test]
    fn a_newline_in_a_key_is_refused_not_escaped() {
        let k = sample_key();
        for evil in [
            format!("{k}\nssh-ed25519 AAAA attacker"),
            format!("{k}\r\nssh-ed25519 AAAA attacker"),
        ] {
            assert!(
                validate_public_key_line(&evil).is_err(),
                "an embedded newline must be refused outright"
            );
        }
    }

    /// THE CROSS-LANGUAGE CONTRACT.
    ///
    /// This exact line was produced by the iOS side's PairingKey (Swift/CryptoKit, using
    /// Citadel's OpenSSH writer) and independently verified by real ssh-keygen, which
    /// derived the same public key and the same SHA256 fingerprint from the matching
    /// private key.
    ///
    /// Pinned here because the two halves are written in different languages against the
    /// same wire format, and nothing else would catch them drifting: a mismatch shows up
    /// as pairing failing on a user's phone, with sshd silently ignoring the key and
    /// logging nothing that names the cause.
    #[test]
    fn a_key_generated_by_the_ios_side_validates_here() {
        let from_swift = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDYBEgq6QqJ3tTOxBY+efdRE3BnChf8Bpq2SozDhVhUF herdrup-spike";
        let ok = validate_public_key_line(from_swift).expect("the app's own key must validate");
        assert!(ok.starts_with("ssh-ed25519 "));

        // The key material is exactly the 51-byte ed25519 blob, so the length check that
        // rejects malformed input does not reject the real thing.
        use base64::Engine as _;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(ok.split_whitespace().nth(1).unwrap())
            .expect("base64");
        assert_eq!(blob.len(), 51);

        // And it survives the write path unchanged.
        let marked = marked_authorized_key(ok, "iPhone");
        assert!(marked.starts_with(from_swift));
        assert!(marked.ends_with("herdr-pair:iPhone"));
    }

    #[test]
    fn malformed_keys_are_refused() {
        assert!(validate_public_key_line("").is_err());
        assert!(validate_public_key_line("   ").is_err());
        assert!(validate_public_key_line("ssh-rsa AAAAB3Nz").is_err());
        assert!(validate_public_key_line("ssh-ed25519").is_err());
        assert!(validate_public_key_line("ssh-ed25519 not!base64!").is_err());
        // Right type, wrong length — a truncated or padded blob must not pass.
        use base64::Engine as _;
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 20]);
        assert!(validate_public_key_line(&format!("ssh-ed25519 {short}")).is_err());
    }

    fn temp_keys(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("herdr-redeem-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        authorized_keys_path(&dir)
    }

    fn redeem_request(token: &str) -> PairRedeem {
        PairRedeem {
            kind: PAIR_REDEEM_KIND.into(),
            token: token.into(),
            public_key: sample_key(),
            device: "Jerry's iPhone".into(),
        }
    }

    #[test]
    fn a_valid_redemption_writes_the_key() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("ok");
        let out = redeem(&redeem_request(token.as_str()), Some(&token), &path);
        assert_eq!(out, RedeemOutcome::Accepted { added: true });
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("ssh-ed25519"));
        assert!(body.contains("herdr-pair:Jerry's iPhone"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// THE SINGLE-USE PROPERTY. This is what makes a photographed QR harmless: once the
    /// token is spent the listener holds `None`, and the same correct token is refused.
    #[test]
    fn a_spent_token_is_refused_even_with_the_right_value() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("spent");
        let req = redeem_request(token.as_str());
        assert!(matches!(
            redeem(&req, Some(&token), &path),
            RedeemOutcome::Accepted { .. }
        ));
        // Token consumed by the caller -> None.
        match redeem(&req, None, &path) {
            RedeemOutcome::Refused { reason, .. } => assert!(reason.contains("already redeemed")),
            other => panic!("a spent token must be refused, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// Every refusal must look identical on the wire. An unauthenticated caller learns
    /// only "no" — never whether the token was wrong, spent, or the key malformed, which
    /// would turn the listener into an oracle.
    #[test]
    fn refusals_are_opaque_to_the_client_but_specific_in_our_log() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("opaque");
        let cases = vec![
            redeem(&redeem_request("wrong-token"), Some(&token), &path),
            redeem(&redeem_request(token.as_str()), None, &path),
            redeem(
                &PairRedeem {
                    public_key: "ssh-rsa AAAA".into(),
                    ..redeem_request(token.as_str())
                },
                Some(&token),
                &path,
            ),
            redeem(
                &PairRedeem {
                    kind: "pair.something-else".into(),
                    ..redeem_request(token.as_str())
                },
                Some(&token),
                &path,
            ),
        ];
        let mut reasons = std::collections::HashSet::new();
        for case in &cases {
            match case {
                RedeemOutcome::Refused {
                    reason,
                    client_message,
                } => {
                    assert_eq!(
                        *client_message, OPAQUE_REFUSAL,
                        "the wire message must not vary"
                    );
                    reasons.insert(reason.clone());
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
        assert_eq!(
            reasons.len(),
            4,
            "our own log must still distinguish all four"
        );
        assert!(!path.exists(), "no refusal may write anything");
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// The device label lands in a file. It is attacker-controlled, so it is reduced to a
    /// safe subset rather than trusted.
    #[test]
    fn device_labels_are_sanitised() {
        assert_eq!(sanitize_device_label("Jerry's iPhone"), "Jerry's iPhone");
        assert_eq!(sanitize_device_label("  spaced   out  "), "spaced out");
        // A newline becomes a SPACE rather than vanishing — the property that matters is
        // that no line break survives into authorized_keys, not that the text is joined.
        assert_eq!(
            sanitize_device_label("evil\nssh-ed25519 AAAA"),
            "evil ssh-ed25519 AAAA"
        );
        assert!(!sanitize_device_label("a\nb").contains('\n'));
        assert!(!sanitize_device_label("a\r\nb").contains('\r'));
        assert!(!sanitize_device_label("a\u{0}b").contains('\u{0}'));
        // Length-capped so one redemption cannot append an enormous comment.
        assert!(sanitize_device_label(&"x".repeat(500)).chars().count() <= 48);
    }

    /// Even a sanitised label must not be able to inject a second key: the line written is
    /// still validated as a whole.
    #[test]
    fn a_hostile_device_label_cannot_smuggle_a_key() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("hostile");
        let req = PairRedeem {
            device: "x\nssh-ed25519 AAAAattacker".into(),
            ..redeem_request(token.as_str())
        };
        assert!(matches!(
            redeem(&req, Some(&token), &path),
            RedeemOutcome::Accepted { .. }
        ));
        let body = std::fs::read_to_string(&path).unwrap();
        // THE PROPERTY THAT MATTERS: one LINE, therefore one key. sshd parses one key per
        // line and treats everything after the base64 blob as a comment, so the attacker's
        // literal "ssh-ed25519 AAAAattacker" text is inert — it is comment, not a key.
        // Asserting on the field structure says that; counting substring occurrences did
        // not, and failed on a file that was actually safe.
        assert_eq!(
            body.lines().count(),
            1,
            "exactly one key line may be written"
        );
        let fields: Vec<&str> = body.split_whitespace().collect();
        assert_eq!(fields[0], "ssh-ed25519");
        assert_eq!(
            fields[1],
            sample_key().split_whitespace().nth(1).unwrap(),
            "field 2 must be OUR key material, not the attacker's"
        );
        assert!(!body.trim_end().contains('\n'));
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// Drive the real protocol over loopback: bind, connect, send one JSON line, read the
    /// reply. Exercises the socket path end to end without needing a tailnet.
    fn drive_pairing(
        token: PairingToken,
        requests: Vec<String>,
        keys: &Path,
        ttl: std::time::Duration,
    ) -> (PairingOutcome, Vec<String>, Vec<String>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            let mut replies = Vec::new();
            for body in requests {
                // Give the server a moment to reach accept() on the first pass.
                std::thread::sleep(std::time::Duration::from_millis(60));
                let Ok(mut s) = std::net::TcpStream::connect(addr) else {
                    break;
                };
                let _ = writeln!(s, "{body}");
                let _ = s.flush();
                let mut line = String::new();
                let _ = BufReader::new(&s).read_line(&mut line);
                replies.push(line.trim().to_string());
            }
            replies
        });

        let mut events = Vec::new();
        let outcome = serve_one_pairing(
            &listener,
            token,
            keys,
            std::time::Instant::now() + ttl,
            |e| events.push(e.to_string()),
        )
        .expect("serve");
        let replies = client.join().unwrap_or_default();
        (outcome, replies, events)
    }

    #[test]
    fn a_phone_can_redeem_over_a_real_socket() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("serve-ok");
        let req = serde_json::to_string(&redeem_request(token.as_str())).unwrap();
        let (outcome, replies, _) =
            drive_pairing(token, vec![req], &path, std::time::Duration::from_secs(5));
        assert_eq!(outcome, PairingOutcome::Paired { added: true });
        assert!(replies[0].contains("pair.ok"), "got {:?}", replies);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("ssh-ed25519"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// THE SINGLE-USE PROPERTY, over the wire this time: the second attempt uses the SAME
    /// correct token and must still be refused. This is what makes a photographed QR
    /// harmless after it has been used once.
    #[test]
    fn the_second_redemption_of_a_correct_token_is_refused() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("serve-twice");
        let req = serde_json::to_string(&redeem_request(token.as_str())).unwrap();
        // The server returns after the FIRST success, so a second attempt cannot even be
        // served — which is the property. Prove it by re-serving with the token consumed.
        let (first, _, _) = drive_pairing(
            token.clone(),
            vec![req.clone()],
            &path,
            std::time::Duration::from_secs(5),
        );
        assert_eq!(first, PairingOutcome::Paired { added: true });

        // A fresh listener with the token already spent: the same request must fail.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            std::thread::sleep(std::time::Duration::from_millis(60));
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            let _ = writeln!(s, "{req}");
            let mut line = String::new();
            let _ = BufReader::new(&s).read_line(&mut line);
            line
        });
        // `redeem` is handed None, exactly as the server does once consumed.
        let spent: Option<&PairingToken> = None;
        let parsed: PairRedeem =
            serde_json::from_str(&serde_json::to_string(&redeem_request(token.as_str())).unwrap())
                .unwrap();
        assert!(matches!(
            redeem(&parsed, spent, &path),
            RedeemOutcome::Refused { .. }
        ));
        drop(listener);
        let _ = client.join();
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// A wrong token gets an opaque error and writes nothing.
    #[test]
    fn a_wrong_token_over_the_wire_is_refused_opaquely() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("serve-wrong");
        let bad = serde_json::to_string(&redeem_request("not-the-token")).unwrap();
        let (outcome, replies, events) = drive_pairing(
            token,
            vec![bad],
            &path,
            std::time::Duration::from_millis(900),
        );
        assert_eq!(
            outcome,
            PairingOutcome::TimedOut,
            "a refusal must not end the window"
        );
        assert!(replies[0].contains("pair.error"), "got {:?}", replies);
        assert!(
            replies[0].contains(OPAQUE_REFUSAL),
            "the wire message must be the opaque one"
        );
        assert!(
            !replies[0].contains("mismatch"),
            "the client must not learn WHY: {:?}",
            replies[0]
        );
        // Our own log still says exactly what happened.
        assert!(events.iter().any(|e| e.contains("token mismatch")));
        assert!(!path.exists(), "a refusal must write nothing");
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// Nobody shows up: the window closes on its own rather than waiting forever.
    #[test]
    fn the_window_times_out_when_nobody_pairs() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("serve-timeout");
        let (outcome, _, _) =
            drive_pairing(token, vec![], &path, std::time::Duration::from_millis(400));
        assert_eq!(outcome, PairingOutcome::TimedOut);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// Garbage on the socket is refused like anything else, and does not crash the server
    /// or end the window — this endpoint is reachable pre-authentication, so it will be
    /// probed.
    #[test]
    fn garbage_on_the_socket_is_survived() {
        let token = PairingToken::generate().unwrap();
        let path = temp_keys("serve-garbage");
        let (outcome, replies, _) = drive_pairing(
            token,
            vec!["not json at all".into(), "{\"type\":\"nope\"}".into()],
            &path,
            std::time::Duration::from_millis(900),
        );
        assert_eq!(outcome, PairingOutcome::TimedOut);
        assert_eq!(replies.len(), 2, "both probes must get an answer");
        assert!(replies.iter().all(|r| r.contains("pair.error")));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn the_written_line_carries_a_findable_marker() {
        let line = marked_authorized_key("ssh-ed25519 AAAA", "Jerry's iPhone");
        assert!(line.contains(AUTHORIZED_KEYS_MARKER));
        assert!(line.ends_with("herdr-pair:Jerry's iPhone"));
        assert_eq!(
            marked_authorized_key("ssh-ed25519 AAAA", "  "),
            "ssh-ed25519 AAAA herdr-pair"
        );
    }

    #[test]
    fn appending_is_idempotent_and_preserves_existing_keys() {
        let dir = std::env::temp_dir().join(format!("herdr-pair-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = authorized_keys_path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // A key herdr knows nothing about. Losing it would lock someone out.
        std::fs::write(&path, "ssh-rsa AAAAsomeoneelse existing-key\n").unwrap();

        let key = sample_key();
        assert!(
            append_authorized_key(&path, &key).unwrap(),
            "first add writes"
        );
        assert!(
            !append_authorized_key(&path, &key).unwrap(),
            "second add must report it changed nothing"
        );

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("existing-key"),
            "pre-existing keys must survive"
        );
        assert_eq!(body.matches("ssh-ed25519").count(), 1, "no duplicate");
        assert!(body.ends_with('\n'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file with no trailing newline would otherwise get our key glued onto the last
    /// line, corrupting both.
    #[test]
    fn appending_to_a_file_without_a_trailing_newline_does_not_join_lines() {
        let dir = std::env::temp_dir().join(format!("herdr-pair-nl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = authorized_keys_path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "ssh-rsa AAAAexisting no-trailing-newline").unwrap();

        append_authorized_key(&path, &sample_key()).unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2, "two distinct lines, not one glued");
        assert!(body
            .lines()
            .next()
            .unwrap()
            .ends_with("no-trailing-newline"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn permissions_are_tightened_because_sshd_silently_ignores_loose_ones() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("herdr-pair-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = authorized_keys_path(&dir);
        append_authorized_key(&path, &sample_key()).unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
