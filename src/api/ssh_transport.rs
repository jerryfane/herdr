//! Outbound key-based SSH transport for the federation client.
//!
//! Modeled on `crate::remote::attach::bridge_connection`: spawn
//! `ssh -T <user@host> exec <remote_herdr> api-bridge [<arg>]` and wire the
//! child's stdin/stdout into an [`ApiStream::Ssh`]. Unlike the interactive
//! remote bridge (one long-lived TUI socket pumped as raw bytes), the JSON API
//! bridge is **one request per invocation** — so this transport spawns a fresh
//! child for each request, with the request already embedded, and the caller
//! reads the reply line(s) off the child's stdout until EOF.
//!
//! The request reaches the remote `api-bridge` two ways, chosen by size:
//!
//! - **base64 argv** (default): `api-bridge <base64(json)>`. The kernel caps a
//!   single argv string at `MAX_ARG_STRLEN` (~128 KiB), and base64's 4/3
//!   expansion caps the raw JSON near ~98 KiB, so this is the client's job to
//!   bound — see [`SSH_ARGV_MAX_REQUEST_BYTES`].
//! - **stdin form** (large requests): `api-bridge` with no arg; the request
//!   JSON is piped to the child's stdin, which has no such limit.
//!
//! v1 is KEY-BASED ssh only. [`SshCredential::Password`] is reserved and
//! rejected here; password auth is not implemented.

use std::io::{self, Write as _};
use std::process::{Command, Stdio};

use base64::Engine as _;

use super::client::{SshCredential, SshTarget};
use super::transport::{ApiStream, SshPipe};

/// Remote `herdr` invocation used in the bridge command. Resolved on the remote
/// host's `PATH`; shell-quoted before it reaches the remote shell.
const DEFAULT_REMOTE_HERDR: &str = "herdr";

/// Raw-JSON byte length above which a request is delivered on the child's stdin
/// instead of as a base64 argv argument. Kept safely below `MAX_ARG_STRLEN`
/// after base64's 4/3 expansion (~90 KiB raw → ~120 KiB encoded).
pub(crate) const SSH_ARGV_MAX_REQUEST_BYTES: usize = 90_000;

/// Whether a request of `raw_len` raw-JSON bytes is sent on stdin (`true`) or as
/// a base64 argv argument (`false`).
pub(crate) fn request_uses_stdin(raw_len: usize) -> bool {
    raw_len > SSH_ARGV_MAX_REQUEST_BYTES
}

/// Build the remote command: `exec <remote_herdr> api-bridge [<arg>]`. Both the
/// binary path and the argument are shell-quoted so the remote shell parses them
/// as single words.
pub(crate) fn federation_bridge_command(remote_herdr: &str, arg: Option<&str>) -> String {
    let mut command = format!(
        "exec {} api-bridge",
        crate::remote::shell_quote(remote_herdr)
    );
    if let Some(arg) = arg {
        command.push(' ');
        command.push_str(&crate::remote::shell_quote(arg));
    }
    command
}

/// The SSH destination (`user@host` or bare `host`) for a target.
fn destination(target: &SshTarget) -> String {
    match &target.user {
        Some(user) => format!("{user}@{}", target.host),
        None => target.host.clone(),
    }
}

/// Spawn the per-request SSH bridge for `request_json` and return the connected
/// [`ApiStream::Ssh`]. The request is embedded at spawn time (base64 argv, or
/// stdin for oversized requests), so the caller must NOT write the request again
/// — it only reads reply lines off the returned stream.
pub(crate) fn spawn_request(target: &SshTarget, request_json: &str) -> io::Result<ApiStream> {
    match &target.credential {
        SshCredential::Key => {}
        // Reserved variant; password auth is intentionally not implemented in v1.
        SshCredential::Password(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "federation ssh password authentication is not supported (v1 is key-based only)",
            ));
        }
    }

    let use_stdin = request_uses_stdin(request_json.len());
    let remote_command = if use_stdin {
        federation_bridge_command(DEFAULT_REMOTE_HERDR, None)
    } else {
        let encoded = base64::engine::general_purpose::STANDARD.encode(request_json.as_bytes());
        federation_bridge_command(DEFAULT_REMOTE_HERDR, Some(&encoded))
    };

    let mut command = Command::new("ssh");
    // No managed-ssh options for federation yet; reuse the same application point
    // as the interactive bridge so control-master/config support is a one-liner
    // when federation grows it.
    crate::remote::apply_managed_ssh_options(&mut command, None);
    command
        .arg("-T")
        .arg(destination(target))
        .arg(&remote_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = command.spawn().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to start federation ssh bridge: {err}"),
        )
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "ssh bridge stdin missing"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "ssh bridge stdout missing"))?;

    if use_stdin {
        // Deliver the single request line on stdin; the bridge reads exactly one
        // line then streams replies. Stdin stays open (held in SshPipe) — the
        // bridge tears down on stdout hangup, not stdin EOF.
        stdin.write_all(request_json.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
    }

    Ok(ApiStream::Ssh(SshPipe::new(stdin, stdout, child)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_request_uses_base64_argv_and_large_uses_stdin() {
        assert!(!request_uses_stdin(10));
        assert!(!request_uses_stdin(SSH_ARGV_MAX_REQUEST_BYTES));
        assert!(request_uses_stdin(SSH_ARGV_MAX_REQUEST_BYTES + 1));
    }

    #[test]
    fn bridge_command_shapes_argv_and_stdin_forms() {
        assert_eq!(
            federation_bridge_command("herdr", None),
            "exec herdr api-bridge"
        );
        assert_eq!(
            federation_bridge_command("herdr", Some("QUJD")),
            "exec herdr api-bridge QUJD"
        );
        // A path with a space is quoted so the remote shell reads one word.
        assert_eq!(
            federation_bridge_command("/opt/my herdr/herdr", None),
            "exec '/opt/my herdr/herdr' api-bridge"
        );
    }

    #[test]
    fn base64_argv_decodes_back_to_the_original_request() {
        let request = r#"{"id":"7","method":"agent.list","params":{}}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(request.as_bytes());
        let command = federation_bridge_command("herdr", Some(&encoded));
        // Recover the argv argument and confirm it round-trips to the request.
        let arg = command.rsplit(' ').next().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(arg)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), request);
    }

    #[test]
    fn password_credential_is_rejected() {
        let target = SshTarget {
            host: "example".into(),
            user: Some("herder".into()),
            credential: SshCredential::Password("nope".into()),
        };
        // `ApiStream` is not `Debug`, so recover the error via `.err()` rather
        // than `unwrap_err()`.
        let result = spawn_request(&target, r#"{"id":"1","method":"ping"}"#);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Unsupported);
    }
}
