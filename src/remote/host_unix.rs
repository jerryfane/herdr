//! Unix remote-host side of the SSH stdio bridge.

use std::io;
use std::io::{BufRead as _, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

pub(crate) fn run_remote_client_bridge() -> io::Result<()> {
    ensure_remote_server_running()?;

    let socket_path = crate::server::socket_paths::client_socket_path();
    let stream = UnixStream::connect(&socket_path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to connect to remote Herdr client socket {}: {err}",
                socket_path.display()
            ),
        )
    })?;

    let mut stdout = io::stdout().lock();
    let mut socket_to_stdout = stream.try_clone()?;
    let mut stdin_to_socket = stream;

    let _upload = thread::spawn(move || {
        let mut stdin = io::stdin();
        let _ = copy_flush(&mut stdin, &mut stdin_to_socket);
        let _ = stdin_to_socket.shutdown(std::net::Shutdown::Write);
    });

    copy_flush(&mut socket_to_stdout, &mut stdout).map(|_| ())
}

fn copy_flush<R: io::Read, W: io::Write>(reader: &mut R, writer: &mut W) -> io::Result<u64> {
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        writer.write_all(&buffer[..read])?;
        writer.flush()?;
        total += read as u64;
    }
}

fn ensure_remote_server_running() -> io::Result<()> {
    let socket_path = crate::server::socket_paths::client_socket_path();
    if crate::server::autodetect::is_server_listening() {
        let status = crate::api::read_runtime_status_at(
            &crate::api::socket_path(),
            Duration::from_millis(500),
        )?
        .ok_or_else(|| io::Error::other("remote server status API is unavailable"))?;
        if status.protocol == Some(crate::protocol::PROTOCOL_VERSION) {
            return Ok(());
        }
        return Err(io::Error::other(
            "remote herdr server must restart before this bridge can attach; rerun `herdr --remote` from an interactive terminal to approve stopping it",
        ));
    }

    crate::server::autodetect::spawn_server_daemon()?;
    crate::server::autodetect::wait_for_server_socket(&socket_path, Duration::from_secs(5))
}

/// Bridges stdio to the JSON API socket for a remote (mobile) client.
///
/// Unlike `run_remote_client_bridge`, which pumps one long-lived TUI-socket
/// connection as a raw byte stream, the API socket is single-shot: one request
/// per connection.
///
/// ONE REQUEST PER INVOCATION. The client opens one SSH channel — one
/// `herdr api-bridge` exec — per API call, multiplexing at the SSH-channel level
/// over its single held connection, which is where multiplexing belongs. So this
/// reads exactly one request line from stdin, forwards it to a fresh API
/// connection, and streams every reply line back until the connection closes.
/// A round-trip yields one reply and exits; an `events.subscribe` streams until
/// the client drops the channel. That makes each process handle exactly one
/// request/response or one subscription, so replies never share stdout (no
/// identity ambiguity for streamed events, which carry no request id), there is
/// no unbounded fan-out, and stdin EOF has nothing to join or hang on.
///
/// An earlier version multiplexed many stdin lines over one process, which gave
/// concurrent subscriptions indistinguishable output, an unbounded thread per
/// line, and a stdin-EOF join that hung on an active stream. Channel-level
/// multiplexing removes all three.
///
/// Reached only over the same SSH authentication that already gates
/// `remote-client-bridge`; it opens no network listener.
pub(crate) fn run_api_client_bridge(encoded_request: Option<&str>) -> io::Result<()> {
    // Deliberately does NOT call ensure_remote_server_running(): that gates on
    // status.protocol == CURRENT_PROTOCOL, an exact TUI-protocol-version lock
    // that is fatal for a shipped client which cannot move in lockstep with
    // every server it connects to. The JSON API is versioned by its schema, not
    // that byte, so this connects directly and surfaces a clear error if no
    // server is listening rather than auto-starting one over an SSH exec.
    let socket_path = crate::api::socket_path();

    // The request may arrive as a base64 ARGUMENT or on stdin. The argument form
    // is what an SSH-exec client uses: `herdr api-bridge <base64(json)>` runs the
    // request through the remote shell without needing to write the channel's
    // stdin, and base64 keeps arbitrary JSON off the shell's quoting rules.
    // Stdin remains the fallback so `printf … | herdr api-bridge` still works.
    //
    // SIZE LIMIT, and it is the CLIENT's to enforce, not the bridge's. The
    // kernel caps a single argv string at MAX_ARG_STRLEN (32 pages, ~128 KiB on
    // a 4-KiB-page host) and returns E2BIG from execve BEFORE this process
    // starts — so an oversized request fails with no bridge running to emit a
    // correlated error. base64's 4/3 expansion caps the raw JSON at ~98 KiB. API
    // methods with unbounded text (agent.prompt, pane.send_text/send_input) can
    // exceed that, so a client using the argument form MUST enforce a portable
    // maximum below MAX_ARG_STRLEN and fall back to the stdin form (which has no
    // such limit) for larger requests. The bridge cannot enforce this — E2BIG
    // fires before it runs — so it is stated as the client's contract.
    let request_line = match encoded_request {
        Some(encoded) => decode_request_arg(encoded)?,
        None => {
            let mut line = String::new();
            if io::stdin().lock().read_line(&mut line)? == 0 {
                return Ok(()); // stdin closed with no request
            }
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
    };
    if request_line.trim().is_empty() {
        return Ok(());
    }

    let conn = match UnixStream::connect(&socket_path) {
        Ok(conn) => conn,
        Err(err) => {
            let mut stdout = io::stdout().lock();
            return emit_transport_error(&mut stdout, &request_line, &err);
        }
    };

    // TEARDOWN VIA STDOUT HANGUP, not stdin EOF. A round-trip client half-closes
    // stdin right after its request while still awaiting the reply, so watching
    // stdin EOF tore the reply out from under it (reproduced, reverted). The
    // output peer is the honest signal: when the SSH channel's read side closes,
    // fd 1 reports POLLHUP/POLLERR, and unlike a stdin half-close that only
    // happens when the client is genuinely gone. So a quiet subscription whose
    // client vanished is torn down, while a round-trip's half-close is not.
    if let Ok(teardown) = conn.try_clone() {
        let output_fd = std::os::unix::io::AsRawFd::as_raw_fd(&io::stdout());
        thread::spawn(move || wait_for_output_hangup_then_shutdown(output_fd, teardown));
    }

    let mut stdout = io::stdout().lock();
    send_and_stream(conn, &request_line, &mut stdout)
}

/// Blocks until `output_fd` reports POLLHUP/POLLERR (its read peer disappeared),
/// then shuts down `teardown` so a reader blocked on the API socket wakes and
/// the process exits. Separated and fd-parameterised so a test can drive it with
/// a pipe instead of the real stdout.
fn wait_for_output_hangup_then_shutdown(output_fd: std::os::unix::io::RawFd, teardown: UnixStream) {
    // Request POLLIN so poll() actually WAKES on hangup across platforms.
    // POLLHUP/POLLERR/POLLNVAL are reported in revents regardless of the mask,
    // but with events=0 macOS/BSD poll() does not wake on them (Linux does) —
    // caught by the macOS CI, which the Linux-only `just check` cannot see. A
    // write-only stdout is never POLLIN-readable, so POLLIN never fires
    // spuriously; it only makes poll return when the read peer disappears.
    let mut pfd = libc::pollfd {
        fd: output_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        pfd.revents = 0;
        let result = unsafe { libc::poll(&mut pfd, 1, -1) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break; // poll itself failed; give up watching rather than spin
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            let _ = teardown.shutdown(std::net::Shutdown::Both);
            break;
        }
    }
}

/// Decodes the base64 request argument into a single JSON request line. A
/// decode or UTF-8 failure is a client bug (the transport controls the
/// encoding), surfaced as an io error rather than silently forwarding garbage.
fn decode_request_arg(encoded: &str) -> io::Result<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("api-bridge: request argument is not valid base64: {err}"),
            )
        })?;
    String::from_utf8(bytes)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("api-bridge: request is not valid UTF-8: {err}"),
            )
        })
        .map(|line| line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Connects to the API socket and forwards the request/reply. The testable core
/// (connect + `send_and_stream`) without the stdin read or the teardown watcher,
/// so a fake socket exercises the forwarding and error paths directly. Only used
/// by tests now that `run_api_client_bridge` owns the connection to wire the
/// hangup watcher.
#[cfg(test)]
fn forward_api_request<W: Write>(
    socket_path: &std::path::Path,
    request_line: &str,
    out: &mut W,
) -> io::Result<()> {
    let conn = match UnixStream::connect(socket_path) {
        Ok(conn) => conn,
        Err(err) => return emit_transport_error(out, request_line, &err),
    };
    send_and_stream(conn, request_line, out)
}

/// Sends `request_line` on an established connection and forwards every reply
/// line to `out`, emitting a correlated transport error on failure.
fn send_and_stream<W: Write>(
    mut conn: UnixStream,
    request_line: &str,
    out: &mut W,
) -> io::Result<()> {
    let sent = conn
        .write_all(request_line.as_bytes())
        .and_then(|()| conn.write_all(b"\n"))
        .and_then(|()| conn.flush());
    if let Err(err) = sent {
        return emit_transport_error(out, request_line, &err);
    }

    let reader = io::BufReader::new(conn);
    for reply in reader.lines() {
        match reply {
            Ok(line) => {
                out.write_all(line.as_bytes())?;
                out.write_all(b"\n")?;
                out.flush()?;
            }
            Err(err) => return emit_transport_error(out, request_line, &err),
        }
    }
    Ok(())
}

/// Emits an NDJSON transport error carrying the originating request's `id`, so a
/// client waiting on that id is released rather than hanging.
///
/// `ErrorResponse.id` is a `String`, so only a STRING id is schema-valid. A
/// numeric id, or a request that is not valid JSON, falls back to the server's
/// own empty-string convention rather than emitting `null` or a number, which
/// the client's typed decoder would reject.
fn emit_transport_error<W: Write>(
    out: &mut W,
    request_line: &str,
    err: &io::Error,
) -> io::Result<()> {
    let id = serde_json::from_str::<serde_json::Value>(request_line)
        .ok()
        .and_then(|value| {
            value
                .get("id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    let envelope = serde_json::json!({
        "id": id,
        "error": {
            "code": "transport_error",
            "message": format!("api-bridge: {err}"),
        }
    });
    writeln!(out, "{envelope}")?;
    out.flush()
}

#[cfg(test)]
mod api_bridge_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read as _};
    use std::os::unix::net::UnixListener;

    /// forward_api_request must deliver the request line verbatim (with a
    /// trailing newline) and forward every reply line back, in order, one line
    /// at a time — the multiplex/framing contract, proven against a fake socket
    /// with no live server.
    #[test]
    fn forwards_request_and_reply_lines_verbatim() {
        let dir = std::env::temp_dir().join(format!("herdr-apibridge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sock = dir.join("api.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).expect("bind");

        // Fake API server: read one request line, then emit two reply lines and
        // close — a one-shot reply plus a streamed follow-up on one connection.
        let server = thread::spawn(move || {
            let (conn, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(conn.try_clone().expect("clone"));
            let mut request = String::new();
            reader.read_line(&mut request).expect("read request");
            let mut writer = conn;
            writer
                .write_all(b"{\"id\":\"1\",\"result\":1}\n")
                .expect("reply 1");
            writer
                .write_all(b"{\"id\":\"1\",\"stream\":\"x\"}\n")
                .expect("reply 2");
            request
        });

        let mut out = Vec::<u8>::new();
        forward_api_request(&sock, "{\"id\":\"1\",\"method\":\"ping\"}", &mut out)
            .expect("forward");
        let written = String::from_utf8(out).expect("utf8");
        let request_seen = server.join().expect("join");

        assert_eq!(
            request_seen, "{\"id\":\"1\",\"method\":\"ping\"}\n",
            "the request line was not delivered verbatim with its newline"
        );
        assert_eq!(
            written, "{\"id\":\"1\",\"result\":1}\n{\"id\":\"1\",\"stream\":\"x\"}\n",
            "reply lines were not forwarded in order, one per line"
        );

        let _ = std::fs::remove_file(&sock);
    }

    /// A transport failure (here: no socket at the path) must emit a correlated
    /// NDJSON error carrying the request's id, not exit silently — otherwise a
    /// client waiting on that id hangs forever, and the subcommand has no tracing
    /// subscriber so a logged error reaches no one.
    #[test]
    fn transport_failure_emits_correlated_error() {
        let missing = std::env::temp_dir().join(format!(
            "herdr-apibridge-missing-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);

        let mut out = Vec::<u8>::new();
        forward_api_request(
            &missing,
            "{\"id\":\"req-7\",\"method\":\"agent.list\"}",
            &mut out,
        )
        .expect("error path should not itself fail");
        let written = String::from_utf8(out).expect("utf8");

        let value: serde_json::Value =
            serde_json::from_str(written.trim()).expect("emitted valid JSON");
        assert_eq!(
            value["id"], "req-7",
            "the error was not correlated to the request id"
        );
        assert_eq!(
            value["error"]["code"], "transport_error",
            "wrong error code"
        );
    }

    /// The emitted error id must be a STRING (ErrorResponse.id is String). A
    /// numeric id or an unparseable request falls back to "" — never null or a
    /// number, which a typed client decoder would reject.
    #[test]
    fn transport_error_id_is_always_a_string() {
        let missing = std::env::temp_dir().join(format!(
            "herdr-apibridge-idcheck-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);

        let mut out = Vec::<u8>::new();
        forward_api_request(&missing, "{\"id\":7,\"method\":\"x\"}", &mut out).expect("no fail");
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
        assert!(
            v["id"].is_string(),
            "a numeric request id produced a non-string id"
        );
        assert_eq!(
            v["id"], "",
            "a numeric request id was not normalised to empty string"
        );

        let mut out2 = Vec::<u8>::new();
        forward_api_request(&missing, "not json at all", &mut out2).expect("no fail");
        let v2: serde_json::Value =
            serde_json::from_str(String::from_utf8(out2).unwrap().trim()).unwrap();
        assert!(
            v2["id"].is_string(),
            "an unparseable request produced a non-string id"
        );
        assert_eq!(
            v2["id"], "",
            "an unparseable request did not fall back to empty string id"
        );
    }

    /// The teardown watcher fires on OUTPUT hangup and not before. Closing the
    /// output fd's read peer (the client's read side gone) shuts the API
    /// connection; while the output stays open (a round-trip client half-closing
    /// stdin, output still connected) it does NOT fire, so the reply is not torn
    /// out — the distinction the stdin-EOF approach could not make.
    #[test]
    fn output_hangup_tears_down_api_connection_but_open_output_does_not() {
        let (a, mut b) = UnixStream::pair().expect("pair");
        // KEEP A SECOND HANDLE TO THE SAME SOCKET ALIVE through the final
        // assertion. Without it the watcher owns the only `a` fd, so its return
        // drops the socket and `b` gets EOF from that drop alone — the reviewer
        // showed deleting the production shutdown() then left this test green.
        // With `a_keep` open, the socket is not closed by the watcher returning,
        // so `b`'s EOF can only come from shutdown() propagating across the live
        // connection.
        let a_keep = a.try_clone().expect("clone a");
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let (read_fd, write_fd) = (fds[0], fds[1]);

        let handle = thread::spawn(move || wait_for_output_hangup_then_shutdown(write_fd, a));

        // Output still open: the watcher must NOT have torn down the connection,
        // so a read on `b` times out rather than returning EOF.
        b.set_read_timeout(Some(std::time::Duration::from_millis(150)))
            .unwrap();
        let mut buf = [0u8; 1];
        assert!(
            b.read(&mut buf).is_err(),
            "connection was torn down while output was still open (would break round-trips)"
        );

        // Client's read side goes away: the write fd hangs up, the watcher fires.
        assert_eq!(unsafe { libc::close(read_fd) }, 0, "close read_fd");
        b.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        assert_eq!(
            b.read(&mut buf).expect("read after teardown"),
            0,
            "the API connection was not shut down on output hangup"
        );

        // Held open until AFTER the EOF assertion so that EOF proves shutdown,
        // not a drop.
        drop(a_keep);
        let _ = handle.join();
        unsafe { libc::close(write_fd) };
    }

    /// The base64 request argument decodes back to the exact JSON line, and
    /// invalid base64 is a clean error rather than a forwarded-garbage request.
    #[test]
    fn request_arg_decodes_base64_and_rejects_garbage() {
        use base64::Engine as _;
        let request = "{\"id\":\"7\",\"method\":\"agent.list\",\"params\":{}}";
        let encoded = base64::engine::general_purpose::STANDARD.encode(request);
        assert_eq!(decode_request_arg(&encoded).expect("decode"), request);
        // trailing newline in the encoded payload is trimmed, matching stdin.
        let with_nl = base64::engine::general_purpose::STANDARD.encode("{\"id\":\"7\"}\n");
        assert_eq!(
            decode_request_arg(&with_nl).expect("decode"),
            "{\"id\":\"7\"}"
        );
        // Invalid base64 -> InvalidInput, exactly.
        let bad_b64 =
            decode_request_arg("not valid base64 !!!").expect_err("garbage base64 accepted");
        assert_eq!(
            bad_b64.kind(),
            io::ErrorKind::InvalidInput,
            "wrong kind for invalid base64"
        );

        // Valid base64 of invalid UTF-8 (0xFF) -> InvalidData, exactly, never a
        // lossy-decoded request. base64([0xff]) is "/w==".
        let bad_utf8 = decode_request_arg("/w==").expect_err("invalid UTF-8 accepted");
        assert_eq!(
            bad_utf8.kind(),
            io::ErrorKind::InvalidData,
            "wrong kind for invalid UTF-8"
        );
    }
}
