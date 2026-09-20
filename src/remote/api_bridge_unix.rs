use std::io::{self, BufRead as _, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;

pub(crate) fn run_api_client_bridge(args: &[String]) -> io::Result<()> {
    let encoded_request = match args {
        [] => None,
        [encoded] => Some(encoded.as_str()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "api-bridge accepts at most one encoded request",
            ));
        }
    };
    let request_line = match encoded_request {
        Some(encoded) => decode_request_arg(encoded)?,
        None => {
            let mut line = String::new();
            if io::stdin().lock().read_line(&mut line)? == 0 {
                return Ok(());
            }
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
    };
    if request_line.trim().is_empty() {
        return Ok(());
    }

    let socket_path = crate::api::socket_path();
    let conn = match UnixStream::connect(&socket_path) {
        Ok(conn) => conn,
        Err(err) => {
            let mut stdout = io::stdout().lock();
            return emit_transport_error(&mut stdout, &request_line, &err);
        }
    };

    // A round-trip client closes the SSH channel after reading its response, not
    // before. Wake subscriptions and other long-lived reads when stdout loses
    // its peer without treating stdin's normal half-close as cancellation.
    if let Ok(teardown) = conn.try_clone() {
        let output_fd = io::stdout().as_raw_fd();
        std::thread::spawn(move || wait_for_output_hangup_then_shutdown(output_fd, teardown));
    }

    let mut stdout = io::stdout().lock();
    send_and_stream(conn, &request_line, &mut stdout)
}

fn wait_for_output_hangup_then_shutdown(output_fd: std::os::fd::RawFd, teardown: UnixStream) {
    let mut poll_fd = libc::pollfd {
        fd: output_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        poll_fd.revents = 0;
        let result = unsafe { libc::poll(&mut poll_fd, 1, -1) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if poll_fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            let _ = teardown.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
}

fn decode_request_arg(encoded: &str) -> io::Result<String> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let request =
        String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    Ok(request.trim_end_matches(['\r', '\n']).to_owned())
}

fn send_and_stream<W: Write>(
    mut conn: UnixStream,
    request_line: &str,
    out: &mut W,
) -> io::Result<()> {
    if let Err(err) = conn
        .write_all(request_line.as_bytes())
        .and_then(|()| conn.write_all(b"\n"))
        .and_then(|()| conn.flush())
    {
        return emit_transport_error(out, request_line, &err);
    }

    for reply in io::BufReader::new(conn).lines() {
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
