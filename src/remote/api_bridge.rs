//! `herdr api-bridge`: the HerdrUp app's request entrypoint over SSH exec
//! channels.
//!
//! * `api-bridge [<base64(request)>]` forwards one request per process.
//! * `api-bridge --multi` stays up for a whole app session and forwards every
//!   newline-delimited request it reads on stdin, so a request costs one local
//!   socket connection instead of a process start and an SSH channel (#294).
//!
//! Everything here is shared by Unix and Windows. The platform module
//! (`api_bridge_unix` or `api_bridge_windows`) supplies the API connection,
//! a [`ConnectionShutdown`] that ends a connection's reads from another
//! thread, and the wait for stdout's peer (the SSH channel) to go away.

use std::collections::HashMap;
use std::io::{self, BufRead, Read as _, Write};
use std::path::Path;
use std::sync::{mpsc, Mutex, MutexGuard, PoisonError};

#[cfg(unix)]
use super::api_bridge_unix as transport;
#[cfg(windows)]
use super::api_bridge_windows as transport;
use transport::{Connection, ConnectionShutdown};

use super::api_bridge_outbox::{Delivery, Outbox, RequestKey, Session};
use crate::remote::{
    API_BRIDGE_FRAME_BYTES as FRAME_BYTES, API_BRIDGE_MULTI_MAX_IN_FLIGHT as MULTI_MAX_IN_FLIGHT,
    API_BRIDGE_MULTI_MAX_REQUEST_LINE_BYTES as MULTI_MAX_REQUEST_LINE_BYTES,
    API_BRIDGE_MULTI_STREAMING_METHODS as MULTI_UNSUPPORTED_METHODS,
};

pub(crate) fn run_api_client_bridge(args: &[String]) -> io::Result<()> {
    let encoded_request = match args {
        [] => None,
        [flag] if flag == "--multi" => return run_multi_bridge(),
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

    // Not held locked: the Windows hangup probe takes the stdout lock between
    // lines.
    forward_single_request(
        &request_line,
        &crate::api::socket_path(),
        &mut io::stdout(),
        true,
    )
}

/// Forwards a single-shot request and streams every reply line to `out`.
/// With `watch_output`, losing stdout's peer ends the connection.
fn forward_single_request<W: Write>(
    request_line: &str,
    socket_path: &Path,
    out: &mut W,
    watch_output: bool,
) -> io::Result<()> {
    if let Some(reply) = single_request_error(request_line) {
        writeln!(out, "{reply}")?;
        return out.flush();
    }
    let conn = match transport::connect(socket_path) {
        Ok(conn) => conn,
        Err(err) => return emit_transport_error(out, request_line, &err),
    };

    // A round-trip client closes the SSH channel after reading its response, not
    // before. Wake subscriptions and other long-lived reads when stdout loses
    // its peer without treating stdin's normal half-close as cancellation.
    if watch_output {
        if let Ok(shutdown) = ConnectionShutdown::new(&conn) {
            std::thread::spawn(move || {
                transport::wait_for_output_hangup();
                shutdown.shut_down();
            });
        }
    }

    send_and_stream(conn, request_line, out)
}

/// The `invalid_request` reply for a single-shot request that is not one line
/// within the `--multi` line limit. The API server reads only a connection's
/// first line, so anything after an embedded newline would never be read, and
/// writing it could block the bridge on a full socket or pipe.
fn single_request_error(request_line: &str) -> Option<String> {
    let message = if request_line.len() > MULTI_MAX_REQUEST_LINE_BYTES {
        format!("api-bridge: request line exceeds {MULTI_MAX_REQUEST_LINE_BYTES} bytes")
    } else if request_line.contains('\n') {
        "api-bridge: request must be a single line".to_owned()
    } else {
        return None;
    };
    let id = RequestProbe::scan(request_line.as_bytes())
        .id
        .unwrap_or_default();
    Some(error_envelope(&id, "invalid_request", &message))
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
    mut conn: Connection,
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
    writeln!(out, "{}", transport_error_envelope(&id, err))?;
    out.flush()
}

fn transport_error_envelope(id: &str, err: &io::Error) -> String {
    error_envelope(id, "transport_error", &format!("api-bridge: {err}"))
}

fn error_envelope(id: &str, code: &str, message: &str) -> String {
    serde_json::json!({
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
    .to_string()
}

fn run_multi_bridge() -> io::Result<()> {
    let teardown = std::sync::Arc::new(Teardown::default());
    // Same contract as the single-shot bridge: when the app's channel goes
    // away, wake every in-flight read (an `agent.wait` could otherwise hold
    // the process open long after nobody is listening). The watcher stays
    // detached because the hangup may never come.
    let watcher = std::sync::Arc::clone(&teardown);
    std::thread::Builder::new()
        .name("api-bridge-hangup".into())
        .spawn(move || {
            transport::wait_for_output_hangup();
            watcher.hang_up();
        })?;
    run_multi(
        io::stdin().lock(),
        io::stdout(),
        &crate::api::socket_path(),
        &teardown,
    )
}

/// Live `--multi` connections, so a lost output peer can shut them all down.
#[derive(Default)]
struct Teardown {
    state: Mutex<TeardownState>,
}

#[derive(Default)]
struct TeardownState {
    hung_up: bool,
    next_key: u64,
    live: HashMap<u64, ConnectionShutdown>,
}

impl Teardown {
    fn state(&self) -> MutexGuard<'_, TeardownState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tracks `conn` until the guard drops; `Ok(None)` once output is gone.
    fn track(&self, conn: &Connection) -> io::Result<Option<TrackedConnection<'_>>> {
        let shutdown = ConnectionShutdown::new(conn)?;
        let mut state = self.state();
        if state.hung_up {
            return Ok(None);
        }
        let key = state.next_key;
        state.next_key += 1;
        state.live.insert(key, shutdown);
        Ok(Some(TrackedConnection {
            teardown: self,
            key,
        }))
    }

    fn hang_up(&self) {
        let mut state = self.state();
        state.hung_up = true;
        for (_, shutdown) in state.live.drain() {
            shutdown.shut_down();
        }
    }

    fn is_hung_up(&self) -> bool {
        self.state().hung_up
    }
}

struct TrackedConnection<'a> {
    teardown: &'a Teardown,
    key: u64,
}

impl Drop for TrackedConnection<'_> {
    fn drop(&mut self) {
        self.teardown.state().live.remove(&self.key);
    }
}

/// Request methods the `--multi` bridge answers itself instead of forwarding.
/// An older bridge forwards them, and the server answers `invalid_request`,
/// which tells the client the bridge lacks them.
const BRIDGE_HELLO: &str = "bridge.hello";
const BRIDGE_CANCEL: &str = "bridge.cancel";

struct MultiJob {
    line: Vec<u8>,
    id: String,
    /// Registered before the job is handed to a worker, so a `bridge.cancel`
    /// read right after the request finds it.
    key: RequestKey,
}

/// Forwards newline-delimited requests from `input` to the API socket at
/// `socket_path`, one connection per request, up to [`MULTI_MAX_IN_FLIGHT`] at
/// once, writing every response to `output` as it arrives (whole lines, or
/// interleaved frames once the client sent `bridge.hello`). Returns once
/// `input` ends and every in-flight request has finished.
fn run_multi<R: BufRead, W: Write + Send>(
    mut input: R,
    output: W,
    socket_path: &Path,
    teardown: &Teardown,
) -> io::Result<()> {
    let outbox = Outbox::default();
    let (jobs_tx, jobs_rx) = mpsc::sync_channel::<MultiJob>(0);
    let jobs_rx = Mutex::new(jobs_rx);
    let output_error = Mutex::new(None::<io::Error>);

    let (read_result, write_result) = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            let result = outbox.run_writer(output);
            if result.is_err() {
                // Nobody can read further responses: stop in-flight work and
                // let the reader loop wind down.
                teardown.hang_up();
            }
            result
        });
        let read_result = std::thread::scope(|workers| {
            for _ in 0..MULTI_MAX_IN_FLIGHT {
                workers.spawn(|| loop {
                    let job = jobs_rx
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .recv();
                    let Ok(job) = job else { return };
                    if let Err(err) = forward_request(socket_path, &job, &outbox, teardown) {
                        output_error
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get_or_insert(err);
                    }
                });
            }
            // Moving the sender in means every return path closes the job
            // queue, so the scope's implicit join drains in-flight work.
            read_requests(&mut input, jobs_tx, &outbox, teardown)
        });
        // Every producer is done: let the writer drain and return.
        outbox.close();
        let write_result = writer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("api-bridge: reply writer panicked")));
        (read_result, write_result)
    });

    let output_error = output_error
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    read_result
        .and(write_result)
        .and(output_error.map_or(Ok(()), Err))
}

fn send_error(outbox: &Outbox, id: &str, code: &str, message: &str) -> io::Result<()> {
    outbox
        .send(None, id, error_envelope(id, code, message).into_bytes())
        .map(drop)
}

enum InputLine {
    Eof,
    Line,
    TooLong,
}

fn read_requests<R: BufRead>(
    input: &mut R,
    jobs: mpsc::SyncSender<MultiJob>,
    outbox: &Outbox,
    teardown: &Teardown,
) -> io::Result<()> {
    let mut line = Vec::new();
    loop {
        if teardown.is_hung_up() {
            return Ok(());
        }
        match read_bounded_line(input, &mut line)? {
            InputLine::Eof => return Ok(()),
            InputLine::TooLong => {
                let probe = RequestProbe::scan(&line);
                send_error(
                    outbox,
                    &probe.id.unwrap_or_default(),
                    "invalid_request",
                    &format!(
                        "api-bridge: request line exceeds {MULTI_MAX_REQUEST_LINE_BYTES} bytes"
                    ),
                )?;
                continue;
            }
            InputLine::Line => {}
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let probe = RequestProbe::scan(&line);
        let id = probe.id.unwrap_or_default();
        let method = match (probe.error, probe.method) {
            (None, Some(method)) => method,
            (None, None) => {
                send_error(
                    outbox,
                    &id,
                    "invalid_request",
                    "api-bridge: request has no method",
                )?;
                continue;
            }
            (Some(err), _) => {
                send_error(
                    outbox,
                    &id,
                    "invalid_request",
                    &format!("api-bridge: malformed request line: {err}"),
                )?;
                continue;
            }
        };
        if MULTI_UNSUPPORTED_METHODS.contains(&method.as_str()) {
            send_error(
                outbox,
                &id,
                "unsupported_method",
                &format!(
                    "api-bridge --multi does not forward streaming method {method}; open a dedicated channel for it"
                ),
            )?;
            continue;
        }
        match method.as_str() {
            BRIDGE_HELLO => {
                answer_hello(&line, &id, outbox)?;
                continue;
            }
            BRIDGE_CANCEL => {
                answer_cancel(&line, &id, outbox)?;
                continue;
            }
            _ => {}
        }

        let key = outbox.begin(&id);
        let job = MultiJob {
            line: std::mem::take(&mut line),
            id,
            key,
        };
        if jobs.send(job).is_err() {
            outbox.end(key);
            // Every worker is gone (only possible if they all panicked).
            return Err(io::Error::other("api-bridge: request workers stopped"));
        }
    }
}

fn request_params(line: &[u8]) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(line)
        .ok()
        .and_then(|mut request| request.get_mut("params").map(serde_json::Value::take))
        .unwrap_or(serde_json::Value::Null)
}

/// `bridge.hello {frames, compress}`: with `frames: true`, every reply written
/// after this one is framed and interleaved; with `compress: "gzip"` as well,
/// large replies are gzipped. Compression needs frames (a gzipped reply is
/// binary, so it cannot be a line). Neither can be turned off again.
fn answer_hello(line: &[u8], id: &str, outbox: &Outbox) -> io::Result<()> {
    let params = request_params(line);
    let frames = params.get("frames").and_then(serde_json::Value::as_bool) == Some(true);
    let gzip = params.get("compress").and_then(serde_json::Value::as_str) == Some("gzip");
    let current = outbox.session();
    let wanted = Session {
        frames: current.frames || frames,
        gzip: current.gzip || (gzip && (current.frames || frames)),
    };
    let reply = |session: Session| {
        serde_json::json!({
            "id": id,
            "result": {
                "type": "bridge_hello",
                "frames": session.frames,
                "frame_bytes": FRAME_BYTES,
                "cancel": true,
                "compress": session.gzip.then_some("gzip"),
            }
        })
        .to_string()
        .into_bytes()
    };
    if wanted == current {
        outbox.send(None, id, reply(current))
    } else {
        outbox.send_switch(id, reply(wanted), wanted)
    }
    .map(drop)
}

/// `bridge.cancel {id}`: stops every unanswered request with that id. Each
/// stopped request is answered with a `cancelled` error.
fn answer_cancel(line: &[u8], id: &str, outbox: &Outbox) -> io::Result<()> {
    let params = request_params(line);
    let Some(target) = params.get("id").and_then(serde_json::Value::as_str) else {
        return send_error(
            outbox,
            id,
            "invalid_request",
            "api-bridge: bridge.cancel needs params.id, the id of the request to cancel",
        );
    };
    let cancelled = outbox.cancel(target);
    let reply = serde_json::json!({
        "id": id,
        "result": { "type": "bridge_cancel", "cancelled": cancelled }
    });
    outbox
        .send(None, id, reply.to_string().into_bytes())
        .map(drop)
}

/// Reads one request line into `line` without its terminator. A line longer
/// than [`MULTI_MAX_REQUEST_LINE_BYTES`] is consumed through its newline,
/// leaving only its first bytes in `line` (enough to recover a leading `id`).
fn read_bounded_line<R: BufRead>(input: &mut R, line: &mut Vec<u8>) -> io::Result<InputLine> {
    line.clear();
    let limit = MULTI_MAX_REQUEST_LINE_BYTES as u64 + 1;
    if input.by_ref().take(limit).read_until(b'\n', line)? == 0 {
        return Ok(InputLine::Eof);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        return Ok(InputLine::Line);
    }
    if line.len() <= MULTI_MAX_REQUEST_LINE_BYTES {
        // Final line without a trailing newline.
        return Ok(InputLine::Line);
    }
    input.skip_until(b'\n')?;
    Ok(InputLine::TooLong)
}

/// Pulls `id` and `method` out of a request line without building a JSON tree
/// for its params (a `gram.upload_chunk` line can be a megabyte of base64).
/// Fields seen before a syntax error or truncation are still reported, except
/// a repeated `id`, which is ambiguous and reported as none (as the server
/// does).
#[derive(Default)]
struct RequestProbe {
    id: Option<String>,
    method: Option<String>,
    /// Why the line is not exactly one JSON object with string `id`/`method`.
    error: Option<serde_json::Error>,
}

impl RequestProbe {
    fn scan(line: &[u8]) -> Self {
        let mut probe = Self::default();
        let mut de = serde_json::Deserializer::from_slice(line);
        let result =
            serde::Deserializer::deserialize_map(&mut de, &mut probe).and_then(|()| de.end());
        probe.error = result.err();
        probe
    }
}

impl<'de> serde::de::Visitor<'de> for &mut RequestProbe {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON request object")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        use serde::de::Error as _;

        let (mut seen_id, mut seen_method) = (false, false);
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            match &*key {
                "id" if seen_id => {
                    self.id = None;
                    return Err(A::Error::duplicate_field("id"));
                }
                "id" => {
                    seen_id = true;
                    self.id = map.next_value::<Option<String>>()?;
                }
                "method" if seen_method => return Err(A::Error::duplicate_field("method")),
                "method" => {
                    seen_method = true;
                    self.method = map.next_value::<Option<String>>()?;
                }
                _ => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

/// Runs one `--multi` request on its own socket connection. Only an output
/// failure is returned; socket failures become a `transport_error` response
/// and a `bridge.cancel` a `cancelled` one.
fn forward_request(
    socket_path: &Path,
    job: &MultiJob,
    outbox: &Outbox,
    teardown: &Teardown,
) -> io::Result<()> {
    let key = job.key;
    let result = forward_tracked_request(socket_path, job, key, outbox, teardown).and_then(|()| {
        if outbox.is_cancelled(key) {
            // Not tied to `key`, which refuses replies once cancelled.
            send_error(
                outbox,
                &job.id,
                "cancelled",
                "api-bridge: request cancelled by bridge.cancel",
            )
        } else {
            Ok(())
        }
    });
    outbox.end(key);
    result
}

fn forward_tracked_request(
    socket_path: &Path,
    job: &MultiJob,
    key: RequestKey,
    outbox: &Outbox,
    teardown: &Teardown,
) -> io::Result<()> {
    let reply = |line: Vec<u8>| outbox.send(Some(key), &job.id, line);
    let transport_error = |err: io::Error| {
        if outbox.is_cancelled(key) {
            // The cancel ended the connection; that is not a transport fault.
            return Ok(());
        }
        reply(transport_error_envelope(&job.id, &err).into_bytes()).map(drop)
    };

    let mut conn = match transport::connect(socket_path) {
        Ok(conn) => conn,
        Err(err) => return transport_error(err),
    };
    let _tracked = match teardown.track(&conn) {
        Ok(Some(tracked)) => tracked,
        // Output is already gone; nobody would read the response.
        Ok(None) => return Ok(()),
        Err(err) => return transport_error(err),
    };
    match ConnectionShutdown::new(&conn) {
        Ok(shutdown) => {
            if !outbox.on_cancel(key, Box::new(move || shutdown.shut_down())) {
                return Ok(());
            }
        }
        Err(err) => return transport_error(err),
    }
    if let Err(err) = conn
        .write_all(&job.line)
        .and_then(|()| conn.write_all(b"\n"))
        .and_then(|()| conn.flush())
    {
        return transport_error(err);
    }

    let mut reader = io::BufReader::new(conn);
    loop {
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if reply(line)? == Delivery::Cancelled {
                    return Ok(());
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return transport_error(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::API_BRIDGE_COMPRESS_MIN_BYTES;
    use interprocess::local_socket::traits::ListenerExt as _;
    use serde_json::{json, Value};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn unique_socket_path(name: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        // A short directory on Unix keeps the socket path under `sun_path`'s
        // limit; on Windows the path only names the pipe and its marker file.
        #[cfg(unix)]
        let dir = PathBuf::from("/tmp");
        #[cfg(windows)]
        let dir = std::env::temp_dir();
        dir.join(format!(
            "hab-{name}-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[derive(Default)]
    struct ServerStats {
        requests: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    /// Emulates the herdr API endpoint: one request per connection, one
    /// response line, then close. `params.delay_ms` delays the reply.
    struct FakeApiServer {
        path: PathBuf,
        stats: Arc<ServerStats>,
    }

    impl FakeApiServer {
        fn start(name: &str) -> Self {
            let path = unique_socket_path(name);
            let _ = std::fs::remove_file(&path);
            let listener = crate::ipc::bind_local_listener(&path).unwrap();
            let stats = Arc::new(ServerStats::default());
            let accept_stats = Arc::clone(&stats);
            thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(conn) = conn else { return };
                    let stats = Arc::clone(&accept_stats);
                    thread::spawn(move || serve_one(conn, &stats));
                }
            });
            Self { path, stats }
        }
    }

    impl Drop for FakeApiServer {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn serve_one(conn: crate::ipc::LocalStream, stats: &ServerStats) {
        let active = stats.active.fetch_add(1, Ordering::SeqCst) + 1;
        stats.max_active.fetch_max(active, Ordering::SeqCst);
        stats.requests.fetch_add(1, Ordering::SeqCst);
        let mut reader = io::BufReader::new(conn);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            return;
        };
        if let Some(delay) = request["params"]["delay_ms"].as_u64() {
            thread::sleep(Duration::from_millis(delay));
        }
        let mut result = json!({"method": request["method"]});
        if let Some(pad) = request["params"]["pad_bytes"].as_u64() {
            result["pad"] = Value::String("x".repeat(pad as usize));
        }
        let response = json!({
            "id": request["id"],
            "result": result,
        });
        let mut conn = reader.into_inner();
        let _ = writeln!(conn, "{response}");
        stats.active.fetch_sub(1, Ordering::SeqCst);
        // Dropping the stream closes the connection: one request each.
    }

    fn request(id: &str, method: &str, delay_ms: u64) -> String {
        json!({"id": id, "method": method, "params": {"delay_ms": delay_ms}}).to_string()
    }

    fn run(input: &str, socket_path: &Path) -> Vec<Value> {
        run_bytes(input.as_bytes().to_vec(), socket_path)
    }

    fn run_bytes(input: Vec<u8>, socket_path: &Path) -> Vec<Value> {
        let mut output = Vec::new();
        run_multi(
            io::Cursor::new(input),
            &mut output,
            socket_path,
            &Teardown::default(),
        )
        .unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn ids(responses: &[Value]) -> Vec<&str> {
        responses
            .iter()
            .map(|response| response["id"].as_str().unwrap())
            .collect()
    }

    fn by_id<'a>(responses: &'a [Value], id: &str) -> &'a Value {
        responses
            .iter()
            .find(|response| response["id"] == id)
            .unwrap_or_else(|| panic!("no response for {id}: {responses:?}"))
    }

    #[test]
    fn multi_answers_every_request_with_bounded_concurrency() {
        let server = FakeApiServer::start("many");
        let input: String = (0..48)
            .map(|n| request(&format!("r{n}"), "ping", 50) + "\n")
            .collect();

        let responses = run(&input, &server.path);

        let got: HashSet<&str> = ids(&responses).into_iter().collect();
        let want: Vec<String> = (0..48).map(|n| format!("r{n}")).collect();
        assert_eq!(responses.len(), 48);
        assert_eq!(got, want.iter().map(String::as_str).collect());
        for response in &responses {
            assert_eq!(response["result"]["method"], "ping");
        }
        let max_active = server.stats.max_active.load(Ordering::SeqCst);
        assert!(
            (2..=MULTI_MAX_IN_FLIGHT).contains(&max_active),
            "max concurrent requests {max_active}"
        );
    }

    #[test]
    fn multi_writes_responses_as_they_complete() {
        let server = FakeApiServer::start("order");
        let input = format!(
            "{}\n{}\n",
            request("slow", "agent.wait", 400),
            request("fast", "ping", 0)
        );

        let responses = run(&input, &server.path);

        assert_eq!(ids(&responses), ["fast", "slow"]);
        assert_eq!(by_id(&responses, "slow")["result"]["method"], "agent.wait");
        assert_eq!(by_id(&responses, "fast")["result"]["method"], "ping");
    }

    #[test]
    fn multi_waits_for_in_flight_requests_after_stdin_closes() {
        let server = FakeApiServer::start("drain");
        // No trailing newline: stdin closes right after the last request.
        let input = request("last", "agent.wait", 300);

        let started = Instant::now();
        let responses = run(&input, &server.path);

        assert!(started.elapsed() >= Duration::from_millis(300));
        assert_eq!(ids(&responses), ["last"]);
    }

    #[test]
    fn multi_rejects_streaming_methods_and_keeps_running() {
        let server = FakeApiServer::start("stream");
        let input: String = [
            request("sub", "events.subscribe", 0),
            request("pane", "pane.stream", 0),
            request("upload", "gram.upload.stream", 0),
            request("input", "pane.input.stream", 0),
            request("agent", "server.ssh_agent.register", 0),
            request("after", "ping", 0),
        ]
        .map(|line| line + "\n")
        .concat();

        let responses = run(&input, &server.path);

        for (id, method) in [
            ("sub", "events.subscribe"),
            ("pane", "pane.stream"),
            ("upload", "gram.upload.stream"),
            ("input", "pane.input.stream"),
            ("agent", "server.ssh_agent.register"),
        ] {
            let error = &by_id(&responses, id)["error"];
            assert_eq!(error["code"], "unsupported_method", "{id}");
            assert!(
                error["message"].as_str().unwrap().contains(method),
                "{error}"
            );
        }
        assert_eq!(by_id(&responses, "after")["result"]["method"], "ping");
        assert_eq!(server.stats.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multi_answers_malformed_lines_and_keeps_running() {
        let server = FakeApiServer::start("malformed");
        let input = [
            "not json".to_owned(),
            r#"{"id":"no-method","params":{}}"#.to_owned(),
            r#"{"id":"broken","method":"ping""#.to_owned(),
            "[1,2]".to_owned(),
            r#"{"id":"numeric","method":7}"#.to_owned(),
            r#"{"id":"a","id":"b","method":"ping"}"#.to_owned(),
            "   ".to_owned(),
            request("after", "ping", 0),
        ]
        .map(|line| line + "\n")
        .concat();

        let responses = run(&input, &server.path);

        assert_eq!(responses.len(), 7, "{responses:?}");
        assert_eq!(
            ids(&responses)[..6],
            ["", "no-method", "broken", "", "numeric", ""]
        );
        for response in &responses[..6] {
            assert_eq!(response["error"]["code"], "invalid_request", "{response}");
        }
        assert_eq!(by_id(&responses, "after")["result"]["method"], "ping");
        assert_eq!(server.stats.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multi_rejects_over_long_lines_and_keeps_running() {
        let server = FakeApiServer::start("long");
        let mut input = format!(
            r#"{{"id":"huge","method":"gram.upload_chunk","params":{{"data":"{}"}}}}"#,
            "A".repeat(MULTI_MAX_REQUEST_LINE_BYTES)
        )
        .into_bytes();
        input.push(b'\n');
        input.extend_from_slice(request("after", "ping", 0).as_bytes());
        input.push(b'\n');

        let responses = run_bytes(input, &server.path);

        assert_eq!(responses.len(), 2, "{responses:?}");
        let error = &by_id(&responses, "huge")["error"];
        assert_eq!(error["code"], "invalid_request");
        assert!(error["message"]
            .as_str()
            .unwrap()
            .contains(&MULTI_MAX_REQUEST_LINE_BYTES.to_string()));
        assert_eq!(by_id(&responses, "after")["result"]["method"], "ping");
        assert_eq!(server.stats.requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multi_accepts_a_line_at_the_length_limit() {
        let server = FakeApiServer::start("limit");
        let prefix = r#"{"id":"edge","method":"ping","params":{"pad":""#;
        let suffix = r#""}}"#;
        let pad = "A".repeat(MULTI_MAX_REQUEST_LINE_BYTES - prefix.len() - suffix.len());
        let input = format!("{prefix}{pad}{suffix}\n");
        assert_eq!(input.len(), MULTI_MAX_REQUEST_LINE_BYTES + 1);

        let responses = run(&input, &server.path);

        assert_eq!(by_id(&responses, "edge")["result"]["method"], "ping");
    }

    #[test]
    fn multi_reports_connect_failures_per_request_and_keeps_running() {
        let missing = unique_socket_path("missing");
        let input = format!(
            "{}\n{}\n",
            request("one", "ping", 0),
            request("two", "ping", 0)
        );

        let responses = run(&input, &missing);

        let mut got = ids(&responses);
        got.sort_unstable();
        assert_eq!(got, ["one", "two"]);
        for response in &responses {
            assert_eq!(response["error"]["code"], "transport_error", "{response}");
            assert!(response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("api-bridge: "));
        }
    }

    #[test]
    fn multi_teardown_wakes_in_flight_requests() {
        let server = FakeApiServer::start("hangup");
        let teardown = Teardown::default();
        let input = request("stuck", "agent.wait", 10_000) + "\n";

        let started = Instant::now();
        thread::scope(|scope| {
            scope.spawn(|| {
                // Hang up once the request is on the wire.
                let deadline = Instant::now() + Duration::from_secs(5);
                while teardown.state().live.is_empty() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(5));
                }
                teardown.hang_up();
            });
            let mut output = Vec::new();
            run_multi(
                io::Cursor::new(input.into_bytes()),
                &mut output,
                &server.path,
                &teardown,
            )
            .unwrap();
        });

        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(teardown.state().live.is_empty());
    }

    #[test]
    fn single_request_streams_the_reply_to_output() {
        let server = FakeApiServer::start("single");
        let conn = transport::connect(&server.path).unwrap();
        let mut output = Vec::new();

        send_and_stream(conn, &request("one", "agent.wait", 50), &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        let lines: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 1, "{output}");
        assert_eq!(lines[0]["id"], "one");
        assert_eq!(lines[0]["result"]["method"], "agent.wait");
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn single_request_reports_connect_failures_as_transport_errors() {
        let missing = unique_socket_path("single-missing");
        let Err(err) = transport::connect(&missing) else {
            panic!("connected to a missing endpoint");
        };
        let mut output = Vec::new();

        emit_transport_error(&mut output, &request("one", "ping", 0), &err).unwrap();

        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["id"], "one");
        assert_eq!(response["error"]["code"], "transport_error");
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("api-bridge: "));
    }

    #[test]
    fn connection_shutdown_ends_a_pending_read() {
        let server = FakeApiServer::start("shutdown");
        let conn = transport::connect(&server.path).unwrap();
        let shutdown = ConnectionShutdown::new(&conn).unwrap();
        let mut output = Vec::new();

        let started = Instant::now();
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(100));
                shutdown.shut_down();
            });
            send_and_stream(conn, &request("stuck", "agent.wait", 10_000), &mut output).unwrap();
        });

        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(output.is_empty(), "{}", String::from_utf8_lossy(&output));
    }

    #[test]
    fn single_request_refuses_more_than_one_line_without_connecting() {
        let server = FakeApiServer::start("single-lines");
        let embedded_newline = format!(
            "{}\n{}",
            request("two", "ping", 0),
            "A".repeat(4 * 1024 * 1024)
        );
        let over_long = format!(
            r#"{{"id":"two","method":"ping","params":{{"data":"{}"}}}}"#,
            "A".repeat(MULTI_MAX_REQUEST_LINE_BYTES)
        );

        for line in [embedded_newline, over_long] {
            let mut output = Vec::new();
            forward_single_request(&line, &server.path, &mut output, false).unwrap();

            let response: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(response["id"], "two");
            assert_eq!(response["error"]["code"], "invalid_request", "{response}");
        }
        assert_eq!(server.stats.requests.load(Ordering::SeqCst), 0);

        let mut output = Vec::new();
        forward_single_request(&request("one", "ping", 0), &server.path, &mut output, false)
            .unwrap();
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["result"]["method"], "ping");
    }

    /// A peer that reads one line and then stops reading must not keep the
    /// rest of a write blocked past a shutdown. On Unix, `shutdown(2)` already
    /// fails the write. On Windows the shutdown cancels it.
    #[test]
    fn shutdown_releases_a_write_the_server_stopped_reading() {
        let path = unique_socket_path("unread");
        let listener = crate::ipc::bind_local_listener(&path).unwrap();
        let (release, released) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let conn = listener.incoming().next().unwrap().unwrap();
            let mut reader = io::BufReader::new(conn);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            // Stop reading, but keep the connection open.
            let _ = released.recv();
        });
        let conn = transport::connect(&path).unwrap();
        let shutdown = ConnectionShutdown::new(&conn).unwrap();
        let request_line = format!(
            "{}\n{}",
            request("one", "ping", 0),
            "A".repeat(16 * 1024 * 1024)
        );
        let mut output = Vec::new();

        let started = Instant::now();
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(200));
                shutdown.shut_down();
            });
            send_and_stream(conn, &request_line, &mut output).unwrap();
        });

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["error"]["code"], "transport_error", "{response}");
        drop(release);
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn request_argument_is_base64_without_its_line_ending() {
        use base64::Engine as _;

        let line = request("arg", "ping", 0);
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{line}\r\n"));
        assert_eq!(decode_request_arg(&encoded).unwrap(), line);
        assert_eq!(
            decode_request_arg("not base64!").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// Feeds a bridge's stdin one chunk at a time; a closed sender is EOF.
    struct ChannelInput {
        chunks: mpsc::Receiver<Vec<u8>>,
        buf: Vec<u8>,
        pos: usize,
    }

    impl io::Read for ChannelInput {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let n = available.len().min(out.len());
            out[..n].copy_from_slice(&available[..n]);
            self.consume(n);
            Ok(n)
        }
    }

    impl BufRead for ChannelInput {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.pos == self.buf.len() {
                self.buf = self.chunks.recv().unwrap_or_default();
                self.pos = 0;
            }
            Ok(&self.buf[self.pos..])
        }

        fn consume(&mut self, n: usize) {
            self.pos += n;
        }
    }

    /// A bridge's stdout as a slow link: each write takes `delay`.
    struct ChannelOutput {
        writes: mpsc::Sender<Vec<u8>>,
        delay: Duration,
    }

    impl Write for ChannelOutput {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            thread::sleep(self.delay);
            let _ = self.writes.send(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A `--multi` bridge on its own thread, written to and read from live.
    struct LiveBridge {
        input: Option<mpsc::Sender<Vec<u8>>>,
        output: mpsc::Receiver<Vec<u8>>,
        pending: Vec<u8>,
        /// Reply bytes of frames read so far, by reply id.
        partial: HashMap<String, Vec<u8>>,
        bridge: Option<thread::JoinHandle<io::Result<()>>>,
    }

    impl LiveBridge {
        fn start(socket_path: &Path, write_delay: Duration) -> Self {
            let (input, chunks) = mpsc::channel();
            let (writes, output) = mpsc::channel();
            let socket_path = socket_path.to_owned();
            let bridge = thread::spawn(move || {
                let input = ChannelInput {
                    chunks,
                    buf: Vec::new(),
                    pos: 0,
                };
                let output = ChannelOutput {
                    writes,
                    delay: write_delay,
                };
                run_multi(input, output, &socket_path, &Teardown::default())
            });
            Self {
                input: Some(input),
                output,
                pending: Vec::new(),
                partial: HashMap::new(),
                bridge: Some(bridge),
            }
        }

        fn send(&self, line: &str) {
            let line = format!("{line}\n").into_bytes();
            self.input.as_ref().unwrap().send(line).unwrap();
        }

        fn read_exact(&mut self, len: usize) -> Vec<u8> {
            while self.pending.len() < len {
                let chunk = self
                    .output
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bridge output");
                self.pending.extend_from_slice(&chunk);
            }
            self.pending.drain(..len).collect()
        }

        fn read_line(&mut self) -> Value {
            loop {
                if let Some(end) = self.pending.iter().position(|&byte| byte == b'\n') {
                    let line: Vec<u8> = self.pending.drain(..=end).collect();
                    return serde_json::from_slice(&line).unwrap();
                }
                let chunk = self
                    .output
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bridge output");
                self.pending.extend_from_slice(&chunk);
            }
        }

        fn read_frame(&mut self) -> (Value, Vec<u8>) {
            let header = self.read_line();
            let len = header["len"].as_u64().expect("frame header") as usize;
            let body = self.read_exact(len);
            (header, body)
        }

        /// Reads one frame and keeps its bytes toward its reply.
        fn read_frame_kept(&mut self) -> Value {
            let (header, body) = self.read_frame();
            let id = header["frame"].as_str().unwrap().to_owned();
            self.partial.entry(id).or_default().extend_from_slice(&body);
            header
        }

        /// Reads frames until `count` replies are complete, in completion
        /// order. An aborted reply is `None`.
        fn read_replies(&mut self, count: usize) -> Vec<(String, Option<Value>)> {
            let mut done = Vec::new();
            while done.len() < count {
                let header = self.read_frame_kept();
                let id = header["frame"].as_str().unwrap().to_owned();
                if header["last"] != true {
                    continue;
                }
                let bytes = self.partial.remove(&id).unwrap();
                if header["abort"] == true {
                    done.push((id, None));
                } else {
                    done.push((id, Some(serde_json::from_slice(&bytes).unwrap())));
                }
            }
            done
        }

        fn finish(mut self) {
            drop(self.input.take());
            self.bridge.take().unwrap().join().unwrap().unwrap();
        }
    }

    fn hello(id: &str) -> String {
        json!({"id": id, "method": "bridge.hello", "params": {"frames": true}}).to_string()
    }

    fn cancel(id: &str, target: &str) -> String {
        json!({"id": id, "method": "bridge.cancel", "params": {"id": target}}).to_string()
    }

    fn padded(id: &str, pad_bytes: usize) -> String {
        json!({"id": id, "method": "gram.list", "params": {"pad_bytes": pad_bytes}}).to_string()
    }

    fn reply<'a>(replies: &'a [(String, Option<Value>)], id: &str) -> &'a Option<Value> {
        &replies
            .iter()
            .find(|(reply_id, _)| reply_id == id)
            .unwrap_or_else(|| panic!("no reply for {id}: {replies:?}"))
            .1
    }

    #[test]
    fn multi_switches_to_frames_after_answering_hello() {
        let server = FakeApiServer::start("hello");
        let mut bridge = LiveBridge::start(&server.path, Duration::ZERO);

        bridge.send(&request("before", "ping", 0));
        assert_eq!(bridge.read_line()["id"], "before");
        bridge.send(&hello("h"));
        let hello = bridge.read_line();
        assert_eq!(hello["id"], "h");
        assert_eq!(hello["result"]["type"], "bridge_hello");
        assert_eq!(hello["result"]["frames"], true);
        assert_eq!(hello["result"]["frame_bytes"], FRAME_BYTES);
        assert_eq!(hello["result"]["cancel"], true);

        bridge.send(&request("after", "ping", 0));
        let (header, body) = bridge.read_frame();
        assert_eq!(
            header,
            json!({"frame": "after", "len": body.len(), "last": true})
        );
        let reply: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(reply["result"]["method"], "ping");
        bridge.finish();
        // The bridge answered the hello itself.
        assert_eq!(server.stats.requests.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn multi_frames_let_a_small_reply_overtake_a_big_one() {
        let server = FakeApiServer::start("interleave");
        // About 2 ms per frame: the 1 MiB reply needs 64 frames.
        let mut bridge = LiveBridge::start(&server.path, Duration::from_millis(2));
        bridge.send(&hello("h"));
        bridge.read_line();

        bridge.send(&padded("big", 1024 * 1024));
        let first = bridge.read_frame_kept();
        assert_eq!(first["frame"], "big");
        assert_eq!(first["last"], false);
        assert_eq!(first["len"], FRAME_BYTES);
        bridge.send(&request("small", "ping", 0));

        let replies = bridge.read_replies(2);
        let order: Vec<&str> = replies.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(order, ["small", "big"]);
        let big = reply(&replies, "big").as_ref().unwrap();
        assert_eq!(big["result"]["pad"].as_str().unwrap().len(), 1024 * 1024);
        bridge.finish();
    }

    #[test]
    fn multi_frames_reassemble_into_the_reply_line() {
        let server = FakeApiServer::start("reassemble");
        let mut bridge = LiveBridge::start(&server.path, Duration::ZERO);
        bridge.send(&hello("h"));
        bridge.read_line();

        bridge.send(&padded("big", 3 * FRAME_BYTES));
        let replies = bridge.read_replies(1);
        let big = reply(&replies, "big").as_ref().unwrap();
        assert_eq!(big["id"], "big");
        assert_eq!(big["result"]["pad"].as_str().unwrap().len(), 3 * FRAME_BYTES);
        bridge.finish();
    }

    #[test]
    fn multi_cancel_ends_a_request_still_waiting_for_its_reply() {
        let server = FakeApiServer::start("cancel-wait");
        let mut bridge = LiveBridge::start(&server.path, Duration::ZERO);

        let started = Instant::now();
        bridge.send(&request("slow", "agent.wait", 10_000));
        bridge.send(&cancel("c", "slow"));
        let mut replies = vec![bridge.read_line(), bridge.read_line()];
        replies.sort_by_key(|reply| reply["id"].as_str().unwrap().to_owned());

        assert_eq!(replies[0]["id"], "c");
        assert_eq!(
            replies[0]["result"],
            json!({"type": "bridge_cancel", "cancelled": true})
        );
        assert_eq!(replies[1]["id"], "slow");
        assert_eq!(replies[1]["error"]["code"], "cancelled");
        assert!(started.elapsed() < Duration::from_secs(5));

        // The bridge keeps serving, and a cancelled id is free to reuse.
        bridge.send(&request("slow", "ping", 0));
        assert_eq!(bridge.read_line()["result"]["method"], "ping");
        bridge.finish();
    }

    #[test]
    fn multi_cancel_aborts_a_framed_reply_part_way_through() {
        let server = FakeApiServer::start("cancel-frames");
        let mut bridge = LiveBridge::start(&server.path, Duration::from_millis(5));
        bridge.send(&hello("h"));
        bridge.read_line();

        bridge.send(&padded("big", 1024 * 1024));
        let first = bridge.read_frame_kept();
        assert_eq!(first["frame"], "big");
        bridge.send(&cancel("c", "big"));

        let replies = bridge.read_replies(3);
        let order: Vec<&str> = replies.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(*reply(&replies, "c"), Some(json!({
            "id": "c",
            "result": {"type": "bridge_cancel", "cancelled": true},
        })));
        // The partial reply is dropped, then its `cancelled` error follows.
        let big: Vec<&Option<Value>> = replies
            .iter()
            .filter(|(id, _)| id == "big")
            .map(|(_, reply)| reply)
            .collect();
        assert_eq!(big.len(), 2, "{order:?}");
        assert_eq!(*big[0], None);
        assert_eq!(big[1].as_ref().unwrap()["error"]["code"], "cancelled");
        bridge.finish();
    }

    #[test]
    fn multi_cancel_of_an_answered_request_cancels_nothing() {
        let server = FakeApiServer::start("cancel-late");
        let mut bridge = LiveBridge::start(&server.path, Duration::ZERO);

        bridge.send(&request("done", "ping", 0));
        assert_eq!(bridge.read_line()["id"], "done");
        bridge.send(&cancel("c", "done"));
        assert_eq!(
            bridge.read_line(),
            json!({"id": "c", "result": {"type": "bridge_cancel", "cancelled": false}})
        );
        bridge.send(&json!({"id": "bad", "method": "bridge.cancel", "params": {}}).to_string());
        assert_eq!(bridge.read_line()["error"]["code"], "invalid_request");
        bridge.finish();
    }

    fn hello_with(id: &str, params: Value) -> String {
        json!({"id": id, "method": "bridge.hello", "params": params}).to_string()
    }

    /// Reads frames until the reply `id` is complete: its frame headers and
    /// its bytes as sent.
    fn read_framed_reply(bridge: &mut LiveBridge, id: &str) -> (Vec<Value>, Vec<u8>) {
        let mut headers = Vec::new();
        let mut bytes = Vec::new();
        loop {
            let (header, body) = bridge.read_frame();
            if header["frame"] != id {
                continue;
            }
            bytes.extend_from_slice(&body);
            let last = header["last"] == true;
            headers.push(header);
            if last {
                return (headers, bytes);
            }
        }
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Read as _;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn multi_gzip_session_compresses_large_replies_only() {
        let server = FakeApiServer::start("gzip");
        let mut bridge = LiveBridge::start(&server.path, Duration::ZERO);
        bridge.send(&hello_with("h", json!({"frames": true, "compress": "gzip"})));
        let hello = bridge.read_line();
        assert_eq!(hello["result"]["frames"], true);
        assert_eq!(hello["result"]["compress"], "gzip");

        bridge.send(&padded("big", 4 * FRAME_BYTES));
        let (headers, bytes) = read_framed_reply(&mut bridge, "big");
        assert!(headers.iter().all(|header| header["enc"] == "gzip"), "{headers:?}");
        assert!(bytes.len() < FRAME_BYTES, "{} gzip bytes", bytes.len());
        // A bare 10-byte gzip header (no name, comment or extra field), so a
        // client can strip it and the 8-byte trailer and inflate raw deflate.
        assert_eq!(bytes[..4], [0x1f, 0x8b, 0x08, 0x00]);
        let big: Value = serde_json::from_slice(&gunzip(&bytes)).unwrap();
        assert_eq!(big["id"], "big");
        assert_eq!(big["result"]["pad"].as_str().unwrap().len(), 4 * FRAME_BYTES);

        // Under the threshold: plain frame, no `enc`.
        bridge.send(&request("small", "ping", 0));
        let (header, body) = bridge.read_frame();
        assert_eq!(header, json!({"frame": "small", "len": body.len(), "last": true}));
        assert!(body.len() < API_BRIDGE_COMPRESS_MIN_BYTES);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["id"], "small");
        bridge.finish();
    }

    #[test]
    fn multi_later_hello_turns_on_gzip() {
        let server = FakeApiServer::start("gzip-later");
        let mut bridge = LiveBridge::start(&server.path, Duration::ZERO);
        bridge.send(&hello("h1"));
        assert_eq!(bridge.read_line()["result"]["compress"], Value::Null);
        bridge.send(&padded("plain", 2 * FRAME_BYTES));
        let (headers, bytes) = read_framed_reply(&mut bridge, "plain");
        assert!(headers.iter().all(|header| header.get("enc").is_none()));
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["id"], "plain");

        bridge.send(&hello_with("h2", json!({"compress": "gzip"})));
        let (header, body) = bridge.read_frame();
        assert_eq!(header["frame"], "h2");
        let hello: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(hello["result"]["frames"], true);
        assert_eq!(hello["result"]["compress"], "gzip");
        bridge.send(&padded("zipped", 2 * FRAME_BYTES));
        let (headers, bytes) = read_framed_reply(&mut bridge, "zipped");
        assert!(headers.iter().all(|header| header["enc"] == "gzip"));
        assert_eq!(serde_json::from_slice::<Value>(&gunzip(&bytes)).unwrap()["id"], "zipped");
        bridge.finish();
    }

    #[test]
    fn multi_gzip_needs_frames() {
        let server = FakeApiServer::start("gzip-lines");
        let mut bridge = LiveBridge::start(&server.path, Duration::ZERO);
        bridge.send(&hello_with("h", json!({"compress": "gzip"})));
        let hello = bridge.read_line();
        assert_eq!(hello["result"]["frames"], false);
        assert_eq!(hello["result"]["compress"], Value::Null);
        // Still whole plain lines.
        bridge.send(&padded("big", 2 * FRAME_BYTES));
        let big = bridge.read_line();
        assert_eq!(big["id"], "big");
        assert_eq!(big["result"]["pad"].as_str().unwrap().len(), 2 * FRAME_BYTES);
        bridge.finish();
    }
}
