//! `herdr api-bridge`: the HerdrUp app's request entrypoint over SSH exec
//! channels.
//!
//! * `api-bridge [<base64(request)>]` forwards one request per process.
//! * `api-bridge --multi` stays up for a whole app session and forwards every
//!   newline-delimited request it reads on stdin, so a request costs one local
//!   socket connection instead of a process start and an SSH channel (#294).

use std::collections::HashMap;
use std::io::{self, BufRead, Read as _, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{mpsc, Mutex, MutexGuard, PoisonError};

/// Requests one `--multi` bridge forwards at once. Each holds a worker thread
/// and a local socket connection; with every worker busy the bridge stops
/// reading stdin, so a burst back-pressures the SSH channel instead of growing
/// threads or buffers.
const MULTI_MAX_IN_FLIGHT: usize = 16;

/// Longest request line `--multi` accepts, excluding its newline. It matches
/// the server's own initial-request cap, which would refuse anything longer.
/// Longer lines are drained and answered with `invalid_request`.
const MULTI_MAX_REQUEST_LINE_BYTES: usize = 1024 * 1024;

/// Methods that keep their connection open after the first response line.
/// `--multi` gives each request one connection and answers it from that
/// connection alone, so these keep their own SSH channel.
const MULTI_UNSUPPORTED_METHODS: &[&str] = &[
    "events.subscribe",
    "pane.stream",
    "pane.input.stream",
    "gram.upload.stream",
    "server.ssh_agent.register",
];

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
        std::thread::spawn(move || {
            wait_for_output_hangup(output_fd);
            let _ = teardown.shutdown(std::net::Shutdown::Both);
        });
    }

    let mut stdout = io::stdout().lock();
    send_and_stream(conn, &request_line, &mut stdout)
}

/// Returns once `output_fd` loses its peer (or polling it fails).
fn wait_for_output_hangup(output_fd: std::os::fd::RawFd) {
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
            return;
        }
        // Readiness without a hangup (a regular file, or an SSH socketpair
        // carrying stdin data the bridge has not read yet) stays ready, so
        // back off instead of spinning a core until the bridge exits.
        std::thread::sleep(std::time::Duration::from_millis(50));
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
    let output_fd = io::stdout().as_raw_fd();
    std::thread::Builder::new()
        .name("api-bridge-hangup".into())
        .spawn(move || {
            wait_for_output_hangup(output_fd);
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
    live: HashMap<u64, UnixStream>,
}

impl Teardown {
    fn state(&self) -> MutexGuard<'_, TeardownState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tracks `conn` until the guard drops; `Ok(None)` once output is gone.
    fn track(&self, conn: &UnixStream) -> io::Result<Option<TrackedConnection<'_>>> {
        let clone = conn.try_clone()?;
        let mut state = self.state();
        if state.hung_up {
            return Ok(None);
        }
        let key = state.next_key;
        state.next_key += 1;
        state.live.insert(key, clone);
        Ok(Some(TrackedConnection {
            teardown: self,
            key,
        }))
    }

    fn hang_up(&self) {
        let mut state = self.state();
        state.hung_up = true;
        for (_, conn) in state.live.drain() {
            let _ = conn.shutdown(std::net::Shutdown::Both);
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

/// Whole-line writer shared by the reader and every worker. Each line is one
/// locked write, so concurrent responses never interleave.
struct LineOutput<W> {
    out: Mutex<W>,
}

impl<W: Write> LineOutput<W> {
    /// `line` must already end with `\n`.
    fn write_line(&self, line: &[u8], teardown: &Teardown) -> io::Result<()> {
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let result = out.write_all(line).and_then(|()| out.flush());
        drop(out);
        if result.is_err() {
            // Nobody can read further responses: stop in-flight work and
            // let the reader loop wind down.
            teardown.hang_up();
        }
        result
    }

    fn write_error(
        &self,
        id: &str,
        code: &str,
        message: &str,
        teardown: &Teardown,
    ) -> io::Result<()> {
        let mut line = error_envelope(id, code, message);
        line.push('\n');
        self.write_line(line.as_bytes(), teardown)
    }
}

struct MultiJob {
    line: Vec<u8>,
    id: String,
}

/// Forwards newline-delimited requests from `input` to the API socket at
/// `socket_path`, one connection per request, up to [`MULTI_MAX_IN_FLIGHT`] at
/// once, writing every response line to `output` as it arrives. Returns once
/// `input` ends and every in-flight request has finished.
fn run_multi<R: BufRead, W: Write + Send>(
    mut input: R,
    output: W,
    socket_path: &Path,
    teardown: &Teardown,
) -> io::Result<()> {
    let output = LineOutput {
        out: Mutex::new(output),
    };
    let (jobs_tx, jobs_rx) = mpsc::sync_channel::<MultiJob>(0);
    let jobs_rx = Mutex::new(jobs_rx);
    let output_error = Mutex::new(None::<io::Error>);

    let read_result = std::thread::scope(|scope| {
        for _ in 0..MULTI_MAX_IN_FLIGHT {
            scope.spawn(|| loop {
                let job = jobs_rx
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .recv();
                let Ok(job) = job else { return };
                if let Err(err) = forward_request(socket_path, &job, &output, teardown) {
                    output_error
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get_or_insert(err);
                }
            });
        }
        // Moving the sender in means every return path closes the job queue,
        // so the scope's implicit join drains in-flight work, then ends.
        read_requests(&mut input, jobs_tx, &output, teardown)
    });

    let output_error = output_error
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    read_result.and(output_error.map_or(Ok(()), Err))
}

enum InputLine {
    Eof,
    Line,
    TooLong,
}

fn read_requests<R: BufRead, W: Write>(
    input: &mut R,
    jobs: mpsc::SyncSender<MultiJob>,
    output: &LineOutput<W>,
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
                output.write_error(
                    &probe.id.unwrap_or_default(),
                    "invalid_request",
                    &format!(
                        "api-bridge: request line exceeds {MULTI_MAX_REQUEST_LINE_BYTES} bytes"
                    ),
                    teardown,
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
                output.write_error(
                    &id,
                    "invalid_request",
                    "api-bridge: request has no method",
                    teardown,
                )?;
                continue;
            }
            (Some(err), _) => {
                output.write_error(
                    &id,
                    "invalid_request",
                    &format!("api-bridge: malformed request line: {err}"),
                    teardown,
                )?;
                continue;
            }
        };
        if MULTI_UNSUPPORTED_METHODS.contains(&method.as_str()) {
            output.write_error(
                &id,
                "unsupported_method",
                &format!(
                    "api-bridge --multi does not forward streaming method {method}; open a dedicated channel for it"
                ),
                teardown,
            )?;
            continue;
        }

        let job = MultiJob {
            line: std::mem::take(&mut line),
            id,
        };
        if jobs.send(job).is_err() {
            // Every worker is gone (only possible if they all panicked).
            return Err(io::Error::other("api-bridge: request workers stopped"));
        }
    }
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
/// failure is returned; socket failures become a `transport_error` response.
fn forward_request<W: Write>(
    socket_path: &Path,
    job: &MultiJob,
    output: &LineOutput<W>,
    teardown: &Teardown,
) -> io::Result<()> {
    let transport_error = |err: io::Error| {
        let mut line = transport_error_envelope(&job.id, &err);
        line.push('\n');
        output.write_line(line.as_bytes(), teardown)
    };

    let mut conn = match UnixStream::connect(socket_path) {
        Ok(conn) => conn,
        Err(err) => return transport_error(err),
    };
    let _tracked = match teardown.track(&conn) {
        Ok(Some(tracked)) => tracked,
        // Output is already gone; nobody would read the response.
        Ok(None) => return Ok(()),
        Err(err) => return transport_error(err),
    };
    if let Err(err) = conn
        .write_all(&job.line)
        .and_then(|()| conn.write_all(b"\n"))
        .and_then(|()| conn.flush())
    {
        return transport_error(err);
    }

    let mut reader = io::BufReader::new(conn);
    let mut reply = Vec::new();
    loop {
        reply.clear();
        match reader.read_until(b'\n', &mut reply) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                if reply.last() == Some(&b'\n') {
                    reply.pop();
                }
                if reply.last() == Some(&b'\r') {
                    reply.pop();
                }
                reply.push(b'\n');
                output.write_line(&reply, teardown)?;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return transport_error(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::collections::HashSet;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn unique_socket_path(name: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        PathBuf::from(format!(
            "/tmp/hab-{name}-{}-{}.sock",
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

    /// Emulates the herdr API socket: one request per connection, one response
    /// line, then close. `params.delay_ms` delays the reply.
    struct FakeApiServer {
        path: PathBuf,
        stats: Arc<ServerStats>,
    }

    impl FakeApiServer {
        fn start(name: &str) -> Self {
            let path = unique_socket_path(name);
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
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

    fn serve_one(conn: UnixStream, stats: &ServerStats) {
        let active = stats.active.fetch_add(1, Ordering::SeqCst) + 1;
        stats.max_active.fetch_max(active, Ordering::SeqCst);
        stats.requests.fetch_add(1, Ordering::SeqCst);
        let Ok(read_half) = conn.try_clone() else {
            return;
        };
        let mut line = String::new();
        if io::BufReader::new(read_half).read_line(&mut line).is_err() {
            return;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            return;
        };
        if let Some(delay) = request["params"]["delay_ms"].as_u64() {
            thread::sleep(Duration::from_millis(delay));
        }
        let response = json!({
            "id": request["id"],
            "result": {"method": request["method"]},
        });
        let mut conn = conn;
        let _ = writeln!(conn, "{response}");
        stats.active.fetch_sub(1, Ordering::SeqCst);
        // Dropping both halves closes the connection: one request each.
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
}
