use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;

use crate::api::schema::{
    ErrorResponse, Method, PingParams, Request, ResponseResult, SuccessResponse,
};
use crate::api::ssh_transport;
use crate::api::{ApiStream, ApiStreamRead};

/// Poll granularity for the bounded federation response reader: how long it
/// sleeps between non-blocking read attempts while waiting for more bytes. Short
/// enough that the wall-clock deadline and a `running` shutdown are observed
/// promptly, long enough not to busy-spin.
const BOUNDED_READ_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Credential used for an outbound SSH federation connection.
///
/// v1 supports key-based auth only. [`SshCredential::Password`] is reserved for
/// a future version and is NOT implemented — constructing an SSH transport with
/// it is rejected.
// Constructed by the federation tests and the SSH transport now; CLI wiring that
// builds these from `[federation]` peer config lands in a later part.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshCredential {
    Key,
    Password(String),
}

/// An outbound SSH federation target reached via `herdr api-bridge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    pub host: String,
    pub user: Option<String>,
    pub credential: SshCredential,
}

/// API connection target resolved by clients at the process edge.
///
/// The `Tcp`/`Ssh` federation variants are constructed by tests and the SSH
/// transport now; the CLI surface that builds them from `[federation]` peer
/// config lands in a later part, so they read as unconstructed in a non-test
/// build until then.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionTarget {
    LocalSession(Option<String>),
    SocketPath(PathBuf),
    /// A federation TCP peer. `token`, when set, is sent as the
    /// `federation.hello` line right after connecting, before any request.
    Tcp {
        addr: SocketAddr,
        token: Option<String>,
    },
    /// A federation peer reached over key-based SSH (`herdr api-bridge`).
    Ssh(SshTarget),
}

impl ConnectionTarget {
    /// Local socket path for the socket-backed targets. Only meaningful for
    /// `LocalSession`/`SocketPath`; TCP and SSH targets have no socket path and
    /// return an empty path (they never reach the local-connect path).
    fn socket_path(&self) -> PathBuf {
        match self {
            Self::LocalSession(None) => crate::api::socket_path(),
            Self::LocalSession(Some(name)) => crate::session::api_socket_path_for(Some(name)),
            Self::SocketPath(path) => path.clone(),
            Self::Tcp { .. } | Self::Ssh(_) => PathBuf::new(),
        }
    }
}

/// Reusable client for Herdr's newline-delimited JSON API.
#[derive(Debug, Clone)]
pub struct ApiClient {
    target: ConnectionTarget,
}

impl ApiClient {
    pub fn local() -> Self {
        Self::for_target(ConnectionTarget::LocalSession(None))
    }

    pub fn for_target(target: ConnectionTarget) -> Self {
        Self { target }
    }

    pub fn socket_path(&self) -> PathBuf {
        self.target.socket_path()
    }

    pub fn request(&self, request: Request) -> Result<SuccessResponse, ApiClientError> {
        let value = self.request_value(&request)?;
        parse_response_value(value)
    }

    pub fn request_value(&self, request: &Request) -> Result<serde_json::Value, ApiClientError> {
        // request_value is "the first line of request_stream": one request in,
        // the first NDJSON reply out.
        let mut lines = self.request_stream(request)?;
        match lines.next() {
            Some(Ok(value)) => Ok(value),
            Some(Err(err)) => Err(ApiClientError::Io(err)),
            None => Err(ApiClientError::EmptyResponse),
        }
    }

    /// Send `request` and yield every NDJSON reply line until the peer closes
    /// the connection. A round-trip request yields exactly one line; a streaming
    /// request (`events.subscribe`, `pane.stream`, …) yields many and terminates
    /// when the stream closes.
    ///
    /// Works over every transport: Local/TCP connect then write the request and
    /// read replies off the stream; SSH spawns a per-request `api-bridge` child
    /// with the request embedded and reads replies off its stdout.
    pub fn request_stream(&self, request: &Request) -> io::Result<ResponseLines> {
        match &self.target {
            ConnectionTarget::Ssh(target) => {
                let json = serde_json::to_string(request)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
                let stream = ssh_transport::spawn_request(target, &json)?;
                Ok(ResponseLines::over(stream))
            }
            _ => {
                let mut stream = self.connect()?;
                write_request_line(&mut stream, request)?;
                Ok(ResponseLines::over(stream))
            }
        }
    }

    pub fn request_value_with_timeout(
        &self,
        request: &Request,
        timeout: Duration,
    ) -> Result<serde_json::Value, ApiClientError> {
        if let ConnectionTarget::Ssh(target) = &self.target {
            // The per-request SSH child has no socket-level timeout knob; the
            // ssh client's own ConnectTimeout/ServerAlive settings govern.
            let json = serde_json::to_string(request)?;
            let stream = ssh_transport::spawn_request(target, &json)?;
            let mut lines = ResponseLines::over(stream);
            return match lines.next() {
                Some(Ok(value)) => Ok(value),
                Some(Err(err)) => Err(ApiClientError::Io(err)),
                None => Err(ApiClientError::EmptyResponse),
            };
        }

        let mut stream = self.connect()?;
        set_timeout_best_effort(&mut stream, TimeoutKind::Send, timeout)?;
        set_timeout_best_effort(&mut stream, TimeoutKind::Recv, timeout)?;
        write_request_line(&mut stream, request)?;

        let mut reader = BufReader::new(stream);
        read_json_line(&mut reader)
    }

    /// Send `request` and read the first NDJSON reply line, bounded by BOTH a
    /// byte cap (`max_bytes`) and a wall-clock `total_timeout` deadline, aborting
    /// early if `running` clears.
    ///
    /// Unlike [`Self::request_value_with_timeout`] — whose `SO_RCVTIMEO` only
    /// bounds each individual read, so a peer trickling one byte just under it,
    /// never sending a newline, makes the read run forever while memory climbs —
    /// this method bounds the WHOLE read: it errors the moment the accumulated
    /// line exceeds `max_bytes` (no unbounded allocation / OOM) or the deadline
    /// passes (no unbounded time). This is the federation poll's read path, so a
    /// malicious or faulty peer returning a giant or trickled response degrades
    /// that peer instead of exhausting the polling home daemon. `running` lets an
    /// in-flight read abort promptly on shutdown, so joining the poll threads on
    /// [`ServerHandle`](crate::api::ServerHandle) drop does not hang.
    ///
    /// Covers the TCP and SSH transports (a local socket is never a federation
    /// peer). It deliberately does NOT touch [`Self::request_value`] /
    /// [`Self::request_stream`], so legitimate large *local* `agent.read`
    /// responses keep their uncapped read.
    pub fn request_value_bounded(
        &self,
        request: &Request,
        max_bytes: usize,
        total_timeout: Duration,
        running: Option<&Arc<AtomicBool>>,
    ) -> Result<serde_json::Value, ApiClientError> {
        let deadline = Instant::now() + total_timeout;
        let mut stream = match &self.target {
            ConnectionTarget::Ssh(target) => {
                // The per-request SSH child embeds the request at spawn time, so
                // the reply is read straight off its stdout — no request write.
                let json = serde_json::to_string(request)?;
                ssh_transport::spawn_request(target, &json)?
            }
            _ => {
                let mut stream = self.connect()?;
                write_request_line(&mut stream, request)?;
                stream
            }
        };

        let line = read_bounded_response_line(&mut stream, max_bytes, deadline, running)?;
        if line.trim().is_empty() {
            return Err(ApiClientError::EmptyResponse);
        }
        serde_json::from_str(&line).map_err(ApiClientError::Json)
    }

    /// Two-phase federation proxy: connect + write the request (phase 1), then
    /// bounded-read the single response line (phase 2), returning that line's
    /// content VERBATIM (trimmed of surrounding whitespace) for pass-through to
    /// the originating client.
    ///
    /// Unlike [`Self::request_value_bounded`], the two phases are distinguished in
    /// the error so the caller can tell a request that never reached the peer
    /// ([`ProxyError::Connect`] — connect or request-write failed) from one that
    /// was delivered but whose response could not be read back
    /// ([`ProxyError::Read`] — EOF, timeout, oversized, empty, or shutdown). That
    /// distinction is the home's delivered-vs-unknown verdict: a `Connect` failure
    /// is safe to report as not-delivered and may be retried; a `Read` failure
    /// means the peer may or may not have acted, so the caller must NOT retry.
    ///
    /// The response read is bounded by BOTH `max_bytes` and `total_timeout` and
    /// abortable via `running`, exactly like [`Self::request_value_bounded`], so a
    /// malicious or faulty peer can neither OOM nor indefinitely hang the home.
    pub fn proxy_request_bounded(
        &self,
        request: &Request,
        max_bytes: usize,
        total_timeout: Duration,
        running: Option<&Arc<AtomicBool>>,
    ) -> Result<String, ProxyError> {
        let deadline = Instant::now() + total_timeout;
        let mut stream = match &self.target {
            ConnectionTarget::Ssh(target) => {
                // The per-request SSH child embeds the request at spawn time, so a
                // spawn failure is the connect/write phase.
                let json = serde_json::to_string(request).map_err(|err| {
                    ProxyError::Connect(io::Error::new(io::ErrorKind::InvalidInput, err))
                })?;
                ssh_transport::spawn_request(target, &json).map_err(ProxyError::Connect)?
            }
            _ => {
                let mut stream = self.connect().map_err(ProxyError::Connect)?;
                write_request_line(&mut stream, request).map_err(ProxyError::Connect)?;
                stream
            }
        };

        let line = read_bounded_response_line(&mut stream, max_bytes, deadline, running)
            .map_err(ProxyError::Read)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(ProxyError::Read(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "federation peer returned an empty response",
            )));
        }
        Ok(trimmed.to_string())
    }

    pub fn status(&self) -> Result<crate::api::RuntimeStatus, ApiClientError> {
        let response = self.request(Request {
            id: "api-client:status".into(),
            method: Method::Ping(PingParams::default()),
        })?;
        match response.result {
            ResponseResult::Pong {
                version,
                protocol,
                capabilities,
            } => Ok(crate::api::RuntimeStatus {
                version: Some(version),
                protocol: Some(protocol),
                capabilities,
            }),
            result => Err(ApiClientError::UnexpectedResult(format!("{result:?}"))),
        }
    }

    /// Connect for the socket-backed and TCP transports (never SSH, which is
    /// per-request). For TCP with a token, the `federation.hello` line is written
    /// before this returns, so the caller may write the request immediately.
    fn connect(&self) -> io::Result<ApiStream> {
        match &self.target {
            ConnectionTarget::LocalSession(_) | ConnectionTarget::SocketPath(_) => Ok(
                ApiStream::Local(crate::ipc::connect_local_stream(&self.socket_path())?),
            ),
            ConnectionTarget::Tcp { addr, token } => {
                let mut stream = ApiStream::Tcp(TcpStream::connect(addr)?);
                if let Some(token) = token {
                    write_federation_hello(&mut stream, token)?;
                }
                Ok(stream)
            }
            ConnectionTarget::Ssh(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ssh federation targets connect per-request; use request_value or request_stream",
            )),
        }
    }
}

/// Iterator over the NDJSON reply lines of a request. Owns the underlying
/// transport (including any SSH child process), so dropping it tears the
/// connection down.
pub struct ResponseLines {
    reader: BufReader<ApiStream>,
}

impl ResponseLines {
    fn over(stream: ApiStream) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }
}

impl Iterator for ResponseLines {
    type Item = io::Result<serde_json::Value>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    return Some(
                        serde_json::from_str(trimmed)
                            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
                    );
                }
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

enum TimeoutKind {
    Send,
    Recv,
}

fn set_timeout_best_effort(
    stream: &mut ApiStream,
    kind: TimeoutKind,
    timeout: Duration,
) -> io::Result<()> {
    let result = match kind {
        TimeoutKind::Send => stream.set_send_timeout(Some(timeout)),
        TimeoutKind::Recv => stream.set_recv_timeout(Some(timeout)),
    };
    match result {
        Ok(()) => Ok(()),
        // Named-pipe / some transports report timeouts as unsupported; the
        // request still proceeds without an enforced deadline.
        Err(err) if err.kind() == io::ErrorKind::Unsupported => Ok(()),
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
pub enum ApiClientError {
    Io(io::Error),
    Json(serde_json::Error),
    ErrorResponse(ErrorResponse),
    EmptyResponse,
    UnexpectedResult(String),
}

impl fmt::Display for ApiClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::ErrorResponse(response) => write!(f, "{}", response.error.message),
            Self::EmptyResponse => write!(f, "empty api response"),
            Self::UnexpectedResult(result) => write!(f, "unexpected api result: {result}"),
        }
    }
}

impl std::error::Error for ApiClientError {}

impl From<io::Error> for ApiClientError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for ApiClientError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

/// Which phase of a [`ApiClient::proxy_request_bounded`] federation proxy failed.
///
/// The distinction is the home daemon's delivered-vs-unknown verdict: a
/// `Connect` failure happened before the request left the home, so the peer never
/// received it (safe to report not-delivered / retry); a `Read` failure happened
/// after the request was written, so the peer may or may not have acted on it
/// (report delivery-unknown / never retry).
#[derive(Debug)]
pub enum ProxyError {
    /// Connecting to the peer or writing the request failed — the request never
    /// reached the peer.
    Connect(io::Error),
    /// The request was written but reading the response line back failed (EOF,
    /// timeout, oversized, empty, or an in-flight shutdown).
    Read(io::Error),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(err) => write!(f, "{err}"),
            Self::Read(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ProxyError {}

fn write_request_line(stream: &mut ApiStream, request: &Request) -> io::Result<()> {
    let encoded = serde_json::to_string(request)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    stream.write_all(encoded.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// Write the versioned `federation.hello` line. Must match the exact shape the
/// listener expects — both sides share [`crate::api::federation::FederationHello`].
///
/// `FederationHello::new` stamps the current `FEDERATION_PROTOCOL_VERSION` and an
/// empty `machine_id`: no persisted machine id exists yet (a later workstream),
/// and `machine_id` is informational in this version — the token is the
/// authenticator — so an empty placeholder is sent for now.
fn write_federation_hello(stream: &mut ApiStream, token: &str) -> io::Result<()> {
    let line = crate::api::federation::FederationHello::new(token)
        .to_line()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn read_json_line<T, R>(reader: &mut R) -> Result<T, ApiClientError>
where
    T: DeserializeOwned,
    R: BufRead,
{
    let mut line = String::new();
    let read = reader.read_line(&mut line)?;
    if read == 0 || line.trim().is_empty() {
        return Err(ApiClientError::EmptyResponse);
    }
    serde_json::from_str(&line).map_err(ApiClientError::Json)
}

/// Read one newline-terminated response line off `stream`, bounded by BOTH a
/// wall-clock `deadline` (re-checked between reads) and a `max_bytes` cap on the
/// accumulated line, and responsive to `running` clearing.
///
/// The stream is put in non-blocking (`set_polling`) mode and drained one chunk
/// at a time, so no single read can block past the deadline: a peer that trickles
/// bytes, stalls without ever sending a newline, or returns an oversized line is
/// bounded by `deadline`/`max_bytes` rather than allowed to run (and allocate)
/// without limit. Any of the bounds, an early EOF, or a cleared `running` flag
/// surfaces as an `Err` so the caller degrades that peer. Only the bytes up to
/// (and including) the first newline are retained; anything a peer piles on after
/// it is discarded, so trailing garbage cannot grow the buffer either.
fn read_bounded_response_line(
    stream: &mut ApiStream,
    max_bytes: usize,
    deadline: Instant,
    running: Option<&Arc<AtomicBool>>,
) -> io::Result<String> {
    stream.set_polling(true)?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];

    let result = loop {
        if running.is_some_and(|flag| !flag.load(Ordering::Relaxed)) {
            break Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "federation poll response read interrupted by shutdown",
            ));
        }

        match stream.poll_read(&mut chunk) {
            Ok(ApiStreamRead::Closed) => {
                break Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "federation peer closed the connection before a full response line",
                ));
            }
            Ok(ApiStreamRead::Data(read)) => {
                let data = &chunk[..read];
                let newline = data.iter().position(|&b| b == b'\n');
                let take = newline.map(|i| i + 1).unwrap_or(read);
                buf.extend_from_slice(&data[..take]);
                if buf.len() > max_bytes {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "federation response line is too large",
                    ));
                }
                if newline.is_some() {
                    break String::from_utf8(buf)
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err));
                }
            }
            Ok(ApiStreamRead::Pending) => {
                if Instant::now() >= deadline {
                    break Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out reading federation response",
                    ));
                }
                std::thread::sleep(BOUNDED_READ_POLL_INTERVAL);
            }
            Err(err) => break Err(err),
        }
    };

    // Best-effort restore of blocking mode; the connection is torn down on error
    // anyway, and the caller drops the stream after a successful line.
    let _ = stream.set_polling(false);
    result
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum WireResponse {
    Success(Box<SuccessResponse>),
    Error(ErrorResponse),
}

pub(crate) fn parse_response_value(
    value: serde_json::Value,
) -> Result<SuccessResponse, ApiClientError> {
    match serde_json::from_value(value)? {
        WireResponse::Success(response) => Ok(*response),
        WireResponse::Error(response) => Err(ApiClientError::ErrorResponse(response)),
    }
}

/// Failure parsing a federation peer `endpoint` string into a [`ConnectionTarget`].
#[derive(Debug)]
pub enum EndpointParseError {
    /// The scheme is neither `tcp://` nor `ssh://`.
    UnknownScheme(String),
    /// The authority (host, or host:port for TCP) was empty.
    MissingHost,
    /// A `tcp://host:port` authority did not resolve to a socket address.
    UnresolvedTcpAddress {
        authority: String,
        source: io::Error,
    },
}

impl fmt::Display for EndpointParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScheme(endpoint) => write!(
                f,
                "unsupported federation endpoint scheme in {endpoint:?}; expected tcp:// or ssh://"
            ),
            Self::MissingHost => write!(f, "federation endpoint is missing a host"),
            Self::UnresolvedTcpAddress { authority, source } => {
                write!(
                    f,
                    "could not resolve tcp federation endpoint {authority:?}: {source}"
                )
            }
        }
    }
}

impl std::error::Error for EndpointParseError {}

/// Resolve a federation peer `endpoint` string into a [`ConnectionTarget`].
///
/// - `tcp://host:port` resolves the authority to a [`SocketAddr`] (DNS is
///   allowed) and yields [`ConnectionTarget::Tcp`], carrying `token` as the
///   `federation.hello` credential.
/// - `ssh://[user@]host` yields an [`SshTarget`] with key-based auth. `token` is
///   ignored — SSH federation authenticates with the ssh key, not a token.
/// - Any other scheme is rejected.
pub fn endpoint_to_target(
    endpoint: &str,
    token: Option<String>,
) -> Result<ConnectionTarget, EndpointParseError> {
    if let Some(authority) = endpoint.strip_prefix("tcp://") {
        if authority.is_empty() {
            return Err(EndpointParseError::MissingHost);
        }
        let addr = authority
            .to_socket_addrs()
            .map_err(|source| EndpointParseError::UnresolvedTcpAddress {
                authority: authority.to_string(),
                source,
            })?
            .next()
            .ok_or_else(|| EndpointParseError::UnresolvedTcpAddress {
                authority: authority.to_string(),
                source: io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"),
            })?;
        Ok(ConnectionTarget::Tcp { addr, token })
    } else if let Some(authority) = endpoint.strip_prefix("ssh://") {
        let (user, host) = match authority.split_once('@') {
            Some((user, host)) => (Some(user.to_string()), host),
            None => (None, authority),
        };
        if host.is_empty() {
            return Err(EndpointParseError::MissingHost);
        }
        Ok(ConnectionTarget::Ssh(SshTarget {
            host: host.to_string(),
            user,
            credential: SshCredential::Key,
        }))
    } else {
        Err(EndpointParseError::UnknownScheme(endpoint.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A loopback TCP peer that runs `serve` on the accepted socket, plus the
    /// address to connect to. Joining teardown-safe.
    fn loopback_peer(
        serve: impl FnOnce(TcpStream) + Send + 'static,
    ) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback peer");
        let addr = listener.local_addr().expect("peer addr");
        let handle = std::thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept poll client");
            serve(sock);
        });
        (addr, handle)
    }

    /// A peer returning a line larger than the cap (no newline in sight) makes the
    /// bounded reader error at ~the cap instead of accumulating without limit.
    #[test]
    fn bounded_read_rejects_an_over_cap_line() {
        let (addr, peer) = loopback_peer(|mut sock| {
            // Far more than the 32-byte cap used below, and no newline.
            let _ = sock.write_all(&vec![b'x'; 4096]);
            std::thread::sleep(Duration::from_millis(200));
        });

        let mut stream = ApiStream::Tcp(TcpStream::connect(addr).expect("connect peer"));
        let deadline = Instant::now() + Duration::from_secs(5);
        let err = read_bounded_response_line(&mut stream, 32, deadline, None).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "federation response line is too large");
        peer.join().unwrap();
    }

    /// A peer that trickles bytes but never terminates a line is bounded by the
    /// wall-clock deadline, not left to read forever.
    #[test]
    fn bounded_read_honors_the_deadline_when_a_peer_stalls() {
        let (addr, peer) = loopback_peer(|mut sock| {
            let _ = sock.write_all(b"partial-with-no-newline");
            std::thread::sleep(Duration::from_millis(400));
        });

        let mut stream = ApiStream::Tcp(TcpStream::connect(addr).expect("connect peer"));
        let deadline = Instant::now() + Duration::from_millis(150);
        let started = Instant::now();
        let err = read_bounded_response_line(&mut stream, 64 * 1024, deadline, None).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the read did not stop near the deadline"
        );
        peer.join().unwrap();
    }

    /// Clearing `running` mid-read aborts it promptly, so shutdown (which joins
    /// the poll threads) does not hang on a silent peer.
    #[test]
    fn bounded_read_aborts_when_running_clears() {
        let (addr, peer) = loopback_peer(|sock| {
            // Silent but open: only the running flag can end the read.
            std::thread::sleep(Duration::from_millis(500));
            drop(sock);
        });

        let mut stream = ApiStream::Tcp(TcpStream::connect(addr).expect("connect peer"));
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            flag.store(false, Ordering::Relaxed);
        });

        // Far-future deadline: only the cleared running flag can end this read.
        let deadline = Instant::now() + Duration::from_secs(30);
        let started = Instant::now();
        let err = read_bounded_response_line(&mut stream, 64 * 1024, deadline, Some(&running))
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the read did not abort promptly on shutdown"
        );
        peer.join().unwrap();
    }

    #[test]
    fn local_session_target_resolves_named_session_socket() {
        let client = ApiClient::for_target(ConnectionTarget::LocalSession(Some("work".into())));
        assert!(client.socket_path().ends_with("sessions/work/herdr.sock"));
    }

    #[test]
    fn socket_path_target_uses_explicit_path() {
        let path = PathBuf::from("/tmp/herdr-test.sock");
        let client = ApiClient::for_target(ConnectionTarget::SocketPath(path.clone()));
        assert_eq!(client.socket_path(), path);
    }

    #[test]
    fn tcp_and_ssh_targets_have_no_socket_path() {
        let tcp = ApiClient::for_target(ConnectionTarget::Tcp {
            addr: "127.0.0.1:9000".parse().unwrap(),
            token: Some("t".into()),
        });
        assert_eq!(tcp.socket_path(), PathBuf::new());

        let ssh = ApiClient::for_target(ConnectionTarget::Ssh(SshTarget {
            host: "example".into(),
            user: None,
            credential: SshCredential::Key,
        }));
        assert_eq!(ssh.socket_path(), PathBuf::new());
    }

    #[test]
    fn endpoint_tcp_resolves_to_a_tcp_target_with_token() {
        let target = endpoint_to_target("tcp://127.0.0.1:9000", Some("s3cret".into()))
            .expect("tcp endpoint parses");
        match target {
            ConnectionTarget::Tcp { addr, token } => {
                assert_eq!(addr, "127.0.0.1:9000".parse::<SocketAddr>().unwrap());
                assert_eq!(token.as_deref(), Some("s3cret"));
            }
            other => panic!("expected tcp target, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_ssh_parses_user_and_host_and_ignores_token() {
        let target = endpoint_to_target("ssh://alice@host.example", Some("ignored".into()))
            .expect("ssh endpoint parses");
        assert_eq!(
            target,
            ConnectionTarget::Ssh(SshTarget {
                host: "host.example".into(),
                user: Some("alice".into()),
                credential: SshCredential::Key,
            })
        );
    }

    #[test]
    fn endpoint_ssh_without_user_parses_bare_host() {
        let target =
            endpoint_to_target("ssh://host.example", None).expect("bare ssh endpoint parses");
        assert_eq!(
            target,
            ConnectionTarget::Ssh(SshTarget {
                host: "host.example".into(),
                user: None,
                credential: SshCredential::Key,
            })
        );
    }

    #[test]
    fn endpoint_rejects_unknown_scheme_and_empty_host() {
        assert!(matches!(
            endpoint_to_target("http://host:80", None),
            Err(EndpointParseError::UnknownScheme(_))
        ));
        assert!(matches!(
            endpoint_to_target("garbage", None),
            Err(EndpointParseError::UnknownScheme(_))
        ));
        assert!(matches!(
            endpoint_to_target("ssh://", None),
            Err(EndpointParseError::MissingHost)
        ));
        assert!(matches!(
            endpoint_to_target("tcp://", None),
            Err(EndpointParseError::MissingHost)
        ));
    }

    #[test]
    fn endpoint_tcp_missing_port_is_rejected() {
        assert!(matches!(
            endpoint_to_target("tcp://127.0.0.1", None),
            Err(EndpointParseError::UnresolvedTcpAddress { .. })
        ));
    }
}
