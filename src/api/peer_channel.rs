//! One persistent request channel per SSH-bridged federation peer.
//!
//! The saved-peer bridge opens a new SSH channel and starts a remote
//! `remote-api-bridge` for every local connection, which costs a few round
//! trips before the request is even written. A [`PeerChannel`] instead keeps
//! one `herdr --session <session> api-bridge --multi` running through the same
//! managed SSH transport and multiplexes every one-shot request over it:
//!
//! * each request line goes out with a channel-unique id, and the reader
//!   thread hands each response line to the caller waiting on that id, so
//!   concurrent requests may complete in any order;
//! * the caller's original id is restored by replacing only the top-level
//!   `id` value of the response; every other byte is the peer's;
//! * streaming methods (which `api-bridge --multi` refuses) never use it;
//! * the channel is opened lazily, verified with a `ping` whose capabilities
//!   must advertise `api_bridge_multi`, and only used while the peer's poll
//!   reports that capability. Otherwise callers keep the per-connection path.
//!
//! A request that never reached the channel is not delivered. Once its line is
//! (even partially) written, a missing, garbled or oversized response, or the
//! channel dying, leaves delivery unknown, and the channel never re-sends it.
//! A dead channel is replaced for a later request, after a bounded backoff
//! when it keeps failing.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::ops::Range;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::client::ProxyError;
use crate::api::schema::{Method, PingParams, Request};
use crate::remote::{API_BRIDGE_MULTI_MAX_IN_FLIGHT, API_BRIDGE_MULTI_STREAMING_METHODS};

/// Largest response line the channel buffers. It covers the largest one-shot
/// cap any peer caller uses (the reverse gateway's 4 MiB `agent.list`); each
/// caller still enforces its own, smaller cap. A longer line is drained, and
/// only the request it answers fails.
pub(crate) const PEER_CHANNEL_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Bound on starting the remote bridge and answering the verification ping.
const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
/// First delay before reopening after a failed open; doubles per consecutive
/// failure up to [`CHANNEL_RETRY_MAX`].
const CHANNEL_RETRY_BASE: Duration = Duration::from_secs(1);
const CHANNEL_RETRY_MAX: Duration = Duration::from_secs(30);
/// How often a waiting caller re-checks shutdown, route changes and its
/// deadline.
const CHANNEL_WAIT_POLL: Duration = Duration::from_millis(20);
const CHANNEL_ID_PREFIX: &str = "herdr-peer-channel:";

/// Builds the command that starts `api-bridge --multi` on the peer. The
/// channel sets the command's stdio itself.
pub(crate) type ChannelLauncher = Arc<dyn Fn() -> io::Result<Command> + Send + Sync>;

pub(crate) struct PeerChannel {
    launcher: ChannelLauncher,
    /// The peer's latest poll advertised `api_bridge_multi`.
    advertised: AtomicBool,
    /// The route was retired; nothing opens or uses the channel any more.
    closed: AtomicBool,
    in_flight: AtomicUsize,
    next_id: AtomicU64,
    state: Mutex<ChannelState>,
}

#[derive(Default)]
struct ChannelState {
    connection: Option<Arc<Connection>>,
    /// Consecutive failed opens or connections that died before answering
    /// any request.
    failures: u32,
    retry_at: Option<Instant>,
}

impl std::fmt::Debug for PeerChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerChannel")
            .field("advertised", &self.advertised.load(Ordering::Relaxed))
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("in_flight", &self.in_flight.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl PeerChannel {
    pub(crate) fn new(launcher: ChannelLauncher) -> Arc<Self> {
        Arc::new(Self {
            launcher,
            advertised: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
            next_id: AtomicU64::new(0),
            state: Mutex::new(ChannelState::default()),
        })
    }

    /// Record whether the peer's latest poll advertised `api_bridge_multi`.
    /// A peer that stops advertising it loses its open channel.
    pub(crate) fn set_advertised(&self, advertised: bool) {
        if self.advertised.swap(advertised, Ordering::AcqRel) && !advertised {
            self.drop_connection();
        }
    }

    /// Stop the channel for good: the open connection's SSH process is killed
    /// and its in-flight requests end as delivery-unknown.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.drop_connection();
    }

    fn drop_connection(&self) {
        let connection = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .connection
            .take();
        if let Some(connection) = connection {
            connection.shutdown(&io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "federation peer channel closed",
            ));
        }
    }

    /// Reserve a request slot on an open, verified connection, opening one if
    /// needed. `None` means the caller must use the per-connection path: the
    /// method streams, the peer does not advertise `api_bridge_multi`, every
    /// slot is busy, or the channel is closed, backing off, or failed to open.
    /// Nothing has been sent for the caller's request in any of those cases.
    pub(crate) fn lease(
        self: &Arc<Self>,
        method: &Method,
        running: Option<&AtomicBool>,
    ) -> Option<ChannelLease> {
        if self.closed.load(Ordering::Acquire)
            || !self.advertised.load(Ordering::Acquire)
            || API_BRIDGE_MULTI_STREAMING_METHODS.contains(&crate::api::api_method_name(method))
        {
            return None;
        }
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                (in_flight < API_BRIDGE_MULTI_MAX_IN_FLIGHT).then_some(in_flight + 1)
            })
            .ok()?;
        match self.connection(running) {
            Some(connection) => Some(ChannelLease {
                channel: Arc::clone(self),
                connection,
            }),
            None => {
                self.in_flight.fetch_sub(1, Ordering::AcqRel);
                None
            }
        }
    }

    /// Send `request` and wait for its response without a route fence. `None`
    /// means the caller must use the per-connection path; see [`Self::lease`].
    pub(crate) fn request(
        self: &Arc<Self>,
        request: &Request,
        max_bytes: usize,
        timeout: Duration,
        running: Option<&AtomicBool>,
    ) -> Option<Result<String, ProxyError>> {
        if max_bytes > PEER_CHANNEL_MAX_RESPONSE_BYTES {
            return None;
        }
        let lease = self.lease(&request.method, running)?;
        Some(
            lease
                .send(request)
                .and_then(|pending| pending.wait(&request.id, max_bytes, timeout, running)),
        )
    }

    fn connection(&self, running: Option<&AtomicBool>) -> Option<Arc<Connection>> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(connection) = &state.connection {
            if !connection.shared.is_dead() {
                return Some(Arc::clone(connection));
            }
            let proved = connection.shared.proved.load(Ordering::Acquire);
            state.connection = None;
            // A connection that answered requests before dying is replaced at
            // once; one that keeps dying unproven backs off like a failed open.
            state.failures = if proved { 1 } else { state.failures + 1 };
            state.retry_at = Some(Instant::now() + retry_delay(state.failures - 1));
        }
        if state
            .retry_at
            .is_some_and(|retry_at| Instant::now() < retry_at)
        {
            return None;
        }
        let abort = || {
            self.closed.load(Ordering::Acquire)
                || running.is_some_and(|running| !running.load(Ordering::Relaxed))
        };
        let handshake_id = self.next_channel_id();
        match Connection::open(&self.launcher, &handshake_id, &abort) {
            Ok(connection) if !abort() => {
                let connection = Arc::new(connection);
                state.connection = Some(Arc::clone(&connection));
                state.retry_at = None;
                Some(connection)
            }
            Ok(_) => None,
            Err(error) => {
                state.failures += 1;
                state.retry_at = Some(Instant::now() + retry_delay(state.failures));
                tracing::warn!(%error, "federation peer channel did not open; using per-request bridge");
                None
            }
        }
    }

    fn next_channel_id(&self) -> String {
        format!(
            "{CHANNEL_ID_PREFIX}{}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        )
    }
}

/// Delay before the next open after `failures` consecutive failures: none
/// for the first, then [`CHANNEL_RETRY_BASE`] doubling to [`CHANNEL_RETRY_MAX`].
fn retry_delay(failures: u32) -> Duration {
    match failures {
        0 => Duration::ZERO,
        failures => CHANNEL_RETRY_BASE
            .saturating_mul(1 << (failures - 1).min(16))
            .min(CHANNEL_RETRY_MAX),
    }
}

/// A reserved request slot on an open connection.
pub(crate) struct ChannelLease {
    channel: Arc<PeerChannel>,
    connection: Arc<Connection>,
}

impl Drop for ChannelLease {
    fn drop(&mut self) {
        self.channel.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Serialize)]
struct WireRequest<'a> {
    id: &'a str,
    #[serde(flatten)]
    method: &'a Method,
}

impl ChannelLease {
    /// Write `request` under a channel-unique id. [`ProxyError::Connect`]
    /// means no byte of it reached the channel.
    pub(crate) fn send(self, request: &Request) -> Result<PendingReply, ProxyError> {
        let channel_id = self.channel.next_channel_id();
        let mut line = serde_json::to_vec(&WireRequest {
            id: &channel_id,
            method: &request.method,
        })
        .map_err(|error| ProxyError::Connect(io::Error::new(io::ErrorKind::InvalidInput, error)))?;
        line.push(b'\n');
        let replies = self.connection.send(&channel_id, &line)?;
        Ok(PendingReply {
            lease: self,
            channel_id,
            replies,
        })
    }
}

/// A written request waiting for its response line.
pub(crate) struct PendingReply {
    lease: ChannelLease,
    channel_id: String,
    replies: mpsc::Receiver<io::Result<Reply>>,
}

impl Drop for PendingReply {
    fn drop(&mut self) {
        self.lease.connection.shared.unregister(&self.channel_id);
    }
}

impl PendingReply {
    /// Wait for the response and return it with `original_id` restored. Every
    /// error is [`ProxyError::Read`]: the request was written. Gives up when
    /// `running` clears or `timeout` passes; a response that arrives later is
    /// dropped.
    pub(crate) fn wait(
        self,
        original_id: &str,
        max_bytes: usize,
        timeout: Duration,
        running: Option<&AtomicBool>,
    ) -> Result<String, ProxyError> {
        let deadline = Instant::now() + timeout;
        let reply = loop {
            match self.replies.recv_timeout(CHANNEL_WAIT_POLL) {
                Ok(reply) => break reply,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "federation peer channel closed before a response",
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if running.is_some_and(|running| !running.load(Ordering::Relaxed)) {
                break Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "federation poll response read interrupted by shutdown",
                ));
            }
            if Instant::now() >= deadline {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out reading federation response",
                ));
            }
        };
        let Reply { mut line, id } = reply.map_err(ProxyError::Read)?;
        self.lease
            .connection
            .shared
            .proved
            .store(true, Ordering::Release);
        // The per-connection read counts the newline against the cap too.
        if line.len() >= max_bytes {
            return Err(ProxyError::Read(io::Error::new(
                io::ErrorKind::InvalidData,
                "federation response line is too large",
            )));
        }
        if let Some(message) = bridge_transport_error(&line) {
            return Err(ProxyError::Read(io::Error::other(message)));
        }
        let original = serde_json::to_vec(original_id)
            .map_err(|error| ProxyError::Read(io::Error::new(io::ErrorKind::InvalidData, error)))?;
        line.splice(id, original);
        String::from_utf8(line)
            .map_err(|error| ProxyError::Read(io::Error::new(io::ErrorKind::InvalidData, error)))
    }
}

#[derive(Deserialize)]
struct BridgeErrorProbe {
    error: Option<BridgeError>,
}

#[derive(Deserialize)]
struct BridgeError {
    code: String,
    message: String,
}

/// The message of an `api-bridge` `transport_error` envelope. The bridge
/// emits one when its own connection to the peer's API socket fails, before
/// or after the request reached it; the per-connection path saw the same
/// failure as the channel ending, so it stays delivery-unknown. The API server
/// never uses this code.
fn bridge_transport_error(line: &[u8]) -> Option<String> {
    const CODE: &[u8] = b"\"transport_error\"";
    if !line.windows(CODE.len()).any(|window| window == CODE) {
        return None;
    }
    let error = serde_json::from_slice::<BridgeErrorProbe>(line)
        .ok()?
        .error?;
    (error.code == "transport_error").then_some(error.message)
}

/// One response line and the byte range of its top-level `id` value.
struct Reply {
    line: Vec<u8>,
    id: Range<usize>,
}

/// One running `api-bridge --multi` process and its reader thread.
struct Connection {
    shared: Arc<ConnectionShared>,
    stdin: Mutex<Option<ChildStdin>>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

struct ConnectionShared {
    /// Callers waiting on a response, by channel id; `None` once dead.
    pending: Mutex<Option<HashMap<String, mpsc::SyncSender<io::Result<Reply>>>>>,
    /// The connection answered a request (not just the verification ping).
    proved: AtomicBool,
    child: Mutex<Child>,
}

impl ConnectionShared {
    fn is_dead(&self) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
    }

    fn register(&self, channel_id: &str) -> Option<mpsc::Receiver<io::Result<Reply>>> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()?
            .insert(channel_id.to_owned(), sender);
        Some(receiver)
    }

    fn unregister(&self, channel_id: &str) {
        if let Some(pending) = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            pending.remove(channel_id);
        }
    }

    fn deliver(&self, channel_id: &str, reply: io::Result<Reply>) {
        let waiter = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .and_then(|pending| pending.remove(channel_id));
        match waiter {
            // Capacity one and removed from the map, so this never blocks.
            Some(waiter) => {
                let _ = waiter.try_send(reply);
            }
            None => tracing::debug!(
                channel_id,
                "federation peer channel dropped a response nobody waits for"
            ),
        }
    }

    /// Mark the connection dead and fail every waiter with `error`.
    fn fail(&self, error: &io::Error) {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        for (_, waiter) in pending.into_iter().flatten() {
            let _ = waiter.try_send(Err(io::Error::new(error.kind(), error.to_string())));
        }
    }

    fn kill(&self) {
        let mut child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Connection {
    fn open(
        launcher: &ChannelLauncher,
        handshake_id: &str,
        abort: &dyn Fn() -> bool,
    ) -> io::Result<Self> {
        let mut command = launcher()?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to start federation peer channel: {error}"),
            )
        })?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("federation peer channel stdio missing"));
        };
        let shared = Arc::new(ConnectionShared {
            pending: Mutex::new(Some(HashMap::new())),
            proved: AtomicBool::new(false),
            child: Mutex::new(child),
        });
        let reader_shared = Arc::clone(&shared);
        let reader = std::thread::Builder::new()
            .name("herdr-peer-channel".into())
            .spawn(move || read_replies(stdout, &reader_shared));
        let reader = match reader {
            Ok(reader) => reader,
            Err(error) => {
                shared.kill();
                return Err(error);
            }
        };
        // From here dropping `connection` kills the process and joins the reader.
        let connection = Self {
            shared,
            stdin: Mutex::new(Some(stdin)),
            reader: Mutex::new(Some(reader)),
        };
        connection.verify(handshake_id, abort)?;
        Ok(connection)
    }

    /// Ping through the new channel and require `api_bridge_multi` in the
    /// answer, proving the remote binary runs `api-bridge --multi` for the
    /// selected session.
    fn verify(&self, handshake_id: &str, abort: &dyn Fn() -> bool) -> io::Result<()> {
        let mut line = serde_json::to_vec(&Request {
            id: handshake_id.to_owned(),
            method: Method::Ping(PingParams::default()),
        })
        .map_err(io::Error::other)?;
        line.push(b'\n');
        let replies = self
            .send(handshake_id, &line)
            .map_err(|error| match error {
                ProxyError::Connect(error) | ProxyError::Read(error) => error,
            })?;
        let deadline = Instant::now() + CHANNEL_OPEN_TIMEOUT;
        let reply = loop {
            match replies.recv_timeout(CHANNEL_WAIT_POLL) {
                Ok(reply) => break reply?,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "federation peer channel closed before answering its ping",
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if abort() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "federation peer channel open cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "federation peer channel did not answer its ping",
                ));
            }
        };
        let pong: serde_json::Value = serde_json::from_slice(&reply.line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let multi = pong
            .pointer("/result/type")
            .and_then(serde_json::Value::as_str)
            == Some("pong")
            && pong
                .pointer("/result/capabilities/api_bridge_multi")
                .and_then(serde_json::Value::as_bool)
                == Some(true);
        if multi {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "federation peer api-bridge does not advertise api_bridge_multi",
            ))
        }
    }

    /// Register `channel_id`, then write `line`. A failed write kills the
    /// connection; it is [`ProxyError::Connect`] only when no byte left.
    fn send(
        &self,
        channel_id: &str,
        line: &[u8],
    ) -> Result<mpsc::Receiver<io::Result<Reply>>, ProxyError> {
        let closed = || {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "federation peer channel is closed",
            )
        };
        let replies = self
            .shared
            .register(channel_id)
            .ok_or_else(|| ProxyError::Connect(closed()))?;
        let mut stdin = self.stdin.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(writer) = stdin.as_mut() else {
            self.shared.unregister(channel_id);
            return Err(ProxyError::Connect(closed()));
        };
        let mut written = 0;
        while written < line.len() {
            match writer.write(&line[written..]) {
                Ok(0) => {
                    drop(stdin);
                    return Err(self.write_failed(channel_id, written, closed()));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    drop(stdin);
                    return Err(self.write_failed(channel_id, written, error));
                }
            }
        }
        Ok(replies)
    }

    fn write_failed(&self, channel_id: &str, written: usize, error: io::Error) -> ProxyError {
        self.shared.unregister(channel_id);
        self.shutdown(&error);
        if written == 0 {
            ProxyError::Connect(error)
        } else {
            ProxyError::Read(error)
        }
    }

    /// Fail every waiter with `error` and stop the process; the reader then
    /// sees end of output and exits.
    fn shutdown(&self, error: &io::Error) {
        self.shared.fail(error);
        drop(
            self.stdin
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        self.shared.kill();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.shutdown(&io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "federation peer channel closed",
        ));
        let reader = self
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(reader) = reader {
            let _ = reader.join();
        }
    }
}

fn read_replies(stdout: ChildStdout, shared: &ConnectionShared) {
    let mut reader = BufReader::new(stdout);
    let error = match crate::remote::discard_remote_output_preamble(&mut reader) {
        Ok(()) => dispatch_replies(&mut reader, shared),
        Err(error) => error,
    };
    tracing::debug!(%error, "federation peer channel ended");
    shared.fail(&error);
    shared.kill();
}

/// Hand every response line to its waiter until the channel ends or garbles;
/// returns why it stopped.
fn dispatch_replies(reader: &mut impl BufRead, shared: &ConnectionShared) -> io::Error {
    let garbled = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "federation peer channel sent a response without a request id",
        )
    };
    let mut line = Vec::new();
    loop {
        match read_reply_line(reader, &mut line) {
            Err(error) => return error,
            Ok(ReplyLine::Eof) => {
                return io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "federation peer channel closed",
                );
            }
            Ok(ReplyLine::Line) => {
                let Some(trimmed) = trimmed_range(&line) else {
                    continue;
                };
                line.truncate(trimmed.end);
                line.drain(..trimmed.start);
                let Some((channel_id, id)) = channel_id(&line, true) else {
                    return garbled();
                };
                let line = std::mem::take(&mut line);
                shared.deliver(&channel_id, Ok(Reply { line, id }));
            }
            Ok(ReplyLine::TooLong) => {
                let start = trimmed_range(&line).map_or(0, |range| range.start);
                let Some((channel_id, _)) = channel_id(&line[start..], false) else {
                    return garbled();
                };
                shared.deliver(
                    &channel_id,
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "federation response line is too large",
                    )),
                );
            }
        }
    }
}

enum ReplyLine {
    Eof,
    Line,
    /// Longer than [`PEER_CHANNEL_MAX_RESPONSE_BYTES`]; `line` holds its
    /// first bytes and the rest was drained.
    TooLong,
}

fn read_reply_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<ReplyLine> {
    line.clear();
    let limit = PEER_CHANNEL_MAX_RESPONSE_BYTES as u64 + 1;
    if reader.by_ref().take(limit).read_until(b'\n', line)? == 0 {
        return Ok(ReplyLine::Eof);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(ReplyLine::Line);
    }
    if line.len() <= PEER_CHANNEL_MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "federation peer channel closed mid-response",
        ));
    }
    reader.skip_until(b'\n')?;
    Ok(ReplyLine::TooLong)
}

fn trimmed_range(line: &[u8]) -> Option<Range<usize>> {
    let start = line.iter().position(|byte| !byte.is_ascii_whitespace())?;
    let end = line.iter().rposition(|byte| !byte.is_ascii_whitespace())? + 1;
    Some(start..end)
}

/// The decoded top-level `id` of a response line and the byte range of its
/// JSON string value.
fn channel_id(line: &[u8], complete: bool) -> Option<(String, Range<usize>)> {
    let id = top_level_id_span(line, complete)?;
    let decoded = serde_json::from_slice::<String>(&line[id.clone()]).ok()?;
    Some((decoded, id))
}

/// Byte range of the top-level `"id"` member's string value (quotes
/// included) in a JSON object. A `complete` line is scanned to its end, and a
/// repeated `id` makes it ambiguous; a truncated prefix stops at the first.
fn top_level_id_span(line: &[u8], complete: bool) -> Option<Range<usize>> {
    let mut at = skip_whitespace(line, 0);
    if line.get(at) != Some(&b'{') {
        return None;
    }
    at = skip_whitespace(line, at + 1);
    if line.get(at) == Some(&b'}') {
        return None;
    }
    let mut found = None;
    loop {
        if line.get(at) != Some(&b'"') {
            return None;
        }
        let key_end = json_string_end(line, at)?;
        let is_id = json_key_is_id(&line[at..key_end]);
        at = skip_whitespace(line, key_end);
        if line.get(at) != Some(&b':') {
            return None;
        }
        at = skip_whitespace(line, at + 1);
        let value_end = json_value_end(line, at)?;
        if is_id {
            if found.is_some() || line.get(at) != Some(&b'"') {
                return None;
            }
            found = Some(at..value_end);
            if !complete {
                return found;
            }
        }
        at = skip_whitespace(line, value_end);
        match line.get(at)? {
            b',' => at = skip_whitespace(line, at + 1),
            b'}' => break,
            _ => return None,
        }
    }
    (skip_whitespace(line, at + 1) == line.len())
        .then_some(found)
        .flatten()
}

fn skip_whitespace(line: &[u8], mut at: usize) -> usize {
    while line.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

fn json_key_is_id(key: &[u8]) -> bool {
    key == b"\"id\""
        || (key.contains(&b'\\')
            && serde_json::from_slice::<String>(key).is_ok_and(|key| key == "id"))
}

/// End (exclusive) of the JSON string starting at `start`.
fn json_string_end(line: &[u8], start: usize) -> Option<usize> {
    let mut at = start + 1;
    loop {
        match line.get(at)? {
            b'\\' => at += 2,
            b'"' => return Some(at + 1),
            _ => at += 1,
        }
    }
}

/// End (exclusive) of the JSON value starting at `start`.
fn json_value_end(line: &[u8], start: usize) -> Option<usize> {
    match line.get(start)? {
        b'"' => json_string_end(line, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut at = start;
            loop {
                match line.get(at)? {
                    b'"' => {
                        at = json_string_end(line, at)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(at + 1);
                        }
                    }
                    _ => {}
                }
                at += 1;
            }
        }
        _ => {
            let end = line[start..]
                .iter()
                .position(|byte| matches!(byte, b',' | b'}' | b']') || byte.is_ascii_whitespace())
                .map_or(line.len(), |offset| start + offset);
            (end > start).then_some(end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(line: &str, original: &str) -> Option<String> {
        let (channel, id) = channel_id(line.as_bytes(), true)?;
        assert_eq!(channel, "herdr-peer-channel:7");
        let mut bytes = line.as_bytes().to_vec();
        bytes.splice(id, serde_json::to_vec(original).unwrap());
        Some(String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn response_id_is_restored_byte_exactly() {
        let original = "orig \"quoted\" é/1\\";
        let cases = [
            (
                r#"{"id":"herdr-peer-channel:7","result":{"type":"ok"}}"#,
                r#"{"id":"orig \"quoted\" é/1\\","result":{"type":"ok"}}"#,
            ),
            (
                r#"{"error":{"code":"x","message":"\"id\":\"no\"","id":"nested"} , "id" : "herdr-peer-channel:7" }"#,
                r#"{"error":{"code":"x","message":"\"id\":\"no\"","id":"nested"} , "id" : "orig \"quoted\" é/1\\" }"#,
            ),
            (
                r#"{"result":[1,{"id":"x"},"]"],"n":-1.5e3,"t":true,"\u0069d":"herdr-peer-channel:7"}"#,
                r#"{"result":[1,{"id":"x"},"]"],"n":-1.5e3,"t":true,"\u0069d":"orig \"quoted\" é/1\\"}"#,
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(rewrite(line, original).as_deref(), Some(expected), "{line}");
        }
    }

    #[test]
    fn ambiguous_or_missing_ids_are_garbled() {
        for line in [
            r#"{"result":{"id":"herdr-peer-channel:7"}}"#,
            r#"{"id":"herdr-peer-channel:7","id":"herdr-peer-channel:7"}"#,
            r#"{"id":7}"#,
            r#"["herdr-peer-channel:7"]"#,
            r#"{"id":"herdr-peer-channel:7""#,
            r#"{"id":"herdr-peer-channel:7"} trailing"#,
            "",
        ] {
            assert!(channel_id(line.as_bytes(), true).is_none(), "{line}");
        }
    }

    #[test]
    fn truncated_response_still_names_its_request() {
        let line = br#"{"id":"herdr-peer-channel:7","result":{"type":"pane_read","text":"aaaa"#;
        assert_eq!(
            channel_id(line, false).map(|(id, _)| id).as_deref(),
            Some("herdr-peer-channel:7")
        );
        assert!(channel_id(line, true).is_none());
    }

    #[test]
    fn channel_requests_carry_only_the_channel_id() {
        let request = Request {
            id: "client-id".into(),
            method: Method::Ping(PingParams::default()),
        };
        let wire = serde_json::to_value(WireRequest {
            id: "herdr-peer-channel:3",
            method: &request.method,
        })
        .unwrap();
        let mut expected = serde_json::to_value(&request).unwrap();
        expected["id"] = "herdr-peer-channel:3".into();
        assert_eq!(wire, expected);
    }

    #[test]
    fn retry_delay_is_bounded() {
        assert_eq!(retry_delay(0), Duration::ZERO);
        assert_eq!(retry_delay(1), CHANNEL_RETRY_BASE);
        assert_eq!(retry_delay(2), CHANNEL_RETRY_BASE * 2);
        assert_eq!(retry_delay(40), CHANNEL_RETRY_MAX);
    }

    #[test]
    fn bridge_transport_errors_are_recognized() {
        assert_eq!(
            bridge_transport_error(
                br#"{"error":{"code":"transport_error","message":"api-bridge: refused"},"id":"x"}"#
            )
            .as_deref(),
            Some("api-bridge: refused")
        );
        assert!(
            bridge_transport_error(br#"{"id":"x","result":{"type":"transport_error"}}"#).is_none()
        );
    }
}
