//! The host socket: dialling the relay and multiplexing guest sessions over it.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tracing::debug;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::{header, HeaderValue, StatusCode};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, HandshakeError, Message, WebSocket};

use super::frame::{Frame, HEADER_LEN};
use super::host::GuestHost;
use super::noise::{ResponderKeys, MAX_MESSAGE};
use super::session::Sessions;
use super::{poll, Ended, Signals, Timing, WakeReceiver};

/// Largest relay message: a 70000-byte guest message plus the frame header.
const MAX_RELAY_MESSAGE: usize = 70_000 + HEADER_LEN;
/// Outbound frames queued by sessions while the socket is busy (each at most
/// one Noise message), so a slow relay pushes back on session output.
const OUTBOUND_QUEUE: usize = 64;
/// Frames moved to the socket per turn, so reading keeps up with writing.
const OUTBOUND_BATCH: usize = 16;
/// Relay messages handled per turn, so a relay that never stops sending
/// cannot starve stopping, pings and output.
const READ_BATCH: usize = 64;
/// Bytes tungstenite buffers before writing to the socket.
const WRITE_BUFFER: usize = 64 * 1024;
/// Hard cap on tungstenite's unsent bytes. The loop stops queueing while the
/// socket is blocked, so reaching this means the relay stopped reading.
const MAX_WRITE_BUFFER: usize = WRITE_BUFFER + 4 * (MAX_MESSAGE + HEADER_LEN);
/// Relay close code for a host socket replaced by a newer one.
const CLOSE_REPLACED: u16 = 4000;
/// Relay-supplied text kept in logs and `last_error`.
const MAX_REASON_CHARS: usize = 64;
/// How often a blocking step of dialling re-checks for a stopped link.
const DIAL_SLICE: Duration = Duration::from_millis(100);

/// The WebSocket URL of this host's socket. Production relays must use TLS;
/// tests also accept a plain `ws://` stub.
pub(super) fn host_socket_url(relay_url: &str, host_id: &str) -> Result<String, String> {
    let base = relay_url.trim_end_matches('/');
    let socket = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if cfg!(test) && base.starts_with("ws://") {
        base.to_owned()
    } else {
        return Err(format!("relay_url {relay_url:?} is not an https:// URL"));
    };
    if host_id.is_empty()
        || !host_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("host_id is not base64url".into());
    }
    Ok(format!("{socket}/v1/host/{host_id}"))
}

/// rustls on ring with the webpki roots, for every request to the relay.
pub(super) fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("tls setup: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn tls_connector() -> Result<Connector, String> {
    tls_config().map(Connector::Rustls)
}

/// Relay-supplied text made safe for logs and `guest.list`: control
/// characters become spaces and the length is capped.
pub(super) fn sanitize_reason(reason: &str) -> String {
    let mut clean: String = reason
        .chars()
        .take(MAX_REASON_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if reason.chars().nth(MAX_REASON_CHARS).is_some() {
        clean.push('…');
    }
    clean
}

/// One dial attempt: its wall-clock deadline and the link's stop flag.
struct Dial {
    deadline: Instant,
    signals: Arc<Signals>,
    /// Set once the socket is upgraded; the deadline no longer applies.
    done: AtomicBool,
}

impl Dial {
    fn stopped(&self) -> bool {
        self.signals.stopped()
    }

    fn left(&self) -> Option<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
    }

    /// Runs a blocking socket step in slices until it completes, the
    /// deadline passes, or the link stops.
    fn bounded<T>(
        &self,
        tcp: &TcpStream,
        set_timeout: fn(&TcpStream, Option<Duration>) -> io::Result<()>,
        mut step: impl FnMut(&TcpStream) -> io::Result<T>,
    ) -> io::Result<T> {
        loop {
            if self.stopped() {
                return Err(io::Error::other("guest link stopped"));
            }
            let Some(left) = self.left() else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay handshake timed out",
                ));
            };
            set_timeout(tcp, Some(left.min(DIAL_SLICE)))?;
            match step(tcp) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                result => return result,
            }
        }
    }
}

/// The relay TCP socket. Until the upgrade completes, every read and write is
/// bounded by the dial deadline, so TLS and the HTTP upgrade share it.
struct RelayStream {
    tcp: TcpStream,
    dial: Arc<Dial>,
}

impl Read for RelayStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.dial.done.load(Ordering::Relaxed) {
            return self.tcp.read(buf);
        }
        self.dial
            .bounded(&self.tcp, TcpStream::set_read_timeout, |mut tcp| {
                tcp.read(buf)
            })
    }
}

impl Write for RelayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.dial.done.load(Ordering::Relaxed) {
            return self.tcp.write(buf);
        }
        self.dial
            .bounded(&self.tcp, TcpStream::set_write_timeout, |mut tcp| {
                tcp.write(buf)
            })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

/// Resolves and connects on a helper thread, since DNS cannot be given a
/// timeout. A lookup that outlives the deadline finishes in the background
/// and its result is discarded.
fn connect(host: &str, port: u16, dial: &Dial) -> Result<TcpStream, Ended> {
    let (sender, receiver) = mpsc::channel();
    let (host, deadline) = (
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        dial.deadline,
    );
    thread::Builder::new()
        .name("herdr-guest-link-dial".into())
        .spawn(move || {
            let _ = sender.send(connect_blocking(&host, port, deadline));
        })
        .map_err(|error| Ended::Failed(format!("relay unreachable: {error}")))?;
    loop {
        if dial.stopped() {
            return Err(Ended::Stopped);
        }
        let Some(left) = dial.left() else {
            return Err(Ended::Failed("relay unreachable: timed out".into()));
        };
        match receiver.recv_timeout(left.min(DIAL_SLICE)) {
            Ok(result) => {
                return result.map_err(|error| Ended::Failed(format!("relay unreachable: {error}")))
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(Ended::Failed("relay unreachable".into()))
            }
        }
    }
}

/// Tries each resolved address within what is left of `deadline`.
pub(super) fn connect_blocking(host: &str, port: u16, deadline: Instant) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "relay host has no address");
    for address in (host, port).to_socket_addrs()? {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        else {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
        };
        match TcpStream::connect_timeout(&address, left) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

type Socket = WebSocket<MaybeTlsStream<RelayStream>>;

pub(super) struct Connection {
    socket: Socket,
    /// A handle on the socket's file description, for polling and shutdown.
    tcp: TcpStream,
    keys: Arc<ResponderKeys>,
}

impl Connection {
    /// Dials the relay and upgrades to this host's authenticated socket. DNS,
    /// every address, TLS and the upgrade share one `handshake_timeout`.
    pub(super) fn open<H: GuestHost>(
        host: &H,
        timing: &Timing,
        signals: &Arc<Signals>,
    ) -> Result<Self, Ended> {
        let failed = |error: String| Ended::Failed(error);
        let dial = Arc::new(Dial {
            deadline: Instant::now() + timing.handshake_timeout,
            signals: Arc::clone(signals),
            done: AtomicBool::new(false),
        });
        let info = host
            .host_info()
            .map_err(|error| failed(format!("guest keys unavailable: {error}")))?;
        let url = host_socket_url(&info.relay_url, &info.host_id).map_err(failed)?;
        let mut request = url
            .into_client_request()
            .map_err(|error| failed(format!("relay_url: {error}")))?;
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", info.relay_secret))
            .map_err(|_| failed("relay secret is not a valid header".into()))?;
        bearer.set_sensitive(true);
        request.headers_mut().insert(header::AUTHORIZATION, bearer);
        let uri = request.uri();
        let secure = uri.scheme_str() == Some("wss");
        let authority = uri.host().unwrap_or_default().to_owned();
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });

        let tcp = connect(&authority, port, &dial)?;
        let handle = tcp
            .set_nodelay(true)
            .and_then(|()| tcp.try_clone())
            .map_err(|error| failed(format!("relay socket: {error}")))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_RELAY_MESSAGE))
            .max_frame_size(Some(MAX_RELAY_MESSAGE))
            .write_buffer_size(WRITE_BUFFER)
            .max_write_buffer_size(MAX_WRITE_BUFFER);
        let connector = if secure {
            tls_connector().map_err(failed)?
        } else {
            Connector::Plain
        };
        let stream = RelayStream {
            tcp,
            dial: Arc::clone(&dial),
        };
        let (socket, _) =
            tungstenite::client_tls_with_config(request, stream, Some(config), Some(connector))
                .map_err(|error| {
                    if dial.stopped() {
                        return Ended::Stopped;
                    }
                    failed(match error {
                        HandshakeError::Failure(tungstenite::Error::Http(response))
                            if response.status() == StatusCode::UNAUTHORIZED =>
                        {
                            "relay rejected host secret".to_owned()
                        }
                        HandshakeError::Failure(tungstenite::Error::Http(response)) => {
                            format!("relay answered HTTP {}", response.status().as_u16())
                        }
                        _ if dial.left().is_none() => "relay handshake timed out".to_owned(),
                        HandshakeError::Failure(error) => format!("relay handshake: {error}"),
                        HandshakeError::Interrupted(_) => "relay handshake interrupted".to_owned(),
                    })
                })?;
        dial.done.store(true, Ordering::Relaxed);
        handle
            .set_nonblocking(true)
            .map_err(|error| failed(format!("relay socket: {error}")))?;
        Ok(Self {
            socket,
            tcp: handle,
            keys: Arc::new(ResponderKeys::new(info.node_secret, &info.host_id)),
        })
    }

    /// Serves guest sessions until the socket ends, the link is stopped, or it
    /// is no longer wanted. Every session ends with the connection.
    pub(super) fn run<H: GuestHost>(
        mut self,
        host: &Arc<H>,
        signals: &Signals,
        wake: &WakeReceiver,
        timing: &Timing,
    ) -> Ended {
        let (outbound_tx, outbound) = mpsc::sync_channel(OUTBOUND_QUEUE);
        let mut sessions = Sessions::new(
            Arc::clone(host),
            Arc::clone(&self.keys),
            outbound_tx,
            signals.waker.clone(),
            timing.handshake_timeout,
        );
        let mut last_pong = Instant::now();
        let mut next_ping = last_pong + timing.ping_interval;
        // The socket holds unsent bytes; wait for it before queueing more.
        let mut blocked = false;
        loop {
            if signals.stopped() {
                self.close(CloseCode::Away, "stopping");
                return Ended::Stopped;
            }
            if signals.take_changed() && !host.link_wanted() {
                self.close(CloseCode::Normal, "no guests");
                return Ended::Unwanted;
            }

            // Every frame, including the host's own CLOSEs, goes out through
            // the bounded queue and only while the socket accepts it.
            let mut moved = 0;
            while !blocked && moved < OUTBOUND_BATCH {
                let message = match outbound.try_recv() {
                    Ok(message) => message,
                    // `sessions` holds a sender, so the queue never disconnects.
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                };
                moved += 1;
                if let Some(frame) = sessions.outbound(message) {
                    blocked = match self.write(frame) {
                        Ok(blocked) => blocked,
                        Err(ended) => return ended,
                    };
                }
            }

            let mut read = 0;
            while read < READ_BATCH {
                let message = match self.socket.read() {
                    Ok(message) => message,
                    Err(tungstenite::Error::Io(error))
                        if error.kind() == io::ErrorKind::WouldBlock =>
                    {
                        break;
                    }
                    Err(error) => return Ended::Failed(format!("relay connection lost: {error}")),
                };
                read += 1;
                match message {
                    Message::Binary(message) => match Frame::decode(message) {
                        Ok(Frame::Open(session)) => sessions.open(session),
                        Ok(Frame::Data(session, payload)) => sessions.data(session, payload),
                        Ok(Frame::Close(session, _)) => sessions.close(session),
                        Err(error) => {
                            self.close(CloseCode::Protocol, "bad frame");
                            return Ended::Failed(format!("relay sent a bad frame: {error}"));
                        }
                    },
                    Message::Text(text) if text.as_str() == "pong" => last_pong = Instant::now(),
                    Message::Pong(_) => last_pong = Instant::now(),
                    Message::Close(frame) => {
                        let _ = self.socket.flush();
                        return match frame {
                            Some(frame) if u16::from(frame.code) == CLOSE_REPLACED => {
                                Ended::Replaced
                            }
                            Some(frame) => Ended::Failed(format!(
                                "relay closed the connection ({} {})",
                                u16::from(frame.code),
                                sanitize_reason(&frame.reason)
                            )),
                            None => Ended::Failed("relay closed the connection".into()),
                        };
                    }
                    _ => debug!("guest link: ignoring an unexpected relay message"),
                }
            }
            // Sends queued frames and any control replies reading queued.
            match self.flush() {
                Ok(still_blocked) => blocked = still_blocked,
                Err(ended) => return ended,
            }

            let now = Instant::now();
            if now.duration_since(last_pong) >= timing.pong_timeout {
                return Ended::Failed("relay stopped answering pings".into());
            }
            if now >= next_ping {
                next_ping = now + timing.ping_interval;
                // Invites expire without a change notification, so re-check on
                // every ping (25 s, within the 60 s the contract allows).
                if !host.link_wanted() {
                    self.close(CloseCode::Normal, "no guests");
                    return Ended::Unwanted;
                }
                // A socket that is still draining skips this ping; the pong
                // timeout catches a relay that stopped reading altogether.
                if !blocked {
                    match self.write_message(Message::text("ping")) {
                        Ok(now_blocked) => blocked = now_blocked,
                        Err(ended) => return ended,
                    }
                }
                continue;
            }
            // More input or output may be waiting; take another turn first.
            if read == READ_BATCH || moved == OUTBOUND_BATCH {
                continue;
            }

            let socket_events = if blocked {
                libc::POLLIN | libc::POLLOUT
            } else {
                libc::POLLIN
            };
            let mut fds = [
                libc::pollfd {
                    fd: self.tcp.as_raw_fd(),
                    events: socket_events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let until = next_ping.min(last_pong + timing.pong_timeout);
            if let Err(error) = poll(&mut fds, until.saturating_duration_since(now)) {
                return Ended::Failed(format!("relay socket poll: {error}"));
            }
            wake.drain();
        }
    }
    /// Queues one frame; `Ok(true)` when the socket could not take it all yet.
    fn write(&mut self, frame: Vec<u8>) -> Result<bool, Ended> {
        self.write_message(Message::Binary(frame.into()))
    }

    fn write_message(&mut self, message: Message) -> Result<bool, Ended> {
        would_block(self.socket.write(message))
    }

    fn flush(&mut self) -> Result<bool, Ended> {
        would_block(self.socket.flush())
    }

    /// Best-effort close handshake; the socket is dropped right after.
    fn close(&mut self, code: CloseCode, reason: &'static str) {
        let _ = self.socket.close(Some(CloseFrame {
            code,
            reason: reason.into(),
        }));
    }
}

fn would_block(result: tungstenite::Result<()>) -> Result<bool, Ended> {
    match result {
        Ok(()) => Ok(false),
        // The frame is queued; the rest goes out when the socket drains.
        Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(tungstenite::Error::WriteBufferFull(_)) => {
            Err(Ended::Failed("relay stopped reading".into()))
        }
        Err(error) => Err(Ended::Failed(format!("relay connection lost: {error}"))),
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }
}
