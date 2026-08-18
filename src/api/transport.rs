//! Transport abstraction for the JSON API connection.
//!
//! Today every API connection is a local unix-socket / named-pipe
//! [`LocalStream`]. This enum lets the API server/handlers carry that concrete
//! stream behind a single type so later federation parts can serve the same
//! JSON protocol over a TCP socket or an SSH-tunneled child process without
//! touching the request-handling code.
//!
//! [`ApiStream::Local`] is built by the local unix-socket server and client;
//! [`ApiStream::Tcp`] by the federation TCP listener ([`crate::api::server`])
//! and TCP client; [`ApiStream::Ssh`] by the outbound SSH client
//! ([`crate::api::ssh_transport`]).
//!
//! The `Local` variant delegates every operation to the exact same `crate::ipc`
//! functions and stream methods used before this abstraction existed, so the
//! local path stays byte-identical.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use interprocess::local_socket::traits::Stream as _;

use crate::ipc::{
    is_connection_closed_error, local_stream_peer_closed, poll_local_stream_read_count,
    set_local_stream_polling, LocalStream, LocalStreamReadCount,
};

/// A duplex pipe pair to an SSH child process running `herdr api-bridge`.
///
/// Built by [`crate::api::ssh_transport`], which spawns the child with the
/// request already embedded (base64 argv or piped stdin) and hands the child's
/// stdin/stdout here. Holding `child` keeps the process alive for the lifetime
/// of the stream; dropping the pipe closes both fds so the remote bridge exits.
pub(crate) struct SshPipe {
    // Retained so the pipe write half stays open for the child's lifetime even
    // when the request was delivered as an argv argument (nothing is written to
    // stdin in that form; the bridge tears down on stdout hangup).
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    // Owned so the child is not reaped while the stream is still in use.
    #[allow(dead_code)] // Held for its Drop, not read.
    child: std::process::Child,
}

impl SshPipe {
    pub(crate) fn new(
        stdin: std::process::ChildStdin,
        stdout: std::process::ChildStdout,
        child: std::process::Child,
    ) -> Self {
        Self {
            stdin,
            stdout,
            child,
        }
    }
}

/// One API connection, over any supported transport.
///
/// `Local` is the local unix-socket / named-pipe stream, `Tcp` a federation TCP
/// connection, and `Ssh` an outbound `herdr api-bridge` child over SSH.
pub(crate) enum ApiStream {
    Local(LocalStream),
    Tcp(TcpStream),
    Ssh(SshPipe),
}

/// Result of a single non-blocking [`ApiStream::poll_read`].
///
/// The `Data` byte count is consumed by the TCP/SSH read paths (and the unit
/// test); the local initial-request reader only distinguishes the variants, so
/// the field can read as unused in a local-only build.
#[allow(dead_code)]
pub(crate) enum ApiStreamRead {
    /// `n` bytes were read into the buffer.
    Data(usize),
    /// No data is available yet; the connection is still open.
    Pending,
    /// The peer closed the connection.
    Closed,
}

impl Read for ApiStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ApiStream::Local(stream) => stream.read(buf),
            ApiStream::Tcp(stream) => stream.read(buf),
            ApiStream::Ssh(pipe) => pipe.stdout.read(buf),
        }
    }
}

impl Write for ApiStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ApiStream::Local(stream) => stream.write(buf),
            ApiStream::Tcp(stream) => stream.write(buf),
            ApiStream::Ssh(pipe) => pipe.stdin.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => stream.flush(),
            ApiStream::Tcp(stream) => stream.flush(),
            ApiStream::Ssh(pipe) => pipe.stdin.flush(),
        }
    }
}

impl ApiStream {
    /// Bound the time a blocking write may take before failing. Mirrors the
    /// connection-wide send timeout the API server sets on accept.
    pub(crate) fn set_send_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => stream.set_send_timeout(dur),
            ApiStream::Tcp(stream) => stream.set_write_timeout(dur),
            // SSH write timeouts are handled by the tunnel in a later part.
            ApiStream::Ssh(_) => Ok(()),
        }
    }

    /// Bound the time a blocking read may take. Returning `Unsupported` lets the
    /// framed-read helpers fall back to non-blocking polling.
    pub(crate) fn set_recv_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => stream.set_recv_timeout(dur),
            ApiStream::Tcp(stream) => stream.set_read_timeout(dur),
            // SSH read timeouts land with the SSH client in a later part.
            ApiStream::Ssh(_) => Ok(()),
        }
    }

    /// Toggle non-blocking mode for the [`poll_read`](Self::poll_read) loop.
    ///
    /// The `Local` variant routes through the same `crate::ipc` helper as before
    /// (a no-op on Windows named pipes), which is intentionally distinct from
    /// [`set_nonblocking`](Self::set_nonblocking).
    pub(crate) fn set_polling(&mut self, enabled: bool) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => set_local_stream_polling(stream, enabled),
            ApiStream::Tcp(stream) => stream.set_nonblocking(enabled),
            // SSH pipe polling lands with the SSH client in a later part.
            ApiStream::Ssh(_) => Ok(()),
        }
    }

    /// Put the underlying stream into (non-)blocking mode. Unlike
    /// [`set_polling`](Self::set_polling) this is a real toggle on every
    /// platform, matching the framed-read helpers' expectation.
    pub(crate) fn set_nonblocking(&mut self, enabled: bool) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => stream.set_nonblocking(enabled),
            ApiStream::Tcp(stream) => stream.set_nonblocking(enabled),
            // SSH pipe non-blocking mode lands with the SSH client in a later part.
            ApiStream::Ssh(_) => Ok(()),
        }
    }

    /// Attempt one non-blocking read. The caller must have enabled polling /
    /// non-blocking mode first.
    pub(crate) fn poll_read(&mut self, buf: &mut [u8]) -> io::Result<ApiStreamRead> {
        match self {
            ApiStream::Local(stream) => match poll_local_stream_read_count(stream, buf)? {
                LocalStreamReadCount::Data(read) => Ok(ApiStreamRead::Data(read)),
                LocalStreamReadCount::Pending => Ok(ApiStreamRead::Pending),
                LocalStreamReadCount::Closed => Ok(ApiStreamRead::Closed),
            },
            ApiStream::Tcp(stream) => poll_read_generic(stream, buf),
            ApiStream::Ssh(pipe) => poll_read_generic(&mut pipe.stdout, buf),
        }
    }

    /// Non-destructively check whether the peer has closed the connection.
    pub(crate) fn peer_closed(&mut self) -> io::Result<bool> {
        match self {
            ApiStream::Local(stream) => local_stream_peer_closed(stream),
            ApiStream::Tcp(stream) => tcp_peer_closed(stream),
            // Peeking a pipe without consuming input is not reliable; treat SSH
            // liveness as unknown-open until the SSH client wires this up.
            ApiStream::Ssh(_) => Ok(false),
        }
    }
}

/// Map a single non-blocking `read` into an [`ApiStreamRead`]. Shared by the
/// `Tcp` and `Ssh` variants; the stream must already be non-blocking.
fn poll_read_generic<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<ApiStreamRead> {
    match reader.read(buf) {
        Ok(0) => Ok(ApiStreamRead::Closed),
        Ok(read) => Ok(ApiStreamRead::Data(read)),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(ApiStreamRead::Pending),
        Err(err) if is_connection_closed_error(&err) => Ok(ApiStreamRead::Closed),
        Err(err) => Err(err),
    }
}

/// Non-destructive close probe for a TCP peer, analogous to `probe_stream_closed`
/// in `ipc.rs` but using `peek` so no request byte is consumed.
fn tcp_peer_closed(stream: &mut TcpStream) -> io::Result<bool> {
    stream.set_nonblocking(true)?;
    let mut probe = [0u8; 1];
    let status = match stream.peek(&mut probe) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(err) if is_connection_closed_error(&err) => Ok(true),
        Err(err) => Err(err),
    };
    stream.set_nonblocking(false)?;
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn tcp_api_stream_round_trips_a_line_and_detects_close() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let mut client = TcpStream::connect(addr).expect("connect client");
        let (server, _peer) = listener.accept().expect("accept server side");
        let mut server = ApiStream::Tcp(server);

        // Client writes one NDJSON line.
        let line = b"{\"id\":\"tcp_1\",\"method\":\"ping\"}\n";
        client.write_all(line).expect("client write");
        client.flush().expect("client flush");

        // Server reads it back via poll_read (non-blocking).
        server.set_polling(true).expect("enable polling");
        let mut buf = [0u8; 64];
        let read = loop {
            match server.poll_read(&mut buf).expect("poll_read") {
                ApiStreamRead::Data(read) => break read,
                ApiStreamRead::Pending => std::thread::sleep(Duration::from_millis(5)),
                ApiStreamRead::Closed => panic!("stream closed before data arrived"),
            }
        };
        assert_eq!(&buf[..read], line);

        // While the client is alive, the peer is not closed.
        assert!(!server.peer_closed().expect("peer_closed while open"));

        // Drop the client; poll_read must report Closed and peer_closed true.
        drop(client);
        server.set_polling(true).expect("re-enable polling");
        loop {
            match server.poll_read(&mut buf).expect("poll_read after close") {
                ApiStreamRead::Closed => break,
                ApiStreamRead::Pending => std::thread::sleep(Duration::from_millis(5)),
                ApiStreamRead::Data(0) => break,
                ApiStreamRead::Data(_) => {
                    // Any buffered bytes drain first; keep reading until EOF.
                }
            }
        }
        assert!(server.peer_closed().expect("peer_closed after drop"));
    }
}
