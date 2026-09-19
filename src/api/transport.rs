//! Transport abstraction for local and federation TCP API connections.
//!
//! Saved-machine SSH routes terminate in a shared local `remote-api-bridge`, so
//! this layer only carries local sockets and TCP streams.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use interprocess::local_socket::traits::Stream as _;

use crate::ipc::{
    is_connection_closed_error, local_stream_peer_closed, poll_local_stream_read_count,
    set_local_stream_polling, LocalStream, LocalStreamReadCount,
};

/// One API connection over a local socket or federation TCP stream.
pub(crate) enum ApiStream {
    Local(LocalStream),
    Tcp(TcpStream),
}

/// Result of a single non-blocking [`ApiStream::poll_read`].
///
/// The `Data` byte count is consumed by the TCP read path (and the unit test);
/// the local initial-request reader only distinguishes the variants.
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
        }
    }
}

impl Write for ApiStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ApiStream::Local(stream) => stream.write(buf),
            ApiStream::Tcp(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => stream.flush(),
            ApiStream::Tcp(stream) => stream.flush(),
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
        }
    }

    /// Bound the time a blocking read may take. Returning `Unsupported` lets the
    /// framed-read helpers fall back to non-blocking polling.
    pub(crate) fn set_recv_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => stream.set_recv_timeout(dur),
            ApiStream::Tcp(stream) => stream.set_read_timeout(dur),
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
        }
    }

    /// Put the underlying stream into (non-)blocking mode. Unlike
    /// [`set_polling`](Self::set_polling) this is a real toggle on every
    /// platform, matching the framed-read helpers' expectation.
    pub(crate) fn set_nonblocking(&mut self, enabled: bool) -> io::Result<()> {
        match self {
            ApiStream::Local(stream) => stream.set_nonblocking(enabled),
            ApiStream::Tcp(stream) => stream.set_nonblocking(enabled),
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
        }
    }

    /// Non-destructively check whether the peer has closed the connection.
    pub(crate) fn peer_closed(&mut self) -> io::Result<bool> {
        match self {
            ApiStream::Local(stream) => local_stream_peer_closed(stream),
            ApiStream::Tcp(stream) => tcp_peer_closed(stream),
        }
    }
}

/// Map a single non-blocking `read` into an [`ApiStreamRead`]. The stream must
/// already be non-blocking.
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
