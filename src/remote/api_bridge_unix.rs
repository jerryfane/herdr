//! Unix transport for `herdr api-bridge` (see `api_bridge`): a Unix socket
//! connection to the API, `shutdown(2)` to end its reads from another
//! thread, and `poll(2)` on stdout to notice the SSH channel going away.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;

use super::api_bridge::CONNECT_RETRY_INTERVAL;

pub(super) type Connection = UnixStream;

/// Connects to the API socket, retrying while its listen backlog is full,
/// until `stop` says the request no longer needs it (cancelled, or output
/// gone). Checks `stop` before the first attempt.
pub(super) fn connect(socket_path: &Path, stop: impl Fn() -> bool) -> io::Result<Connection> {
    connect_with(stop, || try_connect(socket_path))
}

/// [`connect`]'s retry loop over any `attempt` (`Ok(None)`: try again).
fn connect_with(
    stop: impl Fn() -> bool,
    mut attempt: impl FnMut() -> io::Result<Option<Connection>>,
) -> io::Result<Connection> {
    loop {
        if stop() {
            return Err(super::api_bridge::connect_stopped());
        }
        if let Some(conn) = attempt()? {
            return Ok(conn);
        }
        thread::sleep(CONNECT_RETRY_INTERVAL);
    }
}

/// One non-blocking connect: `None` while the listen backlog is full
/// (`EAGAIN`), otherwise a blocking stream. A blocking `connect(2)` would
/// wait for a free slot with no way to stop it.
pub(super) fn try_connect(socket_path: &Path) -> io::Result<Option<UnixStream>> {
    // SAFETY: plain libc calls on a zeroed `sockaddr_un` and a socket this
    // function owns from creation (`OwnedFd` closes it on every path).
    unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path = socket_path.as_os_str().as_bytes();
        if path.len() >= addr.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "api-bridge: socket path too long",
            ));
        }
        for (dst, src) in addr.sun_path.iter_mut().zip(path) {
            *dst = *src as libc::c_char;
        }
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let raw = fd.as_raw_fd();
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags < 0
            || libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) < 0
            || libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
        {
            return Err(io::Error::last_os_error());
        }
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if libc::connect(raw, std::ptr::addr_of!(addr).cast(), len) < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EAGAIN) => Ok(None),
                Some(libc::EINTR) => Ok(None),
                _ => Err(err),
            };
        }
        if libc::fcntl(raw, libc::F_SETFL, flags) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(UnixStream::from(fd)))
    }
}

/// Ends a connection from any thread: its blocked or later reads return end
/// of file and its writes fail.
pub(super) struct ConnectionShutdown(UnixStream);

impl ConnectionShutdown {
    pub(super) fn new(conn: &Connection) -> io::Result<Self> {
        conn.try_clone().map(Self)
    }

    pub(super) fn shut_down(&self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// Returns once stdout loses its peer (or polling it fails).
pub(super) fn wait_for_output_hangup() {
    let mut poll_fd = libc::pollfd {
        fd: io::stdout().as_raw_fd(),
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    /// A connect that never gets a slot stops once `stop` says so, on any
    /// unix: it does not depend on how the platform fills a listen backlog.
    #[test]
    fn connect_that_never_gets_a_slot_ends_when_stopped() {
        let stopped = AtomicBool::new(false);
        let attempts = AtomicUsize::new(0);
        let started = Instant::now();
        let err = thread::scope(|scope| {
            let waiting = scope.spawn(|| {
                connect_with(
                    || stopped.load(Ordering::SeqCst),
                    || {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Ok(None)
                    },
                )
            });
            while attempts.load(Ordering::SeqCst) < 3 {
                thread::sleep(Duration::from_millis(5));
            }
            stopped.store(true, Ordering::SeqCst);
            waiting.join().unwrap()
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn connect_stopped_up_front_never_attempts() {
        let err = connect_with(|| true, || panic!("no attempt after stop")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }
}
