//! Unix transport for `herdr api-bridge` (see `api_bridge`): a Unix socket
//! connection to the API, `shutdown(2)` to end its reads from another
//! thread, and `poll(2)` on stdout to notice the SSH channel going away.

use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;

pub(super) type Connection = UnixStream;

pub(super) fn connect(socket_path: &Path) -> io::Result<Connection> {
    UnixStream::connect(socket_path)
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
