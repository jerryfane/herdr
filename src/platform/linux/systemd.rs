//! The systemd manager as a Linux process sees it: which unit runs this process (from
//! `/proc/self/cgroup`), what `systemctl show` says about that unit, and the
//! `sd_notify` wire protocol. What to make of the answers is `server::supervision`'s.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// The unit named by this process' cgroup, and whether a user manager runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CgroupUnit {
    name: String,
    user_manager: Option<u32>,
}

/// Parse `/proc/self/cgroup`: the unified (`0::`) hierarchy, or systemd's own named
/// one on a legacy or hybrid layout. The unit is the innermost `.service`; a
/// `user@<uid>.service` above it means the user manager of `<uid>` runs it.
fn unit_from_cgroup(cgroup: &str) -> Option<CgroupUnit> {
    let path = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.contains(".service"))
        .or_else(|| {
            cgroup
                .lines()
                .find_map(|line| line.split_once(":name=systemd:").map(|(_, path)| path))
        })?;
    let components: Vec<&str> = path
        .split('/')
        .filter(|part| !part.is_empty())
        .map(cgroup_unescape)
        .collect();
    let unit_index = components
        .iter()
        .rposition(|part| part.ends_with(".service"))?;
    let user_manager = components[..unit_index].iter().find_map(|part| {
        part.strip_prefix("user@")?
            .strip_suffix(".service")?
            .parse::<u32>()
            .ok()
    });
    Some(CgroupUnit {
        name: components[unit_index].to_string(),
        user_manager,
    })
}

/// systemd's `cg_unescape`: a cgroup component that could clash with a kernel
/// attribute, or starts with `_` or `.`, gets one `_` in front, so the unit
/// `_herdr.service` lives in the cgroup `__herdr.service`.
fn cgroup_unescape(component: &str) -> &str {
    component.strip_prefix('_').unwrap_or(component)
}

/// `systemctl [--user] show --no-pager -p … -- <unit>`. The `--` keeps a unit whose
/// name starts with `-` from reading as an option.
fn show_command(unit: &CgroupUnit, properties: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new("systemctl");
    if let Some(uid) = unit.user_manager {
        // The user manager's private socket lives in its own runtime dir, which a
        // server started with a different XDG_RUNTIME_DIR would otherwise miss.
        command
            .arg("--user")
            .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
    }
    command.args(["show", "--no-pager"]);
    for property in properties {
        command.args(["-p", property]);
    }
    command.args(["--", &unit.name]);
    command
}

/// `systemctl show` output (`Key=Value` lines) for `properties` of the unit this
/// process runs in, from the manager that runs it, or `None` by `deadline`.
pub(crate) fn show_own_systemd_unit(properties: &[&str], deadline: Instant) -> Option<String> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let unit = unit_from_cgroup(&cgroup)?;
    let mut command = show_command(&unit, properties);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().ok()?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let mut output = String::new();
    io::Read::read_to_string(&mut child.stdout.take()?, &mut output).ok()?;
    Some(output)
}

/// Send one `sd_notify` datagram to `socket` by `deadline`.
pub(crate) fn systemd_notify(socket: &str, message: &str, deadline: Instant) -> io::Result<()> {
    send_with_fd(socket, message, None, deadline)
}

/// Send `BARRIER=1` with a pipe the manager closes once it has processed every
/// datagram before it, and wait for that close by `deadline`.
pub(crate) fn systemd_notify_barrier(socket: &str, deadline: Instant) -> io::Result<()> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both descriptors are open and owned here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    send_with_fd(socket, "BARRIER=1", Some(write.as_raw_fd()), deadline)?;
    drop(write);
    let mut poll = libc::pollfd {
        fd: read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let millis = remaining_millis(deadline);
        // SAFETY: `poll` points at one valid pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready > 0 {
            return Ok(());
        }
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "systemd did not confirm the notification in time",
            ));
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// The poll timeout left until `deadline`, at least 0.
fn remaining_millis(deadline: Instant) -> i32 {
    let left = deadline.saturating_duration_since(Instant::now());
    i32::try_from(left.as_millis()).unwrap_or(i32::MAX)
}

/// Non-blocking send, retried while the manager's queue is full until `deadline`.
///
/// The socket is connected so `POLLOUT` waits for room in the manager's queue: on an
/// unconnected datagram socket it reports writable at once and the retry would spin.
fn send_with_fd(
    socket: &str,
    message: &str,
    fd: Option<RawFd>,
    deadline: Instant,
) -> io::Result<()> {
    let (address, address_len) = address(socket)?;
    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket(2) succeeded, so `raw` is an open descriptor owned here.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: `address` is a valid sockaddr_un of `address_len` bytes. Connecting a
    // datagram socket only records the peer; it never blocks.
    let connected = unsafe {
        libc::connect(
            sock.as_raw_fd(),
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            address_len,
        )
    };
    if connected < 0 {
        return Err(io::Error::last_os_error());
    }
    let iov = [libc::iovec {
        iov_base: message.as_ptr() as *mut libc::c_void,
        iov_len: message.len(),
    }];
    let fd_bytes = std::mem::size_of::<RawFd>();
    // SAFETY: CMSG_SPACE only computes a size.
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }];
    // SAFETY: an all-zero msghdr is a valid empty message to the connected peer.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = iov.len() as _;
    if let Some(fd) = fd {
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;
        // SAFETY: the control buffer is CMSG_SPACE(one fd) bytes long, so the first
        // header and its data fit.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(io::Error::other("failed to allocate fd control message"));
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
            std::ptr::copy_nonoverlapping(
                (&fd as *const RawFd).cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                fd_bytes,
            );
        }
    }
    loop {
        // SAFETY: `msg` points at live buffers for the duration of the call.
        let sent = unsafe {
            libc::sendmsg(
                sock.as_raw_fd(),
                &msg,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if sent >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => {}
            _ => return Err(err),
        }
        let millis = remaining_millis(deadline);
        if millis == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "systemd's notification queue stayed full",
            ));
        }
        let mut poll = libc::pollfd {
            fd: sock.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: `poll` points at one valid pollfd. Any wakeup just retries the send.
        unsafe { libc::poll(&mut poll, 1, millis) };
    }
}

/// `NOTIFY_SOCKET` names a filesystem socket (`/…`) or an abstract one (`@…`).
fn address(socket: &str) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = socket.as_bytes();
    let (prefix, path) = match bytes.first() {
        Some(b'/') => (0, bytes),
        Some(b'@') => (1, &bytes[1..]),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported systemd notification socket {socket:?}"),
            ))
        }
    };
    // SAFETY: an all-zero sockaddr_un is valid; the family and path are set below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // Room for the abstract prefix or the filesystem path's terminating NUL.
    if path.len() + 1 > address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "systemd notification socket path is too long",
        ));
    }
    for (slot, byte) in address.sun_path[prefix..].iter_mut().zip(path) {
        *slot = *byte as libc::c_char;
    }
    let path_offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    // A filesystem path counts its NUL; an abstract name counts its leading NUL.
    let len = path_offset + path.len() + 1;
    Ok((address, len as libc::socklen_t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn the_unit_comes_from_the_innermost_service_cgroup() {
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-0.slice/user@0.service/app.slice/herdr.service\n"
            ),
            Some(CgroupUnit {
                name: "herdr.service".into(),
                user_manager: Some(0),
            })
        );
        assert_eq!(
            unit_from_cgroup("0::/system.slice/herdr.service\n"),
            Some(CgroupUnit {
                name: "herdr.service".into(),
                user_manager: None,
            })
        );
        assert_eq!(
            unit_from_cgroup(
                "12:pids:/user.slice\n1:name=systemd:/user.slice/user-1000.slice/user@1000.service/app.slice/run-u7.service\n0::/\n"
            ),
            Some(CgroupUnit {
                name: "run-u7.service".into(),
                user_manager: Some(1000),
            })
        );
        assert_eq!(
            unit_from_cgroup("0::/user.slice/user-0.slice/session-3.scope\n"),
            None
        );
    }

    /// systemd escapes a cgroup component that starts with `_` by putting one more
    /// `_` in front: the unit `_herdr.service` runs in `__herdr.service`.
    #[test]
    fn an_escaped_cgroup_component_names_the_unescaped_unit() {
        assert_eq!(
            unit_from_cgroup("0::/system.slice/__herdr.service\n"),
            Some(CgroupUnit {
                name: "_herdr.service".into(),
                user_manager: None,
            })
        );
        assert_eq!(
            unit_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/__herdr.service\n"
            ),
            Some(CgroupUnit {
                name: "_herdr.service".into(),
                user_manager: Some(1000),
            })
        );
    }

    /// A unit name is an operand, never an option: `-herdr.service` is a valid unit,
    /// and without `--` systemctl reads it as flags and prints its help.
    #[test]
    fn systemctl_gets_the_unit_after_the_end_of_options() {
        let unit = CgroupUnit {
            name: "-herdr.service".into(),
            user_manager: Some(1000),
        };
        let command = show_command(&unit, &["MainPID", "Type"]);
        assert_eq!(command.get_program(), "systemctl");
        let args: Vec<&std::ffi::OsStr> = command.get_args().collect();
        assert_eq!(
            args,
            [
                "--user",
                "show",
                "--no-pager",
                "-p",
                "MainPID",
                "-p",
                "Type",
                "--",
                "-herdr.service"
            ]
        );
    }

    fn scratch_socket(name: &str) -> (std::path::PathBuf, UnixDatagram, String) {
        let dir = std::env::temp_dir().join(format!("herdr-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let manager = UnixDatagram::bind(&path).unwrap();
        let socket = path.to_str().unwrap().to_string();
        (dir, manager, socket)
    }

    #[test]
    fn notifications_reach_the_socket_and_the_barrier_waits_for_its_close() {
        let (dir, manager, socket) = scratch_socket("notify");
        let deadline = Instant::now() + Duration::from_secs(5);
        systemd_notify(&socket, "MAINPID=4242", deadline).unwrap();
        let mut buf = [0u8; 64];
        let len = manager.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"MAINPID=4242");

        // The manager closes the barrier fd as soon as it has read the datagram; the
        // fd arrives as SCM_RIGHTS, and dropping the receiving socket closes it.
        let reader = std::thread::spawn(move || {
            let len = manager.recv(&mut buf).unwrap();
            assert_eq!(&buf[..len], b"BARRIER=1");
            drop(manager);
        });
        systemd_notify_barrier(&socket, deadline).unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F3: a manager that stopped reading can't hold the server past the deadline,
    /// the sends included.
    #[test]
    fn a_full_notification_queue_fails_by_the_deadline() {
        let (dir, _manager, socket) = scratch_socket("notify-full");
        // One sender runs out of its own send buffer before the manager's queue is
        // full, so keep adding senders until a fresh one can't send either.
        let mut fillers = Vec::new();
        loop {
            let filler = UnixDatagram::unbound().unwrap();
            filler.set_nonblocking(true).unwrap();
            let mut sent = 0;
            while filler.send_to(b"X=1", &socket).is_ok() {
                sent += 1;
            }
            fillers.push(filler);
            if sent == 0 {
                break;
            }
        }

        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(300);
            let sent = systemd_notify(&socket, "MAINPID=4242", deadline);
            let barrier = systemd_notify_barrier(&socket, deadline);
            let _ = done.send((sent, barrier));
        });
        let (sent, barrier) = finished
            .recv_timeout(Duration::from_secs(2))
            .expect("a full notification queue held the sender past its deadline");
        assert_eq!(sent.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(barrier.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
