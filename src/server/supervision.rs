//! Whether this process is the one a service supervisor is watching, and whether that
//! supervisor can follow a live handoff.
//!
//! This exists because of a real incident. `server.apply_staged_update` performs a live
//! handoff: it spawns a replacement, hands over the sockets and PTYs, then the OLD main
//! process exits. That is seamless when herdr owns its own lifetime — and destructive
//! under systemd when systemd is not told about the replacement.
//!
//! A `Type=simple` unit's main process exiting DEACTIVATES the unit, and the default
//! `KillMode=control-group` then kills everything left in the cgroup — including the
//! replacement and every pane it just imported. On this fleet that killed 30 live panes
//! while the API had already answered `ok`, and the panes came back from the session
//! snapshot under the WRONG ACCOUNT, so ~2 hours of work appeared to vanish (it was
//! intact, in the other account's transcript).
//!
//! The handoff cannot detect that from its own success: spawn, import and validation all
//! succeed, and the process is killed a moment later by the supervisor. So the check has
//! to happen BEFORE anything is torn down.
//!
//! A `Type=notify` unit can follow the handoff instead. Once the replacement owns the
//! panes, the OLD process — still the unit's main process, so any `NotifyAccess=` other
//! than `none` accepts it — sends `MAINPID=<replacement>` and waits on `BARRIER=1` until
//! the manager has processed it. Only then does it exit, and its exit is no longer the
//! unit's: the replacement is the main process, the cgroup survives, and `KillMode=`
//! still stops every pane on a real stop. The process that decided the switch was safe is
//! the one that makes it safe, so it never depends on what the new build does.

/// How this process is being supervised, as far as it can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Supervision {
    /// Nothing is watching this process' lifetime; it may hand off and exit freely.
    None,
    /// systemd is watching THIS process as the unit's main process and can't be told
    /// about a replacement. Exiting deactivates the unit and takes the cgroup —
    /// replacement and panes included — down with it.
    SystemdMainProcess,
    /// systemd is watching THIS process as the main process of a `Type=notify` unit that
    /// accepts `MAINPID=` from it: a handoff that moves the main pid first is safe.
    SystemdFollowsMainPid,
}

impl Supervision {
    /// Whether exiting after a handoff would take the replacement down too.
    pub(crate) fn forbids_process_handoff(self) -> bool {
        matches!(self, Self::SystemdMainProcess)
    }

    /// Whether the handoff must move the unit's main pid to the replacement before this
    /// process exits.
    pub(crate) fn hands_over_main_pid(self) -> bool {
        matches!(self, Self::SystemdFollowsMainPid)
    }
}

/// Why a handoff was refused, for every caller that asks for one.
pub(crate) const HANDOFF_REFUSAL: &str = "refusing a live handoff: this process is the main \
     process of a systemd unit that can't follow a replacement (that needs Type=notify and \
     NotifyAccess=main or all), so exiting after the handoff would deactivate the unit and kill \
     the replacement and every pane with it";

/// What the manager reports about the unit this process runs in
/// (`systemctl show -p InvocationID -p MainPID -p Type -p NotifyAccess`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnitProperties {
    pub(crate) invocation_id: String,
    pub(crate) main_pid: Option<u32>,
    pub(crate) service_type: String,
    pub(crate) notify_access: String,
}

/// What the supervisor injected into this process' environment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SystemdEnv<'a> {
    /// `INVOCATION_ID`: set by systemd for every unit it starts.
    pub(crate) invocation_id: Option<&'a str>,
    /// `SYSTEMD_EXEC_PID`: the process systemd started as the unit's main one, or the
    /// replacement that took the main pid over in a handoff (see
    /// [`take_systemd_environment`]).
    pub(crate) exec_pid: Option<&'a str>,
    pub(crate) our_pid: u32,
    /// `NOTIFY_SOCKET` was set, so the unit accepts notifications at all.
    pub(crate) notify_socket: bool,
}

pub(crate) const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";
const EXEC_PID_ENV: &str = "SYSTEMD_EXEC_PID";
/// Set only on a handoff replacement that is to become the unit's main process.
const TAKES_MAIN_PID_ENV: &str = "HERDR_SYSTEMD_TAKES_MAIN_PID";

static NOTIFY_SOCKET: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
    std::env::var(NOTIFY_SOCKET_ENV)
        .ok()
        .filter(|socket| !socket.is_empty())
});

/// Run first thing in a server process, before any thread starts.
///
/// Reads `NOTIFY_SOCKET` once and takes it out of the environment, as `sd_notify` does
/// with `unset_environment`: panes, plugins and the update guard must not inherit the
/// unit's notification socket.
///
/// A handoff replacement that is to become the unit's main process inherited its
/// predecessor's `SYSTEMD_EXEC_PID`, which would read as "a child inside the unit". It
/// names itself instead, exactly as systemd names a process it starts, so it and the
/// panes it spawns see the same main pid systemd will.
pub(crate) fn take_systemd_environment() {
    if notify_socket().is_some() {
        std::env::remove_var(NOTIFY_SOCKET_ENV);
    }
    if std::env::var_os(TAKES_MAIN_PID_ENV).is_some() {
        std::env::remove_var(TAKES_MAIN_PID_ENV);
        std::env::set_var(EXEC_PID_ENV, std::process::id().to_string());
    }
}

/// The unit's notification socket, if the supervisor gave this process one.
pub(crate) fn notify_socket() -> Option<&'static str> {
    NOTIFY_SOCKET.as_deref()
}

/// Give a handoff replacement what it needs to become the unit's main process: the
/// notification socket this process took out of its own environment, and the marker
/// [`take_systemd_environment`] reads. `SYSTEMD_EXEC_PID` names this process, so it is
/// dropped: a build that doesn't know the marker then has no main pid to compare with
/// and fails closed, instead of reading itself as a child whose exit is harmless.
pub(crate) fn prepare_main_pid_successor(command: &mut std::process::Command) {
    if let Some(socket) = notify_socket() {
        command.env(NOTIFY_SOCKET_ENV, socket);
    }
    command.env_remove(EXEC_PID_ENV);
    command.env(TAKES_MAIN_PID_ENV, "1");
}

fn current_env<'a>(
    invocation_id: &'a Option<String>,
    exec_pid: &'a Option<String>,
) -> SystemdEnv<'a> {
    SystemdEnv {
        invocation_id: invocation_id.as_deref(),
        exec_pid: exec_pid.as_deref(),
        our_pid: std::process::id(),
        notify_socket: notify_socket().is_some(),
    }
}

/// Detect supervision from the environment the supervisor injected and, when this is a
/// unit's main process, from the manager itself.
///
/// `SYSTEMD_EXEC_PID` is what makes the first step precise rather than merely cautious.
/// A herdr spawned as a CHILD inside a systemd unit inherits `INVOCATION_ID` but is not
/// the main process, so its exit is harmless — treating it as supervised would block
/// handoffs that are perfectly safe. When systemd is too old to set the pid, fall back to
/// assuming we ARE the main process: refusing a safe handoff costs an operator one manual
/// restart, while allowing an unsafe one costs every live pane.
pub(crate) fn detect() -> Supervision {
    let invocation_id = std::env::var("INVOCATION_ID").ok();
    let exec_pid = std::env::var(EXEC_PID_ENV).ok();
    detect_from(&current_env(&invocation_id, &exec_pid), query_unit)
}

/// The decision, split out from the environment and the manager so it can be tested
/// without either. `query` is asked only when this is the unit's main process.
pub(crate) fn detect_from(
    env: &SystemdEnv<'_>,
    query: impl FnOnce() -> Option<UnitProperties>,
) -> Supervision {
    let Some(invocation_id) = main_process_invocation(env) else {
        return Supervision::None;
    };
    // Without a notification socket nothing can tell systemd about a replacement.
    if !env.notify_socket {
        return Supervision::SystemdMainProcess;
    }
    // FAIL CLOSED from here: anything the manager does not confirm refuses.
    let Some(unit) = query() else {
        return Supervision::SystemdMainProcess;
    };
    let same_unit = unit.invocation_id == invocation_id;
    let we_are_main = unit.main_pid == Some(env.our_pid);
    // `notify-reload` would send SIGHUP on `systemctl reload`, which the server ignores.
    let notify_unit = unit.service_type == "notify";
    // MAINPID= is sent by the main process itself, which `main`, `exec` and `all` accept.
    let accepts_main_pid = matches!(unit.notify_access.as_str(), "main" | "exec" | "all");
    if same_unit && we_are_main && notify_unit && accepts_main_pid {
        Supervision::SystemdFollowsMainPid
    } else {
        Supervision::SystemdMainProcess
    }
}

/// The unit's invocation id when this process' exit would be the unit's exit.
fn main_process_invocation<'a>(env: &SystemdEnv<'a>) -> Option<&'a str> {
    // No unit at all: not supervised.
    let invocation_id = env.invocation_id.filter(|id| !id.is_empty())?;
    match env
        .exec_pid
        .map(str::trim)
        .and_then(|pid| pid.parse::<u32>().ok())
    {
        // Systemd named a main pid and it is not us — we are a child, our exit is our own.
        Some(main_pid) if main_pid != env.our_pid => None,
        // It is us, or systemd did not say: assume our exit is the unit's exit.
        _ => Some(invocation_id),
    }
}

/// Tell a `Type=notify` unit the server is up. Only the main process speaks for the
/// unit, so a herdr started inside some other notify unit stays quiet.
pub(crate) fn notify_ready() {
    let invocation_id = std::env::var("INVOCATION_ID").ok();
    let exec_pid = std::env::var(EXEC_PID_ENV).ok();
    if main_process_invocation(&current_env(&invocation_id, &exec_pid)).is_none() {
        return;
    }
    let Some(socket) = notify_socket() else {
        return;
    };
    if let Err(err) = notify::send(socket, "READY=1") {
        tracing::warn!(%err, "could not tell systemd the server is ready");
    }
}

/// Make `pid` the unit's main process and wait until the manager has processed it, so
/// this process' exit afterwards is no longer the unit's.
pub(crate) fn hand_over_main_pid(pid: u32) -> std::io::Result<()> {
    let socket = notify_socket().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no systemd notification socket",
        )
    })?;
    notify::send(socket, &format!("MAINPID={pid}"))?;
    notify::barrier(socket, MANAGER_TIMEOUT)
}

const MANAGER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The unit named by this process' cgroup, and whether a user manager runs it.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CgroupUnit {
    pub(crate) name: String,
    pub(crate) user_manager: Option<u32>,
}

/// Parse `/proc/self/cgroup`: the unified (`0::`) hierarchy, or systemd's own named
/// one on a legacy or hybrid layout. The unit is the innermost `.service`; a
/// `user@<uid>.service` above it means the user manager of `<uid>` runs it.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unit_from_cgroup(cgroup: &str) -> Option<CgroupUnit> {
    let path = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.contains(".service"))
        .or_else(|| {
            cgroup
                .lines()
                .find_map(|line| line.split_once(":name=systemd:").map(|(_, path)| path))
        })?;
    let components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
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

/// Parse `systemctl show` output (`Key=Value` lines).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_unit_properties(text: &str) -> Option<UnitProperties> {
    let mut invocation_id = None;
    let mut main_pid = None;
    let mut service_type = None;
    let mut notify_access = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "InvocationID" => invocation_id = Some(value.to_string()),
            "MainPID" => main_pid = Some(value.parse::<u32>().ok().filter(|pid| *pid != 0)),
            "Type" => service_type = Some(value.to_string()),
            "NotifyAccess" => notify_access = Some(value.to_string()),
            _ => {}
        }
    }
    Some(UnitProperties {
        invocation_id: invocation_id.filter(|id| !id.is_empty())?,
        main_pid: main_pid?,
        service_type: service_type?,
        notify_access: notify_access?,
    })
}

/// Ask the manager that runs this process' unit for the properties the decision needs.
#[cfg(target_os = "linux")]
fn query_unit() -> Option<UnitProperties> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let unit = unit_from_cgroup(&cgroup)?;
    let mut command = std::process::Command::new("systemctl");
    if let Some(uid) = unit.user_manager {
        // The user manager's private socket lives in its own runtime dir, which a
        // server started with a different XDG_RUNTIME_DIR would otherwise miss.
        command
            .arg("--user")
            .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
    }
    command
        .args(["show", "--no-pager", &unit.name])
        .args([
            "-p",
            "InvocationID",
            "-p",
            "MainPID",
            "-p",
            "Type",
            "-p",
            "NotifyAccess",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().ok()?;
    let deadline = std::time::Instant::now() + MANAGER_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    let mut output = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut output).ok()?;
    let properties = parse_unit_properties(&output);
    if properties.is_none() {
        tracing::warn!(unit = %unit.name, "systemd did not describe the server's unit");
    }
    properties
}

#[cfg(not(target_os = "linux"))]
fn query_unit() -> Option<UnitProperties> {
    None
}

/// The `sd_notify` wire protocol: one datagram per message to `NOTIFY_SOCKET`, and
/// `BARRIER=1` with a pipe the manager closes once it has processed everything before.
#[cfg(target_os = "linux")]
mod notify {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::time::Duration;

    pub(super) fn send(socket: &str, message: &str) -> io::Result<()> {
        send_with_fd(socket, message, None)
    }

    pub(super) fn barrier(socket: &str, timeout: Duration) -> io::Result<()> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` has room for the two descriptors pipe2 writes.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 succeeded, so both descriptors are open and owned here.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        send_with_fd(socket, "BARRIER=1", Some(write.as_raw_fd()))?;
        drop(write);
        let mut poll = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        loop {
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

    fn send_with_fd(socket: &str, message: &str, fd: Option<RawFd>) -> io::Result<()> {
        let (address, address_len) = address(socket)?;
        // SAFETY: plain socket(2) call; the result is checked before use.
        let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket(2) succeeded, so `raw` is an open descriptor owned here.
        let sock = unsafe { OwnedFd::from_raw_fd(raw) };
        let iov = [libc::iovec {
            iov_base: message.as_ptr() as *mut libc::c_void,
            iov_len: message.len(),
        }];
        let fd_bytes = std::mem::size_of::<RawFd>();
        // SAFETY: CMSG_SPACE only computes a size.
        let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }];
        // SAFETY: an all-zero msghdr is a valid empty message.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &address as *const libc::sockaddr_un as *mut libc::c_void;
        msg.msg_namelen = address_len;
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
        // SAFETY: `msg` points at live buffers for the duration of the call.
        if unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
}

#[cfg(not(target_os = "linux"))]
mod notify {
    use std::io;
    use std::time::Duration;

    pub(super) fn send(_socket: &str, _message: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "systemd notifications are only supported on Linux",
        ))
    }

    pub(super) fn barrier(socket: &str, _timeout: Duration) -> io::Result<()> {
        send(socket, "BARRIER=1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(
        invocation_id: Option<&'a str>,
        exec_pid: Option<&'a str>,
        our_pid: u32,
    ) -> SystemdEnv<'a> {
        SystemdEnv {
            invocation_id,
            exec_pid,
            our_pid,
            notify_socket: false,
        }
    }

    fn unit(main_pid: u32, service_type: &str, notify_access: &str) -> UnitProperties {
        UnitProperties {
            invocation_id: "abc123".into(),
            main_pid: Some(main_pid),
            service_type: service_type.into(),
            notify_access: notify_access.into(),
        }
    }

    fn never_asked() -> Option<UnitProperties> {
        panic!("the manager must not be asked")
    }

    #[test]
    fn no_unit_means_unsupervised() {
        assert_eq!(
            detect_from(&env(None, None, 42), never_asked),
            Supervision::None
        );
        assert_eq!(
            detect_from(&env(Some(""), None, 42), never_asked),
            Supervision::None
        );
    }

    /// The incident's exact shape: a `Type=simple` unit's main process. There is no
    /// notification socket, so exiting deactivates the unit and the cgroup kill takes
    /// the replacement and every pane with it.
    #[test]
    fn systemd_main_process_forbids_handoff() {
        let s = detect_from(&env(Some("abc123"), Some("42"), 42), never_asked);
        assert_eq!(s, Supervision::SystemdMainProcess);
        assert!(s.forbids_process_handoff());
        assert!(!s.hands_over_main_pid());
    }

    /// A CHILD inside a systemd unit inherits INVOCATION_ID but is not the main process.
    /// Blocking it would refuse handoffs that are actually safe, so the pid comparison is
    /// what keeps this a guard rather than a blanket ban.
    #[test]
    fn a_child_inside_a_unit_is_not_the_main_process() {
        let s = detect_from(
            &SystemdEnv {
                notify_socket: true,
                ..env(Some("abc123"), Some("42"), 99)
            },
            never_asked,
        );
        assert_eq!(s, Supervision::None);
        assert!(!s.forbids_process_handoff());
        assert!(!s.hands_over_main_pid());
    }

    /// Unparsable or absent main pid under a unit: FAIL CLOSED. Refusing a safe handoff
    /// costs one manual restart; allowing an unsafe one costs every live pane.
    #[test]
    fn an_unknown_main_pid_under_a_unit_fails_closed() {
        assert_eq!(
            detect_from(&env(Some("abc123"), None, 42), never_asked),
            Supervision::SystemdMainProcess
        );
        assert_eq!(
            detect_from(&env(Some("abc123"), Some("not-a-pid"), 42), never_asked),
            Supervision::SystemdMainProcess
        );
    }

    /// The supported shape: the main process of a `Type=notify` unit whose manager
    /// accepts `MAINPID=` from it may hand off, moving the main pid first.
    #[test]
    fn a_notify_unit_follows_the_handoff() {
        for access in ["main", "exec", "all"] {
            let s = detect_from(
                &SystemdEnv {
                    notify_socket: true,
                    ..env(Some("abc123"), Some("42"), 42)
                },
                || Some(unit(42, "notify", access)),
            );
            assert_eq!(
                s,
                Supervision::SystemdFollowsMainPid,
                "NotifyAccess={access}"
            );
            assert!(!s.forbids_process_handoff());
            assert!(s.hands_over_main_pid());
        }
    }

    /// Everything the manager does not confirm keeps today's refusal.
    #[test]
    fn a_unit_that_cannot_follow_keeps_the_refusal() {
        let main = SystemdEnv {
            notify_socket: true,
            ..env(Some("abc123"), Some("42"), 42)
        };
        let refused = [
            ("manager unreachable", None),
            ("Type=simple", Some(unit(42, "simple", "all"))),
            ("Type=notify-reload", Some(unit(42, "notify-reload", "all"))),
            ("NotifyAccess=none", Some(unit(42, "notify", "none"))),
            ("another main pid", Some(unit(7, "notify", "all"))),
            (
                "another unit",
                Some(UnitProperties {
                    invocation_id: "def456".into(),
                    ..unit(42, "notify", "all")
                }),
            ),
        ];
        for (case, properties) in refused {
            assert_eq!(
                detect_from(&main, || properties),
                Supervision::SystemdMainProcess,
                "{case}"
            );
        }
        // No socket: the unit could never hear MAINPID=, so the manager isn't asked.
        assert_eq!(
            detect_from(&env(Some("abc123"), Some("42"), 42), never_asked),
            Supervision::SystemdMainProcess
        );
    }

    /// A replacement that took over the main pid names itself in SYSTEMD_EXEC_PID, but
    /// the manager still decides: only the manager naming it main lets its own next
    /// handoff (an update, or the guard's handoff back) run.
    #[test]
    fn a_replacement_asks_the_manager_whether_it_is_main() {
        let replacement = SystemdEnv {
            notify_socket: true,
            ..env(Some("abc123"), Some("99"), 99)
        };
        assert_eq!(
            detect_from(&replacement, || Some(unit(99, "notify", "main"))),
            Supervision::SystemdFollowsMainPid
        );
        // The predecessor could not move the main pid, so the manager still names it.
        assert_eq!(
            detect_from(&replacement, || Some(unit(42, "notify", "main"))),
            Supervision::SystemdMainProcess
        );
    }

    /// A successor gets the marker and loses its predecessor's SYSTEMD_EXEC_PID, so a
    /// build that ignores the marker fails closed rather than reading itself as a child.
    #[test]
    fn a_main_pid_successor_drops_the_predecessor_pid() {
        let mut command = std::process::Command::new("true");
        command.env(EXEC_PID_ENV, "42");
        prepare_main_pid_successor(&mut command);
        let envs: std::collections::HashMap<_, _> = command.get_envs().collect();
        assert_eq!(
            envs.get(std::ffi::OsStr::new(TAKES_MAIN_PID_ENV)),
            Some(&Some(std::ffi::OsStr::new("1")))
        );
        assert_eq!(envs.get(std::ffi::OsStr::new(EXEC_PID_ENV)), Some(&None));
        assert_eq!(
            detect_from(&env(Some("abc123"), None, 99), never_asked),
            Supervision::SystemdMainProcess
        );
    }

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

    #[test]
    fn systemctl_show_output_parses() {
        let text = "Type=notify\nNotifyAccess=all\nMainPID=4242\nInvocationID=9e2980d4c2cd414d9ce86697755e9d10\n";
        assert_eq!(
            parse_unit_properties(text),
            Some(UnitProperties {
                invocation_id: "9e2980d4c2cd414d9ce86697755e9d10".into(),
                main_pid: Some(4242),
                service_type: "notify".into(),
                notify_access: "all".into(),
            })
        );
        // A stopped unit: no main pid, no invocation.
        assert_eq!(
            parse_unit_properties("Type=notify\nNotifyAccess=all\nMainPID=0\nInvocationID=\n"),
            None
        );
        assert_eq!(
            parse_unit_properties("Type=notify\nNotifyAccess=all\nMainPID=0\nInvocationID=abc\n")
                .and_then(|unit| unit.main_pid),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notifications_reach_the_socket_and_the_barrier_waits_for_its_close() {
        use std::os::unix::net::UnixDatagram;
        let dir = std::env::temp_dir().join(format!("herdr-notify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let manager = UnixDatagram::bind(&path).unwrap();
        let socket = path.to_str().unwrap().to_string();

        notify::send(&socket, "MAINPID=4242").unwrap();
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
        notify::barrier(&socket, std::time::Duration::from_secs(5)).unwrap();
        reader.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
