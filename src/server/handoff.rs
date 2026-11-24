#[cfg(unix)]
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, Command};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tracing::{info, warn};

#[cfg(unix)]
const HANDOFF_VERSION: u32 = 1;
#[cfg(unix)]
const READY_TIMEOUT: Duration = Duration::from_secs(30);
// Descriptors are transferred in batches of this size. A single SCM_RIGHTS
// control message caps out at 253 descriptors on Linux and 254 on macOS, so the
// batch stays well below both limits and the number of panes stays unbounded.
#[cfg(unix)]
const FDS_PER_MESSAGE: usize = 64;
#[cfg(unix)]
pub(crate) const MAX_REPLAY_BYTES_PER_PANE: usize = 8 * 1024;
#[cfg(unix)]
pub(crate) const COMMIT_TIMEOUT: Duration = READY_TIMEOUT;

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
pub(crate) struct HandoffManifest {
    pub version: u32,
    pub source_version: String,
    pub source_protocol: u32,
    pub expected_version: Option<String>,
    pub expected_protocol: Option<u32>,
    pub snapshot: crate::persist::SessionSnapshot,
    pub panes: Vec<crate::handoff_runtime::HandoffRuntimeState>,
    /// An outer window title set over the API outlives the server that took the
    /// call, so a handoff carries it rather than falling back to the config.
    /// Absent from manifests written before this field existed.
    #[serde(default)]
    pub api_window_title: Option<String>,
    /// A host restart or shutdown announced to the old server but not yet
    /// committed. Absent from manifests written before this field existed.
    #[serde(default)]
    pub host_shutdown_intent: Option<crate::platform::HostShutdownIntent>,
}

#[cfg(unix)]
pub(crate) struct ReceivedHandoff {
    pub manifest: HandoffManifest,
    pub fds: Vec<RawFd>,
    pub stream: UnixStream,
}

#[cfg(unix)]
pub(crate) fn handoff_socket_path() -> PathBuf {
    crate::session::data_dir().join(format!("herdr-handoff-{}.sock", std::process::id()))
}

/// `hand_over_main_pid`: the replacement will become the systemd unit's main
/// process once it owns the panes.
#[cfg(unix)]
pub(crate) fn spawn_handoff_import(
    import_exe: Option<&Path>,
    socket_path: &Path,
    token: &str,
    hand_over_main_pid: bool,
) -> io::Result<Child> {
    let fallback_exe;
    let exe = if let Some(import_exe) = import_exe {
        import_exe
    } else {
        fallback_exe = std::env::current_exe().map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to determine herdr executable path: {err}"),
            )
        })?;
        &fallback_exe
    };
    let mut command = Command::new(exe);
    command
        .arg("server")
        .arg("--handoff-import")
        .arg(socket_path)
        .arg(token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if crate::session::explicit_session_requested() {
        // The import child no longer has the original `--session` argument, so
        // stale socket overrides must not mask the inherited HERDR_SESSION.
        command
            .env_remove(crate::api::SOCKET_PATH_ENV_VAR)
            .env_remove(crate::server::socket_paths::CLIENT_SOCKET_PATH_ENV_VAR);
    }
    if hand_over_main_pid {
        crate::server::supervision::prepare_main_pid_successor(&mut command);
    }
    crate::platform::detach_server_daemon_command(&mut command);
    command.spawn().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to spawn handoff import server at {}: {err}",
                exe.display()
            ),
        )
    })
}

#[cfg(unix)]
pub(crate) fn cleanup_failed_import_child(child: &mut Child) {
    let pid = child.id();
    match child.try_wait() {
        Ok(Some(status)) => {
            info!(pid, status = %status, "handoff import server exited during rollback");
            return;
        }
        Ok(None) => {}
        Err(err) => {
            warn!(pid, err = %err, "failed to inspect handoff import server before rollback");
        }
    }

    if let Err(err) = child.kill() {
        warn!(pid, err = %err, "failed to kill handoff import server during rollback");
    }
    match child.wait() {
        Ok(status) => {
            info!(pid, status = %status, "handoff import server reaped during rollback");
        }
        Err(err) => {
            warn!(pid, err = %err, "failed to reap handoff import server during rollback");
        }
    }
}

#[cfg(unix)]
pub(crate) fn bind_listener(socket_path: &Path) -> io::Result<UnixListener> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    listener.set_nonblocking(true)?;
    restrict_socket_permissions(socket_path)?;
    Ok(listener)
}

#[cfg(unix)]
pub(crate) fn accept_and_validate_on(
    listener: UnixListener,
    socket_path: &Path,
    token: &str,
    import_pid: u32,
    manifest: &HandoffManifest,
) -> io::Result<UnixStream> {
    let (mut stream, _) = accept_with_timeout(&listener, READY_TIMEOUT)?;
    // The token is in the importer's argv, which any process of the same user can
    // read from /proc. Only the importer this server spawned may receive the pane
    // fds (docs/next/design/pane-fence.md, B22).
    let peer = crate::platform::unix_stream_peer_pid(&stream);
    if peer != Some(import_pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("handoff socket peer {peer:?} is not the import server {import_pid}"),
        ));
    }
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(READY_TIMEOUT))?;
    stream.set_write_timeout(Some(READY_TIMEOUT))?;
    let token_line = read_line_unbuffered(&mut stream)?;
    if token_line.trim_end() != token {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "handoff import token mismatch",
        ));
    }

    serde_json::to_writer(&mut stream, manifest).map_err(io::Error::other)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    stream.set_read_timeout(Some(READY_TIMEOUT))?;
    let validated = read_line_unbuffered(&mut stream)?;
    if validated.trim_end() != "validated" {
        return Err(io::Error::other("handoff import did not validate manifest"));
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(stream)
}

#[cfg(unix)]
pub(crate) fn send_fds_and_wait_restored(stream: &mut UnixStream, fds: &[RawFd]) -> io::Result<()> {
    send_fds(stream, fds)?;

    stream.set_read_timeout(Some(READY_TIMEOUT))?;
    let restored = read_line_unbuffered(&mut *stream)?;
    if restored.trim_end() != "restored" {
        return Err(io::Error::other(
            "handoff import did not report restored runtimes",
        ));
    }
    Ok(())
}

/// What an import server says it can do, on its `ready` line after the word
/// `ready`: it hands a systemd unit's main pid back if the commit never comes
/// (`supervision::release_main_pid_after_lost_commit`).
///
/// Only an importer told to take the main pid over (`HERDR_SYSTEMD_TAKES_MAIN_PID`,
/// which only a server with this check sets) sends it, so an older server, which
/// wants the line to be exactly `ready`, never sees it. A newer server ignores
/// words it doesn't know.
#[cfg(unix)]
pub(crate) const MAIN_PID_RECOVERY: &str = "main-pid-recovery";

#[cfg(unix)]
/// An import server's `ready` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ready {
    pub(crate) main_pid_recovery: bool,
}

#[cfg(unix)]
/// `ready`, then words naming what the importer supports; unknown words are ignored.
pub(crate) fn parse_ready(line: &str) -> Option<Ready> {
    let mut words = line.split_whitespace();
    (words.next()? == "ready").then_some(())?;
    Some(Ready {
        main_pid_recovery: words.any(|word| word == MAIN_PID_RECOVERY),
    })
}

#[cfg(unix)]
pub(crate) fn wait_ready(stream: &mut UnixStream) -> io::Result<Ready> {
    stream.set_read_timeout(Some(READY_TIMEOUT))?;
    let ready = read_line_unbuffered(&mut *stream)?;
    parse_ready(&ready).ok_or_else(|| io::Error::other("handoff import did not report ready"))
}

/// The old server's commit point: once this write succeeds the importer has the
/// commit, and it takes the panes whether or not its read of it fails later
/// ([`wait_committed_within`]).
#[cfg(unix)]
pub(crate) fn report_committed(stream: &mut UnixStream) -> io::Result<()> {
    stream.write_all(b"committed\n")?;
    stream.flush()
}

/// Run by the old server after the commit, while it still holds every pane: wait for
/// the importer's `owned`.
///
/// `Err` only when the importer closed the handoff stream without saying `owned`: it
/// found the commit lost and is giving the panes up, or it died. Then nobody else
/// serves the panes, so the old server must keep them. Any other outcome (`owned`, a
/// line it doesn't know, no answer by `timeout`) leaves an importer that still holds
/// the stream and has the commit, and it owns the panes from here.
#[cfg(unix)]
pub(crate) fn wait_owned_ack(stream: &mut UnixStream, timeout: Duration) -> io::Result<()> {
    if let Err(err) = stream.set_read_timeout(Some(timeout)) {
        // The stream keeps the timeout of the earlier steps.
        warn!(err = %err, "failed to set handoff ownership ack timeout");
    }
    match read_line_unbuffered(&mut *stream) {
        Ok(owned) if owned.trim_end() == "owned" => Ok(()),
        Ok(other) => {
            warn!(
                response = %other.trim_end(),
                "handoff import sent unexpected ownership ack after commit"
            );
            Ok(())
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ) =>
        {
            Err(io::Error::new(
                err.kind(),
                format!("the handoff import server let go of the panes after the commit: {err}"),
            ))
        }
        Err(err) => {
            warn!(
                err = %err,
                "handoff import ownership ack was not received after commit; the import server holds the commit and owns the panes"
            );
            Ok(())
        }
    }
}

#[cfg(unix)]
pub(crate) fn receive(socket_path: &Path, token: &str) -> io::Result<ReceivedHandoff> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(token.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let manifest_line = read_line_unbuffered(&mut stream)?;
    let manifest: HandoffManifest =
        serde_json::from_str(&manifest_line).map_err(io::Error::other)?;
    if manifest.version != HANDOFF_VERSION {
        return Err(io::Error::other(format!(
            "unsupported handoff version {}",
            manifest.version
        )));
    }
    if manifest
        .expected_protocol
        .is_some_and(|protocol| protocol != crate::protocol::PROTOCOL_VERSION)
    {
        return Err(io::Error::other(format!(
            "handoff expected protocol {}, but this server speaks protocol {}",
            manifest.expected_protocol.unwrap_or_default(),
            crate::protocol::PROTOCOL_VERSION
        )));
    }
    if manifest
        .expected_version
        .as_deref()
        .is_some_and(|version| version != crate::build_info::version())
    {
        return Err(io::Error::other(format!(
            "handoff expected herdr v{}, but this server is v{}",
            manifest.expected_version.as_deref().unwrap_or("unknown"),
            crate::build_info::version()
        )));
    }
    stream.write_all(b"validated\n")?;
    stream.flush()?;
    let fds = recv_fds(&stream, manifest.panes.len())?;
    Ok(ReceivedHandoff {
        manifest,
        fds,
        stream,
    })
}

#[cfg(unix)]
pub(crate) fn report_restored(stream: &mut UnixStream) -> io::Result<()> {
    stream.write_all(b"restored\n")?;
    stream.flush()
}

#[cfg(unix)]
pub(crate) fn report_ready(stream: &mut UnixStream, main_pid_recovery: bool) -> io::Result<()> {
    if main_pid_recovery {
        stream.write_all(format!("ready {MAIN_PID_RECOVERY}\n").as_bytes())?;
    } else {
        stream.write_all(b"ready\n")?;
    }
    stream.flush()
}

/// Run by the import server once it reported `ready`: wait for the old server's
/// `committed`. `Ok` means this process owns the panes.
///
/// Its verdict must be the old server's, or both give the panes up. A signal never ends
/// the wait ([`read_line_into`]), and before it gives up for any other reason (no
/// `committed` by `timeout`, the stream ending) the stream is closed for reading: a
/// `committed` the old server wrote before that is still read and taken, and one it
/// writes after fails, so the old server rolls back and keeps the panes.
#[cfg(unix)]
pub(crate) fn wait_committed(stream: &mut UnixStream) -> io::Result<()> {
    wait_committed_within(stream, COMMIT_TIMEOUT)
}

#[cfg(unix)]
pub(crate) fn wait_committed_within(stream: &mut UnixStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    let mut line = Vec::new();
    if let Err(err) = read_line_into(stream, &mut line) {
        if let Err(fence) = stream.shutdown(std::net::Shutdown::Read) {
            return Err(io::Error::new(
                err.kind(),
                format!("{err}; closing the handoff stream for reading failed: {fence}"),
            ));
        }
        // Closed for reading, the stream gives what is queued, then its end.
        if read_line_into(stream, &mut line).is_err() {
            return Err(err);
        }
    }
    if String::from_utf8_lossy(&line).trim_end() != "committed" {
        return Err(io::Error::other("handoff source did not commit"));
    }
    Ok(())
}

/// Test fault (`HERDR_TEST_HANDOFF_IMPORT_FAIL=commit_unread`): give up once `committed`
/// is queued, without reading it, as import servers did before [`wait_committed_within`]
/// survived a signal.
#[cfg(unix)]
pub(crate) fn drop_commit_unread(stream: &UnixStream) -> io::Result<()> {
    let mut readable = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = libc::c_int::try_from(COMMIT_TIMEOUT.as_millis()).unwrap_or(libc::c_int::MAX);
    while unsafe { libc::poll(&mut readable, 1, timeout) } < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Err(io::Error::other(
        "test: the handoff commit was dropped unread",
    ))
}

#[cfg(unix)]
pub(crate) fn report_owned(stream: &mut UnixStream) -> io::Result<()> {
    stream.write_all(b"owned\n")?;
    stream.flush()
}

#[cfg(unix)]
pub(crate) fn manifest_for(
    snapshot: crate::persist::SessionSnapshot,
    panes: Vec<crate::handoff_runtime::HandoffRuntimeState>,
    expected_protocol: Option<u32>,
    expected_version: Option<String>,
    api_window_title: Option<String>,
    host_shutdown_intent: Option<crate::platform::HostShutdownIntent>,
) -> HandoffManifest {
    HandoffManifest {
        version: HANDOFF_VERSION,
        source_version: crate::build_info::version(),
        source_protocol: crate::protocol::PROTOCOL_VERSION,
        expected_version,
        expected_protocol,
        snapshot,
        panes,
        api_window_title,
        host_shutdown_intent,
    }
}

#[cfg(unix)]
fn restrict_socket_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
fn accept_with_timeout(
    listener: &UnixListener,
    timeout: Duration,
) -> io::Result<(UnixStream, std::os::unix::net::SocketAddr)> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for handoff import connection",
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

#[cfg(unix)]
fn read_line_unbuffered(stream: &mut UnixStream) -> io::Result<String> {
    let mut bytes = Vec::new();
    read_line_into(stream, &mut bytes)?;
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Reads up to and including `\n` into `bytes`, which keeps what was read when it fails.
///
/// A caught signal is no answer and is read past. Linux never restarts a socket read
/// that has a timeout, `SA_RESTART` or not: it fails with `EINTR`, even with the line
/// already queued. The server catches SIGHUP for its whole life, and on 2026-11-24 an
/// import server took that `EINTR` on `committed` for a lost commit: it gave 130 panes
/// up while the old server, its commit written, exited.
#[cfg(unix)]
fn read_line_into(stream: &mut UnixStream, bytes: &mut Vec<u8>) -> io::Result<()> {
    let mut byte = [0u8; 1];
    loop {
        let read = match stream.read(&mut byte) {
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "handoff stream closed while reading line",
            ));
        }
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(());
        }
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handoff line exceeded maximum size",
            ));
        }
    }
}

#[cfg(unix)]
fn send_fds(stream: &UnixStream, fds: &[RawFd]) -> io::Result<()> {
    for batch in fds.chunks(FDS_PER_MESSAGE) {
        send_fd_batch(stream, batch)?;
    }
    Ok(())
}

#[cfg(unix)]
fn send_fd_batch(stream: &UnixStream, fds: &[RawFd]) -> io::Result<()> {
    if fds.is_empty() {
        return Ok(());
    }
    let byte = [b'F'];
    let iov = [libc::iovec {
        iov_base: byte.as_ptr() as *mut libc::c_void,
        iov_len: byte.len(),
    }];
    let fd_bytes = std::mem::size_of_val(fds);
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = iov.len() as _;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("failed to allocate fd control message"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(cmsg), fd_bytes);
        if libc::sendmsg(stream.as_raw_fd(), &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn close_raw_fds(fds: &[RawFd]) {
    for fd in fds {
        let _ = unsafe { libc::close(*fd) };
    }
}

#[cfg(unix)]
fn recv_fds(stream: &UnixStream, expected: usize) -> io::Result<Vec<RawFd>> {
    let mut out: Vec<RawFd> = Vec::with_capacity(expected);
    while out.len() < expected {
        let wanted = (expected - out.len()).min(FDS_PER_MESSAGE);
        let batch = match recv_fd_batch(stream, wanted) {
            Ok(batch) => batch,
            Err(err) => {
                close_raw_fds(&out);
                return Err(err);
            }
        };
        if batch.is_empty() {
            let received = out.len();
            close_raw_fds(&out);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "handoff stream closed after {received} of {expected} pane file descriptors"
                ),
            ));
        }
        out.extend(batch);
    }
    Ok(out)
}

#[cfg(unix)]
fn recv_fd_batch(stream: &UnixStream, wanted: usize) -> io::Result<Vec<RawFd>> {
    let mut byte = [0u8; 1];
    let mut iov = [libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: byte.len(),
    }];
    let fd_bytes = wanted * std::mem::size_of::<RawFd>();
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len() as _;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    let read = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut out = Vec::new();
    unsafe {
        let control_end = control.as_ptr() as usize + msg.msg_controllen as usize;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                // Bound the payload by both the header's own length and the
                // bytes the kernel wrote into `control`, so the read below can
                // never run past the buffer.
                let available = control_end.saturating_sub(data as usize);
                let data_len = ((*cmsg).cmsg_len as usize)
                    .saturating_sub(libc::CMSG_LEN(0) as usize)
                    .min(available);
                let count = data_len / std::mem::size_of::<RawFd>();
                let data = data as *const RawFd;
                for idx in 0..count {
                    out.push(*data.add(idx));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    // Truncation means the kernel closed the descriptors that did not fit, so
    // the batch is unrecoverable rather than merely short.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        close_raw_fds(&out);
        return Err(io::Error::other("handoff fd control message was truncated"));
    }
    if read == 0 {
        close_raw_fds(&out);
        return Ok(Vec::new());
    }
    if out.len() > wanted {
        let received = out.len();
        close_raw_fds(&out);
        return Err(io::Error::other(format!(
            "handoff fd message carried {received} descriptors, expected at most {wanted}"
        )));
    }
    if out.is_empty() {
        return Err(io::Error::other("handoff fd message missing SCM_RIGHTS"));
    }
    Ok(out)
}

#[cfg(unix)]
pub(crate) fn log_import_result(panes: usize) {
    info!(panes, "handoff import ready");
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn empty_snapshot() -> crate::persist::SessionSnapshot {
        crate::persist::SessionSnapshot {
            version: 0,
            workspaces: Vec::new(),
            active: None,
            selected: 0,
            sidebar_width: None,
            sidebar_section_split: None,
            collapsed_space_keys: Default::default(),
            archived_agents: Vec::new(),
        }
    }

    /// Review 5: only an importer that says it can hand a systemd unit's main pid back
    /// may get it. The plain `ready` of an older build says it can't; a newer word
    /// this build doesn't know is ignored rather than failing the handoff.
    #[test]
    fn the_ready_line_says_whether_the_importer_can_hand_the_main_pid_back() {
        let old = parse_ready("ready\n").unwrap();
        assert!(!old.main_pid_recovery);
        let new = parse_ready(&format!("ready {MAIN_PID_RECOVERY}\n")).unwrap();
        assert!(new.main_pid_recovery);
        let newer = parse_ready(&format!("ready some-future-word {MAIN_PID_RECOVERY}\n")).unwrap();
        assert!(newer.main_pid_recovery);
        assert!(
            !parse_ready("ready some-future-word\n")
                .unwrap()
                .main_pid_recovery
        );
        assert_eq!(parse_ready("restored\n"), None);
        assert_eq!(parse_ready(""), None);
    }

    #[test]
    fn a_handoff_carries_an_api_set_window_title() {
        let manifest = manifest_for(
            empty_snapshot(),
            Vec::new(),
            None,
            None,
            Some("deploying".to_string()),
            None,
        );

        assert_eq!(manifest.api_window_title.as_deref(), Some("deploying"));
    }

    #[test]
    fn a_handoff_carries_an_announced_host_shutdown() {
        let intent: crate::platform::HostShutdownIntent =
            serde_json::from_value(serde_json::json!({ "announced_at_ns": 42 }))
                .expect("intent should deserialize");
        let manifest = manifest_for(empty_snapshot(), Vec::new(), None, None, None, Some(intent));
        let encoded = serde_json::to_vec(&manifest).expect("manifest should serialize");
        let decoded: HandoffManifest =
            serde_json::from_slice(&encoded).expect("manifest should deserialize");

        assert_eq!(decoded.host_shutdown_intent, Some(intent));
    }

    #[test]
    fn a_manifest_written_before_the_host_shutdown_field_still_loads() {
        let manifest = manifest_for(empty_snapshot(), Vec::new(), None, None, None, None);
        let mut value = serde_json::to_value(&manifest).expect("manifest should serialize");
        value
            .as_object_mut()
            .expect("manifest should be a json object")
            .remove("host_shutdown_intent");

        let older: HandoffManifest =
            serde_json::from_value(value).expect("an older manifest should still load");

        assert!(older.host_shutdown_intent.is_none());
    }

    #[test]
    fn an_older_server_imports_a_manifest_with_an_announced_host_shutdown() {
        /// The manifest as servers before `host_shutdown_intent` decode it,
        /// frozen here so the new field stays ignorable by them.
        #[derive(Deserialize)]
        #[allow(dead_code)] // Only decoding is under test.
        struct PreHostShutdownManifest {
            version: u32,
            source_version: String,
            source_protocol: u32,
            expected_version: Option<String>,
            expected_protocol: Option<u32>,
            snapshot: crate::persist::SessionSnapshot,
            panes: Vec<crate::handoff_runtime::HandoffRuntimeState>,
            #[serde(default)]
            api_window_title: Option<String>,
        }

        let intent: crate::platform::HostShutdownIntent =
            serde_json::from_value(serde_json::json!({ "announced_at_ns": 42 }))
                .expect("intent should deserialize");
        let manifest = manifest_for(
            empty_snapshot(),
            Vec::new(),
            None,
            None,
            Some("deploying".to_string()),
            Some(intent),
        );
        let encoded = serde_json::to_vec(&manifest).expect("manifest should serialize");

        let older: PreHostShutdownManifest =
            serde_json::from_slice(&encoded).expect("an older server should still load it");

        assert_eq!(older.version, HANDOFF_VERSION);
        assert_eq!(older.api_window_title.as_deref(), Some("deploying"));
    }

    #[test]
    fn a_manifest_written_before_the_title_field_still_loads() {
        let manifest = manifest_for(
            empty_snapshot(),
            Vec::new(),
            None,
            None,
            Some("deploying".to_string()),
            None,
        );
        let mut value = serde_json::to_value(&manifest).expect("manifest should serialize");
        value
            .as_object_mut()
            .expect("manifest should be a json object")
            .remove("api_window_title");

        let older: HandoffManifest =
            serde_json::from_value(value).expect("an older manifest should still load");

        assert!(older.api_window_title.is_none());
    }

    /// 2026-11-24: a signal ended the import server's wait while `committed` was
    /// queued, so it gave 130 panes up while the old server, its commit written,
    /// exited. The server catches SIGHUP, and Linux fails a socket read that has a
    /// timeout with `EINTR` even under `SA_RESTART`, so a signal must not end the wait.
    #[test]
    fn a_signal_while_the_import_server_waits_does_not_lose_the_commit() {
        use std::os::unix::thread::JoinHandleExt as _;

        // Caught like the server's SIGHUP (`SA_RESTART`), without touching SIGHUP here.
        unsafe { signal_hook::low_level::register(libc::SIGUSR1, || {}) }
            .expect("SIGUSR1 handler should install");
        let (mut old_server, mut import_server) = UnixStream::pair().unwrap();
        let waiting = std::thread::spawn(move || wait_committed(&mut import_server));
        let thread = waiting.as_pthread_t();
        let deadline = std::time::Instant::now() + Duration::from_millis(200);
        while std::time::Instant::now() < deadline && !waiting.is_finished() {
            // SAFETY: the thread is not joined yet, so its id is still valid.
            unsafe { libc::pthread_kill(thread, libc::SIGUSR1) };
            std::thread::sleep(Duration::from_millis(1));
        }
        let _ = report_committed(&mut old_server);

        let committed = waiting.join().unwrap();
        assert!(committed.is_ok(), "{committed:?}");
    }

    /// The old server commits by writing `committed`, so once the import server has
    /// given up waiting, that write must fail: the old server then keeps the panes
    /// instead of exiting while the import server drops them.
    #[test]
    fn a_commit_written_after_the_import_server_gave_up_fails() {
        let (mut old_server, mut import_server) = UnixStream::pair().unwrap();
        assert!(wait_committed_within(&mut import_server, Duration::from_millis(50)).is_err());

        assert!(report_committed(&mut old_server).is_err());
    }

    /// After the commit the old server still holds every pane. It takes them back only
    /// from an import server that closed the handoff without `owned` (the 2026-11-24
    /// one closed it with `committed` unread); one that still holds it owns them.
    #[test]
    fn the_old_server_takes_the_panes_back_only_from_an_import_server_that_let_go() {
        let (mut old_server, mut import_server) = UnixStream::pair().unwrap();
        report_owned(&mut import_server).unwrap();
        assert!(wait_owned_ack(&mut old_server, COMMIT_TIMEOUT).is_ok());

        let (mut old_server, _silent_import_server) = UnixStream::pair().unwrap();
        let silent = wait_owned_ack(&mut old_server, Duration::from_millis(50));
        assert!(silent.is_ok(), "{silent:?}");

        let (mut old_server, import_server) = UnixStream::pair().unwrap();
        report_committed(&mut old_server).unwrap();
        drop(import_server);
        assert!(wait_owned_ack(&mut old_server, COMMIT_TIMEOUT).is_err());
    }
}
