use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use interprocess::{local_socket::ConnectOptions, ConnectWaitMode};
use serde::Deserialize;

use crate::api::client::ApiClient;
use crate::api::schema::{
    AgentNotificationEndpoint, AgentNotificationTarget, AgentPromptSafeOutcome,
    AgentPromptSafeParams, ResponseResult,
};
use crate::api::ApiStream;
use crate::app::App;
use crate::detect::{Agent, AgentState};

use super::responses::{encode_error, encode_error_body, encode_success};

const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_NOTIFICATION_BYTES: usize = 32 * 1024;

impl App {
    pub(super) fn handle_deferred_agent_prompt_safe(
        &mut self,
        id: String,
        params: AgentPromptSafeParams,
        respond_to: std::sync::mpsc::Sender<String>,
    ) {
        if id.len() > 256
            || params.text.trim().is_empty()
            || params.text.len() > MAX_NOTIFICATION_BYTES
        {
            let _ = respond_to.send(encode_error(
                id,
                "invalid_notification",
                "notification requires an ID of at most 256 bytes and 1–32768 UTF-8 bytes of text",
            ));
            return;
        }
        let resolved = match self.resolve_agent_target(&params.target) {
            Ok(resolved) => resolved,
            Err(err) => {
                let _ = respond_to.send(encode_error_body(id, self.agent_target_error_body(err)));
                return;
            }
        };
        let Some(agent) = self.agent_info(resolved.ws_idx, resolved.pane_id) else {
            let _ = respond_to.send(encode_error(
                id,
                "agent_not_found",
                "recipient is no longer present",
            ));
            return;
        };
        let admission = (|| {
            let terminal = self
                .state
                .terminals
                .get(agent.terminal_id.as_str())
                .ok_or("unavailable")?;
            if terminal.input_pending || terminal.state == AgentState::Blocked {
                return Err("modal");
            }
            if terminal.state != AgentState::Idle {
                return Err("busy");
            }
            if terminal.managed_agent_launch_pending()
                || terminal.effective_known_agent() != Some(Agent::Omp)
            {
                return Err("unavailable");
            }
            let authority = terminal.hook_authority.as_ref().ok_or("unavailable")?;
            if authority.source != "herdr:omp" || authority.agent_label != "omp" {
                return Err("unavailable");
            }
            let session_ref = authority.session_ref.as_ref().ok_or("unavailable")?;
            let proof = terminal
                .reported_agent_session_runtime_for("herdr:omp", "omp", session_ref)
                .ok_or("unavailable")?;
            let binding = proof.notification.as_ref().ok_or("unavailable")?;
            let reported_pid = proof.process_pid.ok_or("unavailable")?;
            let child_pid = self
                .lookup_runtime_sender(resolved.ws_idx, resolved.pane_id)
                .and_then(|runtime| runtime.child_pid())
                .ok_or("unavailable")?;
            if !foreground_matches(child_pid, reported_pid) {
                return Err("stale_session");
            }
            Ok((binding.clone(), child_pid, reported_pid))
        })();
        match admission {
            Err(reason) => {
                let _ = respond_to.send(encode_success(
                    id,
                    ResponseResult::AgentPromptSafe {
                        agent,
                        outcome: AgentPromptSafeOutcome::Deferred {
                            reason: reason.into(),
                        },
                    },
                ));
            }
            Ok((binding, child_pid, reported_pid)) => {
                std::thread::spawn(move || {
                    let response = match forward_notification(
                        &id,
                        &params.text,
                        &binding,
                        params.expected_target.as_ref(),
                        || foreground_matches(child_pid, reported_pid),
                    ) {
                        Ok(outcome) => {
                            encode_success(id, ResponseResult::AgentPromptSafe { agent, outcome })
                        }
                        Err(err) => encode_error(id, "agent_prompt_safe_unknown", err.to_string()),
                    };
                    let _ = respond_to.send(response);
                });
            }
        }
    }
}

fn foreground_matches(child_pid: u32, reported_pid: u32) -> bool {
    crate::detect::foreground_job(child_pid)
        .as_ref()
        .and_then(|job| crate::session_transfer::omp_reported_process(job, reported_pid))
        == Some(reported_pid)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeReply {
    id: String,
    result: AgentPromptSafeOutcome,
}

fn forward_notification(
    id: &str,
    text: &str,
    binding: &AgentNotificationEndpoint,
    expected_target: Option<&AgentNotificationTarget>,
    still_foreground: impl FnOnce() -> bool,
) -> io::Result<AgentPromptSafeOutcome> {
    if expected_target.is_some_and(|expected| expected != &binding.target) {
        return Ok(AgentPromptSafeOutcome::Deferred {
            reason: "stale_session".into(),
        });
    }
    let deadline = Instant::now() + NOTIFICATION_TIMEOUT;
    let stream = match connect_runtime(Path::new(&binding.endpoint)) {
        Ok(stream) => stream,
        Err(_) => {
            return Ok(AgentPromptSafeOutcome::Deferred {
                reason: "runtime_unreachable".into(),
            })
        }
    };
    if !still_foreground() {
        return Ok(AgentPromptSafeOutcome::Deferred {
            reason: "stale_session".into(),
        });
    }
    let mut stream = ApiStream::Local(stream);
    let mut request = serde_json::to_vec(&serde_json::json!({
        "id": id,
        "method": "agent.prompt_safe",
        "params": { "target": binding.target, "content": text },
    }))?;
    request.push(b'\n');
    let mut remaining = request.as_slice();
    while !remaining.is_empty() {
        let result = if Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime notification write deadline expired",
            ))
        } else {
            stream.write(remaining)
        };
        let err = match result {
            Ok(0) => io::Error::new(
                io::ErrorKind::WriteZero,
                "runtime notification connection closed",
            ),
            Ok(written) => {
                remaining = &remaining[written..];
                continue;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(err) => err,
        };
        if remaining.len() == request.len() {
            return Ok(AgentPromptSafeOutcome::Deferred {
                reason: "runtime_unreachable".into(),
            });
        }
        return Err(err);
    }
    // Once any bytes have been written, a missing or malformed receipt is unknown.
    // Never reconnect, retry, or fall back to writing into the PTY.
    let line = ApiClient::read_proxy_response_bounded(
        stream,
        4096,
        deadline.saturating_duration_since(Instant::now()),
        None,
    )
    .map_err(|err| io::Error::other(err.to_string()))?;
    let reply: RuntimeReply = serde_json::from_str(&line)?;
    if reply.id != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime notification receipt identity mismatch",
        ));
    }
    Ok(reply.result)
}

fn connect_runtime(path: &Path) -> io::Result<crate::ipc::LocalStream> {
    #[cfg(unix)]
    let name = {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let socket = std::fs::symlink_metadata(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("runtime endpoint has no parent"))?;
        let directory = std::fs::symlink_metadata(parent)?;
        // The extension owns a private directory and a private Unix socket.
        let uid = unsafe { libc::geteuid() };
        if !path.is_absolute()
            || !socket.file_type().is_socket()
            || socket.uid() != uid
            || socket.mode() & 0o077 != 0
            || !directory.is_dir()
            || directory.uid() != uid
            || directory.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime endpoint is not private to this user",
            ));
        }
        path.to_fs_name::<GenericFilePath>()?
    };
    #[cfg(windows)]
    let name = {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        let endpoint = path
            .to_str()
            .ok_or_else(|| io::Error::other("invalid runtime pipe name"))?;
        if !endpoint.starts_with(r"\\.\pipe\herdr-notify-") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime endpoint is not a local notification pipe",
            ));
        }
        endpoint.to_fs_name::<GenericFilePath>()?
    };
    ConnectOptions::new()
        .name(name)
        .wait_mode(ConnectWaitMode::Timeout(NOTIFICATION_TIMEOUT))
        .nonblocking_stream(true)
        .connect_sync()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn endpoint() -> (PathBuf, UnixListener, AgentNotificationEndpoint) {
        let directory = std::env::temp_dir().join(format!(
            "herdr-notify-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let socket = directory.join("notify.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let binding = AgentNotificationEndpoint {
            endpoint: socket.to_string_lossy().into_owned(),
            target: crate::api::schema::AgentNotificationTarget {
                runtime_id: "instance".into(),
                session_id: "session".into(),
                generation: 1,
            },
        };
        (directory, listener, binding)
    }

    #[test]
    fn notification_peer_closed_before_write_remains_pending() {
        let (directory, listener, binding) = endpoint();
        let (closed, observed) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            drop(socket);
            closed.send(()).unwrap();
        });
        let outcome =
            forward_notification("notice", "Keep this in the inbox", &binding, None, || {
                observed.recv_timeout(Duration::from_secs(5)).unwrap();
                true
            })
            .unwrap();
        assert_eq!(
            outcome,
            AgentPromptSafeOutcome::Deferred {
                reason: "runtime_unreachable".into()
            },
        );
        peer.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn notification_rebound_recipient_requires_resolved_runtime() {
        let (directory, listener, binding) = endpoint();
        let mut original = binding.target.clone();
        original.runtime_id = "previous-recipient".into();
        assert_eq!(
            forward_notification("notice", "Private mail", &binding, Some(&original), || true)
                .unwrap(),
            AgentPromptSafeOutcome::Deferred {
                reason: "stale_session".into()
            },
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        listener.set_nonblocking(false).unwrap();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(&mut socket).read_line(&mut line).unwrap();
            socket
                .write_all(b"{\"id\":\"notice\",\"result\":{\"status\":\"accepted\"}}\n")
                .unwrap();
            serde_json::from_str::<serde_json::Value>(&line).unwrap()
        });
        assert_eq!(
            forward_notification(
                "notice",
                "Private mail",
                &binding,
                Some(&binding.target),
                || true
            )
            .unwrap(),
            AgentPromptSafeOutcome::Accepted,
        );
        peer.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn notification_occupant_change_after_connect_writes_nothing() {
        let (directory, listener, binding) = endpoint();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            // The sole client closes on return; EOF bounds this read without
            // racing Darwin's timeout socket option against that disconnect.
            socket.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let outcome =
            forward_notification("notice", "Keep this in the inbox", &binding, None, || false)
                .unwrap();
        assert_eq!(
            outcome,
            AgentPromptSafeOutcome::Deferred {
                reason: "stale_session".into()
            }
        );
        assert!(
            peer.join().unwrap().is_empty(),
            "stale occupant received input"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn notification_lost_receipt_is_unknown_without_reconnection() {
        let (directory, listener, binding) = endpoint();
        let peer = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            drop(reader);
            (listener, line)
        });
        let result = forward_notification(
            "notice",
            "Do not duplicate this notice",
            &binding,
            None,
            || true,
        );
        let (listener, line) = peer.join().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["params"]["content"],
            "Do not duplicate this notice"
        );
        assert!(
            result.is_err(),
            "lost receipt was reported as a safe refusal or acceptance"
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn notification_nonprivate_endpoint_is_refused_before_connect() {
        let (directory, listener, binding) = endpoint();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outcome = forward_notification("notice", "Private mail", &binding, None, || {
            panic!("must not connect")
        });
        assert_eq!(
            outcome.unwrap(),
            AgentPromptSafeOutcome::Deferred {
                reason: "runtime_unreachable".into()
            }
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
