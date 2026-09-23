use std::io;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};

use super::attach::{find_installed_remote_herdr, ManagedSshOptions, RemoteSsh, SshStdioBridge};

pub(crate) struct SavedSshBridge {
    _bridge: SshStdioBridge,
}

pub(crate) struct SavedSshStream {
    pub(crate) stream: crate::ipc::LocalStream,
    pub(crate) bridge: SavedSshBridge,
}

pub(crate) fn connect_saved_ssh(
    profile_id: &str,
    target: &str,
    session: &str,
) -> io::Result<SavedSshStream> {
    let ssh = validated_saved_ssh(profile_id, target, session)?;
    let remote_herdr = find_installed_remote_herdr(&ssh)?;
    let metadata = remote_herdr.machine_metadata();
    let path = saved_bridge_path(profile_id);
    let bridge = SshStdioBridge::start(
        target.to_owned(),
        remote_herdr,
        path.clone(),
        session.to_owned(),
        ssh.options(),
        true,
    )?;
    let stream = crate::ipc::connect_local_stream(&path)?;
    if let Some(metadata) = metadata {
        crate::client::endpoint::SshMetadataCache::new(profile_id, target, session)?
            .store(&metadata);
    }
    Ok(SavedSshStream {
        stream,
        bridge: SavedSshBridge { _bridge: bridge },
    })
}

pub(crate) struct SavedSshApiBridge {
    path: PathBuf,
    bridge: SshStdioBridge,
    metadata_cache: crate::client::endpoint::SshMetadataCache,
    pub(crate) used_cached_metadata: bool,
}

impl SavedSshApiBridge {
    pub(crate) fn start(
        profile_id: &str,
        target: &str,
        session: &str,
        use_cached_metadata: bool,
    ) -> io::Result<Self> {
        Self::start_inner(profile_id, target, session, use_cached_metadata, None)
    }

    pub(crate) fn start_cancellable(
        profile_id: &str,
        target: &str,
        session: &str,
        use_cached_metadata: bool,
        cancellation: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Self::start_inner(
            profile_id,
            target,
            session,
            use_cached_metadata,
            Some(cancellation),
        )
    }

    fn start_inner(
        profile_id: &str,
        target: &str,
        session: &str,
        use_cached_metadata: bool,
        cancellation: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        let ssh = validated_saved_ssh_with_cancellation(
            profile_id,
            target,
            session,
            cancellation.clone(),
        )?;
        let metadata_cache =
            crate::client::endpoint::SshMetadataCache::new(profile_id, target, session)?;
        let cached = use_cached_metadata.then(|| metadata_cache.load()).flatten();
        let used_cached_metadata = cached.is_some();
        let metadata = match cached {
            Some(metadata) => metadata,
            None => {
                let metadata = super::attach::discover_remote_api_metadata(&ssh, session)?;
                metadata_cache.store(&metadata);
                metadata
            }
        };
        if cancellation
            .as_deref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "saved SSH bridge startup cancelled",
            ));
        }
        let command = super::attach::cached_remote_api_command(&metadata, session);
        let path = crate::platform::remote_bridge_endpoint_path(
            &format!("herdr-api-ssh-{}-{profile_id}.sock", std::process::id()),
            &format!(
                "herdr-api-{}-{}.sock",
                std::process::id(),
                &profile_id[..16]
            ),
        );
        let bridge = SshStdioBridge::start_command(
            target.to_owned(),
            command,
            path.clone(),
            saved_federation_ssh_options(),
            true,
        )?;
        Ok(Self {
            path,
            bridge,
            metadata_cache,
            used_cached_metadata,
        })
    }

    pub(crate) fn socket_path(&self) -> &std::path::Path {
        &self.path
    }

    pub(crate) fn reported_failure(&self) -> Option<io::Error> {
        self.bridge.reported_failure()
    }

    pub(crate) fn try_reported_failure(&self) -> io::Result<Option<io::Error>> {
        self.bridge.try_reported_failure()
    }

    pub(crate) fn invalidate_metadata(&self) {
        self.metadata_cache.invalidate();
    }

    pub(crate) fn stale_metadata_failure(error: &io::Error) -> bool {
        error
            .to_string()
            .contains(super::attach::STALE_API_METADATA)
    }
}

fn saved_federation_ssh_options() -> Option<&'static ManagedSshOptions> {
    static OPTIONS: OnceLock<Option<ManagedSshOptions>> = OnceLock::new();
    OPTIONS
        .get_or_init(|| {
            super::attach::build_federation_ssh_options()
                .inspect_err(|error| {
                    tracing::warn!(%error, "could not create saved federation SSH config; using plain SSH");
                })
                .ok()
        })
        .as_ref()
}

/// Establish an authenticated SSH streamlocal reverse forward, never a forward
/// to the unrestricted Herdr API. A readiness marker is emitted by the remote
/// command only after OpenSSH has accepted all requested forwards.
#[cfg(unix)]
pub(crate) fn spawn_saved_reverse_forward(
    profile_id: &str,
    target: &str,
    remote_socket: &std::path::Path,
    gateway_socket: &std::path::Path,
) -> io::Result<std::process::Child> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    validate_profile_path_id(profile_id)?;
    if target.is_empty() || target.starts_with('-') || target.chars().any(char::is_whitespace) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid saved SSH target",
        ));
    }
    let options = saved_federation_ssh_options().ok_or_else(|| {
        io::Error::other("managed SSH configuration unavailable; reverse forwarding refused")
    })?;
    let mut command = Command::new("ssh");
    super::attach::apply_managed_ssh_options(&mut command, Some(options));
    super::attach::apply_noninteractive_ssh_options(&mut command);
    command
        .arg("-T")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-o")
        .arg("StreamLocalBindMask=0177")
        .arg("-o")
        .arg("StreamLocalBindUnlink=yes")
        .arg("-R")
        .arg(format!(
            "{}:{}",
            remote_socket.display(),
            gateway_socket.display()
        ))
        .arg(target)
        .arg("printf 'herdr-reverse-ready\\n'; exec sleep 2147483647")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("piped SSH stdout");
    let (tx, rx) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut output = BufReader::new(stdout);
        let mut line = Vec::new();
        let mut total = 0usize;
        let result = loop {
            let available = match output.fill_buf() {
                Ok(bytes) if !bytes.is_empty() => bytes,
                Ok(_) => {
                    break Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "SSH closed before reverse forward readiness",
                    ))
                }
                Err(error) => break Err(error),
            };
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(available.len(), |position| position + 1);
            total += count;
            if total > 16 * 1024 {
                break Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSH stdout exceeded readiness limit",
                ));
            }
            line.extend_from_slice(&available[..count]);
            output.consume(count);
            if newline.is_some() {
                if line == b"herdr-reverse-ready\n" {
                    break Ok(());
                }
                line.clear();
            }
        };
        let _ = tx.send(result);
    });
    let ready = rx.recv_timeout(Duration::from_secs(20));
    if !matches!(ready, Ok(Ok(()))) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        return Err(match ready {
            Err(mpsc::RecvTimeoutError::Timeout) => io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH reverse streamlocal forwarding did not become ready within 20 seconds",
            ),
            Ok(Err(error)) => error,
            _ => io::Error::other("SSH reverse streamlocal forwarding rejected"),
        });
    }
    let _ = reader.join();
    Ok(child)
}

pub(crate) fn saved_ssh_bootstrap_command(target: &str, session: &str) -> String {
    format!(
        "herdr --remote {} --session {}",
        super::shell_quote(target),
        super::shell_quote(session)
    )
}

pub(crate) fn saved_ssh_failure_needs_attention(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::Unsupported
    ) {
        return true;
    }
    let message = error.to_string().to_ascii_lowercase();
    [
        "permission denied",
        "host key verification failed",
        "remote host identification has changed",
        "could not resolve hostname",
        "no matching host key",
        "unsupported remote platform",
        "not ready",
        "install or update",
        "protocol",
        "handshake",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

fn saved_bridge_path(profile_id: &str) -> PathBuf {
    let pid = std::process::id();
    let readable = format!("herdr-ssh-{pid}-{profile_id}.sock");
    let short = format!("herdr-s-{pid}-{}.sock", &profile_id[..16]);
    crate::platform::remote_bridge_endpoint_path(&readable, &short)
}

fn validated_saved_ssh(profile_id: &str, target: &str, session: &str) -> io::Result<RemoteSsh> {
    validated_saved_ssh_with_cancellation(profile_id, target, session, None)
}

fn validated_saved_ssh_with_cancellation(
    profile_id: &str,
    target: &str,
    session: &str,
    cancellation: Option<Arc<AtomicBool>>,
) -> io::Result<RemoteSsh> {
    validate_profile_path_id(profile_id)?;
    crate::session::validate_name(session)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(match cancellation {
        Some(cancellation) => {
            RemoteSsh::new_noninteractive_cancellable(target.to_owned(), cancellation)
        }
        None => RemoteSsh::new_noninteractive(target.to_owned()),
    })
}

fn validate_profile_path_id(profile_id: &str) -> io::Result<()> {
    if profile_id.len() == 32
        && profile_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SSH endpoint profile id",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_paths_use_profile_identity_not_target_or_session() {
        let first = saved_bridge_path("0123456789abcdef0123456789abcdef");
        let second = saved_bridge_path("fedcba9876543210fedcba9876543210");
        assert_ne!(first, second);
        assert!(!first.to_string_lossy().contains("example.com"));
        assert!(!first.to_string_lossy().contains("default"));
    }

    #[test]
    fn bootstrap_command_preserves_the_explicit_remote_session() {
        assert_eq!(
            saved_ssh_bootstrap_command("build host", "agent work"),
            "herdr --remote 'build host' --session 'agent work'"
        );
    }

    #[test]
    fn prompt_and_compatibility_failures_require_attention() {
        for message in [
            "Permission denied (publickey)",
            "Host key verification failed",
            "matching Herdr is not ready; install or update",
            "handshake rejected",
        ] {
            assert!(saved_ssh_failure_needs_attention(&io::Error::other(
                message
            )));
        }
        for message in [
            "ssh: connect to host build port 22: Connection timed out",
            "ssh: connect to host build port 22: Connection refused",
        ] {
            assert!(
                !saved_ssh_failure_needs_attention(&io::Error::other(message)),
                "transient reachability failures must remain retryable"
            );
        }
    }
}
