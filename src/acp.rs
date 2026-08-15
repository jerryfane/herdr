use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

pub(crate) const ACP_ENDPOINT_PROTOCOL_VERSION: u32 = 1;
pub(crate) const ACP_TICKET_TTL: Duration = Duration::from_secs(10);
pub(crate) const ACP_DEFAULT_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(13);
pub(crate) const ACP_HERMES_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(45);

const ACP_DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const ACP_HERMES_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct AcpWorkerIdentity {
    pub terminal_id: String,
    pub workspace_id: String,
    pub tab_id: String,
    pub pane_id: String,
    pub name: String,
    pub agent: String,
    pub session_id: Option<String>,
    pub session_mode: crate::api::schema::AcpSessionMode,
    pub cwd: PathBuf,
}

impl AcpWorkerIdentity {
    pub(crate) fn generation(&self, turn_epoch: u64) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        turn_epoch.hash(&mut hasher);
        self.hash(&mut hasher);
        hasher.finish()
    }
}

#[derive(Clone)]
pub(crate) struct AcpAttachTicket {
    pub token: String,
    pub identity: AcpWorkerIdentity,
    pub generation: u64,
    pub expires_at: Instant,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AcpOwnedLifecycle {
    Ready,
    Attached { lease: String, generation: u64 },
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AcpOwnedWorker {
    pub identity: AcpWorkerIdentity,
    pub adapter_command: PathBuf,
    pub adapter_version: String,
    pub adapter_sha256: [u8; 32],
    pub lifecycle: AcpOwnedLifecycle,
}

impl AcpAttachTicket {
    pub(crate) fn mint(
        identity: AcpWorkerIdentity,
        generation: u64,
        now: Instant,
    ) -> std::io::Result<Self> {
        Ok(Self {
            token: fresh_ticket_token()?,
            identity,
            generation,
            expires_at: now + ACP_TICKET_TTL,
        })
    }

    pub(crate) fn validates(
        &self,
        token: &str,
        identity: &AcpWorkerIdentity,
        generation: u64,
        now: Instant,
    ) -> Result<(), TicketValidationError> {
        if now >= self.expires_at {
            return Err(TicketValidationError::Expired);
        }
        if !constant_time_eq(self.token.as_bytes(), token.as_bytes()) {
            return Err(TicketValidationError::Invalid);
        }
        if self.generation != generation || &self.identity != identity {
            return Err(TicketValidationError::Stale);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketValidationError {
    Expired,
    Invalid,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcpAdapterSpec {
    pub name: &'static str,
    pub command: &'static str,
    pub args: &'static [&'static str],
    pub version_args: &'static [&'static str],
    pub version_timeout: Duration,
    pub capability_args: &'static [&'static str],
    pub capability_timeout: Duration,
}

pub(crate) fn adapter_for(agent: &str) -> Option<AcpAdapterSpec> {
    match agent {
        "codex" => Some(AcpAdapterSpec {
            name: "codex-acp",
            command: "codex-acp",
            args: &[],
            version_args: &["--version"],
            version_timeout: ACP_DEFAULT_PROBE_TIMEOUT,
            capability_args: &[],
            capability_timeout: ACP_DEFAULT_PROBE_TIMEOUT,
        }),
        "claude" => Some(AcpAdapterSpec {
            name: "claude-agent-acp",
            command: "claude-agent-acp",
            args: &[],
            version_args: &["--version"],
            version_timeout: ACP_DEFAULT_PROBE_TIMEOUT,
            capability_args: &[],
            capability_timeout: ACP_DEFAULT_PROBE_TIMEOUT,
        }),
        "gemini" => Some(AcpAdapterSpec {
            name: "gemini",
            command: "gemini",
            args: &["--acp"],
            version_args: &["--version"],
            version_timeout: ACP_DEFAULT_PROBE_TIMEOUT,
            capability_args: &[],
            capability_timeout: ACP_DEFAULT_PROBE_TIMEOUT,
        }),
        "hermes" => Some(AcpAdapterSpec {
            name: "hermes",
            command: "hermes",
            args: &["acp"],
            version_args: &["--version"],
            version_timeout: ACP_HERMES_PROBE_TIMEOUT,
            capability_args: &["acp", "--help"],
            capability_timeout: ACP_HERMES_PROBE_TIMEOUT,
        }),
        _ => None,
    }
}

pub(crate) fn probe_adapter_version_at(
    spec: &AcpAdapterSpec,
    command: &Path,
) -> std::io::Result<String> {
    #[cfg(test)]
    {
        let _ = command;
        return Ok(format!("{} test", spec.name));
    }

    #[cfg(not(test))]
    {
        let command = command
            .to_str()
            .ok_or_else(|| std::io::Error::other("ACP adapter path is not valid UTF-8"))?;
        probe_command_version(command, spec.version_args, spec.version_timeout)
    }
}

pub(crate) fn probe_adapter_capability_at(
    spec: &AcpAdapterSpec,
    command: &Path,
) -> std::io::Result<()> {
    if spec.capability_args.is_empty() {
        return Ok(());
    }

    #[cfg(test)]
    {
        let _ = command;
        Ok(())
    }

    #[cfg(not(test))]
    {
        let command = command
            .to_str()
            .ok_or_else(|| std::io::Error::other("ACP adapter path is not valid UTF-8"))?;
        probe_command_version(command, spec.capability_args, spec.capability_timeout).map(|_| ())
    }
}

pub(crate) fn registration_timeout_for(adapter: &AcpAdapterSpec) -> Duration {
    if adapter.name == "hermes" {
        ACP_HERMES_REGISTRATION_TIMEOUT
    } else {
        ACP_DEFAULT_REGISTRATION_TIMEOUT
    }
}

pub(crate) fn adapter_sha256(command: &Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(command)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(any(not(test), unix))]
fn probe_command_version(
    command: &str,
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<String> {
    use std::io::Read as _;
    use std::process::Stdio;

    let cwd = std::env::current_dir()?;
    let args = args
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();
    let mut child = crate::plugin_command::command_for_argv_in_dir(command, &args, &cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "ACP adapter version probe timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        return Err(std::io::Error::other(
            "ACP adapter version probe exited unsuccessfully",
        ));
    }
    let mut output = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout.take(1024).read_to_end(&mut output)?;
    }
    if output.is_empty() {
        if let Some(stderr) = child.stderr.take() {
            stderr.take(1024).read_to_end(&mut output)?;
        }
    }
    let decoded = String::from_utf8_lossy(&output);
    let version = decoded
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| std::io::Error::other("ACP adapter version output was empty"))?;
    Ok(version.chars().take(128).collect())
}

pub(crate) fn run_adapter(command: &str, args: &[String], cwd: &Path) -> std::io::Result<i32> {
    let child = crate::plugin_command::command_for_argv_in_dir(command, args, cwd).spawn()?;
    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    let signal_child = std::sync::Arc::clone(&child);
    if let Err(error) = ctrlc::set_handler(move || {
        if let Ok(mut child) = signal_child.lock() {
            let _ = child.kill();
        }
    }) {
        if let Ok(mut child) = child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        return Err(std::io::Error::other(format!(
            "failed to install ACP adapter shutdown handler: {error}"
        )));
    }
    loop {
        let status = child
            .lock()
            .map_err(|_| std::io::Error::other("ACP adapter process lock was poisoned"))?
            .try_wait()?;
        if let Some(status) = status {
            return Ok(status.code().unwrap_or(1));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn fresh_ticket_token() -> std::io::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| std::io::Error::other(format!("OS randomness unavailable: {error}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn fresh_lease_token() -> std::io::Result<String> {
    fresh_ticket_token()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |different, (left, right)| different | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> AcpWorkerIdentity {
        AcpWorkerIdentity {
            terminal_id: "terminal-1".into(),
            workspace_id: "w1".into(),
            tab_id: "w1:t1".into(),
            pane_id: "w1:p1".into(),
            name: "worker".into(),
            agent: "codex".into(),
            session_id: Some("session-1".into()),
            session_mode: crate::api::schema::AcpSessionMode::Resume,
            cwd: PathBuf::from("/work"),
        }
    }

    #[test]
    fn ticket_rejects_expiry_wrong_generation_and_identity() {
        let now = Instant::now();
        let identity = identity();
        let generation = identity.generation(7);
        let ticket = AcpAttachTicket::mint(identity.clone(), generation, now).unwrap();
        assert_eq!(
            ticket.validates(&ticket.token, &identity, generation, now),
            Ok(())
        );
        assert_eq!(
            ticket.validates(&ticket.token, &identity, generation, now + ACP_TICKET_TTL),
            Err(TicketValidationError::Expired)
        );
        assert_eq!(
            ticket.validates(&ticket.token, &identity, generation + 1, now),
            Err(TicketValidationError::Stale)
        );
        let mut wrong = identity.clone();
        wrong.pane_id = "w1:p2".into();
        assert_eq!(
            ticket.validates(&ticket.token, &wrong, generation, now),
            Err(TicketValidationError::Stale)
        );
        assert_eq!(
            ticket.validates("wrong", &identity, generation, now),
            Err(TicketValidationError::Invalid)
        );
    }

    #[test]
    fn supported_adapter_commands_are_fixed() {
        assert_eq!(adapter_for("codex").unwrap().command, "codex-acp");
        assert_eq!(adapter_for("claude").unwrap().command, "claude-agent-acp");
        assert_eq!(adapter_for("gemini").unwrap().args, &["--acp"]);
        assert_eq!(adapter_for("hermes").unwrap().args, &["acp"]);
        assert_eq!(adapter_for("hermes").unwrap().version_args, &["--version"]);
        assert!(adapter_for("caller-controlled").is_none());
    }

    #[test]
    fn hermes_requires_a_separate_bounded_acp_capability_probe() {
        let hermes = adapter_for("hermes").unwrap();
        assert_eq!(hermes.version_args, &["--version"]);
        assert_eq!(hermes.capability_args, &["acp", "--help"]);
        assert_eq!(hermes.version_timeout, Duration::from_secs(20));
        assert_eq!(hermes.capability_timeout, Duration::from_secs(20));
        assert_eq!(
            registration_timeout_for(&hermes),
            ACP_HERMES_REGISTRATION_TIMEOUT
        );

        let codex = adapter_for("codex").unwrap();
        assert!(codex.capability_args.is_empty());
        assert_eq!(
            registration_timeout_for(&codex),
            ACP_DEFAULT_REGISTRATION_TIMEOUT
        );
    }

    #[cfg(unix)]
    #[test]
    fn adapter_version_probe_kills_a_slow_command_at_the_deadline() {
        let started = Instant::now();
        let error = probe_command_version(
            "/bin/sh",
            &["-c", "sleep 1; printf 'late\\n'"],
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(750));
    }

    #[test]
    fn tickets_are_unique_csprng_values_without_clock_or_counter_structure() {
        let first = fresh_ticket_token().unwrap();
        let second = fresh_ticket_token().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert_eq!(second.len(), 43);
        assert!(first
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'));
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(first)
            .is_ok_and(|bytes| bytes.len() == 32));
    }
}
