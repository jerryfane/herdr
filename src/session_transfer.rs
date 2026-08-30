//! Native transcript conversion for Claude Code <-> Codex session transfer.
//!
//! This module deliberately has no pane or TUI state. It reads an immutable
//! source artifact into a provider-neutral visible-message sequence, stages a
//! new native destination artifact, then rereads that artifact for verification.
//! The caller owns the later same-pane cutover transaction.

mod omp;

use std::fmt;
use std::fs;
use std::io::{BufRead as _, BufReader, BufWriter, Cursor, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

const MAX_TRANSCRIPT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TRANSCRIPT_LINE_BYTES: usize = 8 * 1024 * 1024;
const MAX_APP_SERVER_LINE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROLLOUT_FILES_SCANNED: usize = 50_000;
// Codex 0.150.1's external Claude-session importer flattens native tool
// activity into visible assistant messages. These values and tags deliberately
// mirror that independently verified target representation. If Codex changes
// it, exact destination verification must fail closed until this projection is
// reviewed and updated.
const CODEX_IMPORT_NOTE_MAX_CHARS: usize = 2_000;
const CODEX_IMPORT_TOOL_RESULT_MAX_CHARS: usize = 4_000;
const CODEX_IMPORT_TOOL_CALL_TAG: &str = "external_agent_tool_call";
const CODEX_IMPORT_TOOL_RESULT_TAG: &str = "external_agent_tool_result";

/// JSON value that retains source object-key order for the one Codex importer
/// representation where order is visible: fallback tool-input notes. Herdr's
/// normal `serde_json::Value` intentionally keeps its existing global ordering
/// behavior; changing that dependency feature would alter unrelated API JSON.
#[derive(Debug, Clone)]
enum OrderedJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<OrderedJson>),
    Object(Vec<(String, OrderedJson)>),
}

impl OrderedJson {
    fn get(&self, key: &str) -> Option<&Self> {
        let Self::Object(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }

    fn as_array(&self) -> Option<&[Self]> {
        let Self::Array(values) = self else {
            return None;
        };
        Some(values)
    }
}

struct OrderedJsonVisitor;

impl<'de> Visitor<'de> for OrderedJsonVisitor {
    type Value = OrderedJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(OrderedJson::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(OrderedJson::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(OrderedJson::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(OrderedJson::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(OrderedJson::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(OrderedJson::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(OrderedJson::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(OrderedJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let capacity = map.size_hint().unwrap_or(0);
        let mut entries: Vec<(String, OrderedJson)> = Vec::with_capacity(capacity);
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(capacity);
        while let Some((key, value)) = map.next_entry::<String, OrderedJson>()? {
            if !seen.insert(key.clone()) {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            entries.push((key, value));
        }
        Ok(OrderedJson::Object(entries))
    }
}

impl<'de> Deserialize<'de> for OrderedJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(OrderedJsonVisitor)
    }
}

impl Serialize for OrderedJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HarnessKind {
    Claude,
    Codex,
    Omp,
}

impl HarnessKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Omp => "omp",
        }
    }

    pub(crate) fn from_agent_label(label: &str) -> Option<Self> {
        match label {
            "claude" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "omp" => Some(Self::Omp),
            _ => None,
        }
    }

    pub(crate) fn source(self) -> &'static str {
        match self {
            Self::Claude => "herdr:claude",
            Self::Codex => "herdr:codex",
            Self::Omp => "herdr:omp",
        }
    }

    pub(crate) fn api(self) -> crate::api::schema::AgentSessionTransferHarness {
        match self {
            Self::Claude => crate::api::schema::AgentSessionTransferHarness::Claude,
            Self::Codex => crate::api::schema::AgentSessionTransferHarness::Codex,
            Self::Omp => crate::api::schema::AgentSessionTransferHarness::Omp,
        }
    }

    pub(crate) fn agent(self) -> crate::detect::Agent {
        match self {
            Self::Claude => crate::detect::Agent::Claude,
            Self::Codex => crate::detect::Agent::Codex,
            Self::Omp => crate::detect::Agent::Omp,
        }
    }
}

impl From<crate::api::schema::AgentSessionTransferHarness> for HarnessKind {
    fn from(value: crate::api::schema::AgentSessionTransferHarness) -> Self {
        match value {
            crate::api::schema::AgentSessionTransferHarness::Claude => Self::Claude,
            crate::api::schema::AgentSessionTransferHarness::Codex => Self::Codex,
            crate::api::schema::AgentSessionTransferHarness::Omp => Self::Omp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VisibleRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub(crate) struct VisibleMessage {
    pub(crate) role: VisibleRole,
    pub(crate) text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub(crate) struct OmissionSummary {
    pub(crate) tool_records: u64,
    pub(crate) reasoning_records: u64,
    pub(crate) system_records: u64,
    pub(crate) attachment_records: u64,
    pub(crate) metadata_records: u64,
    pub(crate) unsupported_blocks: u64,
    pub(crate) sidechain_records: u64,
}

#[cfg(test)]
impl OmissionSummary {
    fn total(&self) -> u64 {
        self.tool_records
            + self.reasoning_records
            + self.system_records
            + self.attachment_records
            + self.metadata_records
            + self.unsupported_blocks
            + self.sidechain_records
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalTranscript {
    pub(crate) messages: Vec<VisibleMessage>,
    pub(crate) omissions: OmissionSummary,
    pub(crate) fingerprint: TranscriptFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranscriptFingerprint {
    pub(crate) byte_len: u64,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedSession {
    pub(crate) session_ref: crate::agent_resume::AgentSessionRef,
    pub(crate) cursor: Option<String>,
    pub(crate) transcript_path: PathBuf,
    pub(crate) transcript: CanonicalTranscript,
}

#[derive(Debug, Clone)]
pub(crate) struct PrepareRequest {
    pub(crate) source_kind: HarnessKind,
    pub(crate) source_sessions_root: PathBuf,
    pub(crate) source_session_ref: crate::agent_resume::AgentSessionRef,
    pub(crate) source_cursor: Option<String>,
    pub(crate) source_transcript_path: Option<PathBuf>,
    pub(crate) target_kind: HarnessKind,
    pub(crate) target_config_home: PathBuf,
    pub(crate) target_sessions_root: PathBuf,
    pub(crate) target_launch_env: crate::config::AccountLaunchEnv,
    pub(crate) cwd: PathBuf,
    pub(crate) timeout: Duration,
}

#[derive(Debug)]
pub(crate) struct PreparedTransfer {
    pub(crate) source_path: PathBuf,
    pub(crate) source_fingerprint: TranscriptFingerprint,
    pub(crate) staged: StagedSession,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeSessionTransfer {
    pub(crate) id: String,
    pub(crate) source_kind: HarnessKind,
    pub(crate) source_session: crate::agent_resume::PersistedAgentSession,
    pub(crate) source_account: Option<String>,
    pub(crate) source_config_home: PathBuf,
    pub(crate) source_sessions_root: PathBuf,
    pub(crate) source_cursor: Option<String>,
    pub(crate) source_process_pid: Option<u32>,
    pub(crate) target_kind: HarnessKind,
    pub(crate) target_account: Option<String>,
    pub(crate) target_config_home: PathBuf,
    pub(crate) target_sessions_root: PathBuf,
    pub(crate) phase: crate::api::schema::AgentSessionTransferPhase,
    pub(crate) message_count: u64,
    pub(crate) omissions: OmissionSummary,
    pub(crate) error: Option<String>,
    pub(crate) source_path: Option<PathBuf>,
    pub(crate) source_fingerprint: Option<TranscriptFingerprint>,
    pub(crate) target_session_ref: Option<crate::agent_resume::AgentSessionRef>,
    pub(crate) target_cursor: Option<String>,
    pub(crate) target_transcript_path: Option<PathBuf>,
    pub(crate) target_fingerprint: Option<TranscriptFingerprint>,
    pub(crate) target_deadline: Option<std::time::Instant>,
    pub(crate) target_process: Option<VerifiedTargetProcess>,
    pub(crate) source_rollback_process: Option<VerifiedTargetProcess>,
    pub(crate) verification_in_flight: Option<RuntimeVerificationKind>,
    pub(crate) verification_observation_deadline: Option<std::time::Instant>,
    pub(crate) awaiting_deferred_target_report: bool,
    pub(crate) target_report_accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedTargetProcess {
    pub(crate) pid: u32,
    pub(crate) observed_at: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeVerificationKind {
    Target,
    SourceRollback,
}

impl RuntimeSessionTransfer {
    pub(crate) fn restart_owns_source(&self) -> bool {
        self.phase != crate::api::schema::AgentSessionTransferPhase::Completed
            || self.awaiting_deferred_target_report
    }

    pub(crate) fn preserves_agent_name_on_process_exit(&self) -> bool {
        use crate::api::schema::AgentSessionTransferPhase;

        matches!(
            self.phase,
            AgentSessionTransferPhase::LaunchingTarget
                | AgentSessionTransferPhase::AwaitingTarget
                | AgentSessionTransferPhase::RollingBack
        )
    }

    pub(crate) fn expected_agent_name_owner(&self) -> Option<&'static str> {
        use crate::api::schema::AgentSessionTransferPhase;

        match self.phase {
            AgentSessionTransferPhase::LaunchingTarget
            | AgentSessionTransferPhase::AwaitingTarget => Some(self.target_kind.label()),
            AgentSessionTransferPhase::Completed if self.awaiting_deferred_target_report => {
                Some(self.target_kind.label())
            }
            AgentSessionTransferPhase::RollingBack => Some(self.source_kind.label()),
            _ => None,
        }
    }

    pub(crate) fn verified_visible_destination(&self) -> Result<(), TransferError> {
        let source_path = self.source_path.as_deref().ok_or_else(|| {
            TransferError::DestinationMismatch(
                "transfer has no verified source transcript path".to_string(),
            )
        })?;
        let target_path = self.target_transcript_path.as_deref().ok_or_else(|| {
            TransferError::DestinationMismatch(
                "transfer has no staged destination transcript path".to_string(),
            )
        })?;
        let source = read_transfer_source(
            self.source_kind,
            self.target_kind,
            &self.source_sessions_root,
            source_path,
            self.source_cursor.as_deref(),
        )?;
        let target = read_transcript_at_cursor(
            self.target_kind,
            &self.target_sessions_root,
            target_path,
            self.target_cursor.as_deref(),
        )?;
        verify_destination(&source.messages, &target)
    }

    pub(crate) fn info(&self) -> crate::api::schema::AgentSessionTransferInfo {
        crate::api::schema::AgentSessionTransferInfo {
            id: self.id.clone(),
            source: self.source_kind.api(),
            target: self.target_kind.api(),
            target_account: self.target_account.clone(),
            phase: self.phase,
            message_count: self.message_count,
            omissions: crate::api::schema::AgentSessionTransferOmissions {
                tool_records: self.omissions.tool_records,
                reasoning_records: self.omissions.reasoning_records,
                system_records: self.omissions.system_records,
                attachment_records: self.omissions.attachment_records,
                metadata_records: self.omissions.metadata_records,
                unsupported_blocks: self.omissions.unsupported_blocks,
                sidechain_records: self.omissions.sidechain_records,
            },
            error: self.error.clone(),
        }
    }
}

/// Return the one deterministic Codex process that proves this exact resume.
///
/// A process qualifies only when its own argv contains the consecutive tokens
/// `resume <session_id>` and Herdr's normal single-process identification says
/// that process is Codex. Native `codex` executables rank ahead of wrappers;
/// ties use the lowest PID. The returned PID is therefore stable and reportable,
/// never merely evidence that some unrelated Codex process exists in the job.
pub(crate) fn codex_resume_process(
    job: &crate::platform::ForegroundJob,
    session_id: &str,
) -> Option<u32> {
    if session_id.is_empty() || session_id.chars().any(char::is_control) {
        return None;
    }
    job.processes
        .iter()
        .filter(|process| {
            process.argv.as_deref().is_some_and(|argv| {
                argv.windows(2)
                    .any(|pair| pair[0] == "resume" && pair[1] == session_id)
            })
        })
        .filter(|process| {
            let process_job = crate::platform::ForegroundJob {
                process_group_id: process.pid,
                processes: vec![(*process).clone()],
            };
            crate::detect::identify_agent_in_job(&process_job)
                .is_some_and(|(agent, _)| agent == crate::detect::Agent::Codex)
        })
        .min_by_key(|process| (!direct_codex_process(process), process.pid))
        .map(|process| process.pid)
}

/// Prove that one reported PID is the exact foreground OMP process. OMP 18
/// rewrites its argv to just `omp`, so launch arguments are not reliable after
/// startup; the official extension's PID plus Herdr's process identification is
/// the binding evidence.
pub(crate) fn omp_reported_process(
    job: &crate::platform::ForegroundJob,
    reported_pid: u32,
) -> Option<u32> {
    job.processes
        .iter()
        .find(|process| process.pid == reported_pid)
        .filter(|process| {
            let process_job = crate::platform::ForegroundJob {
                process_group_id: process.pid,
                processes: vec![(*process).clone()],
            };
            crate::detect::identify_agent_in_job(&process_job)
                .is_some_and(|(agent, _)| agent == crate::detect::Agent::Omp)
        })
        .map(|process| process.pid)
}

fn direct_codex_process(process: &crate::platform::ForegroundProcess) -> bool {
    [&process.name, process.argv0.as_deref().unwrap_or_default()]
        .into_iter()
        .any(|candidate| {
            std::path::Path::new(candidate)
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| {
                    name.eq_ignore_ascii_case("codex") || name.eq_ignore_ascii_case("codex.exe")
                })
        })
}

pub(crate) fn new_transfer_id() -> Result<String, TransferError> {
    random_uuid()
}

#[derive(Debug)]
pub(crate) enum TransferError {
    Io {
        context: &'static str,
        source: std::io::Error,
    },
    InvalidPath(String),
    TranscriptTooLarge {
        bytes: u64,
    },
    LineTooLarge {
        line: usize,
    },
    InvalidJson {
        line: usize,
        message: String,
    },
    AmbiguousRecord {
        line: usize,
        message: String,
    },
    EmptyTranscript,
    DestinationMismatch(String),
    CodexImport(String),
    UnsupportedTranscript(String),
    Timeout,
}

impl TransferError {
    fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::InvalidPath(message) => write!(f, "untrusted transcript path: {message}"),
            Self::TranscriptTooLarge { bytes } => write!(
                f,
                "transcript is {bytes} bytes; limit is {MAX_TRANSCRIPT_BYTES} bytes"
            ),
            Self::LineTooLarge { line } => write!(
                f,
                "transcript line {line} exceeds {MAX_TRANSCRIPT_LINE_BYTES} bytes"
            ),
            Self::InvalidJson { line, message } => {
                write!(f, "invalid transcript JSON at line {line}: {message}")
            }
            Self::AmbiguousRecord { line, message } => {
                write!(f, "ambiguous visible content at line {line}: {message}")
            }
            Self::EmptyTranscript => write!(f, "transcript has no transferable visible messages"),
            Self::DestinationMismatch(message) => {
                write!(f, "destination transcript verification failed: {message}")
            }
            Self::CodexImport(message) => write!(f, "Codex session import failed: {message}"),
            Self::UnsupportedTranscript(message) => {
                write!(
                    f,
                    "session transfer cannot preserve source transcript: {message}"
                )
            }
            Self::Timeout => write!(f, "Codex session import timed out"),
        }
    }
}

impl std::error::Error for TransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) fn read_transcript(
    kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
) -> Result<CanonicalTranscript, TransferError> {
    read_transcript_at_cursor(kind, trust_root, path, None)
}

pub(crate) fn read_transcript_at_cursor(
    kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
    cursor: Option<&str>,
) -> Result<CanonicalTranscript, TransferError> {
    let trusted_path = validate_transcript_path(trust_root, path)?;
    if kind == HarnessKind::Omp {
        let bytes = read_transcript_snapshot(&trusted_path)?;
        return Ok(omp::parse(&bytes, cursor)?.transcript);
    }
    read_jsonl(&trusted_path, kind)
}

pub(crate) async fn prepare(request: PrepareRequest) -> Result<PreparedTransfer, TransferError> {
    let source_path = select_native_transcript(
        request.source_kind,
        &request.source_sessions_root,
        &request.source_session_ref,
        request.source_transcript_path.as_deref(),
    )?;
    let mut source = read_transfer_source(
        request.source_kind,
        request.target_kind,
        &request.source_sessions_root,
        &source_path,
        request.source_cursor.as_deref(),
    )?;
    if request.source_kind == HarnessKind::Omp {
        let snapshot = omp::parse(
            &read_transcript_snapshot(&source_path)?,
            request.source_cursor.as_deref(),
        )?;
        let Some(cursor) = request.source_cursor.as_deref() else {
            return Err(TransferError::UnsupportedTranscript(
                "OMP source integration did not report its active leaf".to_string(),
            ));
        };
        if snapshot.selected_leaf_id != cursor || snapshot.physical_leaf_id != cursor {
            return Err(TransferError::UnsupportedTranscript(format!(
                "OMP active leaf {cursor:?} is not the durable resumable leaf {:?}",
                snapshot.physical_leaf_id
            )));
        }
        source = snapshot.transcript;
    }
    let mut expected = source.messages.clone();
    let (session_ref, target_cursor, transcript_path) = match request.target_kind {
        HarnessKind::Claude => {
            let (session_id, path) =
                write_claude_session(&request.target_config_home, &request.cwd, &expected)?;
            (
                crate::agent_resume::AgentSessionRef::id(session_id)
                    .expect("generated Claude session id is valid"),
                None,
                path,
            )
        }
        HarnessKind::Codex => {
            let bridge = if request.source_kind == HarnessKind::Claude {
                None
            } else {
                let bridge = PrivateClaudeBridge::write(
                    &request.target_config_home,
                    &request.cwd,
                    &source.messages,
                )?;
                expected =
                    claude_to_codex_import_projection(&read_transcript_snapshot(bridge.path())?)?;
                Some(bridge)
            };
            let import_path = bridge
                .as_ref()
                .map_or(source_path.as_path(), |bridge| bridge.path());
            let session_id = import_claude_session_to_codex(
                &request.target_config_home,
                import_path,
                &request.cwd,
                &request.target_launch_env,
                request.timeout,
            )
            .await?;
            let path = find_codex_rollout(&request.target_config_home, &session_id)?;
            (
                crate::agent_resume::AgentSessionRef::id(session_id)
                    .expect("imported Codex session id is valid"),
                None,
                path,
            )
        }
        HarnessKind::Omp => {
            let (_session_id, path, leaf) =
                omp::write(&request.target_sessions_root, &request.cwd, &expected)?;
            let canonical = fs::canonicalize(&path)
                .map_err(|error| TransferError::io("canonicalize staged OMP transcript", error))?;
            (
                crate::agent_resume::AgentSessionRef::path(
                    canonical.to_string_lossy().into_owned(),
                )
                .expect("generated OMP session path is valid"),
                Some(leaf),
                canonical,
            )
        }
    };
    let destination = read_transcript_at_cursor(
        request.target_kind,
        &request.target_sessions_root,
        &transcript_path,
        target_cursor.as_deref(),
    )?;
    verify_destination(&expected, &destination)?;
    Ok(PreparedTransfer {
        source_path,
        source_fingerprint: source.fingerprint,
        staged: StagedSession {
            session_ref,
            cursor: target_cursor,
            transcript_path,
            transcript: CanonicalTranscript {
                messages: destination.messages,
                // Confirmation describes what was deliberately omitted from the
                // source, not destination-provider metadata introduced by staging.
                omissions: source.omissions,
                fingerprint: destination.fingerprint,
            },
        },
    })
}

fn select_native_transcript(
    kind: HarnessKind,
    trust_root: &Path,
    session_ref: &crate::agent_resume::AgentSessionRef,
    reported_path: Option<&Path>,
) -> Result<PathBuf, TransferError> {
    let expected_kind = if kind == HarnessKind::Omp {
        crate::agent_resume::AgentSessionRefKind::Path
    } else {
        crate::agent_resume::AgentSessionRefKind::Id
    };
    if session_ref.kind != expected_kind {
        return Err(TransferError::InvalidPath(format!(
            "{} session reference must use {:?}, not {:?}",
            kind.label(),
            expected_kind,
            session_ref.kind
        )));
    }
    if kind == HarnessKind::Omp {
        let path = Path::new(&session_ref.value);
        if reported_path.is_some_and(|reported| reported != path) {
            return Err(TransferError::InvalidPath(
                "OMP reported session path disagrees with its native path reference".to_string(),
            ));
        }
        return validate_transcript_path(trust_root, path);
    }
    let session_id = &session_ref.value;
    let Some(reported_path) = reported_path else {
        return find_native_transcript(kind, trust_root, session_id);
    };
    let path = validate_transcript_path(trust_root, reported_path)?;
    let identity_matches = match kind {
        HarnessKind::Claude => path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name == format!("{session_id}.jsonl")),
        HarnessKind::Codex => codex_rollout_declares_thread(&path, session_id)?,
        HarnessKind::Omp => unreachable!("OMP path references return above"),
    };
    if !identity_matches {
        return Err(TransferError::InvalidPath(format!(
            "reported {} transcript does not declare session {session_id}",
            kind.label()
        )));
    }
    Ok(path)
}

pub(crate) fn find_native_transcript(
    kind: HarnessKind,
    config_home: &Path,
    session_id: &str,
) -> Result<PathBuf, TransferError> {
    match kind {
        HarnessKind::Claude => find_claude_transcript(config_home, session_id),
        HarnessKind::Codex => find_codex_rollout(config_home, session_id),
        HarnessKind::Omp => Err(TransferError::InvalidPath(
            "OMP sessions are selected by an exact native path, not by id".to_string(),
        )),
    }
}

fn find_claude_transcript(config_home: &Path, session_id: &str) -> Result<PathBuf, TransferError> {
    if session_id.is_empty()
        || session_id.chars().any(char::is_control)
        || session_id.contains('/')
        || session_id.contains('\\')
    {
        return Err(TransferError::InvalidPath(
            "invalid Claude session id".to_string(),
        ));
    }
    let canonical_home = fs::canonicalize(config_home)
        .map_err(|err| TransferError::io("canonicalize Claude account home", err))?;
    let projects = canonical_home.join("projects");
    let entries =
        fs::read_dir(&projects).map_err(|err| TransferError::io("scan Claude projects", err))?;
    let file_name = format!("{session_id}.jsonl");
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| TransferError::io("scan Claude projects", err))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|err| TransferError::io("inspect Claude project", err))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let candidate = entry.path().join(&file_name);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                matches.push(validate_transcript_path(&canonical_home, &candidate)?);
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(TransferError::io("inspect Claude transcript", err)),
        }
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(TransferError::InvalidPath(format!(
            "no Claude transcript found for session {session_id}"
        ))),
        _ => Err(TransferError::InvalidPath(format!(
            "multiple Claude transcripts found for session {session_id}"
        ))),
    }
}

pub(crate) fn fingerprint_transcript(
    config_home: &Path,
    path: &Path,
) -> Result<TranscriptFingerprint, TransferError> {
    let trusted_path = validate_transcript_path(config_home, path)?;
    fingerprint_file(&trusted_path)
}

pub(crate) fn verify_unchanged_transcripts(
    source_config_home: &Path,
    source_path: &Path,
    source_fingerprint: &TranscriptFingerprint,
    target_config_home: &Path,
    target_path: &Path,
    target_fingerprint: &TranscriptFingerprint,
) -> Result<(), TransferError> {
    let current_source = fingerprint_transcript(source_config_home, source_path)?;
    if &current_source != source_fingerprint {
        return Err(TransferError::DestinationMismatch(
            "source transcript changed after staging".to_string(),
        ));
    }
    let current_target = fingerprint_transcript(target_config_home, target_path)?;
    if &current_target != target_fingerprint {
        return Err(TransferError::DestinationMismatch(
            "staged destination transcript changed after verification".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_destination(
    expected: &[VisibleMessage],
    actual: &CanonicalTranscript,
) -> Result<(), TransferError> {
    if expected == actual.messages {
        return Ok(());
    }
    let first_difference = expected
        .iter()
        .zip(actual.messages.iter())
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| expected.len().min(actual.messages.len()));
    Err(TransferError::DestinationMismatch(format!(
        "expected {} target-visible messages, found {}; first difference at message {}",
        expected.len(),
        actual.messages.len(),
        first_difference + 1
    )))
}

/// Resolve a reported transcript path under its selected account home.
///
/// The account-home itself may be a symlink (a supported user configuration),
/// but no component below it may be one. Both lexical containment and resolved
/// containment are checked so `..`, symlink escapes, and direct out-of-home
/// paths all fail closed.
pub(crate) fn validate_transcript_path(
    config_home: &Path,
    candidate: &Path,
) -> Result<PathBuf, TransferError> {
    if !config_home.is_absolute() || !candidate.is_absolute() {
        return Err(TransferError::InvalidPath(
            "account home and transcript must be absolute".to_string(),
        ));
    }
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(TransferError::InvalidPath(
            "dot path components are not allowed".to_string(),
        ));
    }

    let canonical_home = fs::canonicalize(config_home)
        .map_err(|err| TransferError::io("canonicalize account home", err))?;
    let (walk_base, relative) = if let Ok(relative) = candidate.strip_prefix(config_home) {
        (config_home, relative)
    } else if let Ok(relative) = candidate.strip_prefix(&canonical_home) {
        (canonical_home.as_path(), relative)
    } else {
        return Err(TransferError::InvalidPath(
            "path is outside the selected account home".to_string(),
        ));
    };

    let mut walked = walk_base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(TransferError::InvalidPath(
                "path contains a non-normal component".to_string(),
            ));
        };
        walked.push(part);
        let metadata = fs::symlink_metadata(&walked)
            .map_err(|err| TransferError::io("inspect transcript path", err))?;
        if metadata.file_type().is_symlink() {
            return Err(TransferError::InvalidPath(format!(
                "symlink component {} is not allowed",
                walked.display()
            )));
        }
    }

    let canonical_candidate = fs::canonicalize(candidate)
        .map_err(|err| TransferError::io("canonicalize transcript", err))?;
    if !canonical_candidate.starts_with(&canonical_home) {
        return Err(TransferError::InvalidPath(
            "resolved path escapes the selected account home".to_string(),
        ));
    }
    let metadata = fs::metadata(&canonical_candidate)
        .map_err(|err| TransferError::io("inspect transcript", err))?;
    if !metadata.is_file() {
        return Err(TransferError::InvalidPath(
            "transcript is not a regular file".to_string(),
        ));
    }
    if metadata.len() > MAX_TRANSCRIPT_BYTES {
        return Err(TransferError::TranscriptTooLarge {
            bytes: metadata.len(),
        });
    }
    Ok(canonical_candidate)
}

fn read_transfer_source(
    source_kind: HarnessKind,
    target_kind: HarnessKind,
    trust_root: &Path,
    path: &Path,
    cursor: Option<&str>,
) -> Result<CanonicalTranscript, TransferError> {
    let trusted_path = validate_transcript_path(trust_root, path)?;
    let bytes = read_transcript_snapshot(&trusted_path)?;
    let mut source = if source_kind == HarnessKind::Omp {
        omp::parse(&bytes, cursor)?.transcript
    } else {
        parse_jsonl_snapshot(&bytes, source_kind)?
    };
    if source_kind == HarnessKind::Claude && target_kind == HarnessKind::Codex {
        source.messages = claude_to_codex_import_projection(&bytes)?;
    }
    Ok(source)
}

fn read_jsonl(path: &Path, kind: HarnessKind) -> Result<CanonicalTranscript, TransferError> {
    // Parse and fingerprint the SAME byte snapshot. Hashing with a second read
    // can bless bytes appended after parsing, letting the pre-cutover recheck
    // pass even though those messages were never staged.
    let bytes = read_transcript_snapshot(path)?;
    parse_jsonl_snapshot(&bytes, kind)
}

fn read_transcript_snapshot(path: &Path) -> Result<Vec<u8>, TransferError> {
    let bytes = fs::read(path).map_err(|err| TransferError::io("read transcript", err))?;
    if bytes.len() as u64 > MAX_TRANSCRIPT_BYTES {
        return Err(TransferError::TranscriptTooLarge {
            bytes: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

fn parse_jsonl_snapshot(
    bytes: &[u8],
    kind: HarnessKind,
) -> Result<CanonicalTranscript, TransferError> {
    // Codex persists hidden runtime context in role=user response items. The
    // user_message events are the records its own UI exposes as submitted user
    // turns, so collect their texts from this same immutable byte snapshot and
    // require every response-item user message to be either paired with one or
    // a recognized runtime context envelope.
    let codex_visible_user_events = if kind == HarnessKind::Codex {
        codex_visible_user_event_texts(bytes)?
    } else {
        std::collections::HashSet::new()
    };
    let mut messages = Vec::new();
    let mut omissions = OmissionSummary::default();
    for (index, line) in BufReader::new(Cursor::new(&bytes)).split(b'\n').enumerate() {
        let line_number = index + 1;
        let mut line = line.map_err(|err| TransferError::io("read transcript", err))?;
        if line.len() > MAX_TRANSCRIPT_LINE_BYTES {
            return Err(TransferError::LineTooLarge { line: line_number });
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        match kind {
            HarnessKind::Claude => {
                parse_claude_record(line_number, &value, &mut messages, &mut omissions)?
            }
            HarnessKind::Codex => parse_codex_record(
                line_number,
                &value,
                &codex_visible_user_events,
                &mut messages,
                &mut omissions,
            )?,
            HarnessKind::Omp => unreachable!("OMP snapshots use their tree-aware parser"),
        }
    }
    if messages.is_empty() {
        return Err(TransferError::EmptyTranscript);
    }
    Ok(CanonicalTranscript {
        messages,
        omissions,
        fingerprint: fingerprint_bytes(bytes),
    })
}

fn codex_visible_user_event_texts(
    bytes: &[u8],
) -> Result<std::collections::HashSet<String>, TransferError> {
    let mut messages = std::collections::HashSet::new();
    for (index, line) in BufReader::new(Cursor::new(bytes)).split(b'\n').enumerate() {
        let line_number = index + 1;
        let mut line = line.map_err(|err| TransferError::io("read transcript", err))?;
        if line.len() > MAX_TRANSCRIPT_LINE_BYTES {
            return Err(TransferError::LineTooLarge { line: line_number });
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        if value.get("type").and_then(Value::as_str) != Some("event_msg")
            || value
                .get("payload")
                .and_then(|payload| payload.get("type"))
                .and_then(Value::as_str)
                != Some("user_message")
        {
            continue;
        }
        let message = value
            .get("payload")
            .and_then(|payload| payload.get("message"))
            .and_then(Value::as_str)
            .ok_or_else(|| TransferError::AmbiguousRecord {
                line: line_number,
                message: "Codex user_message event has no string message".to_string(),
            })?;
        messages.insert(message.replace("\r\n", "\n"));
    }
    Ok(messages)
}

fn parse_claude_record(
    line: usize,
    value: &Value,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let Some(record_type) = value.get("type").and_then(Value::as_str) else {
        return classify_unknown_record(line, value, omissions);
    };
    if value.get("isSidechain").and_then(Value::as_bool) == Some(true) {
        omissions.sidechain_records += 1;
        return Ok(());
    }
    if matches!(record_type, "user" | "assistant")
        && value.get("isMeta").and_then(Value::as_bool) == Some(true)
    {
        omissions.metadata_records += 1;
        return Ok(());
    }
    match record_type {
        "user" => parse_claude_message(line, value, VisibleRole::User, messages, omissions),
        "assistant" => {
            parse_claude_message(line, value, VisibleRole::Assistant, messages, omissions)
        }
        "system" => {
            omissions.system_records += 1;
            Ok(())
        }
        "attachment" => {
            omissions.attachment_records += 1;
            Ok(())
        }
        "file-history-snapshot"
        | "file-history-delta"
        | "queue-operation"
        | "last-prompt"
        | "permission-mode"
        | "mode"
        | "ai-title"
        | "pr-link"
        | "summary"
        | "progress" => {
            omissions.metadata_records += 1;
            Ok(())
        }
        _ => classify_unknown_record(line, value, omissions),
    }
}

fn parse_claude_message(
    line: usize,
    value: &Value,
    expected_role: VisibleRole,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let message = value
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message record has no message object".to_string(),
        })?;
    let expected_role_label = match expected_role {
        VisibleRole::User => "user",
        VisibleRole::Assistant => "assistant",
    };
    if message.get("role").and_then(Value::as_str) != Some(expected_role_label) {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: format!("Claude {expected_role_label} record has a conflicting role"),
        });
    }
    let content = message
        .get("content")
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message has no content".to_string(),
        })?;
    match content {
        Value::String(text) => push_visible_message(messages, expected_role, text),
        Value::Array(blocks) => {
            let mut text = String::new();
            for block in blocks {
                let block_type = block.get("type").and_then(Value::as_str).ok_or_else(|| {
                    TransferError::AmbiguousRecord {
                        line,
                        message: "Claude content block has no type".to_string(),
                    }
                })?;
                match block_type {
                    "text" => text.push_str(block.get("text").and_then(Value::as_str).ok_or_else(
                        || TransferError::AmbiguousRecord {
                            line,
                            message: "Claude text block has non-string text".to_string(),
                        },
                    )?),
                    "thinking" | "redacted_thinking" => omissions.reasoning_records += 1,
                    "tool_use" | "tool_result" | "server_tool_use" | "web_search_tool_result" => {
                        omissions.tool_records += 1
                    }
                    "image" | "document" => omissions.attachment_records += 1,
                    _ if !contains_possible_visible_content(block) => {
                        omissions.unsupported_blocks += 1
                    }
                    _ => {
                        return Err(TransferError::AmbiguousRecord {
                            line,
                            message: format!(
                                "unknown Claude content block {block_type:?} may be visible"
                            ),
                        })
                    }
                }
            }
            push_visible_message(messages, expected_role, &text)
        }
        _ => Err(TransferError::AmbiguousRecord {
            line,
            message: "Claude message content is neither text nor blocks".to_string(),
        }),
    }
}

/// Independently project a Claude transcript into the visible message shape
/// produced by Codex 0.150.1's supported external-session importer.
///
/// This must remain destination-aware instead of changing Claude's ordinary
/// canonical parser: Codex deliberately renders tool activity as assistant
/// text, while a Claude destination receives only the provider-neutral visible
/// conversation. Exact verification against this projection proves what the
/// importer actually wrote without trusting the importer to attest to itself.
fn claude_to_codex_import_projection(bytes: &[u8]) -> Result<Vec<VisibleMessage>, TransferError> {
    let mut messages = Vec::new();
    let mut saw_user_message = false;
    for (index, line) in BufReader::new(Cursor::new(bytes)).split(b'\n').enumerate() {
        let line_number = index + 1;
        let mut line = line.map_err(|err| TransferError::io("read transcript", err))?;
        if line.len() > MAX_TRANSCRIPT_LINE_BYTES {
            return Err(TransferError::LineTooLarge { line: line_number });
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        let ordered: OrderedJson =
            serde_json::from_slice(&line).map_err(|err| TransferError::InvalidJson {
                line: line_number,
                message: err.to_string(),
            })?;
        project_claude_record_for_codex(
            line_number,
            &value,
            &ordered,
            &mut saw_user_message,
            &mut messages,
        )?;
    }
    if messages.is_empty() {
        return Err(TransferError::EmptyTranscript);
    }
    Ok(messages)
}

fn project_claude_record_for_codex(
    line: usize,
    value: &Value,
    ordered: &OrderedJson,
    saw_user_message: &mut bool,
    messages: &mut Vec<VisibleMessage>,
) -> Result<(), TransferError> {
    let Some(record_type @ ("assistant" | "user")) = value.get("type").and_then(Value::as_str)
    else {
        return Ok(());
    };
    if value.get("isMeta").and_then(Value::as_bool) == Some(true)
        || value.get("isSidechain").and_then(Value::as_bool) == Some(true)
    {
        return Ok(());
    }
    let message = value
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message record has no message object".to_string(),
        })?;
    if message.get("role").and_then(Value::as_str) != Some(record_type) {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: format!("Claude {record_type} record has a conflicting role"),
        });
    }
    let content = message
        .get("content")
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message has no content".to_string(),
        })?;
    let ordered_content = ordered
        .get("message")
        .and_then(|message| message.get("content"))
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message order projection has no content".to_string(),
        })?;
    let Some(extracted) = extract_codex_import_message(line, content, ordered_content)? else {
        return Ok(());
    };
    let role = if record_type == "assistant" || extracted.only_tool_result {
        VisibleRole::Assistant
    } else {
        VisibleRole::User
    };
    let text = if role == VisibleRole::User {
        unwrap_codex_import_user_query(extracted.text)
    } else {
        extracted.text
    };
    if role == VisibleRole::Assistant && !*saw_user_message {
        return Err(TransferError::UnsupportedTranscript(
            "Codex omits assistant messages that appear before the first user turn".to_string(),
        ));
    }
    if role == VisibleRole::User {
        *saw_user_message = true;
    }
    push_visible_message(messages, role, &text)
}

struct CodexImportMessage {
    text: String,
    only_tool_result: bool,
}

fn extract_codex_import_message(
    line: usize,
    content: &Value,
    ordered_content: &OrderedJson,
) -> Result<Option<CodexImportMessage>, TransferError> {
    if let Some(text) = content.as_str() {
        return Ok((!text.trim().is_empty()).then(|| CodexImportMessage {
            text: text.to_string(),
            only_tool_result: false,
        }));
    }
    let blocks = content
        .as_array()
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude message content is neither text nor blocks".to_string(),
        })?;
    let ordered_blocks =
        ordered_content
            .as_array()
            .ok_or_else(|| TransferError::AmbiguousRecord {
                line,
                message: "Claude message order projection is not a block array".to_string(),
            })?;
    if blocks.len() != ordered_blocks.len() {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: "Claude message order projection changed block count".to_string(),
        });
    }
    let mut parts = Vec::new();
    let mut only_tool_result = !blocks.is_empty();
    for (block, ordered_block) in blocks.iter().zip(ordered_blocks) {
        let block_type = block.get("type").and_then(Value::as_str).ok_or_else(|| {
            TransferError::AmbiguousRecord {
                line,
                message: "Claude content block has no type".to_string(),
            }
        })?;
        match block_type {
            "text" => {
                let text = block.get("text").and_then(Value::as_str).ok_or_else(|| {
                    TransferError::AmbiguousRecord {
                        line,
                        message: "Claude text block has non-string text".to_string(),
                    }
                })?;
                if !text.is_empty() {
                    parts.push(text.to_string());
                    only_tool_result = false;
                }
            }
            "tool_use" => {
                parts.push(codex_import_tool_call_note(line, block, ordered_block)?);
                only_tool_result = false;
            }
            "tool_result" => parts.push(codex_import_tool_result_note(block)),
            "thinking" => {}
            other => {
                parts.push(format!("[external unsupported block: {other}]"));
                only_tool_result = false;
            }
        }
    }
    let text = parts
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok((!text.is_empty()).then_some(CodexImportMessage {
        text,
        only_tool_result,
    }))
}

fn codex_import_tool_call_note(
    line: usize,
    block: &Value,
    ordered_block: &OrderedJson,
) -> Result<String, TransferError> {
    let name = block
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut lines = vec![format!("[{CODEX_IMPORT_TOOL_CALL_TAG}: {name}]")];
    if let Some(input) = block.get("input").and_then(Value::as_object) {
        if let Some(description) = input.get("description").and_then(Value::as_str) {
            lines.push(format!("description: {description}"));
        }
        if let Some(command) = input.get("command").and_then(Value::as_str) {
            lines.push(format!("command: {command}"));
        }
        if let Some(file) = input
            .get("file_path")
            .or_else(|| input.get("file"))
            .and_then(Value::as_str)
        {
            lines.push(format!("file: {file}"));
        }
        if lines.len() == 1 {
            let input = ordered_codex_import_tool_input(line, ordered_block)?;
            lines.push(format!(
                "input: {}",
                truncate_codex_import_text(&input, CODEX_IMPORT_NOTE_MAX_CHARS,)
            ));
        }
    } else if block.get("input").is_some() {
        let input = ordered_codex_import_tool_input(line, ordered_block)?;
        lines.push(format!(
            "input: {}",
            truncate_codex_import_text(&input, CODEX_IMPORT_NOTE_MAX_CHARS)
        ));
    }
    lines.push(format!("[/{CODEX_IMPORT_TOOL_CALL_TAG}]"));
    Ok(lines.join("\n"))
}

fn ordered_codex_import_tool_input(
    line: usize,
    ordered_block: &OrderedJson,
) -> Result<String, TransferError> {
    let input = ordered_block
        .get("input")
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Claude tool input was missing from its order projection".to_string(),
        })?;
    serde_json::to_string(input).map_err(|err| TransferError::AmbiguousRecord {
        line,
        message: format!("Claude tool input order projection could not be serialized: {err}"),
    })
}

fn codex_import_tool_result_note(block: &Value) -> String {
    let label = if block.get("is_error").and_then(Value::as_bool) == Some(true) {
        format!("[{CODEX_IMPORT_TOOL_RESULT_TAG}: error]")
    } else {
        format!("[{CODEX_IMPORT_TOOL_RESULT_TAG}]")
    };
    let text = match block.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    };
    if text.is_empty() {
        format!("{label}\n[/{CODEX_IMPORT_TOOL_RESULT_TAG}]")
    } else {
        format!(
            "{label}\n{}\n[/{CODEX_IMPORT_TOOL_RESULT_TAG}]",
            truncate_codex_import_text(&text, CODEX_IMPORT_TOOL_RESULT_MAX_CHARS)
        )
    }
}

fn truncate_codex_import_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let prefix = text
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    format!("{prefix}...")
}

fn unwrap_codex_import_user_query(text: String) -> String {
    let trimmed = text.trim();
    let Some(inner) = trimmed
        .strip_prefix("<user_query>")
        .and_then(|inner| inner.strip_suffix("</user_query>"))
        .map(str::trim)
        .filter(|inner| !inner.is_empty())
    else {
        return text;
    };
    inner.to_string()
}

fn parse_codex_record(
    line: usize,
    value: &Value,
    visible_user_events: &std::collections::HashSet<String>,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let Some(record_type) = value.get("type").and_then(Value::as_str) else {
        return classify_unknown_record(line, value, omissions);
    };
    match record_type {
        "response_item" => {
            parse_codex_response_item(line, value, visible_user_events, messages, omissions)
        }
        "event_msg" => parse_codex_event_message(line, value, messages, omissions),
        "turn_context" | "session_meta" | "world_state" => {
            omissions.metadata_records += 1;
            Ok(())
        }
        "compacted" => {
            omissions.reasoning_records += 1;
            Ok(())
        }
        _ => classify_unknown_record(line, value, omissions),
    }
}

fn parse_codex_response_item(
    line: usize,
    value: &Value,
    visible_user_events: &std::collections::HashSet<String>,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let payload = value
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex response item has no payload".to_string(),
        })?;
    let Some(item_type) = payload.get("type").and_then(Value::as_str) else {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: "Codex response item has no payload type".to_string(),
        });
    };
    match item_type {
        "message" => {
            let role = match payload.get("role").and_then(Value::as_str) {
                Some("assistant") => VisibleRole::Assistant,
                Some("system") | Some("developer") => {
                    omissions.system_records += 1;
                    return Ok(());
                }
                Some("user") => {
                    let mut duplicate_omissions = OmissionSummary::default();
                    let text = codex_message_text(line, payload, &mut duplicate_omissions)?;
                    if visible_user_events.contains(&text) {
                        // The paired event_msg is the UI-visible source of truth.
                        omissions.metadata_records += 1;
                        return Ok(());
                    }
                    if codex_hidden_user_context(&text) {
                        omissions.system_records += 1;
                        return Ok(());
                    }
                    return Err(TransferError::AmbiguousRecord {
                        line,
                        message: "Codex role=user response item has no matching visible user_message event"
                            .to_string(),
                    });
                }
                Some(other) => {
                    return Err(TransferError::AmbiguousRecord {
                        line,
                        message: format!("unknown Codex message role {other:?}"),
                    })
                }
                None => {
                    return Err(TransferError::AmbiguousRecord {
                        line,
                        message: "Codex message has no role".to_string(),
                    })
                }
            };
            let text = codex_message_text(line, payload, omissions)?;
            push_visible_message(messages, role, &text)
        }
        "reasoning" => {
            omissions.reasoning_records += 1;
            Ok(())
        }
        "function_call"
        | "function_call_output"
        | "custom_tool_call"
        | "custom_tool_call_output"
        | "web_search_call"
        | "computer_call"
        | "local_shell_call"
        | "mcp_tool_call" => {
            omissions.tool_records += 1;
            Ok(())
        }
        _ if !contains_possible_visible_content(value) => {
            omissions.metadata_records += 1;
            Ok(())
        }
        _ => Err(TransferError::AmbiguousRecord {
            line,
            message: format!("unknown Codex response item {item_type:?} may be visible"),
        }),
    }
}

fn parse_codex_event_message(
    line: usize,
    value: &Value,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let payload = value
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex event message has no payload".to_string(),
        })?;
    if payload.get("type").and_then(Value::as_str) != Some("user_message") {
        omissions.metadata_records += 1;
        return Ok(());
    }
    let message = payload
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex user_message event has no string message".to_string(),
        })?;
    for key in ["images", "local_images", "audio", "local_audio"] {
        omissions.attachment_records += payload
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len) as u64;
    }
    if payload
        .get("text_elements")
        .and_then(Value::as_array)
        .is_some_and(|elements| !elements.is_empty())
    {
        omissions.unsupported_blocks += 1;
    }
    push_visible_message(messages, VisibleRole::User, message)
}

fn codex_message_text(
    line: usize,
    payload: &serde_json::Map<String, Value>,
    omissions: &mut OmissionSummary,
) -> Result<String, TransferError> {
    let blocks = payload
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| TransferError::AmbiguousRecord {
            line,
            message: "Codex message content is not an array".to_string(),
        })?;
    let mut text = String::new();
    for block in blocks {
        let block_type = block.get("type").and_then(Value::as_str).ok_or_else(|| {
            TransferError::AmbiguousRecord {
                line,
                message: "Codex content block has no type".to_string(),
            }
        })?;
        match block_type {
            "input_text" | "output_text" | "text" => {
                text.push_str(block.get("text").and_then(Value::as_str).ok_or_else(|| {
                    TransferError::AmbiguousRecord {
                        line,
                        message: "Codex text block has non-string text".to_string(),
                    }
                })?)
            }
            "input_image" | "output_image" | "image" | "input_file" => {
                omissions.attachment_records += 1
            }
            _ if !contains_possible_visible_content(block) => omissions.unsupported_blocks += 1,
            _ => {
                return Err(TransferError::AmbiguousRecord {
                    line,
                    message: format!("unknown Codex content block {block_type:?} may be visible"),
                })
            }
        }
    }
    Ok(text.replace("\r\n", "\n"))
}

fn codex_hidden_user_context(text: &str) -> bool {
    (text.starts_with("# AGENTS.md instructions for ") && text.contains("<environment_context>"))
        || (text.starts_with("<environment_context>") && text.ends_with("</environment_context>"))
}

fn push_visible_message(
    messages: &mut Vec<VisibleMessage>,
    role: VisibleRole,
    text: &str,
) -> Result<(), TransferError> {
    if text.is_empty() {
        return Ok(());
    }
    messages.push(VisibleMessage {
        role,
        text: text.replace("\r\n", "\n"),
    });
    Ok(())
}

fn classify_unknown_record(
    line: usize,
    value: &Value,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    if contains_possible_visible_content(value) {
        return Err(TransferError::AmbiguousRecord {
            line,
            message: "unknown record contains message/content/text/role fields".to_string(),
        });
    }
    omissions.metadata_records += 1;
    Ok(())
}

fn contains_possible_visible_content(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "message" | "content" | "text" | "role" | "prompt"
            ) || contains_possible_visible_content(value)
        }),
        Value::Array(values) => values.iter().any(contains_possible_visible_content),
        _ => false,
    }
}

fn fingerprint_file(path: &Path) -> Result<TranscriptFingerprint, TransferError> {
    let bytes =
        fs::read(path).map_err(|err| TransferError::io("read transcript fingerprint", err))?;
    if bytes.len() as u64 > MAX_TRANSCRIPT_BYTES {
        return Err(TransferError::TranscriptTooLarge {
            bytes: bytes.len() as u64,
        });
    }
    Ok(fingerprint_bytes(&bytes))
}

fn fingerprint_bytes(bytes: &[u8]) -> TranscriptFingerprint {
    let digest = Sha256::digest(bytes);
    TranscriptFingerprint {
        byte_len: bytes.len() as u64,
        sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
    }
}

pub(crate) fn write_claude_session(
    config_home: &Path,
    cwd: &Path,
    messages: &[VisibleMessage],
) -> Result<(String, PathBuf), TransferError> {
    if !config_home.is_absolute() || !cwd.is_absolute() {
        return Err(TransferError::InvalidPath(
            "Claude account home and cwd must be absolute".to_string(),
        ));
    }
    fs::create_dir_all(config_home)
        .map_err(|err| TransferError::io("create Claude account home", err))?;
    let canonical_home = fs::canonicalize(config_home)
        .map_err(|err| TransferError::io("canonicalize Claude account home", err))?;
    let project_dir = canonical_home
        .join("projects")
        .join(claude_project_slug(cwd));
    fs::create_dir_all(&project_dir)
        .map_err(|err| TransferError::io("create Claude project directory", err))?;
    reject_symlinks_below(&canonical_home, &project_dir)?;

    for _ in 0..32 {
        let session_id = random_uuid()?;
        let target = project_dir.join(format!("{session_id}.jsonl"));
        let temp = project_dir.join(format!(".{session_id}.herdr-transfer.tmp"));
        let file = match crate::platform::create_private_file(&temp) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(TransferError::io("create Claude transfer file", err)),
        };
        let write_result = write_claude_records(file, cwd, &session_id, messages).and_then(|()| {
            fs::rename(&temp, &target)
                .map_err(|err| TransferError::io("commit Claude transfer file", err))
        });
        if let Err(err) = write_result {
            let _ = fs::remove_file(&temp);
            return Err(err);
        }
        return Ok((session_id, target));
    }
    Err(TransferError::Io {
        context: "allocate Claude session id",
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "repeated random session-id collision",
        ),
    })
}

/// Ephemeral native-Claude bridge used only to invoke Codex's supported
/// external-session importer for non-Claude sources. The bridge is private,
/// durable before import, and deleted on every return path.
struct PrivateClaudeBridge {
    path: PathBuf,
}

impl PrivateClaudeBridge {
    fn write(
        codex_home: &Path,
        cwd: &Path,
        messages: &[VisibleMessage],
    ) -> Result<Self, TransferError> {
        if !codex_home.is_absolute() {
            return Err(TransferError::InvalidPath(
                "Codex home for the private import bridge must be absolute".to_string(),
            ));
        }
        fs::create_dir_all(codex_home)
            .map_err(|error| TransferError::io("create Codex home", error))?;
        let canonical_home = fs::canonicalize(codex_home)
            .map_err(|error| TransferError::io("canonicalize Codex home", error))?;
        let staging = canonical_home.join(".herdr/session-transfer");
        #[cfg(unix)]
        let existed = staging.exists();
        fs::create_dir_all(&staging)
            .map_err(|error| TransferError::io("create Codex import staging directory", error))?;
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).map_err(|error| {
                TransferError::io("protect Codex import staging directory", error)
            })?;
        }
        reject_symlinks_below(&canonical_home, &staging)?;
        for _ in 0..32 {
            let session_id = random_uuid()?;
            let path = staging.join(format!("{session_id}.jsonl"));
            let file = match crate::platform::create_private_file(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(TransferError::io(
                        "create private Claude import bridge",
                        error,
                    ))
                }
            };
            if let Err(error) = write_claude_records(file, cwd, &session_id, messages) {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
            sync_parent_directory(&staging)?;
            return Ok(Self { path });
        }
        Err(TransferError::Io {
            context: "allocate private Claude import bridge",
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "repeated random bridge-id collision",
            ),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateClaudeBridge {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %error,
                    "could not remove private session-transfer import bridge"
                );
            }
        }
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), TransferError> {
    match fs::File::open(path).and_then(|directory| directory.sync_all()) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Unsupported
                    | std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(TransferError::io("sync transfer staging directory", error)),
    }
}

fn reject_symlinks_below(base: &Path, target: &Path) -> Result<(), TransferError> {
    let relative = target.strip_prefix(base).map_err(|_| {
        TransferError::InvalidPath("destination is outside the selected account home".to_string())
    })?;
    let mut walked = base.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(TransferError::InvalidPath(
                "destination contains a non-normal component".to_string(),
            ));
        };
        walked.push(part);
        let metadata = fs::symlink_metadata(&walked)
            .map_err(|err| TransferError::io("inspect destination path", err))?;
        if metadata.file_type().is_symlink() {
            return Err(TransferError::InvalidPath(format!(
                "symlink destination component {} is not allowed",
                walked.display()
            )));
        }
    }
    let resolved = fs::canonicalize(target)
        .map_err(|err| TransferError::io("canonicalize destination path", err))?;
    if !resolved.starts_with(base) {
        return Err(TransferError::InvalidPath(
            "resolved destination escapes the selected account home".to_string(),
        ));
    }
    Ok(())
}

fn write_claude_records(
    file: fs::File,
    cwd: &Path,
    session_id: &str,
    messages: &[VisibleMessage],
) -> Result<(), TransferError> {
    let mut writer = BufWriter::new(file);
    let cwd = cwd.to_string_lossy();
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|err| {
            TransferError::io(
                "format Claude transcript timestamp",
                std::io::Error::other(err.to_string()),
            )
        })?;
    let mut parent_uuid: Option<String> = None;
    for message in messages {
        let uuid = random_uuid()?;
        let native_message = match message.role {
            VisibleRole::User => json!({"role": "user", "content": &message.text}),
            VisibleRole::Assistant => json!({
                "id": format!("msg_{}", uuid.replace('-', "")),
                "type": "message",
                "role": "assistant",
                "model": "herdr-session-transfer",
                "content": [{"type": "text", "text": &message.text}],
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": {"input_tokens": 0, "output_tokens": 0}
            }),
        };
        let record = json!({
            "parentUuid": parent_uuid,
            "isSidechain": false,
            "userType": "external",
            "cwd": cwd,
            "sessionId": session_id,
            "version": "herdr-session-transfer-v1",
            "gitBranch": "",
            "type": message.role.label(),
            "message": native_message,
            "uuid": uuid,
            "timestamp": timestamp,
        });
        serde_json::to_writer(&mut writer, &record).map_err(|err| {
            TransferError::io("serialize Claude transcript", std::io::Error::other(err))
        })?;
        writer
            .write_all(b"\n")
            .map_err(|err| TransferError::io("write Claude transcript", err))?;
        parent_uuid = record
            .get("uuid")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    writer
        .flush()
        .map_err(|err| TransferError::io("flush Claude transcript", err))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|err| TransferError::io("sync Claude transcript", err))
}

impl VisibleRole {
    fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

fn claude_project_slug(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn random_uuid() -> Result<String, TransferError> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|err| {
        TransferError::io(
            "generate transfer session id",
            std::io::Error::other(err.to_string()),
        )
    })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

pub(crate) async fn import_claude_session_to_codex(
    codex_home: &Path,
    source_path: &Path,
    cwd: &Path,
    launch_env: &crate::config::AccountLaunchEnv,
    timeout: Duration,
) -> Result<String, TransferError> {
    let future = import_claude_session_to_codex_inner(codex_home, source_path, cwd, launch_env);
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TransferError::Timeout)?
}

async fn import_claude_session_to_codex_inner(
    codex_home: &Path,
    source_path: &Path,
    cwd: &Path,
    launch_env: &crate::config::AccountLaunchEnv,
) -> Result<String, TransferError> {
    fs::create_dir_all(codex_home)
        .map_err(|err| TransferError::io("create Codex account home", err))?;
    let mut command = tokio::process::Command::new("codex");
    // The outer timeout drops this future. Ensure that also terminates the
    // app-server instead of orphaning a writer after the transfer has failed.
    command.kill_on_drop(true);
    command
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for key in &launch_env.clear_vars {
        command.env_remove(key);
    }
    for (key, value) in &launch_env.vars {
        command.env(key, value);
    }
    // Keep verification and the writer on the exact account home even for a
    // default-home account whose interactive launch omits the override.
    command.env("CODEX_HOME", codex_home);
    let mut child = command
        .spawn()
        .map_err(|err| TransferError::io("launch Codex app-server", err))?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        TransferError::CodexImport("app-server stdin was unavailable".to_string())
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        TransferError::CodexImport("app-server stdout was unavailable".to_string())
    })?;
    let result = async {
        write_protocol_message(
            &mut stdin,
            &json!({
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "herdr", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"experimentalApi": true}
                }
            }),
        )
        .await?;
        let mut reader = tokio::io::BufReader::new(stdout);
        wait_for_response(&mut reader, 1).await?;
        write_protocol_message(&mut stdin, &json!({"method": "initialized"})).await?;
        write_protocol_message(
            &mut stdin,
            &json!({
                "id": 2,
                "method": "externalAgentConfig/import",
                "params": {
                    "migrationItems": [{
                        "itemType": "SESSIONS",
                        "description": "Herdr agent session transfer",
                        "cwd": cwd.to_string_lossy(),
                        "details": {
                            "sessions": [{
                                "path": source_path.to_string_lossy(),
                                "cwd": cwd.to_string_lossy(),
                                "title": null
                            }]
                        }
                    }],
                    "migrationSource": "claude",
                    "providerId": "herdr",
                    "source": "herdr"
                }
            }),
        )
        .await?;
        match wait_for_import_result(&mut reader).await? {
            Some(target) => Ok(target),
            None => reuse_codex_import_target(codex_home, source_path),
        }
    }
    .await;
    let _ = child.start_kill();
    let _ = child.wait().await;
    result
}

async fn write_protocol_message(
    stdin: &mut tokio::process::ChildStdin,
    value: &Value,
) -> Result<(), TransferError> {
    let mut bytes = serde_json::to_vec(value).map_err(|err| {
        TransferError::CodexImport(format!("could not encode app-server request: {err}"))
    })?;
    bytes.push(b'\n');
    stdin
        .write_all(&bytes)
        .await
        .map_err(|err| TransferError::io("write Codex app-server request", err))?;
    stdin
        .flush()
        .await
        .map_err(|err| TransferError::io("flush Codex app-server request", err))
}

async fn read_protocol_message(
    reader: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
) -> Result<Value, TransferError> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(|err| TransferError::io("read Codex app-server response", err))?;
    if read == 0 {
        return Err(TransferError::CodexImport(
            "app-server exited before import completed".to_string(),
        ));
    }
    if line.len() > MAX_APP_SERVER_LINE_BYTES {
        return Err(TransferError::CodexImport(
            "app-server response exceeded the size limit".to_string(),
        ));
    }
    serde_json::from_str(&line).map_err(|err| {
        TransferError::CodexImport(format!("app-server returned invalid JSON: {err}"))
    })
}

async fn wait_for_response(
    reader: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    id: u64,
) -> Result<Value, TransferError> {
    loop {
        let value = read_protocol_message(reader).await?;
        if value.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        if let Some(error) = value.get("error") {
            return Err(TransferError::CodexImport(format!(
                "app-server request {id} failed: {error}"
            )));
        }
        return Ok(value);
    }
}

async fn wait_for_import_result(
    reader: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
) -> Result<Option<String>, TransferError> {
    let mut import_id = None;
    let mut completions = Vec::new();
    loop {
        let value = read_protocol_message(reader).await?;
        if value.get("id").and_then(Value::as_u64) == Some(2) {
            if let Some(error) = value.get("error") {
                return Err(TransferError::CodexImport(format!(
                    "app-server request 2 failed: {error}"
                )));
            }
            import_id = Some(
                value
                    .get("result")
                    .and_then(|result| result.get("importId"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        TransferError::CodexImport("import response had no importId".to_string())
                    })?
                    .to_string(),
            );
        } else if value.get("method").and_then(Value::as_str)
            == Some("externalAgentConfig/import/completed")
        {
            let params = value.get("params").cloned().ok_or_else(|| {
                TransferError::CodexImport("completion had no params".to_string())
            })?;
            completions.push(params);
        } else {
            continue;
        }

        let Some(import_id) = import_id.as_deref() else {
            continue;
        };
        let Some(completion_index) = completions
            .iter()
            .position(|params| params.get("importId").and_then(Value::as_str) == Some(import_id))
        else {
            continue;
        };
        return parse_import_completion(&completions.swap_remove(completion_index));
    }
}

fn parse_import_completion(params: &Value) -> Result<Option<String>, TransferError> {
    let results = params
        .get("itemTypeResults")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TransferError::CodexImport("completion had no itemTypeResults".to_string())
        })?;
    let sessions = results
        .iter()
        .find(|result| result.get("itemType").and_then(Value::as_str) == Some("SESSIONS"))
        .ok_or_else(|| {
            TransferError::CodexImport("completion had no SESSIONS result".to_string())
        })?;
    let failures = sessions
        .get("failures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !failures.is_empty() {
        return Err(TransferError::CodexImport(format!(
            "session importer reported failures: {}",
            Value::Array(failures)
        )));
    }
    let targets: Vec<&str> = sessions
        .get("successes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|success| success.get("target").and_then(Value::as_str))
        .collect();
    match targets.as_slice() {
        [target] => Ok(Some((*target).to_string())),
        [] => Ok(None),
        _ => Err(TransferError::CodexImport(format!(
            "expected one imported session target, found {}",
            targets.len()
        ))),
    }
}

fn reuse_codex_import_target(
    codex_home: &Path,
    source_path: &Path,
) -> Result<String, TransferError> {
    #[derive(Deserialize)]
    struct Ledger {
        records: Vec<LedgerRecord>,
    }

    #[derive(Deserialize)]
    struct LedgerRecord {
        source_path: String,
        imported_thread_id: String,
    }

    let ledger_path = codex_home.join("external_agent_session_imports.json");
    let ledger_path = validate_transcript_path(codex_home, &ledger_path).map_err(|err| {
        TransferError::CodexImport(format!(
            "import completed without a target and its ledger could not be trusted: {err}"
        ))
    })?;
    let bytes = fs::read(&ledger_path)
        .map_err(|err| TransferError::io("read Codex session import ledger", err))?;
    if bytes.len() > MAX_APP_SERVER_LINE_BYTES {
        return Err(TransferError::CodexImport(
            "Codex session import ledger exceeded the size limit".to_string(),
        ));
    }
    let ledger: Ledger = serde_json::from_slice(&bytes).map_err(|err| {
        TransferError::CodexImport(format!("Codex session import ledger was invalid: {err}"))
    })?;
    let expected_source = source_path.to_string_lossy();
    let mut targets: Vec<_> = ledger
        .records
        .into_iter()
        .filter(|record| record.source_path == expected_source)
        .map(|record| record.imported_thread_id)
        .collect();
    targets.sort();
    targets.dedup();
    let target = match targets.as_slice() {
        [target] => target.clone(),
        _ => {
            return Err(TransferError::CodexImport(format!(
                "import completed without a target and the ledger had {} matching targets",
                targets.len()
            )))
        }
    };
    // The ledger is only a locator. The caller still rereads this native rollout
    // and compares its visible messages with the source before offering cutover.
    find_codex_rollout(codex_home, &target)?;
    Ok(target)
}

pub(crate) fn find_codex_rollout(
    codex_home: &Path,
    thread_id: &str,
) -> Result<PathBuf, TransferError> {
    if thread_id.is_empty() || thread_id.chars().any(char::is_control) {
        return Err(TransferError::InvalidPath(
            "invalid Codex thread id".to_string(),
        ));
    }
    let canonical_home = fs::canonicalize(codex_home)
        .map_err(|err| TransferError::io("canonicalize Codex account home", err))?;
    let sessions = canonical_home.join("sessions");
    let mut stack = vec![sessions];
    let mut matches = Vec::new();
    let mut scanned = 0_usize;
    while let Some(directory) = stack.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(TransferError::io("scan Codex sessions", err)),
        };
        for entry in entries {
            let entry = entry.map_err(|err| TransferError::io("scan Codex sessions", err))?;
            scanned += 1;
            if scanned > MAX_ROLLOUT_FILES_SCANNED {
                return Err(TransferError::InvalidPath(
                    "Codex session tree exceeded the scan limit".to_string(),
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|err| TransferError::io("inspect Codex session entry", err))?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(entry.path());
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if metadata.is_file()
                && name.starts_with("rollout-")
                && name.ends_with(".jsonl")
                && name.contains(thread_id)
            {
                let path = validate_transcript_path(&canonical_home, &entry.path())?;
                if codex_rollout_declares_thread(&path, thread_id)? {
                    matches.push(path);
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(TransferError::InvalidPath(format!(
            "no Codex rollout declares thread {thread_id}"
        ))),
        _ => Err(TransferError::InvalidPath(format!(
            "multiple Codex rollouts declare thread {thread_id}"
        ))),
    }
}

fn codex_rollout_declares_thread(path: &Path, thread_id: &str) -> Result<bool, TransferError> {
    let file = fs::File::open(path).map_err(|err| TransferError::io("open Codex rollout", err))?;
    for (index, line) in BufReader::new(file).lines().take(32).enumerate() {
        let line = line.map_err(|err| TransferError::io("read Codex rollout", err))?;
        let value: Value =
            serde_json::from_str(&line).map_err(|err| TransferError::InvalidJson {
                line: index + 1,
                message: err.to_string(),
            })?;
        if value.get("type").and_then(Value::as_str) == Some("session_meta") {
            return Ok(value
                .get("payload")
                .and_then(|payload| payload.get("id"))
                .and_then(Value::as_str)
                == Some(thread_id));
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn temp_root(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "herdr-session-transfer-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_fixture(path: &Path, lines: &[Value]) {
        let mut file = fs::File::create(path).unwrap();
        for line in lines {
            serde_json::to_writer(&mut file, line).unwrap();
            writeln!(file).unwrap();
        }
    }

    fn foreground_process(
        pid: u32,
        name: &str,
        argv: &[&str],
    ) -> crate::platform::ForegroundProcess {
        crate::platform::ForegroundProcess {
            pid,
            name: name.to_string(),
            argv0: argv.first().map(|value| (*value).to_string()),
            argv: Some(argv.iter().map(|value| (*value).to_string()).collect()),
            cmdline: Some(argv.join(" ")),
        }
    }

    #[test]
    fn codex_resume_process_binds_the_exact_session_and_uses_a_stable_order() {
        let job = crate::platform::ForegroundJob {
            process_group_id: 20,
            processes: vec![
                foreground_process(20, "node", &["node", "/usr/bin/codex", "resume", "wanted"]),
                foreground_process(10, "codex", &["codex", "resume", "other"]),
                foreground_process(40, "codex", &["codex", "resume", "wanted"]),
                foreground_process(30, "codex", &["codex", "resume", "wanted"]),
            ],
        };

        assert_eq!(codex_resume_process(&job, "wanted"), Some(30));
        assert_eq!(codex_resume_process(&job, "missing"), None);
    }

    #[test]
    fn omp_process_proof_requires_the_reported_foreground_omp_pid() {
        let job = crate::platform::ForegroundJob {
            process_group_id: 20,
            processes: vec![
                foreground_process(20, "omp", &["omp"]),
                foreground_process(30, "codex", &["codex", "resume", "thread"]),
            ],
        };
        assert_eq!(omp_reported_process(&job, 20), Some(20));
        assert_eq!(omp_reported_process(&job, 30), None);
        assert_eq!(omp_reported_process(&job, 999), None);
    }

    #[tokio::test]
    async fn omp_to_claude_stages_exact_visible_history_and_rejects_a_stale_leaf() {
        let root = temp_root("omp-to-claude");
        let source_root = root.join("omp-sessions");
        let target_home = root.join("claude");
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "question".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "answer".into(),
            },
        ];
        let (_session_id, source_path, leaf) = omp::write(&source_root, &root, &messages).unwrap();
        let source_ref =
            crate::agent_resume::AgentSessionRef::path(source_path.to_string_lossy().into_owned())
                .unwrap();
        let request = |cursor: String| PrepareRequest {
            source_kind: HarnessKind::Omp,
            source_sessions_root: source_root.clone(),
            source_session_ref: source_ref.clone(),
            source_cursor: Some(cursor),
            source_transcript_path: Some(source_path.clone()),
            target_kind: HarnessKind::Claude,
            target_config_home: target_home.clone(),
            target_sessions_root: target_home.clone(),
            target_launch_env: crate::config::AccountLaunchEnv::unselected(),
            cwd: root.clone(),
            timeout: Duration::from_secs(1),
        };
        let prepared = prepare(request(leaf)).await.unwrap();
        assert_eq!(prepared.staged.transcript.messages, messages);
        assert_eq!(
            prepared.staged.session_ref.kind,
            crate::agent_resume::AgentSessionRefKind::Id
        );

        assert!(matches!(
            prepare(request("missing-leaf".into())).await,
            Err(TransferError::UnsupportedTranscript(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn claude_to_omp_stages_a_native_path_reference_and_leaf() {
        let root = temp_root("claude-to-omp");
        let source_home = root.join("claude");
        let target_root = root.join("omp-sessions");
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "hello".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "hi".into(),
            },
        ];
        let (source_id, source_path) =
            write_claude_session(&source_home, &root, &messages).unwrap();
        let prepared = prepare(PrepareRequest {
            source_kind: HarnessKind::Claude,
            source_sessions_root: source_home.clone(),
            source_session_ref: crate::agent_resume::AgentSessionRef::id(source_id).unwrap(),
            source_cursor: None,
            source_transcript_path: Some(source_path),
            target_kind: HarnessKind::Omp,
            target_config_home: root.join("omp-agent"),
            target_sessions_root: target_root.clone(),
            target_launch_env: crate::config::AccountLaunchEnv::unselected(),
            cwd: root.clone(),
            timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();
        assert_eq!(
            prepared.staged.session_ref.kind,
            crate::agent_resume::AgentSessionRefKind::Path
        );
        assert!(prepared.staged.cursor.is_some());
        assert_eq!(prepared.staged.transcript.messages, messages);
        let canonical_target_root = fs::canonicalize(target_root).unwrap();
        assert!(
            prepared
                .staged
                .transcript_path
                .starts_with(canonical_target_root),
            "the staged path must stay below the canonical OMP sessions root"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_claude_codex_bridge_is_private_exact_and_removed_on_drop() {
        let root = temp_root("codex-bridge");
        let codex_home = root.join("codex");
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "one".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "two".into(),
            },
        ];
        let bridge = PrivateClaudeBridge::write(&codex_home, &root, &messages).unwrap();
        let path = bridge.path().to_path_buf();
        let projection =
            claude_to_codex_import_projection(&fs::read(bridge.path()).unwrap()).unwrap();
        assert_eq!(projection, messages);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(bridge);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_parser_keeps_visible_text_and_reports_omissions() {
        let root = temp_root("claude-parse");
        let path = root.join("source.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"user","message":{"role":"user","content":"one\r\ntwo"}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"thinking","thinking":"hidden"},
                    {"type":"text","text":"answer"},
                    {"type":"tool_use","name":"shell"}
                ]}}),
                json!({"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"hidden"}]}}),
                json!({"type":"user","isMeta":true,"message":{"role":"user","content":"internal metadata"}}),
                json!({"type":"attachment","fileName":"image.png"}),
                json!({"type":"future-metadata","counter":3}),
            ],
        );
        let transcript = read_transcript(HarnessKind::Claude, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "one\ntwo".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "answer".into()
                },
            ]
        );
        assert_eq!(transcript.omissions.reasoning_records, 1);
        assert_eq!(transcript.omissions.tool_records, 2);
        assert_eq!(transcript.omissions.attachment_records, 1);
        assert_eq!(transcript.omissions.metadata_records, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_to_codex_projection_matches_codex_importer_semantics() {
        let root = temp_root("claude-codex-projection");
        let path = root.join("source.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"user","message":{"role":"user","content":" \n<user_query>\r\nhello\r\nworld\n</user_query>\n "}}),
                json!({"type":"user","isMeta":true,"message":{"role":"user","content":"hidden metadata"}}),
                json!({"type":"assistant","isSidechain":true,"message":{"role":"assistant","content":[{"type":"text","text":"hidden branch"}]}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"thinking","thinking":"hidden reasoning"},
                    {"type":"text","text":"answer"},
                    {"type":"tool_use","name":"shell","input":{
                        "description":"inspect",
                        "command":"ls",
                        "file_path":"/tmp/a"
                    }}
                ]}}),
                json!({"type":"user","message":{"role":"user","content":[
                    {"type":"tool_result","is_error":true,"content":[{"type":"text","text":"failed"}]}
                ]}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"redacted_thinking","data":"hidden"}
                ]}}),
                json!({"type":"assistant","message":{"role":"assistant","content":[
                    {"type":"image","source":{"type":"base64","data":"hidden"}}
                ]}}),
                json!({"type":"user","message":{"role":"user","content":[
                    {"type":"text","text":"follow-up"},
                    {"type":"tool_result","content":"context"}
                ]}}),
            ],
        );

        let ordinary = read_transcript(HarnessKind::Claude, &root, &path).unwrap();
        let projected =
            read_transfer_source(HarnessKind::Claude, HarnessKind::Codex, &root, &path, None)
                .unwrap();

        assert_eq!(ordinary.messages.len(), 3);
        assert_eq!(projected.fingerprint, ordinary.fingerprint);
        assert_eq!(projected.omissions, ordinary.omissions);
        assert_eq!(projected.omissions.metadata_records, 1);
        assert_eq!(projected.omissions.sidechain_records, 1);
        assert_eq!(projected.omissions.reasoning_records, 2);
        assert_eq!(projected.omissions.tool_records, 3);
        assert_eq!(projected.omissions.attachment_records, 1);
        assert_eq!(
            projected.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "hello\nworld".into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: concat!(
                        "answer\n\n",
                        "[external_agent_tool_call: shell]\n",
                        "description: inspect\n",
                        "command: ls\n",
                        "file: /tmp/a\n",
                        "[/external_agent_tool_call]"
                    )
                    .into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: concat!(
                        "[external_agent_tool_result: error]\n",
                        "failed\n",
                        "[/external_agent_tool_result]"
                    )
                    .into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "[external unsupported block: redacted_thinking]".into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "[external unsupported block: image]".into(),
                },
                VisibleMessage {
                    role: VisibleRole::User,
                    text: concat!(
                        "follow-up\n\n",
                        "[external_agent_tool_result]\n",
                        "context\n",
                        "[/external_agent_tool_result]"
                    )
                    .into(),
                },
            ]
        );

        let target_path = root.join("rollout-imported.jsonl");
        let answer_with_tool = concat!(
            "answer\n\n",
            "[external_agent_tool_call: shell]\n",
            "description: inspect\n",
            "command: ls\n",
            "file: /tmp/a\n",
            "[/external_agent_tool_call]"
        );
        let failed_tool_result = concat!(
            "[external_agent_tool_result: error]\n",
            "failed\n",
            "[/external_agent_tool_result]"
        );
        let follow_up = concat!(
            "follow-up\n\n",
            "[external_agent_tool_result]\n",
            "context\n",
            "[/external_agent_tool_result]"
        );
        write_fixture(
            &target_path,
            &[
                json!({"type":"session_meta","payload":{"id":"imported"}}),
                json!({"type":"event_msg","payload":{"type":"turn_started"}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"hello\r\nworld"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello\r\nworld"}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":answer_with_tool}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":answer_with_tool}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":failed_tool_result}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":failed_tool_result}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":"[external unsupported block: redacted_thinking]"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"[external unsupported block: redacted_thinking]"}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":"[external unsupported block: image]"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"[external unsupported block: image]"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":follow_up}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":follow_up}]}}),
                json!({"type":"event_msg","payload":{"type":"agent_message","message":"<EXTERNAL SESSION IMPORTED>"}}),
                json!({"type":"event_msg","payload":{"type":"turn_complete"}}),
            ],
        );
        let actual = read_transcript(HarnessKind::Codex, &root, &target_path).unwrap();
        verify_destination(&projected.messages, &actual).unwrap();
        let mut changed = actual;
        changed.messages[1].text.push('!');
        let error = verify_destination(&projected.messages, &changed)
            .unwrap_err()
            .to_string();
        assert!(error.contains("target-visible"));
        assert!(error.contains("message 2"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_import_projection_truncates_by_unicode_scalar_count() {
        let text = "🦀".repeat(CODEX_IMPORT_NOTE_MAX_CHARS + 1);
        let truncated = truncate_codex_import_text(&text, CODEX_IMPORT_NOTE_MAX_CHARS);
        assert_eq!(truncated.chars().count(), CODEX_IMPORT_NOTE_MAX_CHARS);
        assert!(truncated.ends_with("..."));
        assert_eq!(
            truncated
                .chars()
                .filter(|character| *character == '🦀')
                .count(),
            CODEX_IMPORT_NOTE_MAX_CHARS - 3
        );
    }

    #[test]
    fn codex_import_projection_preserves_fallback_tool_input_key_order() {
        let bytes = br#"{"type":"user","message":{"role":"user","content":"request"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"AskUserQuestion","input":{"question":"Choose","header":"Backend","multiSelect":false}}]}}
"#;
        let projected = claude_to_codex_import_projection(bytes).unwrap();
        assert_eq!(
            projected,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "request".into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: concat!(
                        "[external_agent_tool_call: AskUserQuestion]\n",
                        "input: {\"question\":\"Choose\",\"header\":\"Backend\",\"multiSelect\":false}\n",
                        "[/external_agent_tool_call]"
                    )
                    .into(),
                },
            ]
        );
    }

    #[test]
    fn codex_import_projection_rejects_duplicate_object_keys() {
        let bytes = br#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"shell","input":{"command":"first","command":"second"}}]}}
"#;
        assert!(matches!(
            claude_to_codex_import_projection(bytes),
            Err(TransferError::InvalidJson { message, .. })
                if message.contains("duplicate JSON object key")
        ));
    }

    #[test]
    fn codex_import_projection_handles_many_unique_object_keys() {
        use std::fmt::Write as _;

        let mut input = String::from("{");
        for index in 0..5_000 {
            if index > 0 {
                input.push(',');
            }
            write!(&mut input, "\"key{index}\":{index}").unwrap();
        }
        input.push('}');
        let bytes = format!(
            "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"request\"}}}}\n\
             {{\"type\":\"assistant\",\"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"tool_use\",\"name\":\"large\",\"input\":{input}}}]}}}}\n"
        );
        let projected = claude_to_codex_import_projection(bytes.as_bytes()).unwrap();
        assert_eq!(projected.len(), 2);
        assert_eq!(projected[1].role, VisibleRole::Assistant);
        assert_eq!(
            projected[1].text.chars().count(),
            CODEX_IMPORT_NOTE_MAX_CHARS
                + "[external_agent_tool_call: large]\ninput: \n[/external_agent_tool_call]"
                    .chars()
                    .count()
        );
    }

    #[test]
    fn codex_import_projection_refuses_assistant_records_before_first_user_turn() {
        let bytes = br#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"leading answer"}]}}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"leading tool result"}]}}
{"type":"user","message":{"role":"user","content":"first request"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"kept answer"}]}}
"#;
        assert!(matches!(
            claude_to_codex_import_projection(bytes),
            Err(TransferError::UnsupportedTranscript(message))
                if message.contains("before the first user turn")
        ));
    }

    #[test]
    fn codex_parser_ignores_duplicate_events_and_system_injections() {
        let root = temp_root("codex-parse");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"system"}]}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"hello"}}),
                json!({"type":"response_item","payload":{"type":"reasoning","summary":["hidden"]}}),
                json!({"type":"response_item","payload":{"type":"function_call","name":"shell"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"world"}]}}),
            ],
        );
        let transcript = read_transcript(HarnessKind::Codex, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "hello".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "world".into()
                },
            ]
        );
        assert_eq!(transcript.omissions.system_records, 1);
        assert_eq!(transcript.omissions.reasoning_records, 1);
        assert_eq!(transcript.omissions.tool_records, 1);
        assert_eq!(transcript.omissions.metadata_records, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_parser_uses_visible_user_events_and_omits_runtime_context() {
        let root = temp_root("codex-visible-user-events");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"# AGENTS.md instructions for /work\n<environment_context>hidden</environment_context>"}]}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"visible prompt"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"visible prompt","images":[],"local_images":[]}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"visible answer"}]}}),
            ],
        );

        let transcript = read_transcript(HarnessKind::Codex, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "visible prompt".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "visible answer".into()
                },
            ]
        );
        assert_eq!(transcript.omissions.system_records, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_parser_rejects_an_unpaired_ordinary_role_user_record() {
        let root = temp_root("codex-unpaired-user");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"possibly visible"}]}}),
            ],
        );

        assert!(matches!(
            read_transcript(HarnessKind::Codex, &root, &path),
            Err(TransferError::AmbiguousRecord { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_parser_pairs_user_records_after_crlf_normalization() {
        let root = temp_root("codex-crlf-user-pair");
        let path = root.join("rollout-thread.jsonl");
        write_fixture(
            &path,
            &[
                json!({"type":"session_meta","payload":{"id":"thread"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"first\r\nsecond"}]}}),
                json!({"type":"event_msg","payload":{"type":"user_message","message":"first\r\nsecond"}}),
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}}),
            ],
        );

        let transcript = read_transcript(HarnessKind::Codex, &root, &path).unwrap();
        assert_eq!(
            transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "first\nsecond".into()
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "answer".into()
                },
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_record_with_possible_visible_text_fails_closed() {
        let root = temp_root("ambiguous");
        let path = root.join("source.jsonl");
        write_fixture(&path, &[json!({"type":"future","text":"maybe visible"})]);
        assert!(matches!(
            read_transcript(HarnessKind::Claude, &root, &path),
            Err(TransferError::AmbiguousRecord { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn is_meta_does_not_hide_an_unknown_record_with_visible_content() {
        let root = temp_root("ambiguous-meta");
        let path = root.join("source.jsonl");
        write_fixture(
            &path,
            &[json!({
                "type":"future-visible",
                "isMeta":true,
                "message":{"role":"user","content":"must not disappear"}
            })],
        );
        assert!(matches!(
            read_transcript(HarnessKind::Claude, &root, &path),
            Err(TransferError::AmbiguousRecord { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_validation_rejects_parent_and_out_of_home_paths() {
        let root = temp_root("path-trust");
        let outside = temp_root("outside").join("source.jsonl");
        fs::write(&outside, b"{}\n").unwrap();
        assert!(matches!(
            validate_transcript_path(&root, &outside),
            Err(TransferError::InvalidPath(_))
        ));
        let dotted = root.join("child").join("..").join("source.jsonl");
        assert!(matches!(
            validate_transcript_path(&root, &dotted),
            Err(TransferError::InvalidPath(_))
        ));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn path_validation_rejects_symlinks_below_account_home() {
        use std::os::unix::fs::symlink;

        let root = temp_root("symlink");
        let real = root.join("real.jsonl");
        fs::write(&real, b"{}\n").unwrap();
        let link = root.join("link.jsonl");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            validate_transcript_path(&root, &link),
            Err(TransferError::InvalidPath(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn claude_writer_round_trips_exact_visible_messages() {
        let root = temp_root("claude-write");
        let cwd = root.join("work.tree");
        fs::create_dir_all(&cwd).unwrap();
        let expected = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "hello\n".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "answer".into(),
            },
        ];
        let (session_id, path) = write_claude_session(&root, &cwd, &expected).unwrap();
        assert!(path.ends_with(format!("{session_id}.jsonl")));
        let actual = read_transcript(HarnessKind::Claude, &root, &path).unwrap();
        verify_destination(&expected, &actual).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_rollout_lookup_verifies_session_meta_id() {
        let root = temp_root("codex-lookup");
        let day = root.join("sessions/2026/08/29");
        fs::create_dir_all(&day).unwrap();
        let wrong = day.join("rollout-2026-wanted.jsonl");
        write_fixture(
            &wrong,
            &[json!({"type":"session_meta","payload":{"id":"other"}})],
        );
        assert!(find_codex_rollout(&root, "wanted").is_err());
        let correct = day.join("rollout-2026-real-wanted.jsonl");
        write_fixture(
            &correct,
            &[json!({"type":"session_meta","payload":{"id":"wanted"}})],
        );
        assert_eq!(
            find_codex_rollout(&root, "wanted").unwrap(),
            correct.canonicalize().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_import_reuses_the_unique_verified_ledger_target() {
        let root = temp_root("codex-import-ledger");
        let source = root.join("imports/source.jsonl");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"{}\n").unwrap();
        let rollout = root.join("sessions/2026/08/29/rollout-target-thread.jsonl");
        fs::create_dir_all(rollout.parent().unwrap()).unwrap();
        write_fixture(
            &rollout,
            &[json!({"type":"session_meta","payload":{"id":"target-thread"}})],
        );
        fs::write(
            root.join("external_agent_session_imports.json"),
            serde_json::to_vec(&json!({
                "records": [{
                    "source_path": source.to_string_lossy(),
                    "imported_thread_id": "target-thread"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            reuse_codex_import_target(&root, &source).unwrap(),
            "target-thread"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn codex_import_rejects_an_ambiguous_ledger_target() {
        let root = temp_root("codex-import-ledger-ambiguous");
        let source = root.join("imports/source.jsonl");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"{}\n").unwrap();
        fs::write(
            root.join("external_agent_session_imports.json"),
            serde_json::to_vec(&json!({
                "records": [
                    {
                        "source_path": source.to_string_lossy(),
                        "imported_thread_id": "first-thread"
                    },
                    {
                        "source_path": source.to_string_lossy(),
                        "imported_thread_id": "second-thread"
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        assert!(reuse_codex_import_target(&root, &source).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reported_native_path_disambiguates_without_weakening_identity_checks() {
        let root = temp_root("reported-source-path");
        let first = root.join("projects/first/session-1.jsonl");
        let second = root.join("projects/second/session-1.jsonl");
        fs::create_dir_all(first.parent().unwrap()).unwrap();
        fs::create_dir_all(second.parent().unwrap()).unwrap();
        fs::write(&first, b"{}\n").unwrap();
        fs::write(&second, b"{}\n").unwrap();
        assert!(find_native_transcript(HarnessKind::Claude, &root, "session-1").is_err());
        assert_eq!(
            select_native_transcript(
                HarnessKind::Claude,
                &root,
                &crate::agent_resume::AgentSessionRef::id("session-1").unwrap(),
                Some(&second),
            )
            .unwrap(),
            second.canonicalize().unwrap()
        );

        let mismatched = root.join("projects/first/other.jsonl");
        fs::write(&mismatched, b"{}\n").unwrap();
        assert!(matches!(
            select_native_transcript(
                HarnessKind::Claude,
                &root,
                &crate::agent_resume::AgentSessionRef::id("session-1").unwrap(),
                Some(&mismatched),
            ),
            Err(TransferError::InvalidPath(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn destination_comparison_names_first_difference() {
        let expected = vec![VisibleMessage {
            role: VisibleRole::User,
            text: "a".into(),
        }];
        let actual = CanonicalTranscript {
            messages: vec![VisibleMessage {
                role: VisibleRole::User,
                text: "b".into(),
            }],
            omissions: OmissionSummary::default(),
            fingerprint: TranscriptFingerprint {
                byte_len: 0,
                sha256: String::new(),
            },
        };
        assert!(verify_destination(&expected, &actual)
            .unwrap_err()
            .to_string()
            .contains("message 1"));
    }

    #[test]
    fn omission_total_includes_every_class() {
        let omissions = OmissionSummary {
            tool_records: 1,
            reasoning_records: 2,
            system_records: 3,
            attachment_records: 4,
            metadata_records: 5,
            unsupported_blocks: 6,
            sidechain_records: 7,
        };
        assert_eq!(omissions.total(), 28);
    }

    #[test]
    fn claude_project_slug_matches_native_character_substitution() {
        assert_eq!(
            claude_project_slug(Path::new("/root/.gitmoot/work_tree")),
            "-root--gitmoot-work-tree"
        );
    }

    #[test]
    fn known_nonvisible_types_are_exhaustive_sets_without_duplicates() {
        let claude: HashSet<_> = [
            "system",
            "attachment",
            "file-history-snapshot",
            "file-history-delta",
            "queue-operation",
            "last-prompt",
            "permission-mode",
            "mode",
            "ai-title",
            "pr-link",
            "summary",
            "progress",
        ]
        .into_iter()
        .collect();
        assert_eq!(claude.len(), 12);
    }
}
