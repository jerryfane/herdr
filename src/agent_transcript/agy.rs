//! Antigravity CLI (`agy`) conversation reader for `agent.transcript`.
//!
//! `agy` stores each conversation in a WAL-mode SQLite database under
//! `~/.gemini/antigravity-cli/conversations/<uuid>.db` with protobuf-encoded
//! step rows in the `steps` table. Unlike `omp`, `agy` does not report its
//! session path to herdr, so we locate the open `.db` from the pane's live
//! process file descriptors (falling back to `--conversation` / `--resume`
//! arguments or a reported session id).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::schema::{
    AskFormStatus, PendingAsk, TranscriptEntry, TranscriptModel, TranscriptNoteSource,
    TranscriptPlanItem, TranscriptStepStatus, TranscriptTaskStatus, TranscriptTurnStatus,
    TranscriptWorking,
};

use super::normalize::{self, DETAIL_MAX_CHARS, NOTE_BODY_MAX_CHARS};
use super::origin::{self, OtherPrompt};
use super::{
    json_len, mark_other_origins, user_entry, Page, PageRequest, TranscriptError, DEFAULT_TURNS,
    MAX_TURNS, PAGE_RECORD_BUDGET,
};

const STEP_TYPE_USER_INPUT: i64 = 14;
const STEP_TYPE_PLANNER_RESPONSE: i64 = 15;
const STEP_TYPE_EPHEMERAL: i64 = 101;
const STEP_TYPE_GENERIC: i64 = 132;

const STATUS_PENDING: i64 = 1;
const STATUS_RUNNING: i64 = 2;
const STATUS_DONE: i64 = 3;
const STATUS_CANCELED: i64 = 6;
const STATUS_ERROR: i64 = 7;
const STATUS_GENERATING: i64 = 8;

const CURSOR_VERSION: &str = "agy1";

const AGY_DETAIL_KEYS: &[&str] = &[
    "CommandLine",
    "Path",
    "command",
    "path",
    "file",
    "Query",
    "query",
    "Url",
    "url",
    "Prompt",
    "prompt",
    "Description",
    "description",
    "TaskId",
    "Recipient",
    "Role",
    "target",
    "task",
];

// ---------------------------------------------------------------------------
// Pane process -> conversation .db resolution
// ---------------------------------------------------------------------------

/// Resolve the live Antigravity conversation `.db` path for a pane.
///
/// Inspects the pane's foreground processes (and session processes as a
/// fallback) for an open `.../conversations/<id>.db` or `.../presence/<id>.lock`
/// file descriptor. Falls back to `--conversation`/`--resume`/`-r` CLI flags or
/// a reported session id under the default Antigravity app data directory.
pub(crate) fn resolve_db_path(
    shell_pid: Option<u32>,
    reported_session_id: Option<&str>,
    reported_session_path: Option<&Path>,
) -> Option<PathBuf> {
    let mut preferred_id = reported_session_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            reported_session_path
                .and_then(conversation_id_from_brain_path)
                .map(str::to_owned)
        });
    let mut fg_pids = Vec::new();

    if let Some(pid) = shell_pid {
        if let Some(job) = crate::detect::foreground_job(pid) {
            // Prefer processes whose name/argv0 looks like `agy`, then others.
            let mut agy_procs = Vec::new();
            let mut other_procs = Vec::new();
            for proc_info in job.processes {
                if preferred_id.is_none() {
                    preferred_id = proc_info
                        .argv
                        .as_deref()
                        .and_then(conversation_id_from_argv);
                }
                if is_agy_process(&proc_info.name, proc_info.argv0.as_deref()) {
                    agy_procs.push(proc_info.pid);
                } else {
                    other_procs.push(proc_info.pid);
                }
            }
            fg_pids.extend(agy_procs);
            fg_pids.extend(other_procs);
        }

        let mut open_files = Vec::new();
        for proc_pid in &fg_pids {
            open_files.extend(crate::platform::process_open_files(*proc_pid));
        }
        if let Some(path) = extract_db_from_open_files(&open_files, preferred_id.as_deref()) {
            return Some(path);
        }

        // Fallback: check other processes in the pane's session (e.g. a child
        // language server or wrapper holding the conversation DB).
        let seen: HashSet<u32> = fg_pids.iter().copied().collect();
        let mut session_files = Vec::new();
        for proc_pid in crate::platform::session_processes(pid) {
            if !seen.contains(&proc_pid) {
                session_files.extend(crate::platform::process_open_files(proc_pid));
            }
        }
        if let Some(path) = extract_db_from_open_files(&session_files, preferred_id.as_deref()) {
            return Some(path);
        }
    }

    if let Some(reported_path) = reported_session_path {
        if let Some(path) = conversation_db_from_brain_path(reported_path, preferred_id.as_deref())
        {
            if path.is_file() || path.parent().is_some_and(Path::is_dir) {
                return Some(path);
            }
        }
    }

    if let Some(id) = preferred_id.as_deref() {
        if let Some(path) = default_conversation_db_path(id) {
            if path.is_file() || path.parent().is_some_and(Path::is_dir) {
                return Some(path);
            }
        }
    }

    None
}

/// Resolve the live Antigravity conversation ID for a pane from its open
/// conversation database path (or CLI flags / reported session).
pub(crate) fn resolve_conversation_id(
    shell_pid: Option<u32>,
    reported_session_id: Option<&str>,
    reported_session_path: Option<&Path>,
) -> Option<String> {
    let db_path = resolve_db_path(shell_pid, reported_session_id, reported_session_path)?;
    conversation_id_from_db_path(&db_path)
}

pub(crate) fn conversation_id_from_db_path(path: &Path) -> Option<String> {
    if path.extension().and_then(|e| e.to_str()) != Some("db") {
        return None;
    }
    let stem = path.file_stem()?.to_str()?.trim();
    is_valid_conversation_id(stem).then(|| stem.to_owned())
}

/// Extract `<id>` from `<app_data_dir>/brain/<id>/...`.
fn conversation_id_from_brain_path(path: &Path) -> Option<&str> {
    let mut iter = path.components();
    while let Some(comp) = iter.next() {
        if comp.as_os_str() == "brain" {
            let id = iter.next()?.as_os_str().to_str()?;
            return is_valid_conversation_id(id).then_some(id);
        }
    }
    None
}

/// Derive `<app_data_dir>/conversations/<id>.db` from a reported path under
/// `<app_data_dir>/brain/<id>/...` so custom app data directories work even
/// when open-file enumeration is unavailable (e.g. Windows).
pub(crate) fn conversation_db_from_brain_path(
    reported_path: &Path,
    preferred_id: Option<&str>,
) -> Option<PathBuf> {
    let mut app_dir = PathBuf::new();
    let mut iter = reported_path.components();
    let mut found_brain = false;
    let mut path_id = None;
    while let Some(comp) = iter.next() {
        if comp.as_os_str() == "brain" {
            found_brain = true;
            path_id = iter
                .next()
                .and_then(|c| c.as_os_str().to_str())
                .filter(|id| is_valid_conversation_id(id));
            break;
        }
        app_dir.push(comp);
    }
    if !found_brain || app_dir.as_os_str().is_empty() {
        return None;
    }
    let id = preferred_id
        .filter(|id| is_valid_conversation_id(id))
        .or(path_id)?;
    Some(app_dir.join("conversations").join(format!("{id}.db")))
}

fn is_agy_process(name: &str, argv0: Option<&str>) -> bool {
    let matches = |value: &str| {
        let lower = value.to_ascii_lowercase();
        lower == "agy" || lower.ends_with("/agy") || lower.contains("antigravity")
    };
    matches(name) || argv0.is_some_and(matches)
}

/// Parse `--conversation`, `--resume`, or `-r` from an `agy` command line.
pub(crate) fn conversation_id_from_argv(argv: &[String]) -> Option<String> {
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        if let Some(val) = arg
            .strip_prefix("--conversation=")
            .or_else(|| arg.strip_prefix("--resume="))
            .or_else(|| arg.strip_prefix("-r="))
        {
            if is_valid_conversation_id(val) {
                return Some(val.to_owned());
            }
        } else if matches!(arg.as_str(), "--conversation" | "--resume" | "-r") {
            if let Some(next) = iter.next() {
                if is_valid_conversation_id(next) {
                    return Some(next.clone());
                }
            }
        }
    }
    None
}

fn is_valid_conversation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains("..")
        && !value.chars().any(char::is_control)
}

/// Pick the conversation `.db` path from a list of open file paths.
///
/// Matches `<appDataDir>/conversations/<id>.db` (ignoring `-wal`, `-shm`, and
/// `<appDataDir>/conversation_summaries.db`), using `<appDataDir>/presence/<id>.lock`
/// as a tie-breaker or fallback when the `.db` descriptor is not yet open.
pub(crate) fn extract_db_from_open_files(
    paths: &[PathBuf],
    preferred_id: Option<&str>,
) -> Option<PathBuf> {
    let mut db_candidates: Vec<(String, PathBuf)> = Vec::new();
    let mut presence_locks: HashMap<String, PathBuf> = HashMap::new();

    for path in paths {
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let parent_name = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str());

        if parent_name == Some("conversations") {
            if let Some(stem) = file_name.strip_suffix(".db") {
                if is_valid_conversation_id(stem)
                    && !db_candidates.iter().any(|(_, existing)| existing == path)
                {
                    db_candidates.push((stem.to_owned(), path.clone()));
                }
            }
        } else if parent_name == Some("presence") {
            if let Some(stem) = file_name.strip_suffix(".lock") {
                if is_valid_conversation_id(stem) {
                    if let Some(app_dir) = path.parent().and_then(Path::parent) {
                        presence_locks.insert(
                            stem.to_owned(),
                            app_dir.join("conversations").join(format!("{stem}.db")),
                        );
                    }
                }
            }
        }
    }

    // When the caller named a specific conversation id, never silently return
    // a different conversation's open DB: match that id's open DB or presence
    // lock, or return None so resolve_db_path falls back to its own path.
    if let Some(pref) = preferred_id {
        if let Some((_, path)) = db_candidates.iter().find(|(id, _)| id == pref) {
            return Some(path.clone());
        }
        return presence_locks.get(pref).cloned();
    }

    if db_candidates.len() == 1 {
        return Some(db_candidates[0].1.clone());
    }

    if let Some((_, path)) = db_candidates
        .iter()
        .find(|(id, _)| presence_locks.contains_key(id))
    {
        return Some(path.clone());
    }

    if let Some((_, path)) = db_candidates.first() {
        return Some(path.clone());
    }

    presence_locks.into_values().next()
}

fn default_conversation_db_path(id: &str) -> Option<PathBuf> {
    if !is_valid_conversation_id(id) {
        return None;
    }
    if let Ok(app_dir) = std::env::var("ANTIGRAVITY_APP_DATA_DIR") {
        let trimmed = app_dir.trim();
        if !trimmed.is_empty() {
            return Some(
                PathBuf::from(trimmed)
                    .join("conversations")
                    .join(format!("{id}.db")),
            );
        }
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    Some(
        home.join(".gemini")
            .join("antigravity-cli")
            .join("conversations")
            .join(format!("{id}.db")),
    )
}

// ---------------------------------------------------------------------------
// Minimal protobuf wire reader (read-only, zero panics)
// ---------------------------------------------------------------------------

enum PbVal<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed32,
    Fixed64,
}

struct PbField<'a> {
    num: u32,
    val: PbVal<'a>,
}

fn decode_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    while *pos < buf.len() {
        let byte = buf[*pos];
        *pos += 1;
        if shift >= 64 {
            return None;
        }
        val |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(val);
        }
        shift += 7;
    }
    None
}

fn decode_pb(buf: &[u8]) -> Option<Vec<PbField<'_>>> {
    let mut pos = 0;
    let mut fields = Vec::new();
    while pos < buf.len() {
        let tag = decode_varint(buf, &mut pos)?;
        let num = u32::try_from(tag >> 3).ok()?;
        if num == 0 {
            return None;
        }
        let wire = tag & 0x7;
        let val = match wire {
            0 => PbVal::Varint(decode_varint(buf, &mut pos)?),
            1 => {
                if pos.checked_add(8)? > buf.len() {
                    return None;
                }
                pos += 8;
                PbVal::Fixed64
            }
            2 => {
                let len = usize::try_from(decode_varint(buf, &mut pos)?).ok()?;
                let end = pos.checked_add(len)?;
                if end > buf.len() {
                    return None;
                }
                let slice = &buf[pos..end];
                pos = end;
                PbVal::Bytes(slice)
            }
            5 => {
                if pos.checked_add(4)? > buf.len() {
                    return None;
                }
                pos += 4;
                PbVal::Fixed32
            }
            _ => return None,
        };
        fields.push(PbField { num, val });
    }
    Some(fields)
}

fn pb_str<'a>(fields: &'a [PbField<'a>], num: u32) -> Option<&'a str> {
    fields.iter().find_map(|field| {
        if field.num == num {
            if let PbVal::Bytes(bytes) = field.val {
                return std::str::from_utf8(bytes).ok();
            }
        }
        None
    })
}

fn pb_bytes<'a>(fields: &'a [PbField<'a>], num: u32) -> Option<&'a [u8]> {
    fields.iter().find_map(|field| {
        if field.num == num {
            if let PbVal::Bytes(bytes) = field.val {
                return Some(bytes);
            }
        }
        None
    })
}

fn pb_timestamp_ms(buf: &[u8]) -> Option<u64> {
    let fields = decode_pb(buf)?;
    let mut secs: u64 = 0;
    let mut nanos: u64 = 0;
    for field in fields {
        if let PbVal::Varint(v) = field.val {
            match field.num {
                1 => secs = v,
                2 => nanos = v,
                _ => {}
            }
        }
    }
    if secs == 0 && nanos == 0 {
        return None;
    }
    Some(secs.saturating_mul(1_000).saturating_add(nanos / 1_000_000))
}

// ---------------------------------------------------------------------------
// Decoded step representation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DecodedStep {
    idx: u32,
    status: i64,
    step_id: String,
    created_ms: u64,
    completed_ms: Option<u64>,
    payload: StepPayload,
}

#[derive(Debug, Clone)]
enum StepPayload {
    User {
        text: String,
    },
    Planner {
        thinking: String,
        reply: String,
        has_tool_calls: bool,
    },
    Tool {
        call_id: String,
        tool: String,
        args_json: Option<Value>,
        kv_args: Vec<(String, String)>,
        ui_verb: Option<String>,
        error_message: Option<String>,
        ask_answer: Option<Vec<String>>,
    },
    Ephemeral {
        tag: String,
        body: String,
    },
    Ignored,
}

impl DecodedStep {
    fn is_user(&self) -> bool {
        matches!(&self.payload, StepPayload::User { text } if !text.trim().is_empty())
    }

    fn is_rendered(&self) -> bool {
        match &self.payload {
            StepPayload::User { text } => !text.trim().is_empty(),
            StepPayload::Planner {
                thinking, reply, ..
            } => !thinking.trim().is_empty() || !reply.trim().is_empty(),
            StepPayload::Tool { .. } => true,
            StepPayload::Ephemeral { tag, body } => {
                tag != "work_efficiently_reminder" && !body.trim().is_empty()
            }
            StepPayload::Ignored => false,
        }
    }

    fn is_running(&self) -> bool {
        matches!(
            self.status,
            STATUS_PENDING | STATUS_RUNNING | STATUS_GENERATING
        ) && matches!(
            self.payload,
            StepPayload::Tool { .. } | StepPayload::Planner { .. }
        )
    }

    fn plan_items(&self) -> Option<Vec<TranscriptPlanItem>> {
        match &self.payload {
            StepPayload::Tool {
                tool, args_json, ..
            } if tool == "update_steps" => parse_update_steps_plan(args_json.as_ref()),
            _ => None,
        }
    }
}

struct ParsedMeta {
    created_ms: u64,
    completed_ms: Option<u64>,
    step_id: Option<String>,
    tool_call_id: Option<String>,
    tool_name: Option<String>,
    tool_args_json: Option<Value>,
}

fn parse_metadata(buf: &[u8]) -> ParsedMeta {
    let mut meta = ParsedMeta {
        created_ms: 0,
        completed_ms: None,
        step_id: None,
        tool_call_id: None,
        tool_name: None,
        tool_args_json: None,
    };
    let Some(fields) = decode_pb(buf) else {
        return meta;
    };
    for field in fields {
        if let PbVal::Bytes(bytes) = field.val {
            match field.num {
                1 => {
                    if let Some(ms) = pb_timestamp_ms(bytes) {
                        meta.created_ms = ms;
                    }
                }
                4 => {
                    if let Some(tc) = decode_pb(bytes) {
                        meta.tool_call_id =
                            pb_str(&tc, 1).filter(|s| !s.is_empty()).map(str::to_owned);
                        meta.tool_name =
                            pb_str(&tc, 2).filter(|s| !s.is_empty()).map(str::to_owned);
                        meta.tool_args_json =
                            pb_str(&tc, 3).and_then(|raw| serde_json::from_str::<Value>(raw).ok());
                    }
                }
                8 => {
                    meta.completed_ms = pb_timestamp_ms(bytes);
                }
                35 => {
                    if let Ok(id) = std::str::from_utf8(bytes) {
                        if !id.is_empty() {
                            meta.step_id = Some(id.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    meta
}

fn parse_error_details(buf: &[u8]) -> Option<String> {
    let fields = decode_pb(buf)?;
    pb_str(&fields, 2)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| pb_str(&fields, 3).filter(|s| !s.trim().is_empty()))
        .map(str::to_owned)
}

fn decode_step_row(
    idx: u32,
    step_type: i64,
    status: i64,
    metadata_blob: Option<&[u8]>,
    error_blob: Option<&[u8]>,
    payload_blob: Option<&[u8]>,
) -> DecodedStep {
    let payload_fields = payload_blob.and_then(decode_pb).unwrap_or_default();
    let meta = metadata_blob
        .or_else(|| pb_bytes(&payload_fields, 5))
        .map(parse_metadata)
        .unwrap_or(ParsedMeta {
            created_ms: 0,
            completed_ms: None,
            step_id: None,
            tool_call_id: None,
            tool_name: None,
            tool_args_json: None,
        });
    let step_id = meta.step_id.unwrap_or_else(|| format!("agy-{idx}"));

    let payload = match step_type {
        STEP_TYPE_USER_INPUT => {
            let text = pb_bytes(&payload_fields, 19)
                .and_then(decode_pb)
                .map(|u| {
                    if let Some(direct) = pb_str(&u, 2).filter(|s| !s.is_empty()) {
                        return direct.to_owned();
                    }
                    u.iter()
                        .filter(|f| f.num == 3)
                        .filter_map(|f| match f.val {
                            PbVal::Bytes(b) => decode_pb(b).and_then(|item| {
                                pb_str(&item, 1)
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_owned)
                            }),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n\n")
                })
                .unwrap_or_default();
            StepPayload::User { text }
        }
        STEP_TYPE_PLANNER_RESPONSE => {
            let (thinking, reply, has_tool_calls) = pb_bytes(&payload_fields, 20)
                .and_then(decode_pb)
                .map(|p| {
                    let thinking = pb_str(&p, 3).unwrap_or_default().to_owned();
                    let reply = pb_str(&p, 8)
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| pb_str(&p, 1).filter(|s| !s.trim().is_empty()))
                        .unwrap_or_default()
                        .to_owned();
                    let has_tool_calls = p.iter().any(|f| f.num == 7);
                    (thinking, reply, has_tool_calls)
                })
                .unwrap_or_default();
            StepPayload::Planner {
                thinking,
                reply,
                has_tool_calls,
            }
        }
        STEP_TYPE_GENERIC => {
            let mut kv_args = Vec::new();
            let mut ui_verb = None;
            let mut ask_answer = None;
            let is_ask = meta.tool_name.as_deref() == Some("ask_question");
            if let Some(g_fields) = pb_bytes(&payload_fields, 140).and_then(decode_pb) {
                for field in &g_fields {
                    if field.num == 1 {
                        if let PbVal::Bytes(b) = field.val {
                            if let Some(kv) = decode_pb(b) {
                                if let (Some(k), Some(v)) = (pb_str(&kv, 1), pb_str(&kv, 2)) {
                                    kv_args.push((k.to_owned(), v.to_owned()));
                                }
                            }
                        }
                    } else if field.num == 2 {
                        if let PbVal::Bytes(b) = field.val {
                            if let Some(res) = decode_pb(b) {
                                if is_ask {
                                    if let Some(text) = pb_str(&res, 1) {
                                        ask_answer = parse_agy_ask_answers(text);
                                    }
                                }
                                if let Some(ui) = pb_bytes(&res, 3).and_then(decode_pb) {
                                    ui_verb = pb_str(&ui, 5)
                                        .filter(|s| !s.trim().is_empty())
                                        .map(str::to_owned);
                                }
                            }
                        }
                    }
                }
            }
            let error_message = error_blob
                .or_else(|| pb_bytes(&payload_fields, 31))
                .and_then(parse_error_details);
            StepPayload::Tool {
                call_id: meta.tool_call_id.unwrap_or_else(|| step_id.clone()),
                tool: meta.tool_name.unwrap_or_else(|| "tool".to_owned()),
                args_json: meta.tool_args_json,
                kv_args,
                ui_verb,
                error_message,
                ask_answer,
            }
        }
        STEP_TYPE_EPHEMERAL => {
            let (tag, body) = pb_bytes(&payload_fields, 114)
                .and_then(decode_pb)
                .map(|e| {
                    let body = pb_str(&e, 1).unwrap_or_default().to_owned();
                    let tag = pb_str(&e, 3).unwrap_or_default().to_owned();
                    (tag, body)
                })
                .unwrap_or_default();
            StepPayload::Ephemeral { tag, body }
        }
        _ => StepPayload::Ignored,
    };

    DecodedStep {
        idx,
        status,
        step_id,
        created_ms: meta.created_ms,
        completed_ms: meta.completed_ms,
        payload,
    }
}

// ---------------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k")]
enum AgyCursor {
    #[serde(rename = "b")]
    Before { idx: u32, id: String },
    #[serde(rename = "a")]
    After {
        seen_next_idx: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tip: Option<(u32, String)>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        running: Vec<u32>,
        /// Entry ids already emitted for steps in `running`, so when a
        /// generating planner step later finishes with a brand-new `:reply`
        /// entry, only previously-emitted ids go into `resent` (clients drop
        /// unknown ids listed in `resent`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        running_emitted: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origins: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        floor: Option<u32>,
        /// `(reply_idx, was_final, end_at_idx)` for the newest planner reply
        /// in the latest turn before `seen_next_idx`. `end_at_idx` is `Some(idx)`
        /// when `{step_id}:end` (`TurnEnd`) was emitted at step `idx`, so an
        /// `after` poll can expire the cursor if a late tool/planner extends an
        /// already-closed turn (clients merge by id in place and cannot move a
        /// previously sent `TurnEnd`), or emit `TurnEnd` once after trailing
        /// tools settle.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tip_reply: Option<(u32, bool, Option<u32>)>,
    },
}

#[derive(Serialize, Deserialize)]
struct CursorEnvelope {
    v: String,
    s: String,
    #[serde(flatten)]
    cursor: AgyCursor,
}

impl AgyCursor {
    fn encode(&self, session_id: &str) -> String {
        let env = CursorEnvelope {
            v: CURSOR_VERSION.to_owned(),
            s: session_id.to_owned(),
            cursor: self.clone(),
        };
        let raw = serde_json::to_vec(&env).unwrap_or_default();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    fn decode(token: &str, session_id: &str) -> Result<Self, TranscriptError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| TranscriptError::CursorExpired)?;
        let env: CursorEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| TranscriptError::CursorExpired)?;
        if env.v != CURSOR_VERSION || env.s != session_id {
            return Err(TranscriptError::CursorExpired);
        }
        Ok(env.cursor)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Read one page of an `agy` conversation SQLite `.db`, matching the wire and
/// paging contract of `agent_transcript::read_page`.
pub(crate) fn read_page(path: &Path, request: &PageRequest) -> Result<Page, TranscriptError> {
    if request.before.is_some() && request.after.is_some() {
        return Err(TranscriptError::InvalidRequest(
            "pass either before or after, not both",
        ));
    }
    if request.topic.is_some() {
        return Err(TranscriptError::TopicNotFound);
    }
    if request.subagent.is_some() {
        return Err(TranscriptError::SubagentNotFound);
    }

    let limit = request.limit.unwrap_or(DEFAULT_TURNS).clamp(1, MAX_TURNS) as usize;
    if !path.exists() {
        if path.parent().is_some_and(Path::is_dir) {
            return empty_page(path, request);
        }
        return Err(TranscriptError::Unavailable(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("conversation database not found: {}", path.display()),
        )));
    }

    let (session_id, steps, model) = load_conversation(path)?;
    let mut page = page_steps(&session_id, &steps, request, limit)?;
    page.model = model;
    Ok(page)
}

fn empty_page(path: &Path, request: &PageRequest) -> Result<Page, TranscriptError> {
    let session_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();
    let valid = match (&request.before, &request.after) {
        (Some(_), _) => false,
        (None, Some(token)) => matches!(
            AgyCursor::decode(token, &session_id)?,
            AgyCursor::After {
                seen_next_idx: 0,
                tip: None,
                ..
            }
        ),
        (None, None) => true,
    };
    if !valid {
        return Err(TranscriptError::CursorExpired);
    }
    let after = AgyCursor::After {
        seen_next_idx: 0,
        tip: None,
        running: Vec::new(),
        running_emitted: Vec::new(),
        origins: Some(origin::fingerprint(&request.other_prompts)),
        floor: Some(0),
        tip_reply: None,
    }
    .encode(&session_id);
    Ok(Page {
        session_id,
        entries: Vec::new(),
        before: None,
        after,
        pending_ask: None,
        working: None,
        model: None,
        plan: None,
        recap: None,
        subagents: None,
        resent: request.after.as_ref().map(|_| Vec::new()),
        relay_entries: false,
    })
}

fn load_conversation(
    path: &Path,
) -> Result<(String, Vec<DecodedStep>, Option<TranscriptModel>), TranscriptError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)
        .map_err(|err| TranscriptError::Unavailable(std::io::Error::other(err.to_string())))?;
    let _ = conn.busy_timeout(Duration::from_millis(250));

    let fallback_session = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();
    let session_id = conn
        .query_row(
            "SELECT cascade_id FROM trajectory_meta LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_session);

    let mut stmt = conn
        .prepare(
            "SELECT idx, step_type, status, metadata, error_details, step_payload \
             FROM steps WHERE step_format = 0 ORDER BY idx ASC",
        )
        .map_err(|err| TranscriptError::Unavailable(std::io::Error::other(err.to_string())))?;

    let rows = stmt
        .query_map([], |row| {
            let idx: i64 = row.get(0)?;
            let step_type: i64 = row.get(1)?;
            let status: i64 = row.get(2)?;
            let metadata: Option<Vec<u8>> = row.get(3)?;
            let error_details: Option<Vec<u8>> = row.get(4)?;
            let step_payload: Option<Vec<u8>> = row.get(5)?;
            Ok((
                idx,
                step_type,
                status,
                metadata,
                error_details,
                step_payload,
            ))
        })
        .map_err(|err| TranscriptError::Unavailable(std::io::Error::other(err.to_string())))?;

    let mut steps = Vec::new();
    for row in rows {
        let (idx_i64, step_type, status, metadata, error_details, step_payload) = row
            .map_err(|err| TranscriptError::Unavailable(std::io::Error::other(err.to_string())))?;
        let Ok(idx) = u32::try_from(idx_i64) else {
            continue;
        };
        steps.push(decode_step_row(
            idx,
            step_type,
            status,
            metadata.as_deref(),
            error_details.as_deref(),
            step_payload.as_deref(),
        ));
    }
    let model = load_conversation_model(&conn);
    Ok((session_id, steps, model))
}

/// Extract the active model from the conversation's `gen_metadata` table:
/// picks the newest usable row (`ORDER BY idx DESC`), preferring within that
/// row field `1.21` (display label like `"Gemini 4 Neon (High)"`), then `1.19`
/// (slug like `"gemini-4-neon"`), then `3.28` (`"gemini-4-neon-high"`).
fn load_conversation_model(conn: &Connection) -> Option<TranscriptModel> {
    let mut stmt = conn
        .prepare("SELECT data FROM gen_metadata ORDER BY idx DESC LIMIT 16")
        .ok()?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))
        .ok()?;
    for row in rows.flatten() {
        let Some(blob) = row else { continue };
        if let Some(model) = decode_gen_metadata_model(&blob) {
            return Some(model);
        }
    }
    None
}

fn decode_gen_metadata_model(blob: &[u8]) -> Option<TranscriptModel> {
    let fields = decode_pb(blob)?;
    if let Some(f1_bytes) = pb_bytes(&fields, 1) {
        if let Some(f1) = decode_pb(f1_bytes) {
            if let Some(label) = pb_str(&f1, 21) {
                if let Some((id, thinking_level)) = parse_agy_model_label(label) {
                    return Some(agy_transcript_model(id, thinking_level));
                }
            }
            if let Some(slug) = pb_str(&f1, 19) {
                if let Some((id, thinking_level)) = parse_agy_model_slug(slug) {
                    return Some(agy_transcript_model(id, thinking_level));
                }
            }
        }
    }
    if let Some(f3_bytes) = pb_bytes(&fields, 3) {
        if let Some(f3) = decode_pb(f3_bytes) {
            if let Some(slug) = pb_str(&f3, 28) {
                if let Some((id, thinking_level)) = parse_agy_model_slug(slug) {
                    return Some(agy_transcript_model(id, thinking_level));
                }
            }
        }
    }
    None
}

fn agy_transcript_model(id: String, thinking_level: Option<String>) -> TranscriptModel {
    TranscriptModel {
        provider: "antigravity".to_owned(),
        id,
        harness: Some("agy".to_owned()),
        thinking_level,
        thinking_auto: false,
    }
}

fn parse_agy_effort(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    ["minimal", "low", "medium", "high", "xhigh", "max"]
        .iter()
        .find(|&&level| trimmed.eq_ignore_ascii_case(level))
        .map(|&level| level.to_owned())
}

fn parse_agy_model_label(raw: &str) -> Option<(String, Option<String>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((base, rest)) = trimmed.rsplit_once(" (") {
        if let Some(inner) = rest.strip_suffix(')') {
            if let Some(effort) = parse_agy_effort(inner) {
                let base = base.trim();
                if !base.is_empty() {
                    return Some((base.to_owned(), Some(effort)));
                }
            }
        }
    }
    Some((trimmed.to_owned(), None))
}

fn parse_agy_model_slug(raw: &str) -> Option<(String, Option<String>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((base, suffix)) = trimmed.rsplit_once('-') {
        if let Some(effort) = parse_agy_effort(suffix) {
            let base = base.trim();
            if !base.is_empty() {
                return Some((base.to_owned(), Some(effort)));
            }
        }
    }
    Some((trimmed.to_owned(), None))
}

fn page_steps(
    session_id: &str,
    steps: &[DecodedStep],
    request: &PageRequest,
    limit: usize,
) -> Result<Page, TranscriptError> {
    let other_prompts = request.other_prompts.as_slice();
    let origins = origin::fingerprint(other_prompts);
    let max_next_idx = steps.last().map_or(0, |s| s.idx.saturating_add(1));

    let pos_of_idx = |target_idx: u32| -> Option<usize> {
        steps.binary_search_by_key(&target_idx, |s| s.idx).ok()
    };

    let (
        start,
        end,
        is_after,
        prev_running,
        prev_running_emitted,
        served_origins,
        served_floor,
        issued_floor,
        prev_tip_reply,
    ) = match (&request.before, &request.after) {
        (Some(token), _) => {
            let AgyCursor::Before { idx, id } = AgyCursor::decode(token, session_id)? else {
                return Err(TranscriptError::CursorExpired);
            };
            let end = pos_of_idx(idx)
                .filter(|&pos| steps[pos].step_id == id)
                .ok_or(TranscriptError::CursorExpired)?;
            (
                page_start(steps, end, limit),
                end,
                false,
                Vec::new(),
                Vec::new(),
                None,
                None,
                None,
                None,
            )
        }
        (None, Some(token)) => {
            let AgyCursor::After {
                seen_next_idx,
                tip,
                running,
                running_emitted,
                origins: prev_origins,
                floor,
                tip_reply,
            } = AgyCursor::decode(token, session_id)?
            else {
                return Err(TranscriptError::CursorExpired);
            };
            if seen_next_idx > max_next_idx {
                return Err(TranscriptError::CursorExpired);
            }
            if let Some((tip_idx, tip_id)) = tip {
                pos_of_idx(tip_idx)
                    .filter(|&pos| steps[pos].step_id == tip_id)
                    .ok_or(TranscriptError::CursorExpired)?;
            }
            let start = steps.partition_point(|s| s.idx < seen_next_idx);
            let held = held_floor(steps, request.held_from.as_deref(), session_id, floor);
            (
                start,
                budget_end(steps, start),
                true,
                running,
                running_emitted,
                prev_origins,
                held,
                floor,
                tip_reply,
            )
        }
        (None, None) => {
            let end = steps.len();
            (
                page_start(steps, end, limit),
                end,
                false,
                Vec::new(),
                Vec::new(),
                None,
                None,
                None,
                None,
            )
        }
    };

    let mut entries = Vec::new();
    let mut resent_ids = Vec::new();
    let mut others: Option<Vec<(usize, String)>> = None;
    let mut pending_turn_end: Option<usize> = None;

    if is_after {
        // If the previous `after` cursor already emitted `TurnEnd` for the
        // turn-tip reply and a late tool or planner has since extended that
        // same turn (either RUNNING or DONE), expire the cursor so the client
        // reloads cleanly: client-side `mergeTranscript` updates by id in place
        // and cannot delete or relocate an earlier `TurnEnd` in front of new
        // steps.
        if let Some((reply_idx, _, Some(prev_end_idx))) = prev_tip_reply {
            if let Some(pos) = pos_of_idx(reply_idx) {
                if pos < start {
                    let now_final = is_reply_final(steps, pos);
                    let now_close_idx = turn_close_pos_for_reply(steps, pos).map(|p| steps[p].idx);
                    if !now_final || now_close_idx != Some(prev_end_idx) {
                        return Err(TranscriptError::CursorExpired);
                    }
                }
            }
        }

        let floor_pos = |floor_idx: Option<u32>| -> usize {
            steps.partition_point(|s| s.idx < floor_idx.unwrap_or(0))
        };
        let resend_origins = served_origins != Some(origins);
        let replay = if resend_origins {
            Some(floor_pos(served_floor)..start)
        } else if served_floor < issued_floor {
            Some(floor_pos(served_floor)..floor_pos(issued_floor).min(start))
        } else {
            None
        };
        if let Some(range) = replay {
            let matched = other_user_turns(steps, other_prompts);
            for &(pos, _) in matched.iter().filter(|(pos, _)| range.contains(pos)) {
                let before_len = entries.len();
                render_step(steps, pos, false, &mut entries);
                for entry in &entries[before_len..] {
                    resent_ids.push(entry.id().to_owned());
                }
            }
            others = Some(matched);
        }

        // Re-send any previously-running/generating tool or planner step before
        // `start` that has now finished (excluding update_steps, handled below
        // per turn). Only entry ids already emitted while running go into
        // `resent_ids`; brand-new entries (e.g. a generating planner's newly
        // populated `:reply`) are omitted from `resent_ids` so incremental
        // clients append them instead of dropping them as unloaded history.
        let prev_emitted_set: HashSet<&str> =
            prev_running_emitted.iter().map(String::as_str).collect();
        let mut resent_planners = HashSet::new();
        let mut resent_plan_turns = HashSet::new();
        for run_idx in prev_running {
            let Some(pos) = pos_of_idx(run_idx) else {
                continue;
            };
            if pos >= start || steps[pos].is_running() {
                continue;
            }
            // If a previously running/pending step settles at or after an
            // earlier turn's tip reply (so it held that reply open) and that
            // turn's reply is no longer tracked by `prev_tip_reply` (e.g. a
            // newer turn already started before `start`), incremental replay
            // cannot insert its `TurnEnd` ahead of the later turn's entries.
            // Expire the cursor so the client reloads in order. A background
            // command strictly before `reply_pos` never held `TurnEnd` open,
            // so it simply resends its settled status in place.
            let (turn_start, turn_end) = turn_bounds(steps, pos);
            if turn_end < start {
                if let Some(reply_pos) = last_nonblank_planner_reply(steps, turn_start..turn_end) {
                    let tracked = prev_tip_reply
                        .is_some_and(|(reply_idx, _, _)| reply_idx == steps[reply_pos].idx);
                    if pos >= reply_pos && !tracked && is_reply_final(steps, reply_pos) {
                        return Err(TranscriptError::CursorExpired);
                    }
                }
            }
            if steps[pos].plan_items().is_some() {
                if resent_plan_turns.insert(turn_start) {
                    if let Some(plan_entry) = build_turn_plan(steps, turn_start, turn_end) {
                        resent_ids.push(plan_entry.id().to_owned());
                        entries.push(plan_entry);
                    }
                }
                continue;
            }
            let before_len = entries.len();
            render_step(steps, pos, false, &mut entries);
            let has_brand_new = entries[before_len..]
                .iter()
                .any(|entry| !prev_emitted_set.contains(entry.id()));
            if has_brand_new && pos + 1 < start {
                // Appending a brand-new entry (like `:reply`) from an earlier
                // step after later steps already sent in `(pos + 1)..start`
                // would violate entry order; expire the cursor to reload cleanly.
                return Err(TranscriptError::CursorExpired);
            }
            for entry in &entries[before_len..] {
                if prev_emitted_set.contains(entry.id()) {
                    resent_ids.push(entry.id().to_owned());
                }
            }
            if matches!(steps[pos].payload, StepPayload::Planner { .. }) {
                resent_planners.insert(pos);
                if is_reply_final(steps, pos)
                    && prev_tip_reply
                        .is_none_or(|(idx, _, end_at)| idx != steps[pos].idx || end_at.is_none())
                {
                    pending_turn_end = Some(pos);
                }
            }
        }

        // Re-send `{turn_id}:plan` when a new `update_steps` in `start..end`
        // updates a turn whose plan owner was already sent before `start`.
        for pos in start..end {
            if steps[pos].plan_items().is_none() {
                continue;
            }
            let (turn_start, turn_end) = turn_bounds(steps, pos);
            if turn_plan_owner(steps, turn_start, turn_end).is_some_and(|owner| owner < start)
                && resent_plan_turns.insert(turn_start)
            {
                if let Some(plan_entry) = build_turn_plan(steps, turn_start, turn_end) {
                    resent_ids.push(plan_entry.id().to_owned());
                    entries.push(plan_entry);
                }
            }
        }

        // Re-send the previous turn-tip reply if its `final` state flipped
        // (e.g. a trailing tool finished), and defer emitting `TurnEnd` until
        // after `start..end` so `TurnEnd` always appears after any new steps.
        if let Some((reply_idx, was_final, end_at_idx)) = prev_tip_reply {
            if let Some(pos) = pos_of_idx(reply_idx) {
                if pos < start {
                    if let StepPayload::Planner { reply, .. } = &steps[pos].payload {
                        if !reply.trim().is_empty() {
                            let now_final = is_reply_final(steps, pos);
                            if !resent_planners.contains(&pos) && now_final != was_final {
                                let reply_id = format!("{}:reply", steps[pos].step_id);
                                resent_ids.push(reply_id.clone());
                                entries.push(TranscriptEntry::Reply {
                                    id: reply_id,
                                    ts_ms: steps[pos].created_ms,
                                    text: reply.clone(),
                                    is_final: now_final,
                                });
                            }
                            if now_final && end_at_idx.is_none() {
                                pending_turn_end = Some(pos);
                            }
                        }
                    }
                }
            }
        }
    }

    let resent = is_after.then_some(resent_ids);

    // If a previously unsettled turn-tip reply (`pos < start`) has now settled
    // AND its closing step is also `< start` (e.g. its trailing tool or planner
    // transitioned RUNNING -> DONE in place), append its `TurnEnd` here — AFTER
    // snapshotting `resent` (it is a brand-new entry) and strictly BEFORE any
    // new steps in `start..end` (which may begin with the next user turn).
    // When `close_pos >= start`, `render_step` emits `TurnEnd` right after the
    // closing step inside `start..end`, still before any subsequent user turn.
    if let Some(reply_pos) = pending_turn_end {
        if turn_close_pos_for_reply(steps, reply_pos).is_some_and(|close_pos| close_pos < start) {
            entries.push(TranscriptEntry::TurnEnd {
                id: format!("{}:end", steps[reply_pos].step_id),
                ts_ms: turn_completed_ms(steps, reply_pos),
                status: turn_end_status(steps, reply_pos),
                error: None,
            });
        }
    }

    let start = match request.max_bytes {
        Some(max_bytes) if !is_after => {
            let matched = other_user_turns(steps, other_prompts);
            let kept = render_within(
                steps,
                start,
                end,
                max_bytes as usize,
                &matched,
                &mut entries,
            );
            others = Some(matched);
            kept
        }
        _ => {
            for pos in start..end {
                render_step(steps, pos, true, &mut entries);
            }
            start
        }
    };

    let has_user = entries
        .iter()
        .any(|entry| matches!(entry, TranscriptEntry::User { .. }));
    let others = match others {
        Some(o) => o,
        None if has_user => other_user_turns(steps, other_prompts),
        None => Vec::new(),
    };
    mark_other_origins(&mut entries, &others);

    let before = (!is_after && start > 0).then(|| {
        let step = &steps[start];
        AgyCursor::Before {
            idx: step.idx,
            id: step.step_id.clone(),
        }
        .encode(session_id)
    });

    let seen_next_idx = if is_after && end < steps.len() {
        steps[end].idx
    } else {
        max_next_idx
    };
    let seen_end_pos = steps.partition_point(|s| s.idx < seen_next_idx);
    let tip = seen_end_pos
        .checked_sub(1)
        .map(|pos| (steps[pos].idx, steps[pos].step_id.clone()));
    let mut running = Vec::new();
    let mut running_emitted = Vec::new();
    let mut scratch = Vec::new();
    let prev_emitted_set: HashSet<&str> = prev_running_emitted.iter().map(String::as_str).collect();
    for (pos, step) in steps[..seen_end_pos].iter().enumerate() {
        if step.is_running() {
            running.push(step.idx);
            scratch.clear();
            render_step(steps, pos, false, &mut scratch);
            for entry in &scratch {
                // On an `after` poll, a still-running step strictly before `start`
                // was skipped above (not sent in `entries`), so only carry forward
                // entry ids that were already emitted to the client on a prior poll.
                if is_after && pos < start && !prev_emitted_set.contains(entry.id()) {
                    continue;
                }
                running_emitted.push(entry.id().to_owned());
            }
        }
    }
    let tip_reply = latest_tip_reply_state(steps, seen_end_pos);
    let floor = if is_after {
        served_floor
    } else {
        Some(steps.get(start).map_or(max_next_idx, |s| s.idx))
    };

    let after = AgyCursor::After {
        seen_next_idx,
        tip,
        running,
        running_emitted,
        origins: Some(origins),
        floor,
        tip_reply,
    }
    .encode(session_id);

    Ok(Page {
        session_id: session_id.to_owned(),
        entries,
        before,
        after,
        pending_ask: current_pending_ask(steps),
        working: current_working(steps),
        model: None,
        plan: current_plan(steps),
        recap: None,
        subagents: None,
        resent,
        relay_entries: false,
    })
}

fn held_floor(
    steps: &[DecodedStep],
    held_from: Option<&str>,
    session_id: &str,
    floor: Option<u32>,
) -> Option<u32> {
    let held = match held_from {
        None => return floor,
        Some("") => 0,
        Some(token) => match AgyCursor::decode(token, session_id) {
            Ok(AgyCursor::Before { idx, id })
                if steps
                    .binary_search_by_key(&idx, |s| s.idx)
                    .ok()
                    .is_some_and(|pos| steps[pos].step_id == id) =>
            {
                idx
            }
            _ => return floor,
        },
    };
    floor.map(|f| f.min(held))
}

fn page_start(steps: &[DecodedStep], end: usize, limit: usize) -> usize {
    let mut turns = 0;
    let mut cost = 0;
    let mut last_turn_start = None;
    let mut pos = end;
    while pos > 0 {
        pos -= 1;
        if steps[pos].is_rendered() {
            cost += 1;
        }
        if steps[pos].is_user() {
            turns += 1;
            last_turn_start = Some(pos);
            if turns == limit {
                return pos;
            }
        }
        if cost >= PAGE_RECORD_BUDGET {
            return last_turn_start.unwrap_or(pos);
        }
    }
    0
}

fn budget_end(steps: &[DecodedStep], start: usize) -> usize {
    let mut cost = 0;
    for (offset, step) in steps[start..].iter().enumerate() {
        if step.is_rendered() {
            cost += 1;
            if cost > PAGE_RECORD_BUDGET {
                return start + offset;
            }
        }
    }
    steps.len()
}

fn other_user_turns(steps: &[DecodedStep], prompts: &[OtherPrompt]) -> Vec<(usize, String)> {
    let Some(earliest_ms) = origin::earliest_turn_ms(prompts) else {
        return Vec::new();
    };
    let mut positions = Vec::new();
    let mut turns = Vec::new();
    for pos in (0..steps.len()).rev() {
        let StepPayload::User { text } = &steps[pos].payload else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        let ts_ms = steps[pos].created_ms;
        if ts_ms < earliest_ms {
            break;
        }
        positions.push(pos);
        turns.push(origin::UserTurn {
            id: steps[pos].step_id.clone(),
            ts_ms,
            sha256: origin::text_digest(text),
        });
    }
    positions.reverse();
    turns.reverse();
    let matched = origin::matched_turns(prompts, &turns);
    positions
        .into_iter()
        .zip(turns)
        .filter(|(_, turn)| matched.contains(&turn.id))
        .map(|(pos, turn)| (pos, turn.id))
        .collect()
}

fn render_within(
    steps: &[DecodedStep],
    start: usize,
    end: usize,
    max_bytes: usize,
    others: &[(usize, String)],
    entries: &mut Vec<TranscriptEntry>,
) -> usize {
    if start == end {
        return start;
    }
    let mut total = 1;
    let mut kept_any = false;
    let mut kept = end;
    let mut rendered: Vec<Vec<TranscriptEntry>> = Vec::new();
    for pos in (start..end).rev() {
        let mut one = Vec::new();
        render_step(steps, pos, true, &mut one);
        mark_other_origins(&mut one, others);
        let size: usize = one.iter().map(|entry| json_len(entry) + 1).sum();
        if size > 0 && kept_any && total + size > max_bytes {
            break;
        }
        total += size;
        kept_any |= size > 0;
        kept = pos;
        rendered.push(one);
    }
    entries.extend(rendered.into_iter().rev().flatten());
    kept
}

fn turn_bounds(steps: &[DecodedStep], pos: usize) -> (usize, usize) {
    let start = (0..=pos).rev().find(|&p| steps[p].is_user()).unwrap_or(0);
    let end = ((pos + 1)..steps.len())
        .find(|&p| steps[p].is_user())
        .unwrap_or(steps.len());
    (start, end)
}

fn turn_id_for(steps: &[DecodedStep], pos: usize) -> &str {
    (0..=pos)
        .rev()
        .find(|&p| steps[p].is_user())
        .map_or(steps[pos].step_id.as_str(), |p| steps[p].step_id.as_str())
}

fn turn_plan_owner(steps: &[DecodedStep], turn_start: usize, turn_end: usize) -> Option<usize> {
    (turn_start..turn_end).find(|&p| steps[p].plan_items().is_some())
}

fn build_turn_plan(
    steps: &[DecodedStep],
    turn_start: usize,
    turn_end: usize,
) -> Option<TranscriptEntry> {
    let turn_id = turn_id_for(steps, turn_start);
    for p in (turn_start..turn_end).rev() {
        if let Some(items) = steps[p].plan_items() {
            return Some(TranscriptEntry::Plan {
                id: format!("{turn_id}:plan"),
                ts_ms: steps[p].created_ms,
                items,
            });
        }
    }
    None
}

/// A planner reply at `pos` is final when:
/// - the step itself is not still running,
/// - no later planner step exists in the same turn,
/// - nothing after it in the same turn is still running, and
/// - if the planner explicitly requested tool calls (`has_tool_calls`), those
///   tool steps have already landed (and none are still running).
fn is_reply_final(steps: &[DecodedStep], pos: usize) -> bool {
    let step = &steps[pos];
    let StepPayload::Planner {
        reply,
        has_tool_calls,
        ..
    } = &step.payload
    else {
        return false;
    };
    if reply.trim().is_empty() || step.is_running() {
        return false;
    }
    let (_, turn_end) = turn_bounds(steps, pos);
    let tail = &steps[(pos + 1)..turn_end];
    if tail
        .iter()
        .any(|s| matches!(s.payload, StepPayload::Planner { .. }) || s.is_running())
    {
        return false;
    }
    if *has_tool_calls
        && !tail
            .iter()
            .any(|s| matches!(s.payload, StepPayload::Tool { .. }))
    {
        return false;
    }
    true
}

fn turn_completed_ms(steps: &[DecodedStep], pos: usize) -> u64 {
    let (_, turn_end) = turn_bounds(steps, pos);
    steps[pos..turn_end]
        .iter()
        .filter_map(|s| s.completed_ms.or(Some(s.created_ms)))
        .max()
        .unwrap_or(steps[pos].created_ms)
}

fn turn_end_status(steps: &[DecodedStep], pos: usize) -> TranscriptTurnStatus {
    let (_, turn_end) = turn_bounds(steps, pos);
    let last_status = steps[pos..turn_end]
        .iter()
        .rev()
        .find(|s| {
            matches!(
                s.payload,
                StepPayload::Planner { .. } | StepPayload::Tool { .. }
            )
        })
        .map(|s| s.status)
        .unwrap_or(steps[pos].status);
    match last_status {
        STATUS_CANCELED => TranscriptTurnStatus::Aborted,
        STATUS_ERROR => TranscriptTurnStatus::Error,
        _ => TranscriptTurnStatus::Done,
    }
}

/// The step position that closes a settled turn owned by the planner reply at
/// `reply_pos`: the last trailing tool step (if any) in the turn, otherwise
/// `reply_pos` itself. `TurnEnd` is attached here so it always appears after
/// any trailing tool steps.
fn turn_close_pos_for_reply(steps: &[DecodedStep], reply_pos: usize) -> Option<usize> {
    if !is_reply_final(steps, reply_pos) {
        return None;
    }
    let (_, turn_end) = turn_bounds(steps, reply_pos);
    let last_tool = ((reply_pos + 1)..turn_end).rev().find(|&p| {
        matches!(steps[p].payload, StepPayload::Tool { .. }) && steps[p].plan_items().is_none()
    });
    Some(last_tool.unwrap_or(reply_pos))
}

fn last_nonblank_planner_reply(
    steps: &[DecodedStep],
    range: std::ops::Range<usize>,
) -> Option<usize> {
    range.rev().find(|&p| {
        matches!(
            &steps[p].payload,
            StepPayload::Planner { reply, .. } if !reply.trim().is_empty()
        )
    })
}

/// If `pos` is the closing step of a settled turn, return the `reply_pos` that
/// owns that turn's `{step_id}:end` entry.
fn settled_turn_reply_for_close_pos(steps: &[DecodedStep], pos: usize) -> Option<usize> {
    let (turn_start, turn_end) = turn_bounds(steps, pos);
    let reply_pos = last_nonblank_planner_reply(steps, turn_start..turn_end)?;
    (turn_close_pos_for_reply(steps, reply_pos) == Some(pos)).then_some(reply_pos)
}

fn latest_tip_reply_state(
    steps: &[DecodedStep],
    seen_end_pos: usize,
) -> Option<(u32, bool, Option<u32>)> {
    if seen_end_pos == 0 {
        return None;
    }
    let last_turn_start = (0..seen_end_pos)
        .rev()
        .find(|&p| steps[p].is_user())
        .unwrap_or(0);
    let reply_pos = last_nonblank_planner_reply(steps, last_turn_start..seen_end_pos)?;
    let reply_idx = steps[reply_pos].idx;
    let now_final = is_reply_final(steps, reply_pos);
    let end_at_idx = turn_close_pos_for_reply(steps, reply_pos)
        .filter(|&close_pos| close_pos < seen_end_pos)
        .map(|close_pos| steps[close_pos].idx);
    Some((reply_idx, now_final, end_at_idx))
}

fn render_step(
    steps: &[DecodedStep],
    pos: usize,
    include_turn_end: bool,
    out: &mut Vec<TranscriptEntry>,
) {
    let step = &steps[pos];
    match &step.payload {
        StepPayload::User { text } => {
            if !text.trim().is_empty() {
                out.push(user_entry(step.step_id.clone(), step.created_ms, text));
            }
        }
        StepPayload::Planner {
            thinking, reply, ..
        } => {
            if !thinking.trim().is_empty() {
                out.push(TranscriptEntry::Thinking {
                    id: format!("{}:thinking", step.step_id),
                    ts_ms: step.created_ms,
                    text: thinking.clone(),
                });
            }
            if !reply.trim().is_empty() {
                let is_final = is_reply_final(steps, pos);
                out.push(TranscriptEntry::Reply {
                    id: format!("{}:reply", step.step_id),
                    ts_ms: step.created_ms,
                    text: reply.clone(),
                    is_final,
                });
            }
        }
        StepPayload::Tool {
            call_id,
            tool,
            args_json,
            kv_args,
            ui_verb,
            error_message,
            ask_answer,
        } => {
            if step.plan_items().is_some() {
                let (turn_start, turn_end) = turn_bounds(steps, pos);
                if turn_plan_owner(steps, turn_start, turn_end) == Some(pos) {
                    if let Some(plan_entry) = build_turn_plan(steps, turn_start, turn_end) {
                        out.push(plan_entry);
                    }
                }
                return;
            }
            if tool == "ask_question" {
                let questions = agy_ask_questions(args_json.as_ref(), kv_args);
                if !questions.is_empty() {
                    let answer = (!step.is_running()).then(|| ask_answer.clone()).flatten();
                    let form_status = match step.status {
                        STATUS_CANCELED | STATUS_ERROR => Some(AskFormStatus::Cancelled),
                        _ => None,
                    };
                    out.push(TranscriptEntry::Ask {
                        id: format!("{}:{call_id}", step.step_id),
                        ts_ms: step.created_ms,
                        questions,
                        answer,
                        form: None,
                        form_answer: None,
                        form_status,
                    });
                    if include_turn_end {
                        if let Some(reply_pos) = settled_turn_reply_for_close_pos(steps, pos) {
                            out.push(TranscriptEntry::TurnEnd {
                                id: format!("{}:end", steps[reply_pos].step_id),
                                ts_ms: turn_completed_ms(steps, reply_pos),
                                status: turn_end_status(steps, reply_pos),
                                error: None,
                            });
                        }
                    }
                    return;
                }
            }
            let status = match step.status {
                STATUS_PENDING | STATUS_RUNNING | STATUS_GENERATING => {
                    TranscriptStepStatus::Running
                }
                STATUS_CANCELED | STATUS_ERROR => TranscriptStepStatus::Error,
                STATUS_DONE => TranscriptStepStatus::Ok,
                _ => TranscriptStepStatus::Ok,
            };
            let intent = agy_step_intent(tool, args_json.as_ref(), kv_args, ui_verb.as_deref());
            let detail = agy_step_detail(args_json.as_ref(), kv_args, error_message.as_deref());
            out.push(TranscriptEntry::Step {
                id: format!("{}:{call_id}", step.step_id),
                ts_ms: step.created_ms,
                tool: tool.clone(),
                intent,
                status,
                detail,
            });
        }
        StepPayload::Ephemeral { tag, body } => {
            if tag == "work_efficiently_reminder" || body.trim().is_empty() {
                return;
            }
            let (source, title) = if tag == "task_notification" {
                (TranscriptNoteSource::AsyncResult, "Task notification")
            } else {
                (TranscriptNoteSource::Other, "System notice")
            };
            out.push(TranscriptEntry::Note {
                id: step.step_id.clone(),
                ts_ms: step.created_ms,
                source,
                title: title.to_owned(),
                from: None,
                body: truncate_chars(body.trim(), NOTE_BODY_MAX_CHARS),
            });
        }
        StepPayload::Ignored => {}
    }

    if include_turn_end {
        if let Some(reply_pos) = settled_turn_reply_for_close_pos(steps, pos) {
            out.push(TranscriptEntry::TurnEnd {
                id: format!("{}:end", steps[reply_pos].step_id),
                ts_ms: turn_completed_ms(steps, reply_pos),
                status: turn_end_status(steps, reply_pos),
                error: None,
            });
        }
    }
}

fn agy_ask_questions(
    args_json: Option<&Value>,
    kv_args: &[(String, String)],
) -> Vec<crate::api::schema::AskQuestion> {
    let direct = normalize::ask_questions(args_json);
    if !direct.is_empty() {
        return direct;
    }
    if let Some((_, raw)) = kv_args.iter().find(|(k, _)| k == "questions") {
        if let Ok(arr @ Value::Array(_)) = serde_json::from_str::<Value>(raw) {
            return normalize::ask_questions(Some(&serde_json::json!({ "questions": arr })));
        }
    }
    Vec::new()
}

fn parse_agy_ask_answers(raw: &str) -> Option<Vec<String>> {
    let mut answers: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    let flush = |current: &mut Option<String>, answers: &mut Vec<String>| {
        if let Some(buf) = current.take() {
            let trimmed = buf.trim_matches(|c| c == '\n' || c == '\r');
            if !trimmed.trim().is_empty() {
                answers.push(trimmed.to_owned());
            }
        }
    };
    for line in raw.lines() {
        if let Some(rest) = strip_agy_answer_prefix(line) {
            flush(&mut current, &mut answers);
            let first = rest.strip_prefix(' ').unwrap_or(rest).trim_end();
            current = Some(first.to_owned());
        } else if let Some(buf) = current.as_mut() {
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(line.trim_end());
        }
    }
    flush(&mut current, &mut answers);
    (!answers.is_empty()).then_some(answers)
}

fn strip_agy_answer_prefix(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('A')?;
    let (digits, after) = rest.split_once(':')?;
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(after)
}

fn current_pending_ask(steps: &[DecodedStep]) -> Option<PendingAsk> {
    let last_user = steps.iter().rposition(DecodedStep::is_user).unwrap_or(0);
    for step in steps[last_user..].iter().rev() {
        if !step.is_running() {
            continue;
        }
        if let StepPayload::Tool {
            call_id,
            tool,
            args_json,
            kv_args,
            ..
        } = &step.payload
        {
            if tool == "ask_question" {
                let questions = agy_ask_questions(args_json.as_ref(), kv_args);
                if !questions.is_empty() {
                    return Some(PendingAsk {
                        id: format!("{}:{call_id}", step.step_id),
                        questions,
                        answerable: false,
                        form: None,
                        form_answerable: false,
                        dismissable: false,
                    });
                }
            }
        }
    }
    None
}

fn current_working(steps: &[DecodedStep]) -> Option<TranscriptWorking> {
    let last_user = steps.iter().rposition(DecodedStep::is_user).unwrap_or(0);
    // Prefer any active tool step (running or queued) in the current turn, even
    // if a planner reply has already been emitted; otherwise surface a
    // generating planner in the current turn, or a background command/workflow
    // still running from an earlier turn.
    let active_tool = steps[last_user..]
        .iter()
        .rev()
        .find(|s| {
            s.is_running()
                && matches!(
                    &s.payload,
                    StepPayload::Tool { tool, .. }
                        if tool != "schedule" && tool != "ask_question"
                )
        })
        .or_else(|| {
            steps[..last_user].iter().rev().find(|s| {
                s.status == STATUS_RUNNING
                    && matches!(
                        &s.payload,
                        StepPayload::Tool { tool, .. }
                            if matches!(tool.as_str(), "run_command" | "run_workflow")
                    )
            })
        });
    if let Some(active) = active_tool {
        if let StepPayload::Tool {
            tool,
            args_json,
            kv_args,
            ui_verb,
            ..
        } = &active.payload
        {
            return Some(TranscriptWorking {
                intent: agy_step_intent(tool, args_json.as_ref(), kv_args, ui_verb.as_deref()),
                tool: tool.clone(),
                since_ms: active.created_ms,
            });
        }
    }
    // If a pending ask_question is waiting for the user, show the ask card
    // rather than spinning "Thinking".
    if current_pending_ask(steps).is_some() {
        return None;
    }
    steps[last_user..]
        .iter()
        .rev()
        .find(|s| s.is_running() && matches!(s.payload, StepPayload::Planner { .. }))
        .map(|s| TranscriptWorking {
            intent: "Thinking".to_owned(),
            tool: "planner".to_owned(),
            since_ms: s.created_ms,
        })
}

fn current_plan(steps: &[DecodedStep]) -> Option<Vec<TranscriptPlanItem>> {
    for step in steps.iter().rev() {
        if let StepPayload::Tool {
            tool, args_json, ..
        } = &step.payload
        {
            if tool == "update_steps" {
                if let Some(items) = parse_update_steps_plan(args_json.as_ref()) {
                    return Some(items);
                }
            }
        }
    }
    None
}

fn parse_update_steps_plan(args: Option<&Value>) -> Option<Vec<TranscriptPlanItem>> {
    let arr = args?.get("steps")?.as_array()?;
    let items: Vec<TranscriptPlanItem> = arr
        .iter()
        .filter_map(|item| {
            let text = item.get("title")?.as_str()?.trim();
            if text.is_empty() {
                return None;
            }
            let status_str = item.get("status").and_then(Value::as_str).unwrap_or("");
            let (done, status) = match status_str {
                "done" => (true, TranscriptTaskStatus::Completed),
                "in_progress" => (false, TranscriptTaskStatus::InProgress),
                "pending" => (false, TranscriptTaskStatus::Pending),
                "failed" => (false, TranscriptTaskStatus::Blocked),
                "skipped" => (true, TranscriptTaskStatus::Completed),
                _ => (false, TranscriptTaskStatus::Unknown),
            };
            Some(TranscriptPlanItem {
                text: text.to_owned(),
                done,
                status,
                phase: None,
                blocker: None,
            })
        })
        .collect();
    (!items.is_empty()).then_some(items)
}

fn agy_step_intent(
    tool: &str,
    args_json: Option<&Value>,
    kv_args: &[(String, String)],
    ui_verb: Option<&str>,
) -> String {
    if let Some(summary) = lookup_arg(args_json, kv_args, "toolSummary") {
        return truncate_chars(summary.trim(), 120);
    }
    if let Some(desc) = lookup_arg(args_json, kv_args, "Description") {
        return truncate_chars(desc.trim(), 120);
    }
    if let Some(verb) = ui_verb.map(str::trim).filter(|v| !v.is_empty()) {
        if let Some(path) = lookup_arg(args_json, kv_args, "Path") {
            let base = Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(path);
            return format!("{verb} {base}");
        }
        return verb.to_owned();
    }
    match tool {
        "read_file" => "Read file",
        "write_file" => "Write file",
        "edit_file" => "Edit file",
        "run_command" => "Run command",
        "search_web" => "Search web",
        "manage_task" => "Manage task",
        "schedule" => "Schedule",
        other => other,
    }
    .to_owned()
}

fn agy_step_detail(
    args_json: Option<&Value>,
    kv_args: &[(String, String)],
    error_message: Option<&str>,
) -> Option<String> {
    for &key in AGY_DETAIL_KEYS {
        if let Some(val) = lookup_arg(args_json, kv_args, key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(truncate_chars(trimmed, DETAIL_MAX_CHARS));
            }
        }
    }
    if let Some(err) = error_message.map(str::trim).filter(|e| !e.is_empty()) {
        return Some(truncate_chars(err, DETAIL_MAX_CHARS));
    }
    // Reuse omp's fallback helper if JSON has other keys.
    normalize::step_detail("tool", args_json)
}

fn lookup_arg<'a>(
    args_json: Option<&'a Value>,
    kv_args: &'a [(String, String)],
    key: &str,
) -> Option<&'a str> {
    if let Some(val) = args_json
        .and_then(|obj| obj.get(key))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    {
        return Some(val);
    }
    kv_args
        .iter()
        .find(|(k, v)| k == key && !v.trim().is_empty())
        .map(|(_, v)| v.as_str())
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut iter = text.char_indices();
    if let Some((idx, _)) = iter.nth(max_chars) {
        let mut out = text[..idx].to_owned();
        out.push('…');
        out
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_copy(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "herdr-agy-test-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("conv-fixture-0001.db");
        std::fs::write(&path, include_bytes!("agy_fixture.db")).unwrap();
        path
    }

    #[test]
    fn decodes_scrubbed_real_fixture_db_into_user_thinking_steps_and_replies() {
        let path = fixture_copy("decode");
        let page = read_page(&path, &PageRequest::default()).unwrap();
        assert_eq!(page.session_id, "conv-fixture-0001");
        assert!(page.before.is_none());
        assert!(page.pending_ask.is_none());
        assert!(page.resent.is_none());

        // Fixture has 2 user prompts, 1 thinking, 2 replies, 4 tool steps (ok, error,
        // canceled->error, running), and 1 internal reminder (which must be skipped).
        let users: Vec<&str> = page
            .entries
            .iter()
            .filter_map(|e| match e {
                TranscriptEntry::User { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(users, ["Hey", "Check README.md and run tests"]);

        let replies: Vec<(&str, bool)> = page
            .entries
            .iter()
            .filter_map(|e| match e {
                TranscriptEntry::Reply { text, is_final, .. } => Some((text.as_str(), *is_final)),
                _ => None,
            })
            .collect();
        assert_eq!(
            replies,
            [
                ("Hey! How can I help?", true),
                (
                    "I read README.md; writing out.txt was denied and cargo test was canceled.",
                    false
                ),
            ]
        );

        let thinking: Vec<&str> = page
            .entries
            .iter()
            .filter_map(|e| match e {
                TranscriptEntry::Thinking { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            thinking,
            ["Reading the README first, then running the test suite."]
        );

        let steps: Vec<(&str, TranscriptStepStatus, &str, Option<&str>)> = page
            .entries
            .iter()
            .filter_map(|e| match e {
                TranscriptEntry::Step {
                    tool,
                    status,
                    intent,
                    detail,
                    ..
                } => Some((tool.as_str(), *status, intent.as_str(), detail.as_deref())),
                _ => None,
            })
            .collect();
        assert_eq!(
            steps,
            [
                (
                    "read_file",
                    TranscriptStepStatus::Ok,
                    "Analyzed README.md",
                    Some("/workspace/README.md")
                ),
                (
                    "write_file",
                    TranscriptStepStatus::Error,
                    "Write file",
                    Some("/workspace/out.txt")
                ),
                (
                    "run_command",
                    TranscriptStepStatus::Error,
                    "Run unit tests",
                    Some("cargo test")
                ),
                (
                    "run_command",
                    TranscriptStepStatus::Running,
                    "Check build",
                    Some("cargo check")
                ),
            ]
        );

        // Internal work_efficiently_reminder must not appear as a Note.
        assert!(!page
            .entries
            .iter()
            .any(|e| matches!(e, TranscriptEntry::Note { .. })));

        // Step 9 is RUNNING so `working` reports it.
        let working = page.working.expect("running step populates working");
        assert_eq!(working.tool, "run_command");
        assert_eq!(working.intent, "Check build");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn paging_with_limit_before_max_bytes_and_after_resend_matches_contract() {
        let path = fixture_copy("paging");

        // Newest 1 turn -> only the second user prompt and its follow-up steps.
        let newest = read_page(
            &path,
            &PageRequest {
                limit: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(newest.before.is_some());
        assert!(newest.entries.iter().any(|e| matches!(
            e,
            TranscriptEntry::User { text, .. } if text == "Check README.md and run tests"
        )));
        assert!(!newest
            .entries
            .iter()
            .any(|e| matches!(e, TranscriptEntry::User { text, .. } if text == "Hey")));

        // Page older with `before` -> returns the first turn ("Hey").
        let older = read_page(
            &path,
            &PageRequest {
                before: newest.before.clone(),
                limit: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(older.before.is_none());
        assert!(older
            .entries
            .iter()
            .any(|e| matches!(e, TranscriptEntry::User { text, .. } if text == "Hey")));

        // `max_bytes` trims from the older end while keeping at least one step.
        let small = read_page(
            &path,
            &PageRequest {
                max_bytes: Some(250),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!small.entries.is_empty());
        assert!(small.before.is_some());

        // `after` with no changes returns empty entries and empty resent.
        let quiet = read_page(
            &path,
            &PageRequest {
                after: Some(newest.after.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(quiet.entries.is_empty());
        assert_eq!(quiet.resent, Some(Vec::new()));

        // Update step idx=9 from RUNNING (2) to DONE (3) in place: the next
        // `after` poll must re-send that step under the same id, clear `working`,
        // flip step 8's reply to `final: true` (resent), and emit `TurnEnd` once.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("UPDATE steps SET status = 3 WHERE idx = 9", [])
                .unwrap();
        }
        let updated = read_page(
            &path,
            &PageRequest {
                after: Some(newest.after.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(updated.working.is_none());
        assert_eq!(updated.entries.len(), 3, "{:?}", updated.entries);
        assert!(matches!(
            &updated.entries[0],
            TranscriptEntry::Step {
                id,
                tool,
                status: TranscriptStepStatus::Ok,
                ..
            } if id == "step-g9:call_cmd_4" && tool == "run_command"
        ));
        assert!(matches!(
            &updated.entries[1],
            TranscriptEntry::Reply {
                id,
                is_final: true,
                ..
            } if id == "step-p8:reply"
        ));
        assert!(matches!(
            &updated.entries[2],
            TranscriptEntry::TurnEnd {
                id,
                status: TranscriptTurnStatus::Done,
                ..
            } if id == "step-p8:end"
        ));
        assert_eq!(
            updated.resent,
            Some(vec![
                "step-g9:call_cmd_4".to_owned(),
                "step-p8:reply".to_owned(),
            ])
        );

        // Once settled, a subsequent `after` poll returns nothing and a fresh
        // read shows `final: true` + `TurnEnd` on the turn ending with a tool.
        let settled = read_page(
            &path,
            &PageRequest {
                after: Some(updated.after.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(settled.entries.is_empty());
        assert_eq!(settled.resent, Some(Vec::new()));

        let fresh_done = read_page(&path, &PageRequest::default()).unwrap();
        assert!(fresh_done.entries.iter().any(|e| matches!(
            e,
            TranscriptEntry::Reply { id, is_final: true, .. } if id == "step-p8:reply"
        )));
        assert!(fresh_done.entries.iter().any(|e| matches!(
            e,
            TranscriptEntry::TurnEnd { id, status: TranscriptTurnStatus::Done, .. }
                if id == "step-p8:end"
        )));

        // Both before and after is invalid_request.
        let err = read_page(
            &path,
            &PageRequest {
                before: newest.before,
                after: Some(newest.after),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_request");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn extracts_conversation_db_from_open_files_and_argv() {
        let files = vec![
            PathBuf::from("/root/.gemini/antigravity-cli/conversation_summaries.db"),
            PathBuf::from("/root/.gemini/antigravity-cli/conversations/abc-123.db-wal"),
            PathBuf::from("/root/.gemini/antigravity-cli/conversations/abc-123.db-shm"),
            PathBuf::from("/root/.gemini/antigravity-cli/conversations/abc-123.db"),
            PathBuf::from("/root/.gemini/antigravity-cli/presence/abc-123.lock"),
        ];
        assert_eq!(
            extract_db_from_open_files(&files, None),
            Some(PathBuf::from(
                "/root/.gemini/antigravity-cli/conversations/abc-123.db"
            ))
        );

        // When preferred_id is set and does NOT match any open DB or lock,
        // never silently return another conversation's DB.
        assert_eq!(extract_db_from_open_files(&files, Some("other-conv")), None);

        // When preferred_id matches a presence lock even without its .db open,
        // return that preferred conversation's DB path.
        let mixed = vec![
            PathBuf::from("/root/.gemini/antigravity-cli/conversations/other-b.db"),
            PathBuf::from("/root/.gemini/antigravity-cli/presence/wanted-a.lock"),
        ];
        assert_eq!(
            extract_db_from_open_files(&mixed, Some("wanted-a")),
            Some(PathBuf::from(
                "/root/.gemini/antigravity-cli/conversations/wanted-a.db"
            ))
        );

        // Falls back to presence lock if only lock is open and no preferred id.
        let lock_only = vec![PathBuf::from(
            "/home/u/.gemini/antigravity-cli/presence/def-456.lock",
        )];
        assert_eq!(
            extract_db_from_open_files(&lock_only, None),
            Some(PathBuf::from(
                "/home/u/.gemini/antigravity-cli/conversations/def-456.db"
            ))
        );

        // Reported brain/ transcript path resolves sibling conversations/<id>.db.
        assert_eq!(
            conversation_db_from_brain_path(
                Path::new("/custom/app-data/brain/conv-42/.system_generated/logs/transcript.jsonl"),
                None,
            ),
            Some(PathBuf::from("/custom/app-data/conversations/conv-42.db"))
        );
        assert_eq!(
            conversation_db_from_brain_path(
                Path::new("/custom/app-data/brain/conv-42/transcript.jsonl"),
                Some("conv-99"),
            ),
            Some(PathBuf::from("/custom/app-data/conversations/conv-99.db"))
        );

        assert_eq!(
            conversation_id_from_argv(&[
                "agy".into(),
                "--dangerously-skip-permissions".into(),
                "--conversation=080fb2b3-f965-484b-8c38-a6d66bd35979".into(),
            ]),
            Some("080fb2b3-f965-484b-8c38-a6d66bd35979".into())
        );
        assert_eq!(
            conversation_id_from_argv(&["agy".into(), "-r".into(), "conv-99".into()]),
            Some("conv-99".into())
        );
        assert_eq!(
            conversation_id_from_argv(&["agy".into(), "--conversation".into(), "../escape".into()]),
            None
        );
    }

    #[test]
    fn plan_updates_emit_one_entry_per_turn_and_resend_on_after() {
        let make_plan_step = |idx: u32, id: &str, ts: u64, status: &str| DecodedStep {
            idx,
            status: STATUS_DONE,
            step_id: id.into(),
            created_ms: ts,
            completed_ms: Some(ts),
            payload: StepPayload::Tool {
                call_id: format!("c{idx}"),
                tool: "update_steps".into(),
                args_json: Some(serde_json::json!({
                    "steps": [
                        { "title": "Build", "status": status },
                        { "title": "Test", "status": "pending" }
                    ]
                })),
                kv_args: Vec::new(),
                ui_verb: None,
                error_message: None,
                ask_answer: None,
            },
        };
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Ship it".into(),
                },
            },
            make_plan_step(1, "p1", 1100, "in_progress"),
            DecodedStep {
                idx: 2,
                status: STATUS_DONE,
                step_id: "g2".into(),
                created_ms: 1150,
                completed_ms: Some(1150),
                payload: StepPayload::Tool {
                    call_id: "c2".into(),
                    tool: "run_command".into(),
                    args_json: None,
                    kv_args: Vec::new(),
                    ui_verb: Some("Ran build".into()),
                    error_message: None,
                    ask_answer: None,
                },
            },
            make_plan_step(3, "p3", 1200, "done"),
        ];

        // Full read: only ONE `{turn_id}:plan` entry, holding the newest items.
        let page = page_steps("sess-plan", &steps, &PageRequest::default(), 20).unwrap();
        let plans: Vec<_> = page
            .entries
            .iter()
            .filter_map(|e| match e {
                TranscriptEntry::Plan { id, items, .. } => Some((id.as_str(), items)),
                _ => None,
            })
            .collect();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].0, "u0:plan");
        assert_eq!(plans[0].1[0].status, TranscriptTaskStatus::Completed);

        // A page sliced after the plan owner (idx 1) covers idx 2..=3 without
        // repeating `u0:plan` for the second `update_steps` at idx 3.
        let sliced = page_steps(
            "sess-plan",
            &steps,
            &PageRequest {
                max_bytes: Some(1),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert_eq!(sliced.entries.len(), 1);
        assert!(matches!(
            &sliced.entries[0],
            TranscriptEntry::Step { id, .. } if id == "g2:c2"
        ));

        // Appending a 3rd update_steps re-sends `u0:plan` on an `after` poll.
        steps.push(DecodedStep {
            idx: 4,
            status: STATUS_DONE,
            step_id: "p4".into(),
            created_ms: 1300,
            completed_ms: Some(1300),
            payload: StepPayload::Tool {
                call_id: "c4".into(),
                tool: "update_steps".into(),
                args_json: Some(serde_json::json!({
                    "steps": [
                        { "title": "Build", "status": "done" },
                        { "title": "Test", "status": "done" }
                    ]
                })),
                kv_args: Vec::new(),
                ui_verb: None,
                error_message: None,
                ask_answer: None,
            },
        });
        let after = page_steps(
            "sess-plan",
            &steps,
            &PageRequest {
                after: Some(page.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert_eq!(after.resent, Some(vec!["u0:plan".to_owned()]));
        assert_eq!(after.entries.len(), 1);
        match &after.entries[0] {
            TranscriptEntry::Plan { id, items, .. } => {
                assert_eq!(id, "u0:plan");
                assert_eq!(items[1].status, TranscriptTaskStatus::Completed);
            }
            other => panic!("expected resent Plan, got {other:?}"),
        }
    }

    #[test]
    fn cursor_round_trips_delimiters_and_reply_flips_on_late_tool() {
        let weird_sess = "sess\nwith spaces";
        let weird_id = "step\nwith spaces";
        let cur = AgyCursor::After {
            seen_next_idx: 2,
            tip: Some((1, weird_id.into())),
            running: vec![1],
            running_emitted: vec!["p1:thinking".into()],
            origins: Some(7),
            floor: Some(0),
            tip_reply: Some((1, true, Some(1))),
        };
        let encoded = cur.encode(weird_sess);
        assert_eq!(AgyCursor::decode(&encoded, weird_sess).unwrap(), cur);

        // Planner with `has_tool_calls: true` must not emit premature TurnEnd
        // before its tool lands; once the tool arrives DONE, the after page
        // order must be [Reply(final: true), Step(Ok), TurnEnd] (TurnEnd AFTER Step).
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User { text: "Run".into() },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_DONE,
                step_id: "p1".into(),
                created_ms: 1100,
                completed_ms: Some(1100),
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: "Running now".into(),
                    has_tool_calls: true,
                },
            },
        ];
        let p1 = page_steps("s1", &steps, &PageRequest::default(), 20).unwrap();
        assert!(p1.entries.iter().any(|e| matches!(
            e,
            TranscriptEntry::Reply { id, is_final: false, .. } if id == "p1:reply"
        )));
        assert!(!p1
            .entries
            .iter()
            .any(|e| matches!(e, TranscriptEntry::TurnEnd { .. })));

        // Tool lands DONE -> reply settles (resent `final: true`), Step lands,
        // and TurnEnd is emitted ONCE strictly AFTER Step.
        steps.push(DecodedStep {
            idx: 2,
            status: STATUS_DONE,
            step_id: "g2".into(),
            created_ms: 1200,
            completed_ms: Some(1250),
            payload: StepPayload::Tool {
                call_id: "c2".into(),
                tool: "run_command".into(),
                args_json: None,
                kv_args: Vec::new(),
                ui_verb: Some("Ran check".into()),
                error_message: None,
                ask_answer: None,
            },
        });
        let p2 = page_steps(
            "s1",
            &steps,
            &PageRequest {
                after: Some(p1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert_eq!(p2.resent, Some(vec!["p1:reply".to_owned()]));
        let kinds: Vec<&str> = p2.entries.iter().map(|e| e.id()).collect();
        assert_eq!(kinds, ["p1:reply", "g2:c2", "p1:end"]);
        assert!(matches!(
            &p2.entries[0],
            TranscriptEntry::Reply { is_final: true, .. }
        ));
        assert!(matches!(
            &p2.entries[2],
            TranscriptEntry::TurnEnd {
                status: TranscriptTurnStatus::Done,
                ..
            }
        ));

        // Fresh read also puts TurnEnd strictly AFTER the trailing tool step.
        let fresh = page_steps("s1", &steps, &PageRequest::default(), 20).unwrap();
        let fresh_ids: Vec<&str> = fresh.entries.iter().map(|e| e.id()).collect();
        assert_eq!(fresh_ids, ["u0", "p1:reply", "g2:c2", "p1:end"]);

        // Fixture shape: reply with NO field 7 (`has_tool_calls: false`) read
        // BEFORE a later tool is inserted closes the turn with TurnEnd; if a
        // late tool is then inserted (RUNNING or DONE), the after poll expires
        // the cursor so the client reloads without a stale TurnEnd in front of
        // the tool. A normal new user turn does NOT expire the cursor.
        let base_steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User { text: "Go".into() },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_DONE,
                step_id: "p1".into(),
                created_ms: 1100,
                completed_ms: Some(1100),
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: "Summary".into(),
                    has_tool_calls: false,
                },
            },
        ];
        let closed = page_steps("s2", &base_steps, &PageRequest::default(), 20).unwrap();
        let closed_ids: Vec<&str> = closed.entries.iter().map(|e| e.id()).collect();
        assert_eq!(closed_ids, ["u0", "p1:reply", "p1:end"]);

        // Normal next turn (new User step) continues cleanly without expiring.
        let mut next_turn = base_steps.clone();
        next_turn.push(DecodedStep {
            idx: 2,
            status: STATUS_DONE,
            step_id: "u2".into(),
            created_ms: 2000,
            completed_ms: Some(2000),
            payload: StepPayload::User {
                text: "Next".into(),
            },
        });
        let cont = page_steps(
            "s2",
            &next_turn,
            &PageRequest {
                after: Some(closed.after.clone()),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert_eq!(cont.entries.len(), 1);
        assert_eq!(cont.entries[0].id(), "u2");

        // Late RUNNING or DONE tool in the same turn expires the closed cursor,
        // and the fresh reload places TurnEnd only when settled and after Step.
        for tool_status in [STATUS_RUNNING, STATUS_DONE] {
            let mut late = base_steps.clone();
            late.push(DecodedStep {
                idx: 2,
                status: tool_status,
                step_id: "g2".into(),
                created_ms: 1200,
                completed_ms: (tool_status == STATUS_DONE).then_some(1250),
                payload: StepPayload::Tool {
                    call_id: "c2".into(),
                    tool: "run_command".into(),
                    args_json: None,
                    kv_args: Vec::new(),
                    ui_verb: Some("Late tool".into()),
                    error_message: None,
                    ask_answer: None,
                },
            });
            let err = page_steps(
                "s2",
                &late,
                &PageRequest {
                    after: Some(closed.after.clone()),
                    ..Default::default()
                },
                20,
            )
            .unwrap_err();
            assert_eq!(err.code(), "cursor_expired");

            let reloaded = page_steps("s2", &late, &PageRequest::default(), 20).unwrap();
            let ids: Vec<&str> = reloaded.entries.iter().map(|e| e.id()).collect();
            if tool_status == STATUS_RUNNING {
                assert_eq!(ids, ["u0", "p1:reply", "g2:c2"]);
                assert!(matches!(
                    &reloaded.entries[1],
                    TranscriptEntry::Reply {
                        is_final: false,
                        ..
                    }
                ));
            } else {
                assert_eq!(ids, ["u0", "p1:reply", "g2:c2", "p1:end"]);
                assert!(matches!(
                    &reloaded.entries[1],
                    TranscriptEntry::Reply { is_final: true, .. }
                ));
            }
        }
    }

    #[test]
    fn inplace_settlement_with_next_user_turn_places_turn_end_before_next_user() {
        // Turn 1 starts with a reply + RUNNING tool; on the next `after` poll,
        // the tool settles RUNNING -> DONE in place AND Turn 2 (User + Reply)
        // lands in the same poll. Turn 1's TurnEnd must appear BEFORE Turn 2's
        // User entry (and not in `resent`).
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Turn 1".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_DONE,
                step_id: "p1".into(),
                created_ms: 1100,
                completed_ms: Some(1100),
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: "Running command".into(),
                    has_tool_calls: true,
                },
            },
            DecodedStep {
                idx: 2,
                status: STATUS_RUNNING,
                step_id: "g2".into(),
                created_ms: 1200,
                completed_ms: None,
                payload: StepPayload::Tool {
                    call_id: "c2".into(),
                    tool: "run_command".into(),
                    args_json: None,
                    kv_args: Vec::new(),
                    ui_verb: Some("Check".into()),
                    error_message: None,
                    ask_answer: None,
                },
            },
        ];
        let p1 = page_steps("s-order", &steps, &PageRequest::default(), 20).unwrap();
        assert_eq!(
            p1.entries.iter().map(|e| e.id()).collect::<Vec<_>>(),
            ["u0", "p1:reply", "g2:c2"]
        );

        // Settle g2 in place AND append Turn 2 (u3 + p4) in the same poll.
        steps[2].status = STATUS_DONE;
        steps[2].completed_ms = Some(1300);
        steps.push(DecodedStep {
            idx: 3,
            status: STATUS_DONE,
            step_id: "u3".into(),
            created_ms: 2000,
            completed_ms: Some(2000),
            payload: StepPayload::User {
                text: "Turn 2".into(),
            },
        });
        steps.push(DecodedStep {
            idx: 4,
            status: STATUS_DONE,
            step_id: "p4".into(),
            created_ms: 2100,
            completed_ms: Some(2100),
            payload: StepPayload::Planner {
                thinking: String::new(),
                reply: "Done with turn 2".into(),
                has_tool_calls: false,
            },
        });

        let p2 = page_steps(
            "s-order",
            &steps,
            &PageRequest {
                after: Some(p1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert_eq!(
            p2.resent,
            Some(vec!["g2:c2".to_owned(), "p1:reply".to_owned()])
        );
        assert_eq!(
            p2.entries.iter().map(|e| e.id()).collect::<Vec<_>>(),
            ["g2:c2", "p1:reply", "p1:end", "u3", "p4:reply", "p4:end"]
        );
    }

    fn pb_len_delim(field_num: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut tag = ((field_num as u64) << 3) | 2;
        loop {
            let mut b = (tag & 0x7f) as u8;
            tag >>= 7;
            if tag != 0 {
                b |= 0x80;
            }
            out.push(b);
            if tag == 0 {
                break;
            }
        }
        let mut len = payload.len() as u64;
        loop {
            let mut b = (len & 0x7f) as u8;
            len >>= 7;
            if len != 0 {
                b |= 0x80;
            }
            out.push(b);
            if len == 0 {
                break;
            }
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn gen_metadata_model_prefers_newest_row_handles_utf8_and_omits_unlinked_log() {
        let dir = std::env::temp_dir().join(format!(
            "herdr-agy-model-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let conv_dir = dir.join("conversations");
        std::fs::create_dir_all(&conv_dir).unwrap();
        let missing_db = conv_dir.join("new-conv.db");
        std::fs::write(
            dir.join("cli.log"),
            "I1127 12:34:02 model_config_manager.go:375] Propagating selected model override to backend: label=\"Gemini 4 Neon (High)\"\n",
        )
        .unwrap();

        // Empty conversation does NOT attribute unrelated app-wide cli.log overrides.
        let empty = read_page(&missing_db, &PageRequest::default()).unwrap();
        assert_eq!(empty.model, None);

        // Conversation with older field 1.19 + newer field 3.28 prefers the newer row (recency).
        let slug_db = conv_dir.join("slug-conv.db");
        let conn = Connection::open(&slug_db).unwrap();
        conn.execute_batch(
            "CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_type INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 0, metadata BLOB, error_details BLOB, step_payload BLOB, step_format INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB);",
        )
        .unwrap();
        let f1_old = pb_len_delim(19, b"gemini-old");
        conn.execute(
            "INSERT INTO gen_metadata (idx, data) VALUES (0, ?1)",
            [&pb_len_delim(1, &f1_old)],
        )
        .unwrap();
        let f3_new = pb_len_delim(28, b"gemini-4-neon-medium");
        conn.execute(
            "INSERT INTO gen_metadata (idx, data) VALUES (1, ?1)",
            [&pb_len_delim(3, &f3_new)],
        )
        .unwrap();
        drop(conn);
        let slug_page = read_page(&slug_db, &PageRequest::default()).unwrap();
        assert_eq!(
            slug_page.model,
            Some(TranscriptModel {
                provider: "antigravity".into(),
                id: "gemini-4-neon".into(),
                harness: Some("agy".into()),
                thinking_level: Some("medium".into()),
                thinking_auto: false,
            })
        );

        // Non-ASCII UTF-8 slug never panics during suffix parsing.
        assert_eq!(
            parse_agy_model_slug("é1234567"),
            Some(("é1234567".into(), None))
        );
        assert_eq!(
            parse_agy_model_slug("café-model-HIGH"),
            Some(("café-model".into(), Some("high".into())))
        );

        // Newer gen_metadata row with field 1.21 display label wins within that row.
        let conn = Connection::open(&slug_db).unwrap();
        let mut f1 = pb_len_delim(19, b"gemini-4-neon");
        f1.extend(pb_len_delim(21, b"Gemini 4 Neon (Low)"));
        conn.execute(
            "INSERT INTO gen_metadata (idx, data) VALUES (2, ?1)",
            [&pb_len_delim(1, &f1)],
        )
        .unwrap();
        drop(conn);
        let label_page = read_page(&slug_db, &PageRequest::default()).unwrap();
        assert_eq!(
            label_page.model,
            Some(TranscriptModel {
                provider: "antigravity".into(),
                id: "Gemini 4 Neon".into(),
                harness: Some("agy".into()),
                thinking_level: Some("low".into()),
                thinking_auto: false,
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn current_working_tracks_background_running_command_after_reply_and_across_turns() {
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Run tests".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_RUNNING,
                step_id: "g1".into(),
                created_ms: 1100,
                completed_ms: None,
                payload: StepPayload::Tool {
                    call_id: "c1".into(),
                    tool: "run_command".into(),
                    args_json: Some(serde_json::json!({"CommandLine": "cargo test --secret-flag"})),
                    kv_args: Vec::new(),
                    ui_verb: None,
                    error_message: None,
                    ask_answer: None,
                },
            },
            DecodedStep {
                idx: 2,
                status: STATUS_DONE,
                step_id: "p2".into(),
                created_ms: 1200,
                completed_ms: Some(1200),
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: "Started tests in background.".into(),
                    has_tool_calls: false,
                },
            },
        ];

        // Even after a non-tool planner reply, the backgrounded run_command is still working,
        // and raw CommandLine args stay out of shared intent (kept in owner-only detail).
        let working = current_working(&steps).expect("background run_command still working");
        assert_eq!(working.tool, "run_command");
        assert_eq!(working.intent, "Run command");

        // A later turn with only a waiting `schedule` timer still surfaces the earlier running command.
        steps.push(DecodedStep {
            idx: 3,
            status: STATUS_DONE,
            step_id: "u3".into(),
            created_ms: 2000,
            completed_ms: Some(2000),
            payload: StepPayload::User {
                text: "Any updates?".into(),
            },
        });
        steps.push(DecodedStep {
            idx: 4,
            status: STATUS_RUNNING,
            step_id: "g4".into(),
            created_ms: 2100,
            completed_ms: None,
            payload: StepPayload::Tool {
                call_id: "c4".into(),
                tool: "schedule".into(),
                args_json: Some(serde_json::json!({"DurationSeconds": 60})),
                kv_args: Vec::new(),
                ui_verb: None,
                error_message: None,
                ask_answer: None,
            },
        });
        let still = current_working(&steps).expect("earlier background command still working");
        assert_eq!(still.tool, "run_command");
        assert_eq!(still.intent, "Run command");

        // Once the command settles, the waiting schedule timer alone is not reported as working.
        steps[1].status = STATUS_DONE;
        assert!(current_working(&steps).is_none());
    }

    #[test]
    fn pending_tool_step_keeps_turn_open_until_settled_and_keeps_raw_command_in_detail_only() {
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Check".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_DONE,
                step_id: "p1".into(),
                created_ms: 1050,
                completed_ms: Some(1050),
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: "Checking status.".into(),
                    has_tool_calls: true,
                },
            },
            DecodedStep {
                idx: 2,
                status: STATUS_PENDING,
                step_id: "g2".into(),
                created_ms: 1100,
                completed_ms: None,
                payload: StepPayload::Tool {
                    call_id: "c2".into(),
                    tool: "run_command".into(),
                    args_json: Some(
                        serde_json::json!({"CommandLine": "git status --private-token"}),
                    ),
                    kv_args: Vec::new(),
                    ui_verb: None,
                    error_message: None,
                    ask_answer: None,
                },
            },
        ];
        let p1 = page_steps("s-pending", &steps, &PageRequest::default(), 20).unwrap();
        let working = p1.working.expect("pending tool reports working");
        assert_eq!(working.intent, "Run command");
        assert!(!working.intent.contains("--private-token"));
        assert!(
            p1.entries
                .iter()
                .all(|e| !matches!(e, TranscriptEntry::TurnEnd { .. })),
            "pending tool must keep turn open"
        );
        assert!(matches!(
            p1.entries.iter().find(|e| e.id() == "p1:reply"),
            Some(TranscriptEntry::Reply {
                is_final: false,
                ..
            })
        ));
        assert!(matches!(
            p1.entries.last(),
            Some(TranscriptEntry::Step {
                status: TranscriptStepStatus::Running,
                intent,
                detail: Some(detail),
                ..
            }) if intent == "Run command" && detail.contains("--private-token")
        ));

        // Transitioning pending -> running must NOT expire the after cursor.
        steps[2].status = STATUS_RUNNING;
        let p2 = page_steps(
            "s-pending",
            &steps,
            &PageRequest {
                after: Some(p1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert!(p2.working.is_some());
    }

    #[test]
    fn earlier_turn_pending_command_settling_after_next_turn_expires_cursor() {
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Turn A".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_DONE,
                step_id: "p1".into(),
                created_ms: 1050,
                completed_ms: Some(1050),
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: "Running command in turn A.".into(),
                    has_tool_calls: true,
                },
            },
            DecodedStep {
                idx: 2,
                status: STATUS_PENDING,
                step_id: "g2".into(),
                created_ms: 1100,
                completed_ms: None,
                payload: StepPayload::Tool {
                    call_id: "c2".into(),
                    tool: "run_command".into(),
                    args_json: Some(serde_json::json!({"CommandLine": "sleep 1"})),
                    kv_args: Vec::new(),
                    ui_verb: None,
                    error_message: None,
                    ask_answer: None,
                },
            },
        ];
        // Poll 1: turn A has reply (not final) + pending command.
        let p1 = page_steps("s-multi", &steps, &PageRequest::default(), 20).unwrap();
        assert!(matches!(
            p1.entries.iter().find(|e| e.id() == "p1:reply"),
            Some(TranscriptEntry::Reply {
                is_final: false,
                ..
            })
        ));

        // Turn B starts while turn A's command is still pending.
        steps.push(DecodedStep {
            idx: 3,
            status: STATUS_DONE,
            step_id: "u3".into(),
            created_ms: 2000,
            completed_ms: Some(2000),
            payload: StepPayload::User {
                text: "Turn B".into(),
            },
        });
        steps.push(DecodedStep {
            idx: 4,
            status: STATUS_DONE,
            step_id: "p4".into(),
            created_ms: 2050,
            completed_ms: Some(2050),
            payload: StepPayload::Planner {
                thinking: String::new(),
                reply: "Done with turn B.".into(),
                has_tool_calls: false,
            },
        });
        // Poll 2: cursor advances past turn B while turn A's command is still tracked as running.
        let p2 = page_steps(
            "s-multi",
            &steps,
            &PageRequest {
                after: Some(p1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();

        // Turn A's command now finishes -> reply p1:reply becomes final and needs p1:end
        // BEFORE turn B, so incremental replay must expire the cursor rather than leave
        // p1:reply permanently non-final.
        steps[2].status = STATUS_DONE;
        steps[2].completed_ms = Some(2100);
        let err = page_steps(
            "s-multi",
            &steps,
            &PageRequest {
                after: Some(p2.after),
                ..Default::default()
            },
            20,
        )
        .unwrap_err();
        assert!(matches!(err, TranscriptError::CursorExpired));

        // Fresh read after CursorExpired includes p1:reply (final=true) and p1:end in order.
        let fresh = page_steps("s-multi", &steps, &PageRequest::default(), 20).unwrap();
        assert!(matches!(
            fresh.entries.iter().find(|e| e.id() == "p1:reply"),
            Some(TranscriptEntry::Reply { is_final: true, .. })
        ));
        let p1_end_idx = fresh
            .entries
            .iter()
            .position(|e| e.id() == "p1:end")
            .expect("p1:end present on fresh reload");
        let u3_idx = fresh
            .entries
            .iter()
            .position(|e| matches!(e, TranscriptEntry::User { text, .. } if text == "Turn B"))
            .expect("Turn B present");
        assert!(p1_end_idx < u3_idx, "p1:end must precede Turn B");
    }

    #[test]
    fn earlier_turn_pre_reply_background_command_resends_without_expiring_cursor() {
        // Turn A starts a background command BEFORE its already-final planner reply.
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Start background build".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_RUNNING,
                step_id: "g1".into(),
                created_ms: 1050,
                completed_ms: None,
                payload: StepPayload::Tool {
                    call_id: "c1".into(),
                    tool: "run_command".into(),
                    args_json: Some(serde_json::json!({"CommandLine": "cargo build"})),
                    kv_args: Vec::new(),
                    ui_verb: None,
                    error_message: None,
                    ask_answer: None,
                },
            },
            DecodedStep {
                idx: 2,
                status: STATUS_DONE,
                step_id: "p2".into(),
                created_ms: 1100,
                completed_ms: Some(1100),
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: "Build running in background.".into(),
                    has_tool_calls: false,
                },
            },
        ];

        // Poll 1: Turn A already closed with p2:end even though g1 is still running.
        let p1 = page_steps("s-prereply", &steps, &PageRequest::default(), 20).unwrap();
        assert_eq!(
            p1.entries.iter().map(|e| e.id()).collect::<Vec<_>>(),
            ["u0", "g1:c1", "p2:reply", "p2:end"]
        );

        // Turn B lands while g1 is still running.
        steps.push(DecodedStep {
            idx: 3,
            status: STATUS_DONE,
            step_id: "u3".into(),
            created_ms: 2000,
            completed_ms: Some(2000),
            payload: StepPayload::User {
                text: "Next question".into(),
            },
        });
        steps.push(DecodedStep {
            idx: 4,
            status: STATUS_DONE,
            step_id: "p4".into(),
            created_ms: 2050,
            completed_ms: Some(2050),
            payload: StepPayload::Planner {
                thinking: String::new(),
                reply: "Answered.".into(),
                has_tool_calls: false,
            },
        });
        let p2 = page_steps(
            "s-prereply",
            &steps,
            &PageRequest {
                after: Some(p1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();

        // Turn A's pre-reply background command finishes while Turn C appends:
        // cursor must NOT expire; g1:c1 resends as Ok and Turn C appends cleanly.
        steps[1].status = STATUS_DONE;
        steps[1].completed_ms = Some(2500);
        steps.push(DecodedStep {
            idx: 5,
            status: STATUS_DONE,
            step_id: "u5".into(),
            created_ms: 3000,
            completed_ms: Some(3000),
            payload: StepPayload::User {
                text: "Turn C".into(),
            },
        });
        let p3 = page_steps(
            "s-prereply",
            &steps,
            &PageRequest {
                after: Some(p2.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert_eq!(p3.resent, Some(vec!["g1:c1".to_owned()]));
        assert_eq!(
            p3.entries.iter().map(|e| e.id()).collect::<Vec<_>>(),
            ["g1:c1", "u5"]
        );
        assert!(matches!(
            &p3.entries[0],
            TranscriptEntry::Step {
                status: TranscriptStepStatus::Ok,
                ..
            }
        ));
    }

    #[test]
    fn generating_planner_delivers_reply_not_in_resent_and_reports_thinking_working() {
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Explain the bug".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_GENERATING,
                step_id: "p1".into(),
                created_ms: 1100,
                completed_ms: None,
                payload: StepPayload::Planner {
                    thinking: "Inspecting live transcript...".into(),
                    reply: String::new(),
                    has_tool_calls: false,
                },
            },
        ];

        // Poll 1 while planner is still STATUS_GENERATING (8): only `:thinking`
        // exists yet, no `:reply` or `:end`, and `working` reports "Thinking".
        let p1 = page_steps("s-gen", &steps, &PageRequest::default(), 20).unwrap();
        assert_eq!(
            p1.entries.iter().map(|e| e.id()).collect::<Vec<_>>(),
            ["u0", "p1:thinking"]
        );
        let working = p1
            .working
            .expect("generating planner should report working");
        assert_eq!(working.intent, "Thinking");

        // Poll 2 after planner finishes (STATUS_DONE = 3) with full reply text:
        // `:thinking` was emitted on poll 1 so it is in `resent`, while brand-new
        // `:reply` MUST NOT be in `resent` (clients drop unheld resent entries),
        // and `:end` closes the turn.
        steps[1].status = STATUS_DONE;
        steps[1].completed_ms = Some(1500);
        steps[1].payload = StepPayload::Planner {
            thinking: "Inspecting live transcript...".into(),
            reply: "Full answer rendered cleanly.".into(),
            has_tool_calls: false,
        };
        let p2 = page_steps(
            "s-gen",
            &steps,
            &PageRequest {
                after: Some(p1.after.clone()),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert!(p2.working.is_none());
        assert_eq!(p2.resent, Some(vec!["p1:thinking".to_owned()]));
        assert_eq!(
            p2.entries.iter().map(|e| e.id()).collect::<Vec<_>>(),
            ["p1:thinking", "p1:reply", "p1:end"]
        );
        assert!(matches!(
            &p2.entries[1],
            TranscriptEntry::Reply {
                text,
                is_final: true,
                ..
            } if text == "Full answer rendered cleanly."
        ));

        // Out-of-order case: if a later step (`g2`) was already delivered on
        // poll 1 while `p1` was still generating without a `:reply`, finishing
        // `p1` with a brand-new `:reply` before `g2` must expire the cursor so
        // the client reloads in proper order rather than appending `:reply`
        // after `g2`.
        let mut ooo_steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Check".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_GENERATING,
                step_id: "p1".into(),
                created_ms: 1100,
                completed_ms: None,
                payload: StepPayload::Planner {
                    thinking: "Planning...".into(),
                    reply: String::new(),
                    has_tool_calls: true,
                },
            },
            DecodedStep {
                idx: 2,
                status: STATUS_RUNNING,
                step_id: "g2".into(),
                created_ms: 1150,
                completed_ms: None,
                payload: StepPayload::Tool {
                    call_id: "c2".into(),
                    tool: "run_command".into(),
                    args_json: None,
                    kv_args: Vec::new(),
                    ui_verb: Some("Check".into()),
                    error_message: None,
                    ask_answer: None,
                },
            },
        ];
        let ooo1 = page_steps("s-gen-ooo", &ooo_steps, &PageRequest::default(), 20).unwrap();
        ooo_steps[1].status = STATUS_DONE;
        ooo_steps[1].payload = StepPayload::Planner {
            thinking: "Planning...".into(),
            reply: "Late reply text".into(),
            has_tool_calls: true,
        };
        let err = page_steps(
            "s-gen-ooo",
            &ooo_steps,
            &PageRequest {
                after: Some(ooo1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap_err();
        assert_eq!(err.code(), "cursor_expired");
    }

    #[test]
    fn ask_question_renders_ask_entry_and_pending_ask_with_multi_select() {
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Ask me".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_RUNNING,
                step_id: "g1".into(),
                created_ms: 1100,
                completed_ms: None,
                payload: StepPayload::Tool {
                    call_id: "c1".into(),
                    tool: "ask_question".into(),
                    args_json: Some(serde_json::json!({
                        "questions": [
                            {
                                "question": "Which targets should ship?",
                                "is_multi_select": true,
                                "options": ["Desktop", "iOS", "Web"]
                            }
                        ]
                    })),
                    kv_args: Vec::new(),
                    ui_verb: None,
                    error_message: None,
                    ask_answer: None,
                },
            },
        ];

        // Running ask_question renders as TranscriptEntry::Ask + Page.pending_ask
        // (read-only) and suppresses the "Thinking" working spinner.
        let p1 = page_steps("s-ask", &steps, &PageRequest::default(), 20).unwrap();
        assert!(p1.working.is_none());
        let pending = p1
            .pending_ask
            .expect("running ask_question sets pending_ask");
        assert_eq!(pending.id, "g1:c1");
        assert!(!pending.answerable);
        assert!(!pending.form_answerable);
        assert!(!pending.dismissable);
        assert_eq!(pending.questions.len(), 1);
        assert_eq!(pending.questions[0].question, "Which targets should ship?");
        assert!(pending.questions[0].multi);
        assert_eq!(pending.questions[0].options, ["Desktop", "iOS", "Web"]);
        assert!(matches!(
            p1.entries.last(),
            Some(TranscriptEntry::Ask { id, questions, .. })
                if id == "g1:c1" && questions.len() == 1 && questions[0].multi
        ));

        // Once answered/completed (STATUS_DONE), pending_ask clears and the Ask
        // entry is resent on the incremental poll with the extracted answer.
        steps[1].status = STATUS_DONE;
        steps[1].completed_ms = Some(1400);
        if let StepPayload::Tool { ask_answer, .. } = &mut steps[1].payload {
            *ask_answer = parse_agy_ask_answers(
                "Created At: 2026-11-27T08:38:59+01:00\nCompleted At: 2026-11-27T08:39:46+01:00\nA1: Desktop, iOS\nA2: Line one\nLine two",
            );
        }
        let p2 = page_steps(
            "s-ask",
            &steps,
            &PageRequest {
                after: Some(p1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert!(p2.pending_ask.is_none());
        assert_eq!(p2.resent, Some(vec!["g1:c1".to_owned()]));
        assert!(matches!(
            p2.entries.first(),
            Some(TranscriptEntry::Ask { id, answer: Some(ans), form_status: None, .. })
                if id == "g1:c1" && ans == &["Desktop, iOS", "Line one\nLine two"]
        ));

        // Decode real protobuf shape for ask_question (f5 metadata + f140 kv_args + f140.f2.f1 answer).
        let mut tc = pb_len_delim(1, b"call_ask_pb");
        tc.extend(pb_len_delim(2, b"ask_question"));
        let mut meta = pb_len_delim(4, &tc);
        meta.extend(pb_len_delim(35, b"step-ask-pb"));
        let mut kv = pb_len_delim(1, b"questions");
        kv.extend(pb_len_delim(
            2,
            br#"[{"question":"Ship now?","is_multi_select":false,"options":["Yes","No"]}]"#,
        ));
        let res = pb_len_delim(
            1,
            b"Created At: 2026-11-27T08:38:59+01:00\nCompleted At: 2026-11-27T08:39:46+01:00\nA1: Yes",
        );
        let mut f140 = pb_len_delim(1, &kv);
        f140.extend(pb_len_delim(2, &res));
        let mut payload = pb_len_delim(5, &meta);
        payload.extend(pb_len_delim(140, &f140));
        let decoded = decode_step_row(
            10,
            STEP_TYPE_GENERIC,
            STATUS_DONE,
            None,
            None,
            Some(&payload),
        );
        let pb_page = page_steps("s-ask-pb", &[decoded], &PageRequest::default(), 20).unwrap();
        assert!(matches!(
            pb_page.entries.first(),
            Some(TranscriptEntry::Ask { id, questions, answer: Some(ans), .. })
                if id == "step-ask-pb:call_ask_pb"
                    && questions.len() == 1
                    && questions[0].question == "Ship now?"
                    && ans == &["Yes"]
        ));
    }

    #[test]
    fn intermediate_generating_poll_with_partial_reply_does_not_mark_reply_resent_on_done() {
        // Regression for #538:
        // Poll 1: planner is STATUS_GENERATING with no reply yet -> running_emitted has no :reply.
        // Poll 2: planner is STILL STATUS_GENERATING with partial reply -> skipped by after-poll
        //   (not sent in entries), so running_emitted MUST NOT add :reply.
        // Poll 3: planner finishes (STATUS_DONE) with final reply -> :reply must be emitted and
        //   NOT marked in resent so incremental clients append it instead of dropping it.
        let mut steps = vec![
            DecodedStep {
                idx: 0,
                status: STATUS_DONE,
                step_id: "u0".into(),
                created_ms: 1000,
                completed_ms: Some(1000),
                payload: StepPayload::User {
                    text: "Status?".into(),
                },
            },
            DecodedStep {
                idx: 1,
                status: STATUS_GENERATING,
                step_id: "agy-1".into(),
                created_ms: 1100,
                completed_ms: None,
                payload: StepPayload::Planner {
                    thinking: String::new(),
                    reply: String::new(),
                    has_tool_calls: false,
                },
            },
        ];

        let p1 = page_steps("s-stream-lost", &steps, &PageRequest::default(), 20).unwrap();
        assert!(p1
            .entries
            .iter()
            .all(|e| !matches!(e, TranscriptEntry::Reply { .. })));

        steps[1].payload = StepPayload::Planner {
            thinking: String::new(),
            reply: "Partial streamed text".into(),
            has_tool_calls: false,
        };
        let p2 = page_steps(
            "s-stream-lost",
            &steps,
            &PageRequest {
                after: Some(p1.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert!(
            p2.entries.is_empty(),
            "still-generating step is skipped on after-poll"
        );

        steps[1].status = STATUS_DONE;
        steps[1].completed_ms = Some(1500);
        steps[1].payload = StepPayload::Planner {
            thinking: String::new(),
            reply: "Final complete answer".into(),
            has_tool_calls: false,
        };
        let p3 = page_steps(
            "s-stream-lost",
            &steps,
            &PageRequest {
                after: Some(p2.after),
                ..Default::default()
            },
            20,
        )
        .unwrap();
        assert!(p3.entries.iter().any(|e| matches!(
            e,
            TranscriptEntry::Reply { id, text, is_final: true, .. }
                if id == "agy-1:reply" && text == "Final complete answer"
        )));
        let resent = p3.resent.unwrap_or_default();
        assert!(
            !resent.iter().any(|id| id == "agy-1:reply"),
            "brand-new reply that was never sent in entries must not appear in resent: {resent:?}"
        );
    }

    #[test]
    fn parse_agy_ask_answers_preserves_leading_newline_blank_lines_and_indentation() {
        // Regression for #539:
        // 1) A1 followed by answer text starting on the next line before A2.
        let leading_nl =
            "Created At: 2026-11-27T08:38:59+01:00\nA1:\nFirst line\n    indented\nA2: Web\n";
        assert_eq!(
            parse_agy_ask_answers(leading_nl),
            Some(vec![
                "First line\n    indented".to_owned(),
                "Web".to_owned()
            ])
        );

        // 2) Multiline answer with internal blank line and 4-space indentation.
        let multiline = "A1: Para one\n\n    code block line\n";
        assert_eq!(
            parse_agy_ask_answers(multiline),
            Some(vec!["Para one\n\n    code block line".to_owned()])
        );

        // 3) Blank A1 with no content before A2 is still ignored.
        let empty_first = "A1:\n\nA2: Only second\n";
        assert_eq!(
            parse_agy_ask_answers(empty_first),
            Some(vec!["Only second".to_owned()])
        );
    }

    #[test]
    fn resolve_conversation_id_extracts_valid_id_from_db_and_brain_path() {
        let dir = std::env::temp_dir().join(format!("herdr-agy-session-id-{}", std::process::id()));
        let conv_dir = dir.join("conversations");
        let brain_dir = dir
            .join("brain")
            .join("080fb2b3-f965-484b-8c38-a6d66bd35979");
        std::fs::create_dir_all(&conv_dir).unwrap();
        std::fs::create_dir_all(&brain_dir).unwrap();
        let db = conv_dir.join("080fb2b3-f965-484b-8c38-a6d66bd35979.db");
        std::fs::write(&db, b"").unwrap();

        assert_eq!(
            conversation_id_from_db_path(&db).as_deref(),
            Some("080fb2b3-f965-484b-8c38-a6d66bd35979")
        );
        assert_eq!(
            resolve_conversation_id(None, None, Some(&brain_dir)).as_deref(),
            Some("080fb2b3-f965-484b-8c38-a6d66bd35979")
        );
        assert_eq!(conversation_id_from_db_path(Path::new("/tmp/.db")), None);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
