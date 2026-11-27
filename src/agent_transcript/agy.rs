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
    TranscriptEntry, TranscriptNoteSource, TranscriptPlanItem, TranscriptStepStatus,
    TranscriptTaskStatus, TranscriptTurnStatus, TranscriptWorking,
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

const STATUS_RUNNING: i64 = 2;
const STATUS_DONE: i64 = 3;
const STATUS_CANCELED: i64 = 6;
const STATUS_ERROR: i64 = 7;

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
        self.status == STATUS_RUNNING
            && matches!(
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

    let (session_id, steps) = load_conversation(path)?;
    page_steps(&session_id, &steps, request, limit)
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

fn load_conversation(path: &Path) -> Result<(String, Vec<DecodedStep>), TranscriptError> {
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
    Ok((session_id, steps))
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

        // Re-send any previously-running tool or planner step before `start`
        // that has now finished (excluding update_steps, handled below per turn).
        let mut resent_planners = HashSet::new();
        let mut resent_plan_turns = HashSet::new();
        for run_idx in prev_running {
            let Some(pos) = pos_of_idx(run_idx) else {
                continue;
            };
            if pos >= start || steps[pos].is_running() {
                continue;
            }
            if steps[pos].plan_items().is_some() {
                let (turn_start, turn_end) = turn_bounds(steps, pos);
                if resent_plan_turns.insert(turn_start) {
                    if let Some(plan_entry) = build_turn_plan(steps, turn_start, turn_end) {
                        resent_ids.push(plan_entry.id().to_owned());
                        entries.push(plan_entry);
                    }
                }
                continue;
            }
            if matches!(steps[pos].payload, StepPayload::Planner { .. }) {
                resent_planners.insert(pos);
            }
            let before_len = entries.len();
            render_step(steps, pos, false, &mut entries);
            for entry in &entries[before_len..] {
                resent_ids.push(entry.id().to_owned());
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

    // If a previously unsettled turn-tip reply (`pos < start`) has now settled
    // and its `TurnEnd` was not already emitted while rendering `start..end`
    // (e.g. its closing tool was `< start` and transitioned RUNNING -> DONE in
    // place), append `TurnEnd` now, strictly after all steps.
    if let Some(reply_pos) = pending_turn_end {
        let end_id = format!("{}:end", steps[reply_pos].step_id);
        let close_in_new = turn_close_pos_for_reply(steps, reply_pos)
            .is_some_and(|close_pos| close_pos >= start && close_pos < end);
        let already_emitted = entries.iter().any(|e| e.id() == end_id);
        let close_visible =
            turn_close_pos_for_reply(steps, reply_pos).is_some_and(|close_pos| close_pos < end);
        if close_visible && !close_in_new && !already_emitted {
            entries.push(TranscriptEntry::TurnEnd {
                id: end_id,
                ts_ms: turn_completed_ms(steps, reply_pos),
                status: turn_end_status(steps, reply_pos),
                error: None,
            });
        }
    }

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
    let running: Vec<u32> = steps[..seen_end_pos]
        .iter()
        .filter(|s| s.is_running())
        .map(|s| s.idx)
        .collect();
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
        pending_ask: None,
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
    if reply.trim().is_empty() || step.status == STATUS_RUNNING {
        return false;
    }
    let (_, turn_end) = turn_bounds(steps, pos);
    let tail = &steps[(pos + 1)..turn_end];
    if tail
        .iter()
        .any(|s| matches!(s.payload, StepPayload::Planner { .. }) || s.status == STATUS_RUNNING)
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

/// If `pos` is the closing step of a settled turn, return the `reply_pos` that
/// owns that turn's `{step_id}:end` entry.
fn settled_turn_reply_for_close_pos(steps: &[DecodedStep], pos: usize) -> Option<usize> {
    let (turn_start, turn_end) = turn_bounds(steps, pos);
    let reply_pos = (turn_start..turn_end).rev().find(|&p| {
        matches!(
            &steps[p].payload,
            StepPayload::Planner { reply, .. } if !reply.trim().is_empty()
        )
    })?;
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
    let reply_pos = (last_turn_start..seen_end_pos).rev().find(|&p| {
        matches!(
            &steps[p].payload,
            StepPayload::Planner { reply, .. } if !reply.trim().is_empty()
        )
    })?;
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
            let status = match step.status {
                STATUS_RUNNING => TranscriptStepStatus::Running,
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

fn current_working(steps: &[DecodedStep]) -> Option<TranscriptWorking> {
    let last_user = steps.iter().rposition(DecodedStep::is_user).unwrap_or(0);
    for step in steps[last_user..].iter().rev() {
        match &step.payload {
            StepPayload::Tool {
                tool,
                args_json,
                kv_args,
                ui_verb,
                ..
            } if step.status == STATUS_RUNNING => {
                return Some(TranscriptWorking {
                    intent: agy_step_intent(tool, args_json.as_ref(), kv_args, ui_verb.as_deref()),
                    tool: tool.clone(),
                    since_ms: step.created_ms,
                });
            }
            StepPayload::Planner {
                reply,
                has_tool_calls: false,
                ..
            } if !reply.trim().is_empty() => return None,
            _ => {}
        }
    }
    None
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
}
