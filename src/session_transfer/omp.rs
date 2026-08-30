use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead as _, BufReader, BufWriter, Cursor, Write as _};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{
    fingerprint_bytes, push_visible_message, CanonicalTranscript, OmissionSummary, TransferError,
    VisibleMessage, VisibleRole, MAX_TRANSCRIPT_LINE_BYTES,
};

const TITLE_SLOT_BYTES: usize = 256;
const CURRENT_SESSION_VERSION: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) transcript: CanonicalTranscript,
    pub(super) session_id: String,
    pub(super) selected_leaf_id: String,
    pub(super) physical_leaf_id: String,
}

#[derive(Debug, Clone)]
struct Entry {
    line: usize,
    id: String,
    parent_id: Option<String>,
    value: Value,
}

pub(super) fn parse(bytes: &[u8], selected_leaf: Option<&str>) -> Result<Snapshot, TransferError> {
    let mut header: Option<(usize, Value)> = None;
    let mut entries = Vec::new();
    let mut ids = HashSet::new();
    let mut first_nonempty = true;

    for (index, raw_line) in BufReader::new(Cursor::new(bytes)).split(b'\n').enumerate() {
        let line_number = index + 1;
        let mut line = raw_line.map_err(|error| TransferError::io("read OMP transcript", error))?;
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
            serde_json::from_slice(&line).map_err(|error| TransferError::InvalidJson {
                line: line_number,
                message: error.to_string(),
            })?;
        let record_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if first_nonempty && record_type == "title" {
            // The newline removed by `split` is part of OMP's fixed-width slot.
            if line.len() + 1 != TITLE_SLOT_BYTES
                || value.get("v").and_then(Value::as_u64) != Some(1)
                || value.get("title").and_then(Value::as_str).is_none()
                || value.get("updatedAt").and_then(Value::as_str).is_none()
                || value.get("pad").and_then(Value::as_str).is_none()
            {
                return Err(TransferError::UnsupportedTranscript(format!(
                    "OMP title slot on line {line_number} is not a valid {TITLE_SLOT_BYTES}-byte v1 slot"
                )));
            }
            first_nonempty = false;
            continue;
        }
        first_nonempty = false;
        if record_type == "session" {
            if header.replace((line_number, value)).is_some() {
                return Err(TransferError::UnsupportedTranscript(
                    "OMP transcript contains more than one session header".to_string(),
                ));
            }
            continue;
        }
        let id = required_string(line_number, &value, "id")?;
        if !ids.insert(id.clone()) {
            return Err(TransferError::UnsupportedTranscript(format!(
                "OMP transcript contains duplicate entry id {id:?}"
            )));
        }
        let parent_id = match value.get("parentId") {
            Some(Value::Null) => None,
            Some(Value::String(parent)) if !parent.is_empty() => Some(parent.clone()),
            _ => {
                return Err(TransferError::UnsupportedTranscript(format!(
                    "OMP entry on line {line_number} has an invalid parentId"
                )))
            }
        };
        entries.push(Entry {
            line: line_number,
            id,
            parent_id,
            value,
        });
    }

    let (header_line, header) = header.ok_or_else(|| {
        TransferError::UnsupportedTranscript("OMP transcript has no session header".to_string())
    })?;
    let version = header.get("version").and_then(Value::as_u64).unwrap_or(1);
    if !(1..=CURRENT_SESSION_VERSION).contains(&version) {
        return Err(TransferError::UnsupportedTranscript(format!(
            "OMP session version {version} is unsupported; versions 1 through {CURRENT_SESSION_VERSION} are accepted"
        )));
    }
    let session_id = required_string(header_line, &header, "id")?;
    let physical_leaf_id = entries
        .last()
        .map(|entry| entry.id.clone())
        .ok_or_else(|| {
            TransferError::UnsupportedTranscript(
                "OMP transcript contains no session entries".to_string(),
            )
        })?;
    let selected_leaf_id = selected_leaf.unwrap_or(&physical_leaf_id).to_string();
    let by_id: HashMap<&str, &Entry> = entries
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    for entry in &entries {
        if let Some(parent) = entry.parent_id.as_deref() {
            if !by_id.contains_key(parent) {
                return Err(TransferError::UnsupportedTranscript(format!(
                    "OMP entry {:?} points to missing parent {:?}",
                    entry.id, parent
                )));
            }
        }
    }
    let mut branch = Vec::new();
    let mut cursor = selected_leaf_id.as_str();
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(cursor.to_string()) {
            return Err(TransferError::UnsupportedTranscript(format!(
                "OMP entry graph contains a cycle at {cursor:?}"
            )));
        }
        let entry = by_id.get(cursor).copied().ok_or_else(|| {
            TransferError::UnsupportedTranscript(format!(
                "OMP reported leaf {selected_leaf_id:?} does not exist in the session"
            ))
        })?;
        branch.push(entry);
        match entry.parent_id.as_deref() {
            Some(parent) => cursor = parent,
            None => break,
        }
    }
    branch.reverse();

    let reset_boundary = branch.iter().rposition(|entry| {
        entry.value.get("type").and_then(Value::as_str) == Some("reset_boundary")
    });
    let branch = reset_boundary.map_or(branch.as_slice(), |index| &branch[index + 1..]);
    let mut messages = Vec::new();
    let mut omissions = OmissionSummary::default();
    if reset_boundary.is_some() {
        // OMP `/clear` retains the old JSONL branch but removes everything
        // before this marker from the live and visible conversation.
        omissions.metadata_records += 1;
    }
    for entry in branch {
        project_entry(entry, &mut messages, &mut omissions)?;
    }
    if messages.is_empty() {
        return Err(TransferError::EmptyTranscript);
    }
    Ok(Snapshot {
        transcript: CanonicalTranscript {
            messages,
            omissions,
            fingerprint: fingerprint_bytes(bytes),
        },
        session_id,
        selected_leaf_id,
        physical_leaf_id,
    })
}

fn required_string(line: usize, value: &Value, field: &str) -> Result<String, TransferError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            TransferError::UnsupportedTranscript(format!(
                "OMP record on line {line} has no valid {field}"
            ))
        })
}

fn project_entry(
    entry: &Entry,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    match entry.value.get("type").and_then(Value::as_str) {
        Some("message") => project_message(entry.line, &entry.value, messages, omissions),
        Some("custom_message") => {
            let content = entry.value.get("content");
            let visibly_nonempty = match content {
                Some(Value::String(text)) => !text.is_empty(),
                Some(Value::Array(items)) => !items.is_empty(),
                Some(Value::Null) | None => false,
                Some(_) => true,
            };
            let display = entry.value.get("display").and_then(Value::as_bool);
            if visibly_nonempty && display != Some(false) {
                return Err(TransferError::UnsupportedTranscript(format!(
                    "visible OMP custom_message on line {} has no lossless transfer projection",
                    entry.line
                )));
            }
            omissions.metadata_records += 1;
            if visibly_nonempty {
                omissions.unsupported_blocks += 1;
            }
            Ok(())
        }
        Some("compaction" | "branch_summary") => {
            omissions.metadata_records += 1;
            omissions.unsupported_blocks += 1;
            Ok(())
        }
        Some(
            "thinking_level_change"
            | "model_change"
            | "service_tier_change"
            | "custom"
            | "label"
            | "title_change"
            | "ttsr_injection"
            | "session_init"
            | "mode_change"
            | "credential_pin",
        ) => {
            omissions.metadata_records += 1;
            Ok(())
        }
        Some(record_type) => Err(TransferError::UnsupportedTranscript(format!(
            "unknown OMP entry type {record_type:?} on line {}",
            entry.line
        ))),
        None => Err(TransferError::UnsupportedTranscript(format!(
            "OMP entry on line {} has no type",
            entry.line
        ))),
    }
}

fn project_message(
    line: usize,
    entry: &Value,
    messages: &mut Vec<VisibleMessage>,
    omissions: &mut OmissionSummary,
) -> Result<(), TransferError> {
    let message = entry
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            TransferError::UnsupportedTranscript(format!(
                "OMP message entry on line {line} has no message object"
            ))
        })?;
    let role = message
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match role {
        "user" | "assistant" => {
            let visible_role = if role == "user" {
                VisibleRole::User
            } else {
                VisibleRole::Assistant
            };
            let mut text = String::new();
            match message.get("content") {
                Some(Value::String(value)) => text.push_str(value),
                Some(Value::Array(blocks)) => {
                    for block in blocks {
                        match block.get("type").and_then(Value::as_str) {
                            Some("text") => {
                                let value =
                                    block.get("text").and_then(Value::as_str).ok_or_else(|| {
                                        TransferError::AmbiguousRecord {
                                            line,
                                            message: "OMP text block has no text".to_string(),
                                        }
                                    })?;
                                text.push_str(value);
                            }
                            Some(
                                "thinking" | "redactedThinking" | "redacted_thinking"
                                | "anthropic_fallback",
                            ) => {
                                omissions.reasoning_records += 1;
                            }
                            Some(
                                "toolCall"
                                | "tool_call"
                                | "server_tool_use"
                                | "anthropicServerTool",
                            ) => {
                                omissions.tool_records += 1;
                            }
                            Some("image") => omissions.attachment_records += 1,
                            Some(other) => {
                                return Err(TransferError::AmbiguousRecord {
                                    line,
                                    message: format!("unknown OMP content block type {other:?}"),
                                })
                            }
                            None => {
                                return Err(TransferError::AmbiguousRecord {
                                    line,
                                    message: "OMP content block has no type".to_string(),
                                })
                            }
                        }
                    }
                }
                _ => {
                    return Err(TransferError::AmbiguousRecord {
                        line,
                        message: "OMP user/assistant message has invalid content".to_string(),
                    })
                }
            }
            if !text.is_empty() {
                push_visible_message(messages, visible_role, &text)?;
            }
            Ok(())
        }
        "toolResult" | "bashExecution" | "pythonExecution" => {
            omissions.tool_records += 1;
            if message
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(|blocks| {
                    blocks
                        .iter()
                        .any(|block| block.get("type").and_then(Value::as_str) == Some("image"))
                })
            {
                omissions.attachment_records += 1;
            }
            Ok(())
        }
        "developer" | "system" => {
            omissions.system_records += 1;
            Ok(())
        }
        "fileMention" => {
            omissions.attachment_records += 1;
            Ok(())
        }
        "custom" | "hookMessage" => {
            omissions.metadata_records += 1;
            omissions.unsupported_blocks += 1;
            Ok(())
        }
        other => Err(TransferError::AmbiguousRecord {
            line,
            message: format!("unknown OMP message role {other:?}"),
        }),
    }
}

pub(super) fn write(
    sessions_root: &Path,
    cwd: &Path,
    messages: &[VisibleMessage],
) -> Result<(String, PathBuf, String), TransferError> {
    if !sessions_root.is_absolute() || !cwd.is_absolute() {
        return Err(TransferError::InvalidPath(
            "OMP sessions root and cwd must be absolute".to_string(),
        ));
    }
    create_private_dir_all(sessions_root)?;
    let canonical_root = fs::canonicalize(sessions_root)
        .map_err(|error| TransferError::io("canonicalize OMP sessions root", error))?;
    let session_dir = canonical_root.join(cwd_bucket(cwd));
    create_private_dir_all(&session_dir)?;
    super::reject_symlinks_below(&canonical_root, &session_dir)?;

    for _ in 0..32 {
        let session_id = uuid_v7()?;
        let timestamp = now_rfc3339()?;
        let safe_timestamp = timestamp.replace([':', '.'], "-");
        let target = session_dir.join(format!("{safe_timestamp}_{session_id}.jsonl"));
        if target.exists() {
            continue;
        }
        let temp = session_dir.join(format!(".{session_id}.herdr-transfer.tmp"));
        let file = match crate::platform::create_private_file(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(TransferError::io("create OMP transfer file", error)),
        };
        let leaf = match write_records(file, cwd, &session_id, &timestamp, messages) {
            Ok(leaf) => leaf,
            Err(error) => {
                let _ = fs::remove_file(&temp);
                return Err(error);
            }
        };
        // A hard link is an atomic no-replace publish within one directory.
        // It cannot overwrite a session that appeared after our collision check.
        if let Err(error) = fs::hard_link(&temp, &target) {
            let _ = fs::remove_file(&temp);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(TransferError::io("commit OMP transfer file", error));
        }
        fs::remove_file(&temp)
            .map_err(|error| TransferError::io("remove OMP transfer staging link", error))?;
        sync_dir(&session_dir)?;
        return Ok((session_id, target, leaf));
    }
    Err(TransferError::Io {
        context: "allocate OMP session id",
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "repeated random session-id collision",
        ),
    })
}

fn write_records(
    file: fs::File,
    cwd: &Path,
    session_id: &str,
    timestamp: &str,
    messages: &[VisibleMessage],
) -> Result<String, TransferError> {
    let mut writer = BufWriter::new(file);
    let slot = title_slot(timestamp)?;
    writer
        .write_all(&slot)
        .map_err(|error| TransferError::io("write OMP title slot", error))?;
    let header = json!({
        "type": "session",
        "version": CURRENT_SESSION_VERSION,
        "id": session_id,
        "timestamp": timestamp,
        "cwd": cwd.to_string_lossy(),
    });
    write_json_line(&mut writer, &header)?;
    let timestamp_ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let mut parent: Option<String> = None;
    for message in messages {
        let id = uuid_v7()?;
        let native_message = match message.role {
            VisibleRole::User => json!({
                "role": "user",
                "content": [{"type": "text", "text": message.text}],
                "timestamp": timestamp_ms,
            }),
            VisibleRole::Assistant => json!({
                "role": "assistant",
                "content": [{"type": "text", "text": message.text}],
                "api": "anthropic-messages",
                "provider": "anthropic",
                "model": "herdr-session-transfer",
                "usage": {
                    "input": 0,
                    "output": 0,
                    "cacheRead": 0,
                    "cacheWrite": 0,
                    "totalTokens": 0,
                    "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "total": 0}
                },
                "stopReason": "stop",
                "timestamp": timestamp_ms,
            }),
        };
        let entry = json!({
            "type": "message",
            "id": id,
            "parentId": parent,
            "timestamp": timestamp,
            "message": native_message,
        });
        write_json_line(&mut writer, &entry)?;
        parent = Some(id);
    }
    writer
        .flush()
        .map_err(|error| TransferError::io("flush OMP transcript", error))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| TransferError::io("sync OMP transcript", error))?;
    parent.ok_or(TransferError::EmptyTranscript)
}

fn write_json_line(writer: &mut BufWriter<fs::File>, value: &Value) -> Result<(), TransferError> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| {
        TransferError::io("serialize OMP transcript", std::io::Error::other(error))
    })?;
    writer
        .write_all(b"\n")
        .map_err(|error| TransferError::io("write OMP transcript", error))
}

fn title_slot(timestamp: &str) -> Result<Vec<u8>, TransferError> {
    let base = json!({
        "type": "title",
        "v": 1,
        "title": "",
        "updatedAt": timestamp,
        "pad": "",
    });
    let mut bytes = serde_json::to_vec(&base).map_err(|error| {
        TransferError::io("serialize OMP title slot", std::io::Error::other(error))
    })?;
    bytes.push(b'\n');
    if bytes.len() > TITLE_SLOT_BYTES {
        return Err(TransferError::UnsupportedTranscript(
            "OMP title slot metadata exceeds 256 bytes".to_string(),
        ));
    }
    let pad = " ".repeat(TITLE_SLOT_BYTES - bytes.len());
    let slot = json!({
        "type": "title",
        "v": 1,
        "title": "",
        "updatedAt": timestamp,
        "pad": pad,
    });
    let mut bytes = serde_json::to_vec(&slot).map_err(|error| {
        TransferError::io("serialize OMP title slot", std::io::Error::other(error))
    })?;
    bytes.push(b'\n');
    if bytes.len() != TITLE_SLOT_BYTES {
        return Err(TransferError::UnsupportedTranscript(
            "OMP title slot serialization did not produce 256 bytes".to_string(),
        ));
    }
    Ok(bytes)
}

fn cwd_bucket(cwd: &Path) -> String {
    let canonical = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let canonical_home = fs::canonicalize(&home).unwrap_or(home);
        if let Ok(relative) = canonical.strip_prefix(canonical_home) {
            return encode_relative("-", relative);
        }
    }
    let temp = std::env::temp_dir();
    let canonical_temp = fs::canonicalize(&temp).unwrap_or(temp);
    if let Ok(relative) = canonical.strip_prefix(canonical_temp) {
        return encode_relative("-tmp", relative);
    }
    format!(
        "--{}--",
        canonical
            .to_string_lossy()
            .trim_start_matches(['/', '\\'])
            .replace(['/', '\\', ':'], "-")
    )
}

fn encode_relative(prefix: &str, relative: &Path) -> String {
    let encoded = relative.to_string_lossy().replace(['/', '\\', ':'], "-");
    if encoded.is_empty() {
        prefix.to_string()
    } else if prefix.ends_with('-') {
        format!("{prefix}{encoded}")
    } else {
        format!("{prefix}-{encoded}")
    }
}

fn create_private_dir_all(path: &Path) -> Result<(), TransferError> {
    #[cfg(unix)]
    let existed = path.exists();
    fs::create_dir_all(path)
        .map_err(|error| TransferError::io("create OMP session directory", error))?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| TransferError::io("protect OMP session directory", error))?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), TransferError> {
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
        Err(error) => Err(TransferError::io("sync OMP session directory", error)),
    }
}

fn now_rfc3339() -> Result<String, TransferError> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| {
            TransferError::io(
                "format OMP transcript timestamp",
                std::io::Error::other(error.to_string()),
            )
        })
}

fn uuid_v7() -> Result<String, TransferError> {
    let millis = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let millis = u64::try_from(millis).map_err(|error| {
        TransferError::io("generate OMP session id", std::io::Error::other(error))
    })?;
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        TransferError::io(
            "generate OMP session id",
            std::io::Error::other(error.to_string()),
        )
    })?;
    let timestamp = millis.to_be_bytes();
    bytes[..6].copy_from_slice(&timestamp[2..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn title(timestamp: &str) -> Vec<u8> {
        title_slot(timestamp).unwrap()
    }

    #[test]
    fn parser_selects_the_reported_branch_and_tracks_the_physical_leaf() {
        let timestamp = "2026-08-30T12:00:00Z";
        let mut bytes = title(timestamp);
        for value in [
            json!({"type":"session","version":3,"id":"session","timestamp":timestamp,"cwd":"/tmp"}),
            json!({"type":"message","id":"root","parentId":null,"timestamp":timestamp,"message":{"role":"user","content":[{"type":"text","text":"hello"}],"timestamp":1}}),
            json!({"type":"message","id":"left","parentId":"root","timestamp":timestamp,"message":{"role":"assistant","content":[{"type":"text","text":"left"}],"api":"x","provider":"x","model":"x","usage":{},"stopReason":"stop","timestamp":2}}),
            json!({"type":"message","id":"right","parentId":"root","timestamp":timestamp,"message":{"role":"assistant","content":[{"type":"text","text":"right"}],"api":"x","provider":"x","model":"x","usage":{},"stopReason":"stop","timestamp":3}}),
        ] {
            bytes.extend(serde_json::to_vec(&value).unwrap());
            bytes.push(b'\n');
        }
        let snapshot = parse(&bytes, Some("left")).unwrap();
        assert_eq!(snapshot.selected_leaf_id, "left");
        assert_eq!(snapshot.physical_leaf_id, "right");
        assert_eq!(snapshot.transcript.messages[1].text, "left");
    }

    #[test]
    fn parser_rejects_dangling_parents_and_future_versions() {
        let timestamp = "2026-08-30T12:00:00Z";
        let cases = [
            vec![
                json!({"type":"session","version":4,"id":"session","timestamp":timestamp,"cwd":"/tmp"}),
                json!({"type":"message","id":"one","parentId":null,"timestamp":timestamp,"message":{"role":"user","content":"hello","timestamp":1}}),
            ],
            vec![
                json!({"type":"session","version":3,"id":"session","timestamp":timestamp,"cwd":"/tmp"}),
                json!({"type":"message","id":"one","parentId":"missing","timestamp":timestamp,"message":{"role":"user","content":"hello","timestamp":1}}),
            ],
        ];
        for records in cases {
            let mut bytes = title(timestamp);
            for value in records {
                bytes.extend(serde_json::to_vec(&value).unwrap());
                bytes.push(b'\n');
            }
            assert!(matches!(
                parse(&bytes, None),
                Err(TransferError::UnsupportedTranscript(_))
            ));
        }
    }

    #[test]
    fn parser_honors_clear_and_classifies_current_native_nonchat_records() {
        let timestamp = "2026-08-30T12:00:00Z";
        let mut bytes = title(timestamp);
        for value in [
            json!({"type":"session","version":3,"id":"session","timestamp":timestamp,"cwd":"/tmp"}),
            json!({"type":"message","id":"old-user","parentId":null,"timestamp":timestamp,"message":{"role":"user","content":[{"type":"text","text":"old and cleared"}],"timestamp":1}}),
            json!({"type":"reset_boundary","id":"reset","parentId":"old-user","timestamp":timestamp}),
            json!({"type":"custom_message","id":"hidden","parentId":"reset","timestamp":timestamp,"customType":"runtime-context","content":"hidden context","display":false}),
            json!({"type":"message","id":"shell","parentId":"hidden","timestamp":timestamp,"message":{"role":"bashExecution","command":"pwd","output":"/tmp","cancelled":false,"truncated":false,"timestamp":2}}),
            json!({"type":"message","id":"new-user","parentId":"shell","timestamp":timestamp,"message":{"role":"user","content":[{"type":"text","text":"current"}],"timestamp":3}}),
            json!({"type":"message","id":"new-assistant","parentId":"new-user","timestamp":timestamp,"message":{"role":"assistant","content":[{"type":"redactedThinking","data":"opaque"},{"type":"text","text":"answer"}],"api":"x","provider":"x","model":"x","usage":{},"stopReason":"stop","timestamp":4}}),
        ] {
            bytes.extend(serde_json::to_vec(&value).unwrap());
            bytes.push(b'\n');
        }
        let snapshot = parse(&bytes, Some("new-assistant")).unwrap();
        assert_eq!(
            snapshot.transcript.messages,
            vec![
                VisibleMessage {
                    role: VisibleRole::User,
                    text: "current".into(),
                },
                VisibleMessage {
                    role: VisibleRole::Assistant,
                    text: "answer".into(),
                },
            ]
        );
        assert_eq!(snapshot.transcript.omissions.metadata_records, 2);
        assert_eq!(snapshot.transcript.omissions.unsupported_blocks, 1);
        assert_eq!(snapshot.transcript.omissions.tool_records, 1);
        assert_eq!(snapshot.transcript.omissions.reasoning_records, 1);
    }

    #[test]
    fn parser_refuses_a_visible_custom_message_without_a_lossless_role() {
        let timestamp = "2026-08-30T12:00:00Z";
        let mut bytes = title(timestamp);
        for value in [
            json!({"type":"session","version":3,"id":"session","timestamp":timestamp,"cwd":"/tmp"}),
            json!({"type":"message","id":"user","parentId":null,"timestamp":timestamp,"message":{"role":"user","content":"hello","timestamp":1}}),
            json!({"type":"custom_message","id":"notice","parentId":"user","timestamp":timestamp,"customType":"notice","content":"visible notice","display":true}),
        ] {
            bytes.extend(serde_json::to_vec(&value).unwrap());
            bytes.push(b'\n');
        }
        assert!(matches!(
            parse(&bytes, Some("notice")),
            Err(TransferError::UnsupportedTranscript(message))
                if message.contains("visible OMP custom_message")
        ));
    }

    #[test]
    fn writer_round_trips_native_v3_with_a_fixed_title_slot() {
        let root = std::env::temp_dir().join(format!("herdr-omp-write-{}", std::process::id()));
        let sessions = root.join("sessions");
        fs::create_dir_all(&root).unwrap();
        let messages = vec![
            VisibleMessage {
                role: VisibleRole::User,
                text: "hello".into(),
            },
            VisibleMessage {
                role: VisibleRole::Assistant,
                text: "world".into(),
            },
        ];
        let (session_id, path, leaf) = write(&sessions, &root, &messages).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes[..TITLE_SLOT_BYTES].len(), TITLE_SLOT_BYTES);
        assert_eq!(bytes[TITLE_SLOT_BYTES - 1], b'\n');
        let snapshot = parse(&bytes, Some(&leaf)).unwrap();
        assert_eq!(snapshot.session_id, session_id);
        assert_eq!(snapshot.transcript.messages, messages);
        if let Some(binary) = std::env::var_os("HERDR_TEST_OMP_BINARY") {
            let status = std::process::Command::new(binary)
                .arg(format!("--export={}", path.display()))
                .current_dir(&root)
                .status()
                .expect("launch the opt-in OMP compatibility probe");
            assert!(
                status.success(),
                "OMP must load and export Herdr's native v3 file"
            );
            assert!(
                fs::read_dir(&root).is_ok_and(|entries| {
                    entries.filter_map(Result::ok).any(|entry| {
                        entry
                            .path()
                            .extension()
                            .is_some_and(|extension| extension == "html")
                            && entry.metadata().is_ok_and(|metadata| metadata.len() > 0)
                    })
                }),
                "OMP export must produce a non-empty HTML transcript"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
