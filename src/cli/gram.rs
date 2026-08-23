use base64::Engine as _;

use crate::api::schema::{
    GramDeleteParams, GramFileUpload, GramGetFileParams, GramGrabParams, GramListParams,
    GramMarkReadParams, GramPostParams, GramSendParams, GramUploadChunkParams, Method, Request,
};

/// Chunk size for a CLI upload over the local socket. Below the server's
/// [`crate::persist::gram_files::MAX_CHUNK_BYTES`] and, base64-encoded, well below
/// the daemon's 1 MiB request-line cap, so the whole request line always fits.
const CLI_CHUNK_BYTES: usize = 256 * 1024;

/// `herdr gram` — the owner<->agent message channel used by the Herdr app.
///
/// Agents mainly use `send` (message the owner, push-notified), `list --queue`
/// (see unclaimed work the owner posted), and `grab <id>` (claim one). `post` and
/// `mark-read` are owner/testing conveniences. The caller's identity comes from
/// `HERDR_PANE_ID`, which every Herdr pane sets; it is sent as `caller_pane_id`
/// and resolved to the agent's label server-side.
pub(super) fn run_gram_command(args: &[String]) -> std::io::Result<i32> {
    let Some(subcommand) = args.first().map(|arg| arg.as_str()) else {
        print_gram_help();
        return Ok(2);
    };

    match subcommand {
        "send" => gram_send(&args[1..]),
        "post" => gram_post(&args[1..]),
        "list" => gram_list(&args[1..]),
        "grab" => gram_grab(&args[1..]),
        "mark-read" => gram_mark_read(&args[1..]),
        "delete" => gram_delete(&args[1..]),
        "get-file" => gram_get_file(&args[1..]),
        "help" | "--help" | "-h" => {
            print_gram_help();
            Ok(0)
        }
        _ => {
            print_gram_help();
            Ok(2)
        }
    }
}

fn env_pane_id() -> Option<String> {
    std::env::var("HERDR_PANE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| super::normalize_pane_id(&value))
}

fn gram_send(args: &[String]) -> std::io::Result<i32> {
    let (text, from, file_path) = match parse_send_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    let file = match file_path {
        Some(path) => match upload_file(&path)? {
            Ok(uploaded) => Some(uploaded),
            // A chunk was rejected server-side; surface that error and stop.
            Err(error_response) => return super::print_response(&error_response),
        },
        None => None,
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:send".into(),
        method: Method::GramSend(GramSendParams {
            text,
            caller_pane_id: env_pane_id(),
            from,
            file,
        }),
    })?)
}

fn gram_post(args: &[String]) -> std::io::Result<i32> {
    let (text, to) = match parse_post_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:post".into(),
        method: Method::GramPost(GramPostParams {
            text,
            to,
            file: None,
        }),
    })?)
}

/// Read a file and upload it in chunks over the local socket, returning the
/// `GramFileUpload` to attach to a `gram.send`. `Ok(Err(response))` carries a
/// server error from a rejected chunk (e.g. the file is too large); the outer
/// error is a local I/O failure (the file could not be read).
fn upload_file(path: &str) -> std::io::Result<Result<GramFileUpload, serde_json::Value>> {
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file is empty",
        ));
    }
    // The server enforces this too, but fail fast with a clear message.
    if bytes.len() as u64 > crate::persist::gram_files::MAX_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file exceeds the size limit",
        ));
    }

    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|component| component.to_str())
        .unwrap_or("file")
        .to_string();
    let mime = guess_mime(&name);
    let upload_id = crate::persist::gram::new_id();

    let mut offset: u64 = 0;
    for chunk in bytes.chunks(CLI_CHUNK_BYTES) {
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(chunk);
        let response = super::send_request(&Request {
            id: "cli:gram:upload_chunk".into(),
            method: Method::GramUploadChunk(GramUploadChunkParams {
                upload_id: upload_id.clone(),
                offset,
                data_base64,
            }),
        })?;
        if response.get("error").is_some() {
            return Ok(Err(response));
        }
        offset += chunk.len() as u64;
    }

    Ok(Ok(GramFileUpload {
        upload_id,
        name,
        mime,
    }))
}

fn gram_get_file(args: &[String]) -> std::io::Result<i32> {
    let (id, out) = match parse_get_file_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    let response = super::send_request(&Request {
        id: "cli:gram:get_file".into(),
        method: Method::GramGetFile(GramGetFileParams {
            id,
            caller_pane_id: env_pane_id(),
        }),
    })?;
    if response.get("error").is_some() {
        return super::print_response(&response);
    }

    let Some(data_base64) = response
        .pointer("/result/data_base64")
        .and_then(|value| value.as_str())
    else {
        eprintln!("unexpected response: {response}");
        return Ok(1);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server returned invalid base64",
            )
        })?;
    // Write owner-only (0600): a downloaded file may be a secret (a temporary API
    // key), and the default umask would otherwise leave it world-readable.
    write_private(&out, &bytes)?;

    let name = response
        .pointer("/result/name")
        .and_then(|value| value.as_str())
        .unwrap_or("file");
    eprintln!("saved {name} ({} bytes) to {out}", bytes.len());
    Ok(0)
}

/// Write a downloaded file with owner-only permissions so a secret is not left
/// world-readable at the default umask. Enforces the mode even if the target
/// already existed with looser permissions.
#[cfg(unix)]
fn write_private(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Best-effort MIME type from a file's extension. Advisory only — the server
/// stores it verbatim for the app to hint the preview.
fn guess_mime(name: &str) -> String {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|component| component.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mime = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain",
        "json" => "application/json",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    };
    mime.to_string()
}

fn gram_list(args: &[String]) -> std::io::Result<i32> {
    let parsed = match parse_list_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    // Default: attach this pane's id for the agent/pane view. `--owner` (and
    // `--unread`, which is an owner-only view) omit it so the server returns the
    // owner view — otherwise the owner view would be unreachable from any pane,
    // since HERDR_PANE_ID is set on every managed pane.
    let owner_view = parsed.owner || parsed.unread_only;
    let caller_pane_id = if owner_view { None } else { env_pane_id() };

    let mut response = super::send_request(&Request {
        id: "cli:gram:list".into(),
        method: Method::GramList(GramListParams {
            caller_pane_id,
            only_queue: parsed.only_queue,
            unread_only: parsed.unread_only,
        }),
    })?;
    // Redact credential-looking bodies before printing so a routine `gram list`
    // can't spill a secret into the reader's transcript. Display-only: stored
    // messages are untouched and `--reveal` prints the raw value. (issue #95)
    if !parsed.reveal {
        redact_gram_response(&mut response);
    }
    super::print_response(&response)
}

/// Redact credential-looking spans in every gram body of a `gram list` response,
/// in place, for DISPLAY only. Walks `result.messages[].text`; leaves ids, files,
/// and all other fields untouched.
fn redact_gram_response(response: &mut serde_json::Value) {
    let Some(messages) = response
        .get_mut("result")
        .and_then(|r| r.get_mut("messages"))
        .and_then(|m| m.as_array_mut())
    else {
        return;
    };
    for message in messages {
        if let Some(text) = message.get("text").and_then(|t| t.as_str()) {
            let redacted = redact_credentials(text);
            if redacted != text {
                message["text"] = serde_json::Value::String(redacted);
            }
        }
    }
}

fn gram_grab(args: &[String]) -> std::io::Result<i32> {
    let (id, grabbed_by) = match parse_grab_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:grab".into(),
        method: Method::GramGrab(GramGrabParams {
            id,
            caller_pane_id: env_pane_id(),
            grabbed_by,
        }),
    })?)
}

fn gram_mark_read(args: &[String]) -> std::io::Result<i32> {
    let id = match parse_single_id(args, "mark-read") {
        Ok(id) => id,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:mark_read".into(),
        method: Method::GramMarkRead(GramMarkReadParams { id }),
    })?)
}

fn gram_delete(args: &[String]) -> std::io::Result<i32> {
    let (id, owner) = match parse_delete_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    // Default: this pane's agent identity, so an agent deletes only a message it
    // is involved in. `--owner` omits the pane to delete with owner authority
    // (any message), matching `list --owner`.
    let caller_pane_id = if owner { None } else { env_pane_id() };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:delete".into(),
        method: Method::GramDelete(GramDeleteParams { id, caller_pane_id }),
    })?)
}

// MARK: - arg parsing (pure, unit-tested)

/// `send [<text>] [--from LABEL] [--file PATH]` -> (text, from, file). At least one
/// of text or a file is required; a file with no caption sends empty text.
fn parse_send_args(args: &[String]) -> Result<(String, Option<String>, Option<String>), String> {
    let mut text: Option<String> = None;
    let mut from: Option<String> = None;
    let mut file: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--from" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --from".into());
                };
                from = Some(value.clone());
                index += 2;
            }
            "--file" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --file".into());
                };
                file = Some(value.clone());
                index += 2;
            }
            other if is_flag(other) => return Err(format!("unknown option: {other}")),
            other => {
                if text.is_some() {
                    return Err("unexpected extra argument; quote the message text".into());
                }
                text = Some(other.to_string());
                index += 1;
            }
        }
    }
    if text.is_none() && file.is_none() {
        return Err("usage: herdr gram send <text> [--from LABEL] [--file PATH]".into());
    }
    Ok((text.unwrap_or_default(), from, file))
}

/// `get-file <id> -o PATH` (or `--out PATH`) -> (id, path).
fn parse_get_file_args(args: &[String]) -> Result<(String, String), String> {
    let mut id: Option<String> = None;
    let mut out: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-o" | "--out" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --out".into());
                };
                out = Some(value.clone());
                index += 2;
            }
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other => {
                if id.is_some() {
                    return Err("unexpected extra argument".into());
                }
                id = Some(other.to_string());
                index += 1;
            }
        }
    }
    let id = id.ok_or("usage: herdr gram get-file <id> -o PATH")?;
    let out = out.ok_or("usage: herdr gram get-file <id> -o PATH")?;
    Ok((id, out))
}

/// `post <text> [--to AGENT]` -> (text, to). `--to` addresses one agent; omit it
/// to post to the shared grab-queue.
fn parse_post_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let mut text: Option<String> = None;
    let mut to: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--to" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --to".into());
                };
                to = Some(value.clone());
                index += 2;
            }
            other if is_flag(other) => return Err(format!("unknown option: {other}")),
            other => {
                if text.is_some() {
                    return Err("unexpected extra argument; quote the message text".into());
                }
                text = Some(other.to_string());
                index += 1;
            }
        }
    }
    let text = text.ok_or("usage: herdr gram post <text> [--to AGENT]")?;
    Ok((text, to))
}

/// `list [--queue] [--unread] [--owner]` -> (only_queue, unread_only, owner).
/// `--queue` (shared unclaimed work) and `--unread` (owner's unread inbox) are
/// mutually exclusive. `--owner` reads as the owner (omits the caller pane);
/// `--unread` implies it.
/// Credential-looking token prefixes redacted from gram bodies on the CLI read
/// path (issue #95). `sk-` covers OpenAI / OpenRouter (`sk-or-`) / Anthropic
/// (`sk-ant-`) / project keys. PEM private-key blocks are handled separately.
const CREDENTIAL_PREFIXES: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "AKIA",
    "xoxb-",
    "xoxp-",
    "AIza",
];

/// A contiguous `[A-Za-z0-9_-]` run counts as a credential when it starts with a
/// known prefix AND is long enough to be a real key (short words like a bare
/// "sk-" in prose never trip it). 20 is the AWS access-key-id length (the shortest
/// of the set).
fn is_credential_token(token: &str) -> bool {
    token.len() >= 20
        && CREDENTIAL_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
}

/// Redact credential-looking spans from `text` for DISPLAY. Never mutates stored
/// messages. Each detected secret becomes `[redacted credential, N chars]` (or
/// `[redacted private key, N chars]` for a PEM block), N being the redacted
/// length. Pure — unit-tested over the prefix set.
fn redact_credentials(text: &str) -> String {
    let collapsed = redact_pem_blocks(text);
    let mut out = String::with_capacity(collapsed.len());
    let mut token = String::new();
    for ch in collapsed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            token.push(ch);
        } else {
            push_token(&token, &mut out);
            token.clear();
            out.push(ch);
        }
    }
    push_token(&token, &mut out);
    out
}

fn push_token(token: &str, out: &mut String) {
    if is_credential_token(token) {
        out.push_str(&format!(
            "[redacted credential, {} chars]",
            token.chars().count()
        ));
    } else {
        out.push_str(token);
    }
}

/// Collapse each `-----BEGIN … PRIVATE KEY-----` … `-----END … -----` block into a
/// single marker (its multi-line base64 body would otherwise slip past the
/// token scanner). If a BEGIN has no well-formed END, redact to end-of-text
/// (over-redacting a key is the safe failure).
fn redact_pem_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(begin) = rest.find("-----BEGIN ") {
        out.push_str(&rest[..begin]);
        let block = &rest[begin..];
        let block_end = block.find("-----END ").and_then(|end| {
            block[end + "-----END ".len()..]
                .find("-----")
                .map(|c| end + "-----END ".len() + c + "-----".len())
        });
        match block_end {
            Some(stop) if block[..stop].contains("PRIVATE KEY") => {
                out.push_str(&format!(
                    "[redacted private key, {} chars]",
                    block[..stop].chars().count()
                ));
                rest = &block[stop..];
            }
            _ => {
                // A BEGIN with no proper END (or not a private key). If it names a
                // PRIVATE KEY, redact the remainder to be safe; else pass it through.
                if block.contains("PRIVATE KEY") {
                    out.push_str(&format!(
                        "[redacted private key, {} chars]",
                        block.chars().count()
                    ));
                    rest = "";
                } else {
                    out.push_str("-----BEGIN ");
                    rest = &block["-----BEGIN ".len()..];
                }
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_list_args(args: &[String]) -> Result<ListArgs, String> {
    let mut parsed = ListArgs::default();
    for arg in args {
        match arg.as_str() {
            "--queue" => parsed.only_queue = true,
            "--unread" => parsed.unread_only = true,
            "--owner" => parsed.owner = true,
            // Print credential-looking bodies in the clear. Default is to redact them
            // (see `redact_credentials`) so a routine `gram list` can't drop a secret
            // into the reader's transcript.
            "--reveal" | "--show-secrets" => parsed.reveal = true,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if parsed.only_queue && parsed.unread_only {
        return Err("--queue and --unread cannot be combined".into());
    }
    Ok(parsed)
}

#[derive(Default)]
struct ListArgs {
    only_queue: bool,
    unread_only: bool,
    owner: bool,
    reveal: bool,
}

/// `grab <id> [--as LABEL]` -> (id, grabbed_by).
fn parse_grab_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let mut id: Option<String> = None;
    let mut grabbed_by: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--as" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --as".into());
                };
                grabbed_by = Some(value.clone());
                index += 2;
            }
            other if is_flag(other) => return Err(format!("unknown option: {other}")),
            other => {
                if id.is_some() {
                    return Err("unexpected extra argument".into());
                }
                id = Some(other.to_string());
                index += 1;
            }
        }
    }
    let id = id.ok_or("usage: herdr gram grab <id> [--as LABEL]")?;
    Ok((id, grabbed_by))
}

/// `delete <id> [--owner]` -> (id, owner). `--owner` deletes with owner authority
/// (any message); the default uses this pane's agent identity (only a message the
/// agent sent, grabbed, or that is addressed to it).
fn parse_delete_args(args: &[String]) -> Result<(String, bool), String> {
    let mut id: Option<String> = None;
    let mut owner = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--owner" => {
                owner = true;
                index += 1;
            }
            other if is_flag(other) => return Err(format!("unknown option: {other}")),
            other => {
                if id.is_some() {
                    return Err("unexpected extra argument".into());
                }
                id = Some(other.to_string());
                index += 1;
            }
        }
    }
    let id = id.ok_or("usage: herdr gram delete <id> [--owner]")?;
    Ok((id, owner))
}

fn parse_single_id(args: &[String], subcommand: &str) -> Result<String, String> {
    match args {
        [id] if !is_flag(id) => Ok(id.clone()),
        _ => Err(format!("usage: herdr gram {subcommand} <id>")),
    }
}

fn is_flag(value: &str) -> bool {
    value.starts_with("--")
}

fn print_gram_help() {
    eprintln!("herdr gram commands:");
    eprintln!(
        "  herdr gram send <text> [--from LABEL] [--file PATH]   message the owner (push-notified)"
    );
    eprintln!("  herdr gram list [--queue] [--unread] [--owner] [--reveal]   list messages (--owner: read as the owner)");
    eprintln!("  herdr gram grab <id> [--as LABEL]        claim a shared queue item");
    eprintln!("  herdr gram get-file <id> -o PATH         download a message's attached file");
    eprintln!("  herdr gram post <text> [--to AGENT]      owner: post to the queue or one agent");
    eprintln!("  herdr gram mark-read <id>                owner: mark an agent message read");
    eprintln!(
        "  herdr gram delete <id> [--owner]         delete a message (and any file) for good"
    );
    eprintln!();
    eprintln!("--from/--as override the attribution label (default: your agent name).");
    eprintln!("delete removes only a message you sent, grabbed, or that is addressed to you;");
    eprintln!("--owner deletes any message (owner authority).");
    eprintln!();
    eprintln!("list REDACTS credential-looking bodies (api keys, tokens, private keys) so a");
    eprintln!("routine `gram list` can't spill a secret into your transcript; pass --reveal to");
    eprintln!("print raw values. Threads are PER-AGENT: `list` only ever shows YOUR own thread,");
    eprintln!("so it cannot audit another agent's grams.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn send_parses_text_from_and_file() {
        assert_eq!(
            parse_send_args(&args(&["digest ready", "--from", "trend-scout"])).unwrap(),
            (
                "digest ready".to_string(),
                Some("trend-scout".to_string()),
                None
            )
        );
        assert_eq!(
            parse_send_args(&args(&["hello"])).unwrap(),
            ("hello".to_string(), None, None)
        );
        // A file with a caption.
        assert_eq!(
            parse_send_args(&args(&["look", "--file", "/tmp/shot.png"])).unwrap(),
            ("look".to_string(), None, Some("/tmp/shot.png".to_string()))
        );
        // A file with no caption sends empty text.
        assert_eq!(
            parse_send_args(&args(&["--file", "/tmp/shot.png"])).unwrap(),
            (String::new(), None, Some("/tmp/shot.png".to_string()))
        );
    }

    #[test]
    fn send_requires_text_or_file_and_rejects_extra() {
        assert!(parse_send_args(&args(&[])).is_err());
        assert!(parse_send_args(&args(&["a", "b"])).is_err());
        // --from alone is not enough; text or file is required.
        assert!(parse_send_args(&args(&["--from", "x"])).is_err());
        assert!(parse_send_args(&args(&["--file"])).is_err());
    }

    #[test]
    fn get_file_parses_id_and_out() {
        assert_eq!(
            parse_get_file_args(&args(&["gram-1", "-o", "/tmp/x"])).unwrap(),
            ("gram-1".to_string(), "/tmp/x".to_string())
        );
        assert_eq!(
            parse_get_file_args(&args(&["gram-1", "--out", "/tmp/x"])).unwrap(),
            ("gram-1".to_string(), "/tmp/x".to_string())
        );
        // Both id and an output path are required.
        assert!(parse_get_file_args(&args(&["gram-1"])).is_err());
        assert!(parse_get_file_args(&args(&["-o", "/tmp/x"])).is_err());
        assert!(parse_get_file_args(&args(&["gram-1", "-o", "/tmp/x", "extra"])).is_err());
    }

    #[test]
    fn post_parses_to() {
        assert_eq!(
            parse_post_args(&args(&["do this", "--to", "alpha"])).unwrap(),
            ("do this".to_string(), Some("alpha".to_string()))
        );
        assert_eq!(
            parse_post_args(&args(&["shared work"])).unwrap(),
            ("shared work".to_string(), None)
        );
    }

    #[test]
    fn list_flags_are_exclusive() {
        let q = parse_list_args(&args(&["--queue"])).unwrap();
        assert!(q.only_queue && !q.unread_only && !q.owner);
        let u = parse_list_args(&args(&["--unread"])).unwrap();
        assert!(!u.only_queue && u.unread_only && !u.owner);
        let o = parse_list_args(&args(&["--owner"])).unwrap();
        assert!(!o.only_queue && !o.unread_only && o.owner);
        let none = parse_list_args(&args(&[])).unwrap();
        assert!(!none.only_queue && !none.unread_only && !none.owner && !none.reveal);
        assert!(parse_list_args(&args(&["--queue", "--unread"])).is_err());
        assert!(parse_list_args(&args(&["--nope"])).is_err());
    }

    #[test]
    fn grab_parses_id_and_as() {
        assert_eq!(
            parse_grab_args(&args(&["gram-1", "--as", "alpha"])).unwrap(),
            ("gram-1".to_string(), Some("alpha".to_string()))
        );
        assert!(parse_grab_args(&args(&[])).is_err());
    }

    #[test]
    fn delete_parses_id_and_owner() {
        assert_eq!(
            parse_delete_args(&args(&["gram-1"])).unwrap(),
            ("gram-1".to_string(), false)
        );
        assert_eq!(
            parse_delete_args(&args(&["gram-1", "--owner"])).unwrap(),
            ("gram-1".to_string(), true)
        );
        assert!(parse_delete_args(&args(&[])).is_err());
        assert!(parse_delete_args(&args(&["a", "b"])).is_err());
        assert!(parse_delete_args(&args(&["--nope"])).is_err());
    }

    #[test]
    fn mark_read_needs_one_id() {
        assert_eq!(
            parse_single_id(&args(&["gram-1"]), "mark-read").unwrap(),
            "gram-1".to_string()
        );
        assert!(parse_single_id(&args(&[]), "mark-read").is_err());
        assert!(parse_single_id(&args(&["--x"]), "mark-read").is_err());
    }

    // --- credential redaction (issue #95) ---
    // Secret-shaped strings are BUILT at runtime from a prefix + synthetic filler,
    // never written as literals, so no real-looking token sits in the source (which
    // would trip secret-scanning push protection) yet the redactor still sees the
    // prefix + length it keys on.

    /// A synthetic, non-secret 40-char suffix. High-charset but obviously fake.
    fn filler() -> String {
        "0a1b2c3d4e".repeat(4)
    }

    fn is_redacted(secret: &str) -> bool {
        let out = redact_credentials(&format!("here is the key {secret} use it"));
        !out.contains(secret) && out.contains("[redacted")
    }

    #[test]
    fn redacts_every_credential_prefix() {
        for prefix in CREDENTIAL_PREFIXES {
            let secret = format!("{prefix}{}", filler());
            assert!(is_redacted(&secret), "not redacted: prefix {prefix}");
        }
    }

    #[test]
    fn keeps_prose_and_short_lookalikes() {
        // A bare prefix in prose is below the length gate and must survive.
        let body = "the ssh-agent sk- and a short gho_x are fine; deploy ok";
        assert_eq!(
            redact_credentials(body),
            body,
            "ordinary prose must survive"
        );
    }

    #[test]
    fn redacts_only_the_token_inside_prose() {
        let secret = format!("ghp_{}", filler());
        let out = redact_credentials(&format!("here: {secret}, thanks"));
        let marker = format!("[redacted credential, {} chars]", secret.chars().count());
        assert_eq!(out, format!("here: {marker}, thanks"), "{out}");
    }

    #[test]
    fn redacts_a_pem_private_key_block() {
        // Build the markers at runtime so no contiguous key header sits in source.
        let begin = format!("-----BEGIN OPENSSH {} KEY-----", "PRIVATE");
        let end = format!("-----END OPENSSH {} KEY-----", "PRIVATE");
        let body = format!("key below:\n{begin}\nAAAABG5vbmU=\nZm9vYmFy\n{end}\ndone");
        let out = redact_credentials(&body);
        assert!(!out.contains(&begin), "pem body leaked: {out}");
        assert!(out.contains("[redacted private key,"));
        assert!(out.starts_with("key below:\n") && out.ends_with("\ndone"));
    }

    #[test]
    fn reveal_flag_disables_redaction_intent() {
        assert!(parse_list_args(&args(&["--reveal"])).unwrap().reveal);
        assert!(parse_list_args(&args(&["--show-secrets"])).unwrap().reveal);
        assert!(!parse_list_args(&args(&[])).unwrap().reveal);
    }

    #[test]
    fn redact_gram_response_only_rewrites_text() {
        let secret = format!("ghp_{}", filler());
        let mut response = serde_json::json!({
            "result": { "messages": [
                { "id": "gram-1", "text": format!("my key is {secret}"), "read_by_owner": false },
                { "id": "gram-2", "text": "nothing secret here" }
            ], "type": "gram_list" }
        });
        redact_gram_response(&mut response);
        let msgs = response["result"]["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["id"], "gram-1", "ids untouched");
        assert_eq!(msgs[0]["read_by_owner"], false, "other fields untouched");
        assert!(
            msgs[0]["text"]
                .as_str()
                .unwrap()
                .contains("[redacted credential,"),
            "the secret body must be redacted"
        );
        assert_eq!(
            msgs[1]["text"], "nothing secret here",
            "clean body unchanged"
        );
    }
}
