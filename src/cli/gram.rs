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
    std::fs::write(&out, &bytes)?;

    let name = response
        .pointer("/result/name")
        .and_then(|value| value.as_str())
        .unwrap_or("file");
    eprintln!("saved {name} ({} bytes) to {out}", bytes.len());
    Ok(0)
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
    let (only_queue, unread_only, owner) = match parse_list_args(args) {
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
    let owner_view = owner || unread_only;
    let caller_pane_id = if owner_view { None } else { env_pane_id() };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:list".into(),
        method: Method::GramList(GramListParams {
            caller_pane_id,
            only_queue,
            unread_only,
        }),
    })?)
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
fn parse_list_args(args: &[String]) -> Result<(bool, bool, bool), String> {
    let mut only_queue = false;
    let mut unread_only = false;
    let mut owner = false;
    for arg in args {
        match arg.as_str() {
            "--queue" => only_queue = true,
            "--unread" => unread_only = true,
            "--owner" => owner = true,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if only_queue && unread_only {
        return Err("--queue and --unread cannot be combined".into());
    }
    Ok((only_queue, unread_only, owner))
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
    eprintln!("  herdr gram list [--queue] [--unread] [--owner]   list messages (--owner: read as the owner)");
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
        assert_eq!(
            parse_list_args(&args(&["--queue"])).unwrap(),
            (true, false, false)
        );
        assert_eq!(
            parse_list_args(&args(&["--unread"])).unwrap(),
            (false, true, false)
        );
        assert_eq!(
            parse_list_args(&args(&["--owner"])).unwrap(),
            (false, false, true)
        );
        assert_eq!(parse_list_args(&args(&[])).unwrap(), (false, false, false));
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
}
