use base64::Engine as _;
use regex::Regex;
use std::sync::LazyLock;

use crate::api::schema::{
    GramDeleteParams, GramFileUpload, GramGetFileChunkParams, GramGrabParams, GramListParams,
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
        #[cfg(unix)]
        "relay-path" if args.len() == 2 => {
            println!(
                "{}",
                crate::api::reverse::reverse_socket_path(
                    &args[1],
                    &crate::persist::machine::get_or_create(),
                )
                .display()
            );
            Ok(0)
        }
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

    let mut response = super::send_request(&Request {
        id: format!("cli:gram:send:{}", crate::persist::gram::new_id()),
        method: Method::GramSend(GramSendParams {
            text,
            caller_pane_id: env_pane_id(),
            from,
            file,
        }),
    })?;
    // Redact the echoed body too, for symmetry with grab/list (the sender already
    // has the text; the confirmation echo doesn't need to reprint a secret).
    redact_message_info(&mut response);
    super::print_response(&response)
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
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    let mut source = std::fs::File::open(path)?;
    let size = source.metadata()?.len();
    if size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file is empty",
        ));
    }
    if size > crate::persist::gram_files::MAX_FILE_BYTES {
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
    let mut digest = Sha256::new();
    let mut buffer = vec![0; CLI_CHUNK_BYTES];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if offset + count as u64 > crate::persist::gram_files::MAX_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "file grew beyond the size limit",
            ));
        }
        let chunk = &buffer[..count];
        digest.update(chunk);
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
    if offset != size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "source file changed during upload",
        ));
    }
    Ok(Ok(GramFileUpload {
        upload_id,
        name,
        mime,
        sha256: Some(format!("{:x}", digest.finalize())),
    }))
}

fn gram_get_file(args: &[String]) -> std::io::Result<i32> {
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;
    let (id, out, reveal) = match parse_get_file_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };
    let mut offset = 0u64;
    let mut size = None;
    let mut expected_hash = String::new();
    let mut name = String::new();
    let mut digest = Sha256::new();
    let mut target: Option<PrivateDownload> = None;
    let mut sniff_tail = Vec::new();
    loop {
        let response = super::send_request(&Request {
            id: format!(
                "cli:gram:get_file:{}:{offset}",
                crate::persist::gram::new_id()
            ),
            method: Method::GramGetFileChunk(GramGetFileChunkParams {
                id: id.clone(),
                offset,
                caller_pane_id: env_pane_id(),
            }),
        })?;
        if response.get("error").is_some() {
            return super::print_response(&response);
        }
        let result = response.get("result").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing Gram file chunk result",
            )
        })?;
        let chunk_size = result
            .get("size")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing file size")
            })?;
        let chunk_hash = result
            .get("sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing file SHA-256")
            })?;
        let chunk_name = result
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing filename")
            })?;
        if chunk_size > crate::persist::gram_files::MAX_FILE_BYTES
            || result.get("offset").and_then(|value| value.as_u64()) != Some(offset)
            || size.is_some_and(|expected| expected != chunk_size)
            || (size.is_some() && (chunk_hash != expected_hash || chunk_name != name))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "inconsistent Gram file chunk",
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(
                result
                    .get("data_base64")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing file bytes")
                    })?,
            )
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if bytes.len() > crate::persist::gram_files::MAX_CHUNK_BYTES
            || bytes.is_empty() && offset != chunk_size
            || offset + bytes.len() as u64 > chunk_size
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid Gram file chunk length",
            ));
        }
        if should_refuse_download_chunk(chunk_name, &bytes, reveal, &mut sniff_tail) {
            eprintln!("refused: \"{chunk_name}\" ({chunk_size} bytes) looks like it contains a credential. Re-run with --reveal to download it anyway.");
            return Ok(3);
        }
        if size.is_none() {
            let temporary = format!("{out}.herdr-{}.part", crate::persist::gram::new_id());
            target = Some(PrivateDownload::new(temporary)?);
            size = Some(chunk_size);
            expected_hash = chunk_hash.to_owned();
            name = chunk_name.to_owned();
        }
        digest.update(&bytes);
        target
            .as_mut()
            .expect("created on first chunk")
            .file
            .write_all(&bytes)?;
        offset += bytes.len() as u64;
        if offset == chunk_size {
            break;
        }
    }
    if format!("{:x}", digest.finalize()) != expected_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Gram file SHA-256 mismatch",
        ));
    }
    target
        .expect("file must have at least one chunk")
        .commit(&out)?;
    eprintln!("saved {name} ({offset} bytes) to {out}");
    Ok(0)
}

/// The destination is replaced only after every chunk and the complete digest
/// have been verified. A failed transfer removes the private staging file.
struct PrivateDownload {
    path: String,
    file: std::fs::File,
    committed: bool,
}

impl PrivateDownload {
    fn new(path: String) -> std::io::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok(Self {
            path,
            file,
            committed: false,
        })
    }

    fn commit(mut self, destination: &str) -> std::io::Result<()> {
        self.file.sync_all()?;
        std::fs::rename(&self.path, destination)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PrivateDownload {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
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
            // The CLI holds no previous list, so it has nothing to validate a digest
            // against and always asks unconditionally.
            if_unchanged_digest: None,
            limit: parsed.limit,
            // One-shot read: nothing here scrolls, so there is no cursor to carry.
            before_id: None,
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
        redact_message_text(message);
        flag_message_file(message);
    }
}

/// Mark a message's file attachment as credential-suspected — an additive
/// `file.credential_suspected = true` JSON field — so a routine `gram list` warns
/// before anyone downloads it. The bytes aren't fetched at list time, so this is a
/// filename heuristic only; the content scan + refusal happens on `gram get-file`.
/// refs #109
fn flag_message_file(message: &mut serde_json::Value) {
    let suspected = message
        .get("file")
        .and_then(|file| file.get("name"))
        .and_then(|name| name.as_str())
        .map(filename_suggests_credential)
        .unwrap_or(false);
    if suspected {
        if let Some(file) = message
            .get_mut("file")
            .and_then(|file| file.as_object_mut())
        {
            file.insert("credential_suspected".into(), serde_json::Value::Bool(true));
        }
    }
}

/// Redact the single echoed message body in a `result.message` response — the
/// shape `gram grab` and `gram send` return. WITHOUT this, `grab`ing a queued
/// credential (the normal claim-work flow) prints it verbatim, bypassing the
/// `list` redaction. grab/send have no `--reveal`: an agent that truly needs the
/// raw value uses `gram list --reveal`.
fn redact_message_info(response: &mut serde_json::Value) {
    if let Some(message) = response
        .get_mut("result")
        .and_then(|r| r.get_mut("message"))
    {
        redact_message_text(message);
    }
}

/// Redact the credential-looking span in one message object's `text` field, in
/// place. Leaves every other field untouched.
fn redact_message_text(message: &mut serde_json::Value) {
    if let Some(text) = message.get("text").and_then(|t| t.as_str()) {
        let redacted = redact_credentials(text);
        if redacted != text {
            message["text"] = serde_json::Value::String(redacted);
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

    let mut response = super::send_request(&Request {
        id: "cli:gram:grab".into(),
        method: Method::GramGrab(GramGrabParams {
            id,
            caller_pane_id: env_pane_id(),
            grabbed_by,
        }),
    })?;
    // Redact the echoed body: `grab` claims a queued item, whose text may hold a
    // credential — printing it raw here bypasses the `list` redaction (issue #95).
    redact_message_info(&mut response);
    super::print_response(&response)
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
fn parse_get_file_args(args: &[String]) -> Result<(String, String, bool), String> {
    let mut id: Option<String> = None;
    let mut out: Option<String> = None;
    let mut reveal = false;
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
            // Download a credential-shaped attachment anyway (default refuses it).
            // `--show-secrets` accepted for symmetry with `gram list`.
            "--reveal" | "--show-secrets" => {
                reveal = true;
                index += 1;
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
    let id = id.ok_or("usage: herdr gram get-file <id> -o PATH [--reveal]")?;
    let out = out.ok_or("usage: herdr gram get-file <id> -o PATH [--reveal]")?;
    Ok((id, out, reveal))
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

/// Filenames that strongly imply a credential file regardless of content — a
/// session/cookie file or a private-key/keystore extension. Complements the
/// content scan so a credential attachment is caught even when its bytes carry no
/// recognizable token prefix (e.g. a session cookie). refs #109
fn filename_suggests_credential(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const NAME_HINTS: &[&str] = &[
        "cookie",
        "credential",
        "secret",
        "id_rsa",
        "id_ed25519",
        "fastlane_session",
    ];
    const EXT_HINTS: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".p8", ".jks", ".keystore"];
    NAME_HINTS.iter().any(|hint| lower.contains(hint))
        || EXT_HINTS.iter().any(|ext| lower.ends_with(ext))
}

/// A JSON Web Token: a base64url header that begins `eyJ` (the encoding of `{"`),
/// then a payload, then a signature (which may be empty for `alg=none`). Session
/// tokens of this shape carry no known key prefix, so #96's prefix scanner misses
/// them. refs #109
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")
        .expect("static JWT regex is valid")
});

/// Session-cookie / cookie-jar / JWT content shapes that carry NO recognizable
/// key prefix, so #96's token/PEM detector misses them. This is the mis-named
/// session-file leak class (#109): a real session blob (Apple/fastlane cookie
/// jar, a raw `Set-Cookie` dump, a JWT) sent under an innocuous name. refs #109
fn content_has_session_or_token(text: &str) -> bool {
    if JWT_RE.is_match(text) {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "set-cookie:",
        "netscape http cookie file",
        "!ruby/object:http::cookie", // fastlane spaceship cookie jar (YAML)
        "myacinfo",                  // Apple ID web session cookie
        "x-apple-id-session-id",
        "x-apple-web-session-token",
        "dqsid", // Apple developer portal session
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Whether decoded text carries a credential, combining #96's body detector
/// (token prefixes + PEM blocks) with the session/cookie/JWT content shapes
/// above. refs #109
fn content_has_credential_shape(text: &str) -> bool {
    redact_credentials(text) != text || content_has_session_or_token(text)
}

/// Whether a bounded download chunk looks like it carries a credential — by
/// filename or by text content. Every chunk is scanned, not just the first:
/// credentials can appear anywhere in a relayed file. refs #109
fn attachment_is_credential_shaped(name: &str, bytes: &[u8]) -> bool {
    if filename_suggests_credential(name) {
        return true;
    }
    let text = String::from_utf8_lossy(bytes);
    content_has_credential_shape(&text)
}

/// Carry a short overlap across chunks so a token split by the transfer
/// boundary cannot evade the per-chunk scan. The chunk itself is bounded by
/// MAX_CHUNK_BYTES; the overlap retains at most 4 KiB.
fn should_refuse_download_chunk(
    name: &str,
    bytes: &[u8],
    reveal: bool,
    tail: &mut Vec<u8>,
) -> bool {
    if reveal {
        return false;
    }
    if should_refuse_download(name, bytes, false) {
        return true;
    }
    const OVERLAP: usize = 4096;
    if !tail.is_empty() {
        tail.extend_from_slice(&bytes[..bytes.len().min(OVERLAP)]);
        if should_refuse_download(name, tail, false) {
            return true;
        }
    }
    tail.clear();
    tail.extend_from_slice(&bytes[bytes.len().saturating_sub(OVERLAP)..]);
    false
}

/// Pure decision for `gram get-file`: refuse to write this attachment? Kept
/// separate from the imperative download (fetch/write/exit) so the make-or-break
/// composition — credential detection AND `!reveal`, not inverted — is unit-tested
/// directly, without a live socket. A regression that drops the guard or inverts
/// `reveal` turns a test red. refs #109
fn should_refuse_download(name: &str, bytes: &[u8], reveal: bool) -> bool {
    !reveal && attachment_is_credential_shaped(name, bytes)
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
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--queue" => {
                parsed.only_queue = true;
                index += 1;
            }
            "--unread" => {
                parsed.unread_only = true;
                index += 1;
            }
            "--owner" => {
                parsed.owner = true;
                index += 1;
            }
            // Print credential-looking bodies in the clear. Default is to redact them
            // (see `redact_credentials`) so a routine `gram list` can't drop a secret
            // into the reader's transcript.
            "--reveal" | "--show-secrets" => {
                parsed.reveal = true;
                index += 1;
            }
            // Newest N only. The CLI reads a terminal, where the tail of a ~870
            // message store is noise; it never pages, so there is no `--before`.
            "--limit" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --limit".into());
                };
                let limit = value
                    .parse::<usize>()
                    .map_err(|_| format!("--limit expects a positive number, got '{value}'"))?;
                if limit == 0 {
                    return Err("--limit expects a positive number, got '0'".into());
                }
                parsed.limit = Some(limit);
                index += 2;
            }
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
    limit: Option<usize>,
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
    eprintln!("  herdr gram list [--queue] [--unread] [--owner] [--reveal] [--limit N]   list messages (--owner: read as the owner; --limit: newest N only)");
    eprintln!("  herdr gram grab <id> [--as LABEL]        claim a shared queue item");
    eprintln!("  herdr gram get-file <id> -o PATH         download a message's attached file");
    eprintln!("  herdr gram relay-path <COORDINATOR_MACHINE_ID>   remote SSH socket path");
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
    eprintln!();
    eprintln!(
        "Cross-machine files: owner daemon must set HERDR_GRAM_RELAY_PEERS=<saved-peer-alias>"
    );
    eprintln!("and use a pinned saved SSH machine profile. Remote daemon must set");
    eprintln!("HERDR_GRAM_REVERSE_SOCKET=$(herdr gram relay-path <coordinator-machine-id>)");
    eprintln!("before startup. OpenSSH must allow StreamLocalForwarding and -R Unix sockets;");
    eprintln!("remote-to-coordinator SSH keys are NOT copied or required. This is trusted-machine");
    eprintln!("access: another same-user process on the trusted peer can claim a pane ID.");
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
            ("gram-1".to_string(), "/tmp/x".to_string(), false)
        );
        assert_eq!(
            parse_get_file_args(&args(&["gram-1", "--out", "/tmp/x"])).unwrap(),
            ("gram-1".to_string(), "/tmp/x".to_string(), false)
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

    /// `--limit` takes a value, so it must not swallow the flag after it or accept a
    /// non-count: a silently misparsed limit would truncate the reader's list.
    #[test]
    fn list_limit_takes_a_positive_count() {
        let parsed = parse_list_args(&args(&["--limit", "20", "--owner"])).unwrap();
        assert_eq!(parsed.limit, Some(20));
        assert!(parsed.owner);
        assert_eq!(parse_list_args(&args(&[])).unwrap().limit, None);
        assert!(parse_list_args(&args(&["--limit"])).is_err());
        assert!(parse_list_args(&args(&["--limit", "0"])).is_err());
        assert!(parse_list_args(&args(&["--limit", "many"])).is_err());
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

    // --- credential-shaped file attachments (issue #109) ---

    #[test]
    fn attachment_flagged_by_credential_content() {
        let secret = format!("ghp_{}", filler());
        let bytes = format!("export TOKEN={secret}\n").into_bytes();
        assert!(attachment_is_credential_shaped("notes.txt", &bytes));
    }

    #[test]
    fn download_refuses_credentials_after_first_chunk_and_across_boundary() {
        let secret = format!("ghp_{}", filler());
        let mut tail = Vec::new();
        let first = vec![b'a'; crate::persist::gram_files::MAX_CHUNK_BYTES];
        assert!(!should_refuse_download_chunk(
            "report.txt",
            &first,
            false,
            &mut tail
        ));
        let mut second = vec![b'b'; 300_000];
        second.extend_from_slice(format!(" {secret}\n").as_bytes());
        assert!(should_refuse_download_chunk(
            "report.txt",
            &second,
            false,
            &mut tail
        ));

        let mut tail = Vec::new();
        let mut split_first = vec![b'a'; crate::persist::gram_files::MAX_CHUNK_BYTES - 5];
        split_first.push(b' ');
        split_first.extend_from_slice(&secret.as_bytes()[..4]);
        assert!(!should_refuse_download_chunk(
            "report.txt",
            &split_first,
            false,
            &mut tail
        ));
        assert!(should_refuse_download_chunk(
            "report.txt",
            &secret.as_bytes()[4..],
            false,
            &mut tail
        ));
    }

    #[test]
    fn attachment_pem_content_flagged() {
        let begin = format!("-----BEGIN OPENSSH {} KEY-----", "PRIVATE");
        let end = format!("-----END OPENSSH {} KEY-----", "PRIVATE");
        let bytes = format!("{begin}\nAAAABG5vbmU=\n{end}\n").into_bytes();
        assert!(attachment_is_credential_shaped("attachment.txt", &bytes));
    }

    #[test]
    fn attachment_flagged_by_filename_without_token() {
        // No recognizable token in the bytes, but the name marks it a credential —
        // the session-cookie / key-file case #96's content scan can miss.
        assert!(attachment_is_credential_shaped(
            "apple-session.cookie",
            b"opaque-blob"
        ));
        assert!(attachment_is_credential_shaped("id_rsa", b"opaque-blob"));
        assert!(attachment_is_credential_shaped(
            "server.pem",
            b"opaque-blob"
        ));
        assert!(filename_suggests_credential("Deploy.p8"));
    }

    #[test]
    fn benign_attachment_not_flagged() {
        assert!(!attachment_is_credential_shaped(
            "report.txt",
            b"just some ordinary prose here, nothing secret"
        ));
        assert!(!attachment_is_credential_shaped(
            "photo.png",
            &[0u8, 159, 200, 1, 255, 42, 7]
        ));
    }

    #[test]
    fn attachment_flagged_by_jwt_content_under_benign_name() {
        // A JWT with no known key prefix, under an innocuous name and extension —
        // caught by content shape, not the filename heuristic.
        let jwt =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlF";
        assert!(attachment_is_credential_shaped("blob.dat", jwt.as_bytes()));
        assert!(!filename_suggests_credential("blob.dat"));
    }

    #[test]
    fn attachment_flagged_by_session_cookie_under_benign_name() {
        // The #109 motivating case: a fastlane/Apple session blob sent under a
        // name that trips no filename hint.
        let jar = "--- !ruby/object:HTTP::Cookie\nname: myacinfo\nvalue: DAWTKNV2opaque\n";
        assert!(attachment_is_credential_shaped("apple.txt", jar.as_bytes()));
        assert!(attachment_is_credential_shaped(
            "session.yml",
            b"Set-Cookie: dqsid=abcdef0123456789; Path=/; Secure"
        ));
        assert!(!filename_suggests_credential("apple.txt"));
        assert!(!filename_suggests_credential("session.yml"));
    }

    #[test]
    fn should_refuse_download_composes_detection_and_reveal() {
        let secret = format!("ghp_{}", filler());
        let cred = format!("token={secret}").into_bytes();
        // Credential + no reveal -> refuse.
        assert!(should_refuse_download("notes.txt", &cred, false));
        // --reveal overrides -> must NOT refuse (guards an inverted `!reveal`).
        assert!(!should_refuse_download("notes.txt", &cred, true));
        // Benign + no reveal -> allow.
        assert!(!should_refuse_download(
            "report.txt",
            b"ordinary prose, nothing secret",
            false
        ));
        // A mis-named session file (benign name, JWT content) is still refused.
        let jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlX2hlcmU";
        assert!(should_refuse_download("blob.dat", jwt, false));
    }

    #[test]
    fn get_file_parses_reveal_flag() {
        let (_, _, reveal) =
            parse_get_file_args(&args(&["gram-1", "-o", "/tmp/x", "--reveal"])).unwrap();
        assert!(reveal);
        let (_, _, reveal) = parse_get_file_args(&args(&["gram-1", "-o", "/tmp/x"])).unwrap();
        assert!(!reveal);
    }

    #[test]
    fn list_flags_credential_shaped_file_by_name() {
        let mut suspect =
            serde_json::json!({ "id": "g", "file": { "name": "apple.cookie", "size": 10 } });
        flag_message_file(&mut suspect);
        assert_eq!(
            suspect["file"]["credential_suspected"],
            serde_json::json!(true)
        );

        let mut benign =
            serde_json::json!({ "id": "g", "file": { "name": "photo.png", "size": 10 } });
        flag_message_file(&mut benign);
        assert!(benign["file"].get("credential_suspected").is_none());
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

    #[test]
    fn redact_message_info_redacts_the_grab_send_echo() {
        // grab/send return a single `result.message`, not `messages[]`. This is the
        // claim-work leak (an agent grabs a queued credential) the list fix missed.
        let secret = format!("ghp_{}", filler());
        let mut response = serde_json::json!({
            "result": {
                "message": { "id": "gram-9", "text": format!("claimed: {secret}"), "grabbed_by": "herdr-app" },
                "type": "gram_grabbed"
            }
        });
        redact_message_info(&mut response);
        let msg = &response["result"]["message"];
        assert_eq!(msg["id"], "gram-9", "ids untouched");
        assert_eq!(msg["grabbed_by"], "herdr-app", "other fields untouched");
        assert!(
            msg["text"]
                .as_str()
                .unwrap()
                .contains("[redacted credential,"),
            "the grabbed/sent body must be redacted"
        );
    }
}
