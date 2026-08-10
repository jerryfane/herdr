//! Blob store for gram file attachments.
//!
//! A gram message may carry one file. The bytes live under
//! `config_dir()/gram-files/<message-id>/<name>`, kept out of the JSON message
//! store ([`crate::persist::gram`]) so a large attachment never bloats gram.json
//! or its per-message text budget.
//!
//! Uploads are chunked. The app's request path over SSH caps a single request
//! near 65 KiB and the daemon caps any request line at 1 MiB, so a client cannot
//! send a multi-megabyte file inline. Instead it appends the file in chunks to a
//! per-upload staging file ([`append_chunk`]); the send/post handler then
//! assembles that staging file onto a freshly minted message id ([`finalize`]).
//! Download is a single response ([`read_message_file`]) because the reply path is
//! not size-capped.
//!
//! Security: gram is meant to carry short-lived secrets (a temporary API key sent
//! as a file), so every directory is `0o700`, every file `0o600`, upload ids and
//! message ids are validated to a safe single path component, the display name is
//! reduced to a sanitized basename (no traversal), and deleting a message removes
//! its bytes. Stale staging files (an upload whose send never arrived) are swept
//! after a TTL. The trust domain is otherwise flat — the same as gram.json — so
//! read access is bounded by filesystem ownership, not per-caller authorization.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Hard cap on a single attachment. Large enough for screenshots, logs, and small
/// docs; small enough that assembling one in memory for download stays cheap.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Upper bound on one upload chunk's decoded payload, enforced server-side so a
/// client cannot bypass it. Chosen so the base64-encoded request line stays under
/// the daemon's 1 MiB cap. The app self-limits well below this (its SSH command
/// budget forces ~64 KiB raw chunks); the CLI over the local socket may use the
/// full size for fewer round-trips.
pub const MAX_CHUNK_BYTES: usize = 512 * 1024;

/// Staging files older than this are swept — an upload whose send never arrived.
const STAGING_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Longest accepted path component (upload id, message id, stored file name).
const MAX_COMPONENT_LEN: usize = 128;

fn config_base() -> PathBuf {
    crate::config::config_dir()
}

fn gram_files_dir_in(dir: &Path) -> PathBuf {
    dir.join("gram-files")
}

fn staging_dir_in(dir: &Path) -> PathBuf {
    gram_files_dir_in(dir).join(".staging")
}

fn message_dir_in(dir: &Path, message_id: &str) -> Option<PathBuf> {
    let safe = safe_component(message_id)?;
    Some(gram_files_dir_in(dir).join(safe))
}

fn staging_path_in(dir: &Path, upload_id: &str) -> Option<PathBuf> {
    let safe = safe_component(upload_id)?;
    Some(staging_dir_in(dir).join(safe))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

/// A single safe path component: non-empty, bounded, ASCII `[A-Za-z0-9._-]`, and
/// never `.`/`..` or containing a `..` run. Used for the server-minted message id
/// and the client-supplied upload id, so neither can escape the store directory.
fn safe_component(value: &str) -> Option<&str> {
    if value.is_empty() || value.len() > MAX_COMPONENT_LEN {
        return None;
    }
    if value == "." || value == ".." || value.contains("..") {
        return None;
    }
    let ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    ok.then_some(value)
}

/// Reduce a client-supplied file name to a safe basename for storage and display.
/// [`Path::file_name`] strips any directory parts (so `../../etc/passwd` becomes
/// `passwd`), then control and separator characters are replaced and the length is
/// bounded. Falls back to `"file"` when nothing safe remains.
pub fn safe_file_name(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|component| component.to_str())
        .unwrap_or("");
    let mut cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect();
    cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "file".to_string();
    }
    if cleaned.len() > MAX_COMPONENT_LEN {
        cleaned = cleaned.chars().take(MAX_COMPONENT_LEN).collect();
    }
    cleaned
}

fn ensure_dir_restricted(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    restrict_dir_permissions(dir)
}

/// Append one decoded chunk to an upload's staging file.
///
/// `offset` is the byte position this chunk must start at — the current staged
/// size — so a dropped or reordered chunk is rejected immediately instead of
/// silently corrupting the assembled file. `offset == 0` (re)starts the upload by
/// truncating any existing staging file. Rejects a chunk larger than
/// [`MAX_CHUNK_BYTES`] or one that would push the staged size past
/// [`MAX_FILE_BYTES`].
pub fn append_chunk(upload_id: &str, offset: u64, bytes: &[u8]) -> io::Result<()> {
    append_chunk_in(&config_base(), upload_id, offset, bytes)
}

fn append_chunk_in(dir: &Path, upload_id: &str, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let Some(path) = staging_path_in(dir, upload_id) else {
        return Err(invalid("invalid upload id"));
    };
    if bytes.len() > MAX_CHUNK_BYTES {
        return Err(invalid("upload chunk is too large"));
    }
    let staging = staging_dir_in(dir);
    ensure_dir_restricted(&staging)?;
    cleanup_stale(&staging);

    let current = match fs::metadata(&path) {
        Ok(metadata) => metadata.len(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => 0,
        Err(err) => return Err(err),
    };
    if offset != 0 && offset != current {
        return Err(invalid(
            "upload chunk offset does not match the staged size; resend from offset 0",
        ));
    }
    if offset.saturating_add(bytes.len() as u64) > MAX_FILE_BYTES {
        return Err(invalid("file exceeds the size limit"));
    }

    let mut options = fs::OpenOptions::new();
    if offset == 0 {
        options.write(true).create(true).truncate(true);
    } else {
        options.append(true);
    }
    restrict_file_options(&mut options);
    let mut file = options.open(&path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// Metadata for an assembled attachment: the stored (sanitized) name, byte size,
/// and hex SHA-256 so a client can verify the assembled bytes match its upload.
pub struct FinalizedFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Assemble a staged upload onto a message: verify the staging file, move it to
/// `gram-files/<message_id>/<name>`, and return its size + sha256. The caller mints
/// `message_id` before appending the message so the bytes and record share an id.
/// The staging file is consumed (renamed) on success.
pub fn finalize(message_id: &str, upload_id: &str, name: &str) -> io::Result<FinalizedFile> {
    finalize_in(&config_base(), message_id, upload_id, name)
}

fn finalize_in(
    dir: &Path,
    message_id: &str,
    upload_id: &str,
    name: &str,
) -> io::Result<FinalizedFile> {
    let Some(staging) = staging_path_in(dir, upload_id) else {
        return Err(invalid("invalid upload id"));
    };
    let Some(target_dir) = message_dir_in(dir, message_id) else {
        return Err(invalid("invalid message id"));
    };

    // Sweep abandoned staging on send too, not only on the next upload chunk, so
    // any gram file activity — an upload OR a completed send — bounds how long a
    // never-finished upload's bytes linger. (A store with zero further gram file
    // activity, or a crash between this rename and the message append, can still
    // strand bytes; a startup reconciler is tracked as a follow-up.)
    cleanup_stale(&staging_dir_in(dir));

    let metadata = fs::metadata(&staging).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            invalid("no staged upload with that id; upload the file chunks first")
        } else {
            err
        }
    })?;
    let size = metadata.len();
    if size == 0 {
        return Err(invalid("staged upload is empty"));
    }
    if size > MAX_FILE_BYTES {
        return Err(invalid("file exceeds the size limit"));
    }

    let sha256 = sha256_of_file(&staging)?;
    let safe_name = safe_file_name(name);

    ensure_dir_restricted(&target_dir)?;
    let target = target_dir.join(&safe_name);
    // The staging file and the message dir are both under `config_dir()`, so a
    // rename stays on one filesystem and is atomic. It also preserves the 0o600
    // mode set when staging began.
    fs::rename(&staging, &target)?;

    Ok(FinalizedFile {
        name: safe_name,
        size,
        sha256,
    })
}

/// Read an assembled attachment's bytes for download. The reply path is not
/// size-capped, so the whole file is returned in one response.
pub fn read_message_file(message_id: &str, name: &str) -> io::Result<Vec<u8>> {
    read_message_file_in(&config_base(), message_id, name)
}

fn read_message_file_in(dir: &Path, message_id: &str, name: &str) -> io::Result<Vec<u8>> {
    let Some(target_dir) = message_dir_in(dir, message_id) else {
        return Err(invalid("invalid message id"));
    };
    let safe_name = safe_file_name(name);
    fs::read(target_dir.join(safe_name))
}

/// Remove a message's attachment directory and its bytes. Best-effort: a missing
/// directory (the message had no file) is not an error. Called when a message is
/// deleted or evicted so no secret bytes outlive the record.
pub fn remove_message_files(message_id: &str) {
    remove_message_files_in(&config_base(), message_id);
}

pub fn remove_message_files_in(dir: &Path, message_id: &str) {
    if let Some(target_dir) = message_dir_in(dir, message_id) {
        let _ = fs::remove_dir_all(target_dir);
    }
}

fn sha256_of_file(path: &Path) -> io::Result<String> {
    // Attachments are capped at MAX_FILE_BYTES, so reading one to hash is cheap.
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

fn cleanup_stale(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if modified.elapsed().unwrap_or_default() > STAGING_MAX_AGE {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(unix)]
fn restrict_file_options(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(windows)]
fn restrict_file_options(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn restrict_dir_permissions(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn restrict_dir_permissions(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "herdr-gram-files-test-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn safe_component_rejects_traversal_and_bad_chars() {
        assert!(safe_component("gram-abc123").is_some());
        assert!(safe_component("upload_1.part").is_some());
        assert!(safe_component("").is_none());
        assert!(safe_component(".").is_none());
        assert!(safe_component("..").is_none());
        assert!(safe_component("a/b").is_none());
        assert!(safe_component("../etc").is_none());
        assert!(safe_component("a..b").is_none());
        assert!(safe_component("space here").is_none());
        assert!(safe_component(&"x".repeat(MAX_COMPONENT_LEN + 1)).is_none());
    }

    #[test]
    fn safe_file_name_strips_directories_and_traversal() {
        assert_eq!(safe_file_name("shot.png"), "shot.png");
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("a/b/c.txt"), "c.txt");
        assert_eq!(safe_file_name(".."), "file");
        assert_eq!(safe_file_name("/"), "file");
        assert_eq!(safe_file_name(""), "file");
        assert_eq!(safe_file_name("bad\u{0000}name.bin"), "bad_name.bin");
    }

    #[test]
    fn chunked_upload_assembles_and_hashes() {
        let dir = unique_temp_dir("assemble");
        let upload = "up-1";
        append_chunk_in(&dir, upload, 0, b"hello ").unwrap();
        append_chunk_in(&dir, upload, 6, b"world").unwrap();

        let finalized = finalize_in(&dir, "gram-msg-1", upload, "greeting.txt").unwrap();
        assert_eq!(finalized.name, "greeting.txt");
        assert_eq!(finalized.size, 11);
        // sha256("hello world")
        assert_eq!(
            finalized.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let read = read_message_file_in(&dir, "gram-msg-1", "greeting.txt").unwrap();
        assert_eq!(read, b"hello world");

        // Staging is consumed on finalize.
        assert!(staging_path_in(&dir, upload)
            .map(|p| !p.exists())
            .unwrap_or(false));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn out_of_order_chunk_is_rejected() {
        let dir = unique_temp_dir("order");
        append_chunk_in(&dir, "up-2", 0, b"abc").unwrap();
        // Next chunk must start at offset 3, not 10.
        let err = append_chunk_in(&dir, "up-2", 10, b"def").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chunk_larger_than_cap_is_rejected() {
        let dir = unique_temp_dir("chunkcap");
        let too_big = vec![0_u8; MAX_CHUNK_BYTES + 1];
        let err = append_chunk_in(&dir, "up-3", 0, &too_big).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn total_size_cap_rejects_exceeding_max_file_bytes() {
        let dir = unique_temp_dir("totalcap");
        // Fill the staged file exactly to the cap in MAX_CHUNK_BYTES steps, each at
        // the matching offset (MAX_FILE_BYTES is an exact multiple of the chunk).
        let chunk = vec![0_u8; MAX_CHUNK_BYTES];
        let mut offset: u64 = 0;
        while offset < MAX_FILE_BYTES {
            append_chunk_in(&dir, "big", offset, &chunk).unwrap();
            offset += MAX_CHUNK_BYTES as u64;
        }
        assert_eq!(
            offset, MAX_FILE_BYTES,
            "the cap must be a whole number of chunks"
        );
        // One more byte, at the offset that MATCHES the staged size, so this hits
        // the total-size check — not the offset-continuation check — and is
        // rejected as exceeding the limit.
        let err = append_chunk_in(&dir, "big", MAX_FILE_BYTES, b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("size limit"),
            "expected a size-cap error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_requires_nonempty_staged_upload() {
        let dir = unique_temp_dir("empty");
        // No chunks uploaded for this id.
        assert!(finalize_in(&dir, "gram-msg-x", "missing", "x.txt").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_message_files_deletes_bytes() {
        let dir = unique_temp_dir("remove");
        append_chunk_in(&dir, "up-5", 0, b"secret-key").unwrap();
        finalize_in(&dir, "gram-msg-2", "up-5", "key.txt").unwrap();
        assert!(read_message_file_in(&dir, "gram-msg-2", "key.txt").is_ok());

        remove_message_files_in(&dir, "gram-msg-2");
        assert!(read_message_file_in(&dir, "gram-msg-2", "key.txt").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
