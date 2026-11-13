//! Cache of Gram image thumbnails ([`crate::gram_thumbnail`]).
//!
//! Previews live at `state_dir()/gram-thumbs/<sha256>/<max_px>.jpg`, keyed by
//! the attachment's SHA-256 so two messages carrying the same image share one.
//! They are derived data: a lost or evicted file is rendered again on the next
//! request. The cache is bounded by [`MAX_CACHE_BYTES`]; each write evicts the
//! least recently used previews (a hit refreshes the file's mtime) beyond it.
//!
//! A preview is only ever served after the caller was authorized for a live
//! message whose file has that hash. Like the attachment bytes themselves
//! ([`crate::persist::gram_files`]), the previews of an attachment go when the
//! last message holding it is deleted or loses it to the store's file budget
//! ([`forget`], called by [`crate::persist::gram`]), so a deleted secret leaves
//! no picture of itself behind. Directories are `0o700`, files `0o600`.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Cap on all cached previews together. At 20-60 KB each that is over a
/// thousand images.
pub const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024;

fn cache_dir() -> PathBuf {
    crate::config::state_dir().join("gram-thumbs")
}

fn entry_path(root: &Path, sha256: &str, max_px: u32) -> Option<PathBuf> {
    is_sha256_hex(sha256).then(|| root.join(sha256).join(format!("{max_px}.jpg")))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The cached preview of the attachment `sha256` at `max_px`.
pub fn get(sha256: &str, max_px: u32) -> Option<Vec<u8>> {
    get_in(&cache_dir(), sha256, max_px)
}

/// Caches `jpeg` as the preview of `sha256` at `max_px`, then trims the cache
/// to [`MAX_CACHE_BYTES`]. A failure only costs a later re-render.
pub fn put(sha256: &str, max_px: u32, jpeg: &[u8]) {
    let root = cache_dir();
    if let Err(err) = put_in(&root, sha256, max_px, jpeg) {
        tracing::warn!(err = %err, "could not cache a gram thumbnail");
        return;
    }
    trim_in(&root, MAX_CACHE_BYTES);
}

/// Drops every cached preview of the attachment `sha256`.
pub fn forget(sha256: &str) {
    forget_in(&cache_dir(), sha256);
}

fn get_in(root: &Path, sha256: &str, max_px: u32) -> Option<Vec<u8>> {
    let path = entry_path(root, sha256, max_px)?;
    let bytes = fs::read(&path).ok()?;
    // Recently used: the last to go when the cache is trimmed.
    if let Ok(file) = fs::File::options().write(true).open(&path) {
        let _ = file.set_modified(SystemTime::now());
    }
    Some(bytes)
}

fn put_in(root: &Path, sha256: &str, max_px: u32, jpeg: &[u8]) -> io::Result<()> {
    let path = entry_path(root, sha256, max_px)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a sha256"))?;
    let dir = path.parent().expect("an entry sits in its hash directory");
    create_private_dir(root)?;
    create_private_dir(dir)?;
    // Concurrent renders of one preview each write their own temporary file;
    // the rename makes whichever finishes last the entry, whole.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{max_px}.{}.{n}.tmp", std::process::id()));
    let written = private_file(&tmp)
        .and_then(|mut file| file.write_all(jpeg))
        .and_then(|()| fs::rename(&tmp, &path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

fn forget_in(root: &Path, sha256: &str) {
    if is_sha256_hex(sha256) {
        let _ = fs::remove_dir_all(root.join(sha256));
    }
}

/// Deletes the least recently used previews until the cache holds at most
/// `cap` bytes, and hash directories left empty.
fn trim_in(root: &Path, cap: u64) {
    let Ok(dirs) = fs::read_dir(root) else {
        return;
    };
    let mut entries = Vec::new();
    let mut total = 0u64;
    for dir in dirs.flatten() {
        let Ok(files) = fs::read_dir(dir.path()) else {
            continue;
        };
        for file in files.flatten() {
            let Ok(meta) = file.metadata() else {
                continue;
            };
            total += meta.len();
            let used = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            entries.push((used, meta.len(), file.path()));
        }
    }
    if total <= cap {
        return;
    }
    entries.sort_by_key(|(used, _, _)| *used);
    for (_, len, path) in entries {
        if total <= cap {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
            if let Some(dir) = path.parent() {
                // Only succeeds once the directory is empty.
                let _ = fs::remove_dir(dir);
            }
        }
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn private_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::File::options();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn temp_root(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "herdr-gram-thumbs-test-{}-{tag}-{n}",
            std::process::id()
        ))
    }

    fn sha(fill: char) -> String {
        std::iter::repeat_n(fill, 64).collect()
    }

    #[test]
    fn put_then_get_round_trips_per_size() {
        let root = temp_root("roundtrip");
        put_in(&root, &sha('a'), 256, b"small").unwrap();
        put_in(&root, &sha('a'), 512, b"large").unwrap();
        assert_eq!(get_in(&root, &sha('a'), 256).as_deref(), Some(&b"small"[..]));
        assert_eq!(get_in(&root, &sha('a'), 512).as_deref(), Some(&b"large"[..]));
        assert_eq!(get_in(&root, &sha('b'), 256), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&root.join(sha('a'))), 0o700);
            assert_eq!(mode(&root.join(sha('a')).join("256.jpg")), 0o600);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_key_that_is_not_a_sha256_names_no_file() {
        let root = temp_root("unsafe");
        assert!(put_in(&root, "../escape", 256, b"x").is_err());
        assert!(put_in(&root, &sha('A'), 256, b"x").is_err());
        assert_eq!(get_in(&root, "../escape", 256), None);
        forget_in(&root, "..");
        assert!(!root.exists());
    }

    #[test]
    fn forget_drops_every_size_of_one_attachment() {
        let root = temp_root("forget");
        put_in(&root, &sha('a'), 256, b"one").unwrap();
        put_in(&root, &sha('a'), 512, b"two").unwrap();
        put_in(&root, &sha('b'), 256, b"other").unwrap();
        forget_in(&root, &sha('a'));
        assert!(!root.join(sha('a')).exists());
        assert_eq!(get_in(&root, &sha('b'), 256).as_deref(), Some(&b"other"[..]));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn trim_evicts_the_least_recently_used_first() {
        let root = temp_root("trim");
        let old = SystemTime::now() - Duration::from_secs(3600);
        for (index, fill) in ['a', 'b', 'c'].into_iter().enumerate() {
            put_in(&root, &sha(fill), 256, &[0; 100]).unwrap();
            let path = entry_path(&root, &sha(fill), 256).unwrap();
            let used = old + Duration::from_secs(index as u64 * 60);
            fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(used)
                .unwrap();
        }
        // A hit makes the oldest the most recently used.
        assert!(get_in(&root, &sha('a'), 256).is_some());
        trim_in(&root, 200);
        assert!(get_in(&root, &sha('a'), 256).is_some());
        assert!(!root.join(sha('b')).exists(), "the least recently used goes, with its directory");
        assert!(get_in(&root, &sha('c'), 256).is_some());
        let _ = fs::remove_dir_all(&root);
    }
}
