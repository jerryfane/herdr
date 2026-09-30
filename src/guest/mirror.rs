//! Guest copies of Grams kept on a Gram-relay remote. There the owner's Gram
//! lives on the coordinator, so a shared agent's Grams and a guest's own posts
//! never reach this machine's store. After a relayed send or post succeeds,
//! the gate keeps a copy here (the record and its file bytes) for the guests
//! who may see it. The owner's and the agents' views never read this store,
//! and nothing here is forwarded again.
//!
//! Copies live in `gram-mirror.json` and `gram-mirror/` beside the guest
//! store, bounded by count and bytes (oldest dropped first), and are pruned
//! when no active sharing guest can see them any more.
//!
//! Every such relayed Gram is also recorded without its bytes in
//! `gram-witnessed.json`, even while its guest does not share the Gram, so
//! turning sharing on (again) can bring the guest's history back from the
//! coordinator.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::persist::gram::GramItem;

use super::store;

const MIRROR_FILE: &str = "gram-mirror.json";
const FILES_DIR: &str = "gram-mirror";
/// Records (no bytes) of the Grams relayed for guests; see [`witnessed`].
const WITNESS_FILE: &str = "gram-witnessed.json";
/// Most copies kept.
const MAX_ITEMS: usize = 500;
/// Most file bytes kept across all copies.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

fn file_path(dir: &Path, message_id: &str) -> PathBuf {
    let digest: String = Sha256::digest(message_id.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    dir.join(FILES_DIR).join(digest)
}

/// Every copy, oldest first.
pub(crate) fn load(dir: &Path) -> io::Result<Vec<GramItem>> {
    store::load_side(dir, MIRROR_FILE)
}

/// Keep a copy of `item` with its file `bytes`, which must match the
/// recorded size and SHA-256. Replaces an earlier copy with the same id. The
/// bytes are staged beside the store and take the copy's place only once its
/// record is saved, so a failed call leaves an earlier copy of the same id,
/// record and file, as it was.
pub(crate) fn add(dir: &Path, item: GramItem, bytes: Option<&[u8]>) -> io::Result<()> {
    let staged = match (&item.file, bytes) {
        (None, None) => None,
        (Some(file), Some(bytes)) => {
            let digest: String = Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            if bytes.len() as u64 != file.size || !digest.eq_ignore_ascii_case(&file.sha256) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mirrored file does not match its record",
                ));
            }
            store::ensure_dir(&dir.join(FILES_DIR))?;
            let staged = staging_path(dir, &item.id);
            store::write_private(&staged, bytes)?;
            Some(staged)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a file record needs its bytes",
            ))
        }
    };
    let final_path = file_path(dir, &item.id);
    let updated = store::update_side(dir, MIRROR_FILE, |items: &mut Vec<GramItem>| {
        items.retain(|existing| existing.id != item.id);
        items.push(item);
        items.sort_by_key(|item| item.created_unix_ms);
        let mut evicted = Vec::new();
        let file_bytes = |items: &[GramItem]| -> u64 {
            items
                .iter()
                .filter_map(|item| item.file.as_ref())
                .map(|file| file.size)
                .sum()
        };
        while items.len() > MAX_ITEMS || file_bytes(items) > MAX_FILE_BYTES {
            evicted.push(items.remove(0));
        }
        (evicted, true)
    });
    let evicted = match updated {
        Ok(evicted) => evicted,
        Err(err) => {
            // Only the bytes this call staged go; an earlier copy stays.
            if let Some(staged) = &staged {
                let _ = std::fs::remove_file(staged);
            }
            return Err(err);
        }
    };
    if let Some(staged) = &staged {
        if let Err(err) = std::fs::rename(staged, &final_path) {
            let _ = std::fs::remove_file(staged);
            return Err(err);
        }
    }
    for item in evicted {
        remove_file(dir, &item);
    }
    Ok(())
}

/// A unique staging path for a copy's bytes, in the copies' directory.
fn staging_path(dir: &Path, message_id: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut path = file_path(dir, message_id).into_os_string();
    path.push(format!(
        ".{}-{}.part",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    PathBuf::from(path)
}

/// Record that this machine relayed `item` from a pane a guest's grant names
/// (see `witnessed`). Kept whether or not the guest shares the Gram now.
pub(crate) fn witness(dir: &Path, item: GramItem) -> io::Result<()> {
    let item = GramItem {
        read_by_owner: false,
        ..item
    };
    store::update_side(dir, WITNESS_FILE, |items: &mut Vec<GramItem>| {
        items.retain(|existing| existing.id != item.id);
        items.push(item);
        items.sort_by_key(|item| item.created_unix_ms);
        while items.len() > MAX_ITEMS {
            items.remove(0);
        }
        ((), true)
    })
}

/// Grams this machine relayed to the coordinator for a guest's shared agent
/// or from a guest: the agents' sends with the sender binding taken from the
/// pane that sent them, and the guests' own posts. Only these are brought
/// back from the coordinator when Gram sharing is turned on (again).
pub(crate) fn witnessed(dir: &Path) -> io::Result<Vec<GramItem>> {
    if !dir.join(WITNESS_FILE).exists() {
        return Ok(Vec::new());
    }
    store::load_side(dir, WITNESS_FILE)
}

/// Forget every witnessed Gram `keep` rejects.
pub(crate) fn forget_witnessed(dir: &Path, keep: impl Fn(&GramItem) -> bool) -> io::Result<()> {
    if !dir.join(WITNESS_FILE).exists() {
        return Ok(());
    }
    store::update_side(dir, WITNESS_FILE, |items: &mut Vec<GramItem>| {
        let before = items.len();
        items.retain(|item| keep(item));
        ((), items.len() != before)
    })
}

/// The copy with this id, if kept.
pub(crate) fn get(dir: &Path, message_id: &str) -> Option<GramItem> {
    load(dir)
        .ok()?
        .into_iter()
        .find(|item| item.id == message_id)
}

/// `len` bytes of a copy's file from `offset` (fewer at its end).
pub(crate) fn read_file(
    dir: &Path,
    message_id: &str,
    offset: u64,
    len: u64,
) -> io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = std::fs::File::open(file_path(dir, message_id))?;
    let length = file.metadata()?.len();
    if offset > length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file offset exceeds size",
        ));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; len.min(length - offset) as usize];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Drop the copy of `message_id`, if kept.
pub(crate) fn remove(dir: &Path, message_id: &str) -> io::Result<()> {
    prune(dir, |item| item.id != message_id)
}

/// Drop every copy `keep` rejects, with its file.
pub(crate) fn prune(dir: &Path, keep: impl Fn(&GramItem) -> bool) -> io::Result<()> {
    if !dir.join(MIRROR_FILE).exists() {
        return Ok(());
    }
    let dropped = store::update_side(dir, MIRROR_FILE, |items: &mut Vec<GramItem>| {
        let (kept, dropped): (Vec<_>, Vec<_>) = items.drain(..).partition(|item| keep(item));
        *items = kept;
        let changed = !dropped.is_empty();
        (dropped, changed)
    })?;
    for item in dropped {
        remove_file(dir, &item);
    }
    Ok(())
}

fn remove_file(dir: &Path, item: &GramItem) {
    if item.file.is_some() {
        let _ = std::fs::remove_file(file_path(dir, &item.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::gram::{GramDirection, GramFile};

    fn item_with_file(bytes: &[u8]) -> GramItem {
        let sha: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        GramItem {
            id: "relay-1".into(),
            direction: GramDirection::AgentToOwner,
            from: "llm-opt".into(),
            to: None,
            text: String::new(),
            grabbed_by: None,
            grabbed_unix_ms: None,
            created_unix_ms: 1,
            read_by_owner: false,
            file: Some(GramFile {
                name: "a.txt".into(),
                size: bytes.len() as u64,
                mime: "text/plain".into(),
                sha256: sha,
            }),
            origin_id: String::new(),
            sender: None,
        }
    }

    #[test]
    fn a_copy_that_cannot_be_recorded_leaves_no_file() {
        let dir = store::tests::TempDir::new("mirror-orphan");
        store::ensure_dir(&dir.0).unwrap();
        store::write_private(&dir.0.join(MIRROR_FILE), b"not json").unwrap();
        assert!(add(&dir.0, item_with_file(b"hello"), Some(b"hello")).is_err());
        assert_eq!(
            files(&dir.0),
            Vec::<String>::new(),
            "nothing staged is left"
        );

        std::fs::remove_file(dir.0.join(MIRROR_FILE)).unwrap();
        add(&dir.0, item_with_file(b"hello"), Some(b"hello")).unwrap();
        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
        remove(&dir.0, "relay-1").unwrap();
        assert!(!file_path(&dir.0, "relay-1").exists());
    }

    fn files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir.join(FILES_DIR))
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn a_failed_retry_of_a_kept_copy_keeps_its_file() {
        let dir = store::tests::TempDir::new("mirror-retry");
        add(&dir.0, item_with_file(b"hello"), Some(b"hello")).unwrap();
        let record = std::fs::read(dir.0.join(MIRROR_FILE)).unwrap();

        // The same message again, while its record cannot be written.
        store::write_private(&dir.0.join(MIRROR_FILE), b"not json").unwrap();
        assert!(add(&dir.0, item_with_file(b"hello"), Some(b"hello")).is_err());
        store::write_private(&dir.0.join(MIRROR_FILE), &record).unwrap();

        assert_eq!(get(&dir.0, "relay-1").unwrap().id, "relay-1");
        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
        assert_eq!(
            files(&dir.0).len(),
            1,
            "only the kept file: {:?}",
            files(&dir.0)
        );
    }
}
