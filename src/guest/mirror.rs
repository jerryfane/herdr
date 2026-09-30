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

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::persist::gram::GramItem;

use super::store;

const MIRROR_FILE: &str = "gram-mirror.json";
const FILES_DIR: &str = "gram-mirror";
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
/// recorded size and SHA-256. Replaces an earlier copy with the same id.
pub(crate) fn add(dir: &Path, item: GramItem, bytes: Option<&[u8]>) -> io::Result<()> {
    match (&item.file, bytes) {
        (None, None) => {}
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
            let path = file_path(dir, &item.id);
            store::ensure_dir(&dir.join(FILES_DIR))?;
            store::write_private(&path, bytes)?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a file record needs its bytes",
            ))
        }
    }
    let id = item.id.clone();
    let has_file = item.file.is_some();
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
            // The record was not kept: do not leave its bytes behind,
            // outside the byte budget.
            if has_file {
                let _ = std::fs::remove_file(file_path(dir, &id));
            }
            return Err(err);
        }
    };
    for item in evicted {
        remove_file(dir, &item);
    }
    Ok(())
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
        assert!(!file_path(&dir.0, "relay-1").exists());

        std::fs::remove_file(dir.0.join(MIRROR_FILE)).unwrap();
        add(&dir.0, item_with_file(b"hello"), Some(b"hello")).unwrap();
        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
        remove(&dir.0, "relay-1").unwrap();
        assert!(!file_path(&dir.0, "relay-1").exists());
    }
}
