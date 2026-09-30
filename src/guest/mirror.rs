//! Guest copies of Grams kept on a Gram-relay remote. There the owner's Gram
//! lives on the coordinator, so a shared agent's Grams and a guest's own posts
//! never reach this machine's store. After a relayed send or post succeeds,
//! the gate keeps a copy here (the record and its file bytes) for the guests
//! who may see it. The owner's and the agents' views never read this store,
//! and nothing here is forwarded again.
//!
//! Copies live in `gram-mirror.json` and `gram-mirror/` beside the guest
//! store, bounded by count and bytes (oldest dropped first), and are pruned
//! when no active sharing guest can see them any more. Each record names its
//! own file, written under a fresh name before the record points at it and
//! under the store lock, so a record never points at bytes another write is
//! replacing, and a file no record names is reaped by the next prune.
//!
//! Every such relayed Gram is also recorded without its bytes in
//! `gram-witnessed.json`, even while its guest does not share the Gram, so
//! turning sharing on (again) can bring the guest's history back from the
//! coordinator.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
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

/// One kept copy: the Gram and the name of its file in `gram-mirror/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Copy {
    #[serde(flatten)]
    item: GramItem,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blob: Option<String>,
}

fn files_dir(dir: &Path) -> PathBuf {
    dir.join(FILES_DIR)
}

/// A name no other write uses: the message's digest plus a unique suffix.
fn new_blob_name(message_id: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let digest: String = Sha256::digest(message_id.as_bytes())
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{digest}-{:x}-{:x}-{:x}",
        std::process::id(),
        store::now_ms(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn load_copies(dir: &Path) -> io::Result<Vec<Copy>> {
    store::load_side(dir, MIRROR_FILE)
}

/// Runs between a copy's bytes being written and its record being saved,
/// for an add in the given directory.
#[cfg(test)]
pub(crate) type AddHook = (PathBuf, Box<dyn FnOnce() + Send>);
#[cfg(test)]
pub(crate) static DURING_ADD: std::sync::Mutex<Option<AddHook>> = std::sync::Mutex::new(None);

/// Every copy, oldest first.
pub(crate) fn load(dir: &Path) -> io::Result<Vec<GramItem>> {
    Ok(load_copies(dir)?
        .into_iter()
        .map(|copy| copy.item)
        .collect())
}

/// Every copy, oldest first, each with whether its file is there with the
/// recorded size and SHA-256 (always true for a copy without a file).
pub(crate) fn load_verified(dir: &Path) -> io::Result<Vec<(GramItem, bool)>> {
    Ok(load_copies(dir)?
        .into_iter()
        .map(|copy| {
            let intact = match (&copy.item.file, &copy.blob) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(file), Some(blob)) => {
                    std::fs::read(files_dir(dir).join(blob)).is_ok_and(|bytes| {
                        bytes.len() as u64 == file.size
                            && sha256_hex(&bytes).eq_ignore_ascii_case(&file.sha256)
                    })
                }
            };
            (copy.item, intact)
        })
        .collect())
}

/// Keep a copy of `item` with its file `bytes`, which must match the
/// recorded size and SHA-256. Replaces an earlier copy with the same id.
///
/// Under the store lock, the bytes are written under a fresh name and then
/// the record naming them is saved. A failed call removes only the file it
/// wrote and leaves an earlier copy of the same id, record and file, as it
/// was; the earlier file goes only once the new record is saved.
pub(crate) fn add(dir: &Path, item: GramItem, bytes: Option<&[u8]>) -> io::Result<()> {
    match (&item.file, bytes) {
        (None, None) => {}
        (Some(file), Some(bytes)) => {
            if bytes.len() as u64 != file.size
                || !sha256_hex(bytes).eq_ignore_ascii_case(&file.sha256)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mirrored file does not match its record",
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a file record needs its bytes",
            ))
        }
    }
    let blob = bytes.map(|_| new_blob_name(&item.id));
    let written = blob.clone();
    let updated = store::update_side(dir, MIRROR_FILE, |copies: &mut Vec<Copy>| {
        if let (Some(blob), Some(bytes)) = (&blob, bytes) {
            let installed = store::ensure_dir(&files_dir(dir))
                .and_then(|()| store::write_private(&files_dir(dir).join(blob), bytes));
            if let Err(err) = installed {
                return (Err(err), false);
            }
        }
        #[cfg(test)]
        {
            let mut hook = DURING_ADD
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if hook.as_ref().is_some_and(|(at, _)| at == dir) {
                let (_, run) = hook.take().unwrap();
                drop(hook);
                run();
            }
        }
        let mut dropped: Vec<Copy> = Vec::new();
        copies.retain(|existing| {
            let replaced = existing.item.id == item.id;
            if replaced {
                dropped.push(existing.clone());
            }
            !replaced
        });
        copies.push(Copy { item, blob });
        copies.sort_by_key(|copy| copy.item.created_unix_ms);
        let file_bytes = |copies: &[Copy]| -> u64 {
            copies
                .iter()
                .filter_map(|copy| copy.item.file.as_ref())
                .map(|file| file.size)
                .sum()
        };
        while copies.len() > MAX_ITEMS || file_bytes(copies) > MAX_FILE_BYTES {
            dropped.push(copies.remove(0));
        }
        (Ok(dropped), true)
    });
    match updated.and_then(|dropped| dropped) {
        Ok(dropped) => {
            for copy in dropped {
                remove_blob(dir, &copy);
            }
            Ok(())
        }
        Err(err) => {
            // Only the file this call wrote goes; no record names it.
            if let Some(written) = written {
                let _ = std::fs::remove_file(files_dir(dir).join(written));
            }
            Err(err)
        }
    }
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
    let blob = load_copies(dir)?
        .into_iter()
        .find(|copy| copy.item.id == message_id)
        .and_then(|copy| copy.blob)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no kept file"))?;
    let mut file = std::fs::File::open(files_dir(dir).join(blob))?;
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

/// Drop every copy `keep` rejects, with its file, and reap the files no
/// record names (left by a write that stopped before its record was saved).
pub(crate) fn prune(dir: &Path, keep: impl Fn(&GramItem) -> bool) -> io::Result<()> {
    if !dir.join(MIRROR_FILE).exists() && !files_dir(dir).exists() {
        return Ok(());
    }
    let dropped = store::update_side(dir, MIRROR_FILE, |copies: &mut Vec<Copy>| {
        // Under the lock no write is between its file and its record, so a
        // file no record names now is left over.
        let named: std::collections::HashSet<&str> = copies
            .iter()
            .filter_map(|copy| copy.blob.as_deref())
            .collect();
        if let Ok(entries) = std::fs::read_dir(files_dir(dir)) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if !named.contains(name.to_string_lossy().as_ref()) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let (kept, dropped): (Vec<_>, Vec<_>) = copies.drain(..).partition(|copy| keep(&copy.item));
        *copies = kept;
        let changed = !dropped.is_empty();
        (dropped, changed)
    })?;
    for copy in dropped {
        remove_blob(dir, &copy);
    }
    Ok(())
}

fn remove_blob(dir: &Path, copy: &Copy) {
    if let Some(blob) = &copy.blob {
        let _ = std::fs::remove_file(files_dir(dir).join(blob));
    }
}

/// The path of a copy's file, for tests that damage it.
#[cfg(test)]
pub(crate) fn file_of(dir: &Path, message_id: &str) -> Option<PathBuf> {
    load_copies(dir)
        .ok()?
        .into_iter()
        .find(|copy| copy.item.id == message_id)
        .and_then(|copy| copy.blob)
        .map(|blob| files_dir(dir).join(blob))
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

    fn files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir.join(FILES_DIR))
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every record's file is there and intact, and every file is named by
    /// a record.
    fn assert_consistent(dir: &Path) {
        let copies = load_copies(dir).unwrap();
        let named: Vec<String> = copies.iter().filter_map(|copy| copy.blob.clone()).collect();
        let mut on_disk = files(dir);
        on_disk.sort();
        let mut expected = named.clone();
        expected.sort();
        assert_eq!(
            on_disk, expected,
            "files on disk are exactly the named ones"
        );
        for (item, intact) in load_verified(dir).unwrap() {
            assert!(intact, "{} has its file", item.id);
        }
    }

    #[test]
    fn a_copy_that_cannot_be_recorded_leaves_no_file() {
        let dir = store::tests::TempDir::new("mirror-orphan");
        store::ensure_dir(&dir.0).unwrap();
        store::write_private(&dir.0.join(MIRROR_FILE), b"not json").unwrap();
        assert!(add(&dir.0, item_with_file(b"hello"), Some(b"hello")).is_err());
        assert!(files(&dir.0).is_empty(), "{:?}", files(&dir.0));

        std::fs::remove_file(dir.0.join(MIRROR_FILE)).unwrap();
        add(&dir.0, item_with_file(b"hello"), Some(b"hello")).unwrap();
        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
        assert_consistent(&dir.0);
        remove(&dir.0, "relay-1").unwrap();
        assert!(files(&dir.0).is_empty());
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

        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
        assert_consistent(&dir.0);

        // Again, failing only when saving the record, after the new file was
        // written: the new file goes, the kept one stays.
        let blocker = dir.0.join(MIRROR_FILE).with_extension("tmp");
        std::fs::create_dir(&blocker).unwrap();
        assert!(add(&dir.0, item_with_file(b"hello"), Some(b"hello")).is_err());
        std::fs::remove_dir(&blocker).unwrap();
        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
        assert_consistent(&dir.0);

        // A successful retry replaces the file and drops the earlier one.
        add(&dir.0, item_with_file(b"hello"), Some(b"hello")).unwrap();
        assert_eq!(files(&dir.0).len(), 1);
        assert_consistent(&dir.0);
    }

    #[test]
    fn a_file_left_by_an_interrupted_write_is_reaped() {
        let dir = store::tests::TempDir::new("mirror-crash");
        add(&dir.0, item_with_file(b"hello"), Some(b"hello")).unwrap();
        // A write that stopped after its file, before its record.
        std::fs::write(dir.0.join(FILES_DIR).join("left-over"), b"hello").unwrap();
        prune(&dir.0, |_| true).unwrap();
        assert_consistent(&dir.0);
        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
    }

    #[test]
    fn a_prune_during_an_add_leaves_every_file_named() {
        let dir = store::tests::TempDir::new("mirror-race");
        store::ensure_dir(&dir.0).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let pruner_dir = dir.0.clone();
        *DURING_ADD.lock().unwrap() = Some((
            dir.0.clone(),
            Box::new(move || {
                // Between the add's file and its record, a prune starts.
                let handle = std::thread::spawn(move || prune(&pruner_dir, |_| true).unwrap());
                std::thread::sleep(std::time::Duration::from_millis(200));
                tx.send(handle).unwrap();
            }),
        ));
        add(&dir.0, item_with_file(b"hello"), Some(b"hello")).unwrap();
        rx.recv().unwrap().join().unwrap();
        assert_consistent(&dir.0);
        assert_eq!(read_file(&dir.0, "relay-1", 0, 5).unwrap(), b"hello");
    }
}
