//! Agent profile pictures, keyed by stable terminal id.
//!
//! The descriptor index lives at `config_dir()/agent-avatars/index.json` and
//! uploaded images at `agent-avatars/<sha256>`, content-addressed so clients
//! cache them forever. The index is kept apart from the session snapshot so an
//! avatar survives restart, rename and archive/unarchive (the terminal id is
//! stable across all of them) and `agent.forget` drops it explicitly.
//!
//! The daemon holds the index in memory for `agent.list`. Every mutation is a
//! read-modify-write under `.index.lock`, so a live-handoff daemon sharing the
//! directory never loses the other's change, and ends by deleting every blob no
//! entry references: a replaced or cleared image, a forgotten agent's image, and
//! a blob left behind by a crash before its index write. Files are owner-only
//! (`0600`, directory `0700`), like the rest of the config dir's private stores.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::schema::{AgentAvatar, AgentAvatarStyle};

/// Largest accepted image, decoded. A 256x256 JPEG is 20-40 KB.
pub const MAX_IMAGE_BYTES: usize = 64 * 1024;

const INDEX_FILE: &str = "index.json";
const LOCK_FILE: &str = ".index.lock";

#[derive(Debug, Default, Serialize, Deserialize)]
struct IndexFile {
    #[serde(default)]
    agents: BTreeMap<String, AgentAvatar>,
}

/// Why a picture was refused.
#[derive(Debug)]
pub enum AvatarError {
    /// The request itself is malformed (mascot id, image type).
    Invalid(String),
    /// The decoded image exceeds [`MAX_IMAGE_BYTES`].
    TooLarge(usize),
    Io(io::Error),
}

impl From<io::Error> for AvatarError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// `^[a-z0-9-]{1,32}$`: any future bundled mascot, nothing path-like.
pub fn valid_mascot_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The image type from its magic bytes; only JPEG and PNG are pictures.
pub fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("image/png")
    } else {
        None
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

pub struct AgentAvatarStore {
    root: PathBuf,
    agents: BTreeMap<String, AgentAvatar>,
}

impl AgentAvatarStore {
    /// The production location, `config_dir()/agent-avatars`.
    pub fn default_root() -> PathBuf {
        crate::config::config_dir().join("agent-avatars")
    }

    /// A unique, not-yet-created root under the temp dir, for a daemon that
    /// does not persist its session (tests).
    pub fn ephemeral_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "herdr-agent-avatars-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    /// Load the index under `root`. Lenient: a missing or unreadable index is
    /// empty (the next mutation rewrites it), so a damaged file costs pictures,
    /// never the daemon. Nothing is created until the first mutation.
    pub fn open(root: PathBuf) -> Self {
        let agents = match read_index(&root) {
            Ok(index) => index.agents,
            Err(err) => {
                tracing::warn!(root = %root.display(), err = %err, "agent avatar index unreadable; starting empty");
                BTreeMap::new()
            }
        };
        Self { root, agents }
    }

    #[cfg(test)]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn get(&self, terminal_id: &str) -> Option<&AgentAvatar> {
        self.agents.get(terminal_id)
    }

    /// Show bundled mascot `mascot` for the agent.
    pub fn set_mascot(
        &mut self,
        terminal_id: &str,
        mascot: &str,
        now_unix_ms: u64,
    ) -> Result<AgentAvatar, AvatarError> {
        if !valid_mascot_id(mascot) {
            return Err(AvatarError::Invalid(format!(
                "mascot must match ^[a-z0-9-]{{1,32}}$, got {mascot:?}"
            )));
        }
        let avatar = AgentAvatar {
            style: AgentAvatarStyle::Mascot,
            mascot: Some(mascot.to_string()),
            sha256: None,
            updated_unix_ms: now_unix_ms,
        };
        self.mutate(|agents| {
            agents.insert(terminal_id.to_string(), avatar.clone());
            Ok(())
        })?;
        Ok(avatar)
    }

    /// Store `bytes` (JPEG or PNG, at most [`MAX_IMAGE_BYTES`]) as the agent's
    /// picture. The previous image is deleted once nothing references it.
    pub fn set_image(
        &mut self,
        terminal_id: &str,
        bytes: &[u8],
        now_unix_ms: u64,
    ) -> Result<AgentAvatar, AvatarError> {
        if bytes.len() > MAX_IMAGE_BYTES {
            return Err(AvatarError::TooLarge(bytes.len()));
        }
        if image_mime(bytes).is_none() {
            return Err(AvatarError::Invalid(
                "image must be a JPEG or PNG".to_string(),
            ));
        }
        let sha256 = sha256_hex(bytes);
        let avatar = AgentAvatar {
            style: AgentAvatarStyle::Image,
            mascot: None,
            sha256: Some(sha256.clone()),
            updated_unix_ms: now_unix_ms,
        };
        let blob = self.root.join(&sha256);
        self.mutate(|agents| {
            if !blob.exists() {
                write_owner_only(&blob, bytes)?;
            }
            agents.insert(terminal_id.to_string(), avatar.clone());
            Ok(())
        })?;
        Ok(avatar)
    }

    /// Drop the agent's picture (clear, or `agent.forget`) and its image once
    /// unreferenced. Returns whether there was one.
    pub fn remove(&mut self, terminal_id: &str) -> io::Result<bool> {
        if !self.agents.contains_key(terminal_id) && !self.root.join(INDEX_FILE).exists() {
            return Ok(false);
        }
        let mut removed = false;
        self.mutate(|agents| {
            removed = agents.remove(terminal_id).is_some();
            Ok(())
        })?;
        Ok(removed)
    }

    /// The stored image `sha256` with its type, when it is one this store holds.
    pub fn image(&self, sha256: &str) -> io::Result<Option<(&'static str, Vec<u8>)>> {
        if !is_sha256_hex(sha256) {
            return Ok(None);
        }
        let bytes = match fs::read(self.root.join(sha256)) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        Ok(image_mime(&bytes).map(|mime| (mime, bytes)))
    }

    /// Read-modify-write the on-disk index under the lock, then sweep
    /// unreferenced blobs and adopt the result in memory.
    fn mutate(
        &mut self,
        change: impl FnOnce(&mut BTreeMap<String, AgentAvatar>) -> io::Result<()>,
    ) -> io::Result<()> {
        create_private_dir(&self.root)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join(LOCK_FILE))?;
        lock.lock()?;
        let mut index = read_index(&self.root)?;
        change(&mut index.agents)?;
        super::devices::save_owner_only_json(&self.root.join(INDEX_FILE), &index)?;
        sweep_unreferenced(&self.root, &index.agents);
        self.agents = index.agents;
        Ok(())
    }
}

fn read_index(root: &Path) -> io::Result<IndexFile> {
    match fs::read(root.join(INDEX_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(IndexFile::default()),
        Err(err) => Err(err),
    }
}

/// Delete every blob (a 64-hex file name) no entry names. Best-effort: a
/// failure is logged and retried by the next mutation's sweep.
fn sweep_unreferenced(root: &Path, agents: &BTreeMap<String, AgentAvatar>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_sha256_hex(name)
            || agents
                .values()
                .any(|avatar| avatar.sha256.as_deref() == Some(name))
        {
            continue;
        }
        if let Err(err) = fs::remove_file(entry.path()) {
            tracing::warn!(blob = name, err = %err, "failed to delete unreferenced agent avatar");
        }
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to `path` via an owner-only temp file and a rename, so a
/// reader never sees a partial image.
fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let tmp_path = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&tmp_path).and_then(|mut file| {
        #[cfg(unix)]
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(err) = written.and_then(|()| fs::rename(&tmp_path, path)) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub(crate) const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];
    pub(crate) const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 4, 5, 6];

    /// A fresh, not-yet-created store root under the temp dir.
    pub(crate) fn temp_root(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "herdr-agent-avatars-test-{}-{tag}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn blobs(root: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(root)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
                    .filter(|name| is_sha256_hex(name))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[test]
    fn mascot_ids_follow_the_contract_pattern() {
        for ok in ["herdy", "bot", "a", "pebbles-2", &"x".repeat(32)] {
            assert!(valid_mascot_id(ok), "{ok}");
        }
        for bad in ["", "Bot", "../x", "a b", "bot_1", "é", &"x".repeat(33)] {
            assert!(!valid_mascot_id(bad), "{bad}");
        }
    }

    #[test]
    fn mascot_round_trips_and_survives_reopen() {
        let root = temp_root("mascot");
        let mut store = AgentAvatarStore::open(root.clone());
        assert!(store.get("term_1").is_none());
        let avatar = store.set_mascot("term_1", "bot", 7).unwrap();
        assert_eq!(avatar.style, AgentAvatarStyle::Mascot);
        assert_eq!(avatar.mascot.as_deref(), Some("bot"));
        assert_eq!(avatar.sha256, None);
        assert_eq!(avatar.updated_unix_ms, 7);

        let reopened = AgentAvatarStore::open(root.clone());
        assert_eq!(reopened.get("term_1"), Some(&avatar));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bad_mascot_is_refused_and_nothing_is_written() {
        let root = temp_root("bad-mascot");
        let mut store = AgentAvatarStore::open(root.clone());
        assert!(matches!(
            store.set_mascot("term_1", "../etc", 1),
            Err(AvatarError::Invalid(_))
        ));
        assert!(store.get("term_1").is_none());
        assert!(!root.exists());
    }

    #[test]
    fn image_round_trips_content_addressed() {
        let root = temp_root("image");
        let mut store = AgentAvatarStore::open(root.clone());
        let avatar = store.set_image("term_1", PNG, 9).unwrap();
        let sha = avatar.sha256.clone().unwrap();
        assert_eq!(sha, sha256_hex(PNG));
        assert_eq!(avatar.style, AgentAvatarStyle::Image);
        assert_eq!(avatar.mascot, None);
        assert_eq!(
            store.image(&sha).unwrap(),
            Some(("image/png", PNG.to_vec()))
        );
        assert_eq!(blobs(&root), vec![sha.clone()]);

        let reopened = AgentAvatarStore::open(root.clone());
        assert_eq!(reopened.get("term_1"), Some(&avatar));
        assert_eq!(
            reopened.image(&sha).unwrap(),
            Some(("image/png", PNG.to_vec()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&root), 0o700);
            assert_eq!(mode(&root.join(&sha)), 0o600);
            assert_eq!(mode(&root.join(INDEX_FILE)), 0o600);
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn oversized_and_non_image_bytes_are_refused() {
        let root = temp_root("refuse");
        let mut store = AgentAvatarStore::open(root.clone());
        let mut big = PNG.to_vec();
        big.resize(MAX_IMAGE_BYTES + 1, 0);
        assert!(matches!(
            store.set_image("term_1", &big, 1),
            Err(AvatarError::TooLarge(len)) if len == MAX_IMAGE_BYTES + 1
        ));
        let mut exact = JPEG.to_vec();
        exact.resize(MAX_IMAGE_BYTES, 0);
        assert!(store.set_image("term_2", &exact, 1).is_ok());
        assert!(matches!(
            store.set_image("term_1", b"GIF89a....", 1),
            Err(AvatarError::Invalid(_))
        ));
        assert!(store.get("term_1").is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replacing_an_image_deletes_the_old_blob_unless_shared() {
        let root = temp_root("replace");
        let mut store = AgentAvatarStore::open(root.clone());
        let png = store.set_image("term_1", PNG, 1).unwrap().sha256.unwrap();
        store.set_image("term_2", PNG, 1).unwrap();
        let jpeg = store.set_image("term_1", JPEG, 2).unwrap().sha256.unwrap();
        // term_2 still shows the PNG.
        let mut both = vec![png.clone(), jpeg.clone()];
        both.sort();
        assert_eq!(blobs(&root), both);

        store.set_mascot("term_2", "drop", 3).unwrap();
        assert_eq!(blobs(&root), vec![jpeg.clone()]);
        assert_eq!(store.image(&png).unwrap(), None);

        assert!(store.remove("term_1").unwrap());
        assert!(blobs(&root).is_empty());
        assert!(store.get("term_1").is_none());
        assert!(!store.remove("term_1").unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn image_lookup_rejects_non_hash_names() {
        let root = temp_root("names");
        let mut store = AgentAvatarStore::open(root.clone());
        store.set_mascot("term_1", "pip", 1).unwrap();
        assert_eq!(store.image("index.json").unwrap(), None);
        assert_eq!(store.image("../index.json").unwrap(), None);
        assert_eq!(store.image(&"a".repeat(64)).unwrap(), None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_second_store_on_the_same_root_keeps_the_others_change() {
        let root = temp_root("shared");
        let mut first = AgentAvatarStore::open(root.clone());
        let mut second = AgentAvatarStore::open(root.clone());
        first.set_mascot("term_1", "bot", 1).unwrap();
        second.set_mascot("term_2", "cub", 2).unwrap();
        let reopened = AgentAvatarStore::open(root.clone());
        assert!(reopened.get("term_1").is_some());
        assert!(reopened.get("term_2").is_some());
        let _ = fs::remove_dir_all(root);
    }
}
