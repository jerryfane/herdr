//! Persistent "gram" message store.
//!
//! Gram is an owner<->agent message channel surfaced in the Herdr mobile app: an
//! agent sends the owner a push-notified update (`agent_to_owner`), and the owner
//! posts work into a shared grab-queue or directly to one agent
//! (`owner_to_agent`). Messages persist at `~/.config/herdr/gram.json`, guarded by
//! a `.gram.lock` sidecar, mirroring the atomic-write / lenient-load /
//! strict-under-lock pattern used by [`crate::persist::devices`].
//!
//! Grab atomicity: [`update`] read-modify-writes the whole list while holding the
//! advisory lock, so a claim's check-then-set cannot interleave with another
//! process. Within one process the app loop already serializes API requests, so
//! the two layers together make "first grab wins" exact.
//!
//! The store is bounded on two axes (see [`normalize`]): a message-count cap and
//! a total-text-bytes budget. Per-message text is capped by the caller (see
//! [`MAX_TEXT_BYTES`]) so a single message cannot bloat the file.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tracing::warn;

const GRAM_LOCK_FILE: &str = ".gram.lock";

/// Keep the store bounded by message count: a personal channel never needs
/// unbounded history, and an ever-growing file would slow every
/// read-modify-write. On save the oldest messages beyond this many are dropped.
const MAX_ITEMS: usize = 1000;

/// Budget for the sum of all stored message *texts*; the oldest are dropped first
/// once it is exceeded. Labels (`from`/`to`/`grabbed_by`, each ≤ [`MAX_LABEL_BYTES`])
/// and ids are bounded separately and per-item, so together with [`MAX_ITEMS`] the
/// whole file stays comfortably bounded.
const MAX_TOTAL_TEXT_BYTES: usize = 1024 * 1024;

/// Maximum bytes of a single message's text. Enforced by the API handler before
/// a message reaches the store (a message is a notification, not a document —
/// large payloads belong in a file transfer). Exposed so the handler and this
/// module agree on one limit.
pub const MAX_TEXT_BYTES: usize = 8 * 1024;

/// Maximum bytes of a persisted label (`from`, `to`, `grabbed_by`). These are
/// agent identities, not free text; capping them keeps a caller-supplied override
/// from bypassing the text budget and bloating the store.
pub const MAX_LABEL_BYTES: usize = 128;

/// Whether a message flows from an agent to the owner or the other way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GramDirection {
    /// An agent sent the owner a message (push-notified).
    AgentToOwner,
    /// The owner posted a message to the shared queue or a specific agent.
    OwnerToAgent,
}

/// One stored gram message. Field order is the wire/JSON order; new optional
/// fields must carry `#[serde(default)]` so a store written by an older build
/// still loads strictly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GramItem {
    /// Opaque, unique message id (minted by [`new_id`]).
    pub id: String,
    pub direction: GramDirection,
    /// Sender label: an agent's effective identity for `agent_to_owner`, or
    /// `"owner"` for `owner_to_agent`.
    pub from: String,
    /// For `owner_to_agent`: `Some(agent)` addresses one agent directly (not
    /// grabbable); `None` posts to the shared grab-queue. Always `None` for
    /// `agent_to_owner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub text: String,
    /// The agent that claimed a shared-queue item; `None` while unclaimed. Only
    /// meaningful for shared `owner_to_agent` items. This is the claimant's
    /// identity label at grab time (see the handler module for its semantics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grabbed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grabbed_unix_ms: Option<u64>,
    pub created_unix_ms: u64,
    /// Owner has viewed this `agent_to_owner` message (clears the app badge).
    #[serde(default)]
    pub read_by_owner: bool,
}

impl GramItem {
    /// A shared, still-open queue item any agent may claim.
    fn is_open_shared_queue(&self) -> bool {
        self.direction == GramDirection::OwnerToAgent
            && self.to.is_none()
            && self.grabbed_by.is_none()
    }
}

/// Mint a unique message id. The wall-clock millis keep ids roughly time-ordered
/// for humans; the process id makes ids unique across herdr processes that might
/// share a config dir, and the monotonic counter guarantees uniqueness within a
/// process even inside one millisecond.
pub fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("gram-{millis:x}-{pid:x}-{seq:x}")
}

fn config_base() -> PathBuf {
    crate::config::config_dir()
}

fn registry_path_in(dir: &Path) -> PathBuf {
    dir.join("gram.json")
}

fn registry_lock_path_in(dir: &Path) -> PathBuf {
    dir.join(GRAM_LOCK_FILE)
}

fn with_registry_lock_in<T>(
    dir: &Path,
    operation: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let lock_path = registry_lock_path_in(dir);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    lock.lock()?;
    operation()
}

fn save_json_to_path<T: serde::Serialize + ?Sized>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, json)?;
    #[cfg(windows)]
    if path.exists() {
        if let Err(err) = std::fs::remove_file(path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
    }
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

/// Read-modify-write the store under the lock in `dir`. The mutation returns its
/// result plus a `changed` flag; the list is normalized and rewritten only when
/// `changed`, so a no-op (a lost grab race, a redundant mark-read) does not
/// rewrite the file or evict messages via the caps. Tests pass a temp dir to
/// exercise the real lock + disk.
fn update_in_checked<T>(
    dir: &Path,
    mutation: impl FnOnce(&mut Vec<GramItem>) -> (T, bool),
) -> std::io::Result<(T, Vec<GramItem>)> {
    with_registry_lock_in(dir, || {
        let path = registry_path_in(dir);
        let mut items = load_from_path_strict(&path)?;
        let (result, changed) = mutation(&mut items);
        if changed {
            normalize(&mut items);
            save_json_to_path(&path, &items)?;
        }
        Ok((result, items))
    })
}

fn update_in<T>(
    dir: &Path,
    mutation: impl FnOnce(&mut Vec<GramItem>) -> T,
) -> std::io::Result<(T, Vec<GramItem>)> {
    update_in_checked(dir, |items| (mutation(items), true))
}

/// Read-modify-write the store under the lock. The mutation reports whether it
/// changed anything; the file is rewritten only when it did, so a no-op does not
/// churn the store or evict messages via the caps. All mutating operations funnel
/// through here (or [`append`]) so the lock is never bypassed.
pub fn update_if_changed<T>(
    mutation: impl FnOnce(&mut Vec<GramItem>) -> (T, bool),
) -> std::io::Result<(T, Vec<GramItem>)> {
    update_in_checked(&config_base(), mutation)
}

/// Sort oldest-first, then drop the oldest until both the count cap and the
/// total-text-bytes budget are satisfied. Dropping an unclaimed shared item or
/// an unread owner message is surprising, so those are logged.
fn normalize(items: &mut Vec<GramItem>) {
    items.sort_by(|left, right| {
        left.created_unix_ms
            .cmp(&right.created_unix_ms)
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut total_text: usize = items.iter().map(|item| item.text.len()).sum();
    while items.len() > MAX_ITEMS || (items.len() > 1 && total_text > MAX_TOTAL_TEXT_BYTES) {
        let dropped = items.remove(0);
        total_text = total_text.saturating_sub(dropped.text.len());
        if dropped.is_open_shared_queue() {
            warn!(id = %dropped.id, "gram store dropped an unclaimed shared-queue item at the cap");
        } else if dropped.direction == GramDirection::AgentToOwner && !dropped.read_by_owner {
            warn!(id = %dropped.id, "gram store dropped an unread owner message at the cap");
        }
    }
}

fn append_in(dir: &Path, item: GramItem) -> std::io::Result<Vec<GramItem>> {
    let (_, items) = update_in(dir, move |items| items.push(item))?;
    Ok(items)
}

/// Append a new message and return the persisted list.
pub fn append(item: GramItem) -> std::io::Result<Vec<GramItem>> {
    append_in(&config_base(), item)
}

fn try_load_in(dir: &Path) -> std::io::Result<Vec<GramItem>> {
    with_registry_lock_in(dir, || load_from_path_strict(&registry_path_in(dir)))
}

/// Load the store. Returns an empty vec on failure so a corrupt or missing file
/// never blocks reads; mutations still use strict reads under the lock.
pub fn load() -> Vec<GramItem> {
    let dir = config_base();
    match try_load_in(&dir) {
        Ok(items) => items,
        Err(err) => {
            warn!(path = %registry_path_in(&dir).display(), err = %err, "failed to load gram store");
            Vec::new()
        }
    }
}

fn load_from_path_strict(path: &Path) -> std::io::Result<Vec<GramItem>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str::<Vec<GramItem>>(&content)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, created: u64) -> GramItem {
        GramItem {
            id: id.to_string(),
            direction: GramDirection::OwnerToAgent,
            from: "owner".to_string(),
            to: None,
            text: "hello".to_string(),
            grabbed_by: None,
            grabbed_unix_ms: None,
            created_unix_ms: created,
            read_by_owner: false,
        }
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "herdr-gram-test-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn new_id_is_unique_within_a_millisecond() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b, "ids minted back-to-back must differ");
        assert!(a.starts_with("gram-"));
    }

    #[test]
    fn roundtrip_via_serde_preserves_fields() {
        let mut original = item("gram-1", 10);
        original.direction = GramDirection::AgentToOwner;
        original.from = "trend-scout".to_string();
        original.text = "digest ready".to_string();
        let json = serde_json::to_string(&[original.clone()]).unwrap();
        let loaded: Vec<GramItem> = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded, vec![original]);
    }

    #[test]
    fn normalize_sorts_oldest_first_and_caps_count() {
        let mut items = vec![item("c", 30), item("a", 10), item("b", 20)];
        normalize(&mut items);
        assert_eq!(
            items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );

        let mut many: Vec<GramItem> = (0..(MAX_ITEMS + 5) as u64)
            .map(|n| item(&format!("id-{n}"), n))
            .collect();
        normalize(&mut many);
        assert_eq!(many.len(), MAX_ITEMS);
        assert_eq!(many.first().unwrap().created_unix_ms, 5);
    }

    #[test]
    fn normalize_enforces_total_byte_budget() {
        let big = "x".repeat(MAX_TEXT_BYTES);
        let mut items: Vec<GramItem> = (0..300u64)
            .map(|n| {
                let mut it = item(&format!("id-{n}"), n);
                it.text = big.clone();
                it
            })
            .collect();
        // 300 * 8 KiB = 2.4 MiB > 1 MiB budget; oldest dropped until under budget.
        normalize(&mut items);
        let total: usize = items.iter().map(|i| i.text.len()).sum();
        assert!(total <= MAX_TOTAL_TEXT_BYTES, "total {total} over budget");
        assert!(!items.is_empty());
        // Newest survive: the last id must still be present.
        assert_eq!(items.last().unwrap().id, "id-299");
    }

    #[test]
    fn update_if_changed_skips_save_on_no_change() {
        let dir = unique_temp_dir("nochange");
        let path = registry_path_in(&dir);
        // Write a compact (non-canonical) file; any save rewrites it pretty.
        std::fs::write(&path, serde_json::to_string(&[item("x", 1)]).unwrap()).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        // A no-op mutation must not rewrite the file.
        update_in_checked(&dir, |_items| ((), false)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        // A real change rewrites it (to pretty JSON).
        update_in_checked(&dir, |items| {
            items[0].read_by_owner = true;
            ((), true)
        })
        .unwrap();
        assert_ne!(std::fs::read_to_string(&path).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_grabs_are_first_wins_on_disk() {
        let dir = unique_temp_dir("grab");
        let mut seed = item("shared", 1);
        seed.read_by_owner = true;
        append_in(&dir, seed).unwrap();

        fn try_claim(dir: &Path, who: &str) -> std::io::Result<bool> {
            let who = who.to_string();
            let (claimed, _) = update_in(dir, move |items| {
                match items.iter_mut().find(|item| item.id == "shared") {
                    Some(item) if item.grabbed_by.is_none() => {
                        item.grabbed_by = Some(who);
                        true
                    }
                    _ => false,
                }
            })?;
            Ok(claimed)
        }

        let d1 = dir.clone();
        let d2 = dir.clone();
        let h1 = std::thread::spawn(move || try_claim(&d1, "agent-a").unwrap());
        let h2 = std::thread::spawn(move || try_claim(&d2, "agent-b").unwrap());
        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        // Exactly one claim wins; the real lock + disk serialize the two.
        assert!(r1 ^ r2, "exactly one grab must win (a={r1}, b={r2})");
        let persisted = try_load_in(&dir).unwrap();
        assert_eq!(persisted.len(), 1);
        assert!(persisted[0].grabbed_by.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
