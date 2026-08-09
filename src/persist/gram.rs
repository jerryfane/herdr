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

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tracing::warn;

const GRAM_LOCK_FILE: &str = ".gram.lock";

/// Keep the store bounded: a personal channel never needs unbounded history, and
/// an ever-growing file would slow every read-modify-write. On save the oldest
/// messages beyond this many are dropped (grab/read state does not exempt them).
const MAX_ITEMS: usize = 1000;

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
    /// Sender label: an agent's effective label for `agent_to_owner`, or
    /// `"owner"` for `owner_to_agent`.
    pub from: String,
    /// For `owner_to_agent`: `Some(agent)` addresses one agent directly (not
    /// grabbable); `None` posts to the shared grab-queue. Always `None` for
    /// `agent_to_owner`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub text: String,
    /// The agent that claimed a shared-queue item; `None` while unclaimed. Only
    /// meaningful for shared `owner_to_agent` items.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grabbed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grabbed_unix_ms: Option<u64>,
    pub created_unix_ms: u64,
    /// Owner has viewed this `agent_to_owner` message (clears the app badge).
    #[serde(default)]
    pub read_by_owner: bool,
}

/// Mint a process-unique message id. The wall-clock millis keep ids roughly
/// time-ordered for humans; the monotonic counter guarantees uniqueness even for
/// messages minted in the same millisecond.
pub fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("gram-{millis:x}-{seq:x}")
}

fn registry_path() -> PathBuf {
    crate::config::config_dir().join("gram.json")
}

fn registry_lock_path() -> PathBuf {
    crate::config::config_dir().join(GRAM_LOCK_FILE)
}

fn with_registry_lock<T>(operation: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    let lock_path = registry_lock_path();
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

/// Read-modify-write the store under the lock, returning the mutation's result
/// and the persisted (sorted, capped) list. All mutating operations funnel
/// through here so the lock is never bypassed.
pub fn update<T>(
    mutation: impl FnOnce(&mut Vec<GramItem>) -> T,
) -> std::io::Result<(T, Vec<GramItem>)> {
    with_registry_lock(|| {
        let mut items = load_from_path_strict(&registry_path())?;
        let result = mutation(&mut items);
        normalize(&mut items);
        save_json_to_path(&registry_path(), &items)?;
        Ok((result, items))
    })
}

/// Sort oldest-first by creation time and drop the oldest beyond [`MAX_ITEMS`].
fn normalize(items: &mut Vec<GramItem>) {
    items.sort_by(|left, right| {
        left.created_unix_ms
            .cmp(&right.created_unix_ms)
            .then_with(|| left.id.cmp(&right.id))
    });
    if items.len() > MAX_ITEMS {
        let overflow = items.len() - MAX_ITEMS;
        items.drain(0..overflow);
    }
}

/// Append a new message and return the persisted list.
pub fn append(item: GramItem) -> std::io::Result<Vec<GramItem>> {
    let (_, items) = update(move |items| items.push(item))?;
    Ok(items)
}

pub fn try_load() -> std::io::Result<Vec<GramItem>> {
    with_registry_lock(|| load_from_path_strict(&registry_path()))
}

/// Load the store. Returns an empty vec on failure so a corrupt or missing file
/// never blocks reads; mutations still use strict reads under the lock.
pub fn load() -> Vec<GramItem> {
    match try_load() {
        Ok(items) => items,
        Err(err) => {
            warn!(path = %registry_path().display(), err = %err, "failed to load gram store");
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
    fn normalize_sorts_oldest_first_and_caps() {
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
        // The five oldest (0..5) were dropped; the newest survive.
        assert_eq!(many.first().unwrap().created_unix_ms, 5);
    }

    #[test]
    fn grab_claim_is_first_wins_in_memory() {
        // Exercise the claim mutation directly (no disk / lock) — the same
        // check-then-set `update` runs under the lock in production.
        let mut items = vec![item("shared", 1)];
        let claim = |items: &mut Vec<GramItem>, who: &str| -> Result<(), &'static str> {
            let target = items
                .iter_mut()
                .find(|i| i.id == "shared")
                .ok_or("not_found")?;
            if target.grabbed_by.is_some() {
                return Err("already_grabbed");
            }
            target.grabbed_by = Some(who.to_string());
            Ok(())
        };
        assert!(claim(&mut items, "agent-a").is_ok());
        assert_eq!(claim(&mut items, "agent-b"), Err("already_grabbed"));
        assert_eq!(items[0].grabbed_by.as_deref(), Some("agent-a"));
    }
}
