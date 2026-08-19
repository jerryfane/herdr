//! Per-install machine identity store.
//!
//! Persists a single random, stable-per-install machine id at
//! `~/.config/herdr/machine.json`, guarded by a `.machine.lock` sidecar. Mirrors
//! the atomic-write / lenient-load / strict-under-lock pattern used by
//! [`crate::persist::devices`].
//!
//! The id is minted once on first read and reused across daemon restarts. It is
//! sent in the federation handshake ([`crate::api::federation::FederationHello`])
//! as an install-stable identifier a peer can pin against (`expected_node_id`).
//! It is NOT a secret — the shared token remains the authenticator — and it is a
//! distinct concept from the home-chosen peer alias carried by
//! `AgentInfo.machine_id`, which is a display/routing label, not this install id.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tracing::warn;

const MACHINE_LOCK_FILE: &str = ".machine.lock";

/// The persisted per-install identity. A single-field object so the file shape
/// can grow additively later without a format break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MachineIdentity {
    /// Opaque, random, install-stable id (e.g. `machine_<32 hex>`). Not a secret.
    machine_id: String,
}

fn registry_path() -> PathBuf {
    crate::config::config_dir().join("machine.json")
}

fn registry_lock_path() -> PathBuf {
    crate::config::config_dir().join(MACHINE_LOCK_FILE)
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

/// Mint a fresh random machine id: `machine_` followed by 32 hex digits (128
/// random bits).
///
/// The entropy comes from [`std::collections::hash_map::RandomState`], whose
/// SipHash keys are seeded from the OS RNG (getrandom) on first use. Hashing two
/// fixed sentinels through two independent `RandomState`s yields 128 OS-seeded
/// pseudo-random bits without pulling in a new dependency. This id is an
/// install identity, not a cryptographic secret, so this source is sufficient.
fn generate_machine_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;
    let hi = RandomState::new().hash_one("herdr-machine-id-hi");
    let lo = RandomState::new().hash_one("herdr-machine-id-lo");
    format!("machine_{hi:016x}{lo:016x}")
}

/// Strict read of the identity file: `Ok(None)` when the file is absent or holds
/// an empty id, `Err` on unreadable/corrupt content. Callers hold the lock.
fn load_from_path_strict(path: &Path) -> std::io::Result<Option<MachineIdentity>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    let identity = serde_json::from_str::<MachineIdentity>(&content)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    if identity.machine_id.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(identity))
}

/// Read the persisted id, or mint and persist a new one when absent. Caller must
/// already hold the registry lock; the read and the create are one critical
/// section so two racing daemons cannot mint two different ids.
fn get_or_create_at(path: &Path) -> std::io::Result<String> {
    if let Some(identity) = load_from_path_strict(path)? {
        return Ok(identity.machine_id);
    }
    let identity = MachineIdentity {
        machine_id: generate_machine_id(),
    };
    save_json_to_path(path, &identity)?;
    Ok(identity.machine_id)
}

/// The per-install machine id, minted on first call and cached for the process
/// lifetime. Get-or-create runs once under the file lock; on any I/O failure a
/// fresh in-memory id is returned (and cached) so the handshake still carries a
/// stable id for this process rather than failing.
pub fn get_or_create() -> String {
    static CACHED: OnceLock<String> = OnceLock::new();
    CACHED
        .get_or_init(|| match with_registry_lock(|| get_or_create_at(&registry_path())) {
            Ok(id) => id,
            Err(err) => {
                warn!(
                    path = %registry_path().display(),
                    err = %err,
                    "failed to load or persist machine id; using an ephemeral id for this process"
                );
                generate_machine_id()
            }
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "herdr-machine-{tag}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn generated_ids_have_the_expected_shape_and_are_distinct() {
        let a = generate_machine_id();
        let b = generate_machine_id();
        assert!(a.starts_with("machine_"), "unexpected id: {a}");
        // 8 chars for "machine_" + 32 hex digits.
        assert_eq!(a.len(), "machine_".len() + 32);
        assert!(
            a.trim_start_matches("machine_")
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "id has non-hex digits: {a}"
        );
        assert_ne!(a, b, "two mints should not collide");
    }

    #[test]
    fn get_or_create_at_is_stable_and_persists() {
        let path = temp_path("stable");
        let _ = std::fs::remove_file(&path);

        // First call mints and writes the id.
        let first = get_or_create_at(&path).unwrap();
        assert!(path.exists());
        // Second call returns the same id (read from disk, not re-minted).
        let second = get_or_create_at(&path).unwrap();
        assert_eq!(first, second);

        // A fresh strict load from the same dir yields the same id, proving it
        // survives a restart (no in-process cache involved here).
        let loaded = load_from_path_strict(&path).unwrap().unwrap();
        assert_eq!(loaded.machine_id, first);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_none_and_corrupt_is_error() {
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(load_from_path_strict(&path).unwrap().is_none());

        std::fs::write(&path, b"not json {{{").unwrap();
        assert!(load_from_path_strict(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_id_is_treated_as_absent() {
        let path = temp_path("empty");
        std::fs::write(&path, br#"{"machine_id":""}"#).unwrap();
        assert!(load_from_path_strict(&path).unwrap().is_none());
        // get_or_create_at then mints a real id over the empty record.
        let id = get_or_create_at(&path).unwrap();
        assert!(!id.is_empty());
        assert_eq!(
            load_from_path_strict(&path).unwrap().unwrap().machine_id,
            id
        );
        let _ = std::fs::remove_file(&path);
    }
}
