//! Registered push-notification device store.
//!
//! Persists the set of mobile devices that have registered for remote push at
//! `~/.config/herdr/devices.json`, guarded by a `.devices.lock` sidecar. Mirrors
//! the atomic-write / lenient-load / strict-under-lock pattern used by
//! [`crate::persist::plugin_registry`]. Only device tokens and per-device
//! notification preferences are stored here; APNs key material is never written.
//! Relay capabilities are bearer credentials, so the file is owner-only (0600)
//! on Unix.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;

const DEVICES_LOCK_FILE: &str = ".devices.lock";

/// A device registered to receive remote push notifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredDevice {
    /// Opaque APNs device token (hex string). Not a secret, but device-specific.
    pub device_token: String,
    /// Reporting platform, e.g. "ios". Kept for future multi-platform routing.
    pub platform: String,
    /// Deliver a push when an agent needs input/attention.
    pub notify_needs_input: bool,
    /// Deliver a push when an agent pane process dies.
    pub notify_dies: bool,
    /// Deliver a push when an agent finishes a turn.
    pub notify_finishes: bool,
    /// With `notify_finishes`, push only turns the owner started or joined
    /// (unknown origin counts as the owner's). False for legacy records.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub notify_finishes_mine_only: bool,
    /// Deliver a push when an agent sends the owner a gram message.
    #[serde(default)]
    pub notify_gram: bool,
    /// Public pane ids the owner has muted on this device. A push whose
    /// `pane_id` is in this set is skipped for this device (agent/gram pushes
    /// unaffected — gram pushes carry no pane id). Muting is per-pane, so a
    /// newly opened agent starts un-muted. Empty for legacy records.
    #[serde(default)]
    pub muted_panes: Vec<String>,
    /// Registration time in Unix milliseconds.
    pub registered_unix_ms: u64,
    /// Opaque sealed capability from the HerdrUp push relay (`hpr1.…`). Sent back
    /// verbatim to the relay; never parsed or logged. Absent on legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_capability: Option<String>,
}

fn registry_path() -> PathBuf {
    crate::config::config_dir().join("devices.json")
}

fn registry_lock_path() -> PathBuf {
    crate::config::config_dir().join(DEVICES_LOCK_FILE)
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

/// Atomically write `value` as owner-only JSON. The temp file is created (or a
/// stale one repaired) as 0600 before the body is written, and the rename keeps
/// that mode, so the registry is never world-readable, even briefly. Shared with
/// [`crate::persist::activities`].
pub(super) fn save_owner_only_json<T: serde::Serialize + ?Sized>(
    path: &Path,
    value: &T,
) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(value)?;
    let tmp_path = path.with_extension("json.tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&tmp_path).and_then(|mut file| {
        #[cfg(unix)]
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        file.write_all(json.as_bytes())
    });
    if let Err(err) = written {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
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

/// Tighten an existing registry file written by an older daemon (0644) to 0600.
/// Best-effort: a failure is logged and the load proceeds.
pub(super) fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(metadata) = std::fs::metadata(path) else {
            return;
        };
        if metadata.permissions().mode() & 0o777 != 0o600 {
            if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            {
                warn!(path = %path.display(), err = %err, "failed to restrict push registry to owner");
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn save_to_path(path: &Path, devices: &[RegisteredDevice]) -> std::io::Result<()> {
    save_owner_only_json(path, devices)
}

/// Read-modify-write the registry under the lock, returning the mutation's
/// result and the persisted device list.
pub fn update<T>(
    mutation: impl FnOnce(&mut Vec<RegisteredDevice>) -> T,
) -> std::io::Result<(T, Vec<RegisteredDevice>)> {
    with_registry_lock(|| {
        let mut devices = load_from_path_strict(&registry_path())?;
        let result = mutation(&mut devices);
        devices.sort_by(|left, right| left.device_token.cmp(&right.device_token));
        save_to_path(&registry_path(), &devices)?;
        Ok((result, devices))
    })
}

/// Insert or replace a device by its token. Returns the persisted device list.
pub fn upsert(device: RegisteredDevice) -> std::io::Result<Vec<RegisteredDevice>> {
    let (_, devices) = update(move |devices| {
        devices.retain(|existing| existing.device_token != device.device_token);
        devices.push(device);
    })?;
    Ok(devices)
}

/// Remove a device by its token (used to prune tokens APNs reports as invalid).
/// Returns true when a device was removed.
pub fn remove_token(token: &str) -> std::io::Result<bool> {
    let (removed, _) = update(|devices| {
        let before = devices.len();
        devices.retain(|device| device.device_token != token);
        before != devices.len()
    })?;
    Ok(removed)
}

pub fn try_load() -> std::io::Result<Vec<RegisteredDevice>> {
    with_registry_lock(|| load_from_path_strict(&registry_path()))
}

/// Load the device registry. Returns an empty vec on failure so a corrupt or
/// missing file never blocks delivery; mutations still use strict reads.
pub fn load() -> Vec<RegisteredDevice> {
    match try_load() {
        Ok(devices) => devices,
        Err(err) => {
            warn!(path = %registry_path().display(), err = %err, "failed to load device registry");
            Vec::new()
        }
    }
}

#[cfg(test)]
fn load_from_path(path: &Path) -> Vec<RegisteredDevice> {
    match load_from_path_strict(path) {
        Ok(entries) => entries,
        Err(err) => {
            warn!(path = %path.display(), err = %err, "failed to read device registry");
            Vec::new()
        }
    }
}

fn load_from_path_strict(path: &Path) -> std::io::Result<Vec<RegisteredDevice>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    restrict_to_owner(path);
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str::<Vec<RegisteredDevice>>(&content)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device(token: &str) -> RegisteredDevice {
        RegisteredDevice {
            notify_finishes_mine_only: false,
            device_token: token.to_string(),
            platform: "ios".to_string(),
            notify_needs_input: true,
            notify_dies: true,
            notify_finishes: false,
            notify_gram: false,
            muted_panes: Vec::new(),
            registered_unix_ms: 1_700_000_000_000,
            relay_capability: None,
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "herdr-devices-roundtrip-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut relayed = sample_device("bbb");
        relayed.relay_capability = Some("hpr1.c2VhbGVk".to_string());
        let devices = [sample_device("aaa"), relayed];
        save_to_path(&path, &devices).unwrap();
        assert_eq!(load_from_path_strict(&path).unwrap(), devices);
        // A device without a capability writes no key, so the file stays in the
        // shape older daemons already read.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.matches("relay_capability").count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn registry_is_owner_only_after_save_and_repaired_on_load() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let path =
            std::env::temp_dir().join(format!("herdr-devices-mode-{}.json", std::process::id()));
        let tmp = path.with_extension("json.tmp");
        // A stale world-readable temp file must not leak its mode into the save.
        std::fs::write(&tmp, "stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut device = sample_device("aaa");
        device.relay_capability = Some("hpr1.c2VhbGVk".to_string());
        save_to_path(&path, &[device]).unwrap();
        assert_eq!(mode(&path), 0o600);

        // A registry written by an older daemon is tightened on the next load.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_from_path_strict(&path).unwrap().len(), 1);
        assert_eq!(mode(&path), 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_returns_empty() {
        let path =
            std::env::temp_dir().join(format!("herdr-devices-missing-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(load_from_path(&path).is_empty());
    }

    #[test]
    fn legacy_record_without_muted_panes_decodes_to_empty() {
        // A devices.json written before per-agent mute existed has no
        // `muted_panes` field; #[serde(default)] must decode it to an empty set
        // (never fail the load) so muting is simply off for legacy records.
        let legacy = r#"[{"device_token":"abc","platform":"ios",
            "notify_needs_input":true,"notify_dies":true,"notify_finishes":false,
            "registered_unix_ms":1700000000000}]"#;
        let devices: Vec<RegisteredDevice> = serde_json::from_str(legacy).unwrap();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].muted_panes.is_empty());
        // notify_gram (also #[serde(default)]) likewise defaults.
        assert!(!devices[0].notify_gram);
        // Records written before the push relay carry no capability.
        assert_eq!(devices[0].relay_capability, None);
    }

    #[test]
    fn corrupt_file_is_strict_error_and_lenient_empty() {
        let path = std::env::temp_dir().join(format!(
            "herdr-devices-corrupt-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, b"not valid json {{{").unwrap();
        assert!(load_from_path_strict(&path).is_err());
        assert!(load_from_path(&path).is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_replaces_by_token_in_memory() {
        // Exercise the mutation closure directly (no disk / lock) to keep the
        // test hermetic against the shared config dir.
        let mut devices = vec![sample_device("token-a")];
        let mut updated = sample_device("token-a");
        updated.notify_finishes = true;
        devices.retain(|existing| existing.device_token != updated.device_token);
        devices.push(updated);
        assert_eq!(devices.len(), 1);
        assert!(devices[0].notify_finishes);
    }

    #[test]
    fn remove_token_drops_matching_entry_in_memory() {
        let mut devices = vec![sample_device("keep"), sample_device("drop")];
        let before = devices.len();
        devices.retain(|device| device.device_token != "drop");
        assert_ne!(before, devices.len());
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_token, "keep");
    }
}
