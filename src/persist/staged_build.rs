//! The "staged build" manifest.
//!
//! A fleet build step can build a newer daemon binary and STAGE it (without restarting),
//! recording what it staged in `~/.config/herdr/staged-build.json`. The app reads this (via
//! `server.staged_update`) to show "an update is available", and the owner activates it with
//! `server.apply_staged_update`. Device-local JSON, secret-free, mirroring the other small
//! persist stores ([`crate::persist::machine`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A daemon build that has been compiled and staged but is not yet the running binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedBuild {
    /// Human-readable version string of the staged binary (e.g. `"0.8.0"`).
    pub version: String,
    /// Short git sha the staged binary was built from.
    pub sha: String,
    /// When it was built, as an RFC3339 timestamp (advisory, for display/ordering).
    pub built_at: String,
    /// Absolute path to the staged binary on disk, so the activate step knows what to swap
    /// in. The staged file lives outside the live path until activation.
    pub path: String,
}

fn manifest_path() -> PathBuf {
    crate::config::config_dir().join("staged-build.json")
}

/// Read the staged-build manifest, or `None` when nothing is staged or it is unreadable.
///
/// Best-effort by design: a missing or malformed manifest simply means "no update staged",
/// never an error — a read of update state must not fail the caller.
pub fn load() -> Option<StagedBuild> {
    load_from_path(&manifest_path())
}

fn load_from_path(path: &Path) -> Option<StagedBuild> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "herdr-staged-{tag}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn round_trips_a_staged_manifest() {
        let staged = StagedBuild {
            version: "0.8.0".into(),
            sha: "abc1234".into(),
            built_at: "2026-08-23T15:00:00Z".into(),
            path: "/root/.local/bin/herdr.staged".into(),
        };
        let path = temp_path("roundtrip");
        std::fs::write(&path, serde_json::to_string(&staged).unwrap()).unwrap();
        assert_eq!(load_from_path(&path), Some(staged));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_or_malformed_is_none_never_an_error() {
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_from_path(&path), None, "missing manifest → None");

        std::fs::write(&path, b"not json {{").unwrap();
        assert_eq!(load_from_path(&path), None, "malformed manifest → None");
        let _ = std::fs::remove_file(&path);
    }
}
