//! The "staged build" manifest.
//!
//! A fleet build step can build a newer daemon binary and STAGE it (without restarting),
//! recording what it staged in `~/.config/herdr/staged-build.json`. The app reads this (via
//! `server.staged_update`) to show "an update is available", and the owner activates it with
//! `server.apply_staged_update`. Device-local JSON, secret-free, mirroring the other small
//! persist stores ([`crate::persist::machine`]).

use std::io;
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

/// Remove the staged manifest — called once the staged build is the one running, so the app
/// stops reporting an available update.
pub fn clear() {
    let _ = std::fs::remove_file(manifest_path());
}

/// Append a suffix to a path's file name (not [`Path::with_extension`], which would REPLACE any
/// existing extension — the daemon binary has none, but appending is unambiguous).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Verify a staged binary is safe to swap in: it exists, is a regular non-empty file, and (unix)
/// has an executable bit. This is a cheap sanity gate; the real correctness guard is that the
/// live-handoff validates the replacement reports the expected version.
pub fn verify_staged_binary(path: &Path) -> io::Result<()> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "staged binary is not a regular file",
        ));
    }
    if meta.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged binary is empty",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "staged binary is not executable",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Install the staged binary over the `live` path, first backing up the current live binary so a
/// failed apply can restore it. Returns the backup path. Uses copy-to-temp + rename-over-live: you
/// cannot overwrite a RUNNING executable in place (ETXTBSY), but you can rename another file over
/// its path. Assumes `staged` was already verified with [`verify_staged_binary`].
pub fn install_staged_binary(staged: &Path, live: &Path) -> io::Result<PathBuf> {
    let backup = sibling(live, ".bak-preapply");
    std::fs::copy(live, &backup)?;

    let tmp = sibling(live, ".apply-tmp");
    if let Err(err) = std::fs::copy(staged, &tmp).and_then(|_| set_executable(&tmp)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = std::fs::rename(&tmp, live) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(backup)
}

/// Restore a backup produced by [`install_staged_binary`] back over `live` (rollback after a
/// failed handoff), so the on-disk binary matches the still-running old server.
pub fn restore_backup(backup: &Path, live: &Path) -> io::Result<()> {
    let tmp = sibling(live, ".restore-tmp");
    if let Err(err) = std::fs::copy(backup, &tmp).and_then(|_| set_executable(&tmp)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    std::fs::rename(&tmp, live)
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

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "herdr-apply-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write_exec(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn install_swaps_the_binary_and_backs_up_the_old_one() {
        let dir = temp_dir("install");
        let live = dir.join("herdr");
        let staged = dir.join("herdr.staged");
        write_exec(&live, b"OLD-BINARY");
        write_exec(&staged, b"NEW-BINARY");

        let backup = install_staged_binary(&staged, &live).unwrap();
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"NEW-BINARY",
            "live is now the staged binary"
        );
        assert_eq!(
            std::fs::read(&backup).unwrap(),
            b"OLD-BINARY",
            "backup holds the old binary"
        );

        // Rollback restores the old bytes over live.
        restore_backup(&backup, &live).unwrap();
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"OLD-BINARY",
            "restore rolls live back"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn verify_rejects_empty_missing_and_nonexecutable() {
        let dir = temp_dir("verify");
        assert!(
            verify_staged_binary(&dir.join("nope")).is_err(),
            "missing → err"
        );

        let empty = dir.join("empty");
        write_exec(&empty, b"");
        assert!(verify_staged_binary(&empty).is_err(), "empty → err");

        let nonexec = dir.join("nonexec");
        std::fs::write(&nonexec, b"data").unwrap(); // no exec bit
        assert!(
            verify_staged_binary(&nonexec).is_err(),
            "non-executable → err"
        );

        let good = dir.join("good");
        write_exec(&good, b"MZ...binary");
        assert!(
            verify_staged_binary(&good).is_ok(),
            "regular non-empty executable → ok"
        );

        let _ = std::fs::remove_dir_all(&dir);
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
