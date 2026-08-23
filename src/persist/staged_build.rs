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

/// Swap the staged binary onto the `live` path: copy to a temp beside it, mark it executable, then
/// rename over `live` (atomic, and ETXTBSY-safe — you cannot overwrite a RUNNING executable in
/// place, but you can rename another file over its path).
///
/// Called ONLY AFTER a successful `live_handoff`, so it needs no backup: the new build is already
/// running (the handoff spawned it from the staged path and validated its version before commit),
/// and this only updates the on-disk live path so a future restart runs the new build too. The
/// old binary is being intentionally replaced. Assumes `staged` was verified with
/// [`verify_staged_binary`].
pub fn activate_on_disk(staged: &Path, live: &Path) -> io::Result<()> {
    let tmp = sibling(live, ".apply-tmp");
    if let Err(err) = std::fs::copy(staged, &tmp).and_then(|_| set_executable(&tmp)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(err) = std::fs::rename(&tmp, live) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

/// The outcome of a staged apply once the handoff has committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The new build is running AND the on-disk live path was updated to it.
    Activated,
    /// The new build is running (the handoff committed), but updating the on-disk live path
    /// FAILED — so a future hard restart would run the PREVIOUS build until re-applied. A distinct
    /// signal so this running-new/disk-old divergence is never a silent success.
    ActivatedDiskUpdateFailed,
}

/// Orchestrate a staged apply, VALIDATE-BEFORE-SWAP. Runs `handoff` FIRST — it spawns + validates
/// the replacement from the staged binary and commits it — while the on-disk `live` path is left
/// UNTOUCHED, so a failed handoff propagates with the live binary BYTE-UNCHANGED (nothing to roll
/// back). Only AFTER a committed handoff is the live path swapped to the new build, and that swap
/// is best-effort (the new build is already running): a swap failure returns
/// [`ApplyOutcome::ActivatedDiskUpdateFailed`] rather than a bare success.
///
/// `handoff` is injected so this ordering invariant — the whole point of the apply path — is
/// unit-testable without a real process re-exec.
pub fn apply_with_handoff<F>(staged: &Path, live: &Path, handoff: F) -> io::Result<ApplyOutcome>
where
    F: FnOnce() -> io::Result<()>,
{
    handoff()?; // pre-commit: on failure the live path was never touched
    match activate_on_disk(staged, live) {
        Ok(()) => Ok(ApplyOutcome::Activated),
        Err(err) => {
            tracing::error!(
                %err,
                "apply_staged_update: handed off to the new build, but updating the on-disk live \
                 binary path failed; a future restart may run the previous build until re-applied"
            );
            Ok(ApplyOutcome::ActivatedDiskUpdateFailed)
        }
    }
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
    fn activate_swaps_the_live_binary_to_the_staged_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("activate");
        let live = dir.join("herdr");
        let staged = dir.join("herdr.staged");
        write_exec(&live, b"OLD-BINARY");
        write_exec(&staged, b"NEW-BINARY");

        activate_on_disk(&staged, &live).unwrap();
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"NEW-BINARY",
            "live is now the staged binary"
        );
        assert!(
            std::fs::metadata(&live).unwrap().permissions().mode() & 0o111 != 0,
            "the swapped-in binary keeps its executable bit"
        );
        // No stray backup/temp files linger next to the live path.
        assert!(!sibling(&live, ".apply-tmp").exists());
        assert!(!sibling(&live, ".bak-preapply").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn apply_with_handoff_swaps_only_after_a_committed_handoff() {
        let dir = temp_dir("apply-order");
        let live = dir.join("herdr");
        let staged = dir.join("herdr.staged");
        write_exec(&live, b"OLD-BINARY");
        write_exec(&staged, b"NEW-BINARY");

        // Validate-before-swap invariant: a FAILED handoff must leave the live path BYTE-UNCHANGED
        // (nothing is swapped pre-commit). Mutation guard: reorder the swap before the handoff and
        // this assertion goes RED — the exact HIGH/MEDIUM regression class.
        let result = apply_with_handoff(&staged, &live, || Err(io::Error::other("handoff failed")));
        assert!(result.is_err(), "a failed handoff propagates");
        assert_eq!(
            std::fs::read(&live).unwrap(),
            b"OLD-BINARY",
            "a failed handoff must leave the live binary byte-unchanged"
        );

        // A committed handoff swaps the live path AFTER commit.
        let outcome = apply_with_handoff(&staged, &live, || Ok(())).unwrap();
        assert_eq!(outcome, ApplyOutcome::Activated);
        assert_eq!(std::fs::read(&live).unwrap(), b"NEW-BINARY");

        // Committed handoff but the on-disk swap FAILS (live path is a directory) → a DISTINCT
        // partial outcome, never a silent clean success.
        let live_dir = dir.join("live-as-dir");
        std::fs::create_dir(&live_dir).unwrap();
        let partial = apply_with_handoff(&staged, &live_dir, || Ok(())).unwrap();
        assert_eq!(partial, ApplyOutcome::ActivatedDiskUpdateFailed);

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
    fn clear_removes_the_manifest_and_is_a_noop_when_absent() {
        let _guard = crate::config::test_config_env_lock().lock().unwrap();
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        let home = temp_dir("clear");
        std::env::set_var("XDG_CONFIG_HOME", &home);
        std::fs::create_dir_all(crate::config::config_dir()).unwrap();

        std::fs::write(
            manifest_path(),
            br#"{"version":"1","sha":"a","built_at":"t","path":"/x"}"#,
        )
        .unwrap();
        assert!(load().is_some(), "manifest present before clear");
        clear();
        assert!(load().is_none(), "clear() removes the manifest");
        clear(); // absent now — must not panic/error

        match prev {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);
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
