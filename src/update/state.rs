//! `<config_dir>/updates/`: the in-app update's state file, attempt lock and
//! downloads. It lives beside the config rather than in the server, so
//! whichever server is serving (the new one, or the old one after a rollback)
//! answers `server.update_status` from the same file.
//!
//! Layout:
//! - `state.json`: the newest attempt plus the builds that rolled back here;
//! - `lock`: held from a passing preflight until the guard finishes (O_EXCL);
//! - `previous/herdr`: a copy of the build that was serving, the rollback target
//!   and the binary the guard itself runs from;
//! - `<build_id>/`: the signed manifest, the download and the guard's
//!   `before.json` snapshot. After a passing switch it holds the live image.

// Windows has no live handoff: it only reads the state for `update_status`.
#![cfg_attr(windows, allow(dead_code))]

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api::schema::{UpdateAttempt, UpdateOutcome};

pub(crate) const UPDATES_DIR: &str = "updates";
const STATE_FILE: &str = "state.json";
const LOCK_FILE: &str = "lock";
pub(crate) const PREVIOUS_DIR: &str = "previous";
pub(crate) const BINARY_NAME: &str = "herdr";

/// The paths under one config directory's `updates/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateDirs {
    root: PathBuf,
}

impl UpdateDirs {
    pub(crate) fn current() -> Self {
        Self::at(crate::config::config_dir().join(UPDATES_DIR))
    }

    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn state_file(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    pub(crate) fn lock_file(&self) -> PathBuf {
        self.root.join(LOCK_FILE)
    }

    pub(crate) fn build_dir(&self, build_id: &str) -> PathBuf {
        self.root.join(build_id)
    }

    pub(crate) fn previous_dir(&self) -> PathBuf {
        self.root.join(PREVIOUS_DIR)
    }

    pub(crate) fn previous_exe(&self) -> PathBuf {
        self.previous_dir().join(BINARY_NAME)
    }

    pub(crate) fn guard_log(&self) -> PathBuf {
        self.root.join("guard.log")
    }

    /// Read the state file. A missing or damaged file reads as empty: a
    /// status read must never fail the caller, and the next apply rewrites it.
    pub(crate) fn load(&self) -> UpdateState {
        std::fs::read(self.state_file())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Replace the state file atomically (temp file, then rename), so a reader
    /// never sees a half-written file.
    pub(crate) fn store(&self, state: &UpdateState) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let bytes = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
        let tmp = self
            .root
            .join(format!(".{STATE_FILE}.{}.tmp", std::process::id()));
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, self.state_file())
    }

    /// Load, change and store the state.
    pub(crate) fn update(&self, change: impl FnOnce(&mut UpdateState)) -> io::Result<UpdateState> {
        let mut state = self.load();
        change(&mut state);
        self.store(&state)?;
        Ok(state)
    }

    /// Take the attempt lock. Fails with `AlreadyExists` while another
    /// attempt holds it.
    pub(crate) fn acquire_lock(&self, attempt_id: &str) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.lock_file())?;
        file.write_all(attempt_id.as_bytes())
    }

    #[cfg(test)]
    fn lock_held(&self) -> bool {
        self.lock_file().exists()
    }

    /// Remove a lock that its attempt can no longer release: the attempt
    /// has an outcome, or its guard exited without one. A lock whose holder
    /// the state file does not name is left alone.
    pub(crate) fn clear_stale_lock(&self, state: &UpdateState, alive: impl Fn(u32) -> bool) {
        let Ok(holder) = std::fs::read_to_string(self.lock_file()) else {
            return;
        };
        let stale = state.attempt.as_ref().is_some_and(|record| {
            record.public.attempt_id == holder
                && (record.public.outcome.is_some()
                    || record.guard_pid.is_some_and(|pid| !alive(pid)))
        });
        if stale {
            let _ = std::fs::remove_file(self.lock_file());
        }
    }

    /// Release the lock, but only the one `attempt_id` took.
    pub(crate) fn release_lock(&self, attempt_id: &str) {
        let path = self.lock_file();
        if std::fs::read_to_string(&path).is_ok_and(|holder| holder == attempt_id) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The contents of `state.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UpdateState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) attempt: Option<AttemptRecord>,
    /// Builds that failed the guard's checks here and were rolled back. They
    /// are never offered or applied again; a newer build is.
    #[serde(default)]
    pub(crate) rolled_back: Vec<String>,
}

impl UpdateState {
    pub(crate) fn has_rolled_back(&self, build_id: &str) -> bool {
        self.rolled_back.iter().any(|id| id == build_id)
    }
}

/// One attempt: what `server.update_status` reports, plus what the guard
/// needs to carry it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttemptRecord {
    #[serde(flatten)]
    pub(crate) public: UpdateAttempt,
    /// The API socket of the server that accepted the apply.
    pub(crate) socket: PathBuf,
    /// The on-disk binary a passing update replaces.
    pub(crate) install_path: PathBuf,
    /// The binary the server that accepted the apply runs from.
    pub(crate) running_exe: PathBuf,
    /// sha256 of `previous/herdr`, the build that was serving.
    pub(crate) previous_sha256: String,
    /// Recorded by the guard when it starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) guard_pid: Option<u32>,
}

/// `server.update_status`: the newest attempt, as any server reads it.
pub(crate) fn update_status() -> crate::api::schema::ResponseResult {
    crate::api::schema::ResponseResult::UpdateStatus {
        attempt: status_from(&UpdateDirs::current().load(), process_alive),
    }
}

fn status_from(state: &UpdateState, alive: impl Fn(u32) -> bool) -> Option<UpdateAttempt> {
    let record = state.attempt.as_ref()?;
    let mut attempt = record.public.clone();
    // A guard that died without recording an outcome left the server in an
    // unconfirmed state: report it as such rather than as still running.
    if attempt.outcome.is_none() && record.guard_pid.is_some_and(|pid| !alive(pid)) {
        attempt.outcome = Some(UpdateOutcome::NeedsAttention);
        attempt.message = Some(format!(
            "the update guard exited before finishing ({}); run `herdr status server` and check {}",
            attempt.message.as_deref().unwrap_or("no detail recorded"),
            UpdateDirs::current().guard_log().display()
        ));
    }
    Some(attempt)
}

#[cfg(unix)]
pub(crate) fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that the process exists.
    let exists = unsafe { libc::kill(pid, 0) } == 0
        || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    exists && !is_zombie(pid)
}

#[cfg(target_os = "linux")]
fn is_zombie(pid: libc::pid_t) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let rest = stat.get(stat.rfind(')')? + 2..)?;
            rest.chars().next()
        })
        .is_some_and(|state| state == 'Z')
}

#[cfg(all(unix, not(target_os = "linux")))]
fn is_zombie(pid: libc::pid_t) -> bool {
    std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .ok()
        .is_some_and(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .starts_with('Z')
        })
}

#[cfg(not(unix))]
pub(crate) fn process_alive(_pid: u32) -> bool {
    true
}

/// The on-disk binary an update replaces. After a live switch the server runs
/// from `updates/<build_id>/herdr`, so its own path is not the install; the
/// attempt that started it recorded the real one.
pub(crate) fn install_path() -> io::Result<PathBuf> {
    install_path_for(std::env::current_exe()?, &UpdateDirs::current())
}

/// This process's executable path. Linux reports a running binary whose
/// file was replaced on disk as `<path> (deleted)`; the path is `<path>`.
pub(crate) fn current_exe() -> io::Result<PathBuf> {
    std::env::current_exe().map(without_deleted_suffix)
}

fn without_deleted_suffix(exe: PathBuf) -> PathBuf {
    match exe
        .to_str()
        .and_then(|path| path.strip_suffix(" (deleted)"))
    {
        Some(path) => PathBuf::from(path),
        None => exe,
    }
}

fn install_path_for(exe: PathBuf, dirs: &UpdateDirs) -> io::Result<PathBuf> {
    let exe = without_deleted_suffix(exe);
    if !exe.starts_with(dirs.root()) {
        return Ok(exe);
    }
    dirs.load()
        .attempt
        .map(|record| record.install_path)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "herdr runs from {} but no update attempt recorded its install path",
                    exe.display()
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::UpdatePhase;

    fn temp_dirs(name: &str) -> UpdateDirs {
        let root =
            std::env::temp_dir().join(format!("herdr-update-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        UpdateDirs::at(root.join(UPDATES_DIR))
    }

    fn record(outcome: Option<UpdateOutcome>, guard_pid: Option<u32>) -> AttemptRecord {
        AttemptRecord {
            public: UpdateAttempt {
                attempt_id: "upd-1".into(),
                build_id: "2026-10-28-0123456789ab".into(),
                from: "0.9.5".into(),
                to: "0.9.6-preview.2026-10-28-0123456789ab".into(),
                phase: UpdatePhase::Confirming,
                bytes_done: 10,
                bytes_total: 10,
                restart_later: false,
                panes: Some(3),
                outcome,
                message: None,
            },
            socket: PathBuf::from("/run/herdr.sock"),
            install_path: PathBuf::from("/opt/herdr/bin/herdr"),
            running_exe: PathBuf::from("/opt/herdr/bin/herdr"),
            previous_sha256: "a".repeat(64),
            guard_pid,
        }
    }

    #[test]
    fn state_file_round_trips_and_status_hides_internal_fields() {
        let dirs = temp_dirs("round-trip");
        let state = UpdateState {
            attempt: Some(record(Some(UpdateOutcome::RolledBack), Some(7))),
            rolled_back: vec!["2026-10-28-0123456789ab".into()],
        };
        dirs.store(&state).unwrap();

        assert_eq!(dirs.load(), state);
        let status = serde_json::to_value(status_from(&dirs.load(), |_| true)).unwrap();
        assert_eq!(status["outcome"], "rolled_back");
        assert_eq!(status["phase"], "confirming");
        assert_eq!(status["panes"], 3);
        assert!(status.get("socket").is_none(), "{status}");
        assert!(status.get("install_path").is_none(), "{status}");
        assert!(dirs.load().has_rolled_back("2026-10-28-0123456789ab"));
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[test]
    fn damaged_or_missing_state_reads_as_no_attempt() {
        let dirs = temp_dirs("damaged");
        assert_eq!(status_from(&dirs.load(), |_| true), None);
        std::fs::create_dir_all(dirs.root()).unwrap();
        std::fs::write(dirs.state_file(), b"{not json").unwrap();
        assert_eq!(dirs.load(), UpdateState::default());
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[test]
    fn a_dead_guard_without_an_outcome_reports_needs_attention() {
        let state = UpdateState {
            attempt: Some(record(None, Some(4242))),
            rolled_back: Vec::new(),
        };
        let running = status_from(&state, |_| true).unwrap();
        assert_eq!(running.outcome, None);
        let dead = status_from(&state, |_| false).unwrap();
        assert_eq!(dead.outcome, Some(UpdateOutcome::NeedsAttention));
        assert!(dead.message.unwrap().contains("guard exited"));
    }

    #[test]
    fn the_lock_admits_one_attempt_and_only_its_holder_releases_it() {
        let dirs = temp_dirs("lock");
        dirs.acquire_lock("upd-a").unwrap();
        let second = dirs.acquire_lock("upd-b").unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::AlreadyExists);

        dirs.release_lock("upd-b");
        assert!(dirs.lock_held(), "another attempt released the lock");
        dirs.release_lock("upd-a");
        assert!(!dirs.lock_held());
        dirs.acquire_lock("upd-b").unwrap();
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[test]
    fn a_lock_left_by_a_finished_or_dead_attempt_is_cleared() {
        let dirs = temp_dirs("stale-lock");
        let mut state = UpdateState {
            attempt: Some(record(None, Some(4242))),
            rolled_back: Vec::new(),
        };
        dirs.acquire_lock("upd-1").unwrap();

        dirs.clear_stale_lock(&state, |_| true);
        assert!(dirs.lock_held(), "a running guard's lock was cleared");
        dirs.clear_stale_lock(&state, |_| false);
        assert!(!dirs.lock_held(), "a dead guard's lock was kept");

        dirs.acquire_lock("upd-1").unwrap();
        state.attempt = Some(record(Some(UpdateOutcome::Updated), None));
        dirs.clear_stale_lock(&state, |_| true);
        assert!(!dirs.lock_held(), "a finished attempt's lock was kept");

        dirs.acquire_lock("upd-other").unwrap();
        dirs.clear_stale_lock(&state, |_| false);
        assert!(
            dirs.lock_held(),
            "a lock the state does not name was cleared"
        );
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[test]
    fn install_path_survives_running_from_the_updates_dir() {
        let dirs = temp_dirs("install-path");
        let installed = PathBuf::from("/opt/herdr/bin/herdr");
        assert_eq!(
            install_path_for(installed.clone(), &dirs).unwrap(),
            installed
        );
        assert_eq!(
            install_path_for(PathBuf::from("/opt/herdr/bin/herdr (deleted)"), &dirs).unwrap(),
            installed
        );

        let running = dirs.build_dir("2026-10-28-0123456789ab").join(BINARY_NAME);
        assert!(install_path_for(running.clone(), &dirs).is_err());
        dirs.store(&UpdateState {
            attempt: Some(record(Some(UpdateOutcome::Updated), None)),
            rolled_back: Vec::new(),
        })
        .unwrap();
        assert_eq!(install_path_for(running, &dirs).unwrap(), installed);
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }
}
