//! `<config_dir>/updates/`: the in-app update's state file, attempt lock and
//! downloads. It lives beside the config rather than in the server, so
//! whichever server is serving (the new one, or the old one after a rollback)
//! answers `server.update_status` from the same file.
//!
//! Layout:
//! - `state.json`: the newest attempt plus the builds that rolled back here;
//! - `lock`: an exclusive `flock` held from a passing preflight until the
//!   guard has recorded the outcome (see `AttemptLock`). The file stays;
//!   only the kernel lock on it matters;
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
const GUARD_LOG: &str = "guard.log";
/// The names under `updates/` that are not build directories.
pub(crate) const LAYOUT_NAMES: [&str; 4] = [STATE_FILE, LOCK_FILE, PREVIOUS_DIR, GUARD_LOG];

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

    #[cfg(unix)]
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
        self.root.join(GUARD_LOG)
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

    /// Take the attempt lock, or `None` while another attempt holds it.
    #[cfg(unix)]
    pub(crate) fn acquire_lock(&self) -> io::Result<Option<AttemptLock>> {
        use std::os::fd::AsRawFd as _;
        std::fs::create_dir_all(&self.root)?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock_file())?;
        // The guard's stdio replaces descriptors 0-2 before it inherits this
        // one, so keep it above them (`try_clone` dups to 3 or higher).
        if file.as_raw_fd() <= 2 {
            file = file.try_clone()?;
        }
        // `load_settled` holds the lock shared for the length of one state
        // read, so a busy lock is retried briefly before it counts as held.
        for _ in 0..LOCK_TRIES {
            if try_flock(&file, libc::LOCK_EX)? {
                return Ok(Some(AttemptLock(file)));
            }
            std::thread::sleep(LOCK_RETRY);
        }
        Ok(None)
    }

    /// The state, and whether an attempt holds the lock, read consistently:
    /// when the lock is free the state is read under a shared lock, which no
    /// attempt can take or give up meanwhile, because apply and the guard
    /// write the state only while they hold it exclusively.
    #[cfg(unix)]
    pub(crate) fn load_settled(&self) -> (UpdateState, bool) {
        let file = match std::fs::File::open(self.lock_file()) {
            Ok(file) => file,
            // No attempt has ever taken the lock here.
            Err(err) if err.kind() == io::ErrorKind::NotFound => return (self.load(), false),
            Err(_) => return (self.load(), true),
        };
        match try_flock(&file, libc::LOCK_SH) {
            Ok(true) => (self.load(), false),
            // Held, or unknown: never report an attempt dead without proof.
            Ok(false) | Err(_) => (self.load(), true),
        }
    }

    /// Windows starts no attempts; nothing proves one dead.
    #[cfg(not(unix))]
    pub(crate) fn load_settled(&self) -> (UpdateState, bool) {
        (self.load(), true)
    }
}

#[cfg(unix)]
const LOCK_TRIES: u32 = 10;
#[cfg(unix)]
const LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(25);

/// `flock(operation | LOCK_NB)`: `Ok(false)` when another open file holds a
/// conflicting lock.
#[cfg(unix)]
fn try_flock(file: &std::fs::File, operation: libc::c_int) -> io::Result<bool> {
    use std::os::fd::AsRawFd as _;
    loop {
        // SAFETY: `file` owns an open descriptor for the whole call.
        if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EWOULDBLOCK) => return Ok(false),
            _ => return Err(err),
        }
    }
}

/// The attempt lock: an exclusive `flock` on `updates/lock`, held from a
/// passing preflight until the guard has recorded the outcome. The server
/// that accepts the apply takes it, the guard inherits the same open file
/// (`pass_to`, then `inherited`), and the server closes its copy. The
/// kernel drops the lock when the last copy closes, so a server that dies
/// before the guard starts, or a guard that dies at any point, leaves no
/// lock behind, and nothing ever decides a lock is stale. The file is never
/// removed: a removed file would let a second attempt lock a new file while
/// the first still holds the old one.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct AttemptLock(std::fs::File);

#[cfg(unix)]
impl AttemptLock {
    /// The descriptor number the guard is told to take over.
    pub(crate) fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.0.as_raw_fd()
    }

    /// Let `command`'s process inherit this lock: the descriptor stays open
    /// across its exec (every other descriptor of this process closes on
    /// exec).
    pub(crate) fn pass_to(&self, command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt as _;
        let fd = self.fd();
        // SAFETY: runs in the forked child before exec; fcntl is
        // async-signal-safe and touches only the child's descriptor table.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    /// Take over the lock `pass_to` handed this process as descriptor `fd`.
    /// Refused unless `fd` is open on `dirs`' lock file and holds its lock;
    /// it is closed on exec again, so the guard's own children don't keep it.
    pub(crate) fn inherited(dirs: &UpdateDirs, fd: std::os::fd::RawFd) -> io::Result<Self> {
        use std::os::fd::{FromRawFd as _, IntoRawFd as _};
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: F_GETFD only reads the flags of `fd`, if it is open.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is open, and nothing else in this process owns it: it
        // was inherited for exactly this. If it is not the lock file it is
        // handed back below without being closed.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let same_file = match (file.metadata(), std::fs::metadata(dirs.lock_file())) {
            (Ok(held), Ok(lock)) => held.dev() == lock.dev() && held.ino() == lock.ino(),
            _ => false,
        };
        if !same_file {
            let _ = file.into_raw_fd();
            return Err(io::Error::other(format!(
                "descriptor {fd} is not {}",
                dirs.lock_file().display()
            )));
        }
        // SAFETY: `file` owns the open descriptor `fd`.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Already held through this open file, this succeeds at once;
        // otherwise another attempt holds it and this process must not run.
        if !try_flock(&file, libc::LOCK_EX)? {
            return Err(io::Error::other("another attempt holds the update lock"));
        }
        Ok(Self(file))
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
}

/// `server.update_status`: the newest attempt, as any server reads it.
pub(crate) fn update_status() -> crate::api::schema::ResponseResult {
    let (state, running) = UpdateDirs::current().load_settled();
    crate::api::schema::ResponseResult::UpdateStatus {
        attempt: status_from(&state, running),
    }
}

/// `running`: an attempt holds the lock (see `UpdateDirs::load_settled`).
fn status_from(state: &UpdateState, running: bool) -> Option<UpdateAttempt> {
    let record = state.attempt.as_ref()?;
    let mut attempt = record.public.clone();
    // An attempt without an outcome whose lock is free was cut short: the
    // server died before the guard started, or the guard died. The server's
    // state is unconfirmed: report it as such rather than as still running.
    if attempt.outcome.is_none() && !running {
        attempt.outcome = Some(UpdateOutcome::NeedsAttention);
        attempt.message = Some(format!(
            "the update attempt stopped before finishing ({}); run `herdr status server` and check {}",
            attempt.message.as_deref().unwrap_or("no detail recorded"),
            UpdateDirs::current().guard_log().display()
        ));
    }
    Some(attempt)
}

/// Server start: a `restart_later` attempt whose build is now the one running
/// has finished, so record it as `updated`. Without this the record would
/// report a pending restart forever. Errors are logged, never fatal.
#[cfg(unix)]
pub(crate) fn settle_restart_later_on_start() {
    let running = super::verify::RunningBuild::current();
    if let Err(err) = settle_restart_later(
        &UpdateDirs::current(),
        running.build_id.as_deref(),
        running.commit.as_deref(),
    ) {
        tracing::warn!("could not settle the pending update record: {err}");
    }
}

/// Rewrite a `DownloadedRestartRequired` attempt as `Updated` when its build
/// is the one running: the running build id matches, or, for a build without
/// an embedded id (manual artifact builds), the running commit matches the
/// record build id's 12-char sha suffix. A record for any other build (the
/// install was replaced, or rolled back) is left alone, and so is everything
/// while an attempt holds the lock. Returns whether the record changed.
#[cfg(unix)]
fn settle_restart_later(
    dirs: &UpdateDirs,
    running_build_id: Option<&str>,
    running_commit: Option<&str>,
) -> io::Result<bool> {
    if running_build_id.is_none() && running_commit.is_none() {
        return Ok(false);
    }
    let pending = |state: &UpdateState| {
        state.attempt.as_ref().is_some_and(|record| {
            record.public.outcome == Some(UpdateOutcome::DownloadedRestartRequired)
                && is_running_build(&record.public.build_id, running_build_id, running_commit)
        })
    };
    // Cheap check first: most starts have nothing to settle and must not
    // create the updates dir or lock file.
    if !pending(&dirs.load()) {
        return Ok(false);
    }
    let Some(_lock) = dirs.acquire_lock()? else {
        return Ok(false);
    };
    let mut changed = false;
    dirs.update(|state| {
        if !pending(state) {
            return;
        }
        if let Some(record) = state.attempt.as_mut() {
            record.public.outcome = Some(UpdateOutcome::Updated);
            record.public.message = Some(format!(
                "build {} took over when herdr restarted",
                record.public.build_id
            ));
            changed = true;
        }
    })?;
    Ok(changed)
}

/// Whether `record_build_id` (`<date>-<12-char sha>`) names the running build.
/// The embedded build id decides when there is one. Without it the running
/// commit's first 12 chars must equal the id's whole 12-char sha suffix. A
/// shorter commit (build.rs's `git rev-parse --short` fallback) never matches:
/// its prefix can name another build, so the record stays pending.
#[cfg(unix)]
fn is_running_build(
    record_build_id: &str,
    running_build_id: Option<&str>,
    running_commit: Option<&str>,
) -> bool {
    if let Some(running_build_id) = running_build_id {
        return record_build_id == running_build_id;
    }
    let Some(commit) = running_commit.and_then(|commit| commit.get(..12)) else {
        return false;
    };
    record_build_id
        .rsplit_once('-')
        .is_some_and(|(_, sha)| sha == commit)
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
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

/// The executable to hand to children that can outlive this server. A
/// server that a live switch started runs from `updates/<build_id>/herdr`,
/// which a later update removes; the install path outlives every update, so
/// children get it whenever it exists. Any other path is returned unchanged.
pub(crate) fn exe_for_children(exe: PathBuf) -> PathBuf {
    exe_for_children_in(exe, &UpdateDirs::current())
}

fn exe_for_children_in(exe: PathBuf, dirs: &UpdateDirs) -> PathBuf {
    if !exe.starts_with(dirs.root()) {
        return exe;
    }
    match install_path_for(exe.clone(), dirs) {
        Ok(install) if install.is_file() => install,
        _ => exe,
    }
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

    fn record(outcome: Option<UpdateOutcome>) -> AttemptRecord {
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
        }
    }

    #[test]
    fn state_file_round_trips_and_status_hides_internal_fields() {
        let dirs = temp_dirs("round-trip");
        let state = UpdateState {
            attempt: Some(record(Some(UpdateOutcome::RolledBack))),
            rolled_back: vec!["2026-10-28-0123456789ab".into()],
        };
        dirs.store(&state).unwrap();

        assert_eq!(dirs.load(), state);
        let status = serde_json::to_value(status_from(&dirs.load(), false)).unwrap();
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
        assert_eq!(status_from(&dirs.load(), false), None);
        std::fs::create_dir_all(dirs.root()).unwrap();
        std::fs::write(dirs.state_file(), b"{not json").unwrap();
        assert_eq!(dirs.load(), UpdateState::default());
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[test]
    fn an_unfinished_attempt_whose_lock_is_free_reports_needs_attention() {
        let state = UpdateState {
            attempt: Some(record(None)),
            rolled_back: Vec::new(),
        };
        let running = status_from(&state, true).unwrap();
        assert_eq!(running.outcome, None);
        let dead = status_from(&state, false).unwrap();
        assert_eq!(dead.outcome, Some(UpdateOutcome::NeedsAttention));
        assert!(dead.message.unwrap().contains("stopped before finishing"));

        let finished = UpdateState {
            attempt: Some(record(Some(UpdateOutcome::Updated))),
            rolled_back: Vec::new(),
        };
        let done = status_from(&finished, false).unwrap();
        assert_eq!(done.outcome, Some(UpdateOutcome::Updated));
    }

    #[cfg(unix)]
    fn pending_restart(dirs: &UpdateDirs) -> UpdateState {
        let mut attempt = record(Some(UpdateOutcome::DownloadedRestartRequired));
        attempt.public.restart_later = true;
        let state = UpdateState {
            attempt: Some(attempt),
            rolled_back: Vec::new(),
        };
        dirs.store(&state).unwrap();
        state
    }

    #[cfg(unix)]
    #[test]
    fn a_restart_later_attempt_settles_once_its_build_is_running() {
        let dirs = temp_dirs("settle-running");
        pending_restart(&dirs);
        assert!(settle_restart_later(&dirs, Some("2026-10-28-0123456789ab"), None).unwrap());
        let status = status_from(&dirs.load(), false).unwrap();
        assert_eq!(status.outcome, Some(UpdateOutcome::Updated));
        assert!(status.message.unwrap().contains("took over"));
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_restart_later_attempt_for_another_build_stays_pending() {
        let dirs = temp_dirs("settle-other");
        let state = pending_restart(&dirs);
        for (build_id, commit) in [
            (Some("2026-10-27-8a02b834abcd"), None),
            // An embedded id decides even when the commit would match.
            (Some("2026-10-27-8a02b834abcd"), Some(RECORD_COMMIT)),
            (None, None),
            // A build without an embedded id, from a different commit.
            (None, Some("8a02b834abcdef0123456789abcdef0123456789")),
            (None, Some("012345")),
        ] {
            assert!(!settle_restart_later(&dirs, build_id, commit).unwrap());
            assert_eq!(dirs.load(), state);
        }
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    /// The full commit of the record's build `2026-10-28-0123456789ab`.
    #[cfg(unix)]
    const RECORD_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[cfg(unix)]
    #[test]
    fn a_restart_later_attempt_settles_on_its_commit_without_a_build_id() {
        let dirs = temp_dirs("settle-commit");
        pending_restart(&dirs);
        assert!(settle_restart_later(&dirs, None, Some(RECORD_COMMIT)).unwrap());
        assert_eq!(
            dirs.load().attempt.unwrap().public.outcome,
            Some(UpdateOutcome::Updated)
        );
        // A commit of exactly the id's 12 chars settles too.
        pending_restart(&dirs);
        assert!(settle_restart_later(&dirs, None, Some("0123456789ab")).unwrap());
        let status = status_from(&dirs.load(), false).unwrap();
        assert_eq!(status.outcome, Some(UpdateOutcome::Updated));
        assert!(status.message.unwrap().contains("2026-10-28-0123456789ab"));
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    /// A git `--short` commit (build.rs's fallback) cannot tell apart builds
    /// that share its prefix: `7c5e760` names both real commits below, so the
    /// record stays pending.
    #[cfg(unix)]
    #[test]
    fn a_short_commit_leaves_a_restart_later_attempt_pending() {
        let dirs = temp_dirs("settle-short");
        let mut attempt = record(Some(UpdateOutcome::DownloadedRestartRequired));
        attempt.public.restart_later = true;
        attempt.public.build_id = "2026-11-17-7c5e760fd2b2".into();
        let state = UpdateState {
            attempt: Some(attempt),
            rolled_back: Vec::new(),
        };
        dirs.store(&state).unwrap();
        for commit in ["7c5e760", "7c5e760684c7bfda7c21153a4e246aaa179af15f"] {
            assert!(!settle_restart_later(&dirs, None, Some(commit)).unwrap());
            assert_eq!(dirs.load(), state);
        }
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_held_lock_leaves_a_restart_later_attempt_alone() {
        let dirs = temp_dirs("settle-locked");
        let state = pending_restart(&dirs);
        let holder = hold_in_child(dirs.acquire_lock().unwrap().unwrap());
        let settled = settle_restart_later(&dirs, Some("2026-10-28-0123456789ab"), None).unwrap();
        let after = dirs.load();
        kill(holder);
        assert!(!settled);
        assert_eq!(after, state);
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    /// Hand `lock` to a child process the way the server hands it to the
    /// guard, then close this process's copy: the child is the only holder.
    #[cfg(unix)]
    fn hold_in_child(lock: AttemptLock) -> std::process::Child {
        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        lock.pass_to(&mut command);
        let child = command.spawn().unwrap();
        drop(lock);
        child
    }

    #[cfg(unix)]
    fn kill(mut child: std::process::Child) {
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_admits_one_attempt_until_its_holder_closes_it() {
        let dirs = temp_dirs("lock");
        assert!(!dirs.load_settled().1, "no attempt ever ran here");
        let first = dirs.acquire_lock().unwrap().expect("a free lock is taken");
        assert!(dirs.acquire_lock().unwrap().is_none());
        assert!(dirs.load_settled().1);

        drop(first);
        assert!(!dirs.load_settled().1);
        let _second = dirs.acquire_lock().unwrap().expect("a closed lock is free");
        assert!(dirs.lock_file().exists(), "the lock file is never removed");
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    /// (a) The server dies after taking the lock, before it records the attempt.
    #[cfg(unix)]
    #[test]
    fn a_server_that_dies_before_recording_the_attempt_leaves_no_lock() {
        let dirs = temp_dirs("dead-before-record");
        let earlier = UpdateState {
            attempt: Some(record(Some(UpdateOutcome::Updated))),
            rolled_back: Vec::new(),
        };
        dirs.store(&earlier).unwrap();
        let server = hold_in_child(dirs.acquire_lock().unwrap().unwrap());
        assert!(dirs.acquire_lock().unwrap().is_none());

        kill(server);

        let (state, running) = dirs.load_settled();
        assert!(!running);
        assert_eq!(
            status_from(&state, running).unwrap().outcome,
            Some(UpdateOutcome::Updated),
            "the earlier attempt is reported unchanged"
        );
        assert!(
            dirs.acquire_lock().unwrap().is_some(),
            "a later apply takes the lock"
        );
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    /// (b) The server dies after recording the attempt, before it spawns the guard.
    #[cfg(unix)]
    #[test]
    fn a_server_that_dies_before_spawning_the_guard_leaves_no_lock() {
        let dirs = temp_dirs("dead-before-spawn");
        let lock = dirs.acquire_lock().unwrap().unwrap();
        dirs.update(|state| state.attempt = Some(record(None)))
            .unwrap();
        let server = hold_in_child(lock);
        let (state, running) = dirs.load_settled();
        assert!(running);
        assert_eq!(status_from(&state, running).unwrap().outcome, None);

        kill(server);

        let (state, running) = dirs.load_settled();
        assert_eq!(
            status_from(&state, running).unwrap().outcome,
            Some(UpdateOutcome::NeedsAttention)
        );
        assert!(
            dirs.acquire_lock().unwrap().is_some(),
            "a later apply takes the lock"
        );
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    /// (c) The guard inherits the lock and dies before it writes anything;
    /// the server already closed its copy.
    #[cfg(unix)]
    #[test]
    fn a_guard_that_dies_before_writing_anything_leaves_no_lock() {
        let dirs = temp_dirs("dead-guard");
        let lock = dirs.acquire_lock().unwrap().unwrap();
        dirs.update(|state| state.attempt = Some(record(None)))
            .unwrap();
        let guard = hold_in_child(lock);
        assert!(
            dirs.acquire_lock().unwrap().is_none(),
            "the guard holds the lock once the server closed its copy"
        );

        kill(guard);

        let (state, running) = dirs.load_settled();
        assert_eq!(
            status_from(&state, running).unwrap().outcome,
            Some(UpdateOutcome::NeedsAttention)
        );
        assert!(
            dirs.acquire_lock().unwrap().is_some(),
            "a later apply takes the lock"
        );
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    /// Holders that close while new attempts and status reads race them: no
    /// two attempts ever hold the lock at once, and the lock file stays put,
    /// so a new holder's lock can't be removed from under it.
    #[cfg(unix)]
    #[test]
    fn racing_attempts_and_status_reads_never_share_the_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dirs = temp_dirs("race");
        let holders = AtomicUsize::new(0);
        let taken = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..10 {
                        if let Some(lock) = dirs.acquire_lock().unwrap() {
                            assert_eq!(
                                holders.fetch_add(1, Ordering::SeqCst),
                                0,
                                "two attempts held the lock"
                            );
                            taken.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(2));
                            holders.fetch_sub(1, Ordering::SeqCst);
                            drop(lock);
                        }
                    }
                });
            }
            scope.spawn(|| {
                for _ in 0..200 {
                    let _ = dirs.load_settled();
                }
            });
        });
        assert!(taken.load(Ordering::SeqCst) > 0);
        assert!(dirs.lock_file().exists());
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn the_guard_takes_over_only_the_lock_it_inherited() {
        use std::os::fd::{AsRawFd as _, IntoRawFd as _};
        let dirs = temp_dirs("inherit");
        let lock = dirs.acquire_lock().unwrap().unwrap();

        let other = std::fs::File::open("/dev/null").unwrap();
        assert!(AttemptLock::inherited(&dirs, other.as_raw_fd()).is_err());
        assert!(other.metadata().is_ok(), "a refused descriptor stays open");

        let taken = AttemptLock::inherited(&dirs, lock.0.into_raw_fd()).unwrap();
        assert!(dirs.acquire_lock().unwrap().is_none());
        drop(taken);

        // An open lock file that is not the holder's is refused.
        let _holder = dirs.acquire_lock().unwrap().unwrap();
        let stray = std::fs::File::open(dirs.lock_file()).unwrap();
        assert!(AttemptLock::inherited(&dirs, stray.into_raw_fd()).is_err());
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
            attempt: Some(record(Some(UpdateOutcome::Updated))),
            rolled_back: Vec::new(),
        })
        .unwrap();
        assert_eq!(install_path_for(running, &dirs).unwrap(), installed);
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }

    #[test]
    fn children_get_the_install_path_while_it_exists() {
        let dirs = temp_dirs("children");
        let install = dirs.root().parent().unwrap().join("bin").join(BINARY_NAME);
        let running = dirs.build_dir("2026-10-28-0123456789ab").join(BINARY_NAME);
        let deleted = PathBuf::from(format!("{} (deleted)", running.display()));
        let elsewhere = PathBuf::from("/opt/herdr/bin/herdr (deleted)");
        // Outside `updates/` the path is untouched, as before.
        assert_eq!(exe_for_children_in(elsewhere.clone(), &dirs), elsewhere);
        // Without a recorded install the running path is all there is.
        assert_eq!(exe_for_children_in(running.clone(), &dirs), running);

        let mut attempt = record(Some(UpdateOutcome::Updated));
        attempt.install_path = install.clone();
        dirs.store(&UpdateState {
            attempt: Some(attempt),
            rolled_back: Vec::new(),
        })
        .unwrap();
        // A recorded install that is gone is no better than the build dir.
        assert_eq!(exe_for_children_in(running.clone(), &dirs), running);

        std::fs::create_dir_all(install.parent().unwrap()).unwrap();
        std::fs::write(&install, b"herdr").unwrap();
        assert_eq!(exe_for_children_in(running, &dirs), install);
        assert_eq!(exe_for_children_in(deleted, &dirs), install);
        assert_eq!(
            exe_for_children_in(dirs.previous_exe(), &dirs),
            install,
            "the rollback copy is replaced by every update too"
        );
        let _ = std::fs::remove_dir_all(dirs.root().parent().unwrap());
    }
}
