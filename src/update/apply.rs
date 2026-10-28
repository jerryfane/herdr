//! `server.update_apply`: preflight, then hand the attempt to the update
//! guard. Everything that can fail without the owner noticing (download,
//! verification, smoke test, the switch and its confirmation) happens in the
//! guard, after this call has answered, because the switch drops every client.
//!
//! The guard runs from `updates/previous/herdr`, a copy of the build that is
//! serving now, in its own session, so it outlives this server and can hand
//! the panes back to that same build if the new one fails its checks.

use std::io;
use std::path::Path;

use crate::api::schema::{
    ResponseResult, ServerUpdateApplyParams, UpdateAttempt, UpdateMode, UpdateModeReason,
    UpdateOutcome, UpdatePhase,
};

use super::server_update::InstallFacts;
use super::state::{AttemptLock, AttemptRecord, UpdateDirs, UpdateState, BINARY_NAME};
use super::verify::{self, PlatformAsset, RunningBuild, VerifyError};
use super::{preview_display_version, PreviewManifest, PREVIEW_UPDATE_MANIFEST_URL};

/// The signed manifest files the guard verifies again from disk.
pub(crate) const MANIFEST_FILE: &str = "preview.json";
pub(crate) const SIGNATURE_FILE: &str = "preview.json.minisig";
/// Room for the download, the copy beside the install and the rollback copy.
const FREE_SPACE_FACTOR: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplyError {
    Verify(VerifyError),
    BuildMismatch {
        requested: String,
        published: String,
    },
    InProgress,
    NotAvailable(String),
    RestartRequired(UpdateModeReason),
    UnsupportedInstall(UpdateModeReason),
    PreflightFailed(String),
}

impl ApplyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Verify(err) => err.code(),
            Self::BuildMismatch { .. } => "update_build_mismatch",
            Self::InProgress => "update_in_progress",
            Self::NotAvailable(_) => "update_not_available",
            Self::RestartRequired(_) => "update_restart_required",
            Self::UnsupportedInstall(_) => "update_unsupported_install",
            Self::PreflightFailed(_) => "update_preflight_failed",
        }
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verify(err) => err.fmt(f),
            Self::BuildMismatch {
                requested,
                published,
            } => write!(
                f,
                "build {requested} is no longer the newest signed build; {published} is. \
                 Check again before updating"
            ),
            Self::InProgress => write!(f, "another update attempt is still running"),
            Self::NotAvailable(detail) => write!(f, "no update to apply: {detail}"),
            Self::RestartRequired(reason) => write!(
                f,
                "this server can't switch builds live ({}); apply with restart_later to \
                 install it for the next restart",
                reason_code(*reason)
            ),
            Self::UnsupportedInstall(reason) => write!(
                f,
                "this install can't be updated from the app ({})",
                reason_code(*reason)
            ),
            Self::PreflightFailed(detail) => write!(f, "update preflight failed: {detail}"),
        }
    }
}

fn reason_code(reason: UpdateModeReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

impl From<VerifyError> for ApplyError {
    fn from(err: VerifyError) -> Self {
        Self::Verify(err)
    }
}

/// Everything preflight decides on, gathered before any change is made.
pub(super) struct Preflight<'a> {
    pub(super) manifest: &'a PreviewManifest,
    pub(super) asset: Option<&'a PlatformAsset>,
    pub(super) running: &'a RunningBuild,
    pub(super) state: &'a UpdateState,
    pub(super) facts: &'a InstallFacts,
    /// Free bytes on the filesystem that holds `updates/`.
    pub(super) free_bytes: io::Result<u64>,
}

/// The refusals that leave everything untouched, in the order the owner
/// should hear about them. They run under the attempt lock, so a busy lock
/// (`update_in_progress`) is reported first.
pub(super) fn preflight(
    params: &ServerUpdateApplyParams,
    checks: Preflight<'_>,
) -> Result<(), ApplyError> {
    let manifest = checks.manifest;
    if params.build_id != manifest.build_id {
        return Err(ApplyError::BuildMismatch {
            requested: params.build_id.clone(),
            published: manifest.build_id.clone(),
        });
    }
    let Some(asset) = checks.asset else {
        return Err(ApplyError::NotAvailable(format!(
            "build {} publishes no binary for {}",
            manifest.build_id,
            verify::platform_asset_key()
        )));
    };
    if !checks.running.is_older_than(manifest) {
        return Err(ApplyError::NotAvailable(format!(
            "build {} is not newer than the running build",
            manifest.build_id
        )));
    }
    if checks.state.has_rolled_back(&manifest.build_id) {
        return Err(ApplyError::NotAvailable(format!(
            "build {} failed its checks here and was rolled back; wait for a newer build",
            manifest.build_id
        )));
    }
    match checks.facts.mode(Some(manifest)) {
        (UpdateMode::Unsupported, reason) => {
            return Err(ApplyError::UnsupportedInstall(
                reason.unwrap_or(UpdateModeReason::InstallDirNotWritable),
            ))
        }
        (UpdateMode::RestartRequired, reason) if !params.restart_later => {
            return Err(ApplyError::RestartRequired(
                reason.unwrap_or(UpdateModeReason::NoLiveHandoff),
            ))
        }
        _ => {}
    }
    let needed = asset.size.saturating_mul(FREE_SPACE_FACTOR);
    match checks.free_bytes {
        Ok(free) if free >= needed => Ok(()),
        Ok(free) => Err(ApplyError::PreflightFailed(format!(
            "{free} bytes free for updates, {needed} needed (3x the {} byte download)",
            asset.size
        ))),
        Err(err) => Err(ApplyError::PreflightFailed(format!(
            "can't read free disk space: {err}"
        ))),
    }
}

/// Run preflight and start the guard; answers with the attempt id.
pub(crate) fn update_apply(params: &ServerUpdateApplyParams) -> Result<ResponseResult, ApplyError> {
    let signed = verify::fetch_signed_manifest_files(PREVIEW_UPDATE_MANIFEST_URL)?;
    let manifest = &signed.manifest;
    let asset = verify::platform_asset(manifest)?;
    let dirs = UpdateDirs::current();
    // Taken before the state is read, so the rolled-back builds preflight
    // checks are the ones the last attempt left.
    let lock = match dirs.acquire_lock() {
        Ok(Some(lock)) => lock,
        Ok(None) => return Err(ApplyError::InProgress),
        Err(err) => {
            return Err(ApplyError::PreflightFailed(format!(
                "can't take the update lock: {err}"
            )))
        }
    };
    let state = dirs.load();
    preflight(
        params,
        Preflight {
            manifest,
            asset: asset.as_ref(),
            running: &RunningBuild::current(),
            state: &state,
            facts: &InstallFacts::detect(),
            free_bytes: free_bytes(dirs.root()),
        },
    )?;
    let asset = asset.expect("preflight requires an asset");
    let attempt_id = new_attempt_id();
    // On success the guard holds the lock; this server's copy closes here
    // either way, so a failed start leaves no lock behind.
    start_attempt(&dirs, params, &signed, &asset, &attempt_id, &lock)
        .map_err(|err| ApplyError::PreflightFailed(err.to_string()))?;
    Ok(ResponseResult::UpdateApply { attempt_id })
}

fn new_attempt_id() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("upd-{millis}-{}", std::process::id())
}

/// Write the manifest, the rollback copy and the state, then spawn the guard.
fn start_attempt(
    dirs: &UpdateDirs,
    params: &ServerUpdateApplyParams,
    signed: &verify::SignedManifest,
    asset: &PlatformAsset,
    attempt_id: &str,
    lock: &AttemptLock,
) -> io::Result<()> {
    let manifest = &signed.manifest;
    let install_path = super::state::install_path()?;

    let build_dir = dirs.build_dir(&manifest.build_id);
    match std::fs::remove_dir_all(&build_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    std::fs::create_dir_all(&build_dir)?;
    std::fs::write(build_dir.join(MANIFEST_FILE), &signed.bytes)?;
    std::fs::write(build_dir.join(SIGNATURE_FILE), &signed.minisig)?;

    let previous = dirs.previous_exe();
    copy_running_image(&previous)?;
    let previous_sha256 = crate::checksum::file_sha256(&previous)?;

    let record = AttemptRecord {
        public: UpdateAttempt {
            attempt_id: attempt_id.to_string(),
            build_id: manifest.build_id.clone(),
            from: crate::build_info::version(),
            to: preview_display_version(&manifest.base_version, &manifest.build_id),
            phase: UpdatePhase::Downloading,
            bytes_done: 0,
            bytes_total: asset.size,
            restart_later: params.restart_later,
            panes: None,
            outcome: None,
            message: None,
        },
        socket: crate::api::socket_path(),
        install_path,
        running_exe: super::state::current_exe()?,
        previous_sha256,
    };
    dirs.update(|state| state.attempt = Some(record))?;

    if let Err(err) = spawn_guard(&previous, attempt_id, lock) {
        let message = format!("the update guard did not start: {err}");
        let _ = dirs.update(|state| {
            if let Some(attempt) = state.attempt.as_mut() {
                attempt.public.outcome = Some(UpdateOutcome::FailedNoChange);
                attempt.public.message = Some(message.clone());
            }
        });
        return Err(io::Error::other(message));
    }
    Ok(())
}

/// Copy the image this process runs, not whatever its path holds now: after a
/// rollback or an on-disk install the path can name a different file.
fn copy_running_image(dest: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let source = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let source = std::env::current_exe()?;
    let dir = dest
        .parent()
        .ok_or_else(|| io::Error::other("rollback copy has no parent directory"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{BINARY_NAME}.{}.tmp", std::process::id()));
    std::fs::copy(&source, &tmp)?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, dest)
}

/// Start `<previous> server update-guard --attempt <id> --lock-fd <fd>` in its
/// own session with null stdio, so neither this server's exit nor its
/// terminal stops it. It inherits the attempt lock as descriptor `<fd>`. The
/// environment is inherited, so the guard resolves the same socket and
/// config directory.
fn spawn_guard(exe: &Path, attempt_id: &str, lock: &AttemptLock) -> io::Result<()> {
    use std::os::unix::process::CommandExt as _;
    let mut command = std::process::Command::new(exe);
    command
        .args(["server", "update-guard", "--attempt", attempt_id])
        .args(["--lock-fd", &lock.fd().to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    lock.pass_to(&mut command);
    // SAFETY: setsid is async-signal-safe and touches no Rust state.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    // Reap it if it ends while this server still runs; after a switch the
    // guard is reparented and this thread ends with the process.
    std::thread::Builder::new()
        .name("herdr-update-guard-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        })?;
    Ok(())
}

fn free_bytes(dir: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains a NUL byte"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stats` is a valid out pointer.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs succeeded, so it filled `stats`.
    let stats = unsafe { stats.assume_init() };
    // The field types differ between platforms (u32 on macOS, u64 on Linux).
    #[allow(clippy::useless_conversion)]
    let (available, fragment) = (u64::from(stats.f_bavail), u64::from(stats.f_frsize));
    Ok(available.saturating_mul(fragment))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: InstallFacts = InstallFacts {
        windows: false,
        package_managed: false,
        install_dir_writable: true,
        live_handoff: true,
        systemd_main_process: false,
    };
    const BUILD_ID: &str = "2026-10-28-0123456789ab";
    const SIZE: u64 = 40_000_000;

    fn manifest() -> PreviewManifest {
        let key = verify::platform_asset_key();
        let mut value = serde_json::json!({
            "schema_version": 2,
            "channel": "preview",
            "base_version": "0.9.6",
            "build_id": BUILD_ID,
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "commit_time": 1_761_638_400,
            "built_at": "2026-10-28T08:00:00Z",
            "protocol": 22,
            "endpoint_generation": crate::protocol::endpoint::ENDPOINT_PROTOCOL_GENERATION,
            "notes": "Preview build",
            "assets": {}
        });
        value["assets"][&key] = serde_json::json!({
            "url": format!("{}preview-{BUILD_ID}/herdr-{key}", super::super::EXPECTED_RELEASE_ROOT),
            "sha256": "b".repeat(64),
            "size": SIZE
        });
        serde_json::from_value(value).unwrap()
    }

    fn running(commit_time: i64) -> RunningBuild {
        RunningBuild {
            commit: Some("8a02b834abcd".into()),
            build_id: None,
            commit_time: Some(commit_time),
        }
    }

    fn params(build_id: &str, restart_later: bool) -> ServerUpdateApplyParams {
        ServerUpdateApplyParams {
            build_id: build_id.into(),
            restart_later,
        }
    }

    struct Case {
        params: ServerUpdateApplyParams,
        running: RunningBuild,
        state: UpdateState,
        facts: InstallFacts,
        free_bytes: io::Result<u64>,
        with_asset: bool,
    }

    impl Case {
        fn passing() -> Self {
            Self {
                params: params(BUILD_ID, false),
                running: running(1_761_580_000),
                state: UpdateState::default(),
                facts: LIVE,
                free_bytes: Ok(SIZE * 3),
                with_asset: true,
            }
        }

        fn run(self) -> Result<(), ApplyError> {
            let manifest = manifest();
            let asset = verify::platform_asset(&manifest).unwrap();
            preflight(
                &self.params,
                Preflight {
                    manifest: &manifest,
                    asset: asset.as_ref().filter(|_| self.with_asset),
                    running: &self.running,
                    state: &self.state,
                    facts: &self.facts,
                    free_bytes: self.free_bytes,
                },
            )
        }
    }

    #[test]
    fn preflight_passes_a_newer_build_with_room_to_spare() {
        assert_eq!(Case::passing().run(), Ok(()));
    }

    #[test]
    fn preflight_refuses_a_build_the_owner_did_not_confirm() {
        let err = Case {
            params: params("2026-10-27-ffffffffffff", false),
            ..Case::passing()
        }
        .run()
        .unwrap_err();
        assert_eq!(err.code(), "update_build_mismatch", "{err}");
    }

    #[test]
    fn preflight_refuses_a_build_that_is_not_newer() {
        let err = Case {
            running: running(1_761_638_400),
            ..Case::passing()
        }
        .run()
        .unwrap_err();
        assert_eq!(err.code(), "update_not_available", "{err}");
    }

    #[test]
    fn preflight_refuses_a_build_without_this_platform() {
        let err = Case {
            with_asset: false,
            ..Case::passing()
        }
        .run()
        .unwrap_err();
        assert_eq!(err.code(), "update_not_available", "{err}");
    }

    #[test]
    fn preflight_refuses_a_build_that_rolled_back_here() {
        let err = Case {
            state: UpdateState {
                attempt: None,
                rolled_back: vec![BUILD_ID.into()],
            },
            ..Case::passing()
        }
        .run()
        .unwrap_err();
        assert_eq!(err.code(), "update_not_available", "{err}");
        assert!(err.to_string().contains("rolled back"), "{err}");
    }

    #[test]
    fn preflight_refuses_each_unsupported_install() {
        for facts in [
            InstallFacts {
                package_managed: true,
                ..LIVE
            },
            InstallFacts {
                install_dir_writable: false,
                ..LIVE
            },
            InstallFacts {
                windows: true,
                ..LIVE
            },
        ] {
            // restart_later can't help an install the server can't replace.
            let err = Case {
                params: params(BUILD_ID, true),
                facts,
                ..Case::passing()
            }
            .run()
            .unwrap_err();
            assert_eq!(err.code(), "update_unsupported_install", "{facts:?}: {err}");
        }
    }

    #[test]
    fn preflight_refuses_a_live_switch_the_supervisor_or_platform_forbids() {
        for facts in [
            InstallFacts {
                systemd_main_process: true,
                ..LIVE
            },
            InstallFacts {
                live_handoff: false,
                ..LIVE
            },
        ] {
            let err = Case {
                facts,
                ..Case::passing()
            }
            .run()
            .unwrap_err();
            assert_eq!(err.code(), "update_restart_required", "{facts:?}: {err}");
            assert_eq!(
                Case {
                    params: params(BUILD_ID, true),
                    facts,
                    ..Case::passing()
                }
                .run(),
                Ok(()),
                "restart_later downloads for the next restart"
            );
        }
    }

    #[test]
    fn preflight_refuses_without_three_times_the_download_free() {
        let err = Case {
            free_bytes: Ok(SIZE * 3 - 1),
            ..Case::passing()
        }
        .run()
        .unwrap_err();
        assert_eq!(err.code(), "update_preflight_failed", "{err}");
        let err = Case {
            free_bytes: Err(io::Error::other("statvfs failed")),
            ..Case::passing()
        }
        .run()
        .unwrap_err();
        assert_eq!(err.code(), "update_preflight_failed", "{err}");
    }

    #[test]
    fn free_bytes_reads_the_filesystem() {
        assert!(free_bytes(&std::env::temp_dir()).unwrap() > 0);
    }
}
