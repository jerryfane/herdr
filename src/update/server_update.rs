//! `server.update_check`: what the owner's app shows before it offers
//! "Update herdr". The manifest goes through the same verification as
//! `herdr update` ([`super::verify`]).

use crate::api::schema::{
    ResponseResult, UpdateLatestBuild, UpdateMode, UpdateModeReason, UpdateRunningBuild,
};

use super::verify::{self, RunningBuild, VerifyError};
use super::{preview_display_version, PreviewManifest, PREVIEW_UPDATE_MANIFEST_URL};

/// Fetch and verify the signed manifest and describe the update it offers.
pub(crate) fn update_check() -> Result<ResponseResult, VerifyError> {
    let manifest = verify::fetch_signed_manifest(PREVIEW_UPDATE_MANIFEST_URL)?;
    let state = super::state::UpdateDirs::current().load();
    update_check_from(
        &manifest,
        &RunningBuild::current(),
        &InstallFacts::detect(),
        &state,
    )
}

/// What the switch to a new build depends on, apart from the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InstallFacts {
    pub(super) windows: bool,
    pub(super) package_managed: bool,
    pub(super) install_dir_writable: bool,
    pub(super) live_handoff: bool,
    pub(super) systemd_main_process: bool,
}

impl InstallFacts {
    pub(super) fn detect() -> Self {
        Self {
            windows: cfg!(windows),
            package_managed: super::is_package_manager_managed_install(),
            install_dir_writable: install_dir_writable(),
            live_handoff: crate::platform::capabilities().live_handoff,
            #[cfg(unix)]
            systemd_main_process: crate::server::supervision::detect().forbids_process_handoff(),
            #[cfg(not(unix))]
            systemd_main_process: false,
        }
    }

    /// Unsupported reasons win over restart-required ones: there is nothing to
    /// download into an install the server can't replace.
    pub(super) fn mode(
        &self,
        manifest: Option<&PreviewManifest>,
    ) -> (UpdateMode, Option<UpdateModeReason>) {
        let unsupported = if self.windows {
            Some(UpdateModeReason::Windows)
        } else if self.package_managed {
            Some(UpdateModeReason::PackageManaged)
        } else if !self.install_dir_writable {
            Some(UpdateModeReason::InstallDirNotWritable)
        } else {
            None
        };
        if let Some(reason) = unsupported {
            return (UpdateMode::Unsupported, Some(reason));
        }
        let restart = if !self.live_handoff {
            Some(UpdateModeReason::NoLiveHandoff)
        } else if self.systemd_main_process {
            Some(UpdateModeReason::SystemdMainProcess)
        } else if manifest.is_some_and(|manifest| {
            manifest.endpoint_generation
                != Some(crate::protocol::endpoint::ENDPOINT_PROTOCOL_GENERATION)
        }) {
            Some(UpdateModeReason::EndpointGenerationChanged)
        } else {
            None
        };
        match restart {
            Some(reason) => (UpdateMode::RestartRequired, Some(reason)),
            None => (UpdateMode::Live, None),
        }
    }
}

/// The install's directory takes a new file. After a live switch the server
/// runs from `updates/`, so this checks the recorded install, not itself.
fn install_dir_writable() -> bool {
    let Some(dir) = super::state::install_path()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
    else {
        return false;
    };
    let probe = dir.join(format!(".herdr-update-probe-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// `state` holds the builds that rolled back here: they are never offered
/// again, so the app does not loop on a build this machine already refused.
pub(super) fn update_check_from(
    manifest: &PreviewManifest,
    running: &RunningBuild,
    facts: &InstallFacts,
    state: &super::state::UpdateState,
) -> Result<ResponseResult, VerifyError> {
    let latest = verify::platform_asset(manifest)?.map(|asset| UpdateLatestBuild {
        version: preview_display_version(&manifest.base_version, &manifest.build_id),
        commit: manifest.commit.clone(),
        build_id: manifest.build_id.clone(),
        built_at: manifest.built_at.clone(),
        commit_time: manifest.commit_time.unwrap_or_default(),
        notes: manifest.notes.clone(),
        size: asset.size,
        protocol: manifest.protocol,
        endpoint_generation: manifest.endpoint_generation,
    });
    let update_available = latest.is_some()
        && running.is_older_than(manifest)
        && !state.has_rolled_back(&manifest.build_id);
    let (mode, reason) = facts.mode(latest.as_ref().map(|_| manifest));
    Ok(ResponseResult::UpdateCheck {
        running: UpdateRunningBuild {
            version: crate::build_info::version(),
            commit: running.commit.clone(),
            build_id: running.build_id.clone(),
            protocol: crate::protocol::PROTOCOL_VERSION,
            endpoint_generation: Some(crate::protocol::endpoint::ENDPOINT_PROTOCOL_GENERATION),
            commit_time: running.commit_time,
        },
        latest,
        update_available,
        mode,
        reason,
    })
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

    fn manifest(
        commit_time: i64,
        endpoint_generation: Option<u32>,
        with_asset: bool,
    ) -> PreviewManifest {
        let key = verify::platform_asset_key();
        let build_id = "2026-10-28-0123456789ab";
        let mut value = serde_json::json!({
            "schema_version": 2,
            "channel": "preview",
            "base_version": "0.9.6",
            "build_id": build_id,
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "commit_time": commit_time,
            "built_at": "2026-10-28T08:00:00Z",
            "protocol": 22,
            "endpoint_generation": endpoint_generation,
            "notes": "Preview build",
            "assets": {}
        });
        if with_asset {
            value["assets"][&key] = serde_json::json!({
                "url": format!("{}preview-{build_id}/herdr-{key}", super::super::EXPECTED_RELEASE_ROOT),
                "sha256": "b".repeat(64),
                "size": 41_943_040
            });
        }
        serde_json::from_value(value).unwrap()
    }

    fn running(commit_time: i64) -> RunningBuild {
        RunningBuild {
            commit: Some("8a02b834abcd".into()),
            build_id: Some("2026-10-27-8a02b834abcd".into()),
            commit_time: Some(commit_time),
        }
    }

    fn json(result: ResponseResult) -> serde_json::Value {
        serde_json::to_value(result).unwrap()
    }

    fn check(
        manifest: &PreviewManifest,
        running: &RunningBuild,
        facts: &InstallFacts,
    ) -> Result<ResponseResult, VerifyError> {
        update_check_from(
            manifest,
            running,
            facts,
            &super::super::state::UpdateState::default(),
        )
    }

    #[test]
    fn a_build_that_rolled_back_here_is_not_offered_again() {
        let newer = manifest(1_761_638_400, Some(1), true);
        let state = super::super::state::UpdateState {
            attempt: None,
            rolled_back: vec![newer.build_id.clone()],
        };
        let result =
            json(update_check_from(&newer, &running(1_761_580_000), &LIVE, &state).unwrap());
        assert_eq!(result["update_available"], false, "{result}");
        assert_eq!(result["latest"]["build_id"], newer.build_id);
    }

    #[test]
    fn newer_signed_build_is_offered_live_with_the_agreed_shape() {
        let result = json(
            check(
                &manifest(1_761_638_400, Some(1), true),
                &running(1_761_580_000),
                &LIVE,
            )
            .unwrap(),
        );

        assert_eq!(result["type"], "update_check");
        assert_eq!(result["update_available"], true);
        assert_eq!(result["mode"], "live");
        assert!(result.get("reason").is_none(), "{result}");
        assert_eq!(result["running"]["commit"], "8a02b834abcd");
        assert_eq!(result["running"]["commit_time"], 1_761_580_000);
        assert_eq!(
            result["latest"]["version"],
            "0.9.6-preview.2026-10-28-0123456789ab"
        );
        assert_eq!(result["latest"]["commit_time"], 1_761_638_400);
        assert_eq!(result["latest"]["size"], 41_943_040);
        assert_eq!(result["latest"]["protocol"], 22);
    }

    #[test]
    fn older_or_equal_signed_build_is_not_offered() {
        for commit_time in [1_761_580_000, 1_700_000_000] {
            let result = json(
                check(
                    &manifest(commit_time, Some(1), true),
                    &running(1_761_580_000),
                    &LIVE,
                )
                .unwrap(),
            );
            assert_eq!(result["update_available"], false, "{commit_time}");
            assert_eq!(result["latest"]["commit_time"], commit_time);
        }
    }

    #[test]
    fn manifest_without_this_platform_reports_latest_null() {
        let result = json(
            check(
                &manifest(1_761_638_400, Some(1), false),
                &running(1_761_580_000),
                &LIVE,
            )
            .unwrap(),
        );
        assert!(result["latest"].is_null(), "{result}");
        assert_eq!(result["update_available"], false);
    }

    #[test]
    fn each_install_fact_selects_its_mode_and_reason() {
        let newer = manifest(1_761_638_400, Some(1), true);
        let cases = [
            (
                InstallFacts {
                    windows: true,
                    ..LIVE
                },
                "unsupported",
                "windows",
            ),
            (
                InstallFacts {
                    package_managed: true,
                    ..LIVE
                },
                "unsupported",
                "package_managed",
            ),
            (
                InstallFacts {
                    install_dir_writable: false,
                    ..LIVE
                },
                "unsupported",
                "install_dir_not_writable",
            ),
            (
                InstallFacts {
                    live_handoff: false,
                    ..LIVE
                },
                "restart_required",
                "no_live_handoff",
            ),
            (
                InstallFacts {
                    systemd_main_process: true,
                    ..LIVE
                },
                "restart_required",
                "systemd_main_process",
            ),
        ];
        for (facts, mode, reason) in cases {
            let result = json(check(&newer, &running(1_761_580_000), &facts).unwrap());
            assert_eq!(result["mode"], mode, "{facts:?}");
            assert_eq!(result["reason"], reason, "{facts:?}");
        }
        let next_generation = manifest(1_761_638_400, Some(2), true);
        let result = json(check(&next_generation, &running(1_761_580_000), &LIVE).unwrap());
        assert_eq!(result["mode"], "restart_required");
        assert_eq!(result["reason"], "endpoint_generation_changed");
    }
}
