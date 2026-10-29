use serde::{Deserialize, Serialize};

/// The build this server is running, as `server.update_check` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpdateRunningBuild {
    pub version: String,
    /// Short git commit; absent on a build with no git context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub protocol: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_generation: Option<u32>,
    /// Committer time of `commit`, unix seconds. A build without it is never
    /// offered an update, because it can't tell a newer build from an older one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_time: Option<i64>,
}

/// The newest signed preview build published for this server's platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpdateLatestBuild {
    /// `<base_version>-preview.<build_id>`.
    pub version: String,
    /// Full git commit.
    pub commit: String,
    pub build_id: String,
    pub built_at: String,
    /// Committer time of `commit`, unix seconds, covered by the signature.
    pub commit_time: i64,
    pub notes: String,
    /// Size of this platform's binary in bytes.
    pub size: u64,
    pub protocol: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_generation: Option<u32>,
}

/// How this server can switch to a new build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    /// A live handoff: panes and connections carry over.
    Live,
    /// The new build can be downloaded now but only takes over on a restart.
    RestartRequired,
    /// This install can't be updated from the app.
    Unsupported,
}

/// Why `mode` is not `live`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateModeReason {
    Windows,
    SystemdMainProcess,
    PackageManaged,
    EndpointGenerationChanged,
    NoLiveHandoff,
    InstallDirNotWritable,
}

/// `server.update_apply`: switch this server to the signed preview build the
/// owner confirmed from `server.update_check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServerUpdateApplyParams {
    /// `latest.build_id` from `server.update_check`. A manifest that names a
    /// different build by the time of the apply is refused
    /// (`update_build_mismatch`).
    pub build_id: String,
    /// Download, verify and install the build on disk without touching the
    /// running server; it takes over on the next restart. Required when
    /// `mode` is `restart_required`.
    #[serde(default)]
    pub restart_later: bool,
}

/// Where an update attempt is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Downloading,
    /// Checking the download's size and sha256.
    Verifying,
    /// Running the new binary's `--version`.
    Testing,
    /// Live handoff to the new build.
    Switching,
    /// Watching the new server (up to 180 s).
    Confirming,
    /// Replacing the binary on disk.
    Installing,
}

/// How an update attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateOutcome {
    /// The new build serves and is installed on disk.
    Updated,
    /// The new build serves, but the on-disk binary could not be replaced, so
    /// a restart would run the previous build.
    UpdatedDiskStale,
    /// The new build failed its checks; one live handoff back restored the
    /// previous build, which passed the same checks.
    RolledBack,
    /// Nothing changed: the attempt stopped before the switch, or the switch
    /// never took effect.
    FailedNoChange,
    /// The server's state could not be confirmed; nothing was killed or
    /// restarted. See `message`.
    NeedsAttention,
    /// `restart_later`: the build is installed on disk and takes over on the
    /// next restart.
    DownloadedRestartRequired,
}

/// The newest update attempt on this machine, as `server.update_status` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpdateAttempt {
    pub attempt_id: String,
    pub build_id: String,
    /// Version that was running when the attempt started.
    pub from: String,
    /// `<base_version>-preview.<build_id>`, as `update_check` reports it.
    pub to: String,
    /// The last phase reached; it stays set once `outcome` is present.
    pub phase: UpdatePhase,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub restart_later: bool,
    /// Panes open before the switch, once the guard has counted them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panes: Option<usize>,
    /// Present once the attempt has ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<UpdateOutcome>,
    /// Why the attempt failed, or what to inspect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
