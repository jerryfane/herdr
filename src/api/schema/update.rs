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
