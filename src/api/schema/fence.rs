use serde::{Deserialize, Serialize};

/// Internal: a request from a caller inside a pane fence that may only act on the
/// caller's own pane or agent. The server builds it; it never comes off the wire.
/// The app looks up the caller's pane by `mount_namespace`, checks that `method`
/// targets it, then runs `method` (docs/next/design/pane-fence.md, section 8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FenceScopedParams {
    /// The caller's mount namespace (inode of `/proc/<pid>/ns/mnt`).
    pub mount_namespace: u64,
    pub method: Box<super::Method>,
}

/// `fence.explain`: how the pane fence treats a pane, and optionally one path in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FenceExplainParams {
    /// A pane id, or an agent name or label.
    pub target: String,
    /// An absolute path, or one starting with `~/` (the server's home).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FenceExplanation {
    pub pane_id: String,
    /// The `[fence.agents]` name the pane is fenced as; absent for a plain pane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Whether the pane's process runs inside a fence now. Absent when it cannot be
    /// inspected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_fenced: Option<bool>,
    /// Whether the current config fences this pane when it next starts.
    pub config_fences: bool,
    /// Read-only paths in the current config's plan, when it fences this pane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_count: Option<usize>,
    /// Configured entries that match nothing on this host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<FencePathExplanation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FencePathExplanation {
    pub path: String,
    /// The path after `~` expansion and symlink resolution on the host.
    pub resolved: String,
    /// Access under the current config.
    pub access: FenceAccess,
    /// The rule that decides `access`, such as `deny /etc` or `not denied`.
    pub rule: String,
    /// The path is a mount point inside the fence, so it cannot be deleted or renamed.
    pub pinned: bool,
    /// Whether the running pane's mount table makes the path read-only. Absent when
    /// it cannot be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced_read_only: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FenceAccess {
    Writable,
    ReadOnly,
    /// A socket hidden behind an empty read-only file.
    Masked,
}
