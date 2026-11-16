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
