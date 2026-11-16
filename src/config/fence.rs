//! `[fence]`: the pane fence (docs/next/design/pane-fence.md).
//!
//! The section is validated as a whole when it is deserialized, so an invalid
//! `[fence]` table is rejected by `herdr server reload-config` without applying
//! half of it, and the previous fence settings stay in force.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The pane fence: every process started in a pane runs with a read-only deny
/// list, masked sockets and reduced capabilities. Linux only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawFenceConfig")]
pub struct FenceConfig {
    /// Fence every pane process started from now on. `false` keeps today's behavior.
    pub enabled: bool,
    /// Paths that are read-only inside fenced panes. Absolute, or starting with `~/`.
    /// A `*` inside one path component matches siblings when the pane starts. Unset
    /// means the built-in default list.
    pub deny: Option<Vec<String>>,
    /// Paths that are writable again inside a denied parent. Each must lie below a
    /// `deny` entry.
    pub allow: Vec<String>,
    /// Unix sockets masked inside fenced panes, so `connect()` fails. Unset means
    /// the built-in default list.
    pub mask_sockets: Option<Vec<String>>,
    /// Paths that stay writable but cannot be deleted or renamed inside fenced
    /// panes (each is bound onto itself). Unset means the built-in list.
    pub pin: Option<Vec<String>>,
    /// Which panes are fenced: every pane, or only the agents listed in `agents`.
    pub scope: FenceScope,
    /// Per-agent entries, keyed by the herdr agent name a pane was started as.
    pub agents: BTreeMap<String, FenceAgent>,
}

/// `[fence] scope`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceScope {
    /// Every pane, except agents listed with `profile = "unfenced"`.
    #[default]
    All,
    /// Only agents listed with `profile = "default"`; every other pane is unfenced.
    Agents,
}

/// `[fence.agents.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceAgent {
    #[serde(default)]
    pub profile: FenceProfile,
    /// Why this agent has an entry. Required.
    pub reason: String,
}

/// The fence an agent entry selects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceProfile {
    /// The `[fence]` settings.
    #[default]
    Default,
    /// No fence for this agent.
    Unfenced,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawFenceConfig {
    enabled: bool,
    deny: Option<Vec<String>>,
    allow: Vec<String>,
    mask_sockets: Option<Vec<String>>,
    pin: Option<Vec<String>>,
    scope: FenceScope,
    agents: BTreeMap<String, FenceAgent>,
}

impl TryFrom<RawFenceConfig> for FenceConfig {
    type Error = String;

    fn try_from(raw: RawFenceConfig) -> Result<Self, Self::Error> {
        let config = Self {
            enabled: raw.enabled,
            deny: raw.deny,
            allow: raw.allow,
            mask_sockets: raw.mask_sockets,
            pin: raw.pin,
            scope: raw.scope,
            agents: raw.agents,
        };
        let errors = crate::fence::validate_config(&config);
        if errors.is_empty() {
            Ok(config)
        } else {
            Err(errors.join("; "))
        }
    }
}
