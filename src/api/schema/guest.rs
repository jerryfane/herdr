//! Guest access (owner RPCs and audit log shapes). Secrets and keys never
//! appear here: invites expose only their links, guests only fingerprints.

use serde::{Deserialize, Serialize};

use super::agents::AgentSessionInfo;

/// `guest.invite.create`: invite one named guest to one live local agent.
/// With `machine`, the coordinator routes the call to that saved SSH machine
/// and `target` names the agent there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestInviteCreateParams {
    /// Agent pane id or agent name. The agent must be named, running and have a
    /// stable harness session.
    pub target: String,
    /// Guest name, `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`. Prompts arrive labeled
    /// `<name> (via HerdrUp): `.
    pub name: String,
    pub owner_name: String,
    pub machine_label: String,
    /// Invite lifetime in seconds (60 to 604800). Default: 86400.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Share the agent's Gram with the guest: every Gram the agent sends from
    /// the moment the guest accepts, with its files and push notifications.
    /// Default: false.
    #[serde(default)]
    pub share_gram: bool,
    /// Saved SSH machine alias to route this call to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// `guest.update`: change an accepted guest's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestUpdateParams {
    pub guest_id: String,
    /// Share the agent's Gram with this guest (see `guest.invite.create`).
    pub share_gram: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// `guest.list`: guests, invites and relay link state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// `guest.revoke`: exactly one of `guest_id` or `invite_id`. Revoking a guest
/// closes its live sessions immediately.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestRevokeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// `guest.audit`: activity log entries, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestAuditParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_id: Option<String>,
    /// Maximum entries (1 to 500). Default: 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Only entries strictly older than this timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
}

/// Internal probe: `terminal_id` wins over `target`.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestAgentProbeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// The one agent a guest may use: the agent with this name and kind in this
/// terminal. A restarted agent keeps the grant, and `agent_session` follows
/// its latest harness session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestGrantInfo {
    pub terminal_id: String,
    pub agent_name: Option<String>,
    /// Agent kind at invite time, for example `claude`. Grants from before
    /// this field use `agent_session.agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_kind: Option<String>,
    pub agent_session: AgentSessionInfo,
}

#[cfg(unix)]
impl GuestGrantInfo {
    pub fn kind(&self) -> &str {
        self.agent_kind
            .as_deref()
            .unwrap_or(&self.agent_session.agent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestInviteInfo {
    pub invite_id: String,
    pub name: String,
    pub grant: GuestGrantInfo,
    pub owner_name: String,
    pub machine_label: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    /// Guest id that accepted this invite, once used.
    pub used_by: Option<String>,
    /// The guest will see the agent's Gram (see `guest.invite.create`).
    #[serde(default)]
    pub share_gram: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestInfo {
    pub guest_id: String,
    pub name: String,
    /// `SHA256:` plus the first 8 bytes of SHA-256(device key), for example
    /// `SHA256:9f3a·e71c·04bd·c21e`.
    pub fingerprint: String,
    pub device: String,
    pub grant: GuestGrantInfo,
    pub created_ms: u64,
    pub last_seen_ms: Option<u64>,
    pub revoked: bool,
    /// The guest sees the agent's Gram: every Gram the agent sent from
    /// `created_ms` on, with its files and push notifications.
    #[serde(default)]
    pub share_gram: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuestLinkState {
    Off,
    Connecting,
    Up,
    Retrying,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestLinkInfo {
    pub state: GuestLinkState,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuestAuditEvent {
    Accepted,
    Connected,
    Prompt,
    Upload,
    Denied,
    Paused,
    Revoked,
    /// The granted agent came back under a new harness session.
    Resumed,
    /// The guest opened a shared Gram's file.
    GramFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestAuditFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// One `audit.jsonl` line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestAuditEntry {
    pub ts_ms: u64,
    pub guest_id: String,
    pub name: String,
    pub fingerprint: String,
    pub event: GuestAuditEvent,
    /// Terminal id of the granted pane.
    pub pane: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<GuestAuditFile>,
}
