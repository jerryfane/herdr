use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::common::{AgentStatus, ReadFormat, ReadSource};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentReadParams {
    pub target: String,
    pub source: ReadSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<u32>,
    #[serde(default)]
    pub format: ReadFormat,
    #[serde(default = "super::common::default_true")]
    pub strip_ansi: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentSendKeysParams {
    pub target: String,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentWaitParams {
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub until: Vec<AgentStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentPromptWaitOptions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub until: Vec<AgentStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentRenameParams {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// `agent.archive` — take an agent out of active rotation (issue #173). The pane
/// is released but the session ref is preserved, so `agent.unarchive` can resume
/// (not recreate) it later. Rejected when the agent is mid-turn unless `force`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentArchiveParams {
    pub target: String,
    /// Optional free-text note recorded on the archived record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Who requested the archive; recorded verbatim. Defaults server-side to
    /// `"api"` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// Opaque open-work list, stored and returned verbatim (gitmoot supplies and
    /// renders it; herdr does not interpret it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parked_work: Vec<serde_json::Value>,
    /// Archive even when the agent is currently working / mid-turn.
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub force: bool,
}

/// `agent.unarchive` — resume a previously archived agent (issue #173). The
/// stored session ref is resumed into a fresh pane, preserving the agent's
/// terminal identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentUnarchiveParams {
    /// The archived agent's name or terminal id.
    pub target: String,
    /// Start a clean agent for the preserved terminal identity instead of
    /// resuming the archived session. The operator escape hatch when the
    /// session is gone or unwanted.
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub fresh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentViewSetParams {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AgentViewFilter>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort: Vec<AgentViewSort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct AgentViewClearParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentViewFilter {
    All {
        filters: Vec<AgentViewFilter>,
    },
    Any {
        filters: Vec<AgentViewFilter>,
    },
    Not {
        filter: Box<AgentViewFilter>,
    },
    Eq {
        field: AgentViewField,
        value: AgentViewValue,
    },
    In {
        field: AgentViewField,
        values: Vec<AgentViewValue>,
    },
    Exists {
        field: AgentViewField,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum AgentViewField {
    Builtin(AgentViewBuiltinField),
    Token { token: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentViewBuiltinField {
    Status,
    InputPending,
    InputPromptKind,
    WorkspaceId,
    TabId,
    PaneId,
    Agent,
    Seen,
    StateChangeSeq,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum AgentViewValue {
    String(String),
    Bool(bool),
    Number(u64),
    Context { context: AgentViewContext },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentViewContext {
    CurrentWorkspaceId,
    CurrentTabId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentViewSort {
    pub field: AgentViewSortField,
    #[serde(default)]
    pub order: AgentViewSortOrder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum AgentViewSortField {
    Builtin(AgentViewBuiltinSortField),
    Token { token: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentViewBuiltinSortField {
    WorkspaceOrder,
    TabOrder,
    PaneOrder,
    Attention,
    Status,
    Agent,
    Seen,
    StateChangeSeq,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentViewSortOrder {
    #[default]
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentStartParams {
    pub name: String,
    pub kind: String,
    pub pane_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Startup timeout in milliseconds. Values must be greater than 3000 and at most 300000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Optional credential/config-home account id (from the `[[accounts]]` config
    /// registry) to launch this agent under. Points the harness at that account's
    /// config-home directory. Must match the agent's kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentRestartParams {
    pub target: String,
    /// Optional credential/config-home account id to resume under. Absent keeps
    /// the agent's remembered account (a plain restart); present swaps to the
    /// named account for this and subsequent restarts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentPromptParams {
    pub target: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<AgentPromptWaitOptions>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentPromptDelivery {
    WrittenToPty,
    Submitted,
}

// `parked_work` holds arbitrary JSON (`serde_json::Value`), which is `PartialEq`
// but not `Eq`, so `AgentInfo` can no longer derive `Eq`. Nothing keys a
// map/set on it, so only the derive is dropped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentInfo {
    pub terminal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_title_stripped: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_agent: Option<String>,
    pub agent_status: AgentStatus,
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub input_pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_prompt_kind: Option<crate::detect::InputPromptKind>,
    #[serde(default)]
    pub composer: super::panes::ComposerInfo,
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub screen_detection_skipped: bool,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub state_labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schemars(schema_with = "super::common::metadata_token_values_schema")]
    pub tokens: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session: Option<AgentSessionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_completed_turn: Option<super::panes::LastCompletedTurn>,
    /// Advisory hint only; use `pane.turns` replay as the completeness authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<u64>,
    /// Advisory hint only; use `pane.turns` replay as the completeness authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_epoch: Option<u64>,
    pub workspace_id: String,
    pub tab_id: String,
    pub pane_id: String,
    pub focused: bool,
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub launch_pending: bool,
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub interactive_ready: bool,
    #[serde(default)]
    pub state_change_seq: u64,
    /// Wall-clock ms when the agent entered its CURRENT status (its last transition).
    /// `None` until the first detected transition, and after a restore/respawn (time in
    /// state restarts). The app derives a compact "5m/2h/3d" badge from `now - this` (#173).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_since_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreground_cwd: Option<String>,
    pub revision: u64,
    /// Federation: alias of the remote peer this agent lives on. `None` for a
    /// local agent (and serialized away).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    /// Federation: reachability of the remote peer as of the last poll. `None`
    /// for a local agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachability: Option<crate::api::federation_store::Reachability>,
    /// Federation: the peer's last-known agent status, preserved when the peer is
    /// unreachable and `agent_status` is surfaced as `unknown`. `None` for a
    /// local agent or a reachable peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_status: Option<AgentStatus>,
    /// Present only for archived agents (issue #173). Its presence is the
    /// load-bearing signal that this agent is archived; absent means active, so
    /// older clients that ignore the field see a normal (active) agent list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived: Option<AgentArchivedInfo>,
    /// Opaque open-work list carried on an archived agent, returned verbatim.
    /// Absent (empty) for active agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parked_work: Vec<serde_json::Value>,
}

/// The `archived { at, by, reason }` provenance surfaced on an archived
/// [`AgentInfo`] in `agent.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentArchivedInfo {
    /// RFC3339 timestamp of when the agent was archived.
    pub at: String,
    /// Who archived it.
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentSessionInfo {
    pub source: String,
    pub agent: String,
    pub kind: crate::agent_resume::AgentSessionRefKind,
    pub value: String,
}
