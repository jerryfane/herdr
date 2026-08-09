use serde::{Deserialize, Serialize};

/// Direction of a gram message on the wire. Mirrors
/// [`crate::persist::gram::GramDirection`]; the handler maps between them so the
/// storage record and the public contract can evolve independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GramDirection {
    AgentToOwner,
    OwnerToAgent,
}

/// `gram.send` — an agent sends the owner a push-notified message.
///
/// The sender label (`from`) is resolved server-side from `caller_pane_id`
/// (the agent's `HERDR_PANE_ID`); `from` overrides that when the caller cannot be
/// resolved to a pane (e.g. a script outside a Herdr pane).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramSendParams {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pane_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// `gram.post` — the owner posts a message to agents (from the app).
///
/// `to: Some(agent)` addresses one agent directly (not grabbable); `to: None`
/// posts to the shared grab-queue any agent can claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramPostParams {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// `gram.list` — read messages. The audience is inferred from `caller_pane_id`:
/// a caller that resolves to an agent gets that agent's view (its direct items,
/// the shared ungrabbed queue, its own grabs, and its own sent items); a caller
/// with no resolvable pane gets the owner view (everything).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct GramListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pane_id: Option<String>,
    /// Agent view only: restrict to the shared, still-ungrabbed queue.
    #[serde(default)]
    pub only_queue: bool,
    /// Owner view only: restrict to unread agent->owner messages.
    #[serde(default)]
    pub unread_only: bool,
}

/// `gram.grab` — an agent claims a shared-queue item. The claimant label is
/// resolved from `caller_pane_id` (or `grabbed_by` when the caller is not a
/// pane). Fails if the item is missing, not a shared item, or already grabbed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramGrabParams {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pane_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grabbed_by: Option<String>,
}

/// `gram.mark_read` — the owner marks an agent->owner message read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramMarkReadParams {
    pub id: String,
}

/// A gram message as returned to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramMessageInfo {
    pub id: String,
    pub direction: GramDirection,
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grabbed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grabbed_unix_ms: Option<u64>,
    pub created_unix_ms: u64,
    #[serde(default)]
    pub read_by_owner: bool,
}
