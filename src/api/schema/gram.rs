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
/// The sender label is `from` when provided; otherwise it is resolved
/// server-side from `caller_pane_id` (the agent's `HERDR_PANE_ID`) to that
/// agent's display identity — the unique per-agent name if set, else the pane's
/// public id. An explicit `from` always wins for display, but the message is
/// still matched to its sender by a stable internal key, so a `from` override
/// never hides it from the sender's own view. `text` is capped server-side
/// (~8 KiB); send large content as a file, not a message.
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
/// `to: Some(agent)` addresses one agent directly by its unique agent name (not
/// grabbable); the name must match a live agent or the call is rejected. `to:
/// None` posts to the shared grab-queue any agent can claim. `text` is capped
/// server-side (~8 KiB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramPostParams {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// `gram.list` — read messages. The audience is chosen by `caller_pane_id`:
/// omit it for the owner view (everything); supply it for that pane's agent view
/// (its direct items, the shared ungrabbed queue, its own grabs, and its own sent
/// items). A `caller_pane_id` that names no live pane is an error, not a
/// fall-through to the owner view. `unread_only` is an owner-view filter and is
/// rejected when `caller_pane_id` is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct GramListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pane_id: Option<String>,
    /// Restrict to the shared, still-ungrabbed queue (either audience).
    #[serde(default)]
    pub only_queue: bool,
    /// Owner view only: restrict to unread agent->owner messages.
    #[serde(default)]
    pub unread_only: bool,
}

/// `gram.grab` — an agent claims a shared-queue item. The claimant is
/// `grabbed_by` when provided, otherwise resolved from `caller_pane_id` to that
/// agent's identity. Fails if the item is missing, not a shared item, or already
/// grabbed.
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
