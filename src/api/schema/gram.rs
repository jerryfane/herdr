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
/// The sender identity is `from` when provided; otherwise it is resolved
/// server-side from `caller_pane_id` (the agent's `HERDR_PANE_ID`) to the agent's
/// name (else the pane's public id). The agent name is the durable identity — it
/// survives a restart or live-handoff — but it is a name: it can be renamed,
/// cleared, or reused, so attribution and the "sent by me" view follow the
/// identity as it stands, not a fixed token. An explicit `from` overrides
/// attribution entirely. `text` is capped server-side (~8 KiB); send large
/// content as a file, not a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramSendParams {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pane_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// An optional file to attach, previously uploaded in chunks via
    /// `gram.upload_chunk` under `file.upload_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<GramFileUpload>,
}

/// A staged file to attach to a `gram.send`/`gram.post`. Its bytes must already be
/// uploaded in chunks via `gram.upload_chunk` under this `upload_id`; the handler
/// assembles them onto the newly minted message and clears the staging file.
/// `name` is the display name (sanitized to a safe basename server-side) and
/// `mime` is an advisory content type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramFileUpload {
    pub upload_id: String,
    pub name: String,
    #[serde(default)]
    pub mime: String,
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
    /// An optional file to attach, previously uploaded in chunks via
    /// `gram.upload_chunk` under `file.upload_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<GramFileUpload>,
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

/// `gram.grab` — an agent claims a shared-queue item. The claim is first-wins and
/// atomic at the storage layer, so no two agents can ever hold the same item —
/// this holds regardless of identity. The claimant label is `grabbed_by` when
/// provided, otherwise resolved from `caller_pane_id` to the agent's identity;
/// that label carries the same name-semantics as `gram.send`'s `from` (a rename
/// or reuse moves which items show as "mine", but never lets a second agent
/// claim one). Fails if the item is missing, not a shared item, or already
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

/// `gram.delete` — remove a message from the store for good.
///
/// Deletion is deliberately destructive: the record (and any attached file bytes)
/// are gone, which is what makes gram safe for a short-lived secret like a
/// temporary API key — send it, use it, delete it. Authority follows the caller:
/// the owner's app sends no `caller_pane_id` and may delete any message; an agent
/// supplies its `caller_pane_id` and may delete only a message it is involved in
/// (one it sent, one addressed to it, or one it grabbed), else the call is
/// rejected. A `caller_pane_id` that names no live pane is an error, not a
/// fall-through to owner authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramDeleteParams {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pane_id: Option<String>,
}

/// `gram.upload_chunk` — append one chunk of a file being uploaded.
///
/// Files are sent in chunks because a single request is size-capped (the app's SSH
/// path near 65 KiB, the daemon at 1 MiB). `upload_id` groups the chunks of one
/// file; `offset` is the byte position this chunk starts at — the current staged
/// size — so a dropped or reordered chunk is caught, and `offset: 0` (re)starts the
/// upload. Attach the assembled file by passing the same `upload_id` in a
/// `gram.send`/`gram.post` `file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramUploadChunkParams {
    pub upload_id: String,
    pub offset: u64,
    pub data_base64: String,
}

/// `gram.get_file` — download the file attached to a message. The bytes come back
/// inline as base64 in one reply (the response path is not size-capped). The owner
/// (no `caller_pane_id`) may download any file; an agent supplies its
/// `caller_pane_id` and may download only a file on a message it can see (the same
/// audience as `gram.list`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramGetFileParams {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_pane_id: Option<String>,
}

/// File attached to a gram message, as returned to clients. Metadata only — fetch
/// the bytes with `gram.get_file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GramFileInfo {
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub sha256: String,
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
    /// Metadata for an attached file, or absent. Fetch the bytes with
    /// `gram.get_file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<GramFileInfo>,
}
