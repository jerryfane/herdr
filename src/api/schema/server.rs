use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct PingParams {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServerLiveHandoffParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_protocol: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServerCapabilities {
    pub live_handoff: bool,
    #[serde(default)]
    pub detached_server_daemon: bool,
    /// The daemon serves the persistent `pane.input.stream` write channel
    /// (issue #62). Clients feature-detect this before using it and otherwise
    /// fall back to per-call `pane.send_text` / `pane.send_input`.
    #[serde(default)]
    pub pane_input_stream: bool,
    /// The daemon serves `gram.upload.stream`, uploading a whole file over one
    /// connection instead of one connection per chunk. Clients feature-detect this
    /// and otherwise fall back to per-chunk `gram.upload_chunk`.
    #[serde(default)]
    pub gram_upload_stream: bool,
    /// The server can transactionally transfer visible session history between
    /// Claude Code, Codex, and OMP in the same logical pane.
    #[serde(default)]
    pub agent_session_transfer: bool,
    /// Native harnesses this daemon can use as session-transfer sources and
    /// destinations. Empty means the older Claude/Codex-only capability shape.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_session_transfer_harnesses: Vec<super::AgentSessionTransferHarness>,
}
