//! Wire shapes of `agent.topics.*`: the long-lived worker conversations
//! ("topics") inside one omp agent, reached through the control socket omp
//! offers the pane it runs in. A topic's chat is read with `agent.transcript`
//! and its `topic` parameter.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicsNewParams {
    pub target: String,
    /// The topic's owner-facing title.
    pub title: String,
    /// The topic's first message.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicsSendParams {
    pub target: String,
    pub topic_id: String,
    pub message: String,
}

/// One topic of one agent (`agent.topics.close`, `agent.topics.reopen`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicTarget {
    pub target: String,
    pub topic_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicsRenameParams {
    pub target: String,
    pub topic_id: String,
    pub title: String,
}

/// Where a topic's worker is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentTopicState {
    Starting,
    Running,
    Idle,
    Dead,
    Closed,
    /// A state this server does not know yet.
    #[serde(other)]
    Unknown,
}

/// One topic as `agent.topics.list` reports it, live from the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicInfo {
    pub topic_id: String,
    pub title: String,
    pub state: AgentTopicState,
    /// Turns the topic has run.
    pub turns: u64,
    /// Messages waiting for the topic's current turn to end.
    pub queued: u64,
    pub created_unix_ms: u64,
    pub last_activity_unix_ms: u64,
    /// The topic's newest step, in the agent's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<String>,
}

/// How `agent.topics.send` delivered a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentTopicSendMode {
    /// Steered into the topic's running turn.
    Steered,
    /// Queued behind the topic's running turn.
    Queued,
    /// Started a new turn.
    Turn,
    /// A delivery this server does not know yet.
    #[serde(other)]
    Unknown,
}

/// Why a topic changed (`agent.topics.changed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentTopicChangeReason {
    Spawned,
    TurnStarted,
    TurnSettled,
    Closed,
    Reopened,
    Retitled,
    /// The agent restored the topic with its session (startup, session switch).
    Restored,
    /// A reason this server does not know yet.
    #[serde(other)]
    Unknown,
}

/// One topic transcript of an omp agent's current session, read from the
/// session file on disk (`agent.list`, `agent.get`): it is listed whether or
/// not the agent can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicSession {
    pub topic_id: String,
    /// The topic's own session file.
    pub path: String,
    /// The newest owner-facing title the session file records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_unix_ms: Option<u64>,
}
