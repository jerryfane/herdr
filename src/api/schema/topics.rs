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

/// `agent.topics.set_enabled`: switch one omp agent onto the topics build or
/// back onto the stock omp (servers advertising `agent_topics_switch`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicsSetEnabledParams {
    pub target: String,
    pub enabled: bool,
    /// Never cut a running turn: on an agent that is working or blocked, keep
    /// the requested choice pending and relaunch at its next idle transition
    /// (`scheduled: true`). On an idle agent the switch happens now. A later
    /// call replaces a pending switch; asking for the state the agent runs now
    /// cancels it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub when_idle: bool,
}

/// One suggestion of one agent (`agent.topics.accept_suggestion`, which
/// starts the topic with the messages the agent picked, and
/// `agent.topics.dismiss_suggestion`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicSuggestionTarget {
    pub target: String,
    pub suggestion_id: String,
    /// Internal only: the guest gate's name for the guest who acts. Never
    /// read from the wire; `None` is the owner.
    #[serde(skip)]
    #[schemars(skip)]
    pub acting_guest: Option<String>,
}

/// `agent.topics.organise`: one agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicsOrganiseParams {
    pub target: String,
    /// Internal only: the guest gate's name for the guest who acts. Never
    /// read from the wire; `None` is the owner.
    #[serde(skip)]
    #[schemars(skip)]
    pub acting_guest: Option<String>,
}

/// One open topic suggestion, as `agent.topics.list` reports it: the agent
/// proposes moving these messages of its main conversation into a new topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTopicSuggestionInfo {
    pub suggestion_id: String,
    pub title: String,
    /// Why the agent suggests it, in its words.
    pub reason: String,
    /// The main conversation's entries (`agent.transcript` ids) the topic
    /// would start with.
    pub message_ids: Vec<String>,
    pub created_unix_ms: u64,
}

/// Where a topic suggestion stands (`agent.transcript` `topic_suggestion`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TopicSuggestionState {
    Open,
    /// A topic was started from it (`topic_id`).
    Accepted,
    Dismissed,
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
    /// The agent suggested a topic: `suggestion_id` names it and `topic_id`
    /// is empty. The suggestion is in `agent.topics.list` at once; its
    /// `agent.transcript` entry appears once the agent's current turn ends.
    Suggested,
    /// Suggestion `suggestion_id` was accepted; `topic_id` is empty (the
    /// topic's id is in the accept reply and the transcript entry).
    SuggestionAccepted,
    /// Suggestion `suggestion_id` was dismissed; `topic_id` is empty.
    SuggestionDismissed,
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
