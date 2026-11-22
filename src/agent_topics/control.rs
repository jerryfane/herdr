//! Client of the control socket an omp agent serves its topics on. Frames are
//! newline-delimited JSON: the client's `hello` carries the token and is
//! answered `{"type":"hello","protocol":1,"pid":…}`; then RPC-shaped
//! `topics_*` commands get `{"id","type":"response","success",…}` replies,
//! and `subscribe` turns the connection into a stream of `topic_update`
//! frames.
//!
//! Every connection first proves that the agent process Herdr tracks for the
//! pane serves the socket (the socket's peer pid): the token is never written
//! to a socket any other process serves.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::{ControlEndpoint, CONTROL_PROTOCOL};
use crate::api::schema::{
    AgentTopicChangeReason, AgentTopicInfo, AgentTopicSendMode, AgentTopicState,
    AgentTopicSuggestionInfo,
};

/// Longest frame read from the agent.
const MAX_FRAME_BYTES: u64 = 4 * 1024 * 1024;
/// How long the agent may take to answer the hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the agent may take to answer a command that only reads or flips
/// a topic's state.
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the agent may take to start a topic or deliver a message to one.
pub(crate) const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(crate) enum ControlError {
    /// Nothing serves the socket, or the connection broke.
    Unreachable(String),
    /// Another process than the agent serves the socket.
    WrongPeer { expected: u32, actual: Option<u32> },
    /// The agent refused the token.
    Unauthorized,
    /// The agent answered something this client does not understand.
    Protocol(String),
    /// The agent did not answer in time.
    TimedOut,
    /// The agent refused the command, naming why in `code` when it is one
    /// herdr passes through (see [`REFUSAL_CODES`]).
    Rejected {
        message: String,
        code: Option<&'static str>,
    },
    /// The agent's omp does not know the command (a build without topic
    /// suggestions).
    Unsupported(String),
}

/// The refusal codes omp's topics answer with that herdr passes through as
/// its own error code; any other refusal is `topic_rejected`.
const REFUSAL_CODES: &[&str] = &[
    "suggestion_not_found",
    "already_accepted",
    "invalid_message_ids",
    "organise_running",
    "topics_disabled",
];

impl ControlError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unreachable(_)
            | Self::WrongPeer { .. }
            | Self::Unauthorized
            | Self::Protocol(_) => "topics_unreachable",
            Self::TimedOut => "topics_timeout",
            Self::Rejected { code, .. } => code.unwrap_or("topic_rejected"),
            Self::Unsupported(_) => "topics_unsupported",
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Unreachable(why) => format!("the agent's topics cannot be reached: {why}"),
            Self::WrongPeer { expected, actual } => format!(
                "the agent's control socket is served by process {}, not the agent (pid {expected}); refused to connect",
                actual.map_or_else(|| "unknown".to_owned(), |pid| pid.to_string())
            ),
            Self::Unauthorized => "the agent refused Herdr's control token".into(),
            Self::Protocol(why) => format!("the agent's control socket answered unexpectedly: {why}"),
            Self::TimedOut => "the agent did not answer in time".into(),
            Self::Rejected { message, .. } => message.clone(),
            Self::Unsupported(command) => format!(
                "the agent's omp does not serve {command}; it needs an omp build with topic suggestions"
            ),
        }
    }
}

fn io_error(error: std::io::Error) -> ControlError {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => ControlError::TimedOut,
        _ => ControlError::Unreachable(error.to_string()),
    }
}

/// One authenticated connection to an agent's control socket.
pub(crate) struct ControlConnection {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl ControlConnection {
    /// Connect, check the socket's peer is the endpoint's agent process, then
    /// present the token.
    pub(crate) fn open(endpoint: &ControlEndpoint) -> Result<Self, ControlError> {
        let stream = UnixStream::connect(&endpoint.socket_path).map_err(|error| {
            ControlError::Unreachable(format!("{}: {error}", endpoint.socket_path.display()))
        })?;
        let peer = crate::platform::unix_stream_peer_pid(&stream);
        if peer != Some(endpoint.pid) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(ControlError::WrongPeer {
                expected: endpoint.pid,
                actual: peer,
            });
        }
        let writer = stream.try_clone().map_err(io_error)?;
        let mut connection = Self {
            reader: BufReader::new(stream),
            writer,
            next_id: 0,
        };
        connection.set_timeout(Some(HELLO_TIMEOUT))?;
        connection.write_frame(&json!({"type": "hello", "token": endpoint.token.expose()}))?;
        let hello = connection.read_frame()?;
        match hello.get("type").and_then(Value::as_str) {
            Some("hello") => {}
            Some("error") => {
                return Err(
                    match hello
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                    {
                        "Unauthorized." => ControlError::Unauthorized,
                        other => ControlError::Protocol(other.to_owned()),
                    },
                );
            }
            _ => return Err(ControlError::Protocol("no hello".into())),
        }
        let protocol = hello.get("protocol").and_then(Value::as_u64);
        if protocol != Some(u64::from(CONTROL_PROTOCOL)) {
            return Err(ControlError::Protocol(format!(
                "protocol {protocol:?} is not {CONTROL_PROTOCOL}"
            )));
        }
        if hello
            .get("pid")
            .and_then(Value::as_u64)
            .is_some_and(|pid| pid != u64::from(endpoint.pid))
        {
            return Err(ControlError::Protocol(
                "the hello names another process".into(),
            ));
        }
        Ok(connection)
    }

    fn set_timeout(&self, timeout: Option<Duration>) -> Result<(), ControlError> {
        self.writer.set_read_timeout(timeout).map_err(io_error)?;
        self.writer.set_write_timeout(timeout).map_err(io_error)
    }

    fn write_frame(&mut self, frame: &Value) -> Result<(), ControlError> {
        let mut line =
            serde_json::to_vec(frame).map_err(|error| ControlError::Protocol(error.to_string()))?;
        line.push(b'\n');
        self.writer.write_all(&line).map_err(io_error)
    }

    fn read_frame(&mut self) -> Result<Value, ControlError> {
        let mut line = Vec::new();
        let read = (&mut self.reader)
            .take(MAX_FRAME_BYTES)
            .read_until(b'\n', &mut line)
            .map_err(io_error)?;
        if read == 0 {
            return Err(ControlError::Unreachable(
                "the agent closed the connection".into(),
            ));
        }
        if line.last() != Some(&b'\n') {
            return Err(ControlError::Protocol("a frame is too long".into()));
        }
        serde_json::from_slice(&line).map_err(|error| ControlError::Protocol(error.to_string()))
    }

    /// Send one command and wait up to `timeout` for its reply's `data`
    /// (`None` when the reply carries none). Other frames are skipped.
    fn request(
        &mut self,
        kind: &str,
        mut frame: Map<String, Value>,
        timeout: Duration,
    ) -> Result<Option<Value>, ControlError> {
        self.set_timeout(Some(timeout))?;
        self.next_id += 1;
        let id = self.next_id.to_string();
        frame.insert("id".into(), Value::String(id.clone()));
        frame.insert("type".into(), Value::String(kind.to_owned()));
        self.write_frame(&Value::Object(frame))?;
        loop {
            let mut reply = self.read_frame()?;
            if reply.get("type").and_then(Value::as_str) != Some("response")
                || reply.get("id").and_then(Value::as_str) != Some(id.as_str())
            {
                continue;
            }
            if reply.get("success").and_then(Value::as_bool) == Some(true) {
                return Ok(reply.get_mut("data").map(Value::take));
            }
            let message = reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the agent refused the command");
            let code = reply.get("code").and_then(Value::as_str);
            if code.is_none() && message.starts_with("Unknown command") {
                return Err(ControlError::Unsupported(kind.to_owned()));
            }
            return Err(ControlError::Rejected {
                message: message.to_owned(),
                code: code
                    .and_then(|code| REFUSAL_CODES.iter().copied().find(|&known| known == code)),
            });
        }
    }

    /// Run one topic command.
    pub(crate) fn run(&mut self, command: TopicCommand) -> Result<TopicReply, ControlError> {
        let fields = |pairs: &[(&str, &str)]| -> Map<String, Value> {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), Value::String((*value).to_owned())))
                .collect()
        };
        match command {
            TopicCommand::List => {
                let data = self.request("topics_list", Map::new(), COMMAND_TIMEOUT)?;
                let list: TopicsListData = parse_data(data)?;
                Ok(TopicReply::List {
                    topics: list.topics.into_iter().map(AgentTopicInfo::from).collect(),
                    // Open ones only, whatever an omp lists.
                    suggestions: list.suggestions.map(|suggestions| {
                        suggestions
                            .into_iter()
                            .filter(|suggestion| {
                                suggestion
                                    .state
                                    .as_deref()
                                    .is_none_or(|state| state == "open")
                            })
                            .map(AgentTopicSuggestionInfo::from)
                            .collect()
                    }),
                })
            }
            TopicCommand::New { title, message } => {
                let data = self.request(
                    "topics_new",
                    fields(&[("title", title.as_str()), ("message", message.as_str())]),
                    DELIVERY_TIMEOUT,
                )?;
                let created: TopicCreatedData = parse_data(data)?;
                Ok(TopicReply::Created {
                    topic_id: created.topic_id,
                })
            }
            TopicCommand::Send { topic_id, message } => {
                let data = self.request(
                    "topics_send",
                    fields(&[
                        ("topicId", topic_id.as_str()),
                        ("message", message.as_str()),
                    ]),
                    DELIVERY_TIMEOUT,
                )?;
                let sent: TopicSentData = parse_data(data)?;
                Ok(TopicReply::Sent {
                    topic_id: sent.topic_id,
                    mode: sent.mode,
                })
            }
            TopicCommand::Close { topic_id } => {
                self.request(
                    "topics_close",
                    fields(&[("topicId", topic_id.as_str())]),
                    COMMAND_TIMEOUT,
                )?;
                Ok(TopicReply::Done { topic_id })
            }
            TopicCommand::Reopen { topic_id } => {
                self.request(
                    "topics_reopen",
                    fields(&[("topicId", topic_id.as_str())]),
                    COMMAND_TIMEOUT,
                )?;
                Ok(TopicReply::Done { topic_id })
            }
            TopicCommand::Rename { topic_id, title } => {
                self.request(
                    "topics_rename",
                    fields(&[("topicId", topic_id.as_str()), ("title", title.as_str())]),
                    COMMAND_TIMEOUT,
                )?;
                Ok(TopicReply::Done { topic_id })
            }
            TopicCommand::AcceptSuggestion { suggestion_id, by } => {
                // The topic starts with the messages the agent picked.
                let data = self.request(
                    "topics_accept_suggestion",
                    fields(&[
                        ("suggestionId", suggestion_id.as_str()),
                        ("by", by.as_str()),
                    ]),
                    DELIVERY_TIMEOUT,
                )?;
                let accepted: SuggestionAcceptedData = parse_data(data)?;
                Ok(TopicReply::SuggestionAccepted {
                    suggestion_id,
                    topic_id: accepted.topic_id,
                    already_accepted: accepted.already_accepted,
                })
            }
            TopicCommand::DismissSuggestion { suggestion_id, by } => {
                let data = self.request(
                    "topics_dismiss_suggestion",
                    fields(&[
                        ("suggestionId", suggestion_id.as_str()),
                        ("by", by.as_str()),
                    ]),
                    COMMAND_TIMEOUT,
                )?;
                let dismissed: SuggestionDismissedData = parse_data(data)?;
                Ok(TopicReply::SuggestionDismissed {
                    suggestion_id,
                    already_dismissed: dismissed.already_dismissed,
                })
            }
            TopicCommand::Organise { by } => {
                let data = self.request(
                    "topics_organise",
                    fields(&[("by", by.as_str())]),
                    COMMAND_TIMEOUT,
                )?;
                let organising: OrganiseData = parse_data(data)?;
                Ok(TopicReply::Organising {
                    queued: organising.queued,
                })
            }
        }
    }

    /// Turn this connection into the agent's stream of topic changes.
    pub(crate) fn subscribe(mut self) -> Result<TopicUpdates, ControlError> {
        self.request("subscribe", Map::new(), COMMAND_TIMEOUT)?;
        self.set_timeout(None)?;
        Ok(TopicUpdates { connection: self })
    }

    /// A second handle on the socket, to shut it down from another thread.
    pub(crate) fn try_clone_stream(&self) -> std::io::Result<UnixStream> {
        self.writer.try_clone()
    }
}

/// One `topics_*` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TopicCommand {
    List,
    New {
        title: String,
        message: String,
    },
    Send {
        topic_id: String,
        message: String,
    },
    Close {
        topic_id: String,
    },
    Reopen {
        topic_id: String,
    },
    Rename {
        topic_id: String,
        title: String,
    },
    /// `by` names who acts, as herdr names them (`owner` or a guest's name);
    /// omp records it and never treats it as authority.
    AcceptSuggestion {
        suggestion_id: String,
        by: String,
    },
    DismissSuggestion {
        suggestion_id: String,
        by: String,
    },
    Organise {
        by: String,
    },
}

/// What a `topics_*` command answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TopicReply {
    List {
        topics: Vec<AgentTopicInfo>,
        /// `None` from an omp without topic suggestions.
        suggestions: Option<Vec<AgentTopicSuggestionInfo>>,
    },
    Created {
        topic_id: String,
    },
    Sent {
        topic_id: String,
        mode: AgentTopicSendMode,
    },
    Done {
        topic_id: String,
    },
    SuggestionAccepted {
        suggestion_id: String,
        topic_id: String,
        already_accepted: bool,
    },
    SuggestionDismissed {
        suggestion_id: String,
        already_dismissed: bool,
    },
    Organising {
        queued: bool,
    },
}

/// One topic change from the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TopicChange {
    pub(crate) topic_id: String,
    pub(crate) reason: AgentTopicChangeReason,
    /// The suggestion whose state changed.
    pub(crate) suggestion_id: Option<String>,
}

/// The agent's stream of topic changes (`subscribe`).
pub(crate) struct TopicUpdates {
    connection: ControlConnection,
}

impl TopicUpdates {
    /// The next topic change; `None` once the stream ended.
    pub(crate) fn next_change(&mut self) -> Option<TopicChange> {
        #[derive(Deserialize)]
        struct Change {
            id: String,
            reason: String,
        }
        loop {
            let frame = self.connection.read_frame().ok()?;
            if frame.get("type").and_then(Value::as_str) != Some("topic_update") {
                continue;
            }
            let Some(change) = frame
                .get("change")
                .and_then(|change| Change::deserialize(change).ok())
            else {
                continue;
            };
            let reason = change_reason(&change.reason);
            // For a suggestion's change, omp's `id` is the suggestion's.
            let suggestion = matches!(
                reason,
                AgentTopicChangeReason::Suggested
                    | AgentTopicChangeReason::SuggestionAccepted
                    | AgentTopicChangeReason::SuggestionDismissed
            );
            return Some(if suggestion {
                TopicChange {
                    topic_id: String::new(),
                    reason,
                    suggestion_id: Some(change.id),
                }
            } else {
                TopicChange {
                    topic_id: change.id,
                    reason,
                    suggestion_id: None,
                }
            });
        }
    }
}

fn change_reason(reason: &str) -> AgentTopicChangeReason {
    match reason {
        "spawned" => AgentTopicChangeReason::Spawned,
        "turn-started" => AgentTopicChangeReason::TurnStarted,
        "turn-settled" => AgentTopicChangeReason::TurnSettled,
        "closed" => AgentTopicChangeReason::Closed,
        "reopened" => AgentTopicChangeReason::Reopened,
        "retitled" => AgentTopicChangeReason::Retitled,
        "restored" => AgentTopicChangeReason::Restored,
        "suggested" => AgentTopicChangeReason::Suggested,
        "suggestion-accepted" => AgentTopicChangeReason::SuggestionAccepted,
        "suggestion-dismissed" => AgentTopicChangeReason::SuggestionDismissed,
        _ => AgentTopicChangeReason::Unknown,
    }
}

fn parse_data<T: serde::de::DeserializeOwned>(data: Option<Value>) -> Result<T, ControlError> {
    serde_json::from_value(data.unwrap_or(Value::Null))
        .map_err(|error| ControlError::Protocol(error.to_string()))
}

#[derive(Deserialize)]
struct TopicsListData {
    topics: Vec<AgentTopicSummary>,
    /// Absent from an omp without topic suggestions.
    #[serde(default)]
    suggestions: Option<Vec<SuggestionSummary>>,
}

/// An open suggestion as omp's `topics_list` describes it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuggestionSummary {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    message_ids: Vec<String>,
    #[serde(default)]
    created_ms: f64,
    /// omp lists open suggestions only and leaves this out; any other state
    /// is dropped.
    #[serde(default)]
    state: Option<String>,
}

impl From<SuggestionSummary> for AgentTopicSuggestionInfo {
    fn from(suggestion: SuggestionSummary) -> Self {
        Self {
            suggestion_id: suggestion.id,
            title: suggestion.title,
            reason: suggestion.reason,
            message_ids: suggestion.message_ids,
            created_unix_ms: unix_ms(suggestion.created_ms),
        }
    }
}

/// A topic as omp's `topics_list` describes it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentTopicSummary {
    id: String,
    #[serde(default)]
    title: String,
    state: AgentTopicState,
    #[serde(default)]
    turns: u64,
    #[serde(default)]
    queued: u64,
    #[serde(default)]
    created_at: f64,
    #[serde(default)]
    last_activity_at: f64,
    #[serde(default)]
    last_activity: Option<String>,
}

fn unix_ms(ms: f64) -> u64 {
    if ms.is_finite() && ms > 0.0 {
        ms as u64
    } else {
        0
    }
}

impl From<AgentTopicSummary> for AgentTopicInfo {
    fn from(topic: AgentTopicSummary) -> Self {
        Self {
            topic_id: topic.id,
            title: topic.title,
            state: topic.state,
            turns: topic.turns,
            queued: topic.queued,
            created_unix_ms: unix_ms(topic.created_at),
            last_activity_unix_ms: unix_ms(topic.last_activity_at),
            last_activity: topic.last_activity,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TopicCreatedData {
    topic_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TopicSentData {
    topic_id: String,
    mode: AgentTopicSendMode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuggestionAcceptedData {
    topic_id: String,
    #[serde(default)]
    already_accepted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuggestionDismissedData {
    #[serde(default)]
    already_dismissed: bool,
}

#[derive(Deserialize)]
struct OrganiseData {
    #[serde(default)]
    queued: bool,
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::mpsc;

    use serde_json::{json, Value};

    use super::*;
    use crate::api::schema::AgentControlToken;

    pub(crate) const TOKEN: &str = "test-control-token-0123456789abcdef";

    /// An omp control socket served by this test process: it answers a hello
    /// with `TOKEN` and each command with `reply(command)`, and records every
    /// frame it reads.
    pub(crate) struct FakeControl {
        pub(crate) path: PathBuf,
        dir: PathBuf,
        pub(crate) frames: mpsc::Receiver<Value>,
        /// Push `topic_update` changes to every subscribed connection.
        pub(crate) updates: mpsc::Sender<Value>,
    }

    impl Drop for FakeControl {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl FakeControl {
        pub(crate) fn start(
            tag: &str,
            reply: impl Fn(&Value) -> Value + Send + Sync + 'static,
        ) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "herdr-topics-{tag}-{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_nanos())
                    .unwrap_or_default()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("c.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (frames_tx, frames) = mpsc::channel();
            let (updates, updates_rx) = mpsc::channel::<Value>();
            let subscribers = std::sync::Arc::new(std::sync::Mutex::new(Vec::<UnixStream>::new()));
            let pushing = std::sync::Arc::clone(&subscribers);
            std::thread::spawn(move || {
                for change in updates_rx {
                    let mut line = json!({"type": "topic_update", "change": change}).to_string();
                    line.push('\n');
                    for stream in pushing.lock().unwrap().iter_mut() {
                        let _ = stream.write_all(line.as_bytes());
                    }
                }
            });
            let reply = std::sync::Arc::new(reply);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    let frames_tx = frames_tx.clone();
                    let reply = std::sync::Arc::clone(&reply);
                    let subscribers = std::sync::Arc::clone(&subscribers);
                    std::thread::spawn(move || {
                        let mut writer = stream.try_clone().unwrap();
                        let mut authenticated = false;
                        for line in BufReader::new(stream).lines() {
                            let Ok(line) = line else { return };
                            let frame: Value = serde_json::from_str(&line).unwrap();
                            let answer = if !authenticated {
                                if frame["type"] == "hello" && frame["token"] == TOKEN {
                                    authenticated = true;
                                    json!({"type": "hello", "protocol": 1, "pid": std::process::id()})
                                } else {
                                    let _ = writeln!(
                                        writer,
                                        "{}",
                                        json!({"type": "error", "error": "Unauthorized."})
                                    );
                                    let _ = frames_tx.send(frame);
                                    return;
                                }
                            } else if frame["type"] == "subscribe" {
                                subscribers
                                    .lock()
                                    .unwrap()
                                    .push(writer.try_clone().unwrap());
                                json!({"id": frame["id"], "type": "response", "command": "subscribe", "success": true})
                            } else {
                                let mut answer = reply(&frame);
                                answer["id"] = frame["id"].clone();
                                answer["type"] = json!("response");
                                answer["command"] = frame["type"].clone();
                                answer
                            };
                            // Recorded once answered, as omp answers `subscribe`
                            // before it pushes any change: a test that sees
                            // `subscribe` knows its stream gets every later
                            // update, after the reply the client waits for (an
                            // update written first would be skipped as it
                            // waits, and lost).
                            let written = writeln!(writer, "{answer}").is_ok();
                            let _ = frames_tx.send(frame);
                            if !written {
                                return;
                            }
                        }
                    });
                }
            });
            Self {
                path,
                dir,
                frames,
                updates,
            }
        }

        pub(crate) fn endpoint(&self, pid: u32) -> ControlEndpoint {
            ControlEndpoint {
                socket_path: self.path.clone(),
                token: AgentControlToken::new(TOKEN),
                pid,
            }
        }
    }

    fn list_reply(_: &Value) -> Value {
        json!({"success": true, "data": {"topics": [{
            "id": "Plan", "title": "Plan the release", "state": "idle", "turns": 2,
            "queued": 0, "createdAt": 1_000, "lastActivityAt": 2_000.5,
            "sessionFile": "/tmp/s/Plan.jsonl",
        }]}})
    }

    #[test]
    fn a_command_reaches_the_agent_after_the_token_and_maps_its_reply() {
        let fake = FakeControl::start("list", list_reply);
        let mut connection = ControlConnection::open(&fake.endpoint(std::process::id())).unwrap();
        let reply = connection.run(TopicCommand::List).unwrap();
        let TopicReply::List {
            topics,
            suggestions,
        } = reply
        else {
            panic!("{reply:?}");
        };
        // An omp without topic suggestions lists none, not an empty list.
        assert_eq!(suggestions, None);
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0].topic_id, "Plan");
        assert_eq!(topics[0].state, AgentTopicState::Idle);
        assert_eq!(topics[0].last_activity_unix_ms, 2_000);
        let hello = fake.frames.recv().unwrap();
        assert_eq!(hello["type"], "hello");
        assert_eq!(fake.frames.recv().unwrap()["type"], "topics_list");
    }

    #[test]
    fn connecting_to_a_socket_another_process_serves_is_refused_before_the_token() {
        let fake = FakeControl::start("wrong-peer", list_reply);
        // The socket is served by this test process, not by "the agent".
        let agent_pid = std::process::id().wrapping_add(1);
        let error = ControlConnection::open(&fake.endpoint(agent_pid))
            .err()
            .unwrap();
        assert!(
            matches!(error, ControlError::WrongPeer { expected, .. } if expected == agent_pid),
            "{error:?}"
        );
        assert_eq!(error.code(), "topics_unreachable");
        // The fake records every frame it reads: the token never reached it.
        assert!(fake
            .frames
            .recv_timeout(Duration::from_millis(200))
            .is_err());
    }

    #[test]
    fn a_missing_socket_is_unreachable() {
        let endpoint = ControlEndpoint {
            socket_path: std::env::temp_dir().join("herdr-topics-missing-socket.sock"),
            token: AgentControlToken::new(TOKEN),
            pid: std::process::id(),
        };
        let error = ControlConnection::open(&endpoint).err().unwrap();
        assert!(matches!(error, ControlError::Unreachable(_)), "{error:?}");
    }

    #[test]
    fn a_wrong_token_is_unauthorized() {
        let fake = FakeControl::start("bad-token", list_reply);
        let mut endpoint = fake.endpoint(std::process::id());
        endpoint.token = AgentControlToken::new("not-the-token-at-all-0123456789ab");
        let error = ControlConnection::open(&endpoint).err().unwrap();
        assert!(matches!(error, ControlError::Unauthorized), "{error:?}");
    }

    #[test]
    fn a_refused_command_carries_the_agents_reason() {
        let fake = FakeControl::start(
            "rejected",
            |_| json!({"success": false, "error": "Unknown topic: Nope"}),
        );
        let mut connection = ControlConnection::open(&fake.endpoint(std::process::id())).unwrap();
        let error = connection
            .run(TopicCommand::Close {
                topic_id: "Nope".into(),
            })
            .unwrap_err();
        assert_eq!(error.code(), "topic_rejected");
        assert_eq!(error.message(), "Unknown topic: Nope");
    }

    #[test]
    fn a_refusal_passes_the_agents_code_through_and_an_unknown_command_is_unsupported() {
        let fake = FakeControl::start("codes", |frame| match frame["suggestionId"].as_str() {
            Some("old-omp") => json!({"success": false, "error": "Unknown command."}),
            Some(code) => {
                json!({"success": false, "error": format!("refused: {code}"), "code": code})
            }
            None => {
                json!({"success": false, "error": "Topics are disabled.", "code": "topics_disabled"})
            }
        });
        let mut connection = ControlConnection::open(&fake.endpoint(std::process::id())).unwrap();
        for code in REFUSAL_CODES {
            let error = connection
                .run(TopicCommand::DismissSuggestion {
                    suggestion_id: (*code).into(),
                    by: "owner".into(),
                })
                .unwrap_err();
            assert_eq!(error.code(), *code);
            assert_eq!(error.message(), format!("refused: {code}"));
        }
        // A code herdr does not know stays a plain refusal.
        let error = connection
            .run(TopicCommand::DismissSuggestion {
                suggestion_id: "not_a_herdr_code".into(),
                by: "owner".into(),
            })
            .unwrap_err();
        assert_eq!(error.code(), "topic_rejected");
        let error = connection
            .run(TopicCommand::Organise { by: "owner".into() })
            .unwrap_err();
        assert_eq!(error.code(), "topics_disabled");
        let error = connection
            .run(TopicCommand::DismissSuggestion {
                suggestion_id: "old-omp".into(),
                by: "owner".into(),
            })
            .unwrap_err();
        assert_eq!(error.code(), "topics_unsupported");
        assert!(
            error.message().contains("topics_dismiss_suggestion"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn a_subscription_reads_topic_changes() {
        let fake = FakeControl::start("subscribe", list_reply);
        let connection = ControlConnection::open(&fake.endpoint(std::process::id())).unwrap();
        let mut updates = connection.subscribe().unwrap();
        fake.updates
            .send(json!({"id": "Plan", "ownerId": "o", "parentSessionId": "p", "reason": "turn-settled"}))
            .unwrap();
        assert_eq!(
            updates.next_change(),
            Some(TopicChange {
                topic_id: "Plan".into(),
                reason: AgentTopicChangeReason::TurnSettled,
                suggestion_id: None,
            })
        );
    }
}
