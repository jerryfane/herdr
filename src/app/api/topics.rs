//! Topics of omp agents (#474): `pane.report_agent_control` keeps the control
//! socket an omp process offers its pane (memory only, see
//! `crate::agent_topics`); `agent.topics.*` talk to it from worker threads;
//! the first such request also follows the agent's topic changes and emits
//! them as `agent.topics.changed`. `topic_sessions` is read from the session
//! file on disk and never asks the agent.

use std::path::PathBuf;

use crate::api::schema::{AgentInfo, AgentTopicSession};
use crate::app::App;

impl App {
    /// An omp terminal's current session file, as its reports named it.
    fn omp_session_path(terminal: &crate::terminal::TerminalState) -> Option<PathBuf> {
        let (source, agent, session_ref) = Self::terminal_resume_source(terminal)?;
        if crate::detect::parse_agent_label(&agent) != Some(crate::detect::Agent::Omp) {
            return None;
        }
        terminal
            .reported_agent_session_path_for(&source, &agent, &session_ref)
            .map(PathBuf::from)
            .or_else(|| {
                (session_ref.kind == crate::agent_resume::AgentSessionRefKind::Path)
                    .then(|| PathBuf::from(&session_ref.value))
            })
    }

    /// The topic transcripts of an omp terminal's session, from disk.
    pub(crate) fn topic_sessions_for(&self, terminal_id: &str) -> Option<Vec<AgentTopicSession>> {
        let path = Self::omp_session_path(self.state.terminals.get(terminal_id)?)?;
        match crate::agent_transcript::topics::topic_sessions(&path) {
            Ok(topics) => Some(topics),
            Err(error) => {
                tracing::debug!(%error, "omp session file unreadable for topic sessions");
                None
            }
        }
    }

    pub(super) fn fill_topic_sessions(&self, agent: &mut AgentInfo) {
        agent.topic_sessions = self.topic_sessions_for(&agent.terminal_id);
    }
}

// The control client speaks to a Unix socket and checks its peer with
// `SO_PEERCRED`/`LOCAL_PEERPID`, so topics exist on Unix only: elsewhere
// `capabilities.agent_topics` is false, `pane.report_agent_control` and
// `agent.topics.*` answer `not_implemented`, and only `topic_sessions` (read
// from disk) remains.
#[cfg(unix)]
mod control {
    use std::path::PathBuf;
    use std::sync::mpsc::Sender;

    use crate::agent_topics::control::{
        ControlConnection, ControlError, TopicChange, TopicCommand, TopicReply,
    };
    use crate::agent_topics::{ControlEndpoint, ControlHandle, CONTROL_PROTOCOL};
    use crate::api::schema::{
        ErrorBody, EventData, EventEnvelope, EventKind, Method, PaneReportAgentControlParams,
        Request, ResponseResult,
    };
    use crate::app::App;
    use crate::events::AppEvent;

    use super::super::responses::{encode_error, encode_error_body, encode_success};

    /// Shortest token omp accepts for its control socket.
    const MIN_TOKEN_LENGTH: usize = 32;

    /// The agent an `agent.topics.*` request reaches, taken off the app thread.
    struct TopicsTarget {
        terminal_id: String,
        agent: String,
        pane_id: String,
        control: ControlHandle,
    }

    impl App {
        /// The omp process Herdr tracks for a terminal from the agent's own
        /// session reports, while the terminal's agent is a live omp.
        pub(crate) fn tracked_omp_pid(terminal: &crate::terminal::TerminalState) -> Option<u32> {
            if terminal.effective_known_agent() != Some(crate::detect::Agent::Omp) {
                return None;
            }
            let (source, agent, session_ref) = Self::terminal_resume_source(terminal)?;
            if crate::detect::parse_agent_label(&agent) != Some(crate::detect::Agent::Omp) {
                return None;
            }
            terminal
                .reported_agent_session_runtime_for(&source, &agent, &session_ref)?
                .process_pid
        }

        /// `pane.report_agent_control`. Accepted only for a pane whose agent is
        /// the omp process Herdr tracks, from that very process: the reported
        /// `agent_process_pid` and, when the API socket tells it, the
        /// connection's peer must both be the pid omp's session report named.
        pub(in crate::app) fn handle_pane_report_agent_control(
            &mut self,
            id: String,
            params: PaneReportAgentControlParams,
        ) -> String {
            let Some(terminal_id) = self
                .parse_pane_id(&params.pane_id)
                .and_then(|(ws_idx, pane_id)| {
                    self.state.workspaces.get(ws_idx)?.terminal_id(pane_id)
                })
                .cloned()
            else {
                return encode_error(
                    id,
                    "pane_not_found",
                    format!("pane {} not found", params.pane_id),
                );
            };
            let refused = |id: String, message: &str| {
                tracing::warn!(pane = %params.pane_id, reason = message, "agent control report refused");
                encode_error(id, "agent_control_refused", message)
            };
            if crate::detect::parse_agent_label(params.agent.trim())
                != Some(crate::detect::Agent::Omp)
            {
                return refused(id, "only omp agents offer a control socket");
            }
            let Some(tracked) = self
                .state
                .terminals
                .get(&terminal_id)
                .and_then(Self::tracked_omp_pid)
            else {
                return refused(id, "the pane runs no omp process that reported its session");
            };
            // A local caller always has a peer pid; a request without one
            // (TCP, a relay, an in-process sender) never registers a control.
            if params.agent_process_pid != tracked || params.reporter_pid != Some(tracked) {
                return refused(id, "the report does not come from the pane's omp process");
            }
            let Some(socket_path) = params.socket_path else {
                self.agent_controls.remove(terminal_id.as_str());
                return encode_success(id, ResponseResult::Ok {});
            };
            let socket_path = PathBuf::from(socket_path);
            if !socket_path.is_absolute() {
                return encode_error(id, "invalid_params", "socket_path must be absolute");
            }
            let Some(token) = params
                .token
                .filter(|token| token.expose().len() >= MIN_TOKEN_LENGTH)
            else {
                return encode_error(
                    id,
                    "invalid_params",
                    "a control socket needs its token (at least 32 characters)",
                );
            };
            if params.protocol != Some(CONTROL_PROTOCOL) {
                return encode_error(
                    id,
                    "unsupported_protocol",
                    format!("this Herdr speaks control protocol {CONTROL_PROTOCOL}"),
                );
            }
            self.agent_controls.register(
                terminal_id,
                ControlEndpoint {
                    socket_path,
                    token,
                    pid: tracked,
                },
            );
            encode_success(id, ResponseResult::Ok {})
        }

        /// Drop the pane's control endpoint unless the omp process Herdr now
        /// tracks there is the one that offered it (it exited, or a session
        /// report named another process).
        pub(in crate::app) fn reconcile_agent_control(
            &mut self,
            ws_idx: usize,
            pane_id: crate::layout::PaneId,
        ) {
            let Some(terminal_id) = self
                .state
                .workspaces
                .get(ws_idx)
                .and_then(|workspace| workspace.terminal_id(pane_id))
            else {
                return;
            };
            let Some(pid) = self.agent_controls.pid(terminal_id.as_str()) else {
                return;
            };
            let tracked = self
                .state
                .terminals
                .get(terminal_id)
                .and_then(Self::tracked_omp_pid);
            if tracked != Some(pid) {
                self.agent_controls.remove(terminal_id.as_str());
            }
        }

        fn topics_target(&self, target: &str) -> Result<TopicsTarget, ErrorBody> {
            let resolved = self
                .resolve_agent_target(target)
                .map_err(|err| self.agent_target_error_body(err))?;
            let not_found = || ErrorBody {
                code: "agent_not_found".into(),
                message: format!("agent target {target} not found"),
            };
            let terminal = self
                .state
                .terminals
                .get(resolved.terminal_id.as_str())
                .ok_or_else(not_found)?;
            let tracked = Self::tracked_omp_pid(terminal).ok_or_else(|| ErrorBody {
                code: "topics_unsupported".into(),
                message: "topics are served by live omp agents only".into(),
            })?;
            let control = self
                .agent_controls
                .handle(&resolved.terminal_id)
                .filter(|control| control.endpoint.pid == tracked)
                .ok_or_else(|| ErrorBody {
                    code: "topics_unreachable".into(),
                    message: "the agent has not offered its topics (omp needs `topics.enabled` and the current Herdr integration)".into(),
                })?;
            let info = self
                .agent_info(resolved.ws_idx, resolved.pane_id)
                .ok_or_else(not_found)?;
            Ok(TopicsTarget {
                terminal_id: resolved.terminal_id,
                agent: info.name.unwrap_or_else(|| "omp".into()),
                pane_id: info.pane_id,
                control,
            })
        }

        /// Answers an `agent.topics.*` request through `respond_to` from a
        /// worker thread: the agent may take a while, and the app thread
        /// never waits on it.
        pub(crate) fn handle_deferred_topics_request(
            &self,
            request: Request,
            respond_to: Sender<String>,
        ) {
            let id = request.id;
            let (target, command) = match request.method {
                Method::AgentTopicsList(params) => (params.target, TopicCommand::List),
                Method::AgentTopicsNew(params) => (
                    params.target,
                    TopicCommand::New {
                        title: params.title,
                        message: params.message,
                    },
                ),
                Method::AgentTopicsSend(params) => (
                    params.target,
                    TopicCommand::Send {
                        topic_id: params.topic_id,
                        message: params.message,
                    },
                ),
                Method::AgentTopicsClose(params) => (
                    params.target,
                    TopicCommand::Close {
                        topic_id: params.topic_id,
                    },
                ),
                Method::AgentTopicsReopen(params) => (
                    params.target,
                    TopicCommand::Reopen {
                        topic_id: params.topic_id,
                    },
                ),
                Method::AgentTopicsRename(params) => (
                    params.target,
                    TopicCommand::Rename {
                        topic_id: params.topic_id,
                        title: params.title,
                    },
                ),
                _ => {
                    let _ = respond_to.send(encode_error(
                        id,
                        "invalid_request",
                        "not an agent.topics request",
                    ));
                    return;
                }
            };
            let target = match self.topics_target(&target) {
                Ok(target) => target,
                Err(error) => {
                    let _ = respond_to.send(encode_error_body(id, error));
                    return;
                }
            };
            self.follow_topic_changes(&target);
            let reply = respond_to.clone();
            let reply_id = id.clone();
            let spawned = crate::thread_spawn::spawn_named("herdr-agent-topics", move || {
                let _ = reply.send(topics_response(reply_id, &target, command));
            });
            if let Err(err) = spawned {
                tracing::warn!(err = %err, "failed to spawn agent topics request");
                let _ = respond_to.send(encode_error(
                    id,
                    "topics_unreachable",
                    format!("could not start the topics request: {err}"),
                ));
            }
        }

        /// Start following the agent's topic changes unless a reader already
        /// does.
        fn follow_topic_changes(&self, target: &TopicsTarget) {
            if !target.control.updates.claim() {
                return;
            }
            let control = target.control.clone();
            let terminal_id = target.terminal_id.clone();
            let event_tx = self.event_tx.clone();
            let spawned =
                crate::thread_spawn::spawn_named("herdr-agent-topic-updates", move || {
                    read_topic_changes(&terminal_id, &control, &event_tx);
                    control.updates.release();
                });
            if spawned.is_err() {
                target.control.updates.release();
            }
        }

        /// One topic change read from the terminal's endpoint `generation`.
        pub(crate) fn handle_agent_topics_changed(
            &mut self,
            terminal_id: &str,
            generation: u64,
            change: TopicChange,
        ) {
            if !self.agent_controls.is_current(terminal_id, generation) {
                return;
            }
            let Some(target) = self.terminal_target_for_terminal_id(terminal_id) else {
                return;
            };
            let Some(pane_id) = self.public_pane_id(target.ws_idx, target.pane_id) else {
                return;
            };
            let workspace_id = self.public_workspace_id(target.ws_idx);
            let agent = self
                .state
                .terminals
                .get(terminal_id)
                .and_then(|terminal| terminal.agent_name.clone())
                .or_else(|| Some("omp".into()));
            self.emit_event(EventEnvelope {
                event: EventKind::AgentTopicsChanged,
                data: EventData::AgentTopicsChanged {
                    pane_id,
                    workspace_id,
                    agent,
                    topic_id: change.topic_id,
                    reason: change.reason,
                },
            });
        }
    }

    fn read_topic_changes(
        terminal_id: &str,
        control: &ControlHandle,
        event_tx: &tokio::sync::mpsc::Sender<AppEvent>,
    ) {
        let connection = match ControlConnection::open(&control.endpoint) {
            Ok(connection) => connection,
            Err(error) => {
                log_control_error("topic updates", &error);
                return;
            }
        };
        let Ok(stream) = connection.try_clone_stream() else {
            return;
        };
        if !control.updates.attach(stream) {
            return;
        }
        let mut updates = match connection.subscribe() {
            Ok(updates) => updates,
            Err(error) => {
                log_control_error("topic updates", &error);
                return;
            }
        };
        while let Some(change) = updates.next_change() {
            let event = AppEvent::AgentTopicsChanged {
                terminal_id: terminal_id.to_owned(),
                generation: control.generation,
                change,
            };
            if event_tx.blocking_send(event).is_err() {
                return;
            }
        }
    }

    fn log_control_error(what: &'static str, error: &ControlError) {
        match error {
            ControlError::WrongPeer { .. } | ControlError::Unauthorized => {
                tracing::warn!(what, error = %error.message(), "agent control socket refused");
            }
            _ => {
                tracing::debug!(what, error = %error.message(), "agent control socket unavailable")
            }
        }
    }

    fn topics_response(id: String, target: &TopicsTarget, command: TopicCommand) -> String {
        let reply = ControlConnection::open(&target.control.endpoint)
            .and_then(|mut connection| connection.run(command));
        let agent = target.agent.clone();
        let pane_id = target.pane_id.clone();
        match reply {
            Ok(TopicReply::List(topics)) => encode_success(
                id,
                ResponseResult::AgentTopics {
                    agent,
                    pane_id,
                    topics,
                },
            ),
            Ok(TopicReply::Created { topic_id }) => encode_success(
                id,
                ResponseResult::AgentTopicCreated {
                    agent,
                    pane_id,
                    topic_id,
                },
            ),
            Ok(TopicReply::Sent { topic_id, mode }) => encode_success(
                id,
                ResponseResult::AgentTopicSent {
                    agent,
                    pane_id,
                    topic_id,
                    mode,
                },
            ),
            Ok(TopicReply::Done { topic_id }) => encode_success(
                id,
                ResponseResult::AgentTopicUpdated {
                    agent,
                    pane_id,
                    topic_id,
                },
            ),
            Err(error) => {
                log_control_error("topics request", &error);
                encode_error(id, error.code(), error.message())
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
