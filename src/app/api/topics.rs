//! Topics of omp agents (#474): `pane.report_agent_control` keeps the control
//! socket an omp process offers its pane (memory only, see
//! `crate::agent_topics`); `agent.topics.*` talk to it from worker threads,
//! except `agent.topics.list`, which answers from the endpoint's kept list
//! and refreshes it behind the answer; the first such request also follows
//! the agent's topic changes and emits them as `agent.topics.changed`.
//! `topic_sessions` is read from the session file on disk and never asks the
//! agent.

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
    use std::time::{Duration, Instant};

    use crate::agent_topics::control::{
        ControlConnection, ControlError, TopicChange, TopicCommand, TopicReply,
    };
    use crate::agent_topics::{
        ControlEndpoint, ControlHandle, ListFailure, TopicList, CONTROL_PROTOCOL,
    };
    use crate::api::schema::{
        AgentTopicChangeReason, ErrorBody, EventData, EventEnvelope, EventKind, Method,
        PaneReportAgentControlParams, Request, ResponseResult,
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
        /// The omp process herdr's own foreground probe identifies in front of
        /// the pane, while the pane's agent is omp. This is the only anchor for
        /// a control socket: an agent's reports name pids in its own words
        /// (`--agent-process-pid` may even name another process), the probe
        /// does not.
        pub(crate) fn live_omp_pid(
            &self,
            ws_idx: usize,
            pane_id: crate::layout::PaneId,
        ) -> Option<u32> {
            let terminal_id = self.state.workspaces.get(ws_idx)?.terminal_id(pane_id)?;
            if self
                .state
                .terminals
                .get(terminal_id)?
                .effective_known_agent()
                != Some(crate::detect::Agent::Omp)
            {
                return None;
            }
            #[cfg(test)]
            if let Some(inspected) = self.agent_controls.inspected_pid_for_test {
                return inspected;
            }
            let (runtime, _) = self.lookup_runtime(ws_idx, pane_id)?;
            let (agent, pid) = crate::pane::identified_foreground_agent(runtime.child_pid()?)?;
            (agent == crate::detect::Agent::Omp).then_some(pid)
        }

        /// `pane.report_agent_control`. Accepted only from the omp process
        /// herdr's own probe identifies in the pane: its pid, the connection's
        /// peer pid (kernel-reported) and the report's `agent_process_pid` must
        /// be one process. Session reports play no part.
        pub(in crate::app) fn handle_pane_report_agent_control(
            &mut self,
            id: String,
            params: PaneReportAgentControlParams,
        ) -> String {
            let Some((ws_idx, pane_id, terminal_id)) = self
                .parse_pane_id(&params.pane_id)
                .and_then(|(ws_idx, pane_id)| {
                    let terminal_id = self
                        .state
                        .workspaces
                        .get(ws_idx)?
                        .terminal_id(pane_id)?
                        .clone();
                    Some((ws_idx, pane_id, terminal_id))
                })
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
            let Some(omp) = self.live_omp_pid(ws_idx, pane_id) else {
                return refused(id, "herdr identifies no omp process in the pane");
            };
            // A local caller always has a peer pid; a request without one
            // (TCP, a relay, an in-process sender) never registers a control.
            if params.reporter_pid != Some(omp) || params.agent_process_pid != omp {
                return refused(
                    id,
                    "the report does not come from the pane's omp process, as herdr identifies it",
                );
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
                    pid: omp,
                },
            );
            encode_success(id, ResponseResult::Ok {})
        }

        /// Drop the pane's control endpoint unless herdr's own probe still
        /// identifies the process that offered it as the pane's omp (it exited
        /// or was replaced).
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
            if self.live_omp_pid(ws_idx, pane_id) != Some(pid) {
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
            let Some(omp) = self.live_omp_pid(resolved.ws_idx, resolved.pane_id) else {
                // herdr's probe can miss omp for a moment (a busy pane, a
                // child process in front): an agent known to have topics is
                // then unreachable, which clients retry, not unsupported.
                let has_topics = self.agent_controls.contains(&resolved.terminal_id)
                    || self
                        .topic_sessions_for(&resolved.terminal_id)
                        .is_some_and(|sessions| !sessions.is_empty());
                return Err(if has_topics {
                    ErrorBody {
                        code: "topics_unreachable".into(),
                        message:
                            "herdr does not see the agent's omp in its pane right now; try again"
                                .into(),
                    }
                } else {
                    ErrorBody {
                        code: "topics_unsupported".into(),
                        message: "topics are served by live omp agents only".into(),
                    }
                });
            };
            let control = self
                .agent_controls
                .handle(&resolved.terminal_id)
                .filter(|control| control.endpoint.pid == omp)
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
                Method::AgentTopicsAcceptSuggestion(params) => (
                    params.target,
                    TopicCommand::AcceptSuggestion {
                        suggestion_id: params.suggestion_id,
                        by: acting_by(params.acting_guest),
                    },
                ),
                Method::AgentTopicsDismissSuggestion(params) => (
                    params.target,
                    TopicCommand::DismissSuggestion {
                        suggestion_id: params.suggestion_id,
                        by: acting_by(params.acting_guest),
                    },
                ),
                Method::AgentTopicsOrganise(params) => (
                    params.target,
                    TopicCommand::Organise {
                        by: acting_by(params.acting_guest),
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
            // Suggestion state changes reach `agent.topics.changed` through
            // the agent's own `topic_update` stream this request follows.
            if matches!(command, TopicCommand::List) {
                if let Some(list) = self.kept_topic_list(&target) {
                    let _ = respond_to.send(encode_topic_list(id, &target, list));
                    start_topic_list_refresh(&target.terminal_id, &target.control, &self.event_tx);
                    return;
                }
            }
            let reply = respond_to.clone();
            let reply_id = id.clone();
            let event_tx = self.event_tx.clone();
            let spawned = crate::thread_spawn::spawn_named("herdr-agent-topics", move || {
                let response = match command {
                    TopicCommand::List => first_topic_list(reply_id, &target, &event_tx),
                    command => topics_response(reply_id, &target, command),
                };
                let _ = reply.send(response);
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

        /// The topic list kept for the agent's endpoint; before the agent
        /// first answers, the topics its session file records (stale), when
        /// it records any.
        fn kept_topic_list(&self, target: &TopicsTarget) -> Option<TopicList> {
            target.control.list.get().or_else(|| {
                let sessions = self
                    .topic_sessions_for(&target.terminal_id)
                    .filter(|sessions| !sessions.is_empty())?;
                Some(target.control.list.seed(TopicList::from_sessions(
                    sessions,
                    crate::app::actions::current_unix_ms(),
                )))
            })
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
                    suggestion_id: change.suggestion_id,
                    code: change.code,
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
            // The kept list takes what the change says for sure at once and
            // is refreshed from the agent behind it.
            control.list.apply_change(&change.topic_id, change.reason);
            start_topic_list_refresh(terminal_id, control, event_tx);
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

    /// A topic list that took at least this long is logged at info, every
    /// other one at debug.
    const SLOW_TOPIC_LIST: Duration = Duration::from_secs(1);

    /// How long a list request with nothing kept waits for the refresh it
    /// joined: the longest pause before a retry, one ask (connect, hello,
    /// `topics_list`) and some slack.
    const FIRST_TOPIC_LIST_WAIT: Duration = Duration::from_secs(16);

    /// The waits before a failed refresh asks the agent again; after the
    /// last one it waits for the next change or list request.
    const TOPIC_LIST_RETRIES: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(5)];

    /// Ask the agent for its topics, logging how long it took.
    fn ask_topic_list(control: &ControlHandle) -> Result<TopicList, ControlError> {
        let started = Instant::now();
        let reply = ControlConnection::open(&control.endpoint)
            .and_then(|mut connection| connection.run(TopicCommand::List))?;
        let TopicReply::List {
            topics,
            suggestions,
        } = reply
        else {
            return Err(ControlError::Protocol(
                "topics_list answered something other than a topic list".into(),
            ));
        };
        let elapsed = started.elapsed();
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        if elapsed >= SLOW_TOPIC_LIST {
            tracing::info!(
                elapsed_ms,
                topics = topics.len(),
                "agent topics listed (slow)"
            );
        } else {
            tracing::debug!(elapsed_ms, topics = topics.len(), "agent topics listed");
        }
        Ok(TopicList {
            topics,
            suggestions,
            as_of_unix_ms: crate::app::actions::current_unix_ms(),
            stale: false,
        })
    }

    fn encode_topic_list(id: String, target: &TopicsTarget, list: TopicList) -> String {
        encode_success(
            id,
            ResponseResult::AgentTopics {
                agent: target.agent.clone(),
                pane_id: target.pane_id.clone(),
                topics: list.topics,
                suggestions: list.suggestions,
                as_of_unix_ms: list.as_of_unix_ms,
                stale: list.stale,
            },
        )
    }

    /// `agent.topics.list` with nothing kept yet: join the one refresh (or
    /// start it) and answer with what it kept, so no second ask races it.
    fn first_topic_list(
        id: String,
        target: &TopicsTarget,
        event_tx: &tokio::sync::mpsc::Sender<AppEvent>,
    ) -> String {
        let seen = target.control.list.rounds();
        start_topic_list_refresh(&target.terminal_id, &target.control, event_tx);
        match target.control.list.wait_answer(seen, FIRST_TOPIC_LIST_WAIT) {
            Ok(list) => encode_topic_list(id, target, list),
            Err(failure) => encode_error(id, failure.code, failure.message),
        }
    }

    /// Refresh the kept topic list from the agent on a worker thread, unless
    /// a refresh already runs (it then asks once more when done).
    fn start_topic_list_refresh(
        terminal_id: &str,
        control: &ControlHandle,
        event_tx: &tokio::sync::mpsc::Sender<AppEvent>,
    ) {
        if !control.list.begin_refresh() {
            return;
        }
        let terminal_id = terminal_id.to_owned();
        let refreshing = control.clone();
        let event_tx = event_tx.clone();
        let spawned = crate::thread_spawn::spawn_named("herdr-agent-topics-refresh", move || {
            refresh_topic_list(&terminal_id, &refreshing, &event_tx);
        });
        if let Err(err) = spawned {
            tracing::warn!(err = %err, "failed to spawn agent topics refresh");
            control.list.abandon_refresh();
        }
    }

    /// The claimed refresh: ask the agent, keep its answer and emit
    /// `agent.topics.changed` (`listed`) when the list changed. A failed ask
    /// is retried after each of [`TOPIC_LIST_RETRIES`].
    fn refresh_topic_list(
        terminal_id: &str,
        control: &ControlHandle,
        event_tx: &tokio::sync::mpsc::Sender<AppEvent>,
    ) {
        let mut retries = TOPIC_LIST_RETRIES.iter();
        loop {
            let ticket = control.list.ticket();
            match ask_topic_list(control) {
                Ok(list) => {
                    retries = TOPIC_LIST_RETRIES.iter();
                    if control.list.store(ticket, list) {
                        let event = AppEvent::AgentTopicsChanged {
                            terminal_id: terminal_id.to_owned(),
                            generation: control.generation,
                            change: TopicChange {
                                topic_id: String::new(),
                                reason: AgentTopicChangeReason::Listed,
                                suggestion_id: None,
                                code: None,
                            },
                        };
                        if event_tx.blocking_send(event).is_err() {
                            control.list.abandon_refresh();
                            return;
                        }
                    }
                }
                Err(error) => {
                    log_control_error("topics refresh", &error);
                    control.list.refresh_failed(ListFailure {
                        code: error.code(),
                        message: error.message(),
                    });
                    if let Some(wait) = retries.next() {
                        std::thread::sleep(*wait);
                        if control.list.is_live() {
                            continue;
                        }
                    }
                }
            }
            if !control.list.end_refresh() {
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

    /// Who acts on a suggestion, as omp's `by` records it: the guest's name
    /// as their share shows it (`<name> (via HerdrUp)`, the sender of their
    /// Gram posts), else `owner` (the owner, their scripts and agents, and
    /// federated peers acting for them).
    fn acting_by(acting_guest: Option<String>) -> String {
        acting_guest.unwrap_or_else(|| "owner".into())
    }

    fn topics_response(id: String, target: &TopicsTarget, command: TopicCommand) -> String {
        let reply = ControlConnection::open(&target.control.endpoint)
            .and_then(|mut connection| connection.run(command));
        let agent = target.agent.clone();
        let pane_id = target.pane_id.clone();
        match reply {
            // `agent.topics.list` is answered by `first_topic_list` or the
            // kept list; no other command gets a list back.
            Ok(TopicReply::List { .. }) => {
                let error = ControlError::Protocol("the agent answered a topic list".into());
                encode_error(id, error.code(), error.message())
            }
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
            Ok(TopicReply::SuggestionAccepted {
                suggestion_id,
                topic_id,
                already_accepted,
            }) => encode_success(
                id,
                ResponseResult::AgentTopicSuggestionAccepted {
                    agent,
                    pane_id,
                    suggestion_id,
                    topic_id,
                    already_accepted,
                },
            ),
            Ok(TopicReply::SuggestionDismissed {
                suggestion_id,
                already_dismissed,
            }) => encode_success(
                id,
                ResponseResult::AgentTopicSuggestionDismissed {
                    agent,
                    pane_id,
                    suggestion_id,
                    already_dismissed,
                },
            ),
            Ok(TopicReply::Organising { queued }) => encode_success(
                id,
                ResponseResult::AgentTopicsOrganiseStarted {
                    agent,
                    pane_id,
                    queued,
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
