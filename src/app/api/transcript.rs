//! `agent.transcript`: resolve the agent's omp session file on the app thread,
//! then read and page it on a worker thread, since a cold index of a long
//! session scans a file of over a hundred megabytes.

use std::path::PathBuf;
use std::sync::mpsc::Sender;

use crate::agent_transcript::{self, PageRequest};
use crate::api::schema::{AgentTranscriptParams, ErrorBody, Method, Request, ResponseResult};
use crate::app::App;

use super::responses::{encode_error, encode_error_body, encode_success};

/// Which harness backs a transcript, and how the worker thread locates its store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TranscriptKind {
    Omp {
        path: PathBuf,
    },
    Agy {
        shell_pid: Option<u32>,
        reported_session_id: Option<String>,
        reported_session_path: Option<PathBuf>,
        #[cfg(test)]
        direct_path: Option<PathBuf>,
    },
}

/// Where an agent's conversation is recorded, and how the reply names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranscriptSource {
    pub(crate) kind: TranscriptKind,
    pub(crate) agent: String,
    pub(crate) pane_id: String,
    /// The pane's remembered non-owner prompts, to mark their user turns.
    pub(crate) other_prompts: Vec<agent_transcript::OtherPrompt>,
}

impl App {
    /// The session backing `target` (an agent name or pane id, as `agent.read`
    /// resolves it). Supports omp (reported session JSONL) and agy (live
    /// conversation SQLite `.db` resolved on the worker thread). Errors are
    /// `agent_not_found` (and the other target errors) or `transcript_unsupported`.
    pub(crate) fn agent_transcript_source(
        &self,
        target: &str,
    ) -> Result<TranscriptSource, ErrorBody> {
        let resolved = self
            .resolve_agent_target(target)
            .map_err(|err| self.agent_target_error_body(err))?;
        let not_found = || ErrorBody {
            code: "agent_not_found".into(),
            message: format!("agent target {target} not found"),
        };
        let unsupported = |message: &str| ErrorBody {
            code: "transcript_unsupported".into(),
            message: message.into(),
        };
        let terminal = self
            .state
            .workspaces
            .get(resolved.ws_idx)
            .and_then(|workspace| workspace.terminal_id(resolved.pane_id))
            .and_then(|terminal_id| self.state.terminals.get(terminal_id))
            .ok_or_else(not_found)?;
        let info = self
            .agent_info(resolved.ws_idx, resolved.pane_id)
            .ok_or_else(not_found)?;
        let resume_source = Self::terminal_resume_source(terminal);

        if let Some((source, agent, session_ref)) = resume_source.as_ref() {
            if crate::detect::parse_agent_label(agent) == Some(crate::detect::Agent::Omp) {
                let path = terminal
                    .reported_agent_session_path_for(source, agent, session_ref)
                    .map(PathBuf::from)
                    .or_else(|| {
                        (session_ref.kind == crate::agent_resume::AgentSessionRefKind::Path)
                            .then(|| PathBuf::from(&session_ref.value))
                    })
                    .ok_or_else(|| unsupported("the agent has not reported a session file"))?;
                return Ok(TranscriptSource {
                    kind: TranscriptKind::Omp { path },
                    agent: info.name.clone().unwrap_or_else(|| agent.clone()),
                    pane_id: info.pane_id,
                    other_prompts: terminal.other_prompts.delivered(),
                });
            }
        }

        let is_agy = info
            .agent
            .as_deref()
            .and_then(crate::detect::parse_agent_label)
            == Some(crate::detect::Agent::Antigravity)
            || resume_source.as_ref().is_some_and(|(_, agent, _)| {
                crate::detect::parse_agent_label(agent) == Some(crate::detect::Agent::Antigravity)
            });
        if is_agy {
            let shell_pid = self
                .lookup_runtime(resolved.ws_idx, resolved.pane_id)
                .and_then(|(runtime, _)| runtime.child_pid());
            let (reported_session_id, reported_session_path) = resume_source
                .as_ref()
                .filter(|(_, agent, _)| {
                    crate::detect::parse_agent_label(agent)
                        == Some(crate::detect::Agent::Antigravity)
                })
                .map(|(source, agent, session_ref)| {
                    let id = (session_ref.kind == crate::agent_resume::AgentSessionRefKind::Id)
                        .then(|| session_ref.value.clone());
                    let path = terminal
                        .reported_agent_session_path_for(source, agent, session_ref)
                        .map(PathBuf::from)
                        .or_else(|| {
                            (session_ref.kind == crate::agent_resume::AgentSessionRefKind::Path)
                                .then(|| PathBuf::from(&session_ref.value))
                        });
                    (id, path)
                })
                .unwrap_or((None, None));
            return Ok(TranscriptSource {
                kind: TranscriptKind::Agy {
                    shell_pid,
                    reported_session_id,
                    reported_session_path,
                    #[cfg(test)]
                    direct_path: None,
                },
                agent: info
                    .name
                    .clone()
                    .or_else(|| info.agent.clone())
                    .unwrap_or_else(|| "agy".into()),
                pane_id: info.pane_id,
                other_prompts: terminal.other_prompts.delivered(),
            });
        }

        if resume_source.is_none() {
            return Err(unsupported("the agent has not reported a session file"));
        }
        Err(unsupported(
            "transcripts are read from omp and agy agents only",
        ))
    }

    /// Answers `agent.transcript` through `respond_to` from a worker thread.
    /// Returns false for any other method.
    pub(crate) fn handle_deferred_transcript_request(
        &self,
        request: Request,
        respond_to: Sender<String>,
    ) -> bool {
        let Method::AgentTranscript(params) = request.method else {
            return false;
        };
        let id = request.id;
        let source = match self.agent_transcript_source(&params.target) {
            Ok(source) => source,
            Err(error) => {
                let _ = respond_to.send(encode_error_body(id, error));
                return true;
            }
        };
        let reply = respond_to.clone();
        let reply_id = id.clone();
        let spawned = crate::thread_spawn::spawn_named("herdr-agent-transcript", move || {
            let _ = reply.send(transcript_response(reply_id, &source, params));
        });
        if let Err(err) = spawned {
            tracing::warn!(err = %err, "failed to spawn agent transcript reader");
            let _ = respond_to.send(encode_error(
                id,
                "transcript_unavailable",
                format!("could not start the transcript reader: {err}"),
            ));
        }
        true
    }
}

fn transcript_response(
    id: String,
    source: &TranscriptSource,
    params: AgentTranscriptParams,
) -> String {
    let request = PageRequest {
        other_prompts: source.other_prompts.clone(),
        before: params.before,
        after: params.after,
        limit: params.limit,
        max_bytes: params.max_bytes,
        held_from: params.held_from,
        subagent: params.subagent,
        topic: params.topic,
        relay_entries: params.relay_entries,
    };
    let page = match &source.kind {
        TranscriptKind::Omp { path } => agent_transcript::read_page(path, &request),
        TranscriptKind::Agy {
            shell_pid,
            reported_session_id,
            reported_session_path,
            #[cfg(test)]
            direct_path,
        } => {
            #[cfg(test)]
            let db_path = direct_path.clone().or_else(|| {
                agent_transcript::agy::resolve_db_path(
                    *shell_pid,
                    reported_session_id.as_deref(),
                    reported_session_path.as_deref(),
                )
            });
            #[cfg(not(test))]
            let db_path = agent_transcript::agy::resolve_db_path(
                *shell_pid,
                reported_session_id.as_deref(),
                reported_session_path.as_deref(),
            );
            match db_path {
                Some(path) => agent_transcript::agy::read_page(&path, &request),
                None => {
                    return encode_error(
                        id,
                        "transcript_unsupported",
                        "the agent has not opened a conversation database",
                    );
                }
            }
        }
    };
    match page {
        Ok(page) => encode_success(
            id,
            ResponseResult::AgentTranscript {
                agent: source.agent.clone(),
                pane_id: source.pane_id.clone(),
                session_id: page.session_id,
                entries: page.entries,
                before: page.before,
                after: page.after,
                pending_ask: page.pending_ask,
                working: page.working,
                model: page.model,
                plan: page.plan,
                recap: page.recap,
                subagents: page.subagents,
                resent: page.resent,
                relay_entries: page.relay_entries,
            },
        ),
        Err(error) => encode_error(id, error.code(), error.message()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::agent_transcript::tests::{text, Fixture};

    fn respond(source: &TranscriptSource, after: Option<&str>) -> Value {
        let params = AgentTranscriptParams {
            target: source.agent.clone(),
            before: None,
            after: after.map(str::to_owned),
            limit: None,
            max_bytes: None,
            held_from: None,
            subagent: None,
            topic: None,
            relay_entries: false,
        };
        serde_json::from_str(&transcript_response("t".into(), source, params)).unwrap()
    }

    #[test]
    fn a_fresh_omp_session_answers_an_empty_page_whose_after_poll_returns_the_first_turn() {
        // omp reports the session file before its first turn creates it (#399).
        let mut session = Fixture::new("api-fresh");
        let header = std::fs::read_to_string(&session.path).unwrap();
        std::fs::remove_file(&session.path).unwrap();
        let source = TranscriptSource {
            kind: TranscriptKind::Omp {
                path: session.path.clone(),
            },
            agent: "omp".into(),
            pane_id: "w1:p1".into(),
            other_prompts: Vec::new(),
        };

        let fresh = respond(&source, None);
        assert_eq!(fresh["result"]["type"], "agent_transcript", "{fresh}");
        assert_eq!(fresh["result"]["entries"], json!([]));
        assert_eq!(fresh["result"]["pending_ask"], Value::Null);
        let after = fresh["result"]["after"].as_str().unwrap();

        session.raw(&header);
        session.user("first");
        session.assistant(vec![text("hello")], "stop");
        let first = respond(&source, Some(after));
        assert_eq!(first["result"]["entries"][0]["kind"], "user", "{first}");
        assert_eq!(first["result"]["entries"][0]["text"], "first");
    }

    #[test]
    fn agy_source_without_open_db_answers_transcript_unsupported() {
        let source = TranscriptSource {
            kind: TranscriptKind::Agy {
                shell_pid: None,
                reported_session_id: None,
                reported_session_path: None,
                direct_path: None,
            },
            agent: "agy".into(),
            pane_id: "w1:p2".into(),
            other_prompts: Vec::new(),
        };
        let reply = respond(&source, None);
        assert_eq!(reply["error"]["code"], "transcript_unsupported", "{reply}");
    }

    #[test]
    fn agy_source_with_fixture_db_answers_agent_transcript_entries() {
        let dir = std::env::temp_dir().join(format!(
            "herdr-api-agy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("conv-fixture-0001.db");
        std::fs::write(&db, include_bytes!("../../agent_transcript/agy_fixture.db")).unwrap();

        let source = TranscriptSource {
            kind: TranscriptKind::Agy {
                shell_pid: None,
                reported_session_id: None,
                reported_session_path: None,
                direct_path: Some(db),
            },
            agent: "agy".into(),
            pane_id: "w1:p2".into(),
            other_prompts: Vec::new(),
        };
        let reply = respond(&source, None);
        assert_eq!(reply["result"]["type"], "agent_transcript", "{reply}");
        assert_eq!(reply["result"]["agent"], "agy");
        assert_eq!(reply["result"]["session_id"], "conv-fixture-0001");
        assert_eq!(reply["result"]["entries"][0]["kind"], "user");
        assert_eq!(reply["result"]["entries"][0]["text"], "Hey");
        assert_eq!(reply["result"]["entries"][1]["kind"], "reply");
        assert_eq!(
            reply["result"]["entries"][1]["text"],
            "Hey! How can I help?"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
