use std::time::Duration;

use bytes::Bytes;

use crate::api::schema::{
    AcpAdapterInfo, AcpAdapterLaunch, AcpEndpointLaunch, AcpSessionInfo, AcpWorkerInfo,
    AgentAcpAttachParams, AgentAcpDetachParams, AgentAcpEndpointParams, AgentPromptDelivery,
    AgentPromptParams, AgentRenameParams, AgentSendKeysParams, AgentStartParams, AgentTarget,
    PaneReadResult, ResponseResult,
};
use crate::app::App;

use super::responses::{encode_error, encode_error_body, encode_success};

const AGENT_PROMPT_SUBMIT_DELAY: Duration = Duration::from_millis(300);

impl App {
    pub(super) fn handle_agent_acp_status(&mut self, id: String, target: AgentTarget) -> String {
        let (terminal_id, worker, identity, adapter, turn_epoch) =
            match self.resolve_acp_worker(&target.target) {
                Ok(worker) => worker,
                Err(error) => return encode_error_body(id, error),
            };
        let Some(owned) = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.acp_owned_worker.as_ref())
        else {
            return encode_error(
                id,
                "acp_ownership_required",
                "worker is not owned by Herdr ACP",
            );
        };
        let lifecycle = match &owned.lifecycle {
            crate::acp::AcpOwnedLifecycle::Ready => "acp_owned_ready",
            crate::acp::AcpOwnedLifecycle::Attached { .. } => "acp_owned_attached",
        };
        encode_success(
            id,
            ResponseResult::AgentAcpStatus {
                worker: AcpWorkerInfo {
                    terminal_id: worker.terminal_id,
                    workspace_id: worker.workspace_id,
                    tab_id: worker.tab_id,
                    pane_id: worker.pane_id,
                    name: identity.name.clone(),
                    agent: identity.agent.clone(),
                    generation: identity.generation(turn_epoch),
                },
                adapter: AcpAdapterInfo {
                    name: adapter.name.into(),
                    version: owned.adapter_version.clone(),
                },
                session: AcpSessionInfo {
                    id: identity.session_id,
                    mode: identity.session_mode,
                },
                cwd: identity.cwd.display().to_string(),
                lifecycle: lifecycle.into(),
            },
        )
    }

    pub(super) fn handle_agent_acp_register(
        &mut self,
        id: String,
        params: crate::api::schema::AgentAcpRegisterParams,
    ) -> String {
        match self.register_acp_worker(params) {
            Ok(agent) => encode_success(id, ResponseResult::AgentAcpRegistered { agent }),
            Err(error) => encode_error_body(id, error),
        }
    }

    pub(super) fn handle_agent_acp_endpoint(
        &mut self,
        id: String,
        params: AgentAcpEndpointParams,
    ) -> String {
        let target_value = params.target;
        let (terminal_id, worker, identity, adapter, turn_epoch) =
            match self.resolve_acp_worker(&target_value) {
                Ok(worker) => worker,
                Err(error) => return encode_error_body(id, error),
            };
        let (version, lifecycle_ready) = match self.state.terminals.get(&terminal_id) {
            Some(terminal) => match terminal.acp_owned_worker.as_ref() {
                Some(owned) if owned.identity == identity => (
                    owned.adapter_version.clone(),
                    matches!(&owned.lifecycle, crate::acp::AcpOwnedLifecycle::Ready),
                ),
                _ => {
                    return encode_error(
                        id,
                        "acp_ownership_required",
                        "worker is owned by a PTY lifecycle, not Herdr ACP",
                    )
                }
            },
            None => return encode_error(id, "agent_not_found", "ACP worker disappeared"),
        };
        if !lifecycle_ready {
            return encode_error(id, "acp_worker_attached", "ACP worker already has an owner");
        }
        let generation = identity.generation(turn_epoch);
        let ticket = match crate::acp::AcpAttachTicket::mint(
            identity.clone(),
            generation,
            std::time::Instant::now(),
        ) {
            Ok(ticket) => ticket,
            Err(_) => {
                return encode_error(
                    id,
                    "acp_ticket_unavailable",
                    "secure ACP attach ticket generation failed",
                )
            }
        };
        let ticket_token = ticket.token.clone();
        let Some(terminal) = self.state.terminals.get_mut(&terminal_id) else {
            return encode_error(id, "agent_not_found", "ACP worker disappeared");
        };
        terminal.acp_attach_ticket = Some(ticket);

        encode_success(
            id,
            ResponseResult::AgentAcpEndpoint {
                endpoint: AcpEndpointLaunch {
                    transport: "stdio".into(),
                    command: "herdr".into(),
                    args: vec![
                        "agent".into(),
                        "acp-attach".into(),
                        target_value,
                        "--generation".into(),
                        generation.to_string(),
                        "--ticket".into(),
                        ticket_token,
                    ],
                    protocol_version: crate::acp::ACP_ENDPOINT_PROTOCOL_VERSION,
                },
                worker: AcpWorkerInfo {
                    terminal_id: worker.terminal_id,
                    workspace_id: worker.workspace_id,
                    tab_id: worker.tab_id,
                    pane_id: worker.pane_id,
                    name: identity.name.clone(),
                    agent: identity.agent.clone(),
                    generation,
                },
                adapter: AcpAdapterInfo {
                    name: adapter.name.into(),
                    version,
                },
                session: AcpSessionInfo {
                    id: identity.session_id.clone(),
                    mode: identity.session_mode,
                },
                cwd: identity.cwd.display().to_string(),
                lifecycle: "acp_owned_ready".into(),
            },
        )
    }

    pub(super) fn handle_agent_acp_attach(
        &mut self,
        id: String,
        params: AgentAcpAttachParams,
    ) -> String {
        let (terminal_id, _worker, identity, adapter, turn_epoch) =
            match self.resolve_acp_worker(&params.target) {
                Ok(worker) => worker,
                Err(error) => return encode_error_body(id, error),
            };
        let generation = identity.generation(turn_epoch);
        let Some(terminal) = self.state.terminals.get_mut(&terminal_id) else {
            return encode_error(id, "agent_not_found", "ACP worker disappeared");
        };
        if !terminal.acp_owned_worker.as_ref().is_some_and(|owned| {
            owned.identity == identity
                && matches!(&owned.lifecycle, crate::acp::AcpOwnedLifecycle::Ready)
        }) {
            return encode_error(
                id,
                "acp_ownership_required",
                "worker is not ready under Herdr ACP ownership",
            );
        }
        let adapter_command = terminal
            .acp_owned_worker
            .as_ref()
            .map(|owned| owned.adapter_command.display().to_string())
            .unwrap_or_default();
        let Some(ticket) = terminal.acp_attach_ticket.as_ref() else {
            return encode_error(id, "acp_ticket_invalid", "ACP attach ticket is invalid");
        };
        let validation = ticket.validates(
            &params.ticket,
            &identity,
            params.generation,
            std::time::Instant::now(),
        );
        if !matches!(validation, Err(crate::acp::TicketValidationError::Invalid)) {
            terminal.acp_attach_ticket = None;
        }
        match validation {
            Ok(()) if params.generation == generation => {}
            Ok(()) | Err(crate::acp::TicketValidationError::Stale) => {
                return encode_error(id, "acp_endpoint_stale", "ACP endpoint generation is stale")
            }
            Err(crate::acp::TicketValidationError::Expired) => {
                return encode_error(id, "acp_ticket_expired", "ACP attach ticket expired")
            }
            Err(crate::acp::TicketValidationError::Invalid) => {
                return encode_error(id, "acp_ticket_invalid", "ACP attach ticket is invalid")
            }
        }

        let adapter_unchanged = terminal.acp_owned_worker.as_ref().is_some_and(|owned| {
            crate::acp::adapter_sha256(&owned.adapter_command)
                .is_ok_and(|sha256| sha256 == owned.adapter_sha256)
        });
        if !adapter_unchanged {
            terminal.revoke_acp_owned_worker();
            return encode_error(
                id,
                "acp_adapter_changed",
                "ACP adapter changed after registration; register the worker again",
            );
        }

        let lease = match crate::acp::fresh_lease_token() {
            Ok(lease) => lease,
            Err(_) => {
                return encode_error(
                    id,
                    "acp_lease_unavailable",
                    "secure ACP ownership lease generation failed",
                )
            }
        };
        if let Some(owned) = terminal.acp_owned_worker.as_mut() {
            owned.lifecycle = crate::acp::AcpOwnedLifecycle::Attached {
                lease: lease.clone(),
                generation,
            };
        }

        encode_success(
            id,
            ResponseResult::AgentAcpAttached {
                launch: AcpAdapterLaunch {
                    command: adapter_command,
                    args: adapter.args.iter().map(|arg| (*arg).into()).collect(),
                    cwd: identity.cwd.display().to_string(),
                    lease,
                },
            },
        )
    }

    pub(super) fn handle_agent_acp_detach(
        &mut self,
        id: String,
        params: AgentAcpDetachParams,
    ) -> String {
        let (terminal_id, _worker, identity, _adapter, turn_epoch) =
            match self.resolve_acp_worker(&params.target) {
                Ok(worker) => worker,
                Err(error) => return encode_error_body(id, error),
            };
        let generation = identity.generation(turn_epoch);
        let Some(terminal) = self.state.terminals.get_mut(&terminal_id) else {
            return encode_error(id, "agent_not_found", "ACP worker disappeared");
        };
        let valid = terminal.acp_owned_worker.as_ref().is_some_and(|owned| {
            owned.identity == identity
                && matches!(
                    &owned.lifecycle,
                    crate::acp::AcpOwnedLifecycle::Attached {
                        lease,
                        generation: attached_generation,
                    } if *attached_generation == generation
                        && params.generation == generation
                        && lease == &params.lease
                )
        });
        if !valid {
            return encode_error(id, "acp_lease_invalid", "ACP ownership lease is invalid");
        }
        if let Some(owned) = terminal.acp_owned_worker.as_mut() {
            owned.lifecycle = crate::acp::AcpOwnedLifecycle::Ready;
        }
        encode_success(id, ResponseResult::Ok {})
    }

    fn resolve_acp_worker(
        &mut self,
        target: &str,
    ) -> Result<
        (
            crate::terminal::TerminalId,
            crate::api::schema::AgentInfo,
            crate::acp::AcpWorkerIdentity,
            crate::acp::AcpAdapterSpec,
            u64,
        ),
        crate::api::schema::ErrorBody,
    > {
        let resolved = self
            .resolve_terminal_target(target)
            .map_err(|error| self.agent_target_error_body(error))?;
        let terminal_id = self
            .state
            .workspaces
            .get(resolved.ws_idx)
            .and_then(|workspace| workspace.terminal_id(resolved.pane_id))
            .cloned()
            .ok_or_else(|| acp_error("agent_not_found", "ACP worker does not exist"))?;
        let worker = self
            .agent_info(resolved.ws_idx, resolved.pane_id)
            .ok_or_else(|| acp_error("agent_not_found", "ACP worker does not exist"))?;
        let Some(name) = worker.name.clone() else {
            if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
                terminal.revoke_acp_owned_worker();
            }
            return Err(acp_error(
                "acp_worker_unauthenticated",
                "ACP endpoint requires an authoritative named Herdr agent",
            ));
        };
        let Some(agent) = worker.agent.clone() else {
            if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
                terminal.revoke_acp_owned_worker();
            }
            return Err(acp_error(
                "acp_worker_unauthenticated",
                "ACP endpoint requires an authoritative agent identity",
            ));
        };
        let adapter = crate::acp::adapter_for(&agent).ok_or_else(|| {
            acp_error(
                "acp_adapter_unsupported",
                format!("agent {agent} has no configured ACP adapter"),
            )
        })?;
        let cwd = worker
            .foreground_cwd
            .as_deref()
            .or(worker.cwd.as_deref())
            .map(std::path::PathBuf::from)
            .filter(|cwd| cwd.is_absolute())
            .ok_or_else(|| acp_error("acp_cwd_unavailable", "ACP worker cwd is unavailable"))?;
        let terminal = self
            .state
            .terminals
            .get(&terminal_id)
            .ok_or_else(|| acp_error("agent_not_found", "ACP worker disappeared"))?;
        let placeholder_shell_owned = self
            .terminal_runtimes
            .get(&terminal_id)
            .and_then(super::super::agents::available_shell_name)
            .is_some();
        let turn_epoch = terminal.turn_epoch;
        let identity = terminal
            .acp_owned_worker
            .as_ref()
            .map(|owned| owned.identity.clone())
            .ok_or_else(|| {
                acp_error(
                    "acp_ownership_required",
                    "worker is owned by a PTY lifecycle, not Herdr ACP",
                )
            })?;
        let ownership_stale = terminal.detected_agent.is_some()
            || !placeholder_shell_owned
            || identity.terminal_id != worker.terminal_id
            || identity.workspace_id != worker.workspace_id
            || identity.tab_id != worker.tab_id
            || identity.pane_id != worker.pane_id
            || identity.name != name
            || identity.agent != agent
            || identity.cwd != cwd;
        if ownership_stale {
            if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
                terminal.revoke_acp_owned_worker();
            }
            return Err(acp_error(
                "acp_endpoint_stale",
                "ACP ownership no longer matches the live worker",
            ));
        }
        Ok((terminal_id, worker, identity, adapter, turn_epoch))
    }

    pub(super) fn handle_agent_list(&mut self, id: String) -> String {
        encode_success(
            id,
            ResponseResult::AgentList {
                agents: self.collect_agent_infos(),
            },
        )
    }

    pub(super) fn handle_agent_get(&mut self, id: String, target: AgentTarget) -> String {
        self.reconcile_managed_agent_target(&target.target);
        let agent = match self.agent_info_for_target(&target.target) {
            Ok(agent) => agent,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };

        encode_success(id, ResponseResult::AgentInfo { agent })
    }

    pub(super) fn handle_agent_focus(&mut self, id: String, target: AgentTarget) -> String {
        let agent = match self.focus_agent_target(&target.target) {
            Ok(agent) => agent,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };

        encode_success(id, ResponseResult::AgentInfo { agent })
    }

    pub(super) fn handle_agent_rename(&mut self, id: String, params: AgentRenameParams) -> String {
        let agent = match self.rename_agent_target(&params.target, params.name) {
            Ok(agent) => agent,
            Err(err) => return encode_error_body(id, self.agent_rename_error_body(err)),
        };

        encode_success(id, ResponseResult::AgentInfo { agent })
    }

    pub(super) fn handle_agent_start(&mut self, id: String, params: AgentStartParams) -> String {
        let (agent, argv) = match self.start_agent(params) {
            Ok(started) => started,
            Err(err) => return encode_error_body(id, self.agent_start_error_body(err)),
        };

        encode_success(id, ResponseResult::AgentStarted { agent, argv })
    }

    pub(super) fn handle_agent_prompt(&mut self, id: String, params: AgentPromptParams) -> String {
        if params.text.is_empty() {
            return encode_error(id, "empty_agent_prompt", "agent prompt must not be empty");
        }
        let resolved = match self.resolve_agent_target(&params.target) {
            Ok(resolved) => resolved,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };
        let Some(terminal_id) = self
            .state
            .workspaces
            .get(resolved.ws_idx)
            .and_then(|workspace| workspace.terminal_id(resolved.pane_id))
            .cloned()
        else {
            return agent_not_found(id, &params.target);
        };
        let Some(terminal) = self.state.terminals.get(&terminal_id) else {
            return agent_not_found(id, &params.target);
        };
        let Some(expected_agent) = terminal.effective_known_agent() else {
            return agent_not_ready(id, &params.target);
        };
        if terminal.managed_agent_launch_pending() {
            return agent_not_ready(id, &params.target);
        }
        if terminal.input_pending {
            let kind = terminal
                .input_prompt_kind
                .map(crate::detect::manifest::input_prompt_kind_label)
                .unwrap_or("unknown");
            return encode_error(
                id,
                "agent_input_pending",
                format!(
                    "agent {} has a pending {kind} input prompt; chat prompt was not written",
                    params.target
                ),
            );
        }
        let Some(runtime) = self.lookup_runtime_sender(resolved.ws_idx, resolved.pane_id) else {
            return agent_not_found(id, &params.target);
        };
        if !super::super::agents::runtime_hosts_agent(runtime, expected_agent) {
            return encode_error(
                id,
                "agent_not_ready",
                format!(
                    "agent {} is no longer the pane foreground process",
                    params.target
                ),
            );
        }
        // Bind the occupant baseline HERE, before a single byte is written.
        // Capturing it after the blocking acknowledgement would adopt whatever
        // occupies the pane by then as the expected occupant, so a same-kind
        // swap during the write/ack window would be baselined as legitimate and
        // the delayed key would land in a session that never received the text.
        let expected_group = super::super::agents::capture_occupant_group(runtime);
        let (text, enter) =
            crate::app::api_helpers::encode_api_submission_parts(runtime, &params.text);
        let composer_baseline = runtime.detection_content_seq();
        let write_result = runtime
            .write_bytes_acknowledged(Bytes::from(text), std::time::Duration::from_secs(5))
            .is_ok();
        // Revalidate the live PTY occupant after the blocking acknowledgement so
        // a foreground identity change during the batch is never reported as
        // receipt by the originally resolved agent.
        if !write_result
            || !super::super::agents::runtime_hosts_same_occupant(
                runtime,
                expected_agent,
                expected_group,
            )
        {
            return encode_error(
                id,
                "agent_prompt_not_received",
                "agent prompt was not fully written to the pane PTY",
            );
        }
        // The revalidation above answered "does this pane still host the expected
        // agent?" for the instant the text finished writing. The Enter lands
        // AGENT_PROMPT_SUBMIT_DELAY later, so it must ask again at that moment:
        // an occupant change inside the window would otherwise deliver a bare
        // Enter to whatever inherited the pane, submitting whatever sits in its
        // line buffer, after the caller was already told the prompt was received.
        // A fresh watch per prompt. Reusing the previous one would let an
        // abandoned submit from an earlier attempt keep reporting against this
        // one — a field that stays true after it stops being true is how #31's
        // misattribution happened in the first place.
        let submit_abandoned = std::sync::Arc::new(crate::terminal::PromptSubmitWatch::default());
        runtime.send_bytes_after_guarded(
            Bytes::from(enter),
            AGENT_PROMPT_SUBMIT_DELAY,
            super::super::agents::runtime_agent_guard(runtime, expected_agent, expected_group),
            Some(std::sync::Arc::clone(&submit_abandoned)),
        );
        self.record_pane_prompt_submit_watch(resolved.ws_idx, resolved.pane_id, submit_abandoned);
        self.record_pane_composer_write(
            resolved.ws_idx,
            resolved.pane_id,
            crate::terminal::ComposerInputSource::AgentPrompt,
            composer_baseline,
            true,
            true,
        );
        let Some(agent) = self.agent_info(resolved.ws_idx, resolved.pane_id) else {
            return agent_not_found(id, &params.target);
        };
        encode_success(
            id,
            ResponseResult::AgentPrompted {
                agent,
                delivery: Some(AgentPromptDelivery::WrittenToPty),
            },
        )
    }

    pub(super) fn handle_agent_read(
        &mut self,
        id: String,
        params: crate::api::schema::AgentReadParams,
    ) -> String {
        let resolved = match self.resolve_agent_target(&params.target) {
            Ok(resolved) => resolved,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };
        let Some((pane, workspace_id)) = self.lookup_runtime(resolved.ws_idx, resolved.pane_id)
        else {
            return agent_not_found(id, &params.target);
        };
        let snapshot = crate::app::api_helpers::read_terminal_snapshot(
            pane,
            params.source,
            params.format,
            params.lines,
        );

        encode_success(
            id,
            ResponseResult::PaneRead {
                read: PaneReadResult {
                    pane_id: self
                        .public_pane_id(resolved.ws_idx, resolved.pane_id)
                        .unwrap_or_else(|| params.target.clone()),
                    workspace_id,
                    tab_id: self
                        .public_tab_id(resolved.ws_idx, resolved.tab_idx)
                        .unwrap(),
                    source: params.source,
                    format: params.format,
                    text: snapshot.text,
                    revision: 0,
                    truncated: snapshot.truncated,
                },
            },
        )
    }

    pub(super) fn handle_agent_explain(&mut self, id: String, target: AgentTarget) -> String {
        let resolved = match self.resolve_agent_target(&target.target) {
            Ok(resolved) => resolved,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };
        let Some((pane, _workspace_id)) = self.lookup_runtime(resolved.ws_idx, resolved.pane_id)
        else {
            return agent_not_found(id, &target.target);
        };
        let Some(terminal_id) = self
            .state
            .workspaces
            .get(resolved.ws_idx)
            .and_then(|workspace| workspace.terminal_id(resolved.pane_id))
            .cloned()
        else {
            return agent_not_found(id, &target.target);
        };
        let Some(terminal) = self.state.terminals.get(&terminal_id) else {
            return agent_not_found(id, &target.target);
        };
        let Some(agent) = terminal.effective_known_agent().or(terminal.detected_agent) else {
            return encode_error(
                id,
                "agent_explain_unavailable",
                format!(
                    "agent target {} does not have a detected agent label",
                    target.target
                ),
            );
        };

        let screen = pane.detection_text();
        let osc_title = pane.agent_osc_title();
        let osc_progress = pane.agent_osc_progress();
        let explain = crate::detect::manifest::explain_with_input(
            agent,
            crate::detect::manifest::DetectionInput {
                screen: &screen,
                osc_title: &osc_title,
                osc_progress: &osc_progress,
            },
        );
        let mut value = crate::detect::manifest::explain_to_json_value(&explain);
        if terminal.full_lifecycle_hook_authority_active() {
            value["state"] = serde_json::Value::String(
                crate::detect::manifest::agent_state_label(terminal.state).to_string(),
            );
            value["matched_rule"] = serde_json::Value::Null;
            value["visible_idle"] = serde_json::Value::Bool(false);
            value["visible_blocker"] = serde_json::Value::Bool(false);
            value["visible_working"] = serde_json::Value::Bool(false);
            value["screen_detection_skipped"] = serde_json::Value::Bool(true);
            value["screen_detection_skip_reason"] =
                serde_json::Value::String("full_lifecycle_hook_authority".to_string());
            value["skip_state_update"] = serde_json::Value::Bool(false);
            value["skipped_update_reason"] = serde_json::Value::Null;
            value["fallback_reason"] = serde_json::Value::Null;
            value["evaluated_rules"] = serde_json::json!([]);
        }

        encode_success(id, ResponseResult::AgentExplain { explain: value })
    }

    pub(super) fn handle_agent_send_keys(
        &mut self,
        id: String,
        params: AgentSendKeysParams,
    ) -> String {
        let resolved = match self.resolve_agent_target(&params.target) {
            Ok(resolved) => resolved,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };
        let Some(terminal_id) = self
            .state
            .workspaces
            .get(resolved.ws_idx)
            .and_then(|workspace| workspace.terminal_id(resolved.pane_id))
            .cloned()
        else {
            return agent_not_found(id, &params.target);
        };
        let Some(expected_agent) = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.effective_known_agent())
        else {
            return agent_not_ready(id, &params.target);
        };
        let Some(runtime) = self.lookup_runtime_sender(resolved.ws_idx, resolved.pane_id) else {
            return agent_not_found(id, &params.target);
        };
        if !super::super::agents::runtime_hosts_agent(runtime, expected_agent) {
            return agent_not_ready(id, &params.target);
        }
        let encoded = match super::super::api_helpers::encode_api_keys(runtime, &params.keys) {
            Ok(encoded) => encoded,
            Err(key) => {
                return encode_error(id, "invalid_key", format!("unsupported key {key}"));
            }
        };
        let bytes: Vec<u8> = encoded.into_iter().flatten().collect();
        let composer_baseline = runtime.detection_content_seq();
        if let Err(err) = runtime.try_send_bytes(Bytes::from(bytes)) {
            return encode_error(id, "agent_send_keys_failed", err.to_string());
        }
        self.record_pane_composer_write(
            resolved.ws_idx,
            resolved.pane_id,
            crate::terminal::ComposerInputSource::Api,
            composer_baseline,
            false,
            false,
        );
        if super::super::api_helpers::api_keys_abort_turn(&params.keys) {
            if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
                terminal.mark_turn_aborted();
            }
        }

        encode_success(id, ResponseResult::Ok {})
    }
}

fn acp_error(code: &'static str, message: impl Into<String>) -> crate::api::schema::ErrorBody {
    crate::api::schema::ErrorBody {
        code: code.into(),
        message: message.into(),
    }
}

fn agent_not_ready(id: String, target: &str) -> String {
    encode_error(
        id,
        "agent_not_ready",
        format!("agent {target} is not an active named agent"),
    )
}

fn agent_not_found(id: String, target: &str) -> String {
    encode_error(
        id,
        "agent_not_found",
        format!("agent target {target} not found"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::schema::{AgentStatus, SuccessResponse},
        app::Mode,
        config::Config,
        detect::{Agent, AgentState},
        workspace::Workspace,
    };

    fn app_with_agent() -> App {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![Workspace::test_new("agent")];
        app.state.ensure_test_terminals();
        app.state.active = Some(0);
        app.state.selected = 0;
        app.state.mode = Mode::Terminal;
        app
    }

    fn test_adapter_command() -> std::path::PathBuf {
        static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        PATH.get_or_init(|| {
            let path = std::env::temp_dir()
                .join(format!("herdr-acp-stable-adapter-{}", std::process::id()));
            std::fs::write(&path, b"stable test adapter").unwrap();
            path
        })
        .clone()
    }

    fn configure_codex_worker(
        app: &mut App,
        acp_owned: bool,
    ) -> (String, crate::terminal::TerminalId) {
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let pane_target = app.public_pane_id(0, pane_id).unwrap();
        if acp_owned {
            let cwd = app.state.terminals[&terminal_id].cwd.display().to_string();
            let adapter_command = test_adapter_command();
            let adapter_sha256 = crate::acp::adapter_sha256(&adapter_command).unwrap();
            let (runtime, _rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
            app.terminal_runtimes.insert(terminal_id.clone(), runtime);
            app.register_acp_worker(crate::api::schema::AgentAcpRegisterParams {
                name: "reviewer".into(),
                kind: "codex".into(),
                pane_id: pane_target,
                cwd,
                session: crate::api::schema::AcpSessionInfo {
                    id: None,
                    mode: crate::api::schema::AcpSessionMode::New,
                },
                adapter_version: Some("codex-acp test".into()),
                adapter_command: Some(adapter_command.display().to_string()),
                adapter_sha256: Some(adapter_sha256),
            })
            .unwrap();
        } else {
            let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
            terminal.set_agent_name("reviewer".into());
            terminal.set_detected_state(Some(Agent::Codex), AgentState::Idle);
        }
        (terminal_id.to_string(), terminal_id)
    }

    fn mint_endpoint(
        app: &mut App,
        target: &str,
    ) -> (
        crate::api::schema::AcpEndpointLaunch,
        crate::api::schema::AcpWorkerInfo,
        crate::api::schema::AcpSessionInfo,
        String,
        String,
    ) {
        let response = app.handle_agent_acp_endpoint(
            "endpoint".into(),
            AgentAcpEndpointParams {
                target: target.into(),
            },
        );
        let success: SuccessResponse = serde_json::from_str(&response).unwrap();
        let ResponseResult::AgentAcpEndpoint {
            endpoint,
            worker,
            session,
            lifecycle,
            ..
        } = success.result
        else {
            panic!("expected ACP endpoint response");
        };
        let ticket = endpoint.args.last().unwrap().clone();
        (endpoint, worker, session, lifecycle, ticket)
    }

    #[test]
    fn acp_endpoint_rejects_normal_live_pty_workers() {
        let mut app = app_with_agent();
        let (target, _) = configure_codex_worker(&mut app, false);
        let response =
            app.handle_agent_acp_endpoint("endpoint".into(), AgentAcpEndpointParams { target });
        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&response).unwrap();
        assert_eq!(error.error.code, "acp_ownership_required");
    }

    #[tokio::test]
    async fn acp_owned_endpoint_is_one_shot_and_detaches_back_to_ready() {
        let mut app = app_with_agent();
        let (target, _) = configure_codex_worker(&mut app, true);
        let (endpoint, worker, session, lifecycle, ticket) = mint_endpoint(&mut app, &target);
        assert_eq!(lifecycle, "acp_owned_ready");
        assert_eq!(endpoint.protocol_version, 1);
        assert_eq!(session.mode, crate::api::schema::AcpSessionMode::New);
        assert!(session.id.is_none());
        assert_eq!(endpoint.args[2], target);
        assert_eq!(endpoint.args[4], worker.generation.to_string());

        let attach_params = AgentAcpAttachParams {
            target: target.clone(),
            generation: worker.generation,
            ticket,
        };
        let attached = app.handle_agent_acp_attach("attach".into(), attach_params.clone());
        let attached: SuccessResponse = serde_json::from_str(&attached).unwrap();
        let ResponseResult::AgentAcpAttached { launch } = attached.result else {
            panic!("expected ACP attach response");
        };
        assert_eq!(launch.command, test_adapter_command().display().to_string());

        let status = app.handle_agent_acp_status(
            "status".into(),
            AgentTarget {
                target: target.clone(),
            },
        );
        assert!(status.contains("\"lifecycle\":\"acp_owned_attached\""));
        assert!(!status.contains(&launch.lease));
        assert!(!status.contains("ticket"));
        assert!(!status.contains("launch"));
        let repeated_status = app.handle_agent_acp_status(
            "status-2".into(),
            AgentTarget {
                target: target.clone(),
            },
        );
        assert!(repeated_status.contains("\"lifecycle\":\"acp_owned_attached\""));

        let replay = app.handle_agent_acp_attach("replay".into(), attach_params);
        let replay: crate::api::schema::ErrorResponse = serde_json::from_str(&replay).unwrap();
        assert_eq!(replay.error.code, "acp_ownership_required");

        let detached = app.handle_agent_acp_detach(
            "detach".into(),
            AgentAcpDetachParams {
                target: target.clone(),
                generation: worker.generation,
                lease: launch.lease,
            },
        );
        assert!(serde_json::from_str::<SuccessResponse>(&detached).is_ok());
        assert_eq!(mint_endpoint(&mut app, &target).3, "acp_owned_ready");
    }

    #[tokio::test]
    async fn acp_attach_revokes_worker_when_registered_adapter_changes() {
        let mut app = app_with_agent();
        let (target, terminal_id) = configure_codex_worker(&mut app, true);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let adapter_path =
            std::env::temp_dir().join(format!("herdr-acp-adapter-{}-{nonce}", std::process::id()));
        std::fs::write(&adapter_path, b"registered adapter").unwrap();
        let registered_sha256 = crate::acp::adapter_sha256(&adapter_path).unwrap();
        let owned = app
            .state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .acp_owned_worker
            .as_mut()
            .unwrap();
        owned.adapter_command = adapter_path.clone();
        owned.adapter_sha256 = registered_sha256;

        let (_endpoint, worker, _session, _lifecycle, ticket) = mint_endpoint(&mut app, &target);
        std::fs::write(&adapter_path, b"replaced adapter").unwrap();
        let response = app.handle_agent_acp_attach(
            "attach".into(),
            AgentAcpAttachParams {
                target,
                generation: worker.generation,
                ticket,
            },
        );
        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&response).unwrap();
        assert_eq!(error.error.code, "acp_adapter_changed");
        let terminal = &app.state.terminals[&terminal_id];
        assert!(terminal.acp_owned_worker.is_none());
        assert!(terminal.acp_attach_ticket.is_none());
        std::fs::remove_file(adapter_path).unwrap();
    }

    #[tokio::test]
    async fn acp_owned_worker_projects_idle_before_and_after_attach() {
        let mut app = app_with_agent();
        let (target, _) = configure_codex_worker(&mut app, true);
        let list: SuccessResponse =
            serde_json::from_str(&app.handle_agent_list("ready-list".into())).unwrap();
        let ResponseResult::AgentList { agents } = list.result else {
            panic!("expected agent list");
        };
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent_status, AgentStatus::Idle);

        let (_endpoint, worker, _session, _lifecycle, ticket) = mint_endpoint(&mut app, &target);
        let attached = app.handle_agent_acp_attach(
            "attach".into(),
            AgentAcpAttachParams {
                target,
                generation: worker.generation,
                ticket,
            },
        );
        assert!(serde_json::from_str::<SuccessResponse>(&attached).is_ok());
        let list: SuccessResponse =
            serde_json::from_str(&app.handle_agent_list("attached-list".into())).unwrap();
        let ResponseResult::AgentList { agents } = list.result else {
            panic!("expected agent list");
        };
        assert_eq!(agents[0].agent_status, AgentStatus::Idle);
    }

    #[tokio::test]
    async fn acp_register_rejects_a_detected_agent_pane() {
        let mut app = app_with_agent();
        let (_target, terminal_id) = configure_codex_worker(&mut app, false);
        let cwd = app.state.terminals[&terminal_id].cwd.display().to_string();
        let (runtime, _rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let pane_target = app.public_pane_id(0, pane_id).unwrap();
        app.terminal_runtimes.insert(terminal_id.clone(), runtime);
        let error = app
            .register_acp_worker(crate::api::schema::AgentAcpRegisterParams {
                name: "second".into(),
                kind: "codex".into(),
                pane_id: pane_target,
                cwd,
                session: crate::api::schema::AcpSessionInfo {
                    id: None,
                    mode: crate::api::schema::AcpSessionMode::New,
                },
                adapter_version: Some("codex-acp test".into()),
                adapter_command: Some("/validated/codex-acp".into()),
                adapter_sha256: Some([0; 32]),
            })
            .unwrap_err();
        assert_eq!(error.code, "acp_placeholder_busy");
    }

    #[test]
    fn acp_register_rejects_resume_and_load_sessions() {
        for mode in [
            crate::api::schema::AcpSessionMode::Load,
            crate::api::schema::AcpSessionMode::Resume,
        ] {
            let mut app = app_with_agent();
            let error = app
                .register_acp_worker(crate::api::schema::AgentAcpRegisterParams {
                    name: "reviewer".into(),
                    kind: "codex".into(),
                    pane_id: "w1:p1".into(),
                    cwd: "/work".into(),
                    session: crate::api::schema::AcpSessionInfo {
                        id: Some("native-session-id".into()),
                        mode,
                    },
                    adapter_version: Some("codex-acp test".into()),
                    adapter_command: Some("/validated/codex-acp".into()),
                    adapter_sha256: Some([0; 32]),
                })
                .unwrap_err();
            assert_eq!(error.code, "acp_session_mode_unsupported");
        }
    }

    #[tokio::test]
    async fn acp_status_revokes_ownership_after_cwd_change() {
        let mut app = app_with_agent();
        let (target, terminal_id) = configure_codex_worker(&mut app, true);
        app.state.terminals.get_mut(&terminal_id).unwrap().cwd = "/different".into();
        let status = app.handle_agent_acp_status("status".into(), AgentTarget { target });
        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&status).unwrap();
        assert_eq!(error.error.code, "acp_endpoint_stale");
        assert!(app.state.terminals[&terminal_id].acp_owned_worker.is_none());
    }

    #[tokio::test]
    async fn acp_status_revokes_ownership_when_placeholder_runtime_disappears() {
        let mut app = app_with_agent();
        let (target, terminal_id) = configure_codex_worker(&mut app, true);
        app.terminal_runtimes.remove(&terminal_id);

        let status = app.handle_agent_acp_status("status".into(), AgentTarget { target });

        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&status).unwrap();
        assert_eq!(error.error.code, "acp_endpoint_stale");
        assert!(app.state.terminals[&terminal_id].acp_owned_worker.is_none());
    }

    #[tokio::test]
    async fn acp_status_revokes_ownership_after_name_authority_is_cleared() {
        let mut app = app_with_agent();
        let (target, terminal_id) = configure_codex_worker(&mut app, true);
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .clear_agent_name();

        let status = app.handle_agent_acp_status("status".into(), AgentTarget { target });

        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&status).unwrap();
        assert_eq!(error.error.code, "acp_worker_unauthenticated");
        assert!(app.state.terminals[&terminal_id].acp_owned_worker.is_none());
    }

    #[tokio::test]
    async fn acp_endpoint_serialization_matches_tendwire_contract() {
        let mut app = app_with_agent();
        let (target, _) = configure_codex_worker(&mut app, true);
        let response = app.handle_agent_acp_endpoint(
            "tw:acp:endpoint".into(),
            AgentAcpEndpointParams {
                target: target.clone(),
            },
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let result = value["result"].as_object().unwrap();
        assert_eq!(
            result
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "adapter",
                "cwd",
                "endpoint",
                "lifecycle",
                "session",
                "type",
                "worker",
            ])
        );
        assert_eq!(result["endpoint"]["command"], "herdr");
        assert_eq!(result["endpoint"]["args"][2], target);
        assert_eq!(result["endpoint"]["protocol_version"], 1);
        assert_eq!(result["session"], serde_json::json!({"mode": "new"}));
    }

    #[tokio::test]
    async fn acp_ticket_rejects_expiry_wrong_target_and_generation() {
        let mut app = app_with_agent();
        let (target, terminal_id) = configure_codex_worker(&mut app, true);
        let (_endpoint, worker, _session, _lifecycle, ticket) = mint_endpoint(&mut app, &target);
        let wrong_target = app.handle_agent_acp_attach(
            "wrong-target".into(),
            AgentAcpAttachParams {
                target: "missing-worker".into(),
                generation: worker.generation,
                ticket: ticket.clone(),
            },
        );
        assert!(serde_json::from_str::<crate::api::schema::ErrorResponse>(&wrong_target).is_ok());

        let stale = app.handle_agent_acp_attach(
            "stale".into(),
            AgentAcpAttachParams {
                target: target.clone(),
                generation: worker.generation.wrapping_add(1),
                ticket,
            },
        );
        let stale: crate::api::schema::ErrorResponse = serde_json::from_str(&stale).unwrap();
        assert_eq!(stale.error.code, "acp_endpoint_stale");

        let (_endpoint, worker, _session, _lifecycle, ticket) = mint_endpoint(&mut app, &target);
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .acp_attach_ticket
            .as_mut()
            .unwrap()
            .expires_at = std::time::Instant::now();
        let expired = app.handle_agent_acp_attach(
            "expired".into(),
            AgentAcpAttachParams {
                target,
                generation: worker.generation,
                ticket,
            },
        );
        let expired: crate::api::schema::ErrorResponse = serde_json::from_str(&expired).unwrap();
        assert_eq!(expired.error.code, "acp_ticket_expired");
    }

    #[tokio::test]
    async fn acp_secrets_never_leak_through_agent_list() {
        let mut app = app_with_agent();
        let (target, _) = configure_codex_worker(&mut app, true);
        let (_, _, _, _, ticket) = mint_endpoint(&mut app, &target);
        let list = app.handle_agent_list("list".into());
        assert!(!list.contains(&ticket));
        assert!(!list.contains("acp_attach_ticket"));
        assert!(!list.contains("acp_owned_worker"));
    }

    #[tokio::test]
    async fn agent_prompt_sends_text_then_delays_enter() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::OpenCode), AgentState::Working);
        let (runtime, mut rx) =
            crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                80, 24, 0, b"", 1,
            );
        runtime.test_process_pty_bytes(b"\x1b[?2004h");
        app.state.insert_test_runtime(pane_id, runtime);

        let public_pane_id = app.public_pane_id(0, pane_id).unwrap();
        let bracketed_started = std::time::Instant::now();
        let response = app.handle_agent_prompt(
            "req".into(),
            AgentPromptParams {
                target: public_pane_id,
                text: "A != B".into(),
                wait: None,
            },
        );
        let success: SuccessResponse = serde_json::from_str(&response).unwrap();
        let ResponseResult::AgentPrompted { agent, delivery } = success.result else {
            panic!("expected prompted response");
        };
        assert_eq!(agent.name.as_deref(), Some("reviewer"));
        assert_eq!(delivery, Some(AgentPromptDelivery::WrittenToPty));
        let first_attempt = agent
            .composer
            .attempt_id
            .as_deref()
            .expect("acknowledged prompt should expose its writer attempt");
        assert!(first_attempt.starts_with("cmp-"));
        assert_eq!(
            agent.composer.evidence.provenance,
            crate::api::schema::ComposerProvenance::AgentPrompt
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            Bytes::from_static(b"\x1b[200~A != B\x1b[201~")
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            Bytes::from_static(b"\r")
        );
        assert!(bracketed_started.elapsed() >= AGENT_PROMPT_SUBMIT_DELAY);

        app.lookup_runtime_sender(0, pane_id)
            .unwrap()
            .test_process_pty_bytes(b"\x1b[?2004l");
        let raw_started = std::time::Instant::now();
        let raw = app.handle_agent_prompt(
            "req-raw".into(),
            AgentPromptParams {
                target: "reviewer".into(),
                text: "A != B".into(),
                wait: None,
            },
        );
        let raw: SuccessResponse = serde_json::from_str(&raw).unwrap();
        let ResponseResult::AgentPrompted { agent, .. } = raw.result else {
            panic!("expected prompted response");
        };
        assert_ne!(
            agent.composer.attempt_id.as_deref(),
            Some(first_attempt),
            "each agent prompt PTY batch needs a fresh opaque attempt"
        );
        assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"A != B"));
        assert!(rx.try_recv().is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap(),
            Bytes::from_static(b"\r")
        );
        assert!(raw_started.elapsed() >= AGENT_PROMPT_SUBMIT_DELAY);

        let rejected = app.handle_agent_prompt(
            "req-label".into(),
            AgentPromptParams {
                target: "opencode".into(),
                text: "wrong target".into(),
                wait: None,
            },
        );
        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&rejected).unwrap();
        assert_eq!(error.error.code, "agent_not_found");
        assert!(rx.try_recv().is_err());
    }

    /// #26: the submitting Enter is scheduled, not sent, when the identity check
    /// runs. If the pane's occupant changes inside the delay window, an
    /// unguarded delayed write delivers a bare Enter to whatever inherited the
    /// pane — submitting whatever sits in its line buffer — after the caller was
    /// already told the prompt was received.
    ///
    /// Asserts on what reached the PTY, not on a log line. Remove the guard
    /// argument from the scheduling call and this must fail.
    #[tokio::test]
    async fn delayed_enter_is_withheld_when_the_pane_occupant_changes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (runtime, mut rx) =
            crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                80, 24, 0, b"", 1,
            );

        // Occupant is unchanged when the text is written, then changes before the
        // delayed Enter fires — exactly the #26 window.
        let still_hosting = Arc::new(AtomicBool::new(true));
        let guard_flag = Arc::clone(&still_hosting);
        let abandoned = Arc::new(crate::terminal::PromptSubmitWatch::default());

        runtime
            .write_bytes_acknowledged(
                Bytes::from_static(b"prompt text"),
                std::time::Duration::from_secs(5),
            )
            .expect("text should reach the PTY");
        assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"prompt text"));

        runtime.send_bytes_after_guarded(
            Bytes::from_static(b"\r"),
            AGENT_PROMPT_SUBMIT_DELAY,
            Box::new(move || guard_flag.load(Ordering::SeqCst)),
            Some(Arc::clone(&abandoned)),
        );

        // The pane changes hands while the Enter is still pending.
        still_hosting.store(false, Ordering::SeqCst);

        // Nothing further may reach the PTY. Wait well past the delay so a
        // delivered Enter would have arrived.
        let late = tokio::time::timeout(
            AGENT_PROMPT_SUBMIT_DELAY + Duration::from_millis(400),
            rx.recv(),
        )
        .await;
        assert!(
            late.is_err(),
            "a bare Enter reached a pane whose occupant had changed: {late:?}"
        );
        assert!(
            abandoned.abandoned.load(Ordering::SeqCst),
            "withholding the Enter must be observable, not silent"
        );
    }

    /// The guard must not withhold the Enter when the occupant is unchanged —
    /// otherwise every prompt would strand, which is the bug the delay exists to
    /// fix (upstream bb29eedb).
    #[tokio::test]
    async fn delayed_enter_is_delivered_when_the_pane_is_unchanged() {
        use std::sync::atomic::Ordering;
        use std::sync::Arc;

        let (runtime, mut rx) =
            crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                80, 24, 0, b"", 1,
            );
        let abandoned = Arc::new(crate::terminal::PromptSubmitWatch::default());
        runtime.send_bytes_after_guarded(
            Bytes::from_static(b"\r"),
            AGENT_PROMPT_SUBMIT_DELAY,
            Box::new(|| true),
            Some(Arc::clone(&abandoned)),
        );
        let delivered = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("Enter should arrive")
            .expect("channel open");
        assert_eq!(delivered, Bytes::from_static(b"\r"));
        assert!(!abandoned.abandoned.load(Ordering::SeqCst));
        assert!(
            abandoned.submitted.load(Ordering::SeqCst),
            "a delivered Enter must record that the prompt submitted"
        );
    }

    /// F3: a post-guard PTY write failure must raise abandonment, not pass
    /// silently. The receiver is dropped so the delayed send fails.
    #[tokio::test]
    async fn a_failed_delayed_write_raises_abandonment() {
        use std::sync::atomic::Ordering;
        use std::sync::Arc;

        let (runtime, rx) =
            crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                80, 24, 0, b"", 1,
            );
        let watch = Arc::new(crate::terminal::PromptSubmitWatch::default());
        drop(rx); // the PTY side is gone, so the delayed write cannot land

        runtime.send_bytes_after_guarded(
            Bytes::from_static(b"\r"),
            AGENT_PROMPT_SUBMIT_DELAY,
            Box::new(|| true),
            Some(Arc::clone(&watch)),
        );
        tokio::time::sleep(AGENT_PROMPT_SUBMIT_DELAY + Duration::from_millis(300)).await;

        assert!(
            watch.abandoned.load(Ordering::SeqCst),
            "a failed delayed write must be loud, not silent"
        );
        assert!(
            !watch.submitted.load(Ordering::SeqCst),
            "a write that failed must not report as submitted"
        );
    }

    /// #31 acceptance, driven through the PRODUCTION path.
    ///
    /// The previous version mutated terminal.turn directly and asserted
    /// retirement — manufacturing a state production cannot reach, because
    /// record_completed_turn_at increments the turn and destroys the watch in
    /// the same call. It passed while the incident still reproduced.
    ///
    /// This drives the real sequence: prompt, let the key land, then complete a
    /// turn the way the runtime does. Reverting resolve-at-clear kills it.
    #[tokio::test]
    async fn a_completed_turn_retires_the_submitted_prompts_claim() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::OpenCode), AgentState::Working);
        let (runtime, mut rx) =
            crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                80, 24, 0, b"", 8,
            );
        app.state.insert_test_runtime(pane_id, runtime);
        let target = app.public_pane_id(0, pane_id).unwrap();

        let response = app.handle_agent_prompt(
            "req".into(),
            AgentPromptParams {
                target,
                text: "api prompt".into(),
                wait: None,
            },
        );
        let success: SuccessResponse = serde_json::from_str(&response).unwrap();
        let ResponseResult::AgentPrompted { agent, .. } = success.result else {
            panic!("expected prompted response");
        };
        let attempt = agent.composer.attempt_id.clone().expect("attempt id");
        assert_eq!(
            agent.composer.evidence.provenance,
            crate::api::schema::ComposerProvenance::AgentPrompt
        );

        // Let the delayed key land so the watch records submitted.
        let _ = rx.try_recv();
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("Enter should arrive")
            .expect("channel open");

        // Complete a turn exactly as the runtime does — this is the call that
        // both increments the turn and discards the watch.
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .record_completed_turn(0, Default::default());

        let after = app.agent_info(0, pane_id).expect("agent info");
        assert_ne!(
            after.composer.attempt_id.as_deref(),
            Some(attempt.as_str()),
            "a submitted prompt whose turn completed must stop being the current attempt"
        );
        assert_ne!(
            after.composer.evidence.provenance,
            crate::api::schema::ComposerProvenance::AgentPrompt,
            "composer text must not inherit the last prompter's identity"
        );
        // F2: author derives from the same condemned source, so it must clear too.
        assert!(
            after.composer.author.is_none(),
            "author must not report api_client for text the prompt did not write"
        );
    }

    /// The axis the deleted turn_at_write test guarded, now covered through the
    /// production path: a retirement belongs to the prompt that earned it and
    /// must not be inherited by the next one.
    ///
    /// Taken from the reviewer's probe. Prompt A submits and its turn completes,
    /// so A retires — correct. Prompt B is then written and is still mid-flight,
    /// so B's claim must stand. With the flag left sticky, B is stripped of
    /// provenance, attempt_id and author, and `spent` has degenerated into
    /// "has this pane ever retired".
    #[tokio::test]
    async fn a_retirement_does_not_carry_over_to_the_next_prompt() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::OpenCode), AgentState::Working);
        let (runtime, mut rx) =
            crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                80, 24, 0, b"", 8,
            );
        app.state.insert_test_runtime(pane_id, runtime);
        let target = app.public_pane_id(0, pane_id).unwrap();

        // Prompt A: submits, its turn completes, so A's claim retires.
        let _ = app.handle_agent_prompt(
            "req-a".into(),
            AgentPromptParams {
                target: target.clone(),
                text: "prompt a".into(),
                wait: None,
            },
        );
        let _ = rx.try_recv();
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("Enter should arrive")
            .expect("channel open");
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .record_completed_turn(0, Default::default());

        // Prompt B: freshly written, Enter not yet landed.
        let response = app.handle_agent_prompt(
            "req-b".into(),
            AgentPromptParams {
                target,
                text: "prompt b".into(),
                wait: None,
            },
        );
        let success: SuccessResponse = serde_json::from_str(&response).unwrap();
        let ResponseResult::AgentPrompted { agent, .. } = success.result else {
            panic!("expected prompted response");
        };
        assert!(
            agent.composer.attempt_id.is_some(),
            "a fresh prompt's claim must not be retired by a previous prompt's retirement"
        );
        assert_eq!(
            agent.composer.evidence.provenance,
            crate::api::schema::ComposerProvenance::AgentPrompt,
            "a fresh mid-flight prompt keeps its draft attribution"
        );
    }

    /// Reviewer finding on #33: retiring on "the key was written" alone erases
    /// attribution from a genuinely STRANDED prompt — the herdr#18 case, where
    /// the Enter reached the PTY and the draft sat in the composer anyway.
    ///
    /// A stranded draft IS the prompt's, and saying "unknown" about it trades one
    /// wrong answer for another. Retirement now also requires a turn to have
    /// begun. This pins the stranded half; the submitted half is pinned by
    /// a_completed_turn_retires_the_submitted_prompts_claim.
    #[tokio::test]
    async fn a_stranded_prompt_keeps_owning_its_own_draft() {
        use std::sync::atomic::Ordering;

        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::OpenCode), AgentState::Working);
        let (runtime, mut rx) =
            crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                80, 24, 0, b"", 8,
            );
        app.state.insert_test_runtime(pane_id, runtime);

        let target = app.public_pane_id(0, pane_id).unwrap();
        let response = app.handle_agent_prompt(
            "req".into(),
            AgentPromptParams {
                target,
                text: "stranded text".into(),
                wait: None,
            },
        );
        let success: SuccessResponse = serde_json::from_str(&response).unwrap();
        let ResponseResult::AgentPrompted { agent, .. } = success.result else {
            panic!("expected prompted response");
        };
        let attempt = agent.composer.attempt_id.clone().expect("attempt id");

        // The Enter is written — but no turn ever starts, which is what stranding
        // looks like from the server's side.
        let _ = rx.try_recv();
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("Enter should arrive")
            .expect("channel open");
        let watch = app
            .state
            .terminals
            .get(&terminal_id)
            .unwrap()
            .prompt_submit_abandoned
            .as_ref()
            .expect("submit watch")
            .clone();
        assert!(
            watch.submitted.load(Ordering::SeqCst),
            "the key was written"
        );

        let after = app.agent_info(0, pane_id).expect("agent info");
        assert_eq!(
            after.composer.attempt_id.as_deref(),
            Some(attempt.as_str()),
            "a stranded prompt must keep owning the draft it wrote"
        );
        assert_eq!(
            after.composer.evidence.provenance,
            crate::api::schema::ComposerProvenance::AgentPrompt,
            "attribution must not be erased when no turn started"
        );
    }

    #[tokio::test]
    async fn agent_prompt_input_preflight_and_write_failure_are_non_receipt_verdicts() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::Claude), AgentState::Idle);
        terminal.set_input_prompt_kind(Some(crate::detect::InputPromptKind::Select));
        let (runtime, mut rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        app.state.insert_test_runtime(pane_id, runtime);

        let blocked = app.handle_agent_prompt(
            "req-input".into(),
            AgentPromptParams {
                target: "reviewer".into(),
                text: "do not write this".into(),
                wait: None,
            },
        );
        let blocked: crate::api::schema::ErrorResponse = serde_json::from_str(&blocked).unwrap();
        assert_eq!(blocked.error.code, "agent_input_pending");
        assert!(blocked.error.message.contains("select"));
        assert!(rx.try_recv().is_err(), "preflight must write zero bytes");

        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .set_input_prompt_kind(None);
        drop(rx);
        let secret_prompt = "private prompt contents";
        let failed_json = app.handle_agent_prompt(
            "req-write".into(),
            AgentPromptParams {
                target: "reviewer".into(),
                text: secret_prompt.into(),
                wait: None,
            },
        );
        let failed: crate::api::schema::ErrorResponse = serde_json::from_str(&failed_json).unwrap();
        assert_eq!(failed.error.code, "agent_prompt_not_received");
        assert!(!failed.error.message.contains(secret_prompt));
        assert!(!failed_json.contains(secret_prompt));
    }

    #[test]
    fn agent_get_and_list_expose_the_input_tuple() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::Claude), AgentState::Idle);
        terminal.set_input_prompt_kind(Some(crate::detect::InputPromptKind::Confirm));

        let get: SuccessResponse = serde_json::from_str(&app.handle_agent_get(
            "get".into(),
            AgentTarget {
                target: "reviewer".into(),
            },
        ))
        .unwrap();
        let ResponseResult::AgentInfo { agent } = get.result else {
            panic!("expected agent info");
        };
        assert!(agent.input_pending);
        assert_eq!(
            agent.input_prompt_kind,
            Some(crate::detect::InputPromptKind::Confirm)
        );

        let list: SuccessResponse =
            serde_json::from_str(&app.handle_agent_list("list".into())).unwrap();
        let ResponseResult::AgentList { agents } = list.result else {
            panic!("expected agent list");
        };
        assert_eq!(agents.len(), 1);
        assert!(agents[0].input_pending);
        assert_eq!(
            agents[0].input_prompt_kind,
            Some(crate::detect::InputPromptKind::Confirm)
        );
    }

    #[tokio::test]
    async fn agent_send_keys_validates_every_key_before_writing() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::Pi), AgentState::Idle);
        let (runtime, mut rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        app.state.insert_test_runtime(pane_id, runtime);

        let rejected = app.handle_agent_send_keys(
            "req-invalid".into(),
            AgentSendKeysParams {
                target: "reviewer".into(),
                keys: vec!["enter".into(), "not-a-key".into()],
            },
        );
        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&rejected).unwrap();
        assert_eq!(error.error.code, "invalid_key");
        assert!(rx.try_recv().is_err());

        let sent = app.handle_agent_send_keys(
            "req-valid".into(),
            AgentSendKeysParams {
                target: "reviewer".into(),
                keys: vec!["up".into(), "enter".into()],
            },
        );
        let success: SuccessResponse = serde_json::from_str(&sent).unwrap();
        assert!(matches!(success.result, ResponseResult::Ok {}));
        assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"\x1b[A\r"));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn agent_prompt_rejects_managed_agent_while_startup_is_pending() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        let now = std::time::Instant::now();
        terminal.begin_managed_agent(
            "reviewer".into(),
            Agent::OpenCode,
            now,
            std::time::Duration::from_secs(3),
            std::time::Duration::from_secs(10),
        );
        terminal.set_detected_state(Some(Agent::OpenCode), AgentState::Idle);
        let (runtime, mut rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        app.state.insert_test_runtime(pane_id, runtime);

        let response = app.handle_agent_prompt(
            "req-pending".into(),
            AgentPromptParams {
                target: "reviewer".into(),
                text: "A != B".into(),
                wait: None,
            },
        );
        let error: crate::api::schema::ErrorResponse = serde_json::from_str(&response).unwrap();
        assert_eq!(error.error.code, "agent_not_ready");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn agent_focus_marks_already_focused_done_agent_seen() {
        let mut app = app_with_agent();
        app.state.outer_terminal_focus = Some(false);

        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .set_detected_state(Some(Agent::Pi), AgentState::Idle);
        app.state.workspaces[0].tabs[0]
            .panes
            .get_mut(&pane_id)
            .unwrap()
            .seen = false;
        app.state.workspaces[0].tabs[0].layout.focus_pane(pane_id);

        let response = app.handle_agent_focus(
            "req".into(),
            AgentTarget {
                target: app.public_pane_id(0, pane_id).unwrap(),
            },
        );

        let success: SuccessResponse = serde_json::from_str(&response).unwrap();
        let ResponseResult::AgentInfo { agent } = success.result else {
            panic!("expected agent info response");
        };
        assert_eq!(agent.agent_status, AgentStatus::Idle);
    }

    #[test]
    fn agent_get_exposes_live_turn_hints_before_first_completion() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_agent_name("reviewer".into());
        terminal.set_detected_state(Some(Agent::Pi), AgentState::Idle);

        let response = app.handle_agent_get(
            "req".into(),
            AgentTarget {
                target: "reviewer".into(),
            },
        );

        let success: SuccessResponse = serde_json::from_str(&response).unwrap();
        let ResponseResult::AgentInfo { agent } = success.result else {
            panic!("expected agent info response");
        };
        assert_eq!(agent.turn, Some(0));
        assert!(agent.turn_epoch.is_some());
        assert!(agent.last_completed_turn.is_none());
    }

    #[test]
    fn agent_rename_does_not_replace_the_pane_label() {
        let mut app = app_with_agent();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_manual_label("shell-pane".into());
        terminal.set_detected_state(Some(Agent::Pi), AgentState::Idle);
        let target = app.public_pane_id(0, pane_id).unwrap();

        for name in [Some("reviewer".to_string()), None] {
            let response = app.handle_agent_rename(
                "req".into(),
                AgentRenameParams {
                    target: target.clone(),
                    name,
                },
            );
            let success: SuccessResponse = serde_json::from_str(&response).unwrap();
            assert!(matches!(success.result, ResponseResult::AgentInfo { .. }));
            assert_eq!(
                app.state.terminals[&terminal_id].manual_label.as_deref(),
                Some("shell-pane")
            );
        }
    }
}
