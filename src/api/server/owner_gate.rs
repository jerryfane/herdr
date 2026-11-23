//! The owner's browsers through the HerdrUp guest relay (owner grants,
//! `crate::guest::owner`). An explicit allowlist per scope:
//!
//! - `chat`: read and talk to local agents (agent panes only), menu keys while
//!   an agent waits on a menu, the owner's Gram, and agent events;
//! - `terminal`: chat, plus any local pane: navigate, watch, and type.
//!
//! Everything else answers `owner_forbidden`, and a method added later is
//! refused until it is listed here. Requests never route to federation
//! peers: targets naming one (`alias/…`) are refused, list and event calls
//! are forced `local_only`, and the connection carries no peers. The grant is
//! read again before every request and while streams run, so a removal, a
//! replacement or the grant's expiry ends the connection.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::remote_gate::{
    self, audit_due, clamp_resize, menu_batch, probe_target, send_menu_keys, Probe, WATCH_INTERVAL,
};
use super::{
    answer_agent, answer_agent_form, dismiss_agent_ask, error_response_json, finish_wait_response,
    handle_request, pane_input_stream, pane_output_stream, prompt_agent,
    write_text_line_allow_disconnect, ApiRequestSender, ConnectionPrincipal, EventHub,
};
use crate::api::schema::{
    GuestAuditEvent, Method, OwnerScope, ReadSource, Request, ResponseResult, SuccessResponse,
};
use crate::api::transport::ApiStream;
use crate::guest::owner::OwnerPrincipal;
use crate::guest::store::now_ms;

const PROMPT_MAX_BYTES: usize = 32 * 1024;
const READ_MAX_LINES: u32 = 1000;
/// A connection with no request for this long ends, as for guests.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Methods either scope may call.
const CHAT: &[&str] = &[
    "ping",
    "agent.list",
    "agent.get",
    "agent.avatar.get",
    "agent.groups.get",
    "agent.read",
    "agent.transcript",
    "agent.prompt",
    "agent.answer",
    "agent.answer_form",
    "agent.dismiss_ask",
    "agent.topics.list",
    "agent.topics.new",
    "agent.topics.send",
    "agent.topics.close",
    "agent.topics.reopen",
    "agent.topics.rename",
    "pane.stream",
    "pane.history",
    "pane.set_pty_size",
    "pane.send_keys",
    "gram.list",
    "gram.mark_read",
    "gram.get_file",
    "gram.get_file_chunk",
    "gram.post",
    "gram.upload_chunk",
    "gram.upload.discard",
    "events.subscribe",
];

/// Methods only the terminal scope may call. A terminal is a shell on this
/// machine, which can already do all of these; the methods only make them
/// convenient for the web owner page (desktop parity): administer agents and
/// terminals, start them, manage guests and Claude accounts, and update
/// herdr. Never `owner_access.*`: a browser must not mint, renew or widen
/// its own grant.
const TERMINAL: &[&str] = &[
    "pane.list",
    "pane.get",
    "workspace.list",
    "tab.list",
    "pane.read",
    "pane.send_text",
    "pane.send_input",
    "pane.input.stream",
    "agent.send_keys",
    // Administer agents.
    "agent.groups.set",
    "agent.rename",
    "agent.avatar.set",
    "agent.archive",
    "agent.restart",
    // Create and close agents and terminals.
    "agent.kinds",
    "agent.start",
    "fs.list_dir",
    "pane.split",
    "pane.rename",
    "pane.close",
    // Claude accounts.
    "accounts.list",
    "accounts.create",
    "accounts.remove",
    // Guests, on this machine only.
    "guest.invite.create",
    "guest.list",
    "guest.update",
    "guest.revoke",
    "guest.remove_device",
    "guest.audit",
    // herdr updates.
    "server.update_check",
    "server.update_apply",
    "server.update_status",
];

/// Event kinds a chat-scope `events.subscribe` may name.
const CHAT_EVENTS: &[&str] = &[
    "pane.agent_detected",
    "pane.agent_status_changed",
    "pane.turn_completed",
    "pane.closed",
    "pane.exited",
    "agent.topics.changed",
];

/// Capabilities an owner browser's `ping` reports: only what this gate
/// serves. The terminal ones are reported for the terminal scope only.
const CHAT_CAPABILITIES: &[&str] = &[
    "events_v2",
    "agent_avatar",
    "agent_groups",
    "pane_history",
    "agent_answer",
    "agent_transcript",
    "ask_form",
    "ask_dismiss",
    "agent_topics",
    "agent_transcript_topic",
    "transcript_max_bytes",
    "pane_stream_resync",
    "gram_thumbnails",
];
const TERMINAL_CAPABILITIES: &[&str] =
    &["pane_input_stream", "rename_preconditions", "server_update"];

/// Whether `scope` may call the method named `name`.
pub(super) fn allowed(name: &str, scope: OwnerScope) -> bool {
    CHAT.contains(&name) || (scope == OwnerScope::Terminal && TERMINAL.contains(&name))
}

/// Run one owner browser connection. The stream closes when this returns.
pub(crate) fn serve_owner_stream(
    principal: OwnerPrincipal,
    stream: std::os::unix::net::UnixStream,
) {
    let Some((api_tx, event_hub, running)) = remote_gate::context() else {
        tracing::warn!("owner browser connection before the API server started; closing");
        return;
    };
    if let Err(err) = serve_owner_with(&api_tx, &event_hub, &running, principal, stream) {
        tracing::debug!(err = %err, "owner browser connection ended with an error");
    }
}

fn serve_owner_with(
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
    principal: OwnerPrincipal,
    stream: std::os::unix::net::UnixStream,
) -> std::io::Result<()> {
    let stream = ApiStream::Local(crate::ipc::LocalStream::from(
        interprocess::os::unix::uds_local_socket::Stream::from(stream),
    ));
    // No federation peers: nothing an owner browser asks routes outbound.
    super::handle_principal_connection(
        stream,
        api_tx,
        event_hub,
        running,
        None,
        None,
        ConnectionPrincipal::OwnerBrowser(principal),
        &HashMap::new(),
        None,
    )
}

/// Serves an owner browser's requests on one connection until it ends: a
/// request takes the connection over (a stream), the grant ends
/// (`owner_not_granted`, `owner_expired`), a line is not a request, the
/// browser leaves, or [`SESSION_IDLE_TIMEOUT`] passes without a request. An
/// `owner_forbidden` reply leaves the session open.
pub(super) fn serve_session(
    mut stream: ApiStream,
    mut request: Request,
    owner: &OwnerPrincipal,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    loop {
        if serve_request(&mut stream, request, owner, api_tx, event_hub, running)? {
            return Ok(());
        }
        let Some(next) =
            remote_gate::next_request(&mut stream, owner.live(), running, SESSION_IDLE_TIMEOUT)?
        else {
            return Ok(());
        };
        request = next;
    }
}

fn owner_error(id: &str, code: &str) -> String {
    let message = match code {
        "owner_not_granted" => "this browser's access to this machine was removed",
        "owner_expired" => "this browser's access to this machine expired",
        "owner_scope_changed" => "this browser's access changed; open the stream again",
        "owner_paused" => "the agent this stream watches is no longer running",
        _ => "owner browsers may not call this method",
    };
    error_response_json(id.to_string(), code, message.to_string())
}

/// Some id or target names a federation peer's object (`alias/…`).
fn names_remote(method: &Method) -> bool {
    // The request's own ids and each subscription's, not free-form content
    // such as a form's answers.
    fn remote(fields: &serde_json::Value) -> bool {
        fields.as_object().is_some_and(|fields| {
            fields.iter().any(|(key, value)| {
                matches!(
                    key.as_str(),
                    "target" | "pane_id" | "target_pane_id" | "workspace_id" | "tab_id" | "to"
                ) && value.as_str().is_some_and(|text| text.contains('/'))
            })
        })
    }
    let Ok(value) = serde_json::to_value(method) else {
        return true;
    };
    let params = &value["params"];
    remote(params)
        || params["subscriptions"]
            .as_array()
            .is_some_and(|subscriptions| subscriptions.iter().any(remote))
}

/// The agent or pane a chat-scope request acts on. `Err` when a chat-scope
/// method names none (a pane left out means the focused pane, which may be a
/// shell).
fn chat_target(method: &Method) -> Result<Option<&str>, ()> {
    Ok(Some(match method {
        Method::AgentGet(params) | Method::AgentTopicsList(params) => &params.target,
        Method::AgentAvatarGet(params) => &params.target,
        Method::AgentRead(params) => &params.target,
        Method::AgentTranscript(params) => &params.target,
        Method::AgentPrompt(params) => &params.target,
        Method::AgentAnswer(params) => &params.target,
        Method::AgentAnswerForm(params) => &params.target,
        Method::AgentDismissAsk(params) => &params.target,
        Method::AgentTopicsNew(params) => &params.target,
        Method::AgentTopicsSend(params) => &params.target,
        Method::AgentTopicsClose(params) | Method::AgentTopicsReopen(params) => &params.target,
        Method::AgentTopicsRename(params) => &params.target,
        Method::PaneStream(params) => &params.pane_id,
        Method::PaneHistory(params) => &params.pane_id,
        Method::PaneSendKeys(params) => &params.pane_id,
        Method::PaneSetPtySize(params) => params.pane_id.as_deref().ok_or(())?,
        _ => return Ok(None),
    }))
}

/// A chat-scope target must be a local agent pane. Returns its probe.
fn chat_agent(api_tx: &ApiRequestSender, target: &str) -> Option<Probe> {
    probe_target(api_tx, None, Some(target))
        .ok()
        .filter(|probe| {
            probe
                .agent
                .as_ref()
                .is_some_and(|agent| agent.machine_id.is_none())
        })
}

/// Answers one request. `Ok(true)` when the session must not read another
/// request after it: it took the connection over (a stream) or the grant
/// ended.
fn serve_request(
    stream: &mut ApiStream,
    mut request: Request,
    owner: &OwnerPrincipal,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<bool> {
    let id = request.id.clone();
    let method = crate::api::api_method_name(&request.method);
    let scope = match owner.current(now_ms()) {
        Ok(scope) => scope,
        Err(code) => {
            write_text_line_allow_disconnect(stream, &owner_error(&id, code))?;
            return Ok(true);
        }
    };
    // Input from the web is not the owner's app.
    request.method.clear_input_source();
    let forbidden = |stream: &mut ApiStream| -> std::io::Result<bool> {
        let key = format!("{}\n{method}", owner.grant_id);
        if audit_due(GuestAuditEvent::OwnerDenied, &key) {
            owner.audit(GuestAuditEvent::OwnerDenied, Some(method), None);
        }
        write_text_line_allow_disconnect(stream, &owner_error(&id, "owner_forbidden"))?;
        Ok(false)
    };
    if !allowed(method, scope) || names_remote(&request.method) {
        return forbidden(stream);
    }
    let chat_probe = match (scope, chat_target(&request.method)) {
        (OwnerScope::Terminal, _) | (OwnerScope::Chat, Ok(None)) => None,
        (OwnerScope::Chat, Err(())) => return forbidden(stream),
        (OwnerScope::Chat, Ok(Some(target))) => match chat_agent(api_tx, target) {
            // Pane methods touch the terminal itself: once the agent's
            // process is gone the pane is a shell, so it must be running.
            Some(probe) if probe.running || !method.starts_with("pane.") => Some(probe),
            _ => return forbidden(stream),
        },
    };
    let guard = StreamGuard {
        owner,
        api_tx,
        id: id.clone(),
        scope,
        agent_terminal: None,
        last_check: Mutex::new(Instant::now()),
    };
    match request.method {
        Method::Ping(params) => {
            let response = handle_request(
                Request {
                    id: id.clone(),
                    method: Method::Ping(params),
                },
                api_tx,
                super::default_capabilities(),
                None,
                None,
                None,
            );
            write_text_line_allow_disconnect(stream, &project_pong(&id, &response, scope))?;
            Ok(false)
        }
        Method::AgentList(mut params) => {
            params.local_only = true;
            pass(stream, id, Method::AgentList(params), api_tx)
        }
        Method::WorkspaceList(mut params) => {
            params.local_only = true;
            pass(stream, id, Method::WorkspaceList(params), api_tx)
        }
        Method::AgentRead(mut params) => {
            if !matches!(params.source, ReadSource::Recent | ReadSource::Visible) {
                return forbidden(stream);
            }
            params.lines = Some(params.lines.unwrap_or(READ_MAX_LINES).min(READ_MAX_LINES));
            pass(stream, id, Method::AgentRead(params), api_tx)
        }
        Method::AgentPrompt(params) => {
            if params.text.len() > PROMPT_MAX_BYTES {
                write_text_line_allow_disconnect(
                    stream,
                    &error_response_json(
                        id,
                        "invalid_params",
                        "owner browser prompts are limited to 32 KiB".into(),
                    ),
                )?;
                return Ok(false);
            }
            let response = prompt_agent(id.clone(), params, stream, api_tx, event_hub, running)?;
            finish_wait_response(stream, response, &id, method, false)?;
            Ok(false)
        }
        Method::AgentAnswer(params) => {
            let response = answer_agent(id.clone(), params, api_tx);
            finish_wait_response(stream, Some(response), &id, method, false)?;
            Ok(false)
        }
        Method::AgentAnswerForm(params) => {
            let response = answer_agent_form(id.clone(), params, api_tx);
            finish_wait_response(stream, Some(response), &id, method, false)?;
            Ok(false)
        }
        Method::AgentDismissAsk(params) => {
            let response = dismiss_agent_ask(id.clone(), params, api_tx);
            finish_wait_response(stream, Some(response), &id, method, false)?;
            Ok(false)
        }
        Method::PaneSendKeys(params) => match scope {
            // Chat never types into a terminal: menu keys only, while the
            // agent waits on a menu, and none after a committing key until
            // the agent's state changes (the menu may already be gone and
            // the keys would reach the pane's shell).
            OwnerScope::Chat => {
                let Some(keys) = menu_batch(&params.keys) else {
                    return forbidden(stream);
                };
                let Some(agent) = chat_probe.and_then(|probe| probe.agent) else {
                    return forbidden(stream);
                };
                let Some(response) = send_menu_keys(api_tx, &owner.dir, &agent, keys, &id, |_| {})
                else {
                    return forbidden(stream);
                };
                write_text_line_allow_disconnect(stream, &response)?;
                Ok(false)
            }
            OwnerScope::Terminal => pass(stream, id, Method::PaneSendKeys(params), api_tx),
        },
        Method::PaneSetPtySize(mut params) => {
            let (cols, rows, ttl) = clamp_resize(params.cols, params.rows, params.ttl_ms);
            params.cols = cols;
            params.rows = rows;
            params.ttl_ms = Some(ttl);
            params.viewer_id = Some(owner.viewer_id());
            // Only while one of this browser's streams watches the pane, so
            // the width lease ends with its last stream.
            params.require_stream = true;
            pass(stream, id, Method::PaneSetPtySize(params), api_tx)
        }
        Method::PaneStream(mut params) => {
            params.viewer_id = Some(owner.viewer_id());
            // A chat stream watches an agent: it ends when the terminal no
            // longer hosts one (on unix the pane is then the agent's shell).
            let guard = StreamGuard {
                agent_terminal: chat_probe
                    .and_then(|probe| probe.agent)
                    .map(|agent| agent.terminal_id),
                ..guard
            };
            let mut stream_watch = |closed: bool| guard.check(closed);
            pane_output_stream::serve_watched(
                stream,
                id,
                params,
                api_tx,
                running,
                Some(&mut stream_watch),
            )?;
            Ok(true)
        }
        Method::EventsSubscribe(mut params) => {
            params.local_only = true;
            if scope == OwnerScope::Chat
                && !params.subscriptions.iter().all(|subscription| {
                    serde_json::to_value(subscription).is_ok_and(|value| {
                        value["type"]
                            .as_str()
                            .is_some_and(|kind| CHAT_EVENTS.contains(&kind))
                    })
                })
            {
                return forbidden(stream);
            }
            super::stream_subscriptions_watched(
                stream,
                id,
                params,
                api_tx,
                event_hub,
                running,
                super::SUBSCRIPTION_HEARTBEAT_INTERVAL,
                Some(&mut || guard.check(false)),
            )?;
            Ok(true)
        }
        Method::PaneInputStream(params) => {
            // Checked in full before each frame is typed, and throttled on
            // the read's idle wakes.
            pane_input_stream::serve_guarded(stream, id, params, api_tx, running, &mut |now| {
                guard.check(now)
            })?;
            Ok(true)
        }
        // The owner's Gram. Remote Gram goes to the coordinator's restricted
        // reverse socket, as for the owner's own clients.
        method @ (Method::GramList(_)
        | Method::GramMarkRead(_)
        | Method::GramGetFile(_)
        | Method::GramGetFileChunk(_)
        | Method::GramPost(_)
        | Method::GramUploadChunk(_)
        | Method::GramUploadDiscard(_)) => {
            let request = Request {
                id: id.clone(),
                method,
            };
            if let Some(response) = crate::api::reverse::forward_local(&request) {
                write_text_line_allow_disconnect(stream, &response)?;
                return Ok(false);
            }
            pass(stream, id, request.method, api_tx)
        }
        // Guests of this machine. `machine` would route the call to a saved
        // SSH machine; an owner browser never routes off this one.
        method @ (Method::GuestInviteCreate(_)
        | Method::GuestList(_)
        | Method::GuestUpdate(_)
        | Method::GuestRevoke(_)
        | Method::GuestRemoveDevice(_)
        | Method::GuestAudit(_)) => {
            if routes_to_machine(&method) {
                return forbidden(stream);
            }
            let response = super::guest_owner::handle_local(&Request { id, method }, api_tx);
            write_text_line_allow_disconnect(stream, &response)?;
            Ok(false)
        }
        method => pass(stream, id, method, api_tx),
    }
}

/// A `guest.*` call that names a saved SSH machine to run on.
fn routes_to_machine(method: &Method) -> bool {
    match method {
        Method::GuestInviteCreate(params) => params.machine.is_some(),
        Method::GuestList(params) => params.machine.is_some(),
        Method::GuestUpdate(params) => params.machine.is_some(),
        Method::GuestRevoke(params) => params.machine.is_some(),
        Method::GuestRemoveDevice(params) => params.machine.is_some(),
        Method::GuestAudit(params) => params.machine.is_some(),
        _ => false,
    }
}

/// Ends a stream an owner browser opened when its grant no longer allows it:
/// at once after a removal or replacement (the live flag), and within
/// [`WATCH_INTERVAL`] after the store changes (removed, expired, or renewed
/// with another scope), or, for a chat stream watching an agent, when the
/// terminal no longer hosts a local agent.
struct StreamGuard<'a> {
    owner: &'a OwnerPrincipal,
    api_tx: &'a ApiRequestSender,
    id: String,
    /// The scope the stream was opened under.
    scope: OwnerScope,
    /// A chat `pane.stream`'s agent terminal.
    agent_terminal: Option<String>,
    last_check: Mutex<Instant>,
}

impl StreamGuard<'_> {
    /// The line that ends the stream, or `None` while it may go on. `now`:
    /// check everything at once (before a frame is typed, or the watched
    /// runtime ended) instead of at most every [`WATCH_INTERVAL`].
    fn check(&self, now: bool) -> Option<String> {
        if self.owner.live().revoked() {
            return Some(owner_error(&self.id, "owner_not_granted"));
        }
        {
            let mut last_check = self
                .last_check
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !now && last_check.elapsed() < WATCH_INTERVAL {
                return None;
            }
            *last_check = Instant::now();
        }
        match self.owner.current(now_ms()) {
            Err(code) => return Some(owner_error(&self.id, code)),
            Ok(scope) if scope != self.scope => {
                return Some(owner_error(&self.id, "owner_scope_changed"));
            }
            Ok(_) => {}
        }
        let terminal = self.agent_terminal.as_deref()?;
        let agent_running = probe_target(self.api_tx, Some(terminal), None).is_ok_and(|probe| {
            probe.running && probe.agent.is_some_and(|agent| agent.machine_id.is_none())
        });
        (!agent_running).then(|| owner_error(&self.id, "owner_paused"))
    }
}

/// Answers through the app, as for the owner's own clients.
fn pass(
    stream: &mut ApiStream,
    id: String,
    method: Method,
    api_tx: &ApiRequestSender,
) -> std::io::Result<bool> {
    let response = handle_request(Request { id, method }, api_tx, None, None, None, None);
    write_text_line_allow_disconnect(stream, &response)?;
    Ok(false)
}

/// The owner's pong with only the capabilities this gate serves, plus
/// `owner` (the owner access protocol) and the grant's `owner_scope`.
fn project_pong(id: &str, response: &str, scope: OwnerScope) -> String {
    let Ok(SuccessResponse {
        result:
            ResponseResult::Pong {
                version,
                protocol,
                capabilities,
            },
        ..
    }) = serde_json::from_str::<SuccessResponse>(response)
    else {
        return response.to_string();
    };
    let all = serde_json::to_value(capabilities).unwrap_or_default();
    let mut served = serde_json::Map::new();
    let names = CHAT_CAPABILITIES.iter().chain(match scope {
        OwnerScope::Chat => [].iter(),
        OwnerScope::Terminal => TERMINAL_CAPABILITIES.iter(),
    });
    for name in names {
        if let Some(value) = all.get(*name) {
            served.insert((*name).to_owned(), value.clone());
        }
    }
    served.insert(
        "owner".into(),
        serde_json::json!(crate::guest::owner::PROTOCOL),
    );
    served.insert("owner_scope".into(), serde_json::json!(scope));
    serde_json::json!({
        "id": id,
        "result": {
            "type": "pong",
            "version": version,
            "protocol": protocol,
            "capabilities": served,
        },
    })
    .to_string()
}

#[cfg(test)]
#[path = "owner_gate/tests.rs"]
mod tests;
