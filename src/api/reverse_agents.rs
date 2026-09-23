//! Restricted coordinator gateway carried over an owner-enabled SSH streamlocal
//! reverse forward. This socket NEVER forwards the coordinator's local API.
//! The SSH host-key trust and saved machine pin authenticate the machine; the
//! caller pane is a trusted-machine assertion, not same-user process isolation.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::client::ApiClient;
use crate::api::federation_manager::PeerRoute;
use crate::api::schema::{
    AgentInfo, AgentListParams, AgentPromptParams, Method, Request, ResponseResult, SuccessResponse,
};
use crate::config::FederationAgentGrant;

const REQUEST_LIMIT: usize = 64 * 1024;
const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(20);
const WIRE_VERSION: u32 = 1;

/// Stable on the remote machine, independent of mutable profile labels and
/// remote sessions. The owner must explicitly pin the coordinator in config.
pub(crate) fn reverse_socket_path(
    coordinator_machine_id: &str,
    remote_machine_id: &str,
) -> PathBuf {
    let digest = Sha256::digest(
        format!("herdr-reverse-v1\0{coordinator_machine_id}\0{remote_machine_id}").as_bytes(),
    );
    let name = format!("herdr-rev-{:x}", digest);
    PathBuf::from("/tmp").join(format!("{}.sock", &name[..27]))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReverseRequest {
    pub version: u32,
    pub caller_terminal_id: String,
    pub method: ReverseMethod,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ReverseMethod {
    AgentList,
    AgentPrompt { target: String, text: String },
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ReverseResponse {
    pub version: u32,
    pub coordinator_machine_id: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

fn error(message: impl Into<String>) -> ReverseResponse {
    ReverseResponse {
        version: WIRE_VERSION,
        coordinator_machine_id: crate::persist::machine::get_or_create(),
        result: None,
        error: Some(message.into()),
    }
}

#[cfg(unix)]
pub(crate) fn request_remote(
    coordinator_machine_id: &str,
    caller_terminal_id: String,
    method: ReverseMethod,
) -> io::Result<serde_json::Value> {
    use std::os::unix::net::UnixStream;
    let path = reverse_socket_path(
        coordinator_machine_id,
        &crate::persist::machine::get_or_create(),
    );
    let mut stream = UnixStream::connect(&path).map_err(|cause| io::Error::new(
        cause.kind(), format!("reverse SSH socket {} is unavailable (coordinator offline, reverse forwarding disabled, or SSH streamlocal forwarding unsupported): {cause}", path.display()),
    ))?;
    stream.set_read_timeout(Some(DEADLINE))?;
    stream.set_write_timeout(Some(DEADLINE))?;
    let line = serde_json::to_vec(&ReverseRequest {
        version: WIRE_VERSION,
        caller_terminal_id,
        method,
    })?;
    if line.len() > REQUEST_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reverse request exceeds 64 KiB",
        ));
    }
    stream.write_all(&line)?;
    stream.write_all(b"\n")?;
    let reply = read_line_bounded(&mut stream, RESPONSE_LIMIT)?;
    let reply: ReverseResponse = serde_json::from_slice(&reply)?;
    if reply.version != WIRE_VERSION || reply.coordinator_machine_id != coordinator_machine_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reverse coordinator identity/protocol mismatch",
        ));
    }
    match (reply.result, reply.error) {
        (Some(result), None) => Ok(result),
        (None, Some(message)) => Err(io::Error::other(message)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid reverse response",
        )),
    }
}

#[cfg(not(unix))]
pub(crate) fn request_remote(
    _: &str,
    _: String,
    _: ReverseMethod,
) -> io::Result<serde_json::Value> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SSH streamlocal reverse forwarding requires Unix",
    ))
}

fn read_line_bounded(stream: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "reverse connection closed before response",
            ));
        }
        let end = chunk[..count]
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(count);
        if data.len() + end > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reverse frame exceeds limit",
            ));
        }
        data.extend_from_slice(&chunk[..end]);
        if end != count {
            return Ok(data);
        }
    }
}

#[cfg(unix)]
struct PrivateGatewayDir(PathBuf);

#[cfg(unix)]
impl Drop for PrivateGatewayDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("gateway.sock"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[cfg(unix)]
pub(crate) struct ReverseGateway {
    stop: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    forward: Option<JoinHandle<()>>,
    _private_dir: PrivateGatewayDir,
}

#[cfg(unix)]
impl ReverseGateway {
    pub(crate) fn start(
        profile_id: &str,
        target: &str,
        expected_machine_id: &str,
        route: PeerRoute,
        grants: Vec<FederationAgentGrant>,
    ) -> io::Result<Self> {
        use std::os::unix::net::UnixListener;
        if grants.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no reverse grants",
            ));
        }
        let coord_id = crate::persist::machine::get_or_create();
        let remote = reverse_socket_path(&coord_id, expected_machine_id);
        use std::os::unix::fs::DirBuilderExt;
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
        let dir = std::env::temp_dir().join(format!(
            "herdr-rg-{}-{:016x}",
            std::process::id(),
            u64::from_be_bytes(nonce)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let private_dir = PrivateGatewayDir(dir);
        let path = private_dir.0.join("gateway.sock");
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let listener_stop = stop.clone();
        let expected = expected_machine_id.to_owned();
        let alias = profile_id.to_owned();
        let listener_join = thread::Builder::new()
            .name("reverse-gateway".into())
            .spawn(move || {
                while !listener_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(DEADLINE));
                            let _ = stream.set_write_timeout(Some(DEADLINE));
                            let reply = match read_line_bounded(&mut stream, REQUEST_LIMIT)
                                .and_then(|bytes| {
                                    serde_json::from_slice::<ReverseRequest>(&bytes)
                                        .map_err(io::Error::other)
                                }) {
                                Ok(request) => handle_request(
                                    request,
                                    &route,
                                    &expected,
                                    &alias,
                                    &grants,
                                    &listener_stop,
                                ),
                                Err(cause) => {
                                    error(format!("invalid bounded reverse request: {cause}"))
                                }
                            };
                            if !listener_stop.load(Ordering::Acquire) {
                                if let Ok(mut bytes) = serde_json::to_vec(&reply) {
                                    if bytes.len() <= RESPONSE_LIMIT {
                                        bytes.push(b'\n');
                                        let _ = stream.write_all(&bytes);
                                    }
                                }
                            }
                        }
                        Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(50))
                        }
                        Err(cause) if cause.kind() == io::ErrorKind::Interrupted => {}
                        Err(cause) => {
                            tracing::warn!(%cause, "restricted reverse gateway accept failed");
                            thread::sleep(Duration::from_secs(1));
                        }
                    }
                }
            })?;
        let forward_stop = stop.clone();
        let target = target.to_owned();
        let profile = profile_id.to_owned();
        let gateway_path = path.clone();
        let forward_join = match thread::Builder::new()
            .name("reverse-ssh-forward".into())
            .spawn(move || {
                while !forward_stop.load(Ordering::Acquire) {
                    match crate::remote::spawn_saved_reverse_forward(
                        &profile, &target, &remote, &gateway_path,
                    ) {
                        Ok(mut child) => {
                            while !forward_stop.load(Ordering::Acquire) {
                                match child.try_wait() {
                                    Ok(None) => thread::sleep(Duration::from_millis(100)),
                                    _ => break,
                                }
                            }
                            let _ = child.kill();
                            let _ = child.wait();
                        }
                        Err(cause) => tracing::warn!(%cause, profile_id = %profile, "reverse SSH forward unavailable"),
                    }
                    for _ in 0..50 {
                        if forward_stop.load(Ordering::Acquire) { break; }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }) {
            Ok(join) => join,
            Err(error) => {
                stop.store(true, Ordering::Release);
                let _ = listener_join.join();
                return Err(error);
            }
        };
        Ok(Self {
            stop,
            listener: Some(listener_join),
            forward: Some(forward_join),
            _private_dir: private_dir,
        })
    }
}

#[cfg(unix)]
impl Drop for ReverseGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.forward.take() {
            let _ = join.join();
        }
        if let Some(join) = self.listener.take() {
            let _ = join.join();
        }
    }
}

fn handle_request(
    request: ReverseRequest,
    route: &PeerRoute,
    expected: &str,
    alias: &str,
    grants: &[FederationAgentGrant],
    stop: &Arc<AtomicBool>,
) -> ReverseResponse {
    if request.version != WIRE_VERSION || request.caller_terminal_id.is_empty() {
        return error("reverse protocol mismatch or missing caller identity");
    }
    let stamp = route.stamp();
    let remote_client = ApiClient::for_target(route.target().clone());
    let remote_list = match agent_list(&remote_client, true, stop) {
        Ok(list) => list,
        Err(cause) => return error(format!("source machine unreachable: {cause}")),
    };
    let ResponseResult::AgentList {
        agents: source_agents,
        origin_machine_id: Some(origin),
        ..
    } = remote_list.result
    else {
        return error("source machine did not report a pinned local-only agent roster");
    };
    if origin != expected || !route.is_current(&stamp) {
        return error("source machine identity changed or route retired");
    }
    let Some(agent) = source_agents.iter().find(|agent| {
        agent.terminal_id == request.caller_terminal_id && agent.machine_id.is_none()
    }) else {
        return error("caller agent not live on selected source machine");
    };
    let Some(grant) = grants.iter().find(|grant| grant_matches(grant, agent)) else {
        return error(
            "caller agent has no live reverse grant (same-user pane identity is spoofable)",
        );
    };
    let coordinator = ApiClient::local();
    let reply = match request.method {
        ReverseMethod::AgentList if grant.observe => agent_list(&coordinator, false, stop)
            .and_then(|mut list| {
                if let ResponseResult::AgentList { agents, .. } = &mut list.result {
                    agents.retain(|agent| {
                        agent.machine_id.as_deref().is_none_or(|peer| {
                            peer != alias
                                && agent.origin_machine_id.as_deref() != Some(expected)
                                && grant.observe_peers.iter().any(|allowed| allowed == peer)
                        })
                    });
                }
                serde_json::to_value(list).map_err(io::Error::other)
            }),
        ReverseMethod::AgentPrompt { target, text } if grant.interact => {
            if text.len() > 32 * 1024 {
                return error("prompt exceeds 32 KiB");
            }
            let peer = target.split_once('/').map(|(peer, _)| peer);
            if peer.is_some_and(|peer| {
                peer == alias || !grant.interact_peers.iter().any(|allowed| allowed == peer)
            }) {
                return error("target peer is not granted for interaction");
            }
            let list = match agent_list(&coordinator, false, stop) {
                Ok(list) => list,
                Err(cause) => return error(format!("coordinator unreachable: {cause}")),
            };
            let ResponseResult::AgentList { agents, .. } = list.result else {
                return error("coordinator roster unavailable");
            };
            let target_agent = agents.iter().find(|agent| {
                agent.terminal_id == target
                    && agent.machine_id.as_deref() == peer
                    && (peer.is_none() || agent.origin_machine_id.as_deref() != Some(expected))
            });
            let Some(target_agent) = target_agent else {
                return error("target stale or absent from coordinator roster");
            };
            if target_agent.archived.is_some() {
                return error("target agent is archived; prompt not delivered");
            }
            if target_agent.reachability.is_some()
                && target_agent.reachability
                    != Some(crate::api::federation_store::Reachability::Reachable)
            {
                return error("target peer offline; prompt not delivered");
            }
            let request = Request {
                id: "reverse:agent.prompt".into(),
                method: Method::AgentPrompt(AgentPromptParams {
                    target,
                    text,
                    wait: None,
                }),
            };
            coordinator
                .request_value_bounded(&request, RESPONSE_LIMIT, DEADLINE, None)
                .map_err(io::Error::other)
        }
        _ => return error("reverse capability denied"),
    };
    if stop.load(Ordering::Acquire) || !route.is_current(&stamp) {
        return error("reverse grant or machine route revoked during request");
    }
    match reply {
        Ok(result) => ReverseResponse {
            version: WIRE_VERSION,
            coordinator_machine_id: crate::persist::machine::get_or_create(),
            result: Some(result),
            error: None,
        },
        Err(cause) => error(format!(
            "reverse request failed or delivery unknown: {cause}"
        )),
    }
}

fn agent_list(
    client: &ApiClient,
    local_only: bool,
    stop: &Arc<AtomicBool>,
) -> io::Result<SuccessResponse> {
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "reverse gateway revoked",
        ));
    }
    let request = Request {
        id: "reverse:agent.list".into(),
        method: Method::AgentList(AgentListParams { local_only }),
    };
    let value = client
        .request_value_bounded(&request, RESPONSE_LIMIT, DEADLINE, None)
        .map_err(io::Error::other)?;
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "reverse gateway revoked",
        ));
    }
    serde_json::from_value(value).map_err(io::Error::other)
}

fn grant_matches(grant: &FederationAgentGrant, agent: &AgentInfo) -> bool {
    grant.terminal_id == agent.terminal_id
        && grant.name == agent.name
        && agent.agent_session.as_ref() == Some(&grant.session)
        && agent.archived.is_none()
        && agent.session_transfer.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn grant_requires_live_same_pane_name_and_harness_session() {
        let mut agent: AgentInfo = serde_json::from_value(json!({
            "terminal_id": "pane-1",
            "name": "worker",
            "agent_status": "idle",
            "agent_session": {"source": "codex", "agent": "codex", "kind": "id", "value": "session-1"},
            "workspace_id": "w", "tab_id": "t", "pane_id": "pane-1",
            "focused": false, "revision": 1
        })).unwrap();
        let grant = FederationAgentGrant {
            terminal_id: agent.terminal_id.clone(),
            name: agent.name.clone(),
            session: agent.agent_session.clone().unwrap(),
            observe: true,
            interact: false,
            observe_peers: vec![],
            interact_peers: vec![],
        };
        assert!(grant_matches(&grant, &agent));
        agent.terminal_id = "pane-2".into();
        assert!(!grant_matches(&grant, &agent));
        agent.terminal_id = "pane-1".into();
        agent.name = Some("renamed".into());
        assert!(!grant_matches(&grant, &agent));
        agent.name = grant.name.clone();
        agent.agent_session.as_mut().unwrap().value = "replacement-session".into();
        assert!(!grant_matches(&grant, &agent));
        agent.agent_session = Some(grant.session.clone());
        agent.archived = Some(crate::api::schema::AgentArchivedInfo {
            at: "2026-09-23T00:00:00Z".into(),
            by: "owner".into(),
            reason: None,
        });
        assert!(!grant_matches(&grant, &agent));
    }
}
