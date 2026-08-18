use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use interprocess::local_socket::traits::ListenerExt as _;
use tracing::{debug, error, info, warn};

#[cfg(all(test, unix))]
use std::fs;

use crate::api::federation::{
    authorized_peer, federation_access, FederationAccess, FederationHello, PeerContext,
    FEDERATION_PROTOCOL_VERSION,
};
use crate::api::schema::{
    ErrorBody, ErrorResponse, Method, Request, ResponseResult, ServerCapabilities, SuccessResponse,
};
use crate::api::subscriptions::ActiveSubscription;
use crate::api::wait::{prompt_agent, wait_for_agent, wait_for_event, wait_for_output};
use crate::api::{
    request_changes_ui, socket_path, ApiRequestMessage, ApiRequestSender, ApiStream, ApiStreamRead,
    EventHub,
};
use crate::config::FederationConfig;
#[cfg(test)]
use crate::ipc::LocalStream;
use crate::ipc::{
    bind_local_listener, is_connection_closed_error, remove_socket_file_if_owned,
    socket_file_identity, SocketFileIdentity,
};

mod pane_graphics_stream;
mod pane_input_stream;
mod pane_output_stream;

const SOCKET_PERMISSION_MODE: u32 = 0o600;
pub(super) const CONNECTION_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub(super) const APP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INITIAL_REQUEST_BYTES: usize = 1024 * 1024;
/// Cap on federation TCP connections handled concurrently. A bounded federation
/// listener cannot be driven to unbounded thread/fd growth by an authenticated
/// (or connect-flooding) peer; connections beyond the cap are refused and closed.
const MAX_FEDERATION_CONNECTIONS: usize = 32;

pub struct ServerHandle {
    _thread: JoinHandle<()>,
    /// Federation TCP accept thread, joined on drop. `None` when federation is
    /// not listening.
    federation_thread: Option<JoinHandle<()>>,
    path: PathBuf,
    identity: SocketFileIdentity,
    running: Arc<AtomicBool>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        // The federation accept loop polls `running` between non-blocking
        // accepts, so clearing it above unblocks the thread; join it to release
        // the TCP listener before returning. (The unix accept thread is detached
        // like before — its listener drops with the process.)
        if let Some(thread) = self.federation_thread.take() {
            let _ = thread.join();
        }

        if let Err(err) = self.remove_socket_file_if_owned() {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(path = %self.path.display(), err = %err, "failed to remove api socket on shutdown");
            }
        }
    }
}

impl ServerHandle {
    pub(crate) fn remove_socket_file_if_owned(&self) -> std::io::Result<()> {
        remove_socket_file_if_owned(&self.path, &self.identity)
    }
}

pub(crate) fn start_server_with_stop_control(
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    server_stop: Arc<AtomicBool>,
    federation: &FederationConfig,
) -> std::io::Result<ServerHandle> {
    start_server_inner(
        api_tx,
        event_hub,
        default_capabilities(),
        Some(server_stop),
        federation,
    )
}

pub fn start_server_with_capabilities(
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    capabilities: Option<ServerCapabilities>,
    federation: &FederationConfig,
) -> std::io::Result<ServerHandle> {
    start_server_inner(api_tx, event_hub, capabilities, None, federation)
}

fn default_capabilities() -> Option<ServerCapabilities> {
    Some(ServerCapabilities {
        live_handoff: crate::platform::capabilities().live_handoff,
        detached_server_daemon: crate::platform::current_process_is_detached_server_daemon(),
        pane_input_stream: true,
    })
}

fn start_server_inner(
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    capabilities: Option<ServerCapabilities>,
    server_stop: Option<Arc<AtomicBool>>,
    federation: &FederationConfig,
) -> std::io::Result<ServerHandle> {
    let path = socket_path();
    prepare_socket_path(&path)?;

    let listener = bind_local_listener(&path)?;
    restrict_socket_permissions(&path)?;
    let identity = socket_file_identity(&path)?;
    info!(path = %path.display(), "api server listening");

    let running = Arc::new(AtomicBool::new(true));
    let listener_running = Arc::clone(&running);
    let listener_api_tx = api_tx.clone();
    let listener_event_hub = event_hub.clone();
    let listener_capabilities = capabilities.clone();
    let listener_server_stop = server_stop.clone();
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let api_tx = listener_api_tx.clone();
                    let event_hub = listener_event_hub.clone();
                    let capabilities = listener_capabilities.clone();
                    let server_stop = listener_server_stop.clone();
                    let connection_running = Arc::clone(&listener_running);
                    std::thread::spawn(move || {
                        if let Err(err) = handle_connection_with_stop(
                            ApiStream::Local(stream),
                            &api_tx,
                            &event_hub,
                            &connection_running,
                            capabilities,
                            server_stop.as_ref(),
                            // Local unix-socket connections are never federation
                            // peers, so they bypass the capability-tier gate.
                            None,
                        ) {
                            warn!(err = %err, "api connection failed");
                        }
                    });
                }
                Err(err) => {
                    error!(err = %err, "api listener accept failed");
                    break;
                }
            }
        }
        debug!("api server thread exiting");
    });

    // A bad federation address or an address already in use must not crash the
    // daemon: `maybe_start_federation_listener` logs and returns `None`, leaving
    // the unix listener above serving on its own.
    let federation_thread = maybe_start_federation_listener(
        federation,
        &api_tx,
        &event_hub,
        &capabilities,
        &running,
        &server_stop,
    );

    Ok(ServerHandle {
        _thread: thread,
        federation_thread,
        path,
        identity,
        running,
    })
}

/// Bind the federation TCP listener and spawn its accept thread when federation
/// is enabled and configured. Returns `None` (federation disabled) for any
/// non-fatal reason — disabled, no address, no usable token, or a bind failure —
/// after logging, so the daemon keeps running on the unix socket alone.
fn maybe_start_federation_listener(
    federation: &FederationConfig,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    capabilities: &Option<ServerCapabilities>,
    running: &Arc<AtomicBool>,
    server_stop: &Option<Arc<AtomicBool>>,
) -> Option<JoinHandle<()>> {
    if !federation.listen {
        return None;
    }
    let Some(addr) = federation.listen_addr.as_deref() else {
        warn!("federation.listen is enabled but federation.listen_addr is unset; not binding");
        return None;
    };

    // Safety floor: never open a federation listener without at least one token
    // to authenticate against, or every peer would be admitted.
    let peers = resolve_federation_tokens(federation);
    if peers.is_empty() {
        warn!(
            addr = %addr,
            "federation.listen is enabled but no peer token file yielded a token; \
             refusing to bind an unauthenticated federation listener"
        );
        return None;
    }

    let listener = match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(err) => {
            error!(addr = %addr, err = %err, "failed to bind federation listener; serving unix socket only");
            return None;
        }
    };
    let bound = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| addr.to_string());
    info!(addr = %bound, peer_tokens = peers.len(), "federation listener listening");

    match spawn_federation_listener(
        listener,
        peers,
        api_tx.clone(),
        event_hub.clone(),
        capabilities.clone(),
        Arc::clone(running),
        server_stop.clone(),
    ) {
        Ok(thread) => Some(thread),
        Err(err) => {
            error!(err = %err, "failed to start federation listener thread; serving unix socket only");
            None
        }
    }
}

/// Read each peer's `token_file`, trimmed, into the accepted set paired with the
/// peer's identity and capability tier. A single unreadable/empty token file is
/// logged and skipped rather than failing the listener; peers without a token
/// file are skipped (they have no inbound credential). The returned tier is the
/// authority a request authenticated by that token is bound to.
fn resolve_federation_tokens(federation: &FederationConfig) -> Vec<(String, PeerContext)> {
    let mut peers = Vec::new();
    for peer in &federation.peers {
        let Some(path) = peer.token_file.as_deref() else {
            continue;
        };
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let token = contents.trim();
                if token.is_empty() {
                    warn!(path = %path, alias = %peer.alias, "federation peer token file is empty; skipping");
                } else {
                    peers.push((
                        token.to_string(),
                        PeerContext {
                            alias: peer.alias.clone(),
                            tier: peer.capability,
                        },
                    ));
                }
            }
            Err(err) => {
                warn!(path = %path, alias = %peer.alias, err = %err, "failed to read federation peer token file; skipping");
            }
        }
    }
    peers
}

/// Spawn the federation TCP accept loop. Each accepted connection is handed to
/// [`handle_federation_connection`], which enforces the token gate before any
/// request is dispatched.
///
/// The listener is non-blocking and the loop polls `running` between accepts, so
/// [`ServerHandle::drop`] can stop and join it by clearing `running`.
fn spawn_federation_listener(
    listener: TcpListener,
    peers: Vec<(String, PeerContext)>,
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    capabilities: Option<ServerCapabilities>,
    running: Arc<AtomicBool>,
    server_stop: Option<Arc<AtomicBool>>,
) -> std::io::Result<JoinHandle<()>> {
    listener.set_nonblocking(true)?;
    let peers = Arc::new(peers);
    let in_flight = Arc::new(AtomicUsize::new(0));

    let thread = std::thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    // Refuse (and immediately close) connections beyond the cap so
                    // a peer cannot drive unbounded thread/fd growth. The accept
                    // loop is the only writer of `in_flight`, so this load/compare
                    // is race-free against itself; connection threads only ever
                    // decrement it via the RAII guard below.
                    if in_flight.load(Ordering::Acquire) >= MAX_FEDERATION_CONNECTIONS {
                        warn!(
                            peer = %peer,
                            max = MAX_FEDERATION_CONNECTIONS,
                            "federation connection cap reached; refusing connection"
                        );
                        drop(stream);
                        continue;
                    }
                    // The accepted socket is used in blocking mode; the framed
                    // reader toggles polling on it as needed.
                    if let Err(err) = stream.set_nonblocking(false) {
                        warn!(err = %err, "federation connection blocking-mode reset failed");
                        continue;
                    }
                    in_flight.fetch_add(1, Ordering::AcqRel);
                    // Released when the connection thread returns, including on an
                    // early return or panic, so a slot is never leaked.
                    let slot = ConnectionSlot {
                        in_flight: Arc::clone(&in_flight),
                    };
                    let peers = Arc::clone(&peers);
                    let api_tx = api_tx.clone();
                    let event_hub = event_hub.clone();
                    let capabilities = capabilities.clone();
                    let server_stop = server_stop.clone();
                    let connection_running = Arc::clone(&running);
                    std::thread::spawn(move || {
                        let _slot = slot;
                        if let Err(err) = handle_federation_connection(
                            ApiStream::Tcp(stream),
                            &peers,
                            &api_tx,
                            &event_hub,
                            &connection_running,
                            capabilities,
                            server_stop.as_ref(),
                        ) {
                            warn!(err = %err, peer = %peer, "federation connection failed");
                        }
                    });
                }
                Err(err) => match classify_accept_error(&err) {
                    // No connection pending: idle back-off, no logging.
                    AcceptBackoff::Idle => {
                        std::thread::sleep(CONNECTION_POLL_INTERVAL);
                    }
                    // A transient accept error (EMFILE from fd exhaustion,
                    // ECONNABORTED from a peer that vanished, ...) must not
                    // permanently kill the listener. Log, back off one poll
                    // interval, and keep serving; the loop still exits when
                    // `running` is cleared. There is deliberately no fatal path.
                    AcceptBackoff::Retry => {
                        warn!(err = %err, "federation listener accept error; continuing");
                        std::thread::sleep(CONNECTION_POLL_INTERVAL);
                    }
                },
            }
        }
        debug!("federation listener thread exiting");
    });

    Ok(thread)
}

/// RAII slot for the federation in-flight connection counter. Incremented before
/// a connection thread is spawned and decremented when that thread returns, so a
/// slot is released even on an early return or a panic.
struct ConnectionSlot {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How the federation accept loop reacts to a `TcpListener::accept()` result that
/// is not a fresh connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptBackoff {
    /// No connection was pending (`WouldBlock` on the non-blocking listener).
    Idle,
    /// A transient accept error: back off and keep serving.
    Retry,
}

/// Classify an accept error. `WouldBlock` is the ordinary "nothing pending"
/// signal; every other error is treated as transient and retried. There is
/// deliberately no fatal classification — a transient accept failure (EMFILE,
/// ECONNABORTED, ...) must never permanently kill the federation listener.
fn classify_accept_error(err: &io::Error) -> AcceptBackoff {
    if err.kind() == io::ErrorKind::WouldBlock {
        AcceptBackoff::Idle
    } else {
        AcceptBackoff::Retry
    }
}

/// Enforce the federation handshake, then dispatch the connection normally.
///
/// The first line MUST be a `federation.hello` whose `proto_version` this daemon
/// speaks and whose token matches one configured peer (constant-time compared).
/// A malformed/missing hello or an unknown token is rejected as `unauthorized`;
/// a version the daemon does not speak is rejected as `federation_protocol_mismatch`.
/// Either way a single JSON error line is written and the connection closes with
/// no request dispatched. On success the connection is bound to the matched
/// peer's [`PeerContext`] and the remaining lines flow through the same
/// [`handle_connection_with_stop`] path as a local connection — but gated to the
/// peer's capability tier.
fn handle_federation_connection(
    mut stream: ApiStream,
    peers: &[(String, PeerContext)],
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
    capabilities: Option<ServerCapabilities>,
    server_stop: Option<&Arc<AtomicBool>>,
) -> std::io::Result<()> {
    if let Err(err) = stream.set_send_timeout(Some(STREAM_WRITE_TIMEOUT)) {
        debug!(err = %err, "federation connection write timeout unavailable");
    }

    let Some(line) = read_initial_request_line(&mut stream)? else {
        return Ok(()); // peer closed before sending the hello
    };

    let Some(hello) = FederationHello::from_line(line.trim()) else {
        // Missing or malformed hello: never reveals whether a token would match.
        write_json_line_allow_disconnect(&mut stream, &federation_unauthorized_error())?;
        return Ok(());
    };

    if hello.proto_version != FEDERATION_PROTOCOL_VERSION {
        write_json_line_allow_disconnect(&mut stream, &federation_protocol_mismatch_error())?;
        return Ok(());
    }

    let Some(peer) = authorized_peer(&hello.token, peers) else {
        write_json_line_allow_disconnect(&mut stream, &federation_unauthorized_error())?;
        return Ok(());
    };

    handle_connection_with_stop(
        stream,
        api_tx,
        event_hub,
        running,
        capabilities,
        server_stop,
        Some(peer),
    )
}

fn federation_unauthorized_error() -> ErrorResponse {
    ErrorResponse {
        id: String::new(),
        error: ErrorBody {
            code: "unauthorized".into(),
            message: "federation authentication failed".into(),
        },
    }
}

/// Rejection line for a hello whose handshake version this daemon does not speak.
fn federation_protocol_mismatch_error() -> ErrorResponse {
    ErrorResponse {
        id: String::new(),
        error: ErrorBody {
            code: "federation_protocol_mismatch".into(),
            message: format!(
                "unsupported federation protocol version; this daemon speaks version {FEDERATION_PROTOCOL_VERSION}"
            ),
        },
    }
}

/// Rejection line for a federated request the peer's capability tier does not
/// permit (an out-of-tier or entirely denied method). Reuses the
/// [`federation_unauthorized_error`] error shape, but carries the request id so
/// the client can correlate it, and a `forbidden` code to distinguish an
/// authenticated-but-insufficient peer from a failed authentication.
fn federation_forbidden_error(id: String, method: &str) -> ErrorResponse {
    ErrorResponse {
        id,
        error: ErrorBody {
            code: "forbidden".into(),
            message: format!("federation peer is not permitted to call '{method}'"),
        },
    }
}

fn prepare_socket_path(path: &Path) -> std::io::Result<()> {
    crate::ipc::prepare_socket_path(path, |path| {
        format!(
            "herdr is already running (socket busy at {})",
            path.display()
        )
    })
}

fn restrict_socket_permissions(path: &Path) -> std::io::Result<()> {
    crate::ipc::restrict_socket_permissions(path, SOCKET_PERMISSION_MODE)
}

#[cfg(test)]
fn handle_connection(
    stream: LocalStream,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
    capabilities: Option<ServerCapabilities>,
) -> std::io::Result<()> {
    handle_connection_with_stop(
        ApiStream::Local(stream),
        api_tx,
        event_hub,
        running,
        capabilities,
        None,
        None,
    )
}

fn handle_connection_with_stop(
    mut stream: ApiStream,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
    capabilities: Option<ServerCapabilities>,
    server_stop: Option<&Arc<AtomicBool>>,
    federation: Option<PeerContext>,
) -> std::io::Result<()> {
    if let Err(err) = stream.set_send_timeout(Some(STREAM_WRITE_TIMEOUT)) {
        debug!(err = %err, "api connection write timeout unavailable");
    }

    let Some(line) = read_initial_request_line(&mut stream)? else {
        return Ok(());
    };

    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }

    let request = match serde_json::from_str::<Request>(line) {
        Ok(request) => request,
        Err(request_error) => {
            write_json_line_allow_disconnect(
                &mut stream,
                &ErrorResponse {
                    id: String::new(),
                    error: ErrorBody {
                        code: "invalid_request".into(),
                        message: format!("invalid request: {request_error}"),
                    },
                },
            )?;
            return Ok(());
        }
    };

    let request_id = request.id.clone();
    let method = api_method_name(&request.method);
    let changes_ui = request_changes_ui(&request);

    // Federation capability gate. Local (unix-socket) connections carry `None`
    // here and are never filtered; only a connection bound to a federation
    // `PeerContext` is checked. A method that is denied to federation entirely,
    // or that requires a higher tier than this peer holds, is refused before any
    // dispatch or stream is set up.
    if let Some(peer) = &federation {
        let permitted = matches!(
            federation_access(method),
            FederationAccess::AllowedAt(required) if required <= peer.tier
        );
        if !permitted {
            warn!(
                method,
                alias = %peer.alias,
                "federation request denied by capability tier"
            );
            crate::logging::api_request_started(&request_id, method, changes_ui);
            let response = federation_forbidden_error(request_id.clone(), method);
            let result = write_json_line_allow_disconnect(&mut stream, &response);
            match &result {
                Ok(()) => crate::logging::api_request_completed(
                    &request_id,
                    method,
                    "forbidden",
                    changes_ui,
                ),
                Err(err) => {
                    crate::logging::api_request_failed(&request_id, method, &err.to_string())
                }
            }
            return result;
        }
    }

    crate::logging::api_request_started(&request_id, method, changes_ui);

    match request.method {
        Method::PaneGraphicsStream(params) => {
            let result =
                pane_graphics_stream::serve(stream, request_id.clone(), params, api_tx, running);
            match &result {
                Ok(()) => crate::logging::api_request_completed(
                    &request_id,
                    method,
                    "stream_closed",
                    changes_ui,
                ),
                Err(err) => {
                    crate::logging::api_request_failed(&request_id, method, &err.to_string())
                }
            }
            result
        }
        Method::PaneStream(params) => {
            let result =
                pane_output_stream::serve(stream, request_id.clone(), params, api_tx, running);
            match &result {
                Ok(()) => crate::logging::api_request_completed(
                    &request_id,
                    method,
                    "stream_closed",
                    changes_ui,
                ),
                Err(err) => {
                    crate::logging::api_request_failed(&request_id, method, &err.to_string())
                }
            }
            result
        }
        Method::PaneInputStream(params) => {
            let result =
                pane_input_stream::serve(stream, request_id.clone(), params, api_tx, running);
            match &result {
                Ok(()) => crate::logging::api_request_completed(
                    &request_id,
                    method,
                    "stream_closed",
                    changes_ui,
                ),
                Err(err) => {
                    crate::logging::api_request_failed(&request_id, method, &err.to_string())
                }
            }
            result
        }
        Method::EventsSubscribe(params) => {
            let result = stream_subscriptions(
                stream,
                request_id.clone(),
                params,
                api_tx,
                event_hub,
                running,
            );
            match &result {
                Ok(()) => crate::logging::api_request_completed(
                    &request_id,
                    method,
                    "stream_closed",
                    changes_ui,
                ),
                Err(err) => {
                    crate::logging::api_request_failed(&request_id, method, &err.to_string())
                }
            }
            result
        }
        Method::EventsWait(params) => {
            let response = wait_for_event(
                request_id.clone(),
                params,
                &mut stream,
                api_tx,
                event_hub,
                running,
            )?;
            finish_wait_response(&mut stream, response, &request_id, method, changes_ui)
        }
        Method::AgentPrompt(params) => {
            let response = prompt_agent(
                request_id.clone(),
                params,
                &mut stream,
                api_tx,
                event_hub,
                running,
            )?;
            finish_wait_response(&mut stream, response, &request_id, method, changes_ui)
        }
        Method::AgentWait(params) => {
            let response = wait_for_agent(
                request_id.clone(),
                params,
                &mut stream,
                api_tx,
                event_hub,
                running,
            )?;
            finish_wait_response(&mut stream, response, &request_id, method, changes_ui)
        }
        Method::PaneWaitForOutput(params) => {
            let response =
                wait_for_output(request_id.clone(), params, &mut stream, api_tx, running)?;
            finish_wait_response(&mut stream, response, &request_id, method, changes_ui)
        }
        method_body => {
            let (response_write_tx, response_write_rx) = std::sync::mpsc::channel();
            let response = handle_request(
                Request {
                    id: request_id.clone(),
                    method: method_body,
                },
                api_tx,
                capabilities,
                server_stop,
                Some(response_write_rx),
            );
            let result = write_text_line_allow_disconnect(&mut stream, &response);
            let _ = response_write_tx.send(());
            match &result {
                Ok(()) => crate::logging::api_request_completed(
                    &request_id,
                    method,
                    api_response_outcome(&response),
                    changes_ui,
                ),
                Err(err) => {
                    crate::logging::api_request_failed(&request_id, method, &err.to_string())
                }
            }
            result
        }
    }
}

fn finish_wait_response(
    stream: &mut ApiStream,
    response: Option<String>,
    request_id: &str,
    method: &'static str,
    changes_ui: bool,
) -> std::io::Result<()> {
    let Some(response) = response else {
        crate::logging::api_request_completed(
            request_id,
            method,
            "client_disconnected",
            changes_ui,
        );
        return Ok(());
    };
    let result = write_text_line_allow_disconnect(stream, &response);
    match &result {
        Ok(()) => crate::logging::api_request_completed(
            request_id,
            method,
            api_response_outcome(&response),
            changes_ui,
        ),
        Err(err) => crate::logging::api_request_failed(request_id, method, &err.to_string()),
    }
    result
}

fn handle_request(
    request: Request,
    api_tx: &ApiRequestSender,
    capabilities: Option<ServerCapabilities>,
    server_stop: Option<&Arc<AtomicBool>>,
    response_write_complete: Option<std::sync::mpsc::Receiver<()>>,
) -> String {
    if matches!(&request.method, Method::Ping(_)) {
        return serde_json::to_string(&SuccessResponse {
            id: request.id,
            result: ResponseResult::Pong {
                version: crate::build_info::version(),
                protocol: crate::protocol::PROTOCOL_VERSION,
                capabilities,
            },
        })
        .unwrap_or_else(|_| {
            r#"{"id":"","error":{"code":"internal_error","message":"failed to encode response"}}"#
                .to_string()
        });
    }

    if matches!(&request.method, Method::ServerStop(_)) {
        if let Some(server_stop) = server_stop {
            server_stop.store(true, Ordering::Release);
            return serde_json::to_string(&SuccessResponse {
                id: request.id,
                result: ResponseResult::Ok {},
            })
            .unwrap_or_else(|_| "{}".to_string());
        }
    } else if server_stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return error_response_json(
            request.id,
            "server_unavailable",
            "server is shutting down".into(),
        );
    }

    dispatch_to_app(request, api_tx, None, response_write_complete, None)
}

fn api_method_name(method: &Method) -> &'static str {
    match method {
        Method::Ping(_) => "ping",
        Method::ServerStop(_) => "server.stop",
        Method::ServerLiveHandoff(_) => "server.live_handoff",
        Method::ServerReloadConfig(_) => "server.reload_config",
        Method::ServerAgentManifests(_) => "server.agent_manifests",
        Method::ServerReloadAgentManifests(_) => "server.reload_agent_manifests",
        Method::NotificationShow(_) => "notification.show",
        Method::NotificationsRegisterDevice(_) => "notifications.register_device",
        Method::NotificationsRegisterActivity(_) => "notifications.register_activity",
        Method::NotificationsUnregisterActivity(_) => "notifications.unregister_activity",
        Method::GramSend(_) => "gram.send",
        Method::GramPost(_) => "gram.post",
        Method::GramList(_) => "gram.list",
        Method::GramGrab(_) => "gram.grab",
        Method::GramMarkRead(_) => "gram.mark_read",
        Method::GramDelete(_) => "gram.delete",
        Method::GramUploadChunk(_) => "gram.upload_chunk",
        Method::GramGetFile(_) => "gram.get_file",
        Method::ClientWindowTitleSet(_) => "client.window_title.set",
        Method::ClientWindowTitleClear(_) => "client.window_title.clear",
        Method::SessionSnapshot(_) => "session.snapshot",
        Method::WorkspaceCreate(_) => "workspace.create",
        Method::WorkspaceList(_) => "workspace.list",
        Method::WorkspaceGet(_) => "workspace.get",
        Method::WorkspaceFocus(_) => "workspace.focus",
        Method::WorkspaceRename(_) => "workspace.rename",
        Method::WorkspaceMove(_) => "workspace.move",
        Method::WorkspaceMoveBlock(_) => "workspace.move_block",
        Method::WorkspaceReportMetadata(_) => "workspace.report_metadata",
        Method::WorkspaceClose(_) => "workspace.close",
        Method::WorktreeList(_) => "worktree.list",
        Method::WorktreeCreate(_) => "worktree.create",
        Method::WorktreeOpen(_) => "worktree.open",
        Method::WorktreeRemove(_) => "worktree.remove",
        Method::TabCreate(_) => "tab.create",
        Method::TabList(_) => "tab.list",
        Method::TabGet(_) => "tab.get",
        Method::TabFocus(_) => "tab.focus",
        Method::TabRename(_) => "tab.rename",
        Method::TabMove(_) => "tab.move",
        Method::TabClose(_) => "tab.close",
        Method::AgentList(_) => "agent.list",
        Method::AgentGet(_) => "agent.get",
        Method::AgentRead(_) => "agent.read",
        Method::AgentExplain(_) => "agent.explain",
        Method::AgentSendKeys(_) => "agent.send_keys",
        Method::AgentRename(_) => "agent.rename",
        Method::AgentViewSet(_) => "agent.view.set",
        Method::AgentViewClear(_) => "agent.view.clear",
        Method::AgentFocus(_) => "agent.focus",
        Method::AgentStart(_) => "agent.start",
        Method::AgentPrompt(_) => "agent.prompt",
        Method::AgentWait(_) => "agent.wait",
        Method::PaneSplit(_) => "pane.split",
        Method::PaneSwap(_) => "pane.swap",
        Method::PaneMove(_) => "pane.move",
        Method::PaneZoom(_) => "pane.zoom",
        Method::PaneLayout(_) => "pane.layout",
        Method::PaneProcessInfo(_) => "pane.process_info",
        Method::LayoutExport(_) => "layout.export",
        Method::LayoutApply(_) => "layout.apply",
        Method::LayoutSetSplitRatio(_) => "layout.set_split_ratio",
        Method::PaneNeighbor(_) => "pane.neighbor",
        Method::PaneEdges(_) => "pane.edges",
        Method::PaneFocusDirection(_) => "pane.focus_direction",
        Method::PaneResize(_) => "pane.resize",
        Method::PaneSetPtySize(_) => "pane.set_pty_size",
        Method::PaneList(_) => "pane.list",
        Method::PaneCurrent(_) => "pane.current",
        Method::PaneGet(_) => "pane.get",
        Method::PaneTurns(_) => "pane.turns",
        Method::PaneFocus(_) => "pane.focus",
        Method::PaneInputSet(_) => "pane.input.set",
        Method::PaneRename(_) => "pane.rename",
        Method::PaneSendText(_) => "pane.send_text",
        Method::PaneSendKeys(_) => "pane.send_keys",
        Method::PaneSendInput(_) => "pane.send_input",
        Method::PaneRead(_) => "pane.read",
        Method::PaneGraphicsSet(_) => "pane.graphics.set",
        Method::PaneGraphicsClear(_) => "pane.graphics.clear",
        Method::PaneGraphicsInfo(_) => "pane.graphics.info",
        Method::PaneGraphicsStream(_) => "pane.graphics.stream",
        Method::PaneGraphicsStreamSet(_) => "pane.graphics.stream.set",
        Method::PaneGraphicsStreamDirect(_) => "pane.graphics.stream.direct",
        Method::PaneGraphicsStreamOpen(_) => "pane.graphics.stream.open",
        Method::PaneGraphicsStreamClose(_) => "pane.graphics.stream.close",
        Method::PaneStream(_) => "pane.stream",
        Method::PaneStreamOpen(_) => "pane.stream.open",
        Method::PaneStreamClose(_) => "pane.stream.close",
        Method::PaneInputStream(_) => "pane.input.stream",
        Method::PaneInputStreamOpen(_) => "pane.input.stream.open",
        Method::PaneReportAgent(_) => "pane.report_agent",
        Method::PaneReportAgentSession(_) => "pane.report_agent_session",
        Method::PaneReportMetadata(_) => "pane.report_metadata",
        Method::PaneClearAgentAuthority(_) => "pane.clear_agent_authority",
        Method::PaneReleaseAgent(_) => "pane.release_agent",
        Method::PaneClose(_) => "pane.close",
        Method::PopupClose(_) => "popup.close",
        Method::EventsSubscribe(_) => "events.subscribe",
        Method::EventsWait(_) => "events.wait",
        Method::PaneWaitForOutput(_) => "pane.wait_for_output",
        Method::IntegrationInstall(_) => "integration.install",
        Method::IntegrationUninstall(_) => "integration.uninstall",
        Method::PluginLink(_) => "plugin.link",
        Method::PluginList(_) => "plugin.list",
        Method::PluginUnlink(_) => "plugin.unlink",
        Method::PluginEnable(_) => "plugin.enable",
        Method::PluginDisable(_) => "plugin.disable",
        Method::PluginActionList(_) => "plugin.action.list",
        Method::PluginActionInvoke(_) => "plugin.action.invoke",
        Method::PluginLogList(_) => "plugin.log.list",
        Method::PluginPaneOpen(_) => "plugin.pane.open",
        Method::PluginPaneFocus(_) => "plugin.pane.focus",
        Method::PluginPaneClose(_) => "plugin.pane.close",
    }
}

fn api_response_outcome(response: &str) -> &'static str {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(response) else {
        return "error";
    };

    match value
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(|code| code.as_str())
    {
        Some("timeout") => "timeout",
        Some(_) => "error",
        None => "ok",
    }
}

fn read_initial_request_line(stream: &mut ApiStream) -> std::io::Result<Option<String>> {
    read_initial_request_line_with_timeout(stream, INITIAL_REQUEST_TIMEOUT)
}

fn read_initial_request_line_with_timeout(
    stream: &mut ApiStream,
    timeout: Duration,
) -> std::io::Result<Option<String>> {
    read_initial_request_line_with_limits(stream, timeout, MAX_INITIAL_REQUEST_BYTES)
}

fn read_initial_request_line_with_limits(
    stream: &mut ApiStream,
    timeout: Duration,
    max_bytes: usize,
) -> std::io::Result<Option<String>> {
    stream.set_polling(true)?;
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];

    let result = loop {
        let read = match stream.poll_read(&mut byte) {
            Ok(read) => read,
            Err(err) => break Err(err),
        };
        match read {
            ApiStreamRead::Closed => break Ok(None),
            ApiStreamRead::Data(_) => {
                bytes.push(byte[0]);
                if byte[0] == b'\n' {
                    break String::from_utf8(bytes)
                        .map(Some)
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err));
                }
                if bytes.len() > max_bytes {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "api request line is too large",
                    ));
                }
            }
            ApiStreamRead::Pending => {
                if Instant::now() >= deadline {
                    break Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out reading api request",
                    ));
                }
                std::thread::sleep(CONNECTION_POLL_INTERVAL);
            }
        }
    };
    stream.set_polling(false)?;
    result
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use interprocess::local_socket::traits::Listener as _;
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc::{self, Receiver};

    fn local_stream_pair(name: &str) -> (LocalStream, LocalStream, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "herdr-api-{name}-{}-{}.sock",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let listener = crate::ipc::bind_local_listener(&path).unwrap();
        let client = crate::ipc::connect_local_stream(&path).unwrap();
        let server = listener.accept().unwrap();
        (client, server, path)
    }

    fn spawn_connection(
        server: LocalStream,
    ) -> (Receiver<std::io::Result<()>>, std::thread::JoinHandle<()>) {
        let (done_tx, done_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (api_tx, _api_rx) = tokio::sync::mpsc::unbounded_channel();
            let result = handle_connection(
                server,
                &api_tx,
                &EventHub::default(),
                &Arc::new(AtomicBool::new(true)),
                None,
            );
            done_tx.send(result).unwrap();
        });
        (done_rx, thread)
    }

    #[test]
    fn windows_delayed_partial_initial_request_returns_pong() {
        let (mut client, server, path) = local_stream_pair("delayed-request");
        let (done_rx, server_thread) = spawn_connection(server);

        std::thread::sleep(Duration::from_millis(300));
        assert!(
            done_rx.try_recv().is_err(),
            "idle connected client must not be treated as closed"
        );

        client
            .write_all(br#"{"id":"delayed","method":"ping","params":{}}"#)
            .unwrap();
        client.flush().unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            done_rx.try_recv().is_err(),
            "partial request must wait for its newline"
        );
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let mut response = String::new();
        BufReader::new(&mut client)
            .read_line(&mut response)
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["id"], "delayed");
        assert_eq!(response["result"]["type"], "pong");

        done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        server_thread.join().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn windows_disconnected_initial_request_returns_promptly() {
        let (client, server, path) = local_stream_pair("disconnected-request");
        let (done_rx, server_thread) = spawn_connection(server);

        drop(client);

        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("disconnected connection handler must finish promptly")
            .unwrap();
        server_thread.join().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn windows_idle_initial_request_honors_timeout() {
        let (_client, server, path) = local_stream_pair("request-timeout");
        let mut server = ApiStream::Local(server);

        let err = read_initial_request_line_with_timeout(&mut server, Duration::from_millis(50))
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn windows_initial_request_enforces_size_limit() {
        let (mut client, server, path) = local_stream_pair("request-size-limit");
        client.write_all(b"12345").unwrap();
        client.flush().unwrap();
        let mut server = ApiStream::Local(server);

        let err = read_initial_request_line_with_limits(&mut server, Duration::from_secs(1), 4)
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "api request line is too large");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn windows_initial_request_rejects_invalid_utf8() {
        let (mut client, server, path) = local_stream_pair("request-invalid-utf8");
        client.write_all(&[0xff, b'\n']).unwrap();
        client.flush().unwrap();
        let mut server = ApiStream::Local(server);

        let err = read_initial_request_line_with_timeout(&mut server, Duration::from_secs(1))
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(path);
    }
}

fn stream_subscriptions(
    mut stream: ApiStream,
    request_id: String,
    params: crate::api::schema::EventsSubscribeParams,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut subscriptions = Vec::with_capacity(params.subscriptions.len());
    for (index, subscription) in params.subscriptions.into_iter().enumerate() {
        let active =
            match ActiveSubscription::new(subscription, &request_id, index, api_tx, event_hub) {
                Ok(active) => active,
                Err(response) => {
                    if let Err(err) = write_json_line(&mut stream, &response) {
                        if is_connection_closed_error(&err) {
                            return Ok(());
                        }
                        return Err(err);
                    }
                    return Ok(());
                }
            };
        subscriptions.push(active);
    }

    if let Err(err) = write_json_line(
        &mut stream,
        &SuccessResponse {
            id: request_id,
            result: ResponseResult::SubscriptionStarted {},
        },
    ) {
        if is_connection_closed_error(&err) {
            return Ok(());
        }
        return Err(err);
    }

    loop {
        if should_stop_connection(&mut stream, running)? {
            return Ok(());
        }

        for subscription in &mut subscriptions {
            if let Some(event) = subscription.poll(api_tx, event_hub) {
                if let Err(err) = write_json_line(&mut stream, &event) {
                    if is_connection_closed_error(&err) {
                        return Ok(());
                    }
                    return Err(err);
                }
            }
        }
        std::thread::sleep(CONNECTION_POLL_INTERVAL);
    }
}

fn write_text_line(stream: &mut ApiStream, value: &str) -> std::io::Result<()> {
    stream.write_all(value.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn write_text_line_allow_disconnect(stream: &mut ApiStream, value: &str) -> std::io::Result<()> {
    match write_text_line(stream, value) {
        Err(err) if is_connection_closed_error(&err) => Ok(()),
        result => result,
    }
}

fn write_json_line<T: serde::Serialize>(stream: &mut ApiStream, value: &T) -> std::io::Result<()> {
    let encoded = serde_json::to_string(value)
        .map_err(|err| std::io::Error::other(format!("failed to encode json: {err}")))?;
    write_text_line(stream, &encoded)
}

fn write_json_line_allow_disconnect<T: serde::Serialize>(
    stream: &mut ApiStream,
    value: &T,
) -> std::io::Result<()> {
    let encoded = serde_json::to_string(value)
        .map_err(|err| std::io::Error::other(format!("failed to encode json: {err}")))?;
    write_text_line_allow_disconnect(stream, &encoded)
}

pub(super) fn should_stop_connection(
    stream: &mut ApiStream,
    running: &Arc<AtomicBool>,
) -> std::io::Result<bool> {
    if !running.load(Ordering::Relaxed) {
        return Ok(true);
    }

    stream.peer_closed()
}

pub(super) fn dispatch_to_app_with_timeout(
    request: Request,
    api_tx: &ApiRequestSender,
    timeout: Option<Duration>,
) -> String {
    dispatch_to_app(request, api_tx, timeout, None, None)
}

pub(super) fn dispatch_stream_open(
    request: Request,
    api_tx: &ApiRequestSender,
    timeout: Duration,
    active: Arc<AtomicBool>,
) -> String {
    dispatch_to_app(request, api_tx, Some(timeout), None, Some(active))
}

pub(super) fn dispatch_stream_frame(
    request: Request,
    api_tx: &ApiRequestSender,
    active: Arc<AtomicBool>,
) -> String {
    dispatch_to_app(
        request,
        api_tx,
        Some(crate::app::pane_graphics::DIRECT_OUTER_TIMEOUT),
        None,
        Some(active),
    )
}

fn dispatch_to_app(
    request: Request,
    api_tx: &ApiRequestSender,
    timeout: Option<Duration>,
    response_write_complete: Option<std::sync::mpsc::Receiver<()>>,
    stream_active: Option<Arc<AtomicBool>>,
) -> String {
    let request_id = request.id.clone();
    let request_active = stream_active.clone();
    let (respond_to, response_rx) = std::sync::mpsc::channel();
    if let Err(err) = api_tx.send(ApiRequestMessage {
        request,
        respond_to,
        response_write_complete,
        stream_active,
    }) {
        if let Some(active) = request_active {
            active.store(false, Ordering::Release);
        }
        return error_response_json(
            request_id,
            "server_unavailable",
            format!("failed to dispatch request: {err}"),
        );
    }

    let response = match timeout {
        Some(timeout) => response_rx.recv_timeout(timeout).map_err(|err| match err {
            std::sync::mpsc::RecvTimeoutError::Timeout => std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting for app response after {} ms",
                    timeout.as_millis()
                ),
            ),
            std::sync::mpsc::RecvTimeoutError::Disconnected => std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "app response channel closed",
            ),
        }),
        None => response_rx
            .recv()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::BrokenPipe, err)),
    };

    match response {
        Ok(response) => response,
        Err(err) => {
            if let Some(active) = request_active {
                active.store(false, Ordering::Release);
            }
            error_response_json(
                request_id,
                "server_unavailable",
                format!("request handling failed: {err}"),
            )
        }
    }
}

fn error_response_json(id: String, code: &str, message: String) -> String {
    serde_json::to_string(&ErrorResponse {
        id,
        error: ErrorBody {
            code: code.into(),
            message,
        },
    })
    .unwrap_or_else(|_| {
        r#"{"id":"","error":{"code":"internal_error","message":"failed to encode error response"}}"#
            .to_string()
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use interprocess::local_socket::traits::Listener as _;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::{Mutex, OnceLock};
    use tokio::sync::mpsc;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_test_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("herdr-{name}-{}-{nanos}", std::process::id()))
    }

    fn read_line(stream: &mut LocalStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line
    }

    fn local_stream_pair(name: &str) -> (LocalStream, LocalStream, PathBuf) {
        let path = unique_test_path(name);
        let listener = crate::ipc::bind_local_listener(&path).unwrap();
        let client = crate::ipc::connect_local_stream(&path).unwrap();
        let server = listener.accept().unwrap();
        (client, server, path)
    }

    fn pane_info(
        pane_id: &str,
        agent_status: crate::api::schema::AgentStatus,
    ) -> crate::api::schema::PaneInfo {
        crate::api::schema::PaneInfo {
            pane_id: pane_id.into(),
            terminal_id: "term_1".into(),
            workspace_id: "ws_1".into(),
            tab_id: "tab_1".into(),
            focused: true,
            cwd: None,
            foreground_cwd: None,
            label: None,
            agent: Some("pi".into()),
            title: None,
            terminal_title: None,
            terminal_title_stripped: None,
            display_agent: None,
            agent_status,
            input_pending: false,
            input_prompt_kind: None,
            composer: Default::default(),
            state_labels: HashMap::new(),
            tokens: HashMap::new(),
            agent_session: None,
            last_completed_turn: None,
            turn: Some(0),
            turn_epoch: Some(9),
            scroll: None,
            alternate_screen: false,
            revision: 0,
        }
    }

    fn spawn_pane_get_responder(
        agent_status: crate::api::schema::AgentStatus,
    ) -> (ApiRequestSender, std::thread::JoinHandle<()>) {
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let responder = std::thread::spawn(move || {
            while let Some(msg) = api_rx.blocking_recv() {
                match msg.request.method {
                    Method::PaneGet(_) => msg
                        .respond_to
                        .send(
                            serde_json::to_string(&SuccessResponse {
                                id: msg.request.id,
                                result: ResponseResult::PaneInfo {
                                    pane: pane_info("pane_1", agent_status),
                                },
                            })
                            .unwrap(),
                        )
                        .unwrap(),
                    Method::EventsWait(_) => msg
                        .respond_to
                        .send(error_response_json(
                            msg.request.id,
                            "unexpected_dispatch",
                            "events.wait should be handled by the api server".into(),
                        ))
                        .unwrap(),
                    other => panic!("unexpected request: {other:?}"),
                }
            }
        });
        (api_tx, responder)
    }

    #[test]
    fn socket_path_prefers_explicit_env_override() {
        let _guard = env_lock().lock().unwrap();
        let unique = format!("/tmp/herdr-test-{}.sock", std::process::id());
        std::env::remove_var(crate::session::SESSION_ENV_VAR);
        crate::session::clear_explicit_session_for_test();
        std::env::set_var(crate::api::SOCKET_PATH_ENV_VAR, &unique);
        assert_eq!(socket_path(), PathBuf::from(&unique));
        std::env::remove_var(crate::api::SOCKET_PATH_ENV_VAR);
    }

    #[test]
    fn socket_path_defaults_to_config_dir_even_when_xdg_runtime_dir_is_set() {
        let _guard = env_lock().lock().unwrap();
        let config_home = unique_test_path("socket-default-config-home");
        let runtime_dir = unique_test_path("socket-default-runtime");
        std::env::remove_var(crate::api::SOCKET_PATH_ENV_VAR);
        std::env::remove_var(crate::session::SESSION_ENV_VAR);
        crate::session::clear_explicit_session_for_test();
        std::env::set_var("XDG_CONFIG_HOME", &config_home);
        std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);

        let expected = config_home
            .join(crate::config::app_dir_name())
            .join("herdr.sock");
        assert_eq!(socket_path(), expected);

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn socket_path_uses_named_session_dir() {
        let _guard = env_lock().lock().unwrap();
        let config_home = unique_test_path("socket-named-config-home");
        std::env::remove_var(crate::api::SOCKET_PATH_ENV_VAR);
        crate::session::clear_explicit_session_for_test();
        std::env::set_var(crate::session::SESSION_ENV_VAR, "work");
        std::env::set_var("XDG_CONFIG_HOME", &config_home);

        let expected = config_home
            .join(crate::config::app_dir_name())
            .join("sessions")
            .join("work")
            .join("herdr.sock");
        assert_eq!(socket_path(), expected);

        std::env::remove_var(crate::session::SESSION_ENV_VAR);
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn restrict_socket_permissions_sets_user_only_mode() {
        let dir = unique_test_path("socket-perms");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api.sock");
        let _listener = UnixListener::bind(&path).unwrap();

        restrict_socket_permissions(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_PERMISSION_MODE);

        drop(_listener);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn api_response_outcome_uses_top_level_error_shape() {
        let ok_with_error_text = r#"{"id":"req","result":{"read":{"text":"user said \"error\": \"timeout\"","revision":1}}}"#;
        assert_eq!(api_response_outcome(ok_with_error_text), "ok");

        let timeout = r#"{"id":"req","error":{"code":"timeout","message":"timed out waiting for output match"}}"#;
        assert_eq!(api_response_outcome(timeout), "timeout");

        let generic_error =
            r#"{"id":"req","error":{"code":"server_unavailable","message":"boom"}}"#;
        assert_eq!(api_response_outcome(generic_error), "error");
    }

    #[test]
    fn ping_request_returns_pong() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let response = handle_request(
            Request {
                id: "req_1".into(),
                method: Method::Ping(crate::api::schema::PingParams::default()),
            },
            &tx,
            Some(ServerCapabilities {
                live_handoff: true,
                detached_server_daemon: true,
                pane_input_stream: false,
            }),
            None,
            None,
        );

        let parsed: SuccessResponse = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed.id, "req_1");
        assert!(matches!(parsed.result, ResponseResult::Pong { .. }));
    }

    #[test]
    fn server_stop_control_bypasses_app_channel() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stop = Arc::new(AtomicBool::new(false));
        let response = handle_request(
            Request {
                id: "priority_stop".into(),
                method: Method::ServerStop(crate::api::schema::EmptyParams::default()),
            },
            &tx,
            None,
            Some(&stop),
            None,
        );

        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["id"], "priority_stop");
        assert_eq!(response["result"]["type"], "ok");
        assert!(stop.load(Ordering::Acquire));

        let rejected = handle_request(
            Request {
                id: "after_stop".into(),
                method: Method::WorkspaceList(crate::api::schema::EmptyParams::default()),
            },
            &tx,
            None,
            Some(&stop),
            None,
        );
        let rejected: serde_json::Value = serde_json::from_str(&rejected).unwrap();
        assert_eq!(rejected["error"]["code"], "server_unavailable");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn request_dispatches_to_app_channel() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let request = Request {
            id: "req_2".into(),
            method: Method::WorkspaceList(crate::api::schema::EmptyParams::default()),
        };

        let request_for_thread = request.clone();
        let thread =
            std::thread::spawn(move || handle_request(request_for_thread, &tx, None, None, None));

        let msg = rx.blocking_recv().unwrap();
        assert_eq!(msg.request.id, "req_2");
        msg.respond_to
            .send(
                serde_json::to_string(&SuccessResponse {
                    id: "req_2".into(),
                    result: ResponseResult::Ok {},
                })
                .unwrap(),
            )
            .unwrap();

        let response = thread.join().unwrap();
        let parsed: SuccessResponse = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed.id, "req_2");
    }

    #[test]
    fn dispatched_request_reports_response_write_completion() {
        let (api_tx, mut api_rx) = mpsc::unbounded_channel();
        let (mut client, server, _path) = local_stream_pair("write-ack");
        client
            .write_all(br#"{"id":"req_write","method":"workspace.list","params":{}}"#)
            .unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let server_running = Arc::clone(&running);
        let event_hub = EventHub::default();
        let server_thread = std::thread::spawn(move || {
            handle_connection(server, &api_tx, &event_hub, &server_running, None)
        });

        let msg = api_rx.blocking_recv().unwrap();
        let response_write_complete = msg
            .response_write_complete
            .expect("socket-dispatched requests include write completion");
        msg.respond_to
            .send(
                serde_json::to_string(&SuccessResponse {
                    id: msg.request.id,
                    result: ResponseResult::Ok {},
                })
                .unwrap(),
            )
            .unwrap();

        response_write_complete
            .recv_timeout(Duration::from_secs(1))
            .expect("response write completion");
        let response: SuccessResponse = serde_json::from_str(&read_line(&mut client)).unwrap();
        assert_eq!(response.id, "req_write");
        server_thread.join().unwrap().unwrap();
    }

    #[test]
    fn events_wait_agent_status_returns_initial_match() {
        let (api_tx, responder) =
            spawn_pane_get_responder(crate::api::schema::AgentStatus::Blocked);

        let (mut client, server, _path) = local_stream_pair("api-events-wait-initial");
        client
            .write_all(br#"{"id":"wait_1","method":"events.wait","params":{"match_event":{"event":"pane_agent_status_changed","pane_id":"pane_1","agent_status":"blocked"},"timeout_ms":1000}}"#)
            .unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let event_hub = EventHub::default();
        handle_connection(server, &api_tx, &event_hub, &running, None).unwrap();

        let response: serde_json::Value = serde_json::from_str(&read_line(&mut client)).unwrap();
        assert_eq!(response["id"], "wait_1");
        assert_eq!(response["result"]["type"], "wait_matched");
        assert_eq!(
            response["result"]["event"]["data"]["agent_status"],
            "blocked"
        );
        assert_eq!(response["result"]["event"]["data"]["turn"], 0);
        assert_eq!(response["result"]["event"]["data"]["turn_epoch"], 9);
        drop(api_tx);
        responder.join().unwrap();
    }

    #[test]
    fn events_wait_agent_status_times_out_server_side() {
        let (api_tx, responder) =
            spawn_pane_get_responder(crate::api::schema::AgentStatus::Unknown);

        let (mut client, server, _path) = local_stream_pair("api-events-wait-timeout");
        client
            .write_all(br#"{"id":"wait_2","method":"events.wait","params":{"match_event":{"event":"pane_agent_status_changed","pane_id":"pane_1","agent_status":"blocked"},"timeout_ms":30}}"#)
            .unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let event_hub = EventHub::default();
        handle_connection(server, &api_tx, &event_hub, &running, None).unwrap();

        let response: serde_json::Value = serde_json::from_str(&read_line(&mut client)).unwrap();
        assert_eq!(response["id"], "wait_2");
        assert_eq!(response["error"]["code"], "timeout");
        assert_eq!(
            response["error"]["message"],
            "timed out waiting for event match"
        );
        drop(api_tx);
        responder.join().unwrap();
    }

    #[test]
    fn events_wait_agent_status_returns_not_found_when_pane_closes() {
        let event_hub = EventHub::default();
        let responder_event_hub = event_hub.clone();
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let responder = std::thread::spawn(move || {
            let mut pane_get_count = 0;
            while let Some(msg) = api_rx.blocking_recv() {
                let Method::PaneGet(_) = msg.request.method else {
                    panic!("unexpected request: {:?}", msg.request.method);
                };
                pane_get_count += 1;
                let response = if pane_get_count == 1 {
                    serde_json::to_string(&SuccessResponse {
                        id: msg.request.id,
                        result: ResponseResult::PaneInfo {
                            pane: pane_info("pane_1", crate::api::schema::AgentStatus::Unknown),
                        },
                    })
                    .unwrap()
                } else {
                    if pane_get_count == 2 {
                        responder_event_hub.push(crate::api::schema::EventEnvelope {
                            event: crate::api::schema::EventKind::PaneClosed,
                            data: crate::api::schema::EventData::PaneClosed {
                                pane_id: "pane_1".into(),
                                workspace_id: "ws_1".into(),
                            },
                        });
                    }
                    error_response_json(
                        msg.request.id,
                        "pane_not_found",
                        "pane pane_1 not found".into(),
                    )
                };
                msg.respond_to.send(response).unwrap();
            }
        });

        let (mut client, server, _path) = local_stream_pair("wait-close");
        client
            .write_all(br#"{"id":"wait_close","method":"events.wait","params":{"match_event":{"event":"pane_agent_status_changed","pane_id":"pane_1","agent_status":"done"},"timeout_ms":500}}"#)
            .unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let running = Arc::new(AtomicBool::new(true));
        handle_connection(server, &api_tx, &event_hub, &running, None).unwrap();

        let response: serde_json::Value = serde_json::from_str(&read_line(&mut client)).unwrap();
        assert_eq!(response["id"], "wait_close");
        assert_eq!(response["error"]["code"], "pane_not_found");
        assert_eq!(response["error"]["message"], "pane pane_1 not found");
        drop(api_tx);
        responder.join().unwrap();
    }

    #[test]
    fn wait_for_output_stops_when_client_disconnects() {
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (first_read_tx, first_read_rx) = std::sync::mpsc::channel();
        let responder = std::thread::spawn(move || {
            let mut notified = false;
            while let Some(msg) = api_rx.blocking_recv() {
                assert!(matches!(msg.request.method, Method::PaneRead(_)));
                if !notified {
                    first_read_tx.send(()).unwrap();
                    notified = true;
                }
                msg.respond_to
                    .send(
                        serde_json::to_string(&SuccessResponse {
                            id: msg.request.id,
                            result: ResponseResult::PaneRead {
                                read: crate::api::schema::PaneReadResult {
                                    pane_id: "pane_1".into(),
                                    workspace_id: "ws_1".into(),
                                    tab_id: "tab_1".into(),
                                    source: crate::api::schema::ReadSource::RecentUnwrapped,
                                    format: crate::api::schema::ReadFormat::Text,
                                    text: String::new(),
                                    revision: 0,
                                    truncated: false,
                                },
                            },
                        })
                        .unwrap(),
                    )
                    .unwrap();
            }
        });

        let (mut client, server, _path) = local_stream_pair("api-wait-disconnect");
        client
            .write_all(br#"{"id":"req_wait","method":"pane.wait_for_output","params":{"pane_id":"pane_1","source":"recent","match":{"type":"substring","value":"never"}}}"#)
            .unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let server_running = Arc::clone(&running);
        let event_hub = EventHub::default();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let result = handle_connection(server, &api_tx, &event_hub, &server_running, None);
            done_tx.send(result).unwrap();
        });

        first_read_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(client);

        let result = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());

        server_thread.join().unwrap();
        drop(running);
        responder.join().unwrap();
    }

    #[test]
    fn subscriptions_stop_when_client_disconnects() {
        let (api_tx, _api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair("api-sub-disconnect");
        client
            .write_all(
                br#"{"id":"sub_1","method":"events.subscribe","params":{"subscriptions":[{"type":"workspace.created"}]}}"#,
            )
            .unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let server_running = Arc::clone(&running);
        let event_hub = EventHub::default();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let result = handle_connection(server, &api_tx, &event_hub, &server_running, None);
            done_tx.send(result).unwrap();
        });

        let ack = read_line(&mut client);
        let ack: serde_json::Value = serde_json::from_str(&ack).unwrap();
        assert_eq!(ack["result"]["type"], "subscription_started");

        drop(client);

        let result = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());
        server_thread.join().unwrap();
    }

    #[test]
    fn subscriptions_stop_when_server_shuts_down() {
        let (api_tx, _api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let (mut client, server, _path) = local_stream_pair("api-sub-shutdown");
        client
            .write_all(
                br#"{"id":"sub_2","method":"events.subscribe","params":{"subscriptions":[{"type":"workspace.created"}]}}"#,
            )
            .unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let server_running = Arc::clone(&running);
        let event_hub = EventHub::default();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let result = handle_connection(server, &api_tx, &event_hub, &server_running, None);
            done_tx.send(result).unwrap();
        });

        let ack = read_line(&mut client);
        let ack: serde_json::Value = serde_json::from_str(&ack).unwrap();
        assert_eq!(ack["result"]["type"], "subscription_started");

        running.store(false, Ordering::Relaxed);

        let result = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());
        server_thread.join().unwrap();
    }

    #[test]
    fn local_connection_bypasses_federation_capability_gate() {
        use std::io::Write as _;

        // A local (unix-socket) connection carries `federation: None`, so even a
        // method federation denies outright (here `pane.close`) must dispatch
        // unfiltered. This is the regression guard that the Part-1 gate never
        // touches the local control path.
        let (mut client, server, path) = local_stream_pair("local-no-fed-filter");
        let (api_tx, mut api_rx) = mpsc::unbounded_channel();
        let running = Arc::new(AtomicBool::new(true));
        let handle = std::thread::spawn(move || {
            let _ = handle_connection_with_stop(
                ApiStream::Local(server),
                &api_tx,
                &EventHub::default(),
                &running,
                None,
                None,
                // Local path: no federation peer, so no capability filtering.
                None,
            );
        });

        let request = serde_json::to_string(&Request {
            id: "local_close".into(),
            method: Method::PaneClose(crate::api::schema::PaneTarget {
                pane_id: "pane_1".into(),
            }),
        })
        .unwrap();
        client.write_all(request.as_bytes()).unwrap();
        client.write_all(b"\n").unwrap();
        client.flush().unwrap();

        // The normally-denied method reached the app dispatch path unfiltered.
        let message = api_rx.blocking_recv().expect("request dispatched to app");
        assert!(matches!(message.request.method, Method::PaneClose(_)));

        // Dropping the message disconnects the response channel so the connection
        // thread unwinds instead of blocking on a reply that never comes.
        drop(message);
        let _ = handle.join();
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod pane_graphics_request_tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn maximum_public_graphics_request_fits_initial_json_line() {
        let request = Request {
            id: "graphics-max".into(),
            method: Method::PaneGraphicsSet(crate::api::schema::PaneGraphicsSetParams {
                pane_id: "pane_1".into(),
                layer_id: None,
                z_index: 0,
                owner: String::new(),
                format: crate::api::schema::PaneGraphicsFormat::Png,
                image_width: 1,
                image_height: 1,
                data_base64: base64::engine::general_purpose::STANDARD
                    .encode(vec![1_u8; crate::api::schema::PANE_GRAPHICS_SET_MAX_BYTES]),
                data: None,
                placement: crate::api::schema::PaneGraphicsPlacementParams::default(),
            }),
        };
        let encoded = serde_json::to_vec(&request).unwrap();

        assert!(encoded.len() < MAX_INITIAL_REQUEST_BYTES);
    }

    #[test]
    fn duplicate_method_cannot_be_reinterpreted_as_graphics_stream() {
        let encoded = r#"{"id":"duplicate","method":"ping","method":"pane.graphics.stream","params":{"pane_id":"pane_1"}}"#;

        assert!(serde_json::from_str::<Request>(encoded).is_err());
    }
}

/// Federation TCP listener + token-gate tests. These run a real loopback
/// `TcpListener` through [`spawn_federation_listener`] and drive it with the
/// real [`ApiClient`] TCP transport (or a raw socket for the rejection paths),
/// entirely in-process — no external machine.
#[cfg(test)]
mod federation_tests {
    use super::*;
    use crate::api::client::{ApiClient, ConnectionTarget};
    use crate::api::schema::{
        AgentPromptParams, AgentRenameParams, AgentStartParams, EmptyParams, EventData,
        EventEnvelope, EventKind, EventsSubscribeParams, PaneTarget, PingParams, Subscription,
    };
    use crate::config::CapabilityTier;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpStream};
    use tokio::sync::mpsc;

    /// A running federation listener bound to a loopback ephemeral port, plus the
    /// app channel receiver so a test can assert whether any request reached the
    /// dispatch path. Dropping it stops and joins the accept thread.
    struct TestFederation {
        addr: SocketAddr,
        event_hub: EventHub,
        running: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        _api_tx: ApiRequestSender,
        api_rx: mpsc::UnboundedReceiver<ApiRequestMessage>,
    }

    impl Drop for TestFederation {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn peer_ctx(alias: &str, tier: CapabilityTier) -> PeerContext {
        PeerContext {
            alias: alias.into(),
            tier,
        }
    }

    /// One peer bound to `token` at `tier`, in the shape `spawn_federation_listener`
    /// expects.
    fn one_peer(token: &str, tier: CapabilityTier) -> Vec<(String, PeerContext)> {
        vec![(token.to_string(), peer_ctx("peer", tier))]
    }

    fn start_federation(peers: Vec<(String, PeerContext)>) -> TestFederation {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback federation listener");
        let addr = listener.local_addr().expect("federation listener addr");
        let (api_tx, api_rx) = mpsc::unbounded_channel();
        let event_hub = EventHub::default();
        let running = Arc::new(AtomicBool::new(true));
        let thread = spawn_federation_listener(
            listener,
            peers,
            api_tx.clone(),
            event_hub.clone(),
            None,
            Arc::clone(&running),
            None,
        )
        .expect("spawn federation listener");
        TestFederation {
            addr,
            event_hub,
            running,
            thread: Some(thread),
            _api_tx: api_tx,
            api_rx,
        }
    }

    fn tcp_client(addr: SocketAddr, token: Option<&str>) -> ApiClient {
        ApiClient::for_target(ConnectionTarget::Tcp {
            addr,
            token: token.map(str::to_owned),
        })
    }

    /// Open a raw federation connection and send `token`'s hello, returning the
    /// still-open stream so the caller can drive requests on it directly.
    fn raw_hello(addr: SocketAddr, token: &str) -> TcpStream {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let hello = FederationHello::new(token).to_line().unwrap();
        writeln!(stream, "{hello}").unwrap();
        stream.flush().unwrap();
        stream
    }

    fn send_request(stream: &mut TcpStream, id: &str, method: Method) {
        let encoded = serde_json::to_string(&Request {
            id: id.into(),
            method,
        })
        .unwrap();
        writeln!(stream, "{encoded}").unwrap();
        stream.flush().unwrap();
    }

    fn read_json_line(stream: &TcpStream) -> serde_json::Value {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response line");
        serde_json::from_str(&line).expect("response is json")
    }

    #[test]
    fn valid_token_round_trips_a_ping_over_tcp() {
        let fed = start_federation(one_peer("s3cret", CapabilityTier::Observe));
        let client = tcp_client(fed.addr, Some("s3cret"));

        let response = client
            .request_value(&Request {
                id: "fed_ping".into(),
                method: Method::Ping(PingParams::default()),
            })
            .expect("federation ping round-trips");

        assert_eq!(response["id"], "fed_ping");
        assert_eq!(response["result"]["type"], "pong");
    }

    #[test]
    fn wrong_token_is_rejected_and_never_dispatches() {
        let mut fed = start_federation(one_peer("right", CapabilityTier::Observe));

        // A bad hello is rejected before the connection handler ever reads a
        // request line, so nothing can reach the app dispatch path.
        let mut stream = TcpStream::connect(fed.addr).expect("connect");
        let hello = FederationHello::new("wrong").to_line().unwrap();
        writeln!(stream, "{hello}").unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read rejection line");
        let value: serde_json::Value = serde_json::from_str(&line).expect("rejection is json");
        assert_eq!(value["error"]["code"], "unauthorized");

        // The connection is closed right after the error line (clean EOF: the
        // whole hello was consumed, so there is no unread data to force an RST).
        let mut rest = String::new();
        assert_eq!(
            reader.read_line(&mut rest).expect("read after close"),
            0,
            "connection was not closed after the rejection"
        );

        // No request ever reached the app dispatch path.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            fed.api_rx.try_recv().is_err(),
            "a rejected connection dispatched a request"
        );
    }

    #[test]
    fn missing_hello_is_rejected() {
        let fed = start_federation(one_peer("right", CapabilityTier::Observe));

        // A request line where the hello is expected is not a hello.
        let mut stream = TcpStream::connect(fed.addr).expect("connect");
        writeln!(stream, r#"{{"id":"x","method":"ping","params":{{}}}}"#).unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read rejection line");
        let value: serde_json::Value = serde_json::from_str(&line).expect("rejection is json");
        assert_eq!(value["error"]["code"], "unauthorized");

        let mut rest = String::new();
        assert_eq!(
            reader.read_line(&mut rest).expect("read after close"),
            0,
            "connection was not closed after the missing-hello rejection"
        );
    }

    #[test]
    fn request_stream_yields_multiple_lines_then_terminates_on_close() {
        let fed = start_federation(one_peer("s3cret", CapabilityTier::Observe));
        let client = tcp_client(fed.addr, Some("s3cret"));

        let mut lines = client
            .request_stream(&Request {
                id: "fed_sub".into(),
                method: Method::EventsSubscribe(EventsSubscribeParams {
                    subscriptions: vec![Subscription::PaneClosed {}],
                }),
            })
            .expect("open subscription stream");

        // Line 1: the subscription ack.
        let ack = lines
            .next()
            .expect("subscription ack line")
            .expect("ack is io-ok");
        assert_eq!(ack["result"]["type"], "subscription_started");

        // Push a matching event; line 2 is that event.
        fed.event_hub.push(EventEnvelope {
            event: EventKind::PaneClosed,
            data: EventData::PaneClosed {
                pane_id: "pane_1".into(),
                workspace_id: "ws_1".into(),
            },
        });
        let event = lines
            .next()
            .expect("streamed event line")
            .expect("event is io-ok");
        assert_eq!(event["event"], "pane_closed");
        assert_eq!(event["data"]["pane_id"], "pane_1");

        // Shutting the server down closes the connection; the stream terminates.
        fed.running.store(false, Ordering::Relaxed);
        assert!(
            lines.next().is_none(),
            "stream did not terminate when the connection closed"
        );
    }

    #[test]
    fn empty_token_set_never_authorizes() {
        // A listener started with no tokens must reject even an empty-token hello
        // (the production bind path refuses to start such a listener at all).
        let fed = start_federation(Vec::new());
        let mut stream = TcpStream::connect(fed.addr).expect("connect");
        let hello = FederationHello::new("").to_line().unwrap();
        writeln!(stream, "{hello}").unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read rejection line");
        let value: serde_json::Value = serde_json::from_str(&line).expect("rejection is json");
        assert_eq!(value["error"]["code"], "unauthorized");
    }

    /// Poll the app channel briefly for a dispatched request, panicking if none
    /// arrives. Used to prove that a permitted federated method reached the
    /// dispatch path (as opposed to being gate-filtered).
    fn recv_dispatched(
        api_rx: &mut mpsc::UnboundedReceiver<ApiRequestMessage>,
    ) -> ApiRequestMessage {
        for _ in 0..200 {
            if let Ok(message) = api_rx.try_recv() {
                return message;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no request reached the app dispatch path within the timeout");
    }

    #[test]
    fn every_wire_method_resolves_to_a_deliberate_access() {
        use CapabilityTier::{Admin, Interact, Observe};
        use FederationAccess::{AllowedAt, Denied};

        // The complete, deliberate classification of every wire-reachable API
        // method. Default-deny means a method added to `Method` without a decision
        // here still resolves to `Denied` (safe), but this table is the audit of
        // exactly what federation exposes and must be updated whenever a method's
        // federation exposure changes.
        let expected: &[(&str, FederationAccess)] = &[
            ("ping", AllowedAt(Observe)),
            ("server.stop", Denied),
            ("server.live_handoff", Denied),
            ("server.reload_config", Denied),
            ("server.agent_manifests", Denied),
            ("server.reload_agent_manifests", Denied),
            ("notification.show", Denied),
            ("notifications.register_device", Denied),
            ("notifications.register_activity", Denied),
            ("notifications.unregister_activity", Denied),
            ("gram.send", Denied),
            ("gram.post", Denied),
            ("gram.list", Denied),
            ("gram.grab", Denied),
            ("gram.mark_read", Denied),
            ("gram.delete", Denied),
            ("gram.upload_chunk", Denied),
            ("gram.get_file", Denied),
            ("client.window_title.set", Denied),
            ("client.window_title.clear", Denied),
            ("session.snapshot", AllowedAt(Observe)),
            ("workspace.create", Denied),
            ("workspace.list", AllowedAt(Observe)),
            ("workspace.get", AllowedAt(Observe)),
            ("workspace.focus", Denied),
            ("workspace.rename", Denied),
            ("workspace.move", Denied),
            ("workspace.move_block", Denied),
            ("workspace.report_metadata", Denied),
            ("workspace.close", Denied),
            ("worktree.list", AllowedAt(Observe)),
            ("worktree.create", Denied),
            ("worktree.open", Denied),
            ("worktree.remove", Denied),
            ("tab.create", Denied),
            ("tab.list", AllowedAt(Observe)),
            ("tab.get", AllowedAt(Observe)),
            ("tab.focus", Denied),
            ("tab.rename", Denied),
            ("tab.move", Denied),
            ("tab.close", Denied),
            ("agent.list", AllowedAt(Observe)),
            ("agent.get", AllowedAt(Observe)),
            ("agent.read", AllowedAt(Observe)),
            ("agent.explain", AllowedAt(Observe)),
            ("agent.send_keys", AllowedAt(Interact)),
            ("agent.rename", AllowedAt(Admin)),
            ("agent.view.set", AllowedAt(Admin)),
            ("agent.view.clear", AllowedAt(Admin)),
            ("agent.focus", AllowedAt(Admin)),
            ("agent.start", Denied),
            ("agent.prompt", AllowedAt(Interact)),
            ("agent.wait", AllowedAt(Observe)),
            ("pane.split", Denied),
            ("pane.swap", Denied),
            ("pane.move", Denied),
            ("pane.zoom", Denied),
            ("pane.layout", Denied),
            ("pane.process_info", AllowedAt(Observe)),
            ("layout.export", AllowedAt(Observe)),
            ("layout.apply", Denied),
            ("layout.set_split_ratio", Denied),
            ("pane.neighbor", AllowedAt(Observe)),
            ("pane.edges", AllowedAt(Observe)),
            ("pane.focus_direction", Denied),
            ("pane.resize", Denied),
            ("pane.set_pty_size", Denied),
            ("pane.list", AllowedAt(Observe)),
            ("pane.current", AllowedAt(Observe)),
            ("pane.get", AllowedAt(Observe)),
            ("pane.turns", AllowedAt(Observe)),
            ("pane.focus", Denied),
            ("pane.input.set", AllowedAt(Admin)),
            ("pane.rename", AllowedAt(Admin)),
            ("pane.send_text", AllowedAt(Interact)),
            ("pane.send_keys", AllowedAt(Interact)),
            ("pane.send_input", AllowedAt(Admin)),
            ("pane.read", AllowedAt(Observe)),
            ("pane.graphics.set", Denied),
            ("pane.graphics.clear", Denied),
            ("pane.graphics.info", AllowedAt(Observe)),
            ("pane.graphics.stream", Denied),
            ("pane.stream", AllowedAt(Observe)),
            ("pane.input.stream", Denied),
            ("pane.report_agent", Denied),
            ("pane.report_agent_session", Denied),
            ("pane.report_metadata", Denied),
            ("pane.clear_agent_authority", Denied),
            ("pane.release_agent", Denied),
            ("pane.close", Denied),
            ("popup.close", Denied),
            ("events.subscribe", AllowedAt(Observe)),
            ("events.wait", AllowedAt(Observe)),
            ("pane.wait_for_output", AllowedAt(Observe)),
            ("integration.install", Denied),
            ("integration.uninstall", Denied),
            ("plugin.link", Denied),
            ("plugin.list", Denied),
            ("plugin.unlink", Denied),
            ("plugin.enable", Denied),
            ("plugin.disable", Denied),
            ("plugin.action.list", Denied),
            ("plugin.action.invoke", Denied),
            ("plugin.log.list", Denied),
            ("plugin.pane.open", Denied),
            ("plugin.pane.focus", Denied),
            ("plugin.pane.close", Denied),
        ];

        for (name, access) in expected {
            assert_eq!(
                federation_access(name),
                *access,
                "method {name} is mis-classified for federation"
            );
        }
        // Tripwire: this table must enumerate every wire method, so its size is
        // pinned. Adding a `Method` variant should come with a decision here.
        assert_eq!(
            expected.len(),
            107,
            "wire-method classification table drifted"
        );
    }

    #[test]
    fn observe_peer_allows_reads_and_denies_writes() {
        let mut fed = start_federation(one_peer("obs", CapabilityTier::Observe));

        // agent.list (observe) reaches the app dispatch path.
        let mut reader = raw_hello(fed.addr, "obs");
        send_request(&mut reader, "list", Method::AgentList(EmptyParams {}));
        let message = recv_dispatched(&mut fed.api_rx);
        assert!(matches!(message.request.method, Method::AgentList(_)));
        drop(message);
        drop(reader);

        // agent.prompt (interact) is above an observe peer's tier: forbidden.
        let mut prompt = raw_hello(fed.addr, "obs");
        send_request(
            &mut prompt,
            "prompt",
            Method::AgentPrompt(AgentPromptParams {
                target: "a".into(),
                text: "hi".into(),
                wait: None,
            }),
        );
        let resp = read_json_line(&prompt);
        assert_eq!(resp["error"]["code"], "forbidden");
        assert_eq!(resp["id"], "prompt");

        // Methods federation denies outright are forbidden at any tier.
        for (id, method) in [
            (
                "start",
                Method::AgentStart(AgentStartParams {
                    name: "n".into(),
                    kind: "k".into(),
                    pane_id: "p".into(),
                    args: vec![],
                    timeout_ms: None,
                }),
            ),
            ("stop", Method::ServerStop(EmptyParams {})),
            (
                "close",
                Method::PaneClose(PaneTarget {
                    pane_id: "p".into(),
                }),
            ),
        ] {
            let mut stream = raw_hello(fed.addr, "obs");
            send_request(&mut stream, id, method);
            assert_eq!(read_json_line(&stream)["error"]["code"], "forbidden");
        }

        // None of the forbidden calls reached the app dispatch path.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            fed.api_rx.try_recv().is_err(),
            "a forbidden federated call reached the dispatch path"
        );
    }

    #[test]
    fn interact_peer_allows_prompt_and_denies_admin() {
        let mut fed = start_federation(one_peer("act", CapabilityTier::Interact));

        // agent.prompt (interact) is dispatched for an interact peer.
        let mut stream = raw_hello(fed.addr, "act");
        send_request(
            &mut stream,
            "prompt",
            Method::AgentPrompt(AgentPromptParams {
                target: "a".into(),
                text: "hi".into(),
                wait: None,
            }),
        );
        let message = recv_dispatched(&mut fed.api_rx);
        assert!(matches!(message.request.method, Method::AgentPrompt(_)));
        drop(message);

        // agent.rename (admin) is above its tier: forbidden.
        let mut stream = raw_hello(fed.addr, "act");
        send_request(
            &mut stream,
            "rename",
            Method::AgentRename(AgentRenameParams {
                target: "a".into(),
                name: Some("n".into()),
            }),
        );
        assert_eq!(read_json_line(&stream)["error"]["code"], "forbidden");
    }

    #[test]
    fn admin_peer_allows_admin_methods() {
        let mut fed = start_federation(one_peer("adm", CapabilityTier::Admin));

        let mut stream = raw_hello(fed.addr, "adm");
        send_request(
            &mut stream,
            "rename",
            Method::AgentRename(AgentRenameParams {
                target: "a".into(),
                name: Some("n".into()),
            }),
        );
        let message = recv_dispatched(&mut fed.api_rx);
        assert!(matches!(message.request.method, Method::AgentRename(_)));
        drop(message);
    }

    #[test]
    fn two_peers_are_each_bound_to_their_own_tier() {
        let mut fed = start_federation(vec![
            (
                "obs-tok".into(),
                peer_ctx("observer", CapabilityTier::Observe),
            ),
            (
                "adm-tok".into(),
                peer_ctx("administrator", CapabilityTier::Admin),
            ),
        ]);

        // The observe peer's token cannot rename.
        let mut stream = raw_hello(fed.addr, "obs-tok");
        send_request(
            &mut stream,
            "r1",
            Method::AgentRename(AgentRenameParams {
                target: "a".into(),
                name: Some("n".into()),
            }),
        );
        assert_eq!(read_json_line(&stream)["error"]["code"], "forbidden");

        // The admin peer's token, over the same listener, can.
        let mut stream = raw_hello(fed.addr, "adm-tok");
        send_request(
            &mut stream,
            "r2",
            Method::AgentRename(AgentRenameParams {
                target: "a".into(),
                name: Some("n".into()),
            }),
        );
        let message = recv_dispatched(&mut fed.api_rx);
        assert!(matches!(message.request.method, Method::AgentRename(_)));
        drop(message);
    }

    #[test]
    fn proto_version_mismatch_is_rejected_and_a_match_proceeds() {
        let fed = start_federation(one_peer("tok", CapabilityTier::Observe));

        // A hello the daemon does not speak is rejected with a distinct code and
        // never dispatches.
        let mut stream = TcpStream::connect(fed.addr).expect("connect");
        let mut hello = FederationHello::new("tok");
        hello.proto_version = FEDERATION_PROTOCOL_VERSION + 1;
        writeln!(stream, "{}", hello.to_line().unwrap()).unwrap();
        stream.flush().unwrap();
        let resp = read_json_line(&stream);
        assert_eq!(resp["error"]["code"], "federation_protocol_mismatch");

        // The matching version with a valid token proceeds to a pong.
        let client = tcp_client(fed.addr, Some("tok"));
        let response = client
            .request_value(&Request {
                id: "v_ok".into(),
                method: Method::Ping(PingParams::default()),
            })
            .expect("ping round-trips at the negotiated version");
        assert_eq!(response["result"]["type"], "pong");
    }

    #[test]
    fn connection_cap_refuses_beyond_max_and_releases_on_close() {
        use std::io::Read as _;

        let fed = start_federation(one_peer("tok", CapabilityTier::Observe));

        // Fill every slot. A slot is reserved as soon as the accept loop spawns
        // the handler, so these connections occupy the cap while their handlers
        // wait (indefinitely, within the handshake timeout) for a hello.
        let mut held: Vec<TcpStream> = Vec::new();
        for _ in 0..MAX_FEDERATION_CONNECTIONS {
            held.push(TcpStream::connect(fed.addr).expect("connect"));
        }
        // Let the accept loop take and count all of them.
        std::thread::sleep(Duration::from_millis(400));

        // The next connection is over the cap: the listener accepts then closes it
        // without writing a byte, so the client reads a clean EOF.
        let mut over = TcpStream::connect(fed.addr).expect("connect");
        over.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 1];
        assert!(
            matches!(over.read(&mut buf), Ok(0)),
            "a connection over the cap was not refused and closed"
        );

        // Closing one in-flight connection frees a slot; a fresh connection then
        // completes a full authenticated ping.
        held.pop();
        std::thread::sleep(Duration::from_millis(500));
        let client = tcp_client(fed.addr, Some("tok"));
        let response = client
            .request_value(&Request {
                id: "after_release".into(),
                method: Method::Ping(PingParams::default()),
            })
            .expect("a slot freed up after a connection closed");
        assert_eq!(response["result"]["type"], "pong");
    }

    #[test]
    fn accept_loop_treats_transient_errors_as_retryable() {
        // The federation listener must never die on a transient accept error;
        // only `WouldBlock` is the idle signal, everything else is retried.
        assert_eq!(
            classify_accept_error(&io::Error::from(io::ErrorKind::WouldBlock)),
            AcceptBackoff::Idle
        );
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
        ] {
            assert_eq!(
                classify_accept_error(&io::Error::from(kind)),
                AcceptBackoff::Retry,
                "{kind:?} should be retried, not fatal"
            );
        }
    }
}
