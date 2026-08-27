use std::collections::HashMap;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use interprocess::local_socket::traits::ListenerExt as _;
use tracing::{debug, error, info, warn};

#[cfg(all(test, unix))]
use std::fs;

use crate::api::client::{
    endpoint_to_target, parse_response_value, ApiClient, ApiClientError, ConnectionTarget,
    ProxyError, FEDERATION_STREAM_IDLE_TIMEOUT,
};
use crate::api::federation::{
    authorized_peer, federation_access, FederationAccess, FederationHello, PeerContext,
    FEDERATION_PROTOCOL_VERSION,
};
use crate::api::federation_manager::FederationPeerManager;
use crate::api::federation_store::{
    FederationStore, PeerCacheEntry, Reachability, ReachabilityTracker,
};
use crate::api::schema::{
    ErrorBody, ErrorResponse, Method, PaneStreamParams, Request, ResponseResult,
    ServerCapabilities, SuccessResponse,
};
use crate::api::subscriptions::ActiveSubscription;
use crate::api::wait::{prompt_agent, wait_for_agent, wait_for_event, wait_for_output};
use crate::api::{
    request_changes_ui, socket_path, ApiRequestMessage, ApiRequestSender, ApiStream, ApiStreamRead,
    EventHub,
};
use crate::config::{FederationConfig, FederationPeer};
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
/// How often each configured peer is polled for its agent list.
const FEDERATION_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Granularity at which the poll sleep re-checks `running`, so a shutdown is not
/// held up for a whole poll interval.
const FEDERATION_POLL_STEP: Duration = Duration::from_millis(100);
/// Total wall-clock bound on an outbound `agent.list` poll's response read —
/// bounds a stuck peer. Unlike a per-read socket timeout, this caps the WHOLE
/// read, so a peer that trickles bytes just under the socket timeout without ever
/// sending a newline cannot keep the read (and shutdown, which joins the poll
/// threads) running forever.
const FEDERATION_POLL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Byte cap on a single outbound federation poll response. Mirrors the inbound
/// [`MAX_INITIAL_REQUEST_BYTES`] cap: an `agent.list` reply is small, so 1 MiB is
/// generous, and a (malicious or faulty) peer returning a larger line is degraded
/// rather than allowed to drive unbounded allocation — an OOM — on the polling
/// home daemon.
const FEDERATION_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Upper bound on the randomized backoff added after a failed poll.
const FEDERATION_POLL_MAX_JITTER: Duration = Duration::from_secs(2);
/// Total wall-clock bound on a single proxied federation request's response read.
/// Generous enough for a waited `agent.prompt` that blocks on the peer until the
/// remote agent reaches a status (matching the local agent-start ceiling), yet
/// finite so a silently-stalled peer cannot leak the connection thread forever.
/// The proxy runs on the per-connection thread — never the single-threaded app
/// loop — so blocking here for the duration is safe; the byte cap, this deadline,
/// and the `running` flag together keep a malicious or faulty peer from OOMing or
/// hanging the home.
const FEDERATION_PROXY_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Per-frame byte cap for a proxied federated `pane.stream`. The pane output ring
/// frames at ~64 KiB, so the 1 MiB [`FEDERATION_MAX_RESPONSE_BYTES`] scale is
/// generous; a peer sending a single frame larger than this degrades that stream
/// (it is closed) rather than driving unbounded allocation — an OOM — on the home.
/// The idle-timeout companion is [`FEDERATION_STREAM_IDLE_TIMEOUT`].
const FEDERATION_MAX_STREAM_FRAME_BYTES: usize = FEDERATION_MAX_RESPONSE_BYTES;

pub struct ServerHandle {
    _thread: JoinHandle<()>,
    /// Federation TCP accept thread, joined on drop. `None` when federation is
    /// not listening.
    federation_thread: Option<JoinHandle<()>>,
    /// Manager for the outbound federation peer set — one poll thread per peer
    /// with an `endpoint`, plus the outbound proxy registry. Shared with the
    /// `App` so `reload-config` can add/remove/change peers live. Drives zero
    /// threads and an empty registry when no peer has an endpoint (the
    /// byte-identical no-federation path). Joined on drop via `join_all`.
    federation_manager: Arc<FederationPeerManager>,
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

        // Outbound poll threads observe the cleared `running` between their short
        // sleep increments; a mid-flight poll is bounded by the request timeout,
        // so joining them here returns promptly. `join_all` also drains any
        // threads still being retired by a concurrent reconcile.
        self.federation_manager.join_all();

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

    /// The shared outbound federation peer manager. Handed to the `App` so its
    /// `reload-config` handler can reconcile the peer set live against the same
    /// manager this server boot-spawned and reads on the hot proxy path.
    pub fn federation_manager(&self) -> Arc<FederationPeerManager> {
        Arc::clone(&self.federation_manager)
    }
}

pub(crate) fn start_server_with_stop_control(
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    server_stop: Arc<AtomicBool>,
    federation: &FederationConfig,
    federation_store: Arc<Mutex<FederationStore>>,
) -> std::io::Result<ServerHandle> {
    start_server_inner(
        api_tx,
        event_hub,
        default_capabilities(),
        Some(server_stop),
        federation,
        federation_store,
    )
}

pub fn start_server_with_capabilities(
    api_tx: ApiRequestSender,
    event_hub: EventHub,
    capabilities: Option<ServerCapabilities>,
    federation: &FederationConfig,
    federation_store: Arc<Mutex<FederationStore>>,
) -> std::io::Result<ServerHandle> {
    start_server_inner(
        api_tx,
        event_hub,
        capabilities,
        None,
        federation,
        federation_store,
    )
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
    federation_store: Arc<Mutex<FederationStore>>,
) -> std::io::Result<ServerHandle> {
    let path = socket_path();
    prepare_socket_path(&path)?;

    let listener = bind_local_listener(&path)?;
    restrict_socket_permissions(&path)?;
    let identity = socket_file_identity(&path)?;
    info!(path = %path.display(), "api server listening");

    let running = Arc::new(AtomicBool::new(true));

    // Outbound federation peer manager: owns the per-peer poll threads and the
    // alias→target proxy registry (W4). Boot-spawns the configured peer set from
    // empty; when no peer has an `endpoint` this spawns zero threads and leaves
    // an empty registry, so the router never matches and local behavior is
    // byte-identical. Shared (as an `Arc`) with the `App` so `reload-config` can
    // add/remove/change peers live.
    let federation_manager =
        FederationPeerManager::new(Arc::clone(&federation_store), Arc::clone(&running));
    federation_manager.reconcile(&federation.peers);

    let listener_running = Arc::clone(&running);
    let listener_api_tx = api_tx.clone();
    let listener_event_hub = event_hub.clone();
    let listener_capabilities = capabilities.clone();
    let listener_server_stop = server_stop.clone();
    let listener_federation_manager = Arc::clone(&federation_manager);
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let api_tx = listener_api_tx.clone();
                    let event_hub = listener_event_hub.clone();
                    let capabilities = listener_capabilities.clone();
                    let server_stop = listener_server_stop.clone();
                    let connection_running = Arc::clone(&listener_running);
                    let federation_manager = Arc::clone(&listener_federation_manager);
                    std::thread::spawn(move || {
                        // Snapshot the outbound proxy registry per connection so a
                        // concurrent reconcile (add/remove/change peer) is picked
                        // up without restarting the accept loop.
                        let federation_peers = federation_manager.registry_snapshot();
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
                            &federation_peers,
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
    // NB: the federation-inbound listener is deliberately NOT given the outbound
    // `federation_peers` registry. The home drives its OWN peers from local
    // clients only; an inbound peer must never be able to relay through the home
    // to its other peers (a confused-deputy trust expansion). Keeping the
    // registry out of this chain makes that unreachable by construction.
    let federation_thread = maybe_start_federation_listener(
        federation,
        &api_tx,
        &event_hub,
        &capabilities,
        &running,
        &server_stop,
    );

    // Outbound side is owned by `federation_manager`, boot-spawned above via
    // `reconcile(&federation.peers)` from an empty set. When no peer has an
    // `endpoint` this drove zero threads and an empty registry, so the local
    // `agent.list` path is unchanged.

    Ok(ServerHandle {
        _thread: thread,
        federation_thread,
        federation_manager,
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
                            expected_node_id: peer.expected_node_id.clone(),
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
#[allow(clippy::too_many_arguments)]
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

/// Poll one peer forever, updating `cache` after each attempt. Resolves the
/// endpoint and token once up front; a bad endpoint logs and exits the thread
/// rather than spinning.
///
/// The thread runs until EITHER the global `running` flag clears (daemon
/// shutdown) OR this peer's own `peer_stop` flag is set (the manager retiring
/// this peer on a `reload-config` reconcile). `peer_stop` is per-peer so one
/// removed peer can be stopped without disturbing the others.
pub(crate) fn run_federation_peer_poll(
    peer: FederationPeer,
    cache: Arc<Mutex<FederationStore>>,
    running: Arc<AtomicBool>,
    peer_stop: Arc<AtomicBool>,
) {
    let Some(endpoint) = peer.endpoint.as_deref() else {
        return; // guarded by the caller; keeps the thread body self-contained
    };
    let token = read_peer_token(&peer);
    let target = match endpoint_to_target(endpoint, token) {
        Ok(target) => target,
        Err(err) => {
            warn!(alias = %peer.alias, endpoint = %endpoint, err = %err, "invalid federation endpoint; peer poll not started");
            return;
        }
    };
    let client = ApiClient::for_target(target);
    let mut tracker = ReachabilityTracker::default();

    while running.load(Ordering::Relaxed) && !peer_stop.load(Ordering::Relaxed) {
        let reachability = poll_once_into_cache(
            &client,
            &peer.alias,
            &cache,
            &mut tracker,
            &running,
            &peer_stop,
        );
        let interval = if reachability == Reachability::Reachable {
            FEDERATION_POLL_INTERVAL
        } else {
            failure_backoff(FEDERATION_POLL_INTERVAL)
        };
        sleep_interruptible(&running, &peer_stop, interval);
    }
    debug!(alias = %peer.alias, "federation peer poll thread exiting");
}

/// Run one poll of `client`'s `agent.list` and fold the result into `cache`:
/// on success, alias-prefix the agents and store them `Reachable`; on failure,
/// advance the miss tracker and degrade the peer (retaining last-known agents)
/// without dropping the entry. Returns the resulting reachability so the caller
/// can pick its next sleep. Factored out of the poll loop so the miss→degrade→
/// unreachable path is testable without waiting on real poll intervals.
fn poll_once_into_cache(
    client: &ApiClient,
    alias: &str,
    cache: &Mutex<FederationStore>,
    tracker: &mut ReachabilityTracker,
    running: &Arc<AtomicBool>,
    peer_stop: &Arc<AtomicBool>,
) -> Reachability {
    match poll_peer_agent_list(client, running) {
        Ok(agents) => {
            let prefixed = agents
                .into_iter()
                .map(|agent| prefix_remote_agent(alias, agent))
                .collect();
            let reachability = tracker.record_success();
            let mut store = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Race guard for a changed peer: the manager sets this peer's
            // `peer_stop` AND evicts the alias while holding this same store
            // Mutex, so checking `peer_stop` here — WHILE HOLDING the lock, just
            // before the write — serializes a retiring thread against the
            // reconcile. If stop is set, skip the write so a stale entry can
            // never reappear after the alias was evicted (or be overwritten by
            // the newly spawned thread for the same alias). The store Mutex is
            // the happens-before edge between the two, so `Relaxed` is correct.
            if peer_stop.load(Ordering::Relaxed) {
                return reachability;
            }
            store.set_peer(
                alias.to_string(),
                PeerCacheEntry::reachable(prefixed, Instant::now()),
            );
            reachability
        }
        Err(err) => {
            let reachability = tracker.record_miss();
            warn!(alias = %alias, err = %err, ?reachability, "federation peer poll failed");
            let mut store = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Same under-lock stop guard as the success arm: never degrade an
            // alias the reconcile has already evicted (the Mutex is the
            // happens-before edge, so `Relaxed` is correct).
            if peer_stop.load(Ordering::Relaxed) {
                return reachability;
            }
            store.degrade_peer(alias, reachability);
            reachability
        }
    }
}

/// Read a peer's shared token from its `token_file`, trimmed. Mirrors the inbound
/// [`resolve_federation_tokens`] read logic. `None` when there is no token file
/// or it is unreadable/empty; the outbound connection then sends no
/// `federation.hello` credential.
fn read_peer_token(peer: &FederationPeer) -> Option<String> {
    let path = peer.token_file.as_deref()?;
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let token = contents.trim();
            if token.is_empty() {
                warn!(path = %path, alias = %peer.alias, "federation peer token file is empty; polling without a token");
                None
            } else {
                Some(token.to_string())
            }
        }
        Err(err) => {
            warn!(path = %path, alias = %peer.alias, err = %err, "failed to read federation peer token file; polling without a token");
            None
        }
    }
}

/// Build the alias→[`ConnectionTarget`] registry the outbound proxy router (W4)
/// uses, from every configured peer that has an `endpoint`. Reuses
/// [`read_peer_token`] + [`endpoint_to_target`], exactly mirroring the poll
/// client's resolution, so an alias reachable for polling is reachable for
/// proxying. A peer with no endpoint, or whose endpoint fails to parse, is skipped
/// (the latter logged). When no peer has a usable endpoint the map is empty — the
/// router then never matches and local behavior is byte-identical.
pub(crate) fn build_peer_registry(peers: &[FederationPeer]) -> HashMap<String, ConnectionTarget> {
    let mut registry = HashMap::new();
    for peer in peers {
        let Some(endpoint) = peer.endpoint.as_deref() else {
            continue;
        };
        let token = read_peer_token(peer);
        match endpoint_to_target(endpoint, token) {
            Ok(target) => {
                registry.insert(peer.alias.clone(), target);
            }
            Err(err) => {
                warn!(
                    alias = %peer.alias,
                    endpoint = %endpoint,
                    err = %err,
                    "invalid federation endpoint; peer not routable for proxying"
                );
            }
        }
    }
    registry
}

/// Poll one peer's `agent.list` and return its agents. A transport error, a
/// timeout, an error response, or an unexpected result all surface as `Err` and
/// count as a miss.
///
/// The response read is BOTH byte-bounded ([`FEDERATION_MAX_RESPONSE_BYTES`]) and
/// total-time-bounded ([`FEDERATION_POLL_REQUEST_TIMEOUT`], a wall-clock deadline)
/// so a malicious peer cannot drive unbounded allocation or an unbounded-time
/// read; `running` lets the read abort promptly on shutdown so [`ServerHandle`]'s
/// drop, which joins the poll threads, does not hang.
fn poll_peer_agent_list(
    client: &ApiClient,
    running: &Arc<AtomicBool>,
) -> Result<Vec<crate::api::schema::AgentInfo>, ApiClientError> {
    let request = Request {
        id: "federation:agent.list".into(),
        method: Method::AgentList(crate::api::schema::EmptyParams {}),
    };
    let value = client.request_value_bounded(
        &request,
        FEDERATION_MAX_RESPONSE_BYTES,
        FEDERATION_POLL_REQUEST_TIMEOUT,
        Some(running),
    )?;
    let response = parse_response_value(value)?;
    match response.result {
        ResponseResult::AgentList { agents } => Ok(agents),
        other => Err(ApiClientError::UnexpectedResult(format!("{other:?}"))),
    }
}

/// Rewrite a remote agent's identity fields so it is unambiguous once merged into
/// the local `agent.list`: `name` and all four id fields gain an `<alias>/`
/// prefix, and `machine_id` records the peer alias.
///
/// The home OWNS the federation-derived fields and must never trust what the peer
/// put in the [`AgentInfo`](crate::api::schema::AgentInfo) it returned: a
/// malicious peer could set `machine_id`/`reachability`/`last_known_status` to
/// forge a live status or a false origin. So `machine_id` is overwritten with the
/// peer's local alias and `reachability`/`last_known_status` are cleared here. The
/// read helper [`FederationStore::merged_agents`] is the ONLY thing that sets
/// `reachability`/`last_known_status`, from the home's own poll-outcome tracking.
fn prefix_remote_agent(
    alias: &str,
    mut agent: crate::api::schema::AgentInfo,
) -> crate::api::schema::AgentInfo {
    agent.name = Some(format!("{alias}/{}", agent.name.unwrap_or_default()));
    agent.terminal_id = format!("{alias}/{}", agent.terminal_id);
    agent.workspace_id = format!("{alias}/{}", agent.workspace_id);
    agent.tab_id = format!("{alias}/{}", agent.tab_id);
    agent.pane_id = format!("{alias}/{}", agent.pane_id);
    // Home-owned federation fields: normalize `machine_id` to the peer's local
    // alias and discard any peer-supplied reachability/last-known status.
    agent.machine_id = Some(alias.to_string());
    agent.reachability = None;
    agent.last_known_status = None;
    agent
}

/// Sleep up to `total`, waking every [`FEDERATION_POLL_STEP`] to re-check the
/// stop flags, so neither a shutdown nor a `reload-config` peer retirement is
/// delayed by the poll interval. Returns early the moment EITHER `running`
/// clears (daemon shutdown) OR `peer_stop` is set (this peer removed/changed).
fn sleep_interruptible(running: &Arc<AtomicBool>, peer_stop: &Arc<AtomicBool>, total: Duration) {
    let mut elapsed = Duration::ZERO;
    while elapsed < total {
        if !running.load(Ordering::Relaxed) || peer_stop.load(Ordering::Relaxed) {
            return;
        }
        let step = FEDERATION_POLL_STEP.min(total - elapsed);
        std::thread::sleep(step);
        elapsed += step;
    }
}

/// Base poll interval plus a small randomized jitter, so peers that fail at the
/// same time do not retry in lockstep. Jitter is a cheap wall-clock-derived
/// value — no RNG dependency — capped at [`FEDERATION_POLL_MAX_JITTER`].
fn failure_backoff(base: Duration) -> Duration {
    let entropy = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::from(since.subsec_nanos()))
        .unwrap_or(0);
    let cap = FEDERATION_POLL_MAX_JITTER
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let jitter = if cap == 0 { 0 } else { entropy % cap };
    base + Duration::from_nanos(jitter)
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
#[allow(clippy::too_many_arguments)]
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

    // Optional identity pin: when this peer is configured with an
    // `expected_node_id`, the install id presented in the hello must match it.
    // The token stays the authenticator; this only ADDS a bind when configured
    // (a peer with no pin is unaffected). Reuse the same opaque unauthorized line
    // as a token failure so a mismatch never reveals which check failed, and
    // reject here — before any request is dispatched.
    if let Some(expected) = peer.expected_node_id.as_deref() {
        if hello.machine_id != expected {
            write_json_line_allow_disconnect(&mut stream, &federation_unauthorized_error())?;
            return Ok(());
        }
    }

    // A federation-INBOUND connection must never drive the home's OWN outbound
    // peer routing. The home drives its peers; it does not RELAY an inbound peer
    // through to its other peers. If the inbound registry were passed here, an
    // inbound peer sending `<other-alias>/…` would be transit-proxied to that
    // other peer using the HOME's credentials/tier — a confused deputy that
    // expands the inbound peer's trust to peers it has no relationship with.
    // Pass an empty registry so `maybe_route_to_peer` never matches on this
    // path and a `<alias>/…` target falls through to a local not-found. This
    // single choke point also keeps the pane.stream proxy inbound-safe, since it
    // reads the same registry.
    let no_outbound_routing: HashMap<String, ConnectionTarget> = HashMap::new();
    handle_connection_with_stop(
        stream,
        api_tx,
        event_hub,
        running,
        capabilities,
        server_stop,
        Some(peer),
        &no_outbound_routing,
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
        &HashMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_connection_with_stop(
    mut stream: ApiStream,
    api_tx: &ApiRequestSender,
    event_hub: &EventHub,
    running: &Arc<AtomicBool>,
    capabilities: Option<ServerCapabilities>,
    server_stop: Option<&Arc<AtomicBool>>,
    federation: Option<PeerContext>,
    federation_peers: &HashMap<String, ConnectionTarget>,
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

    let mut request = match serde_json::from_str::<Request>(line) {
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

    // Federation outbound router (W4). BEFORE the local dispatch match — so it
    // covers both the early-match methods (e.g. `agent.prompt`) and the catch-all
    // methods uniformly — a request whose target names a configured peer
    // (`<alias>/…`) is proxied out to that peer and the peer's REAL response is
    // returned verbatim; the local app is never touched. With no configured peer
    // endpoints the registry is empty, this never matches, and behavior is
    // byte-identical to a non-federated daemon.
    if let Some(result) = maybe_route_to_peer(
        &mut stream,
        &mut request,
        federation_peers,
        running,
        &request_id,
        method,
        changes_ui,
    ) {
        return result;
    }

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
        Method::PaneStream(mut params) => {
            // W5: a `pane.stream` whose target is `<alias>/<remote-pane-id>` names a
            // configured federation peer's agent, so proxy it to that peer and pipe
            // its live-terminal frames back on THIS connection thread — never the
            // single-threaded app loop, and never through the local OutputRing. The
            // outbound W4 router (`maybe_route_to_peer`) skips `pane.stream` on
            // purpose, so this is the only place a federated stream is handled. With
            // no configured peers (or the empty registry the federation-inbound path
            // passes) `federated_stream_target` never matches and the local
            // `pane_output_stream::serve` runs byte-identically to today.
            let result = if let Some((alias, rest, peer_target)) =
                federated_stream_target(&params.pane_id, federation_peers)
            {
                // Strip the `<alias>/` prefix so the peer sees its own local pane id;
                // every other client parameter is forwarded unchanged.
                params.pane_id = rest;
                proxy_federated_pane_stream(
                    stream,
                    request_id.clone(),
                    &alias,
                    params,
                    peer_target,
                    running,
                )
            } else {
                pane_output_stream::serve(stream, request_id.clone(), params, api_tx, running)
            };
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

/// For a method whose target can name a federated remote agent, a mutable
/// reference to that target string; `None` for every other method. The agent
/// methods carry it in `target`; the pane read/turns and pane send-text/send-input
/// methods carry it in `pane_id` (W3 alias-prefixes every identity field, `pane_id`
/// included). This is the exact set the outbound router may proxy — everything else
/// falls through to local dispatch unchanged. `pane.send_text`/`pane.send_input`
/// are the write path the app uses for a federated pane's keystrokes (control keys
/// like S-Tab, `^C`, and Ctrl-chords); both are already `AllowedAt` on the inbound
/// (peer) side, so routing them completes the send symmetry with `agent.send_keys`.
fn routable_target_mut(method: &mut Method) -> Option<&mut String> {
    match method {
        Method::AgentPrompt(params) => Some(&mut params.target),
        Method::AgentSendKeys(params) => Some(&mut params.target),
        Method::AgentGet(params) => Some(&mut params.target),
        Method::AgentRead(params) => Some(&mut params.target),
        Method::AgentExplain(params) => Some(&mut params.target),
        // `agent.restart` routes to the owning peer so a federated `<alias>/pane`
        // agent can be restarted from home; the resume runs where the process is.
        Method::AgentRestart(params) => Some(&mut params.target),
        Method::PaneRead(params) => Some(&mut params.pane_id),
        Method::PaneTurns(params) => Some(&mut params.pane_id),
        Method::PaneSendText(params) => Some(&mut params.pane_id),
        Method::PaneSendInput(params) => Some(&mut params.pane_id),
        // `pane.set_pty_size` carries the target in `pane_id` too (an
        // `Option<String>`); a `None`/current-pane resize stays local, while a
        // federated `<alias>/pane` routes to the owning peer, where the width
        // arbiter runs (#137).
        Method::PaneSetPtySize(params) => params.pane_id.as_mut(),
        _ => None,
    }
}

/// Split a target into `(alias, rest)` when it is federated: it must contain a
/// `/` and its first segment must be a configured peer alias. Local ids/names
/// never contain `/` and never equal a configured alias (W3), and a `w1:p1`-style
/// local id has no `/` either — so neither routes. Returns `None` (fall through to
/// local dispatch) for every non-federated target.
fn federated_split<'a>(
    target: &'a str,
    peers: &HashMap<String, ConnectionTarget>,
) -> Option<(&'a str, &'a str)> {
    let (alias, rest) = target.split_once('/')?;
    if peers.contains_key(alias) {
        Some((alias, rest))
    } else {
        None
    }
}

/// If `request` targets a configured federation peer (`<alias>/…`), proxy it to
/// that peer and return `Some(result)` — the connection is fully handled, the
/// peer's real response already written back. Returns `None` when the request is
/// not federated so the caller dispatches it locally, unchanged.
///
/// On a match the `<alias>/` prefix is stripped from the target before the
/// request is forwarded (the peer knows its agents by their local ids), and the
/// request's own id is preserved so the peer echoes it and the originating client
/// correlates the reply. Owns the completed/failed request logging for the
/// proxied path.
fn maybe_route_to_peer(
    stream: &mut ApiStream,
    request: &mut Request,
    peers: &HashMap<String, ConnectionTarget>,
    running: &Arc<AtomicBool>,
    request_id: &str,
    method: &'static str,
    changes_ui: bool,
) -> Option<std::io::Result<()>> {
    // Empty registry (the default-off, no-endpoint case) → never route.
    if peers.is_empty() {
        return None;
    }
    let target = routable_target_mut(&mut request.method)?;
    // Decide from owned copies so the mutable borrow is free for the rewrite.
    let (alias, rest) = {
        let (alias, rest) = federated_split(target, peers)?;
        (alias.to_string(), rest.to_string())
    };
    let peer_target = peers.get(&alias)?.clone();
    // Federated: strip the `<alias>/` prefix so the peer sees its own local id.
    *target = rest;

    let client = ApiClient::for_target(peer_target);
    let response = proxy_federated_response(&client, request, running);
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
    Some(result)
}

/// Forward `request` to the peer reached by `client` and return the response LINE
/// to write back to the originating client.
///
/// Verdict truth: on success the peer's real response is passed through verbatim —
/// the peer's `AgentPrompted { delivery }`, its `Ok {}`, or a `forbidden` it
/// raised from its OWN capability allowlist all reach the caller unchanged; the
/// home applies no capability logic of its own. Failure is classified by phase:
///
/// - a connect/write failure (the request never left the home) → `peer_unreachable`;
/// - a response-read failure AFTER the write (EOF, timeout, oversized, empty) →
///   `delivery_unknown`, because the peer may or may not have acted — and the home
///   NEVER auto-retries, so a write that did land is not duplicated.
fn proxy_federated_response(
    client: &ApiClient,
    request: &Request,
    running: &Arc<AtomicBool>,
) -> String {
    match client.proxy_request_bounded(
        request,
        FEDERATION_MAX_RESPONSE_BYTES,
        FEDERATION_PROXY_REQUEST_TIMEOUT,
        Some(running),
    ) {
        Ok(line) => line,
        Err(ProxyError::Connect(err)) => {
            warn!(id = %request.id, err = %err, "federation proxy could not reach peer");
            error_response_json(
                request.id.clone(),
                "peer_unreachable",
                format!("could not reach federation peer: {err}"),
            )
        }
        Err(ProxyError::Read(err)) => {
            warn!(
                id = %request.id,
                err = %err,
                "federation proxy: response read failed after the request was delivered"
            );
            error_response_json(
                request.id.clone(),
                "delivery_unknown",
                format!(
                    "request was delivered to the federation peer but its response could not be read: {err}"
                ),
            )
        }
    }
}

/// Resolve a `pane.stream` target into `(alias, peer-pane-id, peer connection)`
/// when it names a configured federation peer (`<alias>/<pane-id>`), owning the
/// alias/pane-id so the borrow of `params.pane_id` is released before it is
/// rewritten. Returns `None` — fall through to the LOCAL `pane_output_stream`
/// path — for every non-federated target (no `/`, or an unknown/empty alias). The
/// `peers.get` cannot miss after a [`federated_split`] match, so this never panics.
fn federated_stream_target(
    pane_id: &str,
    peers: &HashMap<String, ConnectionTarget>,
) -> Option<(String, String, ConnectionTarget)> {
    let (alias, rest) = federated_split(pane_id, peers)?;
    let target = peers.get(alias)?.clone();
    Some((alias.to_string(), rest.to_string(), target))
}

/// Proxy a federated `pane.stream` to the owning peer and pipe its NDJSON frames
/// back to the requesting client, on the per-connection thread.
///
/// `params.pane_id` is already the peer's LOCAL pane id (the `<alias>/` prefix was
/// stripped by the caller); `alias` is re-applied only to the `stream_started`
/// ack's `pane_id` so the client keeps seeing the federated identity. The client's
/// request id is preserved on the forwarded request so the peer echoes it.
///
/// Phases: (1) connect + write — a failure here means the request never reached
/// the peer, so a `peer_unreachable` line is returned; (2) read the first line —
/// re-prefix and forward a `stream_started` ack, or forward a peer error
/// (`forbidden` from its allowlist, `pane_not_found`) VERBATIM and end, the peer's
/// allowlist staying authoritative with no home-side capability logic; (3) pipe
/// every subsequent frame verbatim until the peer/pane ends, the client drops, or
/// `running` clears. On EVERY exit path the peer stream is dropped, so no orphan
/// stream is left running on the peer.
fn proxy_federated_pane_stream(
    mut client_stream: ApiStream,
    request_id: String,
    alias: &str,
    params: PaneStreamParams,
    peer_target: ConnectionTarget,
    running: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let client = ApiClient::for_target(peer_target);
    let request = Request {
        id: request_id.clone(),
        method: Method::PaneStream(params),
    };

    // Phase 1: connect + write. A connect/write failure never reached the peer.
    let mut peer_stream = match client.open_frame_stream(&request) {
        Ok(peer_stream) => peer_stream,
        Err(err) => {
            warn!(
                id = %request_id,
                alias,
                err = %err,
                "federated pane.stream could not reach peer"
            );
            let response = error_response_json(
                request_id,
                "peer_unreachable",
                format!("could not reach federation peer: {err}"),
            );
            return write_text_line_allow_disconnect(&mut client_stream, &response);
        }
    };

    // Phase 2: the first line is the peer's `stream_started` ack or an error line.
    let first = match peer_stream.next_frame(
        FEDERATION_MAX_STREAM_FRAME_BYTES,
        FEDERATION_STREAM_IDLE_TIMEOUT,
        running,
    ) {
        Ok(Some(first)) => first,
        Ok(None) => {
            // Peer closed before answering: it may or may not have opened a stream,
            // so this is delivery-unknown, not a clean not-found.
            let response = error_response_json(
                request_id,
                "delivery_unknown",
                "federation peer closed the pane stream before it started".into(),
            );
            return write_text_line_allow_disconnect(&mut client_stream, &response);
        }
        Err(err) => {
            warn!(
                id = %request_id,
                alias,
                err = %err,
                "federated pane.stream: reading the peer stream_started failed"
            );
            let response = error_response_json(
                request_id,
                "delivery_unknown",
                format!("federation peer pane stream could not be read: {err}"),
            );
            return write_text_line_allow_disconnect(&mut client_stream, &response);
        }
    };

    // Re-prefix a `stream_started` ack's pane_id back to `<alias>/…`; forward a peer
    // error verbatim. `keep_streaming` is false for anything but a real ack, so a
    // peer error ends the proxy after this single line.
    let (first_line, keep_streaming) = prepare_first_stream_line(&first, alias);
    if !emit_line_to_client(&mut client_stream, &first_line)? || !keep_streaming {
        // Client dropped, or the peer's first line was an error/terminal: done.
        // `peer_stream` drops here, tearing the peer connection down.
        return Ok(());
    }

    // Phase 3: pipe every subsequent frame verbatim. Read-one / write-one: a slow
    // client blocks the write, which blocks the read, so the peer's OutputRing (and
    // its snapshot-collapse) absorbs backpressure — the home buffers nothing.
    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        match peer_stream.next_frame(
            FEDERATION_MAX_STREAM_FRAME_BYTES,
            FEDERATION_STREAM_IDLE_TIMEOUT,
            running,
        ) {
            Ok(Some(frame)) => {
                if !emit_line_to_client(&mut client_stream, &frame)? {
                    break; // client dropped
                }
            }
            Ok(None) => break, // peer/pane ended (sent `exited` then closed)
            Err(err) => {
                // Idle timeout, over-cap frame, transport error, or shutdown: close
                // the proxied stream. Shutdown (`Interrupted`) is expected and quiet.
                if err.kind() != std::io::ErrorKind::Interrupted {
                    warn!(
                        id = %request_id,
                        alias,
                        err = %err,
                        "federated pane.stream read ended"
                    );
                }
                break;
            }
        }
    }

    // Every exit path reaches here: dropping the peer stream closes the peer
    // connection so no orphan stream is left running on the peer.
    drop(peer_stream);
    Ok(())
}

/// Prepare the first line of a proxied `pane.stream` for the client, returning
/// `(line, keep_streaming)`.
///
/// A `stream_started` success has its `pane_id` re-prefixed to `<alias>/…` (the
/// federated identity the client expects) and is re-serialized; `keep_streaming`
/// is true so the frame-piping loop runs. Anything else — an error line the peer
/// raised (`forbidden`, `pane_not_found`), or an unexpected/unparseable line — is
/// forwarded VERBATIM with `keep_streaming` false, ending the proxy after it. The
/// home applies NO capability logic of its own; the peer's allowlist is
/// authoritative.
fn prepare_first_stream_line(first: &str, alias: &str) -> (String, bool) {
    match serde_json::from_str::<SuccessResponse>(first) {
        Ok(mut success) => {
            if let ResponseResult::StreamStarted { pane_id, .. } = &mut success.result {
                let reprefixed = format!("{alias}/{pane_id}");
                *pane_id = reprefixed;
                match serde_json::to_string(&success) {
                    Ok(line) => (line, true),
                    // Re-encoding a value we just decoded should not fail; if it
                    // somehow does, forward the peer's original line unchanged.
                    Err(_) => (first.to_string(), true),
                }
            } else {
                // A non-`stream_started` success is not expected as a first line;
                // forward it verbatim and stop.
                (first.to_string(), false)
            }
        }
        // An error line (e.g. `forbidden`, `pane_not_found`) or non-JSON: verbatim.
        Err(_) => (first.to_string(), false),
    }
}

/// Write one raw NDJSON line to the requesting client, returning `false` when the
/// client has closed so the proxy loop can stop cleanly. Mirrors the `emit`
/// pattern in [`pane_output_stream`]: a genuine (non-disconnect) write error still
/// propagates. A wedged socket write is bounded by the connection-wide send
/// timeout and tears down only this connection.
fn emit_line_to_client(stream: &mut ApiStream, line: &str) -> std::io::Result<bool> {
    match write_text_line(stream, line) {
        Ok(()) => Ok(true),
        Err(err) if is_connection_closed_error(&err) => Ok(false),
        Err(err) => Err(err),
    }
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
        Method::ServerStagedUpdate(_) => "server.staged_update",
        Method::ServerApplyStagedUpdate(_) => "server.apply_staged_update",
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
        Method::AgentArchive(_) => "agent.archive",
        Method::AgentUnarchive(_) => "agent.unarchive",
        Method::AgentViewSet(_) => "agent.view.set",
        Method::AgentViewClear(_) => "agent.view.clear",
        Method::AgentFocus(_) => "agent.focus",
        Method::AgentStart(_) => "agent.start",
        Method::AgentPrompt(_) => "agent.prompt",
        Method::AgentWait(_) => "agent.wait",
        Method::AgentRestart(_) => "agent.restart",
        Method::AccountsList(_) => "accounts.list",
        Method::AccountsCreate(_) => "accounts.create",
        Method::AgentKinds(_) => "agent.kinds",
        Method::FsListDir(_) => "fs.list_dir",
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
    let event_start_sequence = event_hub.current_sequence();
    let mut subscriptions = Vec::with_capacity(params.subscriptions.len());
    for (index, subscription) in params.subscriptions.into_iter().enumerate() {
        let active = match ActiveSubscription::new(
            subscription,
            &request_id,
            index,
            api_tx,
            event_hub,
            event_start_sequence,
        ) {
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
                &HashMap::new(),
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
        AgentInfo, AgentPromptDelivery, AgentPromptParams, AgentRenameParams, AgentStartParams,
        AgentStatus, EmptyParams, EventData, EventEnvelope, EventKind, EventsSubscribeParams,
        PaneTarget, PingParams, Subscription,
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
            expected_node_id: None,
        }
    }

    /// A peer bound to `token` at `tier` with a pinned `expected_node_id`.
    fn one_peer_pinned(
        token: &str,
        tier: CapabilityTier,
        node_id: &str,
    ) -> Vec<(String, PeerContext)> {
        vec![(
            token.to_string(),
            PeerContext {
                alias: "peer".into(),
                tier,
                expected_node_id: Some(node_id.to_string()),
            },
        )]
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

    /// Like [`raw_hello`], but stamps an explicit `machine_id` so tests can drive
    /// the `expected_node_id` identity pin with a value they control (the real
    /// `ApiClient` TCP path would send this process's persisted install id).
    fn raw_hello_with_machine_id(addr: SocketAddr, token: &str, machine_id: &str) -> TcpStream {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let hello = FederationHello::new(token)
            .with_machine_id(machine_id.to_string())
            .to_line()
            .unwrap();
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
    fn inbound_peer_target_naming_a_peer_is_not_transit_proxied() {
        // Confused-deputy guard. A FEDERATION-INBOUND peer must never drive the
        // home's OWN outbound routing: the home drives its peers only from LOCAL
        // clients, never by relaying an inbound peer through to its other peers
        // on the home's own credentials. So an inbound Observe peer sending a
        // target that names another peer (`remote/screen`) must fall through to
        // LOCAL dispatch with the target UNREWRITTEN — never split, stripped, and
        // proxied onward. (The local-client side that DOES route is covered by
        // `proxy_returns_the_peers_read_snapshot_verbatim`.) The inbound listener
        // is given no outbound registry at all, so this holds by construction.
        let mut fed = start_federation(one_peer("peertok", CapabilityTier::Observe));

        // App responder: proves the request reached local dispatch, and captures
        // the target it arrived with. A transit-proxied request would never have
        // reached the app at all.
        let mut api_rx = std::mem::replace(&mut fed.api_rx, mpsc::unbounded_channel().1);
        let responder = std::thread::spawn(move || {
            for _ in 0..300 {
                if let Ok(msg) = api_rx.try_recv() {
                    let target = match &msg.request.method {
                        Method::AgentRead(params) => params.target.clone(),
                        other => panic!("unexpected local method: {other:?}"),
                    };
                    let resp = error_response_json(
                        msg.request.id.clone(),
                        "not_found",
                        "no such agent".into(),
                    );
                    let _ = msg.respond_to.send(resp);
                    return Some(target);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            None
        });

        let mut stream = raw_hello(fed.addr, "peertok");
        send_request(
            &mut stream,
            "ir1",
            Method::AgentRead(crate::api::schema::AgentReadParams {
                target: "remote/screen".into(),
                source: crate::api::schema::ReadSource::Visible,
                lines: None,
                format: crate::api::schema::ReadFormat::Text,
                strip_ansi: true,
            }),
        );
        let response = read_json_line(&stream);
        assert_eq!(response["id"], "ir1");
        assert_eq!(
            response["error"]["code"], "not_found",
            "an inbound `<alias>/…` target must resolve locally (not-found), not be proxied"
        );

        let seen_target = responder
            .join()
            .expect("responder thread panicked")
            .expect("inbound request never reached local dispatch (it was transit-proxied)");
        assert_eq!(
            seen_target, "remote/screen",
            "an inbound peer's target must reach local dispatch UNREWRITTEN, never split and proxied"
        );
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
            ("server.staged_update", Denied),
            ("server.apply_staged_update", Denied),
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
            ("agent.archive", Denied),
            ("agent.unarchive", Denied),
            ("agent.view.set", AllowedAt(Admin)),
            ("agent.view.clear", AllowedAt(Admin)),
            ("agent.focus", AllowedAt(Admin)),
            ("agent.start", Denied),
            ("agent.restart", AllowedAt(Admin)),
            ("accounts.list", AllowedAt(Observe)),
            ("accounts.create", Denied),
            ("agent.kinds", AllowedAt(Observe)),
            ("fs.list_dir", Denied),
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
            ("pane.set_pty_size", AllowedAt(Admin)),
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
            ("pane.graphics.stream.set", Denied),
            ("pane.graphics.stream.direct", Denied),
            ("pane.graphics.stream.open", Denied),
            ("pane.graphics.stream.close", Denied),
            ("pane.stream", AllowedAt(Observe)),
            ("pane.stream.open", Denied),
            ("pane.stream.close", Denied),
            ("pane.input.stream", Denied),
            ("pane.input.stream.open", Denied),
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

        let audit_names: std::collections::BTreeSet<&str> =
            expected.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            audit_names.len(),
            expected.len(),
            "the federation audit table lists a method name more than once"
        );

        // Tripwire part 1 — completeness, bound to the source of truth. The audit
        // table must classify every method `api_method_name` handles. That count
        // is derived from `api_method_name`'s own match arms (not a hand-copied
        // constant), so adding a `Method` variant — which the compiler forces to
        // grow `api_method_name` by one exhaustive arm — makes this fail until a
        // deliberate classification row is added here. A hardcoded length could
        // not catch that: the new arm would leave the checked constant unchanged.
        assert_eq!(
            expected.len(),
            api_method_name_arm_count(),
            "the federation audit table must classify every api_method_name arm; \
             a wire method was added without a deliberate federation access row"
        );

        // Tripwire part 2 — spelling/coverage of the serde-visible wire methods.
        // The `Method` schema omits the `#[schemars(skip)]` streaming internals,
        // so it is a subset of the audit, not the whole; but every name it does
        // carry must appear verbatim in the audit, catching a mistyped row that
        // part 1's count alone would miss.
        let wire_names = schema_wire_method_names();
        let missing: Vec<&str> = wire_names
            .iter()
            .filter(|name| !audit_names.contains(name.as_str()))
            .map(String::as_str)
            .collect();
        assert!(
            missing.is_empty(),
            "these serde-visible wire methods are unclassified in the federation audit: {missing:?}"
        );
    }

    /// Number of match arms in [`api_method_name`], the source of truth for the
    /// set of wire methods. Counted from this file's own text, embedded at
    /// compile time (no runtime file I/O, no CWD dependency), so it tracks the
    /// function that actually defines the methods. Each arm is one `Method::…`
    /// pattern, so counting those in the function body yields the arm count.
    fn api_method_name_arm_count() -> usize {
        const SOURCE: &str = include_str!("server.rs");
        let signature = "fn api_method_name(method: &Method) -> &'static str {";
        let start = SOURCE
            .find(signature)
            .expect("api_method_name is defined in this file");
        let after_signature = start + signature.len();
        // The function body ends at the first unindented closing brace.
        let body_len = SOURCE[after_signature..]
            .find("\n}\n")
            .expect("api_method_name has a closing brace");
        let body = &SOURCE[after_signature..after_signature + body_len];
        body.matches("Method::").count()
    }

    /// The serde-visible wire method names, from the `Method` enum's schema.
    /// `Method` is an adjacently-tagged serde enum, so each schema variant
    /// carries its wire name as the `method` tag constant. `#[schemars(skip)]`
    /// variants (the streaming internals) are absent, so this is a subset of the
    /// full method set — see [`api_method_name_arm_count`] for the total.
    fn schema_wire_method_names() -> std::collections::BTreeSet<String> {
        let schema = schemars::schema_for!(Method);
        let value = serde_json::to_value(&schema).expect("method schema serializes to json");
        let variants = value
            .get("oneOf")
            .and_then(serde_json::Value::as_array)
            .expect("Method schema is a tagged-enum `oneOf`");
        variants
            .iter()
            .map(|variant| {
                let method = variant
                    .get("properties")
                    .and_then(|properties| properties.get("method"))
                    .unwrap_or_else(|| {
                        panic!("Method schema variant has no method tag: {variant}")
                    });
                // schemars renders a single-value tag as `const`; tolerate an
                // `enum: [name]` rendering too so a schemars upgrade cannot
                // silently defeat the tripwire.
                let name = method
                    .get("const")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| {
                        method
                            .get("enum")
                            .and_then(serde_json::Value::as_array)
                            .and_then(|values| values.first())
                            .and_then(serde_json::Value::as_str)
                    })
                    .unwrap_or_else(|| panic!("method tag is not a string constant: {method}"));
                name.to_string()
            })
            .collect()
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
                    account: None,
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
    fn expected_node_id_match_proceeds() {
        // A peer pinned to "node-A": a valid token whose hello carries the
        // matching machine_id passes the pin and reaches the app dispatch path.
        let mut fed = start_federation(one_peer_pinned("tok", CapabilityTier::Observe, "node-A"));
        let mut stream = raw_hello_with_machine_id(fed.addr, "tok", "node-A");
        send_request(&mut stream, "list", Method::AgentList(EmptyParams {}));
        let message = recv_dispatched(&mut fed.api_rx);
        assert!(matches!(message.request.method, Method::AgentList(_)));
    }

    #[test]
    fn expected_node_id_mismatch_is_rejected_and_never_dispatches() {
        // A peer pinned to "node-A": the right token but a hello carrying a
        // different machine_id is rejected with the SAME opaque unauthorized line
        // as a bad token (the failing check is never revealed), at handshake time
        // before any request can be read.
        let mut fed = start_federation(one_peer_pinned("tok", CapabilityTier::Observe, "node-A"));

        // Write the hello AND a real request in a SINGLE flush, before the handler
        // reads. This makes "never dispatches" a meaningful check: if the pin
        // failed to reject, the handler would go on to read this request and
        // dispatch it. Doing both in one write (rather than a second write after
        // the hello) is deliberate — a second write racing the handler's
        // rejection-close RSTs on macOS.
        let hello = FederationHello::new("tok")
            .with_machine_id("node-B".to_string())
            .to_line()
            .unwrap();
        let request = serde_json::to_string(&Request {
            id: "list".into(),
            method: Method::AgentList(EmptyParams {}),
        })
        .unwrap();
        let mut stream = TcpStream::connect(fed.addr).expect("connect");
        write!(stream, "{hello}\n{request}\n").expect("write hello+request");
        stream.flush().expect("flush hello+request");
        // Bound the read: a correctly-rejecting handler closes fast, but a broken
        // pin that DISPATCHED the request would then block awaiting a response and
        // never write — the timeout makes the test fall through to the no-dispatch
        // assertion (which catches that regression) instead of hanging.
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set read timeout");

        // The rejection SHOULD be the opaque unauthorized line. Read it
        // best-effort: the handler rejects at the pin without reading the request,
        // so it closes with that request still unread — which on macOS/BSD RSTs the
        // connection and can discard the line (and a broken pin instead times out
        // above). Either way the load-bearing assertion below is that nothing was
        // dispatched.
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) > 0 {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                assert_eq!(
                    value["error"]["code"], "unauthorized",
                    "the rejection line, when delivered, must be the opaque unauthorized error"
                );
            }
        }

        std::thread::sleep(Duration::from_millis(50));
        assert!(
            fed.api_rx.try_recv().is_err(),
            "a machine-id-mismatched connection dispatched a request sent behind the hello"
        );
    }

    #[test]
    fn peer_without_expected_node_id_ignores_machine_id() {
        // Back-compat: a peer with no pin admits any presented machine_id.
        let mut fed = start_federation(one_peer("tok", CapabilityTier::Observe));
        let mut stream = raw_hello_with_machine_id(fed.addr, "tok", "any-unpinned-id");
        send_request(&mut stream, "list", Method::AgentList(EmptyParams {}));
        let message = recv_dispatched(&mut fed.api_rx);
        assert!(matches!(message.request.method, Method::AgentList(_)));
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

    // ---- Outbound federation client (W3) ----

    fn seeded_agent(status: AgentStatus, name: &str) -> AgentInfo {
        serde_json::from_value(serde_json::json!({
            "terminal_id": "term-remote",
            "name": name,
            "agent_status": status,
            "workspace_id": "ws-remote",
            "tab_id": "tab-remote",
            "pane_id": "pane-remote",
            "focused": false,
            "revision": 1,
        }))
        .expect("seeded agent deserializes")
    }

    fn unique_token_file(token: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "herdr-fed-poll-token-{}-{}.txt",
            std::process::id(),
            nanos
        ));
        std::fs::write(&path, token).expect("write token file");
        path
    }

    /// Shared token every seeded loopback peer gates on. The per-peer token
    /// FILES are distinct paths (from `unique_token_file`) but hold this same
    /// value, so a peer can authenticate to any of them.
    const SEEDED_PEER_TOKEN: &str = "poll-secret";

    /// A live loopback federation peer that answers `agent.list` with one seeded
    /// working agent named `agent_name`. Used by the manager reconcile tests.
    struct SeededPeer {
        addr: std::net::SocketAddr,
        token_path: PathBuf,
        running: Arc<AtomicBool>,
        listener: JoinHandle<()>,
        responder: JoinHandle<()>,
    }

    impl SeededPeer {
        /// Bind a loopback listener + responder returning one `agent_name` agent.
        fn spawn(agent_name: &'static str) -> Self {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("bind loopback federation listener");
            let addr = listener.local_addr().expect("listener addr");
            let (api_tx, mut api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
            let event_hub = EventHub::default();
            let running = Arc::new(AtomicBool::new(true));
            let listener_thread = spawn_federation_listener(
                listener,
                one_peer(SEEDED_PEER_TOKEN, CapabilityTier::Observe),
                api_tx,
                event_hub,
                None,
                Arc::clone(&running),
                None,
            )
            .expect("spawn federation listener");
            let responder = std::thread::spawn(move || {
                while let Some(msg) = api_rx.blocking_recv() {
                    let response = match msg.request.method {
                        Method::AgentList(_) => serde_json::to_string(&SuccessResponse {
                            id: msg.request.id,
                            result: ResponseResult::AgentList {
                                agents: vec![seeded_agent(AgentStatus::Working, agent_name)],
                            },
                        })
                        .expect("encode agent.list response"),
                        _ => error_response_json(
                            msg.request.id,
                            "unexpected_dispatch",
                            "only agent.list is expected in this test".into(),
                        ),
                    };
                    let _ = msg.respond_to.send(response);
                }
            });
            let token_path = unique_token_file(SEEDED_PEER_TOKEN);
            Self {
                addr,
                token_path,
                running,
                listener: listener_thread,
                responder,
            }
        }

        /// Stop the listener + responder and remove the token file. Call AFTER the
        /// manager's poll threads are joined so any in-flight poll completes.
        fn shutdown(self) {
            self.running.store(false, Ordering::Relaxed);
            let _ = self.listener.join();
            let _ = self.responder.join();
            let _ = std::fs::remove_file(&self.token_path);
        }
    }

    /// Build an outbound `FederationPeer` targeting `addr` over loopback TCP.
    fn reachable_peer_on(
        addr: std::net::SocketAddr,
        alias: &str,
        token_path: &Path,
    ) -> FederationPeer {
        FederationPeer {
            alias: alias.into(),
            endpoint: Some(format!("tcp://{addr}")),
            token_file: Some(token_path.to_string_lossy().into_owned()),
            expected_node_id: None,
            capability: CapabilityTier::Observe,
        }
    }

    /// Poll the store until `alias` is cached `Reachable` with its first agent
    /// named `expected_name`, or a bounded ~3s wait elapses. Returns whether it
    /// converged.
    fn wait_for_cached(
        cache: &Arc<Mutex<FederationStore>>,
        alias: &str,
        expected_name: &str,
    ) -> bool {
        for _ in 0..300 {
            {
                let store = cache.lock().expect("cache lock");
                if let Some(entry) = store.peer(alias) {
                    if entry.reachability == Reachability::Reachable
                        && entry.agents.first().and_then(|a| a.name.as_deref())
                            == Some(expected_name)
                    {
                        return true;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// The manager, reconciled with one endpoint peer, spawns a poll thread that
    /// caches the peer's agent alias-prefixed and `Reachable`, rewriting all five
    /// identity fields plus `machine_id`, and registers a proxy route for it.
    #[test]
    fn federation_client_caches_alias_prefixed_reachable_agents() {
        let peer_srv = SeededPeer::spawn("builder");
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(Arc::clone(&cache), Arc::clone(&running));
        manager.reconcile(&[reachable_peer_on(
            peer_srv.addr,
            "home",
            &peer_srv.token_path,
        )]);
        assert_eq!(
            manager.live_aliases(),
            vec!["home".to_string()],
            "one endpoint peer → one poll thread"
        );

        // The first poll fires immediately, so the cache populates fast.
        assert!(
            wait_for_cached(&cache, "home", "home/builder"),
            "poll thread did not cache the reachable prefixed agent"
        );
        {
            let store = cache.lock().expect("cache lock");
            let agent = &store.peer("home").expect("home cached").agents[0];
            assert_eq!(agent.terminal_id, "home/term-remote");
            assert_eq!(agent.workspace_id, "home/ws-remote");
            assert_eq!(agent.tab_id, "home/tab-remote");
            assert_eq!(agent.pane_id, "home/pane-remote");
            assert_eq!(agent.machine_id.as_deref(), Some("home"));
        }

        // The read/merge helper stamps a reachable peer as-is with the status.
        let merged = cache.lock().expect("cache lock").merged_agents();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].agent_status, AgentStatus::Working);
        assert_eq!(merged[0].reachability, Some(Reachability::Reachable));
        assert_eq!(merged[0].last_known_status, None);

        // The outbound proxy registry has a route for the peer.
        assert!(manager.registry_snapshot().contains_key("home"));

        // Teardown: join the poll thread (its in-flight poll completes against the
        // still-up listener), then stop the listener + responder.
        manager.join_all();
        peer_srv.shutdown();
    }

    /// The poll→cache path degrades a peer that stops answering: two misses keep
    /// the last-known agents (`Degraded`), a third flips it `Unreachable`, and the
    /// read helper then stamps `Unknown` while preserving the last-known status —
    /// never a stale idle/done. Driven through `poll_once_into_cache` against a
    /// dead port so it needs no real 5s poll intervals.
    #[test]
    fn federation_client_flips_to_unreachable_and_stamps_unknown() {
        // Seed the cache as if a prior poll had succeeded with an idle agent.
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        {
            let mut store = cache.lock().expect("cache lock");
            store.set_peer(
                "home",
                PeerCacheEntry::reachable(
                    vec![prefix_remote_agent(
                        "home",
                        seeded_agent(AgentStatus::Idle, "idler"),
                    )],
                    Instant::now(),
                ),
            );
        }

        // A guaranteed-closed unprivileged loopback port: every poll is refused.
        let dead_addr = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
            probe.local_addr().expect("probe addr")
            // `probe` drops here, freeing the port so connects are refused.
        };
        let client = ApiClient::for_target(ConnectionTarget::Tcp {
            addr: dead_addr,
            token: Some("t".into()),
        });
        let running = Arc::new(AtomicBool::new(true));
        // A live (unset) per-peer stop flag: the under-lock guard must NOT skip
        // these writes.
        let peer_stop = Arc::new(AtomicBool::new(false));
        let mut tracker = ReachabilityTracker::default();

        // First two misses: Degraded. The last-known agents are retained in the
        // cache, but the read helper already stamps the surfaced status `Unknown`
        // (an honest-offline peer never shows a stale idle/done) with the real
        // status preserved in `last_known_status`.
        assert_eq!(
            poll_once_into_cache(&client, "home", &cache, &mut tracker, &running, &peer_stop),
            Reachability::Degraded
        );
        assert_eq!(
            poll_once_into_cache(&client, "home", &cache, &mut tracker, &running, &peer_stop),
            Reachability::Degraded
        );
        {
            let merged = cache.lock().expect("cache lock").merged_agents();
            assert_eq!(
                merged[0].agent_status,
                AgentStatus::Unknown,
                "a degraded peer must not surface a stale idle/done"
            );
            assert_eq!(merged[0].reachability, Some(Reachability::Degraded));
            assert_eq!(merged[0].last_known_status, Some(AgentStatus::Idle));
        }

        // Third miss: Unreachable → the read helper still stamps Unknown + last-known.
        assert_eq!(
            poll_once_into_cache(&client, "home", &cache, &mut tracker, &running, &peer_stop),
            Reachability::Unreachable
        );
        let merged = cache.lock().expect("cache lock").merged_agents();
        assert_eq!(merged.len(), 1, "last-known agents retained across misses");
        assert_eq!(
            merged[0].agent_status,
            AgentStatus::Unknown,
            "an offline peer must never surface a stale idle/done"
        );
        assert_eq!(merged[0].last_known_status, Some(AgentStatus::Idle));
        assert_eq!(merged[0].reachability, Some(Reachability::Unreachable));
        assert_eq!(merged[0].name.as_deref(), Some("home/idler"));

        // A later success recovers immediately.
        assert_eq!(tracker.record_success(), Reachability::Reachable);
    }

    /// A peer with no `endpoint` is inbound-only: reconcile spawns no thread, adds
    /// no proxy route, and writes nothing to the store — the byte-identical
    /// no-outbound-federation path.
    #[test]
    fn reconcile_ignores_inbound_only_peer() {
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(Arc::clone(&cache), Arc::clone(&running));
        manager.reconcile(&[FederationPeer {
            alias: "listen-only".into(),
            endpoint: None,
            token_file: None,
            expected_node_id: None,
            capability: CapabilityTier::Observe,
        }]);
        assert!(
            manager.live_aliases().is_empty(),
            "an endpoint-less peer must spawn no thread"
        );
        assert!(
            manager.registry_snapshot().is_empty(),
            "an endpoint-less peer must not be routable for proxying"
        );
        assert!(cache.lock().expect("cache lock").is_empty());
        manager.join_all();
    }

    /// `reconcile(&[])` from empty is byte-identical to no federation: zero
    /// threads, an empty registry, an empty store, and no merged agents. And a
    /// full teardown (peers → none) leaves the same clean state.
    #[test]
    fn reconcile_empty_is_byte_identical() {
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(Arc::clone(&cache), Arc::clone(&running));

        // From empty.
        manager.reconcile(&[]);
        assert!(manager.live_aliases().is_empty());
        assert!(manager.registry_snapshot().is_empty());
        assert!(cache.lock().expect("cache lock").is_empty());
        assert!(cache.lock().expect("cache lock").merged_agents().is_empty());

        // Full teardown: bring a peer up, then reconcile back to empty.
        let peer_srv = SeededPeer::spawn("builder");
        manager.reconcile(&[reachable_peer_on(
            peer_srv.addr,
            "home",
            &peer_srv.token_path,
        )]);
        assert!(wait_for_cached(&cache, "home", "home/builder"));
        manager.reconcile(&[]);
        assert!(
            manager.live_aliases().is_empty(),
            "teardown stops all threads"
        );
        assert!(
            manager.registry_snapshot().is_empty(),
            "teardown empties registry"
        );
        assert!(
            cache.lock().expect("cache lock").is_empty(),
            "teardown evicts every peer from the store"
        );
        assert!(cache.lock().expect("cache lock").merged_agents().is_empty());

        manager.join_all();
        peer_srv.shutdown();
    }

    /// Adding a second peer on a later reconcile spawns its thread and caches its
    /// agents without disturbing the first peer.
    #[test]
    fn reconcile_adds_second_peer_both_cached() {
        let peer_a = SeededPeer::spawn("a-agent");
        let peer_b = SeededPeer::spawn("b-agent");
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(Arc::clone(&cache), Arc::clone(&running));

        // First reconcile: only A.
        manager.reconcile(&[reachable_peer_on(peer_a.addr, "A", &peer_a.token_path)]);
        assert!(wait_for_cached(&cache, "A", "A/a-agent"));
        assert_eq!(manager.live_aliases(), vec!["A".to_string()]);

        // Second reconcile: A (unchanged) and B (added).
        manager.reconcile(&[
            reachable_peer_on(peer_a.addr, "A", &peer_a.token_path),
            reachable_peer_on(peer_b.addr, "B", &peer_b.token_path),
        ]);
        assert!(wait_for_cached(&cache, "B", "B/b-agent"));
        assert_eq!(
            manager.live_aliases(),
            vec!["A".to_string(), "B".to_string()]
        );
        {
            // A stayed cached across the add.
            let store = cache.lock().expect("cache lock");
            assert_eq!(
                store.peer("A").expect("A still cached").agents[0]
                    .name
                    .as_deref(),
                Some("A/a-agent")
            );
        }
        let registry = manager.registry_snapshot();
        assert!(registry.contains_key("A") && registry.contains_key("B"));

        manager.join_all();
        peer_a.shutdown();
        peer_b.shutdown();
    }

    /// Removing a peer on reconcile evicts it from the registry and the store
    /// immediately, stops its thread (which reaches `is_finished()` within a
    /// bounded wait, without block-joining on the test's critical path), and
    /// leaves the other peer cached.
    #[test]
    fn reconcile_removes_peer_stops_thread_and_evicts_store() {
        let peer_a = SeededPeer::spawn("a-agent");
        let peer_b = SeededPeer::spawn("b-agent");
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(Arc::clone(&cache), Arc::clone(&running));

        manager.reconcile(&[
            reachable_peer_on(peer_a.addr, "A", &peer_a.token_path),
            reachable_peer_on(peer_b.addr, "B", &peer_b.token_path),
        ]);
        assert!(wait_for_cached(&cache, "A", "A/a-agent"));
        assert!(wait_for_cached(&cache, "B", "B/b-agent"));

        // Reconcile to just B: A is removed.
        manager.reconcile(&[reachable_peer_on(peer_b.addr, "B", &peer_b.token_path)]);

        // A is evicted synchronously from the store and the registry; B remains.
        assert!(
            cache.lock().expect("cache lock").peer("A").is_none(),
            "removed peer A must be evicted from the store immediately"
        );
        assert!(cache.lock().expect("cache lock").peer("B").is_some());
        let registry = manager.registry_snapshot();
        assert!(
            !registry.contains_key("A"),
            "A must leave the proxy registry"
        );
        assert!(registry.contains_key("B"));
        assert_eq!(manager.live_aliases(), vec!["B".to_string()]);

        // A's retired thread reaches `is_finished()` within a bounded wait; the
        // reaper joins it only once finished, never blocking this path.
        let mut reaped = false;
        for _ in 0..300 {
            if manager.reap_and_count_pending() == 0 {
                reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            reaped,
            "removed peer A's poll thread did not finish within the bounded wait"
        );

        manager.join_all();
        peer_a.shutdown();
        peer_b.shutdown();
    }

    /// Re-pointing an alias at a new endpoint retires the old thread and spawns a
    /// new one: the cache converges to the NEW addr's agent and never flaps back
    /// to a stale entry from the retiring old thread (exercises the
    /// under-store-lock stop guard), and the registry points at the new addr.
    #[test]
    fn reconcile_changed_endpoint_respawns() {
        let peer_old = SeededPeer::spawn("old-agent");
        let peer_new = SeededPeer::spawn("new-agent");
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(Arc::clone(&cache), Arc::clone(&running));

        // Alias A points at the OLD addr.
        manager.reconcile(&[reachable_peer_on(peer_old.addr, "A", &peer_old.token_path)]);
        assert!(wait_for_cached(&cache, "A", "A/old-agent"));

        // Re-point alias A at the NEW addr: endpoint changed → respawn.
        manager.reconcile(&[reachable_peer_on(peer_new.addr, "A", &peer_new.token_path)]);
        assert_eq!(manager.live_aliases(), vec!["A".to_string()]);

        // The registry now routes A at the new addr.
        match manager.registry_snapshot().get("A") {
            Some(ConnectionTarget::Tcp { addr, .. }) => assert_eq!(*addr, peer_new.addr),
            other => panic!("expected A to route to the new tcp addr, got {other:?}"),
        }

        // The cache converges to the NEW addr's agent.
        assert!(
            wait_for_cached(&cache, "A", "A/new-agent"),
            "cache did not converge to the re-pointed endpoint's agent"
        );

        // And it STAYS the new agent — the retiring old thread's under-lock stop
        // guard means it can never overwrite the evicted+respawned alias with a
        // stale "A/old-agent" entry.
        for _ in 0..20 {
            {
                let store = cache.lock().expect("cache lock");
                let entry = store.peer("A").expect("A cached");
                assert_eq!(
                    entry.agents[0].name.as_deref(),
                    Some("A/new-agent"),
                    "a retiring thread must never write a stale entry after eviction"
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        manager.join_all();
        peer_old.shutdown();
        peer_new.shutdown();
    }

    /// The under-store-lock stop guard skips the DEGRADE (miss) write once the
    /// peer's stop flag is set: the miss is still counted, but no cache entry is
    /// created for the evicted alias.
    #[test]
    fn poll_once_skips_degrade_write_when_peer_stop_set() {
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let dead_addr = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
            probe.local_addr().expect("probe addr")
        };
        let client = ApiClient::for_target(ConnectionTarget::Tcp {
            addr: dead_addr,
            token: Some("t".into()),
        });
        let running = Arc::new(AtomicBool::new(true));
        // The peer is already retiring: the guard must skip the write.
        let peer_stop = Arc::new(AtomicBool::new(true));
        let mut tracker = ReachabilityTracker::default();

        let reachability =
            poll_once_into_cache(&client, "gone", &cache, &mut tracker, &running, &peer_stop);
        assert_eq!(
            reachability,
            Reachability::Degraded,
            "the miss is still counted even though the write is skipped"
        );
        assert!(
            cache.lock().expect("cache lock").peer("gone").is_none(),
            "a stopped peer's degrade write must be skipped, leaving no entry"
        );
        assert!(cache.lock().expect("cache lock").is_empty());
    }

    /// The under-store-lock stop guard also skips the SUCCESS (set) write once the
    /// peer's stop flag is set: the poll succeeds, but nothing is cached for the
    /// evicted alias.
    #[test]
    fn poll_once_skips_set_write_when_peer_stop_set() {
        let peer_srv = SeededPeer::spawn("builder");
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let client = ApiClient::for_target(ConnectionTarget::Tcp {
            addr: peer_srv.addr,
            token: Some(SEEDED_PEER_TOKEN.into()),
        });
        let running = Arc::new(AtomicBool::new(true));
        let peer_stop = Arc::new(AtomicBool::new(true));
        let mut tracker = ReachabilityTracker::default();

        let reachability =
            poll_once_into_cache(&client, "home", &cache, &mut tracker, &running, &peer_stop);
        assert_eq!(
            reachability,
            Reachability::Reachable,
            "the poll itself still succeeds"
        );
        assert!(
            cache.lock().expect("cache lock").peer("home").is_none(),
            "a stopped peer's successful write must be skipped, leaving no entry"
        );

        peer_srv.shutdown();
    }

    /// FIX 3: the home OWNS the federation fields. A malicious/faulty peer cannot
    /// smuggle `machine_id`/`reachability`/`last_known_status` into the cache:
    /// `prefix_remote_agent` normalizes `machine_id` to the peer's local alias and
    /// CLEARS `reachability`/`last_known_status` (only the read helper sets them,
    /// from the home's own poll tracking).
    #[test]
    fn prefix_remote_agent_discards_peer_supplied_federation_fields() {
        let hostile: AgentInfo = serde_json::from_value(serde_json::json!({
            "terminal_id": "term-remote",
            "name": "sneaky",
            "agent_status": "idle",
            "workspace_id": "ws-remote",
            "tab_id": "tab-remote",
            "pane_id": "pane-remote",
            "focused": false,
            "revision": 1,
            // Fields a peer must NOT be trusted to set:
            "machine_id": "not-home",
            "reachability": "reachable",
            "last_known_status": "working",
        }))
        .expect("hostile agent deserializes");
        // Sanity: the peer really did set the home-owned fields.
        assert_eq!(hostile.machine_id.as_deref(), Some("not-home"));
        assert_eq!(hostile.reachability, Some(Reachability::Reachable));
        assert_eq!(hostile.last_known_status, Some(AgentStatus::Working));

        let normalized = prefix_remote_agent("home", hostile);
        assert_eq!(
            normalized.machine_id.as_deref(),
            Some("home"),
            "machine_id must be overwritten with the peer's local alias"
        );
        assert_eq!(
            normalized.reachability, None,
            "a peer-supplied reachability must be discarded"
        );
        assert_eq!(
            normalized.last_known_status, None,
            "a peer-supplied last_known_status must be discarded"
        );
        assert_eq!(normalized.name.as_deref(), Some("home/sneaky"));
    }

    /// FIX 1 (DoS hardening): a peer that returns an over-cap response line must
    /// not drive unbounded allocation. The poll's bounded read errors at ~the cap,
    /// the peer is degraded (a miss) rather than caching any agents, and clearing
    /// `running` then joins the poll thread promptly — an oversized/malicious
    /// response can neither OOM the home nor hang shutdown.
    #[test]
    fn federation_client_bounds_oversized_peer_response_and_shuts_down_promptly() {
        // A raw "peer" that accepts the poll connection, ignores the hello and the
        // request, and floods a single line far larger than the response cap with
        // NO newline. The bounded reader must reject it near the cap.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind hostile peer");
        let addr = listener.local_addr().expect("hostile peer addr");
        let peer_running = Arc::new(AtomicBool::new(true));
        let peer_flag = Arc::clone(&peer_running);
        let peer_thread = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("hostile listener nonblocking");
            while peer_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        // One oversized, newline-free blob. Ignore write errors:
                        // the client closes the moment it crosses the cap.
                        let blob = vec![b'x'; FEDERATION_MAX_RESPONSE_BYTES + 8192];
                        let _ = sock.write_all(&blob);
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let token_path = unique_token_file("hostile-token");
        let peer = reachable_peer_on(addr, "home", &token_path);
        let cache = Arc::new(Mutex::new(FederationStore::default()));
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(Arc::clone(&cache), Arc::clone(&running));
        manager.reconcile(&[peer]);
        assert_eq!(manager.live_aliases(), vec!["home".to_string()]);

        // The over-cap response is rejected, so the peer is recorded as a miss
        // (Degraded on the first failure) rather than caching any agents.
        let mut degraded = false;
        for _ in 0..300 {
            {
                let store = cache.lock().expect("cache lock");
                if let Some(entry) = store.peer("home") {
                    if entry.reachability == Reachability::Degraded && entry.agents.is_empty() {
                        degraded = true;
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            degraded,
            "an oversized peer response must degrade the peer, not cache agents"
        );

        // Shutdown must join the poll thread promptly (the bounded read can't
        // hang). Mirror `ServerHandle::drop`: clear `running` — which aborts any
        // in-flight bounded read — then `join_all`.
        let (join_tx, join_rx) = std::sync::mpsc::channel();
        let manager_for_join = Arc::clone(&manager);
        let running_for_join = Arc::clone(&running);
        std::thread::spawn(move || {
            running_for_join.store(false, Ordering::Relaxed);
            manager_for_join.join_all();
            let _ = join_tx.send(());
        });
        join_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("poll thread did not join promptly after shutdown");

        peer_running.store(false, Ordering::Relaxed);
        let _ = peer_thread.join();
        let _ = std::fs::remove_file(&token_path);
    }

    // ---- Outbound proxy router (W4) ----

    #[test]
    fn federated_split_routes_only_configured_alias_prefixes() {
        let mut peers = HashMap::new();
        peers.insert(
            "w1".to_string(),
            ConnectionTarget::Tcp {
                addr: "127.0.0.1:9000".parse().unwrap(),
                token: None,
            },
        );

        // `<alias>/x` routes; the rest keeps everything after the FIRST slash.
        assert_eq!(
            federated_split("w1/builder", &peers),
            Some(("w1", "builder"))
        );
        assert_eq!(federated_split("w1/ws/tab", &peers), Some(("w1", "ws/tab")));

        // A `/`-containing name whose first segment is NOT a configured alias.
        assert_eq!(federated_split("other/x", &peers), None);
        // A `w1:p1`-style local id (no slash) never routes, even though `w1` is an
        // alias — the colon is not the federation separator.
        assert_eq!(federated_split("w1:p1", &peers), None);
        // A bare local name and the exact alias without a slash never route.
        assert_eq!(federated_split("builder", &peers), None);
        assert_eq!(federated_split("w1", &peers), None);

        // With no configured peers nothing routes.
        assert_eq!(federated_split("w1/builder", &HashMap::new()), None);
    }

    #[test]
    fn routable_target_mut_selects_the_proxyable_target_field() {
        // Agent methods carry the target in `target`; a rewrite is reflected.
        let mut prompt = Method::AgentPrompt(AgentPromptParams {
            target: "remote/a".into(),
            text: "hi".into(),
            wait: None,
        });
        assert_eq!(
            routable_target_mut(&mut prompt).map(|t| t.as_str()),
            Some("remote/a")
        );
        if let Some(target) = routable_target_mut(&mut prompt) {
            *target = "a".into();
        }
        assert!(matches!(&prompt, Method::AgentPrompt(p) if p.target == "a"));

        // Pane read/turns carry it in `pane_id` (W3 alias-prefixes that field too).
        let mut turns: Method = serde_json::from_value(serde_json::json!({
            "method": "pane.turns",
            "params": { "pane_id": "remote/p" },
        }))
        .unwrap();
        assert_eq!(
            routable_target_mut(&mut turns).map(|t| t.as_str()),
            Some("remote/p")
        );

        // Pane send-text/send-input carry it in `pane_id` too — the write path the
        // app uses for a federated pane's keystrokes (S-Tab / ^C / Ctrl-chords).
        let mut send_text: Method = serde_json::from_value(serde_json::json!({
            "method": "pane.send_text",
            "params": { "pane_id": "remote/p", "text": "\u{1b}[Z" },
        }))
        .unwrap();
        assert_eq!(
            routable_target_mut(&mut send_text).map(|t| t.as_str()),
            Some("remote/p")
        );
        let mut send_input: Method = serde_json::from_value(serde_json::json!({
            "method": "pane.send_input",
            "params": { "pane_id": "remote/p", "keys": ["c-c"] },
        }))
        .unwrap();
        assert_eq!(
            routable_target_mut(&mut send_input).map(|t| t.as_str()),
            Some("remote/p")
        );

        // pane.set_pty_size carries the target in `pane_id` too, so a federated
        // width-lease request routes to the owning peer (#137).
        let mut set_pty_size: Method = serde_json::from_value(serde_json::json!({
            "method": "pane.set_pty_size",
            "params": { "pane_id": "remote/p", "cols": 100, "rows": 40, "lock": true },
        }))
        .unwrap();
        assert_eq!(
            routable_target_mut(&mut set_pty_size).map(|t| t.as_str()),
            Some("remote/p")
        );

        // A current-pane (no `pane_id`) set_pty_size has no proxyable target and
        // stays local.
        let mut local_set_pty_size: Method = serde_json::from_value(serde_json::json!({
            "method": "pane.set_pty_size",
            "params": { "cols": 100, "rows": 40, "lock": true },
        }))
        .unwrap();
        assert!(routable_target_mut(&mut local_set_pty_size).is_none());

        // A method with no proxyable target is never routed.
        let mut list = Method::AgentList(EmptyParams {});
        assert!(routable_target_mut(&mut list).is_none());
    }

    #[test]
    fn proxy_response_classifies_transport_failures_by_phase() {
        let running = Arc::new(AtomicBool::new(true));
        let request = Request {
            id: "u1".into(),
            method: Method::Ping(PingParams::default()),
        };

        // Connect/write failure (the request never left the home) → the request
        // was NOT delivered → `peer_unreachable`.
        let dead_addr = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
            probe.local_addr().expect("probe addr")
            // `probe` drops here, freeing the port so connects are refused.
        };
        let unreachable = ApiClient::for_target(ConnectionTarget::Tcp {
            addr: dead_addr,
            token: Some("t".into()),
        });
        let line = proxy_federated_response(&unreachable, &request, &running);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["id"], "u1");
        assert_eq!(value["error"]["code"], "peer_unreachable");

        // Read failure AFTER a successful write (peer drops without answering) →
        // the peer may or may not have acted → `delivery_unknown`.
        let peer = start_proxy_peer(|_req, sock| {
            // A READ-phase failure (peer read the request, then never answered), made deterministic
            // across platforms — macOS included (refs #103). Half-close ONLY the response direction
            // so the home reads a clean EOF, and keep draining the request side so the peer never
            // RSTs the home's already-delivered write. A full `drop(sock)` here is a platform-timing
            // gamble: on macOS the close can RST an in-flight / lazily-flushed home write, which the
            // home then misclassifies as a write-phase `peer_unreachable` instead of the intended
            // read-phase `delivery_unknown`. Keeping the read side open (until the home closes or the
            // harness 2s read-timeout fires) guarantees the write lands and only the response EOFs.
            use std::io::Read as _;
            let _ = sock.shutdown(std::net::Shutdown::Write);
            let mut drain = [0u8; 256];
            loop {
                match (&sock).read(&mut drain) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let dropper = ApiClient::for_target(ConnectionTarget::Tcp {
            addr: peer.addr,
            token: Some("t".into()),
        });
        let line = proxy_federated_response(&dropper, &request, &running);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["id"], "u1");
        assert_eq!(value["error"]["code"], "delivery_unknown");
    }

    /// A raw loopback "peer daemon" for the outbound-proxy tests. It accepts
    /// connections in a loop (so a spurious home reconnect/retry would be
    /// observed), and for each: reads and discards the `federation.hello` line,
    /// reads one request line, records it in `seen`, then hands `(request_line,
    /// socket)` to `serve` to produce the peer's behavior — write a response line
    /// or drop the socket. Runs until `running` clears.
    struct ProxyPeer {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<String>>>,
        running: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Drop for ProxyPeer {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn start_proxy_peer(serve: impl Fn(&str, TcpStream) + Send + 'static) -> ProxyPeer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy peer");
        listener
            .set_nonblocking(true)
            .expect("proxy peer nonblocking");
        let addr = listener.local_addr().expect("proxy peer addr");
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let running = Arc::new(AtomicBool::new(true));
        let seen_thread = Arc::clone(&seen);
        let running_thread = Arc::clone(&running);
        let thread = std::thread::spawn(move || {
            while running_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        // The listener is non-blocking (for the accept loop). On macOS/BSD an
                        // ACCEPTED socket INHERITS the listener's non-blocking flag (Linux does
                        // not), which makes the blocking `read_line`s below return WouldBlock →
                        // the peer never reads the request, and the home then sees the connection
                        // break as a write-phase failure (peer_unreachable) instead of the intended
                        // read-phase delivery_unknown. Force the per-connection socket blocking so
                        // the peer behaves identically on every platform. refs #103
                        let _ = sock.set_nonblocking(false);
                        let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut reader =
                            BufReader::new(sock.try_clone().expect("clone proxy peer sock"));
                        let mut hello = String::new();
                        if reader.read_line(&mut hello).unwrap_or(0) == 0 {
                            continue;
                        }
                        let mut request = String::new();
                        if reader.read_line(&mut request).unwrap_or(0) == 0 {
                            continue;
                        }
                        seen_thread
                            .lock()
                            .expect("seen lock")
                            .push(request.trim().to_string());
                        serve(request.trim(), sock);
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        ProxyPeer {
            addr,
            seen,
            running,
            thread: Some(thread),
        }
    }

    /// A home daemon connection handler running over a loopback TCP pair standing
    /// in for a LOCAL client, with `registry` as its outbound proxy registry. The
    /// test writes requests to `client` and reads responses; `api_rx` lets a test
    /// prove whether a request reached the LOCAL app dispatch path.
    struct HomeConn {
        client: TcpStream,
        api_rx: mpsc::UnboundedReceiver<ApiRequestMessage>,
        running: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Drop for HomeConn {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn drive_home(registry: HashMap<String, ConnectionTarget>) -> HomeConn {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind home listener");
        let addr = listener.local_addr().expect("home addr");
        let client = TcpStream::connect(addr).expect("connect home");
        let (server, _) = listener.accept().expect("accept home");
        let (api_tx, api_rx) = mpsc::unbounded_channel::<ApiRequestMessage>();
        let event_hub = EventHub::default();
        let running = Arc::new(AtomicBool::new(true));
        let handler_running = Arc::clone(&running);
        let registry = Arc::new(registry);
        let thread = std::thread::spawn(move || {
            // A local client carries `federation: None` (never capability-gated).
            let _ = handle_connection_with_stop(
                ApiStream::Tcp(server),
                &api_tx,
                &event_hub,
                &handler_running,
                None,
                None,
                None,
                &registry,
            );
        });
        HomeConn {
            client,
            api_rx,
            running,
            thread: Some(thread),
        }
    }

    fn home_roundtrip(conn: &mut HomeConn, request: serde_json::Value) -> String {
        let encoded = serde_json::to_string(&request).expect("encode home request");
        writeln!(conn.client, "{encoded}").expect("write home request");
        conn.client.flush().expect("flush home request");
        let mut response = String::new();
        BufReader::new(conn.client.try_clone().expect("clone home client"))
            .read_line(&mut response)
            .expect("read home response");
        response.trim().to_string()
    }

    #[test]
    fn proxy_returns_the_peers_agent_prompted_verbatim() {
        // The peer answers agent.prompt for its LOCAL agent id (prefix stripped)
        // with a real AgentPrompted{delivery}. The exact line it sends is captured
        // so the home's reply can be asserted byte-for-byte identical.
        let expected = serde_json::to_string(&SuccessResponse {
            id: "p1".into(),
            result: ResponseResult::AgentPrompted {
                agent: seeded_agent(AgentStatus::Working, "builder"),
                delivery: Some(AgentPromptDelivery::Submitted),
            },
        })
        .unwrap();
        let peer_line = expected.clone();
        let peer = start_proxy_peer(move |request, mut sock| {
            let parsed: serde_json::Value =
                serde_json::from_str(request).expect("peer request is json");
            // The home stripped the `<alias>/` prefix before forwarding, and left
            // the id untouched so the peer can echo it.
            assert_eq!(parsed["method"], "agent.prompt");
            assert_eq!(parsed["params"]["target"], "builder");
            assert_eq!(parsed["id"], "p1");
            writeln!(sock, "{peer_line}").expect("peer writes response");
            let _ = sock.flush();
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        let response = home_roundtrip(
            &mut home,
            serde_json::json!({
                "id": "p1",
                "method": "agent.prompt",
                "params": { "target": "remote/builder", "text": "ship it" },
            }),
        );

        assert_eq!(
            response, expected,
            "the peer's response must pass through verbatim"
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["result"]["type"], "agent_prompted");
        assert_eq!(value["result"]["delivery"], "submitted");

        // A proxied request never touches the local app, and reaches the peer once.
        assert!(
            home.api_rx.try_recv().is_err(),
            "a proxied prompt reached the local app dispatch path"
        );
        assert_eq!(peer.seen.lock().expect("seen lock").len(), 1);
    }

    #[test]
    fn proxy_returns_the_peers_read_snapshot_verbatim() {
        // agent.read (an Observe-tier read) to `<alias>/…` returns the peer's
        // snapshot unchanged. The response body shape is opaque to the home — it
        // passes the line through — so a marker field is enough to prove it.
        let expected = serde_json::json!({
            "id": "r1",
            "result": { "type": "pane_read", "read": { "marker": "peer-snapshot" } },
        })
        .to_string();
        let peer_line = expected.clone();
        let peer = start_proxy_peer(move |request, mut sock| {
            let parsed: serde_json::Value =
                serde_json::from_str(request).expect("peer request is json");
            assert_eq!(parsed["method"], "agent.read");
            assert_eq!(parsed["params"]["target"], "screen");
            writeln!(sock, "{peer_line}").expect("peer writes snapshot");
            let _ = sock.flush();
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        let response = home_roundtrip(
            &mut home,
            serde_json::json!({
                "id": "r1",
                "method": "agent.read",
                "params": { "target": "remote/screen", "source": "visible" },
            }),
        );

        assert_eq!(
            response, expected,
            "the peer snapshot must pass through verbatim"
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["result"]["read"]["marker"], "peer-snapshot");
        assert!(home.api_rx.try_recv().is_err());
    }

    #[test]
    fn proxy_passes_through_a_peers_forbidden_verdict() {
        // A REAL Observe-tier federation listener stands in for the peer. agent.
        // prompt needs Interact, so the peer's OWN capability gate returns
        // `forbidden` before any dispatch — and the home passes it straight
        // through, applying no capability logic of its own.
        let mut fed = start_federation(one_peer("obs-tok", CapabilityTier::Observe));
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: fed.addr,
                token: Some("obs-tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        let response = home_roundtrip(
            &mut home,
            serde_json::json!({
                "id": "f1",
                "method": "agent.prompt",
                "params": { "target": "remote/agent", "text": "hi" },
            }),
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["id"], "f1");
        assert_eq!(value["error"]["code"], "forbidden");

        // The peer's gate rejected before dispatch: nothing reached its app, and
        // nothing reached the home's app either.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            fed.api_rx.try_recv().is_err(),
            "a forbidden proxied call reached the peer's app"
        );
        assert!(home.api_rx.try_recv().is_err());
    }

    #[test]
    fn proxy_reports_delivery_unknown_and_never_retries_when_the_peer_drops() {
        // The peer reads the request then drops the connection WITHOUT a response.
        let peer = start_proxy_peer(|_request, sock| {
            drop(sock);
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        let response = home_roundtrip(
            &mut home,
            serde_json::json!({
                "id": "d1",
                "method": "agent.prompt",
                "params": { "target": "remote/builder", "text": "hi" },
            }),
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["id"], "d1");
        assert_eq!(value["error"]["code"], "delivery_unknown");

        // The peer saw exactly one request: a post-write read failure is NEVER
        // auto-retried (a write that did land must not be duplicated).
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            peer.seen.lock().expect("seen lock").len(),
            1,
            "the proxy retried after a post-write read failure"
        );
        assert!(home.api_rx.try_recv().is_err());
    }

    #[test]
    fn local_prompt_without_alias_prefix_is_not_routed() {
        // A peer that fails the test if it is ever contacted.
        let peer = start_proxy_peer(|_request, _sock| {
            panic!("a local prompt must never reach the peer");
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        // App responder: answer the LOCAL agent.prompt, proving it hit local
        // dispatch with an UNREWRITTEN target.
        let mut api_rx = std::mem::replace(&mut home.api_rx, mpsc::unbounded_channel().1);
        let responder = std::thread::spawn(move || {
            for _ in 0..300 {
                if let Ok(msg) = api_rx.try_recv() {
                    let target = match &msg.request.method {
                        Method::AgentPrompt(params) => params.target.clone(),
                        other => panic!("unexpected local method: {other:?}"),
                    };
                    assert_eq!(
                        target, "local-builder",
                        "a local target must not be rewritten"
                    );
                    let resp = serde_json::to_string(&SuccessResponse {
                        id: msg.request.id.clone(),
                        result: ResponseResult::AgentPrompted {
                            agent: seeded_agent(AgentStatus::Working, "local-builder"),
                            delivery: Some(AgentPromptDelivery::Submitted),
                        },
                    })
                    .unwrap();
                    let _ = msg.respond_to.send(resp);
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        });

        let response = home_roundtrip(
            &mut home,
            serde_json::json!({
                "id": "loc1",
                "method": "agent.prompt",
                "params": { "target": "local-builder", "text": "hi" },
            }),
        );
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["id"], "loc1");
        assert_eq!(value["result"]["type"], "agent_prompted");

        assert!(
            responder.join().unwrap(),
            "the local prompt never reached the app dispatch path"
        );
        assert!(
            peer.seen.lock().expect("seen lock").is_empty(),
            "a local prompt was proxied to the peer"
        );
    }

    // ---- W5: federated pane.stream proxy ------------------------------------

    /// Send a request to the home connection and return a buffered line reader over
    /// its client socket, for reading a MULTI-line streamed response.
    fn home_stream_reader(conn: &mut HomeConn, request: serde_json::Value) -> BufReader<TcpStream> {
        let encoded = serde_json::to_string(&request).expect("encode home request");
        writeln!(conn.client, "{encoded}").expect("write home request");
        conn.client.flush().expect("flush home request");
        BufReader::new(conn.client.try_clone().expect("clone home client"))
    }

    /// Read one NDJSON line (trailing newline stripped), or `None` at EOF — the home
    /// closes the client connection when the proxied stream ends.
    fn next_stream_line(reader: &mut BufReader<TcpStream>) -> Option<String> {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(line.trim_end().to_string()),
            Err(err) => panic!("stream read error: {err}"),
        }
    }

    #[test]
    fn proxy_streams_the_peers_frames_reprefixing_stream_started() {
        // The peer serves a stream for its LOCAL pane id (prefix stripped): a
        // stream_started ack, two data frames, and an exited frame, then closes.
        let started = serde_json::to_string(&SuccessResponse {
            id: "s1".into(),
            result: ResponseResult::StreamStarted {
                pane_id: "screen".into(),
                epoch: 7,
                cols: 80,
                rows: 24,
                base_seq: 100,
                resync: true,
            },
        })
        .unwrap();
        // Opaque-to-the-home control/data frames, asserted byte-verbatim below.
        let data1 =
            r#"{"stream":"pane.bytes","frame":"data","seq":100,"epoch":7,"data_b64":"aGk="}"#;
        let data2 =
            r#"{"stream":"pane.bytes","frame":"data","seq":102,"epoch":7,"data_b64":"Ynll"}"#;
        let exited = r#"{"stream":"pane.bytes","frame":"exited","seq":104,"epoch":7}"#;

        let started_peer = started.clone();
        let peer = start_proxy_peer(move |request, mut sock| {
            let parsed: serde_json::Value =
                serde_json::from_str(request).expect("peer request is json");
            // The home stripped the `<alias>/` prefix and preserved the id.
            assert_eq!(parsed["method"], "pane.stream");
            assert_eq!(parsed["params"]["pane_id"], "screen");
            assert_eq!(parsed["id"], "s1");
            writeln!(sock, "{started_peer}").expect("peer writes stream_started");
            writeln!(sock, "{data1}").expect("peer writes data1");
            writeln!(sock, "{data2}").expect("peer writes data2");
            writeln!(sock, "{exited}").expect("peer writes exited");
            let _ = sock.flush();
            // Return → sock drops → the stream closes.
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        let mut reader = home_stream_reader(
            &mut home,
            serde_json::json!({
                "id": "s1",
                "method": "pane.stream",
                "params": { "pane_id": "remote/screen" },
            }),
        );

        // Line 1: stream_started, pane_id RE-PREFIXED to `<alias>/…`, id preserved,
        // geometry carried through.
        let l1 = next_stream_line(&mut reader).expect("stream_started line");
        let v1: serde_json::Value = serde_json::from_str(&l1).unwrap();
        assert_eq!(v1["id"], "s1");
        assert_eq!(v1["result"]["type"], "stream_started");
        assert_eq!(v1["result"]["pane_id"], "remote/screen");
        assert_eq!(v1["result"]["epoch"], 7);
        assert_eq!(v1["result"]["cols"], 80);
        assert_eq!(v1["result"]["rows"], 24);

        // Lines 2..4: the data/exited frames pass through BYTE-VERBATIM, in order.
        assert_eq!(next_stream_line(&mut reader).as_deref(), Some(data1));
        assert_eq!(next_stream_line(&mut reader).as_deref(), Some(data2));
        assert_eq!(next_stream_line(&mut reader).as_deref(), Some(exited));

        // Peer closed → the home ends the stream (client sees EOF).
        assert!(
            next_stream_line(&mut reader).is_none(),
            "the stream did not end when the peer closed"
        );

        // A proxied stream never touches the local app, and reaches the peer once.
        assert!(
            home.api_rx.try_recv().is_err(),
            "a proxied pane.stream reached the local app dispatch path"
        );
        assert_eq!(peer.seen.lock().expect("seen lock").len(), 1);
    }

    #[test]
    fn proxy_passes_through_a_denied_pane_stream_verbatim() {
        // An observe-denied peer answers pane.stream with a `forbidden` first line;
        // the home forwards it verbatim (its allowlist is authoritative) and ends.
        let forbidden =
            r#"{"id":"s2","error":{"code":"forbidden","message":"pane.stream not permitted"}}"#;
        let peer = start_proxy_peer(move |request, mut sock| {
            let parsed: serde_json::Value =
                serde_json::from_str(request).expect("peer request is json");
            assert_eq!(parsed["method"], "pane.stream");
            assert_eq!(parsed["params"]["pane_id"], "screen");
            writeln!(sock, "{forbidden}").expect("peer writes forbidden");
            let _ = sock.flush();
            // Keep the connection open until the home has consumed the response and closes, so the
            // peer's close never RSTs the home BEFORE it reads the buffered `forbidden` line. A bare
            // drop here races the home's read on macOS — the RST arrives first and the home reports
            // a broken-pipe `peer_unreachable` instead of forwarding the verdict. refs #103
            use std::io::Read as _;
            let mut drain = [0u8; 256];
            loop {
                match (&sock).read(&mut drain) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        let mut reader = home_stream_reader(
            &mut home,
            serde_json::json!({
                "id": "s2",
                "method": "pane.stream",
                "params": { "pane_id": "remote/screen" },
            }),
        );

        let l1 = next_stream_line(&mut reader).expect("forbidden line");
        assert_eq!(l1, forbidden, "a peer error must pass through verbatim");
        let v1: serde_json::Value = serde_json::from_str(&l1).unwrap();
        assert_eq!(v1["error"]["code"], "forbidden");

        // No stream frames follow a forbidden verdict; the stream ends.
        assert!(
            next_stream_line(&mut reader).is_none(),
            "the stream did not end after the forbidden line"
        );
        assert!(home.api_rx.try_recv().is_err());
    }

    #[test]
    fn proxy_closes_an_over_cap_streamed_frame() {
        // After a valid stream_started, the peer floods a single frame far larger
        // than the per-frame cap with NO newline. The proxy must close the stream
        // (bounded — no unbounded allocation); the giant frame is never delivered.
        let started = serde_json::to_string(&SuccessResponse {
            id: "s3".into(),
            result: ResponseResult::StreamStarted {
                pane_id: "screen".into(),
                epoch: 1,
                cols: 80,
                rows: 24,
                base_seq: 0,
                resync: true,
            },
        })
        .unwrap();
        let started_peer = started.clone();
        let peer = start_proxy_peer(move |_request, mut sock| {
            writeln!(sock, "{started_peer}").expect("peer writes stream_started");
            let _ = sock.flush();
            // One oversized, newline-free blob. Ignore write errors: the home closes
            // the moment the in-progress frame crosses the cap.
            let blob = vec![b'x'; FEDERATION_MAX_STREAM_FRAME_BYTES + 8192];
            let _ = sock.write_all(&blob);
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        let mut reader = home_stream_reader(
            &mut home,
            serde_json::json!({
                "id": "s3",
                "method": "pane.stream",
                "params": { "pane_id": "remote/screen" },
            }),
        );

        // The stream_started ack arrives (re-prefixed) ...
        let l1 = next_stream_line(&mut reader).expect("stream_started line");
        let v1: serde_json::Value = serde_json::from_str(&l1).unwrap();
        assert_eq!(v1["result"]["type"], "stream_started");
        assert_eq!(v1["result"]["pane_id"], "remote/screen");

        // ... then the over-cap frame closes the stream with nothing more delivered.
        assert!(
            next_stream_line(&mut reader).is_none(),
            "the over-cap frame was forwarded instead of closing the stream"
        );
    }

    #[test]
    fn local_pane_stream_without_alias_prefix_is_served_locally() {
        // A peer that fails the test if it is ever contacted.
        let peer = start_proxy_peer(|_request, _sock| {
            panic!("a local pane.stream must never reach the peer");
        });
        let registry = HashMap::from([(
            "remote".to_string(),
            ConnectionTarget::Tcp {
                addr: peer.addr,
                token: Some("tok".into()),
            },
        )]);
        let mut home = drive_home(registry);

        // App responder: proves the request reached LOCAL dispatch via
        // `pane_output_stream::serve`, whose first act is a PaneStreamOpen carrying
        // the UNREWRITTEN pane id. Answer the open with an error (so serve returns
        // fast) and the follow-up close with ok, and report the pane id it saw.
        let mut api_rx = std::mem::replace(&mut home.api_rx, mpsc::unbounded_channel().1);
        let responder = std::thread::spawn(move || {
            let mut seen_open: Option<String> = None;
            for _ in 0..300 {
                if let Ok(msg) = api_rx.try_recv() {
                    match &msg.request.method {
                        Method::PaneStreamOpen(params) => {
                            seen_open = Some(params.pane_id.clone());
                            let resp = error_response_json(
                                msg.request.id.clone(),
                                "pane_not_found",
                                "no such pane".into(),
                            );
                            let _ = msg.respond_to.send(resp);
                        }
                        Method::PaneStreamClose(_) => {
                            let resp = serde_json::to_string(&SuccessResponse {
                                id: msg.request.id.clone(),
                                result: ResponseResult::Ok {},
                            })
                            .unwrap();
                            let _ = msg.respond_to.send(resp);
                            return seen_open;
                        }
                        other => panic!("unexpected local method: {other:?}"),
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            seen_open
        });

        let response = home_roundtrip(
            &mut home,
            serde_json::json!({
                "id": "loc-stream",
                "method": "pane.stream",
                "params": { "pane_id": "local-pane" },
            }),
        );
        // serve wrote the pane_not_found error (the open failed) to the client.
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(value["id"], "loc-stream");
        assert_eq!(value["error"]["code"], "pane_not_found");

        let seen = responder.join().unwrap();
        assert_eq!(
            seen.as_deref(),
            Some("local-pane"),
            "the local pane.stream did not reach pane_output_stream::serve with an unrewritten id"
        );
        assert!(
            peer.seen.lock().expect("seen lock").is_empty(),
            "a local pane.stream was proxied to the peer"
        );
    }
}
