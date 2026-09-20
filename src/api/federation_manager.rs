//! Runtime manager for the OUTBOUND federation peer set.
//!
//! One [`FederationPeerManager`] is shared (as an `Arc`) between the API
//! [`ServerHandle`](crate::api::ServerHandle), the app's `reload-config` path,
//! and a lightweight saved-profile watcher. It owns:
//! - the coordinator source: explicit peers plus last-good saved profiles and
//!   immutable-profile trust policy;
//! - one poll thread and one proxy route per resolved outbound peer;
//! - retiring poll joins, kept off the single-threaded app path.
//!
//! `reconcile_config` and the watcher serialize source changes under the
//! coordinator lock, then reconcile the complete desired set. Explicit TCP or
//! non-profile peers remain available when coordinator mode is off. Saved SSH
//! profiles are included only when coordinator mode and per-profile policy are
//! both present.
//!
//! ## Locking model (no deadlock possible)
//! Source-driven updates take **C** (`coordinator`) before **H** (`handles`).
//! Reconcile then takes **S** (`store`) only briefly per eviction, **P**
//! (`reaper`) after releasing S, and finally **R** (`registry`): **C → H → S /
//! P → R**. Poll threads take S only; proxy threads take R only; bridge workers
//! take none of these locks. Shutdown joins the catalog watcher before draining
//! H, so it never waits for C while holding a downstream lock.
//!
//! ## Default-off byte-identical
//! With no peer configured (or none with an `endpoint`), reconcile spawns zero
//! threads and swaps in an empty registry, so the outbound router never matches
//! and the local `agent.list` path is unchanged. `reconcile(&[])` is a clean
//! no-op / full teardown.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use tracing::{debug, info};

use crate::api::client::ConnectionTarget;
use crate::api::federation_store::FederationStore;
use crate::api::server::{read_peer_token, run_federation_peer_poll};
use crate::config::{FederationConfig, FederationPeer, FederationSavedMachinePolicy};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerPresentation {
    pub(crate) profile_id: Option<String>,
    pub(crate) label: String,
}

impl PeerPresentation {
    fn from_peer(peer: &FederationPeer) -> Self {
        Self {
            profile_id: peer.profile_id.clone(),
            label: peer
                .display_label
                .clone()
                .unwrap_or_else(|| peer.alias.clone()),
        }
    }
}

/// Owns the persistent SSH process behind a saved peer's local bridge. A
/// monitor replaces the process in place when it reports a terminal failure.
struct SavedBridgeSupervisor {
    join: Option<JoinHandle<()>>,
    cancellation: Arc<AtomicBool>,
}

impl SavedBridgeSupervisor {
    fn retire(mut self) -> JoinHandle<()> {
        self.cancellation.store(true, Ordering::Release);
        retire_poll(self.join.take().expect("bridge supervisor join handle"))
    }
}

impl Drop for SavedBridgeSupervisor {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            drop(retire_poll(join));
        }
    }
}

/// One outbound route plus the identity-validation state established by its
/// poller. Identity-pinned routes never proxy before a successful validation.
#[derive(Clone, Debug)]
pub(crate) struct PeerRoute {
    target: ConnectionTarget,
    identity_validated: Arc<AtomicBool>,
    identity_validation_required: bool,
}

impl PeerRoute {
    fn new(target: ConnectionTarget, requires_identity_validation: bool) -> Self {
        Self {
            target,
            identity_validated: Arc::new(AtomicBool::new(!requires_identity_validation)),
            identity_validation_required: requires_identity_validation,
        }
    }

    pub(crate) fn target(&self) -> &ConnectionTarget {
        &self.target
    }

    pub(crate) fn identity_validated(&self) -> bool {
        self.identity_validated.load(Ordering::Acquire)
    }

    pub(crate) fn set_identity_validated(&self, validated: bool) {
        self.identity_validated.store(
            validated || !self.identity_validation_required,
            Ordering::Release,
        );
    }

    #[cfg(test)]
    pub(crate) fn for_test(target: ConnectionTarget) -> Self {
        Self::new(target, false)
    }

    #[cfg(test)]
    pub(crate) fn for_test_unvalidated(target: ConnectionTarget) -> Self {
        Self::new(target, true)
    }
}

/// A single running outbound poll thread plus the handle to stop and join it.
struct PeerHandle {
    /// Per-peer stop flag shared by the poller and optional bridge supervisor.
    stop: Arc<AtomicBool>,
    /// Join handle for the poll thread.
    join: JoinHandle<()>,
    /// The peer's `endpoint` this thread was spawned for, for `spec_differs`.
    endpoint: String,
    /// The peer's `token_file` this thread was spawned for, for `spec_differs`.
    token_file: Option<String>,
    /// Resolved token contents used by the live TCP route.
    token: Option<String>,
    /// The peer's expected install identity this thread was spawned with.
    expected_node_id: Option<String>,
    /// Saved-machine profile this SSH bridge was spawned for.
    profile_id: Option<String>,
    /// Named remote session this SSH bridge was spawned for.
    remote_session: Option<String>,
    /// Shared route used by both polling and target proxying.
    route: PeerRoute,
    /// Mutable label/profile presentation shared with the poll thread. Label-only
    /// changes update this cell without reconnecting the transport.
    presentation: Arc<RwLock<PeerPresentation>>,
    /// Keeps the saved peer's persistent SSH bridge supervised and alive.
    _ssh_bridge: Option<SavedBridgeSupervisor>,
}

#[derive(Clone, Default)]
struct CoordinatorSource {
    enabled: bool,
    explicit: Vec<FederationPeer>,
    policies: BTreeMap<crate::client::endpoint::ProfileId, FederationSavedMachinePolicy>,
    profiles: Vec<crate::client::endpoint::SavedSshEndpoint>,
}

/// Manages the outbound federation peer set at runtime: spawns a poll thread and
/// a proxy route per peer, and reconciles that set against desired config on
/// `reload-config`. See the module docs for the locking model.
pub struct FederationPeerManager {
    /// Serializes full reconciliation while allowing the handle lock to be
    /// released during bounded bridge retirement.
    reconcile_lock: Mutex<()>,
    /// One running poll thread per outbound peer, keyed by alias.
    handles: Mutex<HashMap<String, PeerHandle>>,
    /// The outbound proxy registry, snapshot-swapped on reconcile.
    registry: RwLock<Arc<HashMap<String, PeerRoute>>>,
    /// Joins of retiring threads, joined only once `is_finished()`.
    reaper: Mutex<Vec<JoinHandle<()>>>,
    /// Shared cache the poll threads write and `agent.list` reads.
    store: Arc<Mutex<FederationStore>>,
    /// Global daemon-running flag; poll threads also observe it for shutdown.
    running: Arc<AtomicBool>,
    /// Coordinator config plus the last successfully loaded saved profiles.
    coordinator: Mutex<CoordinatorSource>,
    /// Stops the saved-profile catalog watcher independently of the daemon flag.
    catalog_stop: Arc<AtomicBool>,
    /// Catalog watcher that detects CLI add/enable/disable/remove/rename writes.
    catalog_watcher: Mutex<Option<JoinHandle<()>>>,
}

impl FederationPeerManager {
    /// Build an empty manager sharing `store` and the global `running` flag. A
    /// lightweight watcher observes saved-profile catalog changes; it is inert
    /// until coordinator mode is enabled by [`Self::reconcile_config`].
    pub fn new(store: Arc<Mutex<FederationStore>>, running: Arc<AtomicBool>) -> Arc<Self> {
        let catalog_stop = Arc::new(AtomicBool::new(false));
        let manager = Arc::new(Self {
            reconcile_lock: Mutex::new(()),
            handles: Mutex::new(HashMap::new()),
            registry: RwLock::new(Arc::new(HashMap::new())),
            reaper: Mutex::new(Vec::new()),
            store,
            running,
            coordinator: Mutex::new(CoordinatorSource::default()),
            catalog_stop: Arc::clone(&catalog_stop),
            catalog_watcher: Mutex::new(None),
        });
        let weak = Arc::downgrade(&manager);
        let watcher = std::thread::spawn(move || watch_saved_profiles(weak, catalog_stop));
        *manager
            .catalog_watcher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(watcher);
        manager
    }

    /// A cheap snapshot of the outbound proxy registry for the hot per-connection
    /// path: a brief read lock and an `Arc::clone`. The returned `Arc` is a
    /// consistent view even if a reconcile swaps the map immediately after.
    pub fn registry_snapshot(&self) -> Arc<HashMap<String, PeerRoute>> {
        let registry = self
            .registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(&registry)
    }

    /// Apply explicit federation config and coordinator saved-machine policy.
    /// A successful catalog read is folded in immediately; later catalog writes
    /// are detected by the manager's watcher without restarting the server.
    pub fn reconcile_config(&self, config: &FederationConfig) {
        let loaded_profiles = if config.coordinator {
            match crate::client::endpoint::EndpointCatalog::load_profiles() {
                Ok(profiles) => Some(profiles),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "saved-machine federation catalog reload failed; keeping last good routes"
                    );
                    None
                }
            }
        } else {
            None
        };
        let mut source = self
            .coordinator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        source.enabled = config.coordinator;
        source.explicit.clone_from(&config.peers);
        source.policies.clone_from(&config.saved_machines);
        if let Some(profiles) = loaded_profiles {
            source.profiles = profiles;
        }
        let desired = compose_desired(&source);
        self.reconcile(&desired);
    }

    fn refresh_saved_profiles(&self) {
        let enabled = self
            .coordinator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .enabled;
        if !enabled {
            return;
        }
        let profiles = match crate::client::endpoint::EndpointCatalog::load_profiles() {
            Ok(profiles) => profiles,
            Err(error) => {
                tracing::warn!(%error, "saved-machine federation catalog reload failed; keeping last good routes");
                return;
            }
        };
        let mut source = self
            .coordinator
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if source.profiles == profiles {
            return;
        }
        source.profiles = profiles;
        let desired = compose_desired(&source);
        self.reconcile(&desired);
    }

    /// Reconcile the running outbound peer set against `desired`.
    ///
    /// Holds the `handles` lock for the whole call (so two reconciles serialize)
    /// and follows the lock order **H → S → R**:
    /// 1. Reap any finished retiring threads.
    /// 2. Compute the desired OUTBOUND set (peers with an `endpoint`) by alias.
    /// 3. For each running alias no longer desired, or whose connection/trust
    ///    spec (`endpoint`, `token_file`, `expected_node_id`, `profile_id`, or
    ///    `remote_session`) changed: set its `stop` flag AND evict its store
    ///    entry under the store lock, then detach its retirement into the reaper.
    /// 4. For each desired outbound alias not already running: spawn a fresh
    ///    poll thread.
    /// 5. Rebuild and swap the proxy registry from the same live routes used by
    ///    pollers.
    pub fn reconcile(&self, desired: &[FederationPeer]) {
        let _reconcile = self
            .reconcile_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.running.load(Ordering::Acquire) {
            return;
        }
        let mut handles = self
            .handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // 1. Join any retiring threads that have already finished.
        self.reap_finished();

        // 2. Desired OUTBOUND peers (an `endpoint` is present), by alias. A peer
        //    without an endpoint is inbound-only and spawns nothing.
        let mut desired_out: HashMap<&str, &FederationPeer> = HashMap::new();
        for peer in desired {
            if peer.endpoint.is_some() {
                desired_out.insert(peer.alias.as_str(), peer);
            }
        }

        // 3. Stop + evict every running alias that is gone or whose spec changed.
        let to_stop: Vec<String> = handles
            .iter()
            .filter(|(alias, handle)| match desired_out.get(alias.as_str()) {
                None => true,
                Some(peer) => spec_differs(handle, peer),
            })
            .map(|(alias, _)| alias.clone())
            .collect();
        let mut bridge_retirements = Vec::new();
        for alias in &to_stop {
            let Some(handle) = handles.remove(alias) else {
                continue;
            };
            // S (brief): set stop AND evict the alias while holding the store
            // Mutex, so a retiring thread's under-lock stop check (see
            // `poll_once_into_cache`) can never write a stale entry afterward.
            {
                let mut store = self
                    .store
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                handle.stop.store(true, Ordering::Relaxed);
                store.remove_peer(alias);
            }
            let PeerHandle {
                join, _ssh_bridge, ..
            } = handle;
            if let Some(bridge) = _ssh_bridge {
                bridge_retirements.push(bridge.retire());
            }
            let mut reaper = self
                .reaper
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            reaper.push(retire_poll(join));
            info!(alias = %alias, "federation peer stopped and evicted (reconcile)");
        }
        // Supervisor joins run concurrently and never hold the handle registry
        // lock. Waiting here closes stable profile sockets before replacement.
        drop(handles);
        for join in bridge_retirements {
            let _ = join.join();
        }
        let mut handles = self
            .handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // 4. Update display-only presentation in place, or spawn a poll thread
        //    for every newly desired outbound alias.
        for (alias, peer) in &desired_out {
            if let Some(handle) = handles.get(*alias) {
                let presentation = PeerPresentation::from_peer(peer);
                *handle
                    .presentation
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = presentation.clone();
                self.store
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .update_peer_presentation(
                        alias,
                        presentation.profile_id.as_deref(),
                        &presentation.label,
                    );
                debug!(alias = %alias, "federation peer route unchanged; presentation updated");
                continue;
            }
            if let Some(handle) = self.spawn_peer_poll((*peer).clone()) {
                handles.insert((*alias).to_string(), handle);
                info!(alias = %alias, "federation peer spawned (reconcile)");
            }
        }

        // 5. Rebuild the outbound proxy registry from the same routes held by
        // the live pollers. SSH clones point at the manager-owned local bridge.
        let new_map = handles
            .iter()
            .map(|(alias, handle)| (alias.clone(), handle.route.clone()))
            .collect();
        let mut registry = self
            .registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *registry = Arc::new(new_map);
    }

    /// Resolve one outbound route and spawn its poll thread. SSH peers use the
    /// upstream saved-machine `remote-api-bridge`; the manager owns that bridge
    /// and shares its local socket with polling and proxying.
    fn spawn_peer_poll(&self, peer: FederationPeer) -> Option<PeerHandle> {
        let endpoint = peer.endpoint.as_deref()?;
        let token = endpoint
            .starts_with("tcp://")
            .then(|| read_peer_token(&peer))
            .flatten();
        let stop = Arc::new(AtomicBool::new(false));
        let parsed = match crate::api::client::endpoint_to_target(endpoint, token.clone()) {
            Ok(target) => target,
            Err(error) => {
                tracing::warn!(alias = %peer.alias, %endpoint, %error, "invalid federation endpoint; peer not started");
                return None;
            }
        };
        let (route, ssh_bridge) = match parsed {
            ConnectionTarget::Ssh(target) => {
                let Some(profile_id) = peer.profile_id.as_deref() else {
                    tracing::warn!(alias = %peer.alias, "SSH federation peer requires profile_id");
                    return None;
                };
                let Some(session) = peer.remote_session.as_deref() else {
                    tracing::warn!(alias = %peer.alias, "SSH federation peer requires remote_session");
                    return None;
                };
                let target = match target.user {
                    Some(user) => format!("{user}@{}", target.host),
                    None => target.host,
                };
                let (route, bridge) = match start_saved_peer_bridge(
                    profile_id,
                    &target,
                    session,
                    Arc::clone(&self.running),
                    Arc::clone(&stop),
                ) {
                    Ok(started) => started,
                    Err(error) => {
                        tracing::warn!(alias = %peer.alias, %error, "SSH federation remote-api-bridge did not start");
                        return None;
                    }
                };
                (route, Some(bridge))
            }
            target => (target, None),
        };
        let route = PeerRoute::new(route, peer.expected_node_id.is_some());
        let endpoint = peer.endpoint.clone().unwrap_or_default();
        let token_file = peer.token_file.clone();
        let expected_node_id = peer.expected_node_id.clone();
        let profile_id = peer.profile_id.clone();
        let remote_session = peer.remote_session.clone();
        let presentation = Arc::new(RwLock::new(PeerPresentation::from_peer(&peer)));
        let cache = Arc::clone(&self.store);
        let running = Arc::clone(&self.running);
        let thread_stop = Arc::clone(&stop);
        let poll_route = route.clone();
        let poll_presentation = Arc::clone(&presentation);
        let join = std::thread::spawn(move || {
            run_federation_peer_poll(
                peer,
                poll_route,
                poll_presentation,
                cache,
                running,
                thread_stop,
            );
        });
        Some(PeerHandle {
            stop,
            join,
            endpoint,
            token_file,
            expected_node_id,
            token,
            profile_id,
            remote_session,
            route,
            presentation,
            _ssh_bridge: ssh_bridge,
        })
    }

    /// Join every retiring thread that has already finished, leaving the rest in
    /// the reaper. Never blocks: a thread that is still running is left for a
    /// later reap. Takes only the `reaper` lock.
    fn reap_finished(&self) {
        let mut reaper = self
            .reaper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pending = std::mem::take(&mut *reaper);
        for join in pending {
            if join.is_finished() {
                let _ = join.join();
            } else {
                reaper.push(join);
            }
        }
    }

    /// Stop the catalog watcher and every poll thread, then join every retiring
    /// thread. Called once from [`ServerHandle`](crate::api::ServerHandle)'s
    /// drop, where a blocking join is acceptable. Drains `handles` before
    /// joining so no lock is held across a poll join.
    pub fn join_all(&self) {
        self.catalog_stop.store(true, Ordering::Release);
        {
            let barrier = self
                .reconcile_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            drop(barrier);
        }
        let watcher = self
            .catalog_watcher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(watcher) = watcher {
            let _ = watcher.join();
        }
        let live: Vec<PeerHandle> = {
            let mut handles = self
                .handles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            handles.drain().map(|(_, handle)| handle).collect()
        };
        for handle in &live {
            handle.stop.store(true, Ordering::Relaxed);
        }
        let mut poll_joins = Vec::with_capacity(live.len());
        let mut bridge_joins = Vec::new();
        for handle in live {
            let PeerHandle {
                join, _ssh_bridge, ..
            } = handle;
            poll_joins.push(join);
            if let Some(bridge) = _ssh_bridge {
                bridge_joins.push(bridge.retire());
            }
        }
        for join in poll_joins {
            let _ = join.join();
        }
        for join in bridge_joins {
            let _ = join.join();
        }
        let pending: Vec<JoinHandle<()>> = {
            let mut reaper = self
                .reaper
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *reaper)
        };
        for join in pending {
            let _ = join.join();
        }
    }

    /// Aliases with a currently running poll thread, for tests.
    #[cfg(test)]
    pub(crate) fn live_aliases(&self) -> Vec<String> {
        let handles = self
            .handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut aliases: Vec<String> = handles.keys().cloned().collect();
        aliases.sort();
        aliases
    }

    /// Current mutable presentation for one live route, for reload tests.
    #[cfg(test)]
    pub(crate) fn presentation_for(&self, alias: &str) -> Option<PeerPresentation> {
        let handles = self
            .handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        handles.get(alias).map(|handle| {
            handle
                .presentation
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        })
    }

    /// Remote session attached to one live transport generation, for reload tests.
    #[cfg(test)]
    pub(crate) fn remote_session_for(&self, alias: &str) -> Option<String> {
        self.handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(alias)
            .and_then(|handle| handle.remote_session.clone())
    }

    /// Reap finished retiring threads, then report how many are still pending,
    /// for tests polling that a retired thread has actually finished.
    #[cfg(test)]
    pub(crate) fn reap_and_count_pending(&self) -> usize {
        self.reap_finished();
        let reaper = self
            .reaper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reaper.len()
    }
}

fn watch_saved_profiles(manager: Weak<FederationPeerManager>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        let Some(manager) = manager.upgrade() else {
            return;
        };
        manager.refresh_saved_profiles();
        drop(manager);
        for _ in 0..10 {
            if stop.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn compose_desired(source: &CoordinatorSource) -> Vec<FederationPeer> {
    let mut desired = source.explicit.clone();
    if !source.enabled {
        return desired;
    }
    let mut aliases: std::collections::HashSet<String> =
        desired.iter().map(|peer| peer.alias.clone()).collect();
    for profile in source.profiles.iter().filter(|profile| profile.enabled) {
        let Some(policy) = source.policies.get(&profile.id) else {
            continue;
        };
        let alias = profile.id.to_string();
        if !aliases.insert(alias.clone()) {
            tracing::warn!(
                %alias,
                "saved-machine federation alias collides with an explicit peer; explicit peer wins"
            );
            continue;
        }
        desired.push(FederationPeer {
            alias,
            display_label: Some(profile.label.clone()),
            endpoint: Some(format!(
                "ssh://{}",
                profile
                    .target
                    .strip_prefix("ssh://")
                    .unwrap_or(&profile.target)
            )),
            profile_id: Some(profile.id.to_string()),
            remote_session: Some(profile.session.clone()),
            token_file: None,
            expected_node_id: Some(policy.expected_machine_id.clone()),
            capability: crate::config::CapabilityTier::Admin,
        });
    }
    desired
}

/// Whether a running peer's connection or trust spec differs from the desired
/// config, so its thread must be retired and respawned.
fn spec_differs(handle: &PeerHandle, peer: &FederationPeer) -> bool {
    let token = peer
        .endpoint
        .as_deref()
        .is_some_and(|endpoint| endpoint.starts_with("tcp://"))
        .then(|| read_peer_token(peer))
        .flatten();
    handle.endpoint != peer.endpoint.clone().unwrap_or_default()
        || handle.token_file != peer.token_file
        || handle.token != token
        || handle.expected_node_id != peer.expected_node_id
        || handle.profile_id != peer.profile_id
        || handle.remote_session != peer.remote_session
}

fn start_saved_peer_bridge(
    profile_id: &str,
    target: &str,
    session: &str,
    running: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> io::Result<(ConnectionTarget, SavedBridgeSupervisor)> {
    let cancellation = Arc::new(AtomicBool::new(false));
    let bridge = crate::remote::SavedSshApiBridge::start_cancellable(
        profile_id,
        target,
        session,
        true,
        Arc::clone(&cancellation),
    )?;
    let path = bridge.socket_path().to_owned();
    let profile_id = profile_id.to_owned();
    let target = target.to_owned();
    let session = session.to_owned();
    let thread_cancellation = Arc::clone(&cancellation);
    let join = std::thread::spawn(move || {
        supervise_saved_peer_bridge(
            bridge,
            &profile_id,
            &target,
            &session,
            &running,
            &stop,
            &thread_cancellation,
        );
    });
    Ok((
        ConnectionTarget::SocketPath(path),
        SavedBridgeSupervisor {
            join: Some(join),
            cancellation,
        },
    ))
}

fn supervise_saved_peer_bridge(
    initial: crate::remote::SavedSshApiBridge,
    profile_id: &str,
    target: &str,
    session: &str,
    running: &AtomicBool,
    stop: &AtomicBool,
    cancellation: &Arc<AtomicBool>,
) {
    let mut bridge = Some(initial);
    let mut use_cached_metadata = true;
    while !bridge_stopping(running, stop, cancellation) {
        if let Some(active) = bridge.as_ref() {
            let failure = match active.try_reported_failure() {
                Ok(Some(failure)) => failure,
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(failure) => failure,
            };
            if bridge_stopping(running, stop, cancellation) {
                break;
            }
            use_cached_metadata =
                !crate::remote::SavedSshApiBridge::stale_metadata_failure(&failure);
            if !use_cached_metadata {
                active.invalidate_metadata();
            }
            tracing::warn!(%failure, "saved federation bridge exited; restarting");
            drop(bridge.take());
        }
        if bridge_stopping(running, stop, cancellation) {
            break;
        }

        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let profile_id = profile_id.to_owned();
        let target = target.to_owned();
        let session = session.to_owned();
        let restart_cancellation = Arc::clone(cancellation);
        let mut restart = Some(std::thread::spawn(move || {
            let result = crate::remote::SavedSshApiBridge::start_cancellable(
                &profile_id,
                &target,
                &session,
                use_cached_metadata,
                restart_cancellation,
            );
            let _ = result_tx.send(result);
        }));

        loop {
            if bridge_stopping(running, stop, cancellation) {
                cancellation.store(true, Ordering::Release);
                if let Some(join) = restart.take() {
                    let _ = join.join();
                }
                return;
            }
            match result_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(started)) => {
                    if let Some(join) = restart.take() {
                        let _ = join.join();
                    }
                    bridge = Some(started);
                    use_cached_metadata = true;
                    break;
                }
                Ok(Err(error)) => {
                    if let Some(join) = restart.take() {
                        let _ = join.join();
                    }
                    tracing::warn!(%error, "saved federation bridge restart failed");
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    if let Some(join) = restart.take() {
                        let _ = join.join();
                    }
                    tracing::warn!("saved federation bridge restart worker disconnected");
                    break;
                }
            }
        }
        if bridge.is_none() {
            for _ in 0..10 {
                if bridge_stopping(running, stop, cancellation) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    cancellation.store(true, Ordering::Release);
}

fn bridge_stopping(running: &AtomicBool, stop: &AtomicBool, cancellation: &AtomicBool) -> bool {
    !running.load(Ordering::Relaxed)
        || stop.load(Ordering::Relaxed)
        || cancellation.load(Ordering::Acquire)
}

/// Join one stopped poll thread away from the reconcile caller.
fn retire_poll(join: JoinHandle<()>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = join.join();
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_applies_in_place_tcp_token_rotation() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let token_path = std::env::temp_dir().join(format!("herdr-federation-token-{nonce}.txt"));
        std::fs::write(&token_path, "old-token\n").unwrap();
        let peer = FederationPeer {
            alias: "build".into(),
            endpoint: Some("tcp://127.0.0.1:9".into()),
            token_file: Some(token_path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let running = Arc::new(AtomicBool::new(true));
        let manager = FederationPeerManager::new(
            Arc::new(Mutex::new(FederationStore::default())),
            Arc::clone(&running),
        );

        manager.reconcile(std::slice::from_ref(&peer));
        assert_eq!(
            route_token(&manager.registry_snapshot()["build"]),
            Some("old-token")
        );

        std::fs::write(&token_path, "new-token\n").unwrap();
        manager.reconcile(std::slice::from_ref(&peer));
        assert_eq!(
            route_token(&manager.registry_snapshot()["build"]),
            Some("new-token")
        );

        running.store(false, Ordering::Relaxed);
        manager.join_all();
        let _ = std::fs::remove_file(token_path);
    }

    fn route_token(route: &PeerRoute) -> Option<&str> {
        match route.target() {
            ConnectionTarget::Tcp { token, .. } => token.as_deref(),
            _ => panic!("expected TCP route"),
        }
    }

    #[test]
    fn coordinator_adapts_enabled_trusted_profiles_without_label_routing() {
        let mut profile = crate::client::endpoint::SavedSshEndpoint::new(
            "Build",
            "ssh://dev@build.example",
            "agent-work",
        )
        .unwrap();
        let profile_id = profile.id.clone();
        let mut source = CoordinatorSource {
            enabled: true,
            explicit: Vec::new(),
            policies: BTreeMap::from([(
                profile_id.clone(),
                FederationSavedMachinePolicy {
                    expected_machine_id: "machine_build".into(),
                },
            )]),
            profiles: vec![profile.clone()],
        };

        let desired = compose_desired(&source);
        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].alias, profile_id.as_str());
        assert_eq!(desired[0].display_label.as_deref(), Some("Build"));
        assert_eq!(
            desired[0].endpoint.as_deref(),
            Some("ssh://dev@build.example")
        );
        assert_eq!(desired[0].remote_session.as_deref(), Some("agent-work"));
        assert_eq!(
            desired[0].expected_node_id.as_deref(),
            Some("machine_build")
        );

        profile.label = "Renamed".into();
        source.profiles = vec![profile.clone()];
        let renamed = compose_desired(&source);
        assert_eq!(renamed[0].alias, desired[0].alias);
        assert_eq!(renamed[0].endpoint, desired[0].endpoint);
        assert_eq!(renamed[0].display_label.as_deref(), Some("Renamed"));

        profile.enabled = false;
        source.profiles = vec![profile];
        assert!(compose_desired(&source).is_empty());
    }

    #[test]
    fn coordinator_role_and_profile_identity_fail_closed() {
        let profile = crate::client::endpoint::SavedSshEndpoint::new(
            "Build",
            "dev@build.example",
            "agent-work",
        )
        .unwrap();
        let mut source = CoordinatorSource {
            enabled: false,
            explicit: Vec::new(),
            policies: BTreeMap::from([(
                profile.id.clone(),
                FederationSavedMachinePolicy {
                    expected_machine_id: "machine_build".into(),
                },
            )]),
            profiles: vec![profile.clone()],
        };
        assert!(
            compose_desired(&source).is_empty(),
            "remote/default role must not auto-federate saved machines"
        );

        source.enabled = true;
        let replacement = crate::client::endpoint::SavedSshEndpoint::new(
            "Build",
            "dev@build.example",
            "agent-work",
        )
        .unwrap();
        assert_ne!(replacement.id, profile.id);
        source.profiles = vec![replacement];
        assert!(
            compose_desired(&source).is_empty(),
            "remove/re-add must not inherit trust keyed to the old profile id"
        );
    }
}
