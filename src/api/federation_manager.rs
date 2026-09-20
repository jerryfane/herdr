//! Runtime manager for the OUTBOUND federation peer set.
//!
//! One [`FederationPeerManager`] is shared (as an `Arc`) between the API
//! [`ServerHandle`](crate::api::ServerHandle) — which spawns the initial peer
//! set at boot and reads the outbound proxy registry on the hot per-connection
//! path — and the [`App`](crate::app::App), whose `reload-config` handler calls
//! [`FederationPeerManager::reconcile`] to add, remove, or re-point peers with
//! no daemon restart.
//!
//! It owns three things behind their own locks:
//! - `handles`: one poll thread per outbound peer (a peer with an `endpoint`),
//!   each carrying a per-peer `stop` flag so it can be retired individually.
//! - `registry`: the alias→target map the outbound proxy router reads, kept
//!   behind `RwLock<Arc<_>>` so the hot path takes a brief read lock and an
//!   `Arc::clone` (arc-swap semantics, no new dependency) and reconcile swaps a
//!   freshly built map in under a brief write lock.
//! - `reaper`: joins of threads being retired, joined only once they have
//!   finished so the reconcile (called on the single-threaded app loop) never
//!   blocks on a thread teardown.
//!
//! ## Locking model (no deadlock possible)
//! Three locks — **H** (`handles`), **S** (`store`, external), **R**
//! (`registry`). Only [`reconcile`](FederationPeerManager::reconcile) ever holds
//! more than one, always in the order **H → S (briefly) → R**. A changed SSH
//! route is stopped and its bridge is shut down while H remains held so the
//! replacement can safely reuse the profile's socket path; bridge workers do not
//! take H, S, or R. Poll threads take **S** only; accept/proxy threads take **R**
//! only (one `Arc::clone`). No cycle is reachable.
//!
//! ## Default-off byte-identical
//! With no peer configured (or none with an `endpoint`), reconcile spawns zero
//! threads and swaps in an empty registry, so the outbound router never matches
//! and the local `agent.list` path is unchanged. `reconcile(&[])` is a clean
//! no-op / full teardown.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use tracing::{debug, info};

use crate::api::client::ConnectionTarget;
use crate::api::federation_store::FederationStore;
use crate::api::server::{read_peer_token, run_federation_peer_poll};
use crate::config::FederationPeer;

/// Owns the persistent SSH process behind a saved peer's local bridge. A
/// monitor replaces the process in place when it reports a terminal failure.
struct SavedBridgeSupervisor {
    join: Option<JoinHandle<()>>,
}

impl Drop for SavedBridgeSupervisor {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
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
    route: ConnectionTarget,
    /// Keeps the saved peer's persistent SSH bridge supervised and alive.
    _ssh_bridge: Option<SavedBridgeSupervisor>,
}

/// Manages the outbound federation peer set at runtime: spawns a poll thread and
/// a proxy route per peer, and reconciles that set against desired config on
/// `reload-config`. See the module docs for the locking model.
pub struct FederationPeerManager {
    /// One running poll thread per outbound peer, keyed by alias.
    handles: Mutex<HashMap<String, PeerHandle>>,
    /// The outbound proxy registry, snapshot-swapped on reconcile.
    registry: RwLock<Arc<HashMap<String, ConnectionTarget>>>,
    /// Joins of retiring threads, joined only once `is_finished()`.
    reaper: Mutex<Vec<JoinHandle<()>>>,
    /// Shared cache the poll threads write and `agent.list` reads.
    store: Arc<Mutex<FederationStore>>,
    /// Global daemon-running flag; poll threads also observe it for shutdown.
    running: Arc<AtomicBool>,
}

impl FederationPeerManager {
    /// Build an empty manager sharing `store` and the global `running` flag. The
    /// registry starts empty; call [`reconcile`](Self::reconcile) with the boot
    /// peer set to populate it.
    pub fn new(store: Arc<Mutex<FederationStore>>, running: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            handles: Mutex::new(HashMap::new()),
            registry: RwLock::new(Arc::new(HashMap::new())),
            reaper: Mutex::new(Vec::new()),
            store,
            running,
        })
    }

    /// A cheap snapshot of the outbound proxy registry for the hot per-connection
    /// path: a brief read lock and an `Arc::clone`. The returned `Arc` is a
    /// consistent view even if a reconcile swaps the map immediately after.
    pub fn registry_snapshot(&self) -> Arc<HashMap<String, ConnectionTarget>> {
        let registry = self
            .registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(&registry)
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
            // Close the bridge before starting its replacement: saved bridges
            // intentionally use one socket path per immutable profile. Drop is
            // bounded and cancels every active per-connection SSH worker.
            let PeerHandle {
                join, _ssh_bridge, ..
            } = handle;
            drop(_ssh_bridge);
            let mut reaper = self
                .reaper
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            reaper.push(retire_poll(join));
            info!(alias = %alias, "federation peer stopped and evicted (reconcile)");
        }

        // 4. Spawn a poll thread for every newly desired outbound alias.
        for (alias, peer) in &desired_out {
            if handles.contains_key(*alias) {
                debug!(alias = %alias, "federation peer unchanged (reconcile)");
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
        let endpoint = peer.endpoint.clone().unwrap_or_default();
        let token_file = peer.token_file.clone();
        let expected_node_id = peer.expected_node_id.clone();
        let profile_id = peer.profile_id.clone();
        let remote_session = peer.remote_session.clone();
        let cache = Arc::clone(&self.store);
        let running = Arc::clone(&self.running);
        let thread_stop = Arc::clone(&stop);
        let poll_route = route.clone();
        let join = std::thread::spawn(move || {
            run_federation_peer_poll(peer, poll_route, cache, running, thread_stop);
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

    /// Stop and join every poll thread, then join every retiring thread. Called
    /// once from [`ServerHandle`](crate::api::ServerHandle)'s drop, where a
    /// blocking join is acceptable. Drains `handles` before joining so no lock is
    /// held across a join.
    pub fn join_all(&self) {
        let live: Vec<PeerHandle> = {
            let mut handles = self
                .handles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            handles.drain().map(|(_, handle)| handle).collect()
        };
        for handle in live {
            handle.stop.store(true, Ordering::Relaxed);
            let PeerHandle {
                join, _ssh_bridge, ..
            } = handle;
            drop(_ssh_bridge);
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
    let bridge = crate::remote::SavedSshApiBridge::start(profile_id, target, session, true)?;
    let path = bridge.socket_path().to_owned();
    let profile_id = profile_id.to_owned();
    let target = target.to_owned();
    let session = session.to_owned();
    let join = std::thread::spawn(move || {
        supervise_saved_peer_bridge(bridge, &profile_id, &target, &session, &running, &stop);
    });
    Ok((
        ConnectionTarget::SocketPath(path),
        SavedBridgeSupervisor { join: Some(join) },
    ))
}

fn supervise_saved_peer_bridge(
    initial: crate::remote::SavedSshApiBridge,
    profile_id: &str,
    target: &str,
    session: &str,
    running: &AtomicBool,
    stop: &AtomicBool,
) {
    let mut bridge = Some(initial);
    let mut use_cached_metadata = true;
    while running.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
        if let Some(active) = bridge.as_ref() {
            let Some(failure) = active.reported_failure() else {
                continue;
            };
            use_cached_metadata =
                !crate::remote::SavedSshApiBridge::stale_metadata_failure(&failure);
            if !use_cached_metadata {
                active.invalidate_metadata();
            }
            tracing::warn!(%failure, "saved federation bridge exited; restarting");
            drop(bridge.take());
        }
        match crate::remote::SavedSshApiBridge::start(
            profile_id,
            target,
            session,
            use_cached_metadata,
        ) {
            Ok(started) => {
                bridge = Some(started);
                use_cached_metadata = true;
            }
            Err(error) => {
                tracing::warn!(%error, "saved federation bridge restart failed");
                for _ in 0..10 {
                    if !running.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
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

    fn route_token(route: &ConnectionTarget) -> Option<&str> {
        match route {
            ConnectionTarget::Tcp { token, .. } => token.as_deref(),
            _ => panic!("expected TCP route"),
        }
    }
}
