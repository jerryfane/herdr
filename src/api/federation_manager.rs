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
//! more than one, always in the order **H → S (briefly) → R**: `S` is taken and
//! released per evicted alias (never across a spawn or join), and `R` is written
//! only after the token-file reads in `build_peer_registry` are done, never
//! across them. Poll threads take **S** only; accept/proxy threads take **R**
//! only (one `Arc::clone`). No cycle is reachable.
//!
//! ## Default-off byte-identical
//! With no peer configured (or none with an `endpoint`), reconcile spawns zero
//! threads and swaps in an empty registry, so the outbound router never matches
//! and the local `agent.list` path is unchanged. `reconcile(&[])` is a clean
//! no-op / full teardown.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use tracing::{debug, info};

use crate::api::client::ConnectionTarget;
use crate::api::federation_store::FederationStore;
use crate::api::server::{build_peer_registry, run_federation_peer_poll};
use crate::config::FederationPeer;

/// A single running outbound poll thread plus the handle to stop and join it.
struct PeerHandle {
    /// Per-peer stop flag. Setting it (while holding the store lock, in
    /// reconcile) retires just this peer's poll thread.
    stop: Arc<AtomicBool>,
    /// Join handle for the poll thread.
    join: JoinHandle<()>,
    /// The peer's `endpoint` this thread was spawned for, for `spec_differs`.
    endpoint: String,
    /// The peer's `token_file` this thread was spawned for, for `spec_differs`.
    token_file: Option<String>,
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
    /// 3. For each running alias no longer desired, or whose `endpoint`/
    ///    `token_file` changed: set its `stop` flag AND evict its store entry
    ///    under the store lock, then detach its join into the reaper.
    /// 4. For each desired outbound alias not already running: spawn a fresh
    ///    poll thread.
    /// 5. Rebuild and swap the proxy registry (token-file reads happen in
    ///    `build_peer_registry`, before the registry write lock is taken).
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
            // Detach: never join on this (single-threaded app) call path. The
            // reaper joins it later once it has finished.
            let mut reaper = self
                .reaper
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            reaper.push(handle.join);
            info!(alias = %alias, "federation peer stopped and evicted (reconcile)");
        }

        // 4. Spawn a poll thread for every newly desired outbound alias.
        for (alias, peer) in &desired_out {
            if handles.contains_key(*alias) {
                debug!(alias = %alias, "federation peer unchanged (reconcile)");
                continue;
            }
            let handle = self.spawn_peer_poll((*peer).clone());
            handles.insert((*alias).to_string(), handle);
            info!(alias = %alias, "federation peer spawned (reconcile)");
        }

        // 5. Rebuild the outbound proxy registry and swap it in. The token-file
        //    reads happen inside `build_peer_registry`, NOT under the registry
        //    write lock, which is held only for the pointer swap.
        let new_map = build_peer_registry(desired);
        {
            let mut registry = self
                .registry
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *registry = Arc::new(new_map);
        }
    }

    /// Spawn one outbound poll thread for `peer` with a fresh (unset) stop flag.
    /// Only called for peers with an `endpoint`.
    fn spawn_peer_poll(&self, peer: FederationPeer) -> PeerHandle {
        let stop = Arc::new(AtomicBool::new(false));
        let endpoint = peer.endpoint.clone().unwrap_or_default();
        let token_file = peer.token_file.clone();
        let cache = Arc::clone(&self.store);
        let running = Arc::clone(&self.running);
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            run_federation_peer_poll(peer, cache, running, thread_stop);
        });
        PeerHandle {
            stop,
            join,
            endpoint,
            token_file,
        }
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
            let _ = handle.join.join();
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

/// Whether a running peer's spec (`endpoint` or `token_file`) differs from the
/// desired config, so its thread must be retired and respawned.
fn spec_differs(handle: &PeerHandle, peer: &FederationPeer) -> bool {
    handle.endpoint != peer.endpoint.clone().unwrap_or_default()
        || handle.token_file != peer.token_file
}
