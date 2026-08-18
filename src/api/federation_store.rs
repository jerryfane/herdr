//! In-memory cache of remote federation peers' agents.
//!
//! The outbound federation client (see `crate::api::server`) polls each
//! configured peer's `agent.list` on a timer and writes the result here. The
//! local `agent.list` handler reads it back through [`FederationStore::merged_agents`],
//! which stamps every remote agent with an honest reachability status so a stale
//! `idle`/`done` is never presented as current once a peer stops answering.
//!
//! The store is shared behind an `Arc<Mutex<_>>`: the poll threads are writers,
//! the app loop is the reader. When no peer has an `endpoint` no poll thread is
//! ever spawned, so the store stays empty and the merge is a no-op — the local
//! `agent.list` path is byte-identical to a build without federation.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::api::schema::{AgentInfo, AgentStatus};

/// Reachability of a federation peer, derived from consecutive poll outcomes.
///
/// Serialized onto remote [`AgentInfo`]s so a client can tell a live peer from
/// one that has gone quiet. A C-like enum, so it derives `Eq` and keeps
/// [`AgentInfo`]'s `Eq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// The last poll succeeded.
    Reachable,
    /// One or two consecutive polls have failed; last-known agents are retained.
    Degraded,
    /// At least [`UNREACHABLE_MISS_THRESHOLD`] consecutive polls have failed; the
    /// peer is treated as offline and its agents are stamped `unknown`.
    Unreachable,
}

/// Consecutive poll misses at which a peer flips from `Degraded` to
/// `Unreachable`.
pub const UNREACHABLE_MISS_THRESHOLD: u32 = 3;

/// Map a running count of consecutive poll misses to a [`Reachability`].
///
/// `0` misses is [`Reachability::Reachable`]; `1..=2` is
/// [`Reachability::Degraded`] (last-known agents are kept); `>= 3` is
/// [`Reachability::Unreachable`].
pub fn reachability_for_misses(consecutive_misses: u32) -> Reachability {
    match consecutive_misses {
        0 => Reachability::Reachable,
        n if n < UNREACHABLE_MISS_THRESHOLD => Reachability::Degraded,
        _ => Reachability::Unreachable,
    }
}

/// Tracks consecutive poll misses for a single peer and maps them to a
/// [`Reachability`]. Held in a poll thread's local state, not in the store.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReachabilityTracker {
    consecutive_misses: u32,
}

impl ReachabilityTracker {
    /// Record a successful poll: resets the miss counter and reports
    /// [`Reachability::Reachable`].
    pub fn record_success(&mut self) -> Reachability {
        self.consecutive_misses = 0;
        Reachability::Reachable
    }

    /// Record a failed poll: increments the miss counter and reports the
    /// resulting degraded/unreachable status.
    pub fn record_miss(&mut self) -> Reachability {
        self.consecutive_misses = self.consecutive_misses.saturating_add(1);
        reachability_for_misses(self.consecutive_misses)
    }
}

/// One federation peer's cached agents plus its current reachability.
///
/// `agents` are stored already alias-prefixed (see the poll thread); the honest
/// reachability stamping is applied on read in [`FederationStore::merged_agents`].
#[derive(Debug, Clone)]
pub struct PeerCacheEntry {
    /// Current reachability of the peer.
    pub reachability: Reachability,
    /// Last-known agents from this peer, alias-prefixed at write time.
    pub agents: Vec<AgentInfo>,
    /// When the last successful poll landed, if any. Recorded now for a later
    /// staleness surface (e.g. a `last_seen` age in `agent.list`); not yet read
    /// on the merge path, so it reads as unused in a non-test build.
    #[allow(dead_code)]
    pub last_seen: Option<Instant>,
}

impl PeerCacheEntry {
    /// A fresh entry from a successful poll.
    pub fn reachable(agents: Vec<AgentInfo>, last_seen: Instant) -> Self {
        Self {
            reachability: Reachability::Reachable,
            agents,
            last_seen: Some(last_seen),
        }
    }
}

/// Cache of every configured federation peer's agents, keyed by peer alias.
#[derive(Debug, Default)]
pub struct FederationStore {
    peers: HashMap<String, PeerCacheEntry>,
}

impl FederationStore {
    /// Replace a peer's cached entry. Called by the poll thread after each poll.
    pub fn set_peer(&mut self, alias: impl Into<String>, entry: PeerCacheEntry) {
        self.peers.insert(alias.into(), entry);
    }

    /// The cached entry for `alias`, if any. An inspection accessor exercised by
    /// tests; the merge path reads through [`Self::merged_agents`] instead, so
    /// this reads as unused in a non-test build.
    #[allow(dead_code)]
    pub fn peer(&self, alias: &str) -> Option<&PeerCacheEntry> {
        self.peers.get(alias)
    }

    /// Mark a peer's reachability without disturbing its last-known agents.
    ///
    /// Used on a poll miss: the agents from the last success are retained, only
    /// the reachability changes. A miss for a peer that never succeeded records
    /// an empty entry so its offline status is still observable.
    pub fn degrade_peer(&mut self, alias: &str, reachability: Reachability) {
        match self.peers.get_mut(alias) {
            Some(entry) => entry.reachability = reachability,
            None => {
                self.peers.insert(
                    alias.to_string(),
                    PeerCacheEntry {
                        reachability,
                        agents: Vec::new(),
                        last_seen: None,
                    },
                );
            }
        }
    }

    /// Whether any peer is cached. Empty means federation contributed nothing.
    /// Exercised by the no-federation regression tests; the merge path does not
    /// need it (extending by an empty set is a no-op), so it reads as unused in a
    /// non-test build.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Every cached peer's agents, honest-reachability stamped for merge into the
    /// local `agent.list`.
    ///
    /// - `Reachable`: the agent is returned as-is with its `reachability` set.
    /// - `Degraded`/`Unreachable`: the visible `agent_status` is replaced with
    ///   [`AgentStatus::Unknown`] and the last-known status is preserved in
    ///   `last_known_status`, so a stale `idle`/`done` is never shown as current
    ///   the moment a peer stops answering. `reachability` still distinguishes a
    ///   briefly-degraded peer from a fully offline one.
    pub fn merged_agents(&self) -> Vec<AgentInfo> {
        self.peers
            .values()
            .flat_map(|entry| {
                entry
                    .agents
                    .iter()
                    .map(|agent| stamp_agent(agent, entry.reachability))
            })
            .collect()
    }
}

/// Apply the honest-offline reachability stamp to one stored (already-prefixed)
/// remote agent.
fn stamp_agent(agent: &AgentInfo, reachability: Reachability) -> AgentInfo {
    let mut stamped = agent.clone();
    stamped.reachability = Some(reachability);
    // Only a `Reachable` peer surfaces its real live status. The moment a peer
    // stops answering — `Degraded` (1-2 misses) OR `Unreachable` (>= 3) — its
    // last poll's `idle`/`done` is no longer known to be current, so it must not
    // be presented as the live `agent_status`: surface `unknown` and keep the
    // real last-known status separately in `last_known_status`. A consumer that
    // reads `agent_status` alone is then never misled by a stale idle/done; the
    // `reachability` field still tells a briefly-degraded peer from a fully
    // offline one.
    if reachability != Reachability::Reachable {
        stamped.last_known_status = Some(agent.agent_status);
        stamped.agent_status = AgentStatus::Unknown;
    }
    stamped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(status: AgentStatus, name: &str) -> AgentInfo {
        let value = serde_json::json!({
            "terminal_id": "t",
            "name": name,
            "agent_status": status,
            "workspace_id": "ws",
            "tab_id": "tab",
            "pane_id": "pane",
            "focused": false,
            "revision": 1,
        });
        serde_json::from_value(value).expect("agent info deserializes")
    }

    #[test]
    fn miss_state_machine_degrades_then_goes_unreachable_then_recovers() {
        let mut tracker = ReachabilityTracker::default();
        // First and second miss: Degraded, last-known kept.
        assert_eq!(tracker.record_miss(), Reachability::Degraded);
        assert_eq!(tracker.record_miss(), Reachability::Degraded);
        // Third miss: Unreachable.
        assert_eq!(tracker.record_miss(), Reachability::Unreachable);
        // Still unreachable while misses accumulate.
        assert_eq!(tracker.record_miss(), Reachability::Unreachable);
        // A success resets and recovers immediately.
        assert_eq!(tracker.record_success(), Reachability::Reachable);
        // And the counter is back to zero, so the next miss is Degraded again.
        assert_eq!(tracker.record_miss(), Reachability::Degraded);
    }

    #[test]
    fn reachability_for_misses_boundaries() {
        assert_eq!(reachability_for_misses(0), Reachability::Reachable);
        assert_eq!(reachability_for_misses(1), Reachability::Degraded);
        assert_eq!(reachability_for_misses(2), Reachability::Degraded);
        assert_eq!(reachability_for_misses(3), Reachability::Unreachable);
        assert_eq!(reachability_for_misses(9), Reachability::Unreachable);
    }

    #[test]
    fn empty_store_merges_to_nothing() {
        let store = FederationStore::default();
        assert!(store.is_empty());
        assert!(store.merged_agents().is_empty());
    }

    #[test]
    fn reachable_peer_stamps_reachable_and_keeps_status() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![agent(AgentStatus::Working, "home/builder")],
                Instant::now(),
            ),
        );
        let merged = store.merged_agents();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].agent_status, AgentStatus::Working);
        assert_eq!(merged[0].reachability, Some(Reachability::Reachable));
        assert_eq!(merged[0].last_known_status, None);
    }

    #[test]
    fn degraded_peer_stamps_unknown_and_preserves_last_known() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry {
                reachability: Reachability::Degraded,
                agents: vec![agent(AgentStatus::Blocked, "home/reviewer")],
                last_seen: Some(Instant::now()),
            },
        );
        let merged = store.merged_agents();
        // A Degraded peer has stopped answering (1-2 misses): it must NOT surface
        // its last poll's status as current. It is stamped `Unknown` exactly like
        // Unreachable, distinguished only by the `reachability` field.
        assert_eq!(
            merged[0].agent_status,
            AgentStatus::Unknown,
            "a degraded peer must not surface a stale idle/done as current"
        );
        assert_eq!(merged[0].last_known_status, Some(AgentStatus::Blocked));
        assert_eq!(merged[0].reachability, Some(Reachability::Degraded));
    }

    #[test]
    fn unreachable_peer_stamps_unknown_and_preserves_last_known() {
        let mut store = FederationStore::default();
        // A peer last seen idle, then gone offline: must NOT surface `idle`.
        store.set_peer(
            "home",
            PeerCacheEntry {
                reachability: Reachability::Unreachable,
                agents: vec![agent(AgentStatus::Idle, "home/idler")],
                last_seen: Some(Instant::now()),
            },
        );
        let merged = store.merged_agents();
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].agent_status,
            AgentStatus::Unknown,
            "an offline peer must never present a stale idle/done as current"
        );
        assert_eq!(merged[0].last_known_status, Some(AgentStatus::Idle));
        assert_eq!(merged[0].reachability, Some(Reachability::Unreachable));
    }

    #[test]
    fn degrade_peer_retains_agents_but_updates_reachability() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![agent(AgentStatus::Done, "home/done")], Instant::now()),
        );
        store.degrade_peer("home", Reachability::Unreachable);
        let entry = store.peer("home").expect("peer retained");
        assert_eq!(entry.reachability, Reachability::Unreachable);
        assert_eq!(
            entry.agents.len(),
            1,
            "last-known agents retained on a miss"
        );
        // And a miss for an unknown peer records an observable offline entry.
        store.degrade_peer("ghost", Reachability::Unreachable);
        assert_eq!(
            store.peer("ghost").expect("ghost recorded").reachability,
            Reachability::Unreachable
        );
        assert!(store
            .peer("ghost")
            .expect("ghost recorded")
            .agents
            .is_empty());
    }
}
