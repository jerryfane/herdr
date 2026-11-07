//! In-memory cache of remote federation peers' agents and workspaces.
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::api::schema::{
    AgentInfo, AgentStatus, FederationPollErrorClass, PaneAgentStatusChangedEvent,
    ServerCapabilities, WorkspaceInfo,
};

/// Reachability of a federation peer, derived from consecutive poll outcomes.
///
/// Serialized onto remote [`AgentInfo`]s so a client can tell a live peer from
/// one that has gone quiet. A C-like enum, so it derives `Eq`.
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

#[derive(Debug, Clone, Default)]
pub struct PeerObservation {
    pub validated_machine_id: Option<String>,
    pub remote_boot_id: Option<String>,
    pub remote_version: Option<String>,
    pub remote_protocol: Option<u32>,
    pub remote_capabilities: Option<ServerCapabilities>,
}

/// The last status the event relay published to local subscribers for one
/// remote pane (ids alias-qualified), and when it did.
///
/// This is both the relay's de-duplication baseline and the ordering fence
/// against the 5 s poll: a poll that started before `at` carries an older view
/// of the pane, so its status fields yield to this one.
#[derive(Debug, Clone)]
pub struct RelayedStatus {
    pub event: PaneAgentStatusChangedEvent,
    pub at: Instant,
}

/// The last completed turn known for one remote pane (`None`: listed without
/// one), and when it was accepted. The single source of a cached agent's
/// `last_completed_turn`; every source goes through [`accepts_completion`].
#[derive(Debug, Clone, Copy)]
pub struct KnownCompletion {
    pub turn: Option<crate::api::schema::LastCompletedTurn>,
    pub accepted_at: Instant,
}

/// Where a candidate `last_completed_turn` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionSource {
    /// A relayed `pane.turn_completed` line.
    Stream,
    /// An `agent.list` (poll or same-boot resync) whose request started then.
    List { requested_at: Instant },
    /// A resync after the peer restarted: a new boot's state.
    Reset,
}

/// Whether `candidate` replaces `known`, the pane's stored completion.
///
/// Within one turn epoch only a strictly later turn does, whatever its source
/// or timing, so a delayed or older answer never rolls a pane back. A turn
/// from another epoch (a respawned pane, or a restarted peer) is taken from:
/// - a restart resync, which describes the new boot;
/// - a list requested after `known` was accepted;
/// - a stream line whose epoch is the pane's current one (`current_epoch`):
///   the newest any source established, relayed status, poll or resync.
///   Within a boot that only moves forward and a restart resync replaces it,
///   so a line from an earlier incarnation or boot never matches.
pub fn accepts_completion(
    known: Option<&KnownCompletion>,
    candidate: Option<&crate::api::schema::LastCompletedTurn>,
    source: CompletionSource,
    current_epoch: Option<u64>,
) -> bool {
    let known_turn = known.and_then(|known| known.turn.as_ref());
    if let (Some(known_turn), Some(candidate)) = (known_turn, candidate) {
        if known_turn.turn_epoch == candidate.turn_epoch {
            return candidate.turn > known_turn.turn;
        }
    }
    match source {
        CompletionSource::Reset => true,
        CompletionSource::List { requested_at } => {
            known.is_none_or(|known| requested_at > known.accepted_at)
        }
        CompletionSource::Stream => candidate.is_some_and(|candidate| match current_epoch {
            Some(epoch) => epoch == candidate.turn_epoch,
            // Nothing relayed about the pane's epoch: only a pane with no
            // completion yet takes the line.
            None => known_turn.is_none(),
        }),
    }
}

/// How a relay resynchronization compares a fresh `agent.list` with what it
/// already published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayResync {
    /// First stream of this relay: record the current state silently.
    Seed,
    /// Reconnect or lag: publish each pane whose state differs from the last
    /// one published, including panes that appeared meanwhile.
    Diff,
    /// The peer restarted: pane ids from the old boot mean nothing, so publish
    /// every current pane.
    Reset,
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
    /// Last-known workspaces from this peer, alias-qualified at write time and
    /// in the peer's own order. Refreshed on a slower cadence than `agents`
    /// (see [`FederationStore::set_peer_workspaces`]) and kept across agent
    /// polls and misses.
    pub workspaces: Vec<WorkspaceInfo>,
    /// When the last successful poll landed, if any. Recorded now for a later
    /// staleness surface (e.g. a `last_seen` age in `agent.list`); not yet read
    /// on the merge path, so it reads as unused in a non-test build.
    #[allow(dead_code)]
    pub last_seen: Option<Instant>,
    pub last_success_unix_ms: Option<u64>,
    pub last_error_class: Option<FederationPollErrorClass>,
    pub observation: PeerObservation,
    /// Per remote pane (qualified id), the last status the event relay
    /// published. Empty for peers without an event stream.
    pub relayed: HashMap<String, RelayedStatus>,
    /// Per remote pane (qualified id), its last completed turn and who
    /// started it, from polls, resyncs and the stream alike, kept whether or
    /// not the pane is in `agents` yet; a cached agent's `last_completed_turn`
    /// mirrors it.
    pub completions: HashMap<String, KnownCompletion>,
    /// Per remote pane (qualified id), when a relay resync found the peer no
    /// longer lists it or the relay saw it close. A poll that started earlier
    /// may still list the pane, so it must not bring it back.
    pub vanished: HashMap<String, Instant>,
}

impl PeerCacheEntry {
    #[cfg(test)]
    /// A fresh entry from a successful poll.
    pub fn reachable(agents: Vec<AgentInfo>, last_seen: Instant) -> Self {
        Self::reachable_observed(agents, last_seen, PeerObservation::default())
    }

    pub fn reachable_observed(
        agents: Vec<AgentInfo>,
        last_seen: Instant,
        observation: PeerObservation,
    ) -> Self {
        Self {
            reachability: Reachability::Reachable,
            agents,
            workspaces: Vec::new(),
            last_seen: Some(last_seen),
            last_success_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|duration| u64::try_from(duration.as_millis()).ok()),
            last_error_class: None,
            observation,
            relayed: HashMap::new(),
            completions: HashMap::new(),
            vanished: HashMap::new(),
        }
    }
}

/// Most relayed pane lifecycle events held for the app loop at once; older
/// ones are dropped first.
const MAX_PENDING_PANE_EVENTS: usize = 64;

/// A remote pane lifecycle event the relay hands to the app loop, which tells
/// an agent that died from one that finished (see [`FederationStore::relay_pane_event`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemotePaneEvent {
    /// `pane.agent_detected` with `released: true`: the agent left the pane.
    AgentReleased,
    /// `pane.exited`: the pane's process exited.
    Exited,
    /// `pane.closed`: the pane was closed on purpose; it leaves quietly.
    Closed,
}

/// Cache of every configured federation peer's agents, keyed by peer alias.
#[derive(Debug, Default)]
pub struct FederationStore {
    peers: HashMap<String, PeerCacheEntry>,
    /// Bumped by every write that can change a remote agent's status, label,
    /// presence or reachability, so the app loop re-reads the store only after
    /// one (see [`Self::revision`]).
    revision: u64,
    /// Wakes the app loop after such a write, so a remote transition reaches
    /// push notifications without waiting for the loop's idle tick.
    changed: Arc<tokio::sync::Notify>,
    /// Relayed lifecycle events of remote panes (ids alias-qualified), oldest
    /// first, until the app loop takes them.
    pane_events: VecDeque<(String, RemotePaneEvent)>,
}

impl FederationStore {
    /// Replace a peer's cached agent snapshot outside the poll path (tests),
    /// as a poll that started now.
    #[cfg(test)]
    pub fn set_peer(&mut self, alias: impl Into<String>, entry: PeerCacheEntry) {
        self.set_polled_peer(alias, entry, Instant::now());
    }

    /// Replace a peer's cached agent snapshot with a poll that started at
    /// `poll_started`. The peer's cached workspaces are carried over: they
    /// refresh on their own cadence through [`Self::set_peer_workspaces`], so
    /// an agent poll never blanks them.
    ///
    /// Ordering against the event relay: a pane whose status the relay
    /// published after `poll_started` keeps that status (and its turn), since
    /// this poll's answer may predate it, and a pane a resync found gone after
    /// `poll_started` stays gone. The relay's baselines are kept, except for
    /// panes the peer no longer lists that nothing relayed since the poll
    /// started.
    pub fn set_polled_peer(
        &mut self,
        alias: impl Into<String>,
        mut entry: PeerCacheEntry,
        poll_started: Instant,
    ) {
        let alias = alias.into();
        if let Some(previous) = self.peers.get_mut(&alias) {
            entry.workspaces = std::mem::take(&mut previous.workspaces);
            entry.relayed = std::mem::take(&mut previous.relayed);
            entry.completions = std::mem::take(&mut previous.completions);
            entry.vanished = std::mem::take(&mut previous.vanished);
        }
        entry
            .vanished
            .retain(|_, vanished_at| *vanished_at > poll_started);
        let vanished = &entry.vanished;
        entry
            .agents
            .retain(|agent| !vanished.contains_key(&agent.pane_id));
        let now = Instant::now();
        for agent in &mut entry.agents {
            if let Some(relayed) = entry.relayed.get(&agent.pane_id) {
                if relayed.at > poll_started {
                    apply_status_event(agent, &relayed.event);
                }
            }
        }
        let listed: Vec<_> = entry
            .agents
            .iter()
            .map(|agent| (agent.pane_id.clone(), agent.last_completed_turn))
            .collect();
        for (pane_id, candidate) in listed {
            entry.offer_completion(
                &pane_id,
                candidate,
                CompletionSource::List {
                    requested_at: poll_started,
                },
                now,
            );
        }
        let agents = &entry.agents;
        entry.relayed.retain(|pane_id, relayed| {
            relayed.at > poll_started || agents.iter().any(|agent| agent.pane_id == *pane_id)
        });
        entry.completions.retain(|pane_id, known| {
            known.accepted_at > poll_started || agents.iter().any(|agent| agent.pane_id == *pane_id)
        });
        self.peers.insert(alias, entry);
        self.touch();
    }

    /// Record one status event the relay received from `alias` (ids already
    /// qualified) and patch the cached agent. The event's turn is first raised
    /// to the newest the pane has shown ([`PeerCacheEntry::clamp_turn`]), so
    /// what is recorded and published never rewinds it. Returns whether it
    /// should be published: `false` when it repeats the last status published
    /// for the pane (a transition a resync already reported) or the alias is
    /// not cached.
    pub fn relay_status(
        &mut self,
        alias: &str,
        event: &mut PaneAgentStatusChangedEvent,
        now: Instant,
    ) -> bool {
        let Some(entry) = self.peers.get_mut(alias) else {
            return false;
        };
        // A status from an older incarnation is dropped whole, before the
        // clamp could dress it up as the current one.
        if entry.is_stale_epoch(&event.pane_id, event.turn_epoch) {
            return false;
        }
        entry.clamp_turn(event);
        if entry
            .relayed
            .get(&event.pane_id)
            .is_some_and(|last| last.event == *event)
        {
            return false;
        }
        entry.record_relayed(event.clone(), now, EpochRule::Forward);
        self.touch();
        true
    }

    /// Record a relayed `pane.turn_completed`: the pane's turn and epoch move
    /// forward (never back) in the cache and in the relay baseline, so an older
    /// poll cannot rewind them, and the cached agent's `last_completed_turn`
    /// (with who started the turn) becomes this one ([`accepts_completion`]).
    /// A line from an incarnation older than the pane's newest is dropped
    /// whole ([`PeerCacheEntry::is_stale_epoch`]).
    pub fn relay_turn(&mut self, alias: &str, completed: RelayedTurn, now: Instant) {
        let RelayedTurn {
            pane_id,
            turn,
            turn_epoch,
            completed_unix_ms,
            turn_origin,
        } = completed;
        let pane_id = pane_id.as_str();
        let Some(entry) = self.peers.get_mut(alias) else {
            return;
        };
        if entry.is_stale_epoch(pane_id, Some(turn_epoch)) {
            return;
        }
        // The push tracker reads who started the finished turn from here.
        let completed = crate::api::schema::LastCompletedTurn {
            turn,
            turn_epoch,
            completed_unix_ms,
            turn_origin,
        };
        if entry.offer_completion(pane_id, Some(completed), CompletionSource::Stream, now) {
            self.touch();
        }
        let Some(entry) = self.peers.get_mut(alias) else {
            return;
        };
        // Advance the newest of the baseline and the cached agent, so a
        // baseline a later poll overtook is never the one carried forward.
        let baseline = entry
            .relayed
            .get(pane_id)
            .map(|relayed| relayed.event.clone());
        let cached = entry
            .agents
            .iter()
            .find(|agent| agent.pane_id == pane_id)
            .map(agent_status_event);
        let current = match (baseline, cached) {
            (Some(baseline), Some(cached)) => Some(
                if (cached.turn_epoch, cached.turn) > (baseline.turn_epoch, baseline.turn) {
                    cached
                } else {
                    baseline
                },
            ),
            (baseline, cached) => baseline.or(cached),
        };
        let Some(mut event) = current else {
            return;
        };
        if (event.turn_epoch, event.turn) >= (Some(turn_epoch), Some(turn)) {
            return;
        }
        event.turn = Some(turn);
        event.turn_epoch = Some(turn_epoch);
        entry.record_relayed(event, now, EpochRule::Forward);
    }

    /// Forget a closed remote pane: its relay baseline and cached agent go at
    /// once, a poll that started earlier cannot bring it back, and the app loop
    /// learns it was closed rather than lost ([`RemotePaneEvent::Closed`]).
    pub fn relay_pane_closed(&mut self, alias: &str, pane_id: &str, now: Instant) {
        let Some(entry) = self.peers.get_mut(alias) else {
            return;
        };
        entry.relayed.remove(pane_id);
        entry.completions.remove(pane_id);
        entry.agents.retain(|agent| agent.pane_id != pane_id);
        entry.vanished.insert(pane_id.to_owned(), now);
        self.relay_pane_event(alias, pane_id, RemotePaneEvent::Closed);
    }

    /// Queue a relayed pane lifecycle event (pane id qualified) for the app
    /// loop: an exit is pushed as a died alert when the pane was an agent, and
    /// holds back the finished alert of the release that precedes it. Unknown
    /// aliases are ignored, like every other relay write.
    pub fn relay_pane_event(&mut self, alias: &str, pane_id: &str, event: RemotePaneEvent) {
        if !self.peers.contains_key(alias) {
            return;
        }
        if self.pane_events.len() == MAX_PENDING_PANE_EVENTS {
            self.pane_events.pop_front();
        }
        self.pane_events.push_back((pane_id.to_owned(), event));
        self.touch();
    }

    /// Take every queued remote pane lifecycle event, oldest first.
    pub fn take_pane_events(&mut self) -> Vec<(String, RemotePaneEvent)> {
        self.pane_events.drain(..).collect()
    }

    /// Compare a fresh `agent.list` from `alias` (ids qualified, requested at
    /// `requested_at`) with what the relay published, offer each pane's last
    /// completed turn ([`accepts_completion`]), record the list as the new
    /// baseline, and return the events to publish so each missed change is
    /// reported exactly once. The list is authoritative: panes the peer no
    /// longer lists lose their baseline and leave the cached agents, which the
    /// app loop reports as exited. Its turns are taken as they are, never
    /// clamped: the list is newer than every line applied before it, and after
    /// a peer restart the cache may still hold the previous boot's turns,
    /// which mean nothing for the new one. Recording it overwrites them, so
    /// later clamps ([`PeerCacheEntry::clamp_turn`]) only see this boot.
    pub fn relay_resync_agents(
        &mut self,
        alias: &str,
        agents: Vec<AgentInfo>,
        mode: RelayResync,
        requested_at: Instant,
        now: Instant,
    ) -> Vec<PaneAgentStatusChangedEvent> {
        let current = agents.iter().map(agent_status_event).collect();
        let missed = self.relay_resync(alias, current, mode, now);
        let source = if mode == RelayResync::Reset {
            CompletionSource::Reset
        } else {
            CompletionSource::List { requested_at }
        };
        if let Some(entry) = self.peers.get_mut(alias) {
            for agent in &agents {
                entry.offer_completion(&agent.pane_id, agent.last_completed_turn, source, now);
            }
        }
        missed
    }

    /// The status half of [`Self::relay_resync_agents`].
    pub fn relay_resync(
        &mut self,
        alias: &str,
        current: Vec<PaneAgentStatusChangedEvent>,
        mode: RelayResync,
        now: Instant,
    ) -> Vec<PaneAgentStatusChangedEvent> {
        let Some(entry) = self.peers.get_mut(alias) else {
            return Vec::new();
        };
        if mode == RelayResync::Reset {
            entry.relayed.clear();
        }
        let mut missed = Vec::new();
        let mut present = HashSet::with_capacity(current.len());
        // Only a restart resync describes a new boot, whose epochs may be lower.
        let rule = if mode == RelayResync::Reset {
            EpochRule::NewBoot
        } else {
            EpochRule::Forward
        };
        for event in current {
            present.insert(event.pane_id.clone());
            entry.vanished.remove(&event.pane_id);
            if rule == EpochRule::Forward && entry.is_stale_epoch(&event.pane_id, event.turn_epoch)
            {
                continue;
            }
            let changed = entry
                .relayed
                .get(&event.pane_id)
                .is_none_or(|last| last.event != event);
            if mode != RelayResync::Seed && changed {
                missed.push(event.clone());
            }
            entry.record_relayed(event, now, rule);
        }
        entry.relayed.retain(|pane_id, _| present.contains(pane_id));
        entry
            .completions
            .retain(|pane_id, _| present.contains(pane_id));
        // Archived agents have no pane and are never in `current`.
        entry.agents.retain(|agent| {
            if agent.pane_id.is_empty() || present.contains(&agent.pane_id) {
                return true;
            }
            entry.vanished.insert(agent.pane_id.clone(), now);
            false
        });
        self.touch();
        missed
    }

    /// Workspace ids named by `alias`'s cached agents that its cached
    /// workspaces do not contain: the poll's trigger for an early
    /// `workspace.list` refresh. Archived agents (empty workspace id) never count.
    pub fn missing_workspace_ids(&self, alias: &str) -> HashSet<String> {
        let Some(entry) = self.peers.get(alias) else {
            return HashSet::new();
        };
        entry
            .agents
            .iter()
            .map(|agent| agent.workspace_id.as_str())
            .filter(|id| {
                !id.is_empty()
                    && !entry
                        .workspaces
                        .iter()
                        .any(|workspace| workspace.workspace_id == *id)
            })
            .map(str::to_owned)
            .collect()
    }

    /// Replace a peer's cached workspaces (already alias-qualified). A no-op
    /// for an alias with no entry: the agent poll creates the entry first, and
    /// an evicted alias must not reappear.
    pub fn set_peer_workspaces(&mut self, alias: &str, workspaces: Vec<WorkspaceInfo>) {
        if let Some(entry) = self.peers.get_mut(alias) {
            entry.workspaces = workspaces;
        }
    }

    /// The cached entry for `alias`, if any. The event relay reads a peer's
    /// observed capabilities here; the merge path reads through
    /// [`Self::merged_agents`] instead.
    pub fn peer(&self, alias: &str) -> Option<&PeerCacheEntry> {
        self.peers.get(alias)
    }

    /// Every cached peer with its alias, for readers that need a peer's
    /// reachability and workspaces next to its agents.
    pub fn peers(&self) -> impl Iterator<Item = (&str, &PeerCacheEntry)> {
        self.peers
            .iter()
            .map(|(alias, entry)| (alias.as_str(), entry))
    }

    /// Counter bumped by every write that can change a remote agent's status,
    /// label, presence or reachability, and by every queued pane exit.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Notified after every write that bumps [`Self::revision`].
    pub fn change_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.changed)
    }

    fn touch(&mut self) {
        self.revision = self.revision.wrapping_add(1);
        self.changed.notify_one();
    }

    /// Update mutable saved-profile presentation on cached agents without
    /// disturbing transport generation, reachability, status, or last-seen time.
    pub fn update_peer_presentation(&mut self, alias: &str, profile_id: Option<&str>, label: &str) {
        let Some(entry) = self.peers.get_mut(alias) else {
            return;
        };
        for agent in &mut entry.agents {
            agent.machine_profile_id = profile_id.map(str::to_owned);
            agent.machine_label = Some(label.to_owned());
        }
        for workspace in &mut entry.workspaces {
            workspace.machine_profile_id = profile_id.map(str::to_owned);
            workspace.machine_label = Some(label.to_owned());
        }
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
                        workspaces: Vec::new(),
                        last_seen: None,
                        last_success_unix_ms: None,
                        last_error_class: None,
                        observation: PeerObservation::default(),
                        relayed: HashMap::new(),
                        completions: HashMap::new(),
                        vanished: HashMap::new(),
                    },
                );
            }
        }
        self.touch();
    }

    pub fn record_poll_error(&mut self, alias: &str, class: FederationPollErrorClass) {
        if let Some(entry) = self.peers.get_mut(alias) {
            entry.last_error_class = Some(class);
        }
    }

    /// Evict a peer's cache entry so its agents stop being merged into
    /// `agent.list` immediately on removal/change. Called by the federation peer
    /// manager's `reconcile` when a peer is dropped or re-pointed, so a removed
    /// peer's last-known agents never linger past the reload.
    pub fn remove_peer(&mut self, alias: &str) {
        if self.peers.remove(alias).is_some() {
            self.touch();
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

    /// Every cached peer's workspaces for merge into the local
    /// `workspace.list`, grouped by peer alias (sorted, so the order is stable)
    /// and in each peer's own order, so `number` and position reproduce that
    /// machine's sidebar. Stamped like [`Self::merged_agents`]: a peer that is
    /// not `Reachable` keeps its last-known workspaces, surfaces `agent_status`
    /// as `unknown`, and preserves the real value in `last_known_status`.
    pub fn merged_workspaces(&self) -> Vec<WorkspaceInfo> {
        let mut peers: Vec<_> = self.peers.iter().collect();
        peers.sort_unstable_by_key(|(alias, _)| *alias);
        peers
            .into_iter()
            .flat_map(|(_, entry)| {
                entry.workspaces.iter().map(|workspace| {
                    let mut stamped = workspace.clone();
                    stamped.reachability = Some(entry.reachability);
                    if entry.reachability != Reachability::Reachable {
                        stamped.last_known_status = Some(workspace.agent_status);
                        stamped.agent_status = AgentStatus::Unknown;
                    }
                    stamped
                })
            })
            .collect()
    }
}

impl PeerCacheEntry {
    /// Raise `event`'s `(turn_epoch, turn)` to the newest the pane has shown,
    /// in its relay baseline or cached agent, the same forward-only order
    /// [`FederationStore::relay_turn`] keeps. Both belong to the peer's current
    /// boot: every resync overwrites them from the fresh `agent.list`.
    fn clamp_turn(&self, event: &mut PaneAgentStatusChangedEvent) {
        let baseline = self
            .relayed
            .get(&event.pane_id)
            .map(|relayed| (relayed.event.turn_epoch, relayed.event.turn));
        let cached = self
            .agents
            .iter()
            .find(|agent| agent.pane_id == event.pane_id)
            .map(|agent| (agent.turn_epoch, agent.turn));
        if let Some(newest) = baseline.max(cached) {
            if newest > (event.turn_epoch, event.turn) {
                (event.turn_epoch, event.turn) = newest;
            }
        }
    }

    /// The newest turn epoch known for the pane in this boot, from its relay
    /// baseline or its cached agent (a poll, a resync or a relayed status).
    /// Within one boot a pane's epoch only moves forward (a respawn takes a
    /// fresh, later one), so nothing relayed may lower it; only a restart
    /// resync ([`EpochRule::NewBoot`]) may.
    fn newest_epoch(&self, pane_id: &str) -> Option<u64> {
        let baseline = self
            .relayed
            .get(pane_id)
            .and_then(|relayed| relayed.event.turn_epoch);
        let cached = self
            .agents
            .iter()
            .find(|agent| agent.pane_id == pane_id)
            .and_then(|agent| agent.turn_epoch);
        baseline.max(cached)
    }

    /// Whether an item for `pane_id` at `epoch` comes from an incarnation
    /// older than the newest known: stale, to be dropped whole. An item
    /// without an epoch is never stale.
    fn is_stale_epoch(&self, pane_id: &str, epoch: Option<u64>) -> bool {
        matches!(
            (epoch, self.newest_epoch(pane_id)),
            (Some(epoch), Some(newest)) if epoch < newest
        )
    }

    /// Offer `candidate` as the pane's last completion ([`accepts_completion`])
    /// and return whether it was taken. The record is kept even before the
    /// pane is cached; a cached agent always mirrors it.
    fn offer_completion(
        &mut self,
        pane_id: &str,
        candidate: Option<crate::api::schema::LastCompletedTurn>,
        source: CompletionSource,
        now: Instant,
    ) -> bool {
        let taken = accepts_completion(
            self.completions.get(pane_id),
            candidate.as_ref(),
            source,
            self.newest_epoch(pane_id),
        );
        if taken {
            self.completions.insert(
                pane_id.to_owned(),
                KnownCompletion {
                    turn: candidate,
                    accepted_at: now,
                },
            );
        }
        if let Some(known) = self.completions.get(pane_id) {
            if let Some(agent) = self
                .agents
                .iter_mut()
                .find(|agent| agent.pane_id == pane_id)
            {
                agent.last_completed_turn = known.turn;
            }
        }
        taken
    }

    /// Make `event` the pane's relay baseline and patch its cached agent.
    ///
    /// Every relayed status goes through here; under [`EpochRule::Forward`] a
    /// stale one is dropped, so the baseline and the cached agent never move
    /// to an older incarnation.
    fn record_relayed(
        &mut self,
        event: PaneAgentStatusChangedEvent,
        now: Instant,
        rule: EpochRule,
    ) {
        if rule == EpochRule::Forward && self.is_stale_epoch(&event.pane_id, event.turn_epoch) {
            return;
        }
        if let Some(agent) = self
            .agents
            .iter_mut()
            .find(|agent| agent.pane_id == event.pane_id)
        {
            apply_status_event(agent, &event);
        }
        self.relayed
            .insert(event.pane_id.clone(), RelayedStatus { event, at: now });
    }
}

/// Whether a relayed status may lower a pane's turn epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EpochRule {
    /// The same boot: an item from an older incarnation is stale.
    Forward,
    /// A restart resync: the new boot's epochs replace the old ones.
    NewBoot,
}

/// A relayed `pane.turn_completed` for [`FederationStore::relay_turn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayedTurn {
    pub pane_id: String,
    pub turn: u64,
    pub turn_epoch: u64,
    pub completed_unix_ms: u64,
    pub turn_origin: Option<crate::terminal::TurnOrigin>,
}

/// The `pane.agent_status_changed` payload describing `agent`'s current state.
pub fn agent_status_event(agent: &AgentInfo) -> PaneAgentStatusChangedEvent {
    PaneAgentStatusChangedEvent {
        pane_id: agent.pane_id.clone(),
        workspace_id: agent.workspace_id.clone(),
        agent_status: agent.agent_status,
        input_pending: agent.input_pending,
        input_prompt_kind: agent.input_prompt_kind,
        agent: agent.agent.clone(),
        title: agent.title.clone(),
        display_agent: agent.display_agent.clone(),
        state_labels: agent.state_labels.clone(),
        turn: agent.turn,
        turn_epoch: agent.turn_epoch,
    }
}

/// Overwrite `agent`'s status fields with a status event for its pane. The
/// event's turn is already the right one: a streamed status was clamped
/// forward ([`PeerCacheEntry::clamp_turn`]), a resync is authoritative, and a
/// poll only takes a relayed baseline newer than itself.
fn apply_status_event(agent: &mut AgentInfo, event: &PaneAgentStatusChangedEvent) {
    agent.agent_status = event.agent_status;
    agent.input_pending = event.input_pending;
    agent.input_prompt_kind = event.input_prompt_kind;
    agent.agent.clone_from(&event.agent);
    agent.title.clone_from(&event.title);
    agent.display_agent.clone_from(&event.display_agent);
    agent.state_labels.clone_from(&event.state_labels);
    agent.turn = event.turn;
    agent.turn_epoch = event.turn_epoch;
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

    fn relayed_turn(pane_id: &str, turn: u64, turn_epoch: u64) -> RelayedTurn {
        RelayedTurn {
            pane_id: pane_id.into(),
            turn,
            turn_epoch,
            completed_unix_ms: 0,
            turn_origin: None,
        }
    }

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
                workspaces: Vec::new(),
                last_seen: Some(Instant::now()),
                last_success_unix_ms: None,
                last_error_class: None,
                observation: PeerObservation::default(),
                relayed: HashMap::new(),
                completions: HashMap::new(),
                vanished: HashMap::new(),
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
                workspaces: Vec::new(),
                last_seen: Some(Instant::now()),
                last_success_unix_ms: None,
                last_error_class: None,
                observation: PeerObservation::default(),
                relayed: HashMap::new(),
                completions: HashMap::new(),
                vanished: HashMap::new(),
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

    #[test]
    fn remove_peer_evicts_entry_and_clears_merge() {
        let mut store = FederationStore::default();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![agent(AgentStatus::Working, "home/builder")],
                Instant::now(),
            ),
        );
        assert!(store.peer("home").is_some());
        assert_eq!(store.merged_agents().len(), 1);

        store.remove_peer("home");
        assert!(
            store.peer("home").is_none(),
            "removed peer must leave no cache entry"
        );
        assert!(
            store.merged_agents().is_empty(),
            "a removed peer contributes no merged agents"
        );
        assert!(store.is_empty());

        // Removing an absent alias is a no-op, not a panic.
        store.remove_peer("home");
        assert!(store.is_empty());
    }

    fn workspace(workspace_id: &str, number: usize, status: AgentStatus) -> WorkspaceInfo {
        serde_json::from_value(serde_json::json!({
            "workspace_id": workspace_id,
            "number": number,
            "label": format!("label-{number}"),
            "focused": false,
            "pane_count": 1,
            "tab_count": 1,
            "active_tab_id": format!("{workspace_id}:t1"),
            "agent_status": status,
        }))
        .expect("workspace info deserializes")
    }

    #[test]
    fn cached_workspaces_survive_agent_polls_and_go_stale_with_the_peer() {
        let mut store = FederationStore::default();
        store.set_peer_workspaces("home", vec![workspace("home/w0", 1, AgentStatus::Idle)]);
        assert!(
            store.merged_workspaces().is_empty(),
            "an alias without an agent-poll entry must not gain workspaces"
        );

        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![agent(AgentStatus::Working, "a")], Instant::now()),
        );
        store.set_peer_workspaces(
            "home",
            vec![
                workspace("home/w2", 1, AgentStatus::Working),
                workspace("home/w1", 2, AgentStatus::Done),
            ],
        );
        store.set_peer(
            "alpha",
            PeerCacheEntry::reachable(Vec::new(), Instant::now()),
        );
        store.set_peer_workspaces("alpha", vec![workspace("alpha/w1", 1, AgentStatus::Idle)]);
        // The next 5 s agent poll replaces the entry; workspaces are kept.
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![agent(AgentStatus::Working, "a")], Instant::now()),
        );

        let merged = store.merged_workspaces();
        let ids: Vec<_> = merged.iter().map(|ws| ws.workspace_id.as_str()).collect();
        assert_eq!(
            ids,
            ["alpha/w1", "home/w2", "home/w1"],
            "peers sorted by alias, each in its own order"
        );
        assert!(merged
            .iter()
            .all(|ws| ws.reachability == Some(Reachability::Reachable)));
        assert_eq!(merged[1].agent_status, AgentStatus::Working);
        assert_eq!(merged[1].last_known_status, None);

        store.degrade_peer("home", Reachability::Unreachable);
        let merged = store.merged_workspaces();
        let home: Vec<_> = merged
            .iter()
            .filter(|ws| ws.workspace_id.starts_with("home/"))
            .collect();
        assert_eq!(
            home.len(),
            2,
            "an unreachable peer keeps its last-known workspaces"
        );
        assert!(home.iter().all(|ws| {
            ws.reachability == Some(Reachability::Unreachable)
                && ws.agent_status == AgentStatus::Unknown
        }));
        assert_eq!(home[0].last_known_status, Some(AgentStatus::Working));
        assert_eq!(home[1].last_known_status, Some(AgentStatus::Done));

        store.remove_peer("home");
        assert_eq!(store.merged_workspaces().len(), 1);
    }

    #[test]
    fn missing_workspace_ids_names_only_uncached_live_workspaces() {
        let mut store = FederationStore::default();
        let mut archived = agent(AgentStatus::Idle, "archived");
        archived.workspace_id = String::new();
        let mut known = agent(AgentStatus::Idle, "known");
        known.workspace_id = "home/w1".into();
        let mut new = agent(AgentStatus::Idle, "new");
        new.workspace_id = "home/w2".into();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![archived, known, new], Instant::now()),
        );
        store.set_peer_workspaces("home", vec![workspace("home/w1", 1, AgentStatus::Idle)]);

        assert_eq!(
            store.missing_workspace_ids("home"),
            HashSet::from(["home/w2".to_string()])
        );
        assert!(store.missing_workspace_ids("absent").is_empty());
    }

    fn pane_agent(pane_id: &str, status: AgentStatus) -> AgentInfo {
        let mut agent = agent(status, pane_id);
        agent.pane_id = pane_id.into();
        agent
    }

    fn status(pane_id: &str, status: AgentStatus) -> PaneAgentStatusChangedEvent {
        agent_status_event(&pane_agent(pane_id, status))
    }

    fn cached_status(store: &FederationStore, pane_id: &str) -> AgentStatus {
        store
            .peer("home")
            .expect("home cached")
            .agents
            .iter()
            .find(|agent| agent.pane_id == pane_id)
            .expect("pane cached")
            .agent_status
    }

    #[test]
    fn a_poll_older_than_a_relayed_event_keeps_the_event_status() {
        use std::time::Duration;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], t0),
            t0,
        );

        // The poll request goes out, then the stream reports `blocked`, then the
        // poll's (older) `working` answer lands.
        let poll_started = Instant::now();
        let mut blocked = status("home/p1", AgentStatus::Blocked);
        blocked.turn = Some(4);
        blocked.turn_epoch = Some(2);
        assert!(store.relay_status(
            "home",
            &mut blocked,
            poll_started + Duration::from_millis(1)
        ));
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Blocked);
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], t0),
            poll_started,
        );
        assert_eq!(
            cached_status(&store, "home/p1"),
            AgentStatus::Blocked,
            "an older poll must not overwrite a newer relayed status"
        );
        assert_eq!(store.peer("home").unwrap().agents[0].turn, Some(4));

        // A poll that started after the event is authoritative again.
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Idle)], t0),
            Instant::now() + Duration::from_millis(5),
        );
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Idle);
    }

    fn completed_origin(store: &FederationStore, pane_id: &str) -> Option<LastCompletedTurnView> {
        store
            .peer("home")?
            .agents
            .iter()
            .find(|agent| agent.pane_id == pane_id)?
            .last_completed_turn
            .map(|turn| (turn.turn_epoch, turn.turn, turn.turn_origin))
    }

    type LastCompletedTurnView = (u64, u64, Option<crate::terminal::TurnOrigin>);

    #[test]
    fn a_poll_older_than_a_relayed_completion_keeps_its_origin() {
        use std::time::Duration;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], t0),
            t0,
        );

        // The poll goes out; the stream then reports the finish and its
        // completion record (started by someone else); the older poll lands.
        let poll_started = Instant::now();
        let relayed_at = poll_started + Duration::from_millis(1);
        let mut done = status("home/p1", AgentStatus::Done);
        done.turn = Some(1);
        done.turn_epoch = Some(2);
        assert!(store.relay_status("home", &mut done, relayed_at));
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(crate::terminal::TurnOrigin::Other),
                ..relayed_turn("home/p1", 1, 2)
            },
            relayed_at,
        );
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], t0),
            poll_started,
        );

        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Done);
        assert_eq!(store.peer("home").unwrap().agents[0].turn, Some(1));
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((2, 1, Some(crate::terminal::TurnOrigin::Other)))
        );

        // A newer completion from a later poll replaces it.
        let mut later = pane_agent("home/p1", AgentStatus::Done);
        later.last_completed_turn = Some(crate::api::schema::LastCompletedTurn {
            turn: 2,
            turn_epoch: 2,
            completed_unix_ms: 0,
            turn_origin: Some(crate::terminal::TurnOrigin::Mine),
        });
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![later], t0),
            Instant::now() + Duration::from_millis(5),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((2, 2, Some(crate::terminal::TurnOrigin::Mine)))
        );
    }

    #[test]
    fn a_relay_resync_carries_each_panes_completion_origin() {
        let mut store = FederationStore::default();
        let now = Instant::now();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], now),
        );
        let mut listed = pane_agent("home/p1", AgentStatus::Done);
        listed.turn = Some(3);
        listed.turn_epoch = Some(2);
        listed.last_completed_turn = Some(crate::api::schema::LastCompletedTurn {
            turn: 3,
            turn_epoch: 2,
            completed_unix_ms: 0,
            turn_origin: Some(crate::terminal::TurnOrigin::Other),
        });
        // The resync was requested after the poll's answer was taken.
        let requested_at = Instant::now();
        let missed = store.relay_resync_agents(
            "home",
            vec![listed],
            RelayResync::Diff,
            requested_at,
            requested_at,
        );
        assert_eq!(missed.len(), 1, "{missed:?}");
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Done);
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((2, 3, Some(crate::terminal::TurnOrigin::Other)))
        );
    }

    #[test]
    fn a_restarted_peer_with_a_lower_epoch_replaces_the_old_boots_completions() {
        use crate::terminal::TurnOrigin;
        let completed = |turn_epoch, turn, origin| crate::api::schema::LastCompletedTurn {
            turn,
            turn_epoch,
            completed_unix_ms: 0,
            turn_origin: Some(origin),
        };
        let mut store = FederationStore::default();
        let now = Instant::now();
        let mut old_boot = pane_agent("home/p1", AgentStatus::Done);
        old_boot.last_completed_turn = Some(completed(7, 3, TurnOrigin::Other));
        store.set_peer("home", PeerCacheEntry::reachable(vec![old_boot], now));

        // The peer restarted; its new boot's epoch is lower than the old one.
        let mut new_boot = pane_agent("home/p1", AgentStatus::Done);
        new_boot.last_completed_turn = Some(completed(4, 1, TurnOrigin::Mine));
        store.relay_resync_agents("home", vec![new_boot], RelayResync::Reset, now, now);
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((4, 1, Some(TurnOrigin::Mine)))
        );

        // The new boot's next completion is taken too; a repeat is not.
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Mine),
                ..relayed_turn("home/p1", 2, 4)
            },
            now,
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((4, 2, Some(TurnOrigin::Mine)))
        );
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p1", 1, 4)
            },
            now,
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((4, 2, Some(TurnOrigin::Mine)))
        );

        // A poll that started before the restart cannot bring back the old boot.
        let mut stale = pane_agent("home/p1", AgentStatus::Done);
        stale.last_completed_turn = Some(completed(7, 3, TurnOrigin::Other));
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![stale], now),
            now - std::time::Duration::from_millis(1),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((4, 2, Some(TurnOrigin::Mine)))
        );
    }

    fn completed(
        turn_epoch: u64,
        turn: u64,
        origin: crate::terminal::TurnOrigin,
    ) -> crate::api::schema::LastCompletedTurn {
        crate::api::schema::LastCompletedTurn {
            turn,
            turn_epoch,
            completed_unix_ms: 0,
            turn_origin: Some(origin),
        }
    }

    /// `home/p1` as `agent.list` reports it: done, at the turn it completed.
    fn listed_with(turn: Option<crate::api::schema::LastCompletedTurn>) -> AgentInfo {
        let mut agent = pane_agent("home/p1", AgentStatus::Done);
        agent.turn = turn.map(|turn| turn.turn);
        agent.turn_epoch = turn.map(|turn| turn.turn_epoch);
        agent.last_completed_turn = turn;
        agent
    }

    fn status_at(
        pane_id: &str,
        status: AgentStatus,
        turn_epoch: u64,
        turn: u64,
    ) -> PaneAgentStatusChangedEvent {
        let mut event = self::status(pane_id, status);
        event.turn_epoch = Some(turn_epoch);
        event.turn = Some(turn);
        event
    }

    #[test]
    fn a_respawned_panes_completion_is_taken_once_its_status_shows_the_new_epoch() {
        use crate::terminal::TurnOrigin;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![listed_with(Some(completed(4, 2, TurnOrigin::Mine)))],
                t0,
            ),
            t0,
        );
        // The pane respawned (same peer boot, new epoch 8): its status shows
        // the new epoch, then its first turn completes.
        let early = RelayedTurn {
            turn_origin: Some(TurnOrigin::Other),
            ..relayed_turn("home/p1", 1, 8)
        };
        let mut working = status_at("home/p1", AgentStatus::Working, 8, 0);
        let mut done = status_at("home/p1", AgentStatus::Done, 8, 1);
        store.relay_status("home", &mut working, Instant::now());
        store.relay_status("home", &mut done, Instant::now());
        store.relay_turn("home", early, Instant::now());
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((8, 1, Some(TurnOrigin::Other)))
        );
        // The previous incarnation's late line no longer applies.
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Mine),
                ..relayed_turn("home/p1", 3, 4)
            },
            Instant::now(),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((8, 1, Some(TurnOrigin::Other)))
        );
    }

    #[test]
    fn buffered_items_from_before_a_newer_polled_incarnation_are_dropped_whole() {
        use crate::terminal::TurnOrigin;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![listed_with(Some(completed(4, 2, TurnOrigin::Mine)))],
                t0,
            ),
            t0,
        );
        let mut done = status_at("home/p1", AgentStatus::Done, 4, 2);
        store.relay_status("home", &mut done, Instant::now());
        // The pane respawned; a poll requested after that reports epoch 8.
        let poll_started = Instant::now() + std::time::Duration::from_millis(1);
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![listed_with(Some(completed(8, 1, TurnOrigin::Mine)))],
                poll_started,
            ),
            poll_started,
        );
        // Buffered lines from the previous incarnation drain afterwards: a
        // completion, then a status and another completion. All are stale.
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p1", 3, 4)
            },
            Instant::now(),
        );
        let mut working = status_at("home/p1", AgentStatus::Working, 4, 3);
        assert!(
            !store.relay_status("home", &mut working, Instant::now()),
            "a stale status is not published"
        );
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p1", 4, 4)
            },
            Instant::now(),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((8, 1, Some(TurnOrigin::Mine)))
        );
        let agent = &store.peer("home").unwrap().agents[0];
        assert_eq!((agent.turn_epoch, agent.turn), (Some(8), Some(1)));
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Done);
        // The current incarnation's next turn still goes through.
        let mut next = status_at("home/p1", AgentStatus::Working, 8, 1);
        assert!(store.relay_status("home", &mut next, Instant::now()));
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p1", 2, 8)
            },
            Instant::now(),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((8, 2, Some(TurnOrigin::Other)))
        );
    }

    #[test]
    fn a_stream_line_for_an_epoch_no_status_has_shown_is_ignored() {
        use crate::terminal::TurnOrigin;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![listed_with(Some(completed(4, 2, TurnOrigin::Mine)))],
                t0,
            ),
            t0,
        );
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p1", 1, 8)
            },
            Instant::now(),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((4, 2, Some(TurnOrigin::Mine)))
        );
    }

    #[test]
    fn a_completion_relayed_before_its_pane_is_cached_survives_the_delayed_poll() {
        use crate::terminal::TurnOrigin;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_polled_peer("home", PeerCacheEntry::reachable(Vec::new(), t0), t0);
        // A poll goes out and captures the new pane p2 working, no completion.
        let poll_started = Instant::now();
        let mut polled = pane_agent("home/p2", AgentStatus::Working);
        polled.turn = Some(0);
        polled.turn_epoch = Some(9);
        // Before it lands, the stream reports p2 done and its completion.
        let relayed_at = poll_started + std::time::Duration::from_millis(1);
        let mut done = status_at("home/p2", AgentStatus::Done, 9, 1);
        store.relay_status("home", &mut done, relayed_at);
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p2", 1, 9)
            },
            relayed_at,
        );
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(vec![polled], poll_started),
            poll_started,
        );
        assert_eq!(cached_status(&store, "home/p2"), AgentStatus::Done);
        assert_eq!(
            completed_origin(&store, "home/p2"),
            Some((9, 1, Some(TurnOrigin::Other)))
        );
    }

    #[test]
    fn an_older_resync_cannot_roll_back_a_newer_polled_completion() {
        use crate::terminal::TurnOrigin;
        let mut store = FederationStore::default();
        let resync_requested = Instant::now();
        let poll_started = resync_requested + std::time::Duration::from_millis(1);
        // The poll was asked later but answered first.
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![listed_with(Some(completed(7, 2, TurnOrigin::Mine)))],
                poll_started,
            ),
            poll_started,
        );
        store.relay_resync_agents(
            "home",
            vec![listed_with(Some(completed(7, 1, TurnOrigin::Other)))],
            RelayResync::Diff,
            resync_requested,
            Instant::now(),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((7, 2, Some(TurnOrigin::Mine)))
        );
    }

    #[test]
    fn a_delayed_stream_completion_cannot_roll_back_a_newer_poll() {
        use crate::terminal::TurnOrigin;
        let mut store = FederationStore::default();
        let now = Instant::now();
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![listed_with(Some(completed(7, 3, TurnOrigin::Mine)))],
                now,
            ),
            now,
        );
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p1", 2, 7)
            },
            Instant::now(),
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((7, 3, Some(TurnOrigin::Mine)))
        );
    }

    #[test]
    fn a_stream_line_from_another_boot_waits_for_a_list_to_establish_it() {
        use crate::terminal::TurnOrigin;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![listed_with(None)], t0),
        );
        store.relay_resync_agents(
            "home",
            vec![listed_with(Some(completed(4, 1, TurnOrigin::Mine)))],
            RelayResync::Reset,
            t0,
            t0,
        );
        // A late line from the previous boot (epoch 7) is ignored.
        store.relay_turn(
            "home",
            RelayedTurn {
                turn_origin: Some(TurnOrigin::Other),
                ..relayed_turn("home/p1", 4, 7)
            },
            t0,
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((4, 1, Some(TurnOrigin::Mine)))
        );
        // A list requested after that establishes whatever boot it reports.
        let later = t0 + std::time::Duration::from_millis(5);
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![listed_with(Some(completed(9, 1, TurnOrigin::Other)))],
                later,
            ),
            later,
        );
        assert_eq!(
            completed_origin(&store, "home/p1"),
            Some((9, 1, Some(TurnOrigin::Other)))
        );
    }

    #[test]
    fn relay_resync_reports_each_missed_change_once() {
        let mut store = FederationStore::default();
        let now = Instant::now();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(
                vec![
                    pane_agent("home/p1", AgentStatus::Working),
                    pane_agent("home/p2", AgentStatus::Idle),
                ],
                now,
            ),
        );
        let seeded = store.relay_resync(
            "home",
            vec![
                status("home/p1", AgentStatus::Working),
                status("home/p2", AgentStatus::Idle),
            ],
            RelayResync::Seed,
            now,
        );
        assert!(seeded.is_empty(), "the first stream seeds silently");

        // While disconnected p1 blocked and p3 appeared; p2 did not change.
        let missed = store.relay_resync(
            "home",
            vec![
                status("home/p1", AgentStatus::Blocked),
                status("home/p2", AgentStatus::Idle),
                status("home/p3", AgentStatus::Working),
            ],
            RelayResync::Diff,
            now,
        );
        assert_eq!(
            missed
                .iter()
                .map(|event| (event.pane_id.as_str(), event.agent_status))
                .collect::<Vec<_>>(),
            vec![
                ("home/p1", AgentStatus::Blocked),
                ("home/p3", AgentStatus::Working)
            ]
        );
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Blocked);
        // The stream then delivers the same transition: it is not repeated,
        // while a genuinely new one is.
        assert!(!store.relay_status("home", &mut status("home/p1", AgentStatus::Blocked), now));
        assert!(store.relay_status("home", &mut status("home/p1", AgentStatus::Working), now));
        // A second resync with nothing new reports nothing.
        assert!(store
            .relay_resync(
                "home",
                vec![
                    status("home/p1", AgentStatus::Working),
                    status("home/p2", AgentStatus::Idle),
                    status("home/p3", AgentStatus::Working),
                ],
                RelayResync::Diff,
                now,
            )
            .is_empty());
        // After a peer restart every current pane is reported.
        assert_eq!(
            store
                .relay_resync(
                    "home",
                    vec![status("home/p1", AgentStatus::Working)],
                    RelayResync::Reset,
                    now,
                )
                .len(),
            1
        );
    }

    #[test]
    fn relayed_status_never_rewinds_the_cached_turn() {
        let mut store = FederationStore::default();
        let now = Instant::now();
        store.set_peer(
            "home",
            PeerCacheEntry::reachable(vec![pane_agent("home/p1", AgentStatus::Working)], now),
        );
        store.relay_turn("home", relayed_turn("home/p1", 5, 2), now);
        // The cached agent's and the relay baseline's turn.
        let turn = |store: &FederationStore| {
            let entry = store.peer("home").unwrap();
            let agent = &entry.agents[0];
            let baseline = &entry.relayed["home/p1"].event;
            [
                (agent.turn_epoch, agent.turn),
                (baseline.turn_epoch, baseline.turn),
            ]
        };
        assert_eq!(turn(&store), [(Some(2), Some(5)); 2]);

        // A status carrying an older turn, or none, still changes the status,
        // but the cache, the baseline and the event handed back for
        // publishing keep the newer turn.
        let mut older = status("home/p1", AgentStatus::Idle);
        older.turn = Some(4);
        older.turn_epoch = Some(2);
        assert!(store.relay_status("home", &mut older, now));
        assert_eq!((older.turn_epoch, older.turn), (Some(2), Some(5)));
        assert_eq!(cached_status(&store, "home/p1"), AgentStatus::Idle);
        assert_eq!(turn(&store), [(Some(2), Some(5)); 2]);
        let mut unnumbered = status("home/p1", AgentStatus::Working);
        assert!(store.relay_status("home", &mut unnumbered, now));
        assert_eq!((unnumbered.turn_epoch, unnumbered.turn), (Some(2), Some(5)));
        assert_eq!(turn(&store), [(Some(2), Some(5)); 2]);

        // A newer epoch moves it, even with a lower turn.
        let mut restarted = status("home/p1", AgentStatus::Idle);
        restarted.turn = Some(1);
        restarted.turn_epoch = Some(3);
        assert!(store.relay_status("home", &mut restarted, now));
        assert_eq!(turn(&store), [(Some(3), Some(1)); 2]);
    }

    #[test]
    fn closed_remote_pane_leaves_the_cache_at_once_and_stays_gone() {
        use std::time::Duration;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        let listed = || {
            vec![
                pane_agent("home/p1", AgentStatus::Working),
                pane_agent("home/p2", AgentStatus::Idle),
            ]
        };
        store.set_polled_peer("home", PeerCacheEntry::reachable(listed(), t0), t0);
        store.relay_resync(
            "home",
            vec![
                status("home/p1", AgentStatus::Working),
                status("home/p2", AgentStatus::Idle),
            ],
            RelayResync::Seed,
            t0,
        );
        let pane_ids = |store: &FederationStore| {
            store
                .merged_agents()
                .into_iter()
                .map(|agent| agent.pane_id)
                .collect::<Vec<_>>()
        };

        let poll_started = Instant::now();
        let revision = store.revision();
        store.relay_pane_closed("home", "home/p1", poll_started + Duration::from_millis(1));
        assert_eq!(pane_ids(&store), ["home/p2"]);
        assert!(!store.peer("home").unwrap().relayed.contains_key("home/p1"));
        assert_ne!(
            store.revision(),
            revision,
            "the app loop re-reads the store"
        );
        assert_eq!(
            store.take_pane_events(),
            [("home/p1".to_owned(), RemotePaneEvent::Closed)]
        );

        // A poll that started before the close still lists the pane.
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(listed(), t0),
            poll_started,
        );
        assert_eq!(pane_ids(&store), ["home/p2"]);
    }

    #[test]
    fn peer_restart_takes_the_new_boots_turns_over_stale_cached_ones() {
        use std::time::Duration;
        let mut store = FederationStore::default();
        let t0 = Instant::now();
        // The previous boot: p1 at (epoch 10, turn 9), p2 at (10, 3).
        let old_boot = || {
            ["home/p1", "home/p2"].map(|pane_id| {
                let mut agent = pane_agent(pane_id, AgentStatus::Working);
                agent.turn_epoch = Some(10);
                agent.turn = Some(if pane_id == "home/p1" { 9 } else { 3 });
                agent
            })
        };
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(old_boot().to_vec(), t0),
            t0,
        );
        store.relay_resync(
            "home",
            old_boot().iter().map(agent_status_event).collect(),
            RelayResync::Seed,
            t0,
        );
        let turns = |store: &FederationStore, pane_id: &str| {
            let entry = store.peer("home").unwrap();
            let agent = entry
                .agents
                .iter()
                .find(|agent| agent.pane_id == pane_id)
                .unwrap();
            let baseline = &entry.relayed[pane_id].event;
            [
                (agent.turn_epoch, agent.turn),
                (baseline.turn_epoch, baseline.turn),
            ]
        };

        // The peer restarts and the relay reconnects before the poll refreshes
        // the cache: the new boot reports a lower epoch for p1 and no turn for
        // p2 (no agent in it any more).
        let poll_started = Instant::now();
        let reset_at = poll_started + Duration::from_millis(1);
        let mut p1 = status("home/p1", AgentStatus::Idle);
        (p1.turn_epoch, p1.turn) = (Some(4), Some(1));
        let p2 = status("home/p2", AgentStatus::Idle);
        let published = store.relay_resync(
            "home",
            vec![p1.clone(), p2.clone()],
            RelayResync::Reset,
            reset_at,
        );
        assert_eq!(published, [p1, p2], "published as the new boot sent them");
        assert_eq!(turns(&store, "home/p1"), [(Some(4), Some(1)); 2]);
        assert_eq!(turns(&store, "home/p2"), [(None, None); 2]);

        // A poll of the old boot that started before the reset lands after it.
        store.set_polled_peer(
            "home",
            PeerCacheEntry::reachable(old_boot().to_vec(), t0),
            poll_started,
        );
        assert_eq!(turns(&store, "home/p1"), [(Some(4), Some(1)); 2]);

        // The new boot's next turn and statuses move forward from its own.
        store.relay_turn("home", relayed_turn("home/p1", 2, 4), reset_at);
        assert_eq!(turns(&store, "home/p1"), [(Some(4), Some(2)); 2]);
        let mut working = status("home/p1", AgentStatus::Working);
        (working.turn_epoch, working.turn) = (Some(4), Some(2));
        assert!(store.relay_status("home", &mut working, reset_at));
        assert_eq!((working.turn_epoch, working.turn), (Some(4), Some(2)));
    }
}
