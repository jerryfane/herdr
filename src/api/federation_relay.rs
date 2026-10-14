//! Per-peer federation event relay (#245).
//!
//! Next to each outbound peer's 5 s `agent.list` poll, a coordinator holds one
//! `events.subscribe` stream to every identity-validated peer that advertises
//! `events_v2`. Each event is rewritten into the coordinator's namespace (every
//! id gains the peer's `<alias>/` prefix, workspace and tab snapshots get the
//! home-owned machine fields), recorded in the [`FederationStore`], and pushed
//! into the coordinator's own [`EventHub`], so every local subscriber sees a
//! remote status change within about a second with no fan-out of its own.
//!
//! Loop prevention: the stream asks for `local_only`, so a peer that is itself
//! a coordinator leaves out the events it relays (the hub marks them, see
//! [`EventHub::push_relayed`]). An already-qualified id is also refused, like
//! the poll refuses one.
//!
//! Consistency: after every (re)connect and on a `lagged` control line the
//! relay polls `agent.list{local_only:true}` and publishes each status that
//! differs from what it last published, once ([`FederationStore::relay_resync`]).
//! A changed peer boot id resets that baseline. The 5 s poll stays the
//! backstop; it never overwrites a status the relay published after the poll
//! started ([`FederationStore::set_polled_peer`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::api::client::{ApiClient, FederatedStream, FEDERATION_STREAM_IDLE_TIMEOUT};
use crate::api::federation_manager::{PeerPresentation, PeerRoute, PeerRouteStamp};
use crate::api::federation_store::{
    agent_status_event, FederationStore, RelayResync, RemotePaneEvent,
};
use crate::api::schema::{
    EventData, EventEnvelope, EventKind, EventsSubscribeParams, Method,
    PaneAgentStatusChangedEvent, PaneInfo, PaneLayoutSnapshot, Request, ResponseResult,
    Subscription, SubscriptionControlLine, SubscriptionEventData, SubscriptionStreamEvent,
    SubscriptionStreamPayload, SuccessResponse, WorkspaceInfo, WorktreeInfo,
};
use crate::api::server::{
    failure_backoff, poll_peer_agent_list, prefix_remote_agent, qualify_remote_id,
    qualify_remote_tab, qualify_remote_workspace, sleep_interruptible,
    FEDERATION_MAX_STREAM_FRAME_BYTES, FEDERATION_POLL_INTERVAL,
};
use crate::api::subscriptions::status_event_from_hub;
use crate::api::EventHub;

/// Waits and bounds of one relay thread.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayTiming {
    /// How often a relay whose peer is not (yet) eligible re-checks identity
    /// validation and the `events_v2` capability.
    pub(crate) eligibility_step: Duration,
    /// Base of the jittered wait after a stream fails or ends; the same
    /// backoff the poll uses after a miss.
    pub(crate) reconnect_base: Duration,
    /// Longest one read blocks before stop, shutdown and the route stamp are
    /// re-checked.
    pub(crate) read_slice: Duration,
}

impl Default for RelayTiming {
    fn default() -> Self {
        Self {
            eligibility_step: Duration::from_millis(250),
            reconnect_base: FEDERATION_POLL_INTERVAL,
            read_slice: Duration::from_millis(250),
        }
    }
}

/// Everything one peer's relay thread needs. Built by the peer manager next to
/// the poll thread and sharing its route, presentation and stop flag.
pub(crate) struct PeerRelay {
    pub(crate) alias: String,
    pub(crate) expected_node_id: Option<String>,
    pub(crate) route: PeerRoute,
    pub(crate) presentation: Arc<RwLock<PeerPresentation>>,
    pub(crate) store: Arc<Mutex<FederationStore>>,
    pub(crate) event_hub: EventHub,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) timing: RelayTiming,
}

/// Why one stream session ended.
#[derive(Debug)]
enum SessionEnd {
    /// Daemon shutdown or peer retirement: the thread exits.
    Stopped,
    /// The route generation moved (peer boot changed or route retired):
    /// reconnect at once against the current generation.
    Stale,
    /// The poll stopped vouching for the peer's identity: nothing more from
    /// this stream is applied; the thread waits until the peer is eligible
    /// again.
    Revoked,
    /// Transport, protocol or idle failure: reconnect after the backoff.
    Failed(String),
}

/// State carried across one relay thread's stream sessions.
struct RelayState {
    /// How the next resync compares the peer with the relay baseline.
    next_sync: RelayResync,
    /// Peer boot id seen at the last resync.
    boot: Option<String>,
    /// Streams opened so far; names each subscribe request.
    connections: u64,
}

/// The entries a relay subscribes to: every pane's status and completed turns
/// plus the lifecycle and label events a coordinator's clients render.
fn relay_subscriptions() -> Vec<Subscription> {
    vec![
        Subscription::PaneAgentStatusChanged {
            pane_id: None,
            agent_status: None,
        },
        Subscription::PaneTurnCompleted { pane_id: None },
        Subscription::PaneCreated {},
        Subscription::PaneClosed {},
        Subscription::PaneExited {},
        Subscription::PaneAgentDetected {},
        Subscription::WorkspaceCreated {},
        Subscription::WorkspaceRenamed {},
        Subscription::WorkspaceClosed {},
        Subscription::TabCreated {},
        Subscription::TabRenamed {},
        Subscription::TabClosed {},
    ]
}

impl PeerRelay {
    /// Relay this peer's events until the daemon stops or the peer is retired.
    /// Holds at most one upstream stream at a time.
    pub(crate) fn run(self) {
        let client = self.route.client();
        let mut state = RelayState {
            next_sync: RelayResync::Seed,
            boot: None,
            connections: 0,
        };
        while !self.stopping() {
            if !self.eligible() {
                sleep_interruptible(&self.running, &self.stop, self.timing.eligibility_step);
                continue;
            }
            state.connections += 1;
            match self.session(&client, &mut state) {
                SessionEnd::Stopped => break,
                SessionEnd::Stale => {
                    debug!(alias = %self.alias, "federation event relay route changed; reconnecting");
                }
                SessionEnd::Revoked => {
                    info!(alias = %self.alias, "federation peer identity no longer validated; event relay paused");
                }
                SessionEnd::Failed(reason) => {
                    debug!(alias = %self.alias, %reason, "federation event relay stream unavailable");
                    sleep_interruptible(
                        &self.running,
                        &self.stop,
                        failure_backoff(self.timing.reconnect_base),
                    );
                }
            }
        }
        debug!(alias = %self.alias, "federation event relay thread exiting");
    }

    fn stopping(&self) -> bool {
        !self.running.load(Ordering::Relaxed) || self.stop.load(Ordering::Relaxed)
    }

    /// Only an identity-validated peer whose last poll advertised `events_v2`
    /// is streamed; any other keeps the poll alone.
    fn eligible(&self) -> bool {
        self.route.identity_validated()
            && self
                .store
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .peer(&self.alias)
                .and_then(|entry| entry.observation.remote_capabilities.as_ref())
                .is_some_and(|capabilities| capabilities.events_v2)
    }

    /// Whether the stream opened under `stamp` still talks to the current
    /// route generation. The route's first boot observation fills in the
    /// stamp's boot id without a new generation (the same peer process
    /// answered), so it is adopted instead of dropping a healthy stream.
    fn current(&self, stamp: &mut PeerRouteStamp) -> bool {
        if self.route.is_current(stamp) {
            return true;
        }
        let now = self.route.stamp();
        if stamp.remote_boot_id.is_none() && now.generation == stamp.generation {
            *stamp = now;
            return self.route.is_current(stamp);
        }
        false
    }

    fn presentation(&self) -> PeerPresentation {
        self.presentation
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// One stream: subscribe, resync, then relay lines until it ends.
    fn session(&self, client: &ApiClient, state: &mut RelayState) -> SessionEnd {
        let mut stamp = self.route.stamp();
        let request = Request {
            id: format!("federation:events.subscribe:{}", state.connections),
            method: Method::EventsSubscribe(EventsSubscribeParams {
                subscriptions: relay_subscriptions(),
                events_v2: true,
                local_only: true,
            }),
        };
        let mut stream = match self
            .route
            .with_current(&stamp, || client.open_frame_stream_classified(&request))
        {
            None => return SessionEnd::Stale,
            Some(Err(error)) => return SessionEnd::Failed(format!("{error:?}")),
            Some(Ok(stream)) => stream,
        };
        let ack = match self.next_line(&mut stream, &mut stamp) {
            Ok(line) => line,
            Err(end) => return end,
        };
        match serde_json::from_str::<SuccessResponse>(&ack) {
            Ok(SuccessResponse {
                result: ResponseResult::SubscriptionStarted { .. },
                ..
            }) => {}
            _ => return SessionEnd::Failed(format!("peer refused the event stream: {ack}")),
        }
        if let Some(end) = self.resync(client, &mut stamp, state) {
            return end;
        }
        info!(alias = %self.alias, "federation event relay streaming peer events");
        loop {
            let line = match self.next_line(&mut stream, &mut stamp) {
                Ok(line) => line,
                Err(SessionEnd::Failed(reason)) => {
                    warn!(alias = %self.alias, %reason, "federation event relay stream lost; reconnecting");
                    return SessionEnd::Failed(reason);
                }
                Err(end) => return end,
            };
            if let Some(end) = self.handle_line(&line, client, &mut stamp, state) {
                return end;
            }
        }
    }

    /// The next stream line, re-checking stop, the route stamp and the peer's
    /// identity validation at least every read slice. A stream silent for
    /// longer than the federation idle timeout (the peer heartbeats every
    /// 15 s) has failed.
    fn next_line(
        &self,
        stream: &mut FederatedStream,
        stamp: &mut PeerRouteStamp,
    ) -> Result<String, SessionEnd> {
        let idle_deadline = Instant::now() + FEDERATION_STREAM_IDLE_TIMEOUT;
        loop {
            if self.stopping() {
                return Err(SessionEnd::Stopped);
            }
            if !self.current(stamp) {
                return Err(SessionEnd::Stale);
            }
            if !self.route.identity_validated() {
                return Err(SessionEnd::Revoked);
            }
            match stream.next_frame(
                FEDERATION_MAX_STREAM_FRAME_BYTES,
                self.timing.read_slice,
                &self.running,
            ) {
                Ok(Some(line)) => return Ok(line),
                Ok(None) => return Err(SessionEnd::Failed("peer closed the event stream".into())),
                Err(error)
                    if error.kind() == std::io::ErrorKind::TimedOut
                        && Instant::now() < idle_deadline => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    return Err(SessionEnd::Stopped)
                }
                Err(error) => return Err(SessionEnd::Failed(error.to_string())),
            }
        }
    }

    fn handle_line(
        &self,
        line: &str,
        client: &ApiClient,
        stamp: &mut PeerRouteStamp,
        state: &mut RelayState,
    ) -> Option<SessionEnd> {
        if let Ok(event) = serde_json::from_str::<SubscriptionStreamEvent>(line) {
            return self.relay_event(event.payload, stamp);
        }
        match serde_json::from_str::<SubscriptionControlLine>(line) {
            Ok(SubscriptionControlLine::Lagged {
                first_missed_seq,
                last_missed_seq,
                ..
            }) => {
                warn!(
                    alias = %self.alias,
                    first_missed_seq,
                    last_missed_seq,
                    "federation peer event stream lagged; resynchronizing"
                );
                self.resync(client, stamp, state)
            }
            Ok(SubscriptionControlLine::Heartbeat { .. }) => None,
            Err(_) => {
                debug!(alias = %self.alias, line, "federation event relay skipped an unrecognized line");
                None
            }
        }
    }

    /// Poll the peer's `agent.list` and publish every status that differs
    /// from the relay baseline (see [`RelayResync`]).
    fn resync(
        &self,
        client: &ApiClient,
        stamp: &mut PeerRouteStamp,
        state: &mut RelayState,
    ) -> Option<SessionEnd> {
        let snapshot =
            match poll_peer_agent_list(client, &self.running, self.expected_node_id.as_deref()) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Some(SessionEnd::Failed(format!(
                        "resync agent.list failed: {error}"
                    )))
                }
            };
        // A boot the route has not seen yet moves its generation, so this
        // stream is stale and the next one resets the baseline.
        self.route
            .observe_remote_boot(snapshot.remote_boot_id.as_deref());
        if !self.current(stamp) {
            return Some(SessionEnd::Stale);
        }
        let mode = if state.boot.is_some() && state.boot != snapshot.remote_boot_id {
            RelayResync::Reset
        } else {
            state.next_sync
        };
        let presentation = self.presentation();
        let current: Vec<PaneAgentStatusChangedEvent> = snapshot
            .agents
            .into_iter()
            .filter_map(|agent| prefix_remote_agent(&self.alias, &presentation, agent))
            .filter(|agent| !agent.pane_id.is_empty())
            .map(|agent| agent_status_event(&agent))
            .collect();
        let published = self.route.with_current(stamp, || {
            let mut store = self
                .store
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Same under-lock stop guard as the poll: never write an alias
            // the reconcile has already evicted.
            if self.stop.load(Ordering::Relaxed) {
                return Some(0);
            }
            if !self.route.identity_validated() {
                return None;
            }
            let missed = store.relay_resync(&self.alias, current, mode, Instant::now());
            let published = missed.len();
            for event in missed {
                self.event_hub.push_relayed(status_envelope(event));
            }
            Some(published)
        });
        let published = match published {
            None => return Some(SessionEnd::Stale),
            Some(None) => return Some(SessionEnd::Revoked),
            Some(Some(published)) => published,
        };
        debug!(alias = %self.alias, ?mode, published, "federation event relay resynchronized");
        state.boot = snapshot.remote_boot_id;
        state.next_sync = RelayResync::Diff;
        None
    }

    /// Qualify one peer event, record it in the store, and push it into the
    /// local hub unless it repeats a status already published.
    fn relay_event(
        &self,
        payload: SubscriptionStreamPayload,
        stamp: &mut PeerRouteStamp,
    ) -> Option<SessionEnd> {
        let envelope = hub_envelope(payload)?;
        let event = envelope.event;
        let Some(envelope) = qualify_remote_event(&self.alias, &self.presentation(), envelope)
        else {
            warn!(
                alias = %self.alias,
                event = event.dot_name(),
                "federation peer sent an event with already-qualified or invalid ids; dropped"
            );
            return None;
        };
        if !self.current(stamp) {
            return Some(SessionEnd::Stale);
        }
        // `Some(false)`: applied or skipped; `Some(true)`: the peer's identity
        // was revoked, so the line is dropped and the session ends.
        let revoked = self.route.with_current(stamp, || {
            let mut store = self
                .store
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.stop.load(Ordering::Relaxed) {
                return false;
            }
            if !self.route.identity_validated() {
                return true;
            }
            let now = Instant::now();
            let publish = match &envelope.data {
                EventData::PaneAgentStatusChanged { .. } => {
                    // Publish what was recorded: its turn never runs behind
                    // one already relayed for the pane.
                    if let Some(mut status) = status_event_from_hub(&envelope) {
                        if store.relay_status(&self.alias, &mut status, now) {
                            self.event_hub.push_relayed(status_envelope(status));
                        }
                    }
                    false
                }
                EventData::PaneTurnCompleted {
                    pane,
                    turn,
                    turn_epoch,
                    ..
                } => {
                    store.relay_turn(&self.alias, &pane.pane_id, *turn, *turn_epoch, now);
                    true
                }
                EventData::PaneClosed { pane_id, .. } => {
                    store.relay_pane_closed(&self.alias, pane_id, now);
                    true
                }
                EventData::PaneExited { pane_id, .. } => {
                    store.relay_pane_event(&self.alias, pane_id, RemotePaneEvent::Exited);
                    true
                }
                EventData::PaneAgentDetected {
                    pane_id,
                    released: true,
                    ..
                } => {
                    store.relay_pane_event(&self.alias, pane_id, RemotePaneEvent::AgentReleased);
                    true
                }
                _ => true,
            };
            if publish {
                self.event_hub.push_relayed(envelope);
            }
            false
        });
        match revoked {
            None => Some(SessionEnd::Stale),
            Some(true) => Some(SessionEnd::Revoked),
            Some(false) => None,
        }
    }
}

fn status_envelope(event: PaneAgentStatusChangedEvent) -> EventEnvelope {
    let PaneAgentStatusChangedEvent {
        pane_id,
        workspace_id,
        agent_status,
        input_pending,
        input_prompt_kind,
        agent,
        title,
        display_agent,
        state_labels,
        turn,
        turn_epoch,
    } = event;
    EventEnvelope {
        event: EventKind::PaneAgentStatusChanged,
        data: EventData::PaneAgentStatusChanged {
            pane_id,
            workspace_id,
            agent_status,
            input_pending,
            input_prompt_kind,
            agent,
            title,
            display_agent,
            state_labels,
            turn,
            turn_epoch,
        },
    }
}

/// The hub form of one peer stream line: lifecycle events already are hub
/// envelopes; pane subscription lines become the hub event they came from.
fn hub_envelope(payload: SubscriptionStreamPayload) -> Option<EventEnvelope> {
    match payload {
        SubscriptionStreamPayload::Event(envelope) => Some(*envelope),
        SubscriptionStreamPayload::Subscription(envelope) => match envelope.data {
            SubscriptionEventData::PaneAgentStatusChanged(event) => Some(status_envelope(event)),
            SubscriptionEventData::PaneTurnCompleted(event) => {
                let event = *event;
                Some(EventEnvelope {
                    event: EventKind::PaneTurnCompleted,
                    data: EventData::PaneTurnCompleted {
                        pane: event.pane,
                        turn: event.turn,
                        turn_epoch: event.turn_epoch,
                        outcome: event.outcome,
                        message: event.message,
                        message_truncated: event.message_truncated,
                        agent_session_path: event.agent_session_path,
                        completed_unix_ms: event.completed_unix_ms,
                    },
                })
            }
            SubscriptionEventData::PaneOutputMatched(_)
            | SubscriptionEventData::ScrollChanged(_) => None,
        },
    }
}

fn qualify_id(alias: &str, value: &mut String) -> Option<()> {
    *value = qualify_remote_id(alias, std::mem::take(value), true)?;
    Some(())
}

fn qualify_optional_id(alias: &str, value: &mut Option<String>) -> Option<()> {
    match value {
        Some(value) => qualify_id(alias, value),
        None => Some(()),
    }
}

fn qualify_workspace(
    alias: &str,
    presentation: &PeerPresentation,
    workspace: &mut WorkspaceInfo,
) -> Option<()> {
    *workspace = qualify_remote_workspace(alias, presentation, workspace.clone())?;
    Some(())
}

fn qualify_pane(alias: &str, pane: &mut PaneInfo) -> Option<()> {
    qualify_id(alias, &mut pane.pane_id)?;
    qualify_id(alias, &mut pane.terminal_id)?;
    qualify_id(alias, &mut pane.workspace_id)?;
    qualify_id(alias, &mut pane.tab_id)
}

fn qualify_worktree(alias: &str, worktree: &mut WorktreeInfo) -> Option<()> {
    qualify_optional_id(alias, &mut worktree.open_workspace_id)
}

/// Split ids are positions inside one tab's layout, not routable ids, so only
/// the workspace, tab and pane ids are qualified.
fn qualify_layout(alias: &str, layout: &mut PaneLayoutSnapshot) -> Option<()> {
    qualify_id(alias, &mut layout.workspace_id)?;
    qualify_id(alias, &mut layout.tab_id)?;
    qualify_id(alias, &mut layout.focused_pane_id)?;
    for pane in &mut layout.panes {
        qualify_id(alias, &mut pane.pane_id)?;
    }
    Some(())
}

/// Rewrite one peer event into the coordinator's namespace: every pane,
/// terminal, workspace and tab id (including those inside pane, workspace, tab,
/// worktree and layout snapshots) gains one `<alias>/` prefix, and workspace
/// and tab snapshots carry the home-owned machine fields. `None` when the peer
/// sent an id that is already qualified, which is refused rather than
/// prefixed twice.
pub(crate) fn qualify_remote_event(
    alias: &str,
    presentation: &PeerPresentation,
    mut envelope: EventEnvelope,
) -> Option<EventEnvelope> {
    let tab = |tab: &mut crate::api::schema::TabInfo| -> Option<()> {
        *tab = qualify_remote_tab(alias, presentation, tab.clone())?;
        Some(())
    };
    match &mut envelope.data {
        EventData::WorkspaceCreated { workspace }
        | EventData::WorkspaceUpdated { workspace }
        | EventData::WorkspaceMetadataUpdated { workspace } => {
            qualify_workspace(alias, presentation, workspace)?;
        }
        EventData::WorkspaceClosed {
            workspace_id,
            workspace,
        } => {
            qualify_id(alias, workspace_id)?;
            if let Some(workspace) = workspace {
                qualify_workspace(alias, presentation, workspace)?;
            }
        }
        EventData::WorkspaceRenamed { workspace_id, .. }
        | EventData::WorkspaceFocused { workspace_id } => qualify_id(alias, workspace_id)?,
        EventData::WorkspaceMoved {
            workspace_id,
            workspaces,
            ..
        } => {
            qualify_id(alias, workspace_id)?;
            for workspace in workspaces {
                qualify_workspace(alias, presentation, workspace)?;
            }
        }
        EventData::WorkspaceReordered {
            workspace_ids,
            before_workspace_id,
            workspaces,
        } => {
            for workspace_id in workspace_ids {
                qualify_id(alias, workspace_id)?;
            }
            qualify_optional_id(alias, before_workspace_id)?;
            for workspace in workspaces {
                qualify_workspace(alias, presentation, workspace)?;
            }
        }
        EventData::WorktreeCreated {
            workspace,
            worktree,
        }
        | EventData::WorktreeOpened {
            workspace,
            worktree,
            ..
        } => {
            qualify_workspace(alias, presentation, workspace)?;
            qualify_worktree(alias, worktree)?;
        }
        EventData::WorktreeRemoved {
            workspace_id,
            workspace,
            worktree,
            ..
        } => {
            qualify_id(alias, workspace_id)?;
            if let Some(workspace) = workspace {
                qualify_workspace(alias, presentation, workspace)?;
            }
            qualify_worktree(alias, worktree)?;
        }
        EventData::TabCreated { tab: created } => tab(created)?,
        EventData::TabClosed {
            tab_id,
            workspace_id,
        }
        | EventData::TabRenamed {
            tab_id,
            workspace_id,
            ..
        }
        | EventData::TabFocused {
            tab_id,
            workspace_id,
        } => {
            qualify_id(alias, tab_id)?;
            qualify_id(alias, workspace_id)?;
        }
        EventData::TabMoved {
            tab_id,
            workspace_id,
            tabs,
            ..
        } => {
            qualify_id(alias, tab_id)?;
            qualify_id(alias, workspace_id)?;
            for moved in tabs {
                tab(moved)?;
            }
        }
        EventData::PaneCreated { pane } | EventData::PaneUpdated { pane } => {
            qualify_pane(alias, pane)?;
        }
        EventData::PaneTurnCompleted { pane, .. } => qualify_pane(alias, pane)?,
        EventData::PaneClosed {
            pane_id,
            workspace_id,
        }
        | EventData::PaneFocused {
            pane_id,
            workspace_id,
        }
        | EventData::PaneOutputChanged {
            pane_id,
            workspace_id,
            ..
        }
        | EventData::PaneExited {
            pane_id,
            workspace_id,
        }
        | EventData::PaneAgentDetected {
            pane_id,
            workspace_id,
            ..
        }
        | EventData::PaneAgentStatusChanged {
            pane_id,
            workspace_id,
            ..
        } => {
            qualify_id(alias, pane_id)?;
            qualify_id(alias, workspace_id)?;
        }
        EventData::PaneMoved {
            previous_pane_id,
            previous_workspace_id,
            previous_tab_id,
            pane,
            created_workspace,
            created_tab,
            closed_workspace_id,
            closed_tab_id,
        } => {
            qualify_id(alias, previous_pane_id)?;
            qualify_id(alias, previous_workspace_id)?;
            qualify_id(alias, previous_tab_id)?;
            qualify_pane(alias, pane)?;
            if let Some(workspace) = created_workspace {
                qualify_workspace(alias, presentation, workspace)?;
            }
            if let Some(created) = created_tab {
                tab(created)?;
            }
            qualify_optional_id(alias, closed_workspace_id)?;
            qualify_optional_id(alias, closed_tab_id)?;
        }
        EventData::LayoutUpdated { layout } => qualify_layout(alias, layout)?,
    }
    Some(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::KNOWN_EVENT_KINDS;
    use serde_json::{json, Value};

    fn pane(id: &str) -> Value {
        json!({
            "pane_id": id, "terminal_id": "t1", "workspace_id": "w1", "tab_id": "w1:t1",
            "focused": true, "agent_status": "working", "revision": 1,
        })
    }

    fn workspace(id: &str) -> Value {
        json!({
            "workspace_id": id, "number": 1, "label": "api", "focused": true,
            "pane_count": 1, "tab_count": 1, "active_tab_id": "w1:t1", "agent_status": "idle",
            "machine_id": "spoofed", "machine_label": "spoofed",
        })
    }

    fn tab(id: &str) -> Value {
        json!({
            "tab_id": id, "workspace_id": "w1", "number": 1, "label": "main",
            "focused": true, "pane_count": 1, "agent_status": "idle",
        })
    }

    fn worktree() -> Value {
        json!({
            "path": "/src/api", "is_bare": false, "is_detached": false, "is_prunable": false,
            "is_linked_worktree": true, "open_workspace_id": "w1", "label": "api",
        })
    }

    /// One peer-local payload per event kind, with every optional id present.
    /// Exhaustive on purpose: a new event kind must decide its qualification.
    fn peer_event(kind: EventKind) -> EventEnvelope {
        let rect = json!({"x": 0, "y": 0, "width": 80, "height": 24});
        let data = match kind {
            EventKind::WorkspaceCreated => {
                json!({"type": "workspace_created", "workspace": workspace("w1")})
            }
            EventKind::WorkspaceUpdated => {
                json!({"type": "workspace_updated", "workspace": workspace("w1")})
            }
            EventKind::WorkspaceMetadataUpdated => {
                json!({"type": "workspace_metadata_updated", "workspace": workspace("w1")})
            }
            EventKind::WorkspaceClosed => {
                json!({"type": "workspace_closed", "workspace_id": "w1", "workspace": workspace("w1")})
            }
            EventKind::WorkspaceRenamed => {
                json!({"type": "workspace_renamed", "workspace_id": "w1", "label": "api"})
            }
            EventKind::WorkspaceMoved => json!({
                "type": "workspace_moved", "workspace_id": "w1", "insert_index": 0,
                "workspaces": [workspace("w1"), workspace("w2")],
            }),
            EventKind::WorkspaceReordered => json!({
                "type": "workspace_reordered", "workspace_ids": ["w2", "w1"],
                "before_workspace_id": "w3", "workspaces": [workspace("w2")],
            }),
            EventKind::WorkspaceFocused => {
                json!({"type": "workspace_focused", "workspace_id": "w1"})
            }
            EventKind::WorktreeCreated => json!({
                "type": "worktree_created", "workspace": workspace("w1"), "worktree": worktree(),
            }),
            EventKind::WorktreeOpened => json!({
                "type": "worktree_opened", "workspace": workspace("w1"), "worktree": worktree(),
                "already_open": true,
            }),
            EventKind::WorktreeRemoved => json!({
                "type": "worktree_removed", "workspace_id": "w1", "workspace": workspace("w1"),
                "worktree": worktree(), "forced": false,
            }),
            EventKind::TabCreated => json!({"type": "tab_created", "tab": tab("w1:t2")}),
            EventKind::TabClosed => {
                json!({"type": "tab_closed", "tab_id": "w1:t2", "workspace_id": "w1"})
            }
            EventKind::TabRenamed => json!({
                "type": "tab_renamed", "tab_id": "w1:t2", "workspace_id": "w1", "label": "logs",
            }),
            EventKind::TabMoved => json!({
                "type": "tab_moved", "tab_id": "w1:t2", "workspace_id": "w1", "insert_index": 0,
                "tabs": [tab("w1:t2"), tab("w1:t1")],
            }),
            EventKind::TabFocused => {
                json!({"type": "tab_focused", "tab_id": "w1:t2", "workspace_id": "w1"})
            }
            EventKind::PaneCreated => json!({"type": "pane_created", "pane": pane("w1:p1")}),
            EventKind::PaneClosed => {
                json!({"type": "pane_closed", "pane_id": "w1:p1", "workspace_id": "w1"})
            }
            EventKind::PaneUpdated => json!({"type": "pane_updated", "pane": pane("w1:p1")}),
            EventKind::PaneFocused => {
                json!({"type": "pane_focused", "pane_id": "w1:p1", "workspace_id": "w1"})
            }
            EventKind::PaneMoved => json!({
                "type": "pane_moved", "previous_pane_id": "w1:p1", "previous_workspace_id": "w1",
                "previous_tab_id": "w1:t1", "pane": pane("w2:p1"), "created_workspace": workspace("w2"),
                "created_tab": tab("w2:t1"), "closed_workspace_id": "w3", "closed_tab_id": "w3:t1",
            }),
            EventKind::PaneOutputChanged => json!({
                "type": "pane_output_changed", "pane_id": "w1:p1", "workspace_id": "w1", "revision": 7,
            }),
            EventKind::PaneExited => {
                json!({"type": "pane_exited", "pane_id": "w1:p1", "workspace_id": "w1"})
            }
            EventKind::PaneAgentDetected => json!({
                "type": "pane_agent_detected", "pane_id": "w1:p1", "workspace_id": "w1", "agent": "pi",
            }),
            EventKind::PaneAgentStatusChanged => json!({
                "type": "pane_agent_status_changed", "pane_id": "w1:p1", "workspace_id": "w1",
                "agent_status": "blocked", "turn": 3, "turn_epoch": 1,
            }),
            EventKind::PaneTurnCompleted => json!({
                "type": "pane_turn_completed", "pane": pane("w1:p1"), "turn": 3, "turn_epoch": 1,
                "outcome": "completed", "completed_unix_ms": 1,
            }),
            EventKind::LayoutUpdated => json!({"type": "layout_updated", "layout": {
                "workspace_id": "w1", "tab_id": "w1:t1", "zoomed": false, "area": rect,
                "focused_pane_id": "w1:p1",
                "panes": [{"pane_id": "w1:p1", "focused": true, "rect": rect}],
                "splits": [{"id": "split_0_root", "direction": "right", "ratio": 0.5, "rect": rect}],
            }}),
        };
        EventEnvelope {
            event: kind,
            data: serde_json::from_value(data).expect("sample event data"),
        }
    }

    const ID_FIELDS: &[&str] = &[
        "pane_id",
        "terminal_id",
        "workspace_id",
        "tab_id",
        "active_tab_id",
        "previous_pane_id",
        "previous_workspace_id",
        "previous_tab_id",
        "closed_workspace_id",
        "closed_tab_id",
        "open_workspace_id",
        "before_workspace_id",
        "focused_pane_id",
    ];

    /// Every id anywhere in `value` (paths for failure messages), and every
    /// object carrying federation machine fields.
    fn collect(
        value: &Value,
        path: &str,
        ids: &mut Vec<(String, String)>,
        machines: &mut Vec<Value>,
    ) {
        match value {
            Value::Object(map) => {
                if map.contains_key("machine_id") {
                    machines.push(value.clone());
                }
                for (key, child) in map {
                    let child_path = format!("{path}.{key}");
                    match child {
                        Value::String(id) if ID_FIELDS.contains(&key.as_str()) => {
                            ids.push((child_path, id.clone()));
                        }
                        Value::Array(items) if key == "workspace_ids" => {
                            for item in items {
                                ids.push((child_path.clone(), item.as_str().unwrap().into()));
                            }
                        }
                        _ => collect(child, &child_path, ids, machines),
                    }
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    collect(item, &format!("{path}[{index}]"), ids, machines);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn every_event_kind_is_qualified_with_the_peer_alias() {
        let presentation = PeerPresentation {
            profile_id: Some("profile-box".into()),
            label: "Build box".into(),
        };
        for kind in KNOWN_EVENT_KINDS {
            let peer = peer_event(*kind);
            let mut peer_ids = Vec::new();
            collect(
                &serde_json::to_value(&peer).unwrap(),
                "",
                &mut peer_ids,
                &mut Vec::new(),
            );

            let qualified = qualify_remote_event("box", &presentation, peer.clone())
                .unwrap_or_else(|| panic!("{kind:?} was refused"));
            let (mut ids, mut machines) = (Vec::new(), Vec::new());
            collect(
                &serde_json::to_value(&qualified).unwrap(),
                "",
                &mut ids,
                &mut machines,
            );
            assert_eq!(ids.len(), peer_ids.len(), "{kind:?} lost or gained an id");
            for ((path, id), (_, peer_id)) in ids.iter().zip(&peer_ids) {
                assert_eq!(*id, format!("box/{peer_id}"), "{kind:?} {path}");
            }
            for machine in machines {
                assert_eq!(machine["machine_id"], "box", "{kind:?}");
                assert_eq!(machine["machine_label"], "Build box", "{kind:?}");
                assert_eq!(machine["machine_profile_id"], "profile-box", "{kind:?}");
            }
            if let EventData::LayoutUpdated { layout } = &qualified.data {
                assert_eq!(
                    layout.splits[0].id, "split_0_root",
                    "split ids are layout-local"
                );
            }

            // A relayed event that reaches another coordinator is refused, not
            // prefixed twice.
            assert!(
                qualify_remote_event("home", &presentation, qualified).is_none(),
                "{kind:?} was qualified twice"
            );
        }
    }
}
