use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use regex::Regex;

use crate::api::event_hub::{EventBatch, EventHistoryError};
use crate::api::schema::{
    AgentStatus, ErrorBody, ErrorResponse, EventData, EventEnvelope, EventKind, Method,
    PaneAgentStatusChangedEvent, PaneInfo, PaneOutputMatchedEvent, PaneScrollChangedEvent,
    PaneScrollInfo, PaneTurnCompletedEvent, Request, Subscription, SubscriptionEventData,
    SubscriptionEventEnvelope, SubscriptionEventKind, SubscriptionStreamPayload,
};
use crate::api::server::{dispatch_to_app_with_timeout, APP_RESPONSE_TIMEOUT};
use crate::api::{ApiRequestSender, EventHub};

/// How often an all-pane status subscription compares a `pane.list` snapshot
/// with the states it last reported. Hub events carry most transitions at once;
/// the snapshot catches status changes that have no hub event, such as `done`
/// becoming `idle` when a pane is seen.
const ALL_PANES_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);

/// A line one subscription produced during a stream tick.
pub(super) struct SubscriptionLine {
    pub(super) seq: u64,
    /// Derived from pane state rather than taken from a hub event. Sorts after
    /// hub events that share its `seq`, because it was computed after them.
    pub(super) derived: bool,
    pub(super) payload: SubscriptionStreamPayload,
}

impl SubscriptionLine {
    fn hub(seq: u64, payload: SubscriptionStreamPayload) -> Self {
        Self {
            seq,
            derived: false,
            payload,
        }
    }

    fn derived(seq: u64, envelope: SubscriptionEventEnvelope) -> Self {
        Self {
            seq,
            derived: true,
            payload: SubscriptionStreamPayload::Subscription(Box::new(envelope)),
        }
    }
}

fn events_after(batch: &EventBatch, cursor: u64) -> &[(u64, EventEnvelope)] {
    let start = batch
        .events
        .partition_point(|(sequence, _)| *sequence <= cursor);
    &batch.events[start..]
}

pub(super) fn output_match_read_source(
    source: &crate::api::schema::ReadSource,
) -> crate::api::schema::ReadSource {
    match source {
        crate::api::schema::ReadSource::Recent => crate::api::schema::ReadSource::RecentUnwrapped,
        other => *other,
    }
}

pub(super) fn match_output(
    text: &str,
    matcher: &crate::api::schema::OutputMatch,
    regex: Option<&Regex>,
) -> Option<String> {
    match matcher {
        crate::api::schema::OutputMatch::Substring { value } => text
            .lines()
            .find(|line| line.contains(value))
            .map(|line| line.to_string()),
        crate::api::schema::OutputMatch::Regex { .. } => regex.and_then(|re| {
            text.lines()
                .find(|line| re.is_match(line))
                .map(|line| line.to_string())
        }),
    }
}

pub(super) struct ActiveOutputMatchedSubscription {
    pane_id: String,
    source: crate::api::schema::ReadSource,
    lines: Option<u32>,
    matcher: crate::api::schema::OutputMatch,
    regex: Option<Regex>,
    strip_ansi: bool,
    currently_matching: bool,
    request_prefix: String,
}

pub(super) struct ActiveAgentStatusChangedSubscription {
    pane_id: String,
    status_filter: Option<AgentStatus>,
    last_status: Option<AgentStatus>,
    last_presentation: Option<PanePresentationSnapshot>,
    last_input: Option<(bool, Option<crate::detect::InputPromptKind>)>,
    last_sequence: u64,
    initial_event: Option<PaneAgentStatusChangedEvent>,
    request_prefix: String,
    /// An alias-qualified pane of a federation peer. Its changes arrive only
    /// as events the relay pushes into the hub; the local app cannot
    /// `pane.get` it.
    remote: bool,
}

/// `pane.agent_status_changed` without a `pane_id`: every local pane plus any
/// pane whose status events reach the hub.
pub(super) struct ActiveAllPanesAgentStatusSubscription {
    status_filter: Option<AgentStatus>,
    /// Last state reported (or seeded) per pane, so snapshot diffs report only
    /// changes and never repeat a hub event.
    panes: HashMap<String, PaneStatusSnapshot>,
    last_sequence: u64,
    snapshot_interval: Duration,
    next_snapshot: Instant,
    request_prefix: String,
}

pub(super) struct ActiveScrollChangedSubscription {
    pane_id: String,
    last_scroll: Option<PaneScrollInfo>,
    request_prefix: String,
}

pub(super) struct ActiveTurnCompletedSubscription {
    /// `None` watches every pane.
    pane_id: Option<String>,
    last_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PanePresentationSnapshot {
    title: Option<String>,
    display_agent: Option<String>,
    state_labels: std::collections::HashMap<String, String>,
}

impl PanePresentationSnapshot {
    fn from(pane: &crate::api::schema::PaneInfo) -> Self {
        Self {
            title: pane.title.clone(),
            display_agent: pane.display_agent.clone(),
            state_labels: pane.state_labels.clone(),
        }
    }

    fn from_event(
        title: &Option<String>,
        display_agent: &Option<String>,
        state_labels: &std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            title: title.clone(),
            display_agent: display_agent.clone(),
            state_labels: state_labels.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PaneStatusSnapshot {
    status: AgentStatus,
    presentation: PanePresentationSnapshot,
    input: (bool, Option<crate::detect::InputPromptKind>),
}

impl PaneStatusSnapshot {
    fn from_pane(pane: &PaneInfo) -> Self {
        Self {
            status: pane.agent_status,
            presentation: PanePresentationSnapshot::from(pane),
            input: (pane.input_pending, pane.input_prompt_kind),
        }
    }

    fn from_event(event: &PaneAgentStatusChangedEvent) -> Self {
        Self {
            status: event.agent_status,
            presentation: PanePresentationSnapshot::from_event(
                &event.title,
                &event.display_agent,
                &event.state_labels,
            ),
            input: (event.input_pending, event.input_prompt_kind),
        }
    }
}

fn status_event_from_pane(pane: PaneInfo) -> PaneAgentStatusChangedEvent {
    PaneAgentStatusChangedEvent {
        pane_id: pane.pane_id,
        workspace_id: pane.workspace_id,
        agent_status: pane.agent_status,
        input_pending: pane.input_pending,
        input_prompt_kind: pane.input_prompt_kind,
        agent: pane.agent,
        title: pane.title,
        display_agent: pane.display_agent,
        state_labels: pane.state_labels,
        turn: pane.turn,
        turn_epoch: pane.turn_epoch,
    }
}

pub(super) fn status_event_from_hub(event: &EventEnvelope) -> Option<PaneAgentStatusChangedEvent> {
    if event.event != EventKind::PaneAgentStatusChanged {
        return None;
    }
    let EventData::PaneAgentStatusChanged {
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
    } = &event.data
    else {
        return None;
    };
    Some(PaneAgentStatusChangedEvent {
        pane_id: pane_id.clone(),
        workspace_id: workspace_id.clone(),
        agent_status: *agent_status,
        input_pending: *input_pending,
        input_prompt_kind: *input_prompt_kind,
        agent: agent.clone(),
        title: title.clone(),
        display_agent: display_agent.clone(),
        state_labels: state_labels.clone(),
        turn: *turn,
        turn_epoch: *turn_epoch,
    })
}

fn status_envelope(event: PaneAgentStatusChangedEvent) -> SubscriptionEventEnvelope {
    SubscriptionEventEnvelope {
        event: SubscriptionEventKind::PaneAgentStatusChanged,
        data: SubscriptionEventData::PaneAgentStatusChanged(event),
    }
}

pub(super) struct ActiveEventSubscription {
    event_kind: EventKind,
    last_sequence: u64,
}

pub(super) enum ActiveSubscription {
    Event(ActiveEventSubscription),
    OutputMatched(ActiveOutputMatchedSubscription),
    AgentStatusChanged(Box<ActiveAgentStatusChangedSubscription>),
    AllPanesAgentStatusChanged(Box<ActiveAllPanesAgentStatusSubscription>),
    TurnCompleted(ActiveTurnCompletedSubscription),
    ScrollChanged(ActiveScrollChangedSubscription),
}

impl ActiveSubscription {
    pub(super) fn new(
        subscription: Subscription,
        request_id: &str,
        index: usize,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
        event_start_sequence: u64,
    ) -> Result<Self, ErrorResponse> {
        let event_subscription = |event_kind| {
            Self::Event(ActiveEventSubscription {
                event_kind,
                last_sequence: event_start_sequence,
            })
        };

        match subscription {
            Subscription::WorkspaceCreated {} => {
                Ok(event_subscription(EventKind::WorkspaceCreated))
            }
            Subscription::WorkspaceUpdated {} => {
                Ok(event_subscription(EventKind::WorkspaceUpdated))
            }
            Subscription::WorkspaceMetadataUpdated {} => {
                Ok(event_subscription(EventKind::WorkspaceMetadataUpdated))
            }
            Subscription::WorkspaceRenamed {} => {
                Ok(event_subscription(EventKind::WorkspaceRenamed))
            }
            Subscription::WorkspaceMoved {} => Ok(event_subscription(EventKind::WorkspaceMoved)),
            Subscription::WorkspaceReordered {} => {
                Ok(event_subscription(EventKind::WorkspaceReordered))
            }
            Subscription::WorkspaceClosed {} => Ok(event_subscription(EventKind::WorkspaceClosed)),
            Subscription::WorkspaceFocused {} => {
                Ok(event_subscription(EventKind::WorkspaceFocused))
            }
            Subscription::WorktreeCreated {} => Ok(event_subscription(EventKind::WorktreeCreated)),
            Subscription::WorktreeOpened {} => Ok(event_subscription(EventKind::WorktreeOpened)),
            Subscription::WorktreeRemoved {} => Ok(event_subscription(EventKind::WorktreeRemoved)),
            Subscription::TabCreated {} => Ok(event_subscription(EventKind::TabCreated)),
            Subscription::TabClosed {} => Ok(event_subscription(EventKind::TabClosed)),
            Subscription::TabFocused {} => Ok(event_subscription(EventKind::TabFocused)),
            Subscription::TabRenamed {} => Ok(event_subscription(EventKind::TabRenamed)),
            Subscription::TabMoved {} => Ok(event_subscription(EventKind::TabMoved)),
            Subscription::PaneCreated {} => Ok(event_subscription(EventKind::PaneCreated)),
            Subscription::PaneClosed {} => Ok(event_subscription(EventKind::PaneClosed)),
            Subscription::PaneUpdated {} => Ok(event_subscription(EventKind::PaneUpdated)),
            Subscription::PaneFocused {} => Ok(event_subscription(EventKind::PaneFocused)),
            Subscription::PaneMoved {} => Ok(event_subscription(EventKind::PaneMoved)),
            Subscription::PaneExited {} => Ok(event_subscription(EventKind::PaneExited)),
            Subscription::PaneAgentDetected {} => {
                Ok(event_subscription(EventKind::PaneAgentDetected))
            }
            Subscription::LayoutUpdated {} => Ok(event_subscription(EventKind::LayoutUpdated)),
            Subscription::PaneOutputMatched {
                pane_id,
                source,
                lines,
                r#match,
                strip_ansi,
            } => {
                let regex = match &r#match {
                    crate::api::schema::OutputMatch::Regex { value } => match Regex::new(value) {
                        Ok(regex) => Some(regex),
                        Err(err) => {
                            return Err(ErrorResponse {
                                id: request_id.to_string(),
                                error: ErrorBody {
                                    code: "invalid_regex".into(),
                                    message: err.to_string(),
                                },
                            });
                        }
                    },
                    crate::api::schema::OutputMatch::Substring { .. } => None,
                };

                let probe = pane_read(
                    format!("{request_id}:sub:{index}:probe"),
                    &pane_id,
                    source,
                    lines,
                    strip_ansi,
                    api_tx,
                );
                probe?;

                Ok(Self::OutputMatched(ActiveOutputMatchedSubscription {
                    pane_id,
                    source,
                    lines,
                    matcher: r#match,
                    regex,
                    strip_ansi,
                    currently_matching: false,
                    request_prefix: format!("{request_id}:sub:{index}"),
                }))
            }
            Subscription::PaneAgentStatusChanged {
                pane_id: Some(pane_id),
                agent_status,
            } => {
                let last_sequence = event_hub.current_sequence();
                let probe =
                    probe_pane(format!("{request_id}:sub:{index}:probe"), &pane_id, api_tx)?;
                let last = PaneStatusSnapshot::from_event(&probe.event);
                let pane_id = probe.event.pane_id.clone();
                let initial_event = agent_status
                    .is_some_and(|wanted| wanted == probe.event.agent_status)
                    .then_some(probe.event);

                Ok(Self::AgentStatusChanged(Box::new(
                    ActiveAgentStatusChangedSubscription {
                        pane_id,
                        status_filter: agent_status,
                        last_status: Some(last.status),
                        last_presentation: Some(last.presentation),
                        last_input: Some(last.input),
                        last_sequence,
                        initial_event,
                        request_prefix: format!("{request_id}:sub:{index}"),
                        remote: probe.remote,
                    },
                )))
            }
            Subscription::PaneAgentStatusChanged {
                pane_id: None,
                agent_status,
            } => {
                let panes = pane_list(format!("{request_id}:sub:{index}:probe"), api_tx)?;
                Ok(Self::AllPanesAgentStatusChanged(Box::new(
                    ActiveAllPanesAgentStatusSubscription {
                        status_filter: agent_status,
                        panes: panes
                            .iter()
                            .map(|pane| (pane.pane_id.clone(), PaneStatusSnapshot::from_pane(pane)))
                            .collect(),
                        last_sequence: event_start_sequence,
                        snapshot_interval: ALL_PANES_SNAPSHOT_INTERVAL,
                        next_snapshot: Instant::now() + ALL_PANES_SNAPSHOT_INTERVAL,
                        request_prefix: format!("{request_id}:sub:{index}"),
                    },
                )))
            }
            Subscription::PaneTurnCompleted {
                pane_id: Some(pane_id),
            } => {
                let last_sequence = event_hub.current_sequence();
                let probe =
                    probe_pane(format!("{request_id}:sub:{index}:probe"), &pane_id, api_tx)?;
                Ok(Self::TurnCompleted(ActiveTurnCompletedSubscription {
                    pane_id: Some(probe.event.pane_id),
                    last_sequence,
                }))
            }
            Subscription::PaneTurnCompleted { pane_id: None } => {
                Ok(Self::TurnCompleted(ActiveTurnCompletedSubscription {
                    pane_id: None,
                    last_sequence: event_start_sequence,
                }))
            }
            Subscription::PaneScrollChanged { pane_id } => {
                let probe = pane_get(format!("{request_id}:sub:{index}:probe"), &pane_id, api_tx)?;

                Ok(Self::ScrollChanged(ActiveScrollChangedSubscription {
                    pane_id: probe.pane_id,
                    last_scroll: probe.scroll,
                    request_prefix: format!("{request_id}:sub:{index}"),
                }))
            }
        }
    }

    /// Every line this subscription has for one stream tick: one line per
    /// matching hub event in `batch`, in hub order, then any line derived from
    /// polling pane state.
    pub(super) fn poll(
        &mut self,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
        batch: &EventBatch,
    ) -> Vec<SubscriptionLine> {
        match self {
            Self::Event(subscription) => subscription.poll(batch),
            Self::OutputMatched(subscription) => subscription
                .poll(api_tx)
                .map(|envelope| SubscriptionLine::derived(batch.head, envelope))
                .into_iter()
                .collect(),
            Self::AgentStatusChanged(subscription) => subscription
                .poll(api_tx, event_hub, batch)
                .unwrap_or_default(),
            Self::AllPanesAgentStatusChanged(subscription) => {
                subscription.poll(api_tx, event_hub, batch)
            }
            Self::TurnCompleted(subscription) => subscription.poll(batch),
            Self::ScrollChanged(subscription) => subscription
                .poll(api_tx)
                .map(|envelope| SubscriptionLine::derived(batch.head, envelope))
                .into_iter()
                .collect(),
        }
    }

    pub(super) fn poll_for_wait(
        &mut self,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
        batch: &EventBatch,
    ) -> Result<Option<serde_json::Value>, ErrorResponse> {
        let lines = match self {
            Self::AgentStatusChanged(subscription) => {
                subscription.poll(api_tx, event_hub, batch)?
            }
            _ => self.poll(api_tx, event_hub, batch),
        };
        Ok(lines
            .into_iter()
            .next()
            .and_then(|line| serde_json::to_value(line.payload).ok()))
    }
}

/// The error a subscription stream reports, and then closes on, when it can no
/// longer read the hub: a legacy reader that fell behind retained history
/// (`events_lost`; `events_v2` readers get a `lagged` line instead), or a
/// history that is unavailable to every reader.
pub(super) fn history_error(error: EventHistoryError) -> ErrorBody {
    match error {
        EventHistoryError::Lost => ErrorBody {
            code: "events_lost".into(),
            message: "event subscription fell behind retained history; resubscribe and resync with session.snapshot".into(),
        },
        EventHistoryError::Unavailable => ErrorBody {
            code: "server_unavailable".into(),
            message: "event history is unavailable".into(),
        },
    }
}

impl ActiveEventSubscription {
    fn poll(&mut self, batch: &EventBatch) -> Vec<SubscriptionLine> {
        let lines = events_after(batch, self.last_sequence)
            .iter()
            .filter(|(_, event)| event.event == self.event_kind)
            .map(|(sequence, event)| {
                SubscriptionLine::hub(
                    *sequence,
                    SubscriptionStreamPayload::Event(Box::new(event.clone())),
                )
            })
            .collect();
        self.last_sequence = self.last_sequence.max(batch.head);
        lines
    }
}

impl ActiveOutputMatchedSubscription {
    fn poll(&mut self, api_tx: &ApiRequestSender) -> Option<SubscriptionEventEnvelope> {
        let read = pane_read(
            format!("{}:read", self.request_prefix),
            &self.pane_id,
            output_match_read_source(&self.source),
            self.lines,
            self.strip_ansi,
            api_tx,
        )
        .ok()?;

        let matched_line = match_output(&read.text, &self.matcher, self.regex.as_ref());
        match matched_line {
            Some(matched_line) => {
                if self.currently_matching {
                    return None;
                }
                self.currently_matching = true;
                Some(SubscriptionEventEnvelope {
                    event: SubscriptionEventKind::PaneOutputMatched,
                    data: SubscriptionEventData::PaneOutputMatched(PaneOutputMatchedEvent {
                        pane_id: read.pane_id.clone(),
                        matched_line,
                        read,
                    }),
                })
            }
            None => {
                self.currently_matching = false;
                None
            }
        }
    }
}

impl ActiveAgentStatusChangedSubscription {
    fn poll(
        &mut self,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
        batch: &EventBatch,
    ) -> Result<Vec<SubscriptionLine>, ErrorResponse> {
        let mut lines = Vec::new();
        let mut saw_status_event = false;
        for (sequence, event) in events_after(batch, self.last_sequence) {
            let Some(event) = status_event_from_hub(event) else {
                continue;
            };
            if event.pane_id != self.pane_id {
                continue;
            }
            saw_status_event = true;

            let snapshot = PaneStatusSnapshot::from_event(&event);
            self.last_status = Some(snapshot.status);
            self.last_presentation = Some(snapshot.presentation);
            self.last_input = Some(snapshot.input);
            if self
                .status_filter
                .is_some_and(|wanted| wanted != event.agent_status)
            {
                continue;
            }
            lines.push(SubscriptionLine::hub(
                *sequence,
                SubscriptionStreamPayload::Subscription(Box::new(status_envelope(event))),
            ));
        }
        self.last_sequence = self.last_sequence.max(batch.head);

        if saw_status_event {
            self.initial_event = None;
            if !lines.is_empty() {
                return Ok(lines);
            }
        } else if event_hub.current_sequence() != self.last_sequence {
            return Ok(lines);
        } else if let Some(event) = self.initial_event.take() {
            return Ok(vec![SubscriptionLine::derived(
                self.last_sequence,
                status_envelope(event),
            )]);
        }

        if self.remote {
            return Ok(lines);
        }
        let before_snapshot_sequence = self.last_sequence;
        let pane = pane_get(
            format!("{}:pane", self.request_prefix),
            &self.pane_id,
            api_tx,
        );
        if event_hub.current_sequence() != before_snapshot_sequence {
            return Ok(lines);
        }
        let pane = pane?;

        Ok(self
            .event_from_snapshot(pane)
            .map(|envelope| SubscriptionLine::derived(before_snapshot_sequence, envelope))
            .into_iter()
            .collect())
    }

    fn event_from_snapshot(&mut self, pane: PaneInfo) -> Option<SubscriptionEventEnvelope> {
        let current = PaneStatusSnapshot::from_pane(&pane);
        let previous_status = self.last_status.replace(current.status);
        let previous_presentation = self.last_presentation.replace(current.presentation.clone());
        let previous_input = self.last_input.replace(current.input);
        let presentation_changed = previous_presentation
            .as_ref()
            .is_some_and(|previous| previous != &current.presentation);
        let status_changed = previous_status.is_some_and(|previous| previous != current.status);
        let input_changed = previous_input.is_some_and(|previous| previous != current.input);
        if !(status_changed || presentation_changed || input_changed) {
            return None;
        }
        if self
            .status_filter
            .is_some_and(|wanted| wanted != current.status)
        {
            return None;
        }

        Some(status_envelope(status_event_from_pane(pane)))
    }
}

impl ActiveAllPanesAgentStatusSubscription {
    fn poll(
        &mut self,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
        batch: &EventBatch,
    ) -> Vec<SubscriptionLine> {
        let mut lines = Vec::new();
        for (sequence, event) in events_after(batch, self.last_sequence) {
            let Some(event) = status_event_from_hub(event) else {
                continue;
            };
            self.panes.insert(
                event.pane_id.clone(),
                PaneStatusSnapshot::from_event(&event),
            );
            if self.matches(event.agent_status) {
                lines.push(SubscriptionLine::hub(
                    *sequence,
                    SubscriptionStreamPayload::Subscription(Box::new(status_envelope(event))),
                ));
            }
        }
        self.last_sequence = self.last_sequence.max(batch.head);

        // Like the single-pane subscription, only trust a snapshot taken while
        // the hub is quiet, so it cannot overtake an event not yet read.
        if Instant::now() < self.next_snapshot || event_hub.current_sequence() != self.last_sequence
        {
            return lines;
        }
        let before_snapshot_sequence = self.last_sequence;
        // Advance the timer before listing: a snapshot invalidated by an event that
        // lands during the call must still wait a full interval, or a busy hub would
        // turn the once-per-interval diff into a pane.list on every 100 ms tick.
        self.next_snapshot = Instant::now() + self.snapshot_interval;
        let panes = pane_list(format!("{}:panes", self.request_prefix), api_tx);
        if event_hub.current_sequence() != before_snapshot_sequence {
            return lines;
        }
        let Ok(panes) = panes else {
            return lines;
        };

        let mut present = HashSet::with_capacity(panes.len());
        for pane in panes {
            present.insert(pane.pane_id.clone());
            let current = PaneStatusSnapshot::from_pane(&pane);
            let previous = self.panes.insert(pane.pane_id.clone(), current.clone());
            // A pane first seen here is seeded silently: its state is not a
            // change, and one created after the subscription started reports
            // its transitions through hub events.
            if previous.is_none_or(|previous| previous == current) || !self.matches(current.status)
            {
                continue;
            }
            lines.push(SubscriptionLine::derived(
                before_snapshot_sequence,
                status_envelope(status_event_from_pane(pane)),
            ));
        }
        self.panes.retain(|pane_id, _| present.contains(pane_id));
        lines
    }

    fn matches(&self, status: AgentStatus) -> bool {
        self.status_filter.is_none_or(|wanted| wanted == status)
    }
}

impl ActiveTurnCompletedSubscription {
    fn poll(&mut self, batch: &EventBatch) -> Vec<SubscriptionLine> {
        let mut lines = Vec::new();
        for (sequence, event) in events_after(batch, self.last_sequence) {
            if event.event != EventKind::PaneTurnCompleted {
                continue;
            }
            let EventData::PaneTurnCompleted {
                pane,
                turn,
                turn_epoch,
                outcome,
                message,
                message_truncated,
                agent_session_path,
                completed_unix_ms,
                turn_origin,
            } = &event.data
            else {
                continue;
            };
            if self
                .pane_id
                .as_ref()
                .is_some_and(|pane_id| *pane_id != pane.pane_id)
            {
                continue;
            }
            lines.push(SubscriptionLine::hub(
                *sequence,
                SubscriptionStreamPayload::Subscription(Box::new(SubscriptionEventEnvelope {
                    event: SubscriptionEventKind::PaneTurnCompleted,
                    data: SubscriptionEventData::PaneTurnCompleted(Box::new(
                        PaneTurnCompletedEvent {
                            turn_origin: *turn_origin,
                            pane: pane.clone(),
                            turn: *turn,
                            turn_epoch: *turn_epoch,
                            outcome: *outcome,
                            message: message.clone(),
                            message_truncated: *message_truncated,
                            agent_session_path: agent_session_path.clone(),
                            completed_unix_ms: *completed_unix_ms,
                        },
                    )),
                })),
            ));
        }
        self.last_sequence = self.last_sequence.max(batch.head);
        lines
    }
}

impl ActiveScrollChangedSubscription {
    fn poll(&mut self, api_tx: &ApiRequestSender) -> Option<SubscriptionEventEnvelope> {
        let pane = pane_get(
            format!("{}:pane", self.request_prefix),
            &self.pane_id,
            api_tx,
        )
        .ok()?;
        self.event_from_snapshot(pane)
    }

    fn event_from_snapshot(
        &mut self,
        pane: crate::api::schema::PaneInfo,
    ) -> Option<SubscriptionEventEnvelope> {
        let scroll = pane.scroll;
        if self.last_scroll == scroll {
            return None;
        }
        self.last_scroll = scroll;
        let scroll = scroll?;

        Some(SubscriptionEventEnvelope {
            event: SubscriptionEventKind::ScrollChanged,
            data: SubscriptionEventData::ScrollChanged(PaneScrollChangedEvent {
                pane_id: pane.pane_id,
                workspace_id: pane.workspace_id,
                scroll,
            }),
        })
    }
}

fn pane_read(
    request_id: String,
    pane_id: &str,
    source: crate::api::schema::ReadSource,
    lines: Option<u32>,
    strip_ansi: bool,
    api_tx: &ApiRequestSender,
) -> Result<crate::api::schema::PaneReadResult, ErrorResponse> {
    let response = dispatch_to_app_with_timeout(
        Request {
            id: request_id.clone(),
            method: Method::PaneRead(crate::api::schema::PaneReadParams {
                pane_id: pane_id.to_string(),
                source,
                lines,
                format: crate::api::schema::ReadFormat::Text,
                strip_ansi,
                intent: crate::api::schema::ReadIntent::Passive,
            }),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
    let value: serde_json::Value = serde_json::from_str(&response).map_err(|_| ErrorResponse {
        id: request_id.clone(),
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode pane read response".into(),
        },
    })?;
    if value.get("error").is_some() {
        return serde_json::from_value(value).map_err(|_| ErrorResponse {
            id: request_id,
            error: ErrorBody {
                code: "internal_error".into(),
                message: "failed to decode pane read error".into(),
            },
        });
    }
    serde_json::from_value(value["result"]["read"].clone()).map_err(|_| ErrorResponse {
        id: request_id,
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode pane read result".into(),
        },
    })
}

fn pane_get(
    request_id: String,
    pane_id: &str,
    api_tx: &ApiRequestSender,
) -> Result<crate::api::schema::PaneInfo, ErrorResponse> {
    let response = dispatch_to_app_with_timeout(
        Request {
            id: request_id.clone(),
            method: Method::PaneGet(crate::api::schema::PaneTarget {
                pane_id: pane_id.to_string(),
            }),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
    let value: serde_json::Value = serde_json::from_str(&response).map_err(|_| ErrorResponse {
        id: request_id.clone(),
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode pane get response".into(),
        },
    })?;
    if value.get("error").is_some() {
        let response =
            serde_json::from_value::<ErrorResponse>(value).map_err(|_| ErrorResponse {
                id: request_id,
                error: ErrorBody {
                    code: "internal_error".into(),
                    message: "failed to decode pane get error".into(),
                },
            })?;
        return Err(response);
    }
    serde_json::from_value(value["result"]["pane"].clone()).map_err(|_| ErrorResponse {
        id: request_id,
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode pane get result".into(),
        },
    })
}

/// A subscribed pane's current status and whether it belongs to a federation
/// peer.
struct PaneProbe {
    event: PaneAgentStatusChangedEvent,
    remote: bool,
}

/// Probe the pane a subscription names. An alias-qualified id
/// (`<alias>/w1:p9`) that names a cached peer agent is seeded from the
/// coordinator's federation directory, since the peer's events reach the local
/// hub through the relay; any other id, including an unknown alias or pane,
/// is a local `pane.get` and fails with `pane_not_found` as before.
fn probe_pane(
    request_id: String,
    pane_id: &str,
    api_tx: &ApiRequestSender,
) -> Result<PaneProbe, ErrorResponse> {
    if pane_id.contains('/') {
        if let Some(agent) = remote_agent(&request_id, pane_id, api_tx)? {
            return Ok(PaneProbe {
                event: crate::api::federation_store::agent_status_event(&agent),
                remote: true,
            });
        }
    }
    let pane = pane_get(request_id, pane_id, api_tx)?;
    Ok(PaneProbe {
        event: status_event_from_pane(pane),
        remote: false,
    })
}

/// The federation directory's agent for an alias-qualified pane id, read from
/// `agent.list` (the coordinator merges its peers' cached agents there).
fn remote_agent(
    request_id: &str,
    pane_id: &str,
    api_tx: &ApiRequestSender,
) -> Result<Option<crate::api::schema::AgentInfo>, ErrorResponse> {
    let internal_error = |message: &str| ErrorResponse {
        id: request_id.to_string(),
        error: ErrorBody {
            code: "internal_error".into(),
            message: message.into(),
        },
    };
    let response = dispatch_to_app_with_timeout(
        Request {
            id: format!("{request_id}:agents"),
            method: Method::AgentList(crate::api::schema::AgentListParams { local_only: false }),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
    let response = serde_json::from_str::<crate::api::schema::SuccessResponse>(&response)
        .map_err(|_| internal_error("failed to decode agent list response"))?;
    let crate::api::schema::ResponseResult::AgentList { agents, .. } = response.result else {
        return Err(internal_error("unexpected agent list result"));
    };
    Ok(agents
        .into_iter()
        .find(|agent| agent.machine_id.is_some() && agent.pane_id == pane_id))
}

fn pane_list(
    request_id: String,
    api_tx: &ApiRequestSender,
) -> Result<Vec<PaneInfo>, ErrorResponse> {
    let response = dispatch_to_app_with_timeout(
        Request {
            id: request_id.clone(),
            method: Method::PaneList(crate::api::schema::PaneListParams { workspace_id: None }),
        },
        api_tx,
        Some(APP_RESPONSE_TIMEOUT),
    );
    let value: serde_json::Value = serde_json::from_str(&response).map_err(|_| ErrorResponse {
        id: request_id.clone(),
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode pane list response".into(),
        },
    })?;
    if value.get("error").is_some() {
        let response =
            serde_json::from_value::<ErrorResponse>(value).map_err(|_| ErrorResponse {
                id: request_id,
                error: ErrorBody {
                    code: "internal_error".into(),
                    message: "failed to decode pane list error".into(),
                },
            })?;
        return Err(response);
    }
    serde_json::from_value(value["result"]["panes"].clone()).map_err(|_| ErrorResponse {
        id: request_id,
        error: ErrorBody {
            code: "internal_error".into(),
            message: "failed to decode pane list result".into(),
        },
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn tick_json(
        subscription: &mut ActiveSubscription,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
    ) -> Vec<serde_json::Value> {
        subscription
            .poll(api_tx, event_hub, &event_hub.read_after(0))
            .into_iter()
            .map(|line| serde_json::to_value(line.payload).unwrap())
            .collect()
    }

    fn envelopes(lines: Vec<SubscriptionLine>) -> Vec<SubscriptionEventEnvelope> {
        lines
            .into_iter()
            .map(|line| match line.payload {
                SubscriptionStreamPayload::Subscription(envelope) => *envelope,
                SubscriptionStreamPayload::Event(event) => panic!("unexpected hub event {event:?}"),
            })
            .collect()
    }

    fn status_tick(
        subscription: &mut ActiveAgentStatusChangedSubscription,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
    ) -> Vec<SubscriptionEventEnvelope> {
        envelopes(
            subscription
                .poll(api_tx, event_hub, &event_hub.read_after(0))
                .unwrap_or_default(),
        )
    }

    fn presentation_event(title: Option<&str>) -> EventEnvelope {
        EventEnvelope {
            event: EventKind::PaneAgentStatusChanged,
            data: EventData::PaneAgentStatusChanged {
                pane_id: "pane_1".into(),
                workspace_id: "workspace_1".into(),
                agent_status: AgentStatus::Working,
                input_pending: false,
                input_prompt_kind: None,
                agent: Some("pi".into()),
                title: title.map(str::to_string),
                display_agent: None,
                state_labels: HashMap::new(),
                turn: None,
                turn_epoch: None,
            },
        }
    }

    fn workspace_focused_event(workspace_id: &str) -> EventEnvelope {
        EventEnvelope {
            event: EventKind::WorkspaceFocused,
            data: EventData::WorkspaceFocused {
                workspace_id: workspace_id.into(),
            },
        }
    }

    fn input_event(
        input_pending: bool,
        input_prompt_kind: Option<crate::detect::InputPromptKind>,
    ) -> EventEnvelope {
        EventEnvelope {
            event: EventKind::PaneAgentStatusChanged,
            data: EventData::PaneAgentStatusChanged {
                pane_id: "pane_1".into(),
                workspace_id: "workspace_1".into(),
                agent_status: AgentStatus::Working,
                input_pending,
                input_prompt_kind,
                agent: Some("pi".into()),
                title: None,
                display_agent: None,
                state_labels: HashMap::new(),
                turn: None,
                turn_epoch: None,
            },
        }
    }

    fn pane_info_with_scroll(scroll: Option<PaneScrollInfo>) -> PaneInfo {
        PaneInfo {
            pane_id: "pane_1".into(),
            terminal_id: "terminal_1".into(),
            workspace_id: "workspace_1".into(),
            tab_id: "tab_1".into(),
            focused: true,
            cwd: None,
            foreground_cwd: None,
            restore_error: None,
            label: None,
            agent: None,
            title: None,
            terminal_title: None,
            terminal_title_stripped: None,
            display_agent: None,
            agent_status: AgentStatus::Unknown,
            input_pending: false,
            input_prompt_kind: None,
            composer: Default::default(),
            state_labels: HashMap::new(),
            tokens: HashMap::new(),
            agent_session: None,
            last_completed_turn: None,
            turn: None,
            turn_epoch: None,
            scroll,
            alternate_screen: false,
            revision: 0,
        }
    }

    fn pane_status(pane_id: &str, agent_status: AgentStatus) -> PaneInfo {
        PaneInfo {
            pane_id: pane_id.into(),
            agent_status,
            ..pane_info_with_scroll(None)
        }
    }

    #[test]
    fn lifecycle_subscription_skips_history_but_keeps_setup_window_events() {
        let event_hub = EventHub::default();
        event_hub.push(workspace_focused_event("before_subscription"));
        let event_start_sequence = event_hub.current_sequence();
        event_hub.push(workspace_focused_event("during_setup"));

        let (api_tx, _api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut subscription = ActiveSubscription::new(
            Subscription::WorkspaceFocused {},
            "test",
            0,
            &api_tx,
            &event_hub,
            event_start_sequence,
        )
        .expect("workspace focus subscription");

        let setup_events = tick_json(&mut subscription, &api_tx, &event_hub);
        assert_eq!(setup_events.len(), 1);
        assert_eq!(setup_events[0]["data"]["workspace_id"], "during_setup");
        assert!(tick_json(&mut subscription, &api_tx, &event_hub).is_empty());

        event_hub.push(workspace_focused_event("after_setup"));
        let live_events = tick_json(&mut subscription, &api_tx, &event_hub);
        assert_eq!(live_events.len(), 1);
        assert_eq!(live_events[0]["data"]["workspace_id"], "after_setup");
    }

    #[test]
    fn workspace_metadata_subscription_uses_dedicated_event_kind() {
        let event_hub = EventHub::default();
        let (api_tx, _api_rx) = tokio::sync::mpsc::unbounded_channel();
        let subscription = ActiveSubscription::new(
            Subscription::WorkspaceMetadataUpdated {},
            "test",
            0,
            &api_tx,
            &event_hub,
            event_hub.current_sequence(),
        )
        .expect("workspace metadata subscription");

        assert!(matches!(
            subscription,
            ActiveSubscription::Event(ActiveEventSubscription {
                event_kind: EventKind::WorkspaceMetadataUpdated,
                ..
            })
        ));
    }

    #[test]
    fn lifecycle_batch_drains_in_order_and_advances_past_unmatched_events() {
        let event_hub = EventHub::default();
        event_hub.push(workspace_focused_event("old"));
        let start = event_hub.current_sequence();
        event_hub.push(workspace_focused_event("setup"));
        let (api_tx, _api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut subscription = ActiveSubscription::new(
            Subscription::WorkspaceFocused {},
            "batch",
            0,
            &api_tx,
            &event_hub,
            start,
        )
        .unwrap();
        event_hub.push(presentation_event(None));
        event_hub.push(workspace_focused_event("live"));
        let events = tick_json(&mut subscription, &api_tx, &event_hub);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["data"]["workspace_id"], "setup");
        assert_eq!(events[1]["data"]["workspace_id"], "live");
        assert!(tick_json(&mut subscription, &api_tx, &event_hub).is_empty());
        let ActiveSubscription::Event(subscription) = subscription else {
            panic!("expected lifecycle subscription");
        };
        assert_eq!(subscription.last_sequence, event_hub.current_sequence());
    }

    #[test]
    fn agent_status_batch_preserves_transitions_filters_and_initial_state_ordering() {
        for filtered in [false, true] {
            let event_hub = EventHub::default();
            let mut subscription = ActiveSubscription::AgentStatusChanged(Box::new(
                ActiveAgentStatusChangedSubscription {
                    pane_id: "pane_1".into(),
                    status_filter: filtered.then_some(AgentStatus::Working),
                    last_status: Some(AgentStatus::Working),
                    last_presentation: None,
                    last_input: None,
                    last_sequence: event_hub.current_sequence(),
                    initial_event: Some(PaneAgentStatusChangedEvent {
                        pane_id: "pane_1".into(),
                        workspace_id: "workspace_1".into(),
                        agent_status: AgentStatus::Working,
                        input_pending: false,
                        input_prompt_kind: None,
                        agent: Some("pi".into()),
                        title: Some("stale initial snapshot".into()),
                        display_agent: None,
                        state_labels: HashMap::new(),
                        turn: None,
                        turn_epoch: None,
                    }),
                    request_prefix: "batch".into(),
                    remote: false,
                },
            ));
            for (status, title) in [
                (AgentStatus::Working, "started"),
                (AgentStatus::Blocked, "approval"),
                (AgentStatus::Idle, "finished"),
                (AgentStatus::Working, "restarted"),
            ] {
                let mut event = presentation_event(Some(title));
                let EventData::PaneAgentStatusChanged { agent_status, .. } = &mut event.data else {
                    panic!("expected status data");
                };
                *agent_status = status;
                event_hub.push(event);
            }
            let (api_tx, _api_rx) = tokio::sync::mpsc::unbounded_channel();
            let events = tick_json(&mut subscription, &api_tx, &event_hub);
            let titles = events
                .iter()
                .map(|event| event["data"]["title"].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                titles,
                if filtered {
                    vec!["started", "restarted"]
                } else {
                    vec!["started", "approval", "finished", "restarted"]
                }
            );
            let ActiveSubscription::AgentStatusChanged(subscription) = subscription else {
                panic!("expected agent subscription");
            };
            assert_eq!(subscription.last_sequence, event_hub.current_sequence());
            assert!(subscription.initial_event.is_none());
        }
    }

    #[test]
    fn scroll_subscription_emits_when_scroll_snapshot_changes() {
        let at_bottom = PaneScrollInfo {
            offset_from_bottom: 0,
            max_offset_from_bottom: 40,
            viewport_rows: 20,
        };
        let scrolled_back = PaneScrollInfo {
            offset_from_bottom: 8,
            max_offset_from_bottom: 40,
            viewport_rows: 20,
        };
        let mut subscription = ActiveScrollChangedSubscription {
            pane_id: "pane_1".into(),
            last_scroll: Some(at_bottom),
            request_prefix: "test".into(),
        };

        assert!(subscription
            .event_from_snapshot(pane_info_with_scroll(Some(at_bottom)))
            .is_none());

        let event = subscription
            .event_from_snapshot(pane_info_with_scroll(Some(scrolled_back)))
            .expect("scroll event");
        assert_eq!(event.event, SubscriptionEventKind::ScrollChanged);
        let SubscriptionEventData::ScrollChanged(data) = event.data else {
            panic!("wrong event data");
        };
        assert_eq!(data.pane_id, "pane_1");
        assert_eq!(data.workspace_id, "workspace_1");
        assert_eq!(data.scroll, scrolled_back);
    }

    #[test]
    fn turn_completed_subscription_filters_and_round_trips_internal_event() {
        let event_hub = EventHub::default();
        let mut subscription = ActiveTurnCompletedSubscription {
            pane_id: Some("pane_1".into()),
            last_sequence: event_hub.current_sequence(),
        };
        event_hub.push(EventEnvelope {
            event: EventKind::PaneTurnCompleted,
            data: EventData::PaneTurnCompleted {
                turn_origin: None,
                pane: pane_info_with_scroll(None),
                turn: 3,
                turn_epoch: 9,
                outcome: crate::terminal::TurnOutcome::Completed,
                message: Some("done".into()),
                message_truncated: true,
                agent_session_path: Some("/tmp/session.jsonl".into()),
                completed_unix_ms: 123,
            },
        });

        let [event] = envelopes(subscription.poll(&event_hub.read_after(0)))
            .try_into()
            .expect("one turn completion event");
        assert_eq!(event.event, SubscriptionEventKind::PaneTurnCompleted);
        let SubscriptionEventData::PaneTurnCompleted(data) = event.data else {
            panic!("wrong event data");
        };
        assert_eq!(data.pane.pane_id, "pane_1");
        assert_eq!(data.turn, 3);
        assert_eq!(data.outcome, crate::terminal::TurnOutcome::Completed);
        assert!(data.message_truncated);
        assert_eq!(
            data.agent_session_path.as_deref(),
            Some("/tmp/session.jsonl")
        );
    }

    #[test]
    fn agent_status_subscription_replays_queued_metadata_set_and_expiry_events() {
        let event_hub = EventHub::default();
        let mut subscription = ActiveAgentStatusChangedSubscription {
            pane_id: "pane_1".into(),
            status_filter: None,
            last_status: Some(AgentStatus::Working),
            last_presentation: Some(PanePresentationSnapshot {
                title: None,
                display_agent: None,
                state_labels: HashMap::new(),
            }),
            last_input: Some((false, None)),
            last_sequence: event_hub.current_sequence(),
            initial_event: None,
            request_prefix: "test".into(),
            remote: false,
        };

        event_hub.push(presentation_event(Some("short lived")));
        event_hub.push(presentation_event(None));

        let api_tx = tokio::sync::mpsc::unbounded_channel().0;
        let [set_event, expiry_event] = status_tick(&mut subscription, &api_tx, &event_hub)
            .try_into()
            .expect("set and expiry events in one tick");
        let SubscriptionEventData::PaneAgentStatusChanged(set_data) = set_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(set_data.title.as_deref(), Some("short lived"));
        let SubscriptionEventData::PaneAgentStatusChanged(expiry_data) = expiry_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(expiry_data.title, None);
        assert!(status_tick(&mut subscription, &api_tx, &event_hub).is_empty());
    }

    #[test]
    fn agent_status_subscription_prefers_setup_window_events_over_initial_snapshot() {
        let event_hub = EventHub::default();
        let mut subscription = ActiveAgentStatusChangedSubscription {
            pane_id: "pane_1".into(),
            status_filter: Some(AgentStatus::Working),
            last_status: Some(AgentStatus::Working),
            last_presentation: Some(PanePresentationSnapshot {
                title: None,
                display_agent: None,
                state_labels: HashMap::new(),
            }),
            last_input: Some((false, None)),
            last_sequence: event_hub.current_sequence(),
            initial_event: Some(PaneAgentStatusChangedEvent {
                pane_id: "pane_1".into(),
                workspace_id: "workspace_1".into(),
                agent_status: AgentStatus::Working,
                input_pending: false,
                input_prompt_kind: None,
                agent: Some("pi".into()),
                title: None,
                display_agent: None,
                state_labels: HashMap::new(),
                turn: None,
                turn_epoch: None,
            }),
            request_prefix: "test".into(),
            remote: false,
        };

        event_hub.push(presentation_event(Some("short lived")));
        event_hub.push(presentation_event(None));

        let api_tx = tokio::sync::mpsc::unbounded_channel().0;
        let [set_event, expiry_event] = status_tick(&mut subscription, &api_tx, &event_hub)
            .try_into()
            .expect("set and expiry events in one tick");
        let SubscriptionEventData::PaneAgentStatusChanged(set_data) = set_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(set_data.title.as_deref(), Some("short lived"));
        let SubscriptionEventData::PaneAgentStatusChanged(expiry_data) = expiry_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(expiry_data.title, None);
        assert!(status_tick(&mut subscription, &api_tx, &event_hub).is_empty());
    }

    #[test]
    fn agent_status_subscription_initial_and_transition_events_carry_input_tuple() {
        let event_hub = EventHub::default();
        let mut subscription = ActiveAgentStatusChangedSubscription {
            pane_id: "pane_1".into(),
            status_filter: Some(AgentStatus::Working),
            last_status: Some(AgentStatus::Working),
            last_presentation: Some(PanePresentationSnapshot {
                title: None,
                display_agent: None,
                state_labels: HashMap::new(),
            }),
            last_input: Some((true, Some(crate::detect::InputPromptKind::Select))),
            last_sequence: event_hub.current_sequence(),
            initial_event: Some(PaneAgentStatusChangedEvent {
                pane_id: "pane_1".into(),
                workspace_id: "workspace_1".into(),
                agent_status: AgentStatus::Working,
                input_pending: true,
                input_prompt_kind: Some(crate::detect::InputPromptKind::Select),
                agent: Some("pi".into()),
                title: None,
                display_agent: None,
                state_labels: HashMap::new(),
                turn: None,
                turn_epoch: None,
            }),
            request_prefix: "test".into(),
            remote: false,
        };
        let api_tx = tokio::sync::mpsc::unbounded_channel().0;

        let [initial] = status_tick(&mut subscription, &api_tx, &event_hub)
            .try_into()
            .expect("initial snapshot");
        let SubscriptionEventData::PaneAgentStatusChanged(initial) = initial.data else {
            panic!("wrong initial event data");
        };
        assert!(initial.input_pending);
        assert_eq!(
            initial.input_prompt_kind,
            Some(crate::detect::InputPromptKind::Select)
        );

        event_hub.push(input_event(false, None));
        let [transition] = status_tick(&mut subscription, &api_tx, &event_hub)
            .try_into()
            .expect("input-only transition");
        let SubscriptionEventData::PaneAgentStatusChanged(transition) = transition.data else {
            panic!("wrong transition event data");
        };
        assert_eq!(transition.agent_status, AgentStatus::Working);
        assert!(!transition.input_pending);
        assert_eq!(transition.input_prompt_kind, None);
    }

    #[test]
    fn agent_status_subscription_emits_setup_window_event_already_reflected_by_probe() {
        let event_hub = EventHub::default();
        let mut subscription = ActiveAgentStatusChangedSubscription {
            pane_id: "pane_1".into(),
            status_filter: Some(AgentStatus::Working),
            last_status: Some(AgentStatus::Working),
            last_presentation: Some(PanePresentationSnapshot {
                title: Some("short lived".into()),
                display_agent: None,
                state_labels: HashMap::new(),
            }),
            last_input: Some((false, None)),
            last_sequence: event_hub.current_sequence(),
            initial_event: Some(PaneAgentStatusChangedEvent {
                pane_id: "pane_1".into(),
                workspace_id: "workspace_1".into(),
                agent_status: AgentStatus::Working,
                input_pending: false,
                input_prompt_kind: None,
                agent: Some("pi".into()),
                title: Some("short lived".into()),
                display_agent: None,
                state_labels: HashMap::new(),
                turn: None,
                turn_epoch: None,
            }),
            request_prefix: "test".into(),
            remote: false,
        };

        event_hub.push(presentation_event(Some("short lived")));

        let [event] = status_tick(
            &mut subscription,
            &tokio::sync::mpsc::unbounded_channel().0,
            &event_hub,
        )
        .try_into()
        .expect("setup-window event");
        let SubscriptionEventData::PaneAgentStatusChanged(data) = event.data else {
            panic!("wrong event data");
        };
        assert_eq!(data.title.as_deref(), Some("short lived"));
        assert!(subscription.initial_event.is_none());
    }

    /// A hub event that lands while the all-panes diff is listing panes invalidates that
    /// snapshot. The next snapshot must still wait a full interval: otherwise a busy hub
    /// makes every 100 ms tick call pane.list.
    #[test]
    fn an_invalidated_all_panes_snapshot_still_waits_a_full_interval() {
        let event_hub = EventHub::default();
        let lists = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (api_tx, mut api_rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::api::ApiRequestMessage>();
        let responder_hub = event_hub.clone();
        let responder_lists = std::sync::Arc::clone(&lists);
        std::thread::spawn(move || {
            while let Some(msg) = api_rx.blocking_recv() {
                let Method::PaneList(_) = msg.request.method else {
                    panic!("unexpected request {:?}", msg.request.method);
                };
                responder_lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // An unrelated event lands while the list is being taken.
                responder_hub.push(workspace_focused_event("workspace_1"));
                let _ = msg.respond_to.send(
                    serde_json::to_string(&crate::api::schema::SuccessResponse {
                        id: msg.request.id,
                        result: crate::api::schema::ResponseResult::PaneList {
                            panes: vec![pane_status("pane_1", AgentStatus::Working)],
                        },
                    })
                    .unwrap(),
                );
            }
        });
        let ActiveSubscription::AllPanesAgentStatusChanged(mut subscription) =
            ActiveSubscription::new(
                Subscription::PaneAgentStatusChanged {
                    pane_id: None,
                    agent_status: None,
                },
                "test",
                0,
                &api_tx,
                &event_hub,
                event_hub.current_sequence(),
            )
            .expect("all-panes subscription")
        else {
            panic!("expected an all-panes subscription");
        };
        let baseline = lists.load(std::sync::atomic::Ordering::SeqCst);
        subscription.snapshot_interval = Duration::from_secs(3600);
        subscription.next_snapshot = Instant::now();
        for _ in 0..3 {
            let batch = event_hub.read_after(subscription.last_sequence);
            subscription.poll(&api_tx, &event_hub, &batch);
        }
        assert_eq!(
            lists.load(std::sync::atomic::Ordering::SeqCst) - baseline,
            1,
            "an invalidated snapshot must not be retried before the interval"
        );
    }

    #[test]
    fn all_panes_snapshot_seeds_new_panes_silently_and_reports_later_changes_once() {
        let panes = std::sync::Arc::new(std::sync::Mutex::new(vec![pane_status(
            "pane_1",
            AgentStatus::Working,
        )]));
        let (api_tx, mut api_rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::api::ApiRequestMessage>();
        let responder_panes = std::sync::Arc::clone(&panes);
        std::thread::spawn(move || {
            while let Some(msg) = api_rx.blocking_recv() {
                let Method::PaneList(_) = msg.request.method else {
                    panic!("unexpected request {:?}", msg.request.method);
                };
                let panes = responder_panes.lock().unwrap().clone();
                let _ = msg.respond_to.send(
                    serde_json::to_string(&crate::api::schema::SuccessResponse {
                        id: msg.request.id,
                        result: crate::api::schema::ResponseResult::PaneList { panes },
                    })
                    .unwrap(),
                );
            }
        });
        let event_hub = EventHub::default();
        let ActiveSubscription::AllPanesAgentStatusChanged(mut subscription) =
            ActiveSubscription::new(
                Subscription::PaneAgentStatusChanged {
                    pane_id: None,
                    agent_status: None,
                },
                "test",
                0,
                &api_tx,
                &event_hub,
                event_hub.current_sequence(),
            )
            .expect("all-panes subscription")
        else {
            panic!("expected an all-panes subscription");
        };
        subscription.snapshot_interval = Duration::ZERO;
        subscription.next_snapshot = Instant::now();
        let mut tick = || {
            envelopes(subscription.poll(&api_tx, &event_hub, &event_hub.read_after(0)))
                .into_iter()
                .map(|envelope| match envelope.data {
                    SubscriptionEventData::PaneAgentStatusChanged(data) => {
                        (data.pane_id, data.agent_status)
                    }
                    other => panic!("unexpected {other:?}"),
                })
                .collect::<Vec<_>>()
        };

        panes
            .lock()
            .unwrap()
            .push(pane_status("pane_2", AgentStatus::Done));
        assert!(
            tick().is_empty(),
            "a newly listed pane is seeded, not reported"
        );

        panes.lock().unwrap()[1] = pane_status("pane_2", AgentStatus::Idle);
        assert_eq!(tick(), vec![("pane_2".to_string(), AgentStatus::Idle)]);

        event_hub.push(EventEnvelope {
            event: EventKind::PaneAgentStatusChanged,
            data: EventData::PaneAgentStatusChanged {
                pane_id: "pane_2".into(),
                workspace_id: "workspace_1".into(),
                agent_status: AgentStatus::Working,
                input_pending: false,
                input_prompt_kind: None,
                agent: None,
                title: None,
                display_agent: None,
                state_labels: HashMap::new(),
                turn: None,
                turn_epoch: None,
            },
        });
        panes.lock().unwrap()[1] = pane_status("pane_2", AgentStatus::Working);
        assert_eq!(tick(), vec![("pane_2".to_string(), AgentStatus::Working)]);
        assert!(
            tick().is_empty(),
            "the snapshot must not repeat a hub event"
        );
    }
}
