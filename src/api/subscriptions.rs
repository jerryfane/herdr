use regex::Regex;

use crate::api::schema::{
    ErrorBody, ErrorResponse, Method, PaneAgentStatusChangedEvent, PaneOutputMatchedEvent,
    PaneScrollChangedEvent, PaneScrollInfo, PaneTurnCompletedEvent, Request, Subscription,
    SubscriptionEventData, SubscriptionEventEnvelope, SubscriptionEventKind,
};
use crate::api::server::{dispatch_to_app_with_timeout, APP_RESPONSE_TIMEOUT};
use crate::api::{ApiRequestSender, EventHub};

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
    status_filter: Option<crate::api::schema::AgentStatus>,
    last_status: Option<crate::api::schema::AgentStatus>,
    last_presentation: Option<PanePresentationSnapshot>,
    last_input: Option<(bool, Option<crate::detect::InputPromptKind>)>,
    last_sequence: u64,
    initial_event: Option<PaneAgentStatusChangedEvent>,
    request_prefix: String,
}

pub(super) struct ActiveScrollChangedSubscription {
    pane_id: String,
    last_scroll: Option<PaneScrollInfo>,
    request_prefix: String,
}

pub(super) struct ActiveTurnCompletedSubscription {
    pane_id: String,
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

pub(super) struct ActiveEventSubscription {
    event_kind: crate::api::schema::EventKind,
    last_sequence: u64,
}

pub(super) enum ActiveSubscription {
    Event(ActiveEventSubscription),
    OutputMatched(ActiveOutputMatchedSubscription),
    AgentStatusChanged(Box<ActiveAgentStatusChangedSubscription>),
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
    ) -> Result<Self, ErrorResponse> {
        match subscription {
            Subscription::WorkspaceCreated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorkspaceCreated,
                last_sequence: 0,
            })),
            Subscription::WorkspaceUpdated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorkspaceUpdated,
                last_sequence: 0,
            })),
            Subscription::WorkspaceMetadataUpdated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorkspaceMetadataUpdated,
                last_sequence: 0,
            })),
            Subscription::WorkspaceRenamed {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorkspaceRenamed,
                last_sequence: 0,
            })),
            Subscription::WorkspaceMoved {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorkspaceMoved,
                last_sequence: 0,
            })),
            Subscription::WorkspaceClosed {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorkspaceClosed,
                last_sequence: 0,
            })),
            Subscription::WorkspaceFocused {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorkspaceFocused,
                last_sequence: 0,
            })),
            Subscription::WorktreeCreated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorktreeCreated,
                last_sequence: 0,
            })),
            Subscription::WorktreeOpened {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorktreeOpened,
                last_sequence: 0,
            })),
            Subscription::WorktreeRemoved {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::WorktreeRemoved,
                last_sequence: 0,
            })),
            Subscription::TabCreated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::TabCreated,
                last_sequence: 0,
            })),
            Subscription::TabClosed {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::TabClosed,
                last_sequence: 0,
            })),
            Subscription::TabFocused {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::TabFocused,
                last_sequence: 0,
            })),
            Subscription::TabRenamed {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::TabRenamed,
                last_sequence: 0,
            })),
            Subscription::TabMoved {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::TabMoved,
                last_sequence: 0,
            })),
            Subscription::PaneCreated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::PaneCreated,
                last_sequence: 0,
            })),
            Subscription::PaneClosed {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::PaneClosed,
                last_sequence: 0,
            })),
            Subscription::PaneUpdated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::PaneUpdated,
                last_sequence: 0,
            })),
            Subscription::PaneFocused {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::PaneFocused,
                last_sequence: 0,
            })),
            Subscription::PaneMoved {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::PaneMoved,
                last_sequence: 0,
            })),
            Subscription::PaneExited {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::PaneExited,
                last_sequence: 0,
            })),
            Subscription::PaneAgentDetected {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::PaneAgentDetected,
                last_sequence: 0,
            })),
            Subscription::LayoutUpdated {} => Ok(Self::Event(ActiveEventSubscription {
                event_kind: crate::api::schema::EventKind::LayoutUpdated,
                last_sequence: 0,
            })),
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
                pane_id,
                agent_status,
            } => {
                let last_sequence = event_hub.current_sequence();
                let probe = pane_get(format!("{request_id}:sub:{index}:probe"), &pane_id, api_tx)?;
                let last_status = probe.agent_status;
                let last_presentation = PanePresentationSnapshot::from(&probe);
                let last_input = (probe.input_pending, probe.input_prompt_kind);
                let initial_event = agent_status
                    .is_some_and(|wanted| wanted == probe.agent_status)
                    .then_some(PaneAgentStatusChangedEvent {
                        pane_id: probe.pane_id.clone(),
                        workspace_id: probe.workspace_id,
                        agent_status: probe.agent_status,
                        input_pending: probe.input_pending,
                        input_prompt_kind: probe.input_prompt_kind,
                        agent: probe.agent,
                        title: probe.title,
                        display_agent: probe.display_agent,
                        state_labels: probe.state_labels,
                        turn: probe.turn,
                        turn_epoch: probe.turn_epoch,
                    });

                Ok(Self::AgentStatusChanged(Box::new(
                    ActiveAgentStatusChangedSubscription {
                        pane_id: probe.pane_id,
                        status_filter: agent_status,
                        last_status: Some(last_status),
                        last_presentation: Some(last_presentation),
                        last_input: Some(last_input),
                        last_sequence,
                        initial_event,
                        request_prefix: format!("{request_id}:sub:{index}"),
                    },
                )))
            }
            Subscription::PaneTurnCompleted { pane_id } => {
                let last_sequence = event_hub.current_sequence();
                let probe = pane_get(format!("{request_id}:sub:{index}:probe"), &pane_id, api_tx)?;
                Ok(Self::TurnCompleted(ActiveTurnCompletedSubscription {
                    pane_id: probe.pane_id,
                    last_sequence,
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

    pub(super) fn poll(
        &mut self,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
    ) -> Option<serde_json::Value> {
        match self {
            Self::Event(subscription) => subscription.poll(event_hub),
            Self::OutputMatched(subscription) => {
                serde_json::to_value(subscription.poll(api_tx)?).ok()
            }
            Self::AgentStatusChanged(subscription) => {
                serde_json::to_value(subscription.poll(api_tx, event_hub)?).ok()
            }
            Self::TurnCompleted(subscription) => {
                serde_json::to_value(subscription.poll(event_hub)?).ok()
            }
            Self::ScrollChanged(subscription) => {
                serde_json::to_value(subscription.poll(api_tx)?).ok()
            }
        }
    }

    pub(super) fn poll_for_wait(
        &mut self,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
    ) -> Result<Option<serde_json::Value>, ErrorResponse> {
        match self {
            Self::AgentStatusChanged(subscription) => Ok(subscription
                .poll_result(api_tx, event_hub)?
                .and_then(|event| serde_json::to_value(event).ok())),
            _ => Ok(self.poll(api_tx, event_hub)),
        }
    }
}

impl ActiveEventSubscription {
    fn poll(&mut self, event_hub: &EventHub) -> Option<serde_json::Value> {
        for (sequence, event) in event_hub.events_after(self.last_sequence) {
            self.last_sequence = sequence;
            if event.event == self.event_kind {
                return serde_json::to_value(event).ok();
            }
        }
        None
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
    ) -> Option<SubscriptionEventEnvelope> {
        self.poll_result(api_tx, event_hub).ok().flatten()
    }

    fn poll_result(
        &mut self,
        api_tx: &ApiRequestSender,
        event_hub: &EventHub,
    ) -> Result<Option<SubscriptionEventEnvelope>, ErrorResponse> {
        let mut saw_status_event = false;
        for (sequence, event) in event_hub.events_after(self.last_sequence) {
            self.last_sequence = sequence;
            let crate::api::schema::EventData::PaneAgentStatusChanged {
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
            } = event.data
            else {
                continue;
            };
            if event.event != crate::api::schema::EventKind::PaneAgentStatusChanged {
                continue;
            }
            if pane_id != self.pane_id {
                continue;
            }
            saw_status_event = true;

            let current_presentation =
                PanePresentationSnapshot::from_event(&title, &display_agent, &state_labels);
            self.last_status = Some(agent_status);
            self.last_presentation = Some(current_presentation);
            self.last_input = Some((input_pending, input_prompt_kind));
            if self
                .status_filter
                .is_some_and(|wanted| wanted != agent_status)
            {
                continue;
            }

            self.initial_event = None;
            return Ok(Some(SubscriptionEventEnvelope {
                event: SubscriptionEventKind::PaneAgentStatusChanged,
                data: SubscriptionEventData::PaneAgentStatusChanged(PaneAgentStatusChangedEvent {
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
                }),
            }));
        }

        if saw_status_event {
            self.initial_event = None;
        } else if event_hub.current_sequence() != self.last_sequence {
            return Ok(None);
        } else if let Some(event) = self.initial_event.take() {
            return Ok(Some(SubscriptionEventEnvelope {
                event: SubscriptionEventKind::PaneAgentStatusChanged,
                data: SubscriptionEventData::PaneAgentStatusChanged(event),
            }));
        }

        let before_snapshot_sequence = self.last_sequence;
        let pane = pane_get(
            format!("{}:pane", self.request_prefix),
            &self.pane_id,
            api_tx,
        );
        let after_snapshot_sequence = event_hub.current_sequence();
        if after_snapshot_sequence != before_snapshot_sequence {
            return Ok(None);
        }
        let pane = pane?;

        let event = self.event_from_snapshot(pane);
        if event.is_some() {
            self.last_sequence = after_snapshot_sequence;
        }
        Ok(event)
    }

    fn event_from_snapshot(
        &mut self,
        pane: crate::api::schema::PaneInfo,
    ) -> Option<SubscriptionEventEnvelope> {
        let current_status = pane.agent_status;
        let current_presentation = PanePresentationSnapshot::from(&pane);
        let current_input = (pane.input_pending, pane.input_prompt_kind);
        let previous_status = self.last_status.replace(current_status);
        let previous_presentation = self.last_presentation.replace(current_presentation.clone());
        let previous_input = self.last_input.replace(current_input);
        let presentation_changed = previous_presentation
            .as_ref()
            .is_some_and(|previous| previous != &current_presentation);
        let status_changed = previous_status.is_some_and(|previous| previous != current_status);
        let input_changed = previous_input.is_some_and(|previous| previous != current_input);
        if !(status_changed || presentation_changed || input_changed) {
            return None;
        }
        if self
            .status_filter
            .is_some_and(|wanted| wanted != current_status)
        {
            return None;
        }

        Some(SubscriptionEventEnvelope {
            event: SubscriptionEventKind::PaneAgentStatusChanged,
            data: SubscriptionEventData::PaneAgentStatusChanged(PaneAgentStatusChangedEvent {
                pane_id: pane.pane_id,
                workspace_id: pane.workspace_id,
                agent_status: current_status,
                input_pending: pane.input_pending,
                input_prompt_kind: pane.input_prompt_kind,
                agent: pane.agent,
                title: pane.title,
                display_agent: pane.display_agent,
                state_labels: pane.state_labels,
                turn: pane.turn,
                turn_epoch: pane.turn_epoch,
            }),
        })
    }
}

impl ActiveTurnCompletedSubscription {
    fn poll(&mut self, event_hub: &EventHub) -> Option<SubscriptionEventEnvelope> {
        for (sequence, event) in event_hub.events_after(self.last_sequence) {
            self.last_sequence = sequence;
            let crate::api::schema::EventData::PaneTurnCompleted {
                pane,
                turn,
                turn_epoch,
                outcome,
                message,
                message_truncated,
                agent_session_path,
                completed_unix_ms,
            } = event.data
            else {
                continue;
            };
            if event.event != crate::api::schema::EventKind::PaneTurnCompleted
                || pane.pane_id != self.pane_id
            {
                continue;
            }
            return Some(SubscriptionEventEnvelope {
                event: SubscriptionEventKind::PaneTurnCompleted,
                data: SubscriptionEventData::PaneTurnCompleted(Box::new(PaneTurnCompletedEvent {
                    pane,
                    turn,
                    turn_epoch,
                    outcome,
                    message,
                    message_truncated,
                    agent_session_path,
                    completed_unix_ms,
                })),
            });
        }
        None
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::api::schema::{AgentStatus, EventData, EventEnvelope, EventKind, PaneInfo};

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
            revision: 0,
        }
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
            pane_id: "pane_1".into(),
            last_sequence: event_hub.current_sequence(),
        };
        event_hub.push(EventEnvelope {
            event: EventKind::PaneTurnCompleted,
            data: EventData::PaneTurnCompleted {
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

        let event = subscription
            .poll(&event_hub)
            .expect("turn completion event");
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
        };

        event_hub.push(presentation_event(Some("short lived")));
        event_hub.push(presentation_event(None));

        let set_event = subscription
            .poll(&tokio::sync::mpsc::unbounded_channel().0, &event_hub)
            .expect("set event");
        let SubscriptionEventData::PaneAgentStatusChanged(set_data) = set_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(set_data.title.as_deref(), Some("short lived"));

        let expiry_event = subscription
            .poll(&tokio::sync::mpsc::unbounded_channel().0, &event_hub)
            .expect("expiry event");
        let SubscriptionEventData::PaneAgentStatusChanged(expiry_data) = expiry_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(expiry_data.title, None);
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
        };

        event_hub.push(presentation_event(Some("short lived")));
        event_hub.push(presentation_event(None));

        let set_event = subscription
            .poll(&tokio::sync::mpsc::unbounded_channel().0, &event_hub)
            .expect("set event");
        let SubscriptionEventData::PaneAgentStatusChanged(set_data) = set_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(set_data.title.as_deref(), Some("short lived"));

        let expiry_event = subscription
            .poll(&tokio::sync::mpsc::unbounded_channel().0, &event_hub)
            .expect("expiry event");
        let SubscriptionEventData::PaneAgentStatusChanged(expiry_data) = expiry_event.data else {
            panic!("wrong event data");
        };
        assert_eq!(expiry_data.title, None);
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
        };
        let api_tx = tokio::sync::mpsc::unbounded_channel().0;

        let initial = subscription
            .poll(&api_tx, &event_hub)
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
        let transition = subscription
            .poll(&api_tx, &event_hub)
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
        };

        event_hub.push(presentation_event(Some("short lived")));

        let event = subscription
            .poll(&tokio::sync::mpsc::unbounded_channel().0, &event_hub)
            .expect("setup-window event");
        let SubscriptionEventData::PaneAgentStatusChanged(data) = event.data else {
            panic!("wrong event data");
        };
        assert_eq!(data.title.as_deref(), Some("short lived"));
        assert!(subscription.initial_event.is_none());
    }
}
