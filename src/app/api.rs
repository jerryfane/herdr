use std::time::{Duration, Instant};

mod agent_view;
mod agents;
mod env;
mod gram;
mod integrations;
mod layouts;
mod pane_graphics;
mod panes;
pub(crate) mod plugins;
mod responses;
mod session;
mod tabs;
mod workspaces;
mod worktrees;

use super::{api_helpers::pane_agent_status, App, Mode, OverlayPaneState, ToastKind};
use crate::events::AppEvent;

const API_NOTIFICATION_RATE_LIMIT: Duration = Duration::from_secs(1);
#[cfg(windows)]
const WINDOWS_POWERSHELL_AGENT_EXIT_RESPAWN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeExitAction {
    RespawnShell,
    ClosePane,
}

impl App {
    pub(crate) fn dispatch_api_request(
        &mut self,
        id: &'static str,
        method: crate::api::schema::Method,
    ) -> String {
        self.handle_api_request(crate::api::schema::Request {
            id: id.to_string(),
            method,
        })
    }

    pub(crate) fn dispatch_deferred_api_request(
        &mut self,
        id: &'static str,
        method: crate::api::schema::Method,
    ) -> Option<String> {
        let (respond_to, response_rx) = std::sync::mpsc::channel();
        if !self.handle_deferred_worktree_api_request(
            crate::api::schema::Request {
                id: id.to_string(),
                method,
            },
            respond_to,
        ) {
            return None;
        }

        response_rx.try_recv().ok()
    }

    pub(crate) fn handle_internal_event_with_render_impact(&mut self, ev: AppEvent) -> bool {
        match ev {
            AppEvent::GitStatusRefreshed {
                results,
                cache_updates,
            } => self.handle_git_status_refreshed(results, cache_updates),
            ev => {
                self.handle_internal_event(ev);
                true
            }
        }
    }

    fn handle_git_status_refreshed(
        &mut self,
        results: Vec<crate::workspace::WorkspaceGitStatus>,
        cache_updates: Vec<(std::path::PathBuf, crate::workspace::GitStatusCacheEntry)>,
    ) -> bool {
        self.git_refresh_in_flight = false;
        for (key, entry) in cache_updates {
            self.git_status_cache.insert(key, entry);
        }
        if self.git_refresh_due_after_in_flight {
            self.mark_git_status_refresh_due(Instant::now());
            self.git_refresh_due_after_in_flight = false;
        } else {
            self.last_git_remote_status_refresh = Instant::now();
        }
        let changed = self
            .state
            .apply_workspace_git_statuses(&self.terminal_runtimes, results);
        if changed {
            self.render_dirty.request_generic();
            self.render_notify.notify_one();
        }
        changed
    }

    pub(crate) fn handle_internal_event(&mut self, ev: AppEvent) {
        if let AppEvent::ClipboardWrite { content } = ev {
            #[cfg(not(test))]
            crate::selection::write_osc52_bytes(&content);
            #[cfg(test)]
            let _ = content;
            self.show_clipboard_feedback();
            return;
        }

        if let AppEvent::PrefixInputSource { active } = ev {
            // Monolithic path applies the switch here. Server mode forwards it to the foreground
            // client instead (see HeadlessServer::handle_internal_event_with_forwarding); should an
            // App-internal drain consume the event before the forwarding drain, the flag keeps the
            // switch out of the headless server process.
            if !self.local_input_source_switch {
                return;
            }
            if active {
                self.prefix_input_source.switch_to_ascii();
            } else {
                self.prefix_input_source.restore();
            }
            return;
        }

        if let AppEvent::GitStatusRefreshed {
            results,
            cache_updates,
        } = ev
        {
            self.handle_git_status_refreshed(results, cache_updates);
            return;
        }

        if let AppEvent::PluginCommandFinished {
            log_id,
            finished_unix_ms,
            exit_code,
            stdout,
            stderr,
            error,
        } = ev
        {
            self.state.plugin_commands_in_flight =
                self.state.plugin_commands_in_flight.saturating_sub(1);
            if let Some(log) = self
                .state
                .plugin_command_logs
                .iter_mut()
                .find(|log| log.log_id == log_id)
            {
                log.finished_unix_ms = Some(finished_unix_ms);
                log.exit_code = exit_code;
                log.stdout = Some(stdout);
                log.stderr = Some(stderr);
                log.error = error;
                log.status = if log.error.is_none() && log.exit_code == Some(0) {
                    crate::api::schema::PluginCommandStatus::Succeeded
                } else {
                    crate::api::schema::PluginCommandStatus::Failed
                };
            }
            return;
        }

        if let AppEvent::WorktreeAddFinished(result) = ev {
            self.handle_worktree_add_finished(*result);
            return;
        }

        if let AppEvent::WorktreeRemoveFinished(result) = ev {
            self.handle_worktree_remove_finished(*result);
            return;
        }

        if let AppEvent::PaneDied { pane_id } = &ev {
            if self
                .state
                .popup_pane
                .as_ref()
                .is_some_and(|popup| popup.pane_id == *pane_id)
            {
                self.close_popup_pane();
                return;
            }
            let previous_toast = self.state.toast.clone();
            if let Some(update) = self.state.publish_pane_process_exit_if_agent(*pane_id) {
                self.sync_full_lifecycle_authority_detection_pauses();
                self.refresh_new_herdr_toast_context_for_update(&update, &previous_toast);
                self.emit_pane_state_update(&update);
                self.emit_terminal_or_system_agent_notifications(std::slice::from_ref(&update));
                self.emit_apns_agent_notifications(std::slice::from_ref(&update), true);
                self.emit_live_activity_updates();
            }
            if self.runtime_exit_action(*pane_id) == RuntimeExitAction::RespawnShell
                && self.respawn_shell_for_launch_pane(*pane_id)
            {
                self.overlay_panes.remove(pane_id);
                self.render_dirty.request_generic();
                self.render_notify.notify_one();
                return;
            }
        }

        let overlay_state = if let AppEvent::PaneDied { pane_id } = &ev {
            self.overlay_panes.remove(pane_id).map(|overlay| {
                let was_overlay_active =
                    self.state
                        .is_active_pane(overlay.ws_idx, overlay.tab_idx, *pane_id);
                let tab_before_exit = self
                    .state
                    .workspaces
                    .get(overlay.ws_idx)
                    .and_then(|ws| ws.tabs.get(overlay.tab_idx));
                let was_overlay_focused_in_tab =
                    tab_before_exit.is_some_and(|tab| tab.layout.focused() == *pane_id);
                let tab_zoomed_before_exit = tab_before_exit.map(|tab| tab.zoomed);
                (
                    overlay,
                    was_overlay_active,
                    was_overlay_focused_in_tab,
                    tab_zoomed_before_exit,
                )
            })
        } else {
            None
        };

        if let AppEvent::PaneDied { pane_id } = &ev {
            if let Some((ws_idx, _)) = self.find_pane(*pane_id) {
                if let Some(public_pane_id) = self.public_pane_id(ws_idx, *pane_id) {
                    self.emit_event(crate::api::schema::EventEnvelope {
                        event: crate::api::schema::EventKind::PaneExited,
                        data: crate::api::schema::EventData::PaneExited {
                            pane_id: public_pane_id,
                            workspace_id: self.public_workspace_id(ws_idx),
                        },
                    });
                }
            }
        }
        let pane_exit_layout_target = if let AppEvent::PaneDied { pane_id } = &ev {
            self.find_pane(*pane_id).and_then(|(ws_idx, _)| {
                self.layout_update_target_after_pane_removal(ws_idx, *pane_id)
            })
        } else {
            None
        };

        let released_agent = if let AppEvent::HookAgentReleased {
            pane_id,
            known_agent,
            ..
        } = &ev
        {
            known_agent.map(|agent| (*pane_id, agent))
        } else {
            None
        };

        let update_ready = if let AppEvent::UpdateReady {
            version,
            install_command,
        } = &ev
        {
            Some((version.clone(), install_command.clone()))
        } else {
            None
        };
        let manifest_update_agents =
            if let AppEvent::AgentDetectionManifestsUpdated { updated, .. } = &ev {
                Some(updated.iter().map(|item| item.agent).collect::<Vec<_>>())
            } else {
                None
            };
        let terminal_cwd_reported = matches!(ev, AppEvent::TerminalCwdReported { .. });
        let previous_toast = self.state.toast.clone();
        let pane_updates = self.state.handle_app_event(ev);
        if let Some(agents) = manifest_update_agents {
            self.reset_agent_detection_for_agents(&agents);
        }
        if let Some((pane_id, agent)) = released_agent {
            if pane_updates.iter().any(|update| update.pane_id == pane_id) {
                if let Some((ws_idx, _)) = self.find_pane(pane_id) {
                    if let Some(runtime) = self.state.runtime_for_pane_in_workspace(
                        &self.terminal_runtimes,
                        ws_idx,
                        pane_id,
                    ) {
                        runtime.begin_graceful_release(agent);
                    }
                }
            }
        }
        self.sync_full_lifecycle_authority_detection_pauses();
        if terminal_cwd_reported {
            self.request_git_identity_refresh(Instant::now());
            self.render_dirty.request_generic();
            self.render_notify.notify_one();
        }
        for update in &pane_updates {
            self.refresh_new_herdr_toast_context_for_update(update, &previous_toast);
            self.emit_pane_state_update(update);
        }
        self.emit_apns_agent_notifications(&pane_updates, false);
        self.emit_live_activity_updates();
        self.sync_agent_metadata_deadline();
        if let Some((
            overlay,
            was_overlay_active,
            was_overlay_focused_in_tab,
            tab_zoomed_before_exit,
        )) = overlay_state
        {
            self.restore_overlay_after_exit(
                overlay,
                was_overlay_active,
                was_overlay_focused_in_tab,
                tab_zoomed_before_exit,
            );
        }
        if let Some((ws_idx, tab_idx)) = pane_exit_layout_target {
            self.emit_layout_updated_event(ws_idx, tab_idx);
        }

        if self.local_terminal_notifications
            && matches!(
                self.state.toast_config.delivery,
                crate::config::ToastDelivery::Terminal | crate::config::ToastDelivery::System
            )
        {
            let notify = match self.state.toast_config.delivery {
                crate::config::ToastDelivery::Terminal => crate::terminal_notify::show_notification,
                crate::config::ToastDelivery::System => crate::platform::show_desktop_notification,
                _ => unreachable!("toast delivery was checked above"),
            };

            if let Some((version, install_command)) = update_ready {
                let instruction = crate::update::update_install_instruction(&install_command);
                let _ = notify(&format!("v{version} available"), Some(&instruction));
            } else if self.state.toast_config.delay_seconds == 0 {
                self.emit_terminal_or_system_agent_notifications(&pane_updates);
            }
        }

        self.sync_toast_deadline(previous_toast);
        self.shutdown_detached_terminal_runtimes();
    }

    fn reset_agent_detection_for_agents(&self, agents: &[crate::detect::Agent]) {
        if agents.is_empty() {
            return;
        }
        for (terminal_id, terminal) in &self.state.terminals {
            let Some(agent) = terminal.effective_known_agent().or(terminal.detected_agent) else {
                continue;
            };
            if !agents.contains(&agent) {
                continue;
            }
            if let Some(runtime) = self.terminal_runtimes.get(terminal_id) {
                runtime.reset_agent_detection();
            }
        }
    }

    fn reset_all_agent_detection_runtimes(&self) {
        for runtime in self.terminal_runtimes.values() {
            runtime.reset_agent_detection();
        }
    }

    pub(crate) fn refresh_new_herdr_toast_context_for_update(
        &mut self,
        update: &crate::app::actions::PaneStateUpdate,
        previous_toast: &Option<crate::app::state::ToastNotification>,
    ) {
        if !matches!(
            self.state.toast_config.delivery,
            crate::config::ToastDelivery::Herdr
        ) || self.state.toast == *previous_toast
        {
            return;
        }

        let Some(target) = self
            .state
            .toast
            .as_ref()
            .and_then(|toast| toast.target.as_ref())
        else {
            return;
        };
        if target.pane_id != update.pane_id {
            return;
        }
        let Some(ws) = self.state.workspaces.get(update.ws_idx) else {
            return;
        };
        if ws.id != target.workspace_id {
            return;
        }

        let workspace_label = ws.display_name_from(&self.state.terminals, &self.terminal_runtimes);
        let context = crate::app::actions::notification_context(
            ws,
            &workspace_label,
            update.ws_idx,
            update.pane_id,
        );
        if let Some(toast) = self.state.toast.as_mut() {
            toast.context = context;
        }
    }

    fn sync_full_lifecycle_authority_detection_pauses(&self) {
        for workspace in &self.state.workspaces {
            for tab in &workspace.tabs {
                for pane in tab.panes.values() {
                    let Some(terminal) = self.state.terminals.get(&pane.attached_terminal_id)
                    else {
                        continue;
                    };
                    let Some(runtime) = self.terminal_runtimes.get(&pane.attached_terminal_id)
                    else {
                        continue;
                    };
                    runtime.set_full_lifecycle_authority_active(
                        terminal.full_lifecycle_hook_authority_active(),
                    );
                }
            }
        }
    }

    pub(crate) fn show_clipboard_feedback(&mut self) {
        if !self.state.toast_config.clipboard.enabled {
            self.state.copy_feedback = None;
            self.copy_feedback_deadline = None;
            return;
        }
        self.state.copy_feedback = Some(crate::app::state::CopyFeedback {
            message: "copied to clipboard".to_string(),
        });
        self.copy_feedback_deadline = Some(Instant::now() + super::COPY_FEEDBACK_DURATION);
    }

    fn restore_overlay_after_exit(
        &mut self,
        overlay: OverlayPaneState,
        was_overlay_active: bool,
        was_overlay_focused_in_tab: bool,
        tab_zoomed_before_exit: Option<bool>,
    ) {
        for temp_file in &overlay.temp_files {
            let _ = std::fs::remove_file(temp_file);
        }

        let Some(ws) = self.state.workspaces.get_mut(overlay.ws_idx) else {
            return;
        };
        if overlay.tab_idx >= ws.tabs.len() {
            return;
        }

        if !was_overlay_focused_in_tab {
            if let Some(tab_zoomed_before_exit) = tab_zoomed_before_exit {
                ws.tabs[overlay.tab_idx].zoomed = tab_zoomed_before_exit;
            }
            return;
        }

        if was_overlay_active {
            ws.active_tab = overlay.tab_idx;
        }
        let tab = &mut ws.tabs[overlay.tab_idx];
        if tab.panes.contains_key(&overlay.previous_focus) {
            tab.layout.focus_pane(overlay.previous_focus);
        }
        tab.zoomed = overlay.previous_zoomed;

        if was_overlay_active && self.state.active == Some(overlay.ws_idx) {
            self.state.mode = Mode::Terminal;
        }
    }

    fn runtime_exit_action(&self, pane_id: crate::layout::PaneId) -> RuntimeExitAction {
        let Some((_, pane_state)) = self.find_pane(pane_id) else {
            return RuntimeExitAction::ClosePane;
        };
        let Some(terminal) = self.state.terminals.get(&pane_state.attached_terminal_id) else {
            return RuntimeExitAction::ClosePane;
        };

        if terminal.respawn_shell_on_exit || self.should_respawn_shell_after_agent_exit(terminal) {
            RuntimeExitAction::RespawnShell
        } else {
            RuntimeExitAction::ClosePane
        }
    }

    fn should_respawn_shell_after_agent_exit(
        &self,
        terminal: &crate::terminal::TerminalState,
    ) -> bool {
        #[cfg(not(windows))]
        {
            let _ = terminal;
            false
        }

        #[cfg(windows)]
        {
            if !terminal.agent_process_exited_within(
                Instant::now(),
                WINDOWS_POWERSHELL_AGENT_EXIT_RESPAWN_GRACE,
            ) {
                return false;
            }

            crate::pane::uses_windows_powershell_pane_shell(crate::pane::PaneShellConfig::new(
                &self.state.default_shell,
                self.state.shell_mode,
            ))
        }
    }

    fn respawn_shell_for_launch_pane(&mut self, pane_id: crate::layout::PaneId) -> bool {
        let Some((ws_idx, pane_state)) = self.find_pane(pane_id) else {
            return false;
        };
        let terminal_id = pane_state.attached_terminal_id.clone();
        let Some(terminal) = self.state.terminals.get(&terminal_id) else {
            return false;
        };

        let cwd = terminal.cwd.clone();
        let (rows, cols) = self
            .terminal_runtimes
            .get(&terminal_id)
            .map(|runtime| runtime.current_size())
            .unwrap_or_else(|| self.state.estimate_pane_size());
        let Some(launch_env) = self.pane_launch_env(ws_idx, pane_id, Vec::new()) else {
            return false;
        };
        let runtime = match crate::terminal::TerminalRuntime::spawn(
            pane_id,
            rows,
            cols,
            cwd,
            self.state.pane_scrollback_limit_bytes,
            self.state.host_terminal_theme,
            crate::pane::PaneShellConfig::new(&self.state.default_shell, self.state.shell_mode),
            &launch_env,
            self.event_tx.clone(),
            self.render_notify.clone(),
            self.render_dirty.clone(),
        ) {
            Ok(runtime) => runtime,
            Err(err) => {
                tracing::warn!(
                    pane = pane_id.raw(),
                    terminal = %terminal_id,
                    err = %err,
                    "failed to respawn shell after launch command exited"
                );
                return false;
            }
        };

        self.terminal_runtimes.insert(terminal_id.clone(), runtime);
        if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
            terminal.clear_agent_runtime_identity_after_respawn();
        }
        self.state.focus_pane_in_workspace(ws_idx, pane_id);
        self.schedule_session_save();
        true
    }

    pub(crate) fn emit_pane_state_update(&mut self, update: &crate::app::actions::PaneStateUpdate) {
        let Some(pane_id) = self.public_pane_id(update.ws_idx, update.pane_id) else {
            return;
        };
        let workspace_id = self.public_workspace_id(update.ws_idx);

        if update.agent_name_changed {
            self.emit_pane_updated(update.ws_idx, update.pane_id);
        }

        if update.previous_agent_label != update.agent_label || update.agent_released {
            self.emit_event(crate::api::schema::EventEnvelope {
                event: crate::api::schema::EventKind::PaneAgentDetected,
                data: crate::api::schema::EventData::PaneAgentDetected {
                    pane_id: pane_id.clone(),
                    workspace_id: workspace_id.clone(),
                    agent: update.agent_label.clone(),
                    released: update.agent_released,
                    final_status: update.agent_release_status,
                },
            });
        }

        let previous_agent_status = pane_agent_status(update.previous_state, update.previous_seen);
        let agent_status = self
            .state
            .workspaces
            .get(update.ws_idx)
            .and_then(|ws| ws.pane_state(update.pane_id))
            .map(|pane| pane_agent_status(update.state, pane.seen))
            .unwrap_or_else(|| pane_agent_status(update.state, update.seen));

        if previous_agent_status != agent_status
            || update.previous_presentation != update.presentation
            || update.previous_input_pending != update.input_pending
            || update.previous_input_prompt_kind != update.input_prompt_kind
        {
            let presentation = update.presentation.clone();
            self.emit_event(crate::api::schema::EventEnvelope {
                event: crate::api::schema::EventKind::PaneAgentStatusChanged,
                data: crate::api::schema::EventData::PaneAgentStatusChanged {
                    pane_id: pane_id.clone(),
                    workspace_id: workspace_id.clone(),
                    agent_status,
                    input_pending: update.input_pending,
                    input_prompt_kind: update.input_prompt_kind,
                    agent: update.agent_label.clone(),
                    title: presentation.title,
                    display_agent: presentation.display_agent,
                    state_labels: presentation.state_labels,
                    turn: update.turn,
                    turn_epoch: update.turn_epoch,
                },
            });
        }

        if let Some(completed) = &update.completed_turn {
            if let Some(pane) = self.pane_info(update.ws_idx, update.pane_id) {
                self.emit_event(crate::api::schema::EventEnvelope {
                    event: crate::api::schema::EventKind::PaneTurnCompleted,
                    data: crate::api::schema::EventData::PaneTurnCompleted {
                        pane,
                        turn: completed.turn,
                        turn_epoch: completed.turn_epoch,
                        outcome: completed.outcome,
                        message: completed.message.clone(),
                        message_truncated: completed.message_truncated,
                        agent_session_path: completed.agent_session_path.clone(),
                        completed_unix_ms: completed.completed_unix_ms,
                    },
                });
            }
        }
    }

    fn emit_terminal_or_system_agent_notifications(
        &self,
        pane_updates: &[crate::app::actions::PaneStateUpdate],
    ) {
        if !self.local_terminal_notifications
            || self.state.toast_config.delay_seconds != 0
            || !matches!(
                self.state.toast_config.delivery,
                crate::config::ToastDelivery::Terminal | crate::config::ToastDelivery::System
            )
        {
            return;
        }

        let notify = match self.state.toast_config.delivery {
            crate::config::ToastDelivery::Terminal => crate::terminal_notify::show_notification,
            crate::config::ToastDelivery::System => crate::platform::show_desktop_notification,
            _ => return,
        };

        for update in pane_updates {
            let is_active_tab = self
                .state
                .pane_is_in_active_tab(update.ws_idx, update.pane_id);
            let suppress_active_tab_notifications =
                crate::app::actions::active_tab_suppresses_notifications(
                    is_active_tab,
                    self.state.outer_terminal_focus,
                );
            let Some(kind) = crate::app::actions::notification_toast_for_pane_state_update(
                suppress_active_tab_notifications,
                update,
            ) else {
                continue;
            };
            let Some(ws) = self.state.workspaces.get(update.ws_idx) else {
                continue;
            };
            let Some(pane) = ws
                .tabs
                .iter()
                .find_map(|tab| tab.panes.get(&update.pane_id))
            else {
                continue;
            };
            let Some(agent_label) = self
                .state
                .terminals
                .get(&pane.attached_terminal_id)
                .and_then(|terminal| terminal.effective_agent_label())
            else {
                continue;
            };
            let event_text = match kind {
                ToastKind::NeedsAttention => "needs attention",
                ToastKind::Finished => "finished",
                ToastKind::UpdateInstalled => "updated",
            };
            let workspace_label =
                ws.display_name_from(&self.state.terminals, &self.terminal_runtimes);
            let _ = notify(
                &format!("{} {}", agent_label, event_text),
                Some(&crate::app::actions::notification_context(
                    ws,
                    &workspace_label,
                    update.ws_idx,
                    update.pane_id,
                )),
            );
        }
    }

    /// Deliver agent-state transitions to registered remote devices via APNs.
    ///
    /// A sibling of `emit_terminal_or_system_agent_notifications`, but with its
    /// own guard (`crate::push::enabled`), independent of `local_terminal_
    /// notifications` and `ToastDelivery`: a remote device wants push even when
    /// local toasts are Off/Herdr and even on the focused active tab (so
    /// active-tab suppression is intentionally not applied here). Delivery is
    /// detached and best-effort — it never blocks the app loop or holds a lock
    /// across the curl. `from_pane_death` maps every produced alert to the
    /// pane-died kind; otherwise the alert kind follows the toast kind.
    fn emit_apns_agent_notifications(
        &self,
        pane_updates: &[crate::app::actions::PaneStateUpdate],
        from_pane_death: bool,
    ) {
        if self.no_session || !crate::push::enabled(&self.state.push_config) {
            return;
        }

        let mut notifications = Vec::new();
        for update in pane_updates {
            // Pass `false`: remote push is not suppressed on the active tab. A
            // pane death is an event, not a state transition, so `push_kind_for`
            // yields a Died push even when the toast predicate returns None
            // (e.g. an already-idle pane whose process exits).
            let toast_kind =
                crate::app::actions::notification_toast_for_pane_state_update(false, update);
            let Some(push_kind) = push_kind_for(from_pane_death, toast_kind) else {
                continue;
            };
            let Some(ws) = self.state.workspaces.get(update.ws_idx) else {
                continue;
            };
            let Some(pane) = ws
                .tabs
                .iter()
                .find_map(|tab| tab.panes.get(&update.pane_id))
            else {
                continue;
            };
            let Some(agent_label) = self
                .state
                .terminals
                .get(&pane.attached_terminal_id)
                .and_then(|terminal| terminal.effective_agent_label())
            else {
                continue;
            };
            let Some(public_pane_id) = self.public_pane_id(update.ws_idx, update.pane_id) else {
                continue;
            };
            let event_text = match push_kind {
                crate::push::PushKind::NeedsInput => "needs attention",
                crate::push::PushKind::Finished => "finished",
                crate::push::PushKind::Died => "exited",
                // Gram alerts are built in `emit_apns_gram_message`, never from a
                // pane-state update, so this arm is unreachable here; it only
                // keeps the match exhaustive.
                crate::push::PushKind::Gram => "sent a message",
            };
            let workspace_label =
                ws.display_name_from(&self.state.terminals, &self.terminal_runtimes);
            // Bound the alert text so the JSON payload stays well under Apple's 4096-byte
            // limit — workspace/tab names are user-controlled and unbounded, and an oversized
            // payload is a 413 that would be silently dropped. Reuse the local toast path's
            // sanitize+truncate (title 80, body 240); a title that sanitizes away is skipped.
            let Some(title) =
                sanitized_notification_text(&format!("{agent_label} {event_text}"), 80)
            else {
                continue;
            };
            let body = sanitized_notification_text(
                &crate::app::actions::notification_context(
                    ws,
                    &workspace_label,
                    update.ws_idx,
                    update.pane_id,
                ),
                240,
            )
            .unwrap_or_default();
            notifications.push(crate::push::PushNotification {
                title,
                body,
                pane_id: public_pane_id,
                workspace_id: self.public_workspace_id(update.ws_idx),
                kind: push_kind,
            });
        }

        if notifications.is_empty() {
            return;
        }

        // Detached + best-effort: never block the app loop on curl or disk. A
        // named Builder means a thread-creation failure (EAGAIN) is handled
        // instead of panicking the app-loop thread. Bounding fan-out with a
        // single worker queue is a follow-up.
        let cfg = self.state.push_config.clone();
        if let Err(err) = std::thread::Builder::new()
            .name("herdr-push".to_string())
            .spawn(move || crate::push::deliver(cfg, notifications))
        {
            tracing::warn!(error = %err, "failed to spawn push sender thread; dropping batch");
        }
    }

    /// Push the session's aggregate agent status to every registered Live Activity, so the
    /// lock-screen / Dynamic Island widget refreshes while the app is closed. Fired from the
    /// same sites as `emit_apns_agent_notifications` (i.e. whenever agent status changes).
    /// Best-effort + detached; a no-op when push is off or no Live Activity is registered.
    fn emit_live_activity_updates(&self) {
        use std::sync::atomic::Ordering;

        if self.no_session || !crate::push::enabled(&self.state.push_config) {
            return;
        }
        // Cheap gate (no disk on the hot loop): nothing registered → nothing to do.
        if !crate::push::LIVE_ACTIVITY_PRESENT.load(Ordering::Relaxed) {
            return;
        }

        let content_state = live_activity_content_state(&self.collect_agent_infos());

        // Dedup: skip when the aggregate is unchanged since the last dispatch. Status-change
        // events fire often without altering the widget's content (e.g. a git refresh), and
        // Live Activity push budgets are small, so unchanged states must not hit APNs.
        let hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            content_state.to_string().hash(&mut hasher);
            hasher.finish()
        };
        if LAST_LIVE_ACTIVITY_HASH.load(Ordering::Relaxed) == hash {
            return;
        }

        // Monotonic, source-ordered timestamp (seconds), assigned HERE on the single app loop
        // rather than per-thread, so reordered sender threads can't let a stale snapshot
        // overwrite a newer one — APNs keeps the highest aps.timestamp.
        let now_secs = unix_millis_now() / 1000;
        let timestamp = {
            let previous = LAST_LIVE_ACTIVITY_TS.load(Ordering::Relaxed);
            let next = now_secs.max(previous + 1);
            LAST_LIVE_ACTIVITY_TS.store(next, Ordering::Relaxed);
            next
        };
        LAST_LIVE_ACTIVITY_HASH.store(hash, Ordering::Relaxed);

        let cfg = self.state.push_config.clone();
        if let Err(err) = std::thread::Builder::new()
            .name("herdr-liveactivity".to_string())
            .spawn(move || crate::push::deliver_live_activity(cfg, content_state, timestamp))
        {
            tracing::warn!(error = %err, "failed to spawn live-activity sender thread; dropping update");
        }
    }

    pub(crate) fn sync_toast_deadline(
        &mut self,
        previous_toast: Option<crate::app::state::ToastNotification>,
    ) {
        if self.state.toast != previous_toast {
            self.toast_deadline = self.state.toast.as_ref().map(|toast| {
                let duration = match toast.kind {
                    ToastKind::NeedsAttention => Duration::from_secs(8),
                    ToastKind::Finished => Duration::from_secs(5),
                    ToastKind::UpdateInstalled => Duration::from_secs(3),
                };
                Instant::now() + duration
            });
        }
    }

    pub(crate) fn emit_delayed_client_local_agent_notifications(
        &self,
        deliveries: &[crate::app::state::AgentNotificationDelivery],
    ) {
        if !self.local_terminal_notifications
            || !matches!(
                self.state.toast_config.delivery,
                crate::config::ToastDelivery::Terminal | crate::config::ToastDelivery::System
            )
        {
            return;
        }

        let notify = match self.state.toast_config.delivery {
            crate::config::ToastDelivery::Terminal => crate::terminal_notify::show_notification,
            crate::config::ToastDelivery::System => crate::platform::show_desktop_notification,
            _ => unreachable!("toast delivery was checked above"),
        };

        for delivery in deliveries {
            let Some(toast) = &delivery.client_notification else {
                continue;
            };
            let _ = notify(&toast.title, Some(&toast.context));
        }
    }

    pub(crate) fn refresh_agent_notification_delivery_contexts(
        &mut self,
        deliveries: &mut [crate::app::state::AgentNotificationDelivery],
    ) {
        for delivery in deliveries {
            let Some(ws_idx) = self
                .state
                .workspaces
                .iter()
                .position(|ws| ws.id == delivery.workspace_id)
            else {
                continue;
            };
            let ws = &self.state.workspaces[ws_idx];
            let workspace_label =
                ws.display_name_from(&self.state.terminals, &self.terminal_runtimes);
            let context = crate::app::actions::notification_context(
                ws,
                &workspace_label,
                ws_idx,
                delivery.pane_id,
            );
            if let Some(toast) = delivery.toast.as_mut() {
                toast.context = context.clone();
            }
            if let Some(toast) = delivery.client_notification.as_mut() {
                toast.context = context.clone();
            }
            if let Some(toast) = self.state.toast.as_mut() {
                if toast.target.as_ref().is_some_and(|target| {
                    target.workspace_id == delivery.workspace_id
                        && target.pane_id == delivery.pane_id
                }) {
                    toast.context = context;
                }
            }
        }
    }

    pub(super) fn emit_event(&mut self, event: crate::api::schema::EventEnvelope) {
        self.run_plugin_event_hooks(&event);
        self.event_hub.push(event);
    }

    pub(crate) fn emit_pane_updated(&mut self, ws_idx: usize, pane_id: crate::layout::PaneId) {
        if let Some(pane) = self.pane_info(ws_idx, pane_id) {
            self.emit_event(crate::api::schema::EventEnvelope {
                event: crate::api::schema::EventKind::PaneUpdated,
                data: crate::api::schema::EventData::PaneUpdated { pane },
            });
        }
    }

    pub(crate) fn emit_workspace_token_updated(&mut self, ws_idx: usize) {
        // Token updates bypass plugin hooks so a hook cannot refresh its own
        // token and recursively trigger workspace.updated.
        self.event_hub.push(crate::api::schema::EventEnvelope {
            event: crate::api::schema::EventKind::WorkspaceMetadataUpdated,
            data: crate::api::schema::EventData::WorkspaceMetadataUpdated {
                workspace: self.workspace_info(ws_idx),
            },
        });
    }

    pub(crate) fn sync_focus_events(&mut self) {
        self.sync_focus_events_with_outer_event(None);
    }

    pub(super) fn send_outer_focus_event(&mut self, event: crate::ghostty::FocusEvent) {
        self.sync_focus_events_with_outer_event(Some(event));
    }

    fn sync_focus_events_with_outer_event(
        &mut self,
        outer_event: Option<crate::ghostty::FocusEvent>,
    ) {
        let current_focus = self.state.active.and_then(|idx| {
            self.state
                .workspaces
                .get(idx)
                .and_then(|ws| ws.focused_pane_id().map(|pane_id| (idx, pane_id)))
        });
        if current_focus == self.last_focus {
            if let (Some((ws_idx, pane_id)), Some(event)) = (current_focus, outer_event) {
                self.send_pane_focus_event(ws_idx, pane_id, event);
            }
            return;
        }

        if let Some((ws_idx, pane_id)) = self.last_focus {
            self.send_pane_focus_event(ws_idx, pane_id, crate::ghostty::FocusEvent::Lost);
        }
        if let Some((ws_idx, pane_id)) = current_focus {
            let event = outer_event.unwrap_or_else(|| {
                if self.state.outer_terminal_focus == Some(false) {
                    crate::ghostty::FocusEvent::Lost
                } else {
                    crate::ghostty::FocusEvent::Gained
                }
            });
            self.send_pane_focus_event(ws_idx, pane_id, event);
            self.emit_event(crate::api::schema::EventEnvelope {
                event: crate::api::schema::EventKind::WorkspaceFocused,
                data: crate::api::schema::EventData::WorkspaceFocused {
                    workspace_id: self.public_workspace_id(ws_idx),
                },
            });
            if let Some(tab_id) =
                self.public_tab_id(ws_idx, self.state.workspaces[ws_idx].active_tab)
            {
                self.emit_event(crate::api::schema::EventEnvelope {
                    event: crate::api::schema::EventKind::TabFocused,
                    data: crate::api::schema::EventData::TabFocused {
                        tab_id,
                        workspace_id: self.public_workspace_id(ws_idx),
                    },
                });
            }
            if let Some(public_pane_id) = self.public_pane_id(ws_idx, pane_id) {
                self.emit_event(crate::api::schema::EventEnvelope {
                    event: crate::api::schema::EventKind::PaneFocused,
                    data: crate::api::schema::EventData::PaneFocused {
                        pane_id: public_pane_id,
                        workspace_id: self.public_workspace_id(ws_idx),
                    },
                });
            }
        }

        self.last_focus = current_focus;
    }

    fn send_pane_focus_event(
        &self,
        ws_idx: usize,
        pane_id: crate::layout::PaneId,
        event: crate::ghostty::FocusEvent,
    ) {
        let Some(runtime) = self.state.workspaces.get(ws_idx).and_then(|_| {
            self.state
                .runtime_for_pane_in_workspace(&self.terminal_runtimes, ws_idx, pane_id)
        }) else {
            return;
        };
        runtime.try_send_focus_event(event);
    }

    pub(crate) fn handle_api_request(&mut self, request: crate::api::schema::Request) -> String {
        self.drain_all_internal_events();
        self.handle_api_request_after_internal_events_drained(request)
    }

    pub(crate) fn handle_api_request_after_internal_events_drained(
        &mut self,
        request: crate::api::schema::Request,
    ) -> String {
        self.sync_terminal_titles();
        use crate::api::schema::{
            ErrorBody, ErrorResponse, Method, ResponseResult, SuccessResponse,
        };

        let response = match request.method {
            Method::ServerStop(_) => {
                self.state.should_quit = true;
                SuccessResponse {
                    id: request.id,
                    result: ResponseResult::Ok {},
                }
            }
            Method::ServerLiveHandoff(_) => {
                let response = ErrorResponse {
                    id: request.id,
                    error: ErrorBody {
                        code: "unsupported_in_app_mode".into(),
                        message: "live handoff is only supported by the headless server".into(),
                    },
                };
                return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            }
            Method::ServerReloadConfig(_) => {
                let report = self.reload_config();
                SuccessResponse {
                    id: request.id,
                    result: ResponseResult::ConfigReload {
                        status: report.status,
                        diagnostics: report.diagnostics,
                    },
                }
            }
            Method::ServerAgentManifests(_) => {
                self.state.refresh_agent_manifest_summaries();
                let update_status = crate::detect::manifest_update::load_status();
                SuccessResponse {
                    id: request.id,
                    result: ResponseResult::AgentManifestStatus {
                        last_check_unix: update_status.last_check_unix,
                        last_result: update_status.last_result.clone(),
                        manifests: self
                            .state
                            .agent_manifest_summaries
                            .clone()
                            .into_iter()
                            .map(|summary| agent_manifest_info(summary, &update_status))
                            .collect(),
                    },
                }
            }
            Method::ServerReloadAgentManifests(_) => {
                let summaries = crate::detect::manifest::reload_manifests();
                self.state.agent_manifest_summaries = summaries.clone();
                let update_status = crate::detect::manifest_update::load_status();
                self.reset_all_agent_detection_runtimes();
                SuccessResponse {
                    id: request.id,
                    result: ResponseResult::AgentManifestReload {
                        manifests: summaries
                            .into_iter()
                            .map(|summary| agent_manifest_info(summary, &update_status))
                            .collect(),
                    },
                }
            }
            Method::NotificationShow(params) => {
                return self.handle_notification_show(request.id, params);
            }
            Method::NotificationsRegisterDevice(params) => {
                return self.handle_notifications_register_device(request.id, params);
            }
            Method::NotificationsRegisterActivity(params) => {
                return self.handle_notifications_register_activity(request.id, params);
            }
            Method::NotificationsUnregisterActivity(params) => {
                return self.handle_notifications_unregister_activity(request.id, params);
            }
            Method::GramSend(params) => return self.handle_gram_send(request.id, params),
            Method::GramPost(params) => return self.handle_gram_post(request.id, params),
            Method::GramList(params) => return self.handle_gram_list(request.id, params),
            Method::GramGrab(params) => return self.handle_gram_grab(request.id, params),
            Method::GramMarkRead(params) => {
                return self.handle_gram_mark_read(request.id, params);
            }
            Method::GramDelete(params) => return self.handle_gram_delete(request.id, params),
            Method::GramUploadChunk(params) => {
                return self.handle_gram_upload_chunk(request.id, params);
            }
            Method::GramGetFile(params) => return self.handle_gram_get_file(request.id, params),
            Method::ClientWindowTitleSet(_) | Method::ClientWindowTitleClear(_) => {
                return responses::encode_success(
                    request.id,
                    ResponseResult::ClientWindowTitle {
                        changed: false,
                        reason: crate::api::schema::ClientWindowTitleReason::NoForegroundClient,
                    },
                );
            }
            Method::SessionSnapshot(_) => return self.handle_session_snapshot(request.id),
            Method::WorkspaceList(_) => return self.handle_workspace_list(request.id),
            Method::WorkspaceGet(target) => return self.handle_workspace_get(request.id, target),
            Method::WorkspaceCreate(params) => {
                return self.handle_workspace_create(request.id, params);
            }
            Method::WorkspaceFocus(target) => {
                return self.handle_workspace_focus(request.id, target)
            }
            Method::WorkspaceRename(params) => {
                return self.handle_workspace_rename(request.id, params);
            }
            Method::WorkspaceMove(params) => {
                return self.handle_workspace_move(request.id, params);
            }
            Method::WorkspaceMoveBlock(params) => {
                return self.handle_workspace_move_block(request.id, params);
            }
            Method::WorkspaceReportMetadata(params) => {
                return self.handle_workspace_report_metadata(request.id, params);
            }
            Method::WorkspaceClose(target) => {
                return self.handle_workspace_close(request.id, target)
            }
            Method::WorktreeList(params) => return self.handle_worktree_list(request.id, params),
            Method::WorktreeCreate(params) => {
                let _ = params;
                return responses::encode_error(
                    request.id,
                    "invalid_request",
                    "worktree.create is handled asynchronously by the app runtime",
                );
            }
            Method::WorktreeOpen(params) => return self.handle_worktree_open(request.id, params),
            Method::WorktreeRemove(params) => {
                let _ = params;
                return responses::encode_error(
                    request.id,
                    "invalid_request",
                    "worktree.remove is handled asynchronously by the app runtime",
                );
            }
            Method::TabList(params) => return self.handle_tab_list(request.id, params),
            Method::TabGet(target) => return self.handle_tab_get(request.id, target),
            Method::TabCreate(params) => return self.handle_tab_create(request.id, params),
            Method::TabFocus(target) => return self.handle_tab_focus(request.id, target),
            Method::TabRename(params) => return self.handle_tab_rename(request.id, params),
            Method::TabMove(params) => return self.handle_tab_move(request.id, params),
            Method::TabClose(target) => return self.handle_tab_close(request.id, target),
            Method::AgentList(_) => return self.handle_agent_list(request.id),
            Method::AgentGet(target) => return self.handle_agent_get(request.id, target),
            Method::AgentFocus(target) => return self.handle_agent_focus(request.id, target),
            Method::AgentRename(params) => return self.handle_agent_rename(request.id, params),
            Method::AgentViewSet(params) => return self.handle_agent_view_set(request.id, params),
            Method::AgentViewClear(params) => {
                return self.handle_agent_view_clear(request.id, params)
            }
            Method::AgentStart(params) => return self.handle_agent_start(request.id, params),
            Method::AgentPrompt(params) => return self.handle_agent_prompt(request.id, params),
            Method::AgentWait(_) => {
                return responses::encode_error(
                    request.id,
                    "invalid_request",
                    "agent.wait is handled by the api server",
                );
            }
            Method::AgentRead(params) => return self.handle_agent_read(request.id, params),
            Method::AgentExplain(target) => return self.handle_agent_explain(request.id, target),
            Method::AgentSendKeys(params) => {
                return self.handle_agent_send_keys(request.id, params)
            }
            Method::PaneSplit(params) => return self.handle_pane_split(request.id, params),
            Method::PaneSwap(params) => return self.handle_pane_swap(request.id, params),
            Method::PaneMove(params) => return self.handle_pane_move(request.id, params),
            Method::PaneZoom(params) => return self.handle_pane_zoom(request.id, params),
            Method::PaneLayout(params) => return self.handle_pane_layout(request.id, params),
            Method::PaneProcessInfo(params) => {
                return self.handle_pane_process_info(request.id, params);
            }
            Method::LayoutExport(params) => return self.handle_layout_export(request.id, params),
            Method::LayoutApply(params) => return self.handle_layout_apply(request.id, params),
            Method::LayoutSetSplitRatio(params) => {
                return self.handle_layout_set_split_ratio(request.id, params);
            }
            Method::PaneNeighbor(params) => return self.handle_pane_neighbor(request.id, params),
            Method::PaneEdges(params) => return self.handle_pane_edges(request.id, params),
            Method::PaneFocusDirection(params) => {
                return self.handle_pane_focus_direction(request.id, params);
            }
            Method::PaneResize(params) => return self.handle_pane_resize(request.id, params),
            Method::PaneSetPtySize(params) => {
                return self.handle_pane_set_pty_size(request.id, params);
            }
            Method::PaneList(params) => return self.handle_pane_list(request.id, params),
            Method::PaneCurrent(params) => return self.handle_pane_current(request.id, params),
            Method::PaneGet(target) => return self.handle_pane_get(request.id, target),
            Method::PaneTurns(params) => return self.handle_pane_turns(request.id, params),
            Method::PaneFocus(target) => return self.handle_pane_focus(request.id, target),
            Method::PaneRename(params) => return self.handle_pane_rename(request.id, params),
            Method::PaneRead(params) => return self.handle_pane_read(request.id, params),
            Method::PaneGraphicsSet(params) => {
                return self.handle_pane_graphics_set(request.id, params);
            }
            Method::PaneGraphicsClear(params) => {
                return self.handle_pane_graphics_clear(request.id, params);
            }
            Method::PaneGraphicsInfo(params) => {
                return self.handle_pane_graphics_info(request.id, params);
            }
            Method::PaneGraphicsStream(_) => {
                return responses::encode_error(
                    request.id,
                    "stream_transport_required",
                    "pane.graphics.stream requires the streaming socket transport",
                );
            }
            Method::PaneGraphicsStreamSet(params) => {
                return self.handle_pane_graphics_stream_set(request.id, params);
            }
            Method::PaneGraphicsStreamOpen(params) => {
                return self.handle_pane_graphics_stream_open(request.id, params);
            }
            Method::PaneGraphicsStreamClose(params) => {
                return self.handle_pane_graphics_stream_close(request.id, params);
            }
            Method::PaneStream(_) => {
                return responses::encode_error(
                    request.id,
                    "stream_transport_required",
                    "pane.stream requires the streaming socket transport",
                );
            }
            Method::PaneStreamOpen(params) => {
                return self.handle_pane_stream_open(request.id, params);
            }
            Method::PaneStreamClose(params) => {
                return self.handle_pane_stream_close(request.id, params);
            }
            Method::PaneReportAgent(params) => {
                return self.handle_pane_report_agent(request.id, params);
            }
            Method::PaneReportAgentSession(params) => {
                return self.handle_pane_report_agent_session(request.id, params);
            }
            Method::PaneReportMetadata(params) => {
                return self.handle_pane_report_metadata(request.id, params);
            }
            Method::PaneClearAgentAuthority(params) => {
                return self.handle_pane_clear_agent_authority(request.id, params);
            }
            Method::PaneReleaseAgent(params) => {
                return self.handle_pane_release_agent(request.id, params);
            }
            Method::PaneSendText(params) => return self.handle_pane_send_text(request.id, params),
            Method::PaneSendInput(params) => {
                return self.handle_pane_send_input(request.id, params)
            }
            Method::PaneClose(target) => return self.handle_pane_close(request.id, target),
            Method::PopupClose(_) => {
                return if self.close_popup_pane() {
                    responses::encode_success(request.id, ResponseResult::Ok {})
                } else {
                    responses::encode_error(request.id, "popup_not_open", "no popup is open")
                };
            }
            Method::PaneSendKeys(params) => return self.handle_pane_send_keys(request.id, params),
            Method::IntegrationInstall(params) => {
                return self.handle_integration_install(request.id, params);
            }
            Method::IntegrationUninstall(params) => {
                return self.handle_integration_uninstall(request.id, params);
            }
            Method::PluginLink(params) => {
                return self.handle_plugin_link(request.id, params);
            }
            Method::PluginList(params) => {
                return self.handle_plugin_list(request.id, params);
            }
            Method::PluginUnlink(params) => {
                return self.handle_plugin_unlink(request.id, params);
            }
            Method::PluginEnable(params) => {
                return self.handle_plugin_enable(request.id, params);
            }
            Method::PluginDisable(params) => {
                return self.handle_plugin_disable(request.id, params);
            }
            Method::PluginActionList(params) => {
                return self.handle_plugin_action_list(request.id, params);
            }
            Method::PluginActionInvoke(params) => {
                return self.handle_plugin_action_invoke(request.id, params);
            }
            Method::PluginLogList(params) => {
                return self.handle_plugin_log_list(request.id, params);
            }
            Method::PluginPaneOpen(params) => {
                return self.handle_plugin_pane_open(request.id, params);
            }
            Method::PluginPaneFocus(params) => {
                return self.handle_plugin_pane_focus(request.id, params);
            }
            Method::PluginPaneClose(params) => {
                return self.handle_plugin_pane_close(request.id, params);
            }
            _ => {
                return responses::encode_error(
                    request.id,
                    "not_implemented",
                    "method not implemented yet",
                );
            }
        };

        serde_json::to_string(&response).unwrap()
    }

    fn handle_notification_show(
        &mut self,
        id: String,
        params: crate::api::schema::NotificationShowParams,
    ) -> String {
        use crate::api::schema::{NotificationShowReason, ResponseResult};

        let requested_sound = params.sound;
        let Some(title) = sanitized_notification_text(&params.title, 80) else {
            return responses::encode_error(id, "invalid_params", "notification title is empty");
        };
        let body = params
            .body
            .as_deref()
            .and_then(|body| sanitized_notification_text(body, 240));

        let reason = match self.state.toast_config.delivery {
            crate::config::ToastDelivery::Off => NotificationShowReason::Disabled,
            crate::config::ToastDelivery::Herdr => {
                if self.state.toast.is_some() {
                    NotificationShowReason::Busy
                } else if self.api_notification_rate_limited(Instant::now()) {
                    NotificationShowReason::RateLimited
                } else {
                    let previous_toast = self.state.toast.clone();
                    self.mark_api_notification_shown(Instant::now());
                    self.state.toast = Some(crate::app::state::ToastNotification {
                        kind: ToastKind::UpdateInstalled,
                        title,
                        context: body.unwrap_or_default(),
                        position: params.position,
                        target: None,
                    });
                    self.sync_toast_deadline(previous_toast);
                    self.emit_api_notification_sound(requested_sound);
                    NotificationShowReason::Shown
                }
            }
            crate::config::ToastDelivery::Terminal | crate::config::ToastDelivery::System => {
                if self.api_notification_rate_limited(Instant::now()) {
                    NotificationShowReason::RateLimited
                } else {
                    let notify = match self.state.toast_config.delivery {
                        crate::config::ToastDelivery::Terminal => {
                            crate::terminal_notify::show_notification
                        }
                        crate::config::ToastDelivery::System => {
                            crate::platform::show_desktop_notification
                        }
                        _ => unreachable!("notification delivery was checked above"),
                    };
                    match notify(&title, body.as_deref()) {
                        Ok(true) => {
                            self.mark_api_notification_shown(Instant::now());
                            self.emit_api_notification_sound(requested_sound);
                            NotificationShowReason::Shown
                        }
                        Ok(false) | Err(_) => NotificationShowReason::NoForegroundClient,
                    }
                }
            }
        };

        responses::encode_success(
            id,
            ResponseResult::NotificationShow {
                shown: matches!(reason, NotificationShowReason::Shown),
                reason,
            },
        )
    }

    fn handle_notifications_register_device(
        &mut self,
        id: String,
        params: crate::api::schema::NotificationsRegisterDeviceParams,
    ) -> String {
        use crate::api::schema::ResponseResult;

        let device_token = params.device_token.trim();
        if !is_valid_apns_device_token(device_token) {
            return responses::encode_error(
                id,
                "invalid_params",
                "device_token must be 32-200 hexadecimal characters",
            );
        }
        let platform = params.platform.trim();
        if platform.is_empty() {
            return responses::encode_error(id, "invalid_params", "platform is empty");
        }

        // No-session/monolithic mode has no shared device registry to persist
        // to; acknowledge without touching disk, mirroring the plugin handlers.
        if self.no_session {
            return responses::encode_success(id, ResponseResult::Ok {});
        }

        let device = crate::persist::devices::RegisteredDevice {
            device_token: device_token.to_string(),
            platform: platform.to_string(),
            notify_needs_input: params.notify_needs_input,
            notify_dies: params.notify_dies,
            notify_finishes: params.notify_finishes,
            notify_gram: params.notify_gram,
            registered_unix_ms: unix_millis_now(),
        };

        match crate::persist::devices::upsert(device) {
            Ok(_) => responses::encode_success(id, ResponseResult::Ok {}),
            Err(err) => responses::encode_error(id, "device_registry_save_failed", err.to_string()),
        }
    }

    fn handle_notifications_register_activity(
        &mut self,
        id: String,
        params: crate::api::schema::NotificationsRegisterActivityParams,
    ) -> String {
        use crate::api::schema::ResponseResult;

        let token = params.activity_push_token.trim();
        if !is_valid_apns_activity_token(token) {
            return responses::encode_error(
                id,
                "invalid_params",
                "activity_push_token must be 32-512 hexadecimal characters",
            );
        }

        // No-session/monolithic mode has no shared registry to persist to; ack without disk,
        // mirroring handle_notifications_register_device.
        if self.no_session {
            return responses::encode_success(id, ResponseResult::Ok {});
        }

        let activity = crate::persist::activities::RegisteredActivity {
            activity_push_token: token.to_string(),
            registered_unix_ms: unix_millis_now(),
        };
        match crate::persist::activities::upsert(activity) {
            Ok(_) => {
                // A widget is registered again: re-open the app-loop gate and reset the dedup
                // hash so the next status change is delivered to the newly-registered activity.
                crate::push::LIVE_ACTIVITY_PRESENT
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                LAST_LIVE_ACTIVITY_HASH.store(0, std::sync::atomic::Ordering::Relaxed);
                responses::encode_success(id, ResponseResult::Ok {})
            }
            Err(err) => {
                responses::encode_error(id, "activity_registry_save_failed", err.to_string())
            }
        }
    }

    fn handle_notifications_unregister_activity(
        &mut self,
        id: String,
        params: crate::api::schema::NotificationsRegisterActivityParams,
    ) -> String {
        use crate::api::schema::ResponseResult;

        let token = params.activity_push_token.trim();
        // Best-effort: nothing to prune in no-session mode or for an empty token.
        if self.no_session || token.is_empty() {
            return responses::encode_success(id, ResponseResult::Ok {});
        }
        match crate::persist::activities::remove_token(token) {
            Ok(_) => responses::encode_success(id, ResponseResult::Ok {}),
            Err(err) => {
                responses::encode_error(id, "activity_registry_save_failed", err.to_string())
            }
        }
    }

    fn emit_api_notification_sound(&self, sound: crate::api::schema::NotificationShowSound) {
        if !self.state.local_sound_playback || !self.state.sound.allows(None) {
            return;
        }
        if let Some(sound) = sound.to_sound() {
            crate::sound::play(sound, &self.state.sound);
        }
    }

    pub(crate) fn api_notification_rate_limited(&self, now: Instant) -> bool {
        self.last_api_notification_at
            .is_some_and(|last| now.duration_since(last) < API_NOTIFICATION_RATE_LIMIT)
    }

    pub(crate) fn mark_api_notification_shown(&mut self, now: Instant) {
        self.last_api_notification_at = Some(now);
    }
}

fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// An APNs device token is lower/upper hex; bound the length so a garbage
/// registration cannot bloat the store.
fn is_valid_apns_device_token(token: &str) -> bool {
    (32..=200).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Live Activity push tokens are hex like device tokens but LONGER, so allow a wider range.
fn is_valid_apns_activity_token(token: &str) -> bool {
    (32..=512).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Source-ordered, strictly-increasing timestamp (Unix seconds) of the last Live Activity
/// update dispatched. Assigned on the single app loop so reordered sender threads keep order.
static LAST_LIVE_ACTIVITY_TS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Hash of the last content-state dispatched, so an unchanged aggregate is not re-sent.
static LAST_LIVE_ACTIVITY_HASH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Aggregate a session's agents into the Live Activity content-state the widget renders.
/// Keys MUST match the app's `AgentActivityAttributes.State` (camelCase). The status +
/// priority mirror the iOS `AgentGroup` / `LiveActivityController` mapping so the background
/// (push) and foreground (in-app) computations agree: needs-you (blocked/unknown) outranks
/// working, which outranks idle; a dead pane simply drops off this live list.
fn live_activity_content_state(agents: &[crate::api::schema::AgentInfo]) -> serde_json::Value {
    use crate::api::schema::AgentStatus;

    fn rank(status: AgentStatus) -> u8 {
        match status {
            AgentStatus::Blocked => 0,
            AgentStatus::Unknown => 2,
            AgentStatus::Working => 3,
            AgentStatus::Idle | AgentStatus::Done => 4,
        }
    }
    fn status_str(status: AgentStatus) -> &'static str {
        match status {
            AgentStatus::Blocked | AgentStatus::Unknown => "needsYou",
            AgentStatus::Working => "working",
            AgentStatus::Idle | AgentStatus::Done => "idle",
        }
    }

    let needs_you_count = agents
        .iter()
        .filter(|agent| agent.agent_status == AgentStatus::Blocked)
        .count();
    let working_count = agents
        .iter()
        .filter(|agent| agent.agent_status == AgentStatus::Working)
        .count();

    let lead = agents.iter().min_by_key(|agent| rank(agent.agent_status));
    let (headline, status) = match lead {
        Some(agent) => (
            agent
                .name
                .clone()
                .or_else(|| agent.terminal_title_stripped.clone())
                .or_else(|| agent.agent.clone())
                .unwrap_or_else(|| "agent".to_string()),
            status_str(agent.agent_status),
        ),
        None => ("No agents".to_string(), "idle"),
    };

    serde_json::json!({
        "headline": headline,
        "status": status,
        "needsYouCount": needs_you_count,
        "workingCount": working_count,
        "totalCount": agents.len(),
    })
}

#[cfg(test)]
mod live_activity_content_state_tests {
    use super::live_activity_content_state;
    use crate::api::schema::AgentInfo;

    fn agent(status: &str, name: Option<&str>) -> AgentInfo {
        let mut value = serde_json::json!({
            "terminal_id": "t",
            "agent_status": status,
            "workspace_id": "ws",
            "tab_id": "tab",
            "pane_id": "pane",
            "focused": false,
            "revision": 1,
        });
        if let Some(name) = name {
            value["name"] = serde_json::Value::String(name.to_string());
        }
        serde_json::from_value(value).expect("agent info deserializes")
    }

    #[test]
    fn empty_session_reports_no_agents_idle() {
        let cs = live_activity_content_state(&[]);
        assert_eq!(cs["headline"], "No agents");
        assert_eq!(cs["status"], "idle");
        assert_eq!(cs["totalCount"], 0);
        assert_eq!(cs["needsYouCount"], 0);
        assert_eq!(cs["workingCount"], 0);
    }

    #[test]
    fn blocked_leads_and_counts_are_reported() {
        // Blocked (needs you) outranks working and idle regardless of list order.
        let agents = [
            agent("working", Some("builder")),
            agent("blocked", Some("reviewer")),
            agent("idle", Some("idler")),
        ];
        let cs = live_activity_content_state(&agents);
        assert_eq!(cs["headline"], "reviewer");
        assert_eq!(cs["status"], "needsYou");
        assert_eq!(cs["needsYouCount"], 1);
        assert_eq!(cs["workingCount"], 1);
        assert_eq!(cs["totalCount"], 3);
    }

    #[test]
    fn working_leads_when_nothing_needs_you() {
        let agents = [agent("idle", Some("a")), agent("working", Some("b"))];
        let cs = live_activity_content_state(&agents);
        assert_eq!(cs["headline"], "b");
        assert_eq!(cs["status"], "working");
    }
}

/// Map a pane update to the push kind to deliver, if any.
///
/// A process exit (`from_pane_death`) is an event, not a state transition, so it
/// always yields `Died` — even when the toast predicate returned `None` because
/// the pane was already Idle when its process exited. Otherwise the push kind
/// follows the toast kind; `UpdateInstalled` and `None` are not agent
/// transitions and produce no push.
fn push_kind_for(from_pane_death: bool, kind: Option<ToastKind>) -> Option<crate::push::PushKind> {
    if from_pane_death {
        return Some(crate::push::PushKind::Died);
    }
    match kind {
        Some(ToastKind::NeedsAttention) => Some(crate::push::PushKind::NeedsInput),
        Some(ToastKind::Finished) => Some(crate::push::PushKind::Finished),
        Some(ToastKind::UpdateInstalled) | None => None,
    }
}

fn sanitized_notification_text(value: &str, max_chars: usize) -> Option<String> {
    let mut sanitized = String::new();
    let mut previous_space = false;
    for ch in value.chars() {
        let replacement = if ch == '\n' || ch == '\r' || ch == '\t' {
            Some(' ')
        } else if ch.is_control() {
            None
        } else {
            Some(ch)
        };
        let Some(ch) = replacement else {
            continue;
        };
        if ch.is_whitespace() {
            if previous_space {
                continue;
            }
            previous_space = true;
            sanitized.push(' ');
        } else {
            previous_space = false;
            sanitized.push(ch);
        }
        if sanitized.chars().count() >= max_chars {
            break;
        }
    }
    let sanitized = sanitized.trim().to_string();
    (!sanitized.is_empty()).then_some(sanitized)
}

fn agent_manifest_info(
    summary: crate::detect::manifest::AgentManifestSummary,
    update_status: &crate::detect::manifest_update::ManifestUpdateStatus,
) -> crate::api::schema::AgentManifestInfo {
    let remote = update_status.agent_status(summary.agent);
    crate::api::schema::AgentManifestInfo {
        agent: crate::detect::agent_label(summary.agent).to_string(),
        source: summary.active_source.label(),
        source_kind: summary.active_source.kind().to_string(),
        active_version: summary.active_version,
        cached_remote_version: summary.cached_remote_version,
        local_override_shadowing_remote: summary.local_override_shadowing_remote,
        remote_update_result: remote.as_ref().map(|status| status.last_result.clone()),
        remote_update_error: remote.as_ref().and_then(|status| status.last_error.clone()),
        remote_last_checked_unix: remote.and_then(|status| status.last_checked_unix),
        warning: summary.warning,
    }
}

#[cfg(test)]
pub(super) mod test_support {
    pub(crate) fn exiting_test_command() -> &'static str {
        #[cfg(windows)]
        {
            "C:\\Windows\\System32\\whoami.exe"
        }
        #[cfg(not(windows))]
        {
            "/usr/bin/true"
        }
    }

    pub(crate) fn shutdown_test_runtimes(app: &mut crate::app::App) {
        let runtimes: Vec<_> = app.terminal_runtimes.drain().collect();
        for (_terminal_id, runtime) in runtimes {
            runtime.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Agent, AgentState};

    #[test]
    fn push_kind_for_maps_events_and_transitions() {
        use crate::push::PushKind;

        // A process exit is an event: Died even when the toast predicate is None
        // (the idle-pane-exits case that would otherwise drop the notify_dies
        // push entirely).
        assert_eq!(push_kind_for(true, None), Some(PushKind::Died));
        assert_eq!(
            push_kind_for(true, Some(ToastKind::Finished)),
            Some(PushKind::Died)
        );

        // Otherwise the push kind follows the toast kind.
        assert_eq!(
            push_kind_for(false, Some(ToastKind::NeedsAttention)),
            Some(PushKind::NeedsInput)
        );
        assert_eq!(
            push_kind_for(false, Some(ToastKind::Finished)),
            Some(PushKind::Finished)
        );
        // UpdateInstalled and None are not agent transitions.
        assert_eq!(push_kind_for(false, Some(ToastKind::UpdateInstalled)), None);
        assert_eq!(push_kind_for(false, None), None);
    }

    #[test]
    fn apns_device_token_validation_bounds_and_hex() {
        let valid = "a".repeat(64);
        assert!(is_valid_apns_device_token(&valid));
        assert!(is_valid_apns_device_token(&"F0".repeat(16))); // upper hex, 32 chars
        assert!(!is_valid_apns_device_token("")); // empty
        assert!(!is_valid_apns_device_token(&"a".repeat(31))); // too short
        assert!(!is_valid_apns_device_token(&"a".repeat(201))); // too long
        assert!(!is_valid_apns_device_token(&"g".repeat(64))); // non-hex
        assert!(!is_valid_apns_device_token(&format!("{} ", "a".repeat(63)))); // whitespace
    }

    #[cfg(unix)]
    fn init_repo(path: &std::path::Path) {
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .unwrap();
        assert!(status.success(), "git init failed for {}", path.display());
    }

    fn app_with_overlay(
        workspace: crate::workspace::Workspace,
        overlay_pane: crate::layout::PaneId,
        previous_focus: crate::layout::PaneId,
        previous_zoomed: bool,
    ) -> App {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.state.active = Some(0);
        app.state.mode = Mode::Terminal;
        app.overlay_panes.insert(
            overlay_pane,
            OverlayPaneState {
                ws_idx: 0,
                tab_idx: 0,
                previous_focus,
                previous_zoomed,
                temp_files: Vec::new(),
            },
        );
        app
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn respawn_shell_caller_changes_turn_epoch() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("respawn")];
        app.state.ensure_test_terminals();
        app.state.default_shell = "/bin/sh".into();
        app.state.shell_mode = crate::config::ShellModeConfig::NonLogin;
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.terminal_id_for_pane(0, pane_id).unwrap();
        let previous_epoch = app.state.terminals[&terminal_id].turn_epoch;

        assert!(app.respawn_shell_for_launch_pane(pane_id));

        let respawn_epoch = app.state.terminals[&terminal_id].turn_epoch;
        assert_ne!(respawn_epoch, previous_epoch);
        assert_eq!(
            crate::terminal::state::turn_epoch_reset_path_for_test(respawn_epoch),
            crate::terminal::TurnCounterResetPath::PaneRespawn
        );
        if let Some(runtime) = app.terminal_runtimes.remove(&terminal_id) {
            runtime.shutdown();
        }
    }

    #[tokio::test]
    async fn manifest_update_event_resets_matching_agent_detection_runtime() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("manifest-reset")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .detected_agent = Some(Agent::Codex);
        let (runtime, _rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        let reset_notify = runtime.agent_detection_reset_notify_for_test();
        app.terminal_runtimes.insert(terminal_id, runtime);

        app.handle_internal_event(AppEvent::AgentDetectionManifestsUpdated {
            updated: vec![crate::detect::manifest_update::ManifestUpdateCommit {
                agent: Agent::Codex,
                version: crate::detect::manifest_update::ManifestVersion::parse("2026.06.10.1")
                    .unwrap(),
            }],
            status: crate::detect::manifest_update::ManifestUpdateStatus::default(),
        });

        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            reset_notify.notified(),
        )
        .await
        .expect("matching agent detection runtime should be reset");
    }

    #[tokio::test]
    async fn server_reload_agent_manifests_resets_detection_runtimes() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("manifest-reload")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let (runtime, _rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        let reset_notify = runtime.agent_detection_reset_notify_for_test();
        app.terminal_runtimes.insert(terminal_id, runtime);

        let response = app.handle_api_request(crate::api::schema::Request {
            id: "reload_manifests".into(),
            method: crate::api::schema::Method::ServerReloadAgentManifests(
                crate::api::schema::EmptyParams::default(),
            ),
        });
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["result"]["type"], "agent_manifest_reload");
        assert!(!response["result"]["manifests"]
            .as_array()
            .unwrap()
            .is_empty());

        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            reset_notify.notified(),
        )
        .await
        .expect("manual manifest reload should reset detection runtimes");
    }

    #[tokio::test]
    async fn server_agent_manifests_reports_status_without_resetting_runtimes() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("manifest-status")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let (runtime, _rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        let reset_notify = runtime.agent_detection_reset_notify_for_test();
        app.terminal_runtimes.insert(terminal_id, runtime);

        let response = app.handle_api_request(crate::api::schema::Request {
            id: "manifest_status".into(),
            method: crate::api::schema::Method::ServerAgentManifests(
                crate::api::schema::EmptyParams::default(),
            ),
        });
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["result"]["type"], "agent_manifest_status");
        assert!(!response["result"]["manifests"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                reset_notify.notified(),
            )
            .await
            .is_err(),
            "status request should not reset detection runtimes"
        );
    }

    #[tokio::test]
    async fn agent_explain_evaluates_with_server_manifest_cache() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("agent-explain")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .detected_agent = Some(Agent::Codex);
        let runtime = crate::terminal::TerminalRuntime::test_with_screen_bytes(
            80,
            24,
            b"press enter to confirm or esc to cancel",
        );
        app.terminal_runtimes.insert(terminal_id, runtime);
        let target = app.public_pane_id(0, pane_id).unwrap();

        let response = app.handle_api_request(crate::api::schema::Request {
            id: "agent_explain".into(),
            method: crate::api::schema::Method::AgentExplain(crate::api::schema::AgentTarget {
                target,
            }),
        });
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response["result"]["type"], "agent_explain");
        assert_eq!(response["result"]["explain"]["state"], "blocked");
        assert_eq!(
            response["result"]["explain"]["matched_rule"]["id"],
            "live_strong_blocker"
        );
    }

    #[tokio::test]
    async fn agent_explain_rejects_hook_only_full_lifecycle_authority() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("agent-explain-omp")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        app.state
            .terminals
            .get_mut(&terminal_id)
            .unwrap()
            .set_hook_authority(
                "herdr:omp".to_string(),
                "omp".to_string(),
                AgentState::Working,
                None,
                Some(1),
            );
        let runtime = crate::terminal::TerminalRuntime::test_with_screen_bytes(80, 24, b"");
        app.terminal_runtimes.insert(terminal_id, runtime);
        let target = app.public_pane_id(0, pane_id).unwrap();

        let response = app.handle_api_request(crate::api::schema::Request {
            id: "agent_explain_omp".into(),
            method: crate::api::schema::Method::AgentExplain(crate::api::schema::AgentTarget {
                target,
            }),
        });
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response["error"]["code"], "agent_not_found");
    }

    #[tokio::test]
    async fn pane_process_info_returns_response_for_existing_pane() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("process-info")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let (runtime, _rx) = crate::terminal::TerminalRuntime::test_with_channel(80, 24);
        app.terminal_runtimes.insert(terminal_id, runtime);
        let target = app.public_pane_id(0, pane_id).unwrap();

        let response = app.handle_api_request(crate::api::schema::Request {
            id: "process_info".into(),
            method: crate::api::schema::Method::PaneProcessInfo(
                crate::api::schema::PaneProcessInfoParams {
                    pane_id: Some(target.clone()),
                },
            ),
        });
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(response["result"]["type"], "pane_process_info");
        assert_eq!(response["result"]["process_info"]["pane_id"], target);
    }

    #[test]
    fn client_window_title_api_reports_no_foreground_client_in_app_mode() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );

        let set = app.handle_api_request(crate::api::schema::Request {
            id: "title_set".into(),
            method: crate::api::schema::Method::ClientWindowTitleSet(
                crate::api::schema::ClientWindowTitleSetParams {
                    title: "plugin review".into(),
                },
            ),
        });
        let set: serde_json::Value = serde_json::from_str(&set).unwrap();
        assert_eq!(set["result"]["type"], "client_window_title");
        assert_eq!(set["result"]["changed"], false);
        assert_eq!(set["result"]["reason"], "no_foreground_client");

        let clear = app.handle_api_request(crate::api::schema::Request {
            id: "title_clear".into(),
            method: crate::api::schema::Method::ClientWindowTitleClear(
                crate::api::schema::EmptyParams::default(),
            ),
        });
        let clear: serde_json::Value = serde_json::from_str(&clear).unwrap();
        assert_eq!(clear["result"]["type"], "client_window_title");
        assert_eq!(clear["result"]["reason"], "no_foreground_client");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn herdr_toast_context_uses_live_root_runtime_cwd_label() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );

        let mut workspace = crate::workspace::Workspace::test_new("stale");
        workspace.custom_name = None;
        let root = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(root).cloned().unwrap();
        let temp_root = std::env::temp_dir().join(format!(
            "herdr-toast-context-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let stale_cwd = temp_root.join("__herdr_original__");
        let live_cwd = temp_root.join("__herdr_projects__");
        std::fs::create_dir_all(&stale_cwd).unwrap();
        std::fs::create_dir_all(&live_cwd).unwrap();
        init_repo(&stale_cwd);
        init_repo(&live_cwd);

        workspace.identity_cwd = stale_cwd.clone();
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.state.terminals.get_mut(&terminal_id).unwrap().cwd = stale_cwd;
        app.state.active = None;
        app.state.selected = 0;
        app.state.mode = Mode::Terminal;
        app.state.toast_config.delivery = crate::config::ToastDelivery::Herdr;
        app.state.toast_config.delay_seconds = 0;

        let (events, _) = tokio::sync::mpsc::channel(4);
        let runtime = crate::terminal::TerminalRuntime::spawn(
            root,
            24,
            80,
            live_cwd.clone(),
            0,
            crate::terminal_theme::TerminalTheme::default(),
            crate::pane::PaneShellConfig::new("/bin/sh", crate::config::ShellModeConfig::NonLogin),
            &crate::pane::PaneLaunchEnv::default(),
            events,
            std::sync::Arc::new(tokio::sync::Notify::new()),
            std::sync::Arc::new(crate::render_signal::RenderSignal::new()),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while runtime.cwd() != Some(live_cwd.clone()) && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        app.terminal_runtimes.insert(terminal_id, runtime);

        app.handle_internal_event(AppEvent::StateChanged {
            pane_id: root,
            agent: Some(Agent::Codex),
            state: AgentState::Working,
            visible_blocker: false,
            visible_working: false,
            process_exited: false,
            observed_at: std::time::Instant::now(),
        });
        app.handle_internal_event(AppEvent::StateChanged {
            pane_id: root,
            agent: Some(Agent::Codex),
            state: AgentState::Idle,
            visible_blocker: false,
            visible_working: false,
            process_exited: false,
            observed_at: std::time::Instant::now(),
        });

        assert_eq!(
            app.state.toast.as_ref().map(|toast| toast.context.as_str()),
            Some("__herdr_projects__ · 1")
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delayed_herdr_toast_context_uses_live_root_runtime_cwd_label() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );

        let mut workspace = crate::workspace::Workspace::test_new("stale");
        workspace.custom_name = None;
        let root = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(root).cloned().unwrap();
        let temp_root = std::env::temp_dir().join(format!(
            "herdr-delayed-toast-context-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let stale_cwd = temp_root.join("__herdr_original__");
        let live_cwd = temp_root.join("__herdr_projects__");
        std::fs::create_dir_all(&stale_cwd).unwrap();
        std::fs::create_dir_all(&live_cwd).unwrap();
        init_repo(&stale_cwd);
        init_repo(&live_cwd);

        workspace.identity_cwd = stale_cwd.clone();
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.state.terminals.get_mut(&terminal_id).unwrap().cwd = stale_cwd;
        app.state.active = None;
        app.state.selected = 0;
        app.state.mode = Mode::Terminal;
        app.state.toast_config.delivery = crate::config::ToastDelivery::Herdr;
        app.state.toast_config.delay_seconds = 1;

        let (events, _) = tokio::sync::mpsc::channel(4);
        let runtime = crate::terminal::TerminalRuntime::spawn(
            root,
            24,
            80,
            live_cwd.clone(),
            0,
            crate::terminal_theme::TerminalTheme::default(),
            crate::pane::PaneShellConfig::new("/bin/sh", crate::config::ShellModeConfig::NonLogin),
            &crate::pane::PaneLaunchEnv::default(),
            events,
            std::sync::Arc::new(tokio::sync::Notify::new()),
            std::sync::Arc::new(crate::render_signal::RenderSignal::new()),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while runtime.cwd() != Some(live_cwd.clone()) && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        app.terminal_runtimes.insert(terminal_id, runtime);

        app.handle_internal_event(AppEvent::StateChanged {
            pane_id: root,
            agent: Some(Agent::Codex),
            state: AgentState::Working,
            visible_blocker: false,
            visible_working: false,
            process_exited: false,
            observed_at: std::time::Instant::now(),
        });
        app.handle_internal_event(AppEvent::StateChanged {
            pane_id: root,
            agent: Some(Agent::Codex),
            state: AgentState::Idle,
            visible_blocker: false,
            visible_working: false,
            process_exited: false,
            observed_at: std::time::Instant::now(),
        });

        let notification_deadline = app
            .state
            .next_pending_agent_notification_deadline()
            .expect("pending notification deadline");
        assert!(app.handle_scheduled_tasks(notification_deadline, false));
        assert_eq!(
            app.state.toast.as_ref().map(|toast| toast.context.as_str()),
            Some("__herdr_projects__ · 1")
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn overlay_exit_preserves_focus_changed_before_exit() {
        let mut workspace = crate::workspace::Workspace::test_new("overlay");
        let previous_focus = workspace.tabs[0].root_pane;
        let overlay_pane = workspace.test_split(ratatui::layout::Direction::Horizontal);
        workspace.tabs[0].zoomed = true;
        let new_tab = workspace.test_add_tab(Some("new"));
        workspace.switch_tab(new_tab);
        let mut app = app_with_overlay(workspace, overlay_pane, previous_focus, true);

        app.handle_internal_event(AppEvent::PaneDied {
            pane_id: overlay_pane,
        });

        let overlay_tab = &app.state.workspaces[0].tabs[0];
        assert_eq!(app.state.workspaces[0].active_tab, new_tab);
        assert_eq!(overlay_tab.layout.focused(), previous_focus);
        assert!(overlay_tab.zoomed);
        assert!(app.overlay_panes.is_empty());
    }

    #[test]
    fn pane_exit_emits_layout_updated_when_tab_survives() {
        let event_hub = crate::api::EventHub::default();
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            event_hub.clone(),
        );
        let mut workspace = crate::workspace::Workspace::test_new("pane-exit-layout");
        let dead_pane = workspace.test_split(ratatui::layout::Direction::Horizontal);
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        let tab_id = app.public_tab_id(0, 0).unwrap();

        app.handle_internal_event(AppEvent::PaneDied { pane_id: dead_pane });

        let events = event_hub.events_after(0);
        let pane_exited = events
            .iter()
            .position(|(_, event)| event.event == crate::api::schema::EventKind::PaneExited)
            .expect("pane.exited should be emitted");
        let layout_updated = events
            .iter()
            .position(|(_, event)| event.event == crate::api::schema::EventKind::LayoutUpdated)
            .expect("layout.updated should be emitted");
        assert!(pane_exited < layout_updated);
        assert!(matches!(
            &events[layout_updated].1.data,
            crate::api::schema::EventData::LayoutUpdated { layout }
                if layout.tab_id == tab_id && layout.panes.len() == 1
        ));
    }

    #[test]
    fn idle_agent_exit_emits_release_event_without_a_state_change() {
        for agent_name in [None, Some("reviewer")] {
            let event_hub = crate::api::EventHub::default();
            let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut app = App::new(
                &crate::config::Config::default(),
                true,
                None,
                api_rx,
                event_hub.clone(),
            );
            let workspace = crate::workspace::Workspace::test_new("idle-agent-exit");
            let pane_id = workspace.tabs[0].root_pane;
            let terminal_id = workspace.terminal_id(pane_id).cloned().unwrap();
            app.state.workspaces = vec![workspace];
            app.state.ensure_test_terminals();
            let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
            terminal.set_detected_state(Some(Agent::Pi), AgentState::Idle);
            if let Some(agent_name) = agent_name {
                terminal.set_agent_name(agent_name.into());
            }

            app.handle_internal_event(AppEvent::StateChanged {
                pane_id,
                agent: Some(Agent::Pi),
                state: AgentState::Idle,
                visible_blocker: false,
                visible_working: false,
                process_exited: true,
                observed_at: std::time::Instant::now(),
            });

            assert!(app.state.terminals[&terminal_id].agent_name.is_none());
            assert!(event_hub.events_after(0).iter().any(|(_, event)| matches!(
                &event.data,
                crate::api::schema::EventData::PaneAgentDetected {
                    released: true,
                    final_status: Some(crate::api::schema::AgentStatus::Idle),
                    ..
                }
            )));
        }
    }

    #[test]
    fn process_exit_releases_a_newer_hook_owned_agent() {
        let event_hub = crate::api::EventHub::default();
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            event_hub.clone(),
        );
        let workspace = crate::workspace::Workspace::test_new("stale-agent-exit");
        let pane_id = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(pane_id).cloned().unwrap();
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        let observed_at = std::time::Instant::now();
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        terminal.set_detected_state(Some(Agent::Codex), AgentState::Working);
        terminal
            .set_hook_authority_at(
                "herdr:codex".into(),
                "codex".into(),
                AgentState::Working,
                None,
                None,
                Some(1),
                observed_at + std::time::Duration::from_secs(1),
            )
            .unwrap();
        terminal.set_agent_name("reviewer".into());

        app.handle_internal_event(AppEvent::StateChanged {
            pane_id,
            agent: Some(Agent::Codex),
            state: AgentState::Idle,
            visible_blocker: false,
            visible_working: false,
            process_exited: true,
            observed_at,
        });

        let terminal = &app.state.terminals[&terminal_id];
        assert_eq!(terminal.state, AgentState::Idle);
        assert!(terminal.agent_name.is_none());
        assert!(event_hub.events_after(0).iter().any(|(_, event)| matches!(
            event.data,
            crate::api::schema::EventData::PaneAgentDetected { released: true, .. }
        )));
    }

    #[test]
    fn overlay_exit_layout_updated_uses_restored_zoom_state() {
        let event_hub = crate::api::EventHub::default();
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            event_hub.clone(),
        );
        let mut workspace = crate::workspace::Workspace::test_new("overlay-layout");
        let previous_focus = workspace.tabs[0].root_pane;
        let overlay_pane = workspace.test_split(ratatui::layout::Direction::Horizontal);
        workspace.tabs[0].layout.focus_pane(previous_focus);
        workspace.tabs[0].zoomed = true;
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.state.active = Some(0);
        app.state.mode = Mode::Terminal;
        let tab_id = app.public_tab_id(0, 0).unwrap();
        app.overlay_panes.insert(
            overlay_pane,
            OverlayPaneState {
                ws_idx: 0,
                tab_idx: 0,
                previous_focus,
                previous_zoomed: false,
                temp_files: Vec::new(),
            },
        );

        app.handle_internal_event(AppEvent::PaneDied {
            pane_id: overlay_pane,
        });

        let events = event_hub.events_after(0);
        let layout_updated = events
            .iter()
            .rposition(|(_, event)| event.event == crate::api::schema::EventKind::LayoutUpdated)
            .expect("layout.updated should be emitted");
        assert!(matches!(
            &events[layout_updated].1.data,
            crate::api::schema::EventData::LayoutUpdated { layout }
                if layout.tab_id == tab_id && layout.zoomed
        ));
    }

    #[test]
    fn overlay_exit_preserves_same_tab_focus_changed_before_exit() {
        let mut workspace = crate::workspace::Workspace::test_new("overlay");
        let previous_focus = workspace.tabs[0].root_pane;
        let overlay_pane = workspace.test_split(ratatui::layout::Direction::Horizontal);
        workspace.tabs[0].layout.focus_pane(previous_focus);
        workspace.tabs[0].zoomed = true;
        let mut app = app_with_overlay(workspace, overlay_pane, previous_focus, false);

        app.handle_internal_event(AppEvent::PaneDied {
            pane_id: overlay_pane,
        });

        let tab = &app.state.workspaces[0].tabs[0];
        assert_eq!(app.state.workspaces[0].active_tab, 0);
        assert_eq!(tab.layout.focused(), previous_focus);
        assert!(tab.zoomed);
        assert!(app.overlay_panes.is_empty());
    }

    #[test]
    fn overlay_exit_restores_previous_focus_when_overlay_still_focused() {
        let mut workspace = crate::workspace::Workspace::test_new("overlay");
        let previous_focus = workspace.tabs[0].root_pane;
        let overlay_pane = workspace.test_split(ratatui::layout::Direction::Horizontal);
        workspace.tabs[0].zoomed = true;
        let mut app = app_with_overlay(workspace, overlay_pane, previous_focus, false);

        app.handle_internal_event(AppEvent::PaneDied {
            pane_id: overlay_pane,
        });

        let tab = &app.state.workspaces[0].tabs[0];
        assert_eq!(app.state.workspaces[0].active_tab, 0);
        assert_eq!(tab.layout.focused(), previous_focus);
        assert!(!tab.zoomed);
        assert!(app.overlay_panes.is_empty());
    }

    #[tokio::test]
    async fn pane_died_respawns_shell_and_clears_restored_agent_session() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        let workspace = crate::workspace::Workspace::test_new("restored");
        let pane_id = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(pane_id).cloned().unwrap();
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        let terminal = app
            .state
            .terminals
            .get_mut(&terminal_id)
            .expect("test terminal should exist");
        terminal.respawn_shell_on_exit = true;
        terminal.set_agent_name("codex".into());
        terminal.set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
            source: "herdr:codex".into(),
            agent: "codex".into(),
            session_ref: crate::agent_resume::AgentSessionRef::id("codex-session")
                .expect("test session id should be valid"),
        });

        app.handle_internal_event(AppEvent::PaneDied { pane_id });

        assert!(
            app.find_pane(pane_id).is_some(),
            "respawnable agent pane should stay attached after the agent process exits"
        );
        let terminal = app
            .state
            .terminals
            .get(&terminal_id)
            .expect("terminal should survive respawn");
        assert!(!terminal.respawn_shell_on_exit);
        assert!(terminal.persisted_agent_session.is_none());
        assert!(terminal.agent_name.is_none());

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_powershell_exit_after_agent_process_exit_respawns_shell() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        let workspace = crate::workspace::Workspace::test_new("powershell");
        let pane_id = workspace.tabs[0].root_pane;
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.state.default_shell = "powershell.exe".into();
        app.state.shell_mode = crate::config::ShellModeConfig::NonLogin;

        app.handle_internal_event(AppEvent::StateChanged {
            pane_id,
            agent: Some(crate::detect::Agent::OpenCode),
            state: AgentState::Idle,
            visible_blocker: false,
            visible_working: false,
            process_exited: true,
            observed_at: std::time::Instant::now(),
        });

        assert_eq!(
            app.runtime_exit_action(pane_id),
            RuntimeExitAction::RespawnShell
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_powershell_exit_without_recent_agent_process_exit_closes_pane() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        let workspace = crate::workspace::Workspace::test_new("powershell");
        let pane_id = workspace.tabs[0].root_pane;
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.state.default_shell = "powershell.exe".into();
        app.state.shell_mode = crate::config::ShellModeConfig::NonLogin;

        assert_eq!(
            app.runtime_exit_action(pane_id),
            RuntimeExitAction::ClosePane
        );
    }

    #[test]
    fn terminal_delivery_does_not_refresh_existing_targeted_toast() {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );
        app.local_terminal_notifications = false;

        let mut workspace = crate::workspace::Workspace::test_new("stale");
        workspace.custom_name = None;
        workspace.identity_cwd = "/__herdr_original__".into();
        let root = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(root).cloned().unwrap();
        let workspace_id = workspace.id.clone();
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.state.terminals.get_mut(&terminal_id).unwrap().cwd = "/__herdr_projects__".into();
        app.state.active = None;
        app.state.selected = 0;
        app.state.mode = Mode::Terminal;
        app.state.toast_config.delivery = crate::config::ToastDelivery::Terminal;

        app.handle_internal_event(AppEvent::StateChanged {
            pane_id: root,
            agent: Some(Agent::Codex),
            state: AgentState::Working,
            visible_blocker: false,
            visible_working: false,
            process_exited: false,
            observed_at: std::time::Instant::now(),
        });
        app.state.toast = Some(crate::app::state::ToastNotification {
            kind: ToastKind::Finished,
            title: "codex finished".into(),
            context: "__herdr_original__ · 1".into(),
            position: None,
            target: Some(crate::app::state::ToastTarget {
                workspace_id,
                pane_id: root,
            }),
        });

        app.handle_internal_event(AppEvent::StateChanged {
            pane_id: root,
            agent: Some(Agent::Codex),
            state: AgentState::Idle,
            visible_blocker: false,
            visible_working: false,
            process_exited: false,
            observed_at: std::time::Instant::now(),
        });

        assert_eq!(
            app.state.toast.as_ref().map(|toast| toast.context.as_str()),
            Some("__herdr_original__ · 1")
        );
    }

    #[test]
    fn input_only_change_emits_status_event_without_changing_lifecycle_sequence() {
        let event_hub = crate::api::EventHub::default();
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            event_hub.clone(),
        );
        let workspace = crate::workspace::Workspace::test_new("input");
        let pane_id = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(pane_id).cloned().unwrap();
        app.state.workspaces = vec![workspace];
        app.state.ensure_test_terminals();
        app.handle_internal_event(AppEvent::StateChanged {
            pane_id,
            agent: Some(Agent::Kimi),
            state: AgentState::Working,
            visible_blocker: false,
            visible_working: true,
            process_exited: false,
            observed_at: std::time::Instant::now(),
        });
        let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
        let session_ref = crate::agent_resume::AgentSessionRef::id("kimi-session")
            .expect("test session id should be valid");
        terminal
            .set_agent_session_ref_for_session_start(
                "herdr:kimi".to_string(),
                "kimi".to_string(),
                Some(session_ref.clone()),
                Some(1),
                Some("startup".to_string()),
            )
            .expect("session start should anchor full-lifecycle authority");
        terminal
            .set_hook_authority_with_session_ref(
                "herdr:kimi".to_string(),
                "kimi".to_string(),
                AgentState::Working,
                None,
                Some(session_ref),
                Some(2),
            )
            .expect("anchored hook report should be accepted");
        let baseline_sequence = app.state.terminals[&terminal_id].last_agent_state_change_seq;
        let baseline_event_sequence = event_hub.current_sequence();

        app.handle_internal_event(AppEvent::InputStateChanged {
            pane_id,
            kind: Some(crate::detect::InputPromptKind::Select),
        });

        let terminal = &app.state.terminals[&terminal_id];
        assert!(terminal.full_lifecycle_hook_authority_active());
        assert_eq!(terminal.state, AgentState::Working);
        assert_eq!(terminal.last_agent_state_change_seq, baseline_sequence);
        assert!(terminal.input_pending);
        assert_eq!(
            terminal.input_prompt_kind,
            Some(crate::detect::InputPromptKind::Select)
        );
        let pane = app.pane_info(0, pane_id).expect("pane info");
        assert!(pane.input_pending);
        assert_eq!(
            pane.input_prompt_kind,
            Some(crate::detect::InputPromptKind::Select)
        );
        let agent = app.agent_info(0, pane_id).expect("agent info");
        assert!(agent.input_pending);
        assert_eq!(
            agent.input_prompt_kind,
            Some(crate::detect::InputPromptKind::Select)
        );
        let events = event_hub.events_after(baseline_event_sequence);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].1.data,
            crate::api::schema::EventData::PaneAgentStatusChanged {
                agent_status: crate::api::schema::AgentStatus::Working,
                input_pending: true,
                input_prompt_kind: Some(crate::detect::InputPromptKind::Select),
                ..
            }
        ));

        app.handle_internal_event(AppEvent::InputStateChanged {
            pane_id,
            kind: None,
        });
        let terminal = &app.state.terminals[&terminal_id];
        assert!(terminal.full_lifecycle_hook_authority_active());
        assert_eq!(terminal.last_agent_state_change_seq, baseline_sequence);
        assert!(!terminal.input_pending);
        assert_eq!(terminal.input_prompt_kind, None);
    }
}
