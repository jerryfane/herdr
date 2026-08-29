use std::time::Instant;

use bytes::Bytes;
use ratatui::layout::Rect;

use super::App;

struct PendingAgentResumeCandidate {
    pane_id: crate::layout::PaneId,
    terminal_id: crate::terminal::TerminalId,
    cwd: std::path::PathBuf,
    plan: crate::agent_resume::AgentResumePlan,
    rows: u16,
    cols: u16,
}

/// What environment a resumed agent should launch with — or that it must NOT launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResumeLaunchEnv {
    /// Launch with this account env. Fully empty means the harness default, which is
    /// correct for a pane that never selected an account. Note a SELECTED account can
    /// carry an empty override set and a non-empty clear-list — see
    /// [`crate::config::AccountLaunchEnv`].
    Ready(crate::config::AccountLaunchEnv),
    /// The pane RECORDED an account that no longer resolves — removed from the registry,
    /// renamed, or its config-home gone.
    ///
    /// This must not fall back to the default. Falling back is precisely the incident: a
    /// seat switched to a secondary account came back on the primary and appended to the
    /// PRIMARY transcript, and the owner experienced that as one to two hours of history
    /// disappearing while the records sat intact in the other account's file.
    ///
    /// Between "never leave a pane unlaunchable" and "never write to the wrong transcript",
    /// the second wins: an unlaunched agent is visible and recoverable, whereas a divergent
    /// transcript branch is silent, is discovered late, and costs a manual reconstruction.
    Unresolvable { account_id: String },
}

impl App {
    pub(crate) fn has_pending_agent_resumes(&self) -> bool {
        self.state
            .terminals
            .values()
            .any(|terminal| terminal.pending_agent_resume_plan.is_some())
    }

    pub(crate) fn sync_pending_agent_resume_deadline(&mut self, now: Instant) {
        if !self.has_pending_agent_resumes() {
            self.pending_agent_resume_deadline = None;
            return;
        }
        if self.pending_agent_resume_candidates().is_empty() {
            self.pending_agent_resume_deadline = None;
            return;
        }
        self.pending_agent_resume_deadline
            .get_or_insert(now + super::PENDING_AGENT_RESUME_THEME_WAIT);
    }

    pub(crate) fn pending_agent_resume_due(&self, now: Instant) -> bool {
        self.pending_agent_resume_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    pub(crate) fn start_pending_agent_resumes(&mut self, allow_empty_theme: bool) -> bool {
        let pending = self.pending_agent_resume_candidates();
        let mut changed = false;
        for PendingAgentResumeCandidate {
            pane_id,
            terminal_id,
            cwd,
            plan,
            rows,
            cols,
        } in pending
        {
            if self.terminal_runtimes.get(&terminal_id).is_some() {
                continue;
            }
            changed |= self.start_pending_agent_resume(
                pane_id,
                terminal_id,
                cwd,
                plan,
                rows,
                cols,
                allow_empty_theme,
            );
        }

        if changed {
            self.schedule_session_save();
        }
        if !self.has_pending_agent_resumes() || self.pending_agent_resume_candidates().is_empty() {
            self.pending_agent_resume_deadline = None;
        }
        changed
    }

    fn pending_agent_resume_candidates(&self) -> Vec<PendingAgentResumeCandidate> {
        let terminal_area = self.state.view.terminal_area;
        if terminal_area.width == 0 || terminal_area.height == 0 {
            return Vec::new();
        };

        let mut pending = Vec::new();
        for (ws_idx, ws) in self.state.workspaces.iter().enumerate() {
            for (tab_idx, tab) in ws.tabs.iter().enumerate() {
                for info in
                    self.pending_agent_resume_pane_infos(ws_idx, tab_idx, tab, terminal_area)
                {
                    let Some(pane) = tab.panes.get(&info.id) else {
                        continue;
                    };
                    if self
                        .terminal_runtimes
                        .get(&pane.attached_terminal_id)
                        .is_some()
                    {
                        continue;
                    }
                    let Some(terminal) = self.state.terminals.get(&pane.attached_terminal_id)
                    else {
                        continue;
                    };
                    let Some(plan) = terminal.pending_agent_resume_plan.clone() else {
                        continue;
                    };
                    // Already refused: its account does not resolve. Retrying would only
                    // re-refuse and re-log. Cleared when the accounts registry reloads.
                    if terminal.account_resume_blocked.is_some() {
                        continue;
                    }
                    pending.push(PendingAgentResumeCandidate {
                        pane_id: info.id,
                        terminal_id: pane.attached_terminal_id.clone(),
                        cwd: terminal.cwd.clone(),
                        plan,
                        rows: info.inner_rect.height,
                        cols: info.inner_rect.width,
                    });
                }
            }
        }
        pending
    }

    fn pending_agent_resume_pane_infos(
        &self,
        ws_idx: usize,
        tab_idx: usize,
        tab: &crate::workspace::Tab,
        terminal_area: Rect,
    ) -> Vec<crate::layout::PaneInfo> {
        let mut pane_infos = derived_pending_agent_resume_pane_infos(
            tab,
            terminal_area,
            self.state.pane_borders,
            self.state.pane_gaps,
            self.state.pane_outer_borders,
        );

        if self.state.active == Some(ws_idx)
            && self
                .state
                .workspaces
                .get(ws_idx)
                .is_some_and(|ws| tab_idx == ws.active_tab_index())
        {
            for visible_info in &self.state.view.pane_infos {
                if let Some(info) = pane_infos
                    .iter_mut()
                    .find(|info| info.id == visible_info.id)
                {
                    *info = visible_info.clone();
                } else {
                    pane_infos.push(visible_info.clone());
                }
            }
        }

        pane_infos
    }

    pub(crate) fn start_pending_agent_resume_for_terminal(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        rows: u16,
        cols: u16,
        allow_empty_theme: bool,
    ) -> bool {
        if self.terminal_runtimes.get(terminal_id).is_some() {
            return false;
        }
        let Some((pane_id, cwd, plan)) = self.state.workspaces.iter().find_map(|ws| {
            ws.tabs.iter().find_map(|tab| {
                tab.layout.pane_ids().into_iter().find_map(|pane_id| {
                    let pane = tab.panes.get(&pane_id)?;
                    if &pane.attached_terminal_id != terminal_id {
                        return None;
                    }
                    let terminal = self.state.terminals.get(terminal_id)?;
                    Some((
                        pane_id,
                        terminal.cwd.clone(),
                        terminal.pending_agent_resume_plan.clone()?,
                    ))
                })
            })
        }) else {
            return false;
        };

        let changed = self.start_pending_agent_resume(
            pane_id,
            terminal_id.clone(),
            cwd,
            plan,
            rows,
            cols,
            allow_empty_theme,
        );
        if changed {
            self.schedule_session_save();
        }
        if !self.has_pending_agent_resumes() {
            self.pending_agent_resume_deadline = None;
        }
        changed
    }

    /// The child environment a resumed agent must launch with: the env armed by
    /// `agent.restart`, or — when nothing is armed — one REBUILT from the account registry
    /// for the account this terminal belongs to.
    ///
    /// The rebuild is the part that matters. "Nothing armed" is the normal state after any
    /// restart, crash or staged update, and it used to mean the agent resumed under the
    /// harness DEFAULT. A seat switched to a secondary account then silently began
    /// appending to the PRIMARY transcript — which reads as hours of work vanishing, while
    /// the records sit intact in the other account's file.
    ///
    /// Only the account ID is persisted, so the config-home is resolved here against the
    /// live registry: a rotated config-home follows the registry, and no credential material
    /// is ever written to a snapshot. An id that no longer resolves yields an empty env,
    /// i.e. the pre-existing default behaviour rather than a failure.
    ///
    /// The returned env carries the config-home var, and `apply_pane_launch_env` clears the
    /// conflicting global auth token whenever it sees one — so routing cannot be overridden
    /// by a machine-global `CLAUDE_CODE_OAUTH_TOKEN`.
    pub(crate) fn resume_launch_env(
        &self,
        terminal_id: &crate::terminal::TerminalId,
        agent_kind: &str,
    ) -> ResumeLaunchEnv {
        let Some(terminal) = self.state.terminals.get(terminal_id) else {
            return ResumeLaunchEnv::Ready(crate::config::AccountLaunchEnv::unselected());
        };
        if !terminal.pending_launch_env.is_empty() {
            return ResumeLaunchEnv::Ready(crate::config::AccountLaunchEnv::from_resolved_vars(
                terminal.pending_launch_env.clone(),
            ));
        }
        let Some(account_id) = terminal.agent_account.as_deref() else {
            // No account was ever selected for this pane: the harness default is correct,
            // and this is the pre-existing behaviour, unchanged.
            return ResumeLaunchEnv::Ready(crate::config::AccountLaunchEnv::unselected());
        };
        match self.resolve_account_launch_env(account_id, agent_kind) {
            Ok(env) => ResumeLaunchEnv::Ready(env),
            // A pane that RECORDED an account and cannot resolve it must not come back on
            // the default one. See `ResumeLaunchEnv::Unresolvable`.
            Err(_) => ResumeLaunchEnv::Unresolvable {
                account_id: account_id.to_string(),
            },
        }
    }

    fn start_pending_agent_resume(
        &mut self,
        pane_id: crate::layout::PaneId,
        terminal_id: crate::terminal::TerminalId,
        cwd: std::path::PathBuf,
        plan: crate::agent_resume::AgentResumePlan,
        rows: u16,
        cols: u16,
        allow_empty_theme: bool,
    ) -> bool {
        let host_terminal_theme = self.state.host_terminal_theme;
        if host_terminal_theme.is_empty() && !allow_empty_theme {
            return false;
        }

        let Some(resume_command) = shell_command_from_argv(&plan.argv) else {
            tracing::warn!(
                pane = pane_id.raw(),
                terminal = %terminal_id,
                agent = %plan.agent,
                "failed to start deferred agent resume with empty argv"
            );
            return false;
        };
        // Carry the account config-home env armed by `agent.restart`, and REBUILD it from
        // the account registry when it is absent.
        //
        // "Empty for a plain restore" used to be the whole story, and it is exactly how a
        // fleet loses its account routing: a restart, crash or staged update rebuilds panes
        // from the snapshot with no armed env, every agent resumes under the harness
        // default, and a seat that had been switched to a secondary account silently starts
        // appending to the PRIMARY transcript. That reads as hours of work vanishing when
        // the records are intact in the other account's file.
        //
        // The snapshot persists the account ID only, so the env is resolved HERE, from the
        // live registry — a rotated config-home follows the registry, and no credential
        // material is ever written to disk by us.
        //
        // AND IF THE RECORDED ACCOUNT NO LONGER RESOLVES, THE AGENT DOES NOT COME BACK AT
        // ALL. Resuming it on the default account is what wrote hours of work into the
        // wrong transcript; refusing leaves a shell the operator can see and fix.
        let extra_env = match self.resume_launch_env(&terminal_id, &plan.agent) {
            ResumeLaunchEnv::Ready(env) => env,
            ResumeLaunchEnv::Unresolvable { account_id } => {
                tracing::error!(
                    event = "agent.account_routing",
                    subsystem = "agents",
                    outcome = "refused_unresolved_account",
                    pane = pane_id.raw(),
                    terminal = %terminal_id,
                    account = %account_id,
                    session = %plan.argv.last().map(String::as_str).unwrap_or(""),
                    "refusing to resume: this pane's account no longer resolves, and resuming \
                     it on the default account would append to the wrong transcript"
                );
                // Record the refusal and stop retrying. The resume PLAN is deliberately
                // kept, so re-registering the account brings the agent back; without this
                // marker the pane stays a candidate and re-refuses on every tick, logging
                // an error each time and never becoming visible as a distinct state.
                if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
                    terminal.account_resume_blocked = Some(account_id);
                }
                return false;
            }
        };
        // Capture what we are about to apply, for the per-pane routing report below.
        // Read from the RECORDED account, never inferred from the env: an empty override
        // set means "this account needs no override", not "no account".
        let routed_account = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.agent_account.clone());
        let routed_config_dir = extra_env
            .vars
            .iter()
            .find(|(key, _)| crate::config::kind_for_config_env_var(key).is_some())
            .map(|(_, value)| value.clone());
        let cleared_conflicting_auth = !extra_env.clear_vars.is_empty();

        let Some(launch_env) = self
            .find_pane(pane_id)
            .and_then(|(ws_idx, _)| self.pane_launch_env(ws_idx, pane_id, extra_env))
        else {
            return false;
        };

        let runtime = match crate::terminal::TerminalRuntime::spawn(
            pane_id,
            rows,
            cols,
            cwd,
            self.state.pane_scrollback_limit_bytes,
            host_terminal_theme,
            self.state.host_terminal_appearance,
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
                    agent = %plan.agent,
                    err = %err,
                    "failed to start shell for deferred agent resume"
                );
                if self.begin_agent_session_transfer_rollback(
                    &terminal_id,
                    format!("could not launch the target harness shell: {err}"),
                ) {
                    return self.resume_pending_agent_for_pane(pane_id);
                }
                if self.fail_agent_session_transfer_rollback_launch(
                    &terminal_id,
                    format!("could not launch the source harness shell: {err}"),
                ) {
                    return false;
                }
                if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
                    terminal.clear_agent_runtime_identity_after_respawn();
                }
                return false;
            }
        };

        let mut input = resume_command;
        input.push('\r');
        if let Err(err) = runtime.try_send_bytes(Bytes::from(input)) {
            tracing::warn!(
                pane = pane_id.raw(),
                terminal = %terminal_id,
                agent = %plan.agent,
                err = %err,
                "failed to send deferred agent resume command to shell"
            );
            runtime.shutdown();
            if self.begin_agent_session_transfer_rollback(
                &terminal_id,
                format!("could not submit the target harness resume command: {err}"),
            ) {
                return self.resume_pending_agent_for_pane(pane_id);
            }
            if self.fail_agent_session_transfer_rollback_launch(
                &terminal_id,
                format!("could not submit the source harness resume command: {err}"),
            ) {
                return false;
            }
            return false;
        }

        self.terminal_runtimes.insert(terminal_id.clone(), runtime);
        if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
            terminal.pending_agent_resume_plan = None;
            terminal.pending_launch_env.clear();
            terminal.respawn_shell_on_exit = false;
            terminal.account_resume_blocked = None;
        }
        self.mark_session_transfer_runtime_launched(&terminal_id, &plan.agent);
        // Say which account this pane actually came back on. Emitted AFTER the runtime is
        // inserted, so it reports what launched rather than what was intended.
        crate::logging::agent_account_routing(
            pane_id.raw(),
            &terminal_id.to_string(),
            routed_account.as_deref(),
            routed_config_dir.as_deref(),
            cleared_conflicting_auth,
        );
        true
    }
}

fn derived_pending_agent_resume_pane_infos(
    tab: &crate::workspace::Tab,
    terminal_area: Rect,
    pane_borders: bool,
    pane_gaps: bool,
    pane_outer_borders: bool,
) -> Vec<crate::layout::PaneInfo> {
    crate::ui::apply_pane_chrome(
        tab.layout.panes(terminal_area),
        pane_borders,
        pane_gaps,
        pane_outer_borders,
    )
    .into_iter()
    .map(|mut info| {
        let pane_inner = crate::ui::pane_inner_rect(info.rect, info.borders);
        info.inner_rect = stable_terminal_inner_rect(pane_inner);
        info
    })
    .collect()
}

fn stable_terminal_inner_rect(pane_inner: Rect) -> Rect {
    if pane_inner.width <= 4 {
        return pane_inner;
    }

    Rect::new(
        pane_inner.x,
        pane_inner.y,
        pane_inner.width.saturating_sub(1),
        pane_inner.height,
    )
}

fn shell_command_from_argv(argv: &[String]) -> Option<String> {
    let mut parts = argv.iter();
    let first = shell_quote(parts.next()?);
    let mut command = first;
    for part in parts {
        command.push(' ');
        command.push_str(&shell_quote(part));
    }
    Some(command)
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'%' | b'+' | b'='
            )
    }) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOT `#[cfg(unix)]`: the PTY-spawning tests below are unix-only, but constructing an
    // `App` is portable (see `app_with_agent` in api/agents.rs, which is ungated). The
    // account-routing tests need this on every platform — the routing logic they cover is
    // not unix-specific, and gating them would drop Windows coverage of the exact bug that
    // sent a fleet's work to the wrong account.
    fn test_app() -> App {
        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        )
    }

    #[cfg(unix)]
    fn long_running_test_argv() -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), "sleep 5".into()]
    }

    #[cfg(unix)]
    fn marker_resume_test_argv() -> Vec<String> {
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s' 'restored agent: shell quoted | marker'; sleep 5".into(),
        ]
    }

    /// A resumed agent must launch under ITS OWN account, rebuilt from the registry.
    ///
    /// The armed env is only present right after `agent.restart`. Every other path —
    /// ordinary restore, crash recovery, staged update, pane respawn — has nothing armed,
    /// and that used to mean the agent resumed under the harness DEFAULT. A seat switched
    /// to a secondary account then silently appended to the PRIMARY transcript, which is
    /// what made hours of work look lost while the records sat intact elsewhere.
    #[test]
    fn a_resumed_agent_launches_under_its_own_account() {
        let mut app = test_app();
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("agent")];
        app.state.ensure_test_terminals();
        app.loaded_accounts = vec![crate::config::AccountConfig {
            id: "claudecrazy".into(),
            kind: "claude".into(),
            label: "ClaudeCrazy".into(),
            config_dir: "/root/.claude-9".into(),
        }];
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();

        // Nothing armed and no account: the pre-existing default, unchanged.
        assert_eq!(
            app.resume_launch_env(&terminal_id, "claude"),
            ResumeLaunchEnv::Ready(crate::config::AccountLaunchEnv::unselected())
        );

        // Nothing armed, but the pane belongs to an account — rebuild from the registry.
        app.state
            .terminals
            .get_mut(&terminal_id)
            .expect("terminal")
            .agent_account = Some("claudecrazy".to_string());
        assert_eq!(
            app.resume_launch_env(&terminal_id, "claude"),
            ResumeLaunchEnv::Ready(crate::config::AccountLaunchEnv {
                vars: vec![(
                    "CLAUDE_CONFIG_DIR".to_string(),
                    "/root/.claude-9".to_string()
                )],
                clear_vars: vec!["CLAUDE_CODE_OAUTH_TOKEN".to_string()],
            }),
            "a resumed agent must be pointed at its own config-home, not the default"
        );

        // An armed env still wins — `agent.restart` is choosing deliberately.
        app.state
            .terminals
            .get_mut(&terminal_id)
            .expect("terminal")
            .pending_launch_env = vec![("CLAUDE_CONFIG_DIR".to_string(), "/armed".to_string())];
        assert_eq!(
            app.resume_launch_env(&terminal_id, "claude"),
            ResumeLaunchEnv::Ready(crate::config::AccountLaunchEnv {
                vars: vec![("CLAUDE_CONFIG_DIR".to_string(), "/armed".to_string())],
                clear_vars: vec!["CLAUDE_CODE_OAUTH_TOKEN".to_string()],
            })
        );
    }

    /// A REFUSAL MUST BE A STATE, NOT A LOOP.
    ///
    /// The fail-closed guard returned early WITHOUT clearing the pending resume plan, so
    /// the pane stayed a resume candidate: every tick re-refused it and logged another
    /// `error!`. A permanent condition (the account is gone) was being retried forever,
    /// which both floods the log and hides the one line that matters.
    ///
    /// It must refuse exactly once, record WHY, and keep the plan so re-registering the
    /// account can still bring the agent back.
    #[test]
    fn a_refused_resume_records_the_reason_and_stops_retrying() {
        let mut app = test_app();
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("agent")];
        app.state.ensure_test_terminals();
        app.state.view.terminal_area = Rect::new(0, 0, 80, 24);
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        let plan = crate::agent_resume::AgentResumePlan {
            agent: "claude".to_string(),
            argv: vec![
                "claude".to_string(),
                "--resume".to_string(),
                "sess".to_string(),
            ],
            dedupe_key: "claude:sess".to_string(),
        };
        {
            let terminal = app.state.terminals.get_mut(&terminal_id).expect("terminal");
            terminal.agent_account = Some("deleted-account".to_string());
            terminal.pending_agent_resume_plan = Some(plan.clone());
        }

        // Before: this pane is a resume candidate.
        assert_eq!(
            app.pending_agent_resume_candidates().len(),
            1,
            "precondition: the pane is pending a resume"
        );

        let started = app.start_pending_agent_resume(
            pane_id,
            terminal_id.clone(),
            std::path::PathBuf::from("/tmp"),
            plan,
            24,
            80,
            true,
        );
        assert!(!started, "an unresolvable account must not launch an agent");

        let terminal = app.state.terminals.get(&terminal_id).expect("terminal");
        assert_eq!(
            terminal.account_resume_blocked.as_deref(),
            Some("deleted-account"),
            "the refusal must be recorded so it can be reported, not just logged and lost"
        );
        assert!(
            terminal.pending_agent_resume_plan.is_some(),
            "the resume plan must SURVIVE: re-registering the account has to be able to \
             bring this agent back, so refusing must not destroy its resume identity"
        );

        // After: it is no longer a candidate, so nothing re-refuses it every tick.
        assert!(
            app.pending_agent_resume_candidates().is_empty(),
            "a refused pane must stop being retried; re-refusing on every tick floods the \
             log with the same error and never becomes a distinct, visible state"
        );
    }

    /// Re-registering the account unblocks the pane, which is what makes the marker a
    /// recoverable state rather than a dead end until restart.
    #[test]
    fn reloading_the_accounts_registry_clears_a_block() {
        let mut app = test_app();
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("agent")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        app.state
            .terminals
            .get_mut(&terminal_id)
            .expect("terminal")
            .account_resume_blocked = Some("deleted-account".to_string());

        app.apply_config_from_disk(false);

        assert!(
            app.state
                .terminals
                .get(&terminal_id)
                .expect("terminal")
                .account_resume_blocked
                .is_none(),
            "an accounts reload must give a blocked pane another chance"
        );
    }

    /// THE DIVERGENT-BRANCH GUARD — the test that judges the SYMPTOM, not the mechanism.
    ///
    /// A pane that recorded an account which no longer resolves must NOT come back on the
    /// default account. That fallback is exactly the incident: eleven seats switched to a
    /// secondary account were restored onto the primary and began appending to the PRIMARY
    /// transcript, and the owner experienced it as one to two hours of history vanishing
    /// while the records sat intact in the other account's file.
    ///
    /// Note what this deliberately does NOT assert: not pane count, not that a session id
    /// survived, not that a process exists. All three of those PASSED during the incident.
    #[test]
    fn a_recorded_account_that_cannot_resolve_refuses_rather_than_re_homing() {
        let mut app = test_app();
        app.state.workspaces = vec![crate::workspace::Workspace::test_new("agent")];
        app.state.ensure_test_terminals();
        let pane_id = app.state.workspaces[0].tabs[0].root_pane;
        let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane_id]
            .attached_terminal_id
            .clone();
        app.state
            .terminals
            .get_mut(&terminal_id)
            .expect("terminal")
            .agent_account = Some("deleted-account".to_string());

        assert_eq!(
            app.resume_launch_env(&terminal_id, "claude"),
            ResumeLaunchEnv::Unresolvable {
                account_id: "deleted-account".to_string()
            },
            "a recorded-but-unresolvable account must REFUSE, not silently resume on the \
             default account and write to the wrong transcript"
        );
        // And specifically: it must not produce a usable env. An empty env is the default
        // account, which is the failure being prevented.
        assert!(
            !matches!(
                app.resume_launch_env(&terminal_id, "claude"),
                ResumeLaunchEnv::Ready(_)
            ),
            "refusal must not degrade into Ready(empty) — that IS the default account"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pending_agent_resume_waits_for_host_theme_before_launch() {
        let mut app = test_app();
        let workspace = crate::workspace::Workspace::test_new("restored");
        let pane_id = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(pane_id).cloned().unwrap();
        let pane_infos = workspace.tabs[0]
            .layout
            .panes(ratatui::layout::Rect::new(0, 0, 100, 30));
        app.state.workspaces = vec![workspace];
        app.state.active = Some(0);
        app.state.ensure_test_terminals();
        app.state.view.terminal_area = ratatui::layout::Rect::new(0, 0, 100, 30);
        app.state.view.pane_infos = pane_infos;
        let terminal = app
            .state
            .terminals
            .get_mut(&terminal_id)
            .expect("test terminal should exist");
        terminal.pending_agent_resume_plan = Some(crate::agent_resume::AgentResumePlan {
            agent: "codex".into(),
            argv: marker_resume_test_argv(),
            dedupe_key: "herdr:codex\0codex\0Id\0codex-session".into(),
        });

        assert!(!app.start_pending_agent_resumes(false));
        assert!(app.terminal_runtimes.get(&terminal_id).is_none());

        app.state.host_terminal_theme = crate::terminal_theme::TerminalTheme {
            foreground: Some(crate::terminal_theme::RgbColor {
                r: 220,
                g: 220,
                b: 220,
            }),
            background: Some(crate::terminal_theme::RgbColor {
                r: 20,
                g: 20,
                b: 20,
            }),
            ..Default::default()
        };

        assert!(app.start_pending_agent_resumes(false));
        assert!(app.terminal_runtimes.get(&terminal_id).is_some());
        let terminal = app
            .state
            .terminals
            .get(&terminal_id)
            .expect("terminal should survive launch");
        assert!(terminal.pending_agent_resume_plan.is_none());
        assert!(!terminal.respawn_shell_on_exit);

        let runtime = app
            .terminal_runtimes
            .get(&terminal_id)
            .expect("pending resume should leave a shell runtime");
        let marker = "restored agent: shell quoted | marker";
        for _ in 0..20 {
            if runtime
                .snapshot_history()
                .is_some_and(|text| text.contains(marker))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            runtime
                .snapshot_history()
                .expect("runtime should expose terminal history")
                .contains(marker),
            "deferred restore should inject the resume argv into the restored shell"
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pending_agent_resume_can_launch_after_theme_wait_expires() {
        let mut app = test_app();
        let workspace = crate::workspace::Workspace::test_new("restored");
        let pane_id = workspace.tabs[0].root_pane;
        let terminal_id = workspace.terminal_id(pane_id).cloned().unwrap();
        app.state.view.pane_infos = workspace.tabs[0]
            .layout
            .panes(ratatui::layout::Rect::new(0, 0, 100, 30));
        app.state.view.terminal_area = ratatui::layout::Rect::new(0, 0, 100, 30);
        app.state.workspaces = vec![workspace];
        app.state.active = Some(0);
        app.state.ensure_test_terminals();
        app.state
            .terminals
            .get_mut(&terminal_id)
            .expect("test terminal should exist")
            .pending_agent_resume_plan = Some(crate::agent_resume::AgentResumePlan {
            agent: "codex".into(),
            argv: long_running_test_argv(),
            dedupe_key: "herdr:codex\0codex\0Id\0codex-session".into(),
        });

        app.sync_pending_agent_resume_deadline(std::time::Instant::now());
        assert!(!app.start_pending_agent_resumes(false));
        assert!(app.start_pending_agent_resumes(true));
        assert!(app.terminal_runtimes.get(&terminal_id).is_some());

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn pending_agent_resume_launches_hidden_panes_with_current_terminal_area() {
        let mut app = test_app();
        let active_workspace = crate::workspace::Workspace::test_new("active");
        let active_pane = active_workspace.tabs[0].root_pane;
        let active_terminal = active_workspace.terminal_id(active_pane).cloned().unwrap();
        let hidden_workspace = crate::workspace::Workspace::test_new("hidden");
        let hidden_pane = hidden_workspace.tabs[0].root_pane;
        let hidden_terminal = hidden_workspace.terminal_id(hidden_pane).cloned().unwrap();
        app.state.view.pane_infos = active_workspace.tabs[0]
            .layout
            .panes(ratatui::layout::Rect::new(0, 0, 100, 30));
        app.state.view.terminal_area = ratatui::layout::Rect::new(0, 0, 100, 30);
        app.state.workspaces = vec![active_workspace, hidden_workspace];
        app.state.active = Some(0);
        app.state.ensure_test_terminals();
        app.state.host_terminal_theme = crate::terminal_theme::TerminalTheme {
            foreground: Some(crate::terminal_theme::RgbColor {
                r: 220,
                g: 220,
                b: 220,
            }),
            background: Some(crate::terminal_theme::RgbColor {
                r: 20,
                g: 20,
                b: 20,
            }),
            ..Default::default()
        };
        for terminal_id in [&active_terminal, &hidden_terminal] {
            app.state
                .terminals
                .get_mut(terminal_id)
                .expect("test terminal should exist")
                .pending_agent_resume_plan = Some(crate::agent_resume::AgentResumePlan {
                agent: "codex".into(),
                argv: long_running_test_argv(),
                dedupe_key: format!("herdr:codex\0codex\0Id\0{terminal_id}"),
            });
        }
        app.pending_agent_resume_deadline =
            Some(std::time::Instant::now() - std::time::Duration::from_millis(1));

        assert!(app.start_pending_agent_resumes(false));
        assert!(app.terminal_runtimes.get(&active_terminal).is_some());
        assert!(app.terminal_runtimes.get(&hidden_terminal).is_some());
        assert!(
            app.pending_agent_resume_deadline.is_none(),
            "launched pending resumes should clear the wakeup deadline"
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn pending_agent_resume_launches_inactive_tab_panes_with_current_terminal_area() {
        let mut app = test_app();
        let mut workspace = crate::workspace::Workspace::test_new("tabs");
        let active_pane = workspace.tabs[0].root_pane;
        let inactive_tab = workspace.test_add_tab(Some("agents"));
        let inactive_pane = workspace.tabs[inactive_tab].root_pane;
        let inactive_terminal = workspace.tabs[inactive_tab]
            .terminal_id(inactive_pane)
            .cloned()
            .unwrap();
        app.state.view.pane_infos = workspace.tabs[0]
            .layout
            .panes(ratatui::layout::Rect::new(0, 0, 100, 30));
        app.state.view.terminal_area = ratatui::layout::Rect::new(0, 0, 100, 30);
        app.state.workspaces = vec![workspace];
        app.state.active = Some(0);
        app.state.ensure_test_terminals();
        assert!(app
            .state
            .workspaces
            .first()
            .and_then(|ws| ws.tabs[0].terminal_id(active_pane))
            .is_some());
        app.state.host_terminal_theme = crate::terminal_theme::TerminalTheme {
            foreground: Some(crate::terminal_theme::RgbColor {
                r: 220,
                g: 220,
                b: 220,
            }),
            background: Some(crate::terminal_theme::RgbColor {
                r: 20,
                g: 20,
                b: 20,
            }),
            ..Default::default()
        };
        app.state
            .terminals
            .get_mut(&inactive_terminal)
            .expect("inactive tab terminal should exist")
            .pending_agent_resume_plan = Some(crate::agent_resume::AgentResumePlan {
            agent: "codex".into(),
            argv: long_running_test_argv(),
            dedupe_key: "herdr:codex\0codex\0Id\0inactive-tab-session".into(),
        });

        assert!(app.start_pending_agent_resumes(false));
        assert!(app.terminal_runtimes.get(&inactive_terminal).is_some());
        assert!(
            app.state
                .terminals
                .get(&inactive_terminal)
                .expect("inactive tab terminal should still exist")
                .pending_agent_resume_plan
                .is_none(),
            "inactive tab restored panes should not wait for tab focus"
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn pending_agent_resume_launches_zoom_hidden_active_tab_panes() {
        let mut app = test_app();
        let mut workspace = crate::workspace::Workspace::test_new("zoomed");
        let hidden_pane = workspace.tabs[0].root_pane;
        let visible_pane = workspace.test_split(ratatui::layout::Direction::Horizontal);
        workspace.tabs[0].zoomed = true;
        let hidden_terminal = workspace.terminal_id(hidden_pane).cloned().unwrap();
        app.state.view.pane_infos = vec![crate::layout::PaneInfo {
            id: visible_pane,
            rect: ratatui::layout::Rect::new(0, 0, 100, 30),
            inner_rect: ratatui::layout::Rect::new(1, 1, 98, 28),
            scrollbar_rect: None,
            borders: ratatui::widgets::Borders::ALL,
            is_focused: true,
        }];
        app.state.view.terminal_area = ratatui::layout::Rect::new(0, 0, 100, 30);
        app.state.workspaces = vec![workspace];
        app.state.active = Some(0);
        app.state.ensure_test_terminals();
        app.state.host_terminal_theme = crate::terminal_theme::TerminalTheme {
            foreground: Some(crate::terminal_theme::RgbColor {
                r: 220,
                g: 220,
                b: 220,
            }),
            background: Some(crate::terminal_theme::RgbColor {
                r: 20,
                g: 20,
                b: 20,
            }),
            ..Default::default()
        };
        app.state
            .terminals
            .get_mut(&hidden_terminal)
            .expect("hidden zoom pane terminal should exist")
            .pending_agent_resume_plan = Some(crate::agent_resume::AgentResumePlan {
            agent: "codex".into(),
            argv: long_running_test_argv(),
            dedupe_key: "herdr:codex\0codex\0Id\0zoom-hidden-session".into(),
        });

        assert!(app.start_pending_agent_resumes(false));
        assert!(app.terminal_runtimes.get(&hidden_terminal).is_some());
        assert!(
            app.state
                .terminals
                .get(&hidden_terminal)
                .expect("hidden zoom pane terminal should still exist")
                .pending_agent_resume_plan
                .is_none(),
            "zoom-hidden restored panes should not wait for pane focus"
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn pending_agent_resume_uses_current_terminal_area_for_background_panes() {
        let mut app = test_app();
        let previous_workspace = crate::workspace::Workspace::test_new("previous");
        let previous_pane = previous_workspace.tabs[0].root_pane;
        let previous_terminal = previous_workspace
            .terminal_id(previous_pane)
            .cloned()
            .unwrap();
        let current_workspace = crate::workspace::Workspace::test_new("current");
        app.state.view.pane_infos = previous_workspace.tabs[0]
            .layout
            .panes(ratatui::layout::Rect::new(0, 0, 100, 30));
        app.state.view.terminal_area = ratatui::layout::Rect::new(0, 0, 80, 24);
        app.state.workspaces = vec![previous_workspace, current_workspace];
        app.state.active = Some(1);
        app.state.ensure_test_terminals();
        app.state.host_terminal_theme = crate::terminal_theme::TerminalTheme {
            foreground: Some(crate::terminal_theme::RgbColor {
                r: 220,
                g: 220,
                b: 220,
            }),
            background: Some(crate::terminal_theme::RgbColor {
                r: 20,
                g: 20,
                b: 20,
            }),
            ..Default::default()
        };
        app.state
            .terminals
            .get_mut(&previous_terminal)
            .expect("test terminal should exist")
            .pending_agent_resume_plan = Some(crate::agent_resume::AgentResumePlan {
            agent: "codex".into(),
            argv: long_running_test_argv(),
            dedupe_key: "herdr:codex\0codex\0Id\0codex-session".into(),
        });

        app.sync_pending_agent_resume_deadline(std::time::Instant::now());
        assert!(app.pending_agent_resume_deadline.is_some());
        assert!(app.start_pending_agent_resumes(false));
        assert!(app.terminal_runtimes.get(&previous_terminal).is_some());
        assert!(
            app.state
                .terminals
                .get(&previous_terminal)
                .expect("previous terminal should still exist")
                .pending_agent_resume_plan
                .is_none(),
            "background restored panes should not wait for focus once terminal area is known"
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pending_agent_resume_launches_with_inner_rect_size() {
        let mut app = test_app();
        let mut workspace = crate::workspace::Workspace::test_new("split");
        let pane_id = workspace.test_split(ratatui::layout::Direction::Horizontal);
        let terminal_id = workspace.terminal_id(pane_id).cloned().unwrap();
        app.state.view.pane_infos = vec![crate::layout::PaneInfo {
            id: pane_id,
            rect: ratatui::layout::Rect::new(0, 0, 100, 30),
            inner_rect: ratatui::layout::Rect::new(1, 1, 98, 28),
            scrollbar_rect: None,
            borders: ratatui::widgets::Borders::ALL,
            is_focused: true,
        }];
        app.state.view.terminal_area = ratatui::layout::Rect::new(0, 0, 100, 30);
        app.state.workspaces = vec![workspace];
        app.state.active = Some(0);
        app.state.ensure_test_terminals();
        app.state.host_terminal_theme = crate::terminal_theme::TerminalTheme {
            foreground: Some(crate::terminal_theme::RgbColor {
                r: 220,
                g: 220,
                b: 220,
            }),
            background: Some(crate::terminal_theme::RgbColor {
                r: 20,
                g: 20,
                b: 20,
            }),
            ..Default::default()
        };
        app.state
            .terminals
            .get_mut(&terminal_id)
            .expect("test terminal should exist")
            .pending_agent_resume_plan = Some(crate::agent_resume::AgentResumePlan {
            agent: "codex".into(),
            argv: long_running_test_argv(),
            dedupe_key: "herdr:codex\0codex\0Id\0codex-session".into(),
        });

        assert!(app.start_pending_agent_resumes(false));
        assert_eq!(
            app.terminal_runtimes
                .get(&terminal_id)
                .expect("pending resume should launch")
                .current_size(),
            (28, 98)
        );

        for (_, runtime) in app.terminal_runtimes.drain() {
            runtime.shutdown();
        }
    }

    #[test]
    fn shell_command_from_argv_quotes_resume_arguments() {
        let argv = vec![
            "claude".to_string(),
            "--resume".to_string(),
            "session with ' quote".to_string(),
        ];

        assert_eq!(
            shell_command_from_argv(&argv).as_deref(),
            Some("claude --resume 'session with '\\'' quote'")
        );
        assert_eq!(shell_command_from_argv(&[]), None);
    }
}
