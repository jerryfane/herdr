//! Agent identity across foreground changes: real exits, relaunches, and
//! an agent suspended behind the shell.

use std::time::{Duration, Instant};

use crate::agent_resume::AgentSessionRef;
use crate::app::state::AppState;
use crate::detect::{Agent, AgentState};
use crate::events::AppEvent;
use crate::layout::PaneId;
use crate::terminal::TerminalId;

fn adversarial_pane() -> (AppState, PaneId, TerminalId) {
    let app = AppState::test_with_adversarial_identity_state();
    let ws = &app.workspaces[0];
    let pane_id = ws.tabs[ws.active_tab].root_pane;
    let terminal_id = ws.panes[&pane_id].attached_terminal_id.clone();
    (app, pane_id, terminal_id)
}

fn pi_session() -> AgentSessionRef {
    AgentSessionRef::path(
        std::env::current_dir()
            .expect("cwd")
            .join("takeover-pi.jsonl")
            .display()
            .to_string(),
    )
    .expect("pi session path")
}

fn claude_session() -> AgentSessionRef {
    AgentSessionRef::id("2f0c0c2e-1647-4a4b-9a3e-0000000c1a0d").expect("claude session id")
}

fn detect(app: &mut AppState, pane_id: PaneId, agent: Agent, at: Instant) {
    app.handle_app_event(AppEvent::AgentProcessDetected {
        pane_id,
        runtime_epoch: None,
        agent,
        observed_at: at,
    });
}

fn detection_state(
    app: &mut AppState,
    pane_id: PaneId,
    agent: Option<Agent>,
    process_exited: bool,
    at: Instant,
) {
    app.handle_app_event(AppEvent::StateChanged {
        pane_id,
        runtime_epoch: None,
        agent,
        state: AgentState::Idle,
        visible_blocker: false,
        visible_working: false,
        process_exited,
        observed_at: at,
    });
}

/// The two events the detection loop publishes when the pane shell takes the
/// foreground back from an agent whose process is gone.
fn real_exit(app: &mut AppState, pane_id: PaneId, agent: Agent, at: Instant) {
    detection_state(app, pane_id, Some(agent), true, at);
    detection_state(app, pane_id, None, false, at + Duration::from_millis(1));
}

fn pi_report(app: &mut AppState, pane_id: PaneId, state: AgentState, seq: u64) {
    app.handle_app_event(AppEvent::HookStateReported {
        pane_id,
        source: "herdr:pi".into(),
        agent_label: "pi".into(),
        state,
        message: None,
        seq: Some(seq),
        session_ref: Some(pi_session()),
        session_cursor: None,
        process_pid: None,
    });
}

fn pi_session_report(
    app: &mut AppState,
    pane_id: PaneId,
    session_start_source: Option<&str>,
    seq: u64,
) {
    app.handle_app_event(AppEvent::AgentSessionReported {
        pane_id,
        source: "herdr:pi".into(),
        agent_label: "pi".into(),
        seq: Some(seq),
        session_ref: Some(pi_session()),
        session_path: None,
        session_cursor: None,
        process_pid: None,
        session_start_source: session_start_source.map(str::to_string),
    });
}

fn claude_session_report(app: &mut AppState, pane_id: PaneId, seq: u64) {
    app.handle_app_event(AppEvent::AgentSessionReported {
        pane_id,
        source: "herdr:claude".into(),
        agent_label: "claude".into(),
        seq: Some(seq),
        session_ref: Some(claude_session()),
        session_path: None,
        session_cursor: None,
        process_pid: None,
        session_start_source: Some("startup".into()),
    });
}

fn session_value(app: &AppState, terminal_id: &TerminalId) -> Option<String> {
    let terminal = &app.terminals[terminal_id];
    terminal
        .hook_authority
        .as_ref()
        .and_then(|authority| authority.session_ref.as_ref())
        .or_else(|| {
            terminal
                .persisted_agent_session
                .as_ref()
                .map(|session| &session.session_ref)
        })
        .map(|session_ref| session_ref.value.clone())
}

fn name_agent(app: &mut AppState, terminal_id: &TerminalId, name: &str) {
    app.terminals
        .get_mut(terminal_id)
        .expect("terminal")
        .set_agent_name(name.into());
}

fn pi_with_live_authority(start: Instant) -> (AppState, PaneId, TerminalId) {
    let (mut app, pane_id, terminal_id) = adversarial_pane();
    detect(&mut app, pane_id, Agent::Pi, start);
    pi_session_report(&mut app, pane_id, Some("startup"), 99);
    pi_report(&mut app, pane_id, AgentState::Working, 100);
    name_agent(&mut app, &terminal_id, "worker");
    assert!(app.terminals[&terminal_id].full_lifecycle_hook_authority_active());
    assert_eq!(session_value(&app, &terminal_id), Some(pi_session().value));
    (app, pane_id, terminal_id)
}

fn claude_with_session(start: Instant) -> (AppState, PaneId, TerminalId) {
    let (mut app, pane_id, terminal_id) = adversarial_pane();
    detect(&mut app, pane_id, Agent::Claude, start);
    claude_session_report(&mut app, pane_id, 1);
    name_agent(&mut app, &terminal_id, "c1");
    assert_eq!(
        session_value(&app, &terminal_id),
        Some(claude_session().value)
    );
    (app, pane_id, terminal_id)
}

#[test]
fn real_exit_clears_claude_session_and_name() {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = claude_with_session(start);

    real_exit(
        &mut app,
        pane_id,
        Agent::Claude,
        start + Duration::from_secs(1),
    );

    let terminal = &app.terminals[&terminal_id];
    assert_eq!(session_value(&app, &terminal_id), None);
    assert_eq!(terminal.agent_name, None);
    assert_eq!(terminal.effective_agent_label(), None);
    app.assert_invariants_for_test();
}

#[test]
fn real_exit_clears_pi_session_name_and_authority() {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = pi_with_live_authority(start);

    real_exit(&mut app, pane_id, Agent::Pi, start + Duration::from_secs(1));

    let terminal = &app.terminals[&terminal_id];
    assert_eq!(session_value(&app, &terminal_id), None);
    assert!(terminal.hook_authority.is_none());
    assert_eq!(terminal.agent_name, None);
    assert_eq!(terminal.effective_agent_label(), None);
    app.assert_invariants_for_test();
}

#[test]
fn exit_then_different_agent_relaunch_drops_previous_identity() {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = claude_with_session(start);

    real_exit(
        &mut app,
        pane_id,
        Agent::Claude,
        start + Duration::from_secs(1),
    );
    detect(
        &mut app,
        pane_id,
        Agent::Codex,
        start + Duration::from_secs(2),
    );

    let terminal = &app.terminals[&terminal_id];
    assert_eq!(session_value(&app, &terminal_id), None);
    assert_eq!(terminal.agent_name, None);
    assert_eq!(terminal.effective_agent_label(), Some("codex"));
    app.assert_invariants_for_test();
}

#[test]
fn exited_pi_session_is_not_replayed_into_a_relaunched_pi() {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = pi_with_live_authority(start);

    real_exit(&mut app, pane_id, Agent::Pi, start + Duration::from_secs(1));
    detect(&mut app, pane_id, Agent::Pi, start + Duration::from_secs(2));
    // A late report from the exited process still carries its old session.
    pi_report(&mut app, pane_id, AgentState::Working, 101);

    let terminal = &app.terminals[&terminal_id];
    assert!(!terminal.full_lifecycle_hook_authority_active());
    assert_eq!(session_value(&app, &terminal_id), None);
    app.assert_invariants_for_test();
}

#[test]
fn suspended_pi_keeps_session_name_and_authority_for_its_next_reports() {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = pi_with_live_authority(start);

    // While Pi's job is stopped behind the shell, detection publishes nothing.
    // After `fg`, Pi re-announces its session on agent_start and reports state.
    pi_session_report(&mut app, pane_id, None, 101);
    pi_report(&mut app, pane_id, AgentState::Idle, 102);

    let terminal = &app.terminals[&terminal_id];
    assert!(terminal.full_lifecycle_hook_authority_active());
    assert_eq!(terminal.state, AgentState::Idle);
    assert_eq!(terminal.agent_name.as_deref(), Some("worker"));
    assert_eq!(session_value(&app, &terminal_id), Some(pi_session().value));
    app.assert_invariants_for_test();
}

/// The events detection publishes when a new process of the same agent kind
/// replaces the previous one without the shell in between.
fn same_kind_replacement(app: &mut AppState, pane_id: PaneId, agent: Agent, at: Instant) {
    detection_state(app, pane_id, Some(agent), true, at);
    detect(app, pane_id, agent, at + Duration::from_millis(1));
}

#[test]
fn same_kind_replacement_drops_the_previous_claude_session() {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = claude_with_session(start);

    same_kind_replacement(
        &mut app,
        pane_id,
        Agent::Claude,
        start + Duration::from_secs(1),
    );

    assert_eq!(session_value(&app, &terminal_id), None);
    assert_eq!(
        app.terminals[&terminal_id].effective_agent_label(),
        Some("claude")
    );
    app.assert_invariants_for_test();
}

#[test]
fn same_kind_replacement_drops_the_previous_pi_session_and_authority() {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = pi_with_live_authority(start);

    same_kind_replacement(&mut app, pane_id, Agent::Pi, start + Duration::from_secs(1));
    pi_report(&mut app, pane_id, AgentState::Working, 101);

    let terminal = &app.terminals[&terminal_id];
    assert!(!terminal.full_lifecycle_hook_authority_active());
    assert_eq!(session_value(&app, &terminal_id), None);
    app.assert_invariants_for_test();
}

fn omp_session(file: &str) -> AgentSessionRef {
    AgentSessionRef::path(
        std::env::current_dir()
            .expect("cwd")
            .join(file)
            .display()
            .to_string(),
    )
    .expect("omp session path")
}

/// What omp's integration sends when a process comes up on `session`: its
/// session report (`session_start` reports "startup", also for `--resume`)
/// and then its state, both from that process's pid.
fn omp_starts_on(
    app: &mut AppState,
    pane_id: PaneId,
    session: &AgentSessionRef,
    process_pid: u32,
    seq: u64,
) {
    app.handle_app_event(AppEvent::AgentSessionReported {
        pane_id,
        source: "herdr:omp".into(),
        agent_label: "omp".into(),
        seq: Some(seq),
        session_ref: Some(session.clone()),
        session_path: None,
        session_cursor: None,
        process_pid: Some(process_pid),
        session_start_source: Some("startup".into()),
    });
    app.handle_app_event(AppEvent::HookStateReported {
        pane_id,
        source: "herdr:omp".into(),
        agent_label: "omp".into(),
        state: AgentState::Idle,
        message: None,
        seq: Some(seq + 1),
        session_ref: Some(session.clone()),
        session_cursor: None,
        process_pid: Some(process_pid),
    });
}

/// How the agent in #480 got its name.
#[derive(Clone, Copy)]
enum Naming {
    /// `agent rename` after its session was known.
    Rename,
    /// `agent start --name` (a managed seat), before any session exists:
    /// the ordinals pilot case.
    Start,
}

/// #480: the agent `ordinals` runs omp in its pane and is exited (`/exit`).
fn omp_named_then_exited(naming: Naming) -> (AppState, PaneId, TerminalId, Instant) {
    let start = Instant::now();
    let (mut app, pane_id, terminal_id) = adversarial_pane();
    let session = omp_session("ordinals-omp.jsonl");
    if let Naming::Start = naming {
        app.terminals
            .get_mut(&terminal_id)
            .expect("terminal")
            .begin_managed_agent(
                "ordinals".into(),
                Agent::Omp,
                start,
                Duration::ZERO,
                Duration::from_secs(600),
            );
    }
    detect(&mut app, pane_id, Agent::Omp, start);
    omp_starts_on(&mut app, pane_id, &session, 1001, 100);
    if let Naming::Rename = naming {
        name_agent(&mut app, &terminal_id, "ordinals");
    }
    let terminal = &app.terminals[&terminal_id];
    assert_eq!(terminal.agent_name.as_deref(), Some("ordinals"));
    assert_eq!(
        terminal.managed_agent_interactive_ready(),
        matches!(naming, Naming::Start)
    );
    assert_eq!(session_value(&app, &terminal_id), Some(session.value));

    real_exit(
        &mut app,
        pane_id,
        Agent::Omp,
        start + Duration::from_secs(1),
    );
    assert_eq!(
        app.terminals[&terminal_id].agent_name, None,
        "the exited agent's name is free while the pane is a shell"
    );
    (app, pane_id, terminal_id, start)
}

/// Another omp process (from a different binary, so a new pid) starts in
/// the pane on `session`.
fn omp_resumes_in_its_pane(
    app: &mut AppState,
    pane_id: PaneId,
    terminal_id: &TerminalId,
    start: Instant,
    session: &AgentSessionRef,
) {
    detect(app, pane_id, Agent::Omp, start + Duration::from_secs(2));
    omp_starts_on(app, pane_id, session, 2002, 200);
    assert_eq!(session_value(app, terminal_id), Some(session.value.clone()));
}

#[test]
fn an_agent_restarted_in_its_pane_on_the_same_session_keeps_its_name() {
    for naming in [Naming::Rename, Naming::Start] {
        let (mut app, pane_id, terminal_id, start) = omp_named_then_exited(naming);
        let session = omp_session("ordinals-omp.jsonl");
        omp_resumes_in_its_pane(&mut app, pane_id, &terminal_id, start, &session);

        let terminal = &app.terminals[&terminal_id];
        assert_eq!(terminal.agent_name.as_deref(), Some("ordinals"));
        assert_eq!(terminal.effective_agent_label(), Some("omp"));
        app.assert_invariants_for_test();
    }
}

#[test]
fn a_different_session_in_the_pane_does_not_inherit_the_name() {
    for naming in [Naming::Rename, Naming::Start] {
        let (mut app, pane_id, terminal_id, start) = omp_named_then_exited(naming);
        let session = omp_session("someone-else-omp.jsonl");
        omp_resumes_in_its_pane(&mut app, pane_id, &terminal_id, start, &session);

        let terminal = &app.terminals[&terminal_id];
        assert_eq!(terminal.agent_name, None);
        assert_eq!(terminal.effective_agent_label(), Some("omp"));
        app.assert_invariants_for_test();
    }
}

#[test]
fn a_later_shell_observation_keeps_the_remembered_name() {
    let (mut app, pane_id, terminal_id, start) = omp_named_then_exited(Naming::Rename);
    detection_state(
        &mut app,
        pane_id,
        None,
        false,
        start + Duration::from_millis(1500),
    );
    let session = omp_session("ordinals-omp.jsonl");
    omp_resumes_in_its_pane(&mut app, pane_id, &terminal_id, start, &session);

    assert_eq!(
        app.terminals[&terminal_id].agent_name.as_deref(),
        Some("ordinals")
    );
}

#[test]
fn a_name_taken_while_the_agent_was_gone_is_not_restored_twice() {
    let (mut app, pane_id, terminal_id, start) = omp_named_then_exited(Naming::Rename);
    let other_terminal = app
        .terminals
        .keys()
        .find(|id| **id != terminal_id)
        .cloned()
        .expect("a second terminal");
    name_agent(&mut app, &other_terminal, "ordinals");

    let session = omp_session("ordinals-omp.jsonl");
    omp_resumes_in_its_pane(&mut app, pane_id, &terminal_id, start, &session);

    assert_eq!(app.terminals[&terminal_id].agent_name, None);
    assert_eq!(
        app.terminals[&other_terminal].agent_name.as_deref(),
        Some("ordinals")
    );
}

#[test]
fn a_name_an_archived_agent_holds_is_not_restored() {
    let (mut app, pane_id, terminal_id, start) = omp_named_then_exited(Naming::Rename);
    app.archived_agents
        .push(crate::persist::ArchivedAgentSnapshot {
            name: Some("ordinals".into()),
            kind: "omp".into(),
            terminal_id: "term-archived-ordinals".into(),
            agent_session: crate::persist::PaneAgentSessionSnapshot {
                source: "herdr:omp".into(),
                agent: "omp".into(),
                kind: crate::agent_resume::AgentSessionRefKind::Path,
                value: omp_session("archived-omp.jsonl").value,
            },
            cwd: std::env::current_dir().expect("cwd"),
            occupant_generation: 1,
            archived: crate::persist::ArchivedAgentMeta {
                at: "2026-11-21T00:00:00Z".into(),
                by: "tester".into(),
                reason: None,
            },
            parked_work: Vec::new(),
            origin_workspace_id: None,
            origin_tab_id: None,
            pane_label: None,
            fence: None,
            topics_enabled: false,
            topics_switch_pending: None,
        });

    let session = omp_session("ordinals-omp.jsonl");
    omp_resumes_in_its_pane(&mut app, pane_id, &terminal_id, start, &session);

    assert_eq!(app.terminals[&terminal_id].agent_name, None);
}
