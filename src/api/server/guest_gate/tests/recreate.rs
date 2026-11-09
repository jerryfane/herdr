//! Guests of agents recreated in new terminals.

use super::*;

/// One pass of the server loop over recreated agents (see
/// `HeadlessServer::handle_scheduled_tasks_headless`).
fn server_pass(harness: &Harness) {
    let (done_tx, done_rx) = std_mpsc::channel();
    harness
        .control
        .send(Box::new(move |app: &mut App| {
            app.follow_recreated_guest_agents_if_changed();
            let _ = done_tx.send(());
        }))
        .unwrap();
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
}

/// The owner recreates the granted agent (agent 0) in agent 1's terminal,
/// as `herdr agent start` resuming its harness session did after the
/// outage of 2026-11-08: the granted terminal is gone, a shell in a new
/// terminal takes its pane, and agent 1's terminal runs a `pi` agent
/// named `name` on harness session `session` (the granted agent's is
/// `session-0`). With `twin`, the new shell terminal holds `session` too.
/// Then the server loop passes. Returns the agent's new terminal id.
fn recreate_granted_agent(harness: &Harness, name: &str, session: &str, twin: bool) -> String {
    let (name, session) = (name.to_string(), session.to_string());
    let (done_tx, done_rx) = std_mpsc::channel();
    harness
        .control
        .send(Box::new(move |app: &mut App| {
            let held = || crate::agent_resume::PersistedAgentSession {
                source: "herdr".into(),
                agent: "pi".into(),
                session_ref: crate::agent_resume::AgentSessionRef::id(session.clone()).unwrap(),
            };
            let tab = &mut app.state.workspaces[0].tabs[0];
            let pane = tab.root_pane;
            let shell = crate::terminal::TerminalId::alloc();
            let gone = std::mem::replace(
                &mut tab.panes.get_mut(&pane).unwrap().attached_terminal_id,
                shell.clone(),
            );
            let mut terminal =
                crate::terminal::TerminalState::new(shell.clone(), std::env::temp_dir());
            if twin {
                terminal.set_persisted_agent_session(held());
            }
            app.state.terminals.insert(shell, terminal);
            app.state.remove_unattached_terminal_ids([gone]);
            let pane = app.state.workspaces[1].tabs[0].root_pane;
            let recreated = app.state.workspaces[1].tabs[0].panes[&pane]
                .attached_terminal_id
                .clone();
            let terminal = app.state.terminals.get_mut(&recreated).unwrap();
            terminal.set_agent_name(name);
            terminal.set_persisted_agent_session(held());
            app.follow_recreated_guest_agents_if_changed();
            let _ = done_tx.send(recreated.to_string());
        }))
        .unwrap();
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap()
}

fn stored_record(harness: &Harness, guest_id: &str) -> crate::guest::store::GuestRecord {
    crate::guest::store::load_store(&harness.dir.0)
        .unwrap()
        .guests
        .into_iter()
        .find(|record| record.guest_id == guest_id)
        .unwrap()
}

fn stored_invite_terminal(harness: &Harness, invite_id: &str) -> String {
    crate::guest::store::load_store(&harness.dir.0)
        .unwrap()
        .invites
        .into_iter()
        .find(|invite| invite.invite_id == invite_id)
        .unwrap()
        .grant
        .terminal_id
}

/// 2026-11-08: the owner recreated shared agents in new terminals on the
/// sessions they ran before, and their guest lost them. The grant follows
/// the agent's session to its new terminal, a pending invite too, and the
/// guest's Gram from before stays with it.
#[test]
fn a_guest_keeps_its_agent_recreated_in_a_new_terminal() {
    let _config = ConfigHome::new("recreate");
    let harness = start_renaming("recreate");
    let tick = || std::thread::sleep(Duration::from_millis(5));
    let admitted = harness.admit_with(0, true);
    let pending = harness.invite(0, "later");
    // The startup pass leaves a grant whose terminal is live alone.
    server_pass(&harness);
    assert_eq!(
        stored_record(&harness, &admitted.guest_id).grant,
        admitted.grant
    );
    send_gram(&harness, "llm-opt", "agent before");
    tick();

    let recreated = recreate_granted_agent(&harness, "llm-opt", "session-0", false);
    tick();
    let record = stored_record(&harness, &admitted.guest_id);
    assert!(!record.revoked);
    assert_eq!(record.grant.terminal_id, recreated);
    assert_eq!(record.grant.agent_name.as_deref(), Some("llm-opt"));
    assert_eq!(
        stored_invite_terminal(&harness, &pending.record.invite_id),
        recreated
    );

    // A connection admitted before reads the moved grant.
    let lines = harness.call(&admitted, prompt_request("llm-opt", "still here"));
    assert_eq!(lines[0]["result"]["type"], "agent_prompted", "{lines:?}");
    let written = harness.pty_text(1, Duration::from_millis(600));
    assert!(
        written.contains("plotarmordev (via HerdrUp): still here"),
        "{written:?}"
    );
    let (guest, reply) = readmit(&harness, &admitted);
    assert_eq!(reply["agent"]["target"], recreated.as_str(), "{reply}");
    send_gram_as(
        &harness,
        Some(harness.pane_ids[1].clone()),
        "llm-opt",
        "agent after",
    );
    let listed = guest_list(&harness, &guest, json!({}));
    assert_eq!(texts(&listed), ["agent after", "agent before"], "{listed}");
}

/// An agent's Gram from `pane` carrying a file holding `hello`.
fn send_file_from(harness: &Harness, pane: &str, from: &str, name: &str) -> String {
    let upload = format!("up-{name}");
    let staged = owner(
        harness,
        json!({"id": "u", "method": "gram.upload_chunk", "params": {"upload_id": upload, "offset": 0, "data_base64": "aGVsbG8="}}),
    );
    assert_eq!(staged["result"]["type"], "ok", "{staged}");
    sent_id(&owner(
        harness,
        json!({"id": "s", "method": "gram.send", "params": {"text": name, "from": from, "caller_pane_id": pane, "file": {"upload_id": upload, "name": name, "mime": "text/plain"}}}),
    ))
}

/// #387-f1: the terminal a grant follows to may have run another
/// conversation first, under the granted name. Its Grams and files from
/// before the grant arrived stay hidden from the guest; the agent's Grams
/// from its old terminal and from the new one since the move are the guest's.
#[test]
fn grams_the_new_terminal_sent_before_the_grant_moved_stay_private() {
    let _config = ConfigHome::new("recreate-private");
    let harness = start_renaming("recreate-private");
    let tick = || std::thread::sleep(Duration::from_millis(5));
    let admitted = harness.admit_with(0, true);
    server_pass(&harness);
    send_file_from(&harness, &harness.pane_ids[0], "llm-opt", "before.txt");
    tick();

    // The granted terminal is gone; agent 1's terminal runs another
    // conversation under the granted name, so the grant stays.
    let recreated = recreate_granted_agent(&harness, "llm-opt", "session-private", false);
    tick();
    let pane = harness.pane_ids[1].clone();
    send_gram_as(&harness, Some(pane.clone()), "llm-opt", "private");
    let private_file = send_file_from(&harness, &pane, "llm-opt", "private.txt");
    tick();
    assert_eq!(
        stored_record(&harness, &admitted.guest_id).grant,
        admitted.grant
    );

    // That terminal resumes the granted session: the grant follows.
    let (done_tx, done_rx) = std_mpsc::channel();
    harness
        .control
        .send(Box::new(move |app: &mut App| {
            let pane = app.state.workspaces[1].tabs[0].root_pane;
            let terminal_id = app.state.workspaces[1].tabs[0].panes[&pane]
                .attached_terminal_id
                .clone();
            let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
            terminal.set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
                source: "herdr".into(),
                agent: "pi".into(),
                session_ref: crate::agent_resume::AgentSessionRef::id("session-0").unwrap(),
            });
            app.state.mark_session_dirty();
            app.follow_recreated_guest_agents_if_changed();
            let _ = done_tx.send(());
        }))
        .unwrap();
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    tick();
    assert_eq!(
        stored_record(&harness, &admitted.guest_id)
            .grant
            .terminal_id,
        recreated
    );
    let after_file = send_file_from(&harness, &pane, "llm-opt", "after.txt");

    let (guest, _) = readmit(&harness, &admitted);
    let listed = guest_list(&harness, &guest, json!({}));
    assert_eq!(texts(&listed), ["after.txt", "before.txt"], "{listed}");
    let fetch = |id: &str| {
        harness.call(
            &guest,
            json!({"id": "f", "method": "gram.get_file", "params": {"id": id}}),
        )
    };
    let refused = fetch(&private_file);
    assert_eq!(code(&refused), "guest_forbidden", "{refused:?}");
    assert_eq!(fetch(&after_file)[0]["result"]["data_base64"], "aGVsbG8=");
}

/// A guest never reaches another conversation: an agent recreated under
/// the granted name but on another harness session gets no grant.
#[test]
fn another_session_in_a_new_terminal_gains_no_guest() {
    let _config = ConfigHome::new("recreate-other");
    let harness = start_renaming("recreate-other");
    let guest = harness.admit();
    let pending = harness.invite(0, "later");
    server_pass(&harness);

    let other = recreate_granted_agent(&harness, "llm-opt", "session-other", false);
    assert_eq!(stored_record(&harness, &guest.guest_id).grant, guest.grant);
    assert_eq!(
        stored_invite_terminal(&harness, &pending.record.invite_id),
        guest.grant.terminal_id
    );
    assert_eq!(
        code(&harness.call(&guest, prompt_request("llm-opt", "x"))),
        "guest_paused"
    );
    for target in [other.as_str(), harness.pane_ids[1].as_str()] {
        let lines = harness.call(&guest, prompt_request(target, "x"));
        assert_eq!(code(&lines), "guest_forbidden", "{target} -> {lines:?}");
    }
    assert!(harness.pty_text(1, Duration::from_millis(200)).is_empty());
}

/// Two terminals holding the granted session: which one is the agent is
/// unknown, so the grant and the pending invite stay where they are.
#[test]
fn a_session_held_by_two_terminals_leaves_the_grant_unattached() {
    let _config = ConfigHome::new("recreate-twin");
    let harness = start_renaming("recreate-twin");
    let guest = harness.admit();
    let pending = harness.invite(0, "later");
    server_pass(&harness);

    recreate_granted_agent(&harness, "llm-opt", "session-0", true);
    assert_eq!(stored_record(&harness, &guest.guest_id).grant, guest.grant);
    assert_eq!(
        stored_invite_terminal(&harness, &pending.record.invite_id),
        guest.grant.terminal_id
    );
    assert_eq!(
        code(&harness.call(&guest, prompt_request("llm-opt", "x"))),
        "guest_paused"
    );
    assert!(harness.pty_text(1, Duration::from_millis(200)).is_empty());
}

/// A revoked guest's grant never moves, while the pending invite to the
/// same agent does.
#[test]
fn a_revoked_guest_stays_revoked_when_its_agent_is_recreated() {
    let _config = ConfigHome::new("recreate-revoked");
    let harness = start_renaming("recreate-revoked");
    let guest = harness.admit();
    let pending = harness.invite(0, "later");
    server_pass(&harness);
    crate::guest::store::revoke_in(
        &harness.dir.0,
        RevokeTarget::Guest(&guest.guest_id),
        now_ms(),
    )
    .unwrap();

    let recreated = recreate_granted_agent(&harness, "llm-opt", "session-0", false);
    assert_eq!(
        stored_invite_terminal(&harness, &pending.record.invite_id),
        recreated
    );
    let record = stored_record(&harness, &guest.guest_id);
    assert!(record.revoked);
    assert_eq!(record.grant, guest.grant);
    assert_eq!(
        code(&harness.call(&guest, prompt_request("llm-opt", "x"))),
        "guest_revoked"
    );
    let hello = json!({"v": 1, "guest_id": guest.guest_id});
    assert!(matches!(
        admit_in(harness.dir.0.clone(), [4; 32], &hello),
        Admission::Refused(_)
    ));
    assert!(harness.pty_text(1, Duration::from_millis(200)).is_empty());
}

/// Agent `index`'s Gram relayed to the coordinator from its pane, carrying
/// a file named `name` holding `hello`; returns its id.
fn relay_file(harness: &Harness, index: usize, name: &str) -> String {
    let upload = format!("up-{name}");
    let staged = local_call(
        harness,
        json!({"id": "u", "method": "gram.upload_chunk", "params": {"upload_id": upload, "offset": 0, "data_base64": "aGVsbG8="}}),
    );
    assert_eq!(staged["result"]["type"], "ok", "{staged}");
    sent_id(&local_call(
        harness,
        json!({"id": "s", "method": "gram.send", "params": {"text": name, "caller_pane_id": harness.pane_ids[index], "file": {"upload_id": upload, "name": name, "mime": "text/plain"}}}),
    ))
}

/// Agent 1's terminal resumes the granted agent's session `session-0`, and
/// the server loop passes.
fn resume_granted_session_in_agent_1(harness: &Harness) {
    agent_1_runs_session(harness, "session-0");
}

/// Agent 1's terminal now runs harness session `session`, and the server
/// loop passes.
fn agent_1_runs_session(harness: &Harness, session: &'static str) {
    let (done_tx, done_rx) = std_mpsc::channel();
    harness
        .control
        .send(Box::new(move |app: &mut App| {
            let pane = app.state.workspaces[1].tabs[0].root_pane;
            let terminal_id = app.state.workspaces[1].tabs[0].panes[&pane]
                .attached_terminal_id
                .clone();
            let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
            terminal.set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
                source: "herdr".into(),
                agent: "pi".into(),
                session_ref: crate::agent_resume::AgentSessionRef::id(session).unwrap(),
            });
            app.state.mark_session_dirty();
            app.follow_recreated_guest_agents_if_changed();
            let _ = done_tx.send(());
        }))
        .unwrap();
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
}

/// #387-f1 on a Gram-relay remote, where the coordinator stamps each Gram
/// with its own clock, `skew_ms` off this machine's. Another conversation's
/// Gram and file the destination terminal relayed before the grant moved
/// stay private, and the agent's Grams from its old terminal and from the
/// new one after the move reach the guest, whatever the skew.
fn relayed_grams_follow_the_session_not_the_clock(tag: &str, skew_ms: i64) {
    let (_config, harness, coordinator) = relay_remote(tag);
    coordinator.skew(skew_ms);
    let admitted = harness.admit_with(0, true);
    server_pass(&harness);
    // Room for a coordinator behind by less than the time since acceptance.
    std::thread::sleep(Duration::from_millis(400));
    relay_file(&harness, 0, "before.txt");

    let recreated = recreate_granted_agent(&harness, "llm-opt", "session-private", false);
    coordinator.names(&harness.pane_ids[1], "mac-studio/llm-opt");
    let private_file = relay_file(&harness, 1, "private.txt");
    assert_eq!(
        stored_record(&harness, &admitted.guest_id).grant,
        admitted.grant
    );

    resume_granted_session_in_agent_1(&harness);
    assert_eq!(
        stored_record(&harness, &admitted.guest_id)
            .grant
            .terminal_id,
        recreated
    );
    let after_file = relay_file(&harness, 1, "after.txt");

    let (guest, _) = readmit(&harness, &admitted);
    let listed = guest_list(&harness, &guest, json!({}));
    assert_eq!(texts(&listed), ["after.txt", "before.txt"], "{listed}");
    let fetch = |id: &str| {
        harness.call(
            &guest,
            json!({"id": "f", "method": "gram.get_file", "params": {"id": id}}),
        )
    };
    let refused = fetch(&private_file);
    assert_eq!(code(&refused), "guest_forbidden", "{refused:?}");
    let fetched = fetch(&after_file);
    assert_eq!(
        fetched[0]["result"]["data_base64"], "aGVsbG8=",
        "{fetched:?}"
    );
}

#[test]
fn relayed_grams_follow_the_session_with_the_coordinator_on_the_same_clock() {
    relayed_grams_follow_the_session_not_the_clock("recreate-relay-same", 0);
}

#[test]
fn relayed_grams_follow_the_session_with_the_coordinator_clock_ahead() {
    relayed_grams_follow_the_session_not_the_clock("recreate-relay-ahead", 3_600_000);
}

#[test]
fn relayed_grams_follow_the_session_with_the_coordinator_clock_behind() {
    relayed_grams_follow_the_session_not_the_clock("recreate-relay-behind", -200);
}

/// The harness session `session-restarted` of the granted `pi` agent.
fn restarted_session() -> crate::api::schema::AgentSessionInfo {
    serde_json::from_value(
        json!({"source": "herdr", "agent": "pi", "kind": "id", "value": "session-restarted"}),
    )
    .unwrap()
}

/// #387-f2: after the grant followed its agent to a new terminal, the agent
/// restarts there on a new harness session and sends a Gram with a file
/// before the guest asks for anything. The server records that session on
/// the grant when the Gram is sent, and the guest sees the Gram and its file.
#[test]
fn a_moved_agent_restarted_on_a_new_session_keeps_its_grams_for_the_guest() {
    let _config = ConfigHome::new("recreate-restart");
    let harness = start_renaming("recreate-restart");
    let admitted = harness.admit_with(0, true);
    server_pass(&harness);
    let recreated = recreate_granted_agent(&harness, "llm-opt", "session-0", false);
    assert_eq!(
        stored_record(&harness, &admitted.guest_id)
            .grant
            .terminal_id,
        recreated
    );

    agent_1_runs_session(&harness, "session-restarted");
    let restarted = send_file_from(&harness, &harness.pane_ids[1], "llm-opt", "restarted.txt");
    assert!(
        stored_record(&harness, &admitted.guest_id)
            .terminal_sessions
            .contains(&restarted_session()),
        "the send recorded the restarted session before any guest request"
    );

    let (guest, _) = readmit(&harness, &admitted);
    let listed = guest_list(&harness, &guest, json!({}));
    assert_eq!(texts(&listed), ["restarted.txt"], "{listed}");
    let fetched = harness.call(
        &guest,
        json!({"id": "f", "method": "gram.get_file", "params": {"id": restarted}}),
    );
    assert_eq!(
        fetched[0]["result"]["data_base64"], "aGVsbG8=",
        "{fetched:?}"
    );
}

/// #387-f2 on a Gram-relay remote: the restarted agent's relayed Gram is
/// recorded and mirrored for the guest when it is sent, so the guest lists it
/// across reconciliation with the coordinator and opens its file.
#[test]
fn a_moved_agent_restarted_on_a_new_session_keeps_its_relayed_grams_for_the_guest() {
    let (_config, harness, coordinator) = relay_remote("recreate-relay-restart");
    let admitted = harness.admit_with(0, true);
    server_pass(&harness);
    let recreated = recreate_granted_agent(&harness, "llm-opt", "session-0", false);
    coordinator.names(&harness.pane_ids[1], "mac-studio/llm-opt");
    assert_eq!(
        stored_record(&harness, &admitted.guest_id)
            .grant
            .terminal_id,
        recreated
    );

    agent_1_runs_session(&harness, "session-restarted");
    let restarted = relay_file(&harness, 1, "restarted.txt");
    assert!(
        stored_record(&harness, &admitted.guest_id)
            .terminal_sessions
            .contains(&restarted_session()),
        "the relayed send recorded the restarted session before any guest request"
    );

    let (guest, _) = readmit(&harness, &admitted);
    for _ in 0..2 {
        let listed = guest_list(&harness, &guest, json!({}));
        assert_eq!(texts(&listed), ["restarted.txt"], "{listed}");
    }
    let fetched = harness.call(
        &guest,
        json!({"id": "f", "method": "gram.get_file", "params": {"id": restarted}}),
    );
    assert_eq!(
        fetched[0]["result"]["data_base64"], "aGVsbG8=",
        "{fetched:?}"
    );
}
