use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::agent_topics::control::tests::{FakeControl, TOKEN};
use crate::agent_transcript::tests::Fixture;
use crate::agent_transcript::topics::tests_support::spawn_entry;
use crate::api::schema::{
    AgentControlToken, AgentTarget, Method, PaneReportAgentControlParams, Request,
};
use crate::app::App;
use crate::config::Config;
use crate::detect::{Agent, AgentState};
use crate::workspace::Workspace;

/// An app whose one pane runs omp process `pid`, whose session file is
/// `session`.
fn omp_app(session: &std::path::Path, pid: u32) -> (App, String, String) {
    let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut app = App::new(
        &Config::default(),
        crate::app::AppPolicy::TEST,
        None,
        api_rx,
        crate::api::EventHub::default(),
    );
    app.state.workspaces = vec![Workspace::test_new("topics")];
    app.state.ensure_test_terminals();
    let pane_id = app.state.workspaces[0].tabs[0].root_pane;
    let public_pane_id = app.public_pane_id(0, pane_id).unwrap();
    let terminal_id = app.state.terminal_id_for_pane(0, pane_id).unwrap();
    let session_ref =
        crate::agent_resume::AgentSessionRef::path(session.display().to_string()).unwrap();
    let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
    terminal.set_detected_state(Some(Agent::Omp), AgentState::Idle);
    terminal.set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
        source: "herdr:omp".into(),
        agent: "omp".into(),
        session_ref: session_ref.clone(),
    });
    terminal.set_reported_agent_session_runtime("herdr:omp", "omp", &session_ref, None, Some(pid));
    // herdr's own probe finds the same omp process in front of the pane.
    app.agent_controls.inspected_pid_for_test = Some(Some(pid));
    (app, public_pane_id, terminal_id.as_str().to_owned())
}

fn report(
    pane_id: &str,
    socket_path: Option<&std::path::Path>,
    agent_process_pid: u32,
    reporter_pid: Option<u32>,
) -> PaneReportAgentControlParams {
    PaneReportAgentControlParams {
        pane_id: pane_id.to_owned(),
        source: "herdr:omp".into(),
        agent: "omp".into(),
        agent_process_pid,
        socket_path: socket_path.map(|path| path.display().to_string()),
        token: socket_path.map(|_| AgentControlToken::new(TOKEN)),
        protocol: socket_path.map(|_| 1),
        reporter_pid,
    }
}

fn send(app: &mut App, method: Method) -> Value {
    serde_json::from_str(&app.handle_api_request(Request {
        id: "r".into(),
        method,
    }))
    .unwrap()
}

/// An `agent.topics.*` request answered from its worker thread.
fn topics(app: &App, method: Method) -> Value {
    let (respond_to, response) = std::sync::mpsc::channel();
    app.handle_deferred_topics_request(
        Request {
            id: "t".into(),
            method,
        },
        respond_to,
    );
    serde_json::from_str(&response.recv_timeout(WAIT).expect("no topics reply")).unwrap()
}

fn list(target: &str) -> Method {
    Method::AgentTopicsList(AgentTarget {
        target: target.to_owned(),
    })
}

fn empty_topics(_: &Value) -> Value {
    json!({"success": true, "data": {"topics": []}})
}

#[test]
fn a_report_from_any_process_but_the_panes_omp_is_refused() {
    let session = Fixture::new("topics-spoof");
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    let fake = FakeControl::start("spoof", empty_topics);

    // A shell in the pane names a pid that is not the tracked omp process.
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp + 1, Some(omp + 1))),
    );
    assert_eq!(
        response["error"]["code"], "agent_control_refused",
        "{response}"
    );
    // It copies omp's pid into the body, but the socket names the caller.
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp + 1))),
    );
    assert_eq!(
        response["error"]["code"], "agent_control_refused",
        "{response}"
    );
    assert!(app.agent_controls.handle(&terminal).is_none());

    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
    );
    assert!(response.get("result").is_some(), "{response}");
    assert!(app.agent_controls.handle(&terminal).is_some());
}

#[test]
fn a_pane_where_herdr_detects_no_omp_accepts_no_control() {
    let session = Fixture::new("topics-no-omp");
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    // herdr's detection no longer sees omp in the pane, whatever it reports.
    app.state
        .terminals
        .get_mut(terminal.as_str())
        .unwrap()
        .set_detected_state(None, AgentState::Unknown);
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&session.path), omp, Some(omp))),
    );
    assert_eq!(
        response["error"]["code"], "agent_control_refused",
        "{response}"
    );
}

#[test]
fn the_control_token_never_leaves_server_memory() {
    let mut session = Fixture::new("topics-token");
    session.push(spawn_entry("Plan"));
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    let fake = FakeControl::start("token", empty_topics);
    let params = report(&pane, Some(&fake.path), omp, Some(omp));
    let response = send(&mut app, Method::PaneReportAgentControl(params.clone()));
    assert!(response.get("result").is_some(), "{response}");
    // Exercise the topics path so its events and logs exist too.
    let listed = topics(&app, list(&pane));
    assert_eq!(listed["result"]["topics"], json!([]), "{listed}");

    let mut outputs = vec![
        send(&mut app, Method::AgentList(Default::default())).to_string(),
        send(
            &mut app,
            Method::AgentGet(AgentTarget {
                target: pane.clone(),
            }),
        )
        .to_string(),
        send(&mut app, Method::SessionSnapshot(Default::default())).to_string(),
        serde_json::to_string(&crate::persist::capture(
            &app.state.workspaces,
            &app.state.terminals,
            &app.terminal_runtimes,
            app.state.active,
            app.state.selected,
            &app.state.archived_agents,
        ))
        .unwrap(),
        format!("{params:?}"),
        format!(
            "{:?}",
            app.agent_controls.handle(&terminal).unwrap().endpoint
        ),
    ];
    outputs.extend(
        app.event_hub
            .events_after(0)
            .into_iter()
            .map(|(_, event)| serde_json::to_string(&event).unwrap()),
    );
    for output in outputs {
        assert!(!output.contains(TOKEN), "the token leaked: {output}");
    }
}

#[test]
fn topics_list_tells_an_unreachable_agent_from_one_without_topics() {
    let session = Fixture::new("topics-reach");
    let omp = std::process::id();
    let (mut app, pane, _) = omp_app(&session.path, omp);

    // Nothing offered yet.
    let response = topics(&app, list(&pane));
    assert_eq!(
        response["error"]["code"], "topics_unreachable",
        "{response}"
    );

    let fake = FakeControl::start("reach", empty_topics);
    send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
    );
    let response = topics(&app, list(&pane));
    assert_eq!(response["result"]["type"], "agent_topics", "{response}");
    assert_eq!(response["result"]["topics"], json!([]));

    // The socket went away under a still-registered endpoint.
    drop(fake);
    let response = topics(&app, list(&pane));
    assert_eq!(
        response["error"]["code"], "topics_unreachable",
        "{response}"
    );
}

#[test]
fn topic_sessions_are_read_from_disk_whether_or_not_the_socket_answers() {
    let mut session = Fixture::new("topics-disk");
    session.push(spawn_entry("Plan"));
    let child = session.path.with_extension("").join("Plan.jsonl");
    std::fs::create_dir_all(child.parent().unwrap()).unwrap();
    std::fs::write(&child, "{\"type\":\"session\"}\n").unwrap();
    let omp = std::process::id();
    let (mut app, pane, _) = omp_app(&session.path, omp);
    let get = |app: &mut App| {
        send(
            app,
            Method::AgentGet(AgentTarget {
                target: pane.clone(),
            }),
        )["result"]["agent"]["topic_sessions"]
            .clone()
    };

    let without_socket = get(&mut app);
    assert_eq!(without_socket[0]["topic_id"], "Plan", "{without_socket}");
    assert_eq!(without_socket[0]["path"], child.display().to_string());

    // A registered socket that is down changes nothing.
    let missing = std::env::temp_dir().join("herdr-topics-down.sock");
    send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&missing), omp, Some(omp))),
    );
    assert_eq!(get(&mut app), without_socket);
    let listed = send(&mut app, Method::AgentList(Default::default()));
    assert_eq!(
        listed["result"]["agents"][0]["topic_sessions"], without_socket,
        "{listed}"
    );
}

/// Contract with an external consumer: workspace-janitor reads `agent list --json`
/// and protects `agent_session.value` plus every `topic_sessions[].path` from
/// archive, quarantine and expiry, failing closed on any other shape. Changing
/// these fields silently broke its nightly run once (topic_sessions went from
/// plain paths to objects). Tell workspace-janitor before changing this shape;
/// update this test only together with that notice.
#[test]
fn agent_list_keeps_the_session_file_shape_workspace_janitor_relies_on() {
    let mut session = Fixture::new("topics-janitor-contract");
    session.push(spawn_entry("Plan"));
    let child = session.path.with_extension("").join("Plan.jsonl");
    std::fs::create_dir_all(child.parent().unwrap()).unwrap();
    std::fs::write(&child, "{\"type\":\"session\"}\n").unwrap();
    let (mut app, _pane, _) = omp_app(&session.path, std::process::id());

    let listed = send(&mut app, Method::AgentList(Default::default()));
    let agent = &listed["result"]["agents"][0];

    let agent_session = &agent["agent_session"];
    assert_eq!(agent_session["kind"], "path", "{listed}");
    assert_eq!(
        agent_session["value"],
        session.path.display().to_string(),
        "{listed}"
    );

    let topics = agent["topic_sessions"]
        .as_array()
        .expect("topic_sessions is an array");
    assert_eq!(topics.len(), 1, "{listed}");
    let topic = topics[0]
        .as_object()
        .expect("each topic session is an object");
    let mut keys: Vec<&str> = topic.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["created_unix_ms", "path", "title", "topic_id"],
        "{listed}"
    );
    // `path` = the agent_session path without `.jsonl`, then `<topic_id>.jsonl`.
    let path = topic["path"].as_str().expect("path is a string");
    assert_eq!(path, child.display().to_string());
    assert!(std::path::Path::new(path).is_absolute(), "{path}");
    assert_eq!(topic["topic_id"], "Plan");
}

#[test]
fn the_control_is_dropped_on_clear_and_when_herdr_finds_another_omp_process() {
    let session = Fixture::new("topics-lifetime");
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    let fake = FakeControl::start("lifetime", empty_topics);
    let register = |app: &mut App| {
        send(
            app,
            Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
        )
    };

    register(&mut app);
    send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, None, omp, Some(omp))),
    );
    assert!(app.agent_controls.handle(&terminal).is_none(), "cleared");

    register(&mut app);
    // omp restarted in the pane: herdr's probe now finds another process.
    app.agent_controls.inspected_pid_for_test = Some(Some(omp + 1));
    let pane_id = app.state.workspaces[0].tabs[0].root_pane;
    app.reconcile_agent_control(0, pane_id);
    app.agent_controls.inspected_pid_for_test = Some(Some(omp));
    assert!(
        app.agent_controls.handle(&terminal).is_none(),
        "new process"
    );

    register(&mut app);
    app.shutdown_terminal_runtime(crate::terminal::TerminalId::from_persisted(
        terminal.clone(),
    ));
    assert!(
        app.agent_controls.handle(&terminal).is_none(),
        "terminal gone"
    );
}

#[test]
fn a_topic_change_from_the_agent_becomes_an_agent_topics_changed_event() {
    let session = Fixture::new("topics-events");
    let omp = std::process::id();
    let (mut app, pane, _) = omp_app(&session.path, omp);
    let fake = FakeControl::start("events", empty_topics);
    send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
    );
    // The first topics request also subscribes to the agent's changes.
    topics(&app, list(&pane));
    received(&fake, "subscribe");
    fake.updates
        .send(json!({"id": "Plan", "ownerId": "o", "parentSessionId": "p", "reason": "spawned"}))
        .unwrap();
    let event = next_topics_change(&mut app);
    app.handle_internal_event_with_render_impact(event);
    let emitted: Vec<_> = app
        .event_hub
        .events_after(0)
        .into_iter()
        .map(|(_, event)| serde_json::to_value(event).unwrap())
        .filter(|event| event["data"]["type"] == "agent_topics_changed")
        .collect();
    assert_eq!(emitted.len(), 1, "{emitted:?}");
    assert_eq!(emitted[0]["event"], "agent_topics_changed");
    assert_eq!(emitted[0]["data"]["pane_id"], pane);
    assert_eq!(emitted[0]["data"]["topic_id"], "Plan");
    assert_eq!(emitted[0]["data"]["reason"], "spawned");
}

#[test]
fn a_report_without_a_peer_pid_is_refused() {
    let session = Fixture::new("topics-no-peer");
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    let fake = FakeControl::start("no-peer", empty_topics);
    // The right pid in the body, but no socket that names the caller (TCP,
    // a relayed request).
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, None)),
    );
    assert_eq!(
        response["error"]["code"], "agent_control_refused",
        "{response}"
    );
    assert!(app.agent_controls.handle(&terminal).is_none());
}

#[test]
fn after_a_handoff_the_agents_re_report_restores_its_topics_idempotently() {
    let session = Fixture::new("topics-handoff");
    let omp = std::process::id();
    let (mut old, pane, terminal) = omp_app(&session.path, omp);
    let fake = FakeControl::start("handoff", empty_topics);
    let offer = report(&pane, Some(&fake.path), omp, Some(omp));
    send(&mut old, Method::PaneReportAgentControl(offer.clone()));
    assert!(old.agent_controls.handle(&terminal).is_some());

    // The replacement server imports the session state; the control map is
    // memory only and does not travel.
    let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut app = App::new(
        &Config::default(),
        crate::app::AppPolicy::TEST,
        None,
        api_rx,
        crate::api::EventHub::default(),
    );
    app.state = std::mem::replace(&mut old.state, crate::app::AppState::test_new());
    app.agent_controls.inspected_pid_for_test = Some(Some(omp));
    drop(old);
    let response = topics(&app, list(&pane));
    assert_eq!(
        response["error"]["code"], "topics_unreachable",
        "{response}"
    );

    // The extension's periodic re-report hands the socket over again.
    let response = send(&mut app, Method::PaneReportAgentControl(offer.clone()));
    assert!(response.get("result").is_some(), "{response}");
    let generation = app.agent_controls.handle(&terminal).unwrap().generation;
    let response = topics(&app, list(&pane));
    assert_eq!(response["result"]["topics"], json!([]), "{response}");

    // The same offer again changes nothing and announces nothing.
    let events_before = app.event_hub.events_after(0).len();
    let response = send(&mut app, Method::PaneReportAgentControl(offer));
    assert!(response.get("result").is_some(), "{response}");
    assert!(app.agent_controls.is_current(&terminal, generation));
    assert_eq!(app.event_hub.events_after(0).len(), events_before);
}

#[test]
fn a_self_consistent_impostor_is_refused_because_herdr_identifies_another_omp() {
    let session = Fixture::new("topics-impostor");
    let impostor = std::process::id();
    // A process in the pane reported the omp session with its own pid, and
    // reports the control from its own socket, so every self-report agrees.
    let (mut app, pane, terminal) = omp_app(&session.path, impostor);
    // herdr's own foreground probe identifies the real omp, another process.
    app.agent_controls.inspected_pid_for_test = Some(Some(impostor + 1));
    let fake = FakeControl::start("impostor", empty_topics);
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), impostor, Some(impostor))),
    );
    assert_eq!(
        response["error"]["code"], "agent_control_refused",
        "{response}"
    );
    assert!(app.agent_controls.handle(&terminal).is_none());
    // Nor when herdr's probe identifies no omp at all.
    app.agent_controls.inspected_pid_for_test = Some(None);
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), impostor, Some(impostor))),
    );
    assert_eq!(
        response["error"]["code"], "agent_control_refused",
        "{response}"
    );
}

#[test]
fn the_real_omp_identified_reported_and_connected_as_one_process_is_accepted() {
    let session = Fixture::new("topics-real");
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    let fake = FakeControl::start("real", empty_topics);
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
    );
    assert!(response.get("result").is_some(), "{response}");
    assert_eq!(
        app.agent_controls.handle(&terminal).unwrap().endpoint.pid,
        omp
    );
}

#[test]
fn a_session_report_naming_another_process_is_accepted_and_moves_no_control() {
    let session = Fixture::new("topics-helper-pid");
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    let fake = FakeControl::start("helper-pid", empty_topics);
    send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
    );
    // `herdr pane report-agent-session --agent-process-pid` names another
    // process (a helper, or a process claiming to be omp): still accepted.
    let request: Request = serde_json::from_value(json!({
        "id": "s", "method": "pane.report_agent_session", "params": {
            "pane_id": pane, "source": "herdr:omp", "agent": "omp",
            "agent_session_path": session.path.display().to_string(),
            "agent_process_pid": omp + 1, "seq": u64::MAX / 2,
        },
    }))
    .unwrap();
    let response = send(&mut app, request.method);
    assert!(response.get("result").is_some(), "{response}");
    // The control stays with the omp process herdr identifies.
    assert_eq!(
        app.agent_controls.handle(&terminal).unwrap().endpoint.pid,
        omp
    );
    let listed = topics(&app, list(&pane));
    assert_eq!(listed["result"]["topics"], json!([]), "{listed}");
}

/// A fake topics build the switch accepts: an executable file.
fn usable_topics_build(name: &str) -> crate::config::TopicsConfig {
    let dir = std::env::temp_dir().join(format!(
        "herdr-topics-control-build-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let binary = dir.join("omp");
    std::fs::write(&binary, "#!/bin/sh\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    crate::config::TopicsConfig {
        omp_binary: Some(binary),
        omp_config: None,
    }
}

/// An omp already on a topics build (it offers a control) but never switched on:
/// switching it on records the choice, so a later restart, restore or unarchive
/// stays on the topics build, and it is not relaunched for nothing.
#[test]
fn switching_on_an_omp_that_already_offers_topics_records_the_choice() {
    let session = Fixture::new("topics-switch-control");
    let omp = std::process::id();
    let (mut app, pane, terminal) = omp_app(&session.path, omp);
    app.topics_config = usable_topics_build("record");
    // Short tag: the socket path must fit macOS's 104-byte SUN_LEN.
    let fake = FakeControl::start("switch", empty_topics);
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
    );
    assert!(response.get("result").is_some(), "{response}");
    let terminal_id = crate::terminal::TerminalId::from_persisted(terminal.clone());
    assert!(!app.state.terminals[&terminal_id].agent_topics_enabled);

    let response = send(
        &mut app,
        Method::AgentTopicsSetEnabled(crate::api::schema::AgentTopicsSetEnabledParams {
            target: pane.clone(),
            enabled: true,
            when_idle: false,
        }),
    );

    assert_eq!(response["result"]["topics_enabled"], true, "{response}");
    assert_eq!(response["result"]["changed"], true, "{response}");
    let state = &app.state.terminals[&terminal_id];
    assert!(state.agent_topics_enabled, "the choice was not recorded");
    assert!(
        state.pending_agent_resume_plan.is_none(),
        "an omp already on the topics build was relaunched"
    );
    // Asked again, nothing changes.
    let response = send(
        &mut app,
        Method::AgentTopicsSetEnabled(crate::api::schema::AgentTopicsSetEnabledParams {
            target: pane,
            enabled: true,
            when_idle: false,
        }),
    );
    assert_eq!(response["result"]["changed"], false, "{response}");
}

/// An `agent.topics.*` request as a client sends it.
fn wire(method: &str, params: Value) -> Method {
    serde_json::from_value::<Request>(json!({"id": "t", "method": method, "params": params}))
        .unwrap()
        .method
}

/// An app whose omp offered the control `fake` serves.
fn offered(tag: &str, fake: &FakeControl) -> (Fixture, App, String) {
    let session = Fixture::new(tag);
    let omp = std::process::id();
    let (mut app, pane, _) = omp_app(&session.path, omp);
    send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&fake.path), omp, Some(omp))),
    );
    (session, app, pane)
}

/// How long a test waits for one thing the agent or the app's worker
/// threads do: generous for a loaded CI runner, still red when it never
/// happens.
const WAIT: Duration = Duration::from_secs(60);

/// The next `kind` frame the agent read, skipping any others.
fn received(fake: &FakeControl, kind: &str) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let frame = fake
            .frames
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("the agent never got {kind}"));
        if frame["type"] == kind {
            return frame;
        }
    }
}

/// The next topic change the app's reader thread queued, skipping other
/// app events; each call gets its own deadline.
fn next_topics_change(app: &mut App) -> crate::events::AppEvent {
    let deadline = Instant::now() + WAIT;
    loop {
        match app.event_rx.try_recv() {
            Ok(event @ crate::events::AppEvent::AgentTopicsChanged { .. }) => return event,
            Ok(_) => {}
            Err(_) => {
                assert!(Instant::now() < deadline, "no agent.topics.changed");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[test]
fn the_owner_acts_on_suggestions_as_owner_and_a_repeat_is_a_success() {
    let fake = FakeControl::start("sg-owner", |frame| {
        let again = frame["suggestionId"] == "sg_again";
        match frame["type"].as_str().unwrap_or_default() {
            "topics_accept_suggestion" => {
                json!({"success": true, "data": {"topicId": "T1", "alreadyAccepted": again}})
            }
            "topics_dismiss_suggestion" => {
                json!({"success": true, "data": {"alreadyDismissed": again}})
            }
            "topics_organise" => json!({"success": true, "data": {"queued": false}}),
            _ => json!({"success": true, "data": {"topics": []}}),
        }
    });
    let (_session, mut app, pane) = offered("sg-owner", &fake);
    // The first topics request also subscribes to the agent's changes; wait
    // for it before the commands, whose frames `received` skips past.
    topics(&app, list(&pane));
    received(&fake, "subscribe");

    let accepted = topics(
        &app,
        wire(
            "agent.topics.accept_suggestion",
            json!({"target": pane, "suggestion_id": "sg_1"}),
        ),
    );
    assert_eq!(
        accepted["result"],
        json!({"type": "agent_topic_suggestion_accepted", "agent": "omp", "pane_id": pane,
            "suggestion_id": "sg_1", "topic_id": "T1", "already_accepted": false}),
        "{accepted}"
    );
    let frame = received(&fake, "topics_accept_suggestion");
    assert_eq!(frame["suggestionId"], "sg_1");
    // The agent picked the messages: herdr forwards none.
    assert!(frame.get("messageIds").is_none(), "{frame}");
    assert_eq!(frame["by"], "owner");

    // A repeat answers the same topic as a success.
    let again = topics(
        &app,
        wire(
            "agent.topics.accept_suggestion",
            json!({"target": pane, "suggestion_id": "sg_again"}),
        ),
    );
    assert_eq!(again["result"]["already_accepted"], true, "{again}");
    assert_eq!(again["result"]["topic_id"], "T1", "{again}");

    let dismissed = topics(
        &app,
        wire(
            "agent.topics.dismiss_suggestion",
            json!({"target": pane, "suggestion_id": "sg_2"}),
        ),
    );
    assert_eq!(
        dismissed["result"],
        json!({"type": "agent_topic_suggestion_dismissed", "agent": "omp", "pane_id": pane,
            "suggestion_id": "sg_2", "already_dismissed": false}),
        "{dismissed}"
    );
    assert_eq!(received(&fake, "topics_dismiss_suggestion")["by"], "owner");
    let again = topics(
        &app,
        wire(
            "agent.topics.dismiss_suggestion",
            json!({"target": pane, "suggestion_id": "sg_again"}),
        ),
    );
    assert_eq!(again["result"]["already_dismissed"], true, "{again}");

    let organised = topics(&app, wire("agent.topics.organise", json!({"target": pane})));
    assert_eq!(
        organised["result"],
        json!({"type": "agent_topics_organise_started", "agent": "omp", "pane_id": pane,
            "queued": false}),
        "{organised}"
    );
    assert_eq!(received(&fake, "topics_organise")["by"], "owner");

    // The guest gate names a guest; herdr passes the name as `by`.
    topics(
        &app,
        Method::AgentTopicsOrganise(crate::api::schema::AgentTopicsOrganiseParams {
            target: pane.clone(),
            acting_guest: Some("Ana (via HerdrUp)".into()),
        }),
    );
    assert_eq!(
        received(&fake, "topics_organise")["by"],
        "Ana (via HerdrUp)"
    );

    // The agent announces each suggestion change on its `topic_update`
    // stream (which the requests above subscribed to), naming the
    // suggestion: each one is an `agent.topics.changed` with
    // `suggestion_id`, not a topic id.
    for (id, reason) in [
        ("sg_3", "suggested"),
        ("sg_1", "suggestion-accepted"),
        ("sg_2", "suggestion-dismissed"),
    ] {
        fake.updates
            .send(json!({"id": id, "ownerId": "o", "parentSessionId": "p", "reason": reason}))
            .unwrap();
    }
    let changes: Vec<_> = (0..3).map(|_| next_topics_change(&mut app)).collect();
    for change in changes {
        app.handle_internal_event_with_render_impact(change);
    }
    let emitted: Vec<_> = app
        .event_hub
        .events_after(0)
        .into_iter()
        .map(|(_, event)| serde_json::to_value(event).unwrap()["data"].clone())
        .filter(|data| data["type"] == "agent_topics_changed")
        .collect();
    let workspace = emitted[0]["workspace_id"].clone();
    assert_eq!(
        emitted,
        [
            json!({"type": "agent_topics_changed", "pane_id": pane, "workspace_id": workspace,
                "agent": "omp", "topic_id": "", "reason": "suggested", "suggestion_id": "sg_3"}),
            json!({"type": "agent_topics_changed", "pane_id": pane, "workspace_id": workspace,
                "agent": "omp", "topic_id": "", "reason": "suggestion_accepted", "suggestion_id": "sg_1"}),
            json!({"type": "agent_topics_changed", "pane_id": pane, "workspace_id": workspace,
                "agent": "omp", "topic_id": "", "reason": "suggestion_dismissed", "suggestion_id": "sg_2"}),
        ]
    );
}

#[test]
fn a_suggestion_refusal_keeps_the_agents_code() {
    let fake = FakeControl::start("sg-codes", |frame| {
        let code = match frame["type"].as_str().unwrap_or_default() {
            "topics_organise" => "organise_running",
            _ => frame["suggestionId"].as_str().unwrap_or("topic_rejected"),
        };
        json!({"success": false, "error": format!("refused: {code}"), "code": code})
    });
    let (_session, app, pane) = offered("sg-codes", &fake);
    for code in [
        "suggestion_not_found",
        "invalid_message_ids",
        "topics_disabled",
    ] {
        let response = topics(
            &app,
            wire(
                "agent.topics.accept_suggestion",
                json!({"target": pane, "suggestion_id": code}),
            ),
        );
        assert_eq!(response["error"]["code"], code, "{response}");
        assert_eq!(response["error"]["message"], format!("refused: {code}"));
    }
    let response = topics(
        &app,
        wire(
            "agent.topics.dismiss_suggestion",
            json!({"target": pane, "suggestion_id": "already_accepted"}),
        ),
    );
    assert_eq!(response["error"]["code"], "already_accepted", "{response}");
    let response = topics(&app, wire("agent.topics.organise", json!({"target": pane})));
    assert_eq!(response["error"]["code"], "organise_running", "{response}");
}

/// The agent's copy of the suggestion's messages cannot fit the topic's model
/// even trimmed: the accept is refused with the agent's `seed_too_large`, no
/// topic starts, and the suggestion is still listed open, so it can be
/// accepted again.
#[test]
fn an_oversized_seed_refuses_the_accept_and_the_suggestion_stays_open() {
    let open = json!({"id": "sg_big", "title": "Release notes", "reason": "a separate subject",
        "messageIds": ["m1"], "createdMs": 5_000});
    let fake = FakeControl::start("sg-seed", move |frame| {
        match frame["type"].as_str().unwrap_or_default() {
            "topics_accept_suggestion" => json!({"success": false,
                "error": "The picked messages do not fit the topic's model.",
                "code": "seed_too_large"}),
            _ => json!({"success": true, "data": {"topics": [], "suggestions": [open.clone()]}}),
        }
    });
    let (_session, mut app, pane) = offered("sg-seed", &fake);
    topics(&app, list(&pane));
    received(&fake, "subscribe");

    let response = topics(
        &app,
        wire(
            "agent.topics.accept_suggestion",
            json!({"target": pane, "suggestion_id": "sg_big"}),
        ),
    );
    assert_eq!(response["error"]["code"], "seed_too_large", "{response}");
    assert_eq!(
        response["error"]["message"],
        "The picked messages do not fit the topic's model."
    );
    assert_eq!(
        received(&fake, "topics_accept_suggestion")["suggestionId"],
        "sg_big"
    );

    let response = topics(&app, list(&pane));
    assert_eq!(
        response["result"]["suggestions"][0]["suggestion_id"], "sg_big",
        "{response}"
    );
    while let Ok(event) = app.event_rx.try_recv() {
        app.handle_internal_event_with_render_impact(event);
    }
    assert!(
        app.event_hub
            .events_after(0)
            .into_iter()
            .all(
                |(_, event)| serde_json::to_value(event).unwrap()["data"]["type"]
                    != "agent_topics_changed"
            ),
        "a refused accept changed nothing"
    );
}

/// The late case: the accept succeeded, but the topic ended before its first
/// turn. The agent says so on its `topic_update` stream once, naming the
/// topic, the suggestion (still open) and why; herdr passes it on as an
/// `agent.topics.changed` the apps refresh on.
#[test]
fn a_topic_that_never_started_is_an_agent_topics_change_naming_the_suggestion() {
    let fake = FakeControl::start("sg-late", empty_topics);
    let (_session, mut app, pane) = offered("sg-late", &fake);
    topics(&app, list(&pane));
    received(&fake, "subscribe");

    fake.updates
        .send(json!({"id": "T2", "ownerId": "o", "parentSessionId": "p",
            "reason": "start-failed", "suggestionId": "sg_big", "code": "seed_too_large",
            "tokens": 210_000, "limit": 128_000}))
        .unwrap();
    let change = next_topics_change(&mut app);
    app.handle_internal_event_with_render_impact(change);
    let emitted: Vec<_> = app
        .event_hub
        .events_after(0)
        .into_iter()
        .map(|(_, event)| serde_json::to_value(event).unwrap()["data"].clone())
        .filter(|data| data["type"] == "agent_topics_changed")
        .collect();
    let workspace = emitted[0]["workspace_id"].clone();
    assert_eq!(
        emitted,
        [
            json!({"type": "agent_topics_changed", "pane_id": pane, "workspace_id": workspace,
            "agent": "omp", "topic_id": "T2", "reason": "start_failed",
            "suggestion_id": "sg_big", "code": "seed_too_large"})
        ]
    );
}

#[test]
fn topics_list_passes_only_open_suggestions_through() {
    let fake = FakeControl::start("sg-list", |_| {
        json!({"success": true, "data": {"topics": [], "suggestions": [
            {"id": "sg_open", "title": "Release notes", "reason": "a separate subject",
                "messageIds": ["m1", "m2"], "createdMs": 5_000},
            {"id": "sg_gone", "title": "Old", "reason": "r", "messageIds": [], "createdMs": 1,
                "state": "dismissed"},
        ]}})
    });
    let (_session, app, pane) = offered("sg-list", &fake);
    let response = topics(&app, list(&pane));
    assert_eq!(
        response["result"]["suggestions"],
        json!([{"suggestion_id": "sg_open", "title": "Release notes",
            "reason": "a separate subject", "message_ids": ["m1", "m2"],
            "created_unix_ms": 5_000}]),
        "{response}"
    );

    // An omp without suggestions lists none rather than an empty list.
    let older = FakeControl::start("sg-list-0", empty_topics);
    let (_session, app, pane) = offered("sg-list-0", &older);
    let response = topics(&app, list(&pane));
    assert_eq!(response["result"]["topics"], json!([]), "{response}");
    assert!(
        response["result"].get("suggestions").is_none(),
        "{response}"
    );
}

#[test]
fn an_omp_without_suggestions_answers_topics_unsupported() {
    let fake = FakeControl::start("sg-old", |frame| {
        if frame["type"] == "topics_list" {
            empty_topics(frame)
        } else {
            json!({"success": false, "error": "Unknown command."})
        }
    });
    let (_session, app, pane) = offered("sg-old", &fake);
    let response = topics(
        &app,
        wire(
            "agent.topics.dismiss_suggestion",
            json!({"target": pane, "suggestion_id": "sg_1"}),
        ),
    );
    assert_eq!(
        response["error"]["code"], "topics_unsupported",
        "{response}"
    );
}
