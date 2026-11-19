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
    serde_json::from_str(&response.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap()
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
fn a_pane_without_a_reported_omp_process_accepts_no_control() {
    let session = Fixture::new("topics-no-omp");
    let (mut app, pane, terminal) = omp_app(&session.path, 4242);
    let terminal_state = app.state.terminals.get_mut(terminal.as_str()).unwrap();
    // The pane's omp claim is gone: no session report names a process.
    terminal_state.forget_inactive_agent_claim();
    let response = send(
        &mut app,
        Method::PaneReportAgentControl(report(&pane, Some(&session.path), 4242, None)),
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

#[test]
fn the_control_is_dropped_on_clear_and_when_omp_reports_another_process() {
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
    // omp restarted in the pane: its session report names a new process.
    let session_ref =
        crate::agent_resume::AgentSessionRef::path(session.path.display().to_string()).unwrap();
    app.state
        .terminals
        .get_mut(terminal.as_str())
        .unwrap()
        .set_reported_agent_session_runtime("herdr:omp", "omp", &session_ref, None, Some(omp + 1));
    let pane_id = app.state.workspaces[0].tabs[0].root_pane;
    app.reconcile_agent_control(0, pane_id);
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
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let frame = fake.frames.recv_timeout(Duration::from_secs(10)).unwrap();
        if frame["type"] == "subscribe" {
            break;
        }
        assert!(Instant::now() < deadline, "no subscription");
    }
    fake.updates
        .send(json!({"id": "Plan", "ownerId": "o", "parentSessionId": "p", "reason": "spawned"}))
        .unwrap();
    let event = loop {
        match app.event_rx.try_recv() {
            Ok(event @ crate::events::AppEvent::AgentTopicsChanged { .. }) => break event,
            Ok(_) => {}
            Err(_) => {
                assert!(Instant::now() < deadline, "no topic change");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
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
