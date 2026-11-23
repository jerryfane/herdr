use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};

use super::*;
use crate::api::server::remote_gate::test_app::{
    ask, hang_up_after_reply, read_reply, start, Harness,
};
use crate::guest::owner::{remove_in, renew_in, test_principal, RemoveTarget};

const BROWSER: [u8; 32] = [0x42; 32];

/// Every API method and who may call it: `chat` (both scopes), `terminal`
/// (terminal scope only) or `-` (refused). A method missing here fails the
/// test, so each new method gets a decision.
const TABLE: &[(&str, &str)] = &[
    ("ping", "chat"),
    ("server.stop", "-"),
    ("server.live_handoff", "-"),
    ("server.reload_config", "-"),
    ("machine.status", "-"),
    ("server.staged_update", "-"),
    ("server.apply_staged_update", "-"),
    ("server.update_check", "terminal"),
    ("server.update_apply", "terminal"),
    ("server.update_status", "terminal"),
    ("server.ssh_agent.register", "-"),
    ("server.agent_manifests", "-"),
    ("server.reload_agent_manifests", "-"),
    ("notification.show", "-"),
    ("product_announcement.dismiss", "-"),
    ("release_notes.dismiss", "-"),
    ("command.invoke", "-"),
    ("notifications.register_device", "-"),
    ("notifications.unregister_device", "-"),
    ("notifications.register_activity", "-"),
    ("notifications.unregister_activity", "-"),
    ("notifications.status", "-"),
    ("gram.send", "-"),
    ("gram.post", "chat"),
    ("gram.list", "chat"),
    ("gram.grab", "-"),
    ("gram.mark_read", "chat"),
    ("gram.delete", "-"),
    ("gram.upload_chunk", "chat"),
    ("gram.upload.discard", "chat"),
    ("gram.get_file", "chat"),
    ("gram.get_file_chunk", "chat"),
    ("gram.relay", "-"),
    ("gram.relay_status", "-"),
    ("guest.invite.create", "terminal"),
    ("guest.list", "terminal"),
    ("guest.revoke", "terminal"),
    ("guest.update", "terminal"),
    ("guest.remove_device", "terminal"),
    ("guest.audit", "terminal"),
    ("owner_access.info", "-"),
    ("owner_access.list", "-"),
    ("owner_access.add", "-"),
    ("owner_access.renew", "-"),
    ("owner_access.remove", "-"),
    ("guest.agent_probe", "-"),
    ("client.window_title.set", "-"),
    ("client.window_title.clear", "-"),
    ("client_shell.surface.set", "-"),
    ("session.snapshot", "-"),
    ("workspace.create", "-"),
    ("workspace.list", "terminal"),
    ("workspace.get", "-"),
    ("workspace.focus", "-"),
    ("workspace.rename", "-"),
    ("workspace.move", "-"),
    ("workspace.move_block", "-"),
    ("workspace.report_metadata", "-"),
    ("workspace.close", "-"),
    ("worktree.list", "-"),
    ("worktree.create", "-"),
    ("worktree.open", "-"),
    ("worktree.remove", "-"),
    ("tab.create", "-"),
    ("tab.list", "terminal"),
    ("tab.get", "-"),
    ("tab.focus", "-"),
    ("tab.rename", "-"),
    ("tab.move", "-"),
    ("tab.close", "-"),
    ("agent.list", "chat"),
    ("agent.get", "chat"),
    ("agent.read", "chat"),
    ("agent.transcript", "chat"),
    ("agent.explain", "-"),
    ("fence.explain", "-"),
    ("agent.send_keys", "terminal"),
    ("agent.rename", "terminal"),
    ("agent.avatar.set", "terminal"),
    ("agent.avatar.get", "chat"),
    ("agent.groups.get", "chat"),
    ("agent.groups.set", "terminal"),
    ("agent.archive", "terminal"),
    ("agent.unarchive", "-"),
    ("agent.forget", "-"),
    ("agent.view.set", "-"),
    ("agent.view.clear", "-"),
    ("agent.focus", "-"),
    ("agent.start", "terminal"),
    ("agent.prompt", "chat"),
    ("agent.wait", "-"),
    ("agent.answer", "chat"),
    ("agent.answer_form", "chat"),
    ("agent.dismiss_ask", "chat"),
    ("agent.restart", "terminal"),
    ("agent.transfer_session", "-"),
    ("accounts.list", "terminal"),
    ("accounts.create", "terminal"),
    ("accounts.remove", "terminal"),
    ("agent.kinds", "terminal"),
    ("fs.list_dir", "terminal"),
    ("pane.split", "terminal"),
    ("pane.swap", "-"),
    ("pane.move", "-"),
    ("pane.zoom", "-"),
    ("pane.layout", "-"),
    ("pane.process_info", "-"),
    ("layout.export", "-"),
    ("layout.apply", "-"),
    ("layout.set_split_ratio", "-"),
    ("pane.neighbor", "-"),
    ("pane.edges", "-"),
    ("pane.focus_direction", "-"),
    ("pane.resize", "-"),
    ("pane.scroll", "-"),
    ("pane.clear", "-"),
    ("pane.edit_scrollback", "-"),
    ("pane.selection.read", "-"),
    ("pane.copy_motion", "-"),
    ("pane.copy_search", "-"),
    ("pane.set_pty_size", "chat"),
    ("pane.list", "terminal"),
    ("pane.current", "-"),
    ("pane.get", "terminal"),
    ("pane.turns", "-"),
    ("pane.focus", "-"),
    ("pane.input.set", "-"),
    ("pane.link.activate", "-"),
    ("pane.link.resolve", "-"),
    ("pane.rename", "terminal"),
    ("pane.send_text", "terminal"),
    ("pane.send_keys", "chat"),
    ("pane.send_input", "terminal"),
    ("pane.read", "terminal"),
    ("pane.history", "chat"),
    ("pane.stream", "chat"),
    ("pane.stream.open", "-"),
    ("pane.stream.close", "-"),
    ("pane.pty_lease.release", "-"),
    ("pane.input.stream", "terminal"),
    ("pane.input.stream.open", "-"),
    ("gram.upload.stream", "-"),
    ("gram.upload.stream.open", "-"),
    ("fence.scoped", "-"),
    ("pane.report_agent", "-"),
    ("pane.report_agent_session", "-"),
    ("pane.report_metadata", "-"),
    ("pane.clear_agent_authority", "-"),
    ("pane.release_agent", "-"),
    ("pane.close", "terminal"),
    ("popup.close", "-"),
    ("events.subscribe", "chat"),
    ("events.wait", "-"),
    ("pane.wait_for_output", "-"),
    ("integration.list", "-"),
    ("integration.install", "-"),
    ("integration.uninstall", "-"),
    ("plugin.link", "-"),
    ("plugin.list", "-"),
    ("plugin.unlink", "-"),
    ("plugin.enable", "-"),
    ("plugin.disable", "-"),
    ("plugin.action.list", "-"),
    ("plugin.action.invoke", "-"),
    ("plugin.log.list", "-"),
    ("plugin.pane.open", "-"),
    ("plugin.pane.focus", "-"),
    ("plugin.pane.close", "-"),
    ("pane.report_agent_control", "-"),
    ("agent.topics.list", "chat"),
    ("agent.topics.new", "chat"),
    ("agent.topics.send", "chat"),
    ("agent.topics.close", "chat"),
    ("agent.topics.reopen", "chat"),
    ("agent.topics.rename", "chat"),
    ("agent.topics.set_enabled", "-"),
    ("agent.topics.accept_suggestion", "chat"),
    ("agent.topics.dismiss_suggestion", "chat"),
    ("agent.topics.organise", "chat"),
];

#[test]
fn every_method_is_allowed_or_refused_per_scope_as_the_table_says() {
    let operations: std::collections::BTreeSet<&str> = Method::OPERATIONS
        .iter()
        .map(|operation| operation.name)
        .collect();
    let listed: std::collections::BTreeSet<&str> = TABLE.iter().map(|(name, _)| *name).collect();
    assert_eq!(TABLE.len(), listed.len(), "a method is listed twice");
    let missing: Vec<_> = operations.difference(&listed).collect();
    assert!(missing.is_empty(), "decide for these methods: {missing:?}");
    let unknown: Vec<_> = listed.difference(&operations).collect();
    assert!(unknown.is_empty(), "not API methods: {unknown:?}");
    for (name, who) in TABLE {
        let (chat, terminal) = match *who {
            "chat" => (true, true),
            "terminal" => (false, true),
            "-" => (false, false),
            other => panic!("{name}: {other}"),
        };
        assert_eq!(allowed(name, OwnerScope::Chat), chat, "{name} for chat");
        assert_eq!(
            allowed(name, OwnerScope::Terminal),
            terminal,
            "{name} for terminal"
        );
    }
}

#[test]
fn targets_naming_a_federation_peer_are_spotted_anywhere_in_the_params() {
    let method = |json: Value| serde_json::from_value::<Request>(json).unwrap().method;
    for request in [
        json!({"id": "1", "method": "agent.get", "params": {"target": "studio/builder"}}),
        json!({"id": "1", "method": "pane.send_text", "params": {"pane_id": "studio/w1:p1", "text": "x"}}),
        json!({"id": "1", "method": "tab.list", "params": {"workspace_id": "studio/w1"}}),
        json!({"id": "1", "method": "gram.post", "params": {"text": "x", "to": "studio/builder"}}),
        json!({"id": "1", "method": "events.subscribe", "params": {"subscriptions": [{"type": "pane.agent_status_changed", "pane_id": "studio/w1:p1"}]}}),
    ] {
        assert!(names_remote(&method(request.clone())), "{request}");
    }
    for request in [
        json!({"id": "1", "method": "agent.get", "params": {"target": "builder"}}),
        json!({"id": "1", "method": "agent.prompt", "params": {"target": "w1:p1", "text": "a/b and c/d"}}),
    ] {
        assert!(!names_remote(&method(request.clone())), "{request}");
    }
}

/// One owner browser connection: the first request, then each reply.
fn open(
    harness: &Harness,
    owner: OwnerPrincipal,
    request: Value,
) -> (BufReader<UnixStream>, JoinHandle<()>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    let (api_tx, event_hub, running) = (
        harness.api_tx.clone(),
        harness.event_hub.clone(),
        Arc::clone(&harness.running),
    );
    let handle = std::thread::spawn(move || {
        let _ = serve_owner_with(&api_tx, &event_hub, &running, owner, server);
    });
    writeln!(client, "{request}").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (BufReader::new(client), handle)
}

fn code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("<success>")
}

fn owner(harness: &Harness, scope: OwnerScope) -> OwnerPrincipal {
    test_principal(&harness.dir.0, BROWSER, scope)
}

/// Sends each request on one connection and returns each reply's code.
fn codes(harness: &Harness, scope: OwnerScope, requests: &[Value]) -> Vec<String> {
    let (first, rest) = requests.split_first().unwrap();
    let (mut reader, handle) = open(harness, owner(harness, scope), first.clone());
    let mut codes = vec![code(&read_reply(&mut reader).unwrap()).to_owned()];
    for request in rest {
        codes.push(code(&ask(&mut reader, request.clone())).to_owned());
    }
    hang_up_after_reply(reader.get_ref());
    handle.join().unwrap();
    codes
}

#[test]
fn chat_scope_never_types_into_a_terminal_and_reaches_agents_only() {
    let harness = start("owner-chat");
    let pane = harness.pane_ids[0].clone();
    let requests = [
        json!({"id": "1", "method": "pane.send_text", "params": {"pane_id": pane, "text": "rm -rf ~\n"}}),
        json!({"id": "2", "method": "pane.send_keys", "params": {"pane_id": pane, "keys": ["a"]}}),
        // The agent is idle, not waiting on a menu.
        json!({"id": "3", "method": "pane.send_keys", "params": {"pane_id": pane, "keys": ["Enter"]}}),
        json!({"id": "4", "method": "pane.list", "params": {}}),
        json!({"id": "5", "method": "pane.input.stream", "params": {"pane_id": pane}}),
        json!({"id": "6", "method": "agent.send_keys", "params": {"target": "llm-opt", "keys": ["a"]}}),
        json!({"id": "7", "method": "events.subscribe", "params": {"subscriptions": [{"type": "pane.created"}]}}),
        // A focused pane may be a shell.
        json!({"id": "8", "method": "pane.set_pty_size", "params": {"cols": 80, "rows": 24}}),
        json!({"id": "9", "method": "agent.get", "params": {"target": "llm-opt"}}),
    ];
    let codes = codes(&harness, OwnerScope::Chat, &requests);
    let refused = vec!["owner_forbidden".to_owned(); 8];
    assert_eq!(codes[..8], refused[..], "{codes:?}");
    assert_eq!(codes[8], "<success>", "a local agent is reachable");
    assert!(harness.pty_text(0, Duration::from_millis(200)).is_empty());

    // Prompts arrive as the owner's own, unlabeled.
    let (mut reader, handle) = open(
        &harness,
        owner(&harness, OwnerScope::Chat),
        json!({"id": "p", "method": "agent.prompt", "params": {"target": "llm-opt", "text": "hello"}}),
    );
    let reply = read_reply(&mut reader).unwrap();
    assert_eq!(code(&reply), "<success>", "{reply}");
    hang_up_after_reply(reader.get_ref());
    handle.join().unwrap();
    let typed = harness.pty_text(0, Duration::from_millis(500));
    assert!(typed.contains("hello"), "{typed:?}");
    assert!(!typed.contains("via HerdrUp"), "{typed:?}");
}

#[test]
fn terminal_scope_types_into_any_local_pane() {
    let harness = start("owner-terminal");
    let codes = codes(
        &harness,
        OwnerScope::Terminal,
        &[
            json!({"id": "1", "method": "pane.send_text", "params": {"pane_id": harness.pane_ids[1], "text": "ls"}}),
            json!({"id": "2", "method": "pane.list", "params": {}}),
            json!({"id": "3", "method": "workspace.list", "params": {}}),
        ],
    );
    assert_eq!(codes, ["<success>"; 3], "{codes:?}");
    assert!(harness
        .pty_text(1, Duration::from_millis(500))
        .contains("ls"));
}

#[test]
fn both_scopes_refuse_peers_grants_server_and_forged_gram_and_stay_open() {
    let harness = start("owner-forbidden");
    for scope in [OwnerScope::Chat, OwnerScope::Terminal] {
        let requests = [
            json!({"id": "1", "method": "agent.get", "params": {"target": "studio/builder"}}),
            json!({"id": "2", "method": "pane.stream", "params": {"pane_id": "studio/w1:p1"}}),
            json!({"id": "3", "method": "guest.list", "params": {"machine": "studio"}}),
            json!({"id": "4", "method": "owner_access.list", "params": {}}),
            json!({"id": "5", "method": "owner_access.add", "params": {"device_pub": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI", "device_name": "x", "ttl_secs": 3600, "account_statement": "a.b.c", "approved_by": "x"}}),
            json!({"id": "6", "method": "gram.send", "params": {"text": "x", "from": "llm-opt"}}),
            json!({"id": "7", "method": "server.stop", "params": {}}),
            json!({"id": "8", "method": "agent.topics.set_enabled", "params": {"target": "llm-opt", "enabled": true}}),
            json!({"id": "9", "method": "ping", "params": {}}),
        ];
        let codes = codes(&harness, scope, &requests);
        let refused = vec!["owner_forbidden".to_owned(); 8];
        assert_eq!(codes[..8], refused[..], "{scope:?}: {codes:?}");
        assert_eq!(codes[8], "<success>", "{scope:?}: the session stayed open");
    }
    let denied = crate::guest::audit::read(&harness.dir.0, None, None, 500)
        .unwrap()
        .iter()
        .filter(|entry| entry.event == GuestAuditEvent::OwnerDenied)
        .count();
    assert!(denied > 0, "refusals are audited");
}

#[test]
fn ping_reports_the_owner_protocol_and_scope_but_not_the_owners_capabilities() {
    let harness = start("owner-ping");
    for (scope, input_stream) in [(OwnerScope::Chat, false), (OwnerScope::Terminal, true)] {
        let (mut reader, handle) = open(
            &harness,
            owner(&harness, scope),
            json!({"id": "1", "method": "ping", "params": {}}),
        );
        let pong = read_reply(&mut reader).unwrap();
        hang_up_after_reply(reader.get_ref());
        handle.join().unwrap();
        let capabilities = &pong["result"]["capabilities"];
        assert_eq!(capabilities["owner"], 2, "{pong}");
        assert_eq!(capabilities["owner_scope"], json!(scope), "{pong}");
        assert_eq!(capabilities["agent_transcript"], true, "{pong}");
        assert_eq!(capabilities["agent_topic_suggestions"], true, "{pong}");
        assert_eq!(capabilities["agent_read_recent_unwrapped"], true, "{pong}");
        assert_eq!(
            capabilities.get("server_update").is_some(),
            input_stream,
            "{pong}"
        );
        assert!(
            capabilities.get("ssh_agent_registration").is_none(),
            "{pong}"
        );
        assert_eq!(
            capabilities.get("pane_input_stream").is_some(),
            input_stream,
            "{pong}"
        );
    }
}

/// The web owner page's "Copy recent" (`recent_unwrapped`) and its topic
/// suggestion and Organise actions reach a local agent in chat scope; they
/// may fail in the app (no topics control here), never at the gate.
#[test]
fn chat_scope_copies_recent_and_acts_on_topic_suggestions() {
    let harness = start("owner-chat-web");
    let target = harness.pane_ids[0].clone();
    let requests = [
        json!({"id": "1", "method": "agent.read", "params": {"target": target, "source": "recent_unwrapped"}}),
        json!({"id": "2", "method": "agent.topics.accept_suggestion", "params": {"target": target, "suggestion_id": "s1"}}),
        json!({"id": "3", "method": "agent.topics.dismiss_suggestion", "params": {"target": target, "suggestion_id": "s1"}}),
        json!({"id": "4", "method": "agent.topics.organise", "params": {"target": target}}),
    ];
    let replies = codes(&harness, OwnerScope::Chat, &requests);
    assert_eq!(replies[0], "<success>", "{replies:?}");
    for (request, code) in requests.iter().zip(&replies) {
        assert_ne!(code, "owner_forbidden", "{request}");
    }
    // Still local only, and reads are still capped rather than refused.
    let more = codes(
        &harness,
        OwnerScope::Chat,
        &[
            json!({"id": "5", "method": "agent.topics.organise", "params": {"target": "studio/builder"}}),
            json!({"id": "6", "method": "agent.read", "params": {"target": target, "source": "recent_unwrapped", "lines": 5000}}),
        ],
    );
    assert_eq!(more, ["owner_forbidden", "<success>"], "{more:?}");
}

#[test]
fn a_removed_grant_ends_its_stream_and_refuses_the_next_request() {
    let harness = start("owner-removed");
    let principal = owner(&harness, OwnerScope::Terminal);
    let grant_id = principal.grant_id.clone();
    let (mut reader, handle) = open(
        &harness,
        principal,
        json!({"id": "s", "method": "pane.stream", "params": {"pane_id": harness.pane_ids[0]}}),
    );
    let started = read_reply(&mut reader).unwrap();
    assert_eq!(code(&started), "<success>", "{started}");
    remove_in(&harness.dir.0, RemoveTarget::Grant(&grant_id), now_ms()).unwrap();
    let ended = reader
        .by_ref()
        .lines()
        .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
        .find(|line| line.get("error").is_some())
        .expect("the stream ends with an error line");
    assert_eq!(code(&ended), "owner_not_granted", "{ended}");
    handle.join().unwrap();

    // A connection the grant's removal did not reach (another process wrote
    // the store) is refused at its next request.
    let principal = owner(&harness, OwnerScope::Chat);
    let grant_id = principal.grant_id.clone();
    let (mut reader, handle) = open(
        &harness,
        principal,
        json!({"id": "1", "method": "ping", "params": {}}),
    );
    assert_eq!(code(&read_reply(&mut reader).unwrap()), "<success>");
    crate::guest::store::update_store(&harness.dir.0, |store| {
        for grant in &mut store.owners {
            if grant.grant_id == grant_id {
                grant.revoked = true;
            }
        }
        ((), true)
    })
    .unwrap();
    let refused = ask(
        &mut reader,
        json!({"id": "2", "method": "ping", "params": {}}),
    );
    assert_eq!(code(&refused), "owner_not_granted", "{refused}");
    assert_eq!(read_reply(&mut reader), None, "the session ended");
    handle.join().unwrap();
}

#[test]
fn an_expired_grant_is_refused_and_chat_events_are_limited_to_agent_kinds() {
    let harness = start("owner-expired");
    let principal = owner(&harness, OwnerScope::Chat);
    let grant_id = principal.grant_id.clone();
    let (mut reader, handle) = open(
        &harness,
        principal,
        json!({"id": "1", "method": "events.subscribe", "params": {"subscriptions": [{"type": "pane.agent_status_changed"}]}}),
    );
    let started = read_reply(&mut reader).unwrap();
    assert_eq!(
        started["result"]["type"], "subscription_started",
        "{started}"
    );
    crate::guest::store::update_store(&harness.dir.0, |store| {
        for grant in &mut store.owners {
            if grant.grant_id == grant_id {
                grant.expires_ms = now_ms() - 1;
            }
        }
        ((), true)
    })
    .unwrap();
    let ended = reader
        .by_ref()
        .lines()
        .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
        .find(|line| line.get("error").is_some())
        .expect("the subscription ends with an error line");
    assert_eq!(code(&ended), "owner_expired", "{ended}");
    handle.join().unwrap();
}

#[test]
fn chat_scope_sends_menu_keys_only_while_an_agent_waits_on_a_menu() {
    let harness = start("owner-menu");
    harness.with_granted_terminal(|terminal| {
        terminal.set_detected_state(
            Some(crate::detect::Agent::Pi),
            crate::detect::AgentState::Blocked,
        );
    });
    let pane = harness.pane_ids[0].clone();
    let keys = |keys: Value| json!({"id": "k", "method": "pane.send_keys", "params": {"pane_id": pane, "keys": keys}});
    let codes = codes(
        &harness,
        OwnerScope::Chat,
        &[
            keys(json!(["a"])),
            keys(json!(["ctrl+c"])),
            keys(json!(["enter", "down"])),
            keys(json!(["down", "enter"])),
        ],
    );
    assert_eq!(
        codes,
        [
            "owner_forbidden",
            "owner_forbidden",
            "owner_forbidden",
            "<success>"
        ],
        "{codes:?}"
    );
    let typed = harness.pty_text(0, Duration::from_millis(500));
    assert!(
        !typed.contains('a') && !typed.contains('\u{3}'),
        "{typed:?}"
    );
    assert!(typed.contains('\r'), "{typed:?}");
}

/// The first error line the server sends, skipping stream frames.
fn ending_error(reader: &mut BufReader<UnixStream>) -> Value {
    reader
        .by_ref()
        .lines()
        .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
        .find(|line| line.get("error").is_some())
        .expect("the stream ends with an error line")
}

/// P2: after a committing menu key the agent's menu may be gone, so chat
/// refuses further keys until detection sees the agent's state change;
/// otherwise a second `y` or Enter lands in the pane's shell.
#[test]
fn chat_menu_keys_stop_after_a_commit_until_the_agent_changes_state() {
    let harness = start("owner-menu-commit");
    harness.with_granted_terminal(|terminal| {
        terminal.set_detected_state(
            Some(crate::detect::Agent::Pi),
            crate::detect::AgentState::Blocked,
        );
    });
    let pane = harness.pane_ids[0].clone();
    let keys = |keys: Value| json!({"id": "k", "method": "pane.send_keys", "params": {"pane_id": pane, "keys": keys}});
    let first = codes(
        &harness,
        OwnerScope::Chat,
        &[
            keys(json!(["enter"])),
            keys(json!(["y"])),
            keys(json!(["enter"])),
        ],
    );
    assert_eq!(
        first,
        ["<success>", "owner_forbidden", "owner_forbidden"],
        "{first:?}"
    );
    let typed = harness.pty_text(0, Duration::from_millis(500));
    assert_eq!(typed.matches('\r').count(), 1, "{typed:?}");
    assert!(!typed.contains('y'), "{typed:?}");
    // A new menu (detection saw the agent change state) takes keys again.
    harness.with_granted_terminal(|terminal| {
        let next = terminal.last_agent_state_change_seq.unwrap_or(0) + 1;
        terminal.last_agent_state_change_seq = Some(next);
    });
    let again = codes(&harness, OwnerScope::Chat, &[keys(json!(["enter"]))]);
    assert_eq!(again, ["<success>"], "{again:?}");
}

/// P2: renewing a grant with a narrower scope ends the streams it opened
/// under the wider one: a terminal input stream must not keep typing, and a
/// subscription must not keep every event kind.
#[test]
fn a_scope_change_ends_open_input_streams_and_subscriptions() {
    let harness = start("owner-scope-change");
    let principal = owner(&harness, OwnerScope::Terminal);
    let grant_id = principal.grant_id.clone();
    let (mut input, input_handle) = open(
        &harness,
        principal,
        json!({"id": "i", "method": "pane.input.stream", "params": {"pane_id": harness.pane_ids[1]}}),
    );
    let opened = read_reply(&mut input).unwrap();
    assert_eq!(code(&opened), "<success>", "{opened}");
    let (mut events, events_handle) = open(
        &harness,
        owner(&harness, OwnerScope::Terminal),
        json!({"id": "e", "method": "events.subscribe", "params": {"subscriptions": [{"type": "pane.created"}]}}),
    );
    assert_eq!(
        read_reply(&mut events).unwrap()["result"]["type"],
        "subscription_started"
    );
    let events_grant = crate::guest::store::load_store(&harness.dir.0)
        .unwrap()
        .owners
        .iter()
        .map(|grant| grant.grant_id.clone())
        .find(|id| *id != grant_id)
        .unwrap();
    for grant in [&grant_id, &events_grant] {
        renew_in(
            &harness.dir.0,
            grant,
            3600,
            Some(OwnerScope::Chat),
            now_ms(),
        )
        .unwrap();
    }
    let ended = ending_error(&mut input);
    assert_eq!(code(&ended), "owner_scope_changed", "{ended}");
    // Nothing typed after the change reaches the shell.
    let _ = writeln!(input.get_mut(), r#"{{"seq":1,"text":"rm -rf ~"}}"#);
    assert!(!harness
        .pty_text(1, Duration::from_millis(500))
        .contains("rm -rf"));
    input_handle.join().unwrap();
    let ended = ending_error(&mut events);
    assert_eq!(code(&ended), "owner_scope_changed", "{ended}");
    events_handle.join().unwrap();
}

/// P2: a chat stream watches an agent; when the agent leaves the pane (on
/// unix the pane is then its shell), the stream ends.
#[test]
fn a_chat_stream_ends_when_the_pane_stops_being_an_agent() {
    let harness = start("owner-agent-gone");
    let (mut reader, handle) = open(
        &harness,
        owner(&harness, OwnerScope::Chat),
        json!({"id": "s", "method": "pane.stream", "params": {"pane_id": harness.pane_ids[0]}}),
    );
    let started = read_reply(&mut reader).unwrap();
    assert_eq!(code(&started), "<success>", "{started}");
    harness.with_granted_terminal(|terminal| {
        terminal.set_detected_state(None, crate::detect::AgentState::Idle);
    });
    let ended = ending_error(&mut reader);
    assert_eq!(code(&ended), "owner_paused", "{ended}");
    handle.join().unwrap();
}

/// An idle input stream closes within the watch interval of a removal, not
/// at its next frame.
#[test]
fn an_idle_input_stream_closes_soon_after_removal() {
    let harness = start("owner-idle-input");
    let principal = owner(&harness, OwnerScope::Terminal);
    let grant_id = principal.grant_id.clone();
    let (mut reader, handle) = open(
        &harness,
        principal,
        json!({"id": "i", "method": "pane.input.stream", "params": {"pane_id": harness.pane_ids[1]}}),
    );
    assert_eq!(code(&read_reply(&mut reader).unwrap()), "<success>");
    reader
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // Written by another process: no live flag, only the store.
    crate::guest::store::update_store(&harness.dir.0, |store| {
        for grant in &mut store.owners {
            if grant.grant_id == grant_id {
                grant.revoked = true;
            }
        }
        ((), true)
    })
    .unwrap();
    let ended = read_reply(&mut reader).expect("closed within 2 s of the removal");
    assert_eq!(code(&ended), "owner_not_granted", "{ended}");
    handle.join().unwrap();
}

/// A frame read right after the grant was removed (by another process: no
/// live flag, only the store) is never typed, however recently the grant
/// was last checked.
#[test]
fn a_frame_arriving_right_after_removal_is_never_dispatched() {
    let harness = start("owner-frame-after-removal");
    let principal = owner(&harness, OwnerScope::Terminal);
    let grant_id = principal.grant_id.clone();
    let (mut reader, handle) = open(
        &harness,
        principal,
        json!({"id": "i", "method": "pane.input.stream", "params": {"pane_id": harness.pane_ids[1]}}),
    );
    assert_eq!(code(&read_reply(&mut reader).unwrap()), "<success>");
    // The grant is checked for this frame, so the next check may be within
    // the watch interval.
    let acked = ask(&mut reader, json!({"seq": 1, "text": "ok", "ack": true}));
    assert_eq!(acked["ok"], true, "{acked}");
    crate::guest::store::update_store(&harness.dir.0, |store| {
        for grant in &mut store.owners {
            if grant.grant_id == grant_id {
                grant.revoked = true;
            }
        }
        ((), true)
    })
    .unwrap();
    let refused = ask(
        &mut reader,
        json!({"seq": 2, "text": "after-removal", "ack": true}),
    );
    assert_eq!(code(&refused), "owner_not_granted", "{refused}");
    assert!(!harness
        .pty_text(1, Duration::from_millis(500))
        .contains("after-removal"));
    handle.join().unwrap();
}

/// Terminal scope administers and creates agents and terminals, manages
/// guests and Claude accounts and updates herdr, as the desktop does: a
/// terminal is already a shell on this machine. Chat scope reaches none of
/// it, and neither scope reaches `owner_access.*`, so no browser can mint,
/// renew or widen its own grant. Calls are still local: a `guest.*` naming
/// a saved machine and a split of another machine's pane are refused.
#[test]
fn terminal_scope_runs_the_owner_shell_chat_scope_never_does() {
    let harness = start("owner-shell");
    // Arguments that fail in the app (no such agent, pane, kind or account),
    // so nothing here changes this machine or reaches the network.
    let terminal_ok = [
        json!({"id": "1", "method": "agent.groups.set", "params": {"revision": 999_999, "folders": [], "stars": []}}),
        json!({"id": "2", "method": "agent.rename", "params": {"target": "nobody", "name": "x"}}),
        json!({"id": "3", "method": "agent.avatar.set", "params": {"target": "nobody"}}),
        json!({"id": "4", "method": "agent.archive", "params": {"target": "nobody"}}),
        json!({"id": "5", "method": "agent.restart", "params": {"target": "nobody"}}),
        json!({"id": "6", "method": "agent.kinds", "params": {}}),
        json!({"id": "7", "method": "agent.start", "params": {"name": "x", "kind": "nope", "pane_id": "w9:p9"}}),
        json!({"id": "8", "method": "fs.list_dir", "params": {"path": "/nonexistent-herdr-owner-test"}}),
        json!({"id": "9", "method": "pane.split", "params": {"target_pane_id": "w9:p9", "direction": "right"}}),
        json!({"id": "10", "method": "pane.rename", "params": {"pane_id": "w9:p9", "label": "x"}}),
        json!({"id": "11", "method": "pane.close", "params": {"pane_id": "w9:p9"}}),
        json!({"id": "12", "method": "accounts.list", "params": {}}),
        json!({"id": "13", "method": "accounts.create", "params": {"kind": "nope", "label": "x"}}),
        json!({"id": "14", "method": "accounts.remove", "params": {"id": "nope"}}),
        json!({"id": "15", "method": "guest.revoke", "params": {}}),
        json!({"id": "16", "method": "server.update_status", "params": {}}),
    ];
    let replies = codes(&harness, OwnerScope::Terminal, &terminal_ok);
    for (request, code) in terminal_ok.iter().zip(&replies) {
        assert_ne!(code, "owner_forbidden", "terminal: {request}");
    }
    assert_eq!(replies[5], "<success>", "agent.kinds: {replies:?}");
    assert_eq!(replies[11], "<success>", "accounts.list: {replies:?}");
    // It reached the guest RPCs, which want exactly one id.
    assert_eq!(replies[14], "invalid_params", "guest.revoke: {replies:?}");

    let terminal_refused = [
        json!({"id": "20", "method": "guest.list", "params": {"machine": "studio"}}),
        json!({"id": "21", "method": "guest.revoke", "params": {"guest_id": "g", "machine": "studio"}}),
        json!({"id": "22", "method": "pane.split", "params": {"target_pane_id": "studio/w1:p1", "direction": "right"}}),
        json!({"id": "23", "method": "agent.restart", "params": {"target": "studio/builder"}}),
    ];
    let replies = codes(&harness, OwnerScope::Terminal, &terminal_refused);
    assert_eq!(replies, ["owner_forbidden"; 4], "{replies:?}");

    let mut chat_refused: Vec<Value> = terminal_ok.to_vec();
    chat_refused.extend([
        json!({"id": "30", "method": "guest.invite.create", "params": {"target": "llm-opt", "name": "friend", "owner_name": "Jerry", "machine_label": "Mac"}}),
        json!({"id": "31", "method": "guest.list", "params": {}}),
        json!({"id": "32", "method": "guest.update", "params": {"guest_id": "g", "share_gram": true}}),
        json!({"id": "33", "method": "guest.remove_device", "params": {"guest_id": "g", "fingerprint": "f"}}),
        json!({"id": "34", "method": "guest.audit", "params": {}}),
        json!({"id": "35", "method": "server.update_check", "params": {}}),
        json!({"id": "36", "method": "server.update_apply", "params": {"build_id": "2026-11-23-0123456789ab"}}),
    ]);
    let replies = codes(&harness, OwnerScope::Chat, &chat_refused);
    for (request, code) in chat_refused.iter().zip(&replies) {
        assert_eq!(code, "owner_forbidden", "chat: {request}");
    }

    let owner_access = [
        json!({"id": "40", "method": "owner_access.info", "params": {}}),
        json!({"id": "41", "method": "owner_access.list", "params": {}}),
        json!({"id": "42", "method": "owner_access.add", "params": {"device_pub": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI", "device_name": "x", "ttl_secs": 3600, "account_statement": "a.b.c", "approved_by": "x"}}),
        json!({"id": "43", "method": "owner_access.renew", "params": {"grant_id": "g", "ttl_secs": 2_592_000}}),
        json!({"id": "44", "method": "owner_access.remove", "params": {"grant_id": "g"}}),
    ];
    for scope in [OwnerScope::Chat, OwnerScope::Terminal] {
        let replies = codes(&harness, scope, &owner_access);
        assert_eq!(replies, ["owner_forbidden"; 5], "{scope:?}: {replies:?}");
    }
}
