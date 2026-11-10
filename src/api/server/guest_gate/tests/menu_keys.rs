//! Guest menu keys while the app is slow to answer.

use super::*;

/// Like `Harness::open`, with the gate dispatching to the app through
/// `api_tx`.
fn open_via(
    harness: &Harness,
    api_tx: &ApiRequestSender,
    guest: &GuestPrincipal,
    request: Value,
) -> (BufReader<UnixStream>, JoinHandle<()>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    let (api_tx, event_hub, running, guest) = (
        api_tx.clone(),
        harness.event_hub.clone(),
        Arc::clone(&harness.running),
        guest.clone(),
    );
    let handle = std::thread::spawn(move || {
        let _ = serve_guest_with(&api_tx, &event_hub, &running, guest, server);
    });
    writeln!(client, "{request}").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (BufReader::new(client), handle)
}

/// Agent 1 (in the second workspace) waits on a menu too.
fn block_second_agent(harness: &Harness) {
    let (done_tx, done_rx) = std_mpsc::channel();
    harness
        .control
        .send(Box::new(move |app: &mut App| {
            let pane = app.state.workspaces[1].tabs[0].root_pane;
            let terminal_id = app.state.workspaces[1].tabs[0].panes[&pane]
                .attached_terminal_id
                .clone();
            app.state
                .terminals
                .get_mut(&terminal_id)
                .unwrap()
                .set_detected_state(
                    Some(crate::detect::Agent::Pi),
                    crate::detect::AgentState::Blocked,
                );
            let _ = done_tx.send(());
        }))
        .unwrap();
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
}

/// A key batch the app has not answered yet holds up only its own terminal:
/// another guest's keys to another agent still go through (#352-f6).
#[test]
fn a_stalled_key_write_does_not_hold_up_keys_to_another_terminal() {
    let harness = start("menu-keys-stalled");
    let stalled_guest = harness.admit_to(0);
    let other_guest = harness.admit_to(1);
    block_granted_agent(&harness);
    block_second_agent(&harness);

    // The app leaves the first key write unanswered until the test hands it
    // on; every other request goes straight through.
    let (proxy_tx, mut proxy_rx) = tokio::sync::mpsc::unbounded_channel::<ApiRequestMessage>();
    let (held_tx, held_rx) = std_mpsc::channel();
    let app_tx = harness.api_tx.clone();
    std::thread::spawn(move || {
        let mut held_tx = Some(held_tx);
        while let Some(message) = proxy_rx.blocking_recv() {
            if matches!(message.request.method, Method::PaneSendKeys(_)) {
                if let Some(held_tx) = held_tx.take() {
                    let _ = held_tx.send(message);
                    continue;
                }
            }
            let _ = app_tx.send(message);
        }
    });

    let (mut stalled, stalled_handle) = open_via(
        &harness,
        &proxy_tx,
        &stalled_guest,
        send_keys(&harness.pane_ids[0], json!(["Enter"])),
    );
    let held: ApiRequestMessage = held_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the first guest's keys reach the app");

    let (mut other, other_handle) = open_via(
        &harness,
        &proxy_tx,
        &other_guest,
        send_keys(&harness.pane_ids[1], json!(["Enter"])),
    );
    other
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut line = String::new();
    let read = other.read_line(&mut line);
    assert!(
        matches!(read, Ok(len) if len > 0),
        "keys to another terminal waited on the stalled write: {read:?}"
    );
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["result"], json!({"type": "ok"}), "{reply}");
    assert_eq!(harness.pty_text(1, Duration::from_millis(300)), "\r");

    // Once the app answers, the stalled batch completes as usual.
    harness.api_tx.send(held).unwrap();
    let reply = read_reply(&mut stalled).expect("the stalled batch is answered");
    assert_eq!(reply["result"], json!({"type": "ok"}), "{reply}");
    assert_eq!(harness.pty_text(0, Duration::from_millis(300)), "\r");

    hang_up_after_reply(stalled.get_ref());
    hang_up_after_reply(other.get_ref());
    stalled_handle.join().unwrap();
    other_handle.join().unwrap();
}
