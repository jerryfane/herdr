//! A real `App` on its own thread for the relay gates' tests (the guest gate
//! and the owner browser gate), with two named agents, and the client side
//! of one relay connection.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::api::schema::Method;
use crate::api::{ApiRequestMessage, ApiRequestSender, EventHub};
use crate::app::App;
use crate::guest::store::tests::TempDir;

pub(in crate::api::server) type Control = Box<dyn FnOnce(&mut App) + Send>;
pub(in crate::api::server) type PtyHook = Box<dyn FnMut(&mut App, usize, &[u8]) + Send>;
pub(in crate::api::server) type PtyView = ((u16, u16), Vec<(String, u16, u16, Duration)>);

/// A real `App` on its own thread with two named agents: the granted
/// `llm-opt` and `other-agent` on another pane.
pub(in crate::api::server) struct Harness {
    pub(in crate::api::server) api_tx: ApiRequestSender,
    pub(in crate::api::server) event_hub: EventHub,
    pub(in crate::api::server) running: Arc<AtomicBool>,
    pub(in crate::api::server) control: std_mpsc::Sender<Control>,
    pub(in crate::api::server) pty: std_mpsc::Receiver<(usize, bytes::Bytes)>,
    pub(in crate::api::server) pane_ids: Vec<String>,
    pub(in crate::api::server) dir: TempDir,
    /// Runs once on the app thread just before it applies the next
    /// `pane.set_pty_size`.
    pub(in crate::api::server) before_resize: Arc<Mutex<Option<Control>>>,
    /// Sees every write to an agent's terminal on the app thread, before
    /// `pty` does: a fake program answering its keys.
    pub(in crate::api::server) pty_hook: Arc<Mutex<Option<PtyHook>>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(in crate::api::server) fn start(tag: &str) -> Harness {
    let (api_tx, mut api_rx) = tokio::sync::mpsc::unbounded_channel::<ApiRequestMessage>();
    let (control_tx, control_rx) = std_mpsc::channel::<Control>();
    let (pty_tx, pty_rx) = std_mpsc::channel();
    let (ids_tx, ids_rx) = std_mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));
    let app_running = Arc::clone(&running);
    let before_resize: Arc<Mutex<Option<Control>>> = Arc::default();
    let app_before_resize = Arc::clone(&before_resize);
    let pty_hook: Arc<Mutex<Option<PtyHook>>> = Arc::default();
    let app_pty_hook = Arc::clone(&pty_hook);
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let (_unused, app_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            crate::app::AppPolicy::TEST,
            None,
            app_rx,
            EventHub::default(),
        );
        app.state.workspaces = vec![
            crate::workspace::Workspace::test_new("agent"),
            crate::workspace::Workspace::test_new("other"),
        ];
        app.state.ensure_test_terminals();
        app.state.active = Some(0);
        let mut ptys = Vec::new();
        let mut ids = Vec::new();
        for (ws_idx, name) in [(0, "llm-opt"), (1, "other-agent")] {
            let pane = app.state.workspaces[ws_idx].tabs[0].root_pane;
            let terminal_id = app.state.workspaces[ws_idx].tabs[0].panes[&pane]
                .attached_terminal_id
                .clone();
            let terminal = app.state.terminals.get_mut(&terminal_id).unwrap();
            terminal.set_agent_name(name.into());
            terminal.set_detected_state(
                Some(crate::detect::Agent::Pi),
                crate::detect::AgentState::Idle,
            );
            terminal.set_persisted_agent_session(crate::agent_resume::PersistedAgentSession {
                source: "herdr".into(),
                agent: "pi".into(),
                session_ref: crate::agent_resume::AgentSessionRef::id(format!("session-{ws_idx}"))
                    .unwrap(),
            });
            let (runtime, rx) =
                crate::terminal::TerminalRuntime::test_with_channel_and_scrollback_bytes(
                    80,
                    24,
                    1024 * 1024,
                    &[],
                    4,
                );
            app.state.insert_test_runtime(pane, runtime);
            ptys.push(rx);
            ids.push(app.public_pane_id(ws_idx, pane).unwrap());
        }
        ids_tx.send(ids).unwrap();
        while app_running.load(Ordering::Acquire) {
            while let Ok(control) = control_rx.try_recv() {
                control(&mut app);
            }
            for (index, rx) in ptys.iter_mut().enumerate() {
                while let Ok(bytes) = rx.try_recv() {
                    if let Some(hook) = app_pty_hook
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .as_mut()
                    {
                        hook(&mut app, index, &bytes);
                    }
                    let _ = pty_tx.send((index, bytes));
                }
            }
            match api_rx.try_recv() {
                Ok(message) if matches!(message.request.method, Method::AgentPrompt(_)) => {
                    app.handle_deferred_agent_api_request(message.request, message.respond_to);
                }
                Ok(message) if matches!(message.request.method, Method::AgentTranscript(_)) => {
                    app.handle_deferred_transcript_request(message.request, message.respond_to);
                }
                Ok(message) if message.request.method.is_agent_topics() => {
                    app.handle_deferred_topics_request(message.request, message.respond_to);
                }
                Ok(message) => {
                    if matches!(message.request.method, Method::PaneSetPtySize(_)) {
                        let hook = app_before_resize
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .take();
                        if let Some(hook) = hook {
                            hook(&mut app);
                        }
                    }
                    let response = app.handle_api_request(message.request);
                    let _ = message.respond_to.send(response);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    });
    let pane_ids = ids_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    Harness {
        api_tx,
        event_hub: EventHub::default(),
        running,
        control: control_tx,
        pty: pty_rx,
        pane_ids,
        dir: TempDir::new(tag),
        before_resize,
        pty_hook,
        thread: Some(thread),
    }
}

impl Harness {
    pub(in crate::api::server) fn pty_text(&self, index: usize, wait: Duration) -> String {
        let deadline = Instant::now() + wait;
        let mut text = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.pty.recv_timeout(left) {
                Ok((pane, bytes)) if pane == index => text.extend_from_slice(&bytes),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&text).into_owned()
    }

    /// Change the granted terminal's agent on the app thread.
    pub(in crate::api::server) fn with_granted_terminal(
        &self,
        change: impl FnOnce(&mut crate::terminal::TerminalState) + Send + 'static,
    ) {
        let (done_tx, done_rx) = std_mpsc::channel();
        self.control
            .send(Box::new(move |app: &mut App| {
                let pane = app.state.workspaces[0].tabs[0].root_pane;
                let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane]
                    .attached_terminal_id
                    .clone();
                change(app.state.terminals.get_mut(&terminal_id).unwrap());
                let _ = done_tx.send(());
            }))
            .unwrap();
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    /// Who started the granted agent's current turn, and how many prompts
    /// that were not the owner's its transcript will mark `other`.
    pub(in crate::api::server) fn granted_turn_origin(
        &self,
    ) -> (Option<crate::terminal::TurnOrigin>, usize) {
        let (tx, rx) = std_mpsc::channel();
        self.with_granted_terminal(move |terminal| {
            let _ = tx.send((terminal.turn_origin, terminal.other_prompts.len()));
        });
        rx.recv().unwrap()
    }

    /// The granted agent's process ends: the pane is left with its shell.
    pub(in crate::api::server) fn agent_exits(&self) {
        self.control
            .send(Box::new(|app: &mut App| {
                let pane = app.state.workspaces[0].tabs[0].root_pane;
                let terminal_id = app.state.workspaces[0].tabs[0].panes[&pane]
                    .attached_terminal_id
                    .clone();
                app.state
                    .terminals
                    .get_mut(&terminal_id)
                    .unwrap()
                    .set_detected_state(None, crate::detect::AgentState::Idle);
            }))
            .unwrap();
    }
}

/// Closes the client's write side after a reply. The server may already
/// have ended the connection (a refusal, a stream, a one-shot reply); macOS
/// then answers `shutdown` with ENOTCONN, which means the same thing here.
pub(in crate::api::server) fn hang_up_after_reply(client: &UnixStream) {
    match client.shutdown(std::net::Shutdown::Write) {
        Err(err) if err.kind() != std::io::ErrorKind::NotConnected => {
            panic!("shutdown: {err}")
        }
        _ => {}
    }
}

/// The next reply line, or `None` once the server closed.
pub(in crate::api::server) fn read_reply(reader: &mut BufReader<UnixStream>) -> Option<Value> {
    let mut line = String::new();
    (reader.read_line(&mut line).unwrap() > 0).then(|| serde_json::from_str(&line).unwrap())
}

/// Sends one more request on an open guest connection and reads its reply.
pub(in crate::api::server) fn ask(reader: &mut BufReader<UnixStream>, request: Value) -> Value {
    writeln!(reader.get_mut(), "{request}").unwrap();
    read_reply(reader).unwrap_or_else(|| panic!("closed before answering {request}"))
}
