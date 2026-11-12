use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::sync::mpsc;

use super::*;
use crate::api::schema::AgentSessionInfo;

const FAST: Timing = Timing {
    selector_pause: Duration::ZERO,
    confirm_poll: Duration::from_millis(5),
    confirm_timeout: Duration::from_millis(150),
};

/// An omp pane behind the app: a boxed ask dialog that arrows move through
/// (clamped at the ends, like omp 18.10.4) and Enter submits by appending the
/// ask's tool result to the session file.
struct FakeOmp {
    options: Vec<String>,
    rows: Vec<String>,
    highlighted: usize,
    session: PathBuf,
    ask_id: String,
    arrows_land: bool,
    records_answer: bool,
    keys: Vec<String>,
}

impl FakeOmp {
    fn screen(&self) -> String {
        let mut screen = String::from("╭─ Ask ─────────────────────────────────────╮\n");
        screen.push_str("│ Which deploy path should I take?          │\n");
        for (index, row) in self.rows.iter().enumerate() {
            let cursor = if index == self.highlighted {
                "❯"
            } else {
                " "
            };
            screen.push_str(&format!("│ {cursor} ○ {row:<38}│\n"));
        }
        screen.push_str("╰───────────────────────────────────────────╯\n");
        screen
    }

    fn press(&mut self, key: &str) {
        self.keys.push(key.to_owned());
        match key {
            "up" if self.arrows_land => self.highlighted = self.highlighted.saturating_sub(1),
            "down" if self.arrows_land => {
                self.highlighted = (self.highlighted + 1).min(self.rows.len() - 1);
            }
            "enter" if self.records_answer => {
                let line = json!({
                    "type": "message",
                    "id": "e_result",
                    "parentId": "e_ask",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": self.ask_id,
                        "toolName": "ask",
                        "details": {"selectedOptions": [self.options[self.highlighted]]},
                    },
                });
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&self.session)
                    .unwrap();
                writeln!(file, "{line}").unwrap();
            }
            _ => {}
        }
    }
}

struct Harness {
    omp: Arc<Mutex<FakeOmp>>,
    agent: AgentInfo,
    pane_id: String,
    session: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.session);
    }
}

fn ask_line(id: &str, questions: Value) -> String {
    json!({
        "type": "message",
        "id": "e_ask",
        "message": {
            "role": "assistant",
            "content": [{
                "type": "toolCall",
                "id": id,
                "name": "ask",
                "arguments": {"questions": questions},
            }],
        },
    })
    .to_string()
}

fn deploy_question() -> Value {
    json!([{
        "id": "deploy",
        "question": "Which deploy path should I take?",
        "options": [
            {"label": "Ship it now"},
            {"label": "Wait for review"},
            {"label": "Abort the change"},
        ],
        "recommended": 1,
    }])
}

/// A harness whose pane and ask ids are unique, so the process-wide claim set
/// never couples two tests.
fn harness(questions: Value) -> Harness {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let pane_id = format!("w1:p{n}");
    let ask_id = format!("call_{n}");
    let session =
        std::env::temp_dir().join(format!("herdr-answer-{}-{n}.jsonl", std::process::id()));
    std::fs::write(&session, ask_line(&ask_id, questions.clone()) + "\n").unwrap();
    let question = &questions[0];
    let options: Vec<String> = question["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|option| option["label"].as_str().unwrap().to_owned())
        .collect();
    let recommended = question["recommended"].as_u64().map(|index| index as usize);
    let rows = selector::display_rows(&options, recommended);
    let omp = FakeOmp {
        options,
        rows,
        highlighted: recommended.unwrap_or(0),
        session: session.clone(),
        ask_id,
        arrows_land: true,
        records_answer: true,
        keys: Vec::new(),
    };
    let agent = AgentInfo {
        account: None,
        account_config_dir: None,
        account_unresolved: false,
        restore_error: None,
        terminal_id: "term_1".into(),
        name: None,
        agent: Some("omp".into()),
        title: None,
        terminal_title: None,
        terminal_title_stripped: None,
        display_agent: None,
        agent_status: crate::api::schema::AgentStatus::Blocked,
        input_pending: true,
        input_prompt_kind: None,
        composer: Default::default(),
        screen_detection_skipped: false,
        state_labels: Default::default(),
        tokens: Default::default(),
        agent_session: Some(AgentSessionInfo {
            source: "omp".into(),
            agent: "omp".into(),
            kind: AgentSessionRefKind::Path,
            value: session.display().to_string(),
        }),
        last_completed_turn: None,
        turn: None,
        turn_epoch: None,
        workspace_id: "w1".into(),
        tab_id: "w1:t1".into(),
        pane_id: pane_id.clone(),
        focused: true,
        launch_pending: false,
        interactive_ready: true,
        state_change_seq: 1,
        status_since_unix_ms: None,
        completion_seq: None,
        cwd: None,
        foreground_cwd: None,
        revision: 1,
        machine_id: None,
        machine_profile_id: None,
        machine_label: None,
        origin_machine_id: None,
        reachability: None,
        last_known_status: None,
        gram_reachable: None,
        archived: None,
        parked_work: Vec::new(),
        session_transfer: None,
        avatar: None,
    };
    Harness {
        omp: Arc::new(Mutex::new(omp)),
        agent,
        pane_id,
        session,
    }
}

impl Harness {
    fn ask_id(&self) -> String {
        self.omp.lock().unwrap().ask_id.clone()
    }

    fn keys(&self) -> Vec<String> {
        self.omp.lock().unwrap().keys.clone()
    }

    fn params(&self, option: &str) -> AgentAnswerParams {
        AgentAnswerParams {
            target: self.pane_id.clone(),
            ask_id: self.ask_id(),
            option: option.into(),
        }
    }

    /// Run `agent.answer` against an app that serves `agent.get` with this
    /// harness's agent and pane reads/keys from the fake omp.
    fn answer(&self, params: &AgentAnswerParams) -> Value {
        let (api_tx, mut api_rx) = mpsc::unbounded_channel::<crate::api::ApiRequestMessage>();
        let omp = Arc::clone(&self.omp);
        let agent = self.agent.clone();
        let app = std::thread::spawn(move || {
            while let Some(message) = api_rx.blocking_recv() {
                let id = message.request.id;
                let result = match message.request.method {
                    Method::AgentGet(_) => json!({"type": "agent_info", "agent": agent}),
                    Method::PaneRead(read) => {
                        let text = omp.lock().unwrap().screen();
                        json!({"type": "pane_read", "read": {
                            "pane_id": read.pane_id, "workspace_id": "w1", "tab_id": "w1:t1",
                            "source": "visible", "format": "text", "text": text,
                            "revision": 1, "truncated": false,
                        }})
                    }
                    Method::PaneSendKeys(keys) => {
                        let mut omp = omp.lock().unwrap();
                        for key in &keys.keys {
                            omp.press(key);
                        }
                        json!({"type": "ok"})
                    }
                    other => panic!("unexpected app request: {other:?}"),
                };
                let _ = message
                    .respond_to
                    .send(json!({"id": id, "result": result}).to_string());
            }
        });
        let response = answer_response("req".into(), params, &api_tx, FAST);
        drop(api_tx);
        app.join().unwrap();
        serde_json::from_str(&response).unwrap()
    }
}

fn error_code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or_else(|| {
        panic!("expected an error, got {response}");
    })
}

#[test]
fn answers_by_moving_from_the_recommended_row_and_confirms_from_the_session() {
    let harness = harness(deploy_question());
    let response = harness.answer(&harness.params("Ship it now"));
    assert_eq!(
        response["result"],
        json!({"type": "agent_answer", "status": "answered"})
    );
    assert_eq!(harness.keys(), ["up", "enter"]);
    assert_eq!(
        crate::agent_transcript::ask_result(&harness.session, &harness.ask_id()).unwrap(),
        Some(vec!["Ship it now".to_owned()])
    );
}

#[test]
fn recommended_option_is_submitted_without_arrows() {
    let harness = harness(deploy_question());
    let response = harness.answer(&harness.params("Wait for review"));
    assert_eq!(response["result"]["status"], "answered");
    assert_eq!(harness.keys(), ["enter"]);
}

#[test]
fn highlight_that_does_not_land_never_sends_enter() {
    let harness = harness(deploy_question());
    harness.omp.lock().unwrap().arrows_land = false;
    let response = harness.answer(&harness.params("Abort the change"));
    assert_eq!(error_code(&response), "selection_mismatch");
    assert_eq!(harness.keys(), ["down"]);
    // Nothing was sent, so the claim is released and a retry is allowed.
    harness.omp.lock().unwrap().arrows_land = true;
    let retry = harness.answer(&harness.params("Abort the change"));
    assert_eq!(retry["result"]["status"], "answered");
}

#[test]
fn second_answer_to_the_same_ask_presses_nothing() {
    let harness = harness(deploy_question());
    // omp has not written its tool result yet: the ask still looks pending.
    harness.omp.lock().unwrap().records_answer = false;
    let first = harness.answer(&harness.params("Ship it now"));
    assert_eq!(first["result"]["status"], "sent_unconfirmed");
    assert_eq!(harness.keys(), ["up", "enter"]);
    let second = harness.answer(&harness.params("Abort the change"));
    assert_eq!(error_code(&second), "ask_not_pending");
    assert_eq!(
        harness.keys(),
        ["up", "enter"],
        "no key after the first Enter"
    );
}

#[test]
fn answered_ask_is_not_pending() {
    let harness = harness(deploy_question());
    let first = harness.answer(&harness.params("Ship it now"));
    assert_eq!(first["result"]["status"], "answered");
    super::CLAIMS.lock().unwrap().clear();
    let again = harness.answer(&harness.params("Ship it now"));
    assert_eq!(error_code(&again), "ask_not_pending");
    assert_eq!(harness.keys(), ["up", "enter"]);
}

#[test]
fn stale_ask_id_is_not_pending() {
    let harness = harness(deploy_question());
    let mut params = harness.params("Ship it now");
    params.ask_id = "call_older".into();
    assert_eq!(error_code(&harness.answer(&params)), "ask_not_pending");
    assert!(harness.keys().is_empty());
}

#[test]
fn option_that_is_not_a_label_is_invalid() {
    let harness = harness(deploy_question());
    for option in [
        "Wait for review (Recommended)",
        "Other (type your own)",
        "ship it now",
    ] {
        let response = harness.answer(&harness.params(option));
        assert_eq!(error_code(&response), "invalid_request", "{option}");
    }
    assert!(harness.keys().is_empty());
}

#[test]
fn multi_select_and_non_omp_agents_are_unsupported() {
    let multi = harness(json!([{
        "id": "q", "question": "Which?", "multi": true,
        "options": [{"label": "A"}, {"label": "B"}],
    }]));
    assert_eq!(
        error_code(&multi.answer(&multi.params("A"))),
        "ask_unsupported"
    );
    assert!(multi.keys().is_empty());

    let mut claude = harness(deploy_question());
    claude.agent.agent = Some("claude".into());
    assert_eq!(
        error_code(&claude.answer(&claude.params("Ship it now"))),
        "ask_unsupported"
    );
    let mut by_id = harness(deploy_question());
    by_id.agent.agent_session.as_mut().unwrap().kind = AgentSessionRefKind::Id;
    assert_eq!(
        error_code(&by_id.answer(&by_id.params("Ship it now"))),
        "ask_unsupported"
    );
    assert!(claude.keys().is_empty() && by_id.keys().is_empty());
}

const FORM_HTML: &str = r#"<form><fieldset><legend>Database</legend>
<label><input type="radio" name="db" value="pg" checked> Postgres</label>
<label><input type="radio" name="db" value="my"> MySQL</label></fieldset>
<fieldset><legend>Tools</legend>
<label><input type="checkbox" name="tools" value="ci" checked> CI</label>
<label><input type="checkbox" name="tools" value="tf"> Terraform</label></fieldset></form>"#;

/// omp's terminal form for [`FORM_HTML`], written independently of
/// `form.rs`: stops db:pg, db:my, db:Other, tools:ci, tools:tf, tools:Other,
/// Submit; keys behave as in omp's dialog.ts. Enter on Submit appends the
/// result omp would record.
struct FakeForm {
    session: PathBuf,
    ask_id: String,
    focus: usize,
    db: Option<usize>,
    db_other: String,
    tools: [bool; 2],
    tools_other: String,
    /// Someone already moved the focus in the terminal.
    touched: bool,
    /// Enter on Submit does nothing (omp stalled; no result is written).
    stalls_submit: bool,
    keys: Vec<String>,
}

const FIELD_OF_STOP: [Option<usize>; 7] =
    [Some(0), Some(0), Some(0), Some(1), Some(1), Some(1), None];
const DB: [(&str, &str); 2] = [("pg", "Postgres"), ("my", "MySQL")];
const TOOLS: [(&str, &str); 2] = [("ci", "CI"), ("tf", "Terraform")];

impl FakeForm {
    fn screen(&self) -> String {
        let cursor = |stop: usize| if self.focus == stop { "❯ " } else { "  " };
        let other = |text: &str| {
            if text.is_empty() {
                "type your own".to_owned()
            } else {
                text.to_owned()
            }
        };
        let mut screen = String::from("agent: two picks\n╭─ Ask ─╮\n Database\n");
        for (index, (_, label)) in DB.iter().enumerate() {
            let marker = if self.db == Some(index) { "◉" } else { "○" };
            screen.push_str(&format!("│ {}{marker} {label}\n", cursor(index)));
        }
        let db_other = if self.db.is_none() && !self.db_other.is_empty() {
            "◉"
        } else {
            "○"
        };
        screen.push_str(&format!(
            "│ {}{db_other} Other: {}\n Tools\n",
            cursor(2),
            other(&self.db_other)
        ));
        for (index, (_, label)) in TOOLS.iter().enumerate() {
            let marker = if self.tools[index] { "☑" } else { "☐" };
            screen.push_str(&format!("│ {}{marker} {label}\n", cursor(3 + index)));
        }
        let tools_other = if self.tools_other.is_empty() {
            "☐"
        } else {
            "☑"
        };
        screen.push_str(&format!(
            "│ {}{tools_other} Other: {}\n",
            cursor(5),
            other(&self.tools_other)
        ));
        screen.push_str(&format!("│ {}Submit\n╰───────╯\n", cursor(6)));
        screen
    }

    fn move_field(&mut self) {
        let field = FIELD_OF_STOP[self.focus];
        while self.focus + 1 < FIELD_OF_STOP.len() && FIELD_OF_STOP[self.focus] == field {
            self.focus += 1;
        }
    }

    fn press(&mut self, key: &str) {
        self.keys.push(key.to_owned());
        match (key, self.focus) {
            ("up", _) => self.focus = self.focus.saturating_sub(1),
            ("down", _) => self.focus = (self.focus + 1).min(6),
            ("tab", _) => self.move_field(),
            ("enter", 0 | 1) => {
                self.db = Some(self.focus);
                self.move_field();
            }
            ("enter", 2) => {
                if !self.db_other.trim().is_empty() {
                    self.db = None;
                }
                self.move_field();
            }
            ("space", 0 | 1) => self.db = Some(self.focus),
            ("space", 3 | 4) => self.tools[self.focus - 3] ^= true,
            ("ctrl+u", 2) => self.db_other.clear(),
            ("ctrl+u", 5) => self.tools_other.clear(),
            ("enter", 6) if self.stalls_submit => {}
            ("enter", 6) => self.submit(),
            _ => {}
        }
    }

    fn type_text(&mut self, text: &str) {
        self.keys.push(format!("text:{text}"));
        match self.focus {
            2 => {
                self.db_other.push_str(text);
                self.db = None;
            }
            5 => self.tools_other.push_str(text),
            _ => {}
        }
    }

    fn submit(&self) {
        let db = match self.db {
            Some(index) => DB[index].1.to_owned(),
            None => format!("Other: {}", self.db_other.trim()),
        };
        let mut tools: Vec<String> = TOOLS
            .iter()
            .zip(self.tools)
            .filter(|(_, on)| *on)
            .map(|((_, label), _)| (*label).to_owned())
            .collect();
        if !self.tools_other.trim().is_empty() {
            tools.push(format!("Other: {}", self.tools_other.trim()));
        }
        let db_value = match self.db {
            Some(index) => DB[index].0.to_owned(),
            None => self.db_other.trim().to_owned(),
        };
        let mut tools_value: Vec<String> = TOOLS
            .iter()
            .zip(self.tools)
            .filter(|(_, on)| *on)
            .map(|((value, _), _)| (*value).to_owned())
            .collect();
        if !self.tools_other.trim().is_empty() {
            tools_value.push(self.tools_other.trim().to_owned());
        }
        let data = json!({"db": db_value, "tools": tools_value});
        let line = json!({
            "type": "message", "id": "e_result", "parentId": "e_ask",
            "message": {"role": "toolResult", "toolCallId": self.ask_id, "toolName": "ask",
                "content": [{"type": "text", "text": format!("User answers:\n{data:#}")}],
                "details": {"answers": [
                    {"name": "db", "question": "Database", "answer": db},
                    {"name": "tools", "question": "Tools", "answer": tools.join(", ")},
                ]}},
        });
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.session)
            .unwrap();
        writeln!(file, "{line}").unwrap();
    }
}

/// A harness whose session holds a pending form ask, with the fake form.
fn form_harness() -> (Harness, Arc<Mutex<FakeForm>>) {
    let harness = harness(deploy_question());
    let ask_id = harness.ask_id();
    let line = json!({
        "type": "message", "id": "e_ask",
        "message": {"role": "assistant", "content": [{
            "type": "toolCall", "id": ask_id, "name": "ask", "arguments": {"html": FORM_HTML},
        }]},
    });
    std::fs::write(&harness.session, format!("{line}\n")).unwrap();
    let form = FakeForm {
        session: harness.session.clone(),
        ask_id,
        focus: 0,
        db: Some(0),
        db_other: String::new(),
        tools: [true, false],
        tools_other: String::new(),
        touched: false,
        stalls_submit: false,
        keys: Vec::new(),
    };
    (harness, Arc::new(Mutex::new(form)))
}

fn answer_form_via_app(harness: &Harness, form: &Arc<Mutex<FakeForm>>, values: Value) -> Value {
    let (api_tx, mut api_rx) = mpsc::unbounded_channel::<crate::api::ApiRequestMessage>();
    let fake = Arc::clone(form);
    let agent = harness.agent.clone();
    let app = std::thread::spawn(move || {
        while let Some(message) = api_rx.blocking_recv() {
            let id = message.request.id;
            let result = match message.request.method {
                Method::AgentGet(_) => json!({"type": "agent_info", "agent": agent}),
                Method::PaneRead(read) => {
                    let mut fake = fake.lock().unwrap();
                    if fake.touched {
                        fake.focus = 1;
                    }
                    json!({"type": "pane_read", "read": {
                        "pane_id": read.pane_id, "workspace_id": "w1", "tab_id": "w1:t1",
                        "source": "visible", "format": "text", "text": fake.screen(),
                        "revision": 1, "truncated": false,
                    }})
                }
                Method::PaneSendKeys(keys) => {
                    let mut fake = fake.lock().unwrap();
                    for key in &keys.keys {
                        fake.press(key);
                    }
                    json!({"type": "ok"})
                }
                Method::PaneSendInput(input) => {
                    fake.lock().unwrap().type_text(&input.text);
                    json!({"type": "ok"})
                }
                other => panic!("unexpected app request: {other:?}"),
            };
            let _ = message
                .respond_to
                .send(json!({"id": id, "result": result}).to_string());
        }
    });
    let params: AgentAnswerFormParams = serde_json::from_value(json!({
        "target": harness.pane_id, "ask_id": harness.ask_id(), "values": values,
    }))
    .unwrap();
    let response = answer_form_response("req".into(), &params, &api_tx, FAST);
    drop(api_tx);
    app.join().unwrap();
    serde_json::from_str(&response).unwrap()
}

#[test]
fn answer_form_drives_the_terminal_form_and_confirms_the_result() {
    let (harness, form) = form_harness();
    let response = answer_form_via_app(
        &harness,
        &form,
        json!({"db": {"options": [], "other": "Mongo"}, "tools": {"options": ["tf"]}}),
    );
    assert_eq!(
        response["result"]["type"], "ask_form_answered",
        "{response}"
    );
    assert_eq!(response["result"]["status"], "answered", "{response}");
    assert_eq!(
        response["result"]["answers"],
        json!([
            {"name": "db", "question": "Database", "answer": "Other: Mongo"},
            {"name": "tools", "question": "Tools", "answer": "Terraform"},
        ])
    );
    // A second call finds the ask answered.
    let again = answer_form_via_app(&harness, &form, json!({}));
    assert_eq!(error_code(&again), "ask_not_pending");
}

#[test]
fn answer_form_accepts_the_recommendations_with_empty_values() {
    let (harness, form) = form_harness();
    let response = answer_form_via_app(&harness, &form, json!({}));
    assert_eq!(response["result"]["status"], "answered", "{response}");
    // Every field is set outright: Other emptied, the default picked, each
    // checkbox read and kept.
    assert_eq!(
        form.lock().unwrap().keys,
        [
            "up", "down", "down", "ctrl+e", "ctrl+u", "up", "up", "space", "tab", "down", "down",
            "ctrl+e", "ctrl+u", "up", "up", "down", "tab", "enter"
        ]
    );
    assert_eq!(response["result"]["answers"][1]["answer"], "CI");
}

#[test]
fn answer_form_refuses_a_form_someone_is_answering_in_the_terminal() {
    let (harness, form) = form_harness();
    form.lock().unwrap().touched = true;
    let response = answer_form_via_app(&harness, &form, json!({}));
    assert_eq!(error_code(&response), "ask_form_moved", "{response}");
    assert!(form.lock().unwrap().keys.is_empty(), "nothing is sent");
    // The failed attempt released the claim: a retry may try again.
    form.lock().unwrap().touched = false;
    form.lock().unwrap().focus = 0;
    let response = answer_form_via_app(&harness, &form, json!({}));
    assert_eq!(response["result"]["status"], "answered", "{response}");
}

#[test]
fn answer_form_rejects_invalid_values_before_any_key() {
    let (harness, form) = form_harness();
    let response = answer_form_via_app(&harness, &form, json!({"db": {"options": ["nope"]}}));
    assert_eq!(error_code(&response), "ask_form_invalid");
    assert_eq!(response["error"]["message"], "db: unknown option \"nope\"");
    assert!(form.lock().unwrap().keys.is_empty());
}

#[test]
fn answer_form_refuses_a_questions_ask() {
    let harness = harness(deploy_question());
    let form = Arc::new(Mutex::new(FakeForm {
        session: harness.session.clone(),
        ask_id: harness.ask_id(),
        focus: 0,
        db: Some(0),
        db_other: String::new(),
        tools: [true, false],
        tools_other: String::new(),
        touched: false,
        stalls_submit: false,
        keys: Vec::new(),
    }));
    let response = answer_form_via_app(&harness, &form, json!({}));
    assert_eq!(error_code(&response), "ask_unsupported");
}

/// A form with a `<textarea>` is answerable from the app.
#[test]
fn a_form_with_a_textarea_is_answerable() {
    let (harness, _form) = form_harness();
    let html = FORM_HTML.replace(
        "</form>",
        r#"<label>Notes <textarea name="notes">draft</textarea></label></form>"#,
    );
    let line = json!({
        "type": "message", "id": "e_ask",
        "message": {"role": "assistant", "content": [{
            "type": "toolCall", "id": harness.ask_id(), "name": "ask", "arguments": {"html": html},
        }]},
    });
    std::fs::write(&harness.session, format!("{line}\n")).unwrap();
    let pending = crate::agent_transcript::pending_ask(&harness.session)
        .unwrap()
        .unwrap();
    assert!(pending.form_answerable);
}

/// #396: a drive that ends without a recorded result (`sent_unconfirmed`)
/// releases its claim: once the terminal shows the form at its start again,
/// a later attempt drives it instead of being refused as `ask_not_pending`.
#[test]
fn an_unconfirmed_answer_does_not_block_a_later_attempt() {
    let (harness, form) = form_harness();
    form.lock().unwrap().stalls_submit = true;
    let response = answer_form_via_app(&harness, &form, json!({}));
    assert_eq!(
        response["result"]["status"], "sent_unconfirmed",
        "{response}"
    );
    {
        let mut fake = form.lock().unwrap();
        fake.stalls_submit = false;
        fake.focus = 0;
    }
    let response = answer_form_via_app(&harness, &form, json!({}));
    assert_eq!(response["result"]["status"], "answered", "{response}");
}
