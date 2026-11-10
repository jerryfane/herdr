//! Actionable question pushes (herdr#309): a NeedsInput alert for an omp agent
//! waiting on an `ask` carries the question and its options as `herdr_ask`,
//! so the phone can answer from the notification through `agent.answer`.
//!
//! The session file is read on the push thread, never the app loop. Only the
//! owner's alerts carry the question; guest payloads are built elsewhere
//! (`guest::push`) from the title and body alone.

use std::cell::LazyCell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use super::{PushKind, PushNotification};
use crate::api::schema::{AskForm, AskFormField, AskFormFieldKind, PendingAsk};

/// Notification actions the phone can show for one alert.
pub(crate) const MAX_OPTIONS: usize = 4;
/// The APNs alert category the phone registers the answer actions under.
pub(super) const CATEGORY: &str = "herdr.ask";
/// The category of a form ask whose recommendations can be accepted from the
/// notification: one action, `accept_defaults` ("Accept recommendations").
pub(super) const FORM_CATEGORY: &str = "herdr.ask_form";
/// A form intro at most this long is the alert body itself.
const FORM_INTRO_BODY_CHARS: usize = 120;
const QUESTION_MAX_CHARS: usize = 240;
const AGENT_MAX_CHARS: usize = 60;
/// Labels travel verbatim (each is an `agent.answer` option), so an ask whose
/// labels would crowd Apple's 4 KB payload gets a plain alert instead.
const OPTIONS_MAX_BYTES: usize = 1024;
/// The alert can fire as omp draws the dialog, a moment before the session
/// line holding the ask is flushed.
const LOOKUP_TRIES: usize = 3;
const LOOKUP_PAUSE: Duration = Duration::from_millis(250);

/// Where a NeedsInput alert's local omp agent keeps its session, so the push
/// thread can look for a pending ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AskSource {
    pub session_path: PathBuf,
    /// The agent's display name (`<agent> asks`).
    pub agent: String,
}

/// The `herdr_ask` payload object. `pane_id` is this daemon's public pane id
/// (the `agent.answer` target) and `machine_id` this daemon's machine id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PushAsk {
    pub agent: String,
    pub pane_id: String,
    pub machine_id: String,
    pub ask_id: String,
    pub question: String,
    /// The options to offer as actions; always empty for a form ask.
    pub options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form: Option<PushAskForm>,
}

/// What a form ask's alert says about the form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PushAskForm {
    /// Answerable fields.
    pub count: usize,
    pub intro: Option<String>,
    /// Every required field has a default, so `values: {}` is a valid answer.
    pub accept_defaults: bool,
}

/// The alert body of a form ask: its intro when short, else a count.
pub(super) fn form_body(form: &PushAskForm) -> String {
    match &form.intro {
        Some(intro) if intro.chars().count() <= FORM_INTRO_BODY_CHARS => intro.clone(),
        _ => format!(
            "{} {} · recommended preselected",
            form.count,
            if form.count == 1 { "choice" } else { "choices" }
        ),
    }
}

/// Fill `ask` on every NeedsInput alert whose agent has a pending ask that a
/// notification can answer.
pub(super) fn attach(notifications: &mut [PushNotification]) {
    attach_with(
        notifications,
        crate::persist::machine::get_or_create,
        LOOKUP_PAUSE,
    );
}

fn attach_with(
    notifications: &mut [PushNotification],
    machine_id: impl FnOnce() -> String,
    pause: Duration,
) {
    let machine_id = LazyCell::new(machine_id);
    for notification in notifications {
        let Some(source) = notification.ask_source.take() else {
            continue;
        };
        if notification.kind != PushKind::NeedsInput {
            continue;
        }
        let Some(pending) = lookup(&source.session_path, pause) else {
            continue;
        };
        notification.ask = push_ask(&pending, &source.agent, &notification.pane_id, &machine_id);
    }
}

fn lookup(path: &Path, pause: Duration) -> Option<PendingAsk> {
    for attempt in 0..LOOKUP_TRIES {
        if attempt > 0 {
            std::thread::sleep(pause);
        }
        match crate::agent_transcript::pending_ask(path) {
            Ok(Some(ask)) => return Some(ask),
            Ok(None) => {}
            Err(err) => {
                tracing::debug!(path = %path.display(), error = %err, "push: session file unreadable; plain alert");
                return None;
            }
        }
    }
    None
}

fn push_ask(pending: &PendingAsk, agent: &str, pane_id: &str, machine_id: &str) -> Option<PushAsk> {
    if let Some(form) = &pending.form {
        return push_form_ask(pending, form, agent, pane_id, machine_id);
    }
    let question = crate::api::answer::drivable_question(pending)?;
    let options_bytes: usize = question.options.iter().map(String::len).sum();
    if question.options.len() > MAX_OPTIONS || options_bytes > OPTIONS_MAX_BYTES {
        return None;
    }
    Some(PushAsk {
        agent: super::sanitized_notification_text(agent, AGENT_MAX_CHARS)?,
        pane_id: pane_id.to_owned(),
        machine_id: machine_id.to_owned(),
        ask_id: pending.id.clone(),
        question: super::sanitized_notification_text(&question.question, QUESTION_MAX_CHARS)?,
        options: question.options.clone(),
        form: None,
    })
}

fn push_form_ask(
    pending: &PendingAsk,
    form: &AskForm,
    agent: &str,
    pane_id: &str,
    machine_id: &str,
) -> Option<PushAsk> {
    let has_default = |field: &AskFormField| match field.kind {
        AskFormFieldKind::Choice => field.options.iter().any(|option| option.checked),
        AskFormFieldKind::Text => field.value.is_some(),
    };
    let accept_defaults = pending.form_answerable
        && form
            .fields
            .iter()
            .all(|field| !field.required || has_default(field));
    let intro = form
        .intro
        .as_deref()
        .and_then(|intro| super::sanitized_notification_text(intro, QUESTION_MAX_CHARS));
    let question = intro.clone().or_else(|| {
        form.fields
            .iter()
            .find_map(|field| field.title.as_deref())
            .and_then(|title| super::sanitized_notification_text(title, QUESTION_MAX_CHARS))
    })?;
    Some(PushAsk {
        agent: super::sanitized_notification_text(agent, AGENT_MAX_CHARS)?,
        pane_id: pane_id.to_owned(),
        machine_id: machine_id.to_owned(),
        ask_id: pending.id.clone(),
        question,
        options: Vec::new(),
        form: Some(PushAskForm {
            count: form.fields.len(),
            intro,
            accept_defaults,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct TempSession(PathBuf);

    impl Drop for TempSession {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn session(questions: serde_json::Value, answered: bool) -> TempSession {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "herdr-push-ask-{}-{}.jsonl",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut text = json!({
            "type": "message",
            "id": "e1",
            "message": {"role": "assistant", "content": [{
                "type": "toolCall", "id": "call_7", "name": "ask",
                "arguments": {"questions": questions},
            }]},
        })
        .to_string()
            + "\n";
        if answered {
            text += &json!({
                "type": "message", "id": "e2", "parentId": "e1",
                "message": {"role": "toolResult", "toolCallId": "call_7", "toolName": "ask",
                    "details": {"selectedOptions": ["A"]}},
            })
            .to_string();
            text += "\n";
        }
        std::fs::write(&path, text).unwrap();
        TempSession(path)
    }

    fn labels(count: usize) -> serde_json::Value {
        (0..count)
            .map(|index| json!({"label": format!("Option {index}")}))
            .collect()
    }

    fn alert(kind: PushKind, source: Option<&TempSession>) -> PushNotification {
        PushNotification {
            turn_origin: None,
            title: "jarvis needs attention".into(),
            body: "herdr · 1".into(),
            pane_id: "w1-2".into(),
            workspace_id: "w_1".into(),
            kind,
            #[cfg(unix)]
            guest_scope: None,
            ask_source: source.map(|session| AskSource {
                session_path: session.0.clone(),
                agent: "jarvis".into(),
            }),
            ask: None,
        }
    }

    fn attached(notification: PushNotification) -> Option<PushAsk> {
        let mut batch = [notification];
        attach_with(&mut batch, || "machine-1".into(), Duration::ZERO);
        assert!(batch[0].ask_source.is_none(), "the source is consumed");
        batch[0].ask.take()
    }

    #[test]
    fn pending_single_select_ask_rides_the_needs_input_alert() {
        let file = session(
            json!([{"question": "Ship\nnow?", "options": labels(4)}]),
            false,
        );
        assert_eq!(
            attached(alert(PushKind::NeedsInput, Some(&file))),
            Some(PushAsk {
                agent: "jarvis".into(),
                pane_id: "w1-2".into(),
                machine_id: "machine-1".into(),
                ask_id: "call_7".into(),
                question: "Ship now?".into(),
                options: vec![
                    "Option 0".into(),
                    "Option 1".into(),
                    "Option 2".into(),
                    "Option 3".into(),
                ],
                form: None,
            })
        );
    }

    #[test]
    fn asks_a_notification_cannot_answer_get_a_plain_alert() {
        let five = session(json!([{"question": "Q", "options": labels(5)}]), false);
        assert_eq!(attached(alert(PushKind::NeedsInput, Some(&five))), None);
        let multi = session(
            json!([{"question": "Q", "options": labels(2), "multi": true}]),
            false,
        );
        assert_eq!(attached(alert(PushKind::NeedsInput, Some(&multi))), None);
        let long = session(
            json!([{"question": "Q", "options": [{"label": "x".repeat(OPTIONS_MAX_BYTES + 1)}]}]),
            false,
        );
        assert_eq!(attached(alert(PushKind::NeedsInput, Some(&long))), None);
        let answered = session(json!([{"question": "Q", "options": labels(2)}]), true);
        assert_eq!(attached(alert(PushKind::NeedsInput, Some(&answered))), None);
    }

    #[test]
    fn only_needs_input_alerts_with_a_source_look_for_an_ask() {
        let file = session(json!([{"question": "Q", "options": labels(2)}]), false);
        assert_eq!(attached(alert(PushKind::Finished, Some(&file))), None);
        let mut batch = [alert(PushKind::NeedsInput, None)];
        attach_with(
            &mut batch,
            || panic!("no ask, so no machine id lookup"),
            Duration::ZERO,
        );
        assert_eq!(batch[0].ask, None);
    }

    #[test]
    fn a_form_ask_carries_its_summary_and_accept_action_only_when_defaults_cover_required() {
        let pending = |html: &str| {
            let parsed = crate::agent_transcript::ask_form::parse(html);
            let wire = parsed.to_wire();
            PendingAsk {
                id: "f1".into(),
                questions: parsed.compat_questions(&wire),
                answerable: false,
                form: Some(wire),
                form_answerable: parsed.drivable(),
            }
        };
        let defaults = pending(
            r#"<form><p>Two picks.</p><input type="radio" name="a" value="1" checked required>
            <input type="radio" name="a" value="2"><input name="note"></form>"#,
        );
        let ask = push_ask(&defaults, "jarvis", "w1-2", "m1").unwrap();
        assert_eq!(ask.question, "Two picks.");
        assert!(ask.options.is_empty());
        let form = ask.form.clone().unwrap();
        assert_eq!((form.count, form.accept_defaults), (2, true));
        assert_eq!(form_body(&form), "Two picks.");
        let mut notification = alert(PushKind::NeedsInput, None);
        notification.ask = Some(ask);
        let payload: serde_json::Value =
            serde_json::from_str(&super::super::apns::payload_body(&notification)).unwrap();
        assert_eq!(payload["aps"]["category"], FORM_CATEGORY);
        assert_eq!(payload["aps"]["alert"]["body"], "Two picks.");
        assert_eq!(payload["herdr_ask"]["form"]["accept_defaults"], true);
        assert_eq!(payload["herdr_ask"]["ask_id"], "f1");

        let missing = pending(
            r#"<form><fieldset><legend>Who?</legend><input name="who" required></fieldset></form>"#,
        );
        let ask = push_ask(&missing, "jarvis", "w1-2", "m1").unwrap();
        assert_eq!(ask.question, "Who?");
        let form = ask.form.clone().unwrap();
        assert!(!form.accept_defaults);
        assert_eq!(form_body(&form), "1 choice · recommended preselected");
        let mut notification = alert(PushKind::NeedsInput, None);
        notification.ask = Some(ask);
        let payload: serde_json::Value =
            serde_json::from_str(&super::super::apns::payload_body(&notification)).unwrap();
        assert_eq!(
            payload["aps"].get("category"),
            None,
            "no action without defaults"
        );
    }
}
