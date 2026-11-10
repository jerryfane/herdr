use std::collections::BTreeMap;

use super::*;
use crate::agent_transcript::ask_form::{parse, Block};

const FORM: &str = r#"<form><p>Intro</p>
<fieldset><legend>Database</legend>
<label><input type="radio" name="db" value="pg" checked> Postgres</label>
<label><input type="radio" name="db" value="my"> MySQL</label>
<label><input type="radio" name="db" value="x" disabled> Oracle</label>
<label><input type="radio" name="db" value="sq"> SQLite</label>
</fieldset>
<fieldset><legend>Tools</legend>
<label><input type="checkbox" name="tools" value="ci" checked> CI</label>
<label><input type="checkbox" name="tools" value="tf"> Terraform</label>
<label><input type="checkbox" name="tools" value="nx"> Nix</label>
</fieldset>
<label>Region <select name="region"><option value="us">US</option><option value="eu" disabled>EU</option><option value="ap">AP</option></select></label>
<label>Notes <input name="notes" value="draft"></label>
</form>"#;

fn values(pairs: &[(&str, AskFormValue)]) -> BTreeMap<String, AskFormValue> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}

fn options(list: &[&str]) -> AskFormValue {
    AskFormValue {
        options: Some(list.iter().map(|value| (*value).to_owned()).collect()),
        ..AskFormValue::default()
    }
}

#[test]
fn stops_follow_dialog_ts() {
    let form = parse(FORM);
    assert_eq!(
        stops(&form),
        [
            Stop::Option {
                field: 0,
                option: 0
            },
            Stop::Option {
                field: 0,
                option: 1
            },
            Stop::Option {
                field: 0,
                option: 3
            },
            Stop::Other { field: 0 },
            Stop::Option {
                field: 1,
                option: 0
            },
            Stop::Option {
                field: 1,
                option: 1
            },
            Stop::Option {
                field: 1,
                option: 2
            },
            Stop::Other { field: 1 },
            Stop::Select { field: 2 },
            Stop::Text { field: 3 },
            Stop::Submit,
        ]
    );
}

#[test]
fn invalid_values_name_the_field() {
    let form = parse(FORM);
    let message = |pairs: &[(&str, AskFormValue)]| plan(&form, &values(pairs)).unwrap_err().message;
    assert_eq!(message(&[("nope", options(&[]))]), "nope: unknown field");
    assert_eq!(
        message(&[("db", options(&["pg", "my"]))]),
        "db: choose only one option"
    );
    assert_eq!(
        message(&[("db", options(&["x"]))]),
        "db: option \"x\" is disabled"
    );
    assert_eq!(
        message(&[("db", options(&["zz"]))]),
        "db: unknown option \"zz\""
    );
    assert_eq!(
        message(&[(
            "region",
            AskFormValue {
                other: Some("y".into()),
                ..AskFormValue::default()
            }
        )]),
        "region: this field has no Other answer"
    );
    let required = parse(r#"<form><input name="who" required></form>"#);
    let error = plan(&required, &BTreeMap::new()).unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("ask_form_invalid", "who: Required")
    );
}

#[test]
fn the_screen_check_wants_the_untouched_form() {
    let form = parse(FORM);
    let start = "agent: Two quick choices\n\
        Database\n\
        ❯ ◉ Postgres\n    ○ MySQL\n    ○ Oracle\n    ○ SQLite\n    ○ Other: type your own\n\
        Tools\n    ☑ CI\n    ☐ Terraform\n    ☐ Nix\n    ☐ Other: type your own\n  Submit";
    assert!(at_start(start, &form));
    let moved = start.replace("❯ ◉ Postgres\n    ○ MySQL", "  ◉ Postgres\n❯ ○ MySQL");
    assert!(!at_start(&moved, &form));
    let changed = start.replace("☐ Terraform", "☑ Terraform");
    assert!(!at_start(&changed, &form));
    let typed = start.replacen("○ Other: type your own", "○ Other: Mongo", 1);
    assert!(!at_start(&typed, &form));
    assert!(!at_start("$ omp\n> ", &form), "no form on screen");
}

fn screen(rows: &[&str]) -> String {
    rows.join("\n")
}

fn text(value: &str) -> AskFormValue {
    AskFormValue {
        text: Some(value.into()),
        ..AskFormValue::default()
    }
}

/// A model of omp's terminal form (`dialog.ts` with its `Input` and
/// `Editor`), drawn as omp draws it, wrapping labels at `width`.
struct Dialog {
    form: ParsedForm,
    stops: Vec<Stop>,
    focus: usize,
    checked: Vec<Vec<usize>>,
    other: Vec<String>,
    /// Text fields (single-line `Input`s): value and caret (in chars).
    text: Vec<String>,
    caret: Vec<usize>,
    width: usize,
    keys: Vec<String>,
    submitted: Option<Vec<(String, Option<FormValue>)>>,
    errors: Vec<Option<String>>,
    /// omp's own Submit check, standing in for `pattern`: (field, message).
    refuse: Option<(usize, String)>,
    /// Keys after this many are swallowed (someone else holds the form).
    frozen_after: Option<usize>,
}

impl Dialog {
    fn new(html: &str) -> Self {
        let form = parse(html);
        let stops = stops(&form);
        let count = form.fields.len();
        let mut dialog = Self {
            stops,
            focus: 0,
            checked: vec![Vec::new(); count],
            other: vec![String::new(); count],
            text: vec![String::new(); count],
            caret: vec![0; count],
            width: 200,
            keys: Vec::new(),
            submitted: None,
            errors: vec![None; count],
            refuse: None,
            frozen_after: None,
            form,
        };
        for (index, field) in dialog.form.fields.iter().enumerate() {
            match &field.kind {
                FieldKind::Choice(choice) => dialog.checked[index] = choice.initial_checked(),
                // omp ≥ 18.18.6 opens prefilled fields with the caret at the start.
                FieldKind::Text(input) => dialog.text[index] = input.value.clone(),
            }
        }
        dialog
    }

    /// omp 18.18.3: single-line inputs open with the caret at the end.
    fn caret_at_end(mut self) -> Self {
        for (index, field) in self.form.fields.iter().enumerate() {
            if let FieldKind::Text(_) = &field.kind {
                self.caret[index] = self.text[index].chars().count();
            }
        }
        self
    }

    fn field_of(&self) -> Option<usize> {
        self.stops[self.focus].field()
    }

    fn move_stop(&mut self, delta: isize) {
        self.focus = (self.focus as isize + delta).clamp(0, self.stops.len() as isize - 1) as usize;
    }

    /// `#moveField(-1)`: the previous field's first stop.
    fn move_field_back(&mut self) {
        let field = self.field_of();
        let mut index = self.focus;
        while index > 0 && self.stops[index].field() == field {
            index -= 1;
        }
        let target = self.stops[index].field();
        while index > 0 && self.stops[index - 1].field() == target {
            index -= 1;
        }
        self.focus = index;
    }

    fn move_field(&mut self) {
        let field = self.field_of();
        while self.focus + 1 < self.stops.len() && self.stops[self.focus].field() == field {
            self.focus += 1;
        }
    }

    fn choice(&self, field: usize) -> &Choice {
        self.form.fields[field].choice().unwrap()
    }

    fn press(&mut self, key: &str) {
        if self
            .frozen_after
            .is_some_and(|limit| self.keys.len() >= limit)
        {
            return;
        }
        self.keys.push(key.to_owned());
        if key == "tab" {
            self.move_field();
            return;
        }
        if key == "shift+tab" {
            self.move_field_back();
            return;
        }
        match self.stops[self.focus] {
            Stop::Text { field } => self.text_key(field, key),
            Stop::Select { field } => match key {
                "up" => self.move_stop(-1),
                "down" => self.move_stop(1),
                "left" | "right" => {
                    let choice = self.choice(field).clone();
                    let current = self.checked[field]
                        .first()
                        .copied()
                        .map_or(-1, |c| c as isize);
                    let delta: isize = if key == "right" { 1 } else { -1 };
                    let mut index = current + delta;
                    while index >= 0 && (index as usize) < choice.options.len() {
                        if !choice.options[index as usize].disabled {
                            self.checked[field] = vec![index as usize];
                            break;
                        }
                        index += delta;
                    }
                }
                "enter" => self.move_field(),
                _ => {}
            },
            Stop::Other { field } => match key {
                "up" => self.move_stop(-1),
                "down" => self.move_stop(1),
                "enter" => {
                    if !self.choice(field).multi && !self.other[field].trim().is_empty() {
                        self.checked[field].clear();
                    }
                    self.move_field();
                }
                // Other is an `Input` whose caret follows typing: at the end.
                "ctrl+u" => self.other[field].clear(),
                _ => {}
            },
            Stop::Option { field, option } => match key {
                "up" => self.move_stop(-1),
                "down" => self.move_stop(1),
                "space" => self.toggle(field, option),
                "enter" => {
                    if !self.choice(field).multi {
                        self.toggle(field, option);
                    }
                    self.move_field();
                }
                _ => {}
            },
            Stop::Submit => match key {
                "up" => self.move_stop(-1),
                "down" => self.move_stop(1),
                "enter" => self.submit(),
                _ => {}
            },
        }
    }

    fn toggle(&mut self, field: usize, option: usize) {
        if self.choice(field).multi {
            if let Some(at) = self.checked[field].iter().position(|o| *o == option) {
                self.checked[field].remove(at);
            } else {
                self.checked[field].push(option);
                self.checked[field].sort_unstable();
            }
        } else {
            self.checked[field] = vec![option];
        }
    }

    /// omp's `Input`: ↑/↓ and Enter leave it; Ctrl+E/Ctrl+U/Ctrl+K edit.
    fn text_key(&mut self, field: usize, key: &str) {
        let text = &mut self.text[field];
        let mut col = self.caret[field];
        let byte = |text: &str, col: usize| {
            text.char_indices()
                .nth(col)
                .map_or(text.len(), |(at, _)| at)
        };
        match key {
            "up" => return self.move_stop(-1),
            "down" => return self.move_stop(1),
            "enter" => return self.move_field(),
            "ctrl+e" => col = text.chars().count(),
            "ctrl+u" => {
                let at = byte(text, col);
                text.replace_range(..at, "");
                col = 0;
            }
            "ctrl+k" => {
                let at = byte(text, col);
                text.truncate(at);
            }
            _ => {}
        }
        self.caret[field] = col.min(self.text[field].chars().count());
    }

    fn paste(&mut self, text: &str) {
        if self
            .frozen_after
            .is_some_and(|limit| self.keys.len() >= limit)
        {
            return;
        }
        self.keys.push(format!("text:{text}"));
        match self.stops[self.focus] {
            Stop::Other { field } => {
                self.other[field].push_str(text);
                if !self.choice(field).multi && !self.other[field].trim().is_empty() {
                    self.checked[field].clear();
                }
            }
            Stop::Text { field } => {
                let col = self.caret[field];
                let current = &mut self.text[field];
                let at = current
                    .char_indices()
                    .nth(col)
                    .map_or(current.len(), |(at, _)| at);
                current.insert_str(at, text);
                self.caret[field] = col + text.chars().count();
            }
            _ => {}
        }
    }

    fn values(&self) -> Vec<Option<FormValue>> {
        self.form
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| match &field.kind {
                FieldKind::Choice(choice) => {
                    let other = &self.other[index];
                    let chosen = !other.trim().is_empty()
                        && (choice.multi || self.checked[index].is_empty());
                    choice_value(
                        choice,
                        &self.checked[index],
                        chosen.then_some(other.as_str()),
                    )
                }
                FieldKind::Text(input) => Some(text_value(input, &self.text[index])),
            })
            .collect()
    }

    fn submit(&mut self) {
        if let Some((field, message)) = self.refuse.clone() {
            self.errors[field] = Some(message);
            self.focus = self
                .stops
                .iter()
                .position(|stop| stop.field() == Some(field))
                .unwrap();
            return;
        }
        self.submitted = Some(self.form.submission(&self.values()));
    }

    fn wrap(&self, text: &str, indent: usize) -> Vec<String> {
        let width = self.width.saturating_sub(indent).max(4);
        let mut rows = vec![String::new()];
        for word in text.split(' ') {
            let last = rows.last_mut().unwrap();
            if !last.is_empty() && last.chars().count() + 1 + word.chars().count() > width {
                rows.push(word.to_owned());
            } else {
                if !last.is_empty() {
                    last.push(' ');
                }
                last.push_str(word);
            }
        }
        rows
    }

    fn render(&self) -> String {
        let mut out = vec![
            "❯ an earlier prompt in the chat".to_owned(),
            "╭─ Ask ─╮".to_owned(),
        ];
        for section in &self.form.sections {
            if !section.title.is_empty() {
                out.push(format!("│ {}", section.title));
            }
            for block in &section.blocks {
                match block {
                    Block::Field(index) => self.render_field(*index, &mut out),
                    Block::Text { text, .. } => out.push(format!("│ {}", one_line(text))),
                    _ => {}
                }
            }
        }
        let cursor = if self.stops[self.focus] == Stop::Submit {
            "❯ "
        } else {
            "  "
        };
        out.push(format!("│ {cursor}Submit"));
        out.push("╰───────╯".into());
        out.join("\n")
    }

    fn cursor(&self, stop: Stop) -> &'static str {
        if self.stops[self.focus] == stop {
            "❯ "
        } else {
            "  "
        }
    }

    fn label_rows(&self, index: usize, stop: Stop, suffix: &str, out: &mut Vec<String>) {
        let field = &self.form.fields[index];
        let mut rows = self.wrap(&one_line(&field.label), 4);
        *rows.last_mut().unwrap() += suffix;
        for (row, text) in rows.iter().enumerate() {
            let lead = if row == 0 { self.cursor(stop) } else { "  " };
            out.push(format!("│ {lead}{text}"));
        }
    }

    fn render_field(&self, index: usize, out: &mut Vec<String>) {
        let field = &self.form.fields[index];
        let star = if field.required { " *" } else { "" };
        match &field.kind {
            FieldKind::Text(input) => {
                let stop = Stop::Text { field: index };
                self.label_rows(index, stop, star, out);
                let value = &self.text[index];
                let row = if value.is_empty() {
                    &input.placeholder
                } else {
                    value
                };
                out.push(format!("│   │ {row}"));
            }
            FieldKind::Choice(choice) if choice.is_dropdown() => {
                let stop = Stop::Select { field: index };
                let current = self.checked[index].first().copied();
                let value =
                    current.map_or("—".to_owned(), |c| one_line(&choice.options[c].label));
                let position = current.map_or(String::new(), |c| {
                    format!("  {}/{}", c + 1, choice.options.len())
                });
                if one_line(&field.label).is_empty() {
                    out.push(format!(
                        "│ {}‹ {value} ›{position}{star}",
                        self.cursor(stop)
                    ));
                } else {
                    self.label_rows(index, stop, star, out);
                    out.push(format!("│   │ ‹ {value} ›{position}"));
                }
            }
            FieldKind::Choice(choice) => {
                let (on, off) = if choice.multi {
                    ("☑", "☐")
                } else {
                    ("◉", "○")
                };
                for (option, entry) in choice.options.iter().enumerate() {
                    let stop = Stop::Option {
                        field: index,
                        option,
                    };
                    let marker = if self.checked[index].contains(&option) {
                        on
                    } else {
                        off
                    };
                    let rows = self.wrap(&one_line(&entry.label), 6);
                    for (row, text) in rows.iter().enumerate() {
                        if row == 0 {
                            out.push(format!("│ {}{marker} {text}", self.cursor(stop)));
                        } else {
                            out.push(format!("│     {text}"));
                        }
                    }
                }
                if choice.other {
                    let stop = Stop::Other { field: index };
                    let other = &self.other[index];
                    let chosen = !other.trim().is_empty()
                        && (choice.multi || self.checked[index].is_empty());
                    let marker = if chosen { on } else { off };
                    let shown = if other.is_empty() {
                        if self.stops[self.focus] == stop {
                            " type your own"
                        } else {
                            "type your own"
                        }
                        .to_owned()
                    } else {
                        other.clone()
                    };
                    out.push(format!("│ {}{marker} Other: {shown}", self.cursor(stop)));
                }
            }
        }
        if let Some(error) = &self.errors[index] {
            out.push(format!("│     {error}"));
        }
    }
}

impl FormPane for Dialog {
    fn read_screen(&mut self) -> Result<String, ErrorBody> {
        Ok(self.render())
    }

    fn send(&mut self, action: &Action) -> Result<(), ErrorBody> {
        match action {
            Action::Keys(keys) => keys.iter().for_each(|key| self.press(key)),
            Action::Text(text) => self.paste(text),
        }
        Ok(())
    }

    fn pause(&mut self) {}
}

/// Plan and drive `values` into `dialog`; the data it submitted.
fn answer(
    dialog: &mut Dialog,
    values: BTreeMap<String, AskFormValue>,
) -> Result<Vec<(String, Option<FormValue>)>, ErrorBody> {
    let form = dialog.form.clone();
    let plan = plan(&form, &values)?;
    drive(dialog, &form, &plan)?;
    let submitted = dialog.submitted.clone().expect("the form was submitted");
    assert_eq!(
        submitted, plan.expected,
        "omp submits what the plan expects"
    );
    Ok(submitted)
}

fn value(submitted: &[(String, Option<FormValue>)], name: &str) -> Option<FormValue> {
    submitted
        .iter()
        .find(|(candidate, _)| candidate == name)
        .and_then(|(_, value)| value.clone())
}

fn list(items: &[&str]) -> Option<FormValue> {
    Some(FormValue::List(
        items.iter().map(|item| (*item).to_owned()).collect(),
    ))
}

fn txt(value: &str) -> Option<FormValue> {
    Some(FormValue::Text(value.to_owned()))
}

#[test]
fn accepting_the_recommendations_submits_the_defaults() {
    let mut dialog = Dialog::new(FORM);
    let submitted = answer(&mut dialog, BTreeMap::new()).unwrap();
    assert_eq!(value(&submitted, "db"), txt("pg"));
    assert_eq!(value(&submitted, "tools"), list(&["ci"]));
    assert_eq!(value(&submitted, "region"), txt("us"));
    assert_eq!(value(&submitted, "notes"), txt("draft"));
    assert_eq!(
        dialog.keys.first().map(String::as_str),
        Some("up"),
        "↑ releases a composer draft"
    );
    assert_eq!(dialog.keys.last().map(String::as_str), Some("enter"));
}

#[test]
fn every_control_type_is_driven() {
    let mut dialog = Dialog::new(FORM);
    let submitted = answer(
        &mut dialog,
        values(&[
            ("db", options(&["sq"])),
            (
                "tools",
                AskFormValue {
                    options: Some(vec!["tf".into()]),
                    other: Some("just".into()),
                    text: None,
                },
            ),
            ("region", options(&["ap"])),
            ("notes", text("ship friday")),
        ]),
    )
    .unwrap();
    assert_eq!(value(&submitted, "db"), txt("sq"));
    assert_eq!(value(&submitted, "tools"), list(&["tf", "just"]));
    assert_eq!(value(&submitted, "region"), txt("ap"));
    assert_eq!(value(&submitted, "notes"), txt("ship friday"));
}

#[test]
fn radio_other_replaces_the_option() {
    let mut dialog = Dialog::new(FORM);
    let other = AskFormValue {
        options: Some(Vec::new()),
        other: Some(" CockroachDB ".into()),
        text: None,
    };
    let submitted = answer(&mut dialog, values(&[("db", other)])).unwrap();
    assert_eq!(value(&submitted, "db"), txt("CockroachDB"));
}

/// #392 F1: omp 18.18.3 opens inputs with the caret at the end; the clear
/// does not depend on where it is.
#[test]
fn text_is_replaced_whatever_the_starting_caret() {
    for mut dialog in [Dialog::new(FORM), Dialog::new(FORM).caret_at_end()] {
        let submitted = answer(&mut dialog, values(&[("notes", text("ship friday"))])).unwrap();
        assert_eq!(value(&submitted, "notes"), txt("ship friday"));
    }
    let mut dialog = Dialog::new(FORM).caret_at_end();
    let submitted = answer(&mut dialog, values(&[("notes", text(""))])).unwrap();
    assert_eq!(value(&submitted, "notes"), txt(""));
}

/// #392 F2: text and dropdowns changed in the terminal are set back.
#[test]
fn edited_text_and_dropdowns_are_reset() {
    let mut dialog = Dialog::new(FORM);
    dialog.text[3] = "changed".into();
    dialog.checked[2] = vec![2];
    let submitted = answer(&mut dialog, BTreeMap::new()).unwrap();
    assert_eq!(value(&submitted, "region"), txt("us"));
    assert_eq!(value(&submitted, "notes"), txt("draft"));
}

/// #392 N1: a dropdown whose default is a disabled option ahead of the
/// enabled ones is still set to the answer.
#[test]
fn a_dropdown_starting_on_a_disabled_option_is_set() {
    let html = r#"<form><label>Size <select name="s"><option value="a" disabled selected>A</option><option value="b">B</option><option value="c">C</option></select></label></form>"#;
    let mut dialog = Dialog::new(html);
    let submitted = answer(&mut dialog, values(&[("s", options(&["b"]))])).unwrap();
    assert_eq!(value(&submitted, "s"), txt("b"));
    let mut dialog = Dialog::new(html);
    let submitted = answer(&mut dialog, values(&[("s", options(&["c"]))])).unwrap();
    assert_eq!(value(&submitted, "s"), txt("c"));
}

/// #392 N2: labels omp wraps over several rows are still found.
#[test]
fn wrapped_labels_are_followed() {
    let html = r#"<form><label>Please describe your preferred deployment environment in detail <input name="env" value="x"></label>
        <label>Which of the regions should we deploy to first <select name="r"><option>eu</option><option>us</option></select></label>
        <label><input type="radio" name="p" value="a" checked> A long option label that the form wraps onto a second row</label>
        <label><input type="radio" name="p" value="b"> Short</label></form>"#;
    let mut dialog = Dialog::new(html);
    dialog.width = 24;
    assert!(at_start(&dialog.render(), &dialog.form));
    let submitted = answer(
        &mut dialog,
        values(&[
            ("env", text("prod")),
            ("r", options(&["us"])),
            ("p", options(&["b"])),
        ]),
    )
    .unwrap();
    assert_eq!(value(&submitted, "env"), txt("prod"));
    assert_eq!(value(&submitted, "r"), txt("us"));
    assert_eq!(value(&submitted, "p"), txt("b"));
}

/// A present entry without `options` (`"tools": {}`) means none chosen:
/// only a missing name keeps the default.
#[test]
fn a_present_entry_without_options_unticks_a_checkbox_group() {
    let mut dialog = Dialog::new(FORM);
    let submitted = answer(&mut dialog, values(&[("tools", AskFormValue::default())])).unwrap();
    assert_eq!(value(&submitted, "tools"), list(&[]));

    let required = parse(
        r#"<form><label><input type="checkbox" name="t" value="a" checked required> A</label>
        <label><input type="checkbox" name="t" value="b"> B</label></form>"#,
    );
    let error = plan(&required, &values(&[("t", AskFormValue::default())])).unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("ask_form_invalid", "t: Select at least one")
    );
    // Missing keeps the default, which satisfies `required`.
    assert!(plan(&required, &BTreeMap::new()).is_ok());
}

#[test]
fn a_present_radio_entry_without_options_needs_other() {
    let form = parse(FORM);
    let error = plan(&form, &values(&[("db", AskFormValue::default())])).unwrap_err();
    assert_eq!(error.message, "db: choose one option or Other");
}

/// A field that does not show what was sent stops the drive before Submit.
#[test]
fn a_form_that_stops_responding_is_never_submitted() {
    for limit in [1, 3, 6, 10] {
        let mut dialog = Dialog::new(FORM);
        dialog.frozen_after = Some(limit);
        let form = dialog.form.clone();
        let plan = plan(
            &form,
            &values(&[("db", options(&["sq"])), ("notes", text("x"))]),
        )
        .unwrap();
        let error = drive(&mut dialog, &form, &plan).unwrap_err();
        assert_eq!(error.code, "ask_form_moved", "{limit}");
        assert_eq!(dialog.submitted, None, "{limit}");
    }
}

/// #392 F7: omp checks `pattern` itself; its refusal is read off the screen.
#[test]
fn a_refused_submission_is_read_from_the_screen() {
    let html = r#"<form><label>Code <input name="code" pattern="[A-Z]{3}"></label></form>"#;
    let mut dialog = Dialog::new(html);
    dialog.refuse = Some((0, "Must match [A-Z]{3}".into()));
    let form = dialog.form.clone();
    let plan = plan(&form, &values(&[("code", text("abcd"))])).unwrap();
    drive(&mut dialog, &form, &plan).unwrap();
    assert_eq!(dialog.submitted, None);
    assert_eq!(
        submit_error(&dialog.render(), &form),
        Some(("code".to_owned(), "Must match [A-Z]{3}".to_owned()))
    );
    assert_eq!(submit_error(&Dialog::new(html).render(), &form), None);
}

/// #392 F9: what omp recorded is compared by value, not by spelling.
#[test]
fn recorded_data_is_compared_by_value() {
    let expected = vec![
        ("n".to_owned(), Some(FormValue::Number(2.0f64.powi(-25)))),
        ("t".to_owned(), txt("ship")),
        ("l".to_owned(), list(&["a", "b"])),
        ("none".to_owned(), None),
    ];
    let recorded = |json: serde_json::Value| json.as_object().unwrap().clone();
    assert!(submission_matches(
        &expected,
        // As omp writes it: JS spells 2^-25 `2.9802322387695312e-8`.
        &recorded(
            serde_json::from_str(
                r#"{"n": 2.9802322387695312e-8, "t": " ship ", "l": ["a", "b"], "hidden": "x"}"#
            )
            .unwrap()
        )
    ));
    assert!(!submission_matches(
        &expected,
        &recorded(serde_json::json!({"n": 3e-8, "t": "ship", "l": ["a", "b"]}))
    ));
    assert!(!submission_matches(
        &expected,
        &recorded(serde_json::json!({"n": 2.0f64.powi(-25), "t": "ship", "l": ["b", "a"]}))
    ));
    assert!(!submission_matches(
        &expected,
        &recorded(
            serde_json::json!({"n": 2.0f64.powi(-25), "t": "ship", "l": ["a", "b"], "none": "x"})
        )
    ));
}

/// #392 F3: labels sharing a long prefix are told apart; focus on the third
/// is not the first stop.
#[test]
fn the_screen_check_needs_the_whole_label() {
    let form = parse(
        r#"<form><label><input type="radio" name="r" value="a"> abcdefghijkl A</label>
        <label><input type="radio" name="r" value="b"> abcdefghijkl B</label>
        <label><input type="radio" name="r" value="c"> abcdefghijkl C</label></form>"#,
    );
    let rows = |focus: usize| {
        let mut lines = vec!["Ask".to_owned()];
        for (index, letter) in ["A", "B", "C"].iter().enumerate() {
            let cursor = if index == focus { "❯ " } else { "  " };
            lines.push(format!("│ {cursor}○ abcdefghijkl {letter}   │"));
        }
        lines.push("│   ○ Other: type your own │".into());
        lines.join("\n")
    };
    assert!(at_start(&rows(0), &form));
    assert!(!at_start(&rows(2), &form));
}

/// #392 F4: an option of the agent's own labelled "Other: …" is a label,
/// not the synthetic Other row.
#[test]
fn an_option_labelled_other_is_an_ordinary_row() {
    let form = parse(
        r#"<form><label><input type="radio" name="r" value="a" checked> A</label>
        <label><input type="radio" name="r" value="s"> Other: skip</label></form>"#,
    );
    assert!(!choice_other(&form));
    assert!(at_start(
        &screen(&["❯ ◉ A", "  ○ Other: skip", "  Submit"]),
        &form
    ));
}

fn choice_other(form: &ParsedForm) -> bool {
    form.fields[0].choice().unwrap().other
}

/// #392 F5: Other can be the first stop (every option disabled).
#[test]
fn other_can_be_the_first_stop() {
    let form = parse(
        r#"<form><label><input type="radio" name="r" value="a" disabled> A</label>
        <label><input type="radio" name="r" value="b" disabled> B</label></form>"#,
    );
    assert_eq!(stops(&form)[0], Stop::Other { field: 0 });
    // Focused and empty, omp draws a cursor block before the placeholder.
    let start = screen(&["  ○ A", "  ○ B", "❯ ○ Other:  type your own", "  Submit"]);
    assert!(at_start(&start, &form));
    let typed = screen(&["  ○ A", "  ○ B", "❯ ○ Other: x", "  Submit"]);
    assert!(!at_start(&typed, &form));
}

/// #392 r3: numbers compare exactly; near-zero values are not each other.
#[test]
fn near_zero_numbers_are_not_confused() {
    let expected = vec![("n".to_owned(), Some(FormValue::Number(1e-30)))];
    let recorded = |json: &str| {
        serde_json::from_str::<serde_json::Value>(json)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    };
    assert!(submission_matches(&expected, &recorded(r#"{"n": 1e-30}"#)));
    assert!(!submission_matches(&expected, &recorded(r#"{"n": 0}"#)));
    assert!(!submission_matches(&expected, &recorded(r#"{"n": 1e-17}"#)));
    let zero = vec![("n".to_owned(), Some(FormValue::Number(0.0)))];
    assert!(submission_matches(&zero, &recorded(r#"{"n": 0}"#)));
    assert!(!submission_matches(&zero, &recorded(r#"{"n": 5e-324}"#)));
}

/// #392 r4: forms with a `<textarea>` are refused before anything is read or
/// sent: omp's `Editor` has no key that empties a whole draft, so a textarea
/// is answered in the terminal.
#[test]
fn a_form_with_a_textarea_is_not_driven() {
    let form = parse(
        r#"<form><label><input type="radio" name="r" value="a" checked> A</label>
        <label><input type="radio" name="r" value="b"> B</label>
        <label>Notes <textarea name="notes">draft</textarea></label></form>"#,
    );
    assert!(!form.drivable());
    assert_eq!(
        form.refusal(),
        Some("textarea fields: answer in the terminal")
    );
}
