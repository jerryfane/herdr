//! Drives omp's HTML form `ask` (omp ≥ 18.18.3, upstream
//! `packages/tui/src/html-form/dialog.ts`) with keys.
//!
//! The terminal form has one focus stop per enabled option row of a radio,
//! checkbox or multi-select group (then the group's Other row), one per
//! dropdown (single `<select>`) and text field, then Submit. ↑/↓ move one stop;
//! Tab jumps to the next field's first stop; Enter on a radio option picks it
//! and moves on; Space toggles a checkbox; typing on an Other row or a text
//! field edits it; ←/→ change a dropdown; Enter on Submit submits.
//!
//! [`plan`] turns requested values into that key sequence from the form's
//! starting state (focus on the first stop, defaults checked), which
//! [`at_start`] checks on screen before anything is sent.

use std::collections::BTreeMap;

use crate::agent_transcript::ask_form::{
    choice_value, field_error, one_line, text_value, Choice, FieldKind, FormValue, ParsedForm,
    OTHER_LABEL,
};
use crate::api::schema::{AskFormAnswer, AskFormValue, ErrorBody};

use super::selector::{CURSOR_GLYPHS, LEFT_EDGE};

/// What omp shows in an empty Other row.
const OTHER_PLACEHOLDER: &str = "type your own";
/// Radio markers of omp's unicode, nerd-font and ascii presets: (selected, unselected).
const RADIO_MARKERS: [(&str, &str); 3] = [("◉", "○"), ("\u{f192}", "\u{f10c}"), ("(o)", "( )")];
/// Checkbox markers of the same presets: (checked, unchecked).
const CHECKBOX_MARKERS: [(&str, &str); 3] = [("☑", "☐"), ("\u{f14a}", "\u{f096}"), ("[x]", "[ ]")];
/// How much of a label the screen check compares: enough to tell rows
/// apart, short enough to sit on a label's first wrapped line.
const LABEL_PREFIX_CHARS: usize = 12;

/// One step of the drive: named keys (`pane.send_keys`) or literal text
/// (typed, as a paste when the terminal asked for bracketed paste).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Keys(Vec<&'static str>),
    Text(String),
}

/// The keys to send and the `details.answers` omp should record for them.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    pub actions: Vec<Action>,
    pub expected: Vec<AskFormAnswer>,
}

/// A focus stop of the terminal form, in focus order (`#stops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    Option { field: usize, option: usize },
    Other { field: usize },
    Select { field: usize },
    Text { field: usize },
    Submit,
}

impl Stop {
    fn field(self) -> Option<usize> {
        match self {
            Self::Option { field, .. }
            | Self::Other { field }
            | Self::Select { field }
            | Self::Text { field } => Some(field),
            Self::Submit => None,
        }
    }
}

/// The form's focus stops, as dialog.ts builds them.
pub(crate) fn stops(form: &ParsedForm) -> Vec<Stop> {
    let mut stops = Vec::new();
    for (field, entry) in form.fields.iter().enumerate() {
        match &entry.kind {
            FieldKind::Text(_) => stops.push(Stop::Text { field }),
            FieldKind::Choice(choice) if choice.is_dropdown() => {
                if choice.options.iter().any(|option| !option.disabled) {
                    stops.push(Stop::Select { field });
                }
            }
            FieldKind::Choice(choice) => {
                for (option, entry) in choice.options.iter().enumerate() {
                    if !entry.disabled {
                        stops.push(Stop::Option { field, option });
                    }
                }
                if choice.other {
                    stops.push(Stop::Other { field });
                }
            }
        }
    }
    stops.push(Stop::Submit);
    stops
}

/// A field's state after the drive.
#[derive(Debug, Clone, PartialEq)]
enum Target {
    Choice {
        checked: Vec<usize>,
        other: Option<String>,
    },
    Text(String),
}

fn invalid(name: &str, reason: impl std::fmt::Display) -> ErrorBody {
    ErrorBody {
        code: "ask_form_invalid".into(),
        message: format!("{name}: {reason}"),
    }
}

fn initial(form: &ParsedForm, field: usize) -> Target {
    match &form.fields[field].kind {
        FieldKind::Choice(choice) => Target::Choice {
            checked: choice.initial_checked(),
            other: None,
        },
        FieldKind::Text(input) => Target::Text(input.value.clone()),
    }
}

fn has_control_chars(text: &str, allow_newlines: bool) -> bool {
    text.chars()
        .any(|ch| ch.is_control() && !(allow_newlines && matches!(ch, '\n' | '\t')))
}

fn choice_target(
    name: &str,
    choice: &Choice,
    initial: Vec<usize>,
    value: &AskFormValue,
) -> Result<Target, ErrorBody> {
    if value.text.is_some() {
        return Err(invalid(
            name,
            "a choice field takes options or other, not text",
        ));
    }
    let mut checked: Vec<usize> = Vec::new();
    for raw in value.options.as_deref().unwrap_or_default() {
        let found = choice
            .options
            .iter()
            .enumerate()
            .filter(|(_, option)| option.value == *raw)
            .min_by_key(|(_, option)| option.disabled);
        match found {
            None => return Err(invalid(name, format!("unknown option {raw:?}"))),
            Some((_, option)) if option.disabled => {
                return Err(invalid(name, format!("option {raw:?} is disabled")))
            }
            Some((index, _)) if !checked.contains(&index) => checked.push(index),
            Some(_) => {}
        }
    }
    checked.sort_unstable();
    let other = match value.other.as_deref().map(str::trim) {
        Some("") | None => None,
        Some(_) if !choice.other => {
            return Err(invalid(name, "this field has no Other answer"));
        }
        Some(text) if has_control_chars(text, false) => {
            return Err(invalid(name, "Other takes a single line of plain text"));
        }
        Some(text) => Some(text.to_owned()),
    };
    if choice.multi {
        // Disabled options keep their state: no stop reaches them.
        for (index, option) in choice.options.iter().enumerate() {
            if option.disabled && initial.contains(&index) && !checked.contains(&index) {
                checked.push(index);
            }
        }
        checked.sort_unstable();
        return Ok(Target::Choice { checked, other });
    }
    match (checked.len(), &other) {
        // A present entry without options means "none chosen" (only a missing
        // name keeps the default), and a radio cannot be unpicked.
        (0, None) => Err(invalid(name, "choose one option or Other")),
        (0, Some(_)) => Ok(Target::Choice { checked, other }),
        (1, None) => Ok(Target::Choice { checked, other }),
        (1, Some(_)) => Err(invalid(name, "choose one option or Other, not both")),
        _ => Err(invalid(name, "choose only one option")),
    }
}

fn targets(
    form: &ParsedForm,
    values: &BTreeMap<String, AskFormValue>,
) -> Result<Vec<Target>, ErrorBody> {
    for name in values.keys() {
        if !form
            .fields
            .iter()
            .any(|field| !field.name.is_empty() && field.name == *name)
        {
            return Err(invalid(name, "unknown field"));
        }
    }
    let mut out = Vec::with_capacity(form.fields.len());
    for (index, field) in form.fields.iter().enumerate() {
        let value = (!field.name.is_empty())
            .then(|| values.get(&field.name))
            .flatten();
        let Some(value) = value else {
            out.push(initial(form, index));
            continue;
        };
        let target = match &field.kind {
            FieldKind::Choice(choice) => {
                choice_target(&field.name, choice, choice.initial_checked(), value)?
            }
            FieldKind::Text(input) => {
                if value.options.is_some() || value.other.is_some() {
                    return Err(invalid(&field.name, "a text field takes text"));
                }
                match &value.text {
                    None => initial(form, index),
                    Some(text) if has_control_chars(text, input.multiline) => {
                        return Err(invalid(
                            &field.name,
                            if input.multiline {
                                "control characters are not allowed"
                            } else {
                                "this field takes a single line of plain text"
                            },
                        ));
                    }
                    Some(text) => Target::Text(text.clone()),
                }
            }
        };
        out.push(target);
    }
    Ok(out)
}

fn value_of(form: &ParsedForm, field: usize, target: &Target) -> Option<FormValue> {
    match (&form.fields[field].kind, target) {
        (FieldKind::Choice(choice), Target::Choice { checked, other }) => {
            choice_value(choice, checked, other.as_deref())
        }
        (FieldKind::Text(input), Target::Text(text)) => Some(text_value(input, text)),
        _ => None,
    }
}

/// Where ←/→ presses from `from` land on a dropdown (`#step`): the nearest
/// enabled option one step over, clamped at the ends.
fn dropdown_keys(choice: &Choice, from: Option<usize>, to: usize) -> Vec<&'static str> {
    let enabled: Vec<usize> = (0..choice.options.len())
        .filter(|index| !choice.options[*index].disabled)
        .collect();
    let target = enabled.iter().position(|index| *index == to).unwrap_or(0);
    // `#step` from `from` (or -1): the first press lands on the nearest
    // enabled option in that direction.
    let (key, presses) = match from {
        Some(from) if from == to => return Vec::new(),
        Some(from) if from < to => {
            let start = enabled.iter().filter(|index| **index <= from).count();
            ("right", target + 1 - start)
        }
        Some(from) => {
            let start = enabled.iter().filter(|index| **index < from).count();
            ("left", start - target)
        }
        None => ("right", target + 1),
    };
    vec![key; presses]
}

/// Keys that empty a prefilled text field whose cursor sits at its start
/// (omp opens prefilled fields there): `ctrl+k` deletes to the line end, and
/// at a line end joins the next line.
fn clear_keys(value: &str, multiline: bool) -> Vec<&'static str> {
    if value.is_empty() {
        return Vec::new();
    }
    if !multiline {
        return vec!["ctrl+k"];
    }
    let lines: Vec<&str> = value.split('\n').collect();
    let presses = lines.iter().filter(|line| !line.is_empty()).count() + lines.len() - 1;
    vec!["ctrl+k"; presses]
}

/// The keys that turn the freshly opened form into `values` and submit it,
/// with the answers omp should then record. Validates `values` against the
/// form as omp would before submitting.
pub(crate) fn plan(
    form: &ParsedForm,
    values: &BTreeMap<String, AskFormValue>,
) -> Result<Plan, ErrorBody> {
    let targets = targets(form, values)?;
    let data: Vec<Option<FormValue>> = targets
        .iter()
        .enumerate()
        .map(|(field, target)| value_of(form, field, target))
        .collect();
    for (field, value) in form.fields.iter().zip(&data) {
        if let Some(reason) = field_error(field, value.as_ref()) {
            let name = if field.name.is_empty() {
                one_line(&field.label)
            } else {
                field.name.clone()
            };
            return Err(invalid(&name, reason));
        }
    }

    let stops = stops(form);
    // ↑ first: a draft in the composer holds the keyboard until ↑/↓, and on
    // the first stop ↑ goes nowhere.
    let mut actions = vec![Action::Keys(vec!["up"])];
    let mut keys: Vec<&'static str> = Vec::new();
    let flush = |keys: &mut Vec<&'static str>, actions: &mut Vec<Action>| {
        if !keys.is_empty() {
            actions.push(Action::Keys(std::mem::take(keys)));
        }
    };
    let mut start = 0;
    while let Some(field) = stops[start].field() {
        let end = start
            + stops[start..]
                .iter()
                .take_while(|stop| stop.field() == Some(field))
                .count();
        let own = &stops[start..end];
        let target = &targets[field];
        let unchanged = *target == initial(form, field);
        match (&form.fields[field].kind, target) {
            _ if unchanged => keys.push("tab"),
            (FieldKind::Text(input), Target::Text(text)) => {
                keys.extend(clear_keys(&input.value, input.multiline));
                if !text.is_empty() {
                    flush(&mut keys, &mut actions);
                    actions.push(Action::Text(text.clone()));
                }
                keys.push("tab");
            }
            (FieldKind::Choice(choice), Target::Choice { checked, .. }) if choice.is_dropdown() => {
                let from = choice.initial_checked().first().copied();
                let to = checked.first().copied().unwrap_or_default();
                keys.extend(dropdown_keys(choice, from, to));
                keys.push("tab");
            }
            (FieldKind::Choice(choice), Target::Choice { checked, other }) if !choice.multi => {
                let at = match other {
                    Some(_) => own.len() - 1,
                    None => own
                        .iter()
                        .position(|stop| matches!(stop, Stop::Option { option, .. } if checked.contains(option)))
                        .unwrap_or_default(),
                };
                keys.extend(std::iter::repeat_n("down", at));
                if let Some(other) = other {
                    flush(&mut keys, &mut actions);
                    actions.push(Action::Text(other.clone()));
                }
                // Enter picks the option (or keeps the typed Other) and moves on.
                keys.push("enter");
            }
            (FieldKind::Choice(choice), Target::Choice { checked, other }) => {
                let was = choice.initial_checked();
                let mut at = 0;
                for (position, stop) in own.iter().enumerate() {
                    let Stop::Option { option, .. } = stop else {
                        continue;
                    };
                    if was.contains(option) != checked.contains(option) {
                        keys.extend(std::iter::repeat_n("down", position - at));
                        keys.push("space");
                        at = position;
                    }
                }
                if let Some(other) = other {
                    keys.extend(std::iter::repeat_n("down", own.len() - 1 - at));
                    flush(&mut keys, &mut actions);
                    actions.push(Action::Text(other.clone()));
                }
                keys.push("tab");
            }
            _ => keys.push("tab"),
        }
        start = end;
    }
    keys.push("enter");
    flush(&mut keys, &mut actions);
    Ok(Plan {
        actions,
        expected: form.answers(&data),
    })
}

/// The first `LABEL_PREFIX_CHARS` characters of a label's first line, as
/// the terminal draws it.
fn label_prefix(label: &str) -> String {
    one_line(label.split('\n').next().unwrap_or_default())
        .chars()
        .take(LABEL_PREFIX_CHARS)
        .collect()
}

/// A screen row with omp's form layout: the cursor slot, then (for option
/// rows) a marker, then text.
struct Row<'a> {
    focused: bool,
    /// `Some(selected)` for an option row.
    marker: Option<bool>,
    text: &'a str,
}

fn parse_row(line: &str) -> Row<'_> {
    let line = line.trim_start_matches(LEFT_EDGE);
    let (focused, rest) = match line.chars().next() {
        Some(glyph) if CURSOR_GLYPHS.contains(&glyph) => {
            let rest = &line[glyph.len_utf8()..];
            // An ascii `>` cursor only counts when a space follows it.
            if rest.starts_with(' ') {
                (true, rest.trim_start_matches(' '))
            } else {
                (false, line)
            }
        }
        _ => (false, line),
    };
    for (selected, unselected) in RADIO_MARKERS.into_iter().chain(CHECKBOX_MARKERS) {
        for (marker, is_selected) in [(selected, true), (unselected, false)] {
            if let Some(text) = rest
                .strip_prefix(marker)
                .and_then(|text| text.strip_prefix(' '))
            {
                return Row {
                    focused,
                    marker: Some(is_selected),
                    text,
                };
            }
        }
    }
    Row {
        focused,
        marker: None,
        text: rest,
    }
}

/// An option row the starting form draws: its label (or the Other row) and
/// whether its marker is filled.
struct ExpectedRow {
    text: String,
    selected: bool,
}

/// Whether `screen` shows the form as it opens: focus on its first stop and
/// every visible option row (Other included) in its default state. Anything
/// else means someone is answering in the terminal, the form is collapsed, or
/// it is not on screen; nothing may be sent then.
pub(crate) fn at_start(screen: &str, form: &ParsedForm) -> bool {
    let stops = stops(form);
    let rows: Vec<Row<'_>> = screen.lines().map(parse_row).collect();
    let first_ok = match stops[0] {
        Stop::Option { field, option } => {
            let choice = form.fields[field]
                .choice()
                .expect("option stops are choices");
            let selected = choice.initial_checked().contains(&option);
            let prefix = label_prefix(&choice.options[option].label);
            rows.iter().any(|row| {
                row.focused && row.marker == Some(selected) && row.text.starts_with(&prefix)
            })
        }
        Stop::Text { field } | Stop::Select { field } => {
            let prefix = label_prefix(&form.fields[field].label);
            rows.iter()
                .any(|row| row.focused && row.marker.is_none() && row.text.starts_with(&prefix))
        }
        // A form with no stops but Submit: nothing to verify but the button.
        Stop::Other { .. } | Stop::Submit => rows
            .iter()
            .any(|row| row.focused && row.text.starts_with("Submit")),
    };
    if !first_ok {
        return false;
    }
    let mut expected: Vec<ExpectedRow> = Vec::new();
    for field in &form.fields {
        let Some(choice) = field.choice() else {
            continue;
        };
        if choice.is_dropdown() {
            continue;
        }
        let checked = choice.initial_checked();
        for (index, option) in choice.options.iter().enumerate() {
            expected.push(ExpectedRow {
                text: label_prefix(&option.label),
                selected: checked.contains(&index),
            });
        }
        if choice.other {
            expected.push(ExpectedRow {
                text: format!("{OTHER_LABEL}: {OTHER_PLACEHOLDER}"),
                selected: false,
            });
        }
    }
    // Walk the visible option rows in order against the expected ones; a row
    // that matches a label must show that option's default marker, and an
    // Other row must still be empty.
    let mut next = 0;
    for row in &rows {
        let Some(selected) = row.marker else {
            continue;
        };
        if row.text.starts_with(&format!("{OTHER_LABEL}: "))
            && (selected
                || !row
                    .text
                    .starts_with(&format!("{OTHER_LABEL}: {OTHER_PLACEHOLDER}")))
        {
            return false;
        }
        if let Some(offset) = expected[next..]
            .iter()
            .position(|candidate| row.text.starts_with(&candidate.text))
        {
            if expected[next + offset].selected != selected {
                return false;
            }
            next += offset + 1;
        }
    }
    // No other option row (or Submit) holds the focus; the chat above the
    // form may hold unrelated `❯` lines, so only form rows count.
    rows.iter()
        .filter(|row| row.focused && (row.marker.is_some() || row.text.starts_with("Submit")))
        .count()
        <= 1
}

/// The agent's pane as the form driver sees it.
pub(crate) trait FormPane {
    fn read_screen(&mut self) -> Result<String, ErrorBody>;
    fn send(&mut self, action: &Action) -> Result<(), ErrorBody>;
    fn pause(&mut self);
}

/// Screen reads [`drive`] makes while the form may still be drawing.
const START_READS: usize = 3;

/// Check the form is in its starting state, then send `plan`. Nothing is
/// sent unless the screen shows the untouched form.
pub(crate) fn drive(
    pane: &mut impl FormPane,
    form: &ParsedForm,
    plan: &Plan,
) -> Result<(), ErrorBody> {
    let mut ready = false;
    for attempt in 0..START_READS {
        if attempt > 0 {
            pane.pause();
        }
        if at_start(&pane.read_screen()?, form) {
            ready = true;
            break;
        }
    }
    if !ready {
        return Err(ErrorBody {
            code: "ask_form_moved".into(),
            message: "the form on the agent's screen is not in its starting state (being answered in the terminal, hidden, or scrolled away)".into(),
        });
    }
    for (index, action) in plan.actions.iter().enumerate() {
        if index > 0 {
            pane.pause();
        }
        pane.send(action)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
