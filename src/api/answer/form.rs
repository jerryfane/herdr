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

use super::selector::{trim_right_edge, CURSOR_GLYPHS, LEFT_EDGE};

/// What omp shows in an empty Other row.
const OTHER_PLACEHOLDER: &str = "type your own";
/// Radio markers of omp's unicode, nerd-font and ascii presets: (selected, unselected).
const RADIO_MARKERS: [(&str, &str); 3] = [("◉", "○"), ("\u{f192}", "\u{f10c}"), ("(o)", "( )")];
/// Checkbox markers of the same presets: (checked, unchecked).
const CHECKBOX_MARKERS: [(&str, &str); 3] = [("☑", "☐"), ("\u{f14a}", "\u{f096}"), ("[x]", "[ ]")];

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

/// Keys that set a dropdown to option `to` whatever it shows now: ← once
/// per enabled option reaches the first one (`#step` clamps at the ends),
/// then → steps over enabled options to the target.
fn dropdown_keys(choice: &Choice, to: usize) -> Vec<&'static str> {
    let enabled: Vec<usize> = (0..choice.options.len())
        .filter(|index| !choice.options[*index].disabled)
        .collect();
    let target = enabled.iter().position(|index| *index == to).unwrap_or(0);
    let mut keys = vec!["left"; enabled.len().saturating_sub(1)];
    keys.extend(std::iter::repeat_n("right", target));
    keys
}

/// Lines a textarea is cleared through at least; a draft longer than this
/// (only a paste makes one) keeps its tail, which the result check reports.
const TEXTAREA_CLEAR_LINES: usize = 200;

/// Keys that empty a text field wherever its caret is and whatever it
/// holds. A single-line input: Ctrl+E to the end, Ctrl+U deletes to the
/// start. A textarea: the same on the caret's line, then Ctrl+U pairs merge
/// and empty each line above (a Ctrl+U at a line start joins it to the
/// previous one) and Ctrl+K pairs each line below (a Ctrl+K at a line end
/// joins the next); presses past the first or last line do nothing.
fn clear_keys(value: &str, multiline: bool) -> Vec<&'static str> {
    let mut keys = vec!["ctrl+e", "ctrl+u"];
    if multiline {
        let lines = value.split('\n').count().max(TEXTAREA_CLEAR_LINES);
        keys.extend(std::iter::repeat_n("ctrl+u", 2 * (lines - 1)));
        keys.extend(std::iter::repeat_n("ctrl+k", 2 * (lines - 1)));
    }
    keys
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
        // Text fields and dropdowns are set outright, so whatever they show
        // now (the screen check does not read them) cannot leak through.
        let unchanged = *target == initial(form, field);
        match (&form.fields[field].kind, target) {
            (FieldKind::Text(input), Target::Text(text)) => {
                keys.extend(clear_keys(&input.value, input.multiline));
                if !text.is_empty() {
                    flush(&mut keys, &mut actions);
                    actions.push(Action::Text(text.clone()));
                }
                keys.push("tab");
            }
            (FieldKind::Choice(choice), Target::Choice { checked, .. }) if choice.is_dropdown() => {
                let to = checked.first().copied().unwrap_or_default();
                keys.extend(dropdown_keys(choice, to));
                keys.push("tab");
            }
            _ if unchanged => keys.push("tab"),
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

/// A label's first line as omp draws it, whitespace collapsed.
fn first_line(label: &str) -> String {
    one_line(label.split('\n').next().unwrap_or_default())
}

/// A screen row with omp's form layout: the cursor slot, then (for option
/// rows) a marker, then text, whitespace collapsed and the panel edge cut.
struct Row {
    focused: bool,
    /// `Some(selected)` for an option row.
    marker: Option<bool>,
    text: String,
}

fn parse_row(line: &str) -> Row {
    let line = trim_right_edge(line.trim_start_matches(LEFT_EDGE));
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
                    text: one_line(text),
                };
            }
        }
    }
    Row {
        focused,
        marker: None,
        text: one_line(rest),
    }
}

/// An option row the untouched form draws, in screen order.
struct ExpectedRow {
    /// The label's first line; for the synthetic Other row, its empty text.
    text: String,
    /// The synthetic Other row: only its exact empty text matches.
    other: bool,
    selected: bool,
}

impl ExpectedRow {
    /// Whether a drawn option row is this one: the same marker and the whole
    /// first line, or (a wrapped label) a prefix of it that ends at a word.
    fn matches(&self, row: &Row) -> bool {
        if row.marker != Some(self.selected) || row.text.is_empty() {
            return false;
        }
        if self.other {
            return row.text == self.text;
        }
        row.text == self.text
            || (self.text.starts_with(&row.text) && self.text[row.text.len()..].starts_with(' '))
    }
}

/// The option rows of the untouched form, and the index among them of each
/// option and Other stop.
fn expected_rows(form: &ParsedForm) -> (Vec<ExpectedRow>, Vec<(Stop, usize)>) {
    let mut rows = Vec::new();
    let mut stops = Vec::new();
    for (field, entry) in form.fields.iter().enumerate() {
        let Some(choice) = entry.choice() else {
            continue;
        };
        if choice.is_dropdown() {
            continue;
        }
        let checked = choice.initial_checked();
        for (option, entry) in choice.options.iter().enumerate() {
            stops.push((Stop::Option { field, option }, rows.len()));
            rows.push(ExpectedRow {
                text: first_line(&entry.label),
                other: false,
                selected: checked.contains(&option),
            });
        }
        if choice.other {
            stops.push((Stop::Other { field }, rows.len()));
            rows.push(ExpectedRow {
                text: format!("{OTHER_LABEL}: {OTHER_PLACEHOLDER}"),
                other: true,
                selected: false,
            });
        }
    }
    (rows, stops)
}

/// Whether a focused non-option row is the label row of `field`: its first
/// line, then at most the required star and a text field's bounds.
fn is_label_row(row: &Row, label: &str) -> bool {
    let label = first_line(label);
    if label.is_empty() || !row.text.starts_with(&label) {
        return false;
    }
    let rest = row.text[label.len()..].trim_start_matches(" *").trim();
    rest.is_empty()
        || rest.starts_with('≥')
        || rest.starts_with('≤')
        || rest
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit() || ch == '-')
}

/// Whether `screen` shows the form as it opens, as far as the drive depends
/// on it: the focus on its first stop, and every option row (Other included)
/// in its default state. The visible option rows must line up, in order and
/// in exactly one way, with the rows the untouched form draws; the focused
/// one must be the first stop. Text fields and dropdowns are not checked:
/// the drive sets them whatever they hold.
pub(crate) fn at_start(screen: &str, form: &ParsedForm) -> bool {
    let stops = stops(form);
    let rows: Vec<Row> = screen.lines().map(parse_row).collect();
    let markers: Vec<usize> = (0..rows.len())
        .filter(|index| rows[*index].marker.is_some())
        .collect();
    let focused_markers: Vec<usize> = markers
        .iter()
        .copied()
        .filter(|index| rows[*index].focused)
        .collect();
    let (expected, stop_rows) = expected_rows(form);
    // Every place the visible option rows, all of them in order, line up
    // with the expected ones (a scrolled form shows a window of them).
    let alignments: Vec<usize> = (0..expected.len())
        .filter(|&start| {
            markers.len() <= expected.len() - start
                && markers
                    .iter()
                    .zip(&expected[start..])
                    .all(|(&row, want)| want.matches(&rows[row]))
        })
        .collect();
    let first_stop_row = |stop: Stop| {
        stop_rows
            .iter()
            .find(|(candidate, _)| *candidate == stop)
            .map(|(_, row)| *row)
    };
    match stops[0] {
        stop @ (Stop::Option { .. } | Stop::Other { .. }) => {
            let Some(want) = first_stop_row(stop) else {
                return false;
            };
            let [focused] = focused_markers.as_slice() else {
                return false;
            };
            // Exactly one reading of the screen, and in it the focused row is
            // the first stop; ambiguous or wrong sends nothing.
            matches!(alignments.as_slice(),
                [start] if want >= *start && markers.get(want - start) == Some(focused))
        }
        Stop::Text { field } | Stop::Select { field } => {
            focused_markers.is_empty()
                && rows
                    .iter()
                    .filter(|row| row.focused && row.marker.is_none())
                    .any(|row| is_label_row(row, &form.fields[field].label))
                && (markers.is_empty() || alignments.len() == 1)
        }
        Stop::Submit => {
            focused_markers.is_empty()
                && rows
                    .iter()
                    .any(|row| row.focused && row.text.starts_with("Submit"))
        }
    }
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
