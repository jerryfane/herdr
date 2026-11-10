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
//! [`plan`] validates the requested values and settles every field's
//! target. [`drive`] checks the form is untouched ([`at_start`]), then sets
//! every field outright from whatever it shows (radios with Space, each
//! checkbox to its target, inputs cleared and retyped, dropdowns stepped from
//! the position they show), reading the focused stop back after each step,
//! and presses Submit only once every field showed what was sent.

use std::collections::BTreeMap;

use crate::agent_transcript::ask_form::{
    choice_value, field_error, one_line, text_value, Choice, FieldKind, FormValue, ParsedForm,
    OTHER_LABEL,
};
use crate::api::schema::{AskFormValue, ErrorBody};

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

fn has_control_chars(text: &str) -> bool {
    text.chars().any(char::is_control)
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
        Some(text) if has_control_chars(text) => {
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
            FieldKind::Text(_) => {
                if value.options.is_some() || value.other.is_some() {
                    return Err(invalid(&field.name, "a text field takes text"));
                }
                match &value.text {
                    None => initial(form, index),
                    Some(text) if has_control_chars(text) => {
                        return Err(invalid(
                            &field.name,
                            "this field takes a single line of plain text",
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

/// What `agent.answer_form` will make the form hold: each field's target
/// state, and the name-keyed data omp should then submit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Plan {
    targets: Vec<Target>,
    /// One entry per named field: the value omp should submit (hidden
    /// inputs filling in for fields that give none).
    pub expected: Vec<(String, Option<FormValue>)>,
}

/// Validate `values` against the form as omp would on Submit (all but
/// `pattern`, which omp checks itself) and settle every field's target.
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
    Ok(Plan {
        expected: form.submission(&data),
        targets,
    })
}

/// Whether the data omp recorded (`User answers:` JSON) is the one `plan`
/// asked for, compared by value: numbers numerically, text and option
/// values trimmed, lists in order. Formatting differences between herdr and
/// omp (number spelling, whitespace) never turn a real answer into a miss.
pub(crate) fn submission_matches(
    expected: &[(String, Option<FormValue>)],
    recorded: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    use serde_json::Value;
    let text = |value: &Value| -> Option<String> {
        match value {
            Value::String(text) => Some(text.trim().to_owned()),
            Value::Number(number) => number
                .as_f64()
                .map(crate::agent_transcript::ask_form::js_number_string),
            _ => None,
        }
    };
    expected
        .iter()
        .all(|(name, want)| match (want, recorded.get(name)) {
            (None, None) => true,
            (Some(FormValue::Number(want)), Some(got)) => {
                let got = match got {
                    Value::Number(number) => number.as_f64(),
                    Value::String(text) => text.trim().parse::<f64>().ok(),
                    _ => None,
                };
                // Exact: both sides parse the same decimal text (the one
                // herdr typed): omp's `Number(text)` and its JSON round trip
                // are correctly rounded, and so are Rust's parse and
                // serde_json with `float_roundtrip`, so they are the same f64.
                got == Some(*want)
            }
            (Some(FormValue::Text(want)), Some(got)) => {
                text(got).is_some_and(|got| got == want.trim())
            }
            (Some(FormValue::List(want)), Some(Value::Array(got))) => {
                got.len() == want.len()
                    && got
                        .iter()
                        .zip(want)
                        .all(|(got, want)| text(got).is_some_and(|got| got == want.trim()))
            }
            _ => false,
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

fn rows_of(screen: &str) -> Vec<Row> {
    screen.lines().map(parse_row).collect()
}

/// Whether an option row's text is `label` as omp draws it: the whole first
/// line, or (a wrapped label) a prefix of it ending at a word.
fn reads_as_label(text: &str, label: &str) -> bool {
    let label = first_line(label);
    !text.is_empty()
        && (text == label || (label.starts_with(text) && label[text.len()..].starts_with(' ')))
}

/// The synthetic Other row's text (after `Other: `), `None` when the row is
/// not an Other row. An empty Other shows its placeholder.
fn other_text(text: &str) -> Option<&str> {
    let rest = text
        .strip_prefix(OTHER_LABEL)?
        .strip_prefix(':')?
        .trim_start();
    Some(if rest == OTHER_PLACEHOLDER { "" } else { rest })
}

/// An option row the untouched form draws, in screen order.
struct ExpectedRow {
    /// The option's label; empty for the synthetic Other row.
    label: String,
    other: bool,
    selected: bool,
}

impl ExpectedRow {
    fn matches(&self, row: &Row) -> bool {
        if row.marker != Some(self.selected) {
            return false;
        }
        if self.other {
            return other_text(&row.text) == Some("");
        }
        reads_as_label(&row.text, &self.label)
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
                label: entry.label.clone(),
                other: false,
                selected: checked.contains(&option),
            });
        }
        if choice.other {
            stops.push((Stop::Other { field }, rows.len()));
            rows.push(ExpectedRow {
                label: String::new(),
                other: true,
                selected: false,
            });
        }
    }
    (rows, stops)
}

/// How many rows from `start` the label `label` takes: omp wraps it at the
/// panel width (at a space, or inside a long word), and the last row may add
/// the required star and a number field's bounds. An empty label is one row
/// holding just the cursor. `None` when the rows do not read as the label.
fn label_rows(rows: &[Row], start: usize, label: &str) -> Option<usize> {
    let label = one_line(label);
    let first = rows.get(start)?;
    if first.marker.is_some() {
        return None;
    }
    if label.is_empty() {
        return is_label_suffix(&first.text).then_some(1);
    }
    let mut rest = label.as_str();
    for (offset, row) in rows[start..].iter().enumerate() {
        if offset > 0 && (row.focused || row.marker.is_some()) {
            return None;
        }
        let text = row.text.as_str();
        if text.is_empty() {
            return None;
        }
        if let Some(after) = rest.strip_prefix(text) {
            rest = after.trim_start();
            if rest.is_empty() {
                return Some(offset + 1);
            }
        } else if let Some(suffix) = text.strip_prefix(rest) {
            return is_label_suffix(suffix).then_some(offset + 1);
        } else {
            return None;
        }
    }
    None
}

/// What may follow a field label on its last row: the required star and a
/// number field's bounds (`1–9`, `≥ 1`, `≤ 9`).
fn is_label_suffix(suffix: &str) -> bool {
    let rest = suffix.trim_start();
    let rest = rest.strip_prefix('*').unwrap_or(rest).trim_start();
    rest.is_empty()
        || rest.starts_with('≥')
        || rest.starts_with('≤')
        || rest
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit() || ch == '-')
}

/// The focused text or dropdown field: where its label starts and how many
/// rows it takes, when exactly one focused row starts it.
fn focused_label(rows: &[Row], label: &str) -> Option<(usize, usize)> {
    let mut found = (0..rows.len())
        .filter(|&index| rows[index].focused)
        .filter_map(|index| label_rows(rows, index, label).map(|count| (index, count)));
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

/// Whether `screen` shows the form as it opens: the focus on its first stop,
/// and every visible option row (Other included) in its default state, read
/// in exactly one way against the rows the untouched form draws. Only the
/// starting focus matters to the drive (it sets every field outright and
/// checks each one as it goes); the rest refuses a form someone is filling
/// in the terminal.
pub(crate) fn at_start(screen: &str, form: &ParsedForm) -> bool {
    let stops = stops(form);
    let rows = rows_of(screen);
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
    // with the expected ones (a paged form shows a window of them).
    let alignments: Vec<usize> = (0..expected.len())
        .filter(|&start| {
            markers.len() <= expected.len() - start
                && markers
                    .iter()
                    .zip(&expected[start..])
                    .all(|(&row, want)| want.matches(&rows[row]))
        })
        .collect();
    match stops[0] {
        stop @ (Stop::Option { .. } | Stop::Other { .. }) => {
            let Some(want) = stop_rows
                .iter()
                .find(|(candidate, _)| *candidate == stop)
                .map(|(_, row)| *row)
            else {
                return false;
            };
            let [focused] = focused_markers.as_slice() else {
                return false;
            };
            matches!(alignments.as_slice(),
                [start] if want >= *start && markers.get(want - start) == Some(focused))
        }
        Stop::Text { field } | Stop::Select { field } => {
            focused_markers.is_empty()
                && focused_label(&rows, &form.fields[field].label).is_some()
                && (markers.is_empty() || alignments.len() == 1)
        }
        Stop::Submit => {
            focused_markers.is_empty()
                && rows
                    .iter()
                    .any(|row| row.focused && row.text.starts_with(SUBMIT_LABEL))
        }
    }
}

const SUBMIT_LABEL: &str = "Submit";

/// What the focused stop shows, read off the screen.
#[derive(Debug, Clone, PartialEq)]
enum Seen {
    Option {
        selected: bool,
    },
    Other {
        selected: bool,
        text: String,
    },
    /// A (single-line) text field's value row.
    Text(String),
    /// A dropdown's 1-based position among all its options.
    Select {
        position: Option<usize>,
    },
    Submit,
}

/// The focused stop as `stop`, if the screen shows that stop focused.
fn seen(screen: &str, form: &ParsedForm, stop: Stop) -> Option<Seen> {
    let rows = rows_of(screen);
    let focused_markers: Vec<&Row> = rows
        .iter()
        .filter(|row| row.focused && row.marker.is_some())
        .collect();
    match stop {
        Stop::Option { field, option } => {
            let choice = form.fields[field].choice()?;
            let [row] = focused_markers.as_slice() else {
                return None;
            };
            reads_as_label(&row.text, &choice.options[option].label).then(|| Seen::Option {
                selected: row.marker == Some(true),
            })
        }
        Stop::Other { .. } => {
            let [row] = focused_markers.as_slice() else {
                return None;
            };
            other_text(&row.text).map(|text| Seen::Other {
                selected: row.marker == Some(true),
                text: text.to_owned(),
            })
        }
        Stop::Text { field } => {
            if !matches!(&form.fields[field].kind, FieldKind::Text(_))
                || !focused_markers.is_empty()
            {
                return None;
            }
            let (start, count) = focused_label(&rows, &form.fields[field].label)?;
            Some(Seen::Text(rows.get(start + count)?.text.clone()))
        }
        Stop::Select { field } => {
            if !focused_markers.is_empty() {
                return None;
            }
            let label = &form.fields[field].label;
            let row = if one_line(label).is_empty() {
                // An unlabeled dropdown is one row: cursor, then the value.
                let mut found = rows
                    .iter()
                    .filter(|row| row.focused && row.text.starts_with('‹'));
                let row = found.next()?;
                found.next().is_none().then_some(row)?
            } else {
                let (start, count) = focused_label(&rows, label)?;
                rows.get(start + count)?
            };
            Some(Seen::Select {
                position: dropdown_position(&row.text)?,
            })
        }
        Stop::Submit => (focused_markers.is_empty()
            && rows
                .iter()
                .any(|row| row.focused && row.text.starts_with(SUBMIT_LABEL)))
        .then_some(Seen::Submit),
    }
}

/// `‹ value ›  i/n`: the position `i`, `Some(None)` for `—` (nothing
/// chosen), `None` when the row is not a dropdown row.
fn dropdown_position(text: &str) -> Option<Option<usize>> {
    let rest = text.strip_prefix('‹')?;
    let (_, after) = rest.rsplit_once('›')?;
    let token = after.split_whitespace().next();
    match token.and_then(|token| token.split_once('/')) {
        Some((at, _)) => Some(Some(at.parse().ok()?)),
        None => Some(None),
    }
}

/// Whether a text field's value row shows it empty: blank, or its
/// placeholder.
fn is_empty_text(row: &str, placeholder: &str) -> bool {
    let placeholder = one_line(placeholder);
    row.is_empty() || (!placeholder.is_empty() && placeholder.starts_with(row))
}

/// The agent's pane as the form driver sees it.
pub(crate) trait FormPane {
    fn read_screen(&mut self) -> Result<String, ErrorBody>;
    fn send(&mut self, action: &Action) -> Result<(), ErrorBody>;
    fn pause(&mut self);
}

/// Screen reads (one pause apart) the form gets to show a step.
const SETTLE_READS: usize = 20;
/// Hard caps per field, whatever the screen shows.
const MAX_FIELD_KEYS: usize = 6_000;
const MAX_FIELD_READS: usize = 800;

fn moved(message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        code: "ask_form_moved".into(),
        message: message.into(),
    }
}

struct Driver<'a, P> {
    pane: &'a mut P,
    form: &'a ParsedForm,
    stops: Vec<Stop>,
    /// The stop the focus is on.
    at: usize,
    /// Keys sent and screens read for the current field.
    keys_sent: usize,
    reads: usize,
}

impl<P: FormPane> Driver<'_, P> {
    fn field_name(&self, stop: Stop) -> String {
        match stop.field() {
            Some(field) => format!("field {:?}", self.form.fields[field].name),
            None => "Submit".to_owned(),
        }
    }

    fn keys(&mut self, keys: Vec<&'static str>) -> Result<(), ErrorBody> {
        if keys.is_empty() {
            return Ok(());
        }
        self.keys_sent += keys.len();
        if self.keys_sent > MAX_FIELD_KEYS {
            return Err(moved(
                "a field took more keys than herdr sends to one field; stopped without submitting (answer in the terminal)",
            ));
        }
        self.pane.send(&Action::Keys(keys))
    }

    fn read(&mut self) -> Result<String, ErrorBody> {
        self.reads += 1;
        if self.reads > MAX_FIELD_READS {
            return Err(moved(
                "a field took more screen reads than herdr makes for one field; stopped without submitting (answer in the terminal)",
            ));
        }
        self.pane.read_screen()
    }

    /// Move the focus to stop `to` with ↑/↓ (one stop each).
    fn go(&mut self, to: usize) -> Result<(), ErrorBody> {
        let key = if to > self.at { "down" } else { "up" };
        self.keys(vec![key; to.abs_diff(self.at)])?;
        self.at = to;
        Ok(())
    }

    /// Read until the focused stop is `stop` and `done` holds; stop the
    /// drive otherwise (the settled screen shows `stop` not done, another
    /// stop, or no form). Read failures propagate at once. Nothing more is
    /// sent after a miss: the form keeps whatever was typed so far, and Esc
    /// would cancel the whole ask.
    fn until(&mut self, stop: Stop, done: impl Fn(&Seen) -> bool) -> Result<Seen, ErrorBody> {
        for read in 0..SETTLE_READS {
            if read > 0 {
                self.pane.pause();
            }
            if let Some(seen) = seen(&self.read()?, self.form, stop) {
                if done(&seen) {
                    return Ok(seen);
                }
            }
        }
        Err(self.displaced(stop))
    }

    fn displaced(&self, stop: Stop) -> ErrorBody {
        moved(format!(
            "the terminal form did not show {} as expected; stopped without submitting (answer in the terminal)",
            self.field_name(stop)
        ))
    }

    /// Empty a single-line input (a text field, or an Other row): Ctrl+E to
    /// the end, Ctrl+U deletes everything before it, so nothing can remain
    /// out of view.
    fn clear_line(&mut self, stop: Stop, placeholder: &str) -> Result<(), ErrorBody> {
        self.keys(vec!["ctrl+e", "ctrl+u"])?;
        self.until(stop, |seen| match seen {
            Seen::Text(row) => is_empty_text(row, placeholder),
            Seen::Other { text, .. } => text.is_empty(),
            _ => false,
        })
        .map(drop)
    }

    fn type_text(&mut self, text: &str) -> Result<(), ErrorBody> {
        if text.is_empty() {
            return Ok(());
        }
        self.pane.send(&Action::Text(text.to_owned()))
    }

    fn field(
        &mut self,
        field: usize,
        own: std::ops::Range<usize>,
        target: &Target,
    ) -> Result<(), ErrorBody> {
        let form = self.form;
        match (&form.fields[field].kind, target) {
            // Textareas never get here: `ParsedForm::refusal` refuses them.
            (FieldKind::Text(input), Target::Text(text)) => {
                let stop = Stop::Text { field };
                self.until(stop, |_| true)?;
                self.clear_line(stop, &input.placeholder)?;
                self.type_text(text)
            }
            (FieldKind::Choice(choice), Target::Choice { checked, .. }) if choice.is_dropdown() => {
                let stop = Stop::Select { field };
                let Seen::Select { position } = self.until(stop, |_| true)? else {
                    unreachable!("a dropdown stop reads as a dropdown");
                };
                let target = checked.first().copied().unwrap_or_default();
                let current = position.map(|position| position - 1);
                self.keys(dropdown_keys(choice, current, target))?;
                self.until(stop, |seen| {
                    *seen
                        == Seen::Select {
                            position: Some(target + 1),
                        }
                })
                .map(drop)
            }
            (FieldKind::Choice(choice), Target::Choice { checked, other }) => {
                let stops = self.stops.clone();
                let option_stop = |option: usize| {
                    own.clone()
                        .find(|&index| stops[index] == Stop::Option { field, option })
                };
                if choice.other {
                    // Empty Other first: a radio's Other text would otherwise
                    // stand in for the picked option.
                    self.go(own.end - 1)?;
                    let stop = Stop::Other { field };
                    self.until(stop, |_| true)?;
                    self.clear_line(stop, "")?;
                    if let Some(text) = other {
                        self.type_text(text)?;
                        self.until(stop, |seen| matches!(seen, Seen::Other { selected: true, text: shown } if !shown.is_empty()))?;
                    }
                }
                if choice.multi {
                    // Every enabled option, set to its target whatever it shows.
                    for (option, entry) in choice.options.iter().enumerate() {
                        let Some(index) = option_stop(option).filter(|_| !entry.disabled) else {
                            continue;
                        };
                        self.go(index)?;
                        let stop = Stop::Option { field, option };
                        let want = checked.contains(&option);
                        if let Seen::Option { selected } = self.until(stop, |_| true)? {
                            if selected != want {
                                self.keys(vec!["space"])?;
                            }
                        }
                        self.until(stop, |seen| *seen == Seen::Option { selected: want })?;
                    }
                    return Ok(());
                }
                if other.is_some() {
                    return Ok(());
                }
                match checked
                    .first()
                    .copied()
                    .and_then(|option| option_stop(option).map(|index| (option, index)))
                {
                    // Space picks the option and stays on it.
                    Some((option, index)) => {
                        self.go(index)?;
                        let stop = Stop::Option { field, option };
                        self.until(stop, |_| true)?;
                        self.keys(vec!["space"])?;
                        self.until(stop, |seen| *seen == Seen::Option { selected: true })
                            .map(drop)
                    }
                    // Nothing to pick (no default, no answer): nothing may be
                    // picked either.
                    None => {
                        for option in 0..choice.options.len() {
                            let Some(index) = option_stop(option) else {
                                continue;
                            };
                            self.go(index)?;
                            self.until(Stop::Option { field, option }, |seen| {
                                *seen == Seen::Option { selected: false }
                            })?;
                        }
                        Ok(())
                    }
                }
            }
            _ => Ok(()),
        }
    }
}

/// ←/→ presses from `current` to `target` on a dropdown: `#step` moves to
/// the next enabled option in that direction each press.
fn dropdown_keys(choice: &Choice, current: Option<usize>, target: usize) -> Vec<&'static str> {
    let enabled = |range: std::ops::Range<usize>| {
        range
            .filter(|index| !choice.options[*index].disabled)
            .count()
    };
    match current {
        Some(current) if current == target => Vec::new(),
        Some(current) if current < target => vec!["right"; enabled(current + 1..target + 1)],
        Some(current) => vec!["left"; enabled(target..current)],
        // `#step` from -1: the first press lands on the first enabled option.
        None => vec!["right"; enabled(0..target + 1)],
    }
}

/// Check the form shows its starting state, then set every field to its
/// target, checking each on screen as it goes, and press Submit once the
/// focus is on it. A field that does not show what was sent stops the drive
/// before Submit.
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
        return Err(moved(
            "the form on the agent's screen is not in its starting state (being answered in the terminal, hidden, or scrolled away)",
        ));
    }
    let mut driver = Driver {
        pane,
        form,
        stops: stops(form),
        at: 0,
        keys_sent: 0,
        reads: 0,
    };
    // ↑ first: a draft in the composer holds the keyboard until ↑/↓, and on
    // the first stop ↑ goes nowhere.
    driver.keys(vec!["up"])?;
    while let Some(field) = driver.stops[driver.at].field() {
        let start = driver
            .stops
            .iter()
            .position(|stop| stop.field() == Some(field))
            .unwrap_or(driver.at);
        let end = start
            + driver.stops[start..]
                .iter()
                .take_while(|stop| stop.field() == Some(field))
                .count();
        driver.keys_sent = 0;
        driver.reads = 0;
        driver.field(field, start..end, &plan.targets[field])?;
        // Tab leaves the field from any of its stops for the next field's first.
        driver.keys(vec!["tab"])?;
        driver.at = end;
    }
    driver.keys_sent = 0;
    driver.reads = 0;
    driver.until(Stop::Submit, |_| true)?;
    driver.keys(vec!["enter"])
}

/// Screen reads [`drive`] makes while the form may still be drawing.
const START_READS: usize = 3;

/// An error omp shows under a field after a refused Submit, as
/// `(field name, message)`: the first text field whose rows are followed by
/// one of omp's validation messages (`pattern` and URL checks are omp's).
pub(crate) fn submit_error(screen: &str, form: &ParsedForm) -> Option<(String, String)> {
    const MESSAGES: [&str; 9] = [
        "Must match ",
        "Enter a full URL",
        "Enter an email address",
        "Enter a number",
        "Must be at least",
        "Must be at most",
        "Needs at least",
        "At most",
        "Required",
    ];
    let rows = rows_of(screen);
    for field in &form.fields {
        if !matches!(&field.kind, FieldKind::Text(_)) {
            continue;
        }
        for start in 0..rows.len() {
            let Some(count) = label_rows(&rows, start, &field.label) else {
                continue;
            };
            let Some(row) = rows.get(start + count + 1) else {
                continue;
            };
            if MESSAGES.iter().any(|message| row.text.starts_with(message)) {
                return Some((field.name.clone(), row.text.clone()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests;
