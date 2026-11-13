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
//! target. [`drive`] checks the form is untouched ([`start_state`]), then sets
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

use super::selector::{trim_right_edge, BOX_VERTICAL, CURSOR_GLYPHS, LEFT_EDGE};

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
    /// A textarea the values leave out: left exactly as it is (Tab passes
    /// it). Its prefill is what omp should submit; confirmation reports an
    /// edit made in the terminal.
    Keep,
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
        FieldKind::Text(input) if input.multiline => Target::Keep,
        FieldKind::Text(input) => Target::Text(input.value.clone()),
    }
}

/// Control characters, but for a textarea's line breaks (a tab would be
/// drawn as spaces, which the read-back could not tell apart).
fn has_control_chars(text: &str, multiline: bool) -> bool {
    text.chars()
        .any(|ch| ch.is_control() && !(multiline && ch == '\n'))
}

/// Longest textarea answer herdr types: omp's `Editor` turns a longer paste
/// into a `[Paste #N]` marker (`isMarkerSized`, editor.ts `#handlePaste`),
/// which the read-back could not check.
const TEXTAREA_MAX_CHARS: usize = 1000;

const TOO_LONG: &str = "too long to edit from the app; answer in the terminal";

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
                // A textarea answer's line breaks as omp's editor keeps them:
                // CRLF and lone CR become LF (`#handlePaste`, editor.ts).
                let text = value.text.as_ref().map(|text| {
                    if input.multiline {
                        text.replace("\r\n", "\n").replace('\r', "\n")
                    } else {
                        text.clone()
                    }
                });
                match &text {
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
                    // A character built from several code points cannot be
                    // confirmed on screen: herdr's terminal draws an emoji ZWJ
                    // sequence wider than omp lays it out, and reads a letter
                    // with a separate accent mark back precomposed.
                    Some(text)
                        if input.multiline
                            && unicode_segmentation::UnicodeSegmentation::graphemes(
                                text.as_str(),
                                true,
                            )
                            .any(|grapheme| grapheme.chars().nth(1).is_some()) =>
                    {
                        return Err(invalid(
                            &field.name,
                            "combined characters (emoji sequences, separate accent marks) cannot be checked on screen; answer in the terminal",
                        ));
                    }
                    Some(text) if input.multiline => {
                        if text.split('\n').count() > input.height()
                            || text.chars().count() > TEXTAREA_MAX_CHARS
                        {
                            return Err(invalid(&field.name, TOO_LONG));
                        }
                        // Clearing needs a stop before the textarea to prove
                        // the caret reached the first line (`clear_textarea`).
                        if stops(form).first() == Some(&Stop::Text { field: index }) {
                            return Err(invalid(
                                &field.name,
                                "the form's first field cannot be edited from the app; answer in the terminal",
                            ));
                        }
                        Target::Text(text.clone())
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
        (FieldKind::Text(input), Target::Keep) => Some(text_value(input, &input.value)),
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

/// omp's `boxRound.topLeft` and `boxRound.horizontal` in its symbol presets
/// (unicode and nerd `╭`/`─`, ascii `+`/`-`; pi-tui theme/symbols.ts:436/440,
/// :770/:778, :1238/:1242): the ask panel's top border opens with them, then
/// the title (`topBorder`, chrome/overlay-box.ts:22-33).
const BOX_TOP_LEFT: [char; 2] = ['╭', '+'];
const BOX_HORIZONTAL: [char; 2] = ['─', '-'];
/// The form panel's title (`DEFAULT_TITLE`, dialog.ts:124).
const ASK_TITLE: &str = "Ask";

/// The ask panel's top border: its line index, and the page it shows as
/// `(page, pages)` (1-based) when omp paged the form. The title is `Ask`,
/// `Ask (30s)` while a timeout counts down, then ` · 2/3` on a paged form
/// (`render` and `#titleText`, dialog.ts:598-605, :1247-1250).
fn panel_top(lines: &[&str]) -> Option<(usize, Option<(usize, usize)>)> {
    lines.iter().enumerate().rev().find_map(|(index, line)| {
        let title = line
            .trim_start()
            .strip_prefix(BOX_TOP_LEFT)?
            .strip_prefix(BOX_HORIZONTAL)?
            .strip_prefix(' ')?
            .strip_prefix(ASK_TITLE)?;
        let title = match title.strip_prefix(" (") {
            Some(countdown) => countdown.split_once("s)")?.1,
            None => title,
        };
        if title
            .strip_prefix(' ')
            .is_some_and(|rule| rule.starts_with(BOX_HORIZONTAL))
        {
            return Some((index, None));
        }
        let (page, rest) = title.strip_prefix(" · ")?.split_once('/')?;
        let pages: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let page = page.parse().ok()?;
        let pages = pages.parse().ok()?;
        Some((index, Some((page, pages))))
    })
}

/// Why a screen does not show the form as it opens ([`start_state`]); the
/// reason `ask_form_moved` gives and herdr logs. It names no field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotAtStart {
    /// No row is focused and no ask panel is on the screen: the form is
    /// hidden, scrolled away or closed.
    NoPanel,
    /// The panel shows page `page` of `pages` without a focused row: the
    /// focus is on another page.
    FocusOffPage { page: usize, pages: usize },
    /// No focused row.
    NoFocus,
    /// More than one row reads as focused.
    SeveralFocused,
    /// The focused row is not the form's first stop.
    FocusNotFirst,
    /// The option rows on screen do not read as the untouched form's.
    OptionsChanged,
    /// The option rows read as the untouched form's in more than one place.
    OptionsAmbiguous,
}

impl std::fmt::Display for NotAtStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPanel => f.write_str("no form panel on the screen"),
            Self::FocusOffPage { page, pages } => write!(
                f,
                "the panel shows page {page}/{pages} and the focus is on another page"
            ),
            Self::NoFocus => f.write_str("no focused row"),
            Self::SeveralFocused => f.write_str("more than one focused row"),
            Self::FocusNotFirst => f.write_str("the focus is not on the first field"),
            Self::OptionsChanged => f.write_str("option rows differ from the form's defaults"),
            Self::OptionsAmbiguous => {
                f.write_str("option rows match the form's defaults in more than one place")
            }
        }
    }
}

/// Whether `screen` shows the form as it opens: the focus on its first stop,
/// and every visible option row (Other included) in its default state, read
/// in exactly one way against the rows the untouched form draws. Only the
/// starting focus matters to the drive (it sets every field outright and
/// checks each one as it goes); the rest refuses a form someone is filling
/// in the terminal.
pub(crate) fn start_state(screen: &str, form: &ParsedForm) -> Result<(), NotAtStart> {
    let stops = stops(form);
    let rows = rows_of(screen);
    let lines: Vec<&str> = screen.lines().collect();
    let panel = panel_top(&lines);
    // No focused row inside the panel: omp shows a page the focus is not on
    // (it opened on context before the first stop, or someone paged).
    let panel_focused = panel.is_some_and(|(top, _)| rows[top..].iter().any(|row| row.focused));
    match panel {
        None if !rows.iter().any(|row| row.focused) => return Err(NotAtStart::NoPanel),
        Some((_, Some((page, pages)))) if !panel_focused => {
            return Err(NotAtStart::FocusOffPage { page, pages })
        }
        _ => {}
    }
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
    let aligned = || match alignments.as_slice() {
        _ if markers.is_empty() => Ok(()),
        [] => Err(NotAtStart::OptionsChanged),
        [_] => Ok(()),
        _ => Err(NotAtStart::OptionsAmbiguous),
    };
    match stops[0] {
        stop @ (Stop::Option { .. } | Stop::Other { .. }) => {
            let want = stop_rows
                .iter()
                .find(|(candidate, _)| *candidate == stop)
                .map(|(_, row)| *row)
                .ok_or(NotAtStart::OptionsChanged)?;
            let focused = match focused_markers.as_slice() {
                [focused] => *focused,
                [] if rows.iter().any(|row| row.focused) => return Err(NotAtStart::FocusNotFirst),
                [] => return Err(NotAtStart::NoFocus),
                _ => return Err(NotAtStart::SeveralFocused),
            };
            match alignments.as_slice() {
                [start] if want >= *start && markers.get(want - start) == Some(&focused) => Ok(()),
                [_] => Err(NotAtStart::FocusNotFirst),
                _ => aligned(),
            }
        }
        Stop::Text { field } | Stop::Select { field } => {
            if !focused_markers.is_empty() {
                return Err(NotAtStart::FocusNotFirst);
            }
            if focused_label(&rows, &form.fields[field].label).is_none() {
                return Err(if rows.iter().any(|row| row.focused) {
                    NotAtStart::FocusNotFirst
                } else {
                    NotAtStart::NoFocus
                });
            }
            aligned()
        }
        Stop::Submit => {
            if !focused_markers.is_empty() {
                return Err(NotAtStart::FocusNotFirst);
            }
            if rows
                .iter()
                .any(|row| row.focused && row.text.starts_with(SUBMIT_LABEL))
            {
                Ok(())
            } else {
                Err(NotAtStart::NoFocus)
            }
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

/// The rows of the focused textarea `field`'s editor, raw: the `height`
/// lines after its focused label with only the form's frame removed, every
/// other cell kept as drawn (padding included). omp frames each one as the
/// panel's `│ ` (`row`, overlay-box.ts:47-50), the field's `  │ `
/// (`#textFieldLines`, dialog.ts:1369-1375), the editor's row padded to the
/// field's inner width, then the panel's ` │`; every `│` is the symbol
/// preset's `boxRound.vertical` (`BOX_VERTICAL`). All rows have that width.
fn editor_rows(
    screen: &str,
    form: &ParsedForm,
    field: usize,
    height: usize,
) -> Option<Vec<String>> {
    let lines: Vec<&str> = screen.lines().collect();
    let rows = rows_of(screen);
    let (start, count) = focused_label(&rows, &form.fields[field].label)?;
    let values = lines.get(start + count..start + count + height)?;
    let rows: Vec<String> = values
        .iter()
        .map(|line| {
            let rest = line.trim_start().strip_prefix(BOX_VERTICAL)?;
            let rest = rest.strip_prefix("   ")?.strip_prefix(BOX_VERTICAL)?;
            let rest = rest.strip_prefix(' ')?;
            let rest = rest.trim_end_matches(' ').strip_suffix(BOX_VERTICAL)?;
            Some(rest.strip_suffix(' ')?.to_owned())
        })
        .collect::<Option<_>>()?;
    let width = cells(rows.first()?);
    rows.iter().all(|row| cells(row) == width).then_some(rows)
}

fn cells(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

/// omp's `PLACEHOLDER_MIN_GAP` (editor.ts:465).
const PLACEHOLDER_MIN_GAP: usize = 2;

/// The rows an empty focused textarea of `width` cells and `height` rows
/// shows. With the hardware cursor omp's form uses nothing is drawn at the
/// caret, and the placeholder (the raw attribute, `editor.placeholder`,
/// dialog.ts:677) is painted flush right on the first row when at least
/// `PLACEHOLDER_MIN_GAP` cells stay free before it, else not at all: omp
/// does not truncate it (`hintTail`, editor.ts:1627-1630).
fn empty_rows(placeholder: &str, width: usize, height: usize) -> Vec<String> {
    let blank = " ".repeat(width);
    let mut rows = vec![blank; height];
    let shown = cells(placeholder);
    if !placeholder.is_empty() && width >= shown + PLACEHOLDER_MIN_GAP {
        rows[0] = format!("{}{placeholder}", " ".repeat(width - shown));
    }
    rows
}

/// The rows a focused textarea of `width` cells shows holding `text`, each
/// padded to `width`, as omp's `Editor` lays it out (`#layoutText`,
/// editor.ts:3160-3225): a logical line no wider than the editor is one row
/// as is; a wider one is word-wrapped by `wordWrapLine`.
fn layout_rows(text: &str, width: usize) -> Vec<String> {
    text.split('\n')
        .flat_map(|line| {
            if cells(line) <= width {
                vec![line.to_owned()]
            } else {
                word_wrap_line(line, width)
            }
        })
        .map(|row| {
            let pad = width.saturating_sub(cells(&row));
            format!("{row}{}", " ".repeat(pad))
        })
        .collect()
}

/// JS `\s` / `String.prototype.trimEnd`'s whitespace: Unicode White_Space
/// but U+0085, plus U+FEFF.
fn is_js_space(ch: char) -> bool {
    (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}'
}

/// A port of omp's `wordWrapLine` (editor.ts:169-400) for a line wider than
/// `max`: graphemes (`Intl.Segmenter`, here `unicode-segmentation`) grouped
/// into runs of whitespace and non-whitespace (`getWordNavKind`, by a
/// grapheme's first code point); runs that fit are packed onto a row, a
/// row's trailing whitespace is trimmed when it wraps and the next row's
/// leading whitespace skipped; a run wider than a row is broken by
/// grapheme, first filling what is left of the current row; a run with a
/// wide grapheme (CJK) fills the current row before wrapping.
fn word_wrap_line(line: &str, max: usize) -> Vec<String> {
    use unicode_segmentation::UnicodeSegmentation;
    if line.is_empty() || max == 0 {
        return vec![String::new()];
    }
    // Grapheme start offsets (with an end sentinel) and widths.
    let graphemes: Vec<(usize, &str)> = line.grapheme_indices(true).collect();
    let starts: Vec<usize> = graphemes
        .iter()
        .map(|(start, _)| *start)
        .chain([line.len()])
        .collect();
    let widths: Vec<usize> = graphemes.iter().map(|(_, g)| cells(g)).collect();
    let is_space = |g: &str| g.chars().next().is_some_and(char::is_whitespace);
    struct Token {
        start_g: usize,
        end_g: usize,
        whitespace: bool,
    }
    let mut tokens: Vec<Token> = Vec::new();
    for (index, (_, grapheme)) in graphemes.iter().enumerate() {
        let whitespace = is_space(grapheme);
        match tokens.last_mut() {
            Some(token) if token.whitespace == whitespace => token.end_g = index + 1,
            _ => tokens.push(Token {
                start_g: index,
                end_g: index + 1,
                whitespace,
            }),
        }
    }
    let span = |start_g: usize, end_g: usize| -> usize { widths[start_g..end_g].iter().sum() };
    // The widest grapheme prefix of [start_g, end_g) fitting `available`.
    let prefix_to_width = |start_g: usize, end_g: usize, available: usize| -> usize {
        let mut width = 0;
        let mut g = start_g;
        while g < end_g {
            if width + widths[g] > available {
                break;
            }
            width += widths[g];
            g += 1;
            if width == available {
                break;
            }
        }
        g
    };
    let mut chunks: Vec<String> = Vec::new();
    // The pending chunk is line[chunk_start..chunk_end] (byte offsets).
    let mut chunk_start = 0;
    let mut chunk_end = 0;
    let mut current = 0;
    let mut at_line_start = true;
    for token in &tokens {
        let token_start = starts[token.start_g];
        let token_end = starts[token.end_g];
        let token_width = span(token.start_g, token.end_g);
        if at_line_start && token.whitespace {
            chunk_start = token_end;
            chunk_end = token_end;
            continue;
        }
        at_line_start = false;
        if token_width > max {
            let mut prefix_end_g = token.start_g;
            if chunk_end > chunk_start && current < max {
                prefix_end_g = prefix_to_width(token.start_g, token.end_g, max - current);
            }
            if chunk_end > chunk_start {
                if prefix_end_g > token.start_g {
                    let end = starts[prefix_end_g];
                    chunks.push(line[chunk_start..end].to_owned());
                    chunk_start = end;
                    chunk_end = end;
                } else {
                    chunks.push(line[chunk_start..chunk_end].to_owned());
                    chunk_start = token_start;
                    chunk_end = token_start;
                }
                current = 0;
            }
            let mut piece_start = starts[prefix_end_g];
            let mut piece_end = piece_start;
            let mut piece_width = 0;
            for g in prefix_end_g..token.end_g {
                let w = widths[g];
                if piece_width + w > max && piece_end > piece_start {
                    chunks.push(line[piece_start..piece_end].to_owned());
                    piece_start = piece_end;
                    piece_width = w;
                } else {
                    piece_width += w;
                }
                piece_end = starts[g + 1];
            }
            if piece_end > piece_start {
                chunk_start = piece_start;
                chunk_end = piece_end;
                current = piece_width;
            }
            continue;
        }
        if current + token_width > max {
            if chunk_end > chunk_start
                && !token.whitespace
                && current < max
                && (token.start_g..token.end_g).any(|g| widths[g] > 1)
            {
                let end_g = prefix_to_width(token.start_g, token.end_g, max - current);
                if end_g > token.start_g {
                    let end = starts[end_g];
                    chunks.push(line[chunk_start..end].to_owned());
                    chunk_start = end;
                    chunk_end = token_end;
                    current = cells(&line[end..token_end]);
                    at_line_start = false;
                    continue;
                }
            }
            let trimmed = line[chunk_start..chunk_end].trim_end_matches(is_js_space);
            if !trimmed.is_empty() || chunks.is_empty() {
                chunks.push(trimmed.to_owned());
            }
            at_line_start = true;
            if token.whitespace {
                chunk_start = token_end;
                chunk_end = token_end;
                current = 0;
            } else {
                chunk_start = token_start;
                chunk_end = token_end;
                current = token_width;
                at_line_start = false;
            }
        } else {
            if chunk_end == chunk_start {
                chunk_start = token_start;
            }
            chunk_end = token_end;
            current += token_width;
        }
    }
    if chunk_end > chunk_start {
        chunks.push(line[chunk_start..chunk_end].to_owned());
    }
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    chunks
}

/// The outcome of reading a focused textarea back.
enum ReadBack {
    /// The raw rows the editor showed.
    Shows(Vec<String>),
    /// The raw rows the editor showed last; `None` when it was not on
    /// screen.
    Differs(Option<Vec<String>>),
}

/// The agent's pane as the form driver sees it.
pub(crate) trait FormPane {
    fn read_screen(&mut self) -> Result<String, ErrorBody>;
    fn send(&mut self, action: &Action) -> Result<(), ErrorBody>;
    fn pause(&mut self);
}

/// Screen reads (one pause apart) the form gets to show a step.
const SETTLE_READS: usize = 20;
/// Reads a stop must hold, after a key, to count as not having moved.
const STAY_READS: usize = 3;
/// ↑/↓ presses one textarea may take to reach its first or last line.
const TEXTAREA_MAX_MOVES: usize = 40;
/// Hard caps per field, whatever the screen shows.
const MAX_FIELD_KEYS: usize = 6_000;
const MAX_FIELD_READS: usize = 800;

/// What follows an `ask_form_moved` message when it quotes a textarea's
/// rows (the person's text): herdr's log leaves it out.
pub(crate) const EDITOR_SHOWED: &str = "; the editor showed ";

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

    /// Send `key` and read until the focus settles on one of `stops`: its
    /// index. Leaving for `stops[1]` shows at once; staying on `stops[0]` is
    /// taken once it held for `STAY_READS` reads. A later move than that is
    /// caught by the next key, which then finds focus on neither stop.
    fn step(&mut self, key: &'static str, stops: [Stop; 2]) -> Result<usize, ErrorBody> {
        self.keys(vec![key])?;
        let mut stayed = 0;
        for read in 0..SETTLE_READS {
            if read > 0 {
                self.pane.pause();
            }
            let screen = self.read()?;
            if seen(&screen, self.form, stops[1]).is_some() {
                return Ok(1);
            }
            if seen(&screen, self.form, stops[0]).is_some() {
                stayed += 1;
                if stayed >= STAY_READS {
                    return Ok(0);
                }
            } else {
                stayed = 0;
            }
        }
        Err(self.displaced(stops[0]))
    }

    /// Replace a textarea's whole content with `text`, proving each step by
    /// where omp's form moves the focus rather than by the editor viewport
    /// (which can hide lines and show blank ones):
    /// 1. ↑ until the focus leaves for the stop before: `#textInput`
    ///    (dialog.ts:857-861) hands ↑ to the form only on the first logical
    ///    line, so the caret is then on line 0. Tab comes back (the caret
    ///    stays).
    /// 2. ↓ until the focus leaves for the stop after, counting presses: ↓
    ///    leaves only from the last logical line and moves at most one line
    ///    otherwise, so the count `n` is at least the number of lines.
    ///    Shift+Tab comes back; the caret is on the last line.
    /// 3. Ctrl+E puts the caret at the end of that line (`#moveToLineEnd`,
    ///    editor.ts:4258-4263), the end of the text. Each Ctrl+U deletes to
    ///    the line start, or at a line start joins the line above
    ///    (`#deleteToStartOfLine`, editor.ts:4495-4523), so `2n` of them
    ///    empty the editor; more do nothing on an empty first line.
    /// 4. Paste `text`, then read the focused editor back: every visible
    ///    character of `text` must show, in order, within its rows.
    ///
    /// Too many lines to count (`TEXTAREA_MAX_MOVES`) or an answer that does
    /// not fit the editor is `ask_form_invalid`; anything else unexpected is
    /// `ask_form_moved`. Nothing is submitted either way, and omp's Editor
    /// has no key that empties a whole draft (`keybindings.ts:9-30`), so
    /// these steps are the clear.
    fn edit_textarea(
        &mut self,
        field: usize,
        input: &crate::agent_transcript::ask_form::TextInput,
        text: &str,
    ) -> Result<(), ErrorBody> {
        let stop = Stop::Text { field };
        let index = self
            .stops
            .iter()
            .position(|candidate| *candidate == stop)
            .expect("a text field has a stop");
        // `plan` refuses a textarea that is the first stop.
        let (before, after) = (self.stops[index - 1], self.stops[index + 1]);
        let name = self.form.fields[field].name.clone();
        self.until(stop, |_| true)?;
        let height = input.height();
        // The editor's width (`editor_rows` returns rows of one width),
        // read before anything is sent: an answer that would not show whole,
        // or whose rows could not be told from the empty editor's
        // placeholder, is refused while the draft is intact.
        let width = match self.editor_shows(field, height, |_| true)? {
            ReadBack::Shows(rows) => cells(&rows[0]),
            ReadBack::Differs(rows) => return Err(self.misread(stop, rows)),
        };
        let empty = empty_rows(&input.placeholder, width, height);
        let want = if text.is_empty() {
            empty.clone()
        } else {
            let mut rows = layout_rows(text, width);
            // More rows than the editor shows would scroll.
            if rows.len() > height {
                return Err(invalid(&name, TOO_LONG));
            }
            rows.resize(height, " ".repeat(width));
            rows
        };
        if !text.is_empty() && want == empty {
            return Err(invalid(
                &name,
                "answer looks like the placeholder; answer in the terminal",
            ));
        }
        let mut up = 0;

        while self.step("up", [stop, before])? == 0 {
            up += 1;
            if up > TEXTAREA_MAX_MOVES {
                return Err(invalid(&name, TOO_LONG));
            }
        }
        self.keys(vec!["tab"])?;
        self.until(stop, |_| true)?;
        let mut lines = 1;
        while self.step("down", [stop, after])? == 0 {
            lines += 1;
            if lines > TEXTAREA_MAX_MOVES {
                return Err(invalid(&name, TOO_LONG));
            }
        }
        self.keys(vec!["shift+tab"])?;
        self.until(stop, |_| true)?;
        let mut keys = vec!["ctrl+e"];
        keys.extend(std::iter::repeat_n("ctrl+u", 2 * lines));
        self.keys(keys)?;
        match self.editor_shows(field, height, |rows| rows == empty.as_slice())? {
            ReadBack::Shows(_) => {}
            ReadBack::Differs(rows) => return Err(self.misread(stop, rows)),
        }
        self.type_text(text)?;
        match self.editor_shows(field, height, |rows| rows == want.as_slice())? {
            ReadBack::Shows(_) => Ok(()),
            ReadBack::Differs(rows) => Err(self.misread(stop, rows)),
        }
    }

    /// `ask_form_moved` for a textarea that did not show what was expected,
    /// naming what it showed.
    fn misread(&self, stop: Stop, rows: Option<Vec<String>>) -> ErrorBody {
        let mut error = self.displaced(stop);
        if let Some(rows) = rows {
            let shown: Vec<&str> = rows.iter().map(|row| row.trim_end()).collect();
            error.message.push_str(&format!("{EDITOR_SHOWED}{shown:?}"));
        }
        error
    }

    /// Read until the focused textarea's raw rows satisfy `done`. Backend
    /// errors (`pane_not_found`, a failed read) propagate unchanged; a
    /// screen that never shows it is `ReadBack::Differs` with the rows the
    /// editor showed last, `None` when the editor was not found.
    fn editor_shows(
        &mut self,
        field: usize,
        height: usize,
        done: impl Fn(&[String]) -> bool,
    ) -> Result<ReadBack, ErrorBody> {
        let mut last = None;
        for read in 0..SETTLE_READS {
            if read > 0 {
                self.pane.pause();
            }
            let screen = self.read()?;
            last = editor_rows(&screen, self.form, field, height);
            if let Some(rows) = last.take_if(|rows| done(rows)) {
                return Ok(ReadBack::Shows(rows));
            }
        }
        Ok(ReadBack::Differs(last))
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
            // A textarea the values leave out is left as it is.
            (FieldKind::Text(_), Target::Keep) => {
                self.until(Stop::Text { field }, |_| true).map(drop)
            }
            (FieldKind::Text(input), Target::Text(text)) if input.multiline => {
                self.edit_textarea(field, input, text)
            }
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
    let mut reads = 0;
    let mut revealed = false;
    loop {
        if reads > 0 {
            pane.pause();
        }
        reads += 1;
        match start_state(&pane.read_screen()?, form) {
            Ok(()) => break,
            // omp opened the form on a page of context ahead of the first
            // stop (`#followFocus` false, dialog.ts:290-296, :598-603), at a
            // pane too short for both. There ↑ only brings the focus's page
            // into view and moves nothing (`handleInput`, dialog.ts:486-500).
            // Once only: a second ↑ before omp redrew would move the focus.
            Err(NotAtStart::FocusOffPage { .. }) if !revealed => {
                pane.send(&Action::Keys(vec!["up"]))?;
                revealed = true;
                reads = 0;
            }
            Err(reason) if reads >= if revealed { SETTLE_READS } else { START_READS } => {
                return Err(moved(format!(
                    "the form on the agent's screen is not in its starting state: {reason} (being answered in the terminal, hidden, or scrolled away)"
                )));
            }
            Err(_) => {}
        }
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
/// one of omp's validation messages (`pattern` and URL checks are omp's, and
/// a kept textarea's content was never checked by herdr). omp draws the
/// error after the whole field (dialog.ts:1255-1271): its label rows, then
/// its value rows (`TextInput::height`: one for an input, the textarea's
/// fixed editor height).
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
        let FieldKind::Text(input) = &field.kind else {
            continue;
        };
        for start in 0..rows.len() {
            let Some(count) = label_rows(&rows, start, &field.label) else {
                continue;
            };
            let Some(row) = rows.get(start + count + input.height()) else {
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
