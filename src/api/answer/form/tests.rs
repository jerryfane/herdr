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
    assert_eq!(start_state(start, &form), Ok(()));
    let moved = start.replace("❯ ◉ Postgres\n    ○ MySQL", "  ◉ Postgres\n❯ ○ MySQL");
    assert_eq!(start_state(&moved, &form), Err(NotAtStart::FocusNotFirst));
    let changed = start.replace("☐ Terraform", "☑ Terraform");
    assert_eq!(
        start_state(&changed, &form),
        Err(NotAtStart::OptionsChanged)
    );
    let typed = start.replacen("○ Other: type your own", "○ Other: Mongo", 1);
    assert_eq!(start_state(&typed, &form), Err(NotAtStart::OptionsChanged));
    assert_eq!(
        start_state("$ omp\n> ", &form),
        Err(NotAtStart::NoPanel),
        "no form on screen"
    );
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
    /// Text fields: lines and caret (line, column in chars).
    lines: Vec<Vec<String>>,
    caret: Vec<(usize, usize)>,
    /// A textarea editor's scroll offset (visual rows), kept across frames.
    scroll: Vec<std::cell::Cell<usize>>,
    width: usize,
    keys: Vec<String>,
    submitted: Option<Vec<(String, Option<FormValue>)>>,
    errors: Vec<Option<String>>,
    /// omp's own Submit check, standing in for `pattern`: (field, message).
    refuse: Option<(usize, String)>,
    /// Keys after this many are swallowed (someone else holds the form).
    frozen_after: Option<usize>,
    /// omp opened the form on a page of context ahead of its first stop
    /// (the pane too short for both; `#followFocus` false, dialog.ts:290-296,
    /// :598-603): page 1 of 2 shows no stop until ↑/↓, Space or Enter brings
    /// the focus's page into view without acting (dialog.ts:486-500).
    context_page: bool,
    /// A draft in the composer holds the keys (omp's input guard): ↑/↓
    /// release it and do nothing else; other keys edit the draft
    /// (dialog.ts:468-472).
    draft: bool,
    /// ↑/↓ do not release the draft.
    draft_sticks: bool,
    /// The composer shows a draft under the panel (held or released).
    has_draft: bool,
    /// Reads after a release or reveal that still show the previous frame
    /// (omp has not redrawn yet).
    redraw_lag: usize,
    stale: Option<(String, usize)>,
    /// Draw with omp's ascii symbol preset (`|` borders and rails, `>`
    /// cursor, `(o)`/`[x]` markers; pi-tui theme/symbols.ts:1200-1400).
    ascii: bool,
    /// Each key or paste with the stop it reached.
    received: Vec<(String, Stop)>,
    /// Pastes lose their last character (the terminal mangled the input).
    paste_drops_last: bool,
    /// After a paste, the read with this index fails (`pane_not_found`).
    fail_read_after_paste: Option<usize>,
    reads_since_paste: Option<usize>,
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
            lines: vec![Vec::new(); count],
            caret: vec![(0, 0); count],
            scroll: (0..count).map(|_| std::cell::Cell::new(0)).collect(),
            width: 200,
            keys: Vec::new(),
            submitted: None,
            errors: vec![None; count],
            refuse: None,
            frozen_after: None,
            context_page: false,
            draft: false,
            draft_sticks: false,
            has_draft: false,
            redraw_lag: 0,
            stale: None,
            ascii: false,
            paste_drops_last: false,
            fail_read_after_paste: None,
            reads_since_paste: None,
            received: Vec::new(),
            form,
        };
        for (index, field) in dialog.form.fields.iter().enumerate() {
            match &field.kind {
                FieldKind::Choice(choice) => dialog.checked[index] = choice.initial_checked(),
                // omp ≥ 18.18.6 opens prefilled fields with the caret at the start.
                // omp ≥ 18.18.6 opens prefilled fields with the caret at the start.
                FieldKind::Text(input) => {
                    dialog.lines[index] = input.value.split('\n').map(str::to_owned).collect()
                }
            }
        }
        dialog
    }

    /// omp 18.18.3: single-line inputs open with the caret at the end.
    fn caret_at_end(mut self) -> Self {
        for (index, field) in self.form.fields.iter().enumerate() {
            if let FieldKind::Text(input) = &field.kind {
                if !input.multiline {
                    self.caret[index] = (0, self.lines[index][0].chars().count());
                }
            }
        }
        self
    }

    /// The textarea editor's inner width: the panel's width less its
    /// `│ `/` │` frame and the field's `  │ ` (`#textFieldLines`).
    fn editor_width(&self) -> usize {
        self.width.saturating_sub(8).max(4)
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
        self.received.push((key.to_owned(), self.stops[self.focus]));
        if self.draft {
            if matches!(key, "up" | "down") && !self.draft_sticks {
                self.redraw_later();
                self.draft = false;
            }
            return;
        }
        if self.context_page {
            match key {
                "up" | "down" | "space" | "enter" => {
                    self.redraw_later();
                    self.context_page = false;
                    return;
                }
                "tab" | "shift+tab" => self.context_page = false,
                _ => return,
            }
        }
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

    fn text_key(&mut self, field: usize, key: &str) {
        let multiline =
            matches!(&self.form.fields[field].kind, FieldKind::Text(input) if input.multiline);
        let (mut line, mut col) = self.caret[field];
        let lines = &mut self.lines[field];
        let len = |text: &str| text.chars().count();
        let byte = |text: &str, col: usize| {
            text.char_indices()
                .nth(col)
                .map_or(text.len(), |(at, _)| at)
        };
        match key {
            "up" if !multiline || line == 0 => return self.move_stop(-1),
            "down" if !multiline || line + 1 == lines.len() => return self.move_stop(1),
            "up" => line -= 1,
            "down" => line += 1,
            "enter" if !multiline => return self.move_field(),
            "ctrl+e" => col = len(&lines[line]),
            "ctrl+u" if col > 0 => {
                let at = byte(&lines[line], col);
                lines[line].replace_range(..at, "");
                col = 0;
            }
            "ctrl+u" if multiline && line > 0 => {
                let current = lines.remove(line);
                line -= 1;
                col = len(&lines[line]);
                lines[line].push_str(&current);
            }
            "ctrl+k" if col < len(&lines[line]) => {
                let at = byte(&lines[line], col);
                lines[line].truncate(at);
            }
            "ctrl+k" if multiline && line + 1 < lines.len() => {
                let next = lines.remove(line + 1);
                lines[line].push_str(&next);
            }
            _ => {}
        }
        col = col.min(len(&lines[line]));
        self.caret[field] = (line, col);
    }

    fn paste(&mut self, text: &str) {
        if self
            .frozen_after
            .is_some_and(|limit| self.keys.len() >= limit)
        {
            return;
        }
        self.keys.push(format!("text:{text}"));
        self.reads_since_paste = Some(0);
        self.received
            .push((format!("text:{text}"), self.stops[self.focus]));
        let mut chars: Vec<char> = text.chars().collect();
        if self.paste_drops_last {
            chars.pop();
        }
        let text: &str = &chars.into_iter().collect::<String>();
        match self.stops[self.focus] {
            Stop::Other { field } => {
                self.other[field].push_str(text);
                if !self.choice(field).multi && !self.other[field].trim().is_empty() {
                    self.checked[field].clear();
                }
            }
            Stop::Text { field } => {
                let (line, col) = self.caret[field];
                let current = &self.lines[field][line];
                let at = current
                    .char_indices()
                    .nth(col)
                    .map_or(current.len(), |(at, _)| at);
                let (before, after) = (current[..at].to_owned(), current[at..].to_owned());
                let mut pasted: Vec<String> = format!("{before}{text}")
                    .split('\n')
                    .map(str::to_owned)
                    .collect();
                let last = pasted.len() - 1;
                let caret = (line + last, pasted[last].chars().count());
                pasted[last].push_str(&after);
                self.lines[field].splice(line..=line, pasted);
                self.caret[field] = caret;
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
                FieldKind::Text(input) => Some(text_value(input, &self.lines[index].join("\n"))),
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

    /// Keep showing the current frame for `redraw_lag` reads.
    fn redraw_later(&mut self) {
        if self.redraw_lag > 0 {
            self.stale = Some((self.render(), self.redraw_lag));
        }
    }

    /// omp's footer while a draft holds the keys (`#guardHint`).
    fn footer(&self, out: &mut Vec<String>) {
        if self.draft {
            out.push("│ ↑/↓ answer · typing edits your prompt · ⎋ cancel".into());
        }
    }

    fn render(&self) -> String {
        if self.context_page {
            self.render_context()
        } else {
            self.render_page()
        }
    }

    /// Page 1 of 2: the form's leading context, no stop.
    fn render_context(&self) -> String {
        let mut out = vec![
            "❯ an earlier prompt in the chat".to_owned(),
            "╭─ Ask · 1/2 ─╮".to_owned(),
        ];
        'context: for section in &self.form.sections {
            for block in &section.blocks {
                match block {
                    Block::Field(_) => break 'context,
                    Block::Text { text, .. } => out.push(format!("│ {}", one_line(text))),
                    _ => {}
                }
            }
        }
        self.footer(&mut out);
        out.push("╰───────╯".into());
        self.composer(&mut out);
        out.join("\n")
    }

    /// The composer under the panel, with the draft typed before the form
    /// opened (it stays there once released).
    fn composer(&self, out: &mut Vec<String>) {
        if self.has_draft {
            out.push("❯ half-written note for later".into());
        }
    }

    fn render_page(&self) -> String {
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
        self.footer(&mut out);
        out.push("╰───────╯".into());
        self.composer(&mut out);
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
                let lines = &self.lines[index];
                let height = input.height();
                let value = lines.join("\n");
                let focused = self.stops[self.focus] == stop;
                // As `#textFieldLines`: focused, the input or editor viewport
                // (scrolled to keep the caret in view); unfocused, the value
                // from its first line, `…` past the height, or the
                // placeholder when empty.
                let mut rows: Vec<String> = if focused && input.multiline && !value.is_empty() {
                    // Lines wrap at the field width; the viewport keeps the
                    // caret's row in view like `#updateScrollOffset`.
                    let width = self.editor_width();
                    let mut visual = Vec::new();
                    let mut caret_row = 0;
                    for (line_index, line) in lines.iter().enumerate() {
                        // omp's wrapping, as ported (checked against real
                        // omp by `the_wrap_port_matches_omp_screens`).
                        let parts: Vec<String> = if line.chars().count() <= width {
                            vec![line.clone()]
                        } else {
                            word_wrap_line(line, width)
                        };
                        if line_index == self.caret[index].0 {
                            caret_row =
                                visual.len() + (self.caret[index].1 / width).min(parts.len() - 1);
                        }
                        visual.extend(parts);
                    }
                    let mut offset = self.scroll[index].get();
                    if caret_row < offset {
                        offset = caret_row;
                    } else if caret_row >= offset + height {
                        offset = caret_row + 1 - height;
                    }
                    offset = offset.min(visual.len().saturating_sub(height));
                    self.scroll[index].set(offset);
                    visual.into_iter().skip(offset).take(height).collect()
                } else if value.is_empty() && focused && input.multiline {
                    // omp's Editor with the hardware cursor: the placeholder
                    // flush right when 2 cells stay free before it, else
                    // nothing (`hintTail`, editor.ts:1627-1630).
                    let width = self.editor_width();
                    let shown = input.placeholder.chars().count();
                    if input.placeholder.is_empty() || width < shown + 2 {
                        vec![String::new()]
                    } else {
                        vec![format!(
                            "{}{}",
                            " ".repeat(width - shown),
                            input.placeholder
                        )]
                    }
                } else if value.is_empty() {
                    vec![input.placeholder.clone()]
                } else {
                    lines.clone()
                };
                if rows.len() > height {
                    rows.truncate(height);
                    if !focused {
                        rows[height - 1] = "…".into();
                    }
                }
                rows.resize(height, String::new());
                // The panel pads every row to the field's inner width and
                // closes it with ` │` (overlay-box.ts `row`).
                let width = self.editor_width();
                for row in rows {
                    let pad = width.saturating_sub(row.chars().count());
                    out.push(format!("│   │ {row}{} │", " ".repeat(pad)));
                }
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

/// A screen drawn with omp's unicode preset, redrawn with its ascii one.
fn ascii_preset(screen: &str) -> String {
    let mut out = String::with_capacity(screen.len());
    for ch in screen.chars() {
        match ch {
            '│' => out.push('|'),
            '❯' => out.push('>'),
            '◉' => out.push_str("(o)"),
            '○' => out.push_str("( )"),
            '☑' => out.push_str("[x]"),
            '☐' => out.push_str("[ ]"),
            '╭' | '╮' | '╰' | '╯' => out.push('+'),
            '─' => out.push('-'),
            other => out.push(other),
        }
    }
    out
}

impl FormPane for Dialog {
    fn read_screen(&mut self) -> Result<String, ErrorBody> {
        if let Some(reads) = self.reads_since_paste.as_mut() {
            if Some(*reads) == self.fail_read_after_paste {
                return Err(ErrorBody {
                    code: "pane_not_found".into(),
                    message: "pane w1:p1 not found".into(),
                });
            }
            *reads += 1;
        }
        if let Some((frame, left)) = self.stale.take() {
            if left > 1 {
                self.stale = Some((frame.clone(), left - 1));
            }
            return Ok(frame);
        }
        Ok(if self.ascii {
            ascii_preset(&self.render())
        } else {
            self.render()
        })
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
    dialog.lines[3] = vec!["changed".into()];
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
    assert_eq!(start_state(&dialog.render(), &dialog.form), Ok(()));
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
        let error = drive(&mut dialog, &form, &plan).unwrap_err().body;
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
    assert_eq!(start_state(&rows(0), &form), Ok(()));
    assert_eq!(start_state(&rows(2), &form), Err(NotAtStart::FocusNotFirst));
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
    assert_eq!(
        start_state(&screen(&["❯ ◉ A", "  ○ Other: skip", "  Submit"]), &form),
        Ok(())
    );
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
    assert_eq!(start_state(&start, &form), Ok(()));
    let typed = screen(&["  ○ A", "  ○ B", "❯ ○ Other: x", "  Submit"]);
    assert_eq!(start_state(&typed, &form), Err(NotAtStart::OptionsChanged));
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

/// The owner's shape (xreal-desk): two radio groups and a prefilled,
/// multi-line "edit freely" textarea.
const VOICE_OVER: &str = r#"<form><fieldset><legend>Voice</legend>
<label><input type="radio" name="voice" value="warm" checked> Warm</label>
<label><input type="radio" name="voice" value="crisp"> Crisp</label></fieldset>
<fieldset><legend>Pace</legend>
<label><input type="radio" name="pace" value="slow"> Slow</label>
<label><input type="radio" name="pace" value="normal" checked> Normal</label></fieldset>
<fieldset><legend>Script</legend><label>Voice-over text (edit freely) <textarea name="vo" rows="4">Meet the new desk.
It remembers how you work.</textarea></label></fieldset></form>"#;

const VO_PREFILL: &str = "Meet the new desk.\nIt remembers how you work.";

/// A textarea the values leave out is passed with Tab, never edited, and its
/// prefill is what omp submits.
#[test]
fn an_untouched_textarea_is_kept() {
    for values_in in [BTreeMap::new(), values(&[("pace", options(&["slow"]))])] {
        let mut dialog = Dialog::new(VOICE_OVER);
        let submitted = answer(&mut dialog, values_in).unwrap();
        assert_eq!(value(&submitted, "vo"), txt(VO_PREFILL));
        let at_textarea: Vec<&str> = dialog
            .received
            .iter()
            .filter(|(_, stop)| *stop == Stop::Text { field: 2 })
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(at_textarea, ["tab"], "only Tab reaches the textarea");
    }
}

/// An edit made in the terminal before the app answered is submitted as it
/// is, and confirmation does not call it answered.
#[test]
fn a_terminal_edited_textarea_is_reported_unconfirmed() {
    let mut dialog = Dialog::new(VOICE_OVER);
    dialog.lines[2] = vec![
        "Meet the new desk.".into(),
        "Edited in the terminal.".into(),
    ];
    let form = dialog.form.clone();
    let planned = plan(&form, &BTreeMap::new()).unwrap();
    drive(&mut dialog, &form, &planned).unwrap();
    let submitted = dialog.submitted.clone().expect("submitted");
    let recorded: serde_json::Map<String, serde_json::Value> = submitted
        .iter()
        .filter_map(|(name, value)| {
            let value = match value.as_ref()? {
                FormValue::Text(text) => serde_json::Value::String(text.clone()),
                FormValue::Number(number) => serde_json::json!(number),
                FormValue::List(items) => serde_json::json!(items),
            };
            Some((name.clone(), value))
        })
        .collect();
    assert_eq!(
        value(&submitted, "vo"),
        txt("Meet the new desk.\nEdited in the terminal.")
    );
    assert!(!submission_matches(&planned.expected, &recorded));
}

/// A changed textarea is emptied (wherever the caret is, whatever it holds
/// out of view) and gets exactly the new text.
#[test]
fn a_changed_textarea_is_replaced() {
    let new = "Line one.\nLine two.\nLine three.";
    for (content, caret) in [
        (
            vec![
                "Meet the new desk.".to_owned(),
                "It remembers how you work.".to_owned(),
            ],
            (0, 0),
        ),
        (
            vec![
                "Meet the new desk.".to_owned(),
                "It remembers how you work.".to_owned(),
            ],
            (1, 7),
        ),
        // Blank lines hiding a retained line below the viewport.
        (
            std::iter::repeat_n(String::new(), 20)
                .chain(["retained-secret".to_owned()])
                .collect(),
            (0, 0),
        ),
        (
            std::iter::repeat_n(String::new(), 20)
                .chain(["retained-secret".to_owned()])
                .collect(),
            (10, 0),
        ),
    ] {
        let mut dialog = Dialog::new(VOICE_OVER);
        dialog.lines[2] = content;
        dialog.caret[2] = caret;
        let submitted = answer(
            &mut dialog,
            values(&[("voice", options(&["crisp"])), ("vo", text(new))]),
        )
        .unwrap();
        assert_eq!(value(&submitted, "vo"), txt(new), "caret {caret:?}");
        assert_eq!(value(&submitted, "voice"), txt("crisp"));
    }
}

/// Too much to count, or an answer that does not fit the editor, is
/// `ask_form_invalid` and nothing is submitted; a draft too long to count is
/// left untouched.
#[test]
fn a_textarea_too_long_to_edit_is_invalid() {
    let too_long = "vo: too long to edit from the app; answer in the terminal";
    let mut dialog = Dialog::new(VOICE_OVER);
    let long: Vec<String> = (0..60).map(|line| format!("line{line}")).collect();
    dialog.lines[2] = long.clone();
    dialog.caret[2] = (30, 0);
    let form = dialog.form.clone();
    let planned = plan(&form, &values(&[("vo", text("short"))])).unwrap();
    let error = drive(&mut dialog, &form, &planned).unwrap_err().body;
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("ask_form_invalid", too_long)
    );
    assert_eq!(dialog.lines[2], long, "the draft is untouched");
    assert_eq!(dialog.submitted, None);

    // More lines than the editor shows: refused before anything is sent.
    let form = parse(VOICE_OVER);
    let error = plan(&form, &values(&[("vo", text("1\n2\n3\n4\n5"))])).unwrap_err();
    assert_eq!(error.message, too_long);

    // One long paragraph that wraps past the editor's rows.
    let mut dialog = Dialog::new(VOICE_OVER);
    dialog.width = 30;
    let paragraph = "word ".repeat(60);
    let form = dialog.form.clone();
    let planned = plan(&form, &values(&[("vo", text(paragraph.trim()))])).unwrap();
    let error = drive(&mut dialog, &form, &planned).unwrap_err().body;
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("ask_form_invalid", too_long)
    );
    assert_eq!(dialog.submitted, None);
}

/// The editor not showing what was typed stops before Submit.
#[test]
fn a_textarea_reading_mismatch_is_moved() {
    let mut dialog = Dialog::new(VOICE_OVER);
    dialog.paste_drops_last = true;
    let form = dialog.form.clone();
    let planned = plan(&form, &values(&[("vo", text("New text."))])).unwrap();
    let error = drive(&mut dialog, &form, &planned).unwrap_err().body;
    assert_eq!(error.code, "ask_form_moved");
    assert_eq!(dialog.submitted, None);
    assert!(
        !dialog.keys.iter().any(|key| key == "escape"),
        "Esc would cancel the ask"
    );
}

/// A textarea that is the form's first stop has no stop before it to prove
/// the caret reached its first line: changing it is refused, keeping it works.
#[test]
fn a_first_field_textarea_is_kept_but_not_edited() {
    let html = r#"<form><label>Notes <textarea name="n">draft</textarea></label>
        <label><input type="radio" name="r" value="a" checked> A</label>
        <label><input type="radio" name="r" value="b"> B</label></form>"#;
    let form = parse(html);
    let error = plan(&form, &values(&[("n", text("new"))])).unwrap_err();
    assert_eq!(
        error.message,
        "n: the form's first field cannot be edited from the app; answer in the terminal"
    );
    let mut dialog = Dialog::new(html);
    let submitted = answer(&mut dialog, values(&[("r", options(&["b"]))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt("draft"));
}

const WITH_PLACEHOLDER: &str = r#"<form><label><input type="radio" name="r" value="a" checked> A</label>
<label><input type="radio" name="r" value="b"> B</label>
<label>Notes <textarea name="n" placeholder="Say something">old draft
second line</textarea></label></form>"#;

/// #394 F1: the placeholder omp draws flush right in an emptied editor reads
/// as empty, so the draft is replaced.
#[test]
fn review_replacement_with_real_right_aligned_placeholder() {
    let mut dialog = Dialog::new(WITH_PLACEHOLDER);
    let submitted = answer(&mut dialog, values(&[("n", text("New notes."))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt("New notes."));
}

/// #394 F1: emptying a textarea that has a placeholder works.
#[test]
fn review_empty_answer_with_placeholder() {
    let mut dialog = Dialog::new(WITH_PLACEHOLDER);
    let submitted = answer(&mut dialog, values(&[("n", text(""))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt(""));
}

/// #394 F1: an answer equal to the placeholder is text, not the placeholder.
#[test]
fn an_answer_equal_to_the_placeholder_is_text() {
    let mut dialog = Dialog::new(WITH_PLACEHOLDER);
    let submitted = answer(&mut dialog, values(&[("n", text("Say something"))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt("Say something"));
}

/// #394 F2: CRLF and lone CR line breaks are normalized, not refused.
#[test]
fn review_crlf_textarea_answer() {
    let form = parse(WITH_PLACEHOLDER);
    for raw in ["Line one\r\nLine two", "Line one\rLine two"] {
        let planned = plan(&form, &values(&[("n", text(raw))])).unwrap();
        assert_eq!(
            value(&planned.expected, "n"),
            txt("Line one\nLine two"),
            "{raw:?}"
        );
        let mut dialog = Dialog::new(WITH_PLACEHOLDER);
        let submitted = answer(&mut dialog, values(&[("n", text(raw))])).unwrap();
        assert_eq!(value(&submitted, "n"), txt("Line one\nLine two"));
    }
    let error = plan(&form, &values(&[("n", text("bell\u{7}"))])).unwrap_err();
    assert_eq!(error.message, "n: control characters are not allowed");
}

/// #394 F3: a backend read error while reading the typed answer back is
/// reported as itself.
#[test]
fn review_backend_read_error_is_preserved() {
    for fail_at in [0, 1] {
        let mut dialog = Dialog::new(VOICE_OVER);
        dialog.fail_read_after_paste = Some(fail_at);
        let form = dialog.form.clone();
        let planned = plan(&form, &values(&[("vo", text("Short."))])).unwrap();
        let error = drive(&mut dialog, &form, &planned).unwrap_err().body;
        assert_eq!(error.code, "pane_not_found", "{error:?}");
        assert_eq!(dialog.submitted, None);
    }
}

/// #394 r2: a placeholder with a double space is read exactly, not
/// collapsed, so the emptied editor is recognised.
#[test]
fn a_double_space_placeholder_is_read_exactly() {
    let html = WITH_PLACEHOLDER.replace("Say something", "Say  something");
    let mut dialog = Dialog::new(&html);
    let submitted = answer(&mut dialog, values(&[("n", text("New notes."))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt("New notes."));
    let mut dialog = Dialog::new(&html);
    let submitted = answer(&mut dialog, values(&[("n", text(""))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt(""));
}

/// #394 r2: a literal answer with a leading space is text, never the
/// placeholder.
#[test]
fn a_leading_space_answer_is_text() {
    let mut dialog = Dialog::new(WITH_PLACEHOLDER);
    let submitted = answer(&mut dialog, values(&[("n", text(" Say something"))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt(" Say something"));
}

/// #394 r2: a placeholder too long for the editor is not drawn (omp does not
/// truncate it); the emptied editor is blank.
#[test]
fn a_placeholder_longer_than_the_editor_is_not_drawn() {
    let long = "p".repeat(40);
    let html = WITH_PLACEHOLDER.replace("Say something", &long);
    let mut dialog = Dialog::new(&html);
    dialog.width = 40;
    let submitted = answer(&mut dialog, values(&[("n", text("Short."))])).unwrap();
    assert_eq!(value(&submitted, "n"), txt("Short."));
    assert_eq!(empty_rows(&long, 32, 2), vec![" ".repeat(32); 2]);
    assert_eq!(empty_rows("ab", 4, 1), vec!["  ab".to_owned()]);
    assert_eq!(
        empty_rows("abc", 4, 1),
        vec!["    ".to_owned()],
        "one free cell is too few"
    );
}

/// #394 r2: an answer drawn exactly like the empty editor's placeholder
/// (possible when the placeholder ends in spaces) cannot be confirmed: it is
/// refused before the draft is touched.
#[test]
fn an_answer_drawn_like_the_placeholder_is_invalid() {
    let html = WITH_PLACEHOLDER.replace("Say something", "Say something  ");
    let mut dialog = Dialog::new(&html);
    dialog.width = 40;
    let width = dialog.editor_width();
    let lookalike = format!(
        "{}Say something",
        " ".repeat(width - "Say something  ".len())
    );
    let mut rows = layout_rows(&lookalike, width);
    rows.resize(4, " ".repeat(width));
    assert_eq!(rows, empty_rows("Say something  ", width, 4));
    let form = dialog.form.clone();
    let planned = plan(&form, &values(&[("n", text(&lookalike))])).unwrap();
    let before = dialog.lines[1].clone();
    let error = drive(&mut dialog, &form, &planned).unwrap_err().body;
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        (
            "ask_form_invalid",
            "n: answer looks like the placeholder; answer in the terminal"
        )
    );
    assert_eq!(dialog.lines[1], before, "the draft is untouched");
    assert_eq!(dialog.submitted, None);
}

const OMP_WRAP: &str = include_str!("omp-18.18.6-textarea-wrap.json");

fn shown_chars(line: &str) -> usize {
    line.chars().count()
}

/// The answer rows of a focused textarea, as `editor_rows` reads them from
/// a captured screen line.
fn captured_row(line: &str) -> String {
    let rest = line
        .trim_start()
        .strip_prefix("│   │ ")
        .expect("framed row");
    let rest = rest
        .trim_end_matches(' ')
        .strip_suffix('│')
        .expect("closed row");
    rest.strip_suffix(' ').expect("frame space").to_owned()
}

/// #394 r3: the port of omp's `wordWrapLine` reproduces omp 18.18.6's
/// screens byte for byte: full-width lines, a word straddling the edge, a
/// word longer than the row, a long word after a short one, CJK, ASCII then
/// CJK, emoji, emoji at the edge, spaces at the wrap point, combining marks,
/// two paragraphs. Captured from real omp in a 111-cell, 10-row textarea
/// (`textarea-smoke-394r3/`). A ZWJ emoji sequence is drawn wider by the
/// terminal than omp lays it out, so no port can match it: those answers
/// are refused (`emoji_sequences_are_refused_in_textareas`).
#[test]
fn the_wrap_port_matches_omp_screens() {
    let fixtures: serde_json::Value = serde_json::from_str(OMP_WRAP).unwrap();
    let width = fixtures["width"].as_u64().unwrap() as usize;
    let mut checked = 0;
    for case in fixtures["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();
        let lines: Vec<&str> = case["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row.as_str().unwrap())
            .collect();
        if name == "combining" {
            // omp lays `e` + U+0301 out as one cell, as the port does, but
            // the terminal reads it back precomposed (`é`): such answers are
            // refused (`combined_characters_are_refused_in_textareas`).
            assert!(shown_chars(lines[0]) < cells(lines[0]) + 1);
            continue;
        }
        if name == "zwj-emoji" {
            // Each 👩‍💻 took four cells on the terminal's grid against omp's two:
            // the row overflows the panel.
            let last = shown_chars(lines[lines.len() - 1]);
            assert!(
                lines.iter().any(|line| shown_chars(line) != last),
                "the terminal draws ZWJ sequences off omp's grid"
            );
            continue;
        }
        let shown: Vec<String> = lines.iter().map(|line| captured_row(line)).collect();
        let mut want = layout_rows(text, width);
        want.resize(shown.len(), " ".repeat(width));
        assert_eq!(want, shown, "{name}");
        checked += 1;
    }
    assert_eq!(checked, 15);
}

/// #394 r3: an answer that wraps but fits the editor's rows is typed and
/// confirmed: 40 characters in a 32-cell, 4-row editor.
#[test]
fn a_wrapping_answer_that_fits_is_accepted() {
    let mut dialog = Dialog::new(VOICE_OVER);
    dialog.width = 40;
    assert_eq!(dialog.editor_width(), 32);
    let answer_text = "The new desk remembers how you work best.";
    let submitted = answer(&mut dialog, values(&[("vo", text(answer_text))])).unwrap();
    assert_eq!(value(&submitted, "vo"), txt(answer_text));
    // Two paragraphs that wrap within the four rows.
    let mut dialog = Dialog::new(VOICE_OVER);
    dialog.width = 40;
    let two = "Meet the new desk, built to last.\nIt keeps your notes close by.";
    let submitted = answer(&mut dialog, values(&[("vo", text(two))])).unwrap();
    assert_eq!(value(&submitted, "vo"), txt(two));
}

/// #394 r3: wrapping past the editor's rows is still refused before the
/// draft is touched.
#[test]
fn a_wrapping_answer_past_the_rows_is_too_long() {
    let mut dialog = Dialog::new(VOICE_OVER);
    dialog.width = 40;
    let before = dialog.lines[2].clone();
    let form = dialog.form.clone();
    let planned = plan(&form, &values(&[("vo", text(&"word ".repeat(40)))])).unwrap();
    let error = drive(&mut dialog, &form, &planned).unwrap_err().body;
    assert_eq!(
        error.message,
        "vo: too long to edit from the app; answer in the terminal"
    );
    assert_eq!(dialog.lines[2], before);
}

/// #394 r3: characters built from several code points (ZWJ emoji, a letter
/// plus a separate accent) cannot be confirmed on screen; precomposed
/// letters, CJK and single-code-point emoji can.
#[test]
fn combined_characters_are_refused_in_textareas() {
    let form = parse(VOICE_OVER);
    let refused = "vo: combined characters (emoji sequences, separate accent marks) cannot be checked on screen; answer in the terminal";
    for answer_text in ["Coding 👩\u{200d}💻 today", "Cafe\u{301}"] {
        let error = plan(&form, &values(&[("vo", text(answer_text))])).unwrap_err();
        assert_eq!(error.message, refused, "{answer_text:?}");
    }
    assert!(plan(&form, &values(&[("vo", text("Café 漢字 🙂"))])).is_ok());
}

/// #395: with omp's ascii symbol preset (`|` panel borders and field rail)
/// a textarea is still read and replaced.
#[test]
fn a_textarea_is_replaced_under_the_ascii_preset() {
    let mut dialog = Dialog::new(VOICE_OVER);
    dialog.ascii = true;
    let new = "Line one.\nLine two.";
    let submitted = answer(
        &mut dialog,
        values(&[("voice", options(&["crisp"])), ("vo", text(new))]),
    )
    .unwrap();
    assert_eq!(value(&submitted, "vo"), txt(new));
    assert_eq!(value(&submitted, "voice"), txt("crisp"));
}

/// Screens of a real omp 18.18.6 drawn with its ascii symbol preset
/// (`symbolPreset: ascii`), captured through a scratch herdr server.
const OMP_ASCII: &str = include_str!("omp-18.18.6-ascii-textarea.json");

/// #395: on a real ascii-preset screen the untouched form is recognised at
/// its start and the focused textarea's raw rows are read.
#[test]
fn a_real_ascii_preset_screen_is_read() {
    let fixture: serde_json::Value = serde_json::from_str(OMP_ASCII).unwrap();
    let form = parse(fixture["html"].as_str().unwrap());
    let start = fixture["start_screen"].as_str().unwrap();
    assert_eq!(start_state(start, &form), Ok(()), "{start}");
    let focused = fixture["textarea_focused_screen"].as_str().unwrap();
    let field = form
        .fields
        .iter()
        .position(|field| field.name == "notes")
        .unwrap();
    let FieldKind::Text(input) = &form.fields[field].kind else {
        unreachable!()
    };
    let rows = editor_rows(focused, &form, field, input.height()).expect("textarea rows");
    let width = cells(&rows[0]);
    let mut want = layout_rows(fixture["textarea_text"].as_str().unwrap(), width);
    want.resize(input.height(), " ".repeat(width));
    assert_eq!(rows, want);
}

/// #396: omp draws a validation error under the whole textarea; the row
/// after its last editor row is read, not the one after its first.
#[test]
fn an_error_under_a_textarea_is_read() {
    let html = r#"<form><label><input type="radio" name="r" value="a" checked> A</label>
<label><input type="radio" name="r" value="b"> B</label>
<label>Notes <textarea name="n" rows="4" required>keep me</textarea></label></form>"#;
    let mut dialog = Dialog::new(html);
    // Emptied in the terminal before the app answered.
    dialog.lines[1] = vec![String::new()];
    dialog.refuse = Some((1, "Required".into()));
    let form = dialog.form.clone();
    let planned = plan(&form, &BTreeMap::new()).unwrap();
    drive(&mut dialog, &form, &planned).unwrap();
    assert_eq!(dialog.submitted, None);
    assert_eq!(
        submit_error(&dialog.render(), &form),
        Some(("n".to_owned(), "Required".to_owned()))
    );
}

/// #396: the same on the real screen after omp refused the form's required
/// textarea, emptied in the terminal, with the app's answer that kept it.
#[test]
fn a_real_required_error_under_a_textarea_is_read() {
    let fixture: serde_json::Value = serde_json::from_str(OMP_ASCII).unwrap();
    let form = parse(fixture["html"].as_str().unwrap());
    let screen = fixture["required_refused_screen"].as_str().unwrap();
    assert_eq!(
        submit_error(screen, &form),
        Some(("notes".to_owned(), "Required".to_owned()))
    );
}

/// The textarea reader and the label/option readers share one set of frame
/// glyphs: every preset's `boxRound.vertical` is a row edge for both.
#[test]
fn every_preset_frame_is_a_row_edge() {
    use super::super::selector::RIGHT_EDGE;
    for glyph in BOX_VERTICAL {
        assert!(LEFT_EDGE.contains(&glyph), "{glyph}");
        assert!(RIGHT_EDGE.contains(&glyph), "{glyph}");
    }
}

/// Owner report (6d7a283): a form opened in a pane too short for its
/// context and its first stop shows page 1 of context, with the focus on
/// page 2. herdr brings the focus into view with ↑ and answers it.
#[test]
fn a_form_opened_on_a_context_page_is_answered() {
    let mut dialog = Dialog::new(FORM);
    dialog.context_page = true;
    dialog.redraw_lag = 2;
    let screen = dialog.render();
    assert_eq!(
        start_state(&screen, &dialog.form),
        Err(NotAtStart::FocusOffPage { page: 1, pages: 2 })
    );
    let submitted = answer(&mut dialog, BTreeMap::new()).unwrap();
    assert_eq!(value(&submitted, "db"), txt("pg"));
    assert_eq!(dialog.keys[0], "up", "↑ only revealed the focus");
}

/// The reveal never acts on a form someone moved in the terminal and then
/// paged back to its context: once the focus shows, it is not the first
/// stop, and nothing else is sent.
#[test]
fn a_moved_form_paged_back_is_still_refused() {
    let mut dialog = Dialog::new(FORM);
    dialog.focus = 2;
    dialog.context_page = true;
    // omp redraws a little after the key: one ↑ was sent, not another.
    dialog.redraw_lag = 2;
    let form = dialog.form.clone();
    let planned = plan(&form, &BTreeMap::new()).unwrap();
    let error = drive(&mut dialog, &form, &planned).unwrap_err().body;
    assert_eq!(error.code, "ask_form_moved");
    assert!(
        error
            .message
            .contains("the focus is not on the first field"),
        "{}",
        error.message
    );
    assert_eq!(dialog.keys, ["up"]);
    assert_eq!(dialog.submitted, None);
}

/// Real omp 18.18.8 screens of forms shaped like the ones the owner could
/// not answer from the app (6d7a283: the same layout, neutral text), opened
/// in a phone-sized pane: page 1 is context, the focus on a later page;
/// `after_up_screen` is the same form after one ↑. The last one leads with
/// a textarea.
const OMP_CONTEXT_PAGE: [&str; 3] = [
    include_str!("omp-18.18.8-context-page-52x30.json"),
    include_str!("omp-18.18.8-context-page-52x24.json"),
    include_str!("omp-18.18.8-context-page-textarea-52x22.json"),
];

#[test]
fn real_forms_opened_on_a_context_page_are_answered() {
    for fixture in OMP_CONTEXT_PAGE {
        let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
        let size = fixture["pane"].as_str().unwrap();
        let form = parse(fixture["html"].as_str().unwrap());
        let opened = fixture["opened_screen"].as_str().unwrap();
        let revealed = fixture["after_up_screen"].as_str().unwrap();
        let mut pane = Screens::new(&[opened, revealed]);
        let planned = plan(&form, &BTreeMap::new()).unwrap();
        // The screens stop changing after ↑, so the drive ends somewhere in
        // the form; what matters is that it got past the start check.
        let _ = drive(&mut pane, &form, &planned);
        assert_eq!(pane.sent.first(), Some(&Action::Keys(vec!["up"])), "{size}");
        assert!(pane.sent.len() > 2, "{size}: {:?}", pane.sent);
    }
}

#[test]
fn real_context_pages_read_as_the_focus_off_page() {
    for fixture in OMP_CONTEXT_PAGE {
        let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
        let size = fixture["pane"].as_str().unwrap();
        let form = parse(fixture["html"].as_str().unwrap());
        let opened = fixture["opened_screen"].as_str().unwrap();
        assert!(
            matches!(
                start_state(opened, &form),
                Err(NotAtStart::FocusOffPage { page: 1, .. })
            ),
            "{size}: {opened}"
        );
        let revealed = fixture["after_up_screen"].as_str().unwrap();
        assert_eq!(start_state(revealed, &form), Ok(()), "{size}: {revealed}");
    }
}

/// `ask_form_moved` says which check failed (owner report: the message
/// alone could not tell a moved focus from a misread screen).
#[test]
fn the_refusal_says_which_check_failed() {
    let fixture: serde_json::Value = serde_json::from_str(OMP_CONTEXT_PAGE[0]).unwrap();
    let form = parse(fixture["html"].as_str().unwrap());
    let revealed = fixture["after_up_screen"].as_str().unwrap();
    // Someone moved to the second option in the terminal.
    let moved = revealed
        .replacen("│ ❯ ◉", "│   ◉", 1)
        .replacen("│   ○", "│ ❯ ○", 1);
    let mut pane = Screens::new(&[&moved]);
    let planned = plan(&form, &BTreeMap::new()).unwrap();
    let error = drive(&mut pane, &form, &planned).unwrap_err().body;
    assert_eq!(error.code, "ask_form_moved");
    assert!(
        error
            .message
            .contains(": the focus is not on the first field "),
        "{}",
        error.message
    );
    assert!(pane.sent.is_empty(), "{:?}", pane.sent);
}

/// A pane that shows `screens[0]` until the first action, then the next
/// screens in turn (the last one repeats).
struct Screens {
    screens: Vec<String>,
    shown: usize,
    sent: Vec<Action>,
}

impl Screens {
    fn new(screens: &[&str]) -> Self {
        Self {
            screens: screens.iter().map(|screen| (*screen).to_owned()).collect(),
            shown: 0,
            sent: Vec::new(),
        }
    }
}

impl FormPane for Screens {
    fn read_screen(&mut self) -> Result<String, ErrorBody> {
        Ok(self.screens[self.shown].clone())
    }

    fn send(&mut self, action: &Action) -> Result<(), ErrorBody> {
        self.sent.push(action.clone());
        self.shown = (self.shown + 1).min(self.screens.len() - 1);
        Ok(())
    }

    fn pause(&mut self) {}
}

/// Review #405: a form opened on a context page while a draft sits in the
/// composer. The first ↑ only releases the draft; once the footer shows it
/// released, a second ↑ brings the focus into view, then the form is
/// answered. Each ↑ is sent once, after omp redrew.
#[test]
fn a_draft_and_a_context_page_are_each_passed_once() {
    let mut dialog = Dialog::new(FORM);
    dialog.draft = true;
    dialog.has_draft = true;
    dialog.context_page = true;
    dialog.redraw_lag = 2;
    let screen = dialog.render();
    assert!(draft_holds_keys(&screen), "{screen}");
    let submitted = answer(&mut dialog, BTreeMap::new()).unwrap();
    assert_eq!(value(&submitted, "db"), txt("pg"));
    assert_eq!(dialog.keys[..2], ["up", "up"], "release, then reveal");
    // The drive sends no fallback ↑ after a release it saw.
    assert_ne!(dialog.keys[2], "up", "{:?}", dialog.keys);
}

/// A draft on an ordinary page: one ↑ releases it, nothing else is needed.
#[test]
fn a_draft_is_released_once() {
    let mut dialog = Dialog::new(FORM);
    dialog.draft = true;
    dialog.has_draft = true;
    dialog.redraw_lag = 2;
    answer(&mut dialog, BTreeMap::new()).unwrap();
    assert_eq!(dialog.keys[0], "up");
    assert_ne!(dialog.keys[1], "up", "{:?}", dialog.keys);
}

/// A draft that keeps the keys after ↑ stops the drive with its own
/// reason; ↑ is not repeated and nothing reaches the draft.
#[test]
fn a_draft_that_keeps_the_keys_stops_the_drive() {
    let mut dialog = Dialog::new(FORM);
    dialog.draft = true;
    dialog.has_draft = true;
    dialog.draft_sticks = true;
    dialog.context_page = true;
    let form = dialog.form.clone();
    let planned = plan(&form, &BTreeMap::new()).unwrap();
    let error = drive(&mut dialog, &form, &planned).unwrap_err();
    assert_eq!(error.moved, Some(Moved::DraftHeld));
    assert_eq!(error.body.code, "ask_form_moved");
    assert_eq!(dialog.keys, ["up"]);
}

/// The check that failed travels apart from the message, so the log never
/// depends on the message's wording (which may quote a textarea).
#[test]
fn a_moved_drive_carries_its_check() {
    let mut dialog = Dialog::new(FORM);
    dialog.focus = 2;
    let form = dialog.form.clone();
    let planned = plan(&form, &BTreeMap::new()).unwrap();
    let error = drive(&mut dialog, &form, &planned).unwrap_err();
    assert_eq!(
        error.moved,
        Some(Moved::NotAtStart(NotAtStart::FocusNotFirst))
    );
}

/// A real omp 18.18.8 form opened in a 52x30 pane while a draft sat in the
/// composer (the panel, then the composer and status line under it): the
/// guard's footer on the context page, then (after one ↑)
/// the context page released, then (after another) the focus's page.
const OMP_DRAFT_CONTEXT_PAGE: &str = include_str!("omp-18.18.8-context-page-draft-52x30.json");

#[test]
fn a_real_draft_on_a_context_page_is_released_then_revealed() {
    let fixture: serde_json::Value = serde_json::from_str(OMP_DRAFT_CONTEXT_PAGE).unwrap();
    let form = parse(fixture["html"].as_str().unwrap());
    let opened = fixture["opened_screen"].as_str().unwrap();
    let released = fixture["after_release_screen"].as_str().unwrap();
    let revealed = fixture["after_reveal_screen"].as_str().unwrap();
    assert!(draft_holds_keys(opened), "{opened}");
    assert!(!draft_holds_keys(released), "{released}");
    assert!(matches!(
        start_state(released, &form),
        Err(NotAtStart::FocusOffPage { page: 1, .. })
    ));
    assert_eq!(start_state(revealed, &form), Ok(()));
    let mut pane = Screens::new(&[opened, released, revealed]);
    let planned = plan(&form, &BTreeMap::new()).unwrap();
    let _ = drive(&mut pane, &form, &planned);
    let up = Action::Keys(vec!["up"]);
    assert_eq!(pane.sent[..2], [up.clone(), up.clone()], "{:?}", pane.sent);
    assert_ne!(pane.sent.get(2), Some(&up), "{:?}", pane.sent);
}
