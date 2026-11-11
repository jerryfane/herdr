//! omp's HTML form `ask` (omp ≥ 18.18.3): the agent passes one `<form>` and
//! omp draws it as a terminal form. This is a port of upstream
//! `packages/tui/src/html-form/parse.ts` (what the form contains) and
//! `data.ts` (defaults, questions, answers and validation), so herdr sees the
//! same fields, options, defaults and "Other" answers omp's terminal shows,
//! and can predict the `details.answers` omp records for given values.
//!
//! Context text is kept as plain text: inline emphasis (`<b>`, `<code>`) only
//! matters for drawing, and every consumer here wants strings.

use std::collections::{HashMap, HashSet};

mod dom;

use dom::{Node, NodeRef};

#[cfg(test)]
use crate::api::schema::AskFormAnswer;
use crate::api::schema::{AskForm, AskFormField, AskFormFieldKind, AskFormOption, AskQuestion};

/// Label of the free-text answer omp adds to radio and checkbox groups.
pub(crate) const OTHER_LABEL: &str = "Other";

/// A parsed form: what omp draws, in document order.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ParsedForm {
    pub sections: Vec<Section>,
    /// Every control omp draws, named or not, in document (focus) order.
    pub fields: Vec<Field>,
    /// `<input type="hidden">` pairs; omp submits them itself.
    pub hidden: Vec<(String, String)>,
}

/// A `<fieldset>` (titled by its `<legend>`) or loose content between
/// fieldsets (untitled).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Section {
    pub title: String,
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Block {
    Text {
        text: String,
        heading: bool,
    },
    List {
        items: Vec<String>,
        ordered: bool,
    },
    Pre(String),
    Table(Vec<Vec<String>>),
    /// An `<img>` or inline `<svg>`: only its alt text survives.
    Picture {
        alt: String,
    },
    /// Index into [`ParsedForm::fields`].
    Field(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ChoiceOption {
    pub value: String,
    pub label: String,
    pub checked: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Choice {
    pub multi: bool,
    /// From a `<select>`: never has Other; a single select is a dropdown.
    pub select: bool,
    /// omp adds a free-text "Other" answer.
    pub other: bool,
    pub options: Vec<ChoiceOption>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TextInput {
    /// The `<input type>`, or `textarea`.
    pub input_type: String,
    pub multiline: bool,
    pub value: String,
    pub placeholder: String,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub pattern: Option<String>,
    pub min_length: Option<f64>,
    pub max_length: Option<f64>,
    /// Visible rows a textarea asked for (`rows`, default 4); 1 for inputs.
    pub rows: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FieldKind {
    Choice(Choice),
    Text(TextInput),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Field {
    pub name: String,
    /// The control's own label; empty for radio/checkbox groups. Text fields
    /// without one fall back to their name (`sentry_dsn` → `sentry dsn`).
    pub label: String,
    pub required: bool,
    pub kind: FieldKind,
}

impl Field {
    pub(crate) fn choice(&self) -> Option<&Choice> {
        match &self.kind {
            FieldKind::Choice(choice) => Some(choice),
            FieldKind::Text(_) => None,
        }
    }
}

impl TextInput {
    /// Rows omp's form gives this field (`#textareaRows`, dialog.ts:693-696):
    /// a textarea's fixed editor height, the `rows` asked for grown to fit
    /// the prefilled draft, 2 to 10; 1 for an input.
    pub(crate) fn height(&self) -> usize {
        if !self.multiline {
            return 1;
        }
        let draft = self.value.split('\n').count() as f64;
        self.rows.max(2.0).max(draft).min(10.0).ceil() as usize
    }
}

impl Choice {
    /// A single select draws as a one-row dropdown; multi-selects keep rows.
    pub(crate) fn is_dropdown(&self) -> bool {
        self.select && !self.multi
    }

    /// Whether the field reports an array rather than one value.
    pub(crate) fn is_array(&self) -> bool {
        self.multi && self.options.len() > 1
    }

    /// The options checked when the terminal form opens: for a single
    /// choice the last checked one wins, as in a browser (`#initChoice`).
    pub(crate) fn initial_checked(&self) -> Vec<usize> {
        let mut checked = self
            .options
            .iter()
            .enumerate()
            .filter(|(_, option)| option.checked)
            .map(|(index, _)| index);
        if self.multi {
            checked.collect()
        } else {
            checked.next_back().into_iter().collect()
        }
    }
}

/// A submitted value (`HtmlFormValue`): text, a number for `number`/`range`
/// inputs, or a group's checked values.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FormValue {
    Text(String),
    Number(f64),
    List(Vec<String>),
}

/// The `html` argument of an `ask` call, when it is a form ask.
pub(crate) fn form_html(arguments: Option<&serde_json::Value>) -> Option<&str> {
    arguments?.get("html")?.as_str()
}

const SKIPPED: [&str; 10] = [
    "button", "head", "iframe", "link", "meta", "noscript", "script", "style", "template", "title",
];
const BLOCK: [&str; 18] = [
    "address",
    "article",
    "aside",
    "blockquote",
    "dd",
    "details",
    "div",
    "dl",
    "dt",
    "figure",
    "figcaption",
    "footer",
    "header",
    "li",
    "main",
    "nav",
    "p",
    "section",
];
const HEADING: [&str; 7] = ["h1", "h2", "h3", "h4", "h5", "h6", "summary"];
const IGNORED_INPUTS: [&str; 5] = ["button", "file", "image", "reset", "submit"];

fn is_control(tag: &str) -> bool {
    matches!(tag, "input" | "select" | "textarea")
}

/// Parse agent-written form HTML; content outside the first `<form>` is
/// ignored when one exists.
pub(crate) fn parse(html: &str) -> ParsedForm {
    let document = dom::parse_document(html);
    let root = document
        .root()
        .descendants()
        .skip(1)
        .find(|node| tag(node) == Some("form"))
        .unwrap_or_else(|| document.root());
    Builder::new(root).build()
}

type Dom<'a> = NodeRef<'a>;

fn tag<'a>(node: &Dom<'a>) -> Option<&'a str> {
    node.value().as_element().map(|element| element.name())
}

fn attr<'a>(node: &Dom<'a>, name: &str) -> Option<&'a str> {
    node.value().as_element()?.attr(name)
}

fn has_attr(node: &Dom<'_>, name: &str) -> bool {
    attr(node, name).is_some()
}

fn text_content(node: &Dom<'_>) -> String {
    node.text_content()
}

fn element_children<'a>(node: &Dom<'a>) -> impl Iterator<Item = Dom<'a>> {
    node.children().filter(|child| child.value().is_element())
}

/// Descendant elements (not `node` itself) named `name`, in document order.
fn descendants_named<'a>(node: &Dom<'a>, pred: impl Fn(&str) -> bool) -> Vec<Dom<'a>> {
    node.descendants()
        .skip(1)
        .filter(|descendant| tag(descendant).is_some_and(&pred))
        .collect()
}

fn closest<'a>(node: &Dom<'a>, name: &str) -> Option<Dom<'a>> {
    std::iter::once(*node)
        .chain(node.ancestors())
        .find(|ancestor| tag(ancestor) == Some(name))
}

fn contains(outer: &Dom<'_>, inner: &Dom<'_>) -> bool {
    std::iter::once(*inner)
        .chain(inner.ancestors())
        .any(|ancestor| ancestor.id() == outer.id())
}

fn is_js_space(ch: char) -> bool {
    dom::is_space(ch)
}

/// Collapse whitespace like HTML layout does: runs become one space, spaces
/// next to a hard break vanish, and the ends are trimmed (`normalizeSpans`).
pub(crate) fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        if ch == '\n' {
            pending_space = false;
            if out.ends_with(' ') {
                out.pop();
            }
            out.push('\n');
        } else if is_js_space(ch) {
            pending_space = true;
        } else {
            if pending_space && !out.ends_with('\n') {
                out.push(' ');
            }
            pending_space = false;
            out.push(ch);
        }
    }
    out.trim_matches(is_js_space).to_owned()
}

/// Whitespace runs (newlines included) to one space, trimmed (`oneLine`).
pub(crate) fn one_line(text: &str) -> String {
    text.split(is_js_space)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// JS `Number(raw)` for attribute values: finite numbers only.
fn js_number(raw: &str) -> Option<f64> {
    let raw = raw.trim_matches(is_js_space);
    if raw.is_empty() {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    let radix = [("0x", 16), ("0o", 8), ("0b", 2)]
        .into_iter()
        .find_map(|(prefix, radix)| lower.strip_prefix(prefix).map(|digits| (digits, radix)));
    let value = match radix {
        Some((digits, radix)) => u64::from_str_radix(digits, radix).ok()? as f64,
        // Rust also reads `inf`/`nan` spellings JS does not; neither is finite.
        None if lower
            .chars()
            .any(|ch| ch.is_ascii_alphabetic() && ch != 'e') =>
        {
            return None
        }
        None => raw.parse::<f64>().ok()?,
    };
    value.is_finite().then_some(value)
}

fn number_attr(node: &Dom<'_>, name: &str) -> Option<f64> {
    js_number(attr(node, name)?)
}

/// JS `String(number)` (`Number::toString`, ECMA-262 §6.1.6.1.20): the
/// shortest round-trip digits, positional for exponents in (-7, 21), else
/// `d.ddde±n`.
pub(crate) fn js_number_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value == 0.0 {
        return "0".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // `{:e}` is Rust's shortest round-trip form: `d[.ddd]e<exp>`.
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("`{:e}` has an exponent");
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i64;
    // The decimal point sits after `n` digits.
    let n = exponent
        .parse::<i64>()
        .expect("`{:e}` exponent is an integer")
        + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let exponent = n - 1;
        let sign = if exponent < 0 { '-' } else { '+' };
        let mantissa = if k == 1 {
            digits
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!("{mantissa}e{sign}{}", exponent.abs())
    };
    format!("{sign}{body}")
}

struct Builder<'a> {
    root: Dom<'a>,
    sections: Vec<Section>,
    fields: Vec<Field>,
    hidden: Vec<(String, String)>,
    /// Radio/checkbox groups by `(type, name)`.
    groups: HashMap<(String, String), usize>,
    /// `<label for>` elements by the id of the control they name.
    label_for: HashMap<String, Dom<'a>>,
    inline: String,
    fieldset_depth: usize,
}

impl<'a> Builder<'a> {
    fn new(root: Dom<'a>) -> Self {
        Self {
            root,
            sections: vec![Section {
                title: String::new(),
                blocks: Vec::new(),
            }],
            fields: Vec::new(),
            hidden: Vec::new(),
            groups: HashMap::new(),
            label_for: HashMap::new(),
            inline: String::new(),
            fieldset_depth: 0,
        }
    }

    fn section(&mut self) -> &mut Section {
        self.sections.last_mut().expect("a section is always open")
    }

    fn build(mut self) -> ParsedForm {
        let ids: HashSet<&str> = descendants_named(&self.root, is_control)
            .iter()
            .filter_map(|control| attr(control, "id"))
            .filter(|id| !id.is_empty())
            .collect();
        for label in descendants_named(&self.root, |tag| tag == "label") {
            if let Some(target) = attr(&label, "for") {
                if ids.contains(target) && !self.label_for.contains_key(target) {
                    self.label_for.insert(target.to_owned(), label);
                }
            }
        }
        let root = self.root;
        self.children(&root);
        self.flush(false);
        for field in &mut self.fields {
            let FieldKind::Choice(choice) = &mut field.kind else {
                continue;
            };
            if choice.select || choice.options.len() < 2 {
                continue;
            }
            choice.other = !choice
                .options
                .iter()
                .any(|option| starts_with_other(&option.label));
        }
        ParsedForm {
            sections: self
                .sections
                .into_iter()
                .filter(|section| !section.blocks.is_empty() || !section.title.is_empty())
                .collect(),
            fields: self.fields,
            hidden: self.hidden,
        }
    }

    fn children(&mut self, node: &Dom<'a>) {
        for child in node.children() {
            self.walk(&child);
        }
    }

    fn walk(&mut self, node: &Dom<'a>) {
        let tag = match node.value() {
            Node::Text(text) => {
                self.inline.push_str(text);
                return;
            }
            Node::Element(element) => element.name(),
            _ => return,
        };
        if SKIPPED.contains(&tag) {
            return;
        }
        match tag {
            "br" => self.inline.push('\n'),
            "hr" => self.flush(false),
            "input" | "select" | "textarea" => self.control(node, None),
            "label" => self.label(node),
            "fieldset" => self.fieldset(node),
            "legend" => {
                self.flush(false);
                self.children(node);
                self.flush(true);
            }
            "ul" | "ol" => self.list(node, tag == "ol"),
            "pre" => {
                self.flush(false);
                let text = text_content(node);
                let text = text
                    .strip_prefix('\n')
                    .unwrap_or(&text)
                    .trim_end()
                    .to_owned();
                self.section().blocks.push(Block::Pre(text));
            }
            "table" => self.table(node),
            "img" => {
                if attr(node, "src").is_none_or(|src| src.trim().is_empty()) {
                    return;
                }
                self.flush(false);
                let alt = attr(node, "alt").unwrap_or_default().trim().to_owned();
                self.section().blocks.push(Block::Picture { alt });
            }
            "svg" => {
                self.flush(false);
                let alt = svg_title(node);
                self.section().blocks.push(Block::Picture { alt });
            }
            _ if HEADING.contains(&tag) => {
                self.flush(false);
                self.children(node);
                self.flush(true);
            }
            _ if BLOCK.contains(&tag) => {
                self.flush(false);
                self.children(node);
                self.flush(false);
            }
            _ => self.children(node),
        }
    }

    /// Emit buffered inline content as a text block.
    fn flush(&mut self, heading: bool) {
        let text = normalize(&std::mem::take(&mut self.inline));
        if !text.is_empty() {
            self.section().blocks.push(Block::Text { text, heading });
        }
    }

    fn label(&mut self, label: &Dom<'a>) {
        if let Some(target) = attr(label, "for") {
            if self
                .label_for
                .get(target)
                .is_some_and(|owner| owner.id() == label.id())
            {
                return;
            }
        }
        let controls = descendants_named(label, is_control);
        if controls.is_empty() {
            self.children(label);
            return;
        }
        self.flush(false);
        let text = spans_of(label);
        for control in controls {
            self.control(&control, Some(&text));
        }
    }

    fn fieldset(&mut self, fieldset: &Dom<'a>) {
        self.flush(false);
        let legend = element_children(fieldset).find(|child| tag(child) == Some("legend"));
        if self.fieldset_depth > 0 {
            // Nested fieldsets stay in the outer section; their legend becomes a heading.
            if let Some(legend) = &legend {
                self.walk(legend);
            }
        } else {
            let title = legend.as_ref().map(spans_of).unwrap_or_default();
            self.start_section(title);
        }
        self.fieldset_depth += 1;
        for child in fieldset.children() {
            if legend.is_some_and(|legend| legend.id() == child.id()) {
                continue;
            }
            self.walk(&child);
        }
        self.flush(false);
        self.fieldset_depth -= 1;
        if self.fieldset_depth == 0 {
            self.start_section(String::new());
        }
    }

    fn start_section(&mut self, title: String) {
        let section = self.section();
        if section.blocks.is_empty() && section.title.is_empty() {
            section.title = title;
            return;
        }
        self.sections.push(Section {
            title,
            blocks: Vec::new(),
        });
    }

    fn list(&mut self, list: &Dom<'a>, ordered: bool) {
        self.flush(false);
        if !descendants_named(list, is_control).is_empty() {
            // A list of controls is layout, not content: walk it as flow.
            self.children(list);
            self.flush(false);
            return;
        }
        let items: Vec<String> = element_children(list)
            .filter(|child| tag(child) == Some("li"))
            .map(|item| spans_of(&item))
            .filter(|text| !text.is_empty())
            .collect();
        if !items.is_empty() {
            self.section().blocks.push(Block::List { items, ordered });
        }
    }

    fn table(&mut self, table: &Dom<'a>) {
        self.flush(false);
        let rows: Vec<Dom<'a>> = descendants_named(table, |tag| tag == "tr")
            .into_iter()
            .filter(|row| closest(row, "table").is_some_and(|owner| owner.id() == table.id()))
            .collect();
        let cells_of = |row: &Dom<'a>| -> Vec<Dom<'a>> {
            element_children(row)
                .filter(|cell| matches!(tag(cell), Some("td" | "th")))
                .collect()
        };
        let has_control = |node: &Dom<'a>| !descendants_named(node, is_control).is_empty();
        if !has_control(table) {
            let cells: Vec<Vec<String>> = rows
                .iter()
                .map(|row| cells_of(row).iter().map(spans_of).collect())
                .collect();
            if cells.iter().any(|row| !row.is_empty()) {
                self.section().blocks.push(Block::Table(cells));
            }
            return;
        }
        // A table of controls (a decision matrix): each row's text becomes a line and each
        // unlabeled control borrows its column header as its label.
        let mut header: Vec<String> = Vec::new();
        for row in &rows {
            let cells = cells_of(row);
            if cells.iter().all(|cell| tag(cell) == Some("th")) && !has_control(row) {
                header = cells.iter().map(spans_of).collect();
                continue;
            }
            let text = cells
                .iter()
                .filter(|cell| !has_control(cell))
                .map(spans_of)
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
            if !text.is_empty() {
                self.section().blocks.push(Block::Text {
                    text,
                    heading: false,
                });
            }
            for (column, cell) in cells.iter().enumerate() {
                for control in descendants_named(cell, is_control) {
                    let own = closest(&control, "label").filter(|own| contains(cell, own));
                    let text = match own {
                        Some(own) => spans_of(&own),
                        None => spans_of(cell),
                    };
                    let text = if text.is_empty() {
                        header.get(column).cloned().unwrap_or_default()
                    } else {
                        text
                    };
                    self.control(&control, Some(&text));
                }
            }
        }
    }

    /// Label of a control outside any wrapping `<label>`: `<label for>`, then
    /// `aria-label`, `title`.
    fn detached_label(&self, control: &Dom<'a>) -> String {
        if let Some(label) = attr(control, "id").and_then(|id| self.label_for.get(id)) {
            return spans_of(label);
        }
        normalize(
            attr(control, "aria-label")
                .or_else(|| attr(control, "title"))
                .unwrap_or_default(),
        )
    }

    fn control(&mut self, control: &Dom<'a>, wrapping: Option<&str>) {
        self.flush(false);
        let label = match wrapping {
            Some(text) if !text.is_empty() => text.to_owned(),
            _ => self.detached_label(control),
        };
        let name = attr(control, "name").unwrap_or_default().to_owned();
        let required = has_attr(control, "required");
        match tag(control) {
            Some("select") => {
                let multi = has_attr(control, "multiple");
                let mut options: Vec<ChoiceOption> =
                    descendants_named(control, |tag| tag == "option")
                        .iter()
                        .map(|option| {
                            let text = one_line(&text_content(option));
                            ChoiceOption {
                                value: attr(option, "value")
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| text.clone()),
                                label: text,
                                checked: has_attr(option, "selected"),
                                disabled: has_attr(option, "disabled"),
                            }
                        })
                        .collect();
                // A single select always has a selection: the first enabled option unless one is marked.
                if !multi && !options.iter().any(|option| option.checked) {
                    if let Some(first) = options.iter_mut().find(|option| !option.disabled) {
                        first.checked = true;
                    }
                }
                self.add_field(Field {
                    name,
                    label,
                    required,
                    kind: FieldKind::Choice(Choice {
                        multi,
                        select: true,
                        other: false,
                        options,
                    }),
                });
            }
            Some("textarea") => {
                let label = if label.is_empty() {
                    name_label(&name)
                } else {
                    label
                };
                let text = text_content(control);
                let value = text
                    .strip_prefix("\r\n")
                    .or_else(|| text.strip_prefix('\n'))
                    .unwrap_or(&text)
                    .to_owned();
                self.add_field(Field {
                    name,
                    label,
                    required,
                    kind: FieldKind::Text(TextInput {
                        input_type: "textarea".into(),
                        multiline: true,
                        value,
                        placeholder: attr(control, "placeholder").unwrap_or_default().to_owned(),
                        min: None,
                        max: None,
                        pattern: None,
                        min_length: number_attr(control, "minlength"),
                        max_length: number_attr(control, "maxlength"),
                        rows: number_attr(control, "rows").unwrap_or(4.0),
                    }),
                });
            }
            _ => self.input(control, name, label, required),
        }
    }

    fn input(&mut self, control: &Dom<'a>, name: String, label: String, required: bool) {
        let input_type = attr(control, "type").unwrap_or("text").to_ascii_lowercase();
        if IGNORED_INPUTS.contains(&input_type.as_str()) {
            return;
        }
        let value = attr(control, "value");
        if input_type == "hidden" {
            if !name.is_empty() {
                self.hidden
                    .push((name, value.unwrap_or_default().to_owned()));
            }
            return;
        }
        if input_type == "radio" || input_type == "checkbox" {
            let option = ChoiceOption {
                value: value.unwrap_or("on").to_owned(),
                label: if label.is_empty() {
                    value.unwrap_or(&name).to_owned()
                } else {
                    label
                },
                checked: has_attr(control, "checked"),
                disabled: has_attr(control, "disabled"),
            };
            let key = (input_type.clone(), name.clone());
            if let Some(&index) = self.groups.get(&key) {
                let field = &mut self.fields[index];
                field.required |= required;
                if let FieldKind::Choice(choice) = &mut field.kind {
                    choice.options.push(option);
                }
                return;
            }
            self.groups.insert(key, self.fields.len());
            self.add_field(Field {
                name,
                label: String::new(),
                required,
                kind: FieldKind::Choice(Choice {
                    multi: input_type == "checkbox",
                    select: false,
                    other: false,
                    options: vec![option],
                }),
            });
            return;
        }
        let label = if label.is_empty() {
            name_label(&name)
        } else {
            label
        };
        self.add_field(Field {
            name,
            label,
            required,
            kind: FieldKind::Text(TextInput {
                input_type,
                multiline: false,
                value: value.unwrap_or_default().to_owned(),
                placeholder: attr(control, "placeholder").unwrap_or_default().to_owned(),
                min: number_attr(control, "min"),
                max: number_attr(control, "max"),
                pattern: attr(control, "pattern").map(str::to_owned),
                min_length: number_attr(control, "minlength"),
                max_length: number_attr(control, "maxlength"),
                rows: 1.0,
            }),
        });
    }

    fn add_field(&mut self, field: Field) {
        let index = self.fields.len();
        self.fields.push(field);
        self.section().blocks.push(Block::Field(index));
    }
}

/// An option label omp treats as the group's own Other (`/^\s*other\b/i`).
fn starts_with_other(label: &str) -> bool {
    let label = label.trim_start_matches(is_js_space);
    label.len() >= 5
        && label.is_char_boundary(5)
        && label[..5].eq_ignore_ascii_case("other")
        && !label[5..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// Last-resort label from the control name: `sentry_dsn` → `sentry dsn`.
fn name_label(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for ch in name.chars() {
        if ch == '_' || ch == '-' {
            if !in_run {
                out.push(' ');
            }
            in_run = true;
        } else {
            in_run = false;
            out.push(ch);
        }
    }
    out
}

/// An inline svg's accessible name: its `aria-label`, else its `<title>`.
fn svg_title(svg: &Dom<'_>) -> String {
    if let Some(label) = attr(svg, "aria-label").filter(|label| !label.is_empty()) {
        return label.trim().to_owned();
    }
    element_children(svg)
        .find(|child| tag(child) == Some("title"))
        .map(|title| one_line(&text_content(&title)))
        .unwrap_or_default()
}

/// Inline text of `element`, skipping controls (their label is the text
/// around them).
fn spans_of(element: &Dom<'_>) -> String {
    fn visit(node: &Dom<'_>, out: &mut String) {
        let tag = match node.value() {
            Node::Text(text) => {
                out.push_str(text);
                return;
            }
            Node::Element(element) => element.name(),
            _ => return,
        };
        if SKIPPED.contains(&tag) || is_control(tag) || tag == "svg" {
            return;
        }
        if tag == "br" {
            out.push('\n');
            return;
        }
        // Labels stay text: a picture inside one reads as its alt text.
        if tag == "img" {
            out.push_str(attr(node, "alt").unwrap_or_default());
            return;
        }
        if BLOCK.contains(&tag) || HEADING.contains(&tag) {
            out.push(' ');
        }
        for child in node.children() {
            visit(&child, out);
        }
    }
    let mut out = String::new();
    for child in element.children() {
        visit(&child, &mut out);
    }
    normalize(&out)
}

impl ParsedForm {
    /// The question each field answers (`fieldQuestions`): its own label,
    /// else the text block right before it, else its section title, else a
    /// lone option's label, else its name.
    pub(crate) fn questions(&self) -> Vec<String> {
        let mut questions = vec![String::new(); self.fields.len()];
        for section in &self.sections {
            let mut caption = "";
            for block in &section.blocks {
                match block {
                    Block::Field(index) => {
                        let field = &self.fields[*index];
                        let lone = match field.choice() {
                            Some(choice) if choice.options.len() == 1 => {
                                choice.options[0].label.as_str()
                            }
                            _ => "",
                        };
                        let question = [
                            field.label.as_str(),
                            caption,
                            section.title.as_str(),
                            lone,
                            field.name.as_str(),
                        ]
                        .into_iter()
                        .find(|text| !text.is_empty())
                        .unwrap_or_default();
                        questions[*index] = one_line(question);
                        caption = "";
                    }
                    Block::Text { text, .. } => caption = text,
                    _ => caption = "",
                }
            }
        }
        questions
    }

    /// The value a field submits untouched: its initially checked options or
    /// prefilled text.
    #[cfg(test)]
    pub(crate) fn default_value(&self, field: &Field) -> Option<FormValue> {
        match &field.kind {
            FieldKind::Text(input) => Some(text_value(input, &input.value)),
            FieldKind::Choice(choice) => choice_value(choice, &choice.initial_checked(), None),
        }
    }

    /// The name-keyed data omp submits for `data` (each field's value, in
    /// form order): hidden inputs first, then every named field that gives
    /// a value, so a field that gives none (an unchecked lone checkbox)
    /// reads the hidden input of its name. One entry per named field.
    pub(crate) fn submission(
        &self,
        data: &[Option<FormValue>],
    ) -> Vec<(String, Option<FormValue>)> {
        let mut submitted: HashMap<&str, FormValue> = self
            .hidden
            .iter()
            .map(|(name, value)| (name.as_str(), FormValue::Text(value.clone())))
            .collect();
        for (field, value) in self.fields.iter().zip(data) {
            if let (false, Some(value)) = (field.name.is_empty(), value) {
                submitted.insert(field.name.as_str(), value.clone());
            }
        }
        let mut seen = HashSet::new();
        self.fields
            .iter()
            .filter(|field| !field.name.is_empty() && seen.insert(field.name.as_str()))
            .map(|field| {
                (
                    field.name.clone(),
                    submitted.get(field.name.as_str()).cloned(),
                )
            })
            .collect()
    }

    /// `details.answers` omp records for `data` (`formAnswers`): every named
    /// field in form order, option values shown as their labels.
    #[cfg(test)]
    pub(crate) fn answers(&self, data: &[Option<FormValue>]) -> Vec<AskFormAnswer> {
        let submitted: HashMap<String, Option<FormValue>> =
            self.submission(data).into_iter().collect();
        let questions = self.questions();
        self.fields
            .iter()
            .zip(questions)
            .filter(|(field, _)| !field.name.is_empty())
            .map(|(field, question)| AskFormAnswer {
                name: field.name.clone(),
                question: if question.is_empty() {
                    field.name.clone()
                } else {
                    question
                },
                answer: answer_text(field, submitted.get(&field.name).and_then(Option::as_ref)),
            })
            .collect()
    }

    /// The form as `agent.transcript` serves it.
    pub(crate) fn to_wire(&self) -> AskForm {
        let mut intro: Vec<String> = Vec::new();
        let mut pending: Vec<String> = Vec::new();
        let mut seen_field = false;
        let mut fields = Vec::new();
        for section in &self.sections {
            if !seen_field && !section.title.is_empty() {
                intro.append(&mut pending);
            }
            let in_section = section
                .blocks
                .iter()
                .filter(|block| matches!(block, Block::Field(index) if !self.fields[*index].name.is_empty()))
                .count();
            for block in &section.blocks {
                let Block::Field(index) = block else {
                    pending.extend(block_text(block));
                    continue;
                };
                if !seen_field && section.title.is_empty() {
                    intro.append(&mut pending);
                }
                seen_field = true;
                let description = joined(std::mem::take(&mut pending));
                let field = &self.fields[*index];
                if field.name.is_empty() {
                    continue;
                }
                let title =
                    if !section.title.is_empty() && (in_section == 1 || field.label.is_empty()) {
                        Some(section.title.clone())
                    } else if !field.label.is_empty() {
                        Some(field.label.clone())
                    } else {
                        None
                    };
                fields.push(wire_field(field, title, description));
            }
        }
        AskForm {
            intro: joined(intro),
            fields,
        }
    }

    /// One compatibility question per choice field, for apps that predate
    /// `form`. `form` is [`Self::to_wire`]'s output, whose fields are the
    /// named fields in the same order, so each pairs with its own title even
    /// when names repeat.
    pub(crate) fn compat_questions(&self, form: &AskForm) -> Vec<AskQuestion> {
        let questions = self.questions();
        self.fields
            .iter()
            .zip(questions)
            .filter(|(field, _)| !field.name.is_empty())
            .zip(&form.fields)
            .filter_map(|((field, question), wire)| {
                let choice = field.choice()?;
                let title = wire.title.as_deref();
                Some(AskQuestion {
                    question: title.map_or(question, str::to_owned),
                    options: choice
                        .options
                        .iter()
                        .map(|option| option.label.clone())
                        .collect(),
                    multi: choice.multi,
                    recommended: choice
                        .initial_checked()
                        .first()
                        .and_then(|index| u32::try_from(*index).ok()),
                })
            })
            .collect()
    }

    /// herdr can answer the form by keys (`pending_ask.form_answerable`).
    pub(crate) fn drivable(&self) -> bool {
        self.refusal().is_none()
    }

    /// Why herdr cannot answer the form by keys, `None` when it can: it
    /// needs a named field, and no two named fields sharing a name (a value
    /// could not say which it means).
    pub(crate) fn refusal(&self) -> Option<&'static str> {
        let mut names = HashSet::new();
        let mut any = false;
        for field in &self.fields {
            if field.name.is_empty() {
                continue;
            }
            any = true;
            if !names.insert(field.name.as_str()) {
                return Some("the form has two fields with the same name: answer in the terminal");
            }
        }
        (!any).then_some("the form has no named field: answer in the terminal")
    }
}

fn joined(parts: Vec<String>) -> Option<String> {
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

/// Plain text of a context block; pictures without alt text drop.
fn block_text(block: &Block) -> Option<String> {
    let text = match block {
        Block::Text { text, .. } | Block::Pre(text) => text.clone(),
        Block::List { items, ordered } => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                if *ordered {
                    format!("{}. {item}", index + 1)
                } else {
                    format!("• {item}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Block::Table(rows) => rows
            .iter()
            .map(|row| row.join(" · "))
            .filter(|row| !row.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Block::Picture { alt } => alt.clone(),
        Block::Field(_) => return None,
    };
    (!text.is_empty()).then_some(text)
}

fn wire_number(value: Option<f64>) -> Option<serde_json::Number> {
    let value = value?;
    if value.fract() == 0.0 && value.abs() < 9.0e15 {
        Some(serde_json::Number::from(value as i64))
    } else {
        serde_json::Number::from_f64(value)
    }
}

fn wire_length(value: Option<f64>) -> Option<u64> {
    value
        .filter(|value| *value >= 0.0)
        .map(|value| value.ceil() as u64)
}

fn wire_field(field: &Field, title: Option<String>, description: Option<String>) -> AskFormField {
    let mut wire = AskFormField {
        name: field.name.clone(),
        kind: AskFormFieldKind::Choice,
        title,
        description,
        multi: false,
        select: false,
        other: false,
        required: field.required,
        options: Vec::new(),
        input_type: None,
        placeholder: None,
        value: None,
        min: None,
        max: None,
        minlength: None,
        maxlength: None,
        pattern: None,
    };
    match &field.kind {
        FieldKind::Choice(choice) => {
            let checked = choice.initial_checked();
            wire.multi = choice.multi;
            wire.select = choice.select;
            wire.other = choice.other;
            wire.options = choice
                .options
                .iter()
                .enumerate()
                .map(|(index, option)| AskFormOption {
                    value: option.value.clone(),
                    label: option.label.clone(),
                    checked: checked.contains(&index),
                    disabled: option.disabled,
                })
                .collect();
        }
        FieldKind::Text(input) => {
            wire.kind = AskFormFieldKind::Text;
            wire.input_type = Some(input.input_type.clone());
            wire.placeholder = (!input.placeholder.is_empty()).then(|| input.placeholder.clone());
            wire.value = (!input.value.is_empty()).then(|| input.value.clone());
            wire.min = wire_number(input.min);
            wire.max = wire_number(input.max);
            wire.minlength = wire_length(input.min_length);
            wire.maxlength = wire_length(input.max_length);
            wire.pattern = input.pattern.clone();
        }
    }
    wire
}

/// The value a choice field contributes (`choiceValue`): checked enabled
/// option values plus, when chosen, the Other text. Blank Other is no answer.
pub(crate) fn choice_value(
    choice: &Choice,
    checked: &[usize],
    other: Option<&str>,
) -> Option<FormValue> {
    let typed = if choice.other {
        other
            .map(|text| text.trim_matches(is_js_space))
            .filter(|text| !text.is_empty())
    } else {
        None
    };
    let mut values: Vec<String> = choice
        .options
        .iter()
        .enumerate()
        .filter(|(index, option)| checked.contains(index) && !option.disabled)
        .map(|(_, option)| option.value.clone())
        .collect();
    if choice.is_array() {
        values.extend(typed.map(str::to_owned));
        return Some(FormValue::List(values));
    }
    typed
        .map(str::to_owned)
        .or_else(|| values.into_iter().next())
        .map(FormValue::Text)
}

/// The value a text field contributes (`textValue`): a number for non-empty
/// numeric `number`/`range` inputs, else the text.
pub(crate) fn text_value(input: &TextInput, text: &str) -> FormValue {
    if matches!(input.input_type.as_str(), "number" | "range") && !text.trim().is_empty() {
        if let Some(number) = js_number(text) {
            return FormValue::Number(number);
        }
    }
    FormValue::Text(text.to_owned())
}

#[cfg(test)]
fn answer_text(field: &Field, value: Option<&FormValue>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    let choice = match (&field.kind, value) {
        (FieldKind::Choice(choice), _) => choice,
        (FieldKind::Text(_), FormValue::Number(number)) => return js_number_string(*number),
        (FieldKind::Text(_), FormValue::Text(text)) => return text.clone(),
        (FieldKind::Text(_), FormValue::List(items)) => return items.join(","),
    };
    let label_of = |raw: &str| -> String {
        if let Some(option) = choice.options.iter().find(|option| option.value == raw) {
            let label = one_line(&option.label);
            return if label.is_empty() {
                raw.to_owned()
            } else {
                label
            };
        }
        if choice.other {
            format!("{OTHER_LABEL}: {raw}")
        } else {
            raw.to_owned()
        }
    };
    match value {
        FormValue::List(items) => items
            .iter()
            .map(|item| label_of(item))
            .collect::<Vec<_>>()
            .join(", "),
        FormValue::Text(text) => label_of(text),
        FormValue::Number(number) => label_of(&js_number_string(*number)),
    }
}

/// Why `value` is not an acceptable answer for `field` (`fieldError`), or
/// `None` when it is.
pub(crate) fn field_error(field: &Field, value: Option<&FormValue>) -> Option<String> {
    let input = match &field.kind {
        FieldKind::Choice(choice) => {
            let empty = match value {
                None => true,
                Some(FormValue::List(items)) => items.is_empty(),
                Some(_) => false,
            };
            if !field.required || !empty {
                return None;
            }
            return Some(if choice.is_array() {
                "Select at least one".into()
            } else {
                "Required".into()
            });
        }
        FieldKind::Text(input) => input,
    };
    let text = match value {
        None => String::new(),
        Some(FormValue::Text(text)) => text.clone(),
        Some(FormValue::Number(number)) => js_number_string(*number),
        Some(FormValue::List(items)) => items.join(","),
    };
    if text.trim_matches(is_js_space).is_empty() {
        return field.required.then(|| "Required".into());
    }
    if matches!(input.input_type.as_str(), "number" | "range") {
        let Some(number) = js_number(&text) else {
            return Some("Enter a number".into());
        };
        if let Some(min) = input.min.filter(|min| number < *min) {
            return Some(format!("Must be at least {}", js_number_string(min)));
        }
        if let Some(max) = input.max.filter(|max| number > *max) {
            return Some(format!("Must be at most {}", js_number_string(max)));
        }
    }
    let length = text.encode_utf16().count() as f64;
    if let Some(min) = input.min_length.filter(|min| length < *min) {
        return Some(format!(
            "Needs at least {} characters",
            js_number_string(min)
        ));
    }
    if let Some(max) = input.max_length.filter(|max| length > *max) {
        return Some(format!("At most {} characters", js_number_string(max)));
    }
    if input.input_type == "email" && !is_email(&text) {
        return Some("Enter an email address".into());
    }
    if input.input_type == "url" && !is_url(&text) {
        return Some("Enter a full URL".into());
    }
    // `pattern` is left to omp: it checks an ECMAScript `v`-flag regex on
    // Submit, and `agent.answer_form` reads the error omp then shows.
    None
}

/// `/^[^\s@]+@[^\s@]+$/`.
fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    let ok =
        |part: &str| !part.is_empty() && !part.contains(|ch: char| is_js_space(ch) || ch == '@');
    ok(local) && ok(domain)
}

/// An approximation of `URL.canParse`: a scheme, and for the special web
/// schemes a host.
fn is_url(text: &str) -> bool {
    let text = text.trim_matches(is_js_space);
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    if !chars.next().is_some_and(|ch| ch.is_ascii_alphabetic())
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
    {
        return false;
    }
    if matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ws" | "wss" | "ftp"
    ) {
        let host = rest.trim_start_matches(['/', '\\']);
        let host = host.split(['/', '\\', '?', '#']).next().unwrap_or_default();
        return !host.is_empty() && !host.contains(is_js_space);
    }
    true
}

#[cfg(test)]
mod tests;
