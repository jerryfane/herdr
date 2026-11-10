//! A port of omp's own HTML parser (`packages/utils/src/dom/parser.ts` at
//! v18.18.6) and the slice of its DOM the form parser reads.
//!
//! omp does not build a browser DOM: it tokenizes tags, closes a few optional
//! elements (`<p>`, `<li>`, `<td>`, …) when a sibling opens, decodes only a
//! fixed table of named entities plus numeric references, and keeps
//! everything else as written. Reading the agent's form exactly the way omp
//! reads it is what lets herdr predict the labels omp draws and the answers it
//! records, so this mirrors that parser instead of using a WHATWG one.

/// One node of the parsed tree.
#[derive(Debug)]
pub(crate) enum Node {
    Document,
    Element(Element),
    Text(String),
    Comment,
}

#[derive(Debug)]
pub(crate) struct Element {
    name: String,
    /// Lowercased names, first occurrence wins (as `parseStartTag` keeps it).
    attributes: Vec<(String, String)>,
    svg: bool,
}

impl Element {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl Node {
    pub(crate) fn as_element(&self) -> Option<&Element> {
        match self {
            Self::Element(element) => Some(element),
            _ => None,
        }
    }

    pub(crate) fn as_text(&self) -> Option<&String> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn is_element(&self) -> bool {
        matches!(self, Self::Element(_))
    }
}

struct Slot {
    node: Node,
    parent: Option<usize>,
    children: Vec<usize>,
}

/// A parsed document; node 0 is the document itself.
pub(crate) struct Document {
    nodes: Vec<Slot>,
}

/// A node of a [`Document`].
#[derive(Clone, Copy)]
pub(crate) struct NodeRef<'a> {
    document: &'a Document,
    id: usize,
}

impl<'a> NodeRef<'a> {
    pub(crate) fn id(&self) -> usize {
        self.id
    }

    pub(crate) fn value(&self) -> &'a Node {
        &self.document.nodes[self.id].node
    }

    fn at(&self, id: usize) -> Self {
        Self {
            document: self.document,
            id,
        }
    }

    /// Child nodes. A `<template>`'s children are its content fragment,
    /// which the DOM does not list as children (selectors never see them).
    pub(crate) fn children(&self) -> impl Iterator<Item = NodeRef<'a>> + use<'a> {
        let this = *self;
        let template = matches!(self.value(), Node::Element(element) if element.name == "template");
        let children: &'a [usize] = if template {
            &[]
        } else {
            &self.document.nodes[self.id].children
        };
        children.iter().map(move |&child| this.at(child))
    }

    /// This node and its descendants in document order, as selectors see
    /// them (template content left out).
    pub(crate) fn descendants(&self) -> impl Iterator<Item = NodeRef<'a>> + use<'a> {
        self.walk(false)
    }

    /// `textContent`: the text of every descendant, template content
    /// included (a template's `textContent` is its content's).
    pub(crate) fn text_content(&self) -> String {
        self.walk(true)
            .filter_map(|node| node.value().as_text().map(String::as_str))
            .collect()
    }

    fn walk(&self, templates: bool) -> impl Iterator<Item = NodeRef<'a>> + use<'a> {
        let mut stack = vec![*self];
        std::iter::from_fn(move || {
            let node = stack.pop()?;
            let children: &'a [usize] = if templates {
                &node.document.nodes[node.id].children
            } else {
                let template =
                    matches!(node.value(), Node::Element(element) if element.name == "template");
                if template {
                    &[]
                } else {
                    &node.document.nodes[node.id].children
                }
            };
            stack.extend(children.iter().rev().map(|&child| node.at(child)));
            Some(node)
        })
    }

    pub(crate) fn ancestors(&self) -> impl Iterator<Item = NodeRef<'a>> + use<'a> {
        let mut current = *self;
        std::iter::from_fn(move || {
            let parent = current.document.nodes[current.id].parent?;
            current = current.at(parent);
            Some(current)
        })
    }
}

impl Document {
    pub(crate) fn root(&self) -> NodeRef<'_> {
        NodeRef {
            document: self,
            id: 0,
        }
    }

    fn append(&mut self, parent: usize, node: Node) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Slot {
            node,
            parent: Some(parent),
            children: Vec::new(),
        });
        self.nodes[parent].children.push(id);
        id
    }

    fn is_svg(&self, id: usize) -> bool {
        matches!(&self.nodes[id].node, Node::Element(element) if element.svg)
    }

    fn name(&self, id: usize) -> &str {
        match &self.nodes[id].node {
            Node::Element(element) => &element.name,
            _ => "",
        }
    }
}

const VOID_ELEMENTS: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

fn close_on_open(incoming: &str) -> &'static [&'static str] {
    match incoming {
        "li" => &["li"],
        "dt" | "dd" => &["dt", "dd"],
        "tr" => &["tr"],
        "th" | "td" => &["th", "td"],
        "option" => &["option"],
        "thead" | "tbody" | "tfoot" => &["thead", "tbody", "tfoot"],
        _ => &[],
    }
}

const P_CLOSERS: [&str; 25] = [
    "address",
    "article",
    "aside",
    "blockquote",
    "div",
    "dl",
    "fieldset",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "menu",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "ul",
];

const NAMED_ENTITIES: &[(&str, &str)] = &[
    ("AElig", "Æ"),
    ("Aacute", "Á"),
    ("Acirc", "Â"),
    ("Agrave", "À"),
    ("Aring", "Å"),
    ("Atilde", "Ã"),
    ("Auml", "Ä"),
    ("Ccedil", "Ç"),
    ("ETH", "Ð"),
    ("Eacute", "É"),
    ("Ecirc", "Ê"),
    ("Egrave", "È"),
    ("Euml", "Ë"),
    ("Iacute", "Í"),
    ("Icirc", "Î"),
    ("Igrave", "Ì"),
    ("Iuml", "Ï"),
    ("Ntilde", "Ñ"),
    ("Oacute", "Ó"),
    ("Ocirc", "Ô"),
    ("Ograve", "Ò"),
    ("Oslash", "Ø"),
    ("Otilde", "Õ"),
    ("Ouml", "Ö"),
    ("THORN", "Þ"),
    ("Uacute", "Ú"),
    ("Ucirc", "Û"),
    ("Ugrave", "Ù"),
    ("Uuml", "Ü"),
    ("Yacute", "Ý"),
    ("aacute", "á"),
    ("acirc", "â"),
    ("aelig", "æ"),
    ("agrave", "à"),
    ("aring", "å"),
    ("atilde", "ã"),
    ("auml", "ä"),
    ("amp", "&"),
    ("apos", "'"),
    ("bull", "•"),
    ("brvbar", "¦"),
    ("ccedil", "ç"),
    ("cedil", "¸"),
    ("cent", "¢"),
    ("copy", "©"),
    ("deg", "°"),
    ("curren", "¤"),
    ("divide", "÷"),
    ("emsp", "\u{2003}"),
    ("ensp", "\u{2002}"),
    ("euro", "€"),
    ("eacute", "é"),
    ("ecirc", "ê"),
    ("egrave", "è"),
    ("eth", "ð"),
    ("euml", "ë"),
    ("frac12", "½"),
    ("frac14", "¼"),
    ("frac34", "¾"),
    ("gt", ">"),
    ("iacute", "í"),
    ("icirc", "î"),
    ("iexcl", "¡"),
    ("igrave", "ì"),
    ("iquest", "¿"),
    ("iuml", "ï"),
    ("hellip", "…"),
    ("laquo", "«"),
    ("ldquo", "“"),
    ("lsquo", "‘"),
    ("lt", "<"),
    ("mdash", "—"),
    ("macr", "¯"),
    ("micro", "µ"),
    ("middot", "·"),
    ("nbsp", "\u{a0}"),
    ("ndash", "–"),
    ("ntilde", "ñ"),
    ("oacute", "ó"),
    ("ocirc", "ô"),
    ("ograve", "ò"),
    ("ordf", "ª"),
    ("ordm", "º"),
    ("oslash", "ø"),
    ("otilde", "õ"),
    ("ouml", "ö"),
    ("para", "¶"),
    ("pound", "£"),
    ("plusmn", "±"),
    ("quot", "\""),
    ("raquo", "»"),
    ("rdquo", "”"),
    ("reg", "®"),
    ("rsquo", "’"),
    ("sect", "§"),
    ("shy", "\u{ad}"),
    ("szlig", "ß"),
    ("thorn", "þ"),
    ("sup1", "¹"),
    ("sup2", "²"),
    ("sup3", "³"),
    ("thinsp", "\u{2009}"),
    ("times", "×"),
    ("trade", "™"),
    ("uacute", "ú"),
    ("ucirc", "û"),
    ("ugrave", "ù"),
    ("uml", "¨"),
    ("uuml", "ü"),
    ("yacute", "ý"),
    ("yuml", "ÿ"),
    ("yen", "¥"),
];

fn named_entity(name: &str) -> Option<&'static str> {
    let find = |name: &str| {
        NAMED_ENTITIES
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| *value)
    };
    find(name).or_else(|| find(&name.to_lowercase()))
}

/// JS `\s` (WhiteSpace and LineTerminator): Rust's `is_whitespace` less
/// U+0085, which ECMAScript does not count, plus U+FEFF.
pub(crate) fn is_space(ch: char) -> bool {
    (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}'
}

/// `decodeEntities`: the named table, then valid numeric references;
/// anything else stays as written.
pub(crate) fn decode_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        match entity_at(tail) {
            Some((len, decoded)) => {
                out.push_str(&decoded);
                rest = &tail[len..];
            }
            None => {
                out.push('&');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The match of `(#(?:x[0-9a-f]+|\d+)|[a-z][a-z0-9]+);` (case-insensitive)
/// at the start of `tail` (after the `&`): its length including `;` and the
/// replacement.
fn entity_at(tail: &str) -> Option<(usize, String)> {
    let bytes = tail.as_bytes();
    if bytes.first() == Some(&b'#') {
        let hex = bytes
            .get(1)
            .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'x'));
        let digits_start = if hex { 2 } else { 1 };
        let digits = bytes[digits_start..]
            .iter()
            .take_while(|byte| {
                if hex {
                    byte.is_ascii_hexdigit()
                } else {
                    byte.is_ascii_digit()
                }
            })
            .count();
        let end = digits_start + digits;
        if digits == 0 || bytes.get(end) != Some(&b';') {
            // `&#x;` is not a hex reference, but `#x` never matches `\d+` either.
            return None;
        }
        let code = u32::from_str_radix(&tail[digits_start..end], if hex { 16 } else { 10 }).ok();
        let decoded = code
            .filter(|code| *code > 0)
            .and_then(char::from_u32)
            .map_or_else(|| "\u{fffd}".to_owned(), String::from);
        return Some((end + 1, decoded));
    }
    if !bytes.first()?.is_ascii_alphabetic() {
        return None;
    }
    let len = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric())
        .count();
    if len < 2 || bytes.get(len) != Some(&b';') {
        return None;
    }
    let decoded = named_entity(&tail[..len])?;
    Some((len + 1, decoded.to_owned()))
}

/// `findTagEnd`: the `>` closing a tag, skipping quoted runs; the last index
/// when there is none.
/// Returns where the tag's text ends and where parsing resumes: at the `>`
/// and just past it; without one, JS's `html.length - 1` (the start of the
/// last character) and the end of input.
fn find_tag_end(html: &str, start: usize) -> (usize, usize) {
    let mut quote = None;
    for (offset, ch) in html.get(start..).unwrap_or_default().char_indices() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == '>' => return (start + offset, start + offset + 1),
            None => {}
        }
    }
    let last = html.char_indices().last().map_or(0, |(index, _)| index);
    (last, html.len())
}

struct StartTag {
    name: String,
    attributes: Vec<(String, String)>,
    self_closing: bool,
}

fn skip_spaces(source: &str, index: usize) -> usize {
    index
        + source[index..]
            .char_indices()
            .find(|(_, ch)| !is_space(*ch))
            .map_or(source.len() - index, |(offset, _)| offset)
}

fn run_len(source: &str, index: usize, stop: impl Fn(char) -> bool) -> usize {
    source[index..]
        .char_indices()
        .find(|(_, ch)| stop(*ch))
        .map_or(source.len() - index, |(offset, _)| offset)
}

/// `parseStartTag`.
fn parse_start_tag(source: &str) -> Option<StartTag> {
    let mut index = skip_spaces(source, 0);
    let name_len = run_len(source, index, |ch| is_space(ch) || ch == '/' || ch == '>');
    if name_len == 0 {
        return None;
    }
    let name = source[index..index + name_len].to_lowercase();
    index += name_len;
    let mut attributes: Vec<(String, String)> = Vec::new();
    let mut self_closing = false;
    while index < source.len() {
        index = skip_spaces(source, index);
        if source[index..].starts_with('/') {
            self_closing = true;
            break;
        }
        let attr_len = run_len(source, index, |ch| {
            is_space(ch) || ch == '=' || ch == '/' || ch == '>'
        });
        if attr_len == 0 {
            break;
        }
        let attr_name = &source[index..index + attr_len];
        index += attr_len;
        index = skip_spaces(source, index);
        let mut value = "";
        if source[index..].starts_with('=') {
            index = skip_spaces(source, index + 1);
            match source[index..].chars().next() {
                Some(quote @ ('"' | '\'')) => {
                    index += 1;
                    match source[index..].find(quote) {
                        Some(end) => {
                            value = &source[index..index + end];
                            index += end + 1;
                        }
                        None => {
                            value = &source[index..];
                            index = source.len();
                        }
                    }
                }
                _ => {
                    let len = run_len(source, index, |ch| is_space(ch) || ch == '>');
                    value = &source[index..index + len];
                    index += len;
                }
            }
        }
        let lower = attr_name.to_lowercase();
        if !attributes.iter().any(|(existing, _)| *existing == lower) {
            attributes.push((lower, decode_entities(value)));
        }
    }
    Some(StartTag {
        name,
        attributes,
        self_closing,
    })
}

fn starts_with_ignore_case(html: &str, index: usize, prefix: &str) -> bool {
    html.get(index..index + prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

/// `</name\s*>` (case-insensitive) from `from`: (match start, match end).
fn find_raw_close(html: &str, from: usize, name: &str) -> Option<(usize, usize)> {
    let lower = html.to_ascii_lowercase();
    let needle = format!("</{name}");
    let mut search = from;
    while let Some(found) = lower[search..].find(&needle) {
        let start = search + found;
        let after = start + needle.len();
        let spaces = run_len(html, after, |ch| !is_space(ch));
        if html[after + spaces..].starts_with('>') {
            return Some((start, after + spaces + 1));
        }
        search = start + 1;
    }
    None
}

/// `parseDocument`.
pub(crate) fn parse_document(html: &str) -> Document {
    let mut document = Document {
        nodes: vec![Slot {
            node: Node::Document,
            parent: None,
            children: Vec::new(),
        }],
    };
    let xml_like = is_feed(html);
    let mut stack: Vec<usize> = Vec::new();
    let mut parent = 0;
    let mut index = 0;
    while index < html.len() {
        let rest = &html[index..];
        if rest.starts_with("<!--") {
            let end = html[index + 4..].find("-->").map(|end| index + 4 + end);
            document.append(parent, Node::Comment);
            index = end.map_or(html.len(), |end| end + 3);
            continue;
        }
        if !rest.starts_with('<') {
            let end = rest.find('<').map_or(html.len(), |next| index + next);
            document.append(parent, Node::Text(decode_entities(&html[index..end])));
            index = end;
            continue;
        }
        let next = rest[1..].chars().next();
        if next == Some('!') && starts_with_ignore_case(html, index, "<!doctype") && {
            // `\b` after doctype: the next character is not a word character.
            !html[index + 9..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        } {
            index = html[index + 2..]
                .find('>')
                .map_or(html.len(), |end| index + 2 + end + 1);
            continue;
        }
        if rest.starts_with("<![CDATA[") {
            let end = html[index + 9..].find("]]>").map(|end| index + 9 + end);
            let content_end = end.unwrap_or(html.len());
            document.append(parent, Node::Text(html[index + 9..content_end].to_owned()));
            index = end.map_or(html.len(), |end| end + 3);
            continue;
        }
        if next == Some('/') {
            let (end, resume) = find_tag_end(html, index + 2);
            let closing = html
                .get(index + 2..end.max(index + 2))
                .unwrap_or_default()
                .trim_matches(is_space)
                .split(is_space)
                .next()
                .unwrap_or_default()
                .to_lowercase();
            if let Some(position) = stack.iter().rposition(|&id| document.name(id) == closing) {
                stack.truncate(position);
            }
            parent = stack.last().copied().unwrap_or(0);
            index = resume;
            continue;
        }
        if next == Some('!') || next == Some('?') {
            index = html[index + 2..]
                .find('>')
                .map_or(html.len(), |end| index + 2 + end + 1);
            continue;
        }
        let (end, resume) = find_tag_end(html, index + 1);
        let Some(tag) =
            parse_start_tag(html.get(index + 1..end.max(index + 1)).unwrap_or_default())
        else {
            document.append(parent, Node::Text("<".into()));
            index += 1;
            continue;
        };
        if let Some(&current) = stack.last() {
            let current_name = document.name(current);
            if (current_name == "p" && P_CLOSERS.contains(&tag.name.as_str()))
                || close_on_open(&tag.name).contains(&current_name)
            {
                stack.pop();
            }
        }
        parent = stack.last().copied().unwrap_or(0);
        let svg = (parent != 0 && document.is_svg(parent)) || tag.name == "svg";
        let self_closing = tag.self_closing;
        let name = tag.name.clone();
        let element = document.append(
            parent,
            Node::Element(Element {
                name: tag.name,
                attributes: tag.attributes,
                svg,
            }),
        );
        index = resume;
        if (name == "script" || name == "style") && !self_closing {
            let close = find_raw_close(html, index.min(html.len()), &name);
            let raw_end = close.map_or(html.len(), |(start, _)| start);
            let raw = html.get(index..raw_end).unwrap_or_default().to_owned();
            document.append(element, Node::Text(raw));
            index = close.map_or(html.len(), |(_, end)| end);
            continue;
        }
        let is_void = if xml_like {
            self_closing
        } else {
            VOID_ELEMENTS.contains(&name.as_str()) || (svg && self_closing)
        };
        if !is_void {
            stack.push(element);
            parent = element;
        }
    }
    document
}

/// `/^\s*(?:<\?xml[\s\S]*?\?>\s*)?<(?:feed|rss)\b/i`.
fn is_feed(html: &str) -> bool {
    let mut rest = html.trim_start_matches(is_space);
    if starts_with_ignore_case(rest, 0, "<?xml") {
        let Some(end) = rest.find("?>") else {
            return false;
        };
        rest = rest[end + 2..].trim_start_matches(is_space);
    }
    ["<feed", "<rss"].into_iter().any(|prefix| {
        starts_with_ignore_case(rest, 0, prefix)
            && !rest[prefix.len()..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    })
}
