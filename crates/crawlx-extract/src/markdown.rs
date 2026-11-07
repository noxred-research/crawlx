//! Deterministic HTML to Markdown conversion.
//!
//! The converter walks the filtered content tree in two modes:
//!
//! * a *flow* (block) context that groups consecutive inline content into
//!   paragraphs and renders headings, lists, code blocks, blockquotes, tables
//!   and definition lists as separate blocks joined by one blank line;
//! * an *inline* context that renders emphasis, code spans, links and images
//!   and degrades block elements it meets (for example a `div` inside an
//!   `a`) to space-separated text.
//!
//! Whitespace is collapsed in one pass per inline run, so output never
//! contains more than one blank line between blocks. Characters that would
//! change the Markdown meaning of text are backslash-escaped.

use url::Url;

use crate::dom::{collapse_ws, image_src, is_safe_link_scheme, pre_text, resolve, Elem, Node};
use crate::tables;

/// Marks a `<br>` inside an inline run until whitespace collapsing is done.
const HARD_BREAK: char = '\u{1}';

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    Cell,
    Heading,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Para,
    List,
    Other,
}

struct Block {
    text: String,
    kind: Kind,
}

struct Cx<'a> {
    base: &'a Url,
    /// Emit `data:image/...` sources instead of dropping the image.
    keep_data_images: bool,
}

/// Convert content nodes to Markdown. Relative URLs are resolved against `base`; `data:image/...`
/// sources are kept (verbatim) only when `keep_data_images` is set.
#[must_use]
pub fn to_markdown(nodes: &[Node], base: &Url, keep_data_images: bool) -> String {
    let cx = Cx {
        base,
        keep_data_images,
    };
    join_blocks(&run(nodes, &cx, None))
}

/// Preserve final privacy-redacted text while escaping Markdown interpretation.
pub(crate) fn redacted_plain_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    push_text(&mut escaped, text, Mode::Normal);
    escape_line_starts(&escaped)
}

fn join_blocks(blocks: &[Block]) -> String {
    let mut s = String::new();
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            s.push_str("\n\n");
        }
        s.push_str(&b.text);
    }
    s
}

fn run(nodes: &[Node], cx: &Cx<'_>, hint: Option<&str>) -> Vec<Block> {
    let mut f = Flow {
        cx,
        out: Vec::new(),
        inline: String::new(),
        hint: hint.map(str::to_owned),
    };
    for n in nodes {
        f.node(n);
    }
    f.flush();
    f.out
}

const CONTAINERS: &[&str] = &[
    "div",
    "section",
    "article",
    "main",
    "header",
    "footer",
    "nav",
    "aside",
    "figure",
    "figcaption",
    "details",
    "summary",
    "form",
    "fieldset",
    "legend",
    "address",
    "center",
    "hgroup",
    "dialog",
    "body",
    "html",
    "li",
    "dd",
    "dt",
    "tbody",
    "thead",
    "tfoot",
    "tr",
    "td",
    "th",
    "caption",
    "colgroup",
    "col",
    "search",
];

const INLINE_FORMAT: &[&str] = &[
    "a", "em", "i", "cite", "dfn", "var", "strong", "b", "del", "s", "strike", "code", "kbd", "samp", "tt",
    "q", "img", "wbr",
];

fn is_heading(tag: &str) -> Option<usize> {
    match tag {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        "h5" => Some(5),
        "h6" => Some(6),
        _ => None,
    }
}

fn is_block_like(tag: &str) -> bool {
    is_heading(tag).is_some()
        || CONTAINERS.contains(&tag)
        || matches!(
            tag,
            "p" | "ul" | "ol" | "menu" | "dl" | "pre" | "blockquote" | "hr" | "table"
        )
}

struct Flow<'a> {
    cx: &'a Cx<'a>,
    out: Vec<Block>,
    inline: String,
    hint: Option<String>,
}

impl Flow<'_> {
    fn flush(&mut self) {
        let raw = std::mem::take(&mut self.inline);
        let s = finish_inline(&raw, Mode::Normal);
        if !s.is_empty() {
            self.out.push(Block {
                text: s,
                kind: Kind::Para,
            });
        }
    }

    fn push(&mut self, text: String, kind: Kind) {
        self.flush();
        if !text.is_empty() {
            self.out.push(Block { text, kind });
        }
    }

    fn node(&mut self, n: &Node) {
        match n {
            Node::Text(t) => push_text(&mut self.inline, t, Mode::Normal),
            Node::Elem(e) => self.elem(e),
        }
    }

    fn elem(&mut self, e: &Elem) {
        let tag = e.tag.as_str();
        if let Some(level) = is_heading(tag) {
            let mut raw = String::new();
            inline_nodes(&e.children, self.cx, Mode::Heading, &mut raw);
            let text = finish_inline_raw(&raw, Mode::Heading);
            if !text.is_empty() {
                self.push(format!("{} {}", "#".repeat(level), text), Kind::Other);
            }
            return;
        }
        match tag {
            "p" => {
                self.flush();
                let mut raw = String::new();
                inline_nodes(&e.children, self.cx, Mode::Normal, &mut raw);
                let s = finish_inline(&raw, Mode::Normal);
                if !s.is_empty() {
                    self.out.push(Block {
                        text: s,
                        kind: Kind::Para,
                    });
                }
            }
            "ul" | "ol" | "menu" => {
                if let Some(text) = list(e, self.cx) {
                    self.push(text, Kind::List);
                }
            }
            "pre" => {
                if let Some(text) = code_block(e, self.hint.as_deref()) {
                    self.push(text, Kind::Other);
                }
            }
            "blockquote" => {
                let inner = join_blocks(&run(&e.children, self.cx, None));
                if !inner.is_empty() {
                    let quoted = inner
                        .split('\n')
                        .map(|l| {
                            if l.is_empty() {
                                ">".to_owned()
                            } else {
                                format!("> {l}")
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.push(quoted, Kind::Other);
                }
            }
            "hr" => self.push("---".to_owned(), Kind::Other),
            "table" => self.table(e),
            "dl" => {
                if let Some(text) = definition_list(e, self.cx) {
                    self.push(text, Kind::Other);
                }
            }
            "br" => self.inline.push(HARD_BREAK),
            _ if CONTAINERS.contains(&tag) => {
                self.flush();
                let saved = self.hint.clone();
                if tag == "div" || tag == "figure" || tag == "section" {
                    if let Some(l) = container_language(e) {
                        self.hint = Some(l);
                    }
                }
                for c in &e.children {
                    self.node(c);
                }
                self.hint = saved;
                self.flush();
            }
            _ if INLINE_FORMAT.contains(&tag) => inline_elem(e, self.cx, Mode::Normal, &mut self.inline),
            "video" | "audio" | "rt" | "rp" => {}
            // Unknown or purely presentational elements are transparent.
            _ => {
                for c in &e.children {
                    self.node(c);
                }
            }
        }
    }

    fn table(&mut self, e: &Elem) {
        let model = tables::collect(e);
        if let Some(cell) = model.single_cell() {
            // Layout table: render the content of its only cell as blocks.
            self.flush();
            for c in &cell.children {
                self.node(c);
            }
            self.flush();
            return;
        }
        let cx = self.cx;
        let rendered = model.render(&mut |cell: &Elem| {
            let mut raw = String::new();
            inline_nodes(&cell.children, cx, Mode::Cell, &mut raw);
            finish_inline_raw(&raw, Mode::Cell)
        });
        if let Some(caption) = model.caption {
            let mut raw = String::new();
            inline_nodes(&caption.children, cx, Mode::Normal, &mut raw);
            let text = finish_inline(&raw, Mode::Normal);
            if !text.is_empty() {
                self.push(text, Kind::Para);
            }
        }
        if let Some(t) = rendered {
            self.push(t, Kind::Other);
        }
    }
}

// ---------------------------------------------------------------- inline ----

fn inline_nodes(nodes: &[Node], cx: &Cx<'_>, mode: Mode, out: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) => push_text(out, t, mode),
            Node::Elem(e) => inline_elem(e, cx, mode, out),
        }
    }
}

fn wrap(out: &mut String, marker: &str, inner: &str) {
    let trimmed = inner.trim_matches(char::is_whitespace);
    if trimmed.is_empty() {
        if !inner.is_empty() {
            out.push(' ');
        }
        return;
    }
    if inner.starts_with(char::is_whitespace) {
        out.push(' ');
    }
    out.push_str(marker);
    out.push_str(trimmed);
    out.push_str(marker);
    if inner.ends_with(char::is_whitespace) {
        out.push(' ');
    }
}

fn raw_code_text(nodes: &[Node], s: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) => s.push_str(t),
            Node::Elem(e) if e.tag == "br" => s.push(' '),
            Node::Elem(e) => raw_code_text(&e.children, s),
        }
    }
}

fn code_span(nodes: &[Node], mode: Mode) -> String {
    let mut raw = String::new();
    raw_code_text(nodes, &mut raw);
    let mut t = collapse_ws(&raw);
    t.retain(|c| c != HARD_BREAK);
    if t.is_empty() {
        return String::new();
    }
    if mode == Mode::Cell {
        t = t.replace('|', "\\|");
    }
    let mut longest = 0usize;
    let mut run = 0usize;
    for c in t.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat(longest + 1);
    let pad = if t.starts_with('`') || t.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{t}{pad}{fence}")
}

fn fmt_dest(u: &Url) -> String {
    u.as_str().replace('(', "%28").replace(')', "%29")
}

fn inline_elem(e: &Elem, cx: &Cx<'_>, mode: Mode, out: &mut String) {
    let children = |out: &mut String| inline_nodes(&e.children, cx, mode, out);
    match e.tag.as_str() {
        "em" | "i" | "cite" | "dfn" | "var" => {
            let mut inner = String::new();
            children(&mut inner);
            wrap(out, "*", &inner);
        }
        "strong" | "b" => {
            let mut inner = String::new();
            children(&mut inner);
            wrap(out, "**", &inner);
        }
        "del" | "s" | "strike" => {
            let mut inner = String::new();
            children(&mut inner);
            wrap(out, "~~", &inner);
        }
        "code" | "kbd" | "samp" | "tt" => out.push_str(&code_span(&e.children, mode)),
        "q" => {
            let mut inner = String::new();
            children(&mut inner);
            let t = inner.trim_matches(char::is_whitespace);
            if !t.is_empty() {
                out.push('"');
                out.push_str(t);
                out.push('"');
            }
        }
        "br" => match mode {
            Mode::Cell => out.push_str("<br>"),
            Mode::Heading => out.push(' '),
            Mode::Normal => out.push(HARD_BREAK),
        },
        "wbr" | "video" | "audio" | "rt" | "rp" => {}
        "a" => {
            let mut inner = String::new();
            children(&mut inner);
            let dest = e
                .attr("href")
                .and_then(|h| resolve(cx.base, h))
                .filter(is_safe_link_scheme);
            match dest {
                None => out.push_str(&inner),
                Some(u) => {
                    let text = inner.replace(HARD_BREAK, " ");
                    let t = text.trim_matches(char::is_whitespace);
                    if t.is_empty() {
                        return;
                    }
                    if text.starts_with(char::is_whitespace) {
                        out.push(' ');
                    }
                    out.push('[');
                    out.push_str(t);
                    out.push_str("](");
                    out.push_str(&fmt_dest(&u));
                    out.push(')');
                    if text.ends_with(char::is_whitespace) {
                        out.push(' ');
                    }
                }
            }
        }
        "img" => {
            if let Some(src) = image_src(e, cx.base, cx.keep_data_images) {
                let mut alt = String::new();
                push_text(&mut alt, &collapse_ws(e.attr("alt").unwrap_or("")), mode);
                out.push_str("![");
                out.push_str(&alt);
                out.push_str("](");
                out.push_str(&fmt_dest(&src));
                out.push(')');
            }
        }
        tag if is_block_like(tag) => {
            out.push(' ');
            children(out);
            out.push(' ');
        }
        _ => children(out),
    }
}

fn entity_follows(rest: &[char]) -> bool {
    let n = rest
        .iter()
        .take(33)
        .take_while(|c| c.is_ascii_alphanumeric() || **c == '#')
        .count();
    n > 0 && rest.get(n) == Some(&';')
}

/// Append `t` with Markdown-significant characters escaped. Whitespace is
/// kept as is and collapsed later by [`finish_inline`].
fn push_text(out: &mut String, t: &str, mode: Mode) {
    let chars: Vec<char> = t.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let prev = if i > 0 {
            Some(chars[i - 1])
        } else {
            out.chars().next_back()
        };
        let next = chars.get(i + 1).copied();
        match c {
            '\u{a0}' => out.push(' '),
            '\u{200b}' | '\u{feff}' | '\u{ad}' | '\r' | HARD_BREAK => {}
            '\\' => {
                if next.is_none_or(|n| n.is_ascii_punctuation()) {
                    out.push('\\');
                }
                out.push('\\');
            }
            '*' | '`' | '[' | ']' => {
                out.push('\\');
                out.push(c);
            }
            '_' => {
                let inside_word =
                    prev.is_some_and(char::is_alphanumeric) && next.is_some_and(char::is_alphanumeric);
                if !inside_word {
                    out.push('\\');
                }
                out.push('_');
            }
            '<' => {
                if next.is_some_and(|n| n.is_alphabetic() || matches!(n, '/' | '!' | '?')) {
                    out.push('\\');
                }
                out.push('<');
            }
            '~' => {
                if next == Some('~') {
                    out.push('\\');
                }
                out.push('~');
            }
            '&' => {
                if entity_follows(&chars[i + 1..]) {
                    out.push('\\');
                }
                out.push('&');
            }
            '|' if mode == Mode::Cell => out.push_str("\\|"),
            _ => out.push(c),
        }
    }
}

/// Collapse whitespace of a raw inline run and resolve hard-break markers.
fn finish_inline_raw(raw: &str, mode: Mode) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pending = false;
    for c in raw.chars() {
        if c == HARD_BREAK {
            pending = false;
            if !out.is_empty() && !out.ends_with(HARD_BREAK) {
                out.push(HARD_BREAK);
            }
        } else if c.is_whitespace() {
            pending = true;
        } else {
            if pending && !out.is_empty() && !out.ends_with(HARD_BREAK) {
                out.push(' ');
            }
            pending = false;
            out.push(c);
        }
    }
    while out.ends_with(HARD_BREAK) {
        out.pop();
    }
    match mode {
        Mode::Normal => out.replace(HARD_BREAK, "  \n"),
        Mode::Heading | Mode::Cell => out.replace(HARD_BREAK, " "),
    }
}

/// [`finish_inline_raw`] plus line-start escapes for paragraph text.
fn finish_inline(raw: &str, mode: Mode) -> String {
    let s = finish_inline_raw(raw, mode);
    if mode != Mode::Normal {
        return s;
    }
    escape_line_starts(&s)
}

fn escape_line(line: &str) -> String {
    let bytes = line.as_bytes();
    let Some(&first) = bytes.first() else {
        return String::new();
    };
    let rest_after = |n: usize| bytes.get(n).is_none_or(|b| *b == b' ');
    match first {
        b'>' => format!("\\{line}"),
        b'#' => {
            let n = bytes.iter().take_while(|b| **b == b'#').count();
            if n <= 6 && rest_after(n) {
                format!("\\{line}")
            } else {
                line.to_owned()
            }
        }
        b'-' | b'+' if rest_after(1) => format!("\\{line}"),
        b'-' | b'=' if bytes.iter().all(|b| *b == first) => format!("\\{line}"),
        b'0'..=b'9' => {
            let n = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
            if n <= 9 && matches!(bytes.get(n), Some(b'.' | b')')) && rest_after(n + 1) {
                format!("{}\\{}", &line[..n], &line[n..])
            } else {
                line.to_owned()
            }
        }
        _ => line.to_owned(),
    }
}

fn escape_line_starts(s: &str) -> String {
    s.split('\n').map(escape_line).collect::<Vec<_>>().join("\n")
}

// ---------------------------------------------------------------- blocks ----

fn indent_lines(text: &str, width: usize) -> String {
    let pad = " ".repeat(width);
    text.split('\n')
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{pad}{l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct Item {
    text: String,
    marker_width: usize,
}

fn compose_item(blocks: &[Block], marker: &str, loose: &mut bool) -> String {
    let mut body = String::new();
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            if b.kind == Kind::List {
                body.push('\n');
            } else {
                body.push_str("\n\n");
                *loose = true;
            }
        }
        body.push_str(&b.text);
    }
    let width = marker.chars().count();
    let mut lines = body.split('\n');
    let mut s = String::new();
    if let Some(first) = lines.next() {
        s.push_str(marker);
        s.push_str(first);
    }
    for l in lines {
        s.push('\n');
        if !l.is_empty() {
            s.push_str(&" ".repeat(width));
            s.push_str(l);
        }
    }
    s
}

fn list(e: &Elem, cx: &Cx<'_>) -> Option<String> {
    let ordered = e.tag == "ol";
    let mut n: i64 = e.attr("start").and_then(|v| v.trim().parse().ok()).unwrap_or(1);
    let mut items: Vec<Item> = Vec::new();
    let mut loose = false;
    for c in &e.children {
        match c {
            Node::Elem(li) if li.tag == "li" => {
                let blocks = run(&li.children, cx, None);
                if blocks.is_empty() {
                    continue;
                }
                let marker = if ordered {
                    format!("{n}. ")
                } else {
                    "- ".to_owned()
                };
                n = n.saturating_add(1);
                let marker_width = marker.chars().count();
                items.push(Item {
                    text: compose_item(&blocks, &marker, &mut loose),
                    marker_width,
                });
            }
            Node::Elem(nested) if matches!(nested.tag.as_str(), "ul" | "ol" | "menu") => {
                if let Some(text) = list(nested, cx) {
                    match items.last_mut() {
                        Some(prev) => {
                            prev.text.push('\n');
                            prev.text.push_str(&indent_lines(&text, prev.marker_width));
                        }
                        None => items.push(Item {
                            text,
                            marker_width: 0,
                        }),
                    }
                }
            }
            other => {
                let blocks = run(std::slice::from_ref(other), cx, None);
                if blocks.is_empty() {
                    continue;
                }
                let marker = if ordered {
                    format!("{n}. ")
                } else {
                    "- ".to_owned()
                };
                n = n.saturating_add(1);
                let marker_width = marker.chars().count();
                items.push(Item {
                    text: compose_item(&blocks, &marker, &mut loose),
                    marker_width,
                });
            }
        }
    }
    if items.is_empty() {
        return None;
    }
    let sep = if loose { "\n\n" } else { "\n" };
    Some(items.into_iter().map(|i| i.text).collect::<Vec<_>>().join(sep))
}

fn definition_list(e: &Elem, cx: &Cx<'_>) -> Option<String> {
    fn gather<'a>(e: &'a Elem, out: &mut Vec<&'a Elem>) {
        for c in e.child_elems() {
            match c.tag.as_str() {
                "dt" | "dd" => out.push(c),
                "div" => gather(c, out),
                _ => {}
            }
        }
    }
    let mut entries = Vec::new();
    gather(e, &mut entries);
    let mut out = String::new();
    for entry in entries {
        if entry.tag == "dt" {
            let mut raw = String::new();
            inline_nodes(&entry.children, cx, Mode::Heading, &mut raw);
            let term = finish_inline_raw(&raw, Mode::Heading);
            if term.is_empty() {
                continue;
            }
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out.push_str("**");
            out.push_str(&term);
            out.push_str("**");
        } else {
            let body = join_blocks(&run(&entry.children, cx, None));
            if body.is_empty() {
                continue;
            }
            if !out.is_empty() {
                out.push('\n');
            }
            let mut lines = body.split('\n');
            if let Some(first) = lines.next() {
                out.push_str(": ");
                out.push_str(first);
            }
            for l in lines {
                out.push('\n');
                if !l.is_empty() {
                    out.push_str("  ");
                    out.push_str(l);
                }
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

// ------------------------------------------------------------------ code ----

fn sanitize_language(s: &str) -> Option<String> {
    let l: String = s
        .chars()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '+' | '#' | '-' | '_' | '.'))
        .collect();
    (!l.is_empty()).then_some(l)
}

const CODE_PREFIXES: &[&str] = &["language-", "lang-", "highlight-source-"];
const CONTAINER_PREFIXES: &[&str] = &["highlight-source-", "language-"];

fn language_from_classes(e: &Elem, prefixes: &[&str]) -> Option<String> {
    for token in e.attr("class").unwrap_or("").split_whitespace() {
        let t = token.to_ascii_lowercase();
        for p in prefixes {
            if let Some(l) = t.strip_prefix(p).and_then(sanitize_language) {
                return Some(l);
            }
        }
    }
    None
}

/// Language hint carried by a wrapper element that directly contains a `pre`.
fn container_language(e: &Elem) -> Option<String> {
    if e.child_elems().any(|c| c.tag == "pre") {
        language_from_classes(e, CONTAINER_PREFIXES)
    } else {
        None
    }
}

fn code_language(e: &Elem) -> Option<String> {
    language_from_classes(e, CODE_PREFIXES).or_else(|| {
        ["data-lang", "data-language"]
            .iter()
            .find_map(|n| e.attr(n).and_then(sanitize_language))
            .map(|l| l.to_ascii_lowercase())
    })
}

fn code_block(e: &Elem, hint: Option<&str>) -> Option<String> {
    let mut raw = String::new();
    pre_text(&e.children, &mut raw);
    let raw = raw.replace("\r\n", "\n").replace(['\r', '\u{a0}'], " ");
    let content = raw.trim_start_matches('\n').trim_end();
    if content.trim().is_empty() {
        return None;
    }
    let lang = code_language(e)
        .or_else(|| e.child_elems().find(|c| c.tag == "code").and_then(code_language))
        .or_else(|| hint.map(str::to_owned))
        .unwrap_or_default();
    let mut longest = 0usize;
    for line in content.split('\n') {
        let run = line.trim_start().chars().take_while(|c| *c == '`').count();
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest.max(2) + 1);
    Some(format!("{fence}{lang}\n{content}\n{fence}"))
}
