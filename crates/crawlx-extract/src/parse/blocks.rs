//! Format-neutral document model shared by the non-HTML parsers of [`crate::parse`].
//!
//! Every binary or XML document format is first reduced to a list of [`Block`]s (headings,
//! paragraphs, list items, tables, code and rules) whose text is a list of [`Span`]s (text with an
//! optional hyperlink and bold/italic flags). One set of renderers then produces the Markdown,
//! HTML, plain text and link list of the parsed document, so every format yields identical
//! conventions: ATX headings, `-`/`1.` list items, GFM pipe tables and `[text](url)` links.

use std::collections::BTreeMap;

/// What a binary or XML document parser returns: blocks, document properties and findings.
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    /// The body of the document.
    pub blocks: Vec<Block>,
    /// Document properties by camelCase key (`title`, `author`, `created`, ...).
    pub meta: BTreeMap<String, String>,
    /// Non-fatal findings.
    pub warnings: Vec<String>,
}

impl Parsed {
    /// Set a property unless `value` is blank or the key is already set.
    pub(crate) fn set_meta(&mut self, key: &str, value: &str) {
        let v = collapse(value);
        if !v.is_empty() {
            self.meta.entry(key.to_owned()).or_insert(v);
        }
    }
}

/// A run of text with uniform inline formatting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Span {
    /// The text. May contain no line breaks except an explicit `\n` for a hard break.
    pub text: String,
    /// Hyperlink target.
    pub href: Option<String>,
    /// Bold run.
    pub bold: bool,
    /// Italic run.
    pub italic: bool,
}

impl Span {
    /// A plain span.
    pub(crate) fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    /// A hyperlink span.
    pub(crate) fn link(text: impl Into<String>, href: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            href: Some(href.into()),
            ..Self::default()
        }
    }

    fn same_format(&self, other: &Self) -> bool {
        self.href == other.href && self.bold == other.bold && self.italic == other.italic
    }
}

/// Inline content of one block.
pub(crate) type Spans = Vec<Span>;
/// One table row: a list of cells.
pub(crate) type Row = Vec<Spans>;

/// One block of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Block {
    /// A heading of level 1 to 6.
    Heading { level: u8, spans: Spans },
    /// A paragraph.
    Paragraph(Spans),
    /// A list item at nesting `depth` (0-based).
    Item { depth: u8, ordered: bool, spans: Spans },
    /// A table; the first row is the header row.
    Table(Vec<Row>),
    /// Preformatted text.
    Code(String),
    /// A page, slide or sheet break.
    Rule,
}

/// Merge adjacent spans with identical formatting and drop empty ones.
pub(crate) fn coalesce(spans: Spans) -> Spans {
    let mut out: Spans = Vec::with_capacity(spans.len());
    for s in spans {
        if s.text.is_empty() {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.same_format(&s) => last.text.push_str(&s.text),
            _ => out.push(s),
        }
    }
    out
}

/// Concatenated text of `spans`.
pub(crate) fn spans_text(spans: &[Span]) -> String {
    let mut s = String::new();
    for sp in spans {
        s.push_str(&sp.text);
    }
    s
}

fn spans_blank(spans: &[Span]) -> bool {
    spans.iter().all(|s| s.text.trim().is_empty())
}

/// Collapse runs of whitespace (including line breaks) to single spaces and trim the ends.
pub(crate) fn collapse(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending = false;
    for c in text.chars() {
        if c.is_whitespace() || c == '\u{a0}' {
            pending = true;
        } else {
            if pending && !out.is_empty() {
                out.push(' ');
            }
            pending = false;
            out.push(c);
        }
    }
    out
}

/// Normalise the inline content of a block: coalesce spans, collapse whitespace inside each
/// span (hard `\n` breaks are kept as a space) and trim the block's ends.
pub(crate) fn normalise(spans: Spans) -> Spans {
    let mut out: Spans = Vec::with_capacity(spans.len());
    for mut s in coalesce(spans) {
        let mut t = String::with_capacity(s.text.len());
        let mut pending = false;
        for c in s.text.chars() {
            if c.is_whitespace() || c == '\u{a0}' {
                pending = true;
            } else {
                if pending {
                    t.push(' ');
                }
                pending = false;
                t.push(c);
            }
        }
        if pending {
            t.push(' ');
        }
        s.text = t;
        out.push(s);
    }
    let mut out = coalesce(out);
    // collapse a double space across a span boundary
    for i in 1..out.len() {
        if out[i - 1].text.ends_with(' ') && out[i].text.starts_with(' ') {
            out[i].text.remove(0);
        }
    }
    if let Some(first) = out.first_mut() {
        first.text = first.text.trim_start().to_owned();
    }
    if let Some(last) = out.last_mut() {
        last.text = last.text.trim_end().to_owned();
    }
    coalesce(out)
}

fn md_escape_cell(text: &str) -> String {
    text.replace('|', "\\|")
}

fn md_inline(spans: &[Span], in_table: bool) -> String {
    let mut out = String::new();
    for s in spans {
        let raw = if in_table {
            md_escape_cell(&s.text)
        } else {
            s.text.clone()
        };
        if raw.trim().is_empty() {
            out.push_str(&raw);
            continue;
        }
        let core = raw.trim();
        let lead = &raw[..raw.len() - raw.trim_start().len()];
        let trail = &raw[raw.trim_end().len()..];
        out.push_str(lead);
        let mut piece = core.to_owned();
        if s.bold && s.italic {
            piece = format!("***{piece}***");
        } else if s.bold {
            piece = format!("**{piece}**");
        } else if s.italic {
            piece = format!("*{piece}*");
        }
        match &s.href {
            Some(h) => {
                out.push('[');
                out.push_str(&piece);
                out.push_str("](");
                out.push_str(h);
                out.push(')');
            }
            None => out.push_str(&piece),
        }
        out.push_str(trail);
    }
    out
}

fn md_table(rows: &[Row]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    if cols == 0 {
        return String::new();
    }
    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        out.push('|');
        for c in 0..cols {
            let cell = row.get(c).map_or_else(String::new, |s| md_inline(s, true));
            out.push(' ');
            out.push_str(cell.trim());
            out.push_str(" |");
        }
        out.push('\n');
        if i == 0 {
            out.push('|');
            for _ in 0..cols {
                out.push_str(" --- |");
            }
            out.push('\n');
        }
    }
    out.truncate(out.trim_end().len());
    out
}

/// Render blocks as Markdown.
pub(crate) fn render_markdown(blocks: &[Block]) -> String {
    render_markdown_spans(blocks).0
}

/// Render blocks as Markdown and report, per block, the byte range of its fragment in the output
/// (`None` for blocks that render to nothing).
pub(crate) fn render_markdown_spans(blocks: &[Block]) -> (String, Vec<Option<(usize, usize)>>) {
    let mut out = String::new();
    let mut spans_out: Vec<Option<(usize, usize)>> = Vec::with_capacity(blocks.len());
    let mut counters: Vec<(usize, bool)> = Vec::new();
    let mut prev_item = false;
    for b in blocks {
        let piece = match b {
            Block::Heading { level, spans } => {
                if spans_blank(spans) {
                    counters.clear();
                    prev_item = false;
                    spans_out.push(None);
                    continue;
                }
                let text = md_inline(spans, false);
                format!(
                    "{} {}",
                    "#".repeat(usize::from((*level).clamp(1, 6))),
                    text.trim()
                )
            }
            Block::Paragraph(spans) => {
                if spans_blank(spans) {
                    spans_out.push(None);
                    continue;
                }
                md_inline(spans, false).trim().to_owned()
            }
            Block::Item {
                depth,
                ordered,
                spans,
            } => {
                let d = usize::from(*depth).min(12);
                counters.truncate(d + 1);
                while counters.len() <= d {
                    counters.push((0, *ordered));
                }
                if counters[d].1 != *ordered {
                    counters[d] = (0, *ordered);
                }
                counters[d].0 += 1;
                let marker = if *ordered {
                    format!("{}.", counters[d].0)
                } else {
                    "-".to_owned()
                };
                let text = md_inline(spans, false);
                let line = format!("{}{} {}", "  ".repeat(d), marker, text.trim());
                if !out.is_empty() {
                    out.push_str(if prev_item { "\n" } else { "\n\n" });
                }
                let start = out.len();
                out.push_str(&line);
                spans_out.push(Some((start, out.len())));
                prev_item = true;
                continue;
            }
            Block::Table(rows) => md_table(rows),
            Block::Code(code) => format!("```\n{}\n```", code.trim_end_matches('\n')),
            Block::Rule => "---".to_owned(),
        };
        if piece.is_empty() {
            spans_out.push(None);
            continue;
        }
        counters.clear();
        prev_item = false;
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        let start = out.len();
        out.push_str(&piece);
        spans_out.push(Some((start, out.len())));
    }
    (out, spans_out)
}

/// Escape text for an HTML text node or a quoted attribute.
pub(crate) fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn html_inline(spans: &[Span]) -> String {
    let mut out = String::new();
    for s in spans {
        let mut piece = escape_html(&s.text).replace('\n', "<br>");
        if s.bold {
            piece = format!("<strong>{piece}</strong>");
        }
        if s.italic {
            piece = format!("<em>{piece}</em>");
        }
        match &s.href {
            Some(h) => out.push_str(&format!("<a href=\"{}\">{piece}</a>", escape_html(h))),
            None => out.push_str(&piece),
        }
    }
    out
}

fn close_lists(out: &mut String, open: &mut Vec<bool>) {
    while let Some(ordered) = open.pop() {
        out.push_str(if ordered { "</li></ol>" } else { "</li></ul>" });
    }
}

/// Render blocks as an HTML fragment.
pub(crate) fn render_html(blocks: &[Block]) -> String {
    let mut out = String::new();
    let mut open: Vec<bool> = Vec::new();
    for b in blocks {
        if let Block::Item {
            depth,
            ordered,
            spans,
        } = b
        {
            let d = usize::from(*depth).min(12);
            while open.len() > d + 1 {
                let o = open.pop().unwrap_or(false);
                out.push_str(if o { "</li></ol>" } else { "</li></ul>" });
            }
            if open.len() == d + 1 {
                out.push_str("</li>");
            } else {
                while open.len() < d + 1 {
                    out.push_str(if *ordered { "<ol>" } else { "<ul>" });
                    open.push(*ordered);
                }
            }
            out.push_str("<li>");
            out.push_str(html_inline(spans).trim());
            continue;
        }
        close_lists(&mut out, &mut open);
        match b {
            Block::Heading { level, spans } => {
                let l = (*level).clamp(1, 6);
                out.push_str(&format!("<h{l}>{}</h{l}>", html_inline(spans).trim()));
            }
            Block::Paragraph(spans) => {
                if spans_blank(spans) {
                    continue;
                }
                out.push_str(&format!("<p>{}</p>", html_inline(spans).trim()));
            }
            Block::Table(rows) => {
                out.push_str("<table>");
                for (i, row) in rows.iter().enumerate() {
                    let tag = if i == 0 { "th" } else { "td" };
                    out.push_str("<tr>");
                    for cell in row {
                        out.push_str(&format!("<{tag}>{}</{tag}>", html_inline(cell).trim()));
                    }
                    out.push_str("</tr>");
                }
                out.push_str("</table>");
            }
            Block::Code(code) => out.push_str(&format!("<pre><code>{}</code></pre>", escape_html(code))),
            Block::Rule => out.push_str("<hr>"),
            Block::Item { .. } => {}
        }
    }
    close_lists(&mut out, &mut open);
    out
}

/// Render blocks as plain text.
pub(crate) fn render_text(blocks: &[Block]) -> String {
    let mut out = String::new();
    let mut prev_item = false;
    for b in blocks {
        let (piece, is_item) = match b {
            Block::Heading { spans, .. } | Block::Paragraph(spans) => (collapse(&spans_text(spans)), false),
            Block::Item { depth, spans, .. } => (
                format!(
                    "{}{}",
                    "  ".repeat(usize::from(*depth).min(12)),
                    collapse(&spans_text(spans))
                ),
                true,
            ),
            Block::Table(rows) => (
                rows.iter()
                    .map(|r| {
                        r.iter()
                            .map(|c| collapse(&spans_text(c)))
                            .collect::<Vec<_>>()
                            .join("\t")
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
                false,
            ),
            Block::Code(code) => (code.trim_end_matches('\n').to_owned(), false),
            Block::Rule => (String::new(), false),
        };
        if piece.trim().is_empty() {
            prev_item = false;
            continue;
        }
        if !out.is_empty() {
            out.push_str(if is_item && prev_item { "\n" } else { "\n\n" });
        }
        out.push_str(&piece);
        prev_item = is_item;
    }
    out
}

fn push_link(out: &mut Vec<String>, href: &str) {
    let lower = href.get(..8).unwrap_or(href).to_ascii_lowercase();
    if (lower.starts_with("http://") || lower.starts_with("https://")) && !out.iter().any(|h| h == href) {
        out.push(href.to_owned());
    }
}

/// Distinct `http(s)` hyperlink targets in document order.
pub(crate) fn collect_links(blocks: &[Block]) -> Vec<String> {
    let mut out = Vec::new();
    let mut visit = |spans: &[Span]| {
        for s in spans {
            if let Some(h) = &s.href {
                push_link(&mut out, h.trim());
            }
        }
    };
    for b in blocks {
        match b {
            Block::Heading { spans, .. } | Block::Paragraph(spans) | Block::Item { spans, .. } => {
                visit(spans)
            }
            Block::Table(rows) => {
                for row in rows {
                    for cell in row {
                        visit(cell);
                    }
                }
            }
            Block::Code(_) | Block::Rule => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn markdown_lists_numbered_and_nested() {
        let blocks = vec![
            Block::Item {
                depth: 0,
                ordered: true,
                spans: vec![Span::plain("a")],
            },
            Block::Item {
                depth: 1,
                ordered: false,
                spans: vec![Span::plain("b")],
            },
            Block::Item {
                depth: 0,
                ordered: true,
                spans: vec![Span::plain("c")],
            },
            Block::Paragraph(vec![Span::plain("p")]),
        ];
        assert_eq!(render_markdown(&blocks), "1. a\n  - b\n2. c\n\np");
    }

    #[test]
    fn html_lists_nest() {
        let blocks = vec![
            Block::Item {
                depth: 0,
                ordered: false,
                spans: vec![Span::plain("a")],
            },
            Block::Item {
                depth: 1,
                ordered: false,
                spans: vec![Span::plain("b")],
            },
            Block::Item {
                depth: 0,
                ordered: false,
                spans: vec![Span::plain("c")],
            },
        ];
        assert_eq!(
            render_html(&blocks),
            "<ul><li>a<ul><li>b</li></ul></li><li>c</li></ul>"
        );
    }

    #[test]
    fn inline_formatting_keeps_whitespace_outside_markers() {
        let spans = vec![
            Span::plain("see "),
            Span {
                text: " bold ".into(),
                bold: true,
                ..Span::default()
            },
            Span::link("here", "https://example.com/x"),
        ];
        assert_eq!(
            md_inline(&spans, false),
            "see  **bold** [here](https://example.com/x)"
        );
    }
}
