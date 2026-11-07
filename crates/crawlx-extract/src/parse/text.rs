//! Plain formats: `.txt`, `.md` and `.csv`.
//!
//! * text: paragraphs are the blank-line separated groups; the Markdown is the text itself;
//! * Markdown: a small block/inline parser (ATX headings, bullet and numbered lists, fenced code,
//!   pipe tables, rules, `**bold**`, `*italic*`, `[text](url)`, `<https://autolinks>`) feeds the
//!   HTML, text and link outputs; the Markdown output is the source;
//! * CSV: delimiter detection (`,` `;` tab `|`), RFC 4180 quoting, a Markdown table whose first
//!   row is the header, rows capped at `ParseLimits::max_rows`.

use std::sync::LazyLock;

use encoding_rs::{Encoding, WINDOWS_1252};
use regex::Regex;

use super::blocks::{self, Block, Parsed, Row, Span, Spans};
use super::sheet::MAX_COLUMNS;
use super::{ParseError, ParseLimits};

/// Decode text bytes: BOM, strict UTF-8, otherwise Windows-1252.
pub(crate) fn decode_text(bytes: &[u8]) -> String {
    if let Some((enc, len)) = Encoding::for_bom(bytes) {
        return enc.decode_without_bom_handling(&bytes[len..]).0.into_owned();
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => WINDOWS_1252.decode_without_bom_handling(bytes).0.into_owned(),
    }
}

fn normalise_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

static URL_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r#"https?://[^\s<>"'\]\)]+"#).ok());

/// Distinct bare `http(s)` URLs of `text` in order, trailing punctuation removed.
pub(crate) fn bare_links(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(re) = URL_RE.as_ref() {
        for m in re.find_iter(text) {
            let u = m.as_str().trim_end_matches(['.', ',', ';', ':', '!', '?']);
            if url::Url::parse(u).is_ok() && !out.iter().any(|x| x == u) {
                out.push(u.to_owned());
            }
        }
    }
    out
}

/// Parsed plain text.
pub(crate) struct PlainOut {
    pub parsed: Parsed,
    pub markdown: String,
    pub links: Vec<String>,
}

/// `.txt`.
pub(crate) fn parse_txt(bytes: &[u8]) -> PlainOut {
    let text = normalise_newlines(&decode_text(bytes));
    let mut parsed = Parsed::default();
    for group in text.split("\n\n") {
        let g = group.trim_matches('\n');
        if g.trim().is_empty() {
            continue;
        }
        let spans = vec![Span::plain(
            g.lines().map(str::trim).collect::<Vec<_>>().join("\n"),
        )];
        parsed.blocks.push(Block::Paragraph(spans));
    }
    PlainOut {
        links: bare_links(&text),
        markdown: text.trim().to_owned(),
        parsed,
    }
}

// ---------------------------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------------------------

fn inline(src: &str, links: &mut Vec<String>) -> Spans {
    let chars: Vec<char> = src.chars().collect();
    let mut out: Spans = Vec::new();
    let mut plain = String::new();
    let mut i = 0usize;
    let mut bold = false;
    let mut italic = false;
    let flush = |plain: &mut String, out: &mut Spans, bold: bool, italic: bool| {
        if !plain.is_empty() {
            out.push(Span {
                text: std::mem::take(plain),
                bold,
                italic,
                ..Span::default()
            });
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            plain.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if c == '`' {
            if let Some(end) = chars[i + 1..].iter().position(|x| *x == '`') {
                plain.extend(&chars[i + 1..i + 1 + end]);
                i += end + 2;
                continue;
            }
        }
        if c == '[' || (c == '!' && chars.get(i + 1) == Some(&'[')) {
            let image = c == '!';
            let open = if image { i + 1 } else { i };
            if let Some(close) = chars[open + 1..]
                .iter()
                .position(|x| *x == ']')
                .map(|p| p + open + 1)
            {
                if chars.get(close + 1) == Some(&'(') {
                    if let Some(end) = chars[close + 2..]
                        .iter()
                        .position(|x| *x == ')')
                        .map(|p| p + close + 2)
                    {
                        let label: String = chars[open + 1..close].iter().collect();
                        let target: String = chars[close + 2..end].iter().collect();
                        let target = target.split_whitespace().next().unwrap_or("").to_owned();
                        flush(&mut plain, &mut out, bold, italic);
                        if image {
                            out.push(Span {
                                text: label,
                                bold,
                                italic,
                                ..Span::default()
                            });
                        } else {
                            if target.starts_with("http://") || target.starts_with("https://") {
                                links.push(target.clone());
                            }
                            out.push(Span {
                                text: label,
                                href: Some(target),
                                bold,
                                italic,
                            });
                        }
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        if c == '<' {
            if let Some(end) = chars[i + 1..].iter().position(|x| *x == '>').map(|p| p + i + 1) {
                let inner: String = chars[i + 1..end].iter().collect();
                if inner.starts_with("http://") || inner.starts_with("https://") {
                    flush(&mut plain, &mut out, bold, italic);
                    links.push(inner.clone());
                    out.push(Span::link(inner.clone(), inner));
                    i = end + 1;
                    continue;
                }
            }
        }
        if (c == '*' || c == '_') && chars.get(i + 1) == Some(&c) {
            flush(&mut plain, &mut out, bold, italic);
            bold = !bold;
            i += 2;
            continue;
        }
        if c == '*' || (c == '_' && (i == 0 || !chars[i - 1].is_alphanumeric())) {
            flush(&mut plain, &mut out, bold, italic);
            italic = !italic;
            i += 1;
            continue;
        }
        plain.push(c);
        i += 1;
    }
    flush(&mut plain, &mut out, bold, italic);
    blocks::coalesce(out)
}

fn table_cells(line: &str) -> Vec<String> {
    let t = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut esc = false;
    for c in t.chars() {
        if esc {
            if c != '|' {
                cur.push('\\');
            }
            cur.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '|' {
            cells.push(cur.trim().to_owned());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    cells.push(cur.trim().to_owned());
    cells
}

fn is_table_sep(line: &str) -> bool {
    let t = line.trim();
    t.contains('-') && t.contains('|') && t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
}

fn list_marker(line: &str) -> Option<(usize, bool, &str)> {
    let indent = line.len() - line.trim_start().len();
    let rest = line.trim_start();
    for m in ["- ", "* ", "+ "] {
        if let Some(r) = rest.strip_prefix(m) {
            return Some((indent, false, r));
        }
    }
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    if (1..=9).contains(&digits) {
        let after = &rest[digits..];
        if let Some(r) = after.strip_prefix(". ").or_else(|| after.strip_prefix(") ")) {
            return Some((indent, true, r));
        }
    }
    None
}

fn md_blocks(src: &str, links: &mut Vec<String>) -> Vec<Block> {
    let lines: Vec<&str> = src.lines().collect();
    let mut blocks: Vec<Block> = Vec::new();
    let mut para: Vec<&str> = Vec::new();
    let mut i = 0usize;
    let flush = |para: &mut Vec<&str>, blocks: &mut Vec<Block>, links: &mut Vec<String>| {
        if !para.is_empty() {
            let text = para.iter().map(|l| l.trim()).collect::<Vec<_>>().join(" ");
            blocks.push(Block::Paragraph(inline(&text, links)));
            para.clear();
        }
    };
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim();
        if t.is_empty() {
            flush(&mut para, &mut blocks, links);
            i += 1;
            continue;
        }
        if t.starts_with("```") || t.starts_with("~~~") {
            flush(&mut para, &mut blocks, links);
            let fence = &t[..3];
            let mut code = Vec::new();
            i += 1;
            while i < lines.len() && !lines[i].trim().starts_with(fence) {
                code.push(lines[i]);
                i += 1;
            }
            i += 1;
            blocks.push(Block::Code(code.join("\n")));
            continue;
        }
        let hashes = t.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && t[hashes..].starts_with(' ') {
            flush(&mut para, &mut blocks, links);
            let title = t[hashes..].trim().trim_end_matches('#').trim();
            blocks.push(Block::Heading {
                level: u8::try_from(hashes).unwrap_or(6),
                spans: inline(title, links),
            });
            i += 1;
            continue;
        }
        if t.len() >= 3
            && (t.chars().all(|c| c == '-') || t.chars().all(|c| c == '*') || t.chars().all(|c| c == '_'))
        {
            flush(&mut para, &mut blocks, links);
            blocks.push(Block::Rule);
            i += 1;
            continue;
        }
        if t.contains('|') && lines.get(i + 1).is_some_and(|n| is_table_sep(n)) {
            flush(&mut para, &mut blocks, links);
            let mut rows: Vec<Row> = Vec::new();
            let mut cur = i;
            while cur < lines.len() && lines[cur].contains('|') && !lines[cur].trim().is_empty() {
                if cur != i + 1 {
                    rows.push(table_cells(lines[cur]).iter().map(|c| inline(c, links)).collect());
                }
                cur += 1;
            }
            blocks.push(Block::Table(rows));
            i = cur;
            continue;
        }
        if let Some((indent, ordered, rest)) = list_marker(line) {
            flush(&mut para, &mut blocks, links);
            blocks.push(Block::Item {
                depth: u8::try_from(indent / 2).unwrap_or(8).min(8),
                ordered,
                spans: inline(rest.trim(), links),
            });
            i += 1;
            continue;
        }
        if let Some(q) = t.strip_prefix('>') {
            flush(&mut para, &mut blocks, links);
            blocks.push(Block::Paragraph(inline(q.trim(), links)));
            i += 1;
            continue;
        }
        para.push(line);
        i += 1;
    }
    flush(&mut para, &mut blocks, links);
    blocks
}

/// `.md`.
pub(crate) fn parse_md(bytes: &[u8]) -> PlainOut {
    let text = normalise_newlines(&decode_text(bytes));
    let mut links: Vec<String> = Vec::new();
    let blocks = md_blocks(&text, &mut links);
    let mut seen: Vec<String> = Vec::new();
    for l in links.into_iter().chain(bare_links(&text)) {
        if !seen.contains(&l) {
            seen.push(l);
        }
    }
    PlainOut {
        parsed: Parsed {
            blocks,
            ..Parsed::default()
        },
        markdown: text.trim().to_owned(),
        links: seen,
    }
}

// ---------------------------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------------------------

fn detect_delimiter(text: &str) -> char {
    let first: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
    let mut best = (',', 0usize);
    for d in [',', ';', '\t', '|'] {
        let mut in_q = false;
        let mut n = 0usize;
        for c in first.chars() {
            if c == '"' {
                in_q = !in_q;
            } else if c == d && !in_q {
                n += 1;
            }
        }
        if n > best.1 {
            best = (d, n);
        }
    }
    best.0
}

/// `.csv`.
///
/// # Errors
/// Never in practice; the signature matches the other parsers.
pub(crate) fn parse_csv(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let text = decode_text(bytes);
    let delim = detect_delimiter(&text);
    let mut rows: Vec<Row> = Vec::new();
    let mut row: Row = Vec::new();
    let mut field = String::new();
    let mut in_q = false;
    let mut field_started = false;
    let mut truncated = false;
    let mut wide = false;
    let mut chars = text.chars().peekable();
    let cap_cols = MAX_COLUMNS as usize;
    let push_field = |field: &mut String, row: &mut Row, wide: &mut bool| {
        let t = std::mem::take(field);
        if row.len() < cap_cols {
            row.push(if t.is_empty() {
                Vec::new()
            } else {
                vec![Span::plain(t.replace(['\n', '\r'], " "))]
            });
        } else {
            *wide = true;
        }
    };
    while let Some(c) = chars.next() {
        if in_q {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_q = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' if !field_started => {
                in_q = true;
                field_started = true;
            }
            c if c == delim => {
                push_field(&mut field, &mut row, &mut wide);
                field_started = false;
            }
            '\r' | '\n' => {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                push_field(&mut field, &mut row, &mut wide);
                field_started = false;
                let finished = std::mem::take(&mut row);
                if finished.iter().any(|f| !f.is_empty()) || finished.len() > 1 {
                    if rows.len() < limits.max_rows {
                        rows.push(finished);
                    } else {
                        truncated = true;
                        break;
                    }
                }
            }
            c => {
                field.push(c);
                field_started = true;
            }
        }
    }
    if !truncated && (field_started || !row.is_empty() || !field.is_empty()) {
        push_field(&mut field, &mut row, &mut wide);
        if rows.len() < limits.max_rows {
            rows.push(row);
        } else {
            truncated = true;
        }
    }
    let mut out = Parsed::default();
    if !rows.is_empty() {
        out.blocks.push(Block::Table(rows));
    }
    if truncated {
        out.warnings
            .push("rows beyond the row limit were dropped".to_owned());
    }
    if wide {
        out.warnings
            .push(format!("columns beyond column {MAX_COLUMNS} were dropped"));
    }
    Ok(out)
}
