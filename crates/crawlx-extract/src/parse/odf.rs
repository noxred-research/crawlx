//! OpenDocument: `.odt` (text), `.ods` (spreadsheet) and `.odp` (presentation).
//!
//! One walker over `content.xml` serves all three: paragraphs and headings (`text:h`
//! `outline-level`), nested lists (bullet or numbered from the list style), tables,
//! hyperlinks (`text:a`), bold/italic spans resolved through the automatic styles, spreadsheet
//! sheets and presentation pages (`draw:page`, with `presentation:class="title"` frames as
//! headings). Notes, annotations and speaker notes are skipped. Repeat counts
//! (`table:number-rows-repeated`, `table:number-columns-repeated`) never allocate more than the
//! row and column limits.

use std::collections::{BTreeMap, BTreeSet};

use super::blocks::{self, Block, Parsed, Row, Span, Spans};
use super::sheet::{self, Sheet, MAX_COLUMNS};
use super::xml::{self, attr, tag, Ev};
use super::zipbox::ZipBox;
use super::{ParseError, ParseLimits};

/// Which ODF document family a part belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OdfKind {
    /// `.odt`
    Text,
    /// `.ods`
    Sheet,
    /// `.odp`
    Presentation,
}

impl OdfKind {
    fn format(self) -> &'static str {
        match self {
            Self::Text => "odt",
            Self::Sheet => "ods",
            Self::Presentation => "odp",
        }
    }
}

/// Document properties of `meta.xml`.
fn meta_props(xml_bytes: &[u8], format: &'static str, out: &mut Parsed) {
    let mut cur: Option<&'static str> = None;
    let mut text = String::new();
    let mut keywords: Vec<String> = Vec::new();
    let mut initial_creator = String::new();
    let _ = xml::walk(xml_bytes, format, |ev| {
        match ev {
            Ev::Start(e) => {
                text.clear();
                cur = match tag(e) {
                    b"title" => Some("title"),
                    b"creator" => Some("author"),
                    b"initial-creator" => Some("initial-creator"),
                    b"subject" => Some("subject"),
                    b"keyword" => Some("keyword"),
                    b"description" => Some("description"),
                    b"language" => Some("language"),
                    b"creation-date" => Some("created"),
                    b"date" => Some("modified"),
                    _ => None,
                };
            }
            Ev::Text(t) => {
                if cur.is_some() {
                    text.push_str(t);
                }
            }
            Ev::End(_) => {
                match cur.take() {
                    Some("keyword") => {
                        let k = blocks::collapse(&text);
                        if !k.is_empty() {
                            keywords.push(k);
                        }
                    }
                    Some("initial-creator") => initial_creator = text.clone(),
                    Some(k) => out.set_meta(k, &text),
                    None => {}
                }
                text.clear();
            }
        }
        Ok(true)
    });
    if !keywords.is_empty() {
        out.set_meta("keywords", &keywords.join(", "));
    }
    out.set_meta("author", &initial_creator);
}

#[derive(Default)]
struct OdStyles {
    bold: BTreeSet<String>,
    italic: BTreeSet<String>,
    /// list style name -> level-1 is numbered
    ordered_lists: BTreeMap<String, bool>,
}

#[derive(Default)]
struct OdPara {
    heading: Option<u8>,
    spans: Spans,
}

struct OdfWalk<'a> {
    kind: OdfKind,
    limits: &'a ParseLimits,
    styles: OdStyles,
    // style collection
    cur_style: Option<String>,
    cur_list_style: Option<String>,
    // body
    in_body: bool,
    skip: usize,
    paras: Vec<OdPara>,
    span_fmt: Vec<(bool, bool)>,
    hrefs: Vec<Option<String>>,
    lists: Vec<bool>,
    item_used: Vec<bool>,
    blocks: Vec<Block>,
    // tables
    tbl_depth: usize,
    rows: Vec<Row>,
    row: Row,
    cell: Vec<Spans>,
    cell_repeat: usize,
    rows_truncated: bool,
    // spreadsheet
    sheets: Vec<Sheet>,
    sheet_row: u32,
    sheet_col: u32,
    sheet_cells: Vec<(u32, String)>,
    row_repeat: usize,
    cell_value: String,
    // presentation
    pages: usize,
    frame_class: Option<String>,
    frame_depth: usize,
    page_open: bool,
    truncated_pages: bool,
}

fn style_family_text_props(e: &quick_xml::events::BytesStart<'_>) -> (bool, bool) {
    let bold =
        attr(e, "font-weight").is_some_and(|v| v == "bold" || v.parse::<u32>().is_ok_and(|n| n >= 600));
    let italic = attr(e, "font-style").is_some_and(|v| v == "italic" || v == "oblique");
    (bold, italic)
}

impl OdfWalk<'_> {
    fn fmt(&self) -> (bool, bool) {
        self.span_fmt
            .iter()
            .fold((false, false), |a, f| (a.0 || f.0, a.1 || f.1))
    }

    fn href(&self) -> Option<String> {
        self.hrefs.iter().rev().find_map(Clone::clone)
    }

    fn push_text(&mut self, t: &str) {
        let (bold, italic) = self.fmt();
        let href = self.href();
        if let Some(p) = self.paras.last_mut() {
            p.spans.push(Span {
                text: t.to_owned(),
                href,
                bold,
                italic,
            });
        }
    }

    fn start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        let name = tag(e);
        // automatic styles
        match name {
            b"style" => {
                self.cur_style = attr(e, "name");
            }
            b"text-properties" => {
                if let Some(n) = self.cur_style.clone() {
                    let (b, i) = style_family_text_props(e);
                    if b {
                        self.styles.bold.insert(n.clone());
                    }
                    if i {
                        self.styles.italic.insert(n);
                    }
                }
            }
            b"list-style" => self.cur_list_style = attr(e, "name"),
            b"list-level-style-number" => {
                if let Some(n) = &self.cur_list_style {
                    self.styles.ordered_lists.entry(n.clone()).or_insert(true);
                }
            }
            b"list-level-style-bullet" | b"list-level-style-image" => {
                if let Some(n) = &self.cur_list_style {
                    self.styles.ordered_lists.entry(n.clone()).or_insert(false);
                }
            }
            b"text" | b"spreadsheet" | b"presentation" if e.name().as_ref().starts_with(b"office:") => {
                self.in_body = true;
            }
            _ => {}
        }
        if !self.in_body {
            return;
        }
        match name {
            b"note" | b"annotation" | b"notes" | b"tracked-changes" => self.skip = 1,
            b"p" => self.paras.push(OdPara::default()),
            b"h" => self.paras.push(OdPara {
                heading: Some(
                    attr(e, "outline-level")
                        .and_then(|v| v.parse::<u8>().ok())
                        .unwrap_or(1)
                        .clamp(1, 6),
                ),
                spans: Vec::new(),
            }),
            b"span" => {
                let st = attr(e, "style-name");
                let b = st.as_ref().is_some_and(|s| self.styles.bold.contains(s));
                let i = st.as_ref().is_some_and(|s| self.styles.italic.contains(s));
                self.span_fmt.push((b, i));
            }
            b"a" if e.name().as_ref().starts_with(b"text:") => {
                self.hrefs.push(attr(e, "href"));
            }
            b"s" => {
                let n = attr(e, "c")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(1)
                    .min(64);
                self.push_text(&" ".repeat(n));
            }
            b"tab" => self.push_text("\t"),
            b"line-break" => self.push_text("\n"),
            b"list" => {
                let ordered = attr(e, "style-name")
                    .and_then(|s| self.styles.ordered_lists.get(&s).copied())
                    .or_else(|| self.lists.last().copied())
                    .unwrap_or(false);
                self.lists.push(ordered);
                self.item_used.push(false);
            }
            b"list-item" | b"list-header" => {
                if let Some(u) = self.item_used.last_mut() {
                    *u = false;
                }
            }
            b"page" if e.name().as_ref().starts_with(b"draw:") => {
                self.pages += 1;
                if self.pages > self.limits.max_pages {
                    self.truncated_pages = true;
                    self.skip = 1;
                    return;
                }
                if self.page_open || self.pages > 1 {
                    self.blocks.push(Block::Rule);
                }
                self.page_open = true;
            }
            b"frame" if e.name().as_ref().starts_with(b"draw:") => {
                self.frame_depth += 1;
                if self.frame_depth == 1 {
                    self.frame_class = attr(e, "class");
                }
            }
            b"table" if e.name().as_ref().starts_with(b"table:") => {
                self.tbl_depth += 1;
                if self.tbl_depth == 1 {
                    if self.kind == OdfKind::Sheet {
                        if self.sheets.len() >= self.limits.max_sheets {
                            self.skip = 1;
                            self.tbl_depth = 0;
                            return;
                        }
                        self.sheets.push(Sheet::new(attr(e, "name").unwrap_or_default()));
                        self.sheet_row = 0;
                    } else {
                        self.rows.clear();
                    }
                }
            }
            b"table-row" if self.tbl_depth == 1 => {
                if self.kind == OdfKind::Sheet {
                    self.row_repeat = attr(e, "number-rows-repeated")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(1)
                        .max(1);
                    self.sheet_col = 0;
                    self.sheet_cells.clear();
                } else {
                    self.row = Vec::new();
                }
            }
            b"table-cell" | b"covered-table-cell" if self.tbl_depth == 1 => {
                self.cell_repeat = attr(e, "number-columns-repeated")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(1)
                    .max(1);
                self.cell = Vec::new();
                self.cell_value = if name == b"table-cell" {
                    [
                        "string-value",
                        "date-value",
                        "time-value",
                        "value",
                        "boolean-value",
                    ]
                    .iter()
                    .find_map(|k| attr(e, k))
                    .unwrap_or_default()
                } else {
                    String::new()
                };
            }
            _ => {}
        }
    }

    fn end(&mut self, name: &[u8]) {
        if !self.in_body {
            match name {
                b"style" => self.cur_style = None,
                b"list-style" => self.cur_list_style = None,
                _ => {}
            }
            return;
        }
        match name {
            b"p" | b"h" => self.end_paragraph(),
            b"span" => {
                self.span_fmt.pop();
            }
            b"a" => {
                self.hrefs.pop();
            }
            b"list" => {
                self.lists.pop();
                self.item_used.pop();
            }
            b"frame" => {
                self.frame_depth = self.frame_depth.saturating_sub(1);
                if self.frame_depth == 0 {
                    self.frame_class = None;
                }
            }
            b"table-cell" | b"covered-table-cell" if self.tbl_depth == 1 => self.end_cell(),
            b"table-row" if self.tbl_depth == 1 => self.end_row(),
            b"table" if self.tbl_depth > 0 => {
                self.tbl_depth -= 1;
                if self.tbl_depth == 0 && self.kind != OdfKind::Sheet && !self.rows.is_empty() {
                    self.blocks.push(Block::Table(std::mem::take(&mut self.rows)));
                }
            }
            _ => {}
        }
    }

    fn end_cell(&mut self) {
        let mut joined: Spans = Vec::new();
        for (i, s) in std::mem::take(&mut self.cell).into_iter().enumerate() {
            if i > 0 {
                joined.push(Span::plain(" "));
            }
            joined.extend(s);
        }
        let joined = blocks::coalesce(joined);
        if self.kind == OdfKind::Sheet {
            let shown = blocks::spans_text(&joined);
            let text = if shown.trim().is_empty() {
                std::mem::take(&mut self.cell_value)
            } else {
                shown
            };
            if !text.trim().is_empty() {
                let reps = self.cell_repeat.min(MAX_COLUMNS as usize);
                for k in 0..reps {
                    let col = self
                        .sheet_col
                        .saturating_add(u32::try_from(k).unwrap_or(u32::MAX));
                    self.sheet_cells.push((col, text.clone()));
                }
            }
            self.sheet_col = self
                .sheet_col
                .saturating_add(u32::try_from(self.cell_repeat).unwrap_or(u32::MAX));
        } else {
            for _ in 0..self.cell_repeat.min(64) {
                self.row.push(joined.clone());
            }
        }
    }

    fn end_row(&mut self) {
        if self.kind == OdfKind::Sheet {
            let reps = self.row_repeat;
            let cells = std::mem::take(&mut self.sheet_cells);
            if let Some(sh) = self.sheets.last_mut() {
                if !cells.is_empty() {
                    'rows: for k in 0..reps {
                        let r = self
                            .sheet_row
                            .saturating_add(u32::try_from(k).unwrap_or(u32::MAX));
                        for (c, t) in &cells {
                            if !sh.put(r, *c, t.clone(), self.limits) {
                                break 'rows;
                            }
                        }
                    }
                }
            }
            self.sheet_row = self
                .sheet_row
                .saturating_add(u32::try_from(reps).unwrap_or(u32::MAX));
        } else {
            let row = std::mem::take(&mut self.row);
            if self.rows.len() < self.limits.max_rows {
                self.rows.push(row);
            } else {
                self.rows_truncated = true;
            }
        }
    }

    fn end_paragraph(&mut self) {
        let Some(p) = self.paras.pop() else { return };
        let spans = blocks::normalise(p.spans);
        if self.tbl_depth > 0 {
            if !spans.is_empty() {
                self.cell.push(spans);
            }
            return;
        }
        if spans.is_empty() {
            return;
        }
        if let Some(level) = p.heading {
            self.blocks.push(Block::Heading { level, spans });
            return;
        }
        if !self.lists.is_empty() {
            let first = !self.item_used.last().copied().unwrap_or(true);
            if first {
                if let Some(u) = self.item_used.last_mut() {
                    *u = true;
                }
                let depth = u8::try_from(self.lists.len() - 1).unwrap_or(8).min(8);
                let ordered = self.lists.last().copied().unwrap_or(false);
                self.blocks.push(Block::Item {
                    depth,
                    ordered,
                    spans,
                });
                return;
            }
        }
        match self.frame_class.as_deref() {
            Some("title") => self.blocks.push(Block::Heading { level: 1, spans }),
            Some("outline") => self.blocks.push(Block::Item {
                depth: 0,
                ordered: false,
                spans,
            }),
            _ => self.blocks.push(Block::Paragraph(spans)),
        }
    }
}

/// Parse `.odt`, `.ods` or `.odp`.
///
/// # Errors
/// [`ParseError::Corrupt`] / [`ParseError::TooLarge`] from the container or its XML parts.
pub(crate) fn parse_odf(bytes: &[u8], kind: OdfKind, limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let format = kind.format();
    let mut z = ZipBox::open(bytes, format, limits)?;
    let mut out = Parsed::default();
    if z.has("META-INF/manifest.xml") {
        if let Some(m) = z.read("META-INF/manifest.xml")? {
            if String::from_utf8_lossy(&m).contains("encryption-data") {
                return Err(ParseError::Encrypted { format });
            }
        }
    }
    let content = z.require("content.xml")?;
    if let Some(meta) = z.read("meta.xml")? {
        meta_props(&meta, format, &mut out);
    }
    let mut w = OdfWalk {
        kind,
        limits,
        styles: OdStyles::default(),
        cur_style: None,
        cur_list_style: None,
        in_body: false,
        skip: 0,
        paras: Vec::new(),
        span_fmt: Vec::new(),
        hrefs: Vec::new(),
        lists: Vec::new(),
        item_used: Vec::new(),
        blocks: Vec::new(),
        tbl_depth: 0,
        rows: Vec::new(),
        row: Vec::new(),
        cell: Vec::new(),
        cell_repeat: 1,
        rows_truncated: false,
        sheets: Vec::new(),
        sheet_row: 0,
        sheet_col: 0,
        sheet_cells: Vec::new(),
        row_repeat: 1,
        cell_value: String::new(),
        pages: 0,
        frame_class: None,
        frame_depth: 0,
        page_open: false,
        truncated_pages: false,
    };
    xml::walk(&content, format, |ev| {
        if w.skip > 0 {
            match ev {
                Ev::Start(_) => w.skip += 1,
                Ev::End(_) => w.skip -= 1,
                Ev::Text(_) => {}
            }
            return Ok(true);
        }
        match ev {
            Ev::Start(e) => w.start(e),
            Ev::End(n) => w.end(n),
            Ev::Text(t) => {
                if w.in_body {
                    if w.kind == OdfKind::Sheet && w.tbl_depth >= 1 && w.paras.is_empty() {
                        return Ok(true);
                    }
                    w.push_text(t);
                }
            }
        }
        Ok(true)
    })?;
    if w.rows_truncated {
        out.warnings
            .push("table rows beyond the row limit were dropped".to_owned());
    }
    if w.truncated_pages {
        out.warnings.push(format!(
            "the presentation has {} slides; only the first {} were parsed",
            w.pages, limits.max_pages
        ));
    }
    if kind == OdfKind::Sheet {
        sheet::render(&w.sheets, &mut out.blocks, &mut out.warnings);
    } else {
        out.blocks = w.blocks;
    }
    Ok(out)
}
