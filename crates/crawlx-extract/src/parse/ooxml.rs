//! Office Open XML: `.docx`/`.docm` (WordprocessingML), `.pptx`/`.pptm` (PresentationML) and
//! `.xlsx`/`.xlsm`/`.xlsb` (spreadsheets through `calamine`).
//!
//! * Word: headings come from the paragraph style (`Heading N`, `Title`, or the style's
//!   `outlineLvl`), list items from `numPr` (bullet vs. numbered from `numbering.xml`) or the
//!   `List Bullet`/`List Number` styles, tables become Markdown tables, hyperlinks come from
//!   relationships and `HYPERLINK` fields, bold/italic runs are kept.
//! * PowerPoint: slides in presentation order, title placeholders become headings, body text
//!   becomes list items, tables are kept, slides are separated by a rule.
//! * Excel: one `## sheet` heading and table per sheet; dates and numbers use their display
//!   forms. Sparse sheets never allocate their bounding box.

use std::collections::BTreeMap;
use std::io::Cursor;

use calamine::{Reader, Xlsb, Xlsx};

use super::blocks::{self, Block, Parsed, Row, Span, Spans};
use super::sheet::{self, Sheet};
use super::xml::{self, attr, attr_q, tag, Ev};
use super::zipbox::ZipBox;
use super::{ParseError, ParseLimits};

// ---------------------------------------------------------------------------------------------
// Shared parts
// ---------------------------------------------------------------------------------------------

/// `Id -> (Target, external)` of a `.rels` part.
type Rels = BTreeMap<String, (String, bool)>;

fn parse_rels(xml_bytes: &[u8], format: &'static str) -> Rels {
    let mut out = Rels::new();
    let _ = xml::walk(xml_bytes, format, |ev| {
        if let Ev::Start(e) = ev {
            if tag(e) == b"Relationship" {
                if let (Some(id), Some(target)) = (attr(e, "Id"), attr(e, "Target")) {
                    let external = attr(e, "TargetMode").is_some_and(|m| m.eq_ignore_ascii_case("External"));
                    out.insert(id, (target, external));
                }
            }
        }
        Ok(true)
    });
    out
}

/// `docProps/core.xml` into document properties.
fn core_props(xml_bytes: &[u8], format: &'static str, out: &mut Parsed) {
    let mut cur: Option<&'static str> = None;
    let mut text = String::new();
    let _ = xml::walk(xml_bytes, format, |ev| {
        match ev {
            Ev::Start(e) => {
                text.clear();
                cur = match tag(e) {
                    b"title" => Some("title"),
                    b"creator" => Some("author"),
                    b"subject" => Some("subject"),
                    b"keywords" => Some("keywords"),
                    b"description" => Some("description"),
                    b"language" => Some("language"),
                    b"lastModifiedBy" => Some("lastModifiedBy"),
                    b"created" => Some("created"),
                    b"modified" => Some("modified"),
                    _ => None,
                };
            }
            Ev::Text(t) => {
                if cur.is_some() {
                    text.push_str(t);
                }
            }
            Ev::End(_) => {
                if let Some(k) = cur.take() {
                    out.set_meta(k, &text);
                }
                text.clear();
            }
        }
        Ok(true)
    });
}

/// Resolve `target` relative to the directory of the part `base` (`ppt/presentation.xml`).
fn resolve(base: &str, target: &str) -> String {
    if let Some(abs) = target.strip_prefix('/') {
        return abs.to_owned();
    }
    let mut parts: Vec<&str> = base.split('/').collect();
    parts.pop();
    for seg in target.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

fn truthy(v: Option<String>) -> bool {
    !matches!(v.as_deref(), Some("0" | "false" | "off"))
}

// ---------------------------------------------------------------------------------------------
// DOCX
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Styles {
    /// styleId -> (lower-case name, basedOn, outline level 1-based)
    by_id: BTreeMap<String, (String, Option<String>, Option<u8>)>,
}

impl Styles {
    fn parse(xml_bytes: &[u8]) -> Self {
        let mut s = Self::default();
        let mut cur: Option<(String, String, Option<String>, Option<u8>)> = None;
        let _ = xml::walk(xml_bytes, "docx", |ev| {
            match ev {
                Ev::Start(e) => match tag(e) {
                    b"style" => cur = attr(e, "styleId").map(|id| (id, String::new(), None, None)),
                    b"name" => {
                        if let Some(c) = cur.as_mut() {
                            c.1 = attr(e, "val").unwrap_or_default().to_lowercase();
                        }
                    }
                    b"basedOn" => {
                        if let Some(c) = cur.as_mut() {
                            c.2 = attr(e, "val");
                        }
                    }
                    b"outlineLvl" => {
                        if let Some(c) = cur.as_mut() {
                            c.3 = attr(e, "val")
                                .and_then(|v| v.parse::<u8>().ok())
                                .filter(|v| *v < 9)
                                .map(|v| v + 1);
                        }
                    }
                    _ => {}
                },
                Ev::End(name) => {
                    if name == b"style" {
                        if let Some((id, n, b, o)) = cur.take() {
                            s.by_id.insert(id, (n, b, o));
                        }
                    }
                }
                Ev::Text(_) => {}
            }
            Ok(true)
        });
        s
    }

    fn resolve(&self, id: &str) -> Option<(&str, Option<u8>)> {
        let mut cur = id;
        for _ in 0..8 {
            let (name, based, outline) = self.by_id.get(cur)?;
            if outline.is_some() || name.starts_with("heading ") || name == "title" || name == "subtitle" {
                return Some((name.as_str(), *outline));
            }
            match based {
                Some(b) => cur = b,
                None => return Some((name.as_str(), None)),
            }
        }
        None
    }

    fn name(&self, id: &str) -> Option<&str> {
        self.by_id.get(id).map(|(n, _, _)| n.as_str())
    }

    /// Heading level (1-6) of a paragraph style.
    fn heading_level(&self, id: &str) -> Option<u8> {
        let (name, outline) = self.resolve(id)?;
        if let Some(n) = name.strip_prefix("heading ") {
            if let Ok(l) = n.trim().parse::<u8>() {
                return Some(l.clamp(1, 6));
            }
        }
        if name == "title" {
            return Some(1);
        }
        if name == "subtitle" {
            return Some(2);
        }
        outline.map(|l| l.clamp(1, 6))
    }
}

#[derive(Default)]
struct Numbering {
    /// numId -> abstractNumId
    nums: BTreeMap<String, String>,
    /// (abstractNumId, ilvl) -> numFmt
    levels: BTreeMap<(String, u8), String>,
}

impl Numbering {
    fn parse(xml_bytes: &[u8]) -> Self {
        let mut n = Self::default();
        let mut abstract_id: Option<String> = None;
        let mut ilvl: Option<u8> = None;
        let mut num_id: Option<String> = None;
        let _ = xml::walk(xml_bytes, "docx", |ev| {
            match ev {
                Ev::Start(e) => match tag(e) {
                    b"abstractNum" => abstract_id = attr(e, "abstractNumId"),
                    b"lvl" => ilvl = attr(e, "ilvl").and_then(|v| v.parse().ok()),
                    b"numFmt" => {
                        if let (Some(a), Some(l), Some(f)) = (&abstract_id, ilvl, attr(e, "val")) {
                            n.levels.entry((a.clone(), l)).or_insert(f);
                        }
                    }
                    b"num" => num_id = attr(e, "numId"),
                    b"abstractNumId" if num_id.is_some() => {
                        if let (Some(id), Some(a)) = (&num_id, attr(e, "val")) {
                            n.nums.insert(id.clone(), a);
                        }
                    }
                    _ => {}
                },
                Ev::End(name) => match name {
                    b"abstractNum" => abstract_id = None,
                    b"lvl" => ilvl = None,
                    b"num" => num_id = None,
                    _ => {}
                },
                Ev::Text(_) => {}
            }
            Ok(true)
        });
        n
    }

    fn ordered(&self, num_id: &str, ilvl: u8) -> bool {
        self.nums
            .get(num_id)
            .and_then(|a| self.levels.get(&(a.clone(), ilvl)))
            .is_some_and(|f| !matches!(f.as_str(), "bullet" | "none"))
    }
}

#[derive(Default)]
struct DocPara {
    style: Option<String>,
    ilvl: u8,
    num_id: Option<String>,
    outline: Option<u8>,
    spans: Spans,
}

#[derive(Default)]
struct Field {
    instr: String,
    href: Option<String>,
    in_result: bool,
}

fn hyperlink_instr(instr: &str) -> Option<String> {
    let t = instr.trim();
    let rest = t
        .strip_prefix("HYPERLINK")
        .or_else(|| t.strip_prefix("hyperlink"))?;
    let rest = rest.trim_start();
    let url = if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()?
    } else {
        rest.split_whitespace().next()?
    };
    (!url.is_empty()).then(|| url.to_owned())
}

struct DocxWalk<'a> {
    styles: &'a Styles,
    numbering: &'a Numbering,
    rels: &'a Rels,
    limits: &'a ParseLimits,
    paras: Vec<DocPara>,
    blocks: Vec<Block>,
    tbl_depth: usize,
    rows: Vec<Row>,
    row: Row,
    cell: Vec<Spans>,
    bold: bool,
    italic: bool,
    in_t: bool,
    in_instr: bool,
    hyperlink: Option<String>,
    fields: Vec<Field>,
    skip: usize,
    rows_truncated: bool,
}

impl DocxWalk<'_> {
    fn href(&self) -> Option<String> {
        self.hyperlink.clone().or_else(|| {
            self.fields
                .iter()
                .rev()
                .find(|f| f.in_result)
                .and_then(|f| f.href.clone())
        })
    }

    fn push_text(&mut self, text: &str) {
        let (bold, italic) = (self.bold, self.italic);
        let href = self.href();
        if let Some(p) = self.paras.last_mut() {
            p.spans.push(Span {
                text: text.to_owned(),
                href,
                bold,
                italic,
            });
        }
    }

    fn start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        match tag(e) {
            b"p" => self.paras.push(DocPara::default()),
            b"pStyle" => {
                if let Some(p) = self.paras.last_mut() {
                    p.style = attr(e, "val");
                }
            }
            b"ilvl" => {
                if let Some(p) = self.paras.last_mut() {
                    p.ilvl = attr(e, "val").and_then(|v| v.parse().ok()).unwrap_or(0);
                }
            }
            b"numId" => {
                if let Some(p) = self.paras.last_mut() {
                    p.num_id = attr(e, "val");
                }
            }
            b"outlineLvl" => {
                if let Some(p) = self.paras.last_mut() {
                    p.outline = attr(e, "val")
                        .and_then(|v| v.parse::<u8>().ok())
                        .filter(|v| *v < 9)
                        .map(|v| v + 1);
                }
            }
            b"r" => {
                self.bold = false;
                self.italic = false;
            }
            b"b" => self.bold = truthy(attr(e, "val")),
            b"i" => self.italic = truthy(attr(e, "val")),
            b"t" => self.in_t = true,
            b"instrText" => self.in_instr = true,
            b"tab" => self.push_text("\t"),
            b"br" | b"cr" => {
                if attr(e, "type").as_deref() != Some("page") {
                    self.push_text("\n");
                }
            }
            b"noBreakHyphen" => self.push_text("-"),
            b"hyperlink" => {
                self.hyperlink = attr_q(e, "r:id")
                    .and_then(|id| self.rels.get(&id))
                    .filter(|(_, external)| *external)
                    .map(|(t, _)| t.clone());
            }
            b"fldSimple" => {
                self.fields.push(Field {
                    instr: attr(e, "instr").unwrap_or_default(),
                    href: attr(e, "instr").as_deref().and_then(hyperlink_instr),
                    in_result: true,
                });
            }
            b"fldChar" => match attr(e, "fldCharType").as_deref() {
                Some("begin") => self.fields.push(Field::default()),
                Some("separate") => {
                    if let Some(f) = self.fields.last_mut() {
                        f.href = hyperlink_instr(&f.instr);
                        f.in_result = true;
                    }
                }
                Some("end") => {
                    self.fields.pop();
                }
                _ => {}
            },
            b"tbl" => {
                self.tbl_depth += 1;
                if self.tbl_depth == 1 {
                    self.rows.clear();
                }
            }
            b"tr" if self.tbl_depth == 1 => self.row = Vec::new(),
            b"tc" if self.tbl_depth == 1 => self.cell = Vec::new(),
            _ => {}
        }
    }

    fn end(&mut self, name: &[u8]) {
        match name {
            b"t" => self.in_t = false,
            b"instrText" => self.in_instr = false,
            b"hyperlink" => self.hyperlink = None,
            b"fldSimple" => {
                self.fields.pop();
            }
            b"p" => self.end_paragraph(),
            b"tc" if self.tbl_depth == 1 => {
                let mut joined: Spans = Vec::new();
                for (i, s) in std::mem::take(&mut self.cell).into_iter().enumerate() {
                    if i > 0 {
                        joined.push(Span::plain(" "));
                    }
                    joined.extend(s);
                }
                self.row.push(blocks::coalesce(joined));
            }
            b"tr" if self.tbl_depth == 1 => {
                let row = std::mem::take(&mut self.row);
                if self.rows.len() < self.limits.max_rows {
                    self.rows.push(row);
                } else {
                    self.rows_truncated = true;
                }
            }
            b"tbl" => {
                self.tbl_depth = self.tbl_depth.saturating_sub(1);
                if self.tbl_depth == 0 && !self.rows.is_empty() {
                    self.blocks.push(Block::Table(std::mem::take(&mut self.rows)));
                }
            }
            _ => {}
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
        let style_id = p.style.as_deref();
        let heading = style_id
            .and_then(|s| self.styles.heading_level(s))
            .or_else(|| p.outline.map(|l| l.clamp(1, 6)));
        if let Some(level) = heading {
            self.blocks.push(Block::Heading { level, spans });
            return;
        }
        if let Some(num) = p.num_id.as_deref().filter(|n| *n != "0") {
            self.blocks.push(Block::Item {
                depth: p.ilvl.min(8),
                ordered: self.numbering.ordered(num, p.ilvl),
                spans,
            });
            return;
        }
        if let Some(name) = style_id.and_then(|s| self.styles.name(s)) {
            let list = |prefix: &str| {
                name.strip_prefix(prefix)
                    .filter(|rest| !rest.starts_with(" continue"))
                    .map(|rest| rest.trim().parse::<u8>().unwrap_or(1).saturating_sub(1).min(8))
            };
            if let Some(depth) = list("list bullet") {
                self.blocks.push(Block::Item {
                    depth,
                    ordered: false,
                    spans,
                });
                return;
            }
            if let Some(depth) = list("list number") {
                self.blocks.push(Block::Item {
                    depth,
                    ordered: true,
                    spans,
                });
                return;
            }
        }
        self.blocks.push(Block::Paragraph(spans));
    }
}

/// Parse `.docx`/`.docm`.
///
/// # Errors
/// [`ParseError::Corrupt`] / [`ParseError::TooLarge`] from the container or its XML parts.
pub(crate) fn parse_docx(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let mut z = ZipBox::open(bytes, "docx", limits)?;
    let document = z.require("word/document.xml")?;
    let styles = z
        .read("word/styles.xml")?
        .map(|x| Styles::parse(&x))
        .unwrap_or_default();
    let numbering = z
        .read("word/numbering.xml")?
        .map(|x| Numbering::parse(&x))
        .unwrap_or_default();
    let rels = z
        .read("word/_rels/document.xml.rels")?
        .map(|x| parse_rels(&x, "docx"))
        .unwrap_or_default();
    let mut out = Parsed::default();
    if let Some(core) = z.read("docProps/core.xml")? {
        core_props(&core, "docx", &mut out);
    }
    let mut w = DocxWalk {
        styles: &styles,
        numbering: &numbering,
        rels: &rels,
        limits,
        paras: Vec::new(),
        blocks: Vec::new(),
        tbl_depth: 0,
        rows: Vec::new(),
        row: Vec::new(),
        cell: Vec::new(),
        bold: false,
        italic: false,
        in_t: false,
        in_instr: false,
        hyperlink: None,
        fields: Vec::new(),
        skip: 0,
        rows_truncated: false,
    };
    xml::walk(&document, "docx", |ev| {
        if w.skip > 0 {
            match ev {
                Ev::Start(_) => w.skip += 1,
                Ev::End(_) => w.skip -= 1,
                Ev::Text(_) => {}
            }
            return Ok(true);
        }
        match ev {
            Ev::Start(e) => {
                if tag(e) == b"Fallback" {
                    w.skip = 1;
                } else {
                    w.start(e);
                }
            }
            Ev::End(name) => w.end(name),
            Ev::Text(t) => {
                if w.in_t {
                    w.push_text(t);
                } else if w.in_instr {
                    if let Some(f) = w.fields.last_mut() {
                        f.instr.push_str(t);
                    }
                }
            }
        }
        Ok(true)
    })?;
    if w.rows_truncated {
        out.warnings
            .push("table rows beyond the row limit were dropped".to_owned());
    }
    out.blocks = w.blocks;
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// PPTX
// ---------------------------------------------------------------------------------------------

struct SlidePara {
    level: u8,
    bullet: Option<bool>,
    no_bullet: bool,
    spans: Spans,
}

#[derive(Default)]
struct Shape {
    ph: Option<String>,
    is_ph: bool,
    paras: Vec<SlidePara>,
}

fn parse_slide(xml_bytes: &[u8], rels: &Rels, limits: &ParseLimits) -> Result<Vec<Block>, ParseError> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut shape: Option<Shape> = None;
    let mut shape_depth = 0usize;
    let mut para: Option<SlidePara> = None;
    let mut bold = false;
    let mut italic = false;
    let mut href: Option<String> = None;
    let mut in_t = false;
    let mut tbl_depth = 0usize;
    let mut rows: Vec<Row> = Vec::new();
    let mut row: Row = Vec::new();
    let mut cell: Vec<Spans> = Vec::new();

    xml::walk(xml_bytes, "pptx", |ev| {
        match ev {
            Ev::Start(e) => match tag(e) {
                b"sp" => {
                    shape_depth += 1;
                    if shape_depth == 1 {
                        shape = Some(Shape::default());
                    }
                }
                b"ph" => {
                    if let Some(s) = shape.as_mut() {
                        s.is_ph = true;
                        s.ph = attr(e, "type");
                    }
                }
                b"tbl" => {
                    tbl_depth += 1;
                    if tbl_depth == 1 {
                        rows.clear();
                    }
                }
                b"tr" if tbl_depth == 1 => row = Vec::new(),
                b"tc" if tbl_depth == 1 => cell = Vec::new(),
                b"p" => {
                    para = Some(SlidePara {
                        level: 0,
                        bullet: None,
                        no_bullet: false,
                        spans: Vec::new(),
                    });
                }
                b"pPr" => {
                    if let Some(p) = para.as_mut() {
                        p.level = attr(e, "lvl").and_then(|v| v.parse().ok()).unwrap_or(0);
                    }
                }
                b"buChar" => {
                    if let Some(p) = para.as_mut() {
                        p.bullet = Some(false);
                    }
                }
                b"buAutoNum" => {
                    if let Some(p) = para.as_mut() {
                        p.bullet = Some(true);
                    }
                }
                b"buNone" => {
                    if let Some(p) = para.as_mut() {
                        p.no_bullet = true;
                    }
                }
                b"rPr" => {
                    bold = attr(e, "b").is_some_and(|v| v == "1" || v == "true");
                    italic = attr(e, "i").is_some_and(|v| v == "1" || v == "true");
                    href = None;
                }
                b"hlinkClick" => {
                    href = attr_q(e, "r:id")
                        .and_then(|id| rels.get(&id))
                        .filter(|(_, external)| *external)
                        .map(|(t, _)| t.clone());
                }
                b"t" => in_t = true,
                b"br" => {
                    if let Some(p) = para.as_mut() {
                        p.spans.push(Span::plain("\n"));
                    }
                }
                _ => {}
            },
            Ev::Text(t) => {
                if in_t {
                    if let Some(p) = para.as_mut() {
                        p.spans.push(Span {
                            text: t.to_owned(),
                            href: href.clone(),
                            bold,
                            italic,
                        });
                    }
                }
            }
            Ev::End(name) => match name {
                b"t" => in_t = false,
                b"r" => {
                    bold = false;
                    italic = false;
                    href = None;
                }
                b"p" => {
                    if let Some(mut p) = para.take() {
                        p.spans = blocks::normalise(std::mem::take(&mut p.spans));
                        if tbl_depth > 0 {
                            if !p.spans.is_empty() {
                                cell.push(p.spans);
                            }
                        } else if let Some(s) = shape.as_mut() {
                            if !p.spans.is_empty() {
                                s.paras.push(p);
                            }
                        }
                    }
                }
                b"tc" if tbl_depth == 1 => {
                    let mut joined: Spans = Vec::new();
                    for (i, s) in std::mem::take(&mut cell).into_iter().enumerate() {
                        if i > 0 {
                            joined.push(Span::plain(" "));
                        }
                        joined.extend(s);
                    }
                    row.push(blocks::coalesce(joined));
                }
                b"tr" if tbl_depth == 1 => {
                    let r = std::mem::take(&mut row);
                    if rows.len() < limits.max_rows {
                        rows.push(r);
                    }
                }
                b"tbl" => {
                    tbl_depth = tbl_depth.saturating_sub(1);
                    if tbl_depth == 0 && !rows.is_empty() {
                        blocks.push(Block::Table(std::mem::take(&mut rows)));
                    }
                }
                b"sp" => {
                    shape_depth = shape_depth.saturating_sub(1);
                    if shape_depth == 0 {
                        if let Some(s) = shape.take() {
                            emit_shape(s, &mut blocks);
                        }
                    }
                }
                _ => {}
            },
        }
        Ok(true)
    })?;
    Ok(blocks)
}

fn emit_shape(s: Shape, blocks: &mut Vec<Block>) {
    let ph = s.ph.as_deref();
    if matches!(ph, Some("sldNum" | "ftr" | "dt" | "hdr")) {
        return;
    }
    let title = matches!(ph, Some("title" | "ctrTitle"));
    let body_ph = s.is_ph && !title && !matches!(ph, Some("subTitle"));
    for p in s.paras {
        if title {
            blocks.push(Block::Heading {
                level: 1,
                spans: p.spans,
            });
            continue;
        }
        let listed = !p.no_bullet && (p.bullet.is_some() || body_ph);
        if listed {
            blocks.push(Block::Item {
                depth: p.level.min(8),
                ordered: p.bullet == Some(true),
                spans: p.spans,
            });
        } else {
            blocks.push(Block::Paragraph(p.spans));
        }
    }
}

/// Parse `.pptx`/`.pptm`.
///
/// # Errors
/// [`ParseError::Corrupt`] / [`ParseError::TooLarge`] from the container or its XML parts.
pub(crate) fn parse_pptx(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let mut z = ZipBox::open(bytes, "pptx", limits)?;
    let presentation = z.require("ppt/presentation.xml")?;
    let prels = z
        .read("ppt/_rels/presentation.xml.rels")?
        .map(|x| parse_rels(&x, "pptx"))
        .unwrap_or_default();
    let mut slide_paths: Vec<String> = Vec::new();
    xml::walk(&presentation, "pptx", |ev| {
        if let Ev::Start(e) = ev {
            if tag(e) == b"sldId" {
                if let Some((target, _)) = attr_q(e, "r:id").and_then(|id| prels.get(&id)) {
                    slide_paths.push(resolve("ppt/presentation.xml", target));
                }
            }
        }
        Ok(true)
    })?;
    let mut out = Parsed::default();
    if let Some(core) = z.read("docProps/core.xml")? {
        core_props(&core, "pptx", &mut out);
    }
    if slide_paths.len() > limits.max_pages {
        out.warnings.push(format!(
            "the presentation has {} slides; only the first {} were parsed",
            slide_paths.len(),
            limits.max_pages
        ));
        slide_paths.truncate(limits.max_pages);
    }
    for (i, path) in slide_paths.iter().enumerate() {
        let xml_bytes = z.require(path)?;
        let rels_path = {
            let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
            format!("{dir}/_rels/{file}.rels")
        };
        let rels = z
            .read(&rels_path)?
            .map(|x| parse_rels(&x, "pptx"))
            .unwrap_or_default();
        if i > 0 {
            out.blocks.push(Block::Rule);
        }
        out.blocks.extend(parse_slide(&xml_bytes, &rels, limits)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// XLSX / XLSB
// ---------------------------------------------------------------------------------------------

fn map_xlsx(e: &calamine::XlsxError) -> ParseError {
    let msg = e.to_string();
    if msg.to_lowercase().contains("password") {
        ParseError::Encrypted { format: "xlsx" }
    } else {
        ParseError::corrupt("xlsx", msg)
    }
}

fn map_xlsb(e: &calamine::XlsbError) -> ParseError {
    let msg = e.to_string();
    if msg.to_lowercase().contains("password") {
        ParseError::Encrypted { format: "xlsb" }
    } else {
        ParseError::corrupt("xlsb", msg)
    }
}

fn sheet_meta(z: &mut ZipBox<'_>, format: &'static str, out: &mut Parsed) -> Result<(), ParseError> {
    if let Some(core) = z.read("docProps/core.xml")? {
        core_props(&core, format, out);
    }
    Ok(())
}

/// Parse `.xlsx`/`.xlsm`.
///
/// # Errors
/// [`ParseError::Corrupt`], [`ParseError::Encrypted`] or [`ParseError::TooLarge`].
pub(crate) fn parse_xlsx(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let mut z = ZipBox::open(bytes, "xlsx", limits)?;
    let mut out = Parsed::default();
    sheet_meta(&mut z, "xlsx", &mut out)?;
    z.verify_all()?;
    let mut wb: Xlsx<_> = Xlsx::new(Cursor::new(bytes)).map_err(|e| map_xlsx(&e))?;
    let names = wb.sheet_names();
    if names.len() > limits.max_sheets {
        out.warnings.push(format!(
            "the workbook has {} sheets; only the first {} were parsed",
            names.len(),
            limits.max_sheets
        ));
    }
    let mut sheets = Vec::new();
    for name in names.into_iter().take(limits.max_sheets) {
        let mut sh = Sheet::new(name.clone());
        let mut reader = wb.worksheet_cells_reader(&name).map_err(|e| map_xlsx(&e))?;
        while let Some(cell) = reader.next_cell().map_err(|e| map_xlsx(&e))? {
            let (row, col) = cell.get_position();
            if !sh.put(row, col, sheet::cell_ref_text(cell.get_value()), limits) {
                break;
            }
        }
        sheets.push(sh);
    }
    sheet::render(&sheets, &mut out.blocks, &mut out.warnings);
    Ok(out)
}

/// Parse `.xlsb`.
///
/// # Errors
/// [`ParseError::Corrupt`], [`ParseError::Encrypted`] or [`ParseError::TooLarge`].
pub(crate) fn parse_xlsb(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let mut z = ZipBox::open(bytes, "xlsb", limits)?;
    let mut out = Parsed::default();
    sheet_meta(&mut z, "xlsb", &mut out)?;
    z.verify_all()?;
    let mut wb: Xlsb<_> = Xlsb::new(Cursor::new(bytes)).map_err(|e| map_xlsb(&e))?;
    let names = wb.sheet_names();
    if names.len() > limits.max_sheets {
        out.warnings.push(format!(
            "the workbook has {} sheets; only the first {} were parsed",
            names.len(),
            limits.max_sheets
        ));
    }
    let mut sheets = Vec::new();
    for name in names.into_iter().take(limits.max_sheets) {
        let mut sh = Sheet::new(name.clone());
        let mut reader = wb.worksheet_cells_reader(&name).map_err(|e| map_xlsb(&e))?;
        while let Some(cell) = reader.next_cell().map_err(|e| map_xlsb(&e))? {
            let (row, col) = cell.get_position();
            if !sh.put(row, col, sheet::cell_ref_text(cell.get_value()), limits) {
                break;
            }
        }
        sheets.push(sh);
    }
    sheet::render(&sheets, &mut out.blocks, &mut out.warnings);
    Ok(out)
}
