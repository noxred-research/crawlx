//! PDF text-layer extraction (`/parse` and PDF URL scraping).
//!
//! [`extract_pdf`] reads every page's content stream with `lopdf`, follows the text operators
//! (`Tf`, `Td`, `TD`, `Tm`, `T*`, `Tj`, `TJ`, `'`, `"`, `cm`, `q`/`Q`) to place each shown string
//! on the page, and rebuilds lines and paragraphs from the positions:
//!
//! * strings on one baseline are joined left to right; a horizontal gap wider than a word
//!   space becomes a space, a smaller one (kerning, font change inside a word) does not;
//! * on a single-column page lines are ordered top to bottom whatever the order of the content
//!   stream; on pages with side-by-side text (columns, table rows) the stream order is kept,
//!   because it is the producer's reading order;
//! * lines that wrap (small vertical gap) join into one paragraph, a hyphen at a line end is
//!   removed, a larger gap starts a new paragraph;
//! * lines set in a larger font than the document's body text become `#`/`##`/`###` headings,
//!   lines starting with a bullet or `1.` become list items.
//!
//! Text in form XObjects is out of scope. Pages without extractable text are OCR'd when
//! [`PdfOptions::ocr`] holds an engine and [`PdfOptions::ocr_mode`] allows it
//! ([`super::ocr`]); without one they are counted in a warning. Encrypted documents fail with
//! [`ParseError::Encrypted`]; corrupt ones with [`ParseError::Corrupt`]. No input panics: the
//! `lopdf` calls run under [`super::guard`].

mod sanitize;

pub use sanitize::sanitize_pdf;

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;

use lopdf::content::Content;
use lopdf::{DecompressError, Dictionary, Document, Encoding, LoadOptions, Object, ObjectId};

use super::blocks::{self, Block, Span};
use super::ocr::pdf_pages::{PageOutcome, PdfOcr, Session};
use super::ocr::Ocr;
use super::{ParseError, ParseLimits};

/// The text of one PDF page.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PdfPage {
    /// 1-based physical page number.
    pub number: u32,
    /// Markdown of the page.
    pub markdown: String,
    /// Plain text of the page.
    pub text: String,
    pub(crate) blocks: Vec<Block>,
}

/// Document information dictionary of a PDF.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PdfMetadata {
    /// `/Title`.
    pub title: Option<String>,
    /// `/Author`.
    pub author: Option<String>,
    /// `/Subject`.
    pub subject: Option<String>,
    /// `/Keywords`.
    pub keywords: Option<String>,
    /// `/Creator`: the application that made the original document.
    pub creator: Option<String>,
    /// `/Producer`: the application that made the PDF.
    pub producer: Option<String>,
    /// `/CreationDate` as written (`D:YYYYMMDDHHmmSS...`).
    pub creation_date: Option<String>,
    /// `/ModDate` as written.
    pub modification_date: Option<String>,
    /// File header version, e.g. `1.7`.
    pub version: String,
}

/// Options of [`extract_pdf`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PdfOptions {
    /// Parse at most this many pages (after `pages` selection); `None` parses up to
    /// `limits.max_pages`.
    pub max_pages: Option<u32>,
    /// Parse only these 1-based physical pages (document order, duplicates ignored, pages
    /// beyond the document ignored with a warning). Empty selects every page.
    pub pages: Vec<u32>,
    /// Join pages in [`PdfText::markdown`] with `\n\n---\n\n<!-- page N -->\n\n`, where `N` is
    /// the physical page of the content that follows. Markers appear between pages only and
    /// pages without text are skipped, so numbering can jump.
    pub page_markers: bool,
    /// Fail with [`ParseError::NoText`] when no parsed page has a text layer (`mode: fast`).
    pub require_text: bool,
    /// Also build [`PdfText::layout`], the typed layout blocks with bounding boxes.
    pub layout: bool,
    /// The OCR engine for pages without a text layer (or every page, per [`Self::ocr_mode`]).
    /// `None` keeps the text layer only.
    pub ocr: Option<Arc<Ocr>>,
    /// Which pages are OCR'd when [`Self::ocr`] is set. Default [`PdfOcr::Off`]: set it
    /// explicitly (`parsers[].mode`: `fast` is `Off`, `auto` is `Auto`, `ocr` is `Always`).
    pub ocr_mode: PdfOcr,
    /// Resource limits.
    pub limits: ParseLimits,
}

/// A typed layout block of a page (`parsers[].blocks`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PdfLayoutBlock {
    /// `p<page>.b<index in reading order>`.
    pub id: String,
    /// Block type: `title`, `section_header`, `text`, `table`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// Raw layout label; none for the text-layer parser.
    pub label: Option<String>,
    /// `[x0, y0, x1, y1]` normalised 0-1 relative to the page, origin top left.
    pub bbox: Option<[f64; 4]>,
    /// The Markdown fragment of this block.
    pub content: String,
    /// `[start, end)` character offsets of `content` in the document Markdown.
    pub markdown_span: Option<[usize; 2]>,
    /// Position in the reading order of the page.
    pub reading_order: usize,
    /// Pipeline that produced the block: `native_text` (the text layer) or `ocr`.
    pub source: &'static str,
    /// Detection and OCR confidence; `ocr` is set for `ocr` blocks when the engine reports
    /// confidences (Tesseract does, `ocrs` does not), everything else is `null`.
    pub confidence: LayoutConfidence,
}

/// Confidence of a layout block; `None` when the source provides none.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[non_exhaustive]
pub struct LayoutConfidence {
    /// Layout-model detection score.
    pub layout: Option<f64>,
    /// OCR text confidence.
    pub ocr: Option<f64>,
}

/// Layout blocks of one page.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PdfPageBlocks {
    /// 1-based physical page number.
    pub page_number: u32,
    /// Page width in PDF points.
    pub width: Option<f64>,
    /// Page height in PDF points.
    pub height: Option<f64>,
    /// `ok` when blocks were found, `failed` for a page without a text layer.
    pub status: &'static str,
    /// The blocks in reading order.
    pub items: Vec<PdfLayoutBlock>,
}

/// Text and metadata of a PDF document.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PdfText {
    /// Markdown of the parsed pages; pages are separated by a blank line, or by page markers
    /// when [`PdfOptions::page_markers`] is set.
    pub markdown: String,
    /// Plain text of the parsed pages, separated by a blank line.
    pub text: String,
    /// Number of pages parsed (`numPages`).
    pub num_pages: u32,
    /// Page count of the document before any selection or capping (`totalPages`).
    pub total_pages: u32,
    /// The parsed pages in order.
    pub pages: Vec<PdfPage>,
    /// Typed layout blocks per page; empty unless [`PdfOptions::layout`].
    pub layout: Vec<PdfPageBlocks>,
    /// Info dictionary.
    pub metadata: PdfMetadata,
    /// Distinct `http(s)` targets of link annotations on the parsed pages, in page order.
    pub links: Vec<String>,
    /// Non-fatal findings (pages without a text layer, undecodable content streams, capping).
    pub warnings: Vec<String>,
}

impl PdfText {
    /// Blocks of every parsed page, pages separated by a rule.
    pub(crate) fn all_blocks(&self) -> Vec<Block> {
        let mut out = Vec::new();
        for p in &self.pages {
            if !out.is_empty() && !p.blocks.is_empty() {
                out.push(Block::Rule);
            }
            out.extend(p.blocks.iter().cloned());
        }
        out
    }
}

fn join_pages<'a>(
    pages: impl Iterator<Item = (u32, &'a str)>,
    markers: bool,
) -> (String, BTreeMap<u32, usize>) {
    let mut out = String::new();
    let mut chars = 0usize;
    let mut offsets = BTreeMap::new();
    for (number, md) in pages.filter(|(_, md)| !md.is_empty()) {
        if !out.is_empty() {
            let sep = if markers {
                format!("\n\n---\n\n<!-- page {number} -->\n\n")
            } else {
                "\n\n".to_owned()
            };
            chars += sep.chars().count();
            out.push_str(&sep);
        }
        offsets.insert(number, chars);
        chars += md.chars().count();
        out.push_str(md);
    }
    (out, offsets)
}

/// Extract the text layer and metadata of a PDF.
///
/// Synchronous and CPU-bound: call it from a blocking thread, never from an async task.
///
/// # Errors
/// [`ParseError::TooLarge`] when the input or a decompressed content stream exceeds a limit;
/// [`ParseError::Encrypted`] for password-protected documents;
/// [`ParseError::Corrupt`] when the bytes are not a readable PDF or contain no pages.
pub fn extract_pdf(bytes: &[u8], options: &PdfOptions) -> Result<PdfText, ParseError> {
    let limits = &options.limits;
    if bytes.len() > limits.max_input_bytes {
        return Err(ParseError::TooLarge {
            what: "input bytes",
            limit: limits.max_input_bytes,
            actual: bytes.len(),
        });
    }
    let head = &bytes[..bytes.len().min(1024)];
    if !head.windows(5).any(|w| w == b"%PDF-") {
        return Err(ParseError::corrupt("pdf", "missing %PDF- header"));
    }
    super::guard("pdf", || extract_inner(bytes, options))
}

fn map_lopdf(e: lopdf::Error) -> ParseError {
    match e {
        lopdf::Error::InvalidPassword
        | lopdf::Error::Decryption(_)
        | lopdf::Error::UnsupportedSecurityHandler(_)
        | lopdf::Error::AlreadyEncrypted => ParseError::Encrypted { format: "pdf" },
        lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { limit }) => ParseError::TooLarge {
            what: "decompressed stream bytes",
            limit,
            actual: limit.saturating_add(1),
        },
        other => ParseError::corrupt_from("pdf", "the file structure cannot be read", other),
    }
}

/// Pages to parse: the selection (or all pages), capped, in document order.
fn select_pages(
    all: &BTreeMap<u32, ObjectId>,
    options: &PdfOptions,
    warnings: &mut Vec<String>,
) -> Vec<(u32, ObjectId)> {
    let mut picked: Vec<(u32, ObjectId)> = if options.pages.is_empty() {
        all.iter().map(|(n, id)| (*n, *id)).collect()
    } else {
        let mut want: Vec<u32> = options.pages.clone();
        want.sort_unstable();
        want.dedup();
        let missing: Vec<String> = want
            .iter()
            .filter(|n| !all.contains_key(n))
            .map(ToString::to_string)
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "requested pages not in the document (it has {} pages): {}",
                all.len(),
                missing.join(", ")
            ));
        }
        want.iter()
            .filter_map(|n| all.get(n).map(|id| (*n, *id)))
            .collect()
    };
    let cap = options.max_pages.map_or(options.limits.max_pages, |m| {
        usize::try_from(m)
            .unwrap_or(usize::MAX)
            .min(options.limits.max_pages)
    });
    if picked.len() > cap {
        warnings.push(format!(
            "{} pages selected; only the first {cap} were parsed",
            picked.len()
        ));
        picked.truncate(cap);
    }
    picked
}

/// A page's `MediaBox` as `(x0, y0, x1, y1)` in PDF points.
type PageBox = (f32, f32, f32, f32);
/// A parsed page: number, text lines and media box.
type LinedPage = (u32, Vec<Line>, Option<PageBox>);
/// A page with positioned blocks: number, blocks and media box.
type PlacedPage = (u32, Vec<Placed>, Option<PageBox>);

fn page_box(doc: &Document, page: ObjectId) -> Option<PageBox> {
    let mut id = page;
    for _ in 0..16 {
        let dict = doc.get_dictionary(id).ok()?;
        if let Ok(obj) = dict.get_deref(b"MediaBox", doc) {
            let arr = obj.as_array().ok()?;
            let n: Vec<f32> = arr
                .iter()
                .filter_map(|o| doc.dereference(o).ok().and_then(|(_, o)| o.as_float().ok()))
                .collect();
            if let [a, b, c, d] = n[..] {
                let (x0, x1) = (a.min(c), a.max(c));
                let (y0, y1) = (b.min(d), b.max(d));
                return (x1 > x0 && y1 > y0).then_some((x0, y0, x1, y1));
            }
            return None;
        }
        id = dict.get(b"Parent").ok()?.as_reference().ok()?;
    }
    None
}

/// Char offsets of the byte offsets `at` (ascending) in `s`.
fn char_offsets(s: &str, at: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(at.len());
    let mut chars = 0usize;
    let mut it = s.char_indices().peekable();
    for &b in at {
        while let Some(&(i, _)) = it.peek() {
            if i >= b {
                break;
            }
            chars += 1;
            it.next();
        }
        out.push(chars);
    }
    out
}

fn layout_blocks(
    number: u32,
    dims: Option<PageBox>,
    placed: &[Placed],
    page_md_offset: Option<usize>,
    first_heading_taken: &mut bool,
) -> PdfPageBlocks {
    let blocks: Vec<Block> = placed.iter().map(|p| p.block.clone()).collect();
    let (md, spans) = blocks::render_markdown_spans(&blocks);
    let mut cuts: Vec<usize> = Vec::new();
    for (s, e) in spans.iter().flatten() {
        cuts.push(*s);
        cuts.push(*e);
    }
    let chars = char_offsets(&md, &cuts);
    let mut next = 0usize;
    let mut items = Vec::with_capacity(placed.len());
    for (i, p) in placed.iter().enumerate() {
        let kind = match &p.block {
            Block::Heading { level: 1, .. } if !*first_heading_taken => {
                *first_heading_taken = true;
                "title"
            }
            Block::Heading { .. } => "section_header",
            Block::Table(_) => "table",
            _ => "text",
        };
        let (content, span) = match spans.get(i).copied().flatten() {
            Some((s, e)) => {
                let (cs, ce) = (chars[next], chars[next + 1]);
                next += 2;
                let frag = md.get(s..e).unwrap_or("").to_owned();
                (frag, page_md_offset.map(|o| [o + cs, o + ce]))
            }
            None => (String::new(), None),
        };
        let bbox = dims.map(|(llx, lly, urx, ury)| {
            let (w, h) = (f64::from(urx - llx), f64::from(ury - lly));
            let nx = |x: f32| (f64::from(x - llx) / w).clamp(0.0, 1.0);
            let ny = |y: f32| (f64::from(ury - y) / h).clamp(0.0, 1.0);
            [
                nx(p.extent.x0),
                ny(p.extent.top),
                nx(p.extent.x1),
                ny(p.extent.bottom),
            ]
        });
        items.push(PdfLayoutBlock {
            id: format!("p{number}.b{i}"),
            kind,
            label: None,
            bbox,
            content,
            markdown_span: span,
            reading_order: i,
            source: if p.ocr.is_some() { "ocr" } else { "native_text" },
            confidence: LayoutConfidence {
                layout: None,
                ocr: p.ocr.flatten(),
            },
        });
    }
    PdfPageBlocks {
        page_number: number,
        width: dims.map(|d| f64::from(d.2 - d.0)),
        height: dims.map(|d| f64::from(d.3 - d.1)),
        status: if items.is_empty() { "failed" } else { "ok" },
        items,
    }
}

fn extract_inner(bytes: &[u8], options: &PdfOptions) -> Result<PdfText, ParseError> {
    let limits = &options.limits;
    let load = LoadOptions {
        max_total_decompressed_size: Some(limits.max_uncompressed_bytes),
        max_objects: Some(limits.max_entries),
        ..LoadOptions::with_max_decompressed_size(limits.max_uncompressed_bytes)
    };
    let doc = Document::load_mem_with_options(bytes, load).map_err(map_lopdf)?;
    if doc.is_encrypted() {
        return Err(ParseError::Encrypted { format: "pdf" });
    }
    let all = doc.get_pages();
    if all.is_empty() {
        return Err(ParseError::corrupt("pdf", "the document has no pages"));
    }
    let total_pages = u32::try_from(all.len()).unwrap_or(u32::MAX);
    let mut warnings = Vec::new();
    let chosen = select_pages(&all, options, &mut warnings);
    let page_ids: BTreeMap<u32, ObjectId> = chosen.iter().copied().collect();
    let mut budget = limits.max_uncompressed_bytes;
    let mut page_lines: Vec<LinedPage> = Vec::new();
    let mut links: Vec<String> = Vec::new();
    for (number, id) in chosen {
        let content = doc.get_page_content_with_limit(id, budget).map_err(map_lopdf)?;
        budget = budget.saturating_sub(content.len());
        let lines = match Content::decode(&content) {
            Ok(c) => layout_page(&doc, id, &c),
            Err(e) => {
                warnings.push(format!("page {number}: content stream cannot be decoded: {e}"));
                Vec::new()
            }
        };
        collect_links(&doc, id, &mut links);
        page_lines.push((number, lines, page_box(&doc, id)));
    }
    let body = body_size(page_lines.iter().flat_map(|(_, l, _)| l.iter()));
    let mut ocr_session = match (&options.ocr, options.ocr_mode) {
        (Some(engine), PdfOcr::Auto | PdfOcr::Always) => Some(Session::new(engine, &doc, bytes, budget)),
        _ => None,
    };
    let mut placed_pages: Vec<PlacedPage> = Vec::new();
    let mut pages: Vec<PdfPage> = Vec::new();
    let mut empty_pages = 0usize;
    for (number, lines, dims) in page_lines {
        let mut placed = page_blocks(&lines, body);
        if let (Some(session), Some(id)) = (ocr_session.as_mut(), page_ids.get(&number)) {
            let has_text = !placed.is_empty();
            if options.ocr_mode == PdfOcr::Always || !has_text {
                let PageOutcome {
                    paragraphs,
                    warnings: ocr_warnings,
                    replaces_text,
                } = session.page(number, *id, options.ocr_mode, has_text);
                warnings.extend(ocr_warnings);
                if replaces_text && !paragraphs.is_empty() {
                    placed.clear();
                }
                placed.extend(paragraphs.into_iter().map(|p| Placed {
                    block: Block::Paragraph(vec![Span::plain(p.text)]),
                    extent: Extent {
                        x0: p.bbox[0],
                        bottom: p.bbox[1],
                        x1: p.bbox[2],
                        top: p.bbox[3],
                    },
                    ocr: Some(p.confidence),
                }));
            }
        }
        let blocks: Vec<Block> = placed.iter().map(|p| p.block.clone()).collect();
        if blocks.is_empty() {
            empty_pages += 1;
        }
        pages.push(PdfPage {
            number,
            markdown: blocks::render_markdown(&blocks),
            text: blocks::render_text(&blocks),
            blocks,
        });
        placed_pages.push((number, placed, dims));
    }
    if options.require_text && empty_pages == pages.len() {
        return Err(ParseError::NoText { format: "pdf" });
    }
    if empty_pages > 0 {
        let why = if ocr_session.is_some() {
            "OCR found none"
        } else {
            "scanned or image-only pages are not OCR'd"
        };
        warnings.push(format!(
            "{empty_pages} of {} parsed pages have no extractable text ({why})",
            pages.len()
        ));
    }
    let (markdown, offsets) = join_pages(
        pages.iter().map(|p| (p.number, p.markdown.as_str())),
        options.page_markers,
    );
    let (text, _) = join_pages(pages.iter().map(|p| (p.number, p.text.as_str())), false);
    let mut layout = Vec::new();
    if options.layout {
        let mut first_heading_taken = false;
        for (number, placed, dims) in &placed_pages {
            layout.push(layout_blocks(
                *number,
                *dims,
                placed,
                offsets.get(number).copied(),
                &mut first_heading_taken,
            ));
        }
    }
    Ok(PdfText {
        markdown,
        text,
        num_pages: u32::try_from(pages.len()).unwrap_or(u32::MAX),
        total_pages,
        pages,
        layout,
        metadata: read_metadata(&doc),
        links,
        warnings,
    })
}

fn info_string(doc: &Document, info: &Dictionary, key: &[u8]) -> Option<String> {
    let obj = info.get_deref(key, doc).ok()?;
    let text = lopdf::decode_text_string(obj).ok()?;
    let text = blocks::collapse(&text);
    (!text.is_empty()).then_some(text)
}

fn read_metadata(doc: &Document) -> PdfMetadata {
    let version = doc.version.clone();
    let info = doc
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|o| doc.dereference(o).ok())
        .and_then(|(_, o)| o.as_dict().ok());
    let Some(info) = info else {
        return PdfMetadata {
            version,
            ..PdfMetadata::default()
        };
    };
    PdfMetadata {
        title: info_string(doc, info, b"Title"),
        author: info_string(doc, info, b"Author"),
        subject: info_string(doc, info, b"Subject"),
        keywords: info_string(doc, info, b"Keywords"),
        creator: info_string(doc, info, b"Creator"),
        producer: info_string(doc, info, b"Producer"),
        creation_date: info_string(doc, info, b"CreationDate"),
        modification_date: info_string(doc, info, b"ModDate"),
        version,
    }
}

fn collect_links(doc: &Document, page: ObjectId, out: &mut Vec<String>) {
    let Ok(annots) = doc.get_page_annotations(page) else {
        return;
    };
    for a in annots {
        let Ok(action) = a.get_deref(b"A", doc).and_then(Object::as_dict) else {
            continue;
        };
        let Ok(uri) = action.get_deref(b"URI", doc) else {
            continue;
        };
        let Ok(uri) = lopdf::decode_text_string(uri) else {
            continue;
        };
        let uri = uri.trim();
        let lower = uri.get(..8).unwrap_or(uri).to_ascii_lowercase();
        if (lower.starts_with("http://") || lower.starts_with("https://")) && !out.iter().any(|u| u == uri) {
            out.push(uri.to_owned());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Content stream walk
// ---------------------------------------------------------------------------------------------

pub(crate) type Matrix = [f32; 6];
pub(crate) const IDENTITY: Matrix = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];

/// `a` followed by `b` (row-vector convention of the PDF spec).
pub(crate) fn mul(a: &Matrix, b: &Matrix) -> Matrix {
    [
        a[0] * b[0] + a[1] * b[2],
        a[0] * b[1] + a[1] * b[3],
        a[2] * b[0] + a[3] * b[2],
        a[2] * b[1] + a[3] * b[3],
        a[4] * b[0] + a[5] * b[2] + b[4],
        a[4] * b[1] + a[5] * b[3] + b[5],
    ]
}

fn num(op: &lopdf::content::Operation, i: usize) -> f32 {
    op.operands
        .get(i)
        .and_then(|o| o.as_float().ok())
        .filter(|v| v.is_finite())
        .unwrap_or(0.0)
}

/// Approximate advance width of `c` in thousandths of an em, for fonts without a `/Widths` array.
fn default_width(c: char) -> f32 {
    match c {
        ' ' => 278.0,
        'i' | 'j' | 'l' | '.' | ',' | ':' | ';' | '\'' | '|' | '!' | 'I' => 250.0,
        't' | 'f' | 'r' | '(' | ')' | '[' | ']' | '-' | '/' => 330.0,
        'm' | 'M' | 'w' => 820.0,
        'W' => 940.0,
        '0'..='9' => 556.0,
        'A'..='Z' => 667.0,
        c if (c as u32) >= 0x2E80 => 1000.0,
        _ => 520.0,
    }
}

struct FontInfo<'a> {
    encoding: Option<Encoding<'a>>,
    first: i64,
    widths: Vec<f32>,
    missing: f32,
    composite: bool,
}

impl<'a> FontInfo<'a> {
    fn load(doc: &'a Document, dict: &'a Dictionary) -> Self {
        let composite = dict
            .get(b"Subtype")
            .and_then(Object::as_name)
            .is_ok_and(|n| n == b"Type0");
        let first = dict
            .get_deref(b"FirstChar", doc)
            .ok()
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(0);
        let widths = dict
            .get_deref(b"Widths", doc)
            .ok()
            .and_then(|o| o.as_array().ok())
            .map(|a| {
                a.iter()
                    .take(1024)
                    .map(|w| {
                        doc.dereference(w)
                            .ok()
                            .and_then(|(_, o)| o.as_float().ok())
                            .unwrap_or(0.0)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let missing = dict
            .get_deref(b"FontDescriptor", doc)
            .ok()
            .and_then(|o| o.as_dict().ok())
            .and_then(|d| d.get_deref(b"MissingWidth", doc).ok())
            .and_then(|o| o.as_float().ok())
            .unwrap_or(0.0);
        Self {
            encoding: dict.get_font_encoding(doc).ok(),
            first,
            widths,
            missing,
            composite,
        }
    }

    fn decode(&self, bytes: &[u8]) -> String {
        let decoded = match &self.encoding {
            Some(enc) => enc.bytes_to_string(bytes).ok(),
            None => None,
        };
        let text = decoded.unwrap_or_else(|| bytes.iter().map(|b| char::from(*b)).collect());
        text.chars()
            .map(|c| if c == '\t' || c == '\u{a0}' { ' ' } else { c })
            .filter(|c| !c.is_control())
            .collect()
    }

    /// Advance of `bytes` (shown as `text`) in thousandths of an em, word spacing excluded.
    fn advance(&self, bytes: &[u8], text: &str) -> f32 {
        if self.composite || self.widths.is_empty() {
            return text.chars().map(default_width).sum();
        }
        bytes
            .iter()
            .map(|b| {
                let idx = i64::from(*b) - self.first;
                usize::try_from(idx)
                    .ok()
                    .and_then(|i| self.widths.get(i).copied())
                    .filter(|w| *w > 0.0)
                    .unwrap_or(if self.missing > 0.0 {
                        self.missing
                    } else {
                        default_width(char::from(*b))
                    })
            })
            .sum()
    }
}

/// A shown string placed on the page.
#[derive(Debug, Clone)]
struct Frag {
    x: f32,
    end: f32,
    y: f32,
    size: f32,
    text: String,
}

/// One line of text.
#[derive(Debug, Clone)]
struct Line {
    y: f32,
    x0: f32,
    x1: f32,
    size: f32,
    text: String,
}

struct TextState {
    tm: Matrix,
    tlm: Matrix,
    font_size: f32,
    leading: f32,
    char_space: f32,
    word_space: f32,
    hscale: f32,
}

impl TextState {
    fn new() -> Self {
        Self {
            tm: IDENTITY,
            tlm: IDENTITY,
            font_size: 12.0,
            leading: 0.0,
            char_space: 0.0,
            word_space: 0.0,
            hscale: 1.0,
        }
    }

    fn move_line(&mut self, tx: f32, ty: f32) {
        self.tlm = mul(&[1.0, 0.0, 0.0, 1.0, tx, ty], &self.tlm);
        self.tm = self.tlm;
    }
}

/// Fragments of one page in content-stream order.
fn page_fragments(doc: &Document, page: ObjectId, content: &Content) -> Vec<Frag> {
    let fonts: BTreeMap<Vec<u8>, FontInfo<'_>> = doc
        .get_page_fonts(page)
        .map(|f| f.into_iter().map(|(n, d)| (n, FontInfo::load(doc, d))).collect())
        .unwrap_or_default();
    let mut frags: Vec<Frag> = Vec::new();
    let mut ctm = IDENTITY;
    let mut stack: Vec<Matrix> = Vec::new();
    let mut st = TextState::new();
    let mut font: Option<&FontInfo<'_>> = None;

    let mut show = |st: &mut TextState, font: Option<&FontInfo<'_>>, ctm: &Matrix, bytes: &[u8]| {
        let (text, adv) = match font {
            Some(f) => {
                let t = f.decode(bytes);
                let a = f.advance(bytes, &t);
                (t, a)
            }
            None => {
                let t: String = bytes
                    .iter()
                    .map(|b| char::from(*b))
                    .filter(|c| !c.is_control())
                    .collect();
                let a = t.chars().map(default_width).sum();
                (t, a)
            }
        };
        let chars = u32::try_from(text.chars().count()).unwrap_or(u32::MAX);
        let spaces = u32::try_from(text.chars().filter(|c| *c == ' ').count()).unwrap_or(u32::MAX);
        #[allow(clippy::cast_precision_loss)]
        let advance =
            (adv / 1000.0 * st.font_size + st.char_space * chars as f32 + st.word_space * spaces as f32)
                * st.hscale;
        let origin = mul(&[1.0, 0.0, 0.0, 1.0, st.tm[4], st.tm[5]], ctm);
        let scale_y = (st.tm[2].hypot(st.tm[3])) * (ctm[2].hypot(ctm[3]));
        let scale_x = (st.tm[0].hypot(st.tm[1])) * (ctm[0].hypot(ctm[1]));
        let size = (st.font_size.abs() * scale_y).max(0.1);
        if !text.trim().is_empty() {
            let end = origin[4] + advance * scale_x;
            let dup = frags.last().is_some_and(|l| {
                l.text == text && (l.x - origin[4]).abs() < 0.01 && (l.y - origin[5]).abs() < 0.01
            });
            if !dup {
                frags.push(Frag {
                    x: origin[4],
                    end,
                    y: origin[5],
                    size,
                    text,
                });
            }
        }
        st.tm = mul(&[1.0, 0.0, 0.0, 1.0, advance, 0.0], &st.tm);
    };

    for op in &content.operations {
        match op.operator.as_str() {
            "q" => stack.push(ctm),
            "Q" => {
                if let Some(m) = stack.pop() {
                    ctm = m;
                }
            }
            "cm" => {
                let m = [
                    num(op, 0),
                    num(op, 1),
                    num(op, 2),
                    num(op, 3),
                    num(op, 4),
                    num(op, 5),
                ];
                ctm = mul(&m, &ctm);
            }
            "BT" => {
                st.tm = IDENTITY;
                st.tlm = IDENTITY;
            }
            "Tf" => {
                font = op
                    .operands
                    .first()
                    .and_then(|o| o.as_name().ok())
                    .and_then(|n| fonts.get(n));
                st.font_size = num(op, 1);
            }
            "TL" => st.leading = num(op, 0),
            "Tc" => st.char_space = num(op, 0),
            "Tw" => st.word_space = num(op, 0),
            "Tz" => st.hscale = num(op, 0) / 100.0,
            "Td" => st.move_line(num(op, 0), num(op, 1)),
            "TD" => {
                st.leading = -num(op, 1);
                st.move_line(num(op, 0), num(op, 1));
            }
            "Tm" => {
                let m = [
                    num(op, 0),
                    num(op, 1),
                    num(op, 2),
                    num(op, 3),
                    num(op, 4),
                    num(op, 5),
                ];
                st.tm = m;
                st.tlm = m;
            }
            "T*" => st.move_line(0.0, -st.leading),
            "Tj" => {
                if let Some(Object::String(b, _)) = op.operands.first() {
                    show(&mut st, font, &ctm, b);
                }
            }
            "'" => {
                st.move_line(0.0, -st.leading);
                if let Some(Object::String(b, _)) = op.operands.first() {
                    show(&mut st, font, &ctm, b);
                }
            }
            "\"" => {
                st.word_space = num(op, 0);
                st.char_space = num(op, 1);
                st.move_line(0.0, -st.leading);
                if let Some(Object::String(b, _)) = op.operands.get(2) {
                    show(&mut st, font, &ctm, b);
                }
            }
            "TJ" => {
                if let Some(Object::Array(items)) = op.operands.first() {
                    for item in items {
                        match item {
                            Object::String(b, _) => show(&mut st, font, &ctm, b),
                            other => {
                                if let Ok(n) = other.as_float() {
                                    let dx = -n / 1000.0 * st.font_size * st.hscale;
                                    st.tm = mul(&[1.0, 0.0, 0.0, 1.0, dx, 0.0], &st.tm);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    frags
}

/// Group fragments that share a baseline into lines, preserving the order of first appearance.
fn group_lines(frags: &[Frag], sort_by_y: bool) -> (Vec<Vec<Frag>>, bool) {
    let mut order: Vec<Frag> = frags.to_vec();
    if sort_by_y {
        order.sort_by(|a, b| b.y.total_cmp(&a.y).then(a.x.total_cmp(&b.x)));
    }
    let mut rows: Vec<Vec<Frag>> = Vec::new();
    for f in order {
        let joined = rows.last_mut().filter(|row| {
            let last = &row[row.len() - 1];
            (last.y - f.y).abs() <= 0.35 * last.size.max(f.size)
        });
        match joined {
            Some(row) => row.push(f),
            None => rows.push(vec![f]),
        }
    }
    let mut wide_gap = false;
    for row in &mut rows {
        row.sort_by(|a, b| a.x.total_cmp(&b.x));
        for w in row.windows(2) {
            if w[1].x - w[0].end > 4.0 * w[0].size.max(w[1].size) {
                wide_gap = true;
            }
        }
    }
    (rows, wide_gap)
}

fn render_row(row: &[Frag]) -> Line {
    let mut text = String::new();
    let mut size = 0.0f32;
    let mut prev_end: Option<f32> = None;
    let mut y = row.first().map_or(0.0, |f| f.y);
    let mut x0 = row.first().map_or(0.0, |f| f.x);
    let mut x1 = x0;
    for f in row {
        size = size.max(f.size);
        y = y.max(f.y);
        x0 = x0.min(f.x);
        x1 = x1.max(f.end);
        if let Some(end) = prev_end {
            let gap = f.x - end;
            if gap > 0.15 * f.size && !text.ends_with(' ') && !f.text.starts_with(' ') {
                text.push(' ');
            }
        }
        text.push_str(&f.text);
        prev_end = Some(f.end);
    }
    Line {
        y,
        x0,
        x1,
        size,
        text: text.trim().to_owned(),
    }
}

fn layout_page(doc: &Document, page: ObjectId, content: &Content) -> Vec<Line> {
    let frags = page_fragments(doc, page, content);
    if frags.is_empty() {
        return Vec::new();
    }
    let (sorted, wide) = group_lines(&frags, true);
    let rows = if wide {
        group_lines(&frags, false).0
    } else {
        sorted
    };
    rows.iter()
        .map(|r| render_row(r))
        .filter(|l| !l.text.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Lines to blocks
// ---------------------------------------------------------------------------------------------

/// The most common font size by character count: the body text size.
fn body_size<'a>(lines: impl Iterator<Item = &'a Line>) -> f32 {
    let mut hist: BTreeMap<i64, usize> = BTreeMap::new();
    for l in lines {
        #[allow(clippy::cast_possible_truncation)]
        let key = (l.size * 2.0).round() as i64;
        *hist.entry(key).or_default() += l.text.chars().count();
    }
    hist.into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
        .map_or(0.0, |(k, _)| {
            #[allow(clippy::cast_precision_loss)]
            let v = k as f32 / 2.0;
            v
        })
}

fn heading_level(size: f32, body: f32, text: &str) -> Option<u8> {
    if body <= 0.0 || text.chars().count() > 160 {
        return None;
    }
    let ratio = size / body;
    if ratio >= 1.5 {
        Some(1)
    } else if ratio >= 1.25 {
        Some(2)
    } else if ratio >= 1.12 {
        Some(3)
    } else {
        None
    }
}

/// `(ordered, content)` when `line` starts with a list marker.
fn list_marker(line: &str) -> Option<(bool, &str)> {
    let mut chars = line.chars();
    let first = chars.next()?;
    let rest = chars.as_str();
    if matches!(first, '•' | '◦' | '▪' | '‣' | '●' | '○' | '–' | '·' | '*' | '-') && rest.starts_with(' ')
    {
        return Some((false, rest.trim_start()));
    }
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if (1..=3).contains(&digits) {
        let after = &line[digits..];
        if let Some(rest) = after.strip_prefix(". ").or_else(|| after.strip_prefix(") ")) {
            return Some((true, rest.trim_start()));
        }
    }
    None
}

fn join_wrapped(cur: &mut String, next: &str) {
    if cur.ends_with('-')
        && cur.chars().rev().nth(1).is_some_and(char::is_alphabetic)
        && next.chars().next().is_some_and(char::is_lowercase)
    {
        cur.pop();
        cur.push_str(next);
    } else {
        cur.push(' ');
        cur.push_str(next);
    }
}

/// Extent of text in PDF user space; `top` is the larger y.
#[derive(Debug, Clone, Copy)]
struct Extent {
    x0: f32,
    x1: f32,
    bottom: f32,
    top: f32,
}

impl Extent {
    fn of(l: &Line) -> Self {
        Self {
            x0: l.x0,
            x1: l.x1,
            bottom: l.y - 0.22 * l.size,
            top: l.y + 0.88 * l.size,
        }
    }

    fn grow(&mut self, o: Self) {
        self.x0 = self.x0.min(o.x0);
        self.x1 = self.x1.max(o.x1);
        self.bottom = self.bottom.min(o.bottom);
        self.top = self.top.max(o.top);
    }
}

/// A block with its place on the page.
struct Placed {
    block: Block,
    extent: Extent,
    /// `Some(confidence)` for a block read by OCR.
    ocr: Option<Option<f64>>,
}

enum Open {
    None,
    Para {
        text: String,
        y: f32,
        size: f32,
        extent: Extent,
    },
    Heading {
        level: u8,
        text: String,
        y: f32,
        size: f32,
        extent: Extent,
    },
}

fn flush(open: &mut Open, out: &mut Vec<Placed>) {
    match std::mem::replace(open, Open::None) {
        Open::None => {}
        Open::Para { text, extent, .. } => out.push(Placed {
            block: Block::Paragraph(vec![Span::plain(text)]),
            extent,
            ocr: None,
        }),
        Open::Heading {
            level, text, extent, ..
        } => out.push(Placed {
            block: Block::Heading {
                level,
                spans: vec![Span::plain(text)],
            },
            extent,
            ocr: None,
        }),
    }
}

fn page_blocks(lines: &[Line], body: f32) -> Vec<Placed> {
    let mut out = Vec::new();
    let mut open = Open::None;
    for l in lines {
        if let Some((ordered, rest)) = list_marker(&l.text) {
            flush(&mut open, &mut out);
            out.push(Placed {
                block: Block::Item {
                    depth: 0,
                    ordered,
                    spans: vec![Span::plain(rest)],
                },
                extent: Extent::of(l),
                ocr: None,
            });
            continue;
        }
        let level = heading_level(l.size, body, &l.text);
        match (&mut open, level) {
            (
                Open::Heading {
                    level: cl,
                    text,
                    y,
                    size,
                    extent,
                },
                Some(lv),
            ) if *cl == lv && *y - l.y > 0.0 && *y - l.y <= 1.6 * size.max(l.size) => {
                text.push(' ');
                text.push_str(&l.text);
                *y = l.y;
                extent.grow(Extent::of(l));
            }
            (
                Open::Para {
                    text,
                    y,
                    size,
                    extent,
                },
                None,
            ) if *y - l.y > 0.0 && *y - l.y <= 1.6 * size.max(l.size) => {
                join_wrapped(text, &l.text);
                *y = l.y;
                *size = l.size;
                extent.grow(Extent::of(l));
            }
            (_, Some(lv)) => {
                flush(&mut open, &mut out);
                open = Open::Heading {
                    level: lv,
                    text: l.text.clone(),
                    y: l.y,
                    size: l.size,
                    extent: Extent::of(l),
                };
            }
            (_, None) => {
                flush(&mut open, &mut out);
                open = Open::Para {
                    text: l.text.clone(),
                    y: l.y,
                    size: l.size,
                    extent: Extent::of(l),
                };
            }
        }
    }
    flush(&mut open, &mut out);
    out
}
