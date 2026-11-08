//! Legacy binary Office formats in OLE2 compound files: `.doc` (Word 97-2003), `.ppt`
//! (PowerPoint 97-2003) and `.xls` (Excel 97-2003, through `calamine`).
//!
//! * `.doc`: the text is rebuilt from the piece table (`Clx`) of the table stream, so fast-saved
//!   and complex documents read correctly. Paragraphs end at `\r`, table cells at `\x07`,
//!   `HYPERLINK` fields become links. Styles live in a separate binary structure that is not
//!   read, so a `.doc` yields paragraphs and tables but no headings.
//! * `.ppt`: the record stream is walked for `TextCharsAtom`/`TextBytesAtom`; slides are cut at
//!   `SlidePersistAtom`s and title text (`TextHeaderAtom` type 0/6) becomes a heading. Notes and
//!   master slides are skipped.
//! * `.xls`: `calamine` builds the dense cell grid of each sheet from the workbook stream; BIFF8
//!   caps a sheet at 65,536 x 256 cells, which bounds that allocation.

use std::io::{Cursor, Read};

use calamine::{Reader, Xls};
use encoding_rs::WINDOWS_1252;

use super::blocks::{self, Block, Parsed, Row, Span, Spans};
use super::sheet::{self, Sheet};
use super::{ParseError, ParseLimits};

/// What an OLE2 compound file contains.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OleKind {
    /// Word 97-2003.
    Doc,
    /// Excel 97-2003.
    Xls,
    /// PowerPoint 97-2003.
    Ppt,
    /// An encrypted OOXML package.
    EncryptedPackage,
    /// Any other compound file.
    Other,
}

type Cfb<'a> = cfb::CompoundFile<Cursor<&'a [u8]>>;

fn open_cfb<'a>(bytes: &'a [u8], format: &'static str) -> Result<Cfb<'a>, ParseError> {
    cfb::CompoundFile::open(Cursor::new(bytes))
        .map_err(|e| ParseError::corrupt_from(format, "the OLE2 container cannot be read", e))
}

fn read_stream(
    cf: &mut Cfb<'_>,
    path: &str,
    cap: usize,
    format: &'static str,
) -> Result<Vec<u8>, ParseError> {
    let s = cf
        .open_stream(path)
        .map_err(|e| ParseError::corrupt_from(format, format!("missing stream {path}"), e))?;
    let mut buf = Vec::new();
    s.take(u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| ParseError::corrupt_from(format, format!("stream {path} cannot be read"), e))?;
    if buf.len() > cap {
        return Err(ParseError::TooLarge {
            what: "uncompressed bytes",
            limit: cap,
            actual: cap.saturating_add(1),
        });
    }
    Ok(buf)
}

/// Classify a compound file by its streams.
///
/// # Errors
/// [`ParseError::Corrupt`] when `bytes` is not a readable compound file,
/// [`ParseError::TooLarge`] for too many entries.
pub(crate) fn sniff_ole(bytes: &[u8], limits: &ParseLimits) -> Result<OleKind, ParseError> {
    let cf = open_cfb(bytes, "ole")?;
    let mut kind = OleKind::Other;
    for (n, entry) in cf.walk().enumerate() {
        if n >= limits.max_entries {
            return Err(ParseError::TooLarge {
                what: "archive entries",
                limit: limits.max_entries,
                actual: n,
            });
        }
        if !entry.is_stream() {
            continue;
        }
        match entry.name() {
            "WordDocument" => return Ok(OleKind::Doc),
            "PowerPoint Document" => return Ok(OleKind::Ppt),
            "Workbook" | "Book" => return Ok(OleKind::Xls),
            "EncryptedPackage" => kind = OleKind::EncryptedPackage,
            _ => {}
        }
    }
    Ok(kind)
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o.checked_add(4)?)?.try_into().ok()?))
}

fn usize_of(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

// ---------------------------------------------------------------------------------------------
// DOC
// ---------------------------------------------------------------------------------------------

/// Main-document text of a Word binary file (`ccpText` characters).
fn doc_text(wd: &[u8], table: &[u8], cap: usize) -> Result<String, ParseError> {
    let bad = |m: &str| ParseError::corrupt("doc", m.to_owned());
    let csw = usize::from(u16_at(wd, 32).ok_or_else(|| bad("truncated file header"))?);
    let cslw_at = 34 + csw * 2;
    let cslw = usize::from(u16_at(wd, cslw_at).ok_or_else(|| bad("truncated file header"))?);
    let lw = cslw_at + 2;
    let ccp_text = u32_at(wd, lw + 12).ok_or_else(|| bad("truncated file header"))?;
    let cb_rg = usize::from(u16_at(wd, lw + cslw * 4).ok_or_else(|| bad("truncated file header"))?);
    let blob = lw + cslw * 4 + 2;
    if cb_rg < 34 {
        return Err(bad("the file header has no piece table"));
    }
    let fc_clx = usize_of(u32_at(wd, blob + 33 * 8).ok_or_else(|| bad("truncated file header"))?);
    let lcb_clx = usize_of(u32_at(wd, blob + 33 * 8 + 4).ok_or_else(|| bad("truncated file header"))?);
    let clx = table
        .get(
            fc_clx
                ..fc_clx
                    .checked_add(lcb_clx)
                    .ok_or_else(|| bad("bad piece table range"))?,
        )
        .ok_or_else(|| bad("the piece table lies outside its stream"))?;
    // skip Prc entries (type 1) to the Pcdt (type 2)
    let mut i = 0usize;
    let plc = loop {
        match clx.get(i) {
            Some(1) => {
                let cb = usize::from(u16_at(clx, i + 1).ok_or_else(|| bad("truncated piece table"))?);
                i = i + 3 + cb;
            }
            Some(2) => {
                let lcb = usize_of(u32_at(clx, i + 1).ok_or_else(|| bad("truncated piece table"))?);
                break clx
                    .get(
                        i + 5
                            ..i.checked_add(5 + lcb)
                                .ok_or_else(|| bad("bad piece table range"))?,
                    )
                    .ok_or_else(|| bad("truncated piece table"))?;
            }
            _ => return Err(bad("malformed piece table")),
        }
    };
    let n = plc.len().saturating_sub(4) / 12;
    let mut out = String::new();
    let mut total_chars = 0usize;
    for k in 0..n {
        let cp0 = u32_at(plc, k * 4).ok_or_else(|| bad("truncated piece table"))?;
        let cp1 = u32_at(plc, (k + 1) * 4).ok_or_else(|| bad("truncated piece table"))?;
        if cp0 >= ccp_text {
            break;
        }
        let end = cp1.min(ccp_text);
        let count = usize_of(end.saturating_sub(cp0));
        let fc = u32_at(plc, (n + 1) * 4 + k * 8 + 2).ok_or_else(|| bad("truncated piece table"))?;
        total_chars = total_chars.saturating_add(count);
        if total_chars > cap {
            return Err(ParseError::TooLarge {
                what: "text characters",
                limit: cap,
                actual: total_chars,
            });
        }
        if fc & 0x4000_0000 != 0 {
            let at = usize_of((fc & 0x3FFF_FFFF) / 2);
            let raw = wd
                .get(at..at.saturating_add(count))
                .ok_or_else(|| bad("a text piece lies outside the document stream"))?;
            out.push_str(&WINDOWS_1252.decode(raw).0);
        } else {
            let at = usize_of(fc);
            let raw = wd
                .get(at..at.saturating_add(count * 2))
                .ok_or_else(|| bad("a text piece lies outside the document stream"))?;
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            out.push_str(&String::from_utf16_lossy(&units));
        }
    }
    Ok(out)
}

/// `HYPERLINK "url"` instruction of a Word field.
fn field_href(instr: &str) -> Option<String> {
    let t = instr.trim();
    let rest = t.strip_prefix("HYPERLINK")?.trim_start();
    let url = if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()?
    } else {
        rest.split_whitespace().next()?
    };
    (!url.is_empty()).then(|| url.to_owned())
}

/// A `\r`/`\x07` delimited run of text with its terminator.
struct Segment {
    spans: Spans,
    term: char,
}

fn segments(text: &str) -> Vec<Segment> {
    struct F {
        instr: String,
        href: Option<String>,
        in_result: bool,
    }
    let mut fields: Vec<F> = Vec::new();
    let mut out = Vec::new();
    let mut cur: Spans = Vec::new();
    let mut buf = String::new();
    let mut buf_href: Option<String> = None;
    let flush = |cur: &mut Spans, buf: &mut String, href: &Option<String>| {
        if !buf.is_empty() {
            cur.push(Span {
                text: std::mem::take(buf),
                href: href.clone(),
                ..Span::default()
            });
        }
    };
    for c in text.chars() {
        match c {
            '\x13' => fields.push(F {
                instr: String::new(),
                href: None,
                in_result: false,
            }),
            '\x14' => {
                if let Some(f) = fields.last_mut() {
                    f.href = field_href(&f.instr);
                    f.in_result = true;
                }
            }
            '\x15' => {
                flush(&mut cur, &mut buf, &buf_href);
                fields.pop();
                buf_href = fields
                    .iter()
                    .rev()
                    .find(|f| f.in_result)
                    .and_then(|f| f.href.clone());
            }
            _ if fields.last().is_some_and(|f| !f.in_result) => {
                if let Some(f) = fields.last_mut() {
                    f.instr.push(c);
                }
            }
            '\r' | '\x07' => {
                flush(&mut cur, &mut buf, &buf_href);
                out.push(Segment {
                    spans: std::mem::take(&mut cur),
                    term: c,
                });
            }
            '\x0B' | '\n' => buf.push('\n'),
            '\x0C' | '\x01' | '\x02' | '\x05' | '\x08' | '\x1F' => {}
            '\x1E' => buf.push('-'),
            '\t' => buf.push('\t'),
            c if c.is_control() => {}
            c => {
                let want = fields
                    .iter()
                    .rev()
                    .find(|f| f.in_result)
                    .and_then(|f| f.href.clone());
                if want != buf_href {
                    flush(&mut cur, &mut buf, &buf_href);
                    buf_href = want;
                }
                buf.push(c);
            }
        }
    }
    flush(&mut cur, &mut buf, &buf_href);
    if !cur.is_empty() {
        out.push(Segment {
            spans: cur,
            term: '\r',
        });
    }
    out
}

fn blocks_from_segments(segs: Vec<Segment>, max_rows: usize) -> (Vec<Block>, bool) {
    let mut blocks = Vec::new();
    let mut truncated = false;
    let mut i = 0usize;
    // table state
    let mut rows: Vec<Row> = Vec::new();
    let mut row: Row = Vec::new();
    let mut cols: Option<usize> = None;
    let mut in_table = false;
    let mut cell_paras: Vec<Spans> = Vec::new();
    let join = |paras: Vec<Spans>, last: Spans| -> Spans {
        let mut joined: Spans = Vec::new();
        for (k, p) in paras.into_iter().chain(std::iter::once(last)).enumerate() {
            if k > 0 {
                joined.push(Span::plain(" "));
            }
            joined.extend(p);
        }
        blocks::normalise(joined)
    };
    while i < segs.len() {
        let seg = &segs[i];
        let at_row_start = in_table && row.is_empty() && cell_paras.is_empty();
        if at_row_start && seg.term == '\r' {
            // the table ended
            blocks.push(Block::Table(std::mem::take(&mut rows)));
            in_table = false;
            cols = None;
            continue;
        }
        if !in_table && seg.term == '\r' {
            let spans = blocks::normalise(seg.spans.clone());
            if !spans.is_empty() {
                blocks.push(Block::Paragraph(spans));
            }
            i += 1;
            continue;
        }
        if seg.term == '\r' {
            // a further paragraph of the cell being read
            cell_paras.push(blocks::normalise(seg.spans.clone()));
            i += 1;
            continue;
        }
        // term == '\x07'
        let text_empty =
            blocks::spans_text(&seg.spans).trim().is_empty() && cell_paras.iter().all(|p| p.is_empty());
        let row_end = in_table && !row.is_empty() && text_empty && cols.is_none_or(|c| row.len() >= c);
        if row_end {
            cols = Some(row.len());
            if rows.len() < max_rows {
                rows.push(std::mem::take(&mut row));
            } else {
                truncated = true;
                row.clear();
            }
        } else {
            in_table = true;
            let cell = join(std::mem::take(&mut cell_paras), seg.spans.clone());
            row.push(cell);
        }
        i += 1;
    }
    if in_table {
        if !row.is_empty() {
            rows.push(row);
        }
        if !rows.is_empty() {
            blocks.push(Block::Table(rows));
        }
    }
    (blocks, truncated)
}

/// Parse a Word 97-2003 `.doc`.
///
/// # Errors
/// [`ParseError::Corrupt`], [`ParseError::Encrypted`] or [`ParseError::TooLarge`].
pub(crate) fn parse_doc(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let mut cf = open_cfb(bytes, "doc")?;
    let cap = limits.max_uncompressed_bytes;
    let wd = read_stream(&mut cf, "/WordDocument", cap, "doc")?;
    if u16_at(&wd, 0) != Some(0xA5EC) {
        return Err(ParseError::corrupt(
            "doc",
            "the WordDocument stream has no Word file header",
        ));
    }
    let flags = u16_at(&wd, 0x0A).ok_or_else(|| ParseError::corrupt("doc", "truncated file header"))?;
    if flags & 0x0100 != 0 {
        return Err(ParseError::Encrypted { format: "doc" });
    }
    let table_name = if flags & 0x0200 != 0 { "/1Table" } else { "/0Table" };
    let table = read_stream(&mut cf, table_name, cap, "doc")?;
    let text = doc_text(&wd, &table, cap)?;
    let (blocks, truncated) = blocks_from_segments(segments(&text), limits.max_rows);
    let mut out = Parsed {
        blocks,
        ..Parsed::default()
    };
    if truncated {
        out.warnings
            .push("table rows beyond the row limit were dropped".to_owned());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// PPT
// ---------------------------------------------------------------------------------------------

const RT_SLIDE: u16 = 0x03EE;
const RT_NOTES: u16 = 0x03F0;
const RT_MAIN_MASTER: u16 = 0x03F8;
const RT_HANDOUT: u16 = 0x0FC9;
const RT_SLIDE_LIST: u16 = 0x0FF0;
const RT_SLIDE_PERSIST: u16 = 0x03F3;
const RT_TEXT_HEADER: u16 = 0x0F9F;
const RT_TEXT_CHARS: u16 = 0x0FA0;
const RT_TEXT_BYTES: u16 = 0x0FA8;
const RT_CRYPT_SESSION: u16 = 0x2F14;
const MAX_PPT_DEPTH: usize = 24;

#[derive(Default)]
struct PptSlide {
    items: Vec<(PptKind, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PptKind {
    Title,
    Body,
    Other,
}

struct PptWalk {
    slides: Vec<PptSlide>,
    slide_container: usize,
    header: Option<u32>,
    encrypted: bool,
    atoms: usize,
}

#[derive(Clone, Copy)]
enum PptCtx {
    Top,
    SlideList,
    Slide(usize),
}

impl PptWalk {
    fn walk(&mut self, data: &[u8], depth: usize, ctx: PptCtx) {
        let mut pos = 0usize;
        while pos + 8 <= data.len() {
            let ver_inst = u16_at(data, pos).unwrap_or(0);
            let ty = u16_at(data, pos + 2).unwrap_or(0);
            let len = usize_of(u32_at(data, pos + 4).unwrap_or(0));
            let body_start = pos + 8;
            let body_end = body_start.saturating_add(len).min(data.len());
            let body = &data[body_start..body_end];
            let container = ver_inst & 0x000F == 0x000F;
            let instance = ver_inst >> 4;
            self.atoms += 1;
            if ty == RT_CRYPT_SESSION {
                self.encrypted = true;
            }
            if container {
                if depth < MAX_PPT_DEPTH && !matches!(ty, RT_NOTES | RT_MAIN_MASTER | RT_HANDOUT) {
                    match ty {
                        RT_SLIDE_LIST if instance == 0 => self.walk(body, depth + 1, PptCtx::SlideList),
                        RT_SLIDE_LIST => {}
                        RT_SLIDE => {
                            let idx = self.slide_container;
                            self.slide_container += 1;
                            self.walk(body, depth + 1, PptCtx::Slide(idx));
                        }
                        _ => self.walk(body, depth + 1, ctx),
                    }
                }
            } else {
                match ty {
                    RT_SLIDE_PERSIST if matches!(ctx, PptCtx::SlideList) => {
                        self.slides.push(PptSlide::default())
                    }
                    RT_TEXT_HEADER => self.header = u32_at(body, 0),
                    RT_TEXT_CHARS | RT_TEXT_BYTES => {
                        let text = if ty == RT_TEXT_CHARS {
                            let units: Vec<u16> = body
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|c| u16::from_le_bytes(*c))
                                .collect();
                            String::from_utf16_lossy(&units)
                        } else {
                            WINDOWS_1252.decode(body).0.into_owned()
                        };
                        // type 2 is notes text: not part of the slide
                        let kind = match self.header.take() {
                            Some(0 | 6) => Some(PptKind::Title),
                            Some(1 | 5 | 7 | 8) => Some(PptKind::Body),
                            Some(2) => None,
                            _ => Some(PptKind::Other),
                        };
                        if let Some(k) = kind {
                            self.add(ctx, k, text);
                        }
                    }
                    _ => {}
                }
            }
            pos = body_end;
        }
    }

    fn add(&mut self, ctx: PptCtx, kind: PptKind, text: String) {
        let idx = match ctx {
            PptCtx::SlideList => self.slides.len().checked_sub(1),
            PptCtx::Slide(i) => {
                while self.slides.len() <= i {
                    self.slides.push(PptSlide::default());
                }
                Some(i)
            }
            PptCtx::Top => None,
        };
        if let Some(i) = idx {
            self.slides[i].items.push((kind, text));
        }
    }
}

/// Parse a PowerPoint 97-2003 `.ppt`.
///
/// # Errors
/// [`ParseError::Corrupt`], [`ParseError::Encrypted`] or [`ParseError::TooLarge`].
pub(crate) fn parse_ppt(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let mut cf = open_cfb(bytes, "ppt")?;
    let data = read_stream(
        &mut cf,
        "/PowerPoint Document",
        limits.max_uncompressed_bytes,
        "ppt",
    )?;
    let mut w = PptWalk {
        slides: Vec::new(),
        slide_container: 0,
        header: None,
        encrypted: false,
        atoms: 0,
    };
    w.walk(&data, 0, PptCtx::Top);
    if w.encrypted {
        return Err(ParseError::Encrypted { format: "ppt" });
    }
    if w.atoms == 0 {
        return Err(ParseError::corrupt(
            "ppt",
            "the PowerPoint Document stream has no records",
        ));
    }
    let mut out = Parsed::default();
    if w.slides.len() > limits.max_pages {
        out.warnings.push(format!(
            "the presentation has {} slides; only the first {} were parsed",
            w.slides.len(),
            limits.max_pages
        ));
        w.slides.truncate(limits.max_pages);
    }
    for (n, slide) in w.slides.iter().enumerate() {
        if n > 0 {
            out.blocks.push(Block::Rule);
        }
        for (kind, text) in &slide.items {
            for para in text.split(['\r', '\x0B']) {
                let spans = blocks::normalise(vec![Span::plain(para)]);
                if spans.is_empty() {
                    continue;
                }
                out.blocks.push(match kind {
                    PptKind::Title => Block::Heading { level: 1, spans },
                    PptKind::Body => Block::Item {
                        depth: 0,
                        ordered: false,
                        spans,
                    },
                    PptKind::Other => Block::Paragraph(spans),
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// XLS
// ---------------------------------------------------------------------------------------------

fn map_xls(e: &calamine::XlsError) -> ParseError {
    if matches!(e, calamine::XlsError::Password) {
        ParseError::Encrypted { format: "xls" }
    } else {
        ParseError::corrupt("xls", e.to_string())
    }
}

/// Parse an Excel 97-2003 `.xls`.
///
/// # Errors
/// [`ParseError::Corrupt`] or [`ParseError::Encrypted`].
pub(crate) fn parse_xls(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let mut wb: Xls<_> = Xls::new(Cursor::new(bytes)).map_err(|e| map_xls(&e))?;
    let names = wb.sheet_names();
    let mut out = Parsed::default();
    if names.len() > limits.max_sheets {
        out.warnings.push(format!(
            "the workbook has {} sheets; only the first {} were parsed",
            names.len(),
            limits.max_sheets
        ));
    }
    let mut sheets = Vec::new();
    for name in names.into_iter().take(limits.max_sheets) {
        let range = wb.worksheet_range(&name).map_err(|e| map_xls(&e))?;
        let (r0, c0) = range.start().unwrap_or((0, 0));
        let mut sh = Sheet::new(name);
        'cells: for (r, row) in range.rows().enumerate() {
            for (c, d) in row.iter().enumerate() {
                let rr = r0.saturating_add(u32::try_from(r).unwrap_or(u32::MAX));
                let cc = c0.saturating_add(u32::try_from(c).unwrap_or(u32::MAX));
                if !sh.put(rr, cc, sheet::cell_text(d), limits) {
                    break 'cells;
                }
            }
        }
        sheets.push(sh);
    }
    sheet::render(&sheets, &mut out.blocks, &mut out.warnings);
    Ok(out)
}
