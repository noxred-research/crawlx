//! Rich Text Format (`.rtf`).
//!
//! A single-pass tokenizer over the control words. Supported: paragraphs (`\par`), line breaks,
//! tabs, `\'hh` bytes in the document code page (`\ansicpgN`), `\uN` Unicode with the `\ucN`
//! fallback skip, special characters (`\emdash`, `\lquote`, ...), bold/italic runs, headings
//! from `\outlinelevelN`, list items from `\ls`/`\pntext` paragraphs, tables
//! (`\trowd`/`\cell`/`\row`/`\intbl`), `HYPERLINK` fields and the `\info` group. Font, color,
//! style and list tables, pictures, objects, headers, footers and footnotes are skipped.

use encoding_rs::Encoding;

use super::blocks::{self, Block, Parsed, Row, Span, Spans};
use super::{ParseError, ParseLimits};

/// Deepest group nesting accepted.
const MAX_DEPTH: usize = 512;

/// Destinations whose content is never part of the body.
const SKIP: &[&str] = &[
    "fonttbl",
    "colortbl",
    "stylesheet",
    "pict",
    "object",
    "header",
    "headerl",
    "headerr",
    "headerf",
    "footer",
    "footerl",
    "footerr",
    "footerf",
    "footnote",
    "listtable",
    "listoverridetable",
    "rsidtbl",
    "generator",
    "datastore",
    "themedata",
    "colorschememapping",
    "latentstyles",
    "xmlnstbl",
    "mmathPr",
    "listtext",
    "pntext",
    "pn",
    "pnseclvl",
    "bkmkstart",
    "bkmkend",
    "template",
    "fchars",
    "lchars",
    "private",
    "filetbl",
    "revtbl",
    "falt",
    "panose",
    "fldtype",
    "nonshppict",
    "shpinst",
    "wgrffmtfilter",
    "userprops",
];

#[derive(Clone)]
struct Group {
    skip: bool,
    bold: bool,
    italic: bool,
    uc: usize,
    href: Option<String>,
    capture: Capture,
}

#[derive(Clone, PartialEq, Eq)]
enum Capture {
    None,
    FieldInstr,
    ListText,
    Meta(&'static str),
}

#[derive(Default)]
struct Para {
    spans: Spans,
    outline: Option<u8>,
    list: bool,
    ilvl: u8,
    list_ordered: bool,
    in_table: bool,
}

struct Rtf<'a> {
    limits: &'a ParseLimits,
    codepage: &'static Encoding,
    stack: Vec<Group>,
    out: Parsed,
    buf: String,
    bytes: Vec<u8>,
    high_surrogate: Option<u16>,
    skip_chars: usize,
    para: Para,
    field_instr: String,
    capture_text: String,
    list_text: String,
    rows: Vec<Row>,
    row: Row,
    cell: Vec<Spans>,
    rows_truncated: bool,
}

fn codepage_encoding(cp: i32) -> &'static Encoding {
    let label = match cp {
        437 => "ibm866",
        874 => "windows-874",
        932 => "shift_jis",
        936 => "gbk",
        949 => "euc-kr",
        950 => "big5",
        1250 => "windows-1250",
        1251 => "windows-1251",
        1253 => "windows-1253",
        1254 => "windows-1254",
        1255 => "windows-1255",
        1256 => "windows-1256",
        1257 => "windows-1257",
        1258 => "windows-1258",
        10000 => "macintosh",
        65001 => "utf-8",
        _ => "windows-1252",
    };
    Encoding::for_label(label.as_bytes()).unwrap_or(encoding_rs::WINDOWS_1252)
}

fn hyperlink(instr: &str) -> Option<String> {
    let t = instr.trim();
    let rest = t.strip_prefix("HYPERLINK")?.trim_start();
    let url = if let Some(q) = rest.strip_prefix('"') {
        q.split('"').next()?
    } else {
        rest.split_whitespace().next()?
    };
    (!url.is_empty()).then(|| url.to_owned())
}

impl Rtf<'_> {
    fn top(&mut self) -> &mut Group {
        let last = self.stack.len() - 1;
        &mut self.stack[last]
    }

    fn flush_bytes(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        let (text, _, _) = self.codepage.decode(&self.bytes);
        let text = text.into_owned();
        self.bytes.clear();
        self.emit_str(&text);
    }

    fn emit_str(&mut self, s: &str) {
        let g = self.stack.last();
        let Some(g) = g else { return };
        match &g.capture {
            Capture::FieldInstr => self.field_instr.push_str(s),
            Capture::ListText => self.list_text.push_str(s),
            Capture::Meta(_) => self.capture_text.push_str(s),
            Capture::None => {
                if g.skip {
                    return;
                }
                let span = Span {
                    text: s.to_owned(),
                    href: g.href.clone(),
                    bold: g.bold,
                    italic: g.italic,
                };
                self.para.spans.push(span);
            }
        }
    }

    fn emit_char(&mut self, c: char) {
        if self.skip_chars > 0 {
            self.skip_chars -= 1;
            return;
        }
        self.flush_bytes();
        self.buf.clear();
        self.buf.push(c);
        let s = std::mem::take(&mut self.buf);
        self.emit_str(&s);
        self.buf = s;
    }

    fn emit_text(&mut self, s: &str) {
        self.flush_bytes();
        self.emit_str(s);
    }

    fn unicode(&mut self, n: i32) {
        let unit = u16::try_from(n.rem_euclid(65536)).unwrap_or(0xFFFD);
        self.flush_bytes();
        let uc = self.stack.last().map_or(1, |g| g.uc);
        if let Some(hi) = self.high_surrogate.take() {
            let ch = char::decode_utf16([hi, unit])
                .next()
                .and_then(Result::ok)
                .unwrap_or('\u{FFFD}');
            self.emit_char_raw(ch);
        } else if (0xD800..0xDC00).contains(&unit) {
            self.high_surrogate = Some(unit);
        } else {
            let ch = char::from_u32(u32::from(unit)).unwrap_or('\u{FFFD}');
            self.emit_char_raw(ch);
        }
        self.skip_chars = uc;
    }

    fn emit_char_raw(&mut self, c: char) {
        let mut b = [0u8; 4];
        let s = c.encode_utf8(&mut b);
        self.emit_str(s);
    }

    fn end_paragraph(&mut self) {
        self.flush_bytes();
        let p = std::mem::take(&mut self.para);
        let spans = blocks::normalise(p.spans);
        if p.in_table {
            if !spans.is_empty() {
                self.cell.push(spans);
            }
            return;
        }
        self.flush_table();
        if spans.is_empty() {
            return;
        }
        if let Some(level) = p.outline {
            self.out.blocks.push(Block::Heading {
                level: (level + 1).clamp(1, 6),
                spans,
            });
        } else if p.list {
            self.out.blocks.push(Block::Item {
                depth: p.ilvl.min(8),
                ordered: p.list_ordered,
                spans,
            });
        } else {
            self.out.blocks.push(Block::Paragraph(spans));
        }
    }

    fn end_cell(&mut self) {
        self.flush_bytes();
        let p = std::mem::take(&mut self.para);
        let spans = blocks::normalise(p.spans);
        if !spans.is_empty() {
            self.cell.push(spans);
        }
        let mut joined: Spans = Vec::new();
        for (i, s) in std::mem::take(&mut self.cell).into_iter().enumerate() {
            if i > 0 {
                joined.push(Span::plain(" "));
            }
            joined.extend(s);
        }
        self.row.push(blocks::coalesce(joined));
    }

    fn end_row(&mut self) {
        if !self.cell.is_empty() || !self.para.spans.is_empty() {
            self.end_cell();
        }
        let row = std::mem::take(&mut self.row);
        if self.rows.len() < self.limits.max_rows {
            self.rows.push(row);
        } else {
            self.rows_truncated = true;
        }
    }

    fn flush_table(&mut self) {
        if !self.rows.is_empty() {
            self.out.blocks.push(Block::Table(std::mem::take(&mut self.rows)));
        }
    }

    fn control(&mut self, word: &str, arg: Option<i32>, star: bool, at_start: bool) {
        // destinations
        if at_start || star {
            let capture = match word {
                "fldinst" => Some(Capture::FieldInstr),
                "title" => Some(Capture::Meta("title")),
                "author" => Some(Capture::Meta("author")),
                "subject" => Some(Capture::Meta("subject")),
                "keywords" => Some(Capture::Meta("keywords")),
                "doccomm" => Some(Capture::Meta("description")),
                "listtext" | "pntext" => Some(Capture::ListText),
                _ => None,
            };
            if let Some(c) = capture {
                self.capture_text.clear();
                if c == Capture::ListText {
                    self.list_text.clear();
                    self.para.list = true;
                }
                if c == Capture::FieldInstr {
                    self.field_instr.clear();
                }
                self.top().capture = c;
                return;
            }
            if word == "fldrslt" {
                let href = hyperlink(&self.field_instr);
                self.top().href = href;
                return;
            }
            if SKIP.contains(&word) || star {
                self.top().skip = true;
                return;
            }
        }
        match word {
            "par" | "sect" => self.end_paragraph(),
            "line" => self.emit_char('\n'),
            "tab" => self.emit_char('\t'),
            "emdash" => self.emit_char('\u{2014}'),
            "endash" => self.emit_char('\u{2013}'),
            "bullet" => self.emit_char('\u{2022}'),
            "lquote" => self.emit_char('\u{2018}'),
            "rquote" => self.emit_char('\u{2019}'),
            "ldblquote" => self.emit_char('\u{201C}'),
            "rdblquote" => self.emit_char('\u{201D}'),
            "enspace" | "emspace" | "qmspace" => self.emit_char(' '),
            "u" => {
                if let Some(n) = arg {
                    self.unicode(n);
                }
            }
            "uc" => {
                let n = arg.and_then(|n| usize::try_from(n).ok()).unwrap_or(1);
                self.top().uc = n;
            }
            "ansicpg" => {
                if let Some(cp) = arg {
                    self.codepage = codepage_encoding(cp);
                }
            }
            "b" => self.top().bold = arg != Some(0),
            "i" => self.top().italic = arg != Some(0),
            "plain" => {
                let g = self.top();
                g.bold = false;
                g.italic = false;
            }
            "pard" => {
                self.para.outline = None;
                self.para.list = false;
                self.para.ilvl = 0;
                self.para.in_table = false;
            }
            "outlinelevel" => {
                self.para.outline = arg.and_then(|n| u8::try_from(n).ok()).filter(|n| *n < 9);
            }
            "ls" => self.para.list = true,
            "ilvl" => self.para.ilvl = arg.and_then(|n| u8::try_from(n).ok()).unwrap_or(0),
            "intbl" => self.para.in_table = true,
            "cell" | "nestcell" => self.end_cell(),
            "row" | "nestrow" => self.end_row(),
            _ => {}
        }
    }

    fn close_group(&mut self, g: &Group) {
        self.flush_bytes();
        match &g.capture {
            Capture::Meta(k) => {
                let t = std::mem::take(&mut self.capture_text);
                self.out.set_meta(k, &t);
            }
            Capture::ListText => {
                self.para.list_ordered = self
                    .list_text
                    .trim_start()
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric);
            }
            Capture::FieldInstr | Capture::None => {}
        }
    }
}

/// Parse an RTF document.
///
/// # Errors
/// [`ParseError::Corrupt`] when the input does not start with `{\rtf`;
/// [`ParseError::TooLarge`] for group nesting beyond 512 levels.
pub(crate) fn parse_rtf(bytes: &[u8], limits: &ParseLimits) -> Result<Parsed, ParseError> {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
    if !bytes[start..].starts_with(b"{\\rtf") {
        return Err(ParseError::corrupt("rtf", "missing {\\rtf header"));
    }
    let mut r = Rtf {
        limits,
        codepage: encoding_rs::WINDOWS_1252,
        stack: vec![Group {
            skip: false,
            bold: false,
            italic: false,
            uc: 1,
            href: None,
            capture: Capture::None,
        }],
        out: Parsed::default(),
        buf: String::new(),
        bytes: Vec::new(),
        high_surrogate: None,
        skip_chars: 0,
        para: Para::default(),
        field_instr: String::new(),
        capture_text: String::new(),
        list_text: String::new(),
        rows: Vec::new(),
        row: Vec::new(),
        cell: Vec::new(),
        rows_truncated: false,
    };
    let mut i = start;
    let mut at_start = false;
    let mut star = false;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'{' => {
                if r.stack.len() >= MAX_DEPTH {
                    return Err(ParseError::TooLarge {
                        what: "group depth",
                        limit: MAX_DEPTH,
                        actual: MAX_DEPTH + 1,
                    });
                }
                r.flush_bytes();
                let top = r.stack[r.stack.len() - 1].clone();
                r.stack.push(top);
                at_start = true;
                star = false;
                i += 1;
            }
            b'}' => {
                r.flush_bytes();
                if r.stack.len() > 1 {
                    if let Some(g) = r.stack.pop() {
                        r.close_group(&g);
                    }
                }
                at_start = false;
                star = false;
                i += 1;
            }
            b'\\' => {
                i += 1;
                let Some(&c) = bytes.get(i) else { break };
                if c.is_ascii_alphabetic() {
                    let s = i;
                    while bytes.get(i).is_some_and(u8::is_ascii_alphabetic) {
                        i += 1;
                    }
                    let word = String::from_utf8_lossy(&bytes[s..i]).into_owned();
                    let mut arg: Option<i32> = None;
                    let neg = bytes.get(i) == Some(&b'-');
                    let ds = if neg { i + 1 } else { i };
                    let mut de = ds;
                    while bytes.get(de).is_some_and(u8::is_ascii_digit) {
                        de += 1;
                    }
                    if de > ds {
                        let n: i64 = String::from_utf8_lossy(&bytes[ds..de]).parse().unwrap_or(0);
                        let n = i32::try_from(n.min(i64::from(i32::MAX))).unwrap_or(i32::MAX);
                        arg = Some(if neg { -n } else { n });
                        i = de;
                    }
                    if bytes.get(i) == Some(&b' ') {
                        i += 1;
                    }
                    r.control(&word, arg, star, at_start);
                    at_start = false;
                    star = false;
                } else {
                    match c {
                        b'*' => {
                            star = true;
                            i += 1;
                        }
                        b'\'' => {
                            let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
                            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                                if r.skip_chars > 0 {
                                    r.skip_chars -= 1;
                                } else {
                                    r.bytes.push(v);
                                }
                                i += 3;
                            } else {
                                i += 1;
                            }
                            at_start = false;
                        }
                        b'\\' | b'{' | b'}' => {
                            r.emit_char(char::from(c));
                            i += 1;
                            at_start = false;
                        }
                        b'~' => {
                            r.emit_char(' ');
                            i += 1;
                            at_start = false;
                        }
                        b'_' => {
                            r.emit_char('-');
                            i += 1;
                            at_start = false;
                        }
                        b'\r' | b'\n' => {
                            r.end_paragraph();
                            i += 1;
                        }
                        _ => {
                            i += 1;
                            at_start = false;
                        }
                    }
                }
            }
            b'\r' | b'\n' => i += 1,
            b if b >= 0x80 => {
                r.bytes.push(b);
                at_start = false;
                i += 1;
            }
            _ => {
                // a run of plain ASCII text
                let s = i;
                while i < bytes.len()
                    && !matches!(bytes[i], b'{' | b'}' | b'\\' | b'\r' | b'\n')
                    && bytes[i] < 0x80
                {
                    i += 1;
                }
                let run = String::from_utf8_lossy(&bytes[s..i]).into_owned();
                at_start = false;
                if r.skip_chars > 0 {
                    let n = r.skip_chars.min(run.chars().count());
                    r.skip_chars -= n;
                    let rest: String = run.chars().skip(n).collect();
                    if !rest.is_empty() {
                        r.emit_text(&rest);
                    }
                } else {
                    r.emit_text(&run);
                }
            }
        }
    }
    r.flush_bytes();
    r.end_paragraph();
    r.flush_table();
    if r.rows_truncated {
        r.out
            .warnings
            .push("table rows beyond the row limit were dropped".to_owned());
    }
    Ok(r.out)
}
