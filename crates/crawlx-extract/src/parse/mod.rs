//! Document parsing for the `/parse` upload endpoint and PDF URL scraping.
//!
//! [`parse_document`] turns the bytes of an uploaded file into Markdown, cleaned HTML, plain
//! text, links and metadata. The format is detected from the file name, the declared content
//! type and the bytes themselves (magic numbers, the zip part layout, the OLE2 stream names);
//! the bytes win over a wrong extension. Supported ([`supported_formats`]):
//!
//! | family | extensions | module |
//! |---|---|---|
//! | HTML | `.html` `.htm` `.xhtml` | [`html`] over the page [`crate::Extractor`] |
//! | PDF | `.pdf` | [`pdf`] (text layer, reading order, page breaks, metadata) |
//! | Word | `.docx` `.docm` | [`ooxml`] |
//! | Word 97-2003 | `.doc` | [`legacy`] |
//! | OpenDocument | `.odt` `.ods` `.odp` | [`odf`] |
//! | RTF | `.rtf` | [`rtf`] |
//! | Excel | `.xlsx` `.xlsm` `.xlsb` / `.xls` | [`ooxml`] / [`legacy`] (via `calamine`) |
//! | PowerPoint | `.pptx` `.pptm` / `.ppt` | [`ooxml`] / [`legacy`] |
//! | EPUB | `.epub` | [`epub`] |
//! | text | `.csv` `.txt` `.md` | [`text`] |
//!
//! Hostile input is bounded by [`ParseLimits`]: the input size, the decompressed size of
//! container entries and PDF streams (charged to one shared budget, so a zip bomb stops after
//! `max_uncompressed_bytes + 1` inflated bytes), the number of entries, pages/slides, sheets and
//! rows. Parsers run under a panic guard: no input unwinds into the caller, an unforeseen failure
//! is [`ParseError::Internal`]. Scanned PDF pages and images are read by OCR when an engine is
//! configured ([`ParseOptions::ocr`], [`ocr`]); otherwise scanned pages are reported in
//! [`ParsedDocument::warnings`] and images are refused.

mod blocks;
mod epub;
mod html;
mod legacy;
mod odf;
mod ooxml;
mod rtf;
mod sheet;
mod text;
mod xml;
mod zipbox;

pub mod injection;
pub mod ocr;
pub mod pdf;
pub mod redact;
pub mod traversal;

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;

use self::blocks::{Block, Parsed};
use self::ocr::pdf_pages::PdfOcr;
use self::ocr::Ocr;
use self::pdf::{PdfOptions, PdfPageBlocks};

/// Resource limits of one parse. Every limit is checked before the memory it guards is allocated.
///
/// Hard limits (`max_input_bytes`, `max_uncompressed_bytes`, `max_entries`) fail the parse with
/// [`ParseError::TooLarge`]. Soft limits (`max_pages`, `max_sheets`, `max_rows`) truncate the
/// output and add a message to [`ParsedDocument::warnings`] so a caller still gets the leading
/// part of a very large document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Largest accepted input.
    pub max_input_bytes: usize,
    /// Largest total of decompressed bytes read from container entries and PDF content streams.
    pub max_uncompressed_bytes: usize,
    /// Largest number of zip/OLE entries, PDF loader objects, or PDF content-parser nodes.
    pub max_entries: usize,
    /// Pages (PDF), slides or EPUB chapters parsed; further ones are dropped.
    pub max_pages: usize,
    /// Sheets parsed per workbook; further ones are dropped.
    pub max_sheets: usize,
    /// Rows parsed per sheet or table; further ones are dropped.
    pub max_rows: usize,
}

/// Default of [`ParseLimits::max_input_bytes`]: 50 MiB, the compatibility API's upload limit.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 50 * 1024 * 1024;

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_uncompressed_bytes: 128 * 1024 * 1024,
            max_entries: 10_000,
            max_pages: 2_000,
            max_sheets: 256,
            max_rows: 100_000,
        }
    }
}

/// Why a document could not be parsed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The bounded owned parser process failed.
    #[error(transparent)]
    Isolated(#[from] crate::isolated::IsolatedError),
    /// Parser resource admission could not safely reserve required capacity.
    #[error("{what} resource exhausted: {detail}")]
    ResourceExhausted {
        /// Resource class, never source content.
        what: &'static str,
        /// Privacy-safe finite failure classification.
        detail: String,
    },
    /// The file type is not one of [`supported_formats`].
    #[error("unsupported file type: {detail}")]
    UnsupportedFormat {
        /// What was seen (file name, declared content type, detected signature).
        detail: String,
    },
    /// A resource limit was exceeded.
    #[error("{what} {actual} exceeds limit {limit}")]
    TooLarge {
        /// Which limit (`input bytes`, `uncompressed bytes`, `archive entries`, ...).
        what: &'static str,
        /// The configured limit.
        limit: usize,
        /// The observed value (a lower bound when the check stopped early).
        actual: usize,
    },
    /// The document is password protected or otherwise encrypted.
    #[error("{format} document is encrypted")]
    Encrypted {
        /// The format name.
        format: &'static str,
    },
    /// The bytes are not a valid document of the detected format.
    #[error("invalid {format} document: {reason}")]
    Corrupt {
        /// The format name.
        format: &'static str,
        /// What is wrong.
        reason: String,
        /// The parser error behind it.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// The document has no text layer to extract (a scan or an image-only file) and the caller
    /// required one.
    #[error("{format} document has no extractable text")]
    NoText {
        /// The format name.
        format: &'static str,
    },
    /// A parser failed on an unforeseen input. The input is rejected; this is a defect to report.
    #[error("{format} parser failed internally")]
    Internal {
        /// The format name.
        format: &'static str,
    },
    /// An `includeTags`/`excludeTags` entry is not a valid CSS selector.
    #[error("invalid selector `{selector}`: {reason}")]
    InvalidSelector {
        /// The offending selector.
        selector: String,
        /// Parser message.
        reason: String,
    },
    /// The OCR engine failed on an image (not: the image is unreadable, which is
    /// [`ParseError::Corrupt`]).
    #[error("OCR failed")]
    Ocr(#[source] ocr::OcrError),
    /// The process-wide parse-memory budget could not take the HTML parse's charge. Transient:
    /// nothing was parsed, retry once other parses have finished.
    #[error("parse memory budget exhausted")]
    ParseMemory(#[source] crate::parse_budget::ParseBudgetExhausted),
}

impl ParseError {
    /// A [`ParseError::Corrupt`] without an underlying error.
    #[must_use]
    pub fn corrupt(format: &'static str, reason: impl Into<String>) -> Self {
        Self::Corrupt {
            format,
            reason: reason.into(),
            source: None,
        }
    }

    /// A [`ParseError::Corrupt`] wrapping the parser error behind it.
    #[must_use]
    pub fn corrupt_from(
        format: &'static str,
        reason: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Corrupt {
            format,
            reason: reason.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Run `f`, turning a panic of the parser into [`ParseError::Internal`] so no input can unwind
/// into the caller.
pub(crate) fn guard<T>(
    format: &'static str,
    f: impl FnOnce() -> Result<T, ParseError>,
) -> Result<T, ParseError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(Err(ParseError::Internal { format }))
}

// ---------------------------------------------------------------------------------------------
// Formats
// ---------------------------------------------------------------------------------------------

/// A supported document format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ParseFormat {
    /// `.html` `.htm` `.xhtml`
    Html,
    /// `.pdf`
    Pdf,
    /// `.docx` `.docm`
    Docx,
    /// `.doc`
    Doc,
    /// `.odt`
    Odt,
    /// `.ods`
    Ods,
    /// `.odp`
    Odp,
    /// `.rtf`
    Rtf,
    /// `.xlsx` `.xlsm`
    Xlsx,
    /// `.xls`
    Xls,
    /// `.xlsb`
    Xlsb,
    /// `.pptx` `.pptm`
    Pptx,
    /// `.ppt`
    Ppt,
    /// `.epub`
    Epub,
    /// `.csv`
    Csv,
    /// `.txt`
    Txt,
    /// `.md`
    Md,
    /// `.png` (read by OCR)
    Png,
    /// `.jpg` `.jpeg` (read by OCR)
    Jpeg,
    /// `.gif` (read by OCR)
    Gif,
    /// `.webp` (read by OCR)
    Webp,
    /// `.bmp` (read by OCR)
    Bmp,
    /// `.tif` `.tiff` (read by OCR)
    Tiff,
}

/// Whether a format is parsed as a document or recognised as an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum FormatKind {
    /// Parsed to text.
    Document,
    /// A raster image, read by OCR when a backend is configured ([`ocr`]).
    Image,
}

/// One row of `GET /v2/parse/formats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FormatInfo {
    /// Canonical extension without the dot.
    pub format: &'static str,
    /// Document or image.
    pub kind: FormatKind,
    /// Accepted extensions, canonical first.
    pub extensions: &'static [&'static str],
    /// Accepted MIME types.
    pub mime_types: &'static [&'static str],
    /// Whether uploads of this format are accepted right now.
    pub available: bool,
}

const fn doc(
    format: &'static str,
    extensions: &'static [&'static str],
    mime_types: &'static [&'static str],
) -> FormatInfo {
    FormatInfo {
        format,
        kind: FormatKind::Document,
        extensions,
        mime_types,
        available: true,
    }
}

const fn image(
    format: &'static str,
    extensions: &'static [&'static str],
    mime_types: &'static [&'static str],
) -> FormatInfo {
    FormatInfo {
        format,
        kind: FormatKind::Image,
        extensions,
        mime_types,
        available: false,
    }
}

const FORMATS: &[FormatInfo] = &[
    doc(
        "html",
        &[".html", ".htm", ".xhtml"],
        &["text/html", "application/xhtml+xml"],
    ),
    doc("pdf", &[".pdf"], &["application/pdf"]),
    doc(
        "docx",
        &[".docx", ".docm"],
        &[
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-word.document.macroenabled.12",
        ],
    ),
    doc("doc", &[".doc"], &["application/msword"]),
    doc("odt", &[".odt"], &["application/vnd.oasis.opendocument.text"]),
    doc(
        "ods",
        &[".ods"],
        &["application/vnd.oasis.opendocument.spreadsheet"],
    ),
    doc(
        "odp",
        &[".odp"],
        &["application/vnd.oasis.opendocument.presentation"],
    ),
    doc("rtf", &[".rtf"], &["application/rtf", "text/rtf"]),
    doc(
        "xlsx",
        &[".xlsx", ".xlsm"],
        &[
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-excel.sheet.macroenabled.12",
        ],
    ),
    doc("xls", &[".xls"], &["application/vnd.ms-excel"]),
    doc(
        "xlsb",
        &[".xlsb"],
        &["application/vnd.ms-excel.sheet.binary.macroenabled.12"],
    ),
    doc(
        "pptx",
        &[".pptx", ".pptm"],
        &[
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        ],
    ),
    doc("ppt", &[".ppt"], &["application/vnd.ms-powerpoint"]),
    doc("epub", &[".epub"], &["application/epub+zip"]),
    doc("csv", &[".csv"], &["text/csv", "application/csv"]),
    doc("txt", &[".txt"], &["text/plain"]),
    doc("md", &[".md", ".markdown"], &["text/markdown", "text/x-markdown"]),
    image("png", &[".png"], &["image/png"]),
    image("jpeg", &[".jpeg", ".jpg"], &["image/jpeg"]),
    image("gif", &[".gif"], &["image/gif"]),
    image("webp", &[".webp"], &["image/webp"]),
    image("bmp", &[".bmp"], &["image/bmp"]),
    image("tiff", &[".tiff", ".tif"], &["image/tiff"]),
];

/// The formats `/parse` knows, documents first; images are listed as unavailable (they need an
/// OCR engine: see [`supported_formats_with`]).
#[must_use]
pub fn supported_formats() -> &'static [FormatInfo] {
    FORMATS
}

/// [`supported_formats`] for a server whose OCR engine is `ocr_available`: the image rows are
/// `available` exactly then.
#[must_use]
pub fn supported_formats_with(ocr_available: bool) -> Vec<FormatInfo> {
    FORMATS
        .iter()
        .map(|f| FormatInfo {
            available: f.available || (ocr_available && f.kind == FormatKind::Image),
            ..*f
        })
        .collect()
}

impl ParseFormat {
    /// The canonical short name (`docx`, `pdf`, ...).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Pdf => "pdf",
            Self::Docx => "docx",
            Self::Doc => "doc",
            Self::Odt => "odt",
            Self::Ods => "ods",
            Self::Odp => "odp",
            Self::Rtf => "rtf",
            Self::Xlsx => "xlsx",
            Self::Xls => "xls",
            Self::Xlsb => "xlsb",
            Self::Pptx => "pptx",
            Self::Ppt => "ppt",
            Self::Epub => "epub",
            Self::Csv => "csv",
            Self::Txt => "txt",
            Self::Md => "md",
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Gif => "gif",
            Self::Webp => "webp",
            Self::Bmp => "bmp",
            Self::Tiff => "tiff",
        }
    }

    /// The canonical MIME type of the format.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        FORMATS
            .iter()
            .find(|f| f.format == self.name())
            .and_then(|f| f.mime_types.first().copied())
            .unwrap_or("application/octet-stream")
    }

    /// The format for a file extension (with or without the dot, any case).
    #[must_use]
    pub fn from_extension(ext: &str) -> Option<Self> {
        let e = ext.trim_start_matches('.').to_ascii_lowercase();
        let e = format!(".{e}");
        let f = FORMATS
            .iter()
            .filter(|f| f.kind == FormatKind::Document)
            .find(|f| f.extensions.contains(&e.as_str()))?;
        Self::from_name(f.format)
    }

    /// The format for a MIME type (parameters ignored).
    #[must_use]
    pub fn from_mime(mime: &str) -> Option<Self> {
        let m = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
        let f = FORMATS
            .iter()
            .filter(|f| f.kind == FormatKind::Document)
            .find(|f| f.mime_types.contains(&m.as_str()))?;
        Self::from_name(f.format)
    }

    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "html" => Self::Html,
            "pdf" => Self::Pdf,
            "docx" => Self::Docx,
            "doc" => Self::Doc,
            "odt" => Self::Odt,
            "ods" => Self::Ods,
            "odp" => Self::Odp,
            "rtf" => Self::Rtf,
            "xlsx" => Self::Xlsx,
            "xls" => Self::Xls,
            "xlsb" => Self::Xlsb,
            "pptx" => Self::Pptx,
            "ppt" => Self::Ppt,
            "epub" => Self::Epub,
            "csv" => Self::Csv,
            "txt" => Self::Txt,
            "md" => Self::Md,
            "png" => Self::Png,
            "jpeg" => Self::Jpeg,
            "gif" => Self::Gif,
            "webp" => Self::Webp,
            "bmp" => Self::Bmp,
            "tiff" => Self::Tiff,
            _ => return None,
        })
    }
}

enum Sniff {
    Format(ParseFormat),
    Image(&'static str),
    Encrypted,
    Archive(&'static str),
    Unknown,
}

fn sniff_zip(bytes: &[u8], limits: &ParseLimits) -> Result<Sniff, ParseError> {
    let mut z = zipbox::ZipBox::open(bytes, "zip", limits)?;
    if let Some(mt) = z.read("mimetype")? {
        let mt = String::from_utf8_lossy(&mt);
        let mt = mt.trim();
        let f = match mt {
            "application/epub+zip" => Some(ParseFormat::Epub),
            "application/vnd.oasis.opendocument.text" => Some(ParseFormat::Odt),
            "application/vnd.oasis.opendocument.spreadsheet" => Some(ParseFormat::Ods),
            "application/vnd.oasis.opendocument.presentation" => Some(ParseFormat::Odp),
            _ => None,
        };
        if let Some(f) = f {
            return Ok(Sniff::Format(f));
        }
    }
    if z.has("[Content_Types].xml") {
        for (part, f) in [
            ("word/document.xml", ParseFormat::Docx),
            ("xl/workbook.xml", ParseFormat::Xlsx),
            ("xl/workbook.bin", ParseFormat::Xlsb),
            ("ppt/presentation.xml", ParseFormat::Pptx),
        ] {
            if z.has(part) {
                return Ok(Sniff::Format(f));
            }
        }
    }
    if z.has("META-INF/container.xml") {
        return Ok(Sniff::Format(ParseFormat::Epub));
    }
    Ok(Sniff::Archive("a zip archive that is not a supported document"))
}

fn sniff(bytes: &[u8], limits: &ParseLimits) -> Result<Sniff, ParseError> {
    let head = &bytes[..bytes.len().min(1024)];
    if head.windows(5).any(|w| w == b"%PDF-") {
        return Ok(Sniff::Format(ParseFormat::Pdf));
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return sniff_zip(bytes, limits);
    }
    if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return Ok(match legacy::sniff_ole(bytes, limits)? {
            legacy::OleKind::Doc => Sniff::Format(ParseFormat::Doc),
            legacy::OleKind::Xls => Sniff::Format(ParseFormat::Xls),
            legacy::OleKind::Ppt => Sniff::Format(ParseFormat::Ppt),
            legacy::OleKind::EncryptedPackage => Sniff::Encrypted,
            legacy::OleKind::Other => Sniff::Archive("an OLE2 file that is not a supported document"),
        });
    }
    let trimmed: &[u8] = {
        let start = head.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
        &head[start..]
    };
    if trimmed.starts_with(b"{\\rtf") {
        return Ok(Sniff::Format(ParseFormat::Rtf));
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Ok(Sniff::Image("png"));
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Ok(Sniff::Image("jpeg"));
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Ok(Sniff::Image("gif"));
    }
    if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Ok(Sniff::Image("webp"));
    }
    if bytes.starts_with(b"BM") && bytes.len() > 26 && head.iter().take(14).any(|b| *b == 0) {
        return Ok(Sniff::Image("bmp"));
    }
    if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        return Ok(Sniff::Image("tiff"));
    }
    if bytes.starts_with(&[0x1F, 0x8B]) {
        return Ok(Sniff::Archive("a gzip stream"));
    }
    if bytes.starts_with(b"7z\xBC\xAF\x27\x1C") || bytes.starts_with(b"Rar!\x1A\x07") {
        return Ok(Sniff::Archive("a compressed archive"));
    }
    Ok(Sniff::Unknown)
}

fn looks_like_html(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_ascii_lowercase();
    let t = head.trim_start();
    t.starts_with("<!doctype html")
        || t.starts_with("<html")
        || t.starts_with("<head")
        || t.starts_with("<body")
}

/// Detect the format of an upload.
///
/// The bytes decide when they carry a signature (PDF, zip part layout, OLE2 streams, RTF); for
/// plain-text formats the file extension, then the declared content type, decide.
///
/// # Errors
/// [`ParseError::UnsupportedFormat`] for images (no OCR), archives and unknown types;
/// [`ParseError::Encrypted`] for encrypted OOXML packages; [`ParseError::TooLarge`] for
/// containers beyond the entry or size limits.
pub fn detect_format(
    bytes: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    limits: &ParseLimits,
) -> Result<ParseFormat, ParseError> {
    let name = filename.map(|f| f.rsplit(['/', '\\']).next().unwrap_or(f));
    let ext = name
        .and_then(|n| n.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase());
    let by_ext = ext.as_deref().and_then(ParseFormat::from_extension);
    let by_mime = content_type
        .filter(|m| !m.trim().is_empty())
        .and_then(ParseFormat::from_mime);
    match sniff(bytes, limits)? {
        Sniff::Format(f) => Ok(f),
        Sniff::Image(kind) => ParseFormat::from_name(kind).ok_or_else(|| ParseError::UnsupportedFormat {
            detail: format!("a {kind} image"),
        }),
        Sniff::Encrypted => Err(ParseError::Encrypted {
            format: by_ext.map_or("office", ParseFormat::name),
        }),
        Sniff::Archive(what) => Err(ParseError::UnsupportedFormat {
            detail: what.to_owned(),
        }),
        Sniff::Unknown => by_ext
            .or(by_mime)
            .or_else(|| looks_like_html(bytes).then_some(ParseFormat::Html))
            .ok_or_else(|| {
                let seen = match (name, content_type) {
                    (Some(n), Some(c)) if !c.is_empty() => format!("{n:?} ({c})"),
                    (Some(n), _) => format!("{n:?}"),
                    (None, Some(c)) if !c.is_empty() => format!("content type {c}"),
                    _ => "no file name or content type".to_owned(),
                };
                ParseError::UnsupportedFormat { detail: seen }
            }),
    }
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------

/// Options of [`parse_document_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOptions {
    /// Resource limits.
    pub limits: ParseLimits,
    /// HTML input: keep only the main content block (`onlyMainContent`).
    pub only_main_content: bool,
    /// HTML input: CSS selectors whose matches form the output (`includeTags`).
    pub include_tags: Vec<String>,
    /// HTML input: CSS selectors removed from the output (`excludeTags`).
    pub exclude_tags: Vec<String>,
    /// PDF: parse at most this many pages (`parsers[].maxPages`).
    pub pdf_max_pages: Option<u32>,
    /// PDF: annotate page breaks in the Markdown (`parsers[].pageMarkers`).
    pub pdf_page_markers: bool,
    /// PDF: fail with [`ParseError::NoText`] when no page has a text layer (`mode: fast`).
    pub pdf_require_text: bool,
    /// PDF: also produce the typed layout blocks (`parsers[].blocks`).
    pub pdf_layout: bool,
    /// The OCR engine: scanned PDF pages ([`Self::pdf_ocr`]) and image uploads need one.
    pub ocr: Option<Arc<Ocr>>,
    /// PDF: which pages are OCR'd when [`Self::ocr`] is set (`parsers[].mode`: `fast` is
    /// [`PdfOcr::Off`], `auto` [`PdfOcr::Auto`], `ocr` [`PdfOcr::Always`]).
    pub pdf_ocr: PdfOcr,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            limits: ParseLimits::default(),
            only_main_content: true,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
            pdf_max_pages: None,
            pdf_page_markers: false,
            pdf_require_text: false,
            pdf_layout: false,
            ocr: None,
            pdf_ocr: PdfOcr::Auto,
        }
    }
}

/// Markdown of one PDF page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ParsedPage {
    /// 1-based physical page number.
    pub page_number: u32,
    /// Markdown of the page.
    pub markdown: String,
}

/// A parsed document.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ParsedDocument {
    /// The detected format.
    pub format: ParseFormat,
    /// Canonical MIME type of the format.
    pub content_type: &'static str,
    /// Document title (properties, then the first heading).
    pub title: Option<String>,
    /// Markdown.
    pub markdown: String,
    /// Cleaned HTML.
    pub html: String,
    /// HTML input: the decoded source. Other formats: the generated HTML.
    pub raw_html: String,
    /// Plain text.
    pub text: String,
    /// Distinct absolute `http(s)` links in document order.
    pub links: Vec<String>,
    /// HTML and EPUB input: image URLs.
    pub images: Vec<String>,
    /// Document properties by compatibility API metadata key.
    pub metadata: BTreeMap<String, Value>,
    /// PDF: pages parsed.
    pub num_pages: Option<u32>,
    /// PDF: pages in the document.
    pub total_pages: Option<u32>,
    /// PDF: Markdown per parsed page.
    pub pages: Vec<ParsedPage>,
    /// PDF: typed layout blocks per page (only with `pdf_layout`).
    pub layout: Vec<PdfPageBlocks>,
    /// Non-fatal findings (truncation, pages without text, ...).
    pub warnings: Vec<String>,
}

impl ParsedDocument {
    /// Credits the parse costs: one per PDF page, one per other document.
    #[must_use]
    pub fn credits(&self) -> u64 {
        self.num_pages.map_or(1, |n| u64::from(n.max(1)))
    }
}

fn meta_values(meta: BTreeMap<String, String>) -> BTreeMap<String, Value> {
    meta.into_iter().map(|(k, v)| (k, Value::String(v))).collect()
}

fn first_heading(blocks: &[Block]) -> Option<String> {
    blocks.iter().find_map(|b| match b {
        Block::Heading { spans, .. } => {
            let t = blocks::collapse(&blocks::spans_text(spans));
            (!t.is_empty()).then_some(t)
        }
        _ => None,
    })
}

fn from_parsed(format: ParseFormat, parsed: Parsed) -> ParsedDocument {
    let markdown = blocks::render_markdown(&parsed.blocks);
    let html = blocks::render_html(&parsed.blocks);
    let title = parsed
        .meta
        .get("title")
        .cloned()
        .or_else(|| first_heading(&parsed.blocks));
    let mut metadata = meta_values(parsed.meta);
    if let Some(t) = &title {
        metadata
            .entry("title".to_owned())
            .or_insert_with(|| Value::String(t.clone()));
    }
    ParsedDocument {
        format,
        content_type: format.content_type(),
        title,
        text: blocks::render_text(&parsed.blocks),
        links: blocks::collect_links(&parsed.blocks),
        raw_html: html.clone(),
        html,
        markdown,
        images: Vec::new(),
        metadata,
        num_pages: None,
        total_pages: None,
        pages: Vec::new(),
        layout: Vec::new(),
        warnings: parsed.warnings,
    }
}

/// An image: the recognised text of the picture, or [`ParseError::UnsupportedFormat`] without an
/// OCR engine.
fn from_image(format: ParseFormat, bytes: &[u8], opts: &ParseOptions) -> Result<ParsedDocument, ParseError> {
    let Some(engine) = &opts.ocr else {
        return Err(ParseError::UnsupportedFormat {
            detail: format!("a {} image (image OCR is not available)", format.name()),
        });
    };
    let page = engine.recognize_bytes(bytes).map_err(|e| match e {
        ocr::OcrError::Image(reason) => ParseError::corrupt(format.name(), reason),
        other => ParseError::Ocr(other),
    })?;
    let parsed = Parsed {
        blocks: page
            .paragraphs
            .iter()
            .map(|p| Block::Paragraph(vec![blocks::Span::plain(p.text.clone())]))
            .collect(),
        meta: BTreeMap::new(),
        warnings: if page.paragraphs.is_empty() {
            vec!["OCR found no text in the image".to_owned()]
        } else {
            Vec::new()
        },
    };
    let mut doc = from_parsed(format, parsed);
    doc.metadata.insert("width".to_owned(), Value::from(page.width));
    doc.metadata.insert("height".to_owned(), Value::from(page.height));
    doc.metadata
        .insert("ocrBackend".to_owned(), Value::from(engine.backend().name()));
    if let Some(c) = page.confidence() {
        doc.metadata.insert("ocrConfidence".to_owned(), Value::from(c));
    }
    Ok(doc)
}

fn from_pdf(bytes: &[u8], opts: &ParseOptions) -> Result<ParsedDocument, ParseError> {
    let po = PdfOptions {
        max_pages: opts.pdf_max_pages,
        pages: Vec::new(),
        page_markers: opts.pdf_page_markers,
        require_text: opts.pdf_require_text,
        layout: opts.pdf_layout,
        ocr: opts.ocr.clone(),
        ocr_mode: opts.pdf_ocr,
        limits: opts.limits,
    };
    let p = pdf::extract_pdf(bytes, &po)?;
    let all = p.all_blocks();
    let html = blocks::render_html(&all);
    let mut metadata: BTreeMap<String, Value> = BTreeMap::new();
    let m = &p.metadata;
    for (k, v) in [
        ("title", &m.title),
        ("author", &m.author),
        ("subject", &m.subject),
        ("keywords", &m.keywords),
        ("creator", &m.creator),
        ("producer", &m.producer),
        ("creationDate", &m.creation_date),
        ("modifiedDate", &m.modification_date),
    ] {
        if let Some(v) = v {
            metadata.insert(k.to_owned(), Value::String(v.clone()));
        }
    }
    metadata.insert("pdfVersion".to_owned(), Value::String(m.version.clone()));
    let title = m.title.clone().or_else(|| first_heading(&all));
    if let Some(t) = &title {
        metadata
            .entry("title".to_owned())
            .or_insert_with(|| Value::String(t.clone()));
    }
    let links = {
        let mut l = blocks::collect_links(&all);
        for u in &p.links {
            if !l.contains(u) {
                l.push(u.clone());
            }
        }
        l
    };
    Ok(ParsedDocument {
        format: ParseFormat::Pdf,
        content_type: ParseFormat::Pdf.content_type(),
        title,
        markdown: p.markdown.clone(),
        raw_html: html.clone(),
        html,
        text: p.text.clone(),
        links,
        images: Vec::new(),
        metadata,
        num_pages: Some(p.num_pages),
        total_pages: Some(p.total_pages),
        pages: p
            .pages
            .iter()
            .map(|pg| ParsedPage {
                page_number: pg.number,
                markdown: pg.markdown.clone(),
            })
            .collect(),
        layout: p.layout.clone(),
        warnings: p.warnings.clone(),
    })
}

fn from_html(bytes: &[u8], opts: &ParseOptions) -> Result<ParsedDocument, ParseError> {
    let ho = html::HtmlOpts {
        only_main_content: opts.only_main_content,
        include_tags: &opts.include_tags,
        exclude_tags: &opts.exclude_tags,
    };
    let d = html::convert(bytes, &ho, &opts.limits)?;
    Ok(ParsedDocument {
        format: ParseFormat::Html,
        content_type: ParseFormat::Html.content_type(),
        title: d.title,
        markdown: d.markdown,
        html: d.html,
        raw_html: d.raw,
        text: d.text,
        links: d.links,
        images: d.images,
        metadata: d.metadata,
        num_pages: None,
        total_pages: None,
        pages: Vec::new(),
        layout: Vec::new(),
        warnings: Vec::new(),
    })
}

fn from_epub(bytes: &[u8], opts: &ParseOptions) -> Result<ParsedDocument, ParseError> {
    let e = epub::parse_epub(bytes, &opts.limits)?;
    let mut metadata = meta_values(e.meta);
    if let Some(t) = &e.title {
        metadata
            .entry("title".to_owned())
            .or_insert_with(|| Value::String(t.clone()));
    }
    Ok(ParsedDocument {
        format: ParseFormat::Epub,
        content_type: ParseFormat::Epub.content_type(),
        title: e.title,
        markdown: e.markdown,
        raw_html: e.html.clone(),
        html: e.html,
        text: e.text,
        links: e.links,
        images: e.images,
        metadata,
        num_pages: None,
        total_pages: None,
        pages: Vec::new(),
        layout: Vec::new(),
        warnings: e.warnings,
    })
}

fn from_plain(format: ParseFormat, out: text::PlainOut) -> ParsedDocument {
    let mut d = from_parsed(format, out.parsed);
    d.markdown = out.markdown;
    d.links = out.links;
    d
}

/// Parse an uploaded file with the default options and the given limits.
///
/// # Errors
/// [`ParseError`]: unsupported type, over a limit, encrypted or corrupt.
pub fn parse_document(
    bytes: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    limits: &ParseLimits,
) -> Result<ParsedDocument, ParseError> {
    parse_document_with(
        bytes,
        filename,
        content_type,
        &ParseOptions {
            limits: *limits,
            ..ParseOptions::default()
        },
    )
}

/// Parse an uploaded file.
///
/// Synchronous and CPU-bound: call it from a blocking thread, never from an async task. With an
/// OCR engine in `opts` this includes running the engine (a child process for `tesseract`).
///
/// # Errors
/// [`ParseError`]: unsupported type (an image without an OCR engine included), over a limit,
/// encrypted, corrupt, or [`ParseError::Ocr`] when the engine fails on an image.
pub fn parse_document_with(
    bytes: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    opts: &ParseOptions,
) -> Result<ParsedDocument, ParseError> {
    let limits = &opts.limits;
    if bytes.len() > limits.max_input_bytes {
        return Err(ParseError::TooLarge {
            what: "input bytes",
            limit: limits.max_input_bytes,
            actual: bytes.len(),
        });
    }
    let format = guard("detect", || detect_format(bytes, filename, content_type, limits))?;
    guard(format.name(), || {
        match format {
            ParseFormat::Pdf => return from_pdf(bytes, opts),
            ParseFormat::Html => return from_html(bytes, opts),
            ParseFormat::Epub => return from_epub(bytes, opts),
            ParseFormat::Txt => return Ok(from_plain(format, text::parse_txt(bytes))),
            ParseFormat::Md => return Ok(from_plain(format, text::parse_md(bytes))),
            ParseFormat::Png
            | ParseFormat::Jpeg
            | ParseFormat::Gif
            | ParseFormat::Webp
            | ParseFormat::Bmp
            | ParseFormat::Tiff => return from_image(format, bytes, opts),
            _ => {}
        }
        let parsed = match format {
            ParseFormat::Docx => ooxml::parse_docx(bytes, limits)?,
            ParseFormat::Pptx => ooxml::parse_pptx(bytes, limits)?,
            ParseFormat::Xlsx => ooxml::parse_xlsx(bytes, limits)?,
            ParseFormat::Xlsb => ooxml::parse_xlsb(bytes, limits)?,
            ParseFormat::Odt => odf::parse_odf(bytes, odf::OdfKind::Text, limits)?,
            ParseFormat::Ods => odf::parse_odf(bytes, odf::OdfKind::Sheet, limits)?,
            ParseFormat::Odp => odf::parse_odf(bytes, odf::OdfKind::Presentation, limits)?,
            ParseFormat::Doc => legacy::parse_doc(bytes, limits)?,
            ParseFormat::Ppt => legacy::parse_ppt(bytes, limits)?,
            ParseFormat::Xls => legacy::parse_xls(bytes, limits)?,
            ParseFormat::Rtf => rtf::parse_rtf(bytes, limits)?,
            ParseFormat::Csv => text::parse_csv(bytes, limits)?,
            ParseFormat::Pdf
            | ParseFormat::Html
            | ParseFormat::Epub
            | ParseFormat::Txt
            | ParseFormat::Md
            | ParseFormat::Png
            | ParseFormat::Jpeg
            | ParseFormat::Gif
            | ParseFormat::Webp
            | ParseFormat::Bmp
            | ParseFormat::Tiff => {
                return Err(ParseError::Internal {
                    format: format.name(),
                });
            }
        };
        Ok(from_parsed(format, parsed))
    })
}
