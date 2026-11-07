//! Serialization of the cleaned content tree back to HTML (the `html` output
//! format).
//!
//! Only a small attribute whitelist survives; URL-valued attributes are
//! resolved to absolute URLs and dropped when the scheme is not a safe link
//! scheme. Event handlers, `style` and `class` (except on `pre`/`code`) are
//! never emitted.

use url::Url;

use crate::dom::{image_src, is_safe_link_scheme, resolve, Elem, Node};

const VOID: &[&str] = &["br", "hr", "img", "wbr", "col"];

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
}

fn attr(out: &mut String, name: &str, value: &str) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    escape_attr(value, out);
    out.push('"');
}

fn url_attr(e: &Elem, name: &str, base: &Url, out: &mut String) {
    if let Some(u) = e
        .attr(name)
        .and_then(|v| resolve(base, v))
        .filter(is_safe_link_scheme)
    {
        attr(out, name, u.as_str());
    }
}

fn open_tag(e: &Elem, base: &Url, keep_data_images: bool, out: &mut String) {
    out.push('<');
    out.push_str(&e.tag);
    for name in ["lang", "dir", "title"] {
        if let Some(v) = e.attr(name) {
            attr(out, name, v);
        }
    }
    match e.tag.as_str() {
        "a" => url_attr(e, "href", base, out),
        "img" => {
            if let Some(src) = image_src(e, base, keep_data_images) {
                attr(out, "src", src.as_str());
            }
            if let Some(alt) = e.attr("alt") {
                attr(out, "alt", alt);
            }
        }
        "td" | "th" => {
            for name in ["colspan", "rowspan", "align"] {
                if let Some(v) = e.attr(name) {
                    attr(out, name, v);
                }
            }
        }
        "ol" => {
            if let Some(v) = e.attr("start") {
                attr(out, "start", v);
            }
        }
        "pre" | "code" => {
            if let Some(v) = e.attr("class") {
                attr(out, "class", v);
            }
        }
        "time" => {
            if let Some(v) = e.attr("datetime") {
                attr(out, "datetime", v);
            }
        }
        "blockquote" | "q" => url_attr(e, "cite", base, out),
        _ => {}
    }
    out.push('>');
}

fn write_node(n: &Node, base: &Url, keep_data_images: bool, out: &mut String) {
    match n {
        Node::Text(t) => escape_text(t, out),
        Node::Elem(e) => {
            open_tag(e, base, keep_data_images, out);
            if VOID.contains(&e.tag.as_str()) {
                return;
            }
            for c in &e.children {
                write_node(c, base, keep_data_images, out);
            }
            out.push_str("</");
            out.push_str(&e.tag);
            out.push('>');
        }
    }
}

/// Serialize `nodes` to HTML, resolving URLs against `base`. `data:image/...` sources of `<img>`
/// are kept only when `keep_data_images` is set.
#[must_use]
pub fn to_html(nodes: &[Node], base: &Url, keep_data_images: bool) -> String {
    let mut out = String::new();
    for n in nodes {
        write_node(n, base, keep_data_images, &mut out);
    }
    out
}

/// Render privacy-replaced text without retaining unsafe original inline subtrees.
pub(crate) fn redacted_text_fragment(text: &str) -> String {
    let mut output = String::with_capacity(text.len().saturating_add(11));
    output.push_str("<pre>");
    escape_text(text, &mut output);
    output.push_str("</pre>");
    output
}

/// Shared offline article output rendition. No network or schema resolution occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArticleFormat {
    /// Canonical native text/comments/envelope view, or the existing legacy document.
    Json,
    /// One compact newline-delimited JSON article.
    Jsonl,
    /// Selected main plain text.
    Text,
    /// Existing Markdown rendering.
    Markdown,
    /// Existing sanitized HTML rendering.
    Html,
    /// Spreadsheet-safe CSV record with a header.
    Csv,
    /// Native escaped article XML.
    Xml,
    /// TEI P5 document; schema validation is a separate explicit offline operation.
    Tei,
}

/// Serializer failures preserve their underlying source.
#[derive(Debug, thiserror::Error)]
pub enum ArticleWriteError {
    /// Sink refused bytes.
    #[error("article output failed: {0}")]
    Io(#[from] std::io::Error),
    /// Document serialization failed.
    #[error("article json failed: {0}")]
    Json(#[from] serde_json::Error),
    /// XML 1.0 cannot represent a caller/document scalar. No record bytes were written.
    #[error("article XML contains a forbidden scalar")]
    InvalidXmlScalar,
    /// Chunk ranges no longer describe the finalized canonical text.
    #[error("article chunk source failed validation: {0}")]
    WordChunks(#[from] crawlx_core::extraction::WordChunkErrorV1),
}

fn xml_text(out: &mut dyn std::io::Write, value: &str) -> std::io::Result<()> {
    for ch in value.chars() {
        match ch {
            '&' => out.write_all(b"&amp;")?,
            '<' => out.write_all(b"&lt;")?,
            '>' => out.write_all(b"&gt;")?,
            '"' => out.write_all(b"&quot;")?,
            '\'' => out.write_all(b"&apos;")?,
            '\t' => out.write_all(b"&#9;")?,
            '\n' => out.write_all(b"&#10;")?,
            '\r' => out.write_all(b"&#13;")?,
            // XML 1.0 permits these scalar ranges only.
            '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}' => {
                out.write_all(ch.encode_utf8(&mut [0; 4]).as_bytes())?;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "XML 1.0 forbids an input scalar",
                ))
            }
        }
    }
    Ok(())
}
fn csv_field(out: &mut dyn std::io::Write, value: &str) -> std::io::Result<()> {
    out.write_all(b"\"")?;
    // Spreadsheet importers may discard leading whitespace, controls or a BOM.
    if value
        .trim_start_matches(|ch: char| ch.is_whitespace() || ch.is_control() || ch == '\u{feff}')
        .starts_with(['=', '+', '-', '@'])
        || value.starts_with(['\t', '\r'])
    {
        out.write_all(b"'")?;
    }
    for part in value.split_inclusive('"') {
        out.write_all(part.as_bytes())?;
        if part.ends_with('"') {
            out.write_all(b"\"")?;
        }
    }
    out.write_all(b"\"")
}

#[derive(serde::Serialize)]
struct ArticleContent<'a> {
    text: &'a str,
    comments: &'a str,
    article: &'a crawlx_core::extraction::DocumentEnvelopeV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    item: Option<&'a crawlx_core::selectors::ItemOutcomeV1>,
}

fn valid_xml_scalars(value: &str) -> bool {
    value.chars().all(|ch| matches!(ch, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'))
}

fn article_title_source(document: &crate::Document) -> (&str, &str) {
    let native = document.article.as_ref();
    let title = native
        .and_then(|article| article.metadata.title.value.as_deref())
        .unwrap_or_else(|| {
            if native.is_some() {
                ""
            } else {
                document.title.as_deref().unwrap_or("")
            }
        });
    (
        title,
        if native.is_some() {
            ""
        } else {
            document.base_url.as_str()
        },
    )
}

fn validate_article_scalars(document: &crate::Document) -> Result<(), ArticleWriteError> {
    let (title, source) = article_title_source(document);
    if [title, source, &document.text, &document.comments]
        .into_iter()
        .all(valid_xml_scalars)
    {
        Ok(())
    } else {
        Err(ArticleWriteError::InvalidXmlScalar)
    }
}

fn validate_article_chunks(document: &crate::Document) -> Result<(), ArticleWriteError> {
    if let Some(chunks) = document
        .article
        .as_ref()
        .and_then(|article| article.chunks.as_ref())
    {
        chunks.validate(&document.text, &chunks.policy)?;
    }
    Ok(())
}

/// Stream one document through the shared serializer without a second content-sized buffer.
///
/// The caller owns authorization, redaction and the retention-typed sink. This function
/// must not be used to bypass that boundary for persistent exports.
///
/// # Errors
/// Returns sink I/O, JSON or invalid final chunk-source errors.
pub fn write_article(
    out: &mut dyn std::io::Write,
    document: &crate::Document,
    format: ArticleFormat,
) -> Result<(), ArticleWriteError> {
    validate_article_chunks(document)?;
    if matches!(format, ArticleFormat::Xml | ArticleFormat::Tei) {
        validate_article_scalars(document)?;
    }
    write_article_body(out, document, format, true)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn write_article_body(
    out: &mut dyn std::io::Write,
    document: &crate::Document,
    format: ArticleFormat,
    standalone: bool,
) -> Result<(), ArticleWriteError> {
    let native = document.article.as_ref();
    let (title, source) = article_title_source(document);
    match format {
        ArticleFormat::Json | ArticleFormat::Jsonl => {
            if let Some(article) = native {
                // This approved view excludes unprojected legacy forms/raw metadata/URLs.
                // A sink must not mutate it after source ranges and digests are finalized.
                serde_json::to_writer(
                    &mut *out,
                    &ArticleContent {
                        text: &document.text,
                        comments: &document.comments,
                        article,
                        item: document.item.as_ref(),
                    },
                )?;
            } else {
                serde_json::to_writer(&mut *out, document)?;
            }
        }
        ArticleFormat::Text => out.write_all(document.text.as_bytes())?,
        ArticleFormat::Markdown => out.write_all(document.markdown.as_bytes())?,
        ArticleFormat::Html => out.write_all(document.html.as_bytes())?,
        ArticleFormat::Csv => {
            if standalone {
                out.write_all(b"title,source_url,text,comments\n")?;
            }
            for (index, value) in [title, source, &document.text, &document.comments]
                .into_iter()
                .enumerate()
            {
                if index > 0 {
                    out.write_all(b",")?;
                }
                csv_field(out, value)?;
            }
        }
        ArticleFormat::Xml | ArticleFormat::Tei => {
            let tei = format == ArticleFormat::Tei;
            if standalone {
                out.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
            }
            out.write_all(if tei {
                b"<TEI xmlns=\"http://www.tei-c.org/ns/1.0\"><teiHeader><fileDesc><titleStmt><title>"
            } else {
                b"<article version=\"1\"><title>"
            })?;
            xml_text(out, title)?;
            out.write_all(if tei { b"</title></titleStmt><publicationStmt><p>Native offline extraction</p></publicationStmt><sourceDesc><p>" } else { b"</title><source>" })?;
            xml_text(out, source)?;
            out.write_all(if tei {
                b"</p></sourceDesc></fileDesc></teiHeader><text><body><div type=\"main\"><p>"
            } else {
                b"</source><main>"
            })?;
            xml_text(out, &document.text)?;
            out.write_all(if tei {
                b"</p></div><div type=\"comments\"><p>"
            } else {
                b"</main><comments>"
            })?;
            xml_text(out, &document.comments)?;
            out.write_all(if tei {
                b"</p></div></body></text></TEI>"
            } else {
                b"</comments></article>"
            })?;
        }
    }
    Ok(())
}

/// Incremental collection writer. Call `finish` even when individual inputs fail.
///
/// JSON uses a single array of `{source,document}` records; JSONL uses one such
/// object per line. CSV has one header. XML/TEI/HTML have one collection root.
/// Text and Markdown use byte-length framing, so article content cannot spoof
/// record separators. Source identifiers are caller-approved content.
#[must_use = "finish the article stream to close its collection"]
pub struct ArticleStream<'a> {
    out: &'a mut dyn std::io::Write,
    format: ArticleFormat,
    count: u64,
}

impl<'a> ArticleStream<'a> {
    /// Begin a collection without buffering its documents.
    ///
    /// # Errors
    /// Returns errors from the output sink.
    pub fn begin(out: &'a mut dyn std::io::Write, format: ArticleFormat) -> Result<Self, ArticleWriteError> {
        match format {
            ArticleFormat::Json => out.write_all(b"[\n")?,
            ArticleFormat::Csv => out.write_all(b"source,title,source_url,text,comments\r\n")?,
            ArticleFormat::Xml => out.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<articles version=\"1\">\n")?,
            ArticleFormat::Tei => out.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<teiCorpus xmlns=\"http://www.tei-c.org/ns/1.0\"><teiHeader><fileDesc><titleStmt><title>Offline article collection</title></titleStmt><publicationStmt><p>Native offline extraction</p></publicationStmt><sourceDesc><p>Operator-selected local source tree</p></sourceDesc></fileDesc></teiHeader>\n")?,
            ArticleFormat::Html => out.write_all(b"<!doctype html><html><head><meta charset=\"utf-8\"><title>Offline article collection</title></head><body>\n")?,
            ArticleFormat::Jsonl | ArticleFormat::Text | ArticleFormat::Markdown => {}
        }
        Ok(Self {
            out,
            format,
            count: 0,
        })
    }

    /// Append one finalized approved document.
    ///
    /// # Errors
    /// Returns serialization, invalid final chunk-source or sink errors, including partial writes.
    pub fn push(&mut self, source: &str, document: &crate::Document) -> Result<(), ArticleWriteError> {
        validate_article_chunks(document)?;
        if matches!(self.format, ArticleFormat::Xml | ArticleFormat::Tei) {
            validate_article_scalars(document)?;
        }
        if matches!(self.format, ArticleFormat::Xml | ArticleFormat::Html) && !valid_xml_scalars(source) {
            return Err(ArticleWriteError::InvalidXmlScalar);
        }
        match self.format {
            ArticleFormat::Json | ArticleFormat::Jsonl => {
                if self.format == ArticleFormat::Json && self.count != 0 {
                    self.out.write_all(b",\n")?;
                }
                self.out.write_all(b"{\"source\":")?;
                serde_json::to_writer(&mut *self.out, source)?;
                self.out.write_all(b",\"document\":")?;
                write_article_body(self.out, document, ArticleFormat::Json, false)?;
                self.out.write_all(b"}")?;
                if self.format == ArticleFormat::Jsonl {
                    self.out.write_all(b"\n")?;
                }
            }
            ArticleFormat::Csv => {
                csv_field(self.out, source)?;
                self.out.write_all(b",")?;
                write_article_body(self.out, document, self.format, false)?;
                self.out.write_all(b"\r\n")?;
            }
            ArticleFormat::Xml => {
                self.out.write_all(b"<entry source=\"")?;
                xml_text(self.out, source)?;
                self.out.write_all(b"\">")?;
                write_article_body(self.out, document, self.format, false)?;
                self.out.write_all(b"</entry>\n")?;
            }
            ArticleFormat::Tei => {
                write_article_body(self.out, document, self.format, false)?;
                self.out.write_all(b"\n")?;
            }
            ArticleFormat::Html => {
                self.out.write_all(b"<section data-source=\"")?;
                xml_text(self.out, source)?;
                self.out.write_all(b"\">")?;
                write_article_body(self.out, document, self.format, false)?;
                self.out.write_all(b"</section>\n")?;
            }
            ArticleFormat::Text | ArticleFormat::Markdown => {
                let content = if self.format == ArticleFormat::Text {
                    &document.text
                } else {
                    &document.markdown
                };
                write!(self.out, "\u{1e}{} ", content.len())?;
                serde_json::to_writer(&mut *self.out, source)?;
                self.out.write_all(b"\n")?;
                self.out.write_all(content.as_bytes())?;
                self.out.write_all(b"\n")?;
            }
        }
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Close the collection and flush the sink.
    ///
    /// # Errors
    /// Returns sink write or flush failures.
    pub fn finish(self) -> Result<(), ArticleWriteError> {
        if self.format == ArticleFormat::Tei && self.count == 0 {
            return Err(std::io::Error::other("TEI corpus requires at least one accepted document").into());
        }
        match self.format {
            ArticleFormat::Json => self.out.write_all(b"\n]\n")?,
            ArticleFormat::Xml => self.out.write_all(b"</articles>\n")?,
            ArticleFormat::Tei => self.out.write_all(b"</teiCorpus>\n")?,
            ArticleFormat::Html => self.out.write_all(b"</body></html>\n")?,
            _ => {}
        }
        self.out.flush()?;
        Ok(())
    }
}

/// Version-one serializers for approved generic JSON-object items, not article envelopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ItemFormat {
    /// One JSON object.
    Json,
    /// One compact newline-delimited JSON object.
    Jsonl,
    /// Sorted field names and a spreadsheet-safe CSV row.
    Csv,
    /// Typed escaped XML preserving object/array/scalar distinctions.
    Xml,
}

fn item_xml(out: &mut dyn std::io::Write, value: &serde_json::Value, depth: u16) -> std::io::Result<()> {
    if depth > 32 {
        return Err(std::io::Error::other("item XML depth limit"));
    }
    match value {
        serde_json::Value::Object(fields) => {
            out.write_all(b"<object>")?;
            let mut fields: Vec<_> = fields.iter().collect();
            fields.sort_unstable_by_key(|(name, _)| *name);
            for (name, value) in fields {
                out.write_all(b"<field name=\"")?;
                xml_text(out, name)?;
                out.write_all(b"\">")?;
                item_xml(out, value, depth.saturating_add(1))?;
                out.write_all(b"</field>")?;
            }
            out.write_all(b"</object>")
        }
        serde_json::Value::Array(items) => {
            out.write_all(b"<array>")?;
            for item in items {
                out.write_all(b"<entry>")?;
                item_xml(out, item, depth.saturating_add(1))?;
                out.write_all(b"</entry>")?;
            }
            out.write_all(b"</array>")
        }
        serde_json::Value::String(value) => {
            out.write_all(b"<string>")?;
            xml_text(out, value)?;
            out.write_all(b"</string>")
        }
        serde_json::Value::Number(value) => write!(out, "<number>{value}</number>"),
        serde_json::Value::Bool(value) => write!(out, "<boolean>{value}</boolean>"),
        serde_json::Value::Null => out.write_all(b"<null/>"),
    }
}

struct CsvJson<'a>(&'a mut dyn std::io::Write);
impl std::io::Write for CsvJson<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut start = 0;
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'"' {
                self.0.write_all(&bytes[start..=index])?;
                self.0.write_all(b"\"")?;
                start = index.saturating_add(1);
            }
        }
        self.0.write_all(&bytes[start..])?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Stream an approved generic item with bounded depth and deterministic field order.
///
/// Nested CSV cells contain quoted JSON values; XML uses typed elements rather than
/// treating target-controlled keys as element names. TEI is deliberately article-only.
///
/// # Errors
/// Returns output/JSON errors or a non-object, field-count or nesting bound violation.
pub fn write_item(
    out: &mut dyn std::io::Write,
    item: &serde_json::Value,
    format: ItemFormat,
) -> Result<(), ArticleWriteError> {
    let fields = item
        .as_object()
        .ok_or_else(|| std::io::Error::other("item serializer requires an object"))?;
    if fields.len() > 256 {
        return Err(std::io::Error::other("item serializer field limit").into());
    }
    let mut nodes = 0;
    validate_item(item, 0, &mut nodes, matches!(format, ItemFormat::Xml))?;
    let mut bounded = ItemOutput {
        out,
        remaining: 16 * 1024 * 1024,
    };
    let out: &mut dyn std::io::Write = &mut bounded;
    match format {
        ItemFormat::Json | ItemFormat::Jsonl => serde_json::to_writer(&mut *out, item)?,
        ItemFormat::Csv => {
            let mut fields: Vec<_> = fields.iter().collect();
            fields.sort_unstable_by_key(|(name, _)| *name);
            for (index, (name, _)) in fields.iter().enumerate() {
                if index > 0 {
                    out.write_all(b",")?;
                }
                csv_field(out, name)?;
            }
            out.write_all(b"\n")?;
            for (index, (_, value)) in fields.iter().enumerate() {
                if index > 0 {
                    out.write_all(b",")?;
                }
                if let serde_json::Value::String(value) = value {
                    csv_field(out, value)?;
                } else {
                    out.write_all(b"\"")?;
                    serde_json::to_writer(CsvJson(&mut *out), value)?;
                    out.write_all(b"\"")?;
                }
            }
        }
        ItemFormat::Xml => {
            out.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<item version=\"1\">")?;
            item_xml(out, item, 0)?;
            out.write_all(b"</item>")?;
        }
    }
    out.write_all(b"\n")?;
    Ok(())
}

fn validate_item(
    value: &serde_json::Value,
    depth: u8,
    nodes: &mut u32,
    xml: bool,
) -> Result<(), ArticleWriteError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("item node limit"))?;
    if depth > 32 || *nodes > 100_000 {
        return Err(std::io::Error::other("item structural limit").into());
    }
    match value {
        serde_json::Value::Object(fields) => {
            if fields.len() > 256 {
                return Err(std::io::Error::other("item field limit").into());
            }
            for (name, value) in fields {
                if name.len() > 16 * 1024 * 1024 {
                    return Err(std::io::Error::other("item key byte limit").into());
                }
                if xml && !valid_xml_scalars(name) {
                    return Err(ArticleWriteError::InvalidXmlScalar);
                }
                validate_item(value, depth.saturating_add(1), nodes, xml)?;
            }
        }
        serde_json::Value::Array(items) => {
            if items.len() > 100_000 {
                return Err(std::io::Error::other("item array limit").into());
            }
            for value in items {
                validate_item(value, depth.saturating_add(1), nodes, xml)?;
            }
        }
        serde_json::Value::String(value) => {
            if value.len() > 16 * 1024 * 1024 {
                return Err(std::io::Error::other("item string limit").into());
            }
            if xml && !valid_xml_scalars(value) {
                return Err(ArticleWriteError::InvalidXmlScalar);
            }
        }
        _ => {}
    }
    Ok(())
}

struct ItemOutput<'a> {
    out: &'a mut dyn std::io::Write,
    remaining: usize,
}
impl std::io::Write for ItemOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("item output byte limit"))?;
        self.out.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}
