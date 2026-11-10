//! `POST /parse` (multipart upload) and `GET /parse/formats`.

use super::common::{JsonObject, PdfPage, Warning};
use super::scrape::RedactPii;
use super::Spec;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde_json::Value;
use std::collections::BTreeMap;

// ---- request: the `options` part ------------------------------------------------------------

/// A format by name. `rawBase64`, `screenshot`, `attributes`, `changeTracking`, `branding`,
/// `product`, `menu`, `audio`, `video` and `query` are rejected on uploads.
#[derive(JsonSchema)]
pub(super) enum ParseFormatName {
    /// The document as Markdown (default).
    #[serde(rename = "markdown")]
    Markdown,
    /// Cleaned HTML.
    #[serde(rename = "html")]
    Html,
    /// The HTML the document was converted from.
    #[serde(rename = "rawHtml")]
    RawHtml,
    /// Plain text (a crawlx extension).
    #[serde(rename = "text")]
    Text,
    /// The links of the document.
    #[serde(rename = "links")]
    Links,
    /// The images of the document.
    #[serde(rename = "images")]
    Images,
    /// An LLM summary (needs the configured LLM).
    #[serde(rename = "summary")]
    Summary,
}

/// A format object `{type, ...}`.
#[derive(JsonSchema)]
#[serde(tag = "type")]
pub(super) enum ParseFormatObject {
    /// Markdown.
    #[serde(rename = "markdown")]
    Markdown {},
    /// Cleaned HTML.
    #[serde(rename = "html")]
    Html {},
    /// The HTML the document was converted from.
    #[serde(rename = "rawHtml")]
    RawHtml {},
    /// Plain text.
    #[serde(rename = "text")]
    Text {},
    /// Links.
    #[serde(rename = "links")]
    Links {},
    /// Images.
    #[serde(rename = "images")]
    Images {},
    /// An LLM summary.
    #[serde(rename = "summary")]
    Summary {},
    /// LLM extraction (needs `schema` or `prompt`).
    #[serde(rename = "json")]
    Json {
        /// JSON Schema of the answer.
        schema: Option<JsonObject>,
        /// Extraction instruction (at most 10000 characters).
        prompt: Option<String>,
        /// Scan the content for prompt injection before the LLM reads it.
        #[serde(rename = "checkPromptInjection")]
        check_prompt_injection: Option<bool>,
    },
    /// Answer a question about the document.
    #[serde(rename = "question")]
    Question {
        /// The question (at most 10000 characters).
        question: String,
    },
    /// Select the passages that match a query.
    #[serde(rename = "highlights")]
    Highlights {
        /// The query (at most 10000 characters).
        query: String,
    },
}

/// A `formats[]` entry.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum ParseFormatItem {
    /// A format by name.
    Name(ParseFormatName),
    /// A format with options.
    Object(ParseFormatObject),
}

/// The PDF parser mode.
#[derive(JsonSchema)]
pub(super) enum ParsePdfMode {
    /// Text layer only; fails when no page has one.
    #[serde(rename = "fast")]
    Fast,
    /// Text layer, OCR where a page needs it (reported: crawlx has no OCR engine).
    #[serde(rename = "auto")]
    Auto,
    /// OCR on every page (reported: crawlx has no OCR engine).
    #[serde(rename = "ocr")]
    Ocr,
}

/// A `parsers[]` entry. The only parser is `pdf`; an empty `parsers` list returns a PDF as
/// `rawBase64`.
#[derive(JsonSchema)]
pub(super) struct ParseParser {
    /// Always `pdf`.
    #[serde(rename = "type")]
    kind: String,
    /// Parsing mode.
    mode: Option<ParsePdfMode>,
    /// Most pages to parse (1 to 10000).
    #[serde(rename = "maxPages")]
    #[schemars(range(min = 1, max = 10000))]
    max_pages: Option<u32>,
    /// Return the Markdown of every page in `data.pages`.
    pages: Option<bool>,
    /// Return the layout blocks in `data.blocks`.
    blocks: Option<bool>,
    /// Mark page boundaries in the Markdown.
    #[serde(rename = "pageMarkers")]
    page_markers: Option<bool>,
}

/// Proxy tier (an upload makes no network requests; accepted with a warning).
#[derive(JsonSchema)]
pub(super) enum ParseProxy {
    /// Direct fetch.
    #[serde(rename = "basic")]
    Basic,
    /// Automatic tier.
    #[serde(rename = "auto")]
    Auto,
}

/// `auditMetadata`: accepted.
#[derive(JsonSchema)]
pub(super) struct ParseAuditMetadata {
    /// Required.
    username: String,
}

/// The `options` part of `POST /parse`. Keys outside this list are ignored and reported as
/// `unsupported_option` in `data.warnings`.
#[derive(JsonSchema)]
pub(super) struct ParseOptions {
    /// Output formats; default `["markdown"]`. At most 64.
    formats: Option<Vec<ParseFormatItem>>,
    /// HTML input only: keep the main content (default `true`).
    #[serde(rename = "onlyMainContent")]
    only_main_content: Option<bool>,
    /// HTML input only: CSS selectors of elements to keep (at most 64 of at most 512 characters).
    #[serde(rename = "includeTags")]
    include_tags: Option<Vec<String>>,
    /// HTML input only: CSS selectors of elements to drop (at most 64 of at most 512 characters).
    #[serde(rename = "excludeTags")]
    exclude_tags: Option<Vec<String>>,
    /// Accepted; an upload makes no network requests (warning `option_not_applicable`).
    headers: Option<BTreeMap<String, String>>,
    /// Milliseconds for the whole request (1 to 300000, default 30000); `408 SCRAPE_TIMEOUT` after.
    #[schemars(range(min = 1, max = 300000))]
    timeout: Option<u32>,
    /// PDF parsers; an empty list returns the PDF as `rawBase64`.
    parsers: Option<Vec<ParseParser>>,
    /// Accepted; an upload makes no network requests (warning `option_not_applicable`).
    #[serde(rename = "skipTlsVerification")]
    skip_tls_verification: Option<bool>,
    /// Drop inline base64 images from the Markdown and HTML (default `true`).
    #[serde(rename = "removeBase64Images")]
    remove_base64_images: Option<bool>,
    /// Accepted; an upload is not rendered in a browser (warning `option_not_applicable`).
    #[serde(rename = "blockAds")]
    block_ads: Option<bool>,
    /// Scan the content for prompt injection before an LLM format runs (`403
    /// SCRAPE_PROMPT_INJECTION_DETECTED` when found; billed 4 credits).
    #[serde(rename = "checkPromptInjection")]
    check_prompt_injection: Option<bool>,
    /// Redact personal data from the Markdown, text, pages, blocks and the LLM input.
    #[serde(rename = "redactPII")]
    redact_pii: Option<RedactPii>,
    /// Accepted; an upload makes no network requests (warning `option_not_applicable`).
    proxy: Option<ParseProxy>,
    /// SDK bookkeeping; accepted without effect.
    origin: Option<String>,
    /// SDK bookkeeping; accepted without effect.
    integration: Option<String>,
    /// Accepted without effect.
    #[serde(rename = "auditMetadata")]
    audit_metadata: Option<ParseAuditMetadata>,
    /// The upload is never stored; billed one extra credit.
    #[serde(rename = "zeroDataRetention")]
    zero_data_retention: Option<bool>,
}

/// The `options` multipart part: a JSON text that holds a [`ParseOptions`] object.
fn options_part(g: &mut SchemaGenerator) -> Schema {
    let options = g.subschema_for::<ParseOptions>();
    json_schema!({
        "type": "string",
        "contentMediaType": "application/json",
        "contentSchema": options,
        "description": "The parse options as a JSON text (see ParseOptions). An empty part reads as `{}`. Sent twice is `400`.",
    })
}

/// The `file` multipart part: the document bytes.
fn file_part(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "string",
        "format": "binary",
        "description": "The document (non-empty, at most the server's upload limit). Its type is detected from the bytes, the file name and the part's content type; `GET /parse/formats` lists the supported types. Sent twice is `400`.",
    })
}

/// `POST /parse` body (`multipart/form-data`). Other parts are ignored with an
/// `unsupported_option` warning; at most 16 parts.
#[derive(JsonSchema)]
pub(super) struct ParseUpload {
    /// The document to convert.
    #[schemars(schema_with = "file_part")]
    file: String,
    /// The options.
    #[serde(default)]
    #[schemars(schema_with = "options_part")]
    options: Option<String>,
}

// ---- responses -----------------------------------------------------------------------------

/// The `data` of a parse response: the requested formats, `metadata` and `warnings`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ParseData {
    /// `markdown` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    markdown: Option<String>,
    /// `html` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    /// `rawHtml` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_html: Option<String>,
    /// `text` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    /// `links` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,
    /// `images` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    images: Option<Vec<String>>,
    /// PDF `pages` parser option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pages: Option<Vec<PdfPage>>,
    /// PDF `blocks` parser option.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocks: Option<Value>,
    /// The PDF as base64 (`parsers: []`).
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_base64: Option<String>,
    /// `summary` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    /// `json` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    json: Option<Value>,
    /// `question` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<String>,
    /// `highlights` format, joined by blank lines.
    #[serde(skip_serializing_if = "Option::is_none")]
    highlights: Option<String>,
    /// Document metadata: `sourceURL`, `sourceFile`, `statusCode`, `contentType`, `numPages`,
    /// `totalPages` and the document's own properties.
    metadata: JsonObject,
    /// Options that were not applied and notes about the parse.
    warnings: Vec<Warning>,
}

/// `POST /parse` response.
#[derive(JsonSchema)]
pub(super) struct ParseResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The converted document.
    data: ParseData,
}

/// Whether a format is parsed or only recognised.
#[derive(JsonSchema)]
pub(super) enum FormatKind {
    /// Parsed to text.
    #[serde(rename = "document")]
    Document,
    /// Recognised, but needs OCR.
    #[serde(rename = "image")]
    Image,
}

/// One file format `/parse` knows.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ParseFormatInfo {
    /// Canonical extension without the dot.
    format: String,
    /// Document or image.
    kind: FormatKind,
    /// Accepted extensions, canonical first.
    extensions: Vec<String>,
    /// Accepted MIME types.
    mime_types: Vec<String>,
    /// Whether uploads of this format are accepted right now.
    available: bool,
}

/// The `data` of `GET /parse/formats`.
#[derive(JsonSchema)]
pub(super) struct ParseFormatsData {
    /// The formats.
    formats: Vec<ParseFormatInfo>,
}

/// `GET /parse/formats` response (cacheable for an hour).
#[derive(JsonSchema)]
pub(super) struct ParseFormatsResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The supported formats.
    data: ParseFormatsData,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "compatParse" => Spec::new(&[400, 408, 413, 415, 422, 502, 503, 504])
            .multipart::<ParseUpload>("A `file` part and an optional `options` part.")
            .reply::<ParseResponse>("200", "The converted document."),
        "compatParseFormats" => {
            Spec::new(&[]).reply::<ParseFormatsResponse>("200", "The supported file formats.")
        }
        _ => return None,
    };
    Some(s)
}
