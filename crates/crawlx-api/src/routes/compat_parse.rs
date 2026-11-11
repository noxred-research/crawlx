//! compat v2 `parse` endpoints of the compat facade: `POST /parse` converts an
//! uploaded file (`multipart/form-data`: `file` + an `options` JSON part) into Markdown, HTML,
//! text, links, images and metadata with [`crawlx_extract::pipeline`], and `GET /parse/formats` lists
//! what it accepts.
//!
//! | `options` | behaviour |
//! |---|---|
//! | `formats` | `markdown` (default), `html`, `rawHtml`, `links`, `images`, `text` (crawlx extension) natively; `summary`, `json`, `question`, `highlights` through the configured LLM (`503 llm_not_configured` without one) |
//! | `onlyMainContent`, `includeTags`, `excludeTags` | HTML input only; set on another format they are answered with a warning |
//! | `parsers` | PDF `maxPages`, `pages` (per-page markdown), `blocks` (layout blocks), `pageMarkers`, `mode`; `parsers: []` returns the PDF as `rawBase64` |
//! | `removeBase64Images` | default `true`: inline base64 images leave `markdown` and `html` |
//! | `redactPII` | deterministic redaction of `markdown`, `text`, pages, blocks and of what the LLM sees |
//! | `checkPromptInjection` | scans the content before an LLM format runs, `403 SCRAPE_PROMPT_INJECTION_DETECTED` |
//! | `timeout` | milliseconds for the whole request, `408 SCRAPE_TIMEOUT` |
//! | `zeroDataRetention` | the upload is never stored; billed one extra credit |
//! | `headers`, `skipTlsVerification`, `blockAds`, `proxy` | an upload makes no network requests: answered with a warning |
//!
//! Credits: one per parsed PDF page, one per other document, four per `json`, `question` and
//! `highlights` format, four when the injection check ran, one for zero data retention. Failures:
//! `400 BAD_REQUEST` (bad multipart or options), `413 payload_too_large`, `415
//! unsupported_content_type`, `422` `corrupt_document` / `document_encrypted` / `no_text_layer`.

mod options;

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::common::{llm, llm_error};
use crate::intel::usage::{self, Cost};
use crate::openapi::Operation;
use crate::resources::Warning;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::json_response;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use base64::Engine as _;
use bytes::Bytes;
use crawlx_core::extraction::{ParserPipelineV1, PipelineRouteV1};
use crawlx_core::parser_memory::{self, Budgeted, BytePermit};
use crawlx_extract::base64_images::strip_base64_images;
use crawlx_extract::isolated::IsolatedError;
use crawlx_extract::parse::injection;
use crawlx_extract::parse::ocr::PdfOcr;
use crawlx_extract::parse::redact::redact;
use crawlx_extract::parse::{
    detect_format, supported_formats_with, ParseError, ParseFormat, ParseLimits, ParseOptions, ParsedDocument,
};
use crawlx_extract::pipeline::{ParserPipeline, PipelineContent, PipelineError, PipelineInput};
use crawlx_model::llm::TokenUsage;
use crawlx_worker::isolated_parser::{self, UploadRequest};
use crawlx_worker::CpuPool;
use futures::StreamExt;
use options::{parse_options, ParseRequest, PdfMode};
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tokio_util::sync::CancellationToken;

/// Bytes of a multipart body beyond the file: boundaries, part headers and the options part.
const MULTIPART_OVERHEAD: usize = 1024 * 1024;
/// Most parts of one upload.
const MAX_PARTS: usize = 16;
/// Longest accepted file name.
const MAX_FILENAME_CHARS: usize = 255;
/// Extra credits of the LLM formats `json`, `question` and `highlights`, and of the injection check.
const LLM_EXTRA_CREDITS: u64 = 4;
/// Longest content (bytes) the injection scanner reads; beyond it the check is incomplete.
const MAX_INJECTION_SCAN_BYTES: usize = 8 * 1024 * 1024;
/// Smallest capacity reserved for an upload buffer.
const MIN_UPLOAD_RESERVE: usize = 64 * 1024;

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "post",
        "/compat/v2/parse",
        "compatParse",
        "compat v2 parse: upload a file (multipart/form-data) and convert it to Markdown, HTML, text, links and metadata",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/parse/formats",
        "compatParseFormats",
        "compat v2 parse: the file formats /parse accepts",
        "crawls:read",
        "200",
    ),
];

/// Routes of this module, mounted under `/compat/v2` behind authentication.
///
/// The upload route lifts axum's 2 MiB default body limit: [`read_upload`] enforces
/// `Settings::parse_limits` itself while it streams the body.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/v2/parse", post(parse).layer(DefaultBodyLimit::disable()))
        .route("/compat/v2/parse/formats", get(formats))
}

/// `GET /compat/v2/parse/formats`: `{success, data:{formats:[{format, kind,
/// extensions, mimeTypes, available}]}}`, cacheable for an hour.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`.
pub async fn formats(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let mut resp = json_response(
        StatusCode::OK,
        &json!({ "success": true, "data": { "formats": supported_formats_with(state.ocr.is_some()) } }),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=3600"),
    );
    Ok(resp)
}

// ---- upload --------------------------------------------------------------------------------

struct Upload {
    /// The file bytes and the reservation that covers them.
    file: Budgeted<Bytes>,
    filename: Option<String>,
    content_type: Option<String>,
    options: Option<Value>,
    extra_parts: Vec<String>,
}

fn bad_multipart(why: impl std::fmt::Display) -> HttpError {
    HttpError::compat(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        format!("Invalid multipart form-data request: {why}"),
    )
}

/// The request body, failing once it carries more than `cap` bytes; `exceeded` records it.
fn capped_body(body: Body, cap: usize, exceeded: Arc<AtomicBool>) -> Body {
    let mut seen = 0usize;
    Body::from_stream(body.into_data_stream().map(move |chunk| match chunk {
        Ok(bytes) => {
            seen = seen.saturating_add(bytes.len());
            if seen > cap {
                exceeded.store(true, Ordering::Relaxed);
                Err(std::io::Error::other("request body is too large"))
            } else {
                Ok(bytes)
            }
        }
        Err(e) => Err(std::io::Error::other(e)),
    }))
}

/// A file name without directories or control characters, `None` when nothing is left.
fn clean_filename(raw: &str) -> Option<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FILENAME_CHARS)
        .collect();
    let cleaned = cleaned.trim().to_owned();
    (!cleaned.is_empty()).then_some(cleaned)
}

async fn read_upload(state: &AppState, req: Request) -> ApiResult<Upload> {
    let file_cap = state.settings.parse_limits.max_input_bytes;
    let options_cap = state.settings.max_body_bytes;
    let body_cap = file_cap
        .saturating_add(options_cap)
        .saturating_add(MULTIPART_OVERHEAD);
    let too_large = |cap: usize| HttpError::payload_too_large(cap);
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > body_cap) {
        return Err(too_large(file_cap));
    }
    let exceeded = Arc::new(AtomicBool::new(false));
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(parts, capped_body(body, body_cap, exceeded.clone()));
    let mut mp = Multipart::from_request(req, state)
        .await
        .map_err(|e| bad_multipart(e.body_text()))?;
    let failed = |e: axum::extract::multipart::MultipartError| {
        if exceeded.load(Ordering::Relaxed) {
            too_large(file_cap)
        } else {
            bad_multipart(e.body_text())
        }
    };

    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut options: Option<Value> = None;
    let mut extra_parts: Vec<String> = Vec::new();
    let mut file: Option<(Vec<u8>, BytePermit)> = None;
    let mut count = 0usize;
    while let Some(mut field) = mp.next_field().await.map_err(failed)? {
        count += 1;
        if count > MAX_PARTS {
            return Err(bad_multipart(format!("more than {MAX_PARTS} parts")));
        }
        let name = field.name().unwrap_or("").to_owned();
        match name.as_str() {
            "file" => {
                if file.is_some() {
                    return Err(bad_multipart("the `file` part is sent twice"));
                }
                filename = field.file_name().and_then(clean_filename);
                content_type = field.content_type().map(str::to_owned);
                let mut buf: Vec<u8> = Vec::new();
                let mut permit = parser_memory::global()
                    .try_reserve(0)
                    .map_err(|refused| memory_refused(refused.exceeds_budget()))?;
                while let Some(chunk) = field.chunk().await.map_err(failed)? {
                    if buf.len().saturating_add(chunk.len()) > file_cap {
                        return Err(too_large(file_cap));
                    }
                    grow_upload(&mut buf, &mut permit, chunk.len(), file_cap)?;
                    buf.extend_from_slice(&chunk);
                }
                file = Some((buf, permit));
            }
            "options" => {
                let mut raw: Vec<u8> = Vec::new();
                while let Some(chunk) = field.chunk().await.map_err(failed)? {
                    if raw.len().saturating_add(chunk.len()) > options_cap {
                        return Err(too_large(options_cap));
                    }
                    raw.extend_from_slice(&chunk);
                }
                if options.is_some() {
                    return Err(bad_multipart("the `options` part is sent twice"));
                }
                let value: Value = if raw.iter().all(u8::is_ascii_whitespace) {
                    Value::Null
                } else {
                    serde_json::from_slice(&raw).map_err(|e| {
                        HttpError::bad_request(vec![Detail::new(
                            "/options",
                            "invalid_json",
                            format!("the `options` part is not valid JSON: {e}"),
                        )])
                    })?
                };
                options = Some(value);
            }
            _ => {
                while field.chunk().await.map_err(failed)?.is_some() {}
                extra_parts.push(name);
            }
        }
    }
    // `Bytes::from(Vec)` keeps the allocation, so the reservation made while reading covers it.
    let Some((buf, permit)) = file else {
        return Err(HttpError::bad_request(vec![Detail::new(
            "/file",
            "required",
            "the multipart body needs a `file` part",
        )]));
    };
    if buf.is_empty() {
        return Err(HttpError::bad_request(vec![Detail::new(
            "/file",
            "required",
            "the uploaded file is empty",
        )]));
    }
    Ok(Upload {
        file: Budgeted::new(Bytes::from(buf), permit),
        filename,
        content_type,
        options,
        extra_parts,
    })
}

// ---- parse ---------------------------------------------------------------------------------

/// The outcome of the blocking stage.
enum Parsed {
    Document(Box<ParsedDocument>),
    RawPdf { base64: String },
}

fn parse_error(e: ParseError, req: &ParseRequest) -> HttpError {
    match e {
        ParseError::UnsupportedFormat { detail } => HttpError::compat(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_type",
            format!(
                "unsupported file type: {detail}; GET /compat/v2/parse/formats lists the supported formats"
            ),
        ),
        e @ ParseError::TooLarge { .. } => {
            HttpError::compat(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", e.to_string())
        }
        e @ ParseError::Encrypted { .. } => HttpError::compat(
            StatusCode::UNPROCESSABLE_ENTITY,
            "document_encrypted",
            format!("{e}; remove the password protection and upload it again"),
        ),
        ParseError::NoText { .. } => HttpError::compat(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no_text_layer",
            "the PDF has no text layer; parsers[].mode `fast` does not run OCR (mode `auto` or `ocr` reads scanned pages when the server has an OCR engine)",
        ),
        e @ ParseError::Ocr(_) => {
            let cause = std::error::Error::source(&e).map_or_else(|| e.to_string(), ToString::to_string);
            tracing::error!(error = %cause, "the OCR engine failed on an upload");
            HttpError::compat(
                StatusCode::UNPROCESSABLE_ENTITY,
                "ocr_failed",
                format!("the OCR engine could not read the file: {cause}"),
            )
        }
        ParseError::InvalidSelector { selector, reason } => {
            let path = if req.include_tags.contains(&selector) {
                "/includeTags"
            } else {
                "/excludeTags"
            };
            HttpError::bad_request(vec![Detail::new(
                path,
                "invalid_selector",
                format!("`{selector}` is not a valid CSS selector: {reason}"),
            )])
        }
        ParseError::ParseMemory(refused) => memory_refused(refused.exceeds_budget()),
        ParseError::ResourceExhausted { detail, .. } => match detail.as_str() {
            "size bound exceeded" | "helper terminated by resource limit" => HttpError::compat(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "the document exceeds a parser resource limit",
            ),
            "deadline exceeded" => timed_out(),
            _ => memory_refused(false),
        },
        ParseError::Isolated(source) => {
            tracing::error!(error = %source, "the isolated parser failed on an upload");
            HttpError::compat(
                StatusCode::UNPROCESSABLE_ENTITY,
                "corrupt_document",
                "the document cannot be parsed",
            )
        }
        ParseError::Internal { format } => {
            tracing::error!(format, "a document parser failed on an upload");
            HttpError::compat(
                StatusCode::UNPROCESSABLE_ENTITY,
                "corrupt_document",
                format!("the {format} document cannot be parsed"),
            )
        }
        other => HttpError::compat(
            StatusCode::UNPROCESSABLE_ENTITY,
            "corrupt_document",
            other.to_string(),
        ),
    }
}

fn pipeline_error(error: PipelineError, request: &ParseRequest) -> HttpError {
    match error {
        PipelineError::Detect(error) | PipelineError::Parse(error) => parse_error(error, request),
        error @ PipelineError::Limit { .. } => HttpError::compat(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            error.to_string(),
        ),
        error => {
            tracing::error!(error = %error, "the upload parser pipeline failed");
            HttpError::internal()
        }
    }
}

fn timed_out() -> HttpError {
    HttpError::compat(StatusCode::REQUEST_TIMEOUT, "SCRAPE_TIMEOUT", "Scrape timed out")
}

/// `413 payload_too_large` when a reservation exceeds the whole parser memory budget (terminal),
/// `503` with `Retry-After` when it only does not fit right now (transient).
fn memory_refused(exceeds_budget: bool) -> HttpError {
    if exceeds_budget {
        HttpError::compat(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "the document is larger than the parser memory budget",
        )
    } else {
        HttpError::backend_unavailable(
            "parser_memory_unavailable",
            "parser memory is in use by other requests; retry shortly",
        )
    }
}

/// The HTTP error of a failed isolated HTML parse.
fn isolated_error(error: IsolatedError, request: &ParseRequest) -> HttpError {
    match error {
        // Only here is it known whether the reservation could ever fit.
        IsolatedError::Admission(refused) => memory_refused(refused.exceeds_budget()),
        // Cancellation fires only when the request deadline passed.
        IsolatedError::Cancelled => timed_out(),
        other => parse_error(other.into_parse_error(), request),
    }
}

/// Where the isolated upload parser runs its CPU work: one pool for the process.
fn cpu() -> &'static CpuPool {
    static CPU: LazyLock<CpuPool> = LazyLock::new(CpuPool::default);
    &CPU
}

/// Grow `buf` by `extra` bytes, reserving the new capacity from the shared parser budget first.
/// Capacity at least doubles so the number of reservations stays logarithmic.
fn grow_upload(buf: &mut Vec<u8>, permit: &mut BytePermit, extra: usize, cap: usize) -> ApiResult<()> {
    let needed = buf.len().saturating_add(extra);
    if needed <= buf.capacity() {
        return Ok(());
    }
    let target = needed
        .max(buf.capacity().saturating_mul(2))
        .max(MIN_UPLOAD_RESERVE)
        .min(cap.max(needed));
    permit
        .grow_to(target)
        .map_err(|refused| memory_refused(refused.exceeds_budget()))?;
    buf.try_reserve_exact(target - buf.len()).map_err(|error| {
        tracing::warn!(error = %error, bytes = target, "the upload buffer could not be allocated");
        memory_refused(false)
    })
}

fn parse_blocking(
    bytes: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
    opts: &ParseOptions,
    raw_pdf: bool,
) -> Result<Parsed, PipelineError> {
    if raw_pdf {
        let format =
            detect_format(bytes, filename, content_type, &opts.limits).map_err(PipelineError::Detect)?;
        if format == ParseFormat::Pdf {
            return Ok(Parsed::RawPdf {
                base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            });
        }
    }
    let mut spec = ParserPipelineV1::for_uploads();
    // The document parser retains the existing typed OCR refusal when no engine is configured.
    for format in ["png", "jpeg", "gif", "webp", "bmp", "tiff"] {
        spec.routes.insert(format.to_owned(), PipelineRouteV1::Document);
    }
    let pipeline = ParserPipeline::new(spec)?;
    let mut input = PipelineInput::new(bytes).with_document_options(opts);
    if let Some(filename) = filename {
        input = input.with_filename(filename);
    }
    if let Some(content_type) = content_type {
        input = input.with_content_type(content_type);
    }
    let output = pipeline.run(input)?;
    match output.content {
        PipelineContent::Document(mut document) => {
            // Parser findings live on the pipeline report; the upload renderer reads the document.
            document.warnings = output.warnings;
            Ok(Parsed::Document(document))
        }
        _ => Err(PipelineError::Parse(ParseError::Internal { format: "upload" })),
    }
}

// ---- post-processing -----------------------------------------------------------------------

/// What the PII and base64 passes did to the document.
struct Cleaner<'a> {
    req: &'a ParseRequest,
    unsupported: Vec<&'static str>,
}

impl Cleaner<'_> {
    /// Text that is redacted when `redactPII` is set.
    fn pii(&mut self, text: &str) -> String {
        let Some(opts) = &self.req.redact else {
            return text.to_owned();
        };
        let r = redact(text, opts);
        for e in r.unsupported {
            let n = e.name();
            if !self.unsupported.contains(&n) {
                self.unsupported.push(n);
            }
        }
        r.text
    }

    /// Markdown as returned: base64 images stripped, PII redacted.
    fn markdown(&mut self, md: &str) -> String {
        let stripped = if self.req.remove_base64_images {
            strip_base64_images(md).into_owned()
        } else {
            md.to_owned()
        };
        self.pii(&stripped)
    }
}

fn metadata_of(doc: &ParsedDocument, filename: &str) -> Value {
    let mut m: Map<String, Value> = doc.metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Some(t) = &doc.title {
        m.entry("title".to_owned())
            .or_insert_with(|| Value::String(t.clone()));
    }
    m.insert("sourceURL".to_owned(), json!(filename));
    m.insert("sourceFile".to_owned(), json!(filename));
    m.insert("statusCode".to_owned(), json!(200));
    m.insert("contentType".to_owned(), json!(doc.content_type));
    if let Some(n) = doc.num_pages {
        m.insert("numPages".to_owned(), json!(n));
    }
    if let Some(n) = doc.total_pages {
        m.insert("totalPages".to_owned(), json!(n));
    }
    Value::Object(m)
}

/// The LLM-backed formats over `input`; returns the fields for `data` and the tokens spent.
async fn llm_formats(
    state: &AppState,
    req: &ParseRequest,
    input: &str,
) -> ApiResult<(Map<String, Value>, TokenUsage)> {
    let llm = llm(state)?;
    let mut out = Map::new();
    let mut tokens = TokenUsage::default();
    let f = &req.formats;
    if f.summary {
        let c = llm.summary(input).await.map_err(|e| llm_error(&e))?;
        tokens.add(c.usage);
        out.insert("summary".to_owned(), Value::String(c.value));
    }
    if let Some(j) = &f.json {
        let c = llm
            .json(input, j.schema.as_ref(), j.prompt.as_deref())
            .await
            .map_err(|e| llm_error(&e))?;
        tokens.add(c.usage);
        out.insert("json".to_owned(), c.value);
    }
    if let Some(q) = &f.question {
        let c = llm.answer(input, q).await.map_err(|e| llm_error(&e))?;
        tokens.add(c.usage);
        out.insert("answer".to_owned(), Value::String(c.value));
    }
    if let Some(q) = &f.highlights {
        let c = llm.highlights(input, q).await.map_err(|e| llm_error(&e))?;
        tokens.add(c.usage);
        // The compat API documents `highlights` as one string of selected source text
        out.insert("highlights".to_owned(), Value::String(c.value.join("\n\n")));
    }
    Ok((out, tokens))
}

fn injection_blocked(rule: &str) -> HttpError {
    HttpError::compat(
        StatusCode::FORBIDDEN,
        "SCRAPE_PROMPT_INJECTION_DETECTED",
        format!("The document contains a prompt injection attempt ({rule}); the LLM formats were not run"),
    )
}

/// `POST /compat/v2/parse`: see the module docs.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`; `400 BAD_REQUEST` for a body that is not
/// multipart, a missing or empty `file`, or invalid `options`; `413 payload_too_large` above
/// `Settings::parse_limits` (also for a zip bomb); `415 unsupported_content_type`; `422`
/// `corrupt_document`, `document_encrypted` or `no_text_layer`; `503 llm_not_configured` when an
/// LLM format is requested without a configured LLM; `403 SCRAPE_PROMPT_INJECTION_DETECTED`;
/// `408 SCRAPE_TIMEOUT` after `timeout`; the LLM failures of [`llm_error`].
pub async fn parse(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    req: Request,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let started = Instant::now();
    let upload = read_upload(&state, req).await?;
    let request = parse_options(upload.options.as_ref())?;
    if request.formats.needs_llm() {
        // fail before any parsing work when the answer could not be produced anyway
        llm(&state)?;
    }
    let limits: ParseLimits = state.settings.parse_limits;
    let mut opts = ParseOptions {
        limits,
        only_main_content: request.only_main_content,
        include_tags: request.include_tags.clone(),
        exclude_tags: request.exclude_tags.clone(),
        pdf_max_pages: request.pdf.max_pages,
        pdf_page_markers: request.pdf.page_markers,
        pdf_require_text: request.pdf.mode == PdfMode::Fast,
        pdf_layout: request.pdf.blocks,
        ocr: state.ocr.clone(),
        pdf_ocr: match request.pdf.mode {
            PdfMode::Fast => PdfOcr::Off,
            PdfMode::Auto => PdfOcr::Auto,
            PdfMode::Ocr => PdfOcr::Always,
        },
    };
    let filename = upload.filename.clone().unwrap_or_else(|| "upload".to_owned());
    let (file, name, ctype) = (upload.file, upload.filename.clone(), upload.content_type.clone());
    let raw_pdf = request.parsers_disabled;
    let deadline = tokio::time::Instant::from_std(started + request.timeout);
    let format = detect_format(file.value(), name.as_deref(), ctype.as_deref(), &opts.limits)
        .map_err(|e| parse_error(e, &request))?;
    // Cancelled when the deadline passes or the handler future is dropped; the parser then
    // releases its work without the request waiting for it.
    let cancel = CancellationToken::new();
    let _stop = cancel.clone().drop_guard();
    // The reservation of a parsed HTML document stays alive until the response is assembled.
    let (parsed, _document_hold) = if format == ParseFormat::Html {
        let parser = isolated_parser::shared().map_err(|error| {
            tracing::error!(error = %error, "the isolated upload parser is unavailable");
            HttpError::internal()
        })?;
        // OCR applies to PDFs and images only; a transient handle cannot cross the helper boundary.
        opts.ocr = None;
        opts.pdf_ocr = PdfOcr::Off;
        let mut upload_request = UploadRequest::new(name, ctype);
        upload_request.options = opts;
        let run = parser.parse_upload_html(cpu(), file, upload_request, &cancel);
        match tokio::time::timeout_at(deadline, run).await {
            Err(_) => {
                cancel.cancel();
                return Err(timed_out());
            }
            Ok(Err(e)) => return Err(isolated_error(e, &request)),
            Ok(Ok(upload)) => {
                let (document, hold) = upload.document.into_parts();
                (Parsed::Document(document), Some(hold))
            }
        }
    } else {
        // The closure owns the upload and its reservation until the parse has ended, also when
        // the request times out first.
        let blocking = tokio::task::spawn_blocking(move || {
            parse_blocking(file.value(), name.as_deref(), ctype.as_deref(), &opts, raw_pdf)
        });
        match tokio::time::timeout_at(deadline, blocking).await {
            Err(_) => return Err(timed_out()),
            Ok(Err(e)) => {
                tracing::error!(error = %e, "the parse task did not finish");
                return Err(HttpError::internal());
            }
            Ok(Ok(Err(e))) => return Err(pipeline_error(e, &request)),
            Ok(Ok(Ok(p))) => (p, None),
        }
    };

    let mut warnings: Vec<Warning> = request.warnings.clone();
    for part in &upload.extra_parts {
        warnings.push(Warning::new(
            "unsupported_option",
            &format!("/{part}"),
            "this multipart part is not part of /parse and was ignored",
        ));
    }
    let mut data = Map::new();
    let credits_base;
    let doc = match parsed {
        Parsed::RawPdf { base64 } => {
            credits_base = 1;
            warnings.push(Warning::new(
                "parsers_disabled",
                "/parsers",
                "parsers is empty: the PDF was not parsed and is returned as rawBase64",
            ));
            data.insert("rawBase64".to_owned(), Value::String(base64));
            data.insert(
                "metadata".to_owned(),
                json!({
                    "sourceURL": filename, "sourceFile": filename, "statusCode": 200,
                    "contentType": ParseFormat::Pdf.content_type(),
                }),
            );
            return finish(
                &state,
                &principal,
                data,
                warnings,
                credits_base,
                &request,
                TokenUsage::default(),
            )
            .await;
        }
        Parsed::Document(d) => *d,
    };
    credits_base = doc.credits();
    let is_html = doc.format == ParseFormat::Html;
    if !is_html {
        for (key, why) in [
            ("onlyMainContent", "it applies to HTML input"),
            ("includeTags", "it applies to HTML input"),
            ("excludeTags", "it applies to HTML input"),
        ] {
            if request.has(key) {
                warnings.push(Warning::new(
                    "option_not_applicable",
                    &format!("/{key}"),
                    format!("ignored for a {} file: {why}", doc.format.name()),
                ));
            }
        }
    }
    if doc.format != ParseFormat::Pdf && request.has("parsers") && !request.parsers_disabled {
        warnings.push(Warning::new(
            "option_not_applicable",
            "/parsers",
            format!(
                "the PDF parser options were ignored: the file is {}, not a PDF",
                doc.format.name()
            ),
        ));
    }
    if request.pdf.mode == PdfMode::Ocr && doc.format == ParseFormat::Pdf && state.ocr.is_none() {
        warnings.push(Warning::new(
            "ocr_unavailable",
            "/parsers",
            "mode `ocr` needs an OCR engine and this server has none (set ocr.backend); the text layer was used",
        ));
    }
    if is_html
        && request.has("removeBase64Images")
        && !request.remove_base64_images
        && doc.raw_html.contains(";base64,")
    {
        warnings.push(Warning::new(
            "option_not_applicable",
            "/removeBase64Images",
            "inline base64 images of an uploaded HTML file are not carried into markdown or html; rawHtml keeps them",
        ));
    }
    for w in &doc.warnings {
        warnings.push(Warning::new("parse_warning", "/file", w.clone()));
    }

    let mut cleaner = Cleaner {
        req: &request,
        unsupported: Vec::new(),
    };
    let markdown = cleaner.markdown(&doc.markdown);
    let f = &request.formats;
    if f.markdown {
        data.insert("markdown".to_owned(), Value::String(markdown.clone()));
    }
    if f.html {
        let html = if request.remove_base64_images {
            strip_base64_images(&doc.html).into_owned()
        } else {
            doc.html.clone()
        };
        data.insert("html".to_owned(), Value::String(html));
    }
    if f.raw_html {
        data.insert("rawHtml".to_owned(), Value::String(doc.raw_html.clone()));
    }
    if f.text {
        data.insert("text".to_owned(), Value::String(cleaner.pii(&doc.text)));
    }
    if f.links {
        data.insert("links".to_owned(), json!(doc.links));
    }
    if f.images {
        data.insert("images".to_owned(), json!(doc.images));
    }
    let changed = markdown != doc.markdown;
    if request.pdf.pages && doc.format == ParseFormat::Pdf {
        let pages: Vec<Value> = doc
            .pages
            .iter()
            .map(|p| json!({ "pageNumber": p.page_number, "markdown": cleaner.markdown(&p.markdown) }))
            .collect();
        data.insert("pages".to_owned(), Value::Array(pages));
    }
    if request.pdf.blocks && doc.format == ParseFormat::Pdf {
        let mut layout = doc.layout.clone();
        for page in &mut layout {
            for item in &mut page.items {
                if changed {
                    item.content = cleaner.markdown(&item.content);
                    item.markdown_span = None;
                }
            }
        }
        data.insert(
            "blocks".to_owned(),
            serde_json::to_value(&layout).unwrap_or(Value::Null),
        );
    }
    data.insert("metadata".to_owned(), metadata_of(&doc, &filename));

    // the LLM formats
    let mut credits = credits_base;
    let mut tokens = TokenUsage::default();
    if f.needs_llm() {
        if request.check_prompt_injection {
            let cut = markdown
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|i| *i <= MAX_INJECTION_SCAN_BYTES)
                .last()
                .unwrap_or(0);
            let complete = markdown.len() <= MAX_INJECTION_SCAN_BYTES;
            let scanned = if complete {
                markdown.as_str()
            } else {
                &markdown[..cut]
            };
            if let Some(found) = injection::scan(scanned) {
                usage::record(
                    &state,
                    principal.tenant,
                    "parse",
                    None,
                    "blocked",
                    Cost::credits(LLM_EXTRA_CREDITS),
                )
                .await;
                return Err(injection_blocked(found.rule));
            }
            if complete {
                credits = credits.saturating_add(LLM_EXTRA_CREDITS);
            } else {
                warnings.push(Warning::new(
                    "prompt_injection_check_incomplete",
                    "/checkPromptInjection",
                    "the document is too long to scan completely; the parse continued and the check is not billed",
                ));
            }
        }
        let llm_stage = llm_formats(&state, &request, &markdown);
        match tokio::time::timeout_at(deadline, llm_stage).await {
            Err(_) => {
                usage::record(
                    &state,
                    principal.tenant,
                    "parse",
                    None,
                    "failed",
                    Cost::credits(0),
                )
                .await;
                return Err(timed_out());
            }
            Ok(Err(e)) => {
                usage::record(
                    &state,
                    principal.tenant,
                    "parse",
                    None,
                    "failed",
                    Cost::credits(0),
                )
                .await;
                return Err(e);
            }
            Ok(Ok((fields, used))) => {
                data.extend(fields);
                tokens = used;
            }
        }
        credits = credits.saturating_add(f.surcharged().saturating_mul(LLM_EXTRA_CREDITS));
    } else if request.check_prompt_injection {
        warnings.push(Warning::new(
            "option_not_applicable",
            "/checkPromptInjection",
            "no LLM-backed format (summary, json, question, highlights) was requested; the check did not run",
        ));
    }
    if request.redact.is_some() {
        if !cleaner.unsupported.is_empty() {
            warnings.push(Warning::new(
                "redact_entity_unsupported",
                "/redactPII",
                format!(
                    "{} need a named-entity model, which this server does not run; they were not redacted",
                    cleaner.unsupported.join(" and ")
                ),
            ));
        }
        warnings.push(Warning::new(
            "redact_pii_scope",
            "/redactPII",
            "redactPII covers markdown, text, pages, blocks and the input of the LLM formats; html, rawHtml, links and metadata are returned as parsed",
        ));
    }
    finish(&state, &principal, data, warnings, credits, &request, tokens).await
}

/// Add the zero-data-retention credit, record the usage and render the response.
async fn finish(
    state: &AppState,
    principal: &Principal,
    mut data: Map<String, Value>,
    warnings: Vec<Warning>,
    mut credits: u64,
    request: &ParseRequest,
    tokens: TokenUsage,
) -> ApiResult<Response> {
    if request.zero_data_retention {
        credits = credits.saturating_add(1);
    }
    usage::record(
        state,
        principal.tenant,
        "parse",
        None,
        "completed",
        Cost { credits, tokens },
    )
    .await;
    data.insert("warnings".to_owned(), json!(warnings));
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "data": data }),
    ))
}
