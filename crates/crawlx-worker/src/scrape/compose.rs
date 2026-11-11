//! Turns one fetched or rendered body into the content of a document: markdown, cleaned HTML,
//! links, compatibility-API metadata and the pure formats (`images`, `attributes`).
//!
//! Everything here is synchronous and CPU-bound; the engine runs [`compose`] on the worker's
//! CPU pool.

use crate::scrape::{FailReason, ScrapeFailure};
use bytes::Bytes;
use crawlx_core::scrape::{AttributeResult, FormatSpec, ParserSpec, PdfMode, PdfPageMarkdown, ScrapeOptions};
use crawlx_core::{hash::Digest, StoreError};
use crawlx_extract::parse::ocr::{Ocr, PdfOcr};
use crawlx_extract::parse::{ParseLimits, ParseOptions};
use crawlx_extract::pipeline::{ParserPipeline, PipelineContent, PipelineInput};
use crawlx_extract::ExtractOptions;
use crawlx_extract::{base64_images, compat_meta, endpoints};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use url::Url;

/// Most pages of one PDF (the compatibility API's `maxPages` ceiling).
const MAX_PDF_PAGES: usize = 10_000;

/// What a body is, decided from its `Content-Type` and its first bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BodyKind {
    /// HTML (declared, undeclared, or a rendered DOM).
    Html,
    /// A PDF document.
    Pdf,
    /// JSON, XML, plain text, CSV and other textual bodies.
    Text,
    /// A raster image (PNG, JPEG, JPEG 2000, TIFF, GIF, BMP, WebP, AVIF): the `image` parser's.
    Image,
    /// Anything else.
    Binary,
}

/// The kind of a body. A rendered DOM is always HTML; a missing `Content-Type` means HTML (like
/// the static plane), except that a `%PDF-` signature wins.
pub(crate) fn classify(content_type: Option<&str>, body: &[u8], rendered: bool) -> BodyKind {
    if rendered {
        return BodyKind::Html;
    }
    let media = content_type
        .and_then(|c| c.split(';').next())
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty());
    match media.as_deref() {
        Some("application/pdf") => BodyKind::Pdf,
        None if body.starts_with(b"%PDF-") => BodyKind::Pdf,
        None => BodyKind::Html,
        Some(m) if m.contains("html") => BodyKind::Html,
        Some(m) if is_raster_image(m) => BodyKind::Image,
        Some(_) if endpoints::textual::is_textual(content_type, body) => BodyKind::Text,
        Some(_) => BodyKind::Binary,
    }
}

/// Raster image media types the compatibility API's `image` parser reads (SVG and HEIC are not among them).
fn is_raster_image(media: &str) -> bool {
    matches!(
        media,
        "image/png"
            | "image/jpeg"
            | "image/jpg"
            | "image/jp2"
            | "image/jpx"
            | "image/tiff"
            | "image/gif"
            | "image/bmp"
            | "image/webp"
            | "image/avif"
    )
}

/// Input of [`compose`].
pub(crate) struct ComposeInput {
    pub body: Bytes,
    pub base: Url,
    pub kind: BodyKind,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub options: Arc<ScrapeOptions>,
    pub extract: ExtractOptions,
    /// Reuse the document parsed by acquisition validation instead of parsing HTML twice.
    pub document: Option<Box<crawlx_extract::Document>>,
    /// Reviewed native pipeline; never source-language callbacks.
    pub extensions: crawlx_core::extensions::ExtensionPipelineV1,
    /// Explicit request label, distinct from discovery route templates.
    pub route_label: String,
    /// Shared run cancellation observed by bounded pure transforms.
    pub cancel: tokio_util::sync::CancellationToken,
    /// Trusted request secrets projected out before article quality/ranges/digests.
    pub controls: crawlx_core::request_controls::RequestControls,
    /// Actual run registry; native content policy refuses missing/poisoned state.
    pub captcha_secrets: Option<crawlx_core::captcha::CaptchaSecrets>,
    /// The worker's OCR engine (`WorkerConfig::ocr`).
    pub ocr: Option<Arc<Ocr>>,
}

/// The content of a document.
#[derive(Default)]
pub(crate) struct Composed {
    /// Markdown of the selected content (base64 images stripped when asked).
    pub markdown: Option<String>,
    /// Cleaned HTML of the selected content.
    pub html: Option<String>,
    /// Page title.
    pub title: Option<String>,
    /// Absolute links of the whole document.
    pub links: Vec<Url>,
    /// Compatibility-API `metadata` keys.
    pub meta: BTreeMap<String, serde_json::Value>,
    /// PDF pages parsed.
    pub num_pages: Option<u32>,
    /// PDF pages in the file.
    pub total_pages: Option<u32>,
    /// `images` format.
    pub images: Option<Vec<String>>,
    /// `attributes` format.
    pub attributes: Option<Vec<AttributeResult>>,
    /// Non-fatal findings.
    pub warning: Option<String>,
    /// `pages` parser option: the markdown of every parsed physical page.
    pub pages: Option<Vec<PdfPageMarkdown>>,
    /// `blocks` parser option: typed layout blocks per page.
    pub blocks: Option<serde_json::Value>,
    /// Shared extraction outputs, kept on the scrape content retention path.
    pub outputs: Option<serde_json::Value>,
    /// Parser-produced preview requests, never acquisition authority.
    pub previews: Vec<crawlx_core::extraction::PreviewIntentV1>,
    /// Trusted native envelope, boxed to keep nested async scrape frames bounded.
    article: Option<Box<crawlx_core::extraction::DocumentEnvelopeV1>>,
    /// Approved native schema, populated only by joint source verification on the CPU pool.
    verified_article: Option<serde_json::Value>,
    /// Generated retained cache reference, never page-authored metadata.
    pub article_cache: Option<crawlx_core::scrape::BlobRef>,
    /// Canonical selected text, moved once into the retention-typed article source sink.
    pub article_text: Option<String>,
    /// Separate comment source for comment byte ranges.
    pub article_comments: Option<String>,
}

impl Composed {
    /// Verify the native envelope on the same bounded CPU task that composed its sources.
    ///
    /// # Errors
    /// Rejects source, policy, schema or privacy mismatches without rewriting finalized content.
    pub(crate) fn verify_article(&mut self, input: &ComposeInput) -> Result<(), StoreError> {
        self.verified_article = verified_article(input, self)?;
        self.article = None;
        Ok(())
    }

    /// Move the verified native schema into storage without serializing or rescanning sources.
    pub(crate) fn take_verified_article(&mut self) -> Option<serde_json::Value> {
        self.verified_article.take()
    }
}

/// Verify the native envelope against its exact sources before exempting schema vocabulary
/// from late metadata treatment. Content is checked, never rewritten after finalization.
fn verified_article(
    input: &ComposeInput,
    composed: &Composed,
) -> Result<Option<serde_json::Value>, StoreError> {
    let Some(article) = composed.article.as_ref() else {
        if composed.article_text.is_some() {
            return Err(StoreError::RetentionDenied("article envelope unavailable".into()));
        }
        return Ok(None);
    };
    let denied = || StoreError::RetentionDenied("finalized article source or privacy mismatch".into());
    let text = composed.article_text.as_deref().ok_or_else(denied)?;
    let comments = composed.article_comments.as_deref().unwrap_or("");
    let policy = input.extract.content.as_ref().ok_or_else(denied)?;
    policy.validate().map_err(|_| denied())?;
    let policy_bytes = serde_json::to_vec(policy).map_err(|_| denied())?;
    if article.privacy_projection_version != Some(1)
        || article.policy_digest != Digest::of("crawlx.extract.policy.v1", &policy_bytes)
    {
        return Err(denied());
    }
    match (&article.chunks, &policy.chunks) {
        (Some(chunks), Some(effective)) => chunks.validate(text, effective).map_err(|_| denied())?,
        (None, None) => {}
        _ => return Err(denied()),
    }
    #[derive(serde::Serialize)]
    struct Sources<'a> {
        text: &'a str,
        comments: &'a str,
        article: &'a crawlx_core::extraction::DocumentEnvelopeV1,
    }
    let bytes = serde_json::to_vec(&Sources {
        text,
        comments,
        article,
    })
    .map_err(|_| denied())?;
    crawlx_core::secret::Redactor::new().check_canonical(&bytes)?;
    let clean = |value: &str| {
        input
            .controls
            .secret_values()
            .all(|secret| secret == crawlx_core::secret::REDACTED || !value.contains(secret))
            && input.captcha_secrets.as_ref().is_none_or(|secrets| {
                secrets
                    .redact_if_present(value)
                    .is_ok_and(|redacted| redacted.as_ref() == value)
            })
    };
    let metadata = &article.metadata;
    let clean_content = clean(text)
        && clean(comments)
        && [
            &metadata.title.value,
            &metadata.language.value,
            &metadata.declared_language,
            &metadata.detected_language.value,
            &metadata.publisher.value,
        ]
        .into_iter()
        .flatten()
        .all(|value| clean(value))
        && metadata.authors.value.iter().flatten().all(|value| clean(value))
        && metadata.declared_keywords.iter().all(|value| clean(value))
        && metadata.keywords.iter().all(|keyword| clean(&keyword.token))
        && [
            &metadata.title.evidence,
            &metadata.authors.evidence,
            &metadata.language.evidence,
            &metadata.detected_language.evidence,
            &metadata.publisher.evidence,
            &metadata.published.evidence,
            &metadata.modified.evidence,
        ]
        .into_iter()
        .flatten()
        .all(|evidence| clean(&evidence.raw))
        && [&metadata.published.value, &metadata.modified.value]
            .into_iter()
            .flatten()
            .all(|date| clean(&date.date.to_string()) && date.timestamp.as_deref().is_none_or(clean))
        && article.discovery.iter().all(|intent| clean(intent.url.as_str()));
    if !clean_content {
        return Err(denied());
    }
    serde_json::to_value(article).map(Some).map_err(|_| denied())
}

/// Why a body could not be composed.
pub(crate) enum ComposeError {
    /// The extractor refused the document.
    Extract(String),
    /// The body is not a readable document of its type.
    Unsupported(String),
}

impl ComposeError {
    pub(crate) fn into_failure(self) -> ScrapeFailure {
        match self {
            Self::Extract(m) => ScrapeFailure::new(FailReason::ExtractFailed, m),
            Self::Unsupported(m) => ScrapeFailure::new(FailReason::UnsupportedContent, m),
        }
    }
}

/// Compose the content of `input`. [`BodyKind::Binary`] has no content.
///
/// # Errors
/// [`ComposeError`] when the extractor or the PDF parser refuses the body, or an image arrives
/// while the `image` parser is off.
pub(crate) fn compose(input: &mut ComposeInput) -> Result<Composed, ComposeError> {
    if input.extensions.requires_document() && input.kind != BodyKind::Html {
        return Err(ComposeError::Unsupported(
            "extension requires an HTML document envelope".into(),
        ));
    }
    match input.kind {
        BodyKind::Html => html(input),
        BodyKind::Pdf => pdf(input),
        BodyKind::Image => image(input),
        BodyKind::Text => Ok(Composed {
            markdown: Some(String::from_utf8_lossy(&input.body).into_owned()),
            ..Composed::default()
        }),
        BodyKind::Binary => Ok(Composed::default()),
    }
}

/// Warning text of a parser that would need OCR.
const OCR_UNAVAILABLE: &str =
    "ocr_unavailable: no OCR backend is configured (set CRAWLX_OCR_BACKEND=tesseract|ocrs)";

/// A raster image: with the `image` parser on, an empty document that says why; with it off
/// (a `parsers` list without `image`), an unsupported file.
fn image(input: &ComposeInput) -> Result<Composed, ComposeError> {
    if !input
        .options
        .parsers
        .iter()
        .any(|p| matches!(p, ParserSpec::Image))
    {
        return Err(ComposeError::Unsupported(format!(
            "{} bodies are only read by the `image` parser, which `parsers` does not list",
            input.content_type.as_deref().unwrap_or("image")
        )));
    }
    let Some(ocr) = &input.ocr else {
        return Ok(Composed {
            markdown: Some(String::new()),
            warning: Some(format!("{OCR_UNAVAILABLE}; the image text was not recognized")),
            ..Composed::default()
        });
    };
    let parsed = parse_document(
        input,
        &ParseOptions {
            ocr: Some(Arc::clone(ocr)),
            ..ParseOptions::default()
        },
    )?;
    Ok(Composed {
        warning: (!parsed.warnings.is_empty()).then(|| parsed.warnings.join("; ")),
        markdown: Some(parsed.markdown),
        ..Composed::default()
    })
}

fn strip(text: String, on: bool) -> String {
    if !on {
        return text;
    }
    match base64_images::strip_base64_images(&text) {
        Cow::Borrowed(_) => text,
        Cow::Owned(stripped) => stripped,
    }
}

/// The `html` format: the cleaned `content` inside a document skeleton, as clients of the
/// compatibility API read it: `<!DOCTYPE html><html lang="…">`, a newline, the `<body>` (the
/// content when it already is one, else wrapped around it) and the closing tags. The language is
/// the page's declared one when it is a plain language tag; without one the root has no `lang`.
fn document_skeleton(content: &str, language: Option<&str>) -> String {
    let lang = language.map(str::trim).filter(|l| {
        !l.is_empty()
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    });
    let mut out = String::with_capacity(content.len() + 64);
    out.push_str("<!DOCTYPE html><html");
    if let Some(lang) = lang {
        out.push_str(" lang=\"");
        out.push_str(lang);
        out.push('"');
    }
    out.push_str(">\n");
    let body = content
        .trim_start()
        .get(..5)
        .is_some_and(|head| head.eq_ignore_ascii_case("<body"));
    if body {
        out.push_str(content);
        out.push_str("\n</html>");
    } else {
        out.push_str("<body>\n");
        out.push_str(content);
        out.push_str("\n</body>\n</html>");
    }
    out
}

fn html(input: &mut ComposeInput) -> Result<Composed, ComposeError> {
    let options = &*input.options;
    let extract = ExtractOptions {
        status: input.status,
        headers: input.headers.clone(),
        content_type: input.content_type.clone(),
        acquisition_validation: input.extract.acquisition_validation.clone().or_else(|| {
            input.extensions.configured().then(|| {
                crate::acquisition::context(
                    &crawlx_core::acquisition::AcquisitionPolicyV1::default(),
                    Some(input.status),
                    false,
                )
            })
        }),
        image_references: options.wants("images"),
        attribute_selectors: match options.format("attributes") {
            Some(FormatSpec::Attributes { selectors }) => selectors.clone(),
            _ => Vec::new(),
        },
        ..input.extract.clone()
    };
    let mut doc = match input.document.take() {
        Some(document) => document,
        None => match &input.captcha_secrets {
            Some(captcha) => crate::acquisition::extract_document_with_secrets(
                &input.body,
                &input.base,
                &extract,
                &input.controls,
                captcha,
            ),
            None if extract.content.is_none() => {
                crate::acquisition::extract_document(&input.body, &input.base, &extract, &input.controls)
            }
            None => {
                return Err(ComposeError::Extract(
                    "dynamic-secret registry unavailable".into(),
                ))
            }
        }
        .map(Box::new)
        .map_err(|e| ComposeError::Extract(e.to_string()))?,
    };
    let images = if options.wants("images") {
        Some(
            doc.image_urls
                .take()
                .ok_or_else(|| ComposeError::Extract("shared image projection unavailable".into()))?,
        )
    } else {
        None
    };
    let attributes = match options.format("attributes") {
        Some(FormatSpec::Attributes { selectors }) if selectors.is_empty() => Some(Vec::new()),
        Some(FormatSpec::Attributes { .. }) => Some(
            doc.attributes
                .take()
                .ok_or_else(|| ComposeError::Extract("shared attribute projection unavailable".into()))?,
        ),
        _ => None,
    };
    let mut meta = compat_meta::compat_meta(&doc);
    // Only the compiled pipeline can populate this key. A page meta tag must
    // never masquerade as an accepted native item when no article was parsed.
    meta.remove("extensionItem");
    if !doc.custom_fields.is_empty() {
        meta.insert("customFields".into(), serde_json::json!(doc.custom_fields));
    }
    if let Some(item) = &doc.item {
        meta.insert(
            "item".into(),
            serde_json::to_value(item).map_err(|e| ComposeError::Extract(e.to_string()))?,
        );
    }
    // These fields are content, and follow the existing ScrapeDocument retention/redaction
    // path. They must never be copied into structural page metadata under ZDR.
    if let Some(article) = &doc.article {
        match (
            article.chunks.as_ref(),
            input
                .extract
                .content
                .as_ref()
                .and_then(|policy| policy.chunks.as_ref()),
        ) {
            (Some(chunks), Some(policy)) => chunks
                .validate(&doc.text, policy)
                .map_err(|error| ComposeError::Extract(error.to_string()))?,
            (None, None) => {}
            _ => return Err(ComposeError::Extract("article chunk policy mismatch".into())),
        }
        if input.extensions.configured() && !doc.validation.as_ref().is_some_and(|v| v.content_accepted) {
            return Err(ComposeError::Extract(
                "extension content validation rejected".into(),
            ));
        }
        if input.extensions.configured() {
            let transformed = if doc
                .item
                .as_ref()
                .is_some_and(|item| !item.valid || item.schema_valid == Some(false))
            {
                Err(crawlx_core::extensions::ExtensionError::Rejected)
            } else {
                crate::extensions::transform_document(
                    &input.extensions,
                    &input.route_label,
                    article,
                    &input.cancel,
                )
            };
            match transformed {
                Ok(Some(item)) => {
                    meta.insert("extensionItem".into(), item);
                }
                Ok(None) => {}
                Err(crawlx_core::extensions::ExtensionError::Rejected) => {
                    meta.insert("extensionOutcome".into(), serde_json::json!("rejected"));
                }
                Err(error) => return Err(ComposeError::Extract(error.to_string())),
            }
        }
    }
    if input.extensions.requires_document() && doc.article.is_none() {
        return Err(ComposeError::Extract(
            "extension document envelope unavailable".into(),
        ));
    }
    let previews = doc
        .outputs
        .as_ref()
        .and_then(|outputs| outputs.link_media.as_ref())
        .map(|report| report.previews.clone())
        .unwrap_or_default();
    if doc.outputs.is_none() && (doc.decode.is_some() || doc.markup.is_some()) {
        doc.outputs = Some(crawlx_extract::content_outputs::ContentOutputs::default());
    }
    let mut outputs = doc
        .outputs
        .take()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| ComposeError::Extract(error.to_string()))?;
    for (key, value) in [
        ("decode", doc.decode.take().map(serde_json::to_value).transpose()),
        ("markup", doc.markup.take().map(serde_json::to_value).transpose()),
    ] {
        if let Some(value) = value.map_err(|error| ComposeError::Extract(error.to_string()))? {
            outputs.get_or_insert_with(|| serde_json::json!({}))[key] = value;
        }
    }
    let html = document_skeleton(
        &strip(doc.html, options.remove_base64_images),
        doc.language.as_deref(),
    );
    Ok(Composed {
        meta,
        outputs,
        previews,
        links: doc.links.iter().map(|l| l.url.clone()).collect(),
        title: doc.title,
        markdown: Some(strip(doc.markdown, options.remove_base64_images)),
        html: Some(html),
        images,
        attributes,
        article_text: doc.article.is_some().then_some(doc.text),
        article: doc.article.take().map(Box::new),
        article_comments: (!doc.comments.is_empty()).then_some(doc.comments),
        ..Composed::default()
    })
}

/// A PDF. Without a `pdf` parser in `parsers` (an empty list, or one naming only `image`) the
/// file is not parsed: its markdown is the base64 text of the bytes and `numPages` stays absent.
/// Otherwise the first `pdf` parser's options apply (`maxPages`, `pageMarkers`, `pages`,
/// `blocks`); `mode: ocr` and pages without a text layer are read by OCR when the worker has an
/// engine ([`ComposeInput::ocr`]) and carry an `ocr_unavailable` warning when it has not.
fn pdf(input: &ComposeInput) -> Result<Composed, ComposeError> {
    use base64::Engine as _;
    let parser = input.options.parsers.iter().find_map(|p| match p {
        ParserSpec::Pdf {
            mode,
            max_pages,
            pages,
            blocks,
            page_markers,
        } => Some((*mode, *max_pages, *pages, *blocks, *page_markers)),
        ParserSpec::Image => None,
    });
    let Some((mode, max_pages, want_pages, want_blocks, page_markers)) = parser else {
        return Ok(Composed {
            markdown: Some(base64::engine::general_purpose::STANDARD.encode(&input.body)),
            ..Composed::default()
        });
    };
    let limits = ParseLimits {
        max_pages: MAX_PDF_PAGES,
        ..ParseLimits::default()
    };
    let options = ParseOptions {
        pdf_max_pages: max_pages,
        pdf_page_markers: page_markers,
        pdf_layout: want_blocks,
        ocr: input.ocr.clone(),
        pdf_ocr: match mode {
            PdfMode::Fast => PdfOcr::Off,
            PdfMode::Auto => PdfOcr::Auto,
            PdfMode::Ocr => PdfOcr::Always,
        },
        limits,
        ..ParseOptions::default()
    };
    let text = parse_document(input, &options)?;
    let mut warnings = text.warnings;
    match (&input.ocr, mode) {
        (None, PdfMode::Ocr) => {
            warnings.push(format!("{OCR_UNAVAILABLE}; mode `ocr` extracted the text layer"))
        }
        (None, _) if text.markdown.trim().is_empty() => {
            warnings.push(format!("{OCR_UNAVAILABLE}; the PDF has no text layer"));
        }
        (Some(_), PdfMode::Fast) if text.markdown.trim().is_empty() => {
            warnings.push("mode `fast` reads the text layer only and the PDF has none".to_owned());
        }
        _ => {}
    }
    let meta = text.metadata;
    let pages = want_pages.then(|| {
        text.pages
            .iter()
            .map(|p| PdfPageMarkdown {
                page_number: p.page_number,
                markdown: p.markdown.clone(),
            })
            .collect()
    });
    let blocks = if want_blocks {
        Some(serde_json::to_value(&text.layout).map_err(|e| ComposeError::Unsupported(e.to_string()))?)
    } else {
        None
    };
    Ok(Composed {
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
        pages,
        blocks,
        links: text.links.iter().filter_map(|l| Url::parse(l).ok()).collect(),
        title: text.title,
        num_pages: text.num_pages,
        total_pages: text.total_pages,
        markdown: Some(text.markdown),
        meta,
        ..Composed::default()
    })
}

/// Run a non-page parser under the shared pipeline and the request's privacy projection.
/// OCR-enabled callers explicitly route raster formats; parser findings stay on the returned document.
fn parse_document(
    input: &ComposeInput,
    options: &ParseOptions,
) -> Result<Box<crawlx_extract::parse::ParsedDocument>, ComposeError> {
    let redactor = crawlx_core::secret::Redactor::new();
    let failed = std::cell::Cell::new(false);
    let project = |text: &str| {
        let scrubbed = redactor.scrub_bytes(text.as_bytes(), input.controls.secret_values());
        let scrubbed = String::from_utf8_lossy(scrubbed.as_ref());
        let mut projected = match &input.captcha_secrets {
            Some(registry) => match registry.redact_if_present(&scrubbed) {
                Ok(text) => text,
                Err(_) => {
                    failed.set(true);
                    Cow::Owned(String::new())
                }
            },
            None => Cow::Borrowed(scrubbed.as_ref()),
        };
        if let Some(policy) = &input.extract.content_redaction {
            projected = Cow::Owned(crawlx_extract::parse::redact::redact(&projected, policy).text);
        }
        (projected.as_ref() != text).then(|| projected.into_owned())
    };
    let mut spec = crawlx_core::extraction::ParserPipelineV1::default();
    if options.ocr.is_some() {
        for format in ["png", "jpeg", "gif", "webp", "bmp", "tiff"] {
            spec.routes.insert(
                format.to_owned(),
                crawlx_core::extraction::PipelineRouteV1::Document,
            );
        }
    }
    let pipeline = ParserPipeline::new(spec).map_err(|e| ComposeError::Extract(e.to_string()))?;
    let mut source = PipelineInput::new(&input.body)
        .with_filename(input.base.path())
        .with_page_url(&input.base)
        .with_document_options(options)
        .with_projection(&project);
    if let Some(content_type) = &input.content_type {
        source = source.with_content_type(content_type);
    }
    let output = pipeline
        .run(source)
        .map_err(|e| ComposeError::Unsupported(e.to_string()))?;
    if failed.get() {
        return Err(ComposeError::Extract(
            "dynamic-secret registry unavailable".into(),
        ));
    }
    match output.content {
        PipelineContent::Document(mut document) => {
            document.warnings = output.warnings;
            Ok(document)
        }
        _ => Err(ComposeError::Unsupported(
            "document parser route unavailable".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn bodies_are_classified_by_type_then_signature() {
        let html = Some("text/html; charset=utf-8");
        assert_eq!(classify(html, b"<p>", false), BodyKind::Html);
        assert_eq!(classify(None, b"<p>", false), BodyKind::Html);
        assert_eq!(
            classify(Some("application/pdf"), b"%PDF-1.4", false),
            BodyKind::Pdf
        );
        assert_eq!(classify(None, b"%PDF-1.7 ...", false), BodyKind::Pdf);
        assert_eq!(classify(Some("application/json"), b"{}", false), BodyKind::Text);
        assert_eq!(classify(Some("text/csv"), b"a,b", false), BodyKind::Text);
        assert_eq!(
            classify(Some("image/png"), &[0x89, b'P', b'N', b'G'], false),
            BodyKind::Image
        );
        for raster in [
            "image/jpeg",
            "image/gif",
            "image/webp",
            "image/avif",
            "image/tiff",
        ] {
            assert_eq!(
                classify(Some(raster), &[1, 2, 3], false),
                BodyKind::Image,
                "{raster}"
            );
        }
        assert_eq!(
            classify(Some("application/zip"), b"PK\x03\x04", false),
            BodyKind::Binary
        );
        assert_eq!(
            classify(Some("image/heic"), &[1, 2, 3], false),
            BodyKind::Binary,
            "HEIC is not read by the image parser"
        );
        assert_eq!(
            classify(Some("image/png"), b"", true),
            BodyKind::Html,
            "a rendered DOM is HTML"
        );
    }

    fn input(kind: BodyKind, body: &[u8], options: ScrapeOptions) -> ComposeInput {
        ComposeInput {
            body: Bytes::copy_from_slice(body),
            base: Url::parse("https://example.test/a/").unwrap(),
            kind,
            status: 200,
            headers: Vec::new(),
            content_type: None,
            options: Arc::new(options),
            extract: ExtractOptions::default(),
            document: None,
            extensions: crawlx_core::extensions::ExtensionPipelineV1::default(),
            route_label: "default".into(),
            cancel: tokio_util::sync::CancellationToken::new(),
            controls: crawlx_core::request_controls::RequestControls::default(),
            captcha_secrets: Some(crawlx_core::captcha::CaptchaSecrets::default()),
            ocr: None,
        }
    }

    #[test]
    fn text_bodies_are_their_own_markdown() {
        let c = compose(&mut input(BodyKind::Text, b"{\"a\":1}", ScrapeOptions::default()))
            .ok()
            .unwrap();
        assert_eq!(c.markdown.as_deref(), Some("{\"a\":1}"));
        assert!(c.html.is_none() && c.links.is_empty());
    }

    #[test]
    fn html_yields_markdown_links_and_title() {
        let page = br#"<html><head><title>T</title></head><body><main><h1>Hi</h1>
            <a href="/b">b</a><img src="data:image/png;base64,AAAA"></main></body></html>"#;
        let c = compose(&mut input(BodyKind::Html, page, ScrapeOptions::default()))
            .ok()
            .unwrap();
        assert_eq!(c.title.as_deref(), Some("T"));
        assert!(c.markdown.unwrap().contains("# Hi"));
        assert_eq!(c.links[0].as_str(), "https://example.test/b");
        assert!(
            !c.html.unwrap().contains("base64"),
            "removeBase64Images is on by default"
        );
    }

    #[test]
    fn html_is_a_document_with_doctype_and_language() {
        let page = br#"<!doctype html><html lang="en-GB"><head><title>T</title></head><body><main><h1>Hi</h1></main></body></html>"#;
        let html = compose(&mut input(BodyKind::Html, page, ScrapeOptions::default()))
            .ok()
            .unwrap()
            .html
            .unwrap();
        assert!(
            html.starts_with("<!DOCTYPE html><html lang=\"en-GB\">\n<body>\n<main>"),
            "{html}"
        );
        assert!(
            html.contains("<h1>Hi</h1>") && html.ends_with("</body>\n</html>"),
            "{html}"
        );
        let no_lang = br#"<html><body><main>x</main></body></html>"#;
        let html = compose(&mut input(BodyKind::Html, no_lang, ScrapeOptions::default()))
            .ok()
            .unwrap()
            .html
            .unwrap();
        assert!(html.starts_with("<!DOCTYPE html><html>\n<body>"), "{html}");
    }

    #[test]
    fn a_body_is_not_wrapped_in_another_body() {
        assert_eq!(
            document_skeleton("<body><p>x</p></body>", Some("de")),
            "<!DOCTYPE html><html lang=\"de\">\n<body><p>x</p></body>\n</html>"
        );
        assert_eq!(
            document_skeleton("<main>x</main>", Some("\"><script>")),
            "<!DOCTYPE html><html>\n<body>\n<main>x</main>\n</body>\n</html>",
            "an odd language value never reaches the markup"
        );
    }

    #[test]
    fn a_pdf_signature_without_a_document_is_unsupported() {
        let err = compose(&mut input(
            BodyKind::Pdf,
            b"%PDF-1.4 truncated",
            ScrapeOptions::default(),
        ))
        .err()
        .unwrap();
        assert!(matches!(err, ComposeError::Unsupported(_)));
    }
}
