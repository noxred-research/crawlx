//! Artifacts and the page row of one scraped page; see the [module documentation](super) for the
//! layout.

use crate::error::WorkerError;
use crate::scrape::media::Media;
use crate::scrape::{Acquired, Composed, ScrapeEngine, Scraped};
use crate::url_plane::headers_json;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{FrontierEntry, PageRecord, Sensitivity};
use crawlx_core::scrape::{ActionResults, BlobRef, JobKind, ScrapeDocument};
use crawlx_core::secret::ArtifactSink;
use crawlx_core::{ArtifactRef, StoreError, TrustLane};
use std::collections::BTreeSet;

/// Store `bytes` as a content artifact of page `page`. A retention policy that refuses content
/// (zero data retention without a delivery buffer) yields `None`.
async fn put(
    engine: &ScrapeEngine,
    page: i64,
    content_type: &str,
    bytes: &[u8],
) -> Result<Option<(ArtifactRef, u64)>, WorkerError> {
    let pdf = content_type
        .split(';')
        .next()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/pdf"));
    let sanitized;
    let bytes = if pdf {
        let limits = crawlx_extract::parse::ParseLimits::default();
        if bytes.len() > limits.max_input_bytes {
            return Err(WorkerError::PdfSanitization(
                crawlx_extract::parse::ParseError::TooLarge {
                    what: "input bytes",
                    limit: limits.max_input_bytes,
                    actual: bytes.len(),
                },
            ));
        }
        let native = bytes.to_vec();
        let controls = engine.fetcher.config().controls.clone();
        let captcha = engine.captcha_secrets.clone();
        sanitized = tokio::task::spawn_blocking(move || {
            let redactor = crawlx_core::secret::Redactor::new();
            crawlx_extract::parse::pdf::sanitize_pdf(&native, &limits, &|text| {
                let scrubbed = redactor.scrub_bytes(text.as_bytes(), controls.secret_values());
                let text = std::str::from_utf8(scrubbed.as_ref()).map_err(|source| {
                    crawlx_extract::parse::ParseError::corrupt_from(
                        "pdf",
                        "text redaction encoding failed",
                        source,
                    )
                })?;
                match captcha.as_ref() {
                    Some(registry) => registry
                        .redact_if_present(text)
                        .map(std::borrow::Cow::into_owned)
                        .map_err(|source| {
                            crawlx_extract::parse::ParseError::corrupt_from(
                                "pdf",
                                "dynamic-secret redaction unavailable",
                                source,
                            )
                        }),
                    None => Ok(text.to_owned()),
                }
            })
        })
        .await
        .map_err(WorkerError::PdfSanitizationTask)?
        .map_err(WorkerError::PdfSanitization)?;
        sanitized.as_slice()
    } else {
        bytes
    };
    let text = !pdf && crate::capture::is_text_artifact(content_type) && std::str::from_utf8(bytes).is_ok();
    let bytes = if text {
        engine.redact_bytes(bytes)
    } else {
        match crate::capture::check_run_secrets(
            bytes,
            &engine.fetcher.config().controls,
            engine.captcha_secrets.as_ref(),
        ) {
            Ok(()) => {}
            Err(StoreError::RetentionDenied(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        std::borrow::Cow::Borrowed(bytes)
    };
    let redactor = crawlx_core::secret::Redactor::new();
    let approved = if text {
        redactor.redact_artifact(bytes.as_ref())
    } else {
        redactor.verify_binary(bytes.as_ref())
    };
    let bytes = match approved {
        Ok(bytes) => bytes,
        Err(StoreError::RetentionDenied(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    match ArtifactSink::over(engine.deps.artifacts.as_ref())
        .put_page(engine.run, page, Sensitivity::Content, content_type, &bytes)
        .await
    {
        Ok(artifact) => Ok(Some((
            artifact,
            u64::try_from(bytes.as_ref().len()).unwrap_or(u64::MAX),
        ))),
        Err(StoreError::RetentionDenied(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn put_blob(
    engine: &ScrapeEngine,
    page: i64,
    content_type: &str,
    bytes: &[u8],
) -> Result<Option<BlobRef>, WorkerError> {
    Ok(put(engine, page, content_type, bytes)
        .await?
        .map(|(artifact, size)| BlobRef {
            artifact,
            content_type: content_type.to_owned(),
            size,
        }))
}

/// A distinct article source rendition must not overwrite HTML or another ZDR blob slot.
async fn put_article_blob(
    engine: &ScrapeEngine,
    page: i64,
    rendition: &str,
    bytes: &[u8],
) -> Result<Option<BlobRef>, WorkerError> {
    let content_type = "text/plain; charset=utf-8";
    let bytes = match crawlx_core::secret::Redactor::new().verify_canonical(bytes) {
        Ok(bytes) => bytes,
        Err(StoreError::RetentionDenied(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    match ArtifactSink::over(engine.deps.artifacts.as_ref())
        .put_dataset(engine.run, page, rendition, content_type, &bytes)
        .await
    {
        Ok(artifact) => Ok(Some(BlobRef {
            artifact,
            content_type: content_type.into(),
            size: u64::try_from(bytes.as_ref().len()).unwrap_or(u64::MAX),
        })),
        Err(StoreError::RetentionDenied(_)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Finalize diagnostic rows before exact dedupe or any content-derived artifact identity.
async fn put_virtual_rows(
    engine: &ScrapeEngine,
    cpu: &crate::runtime::CpuPool,
    page: i64,
    ordinal: usize,
    mut report: crawlx_core::dom_ops::VirtualRowsReport,
    options: &crawlx_core::scrape::ScrapeOptions,
    finalized_remaining: usize,
) -> Result<(Option<BlobRef>, usize), WorkerError> {
    let pii = options.redact_pii.as_ref().map(super::guard::redact_options);
    let controls = engine.fetcher.config().controls.clone();
    let captcha = engine.captcha_secrets.clone();
    let approved = cpu
        .run(move || {
            let redactor = crawlx_core::secret::Redactor::new();
            report.project_rows(|text| {
                let controlled = redactor.scrub_bytes(text.as_bytes(), controls.secret_values());
                let text = std::str::from_utf8(controlled.as_ref()).map_err(|_| {
                    WorkerError::Other("virtual rows secret projection encoding failed".into())
                })?;
                let text = match &captcha {
                    Some(registry) => registry.redact_if_present(text).map_err(|_| {
                        WorkerError::Other("virtual rows secret projection unavailable".into())
                    })?,
                    None => std::borrow::Cow::Borrowed(text),
                };
                let text = match &pii {
                    Some(policy) => {
                        std::borrow::Cow::Owned(crawlx_extract::parse::redact::redact(&text, policy).text)
                    }
                    None => text,
                };
                // Preserve decoded JSON keys/literals and duplicate-member protections for
                // every row; text-only scrubbing is not equivalent to this approval policy.
                let decoded = redactor.redact_text(&text).into_inner();
                // Rows are embedded as text, not JSON objects. Project decoded JSON into the
                // text policy before dedupe so the final canonical approval sees stable rows.
                Ok::<_, WorkerError>(redactor.scrub(&decoded))
            })?;
            let maximum = usize::try_from(report.max_bytes)
                .map_err(|_| WorkerError::Other("virtual rows byte limit overflow".into()))?
                .min(finalized_remaining);
            let mut output = crate::delivery::LimitedOutput::new(maximum);
            serde_json::to_writer(&mut output, &report).map_err(|error| {
                output
                    .take_allocation_error()
                    .map_or_else(|| WorkerError::VirtualRowsOutputLimit(error), WorkerError::Store)
            })?;
            redactor
                .verify_canonical_owned(output.bytes)
                .map_err(WorkerError::from)
        })
        .await
        .map_err(|_| WorkerError::Other("virtual rows CPU task failed".into()))??;
    let charged = approved.as_ref().len();
    let size = u64::try_from(charged).unwrap_or(u64::MAX);
    let content_type = "application/vnd.crawlx.virtual-rows+json";
    let rendition = format!("virtual_rows_{ordinal}");
    let stored = match ArtifactSink::over(engine.deps.artifacts.as_ref())
        .put_dataset(engine.run, page, &rendition, content_type, &approved)
        .await
    {
        Ok(artifact) => Some(BlobRef {
            artifact,
            content_type: content_type.into(),
            size,
        }),
        Err(StoreError::RetentionDenied(_)) => None,
        Err(error) => return Err(error.into()),
    };
    Ok((stored, charged))
}

/// Store the artifacts the options ask for and build the page row. `doc` carries everything the
/// format steps produced; the blob references are filled here.
///
/// # Errors
/// [`WorkerError`] when an artifact cannot be stored for a reason other than retention.
pub(crate) async fn assemble(
    engine: &ScrapeEngine,
    cpu: &crate::runtime::CpuPool,
    entry: &FrontierEntry,
    mut acq: Acquired,
    mut composed: Composed,
    mut doc: ScrapeDocument,
    media: Media,
) -> Result<Scraped, WorkerError> {
    let opts = &*engine.options;
    let page = entry.id;
    let mut dropped: Vec<&'static str> = Vec::new();
    let mut native_pdf_stored = false;
    let mut native_meta = std::collections::BTreeMap::new();
    for key in [
        "article",
        "articleParseQuality",
        "articleTextRef",
        "articleCommentsRef",
        "articleDocumentRef",
        "articleCacheSourceRun",
    ] {
        doc.meta.remove(key);
    }
    if let Some(article) = composed.take_verified_article() {
        native_meta.insert("article".to_owned(), article);
    }
    if let Some(reference) = &composed.article_cache {
        if !native_meta.contains_key("article") {
            return Err(StoreError::RetentionDenied("article cache envelope unavailable".into()).into());
        }
        native_meta.insert(
            "articleDocumentRef".into(),
            serde_json::to_value(reference)
                .map_err(|_| WorkerError::Config("article cache reference serialization failed".into()))?,
        );
        native_meta.insert("articleCacheSourceRun".into(), serde_json::json!(engine.run));
    }

    let mut markdown = None;
    if opts.wants("markdown") || opts.wants("changeTracking") {
        if let Some(text) = &composed.markdown {
            markdown = put(engine, page, "text/markdown", text.as_bytes())
                .await?
                .map(|(artifact, _)| artifact);
            if markdown.is_none() {
                dropped.push("markdown");
            }
        }
    }
    let mut html = None;
    if opts.wants("html") {
        if let Some(text) = &composed.html {
            html = put(engine, page, "text/html", text.as_bytes())
                .await?
                .map(|(artifact, _)| artifact);
            if html.is_none() {
                dropped.push("html");
            }
        }
    }
    for (key, rendition, content) in [
        ("articleTextRef", "article_main", &composed.article_text),
        (
            "articleCommentsRef",
            "article_comments",
            &composed.article_comments,
        ),
    ] {
        if let Some(text) = content {
            match put_article_blob(engine, page, rendition, text.as_bytes()).await? {
                Some(reference) => {
                    native_meta.insert(
                        key.to_owned(),
                        serde_json::to_value(reference).map_err(|e| {
                            WorkerError::Other(format!("article source reference is not serializable: {e}"))
                        })?,
                    );
                }
                None => dropped.push(key),
            }
        }
    }
    if !native_meta.contains_key("articleTextRef")
        || (composed.article_comments.is_some() && !native_meta.contains_key("articleCommentsRef"))
    {
        // Source-only ranges must never outlive the canonical source's retention grant.
        for key in [
            "article",
            "articleCommentsRef",
            "articleDocumentRef",
            "articleCacheSourceRun",
        ] {
            native_meta.remove(key);
        }
    }
    if opts.wants("rawHtml") {
        doc.raw_html = put_blob(engine, page, "text/html", &acq.body).await?;
        if doc.raw_html.is_none() {
            dropped.push("rawHtml");
        }
    }
    if opts.wants("rawBase64") {
        let ct = acq.content_type.as_deref().unwrap_or("application/octet-stream");
        doc.raw_base64 = put_blob(engine, page, ct, &acq.body).await?;
        if doc.raw_base64.is_none() {
            dropped.push("rawBase64");
        }
    }
    if let Some(file) = &media.audio {
        doc.audio = put_blob(engine, page, &file.content_type, &file.bytes).await?;
        if doc.audio.is_none() {
            dropped.push("audio");
        }
    }
    if let Some(file) = &media.video {
        // audio that fell back to the video file is the same artifact
        let shared = media
            .audio
            .as_ref()
            .filter(|a| a.url == file.url)
            .and(doc.audio.as_ref());
        doc.video = match shared {
            Some(blob) => Some(blob.clone()),
            None => put_blob(engine, page, &file.content_type, &file.bytes).await?,
        };
        if doc.video.is_none() {
            dropped.push("video");
        }
    }
    if let Some(render) = acq.render {
        if opts.wants("screenshot") {
            if let Some(shot) = &render.screenshot {
                doc.screenshot = put_blob(engine, page, shot.content_type, &shot.bytes).await?;
                if doc.screenshot.is_none() {
                    dropped.push("screenshot");
                }
            }
        }
        if !opts.actions.is_empty() {
            let mut results = ActionResults {
                scrapes: render.actions.scrapes,
                javascript_returns: render.actions.javascript_returns,
                ..ActionResults::default()
            };
            for shot in &render.actions.screenshots {
                match put_blob(engine, page, shot.content_type, &shot.bytes).await? {
                    Some(b) => results.screenshots.push(b),
                    None => dropped.push("actions.screenshots"),
                }
            }
            for shot in &render.actions.pdfs {
                match put_blob(engine, page, shot.content_type, &shot.bytes).await? {
                    Some(b) => {
                        native_pdf_stored = true;
                        results.pdfs.push(b);
                    }
                    None => dropped.push("actions.pdfs"),
                }
            }
            let mut finalized_remaining = match render.actions.virtual_rows_max_bytes {
                Some(maximum) => maximum,
                None if render.actions.virtual_rows.is_empty() => 0,
                None => {
                    return Err(WorkerError::Other(
                        "virtual rows original render allowance unavailable".into(),
                    ))
                }
            };
            for (ordinal, report) in render.actions.virtual_rows.into_iter().enumerate() {
                let (stored, charged) =
                    put_virtual_rows(engine, cpu, page, ordinal, report, opts, finalized_remaining).await?;
                finalized_remaining = finalized_remaining.checked_sub(charged).ok_or_else(|| {
                    WorkerError::Other("virtual rows finalized byte allowance exhausted".into())
                })?;
                match stored {
                    Some(blob) => results.virtual_rows.push(blob),
                    None => dropped.push("actions.virtualRows"),
                }
            }
            doc.actions = Some(results);
        }
    }
    dropped.dedup();
    let retention = (!dropped.is_empty()).then(|| {
        format!(
            "not retained under the run's retention policy: {}",
            dropped.join(", ")
        )
    });
    let pdf_scope = native_pdf_stored.then(|| {
        "PDF sanitization covers mapped native text, strings and XML metadata; images, embedded files, unsupported stream encodings and OCR are outside text-layer coverage".to_owned()
    });
    doc.warning = [doc.warning.take(), composed.warning, retention, pdf_scope]
        .into_iter()
        .flatten()
        .reduce(|acc, w| format!("{acc}; {w}"));

    let fetcher = &engine.fetcher;
    if let Some(raw) = &doc.raw_html {
        match acq.metadata.representation {
            crawlx_core::acquisition::RepresentationV1::RenderedDom => {
                acq.metadata.rendered_dom = Some(raw.artifact.clone())
            }
            crawlx_core::acquisition::RepresentationV1::WireResponse => {
                acq.metadata.wire_body = Some(raw.artifact.clone())
            }
            _ => {}
        }
    }
    acq.metadata
        .bound()
        .map_err(|e| WorkerError::Config(e.to_string()))?;
    let mut scrape = serde_json::to_value(&doc)
        .map_err(|e| WorkerError::Other(format!("scrape document is not serializable: {e}")))?;
    let mut metadata = serde_json::json!({
        "final_url": acq.metadata.final_url.as_ref().map(url::Url::as_str),
        "redirects": acq.redirects,
        "response_headers": headers_json(&acq.headers, &BTreeSet::new(), &fetcher.config().controls),
        "fingerprint": crawlx_url::fingerprint_url(&entry.url.url, None).0,
        "acquisition": acq.metadata,
    });
    engine.redact_value(&mut metadata);
    // Root keys belong to ScrapeDocument, not to page-authored metadata. Arbitrary
    // content (including every metadata key) still takes the recursive scrub.
    if let Some(fields) = scrape.as_object_mut() {
        for (name, value) in fields {
            if !matches!(
                name.as_str(),
                "optionsDigest"
                    | "proxyUsed"
                    | "cacheState"
                    | "rawHtml"
                    | "rawBase64"
                    | "screenshot"
                    | "audio"
                    | "video"
            ) {
                engine.redact_value(value);
            }
        }
    }
    let meta = scrape
        .get_mut("meta")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| WorkerError::Config("scrape metadata object unavailable".into()))?;
    // Only typed native outputs and generated references enter this map. Never
    // exempt a page-authored JSON object merely because its key is `article`.
    meta.extend(native_meta);
    metadata[ScrapeDocument::METADATA_KEY] = scrape;
    let record = PageRecord {
        run: engine.run,
        frontier_id: entry.id,
        url: entry.url.clone(),
        status: acq.status,
        content_type: acq.content_type.clone(),
        content_digest: Digest::of("crawlx/page-body/v1", &acq.body),
        title: composed.title.map(|title| engine.redact(&title)),
        markdown,
        html,
        metadata,
        links: if opts.wants("links") {
            composed
                .links
                .iter()
                .map(|url| engine.redact(url.as_str()))
                .collect()
        } else {
            Vec::new()
        },
        fetched_at: engine.deps.clock.now(),
        lane: TrustLane::Diagnostic,
    };
    Ok(Scraped {
        record,
        accepted: Vec::new(),
        outbox: Vec::new(),
        content_dedupe: None,
        local_dedupe: None,
        links: if engine.kind == JobKind::Crawl {
            composed.links
        } else {
            Vec::new()
        },
        final_url: acq.final_url,
    })
}
