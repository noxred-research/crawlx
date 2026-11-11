//! One admitted local acquisition followed by immutable, network-free page inspection.

use crate::{run_local_with, LocalRun, WorkerError};
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::scrape::{FormatSpec, JobKind, ScrapeJob, ScrapeOptions};
use http::Method;
use tokio_util::sync::CancellationToken;

/// Immutable result of a single admitted acquisition. It contains no network capability.
#[derive(Debug)]
#[non_exhaustive]
pub struct StoredPage {
    /// Actual method used for acquisition.
    pub method: Method,
    /// Final acquired URL.
    pub url: String,
    /// Actual target status.
    pub status: u16,
    /// Stored decoded HTML; empty for HEAD.
    pub html: String,
    /// Extracted Markdown; empty for HEAD.
    pub markdown: String,
    /// Redacted native HEAD evidence, absent for GET.
    pub head: Option<serde_json::Value>,
}

/// Acquire once through the ordinary local-run authorization, scope, robots and budget path.
///
/// This binding disables discovery, retries, browser rendering, preflights and cache reuse.
/// Redirects remain subject to the request's shared finite acquisition allowance.
///
/// # Errors
/// Returns configuration, policy, cancellation, storage or acquisition failures. A denied URL
/// never becomes an empty successful page. The caller must perform admission before this call.
pub async fn acquire(
    mut local: LocalRun,
    method: Method,
    cancel: CancellationToken,
) -> Result<StoredPage, WorkerError> {
    if method != Method::GET && method != Method::HEAD {
        return Err(WorkerError::Config(
            "stored-page acquisition supports only GET and HEAD".into(),
        ));
    }
    if cancel.is_cancelled() {
        return Err(WorkerError::Config("stored-page acquisition cancelled".into()));
    }
    let crawl = &mut local.crawl;
    crawl.mode = CrawlMode::Static;
    crawl.dynamic.enabled = false;
    crawl.limits.urls = 1;
    crawl.scope.max_discovery_depth = 0;
    crawl.scope.path_climb = false;
    crawl.scope.known_files.clear();
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.fetch.retries = 0;
    crawl.fetch.preflight = None;
    crawl.fetch.max_response_bytes = crawl.fetch.max_response_bytes.min(1_048_576);
    crawl.fetch.oversize = Some(crawlx_core::acquisition::OversizePolicy::Refuse);
    let mut allowance = crawl.acquisition.clone().unwrap_or_default();
    allowance.max_decoded_bytes = allowance.max_decoded_bytes.min(1_048_576);
    allowance.max_attempts = 1;
    allowance.retry_on.clear();
    allowance.meta_refresh = None;
    allowance.backend_ids = vec!["native_http".into()];
    allowance.fallback_backend_ids.clear();
    crawl.acquisition = Some(allowance);
    crawl.scrape = if method == Method::GET {
        let options = ScrapeOptions {
            formats: vec![FormatSpec::RawHtml, FormatSpec::Markdown],
            max_age_ms: 0,
            store_in_cache: false,
            parsers: Default::default(),
            only_main_content: false,
            remove_base64_images: false,
            ..ScrapeOptions::default()
        };
        let mut job = ScrapeJob::new(JobKind::Scrape, options);
        job.honor_robots_txt = true;
        Some(job)
    } else {
        None
    };
    let requested_url = local.crawl.seed_url.to_string();
    let stores = match local.stores.take() {
        Some(stores) => stores,
        None => crate::Stores::open(&local.cfg).await?,
    };
    local = local.with_stores(stores.clone());
    let local = local
        .with_cancel(cancel.clone())
        .with_initial_request_method(method.clone())?;
    let report = run_local_with(local).await?;
    if cancel.is_cancelled() {
        return Err(WorkerError::Config("stored-page acquisition cancelled".into()));
    }
    if method == Method::HEAD {
        let head = report.head_responses.into_iter().next().ok_or_else(|| {
            WorkerError::PolicyDenied("stored-page acquisition produced no admitted HEAD response".into())
        })?;
        let status = head
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .ok_or_else(|| WorkerError::Config("HEAD response lacks target status".into()))?;
        return Ok(StoredPage {
            method,
            url: head
                .pointer("/acquisition/finalUrl")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&requested_url)
                .to_owned(),
            status,
            html: String::new(),
            markdown: String::new(),
            head: Some(head),
        });
    }
    let page = report.pages.first().ok_or_else(|| {
        WorkerError::PolicyDenied("stored-page acquisition produced no admitted page".into())
    })?;
    let content = report.page_contents.into_iter().next().ok_or_else(|| {
        WorkerError::Config("stored-page content is unavailable under the retention policy".into())
    })?;
    let document = crawlx_core::scrape::ScrapeDocument::from_page_metadata(&page.metadata)
        .ok_or_else(|| WorkerError::Config("stored scrape metadata is unavailable".into()))?;
    let raw = document.raw_html.ok_or_else(|| {
        WorkerError::Config("stored-page HTML is unavailable under the retention policy".into())
    })?;
    let bytes = stores.artifacts.get(&raw.artifact).await?;
    let charset = document
        .content_type
        .as_deref()
        .and_then(crawlx_extract::decode::charset_of_content_type);
    let html = crawlx_extract::decode::decode(&bytes, charset.as_deref())
        .map_err(|_| {
            WorkerError::Config("stored-page body cannot be decoded within inspection limits".into())
        })?
        .text;
    if html.len() > 1_048_576 {
        return Err(WorkerError::Config(
            "stored-page body exceeds inspection limit".into(),
        ));
    }
    Ok(StoredPage {
        method,
        url: document.final_url,
        status: page.status,
        html,
        markdown: content.markdown.unwrap_or_default(),
        head: None,
    })
}
