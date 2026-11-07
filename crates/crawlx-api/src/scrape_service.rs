//! The scrape service behind the Firecrawl facade: option parsing, run creation and
//! waiting, stored pages rendered as Firecrawl documents, credits and failure mapping.
//!
//! Every scrape product is a normal queued run that a worker executes
//! ([`crawlx_core::scrape::ScrapeJob`]): the API never fetches a page and never starts a
//! browser. `POST /scrape` creates a [`JobKind::Scrape`] run and waits for it
//! ([`scrape_url`]); batch scrapes and crawls create their run and return at once
//! ([`create_scrape_run`]); a stored page becomes the Firecrawl `data` object in
//! [`firecrawl_document`].

mod document;
mod options;

pub use document::{credits_for, firecrawl_document, scrape_id};
pub use options::{parse_scrape_options, parse_scrape_options_in, ParsedScrape};

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::usage::{self, Cost};
use crate::resources::Warning;
use crate::routes::crawls::{apply_verb, create_run_as, Verb};
use crate::routes::pages::sorted_pages;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::ts;
use axum::http::StatusCode;
use crawlx_core::config::{CrawlMode, CreateCrawl, HostScope, SitemapMode};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{CrawlRun, FrontierEntry, FrontierStatus, PageRecord};
use crawlx_core::scrape::{JobKind, ScrapeDocument};
use crawlx_core::{CrawlRunId, TenantId};
use crawlx_model::llm::TokenUsage;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use crawlx_worker::scrape::cache;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

/// Read-only bridge from the API artifact source to the shared cache reader.
struct CacheArtifacts<'a>(&'a dyn crate::store::ArtifactSource);

#[async_trait::async_trait]
impl crawlx_core::repo::ArtifactStore for CacheArtifacts<'_> {
    async fn put(
        &self,
        _run: CrawlRunId,
        _class: crawlx_core::repo::Sensitivity,
        _content_type: &str,
        _bytes: &[u8],
    ) -> Result<crawlx_core::ArtifactRef, crawlx_core::StoreError> {
        Err(crawlx_core::StoreError::AccessDenied(
            "cache artifact reader is read-only".into(),
        ))
    }
    async fn get(&self, artifact: &crawlx_core::ArtifactRef) -> Result<Vec<u8>, crawlx_core::StoreError> {
        self.0.read(artifact).await
    }
}

/// How often [`wait_for_run`] reads the run.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Time a worker gets on top of `timeout` to report its own `scrape_timeout` (so the API can
/// answer with the worker's reason instead of cancelling first).
const TIMEOUT_GRACE: Duration = Duration::from_millis(1_500);

/// The result of one scrape: the Firecrawl `data` object and what it cost.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct ScrapeDone {
    /// The Firecrawl `data` object (`markdown`, ..., `metadata`).
    pub document: Value,
    /// Credits the scrape costs.
    pub credits: u64,
}

/// A URL listed by a map.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct MapEntry {
    /// Absolute URL.
    pub url: String,
    /// Page title when known.
    pub title: Option<String>,
    /// Page description when known.
    pub description: Option<String>,
}

/// The outcome of one scrape request.
pub(crate) struct Scraped {
    /// The Firecrawl `data` object.
    pub document: Value,
    /// Credits the scrape costs.
    pub credits: u64,
    /// The run the request created; `None` when a stored scrape answered.
    pub created_run: Option<CrawlRunId>,
}

/// The principal service callers (the page tools of `/extract`, `/agent`, `/monitor`) act as.
#[must_use]
pub fn service_principal(tenant: TenantId) -> Principal {
    Principal {
        tenant,
        key_id: Uuid::nil(),
        scopes: Scope::all_set(),
    }
}

/// Firecrawl's answer to a request admission rejected: egress-denied targets are
/// `403 UNSUPPORTED_SITE`, every other violation `400 BAD_REQUEST`.
fn admission_error(e: HttpError) -> HttpError {
    if e.status != StatusCode::UNPROCESSABLE_ENTITY {
        return e;
    }
    // only a refused target is a site problem; a refused webhook URL is a bad request
    let target = e
        .details
        .iter()
        .find(|d| d.code == "url_denied" && !d.path.starts_with("/output/webhook"))
        .map(|d| d.message.clone());
    match target {
        Some(m) => {
            let mut denied = HttpError::compat(
                StatusCode::FORBIDDEN,
                "UNSUPPORTED_SITE",
                format!("This URL cannot be scraped: {m}"),
            );
            denied.details = e.details;
            denied
        }
        None => HttpError::bad_request(e.details),
    }
}

/// The base run of every scrape product: static mode, the seed only (no link following, no
/// sitemaps, any host), `limit_urls` pages, with `parsed` applied.
///
/// # Errors
/// `400` details for a header the fetch controls reject.
pub(crate) fn scrape_crawl(
    seed: Url,
    kind: JobKind,
    parsed: &ParsedScrape,
    limit_urls: usize,
) -> Result<CreateCrawl, Vec<Detail>> {
    let mut c = CreateCrawl::new(seed);
    c.mode = CrawlMode::Static;
    c.limits.urls = u32::try_from(limit_urls.max(1)).unwrap_or(u32::MAX);
    c.scope.max_discovery_depth = 0;
    c.scope.sitemap = SitemapMode::Skip;
    c.scope.known_files.clear();
    c.scope.host_scope = HostScope::None;
    parsed.apply(&mut c, kind)?;
    Ok(c)
}

/// Admit and persist `crawl` as a queued run a worker will pick up. No idempotency wrapper (the
/// caller decides). `warnings` gains what admission adds (`limit_clamped`, ...). The option
/// parser warns `ocr_unavailable` for the `image` parser and PDF `mode: ocr`; a server with an
/// OCR engine (`ApiConfig::ocr`) drops those, the worker's own document warning stays the
/// authority on what its engine did.
///
/// # Errors
/// `429 quota_exceeded` above the active-run quota, `403 UNSUPPORTED_SITE` for a target the
/// egress policy denies, `400 BAD_REQUEST` (with `details`) for every other violation, and
/// storage failures.
pub async fn create_scrape_run(
    state: &AppState,
    principal: &Principal,
    crawl: CreateCrawl,
    warnings: &mut Vec<Warning>,
) -> ApiResult<CrawlRun> {
    create_scrape_run_as(state, principal, crawl, warnings, CrawlRunId::new()).await
}

/// As [`create_scrape_run`], creating the run under the already chosen `id`.
///
/// # Errors
/// As [`create_scrape_run`].
pub(crate) async fn create_scrape_run_as(
    state: &AppState,
    principal: &Principal,
    crawl: CreateCrawl,
    warnings: &mut Vec<Warning>,
    id: CrawlRunId,
) -> ApiResult<CrawlRun> {
    if state.ocr.is_some() {
        warnings.retain(|w| w.code != "ocr_unavailable");
    }
    let created = create_run_as(state, principal, crawl, Vec::new(), std::mem::take(warnings), id)
        .await
        .map_err(admission_error)?;
    *warnings = created.warnings;
    Ok(created.run)
}

/// Poll `run` every 50 ms until it is terminal and return it.
///
/// # Errors
/// `408 SCRAPE_TIMEOUT` after `timeout` (the run is cancelled first), `503` when the server
/// shuts down, storage failures.
pub async fn wait_for_run(state: &AppState, run: CrawlRunId, timeout: Duration) -> ApiResult<CrawlRun> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let current = state.repos.runs.get(run).await?;
        if current.status.is_terminal() {
            return Ok(current);
        }
        if tokio::time::Instant::now() >= deadline {
            match apply_verb(state, current, Verb::Cancel).await {
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, %run, "scrape run ended before it could be cancelled"),
            }
            return Err(timeout_error());
        }
        tokio::select! {
            () = tokio::time::sleep(POLL_INTERVAL) => {}
            () = state.shutdown.cancelled() => return Err(HttpError::unavailable()),
        }
    }
}

fn timeout_error() -> HttpError {
    HttpError::compat(StatusCode::REQUEST_TIMEOUT, "SCRAPE_TIMEOUT", "Scrape timed out")
}

/// Parse the `url` of a scrape request: `http(s)` with a host. A value without a scheme
/// (`example.com/a`) gets `http://` and must then name a dotted host or an IP address, like
/// Firecrawl's URL check (`nope` is not a URL).
///
/// # Errors
/// `400` detail for `path` when the value is not a usable URL.
pub(crate) fn parse_target(raw: &str, path: &str) -> Result<Url, Detail> {
    let raw = raw.trim();
    let bad = |m: &str| Detail::new(path, "invalid_string", m);
    if raw.is_empty() {
        return Err(bad("URL must not be empty"));
    }
    let with_scheme = raw.contains("://");
    let candidate = if with_scheme {
        raw.to_owned()
    } else {
        format!("http://{raw}")
    };
    let url = Url::parse(&candidate).map_err(|e| bad(&format!("Invalid URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none_or(str::is_empty) {
        return Err(bad("URL must be an http(s) URL with a host"));
    }
    let dotted = matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)))
        || url.host_str().is_some_and(|h| h.contains('.'));
    if !with_scheme && !dotted {
        return Err(bad("URL must have a valid top-level domain"));
    }
    Ok(url)
}
/// One worker failure reason and the Firecrawl error it is reported as: by `POST /scrape`, by
/// `GET /scrape/{id}` of a failed page and as the `code` of `GET /crawl/{id}/errors`. Every
/// worker reason has exactly one row; a reason without one is reported as
/// `SCRAPE_ALL_ENGINES_FAILED` (HTTP 500).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FailureCode {
    /// The worker's reason (`FailReason::code`, or the frontier denial reason of the URL plane).
    pub reason: &'static str,
    /// HTTP status of a single scrape that failed this way.
    pub status: u16,
    /// The `SCRAPE_*` (or Firecrawl-documented) error code.
    pub code: &'static str,
    /// What went wrong, in words.
    pub text: &'static str,
}

const fn fc(reason: &'static str, status: u16, code: &'static str, text: &'static str) -> FailureCode {
    FailureCode {
        reason,
        status,
        code,
        text,
    }
}

/// The reported error of every worker failure reason (see [`FailureCode`]).
pub const FAILURE_CODES: [FailureCode; 21] = [
    fc("scrape_timeout", 408, "SCRAPE_TIMEOUT", "Scrape timed out"),
    fc(
        "unreachable",
        500,
        "SCRAPE_SITE_ERROR",
        "The site could not be reached",
    ),
    fc(
        "dns_failed",
        500,
        "SCRAPE_DNS_RESOLUTION_ERROR",
        "DNS resolution failed",
    ),
    fc(
        "egress_denied",
        403,
        "UNSUPPORTED_SITE",
        "This URL cannot be scraped",
    ),
    fc(
        "policy_blocked",
        403,
        "SCRAPE_POLICY_BLOCKED",
        "The crawl policy does not allow this URL",
    ),
    fc(
        "robots_disallow",
        403,
        "SCRAPE_ROBOTS_BLOCKED",
        "The site's robots.txt does not allow this URL",
    ),
    fc(
        "robots_unavailable",
        403,
        "SCRAPE_ROBOTS_UNAVAILABLE",
        "The site's robots.txt could not be read",
    ),
    fc(
        "render_failed",
        500,
        "SCRAPE_ALL_ENGINES_FAILED",
        "Rendering the page failed",
    ),
    fc(
        "action_failed",
        500,
        "SCRAPE_ACTION_ERROR",
        "A page action failed",
    ),
    fc(
        "unsupported_content",
        500,
        "SCRAPE_UNSUPPORTED_FILE_ERROR",
        "The content type is not supported",
    ),
    fc(
        "extract_failed",
        500,
        "SCRAPE_EXTRACT_ERROR",
        "The page could not be extracted",
    ),
    fc(
        "llm_not_configured",
        503,
        "SCRAPE_LLM_NOT_CONFIGURED",
        "No LLM endpoint is configured for the json, summary, question, highlights and query formats",
    ),
    fc("llm_failed", 500, "SCRAPE_LLM_ERROR", "The LLM format failed"),
    fc(
        "prompt_injection_detected",
        403,
        "SCRAPE_PROMPT_INJECTION_DETECTED",
        "The page contains a prompt injection attempt",
    ),
    fc(
        "no_cached_data",
        404,
        "SCRAPE_NO_CACHED_DATA",
        "No cached data is available for this URL (minAge)",
    ),
    fc(
        "lockdown_cache_miss",
        404,
        "SCRAPE_LOCKDOWN_CACHE_MISS",
        "No cached data is available and lockdown forbids fetching",
    ),
    fc(
        "stored_body_unavailable",
        410,
        "STORED_BODY_UNAVAILABLE",
        "Stored response body unavailable",
    ),
    fc(
        "cache_identity_unavailable",
        503,
        "CACHE_IDENTITY_UNAVAILABLE",
        "Credential-bearing cache identity requires an operator key",
    ),
    fc(
        "run_stopped",
        500,
        "SCRAPE_CANCELLED",
        "The scrape run was cancelled",
    ),
    fc(
        "abandoned",
        500,
        "SCRAPE_CANCELLED",
        "The scrape run was cancelled",
    ),
    fc("failed", 500, "SCRAPE_ALL_ENGINES_FAILED", "Scrape failed"),
];

/// The row of [`FAILURE_CODES`] for `reason`. The URL plane of native crawls words some reasons
/// itself: `http_<status>` (the site answered an error status) is `SCRAPE_SITE_ERROR`, `dns` is
/// the DNS row and `timeout` the timeout row; any other unknown reason is
/// `SCRAPE_ALL_ENGINES_FAILED`.
#[must_use]
pub fn failure_code(reason: &str) -> FailureCode {
    let key = match reason {
        "dns" => "dns_failed",
        "timeout" => "scrape_timeout",
        r if r.starts_with("http_") => {
            return fc(
                "http_error",
                500,
                "SCRAPE_SITE_ERROR",
                "The site answered with an error status",
            )
        }
        r => r,
    };
    FAILURE_CODES
        .iter()
        .find(|f| f.reason == key)
        .copied()
        .unwrap_or_else(|| fc("failed", 500, "SCRAPE_ALL_ENGINES_FAILED", "Scrape failed"))
}

/// The worker reason of the failed frontier row `row`: its denial reason, else one derived from
/// its status.
pub(crate) fn failure_reason(row: &FrontierEntry) -> &str {
    row.denial_reason.as_deref().unwrap_or(match row.status {
        FrontierStatus::Unreachable => "unreachable",
        FrontierStatus::RobotsBlocked => "robots_disallow",
        FrontierStatus::PolicyBlocked => "policy_blocked",
        FrontierStatus::Abandoned => "abandoned",
        _ => "failed",
    })
}

/// The text of a failure: what went wrong, the worker's own message when it journaled one, and
/// the reason.
pub(crate) fn failure_text(reason: &str, message: Option<&str>) -> String {
    let text = failure_code(reason).text;
    match message {
        Some(m) if !m.is_empty() => format!("{text}: {m} (reason: {reason})"),
        _ => format!("{text} (reason: {reason})"),
    }
}

/// Failure of the page of `row` as the Firecrawl response the caller sees. `message` is the
/// worker's `page.failed` text when it has one.
pub(crate) fn failure_error(row: &FrontierEntry, message: Option<&str>) -> HttpError {
    let reason = failure_reason(row);
    let f = failure_code(reason);
    let text = failure_text(reason, message);
    if f.status == 503 {
        return HttpError::backend_unavailable(f.code, text);
    }
    HttpError::compat(
        StatusCode::from_u16(f.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        f.code,
        text,
    )
}

/// What the worker journaled (`page.failed`) about the failed pages of a run, by URL: the
/// message and the time of the newest event.
pub(crate) type FailureIndex = BTreeMap<String, (Option<String>, crawlx_core::Timestamp)>;

/// The `page.failed` events of `run`.
pub(crate) async fn failure_index(state: &AppState, run: CrawlRunId) -> FailureIndex {
    let events = match state.repos.events.list_after(run, 0, 100_000).await {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(error = %e, %run, "could not read the run events");
            return FailureIndex::new();
        }
    };
    let mut index = FailureIndex::new();
    for e in events.iter().filter(|e| e.kind == "page.failed") {
        if let Some(url) = e.payload.get("url").and_then(Value::as_str) {
            let message = e
                .payload
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned);
            index.insert(url.to_owned(), (message, e.at));
        }
    }
    index
}

/// The Firecrawl error of the failed frontier row `row` of `run`.
pub(crate) fn row_failure(row: &FrontierEntry, index: &FailureIndex) -> HttpError {
    let message = index.get(row.url.url.as_str()).and_then(|(m, _)| m.as_deref());
    failure_error(row, message)
}

/// Why `run` produced no page: the frontier row of its seed mapped to a Firecrawl error.
pub(crate) async fn run_failure(state: &AppState, run: &CrawlRun) -> HttpError {
    let rows = match state.repos.frontier.list(run.id).await {
        Ok(r) => r,
        Err(e) => return e.into(),
    };
    let seed = rows
        .iter()
        .filter(|r| r.depth == 0)
        .min_by_key(|r| r.id)
        .or_else(|| rows.first());
    match seed {
        Some(row) => row_failure(row, &failure_index(state, run.id).await),
        None if run.status == RunStatus::Cancelled => HttpError::compat(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SCRAPE_CANCELLED",
            "The scrape run was cancelled",
        ),
        None => {
            tracing::error!(run = %run.id, status = run.status.as_str(), "scrape run ended without a page or a frontier row");
            HttpError::internal()
        }
    }
}

/// The first page (lowest frontier id) of `run`.
pub(crate) async fn first_page(state: &AppState, run: &CrawlRun) -> ApiResult<Option<PageRecord>> {
    Ok(sorted_pages(state, run, None).await?.into_iter().next())
}

/// `scheme://host` of the request as the client addressed it (`X-Forwarded-Proto` honoured);
/// empty without a `Host` header.
pub(crate) fn base_url(headers: &axum::http::HeaderMap) -> String {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    host.map_or_else(String::new, |h| format!("{proto}://{h}"))
}

/// Record the usage ledger row of a finished scrape (best effort); `run` is the run the scrape
/// created, `None` when a stored scrape answered.
pub(crate) async fn record_usage(
    state: &AppState,
    tenant: TenantId,
    run: Option<CrawlRunId>,
    status: &str,
    credits: u64,
    llm_tokens: u64,
) {
    let cost = Cost {
        credits,
        // the engine stores one total, so it is booked as prompt tokens
        tokens: TokenUsage {
            prompt_tokens: llm_tokens,
            completion_tokens: 0,
        },
    };
    usage::record(state, tenant, "scrape", run.map(|r| r.0), status, cost).await;
}

/// Exact numeric billing, independent of ZDR acknowledgement and operational content expiry.
pub(crate) async fn run_billing(
    state: &AppState,
    id: CrawlRunId,
    live: Option<&CrawlRun>,
) -> ApiResult<crawlx_core::repo::PageBilling> {
    if let Some(billing) = state.repos.pages.billing(id).await? {
        return Ok(billing);
    }
    let loaded;
    let run = match live {
        Some(run) => run,
        None => {
            loaded = state.repos.runs.get(id).await?;
            &loaded
        }
    };
    let pages = state.repos.pages.list(id).await?;
    let mut billing = crawlx_core::repo::PageBilling::default();
    for page in &pages {
        billing.pages = billing.pages.saturating_add(1);
        billing.credits = billing.credits.saturating_add(credits_for(run, page));
        if let Some(document) = ScrapeDocument::from_page_metadata(&page.metadata) {
            billing.llm_tokens = billing.llm_tokens.saturating_add(document.llm_tokens);
        }
    }
    Ok(billing)
}

/// Book a terminal crawl or batch run in the usage ledger once: the credits of every page it
/// stored. Later calls find the row and do nothing. Best effort like every ledger write.
pub async fn record_run_usage(state: &AppState, run: &CrawlRun) {
    record_metadata_usage_with_runtime(state, &crawlx_core::repo::RunMetadata::from(run), Some(run)).await;
}

/// Book numeric-only usage after the transient run configuration has expired.
pub(crate) async fn record_metadata_usage(state: &AppState, run: &crawlx_core::repo::RunMetadata) {
    record_metadata_usage_with_runtime(state, run, None).await;
}

async fn record_metadata_usage_with_runtime(
    state: &AppState,
    run: &crawlx_core::repo::RunMetadata,
    live: Option<&CrawlRun>,
) {
    if !run.status.is_terminal() {
        return;
    }
    match state.repos.intel.usage_by_ref(run.tenant, run.id.0).await {
        Ok(None) => {}
        Ok(Some(_)) => return,
        Err(e) => {
            tracing::warn!(error = %e, run = %run.id, "usage ledger read failed");
            return;
        }
    }
    let billing = match run_billing(state, run.id, live).await {
        Ok(billing) => billing,
        Err(error) => {
            tracing::warn!(%error, run = %run.id, "could not read finished run billing metadata");
            return;
        }
    };
    let endpoint = run.scrape_kind.map_or("crawl", |kind| kind.event_prefix());
    let cost = Cost {
        credits: billing.credits,
        tokens: TokenUsage {
            prompt_tokens: billing.llm_tokens,
            completion_tokens: 0,
        },
    };
    let status = match run.status {
        RunStatus::Completed => "completed",
        RunStatus::Cancelled => "cancelled",
        _ => "failed",
    };
    usage::record(state, run.tenant, endpoint, Some(run.id.0), status, cost).await;
}

/// The stored scrape that answers `parsed`'s cache options for `url` (`maxAge`, `minAge`,
/// `lockdown`), if cache reading applies: zero-data-retention requests and requests for
/// `changeTracking` (which compares a fresh fetch with the stored one) never read the cache
/// unless they are cache-only requests (`minAge`, `lockdown`).
async fn stored_scrape(
    state: &AppState,
    tenant: TenantId,
    url: &Url,
    parsed: &ParsedScrape,
) -> ApiResult<Option<PageRecord>> {
    let o = &parsed.options;
    let fresh_only = (parsed.zero_data_retention && !cache::cache_only(o))
        || (o.cache.is_none() && o.wants("changeTracking"));
    let needs_live_validation = o
        .cache
        .as_ref()
        .is_some_and(|p| !p.cache_only() && p.freshness != crawlx_core::cache::CacheFreshnessV1::Retained);
    if fresh_only || !parsed.headers.is_empty() || !cache::reads(o) || needs_live_validation {
        return Ok(None);
    }
    let canonical = Canonicalizer::canonicalize_url(url, &CanonicalizeOptions::default())
        .map_err(|e| HttpError::bad_request(vec![Detail::new("/url", "invalid_string", e.to_string())]))?;
    let artifacts = CacheArtifacts(state.repos.artifacts.as_ref());
    let acquisition = (o.cache.is_some() && !o.needs_browser())
        .then(crawlx_core::acquisition::AcquisitionPolicyV1::default);
    let result = if o.cache.as_ref().is_some_and(|p| p.development_replay) {
        cache::replay(
            state.repos.pages.as_ref(),
            state.repos.runs.as_ref(),
            &artifacts,
            tenant,
            &canonical,
            o,
            acquisition.as_ref(),
            CrawlRunId(uuid::Uuid::nil()),
            state.clock.now(),
        )
        .await
    } else {
        cache::lookup(
            state.repos.pages.as_ref(),
            state.repos.runs.as_ref(),
            &artifacts,
            tenant,
            &canonical,
            o,
            acquisition.as_ref(),
            CrawlRunId(uuid::Uuid::nil()),
            state.clock.now(),
        )
        .await
    };
    result.map_err(|error| match error {
        cache::CacheError::BodyUnavailable => HttpError::compat(
            StatusCode::GONE,
            "STORED_BODY_UNAVAILABLE",
            "Stored response body unavailable",
        ),
        cache::CacheError::Store(error) => error.into(),
        _ => HttpError::internal(),
    })
}

/// Scrape `url` with `parsed` for `principal`'s tenant: serve a stored scrape when the cache
/// options allow it (`minAge` and `lockdown` never fetch), otherwise run a [`JobKind::Scrape`]
/// run and wait for it. The usage ledger is updated.
///
/// # Errors
/// `503 llm_not_configured` when a format needs the LLM and none is configured; `404
/// SCRAPE_NO_CACHED_DATA` / `SCRAPE_LOCKDOWN_CACHE_MISS` for `minAge` / `lockdown` without a
/// stored scrape; everything [`create_scrape_run`] and [`wait_for_run`] answer; the Firecrawl
/// failure of the page ([`failure_error`]) when the run produced none.
pub(crate) async fn scrape_url(
    state: &AppState,
    principal: &Principal,
    url: &Url,
    parsed: &ParsedScrape,
    base: &str,
    warnings: &mut Vec<Warning>,
) -> ApiResult<Scraped> {
    let mut trusted = parsed.clone();
    trusted.options.cache_principal = Some(principal.key_id);
    trusted.options.cache_header_identity = None;
    trusted.options.cache_execution_context = None;
    let parsed = &trusted;
    if parsed.needs_llm()
        && !parsed
            .options
            .cache
            .as_ref()
            .is_some_and(|p| p.development_replay)
    {
        crate::intel::common::llm(state)?;
    }
    let o = &parsed.options;
    if let Some(page) = stored_scrape(state, principal.tenant, url, parsed).await? {
        let run = state.repos.runs.get(page.run).await?;
        let hit = document::CacheHit {
            cached_at: ts(page.fetched_at),
            options: parsed.options.clone(),
        };
        let (document, credits) = document::render(state, &run, &page, base, Some(&hit)).await;
        let tokens = ScrapeDocument::from_page_metadata(&page.metadata).map_or(0, |d| d.llm_tokens);
        record_usage(state, principal.tenant, None, "completed", credits, tokens).await;
        return Ok(Scraped {
            document,
            credits,
            created_run: None,
        });
    }
    if o.cache.is_none() && o.lockdown {
        // Firecrawl bills a lockdown cache miss one credit
        record_usage(state, principal.tenant, None, "failed", 1, 0).await;
        return Err(HttpError::compat(
            StatusCode::NOT_FOUND,
            "SCRAPE_LOCKDOWN_CACHE_MISS",
            "No cached data is available and lockdown forbids fetching",
        ));
    }
    if cache::cache_only(o) && (o.cache.is_none() || parsed.headers.is_empty()) {
        return Err(HttpError::compat(
            StatusCode::NOT_FOUND,
            "SCRAPE_NO_CACHED_DATA",
            "No cached data is available for this URL (minAge)",
        ));
    }
    let timeout = Duration::from_millis(u64::from(o.timeout_ms));
    let crawl = scrape_crawl(url.clone(), JobKind::Scrape, parsed, 1).map_err(HttpError::bad_request)?;
    let run = create_scrape_run(state, principal, crawl, warnings).await?;
    let run = wait_for_run(state, run.id, timeout + TIMEOUT_GRACE).await?;
    let Some(page) = first_page(state, &run).await? else {
        record_usage(state, principal.tenant, Some(run.id), "failed", 0, 0).await;
        return Err(run_failure(state, &run).await);
    };
    let (document, credits) = document::render(state, &run, &page, base, None).await;
    let tokens = ScrapeDocument::from_page_metadata(&page.metadata).map_or(0, |d| d.llm_tokens);
    record_usage(
        state,
        principal.tenant,
        Some(run.id),
        "completed",
        credits,
        tokens,
    )
    .await;
    Ok(Scraped {
        document,
        credits,
        created_run: Some(run.id),
    })
}

/// Scrape `url` for `tenant` with raw Firecrawl scrape `options` (an object; `null` means
/// defaults) and return the Firecrawl `data` object with its credits. Links to stored blobs are
/// relative to the API root.
///
/// # Errors
/// `400 BAD_REQUEST` for an invalid URL or options and the errors of the scrape itself
/// ([`create_scrape_run`], [`wait_for_run`], `503 llm_not_configured`, the page failure).
pub async fn scrape_one(
    state: &AppState,
    tenant: TenantId,
    url: &str,
    options: &Value,
) -> Result<ScrapeDone, HttpError> {
    let empty = serde_json::Map::new();
    let obj = match options {
        Value::Null => &empty,
        Value::Object(m) => m,
        _ => {
            return Err(HttpError::bad_request(vec![Detail::new(
                "/",
                "invalid_type",
                "scrape options must be an object",
            )]))
        }
    };
    let target = parse_target(url, "/url").map_err(|d| HttpError::bad_request(vec![d]))?;
    let parsed = parse_scrape_options(obj, "").map_err(HttpError::bad_request)?;
    let mut warnings = parsed.warnings.clone();
    let scraped = scrape_url(
        state,
        &service_principal(tenant),
        &target,
        &parsed,
        "",
        &mut warnings,
    )
    .await?;
    Ok(ScrapeDone {
        document: scraped.document,
        credits: scraped.credits,
    })
}

/// The URLs of the site at `url` for `tenant` with raw Firecrawl map `options` (`sitemap`,
/// `includeSubdomains`, `search`, `limit`, ...; an object, `null` means defaults), ranked by
/// `search` and cut to `limit`. One credit is booked in the usage ledger.
///
/// # Errors
/// `400 BAD_REQUEST` for an invalid URL or option and the errors of the map run
/// ([`create_scrape_run`], [`wait_for_run`], the failure of the seed page when nothing is listed).
pub async fn map_site(
    state: &AppState,
    tenant: TenantId,
    url: &str,
    options: &Value,
) -> Result<Vec<MapEntry>, HttpError> {
    crate::routes::compat_map::map_links(state, &service_principal(tenant), url, options).await
}
