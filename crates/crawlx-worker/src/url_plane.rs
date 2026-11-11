//! The static plane: seed, robots, sitemap, frontier,
//! fetch, extract, pages, links, counters. Single-threaded per run: leases come in
//! `(depth, id)` order and links are discovered in document order, so a rerun with the same
//! seed against the same site yields the same page set.
//!
//! Runs that carry a compatibility-API scrape job (`CreateCrawl::scrape`, not a `map`) hand every
//! page to the [`ScrapeEngine`]; `scrape_plane` holds that variant of the page loop.
//!
//! Dynamic sessions publish already-settled DOM through [`UrlPlaneRunner::record_browser_observation`].
//! This output lane never repeats primary acquisition; each rendition commits under its exact
//! frontier fence and originating session fence. Its receipt-only lease is separate from target
//! dispatch admission, so a graceful worker drain can retain an observation it already acquired.

#[path = "discovery.rs"]
mod discovery;
mod protocol_plane;
mod scrape_plane;

/// The configuration the URL plane of a run executes with, which decides what the run's
/// `robots.txt` gate honours (`safety.respectRobotsTxt` after the adaptation of the compatibility API's
/// `scrape` and `batch` jobs, which fetch exactly the URLs they are given).
pub(crate) fn effective_crawl(crawl: CreateCrawl) -> CreateCrawl {
    scrape_plane::adapt(crawl)
}

use crate::authorization::AuthorizationGuard;
use crate::counters::{Attempt, Plane, RunCounters};
use crate::error::WorkerError;
use crate::robots_gate::{RobotsDecision, RobotsGate};
use crate::routes::RouteLearner;
use crate::run::RunContext;
use crate::runtime::CpuPool;
use crate::scrape::ScrapeEngine;
use crate::surface::form_ai::FormAi;
use crate::surface::resume::{ResumeEntry, ResumeState};
use crate::surface::traffic_export::{Exchange, TrafficExporter};
use crawlx_core::config::{
    CrawlMode, KnownFile, OutputFormat, PageType, QueryPolicy, RetentionMode, SimilarityMode, SitemapMode,
};
use crawlx_core::counters::RunStatus;
use crawlx_core::counters::TerminalReason;
use crawlx_core::repo::{
    ArtifactStore, DiscoveryOutcome, EventRepo, FrontierEntry, FrontierRepo, FrontierStatus, PageRecord,
    PageRepo, RunRepo, Sensitivity,
};
use crawlx_core::secret::ArtifactSink;
use crawlx_core::traffic::REDACTED_PLACEHOLDER;
use crawlx_core::{CanonicalUrl, Clock, CrawlRunId, CreateCrawl, StoreError, TrustLane, WorkerId};
use crawlx_extract::endpoints::body::FORM_ACTION;
use crawlx_extract::endpoints::{Confidence, DiscoveryInput, DiscoveryOptions};
use crawlx_extract::form_fill::fill_form;
use crawlx_extract::kb::classify_discovered;
use crawlx_extract::secret_validation::{SecretValidators, Validity};
use crawlx_extract::secrets::{Location as SecretLocation, SecretToken};
use crawlx_extract::{DiscoveredEndpoint, Document, ExtractOptions, Extractor, SecretFinding};
use crawlx_fetch::{FetchError, FetchOptions, FetchResponse, Fetcher};
use crawlx_policy::robots::RobotsTxt;
use crawlx_policy::{Budget, BudgetKind, DenialReason, DenyRule, ScopePolicy, ScopeVerdict};
use crawlx_scheduler::HEARTBEAT_INTERVAL;
use crawlx_storage::LeaseRepo;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_url::content_similarity::Config as SimilarityConfig;
use crawlx_url::{
    parent_paths, CanonicalizeOptions, Canonicalizer, DedupeReason, Frontier, LinkSource, PushOutcome,
    SimilarityIndex, SitemapTraversal,
};
use parking_lot::Mutex;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Entries leased per round trip.
const BATCH: u32 = 16;
/// Poll interval while pending rows wait out a retry backoff.
const RETRY_WAIT: Duration = Duration::from_millis(50);
/// Poll interval while every unfinished row is leased to some worker (a live holder finishes it,
/// a dead one's lease expires and the reaper returns the row to `pending`).
const LEASE_WAIT: Duration = Duration::from_millis(500);

/// Borrow one live parent lease for every destination in a native continuation.
pub(crate) struct NativeHopAdmission<'a> {
    runner: &'a UrlPlaneRunner,
    entry: &'a FrontierEntry,
    fence: i64,
    session: Option<crawlx_core::session_binding::SessionBindingV1>,
}
impl<'a> NativeHopAdmission<'a> {
    fn new(runner: &'a UrlPlaneRunner, entry: &'a FrontierEntry) -> Result<Self, FetchError> {
        let fence = runner
            .held
            .lock()
            .get(&entry.id)
            .copied()
            .ok_or(FetchError::AcquisitionCancelled)?;
        Ok(NativeHopAdmission {
            runner,
            entry,
            fence,
            session: None,
        })
    }
    fn with_session(mut self, session: Option<crawlx_core::session_binding::SessionBindingV1>) -> Self {
        self.session = session;
        self
    }
    async fn authority(&self) -> Result<(), FetchError> {
        let held = self.runner.held.lock().get(&self.entry.id).copied();
        if held != Some(self.fence) {
            return Err(FetchError::AcquisitionCancelled);
        }
        let renewed = self
            .runner
            .deps
            .leases
            .heartbeat_frontier(self.runner.worker, &[(self.entry.id, self.fence)])
            .await
            .map_err(FetchError::OriginAdmission)?;
        if !renewed.contains(&self.entry.id) {
            return Err(FetchError::AcquisitionCancelled);
        }
        self.check_run_stop().await
    }

    /// Poll stop state without renewing the parent lease or changing its deadline.
    async fn check_run_stop(&self) -> Result<(), FetchError> {
        if self.runner.held.lock().get(&self.entry.id).copied() != Some(self.fence)
            || self.runner.authorization_lost().await
            || self
                .runner
                .deps
                .runs
                .get_metadata(self.runner.run)
                .await
                .map_err(FetchError::OriginAdmission)?
                .status
                == RunStatus::Cancelled
        {
            return Err(FetchError::AcquisitionCancelled);
        }
        Ok(())
    }
    async fn scope(&self, url: &Url, allow_leaf: bool) -> Result<CanonicalUrl, FetchError> {
        self.authority().await?;
        let canonical = self
            .runner
            .admit_native_scope(url, self.entry.depth, allow_leaf)
            .await?;
        // Never authorize a normalized URL and then send a different query or path.
        if canonical.url != *url {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(canonical)
    }
}
#[async_trait::async_trait]
impl crate::acquisition::HopAdmission for NativeHopAdmission<'_> {
    async fn admit(
        &self,
        url: &Url,
        options: &FetchOptions,
        budget: &mut crate::acquisition::AcquisitionBudgetV1,
        cancel: &CancellationToken,
    ) -> Result<(), FetchError> {
        let canonical = self.scope(url, options.method == http::Method::HEAD).await?;
        let decision = self
            .runner
            .robots
            .decide_hop_with_budget(
                crawlx_policy::robots::HopKind::Redirect,
                &canonical.url,
                options,
                budget,
                cancel,
                &RobotsHopAdmission {
                    parent: self,
                    destination: &canonical.url,
                },
            )
            .await?;
        if !matches!(decision, RobotsDecision::Allowed) {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(())
    }

    async fn check_authority(&self) -> Result<(), FetchError> {
        self.authority().await
    }

    async fn check_scope(&self, url: &Url) -> Result<(), FetchError> {
        self.authority().await?;
        if self.runner.prefetch.check(url).is_some()
            || !self.runner.scope.decide_protocol_resource(url).is_admitted()
        {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(())
    }

    fn requires_checked_hops(&self) -> bool {
        self.session.is_some()
    }

    async fn fetch_attempt(
        &self,
        fetcher: &Fetcher,
        url: &Url,
        options: &FetchOptions,
    ) -> Result<FetchResponse, FetchError> {
        match &self.session {
            Some(binding) => {
                let (sessions, authority) = self
                    .runner
                    .http_sessions
                    .as_ref()
                    .ok_or(FetchError::AcquisitionUnavailable)?;
                sessions
                    .fetch_once_with_authority(
                        crate::http_sessions::DEFAULT_HTTP_SESSION,
                        binding,
                        url,
                        options,
                        &|| self.authority(),
                        authority.as_ref(),
                    )
                    .await
                    .map_err(|error| match error {
                        crate::http_sessions::HttpSessionError::Fetch(error) => error,
                        _ => FetchError::AcquisitionUnavailable,
                    })
            }
            None => {
                fetcher
                    .fetch_once_with_authority(url, options, &|| self.authority())
                    .await
            }
        }
    }
}

/// A robots lookup may borrow only the exact origin already admitted for this hop.
struct RobotsHopAdmission<'a, 'b> {
    parent: &'a NativeHopAdmission<'b>,
    destination: &'a Url,
}

#[async_trait::async_trait]
impl crate::acquisition::HopAdmission for RobotsHopAdmission<'_, '_> {
    async fn admit(
        &self,
        url: &Url,
        options: &FetchOptions,
        budget: &mut crate::acquisition::AcquisitionBudgetV1,
        cancel: &CancellationToken,
    ) -> Result<(), FetchError> {
        self.parent.admit(url, options, budget, cancel).await
    }

    async fn check_authority(&self) -> Result<(), FetchError> {
        self.parent.authority().await
    }

    async fn check_scope(&self, url: &Url) -> Result<(), FetchError> {
        self.parent.authority().await?;
        if self.parent.runner.prefetch.check(url).is_some()
            || !self
                .parent
                .runner
                .scope
                .decide_robots_for_admitted_hop(url, self.destination)
                .is_admitted()
        {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(())
    }

    async fn fetch_attempt(
        &self,
        fetcher: &Fetcher,
        url: &Url,
        options: &FetchOptions,
    ) -> Result<FetchResponse, FetchError> {
        self.parent.fetch_attempt(fetcher, url, options).await
    }
}

/// Sitemap documents fetched per run (index recursion bound).
const MAX_SITEMAP_DOCUMENTS: usize = 64;
/// Distinct tokens validated per run (each is one request to an operator-listed provider).
const MAX_SECRET_VALIDATIONS: usize = 256;
/// Response bytes read from a validation endpoint.
const MAX_VALIDATION_BODY: usize = 64 * 1024;

struct PendingUrl {
    resume: ResumeEntry,
    is_get: bool,
}

/// What the URL plane knows about its own progress, as [`ResumeState`] is built from it.
#[derive(Default)]
struct ResumeLedger {
    /// Fetched by an earlier run ([`UrlPlaneRunner::seed_resume`]): never discovered again.
    carried: BTreeSet<String>,
    /// Fetched by this run or an earlier one.
    visited: BTreeSet<String>,
    /// Admitted and not fetched yet, by frontier row id.
    pending: BTreeMap<i64, PendingUrl>,
}

/// Repositories the static plane writes.
#[derive(Clone)]
pub struct UrlPlaneDeps {
    /// Runs.
    pub runs: Arc<dyn RunRepo>,
    /// Frontier.
    pub frontier: Arc<dyn FrontierRepo>,
    /// Atomic fenced request/item/state/outbox result transactions.
    pub request_commits: Arc<dyn crawlx_core::orchestration::RequestCommitRepo>,
    /// Tenant/source/role/policy-scoped source metadata; ZDR stays volatile.
    pub source_memo: Arc<dyn crawlx_core::dataset::memo::SourceMemoRepo>,
    /// URL batch lease renewal (`LeaseRepo::heartbeat_frontier`): the plane renews the rows it
    /// holds while a batch is in flight.
    pub leases: Arc<dyn LeaseRepo>,
    /// Pages.
    pub pages: Arc<dyn PageRepo>,
    /// Events.
    pub events: Arc<dyn EventRepo>,
    /// Artifacts.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Tenant-scoped compatible retained archive baselines.
    pub archives: Arc<dyn crawlx_core::archive_catalog::ArchiveRepo>,
    /// Clock.
    pub clock: Arc<dyn Clock>,
}

/// What the static plane concluded.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct UrlPlaneOutcome {
    /// Terminal.
    pub terminal: TerminalReason,
    /// Pages written.
    pub pages_written: u64,
    /// Admitted client-rendered requests recovered from committed page evidence.
    /// Redirect locations never replace the owning durable handler identity.
    pub dynamic_requests: Vec<crawlx_core::request::RequestEnvelopeV1>,
}

/// Why a page was flagged for the browser plane (`DynamicSignals`), in the order
/// the classifier tests them. Thresholds are planning defaults tuned on the labelled
/// mini-corpus in this module's tests (recall ≥ 0.95, false promotion ≤ 0.20).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum DynamicSignal {
    /// The path matches an explicit `dynamic.alwaysBrowserPaths` rule.
    AlwaysBrowserPath,
    /// `<div id="app">`/`root`/`__next`/`__nuxt` with almost no text.
    SpaRoot,
    /// Client-framework bootstrap markers (`__NEXT_DATA__`, `__NUXT__`, `data-reactroot`,
    /// `ng-version`, `data-server-rendered`, `data-sveltekit`, `wire:id`, ...).
    FrameworkMarkers,
    /// A `<noscript>` block telling the user to enable JavaScript.
    NoscriptFallback,
    /// Inline script drives client-side routing with `history.pushState`/`replaceState`.
    PushStateRouting,
    /// Almost no extracted text next to a substantial script payload.
    EmptyTextHeavyScript,
    /// Three or more `<script type="module">`.
    ModuleScripts,
    /// Two or more `href="#/…"` / `href="#!/…"` links.
    HashRoutes,
    /// Inline scripts issue several `fetch`/`XMLHttpRequest`/`$.ajax` calls or use common HTTP client libraries.
    XhrHeavy,
    /// Many interactive controls relative to the amount of text (an application screen).
    InteractiveControlsHeavy,
}

impl DynamicSignal {
    #[must_use]
    /// As str.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysBrowserPath => "always_browser_path",
            Self::SpaRoot => "spa_root",
            Self::FrameworkMarkers => "framework_markers",
            Self::NoscriptFallback => "noscript_fallback",
            Self::PushStateRouting => "pushstate_routing",
            Self::EmptyTextHeavyScript => "empty_text_heavy_script",
            Self::ModuleScripts => "module_scripts",
            Self::HashRoutes => "hash_routes",
            Self::XhrHeavy => "xhr_heavy",
            Self::InteractiveControlsHeavy => "interactive_controls_heavy",
        }
    }
}

/// Word count under which a SPA root or framework shell counts as "almost no text".
const SPA_ROOT_MAX_WORDS: usize = 30;
/// Word count under which a script-heavy page counts as empty.
const EMPTY_TEXT_MAX_WORDS: usize = 50;
/// Inline script bytes that make a payload "substantial".
const HEAVY_INLINE_SCRIPT_BYTES: usize = 4096;
/// External scripts that make a payload "substantial".
const HEAVY_EXTERNAL_SCRIPTS: usize = 3;
/// Minimum interactive controls for the control-density signal.
const CONTROLS_MIN: usize = 25;
/// Words per control above which a page is a document, not an application screen.
const WORDS_PER_CONTROL_MAX: usize = 10;
/// Inline XHR/fetch call sites that make a page XHR-heavy.
const XHR_MIN: usize = 3;

struct SignalPatterns {
    root: Regex,
    framework: Regex,
    noscript: Regex,
    push_state: Regex,
    inline_script: Regex,
    external_script: Regex,
    module: Regex,
    hash: Regex,
    xhr: Regex,
    control: Regex,
    hidden_input: Regex,
}

/// Compiled once; `None` only if a literal pattern fails to compile (a programming error
/// surfaced as "no signal" rather than a panic).
static PATTERNS: std::sync::LazyLock<Option<SignalPatterns>> = std::sync::LazyLock::new(|| {
    Some(SignalPatterns {
        root: Regex::new(r#"(?i)<div[^>]*\bid\s*=\s*["'](app|root|__next|__nuxt)["']"#).ok()?,
        framework: Regex::new(
            r#"(?i)__NEXT_DATA__|__NUXT__|window\.__INITIAL_STATE__|data-reactroot|\bng-version\s*=|data-server-rendered|data-sveltekit|\bwire:id\s*=|ember-application|data-react-helmet"#,
        )
        .ok()?,
        noscript: Regex::new(r"(?is)<noscript[^>]*>(.*?)</noscript>").ok()?,
        push_state: Regex::new(r"(?i)\bhistory\.(pushState|replaceState)\s*\(|\bonpopstate\b").ok()?,
        inline_script: Regex::new(r"(?is)<script(?:\s[^>]*)?>(.*?)</script>").ok()?,
        external_script: Regex::new(r#"(?i)<script[^>]*\bsrc\s*=\s*["']?[^"'\s>]+"#).ok()?,
        module: Regex::new(r#"(?i)<script[^>]*\btype\s*=\s*["']?module\b"#).ok()?,
        hash: Regex::new(r##"(?i)\bhref\s*=\s*["']#!?/"##).ok()?,
        xhr: Regex::new(r"(?i)\bfetch\s*\(|new\s+XMLHttpRequest\b|\baxios\s*[.(]|\$\.ajax\s*\(|\$\.(get|post)\s*\(") // wire-compat: script markers matched on target pages
            .ok()?,
        control: Regex::new(
            r#"(?i)<(button|select|textarea|input)\b|\brole\s*=\s*["']?(button|tab|menuitem|switch|checkbox|combobox)\b|\bonclick\s*=|\bcontenteditable\b"#,
        )
        .ok()?,
        hidden_input: Regex::new(r#"(?i)<input[^>]*\btype\s*=\s*["']?hidden\b"#).ok()?,
    })
});

fn patterns() -> Option<&'static SignalPatterns> {
    PATTERNS.as_ref()
}

/// Heuristic SPA/application markers on a fetched document (`word_count` of the extracted
/// main text); the explicit `alwaysBrowserPaths` rule is applied by [`DynamicClassifier`].
#[must_use]
pub fn classify_dynamic(html: &str, word_count: usize) -> Option<DynamicSignal> {
    let p = patterns()?;
    if p.root.is_match(html) && word_count < SPA_ROOT_MAX_WORDS {
        return Some(DynamicSignal::SpaRoot);
    }
    if p.framework.is_match(html) {
        return Some(DynamicSignal::FrameworkMarkers);
    }
    if p.noscript.captures_iter(html).any(|c| {
        c.get(1)
            .is_some_and(|m| m.as_str().to_ascii_lowercase().contains("javascript"))
    }) {
        return Some(DynamicSignal::NoscriptFallback);
    }
    let inline_bytes: usize = p
        .inline_script
        .captures_iter(html)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().len())
        .sum();
    let inline_text: String = p
        .inline_script
        .captures_iter(html)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if p.push_state.is_match(&inline_text) {
        return Some(DynamicSignal::PushStateRouting);
    }
    let external = p.external_script.find_iter(html).count();
    if word_count < EMPTY_TEXT_MAX_WORDS
        && (inline_bytes >= HEAVY_INLINE_SCRIPT_BYTES || external >= HEAVY_EXTERNAL_SCRIPTS)
    {
        return Some(DynamicSignal::EmptyTextHeavyScript);
    }
    if p.module.find_iter(html).count() >= 3 {
        return Some(DynamicSignal::ModuleScripts);
    }
    if p.hash.find_iter(html).count() >= 2 {
        return Some(DynamicSignal::HashRoutes);
    }
    if p.xhr.find_iter(&inline_text).count() >= XHR_MIN {
        return Some(DynamicSignal::XhrHeavy);
    }
    let controls = p
        .control
        .find_iter(html)
        .count()
        .saturating_sub(p.hidden_input.find_iter(html).count());
    if controls >= CONTROLS_MIN && word_count < controls.saturating_mul(WORDS_PER_CONTROL_MAX) {
        return Some(DynamicSignal::InteractiveControlsHeavy);
    }
    None
}

/// Decides URL-to-browser promotion: the explicit `alwaysBrowserPaths` rule
/// first, then [`classify_dynamic`].
pub struct DynamicClassifier {
    always: Option<crawlx_url::PathFilter>,
}

impl DynamicClassifier {
    /// Compile the crawl's `dynamic.alwaysBrowserPaths`.
    ///
    /// # Errors
    /// A pattern that does not compile under the scope-pattern limits.
    pub fn new(always_browser_paths: &[String]) -> Result<Self, WorkerError> {
        let always = if always_browser_paths.is_empty() {
            None
        } else {
            Some(crawlx_url::PathFilter::new(always_browser_paths, &[])?)
        };
        Ok(Self { always })
    }

    /// `true` when `path` matches an explicit rule.
    #[must_use]
    pub fn always_browser(&self, path: &str) -> bool {
        self.always.as_ref().is_some_and(|f| f.matches_include(path))
    }

    /// Signal for a fetched page, if any.
    #[must_use]
    pub fn classify(&self, path: &str, html: &str, word_count: usize) -> Option<DynamicSignal> {
        if self.always_browser(path) {
            return Some(DynamicSignal::AlwaysBrowserPath);
        }
        classify_dynamic(html, word_count)
    }
}

/// How a frontier URL was found (the request tag/attribute/source triple), kept in memory
/// per frontier id and written to `pages.metadata.request` when the page is fetched.
#[derive(Clone, Debug)]
struct RequestSource {
    tag: &'static str,
    attribute: &'static str,
    source: String,
}

/// Why a fetched page is not expanded further (`pages.metadata.dedupe`).
enum Dedupe {
    Exact,
    Similar(Option<String>),
}

/// Headers whose values are credentials by construction; they feed the extractors (the
/// secrets detector reports them by kind and hash) but never `pages.metadata`.
const CREDENTIAL_HEADERS: [&str; 7] = [
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "www-authenticate",
    "x-api-key",
    "x-auth-token",
];

/// Response headers as `(lowercase name, value)` for the extractors.
pub(crate) fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect()
}

fn response_body_capture_metadata(response: &FetchResponse) -> Option<serde_json::Value> {
    let header = |name: &str| response.headers.get(name).and_then(|value| value.to_str().ok());
    let outcome = header("x-crawlx-stream-body-capture")?;
    Some(serde_json::json!({
        "mode": header("x-crawlx-stream-body-mode"),
        "outcome": outcome,
        "truncated": header("x-crawlx-stream-body-truncated") == Some("true"),
        "limit": header("x-crawlx-stream-body-limit").and_then(|value| value.parse::<u64>().ok()),
        "artifact": response.retained_response_body(),
    }))
}

/// `pages.metadata.response_headers`: credential headers omitted, any header the secrets
/// detector flagged replaced by `[redacted]`, and any header that echoes a
/// configured request header or cookie value (`fetch.extraHeaders`, `fetch.cookies`) too.
pub(crate) fn headers_json(
    pairs: &[(String, String)],
    flagged: &BTreeSet<&str>,
    controls: &crawlx_core::request_controls::RequestControls,
) -> serde_json::Value {
    let map: BTreeMap<&str, &str> = pairs
        .iter()
        .filter(|(n, _)| !CREDENTIAL_HEADERS.contains(&n.as_str()))
        .map(|(n, v)| {
            let value = if flagged.contains(n.as_str()) || controls.echoes_secret(v) {
                "[redacted]"
            } else {
                v.as_str()
            };
            (n.as_str(), value)
        })
        .collect();
    serde_json::json!(map)
}

/// Optional publication attached to one atomically completed request.
#[derive(Default)]
struct RequestPublication {
    outbox: Vec<crawlx_core::dataset::DeliveryBatchV1>,
    page: Option<PageRecord>,
    head_response: Option<serde_json::Value>,
    content_dedupe: Option<crawlx_core::digest_registry::ContentDedupeClaimV1>,
    local_dedupe: Option<crawlx_extract::DedupeCommit>,
}

/// Bind an opted-in, privacy-finalized content digest to its actual run representation.
///
/// # Errors
/// Refuses missing caller scope or an invalid content digest contract.
pub(crate) fn content_dedupe_claim(
    tenant: crawlx_core::TenantId,
    run: CrawlRunId,
    scope: Option<&crawlx_extract::DedupeHandle>,
    document: &Document,
) -> Result<Option<crawlx_core::digest_registry::ContentDedupeClaimV1>, WorkerError> {
    let Some(article) = document.article.as_ref().filter(|article| {
        article.quality.status == crawlx_core::extraction::QualityStatusV1::Accepted
            && article.privacy_projection_version == Some(1)
            && article
                .dedupe
                .as_ref()
                .is_some_and(|dedupe| dedupe.content_sha256.is_some())
    }) else {
        return Ok(None);
    };
    let scope = scope.ok_or_else(|| StoreError::Unavailable("content dedupe scope unavailable".into()))?;
    let representation = crawlx_core::hash::Digest::of_value(
        "crawlx/content-dedupe-representation/v1",
        &(scope.scope().tenant(), scope.scope().role()),
    )
    .map_err(|error| StoreError::Serialization(error.to_string()))?;
    crawlx_core::digest_registry::ContentDedupeClaimV1::from_document(tenant, run, representation, article)
        .map(Some)
        .map_err(WorkerError::from)
}

/// Runs the static plane of one crawl.
pub struct UrlPlaneRunner {
    run: CrawlRunId,
    // Builder steps move the runner; the request must not inflate every move and poll frame.
    crawl: Box<CreateCrawl>,
    worker: WorkerId,
    deps: UrlPlaneDeps,
    fetcher: Arc<Fetcher>,
    http_sessions: Option<(
        Arc<crate::http_sessions::NamedHttpSessions>,
        Arc<dyn crate::http_sessions::HttpSessionAuthority>,
    )>,
    scope: ScopePolicy,
    canon: CanonicalizeOptions,
    /// Learns sibling route slots from admitted URLs into `canon.templater`.
    routes: RouteLearner,
    /// `robots.txt` obedience: the decision and the cache the run's planes share.
    robots: RobotsGate,
    counters: RunCounters,
    budget: Mutex<Budget>,
    extract: ExtractOptions,
    prefetch: crawlx_url::UrlExclusionFilter,
    content_dedupe: Arc<std::sync::Mutex<crawlx_core::extraction::DedupeCache>>,
    /// Durable workers publish digest claims; local workers commit staged cache admission.
    durable_dedupe: bool,
    /// In-memory admission filter mirroring the durable frontier: canonical keys seen,
    /// URL-shape fingerprint budget, per-host page limit, exact-content dedupe.
    frontier: Mutex<Frontier>,
    similarity: Option<Mutex<SimilarityIndex>>,
    secrets_key: Option<[u8; 32]>,
    sources: Mutex<BTreeMap<i64, RequestSource>>,
    classifier: DynamicClassifier,
    protocol_routes: crawlx_core::protocol::CompiledProtocolRoutes,
    protocol_runtime: Result<Option<Arc<crate::protocol::ProtocolRuntime>>, String>,
    request_identity_key: Option<crawlx_core::secret::SecretOr<[u8; 32]>>,
    pages_written: Mutex<u64>,
    cpu_pool: CpuPool,
    /// Actual run-owned dynamic secret registry; absence denies item persistence.
    captcha_secrets: Option<crawlx_core::captcha::CaptchaSecrets>,
    /// Actual browser resource sensor, absent when no run browser pool was supplied.
    admission_browser: Option<crate::pool::BrowserPool>,
    /// Published only after its versioned decision has reached the event trail.
    admission_ceiling: std::sync::atomic::AtomicU32,
    /// The scrape engine of a compatibility-API scrape job (`crawl`, `batch` or `scrape`); `None` for
    /// every other run, whose pages are fetched and extracted as usual.
    pub(crate) scrape: Option<ScrapeEngine>,
    protocol_browser: Option<ScrapeEngine>,
    /// Decides the form fields the deterministic filler left open (`extract.formFill`).
    form_ai: Option<Arc<dyn FormAi>>,
    /// Provider endpoints that validate detected tokens; `Some` exactly under
    /// `extract.validateSecrets`.
    validators: Option<Arc<SecretValidators>>,
    /// Verdicts already obtained, by `(kind, keyed token hash)`: one request per distinct
    /// token per run. The token itself is never kept.
    validated: Mutex<BTreeMap<(&'static str, String), Validity>>,
    /// Receives one exchange per page fetch and redirect hop.
    traffic: Option<Arc<TrafficExporter>>,
    /// What [`Self::resume_state`] reports.
    ledger: Mutex<ResumeLedger>,
    /// State handed to [`Self::seed_resume`], consumed by [`Self::seed`].
    resume_seed: Mutex<Option<ResumeState>>,
    /// The run's authorization guard: the record's target is part of `scope`, its revocation or
    /// expiry stops the plane ([`Self::with_authorization`]).
    authorization: Option<Arc<AuthorizationGuard>>,
    /// Explicit worker/local graceful shutdown signal, never an authorization or lease-loss stop.
    graceful_drain: Option<CancellationToken>,
    /// Independent caller cancellation; it must still interrupt a response after drain starts.
    hard_cancel: Option<CancellationToken>,
    /// The rows this plane holds a lease on, by row id, with the fencing token of each lease:
    /// leased by [`Self::run`], renewed by its heartbeat while a batch is in flight, gone once
    /// the row is finished, handed back or found lost. A row not in here is never completed.
    held: Mutex<BTreeMap<i64, i64>>,
}

impl UrlPlaneRunner {
    /// Publish one already-settled browser document without acquiring it again.
    ///
    /// Browser sessions retain interaction and dataset authority. This lane only parses
    /// their immutable observation and stores page renditions under an observed-only row.
    /// It never seeds URL work or charges HTTP-plane counters.
    ///
    /// # Errors
    /// Returns extraction, retention, cancellation or exact URL-lease failures.
    pub(crate) async fn record_browser_observation(
        &self,
        rc: &RunContext,
        session: &crawlx_core::repo::CrawlSession,
        request: &crawlx_core::request::RequestEnvelopeV1,
        bundle: &crawlx_core::observation::ObservationBundle,
        response: crawlx_core::page_op::PageOpResult,
    ) -> Result<Vec<Url>, WorkerError> {
        if self.crawl.mode != CrawlMode::Dynamic || rc.run != self.run {
            return Err(WorkerError::Config(
                "browser output requires its dynamic run".into(),
            ));
        }
        let html = bundle
            .html
            .as_ref()
            .ok_or_else(|| WorkerError::Config("settled browser document HTML unavailable".into()))?;
        let (status, headers, content_type) = match response {
            crawlx_core::page_op::PageOpResult::Response {
                status,
                headers,
                content_type,
            } => (status, headers, content_type),
            _ => {
                return Err(WorkerError::Config(
                    "browser document response unavailable".into(),
                ))
            }
        };
        let run = self.deps.runs.get(self.run).await?;
        if rc.hard_cancel.is_cancelled()
            || run.status == RunStatus::Cancelled
            || self.authorization_lost().await
        {
            return Err(StoreError::LeaseLost.into());
        }
        // Navigation already passed the browser guard. Re-evaluate output scope without
        // adding another robots request on backends that deliberately model no guard.
        let denial = match self.prefetch.check(&request.url.url) {
            Some(reason) => Some(reason.code().to_owned()),
            None => match self.scope.decide(&request.url, request.depth) {
                ScopeVerdict::Denied(reason) => Some(denial_label(&reason)),
                _ => None,
            },
        };
        let discovery_only = self.discovery_only(&request.url, request.depth, None).is_some();
        if denial.is_some() && !discovery_only {
            return Ok(Vec::new());
        }
        if !self.scope.decide(&bundle.url, request.depth).is_admitted() && !discovery_only {
            return Ok(Vec::new());
        }
        let mut options = self.extract.clone();
        options.status = status.unwrap_or(0);
        options.headers = headers.clone();
        options.content_type = content_type.clone();
        options
            .language_detector
            .clone_from(&rc.article_language_detector);
        options.acquisition_validation = Some(crate::acquisition::context(
            &self.crawl.acquisition.clone().unwrap_or_default(),
            status,
            false,
        ));
        if options
            .content
            .as_ref()
            .is_some_and(|policy| policy.dedupe.is_some())
        {
            let representation = crawlx_core::hash::Digest::of_value(
                "crawlx/browser-extraction-scope/v1",
                &(&session.role, session.id),
            )
            .map_err(|error| WorkerError::Config(error.to_string()))?;
            let (namespace, cache) = if self.durable_dedupe {
                let epoch = crawlx_core::hash::Digest::of_value(
                    "crawlx/browser-extraction-document/v1",
                    &(session.id, bundle.url.key, bundle.epoch),
                )
                .map_err(|error| WorkerError::Config(error.to_string()))?;
                (
                    format!("{}:{}", self.run, epoch.to_hex()),
                    Arc::new(std::sync::Mutex::new(crawlx_core::extraction::DedupeCache::new(
                        65_536,
                    )?)),
                )
            } else {
                (self.run.to_string(), Arc::clone(&self.content_dedupe))
            };
            options.dedupe_cache = Some(crawlx_extract::DedupeHandle::new(
                crawlx_core::extraction::DedupeScopeV1::new(
                    &run.tenant.to_string(),
                    &namespace,
                    &representation.to_hex(),
                )?,
                cache,
            ));
        }
        let dedupe_scope = options.dedupe_cache.clone();
        let body = html.as_bytes().to_vec();
        let base = bundle.url.url.clone();
        let controls = rc.controls.clone();
        let captcha = rc.captcha_secrets.clone();
        let secrets_key = self.secrets_key;
        let validate_tokens = self.validators.is_some();
        let (mut document, secret_pairs) = self
            .cpu_pool
            .run(move || {
                let secret_pairs: Vec<(SecretFinding, Option<SecretToken>)> = match secrets_key {
                    Some(key) if validate_tokens => Extractor::detect_secret_tokens(
                        &key,
                        &options.headers,
                        &String::from_utf8_lossy(&body),
                    )
                    .into_iter()
                    .map(|(finding, token)| (finding, Some(token)))
                    .collect(),
                    Some(key) => {
                        Extractor::detect_secrets(&key, &options.headers, &String::from_utf8_lossy(&body))
                            .into_iter()
                            .map(|finding| (finding, None))
                            .collect()
                    }
                    None => Vec::new(),
                };
                let redactor = crawlx_core::secret::Redactor::new();
                let projected = redactor.scrub_bytes(&body, controls.secret_values());
                let text = String::from_utf8_lossy(&projected);
                let projected = captcha.redact_if_present(&text).map_err(|_| {
                    StoreError::RetentionDenied("browser DOM secret projection unavailable".into())
                })?;
                let document = crate::acquisition::extract_document_with_secrets(
                    projected.as_bytes(),
                    &base,
                    &options,
                    &controls,
                    &captcha,
                )?;
                Ok::<_, WorkerError>((Box::new(document), secret_pairs))
            })
            .await
            .map_err(WorkerError::BrowserExtractionTask)??;
        let dedupe_commit = document.dedupe_commit.take();
        let (secrets, tokens): (Vec<_>, Vec<_>) = secret_pairs.into_iter().unzip();
        let mut links: BTreeMap<String, Url> = document
            .links
            .iter()
            .filter_map(|link| Canonicalizer::canonicalize_url(&link.url, &self.canon).ok())
            .map(|url| (url.url.to_string(), url.url))
            .collect();
        let mut hook_urls = Vec::new();
        for (raw, source) in &bundle.discovered_urls {
            let redactor = crawlx_core::secret::Redactor::new();
            let projected = redactor.scrub_bytes(raw.as_bytes(), rc.controls.secret_values());
            let projected = String::from_utf8_lossy(&projected);
            let projected = rc.captcha_secrets.redact_if_present(&projected).map_err(|_| {
                StoreError::RetentionDenied("browser URL secret projection unavailable".into())
            })?;
            if let Ok(url) = bundle.url.url.join(&projected) {
                if matches!(url.scheme(), "http" | "https") {
                    if let Ok(url) = Canonicalizer::canonicalize_url(&url, &self.canon) {
                        hook_urls.push((url.url.to_string(), source.clone()));
                        links.insert(url.url.to_string(), url.url);
                    }
                }
            }
        }
        if discovery_only {
            return Ok(links.into_values().collect());
        }
        let session_lease = crawlx_core::custody::current_producer()
            .filter(|lease| {
                lease.run == self.run
                    && lease.tenant == run.tenant
                    && lease.worker == self.worker
                    && matches!(&lease.source, crawlx_core::custody::CustodySource::Session(id)
                    if *id == session.id)
            })
            .ok_or(StoreError::LeaseLost)?;
        let observed = self
            .deps
            .request_commits
            .append_observed_fenced(crawlx_core::orchestration::ObservedRequestV1::new(
                session_lease.clone(),
                bundle.epoch,
                request.clone(),
                bundle.captured_at,
            ))
            .await?;
        let (id, revisit_generation) = match observed {
            crawlx_core::orchestration::ObservedAppendV1::Appended {
                request_id,
                revisit_generation,
            } => (request_id, revisit_generation),
            crawlx_core::orchestration::ObservedAppendV1::Duplicate {
                request_id,
                revisit_generation,
            } => (request_id, revisit_generation),
            crawlx_core::orchestration::ObservedAppendV1::CapReached => {
                self.deps
                    .events
                    .append(
                        self.run,
                        "browser.page",
                        serde_json::json!({
                            "outcome": crawlx_core::orchestration::ObservedAppendV1::CapReached,
                            "reason": "revisit_cap_reached",
                            "sessionId": session.id,
                            "url": request.url.url.as_str(),
                            "epoch": bundle.epoch,
                        }),
                    )
                    .await?;
                return Ok(links.into_values().collect());
            }
            _ => return Err(StoreError::AccessDenied("unsupported observed append outcome".into()).into()),
        };
        let Some((entry, fence)) = self
            .deps
            .request_commits
            .lease_observed_fenced(&session_lease, bundle.epoch, id)
            .await?
        else {
            // A recovered session may replay an already-committed append receipt.
            // Only immutable capture custody proves that this is completed output.
            let committed = self
                .deps
                .pages
                .committed_page_keyset(self.run, id.saturating_sub(1), 1)
                .await?;
            if committed
                .first()
                .is_some_and(|page| page.frontier_id == id && page.url.url == request.url.url)
            {
                return Ok(links.into_values().collect());
            }
            return Err(StoreError::LeaseLost.into());
        };
        let queued = self.deps.frontier.get_request(self.run, id).await?;
        if entry.id != id
            || entry.url.url != request.url.url
            || queued.envelope.route != request.route
            || queued.identity.revisit_generation != revisit_generation
        {
            self.deps.frontier.give_back(entry.id, fence).await?;
            return Err(StoreError::Conflict("browser page lease identity mismatch".into()).into());
        }
        self.held.lock().insert(entry.id, fence);
        // Preserve the session's caller-hard-stop and abort veto under this URL fence.
        let mut producer = session_lease.clone();
        producer.source = crawlx_core::custody::CustodySource::Url(entry.id);
        producer.fence = fence;
        let publication = async {
            let validations = self.validate_secrets(&secrets, tokens).await;
            let browser_build = self
                .deps
                .runs
                .list_sessions(self.run)
                .await?
                .into_iter()
                .find(|stored| stored.id == session.id)
                .and_then(|stored| stored.browser);
            let backend = browser_build.map_or_else(
                || {
                    crawlx_core::acquisition::BackendCapabilitiesV1::native_browser_unavailable(
                        "browser_build_evidence_unavailable",
                    )
                },
                crawlx_core::acquisition::BackendCapabilitiesV1::native_browser,
            );
            let mut primary = crawlx_core::acquisition::AcquisitionResultV1::new(
                self.run,
                run.tenant,
                request.url.url.clone(),
                queued.identity.key,
                backend,
            );
            primary.representation = crawlx_core::acquisition::RepresentationV1::RenderedDom;
            primary.session = Some(session.id);
            primary.final_url = Some(bundle.url.url.clone());
            primary.final_url_evidence = crawlx_core::acquisition::UrlEvidenceV1::Observed;
            primary.target_status = status;
            primary.content_type.clone_from(&content_type);
            primary.transport_succeeded = status.is_some();
            primary.extraction_succeeded = Some(true);
            primary.decoded_bytes = u64::try_from(html.len()).unwrap_or(u64::MAX);
            primary.validation = document
                .validation
                .clone()
                .unwrap_or_else(crawlx_core::acquisition::ValidationOutcomeV1::indeterminate);
            primary.backend.limitations.extend([
                "browser_primary_dispatch_counts_unobserved".to_owned(),
                "browser_wire_bytes_unobserved".to_owned(),
                "decoded_allowance_counts_serialized_dom".to_owned(),
            ]);
            let mut record = PageRecord {
                run: self.run,
                frontier_id: entry.id,
                url: request.url.clone(),
                status: status.unwrap_or(0),
                content_type,
                content_digest: document.raw_html_digest,
                title: None,
                markdown: None,
                html: None,
                metadata: serde_json::json!({
                    "final_url": bundle.url.url.as_str(),
                    "response_headers": headers_json(&headers, &BTreeSet::new(), &rc.controls),
                    "acquisition": primary,
                }),
                links: Vec::new(),
                fetched_at: bundle.captured_at,
                lane: TrustLane::Diagnostic,
            };
            self.fill_record(&mut record, &document, &bundle.url.url).await;
            if !secrets.is_empty() {
                let mut findings = serde_json::json!(secrets);
                if let Some(items) = findings.as_array_mut() {
                    for (item, validation) in items.iter_mut().zip(&validations) {
                        if let Some(validation) = validation {
                            item["validation"] = serde_json::json!(validation);
                        }
                    }
                }
                record.metadata["secrets"] = findings;
            }
            record.metadata["endpointDiscovery"] = serde_json::json!({
                "unresolved": document.discovery_unresolved,
                "unresolvedDropped": document.discovery_unresolved_dropped,
            });
            if self.crawl.extract.kb_endpoints {
                record.metadata["endpoints"] = classify_endpoints(&document.discovered_endpoints);
            }
            let recorded: Vec<_> = document
                .discovered_endpoints
                .iter()
                .filter(|endpoint| endpoint.method != http::Method::GET || endpoint.body.is_some())
                .map(|endpoint| {
                    serde_json::json!({
                        "url": endpoint.url.as_str(),
                        "method": endpoint.method.as_str(),
                        "tag": endpoint.source.tag,
                        "attribute": endpoint.source.attribute,
                        "body": endpoint.body,
                        "content_type": endpoint.content_type,
                        "headers": endpoint.headers,
                        "confidence": endpoint.confidence,
                    })
                })
                .collect();
            if !recorded.is_empty() {
                record.metadata["discovered_endpoints"] = serde_json::json!(recorded);
            }
            record.metadata["browser"] = serde_json::json!({
                "representation": "settled_rendered_dom",
                "sessionId": session.id,
                "role": session.role,
                "epoch": bundle.epoch,
                "settle": bundle.settle,
                "statusAvailable": status.is_some(),
                "route": request.route,
                "revisitGeneration": revisit_generation,
                "canonical": revisit_generation == 0,
            });
            // Hook evidence remains provenance, never action authority.
            record.metadata["browser"]["discoveredUrls"] = serde_json::json!(hook_urls);
            for link in links.keys() {
                if !record.links.contains(link) {
                    record.links.push(link.clone());
                }
            }
            record.links.sort();
            let has_previews = document
                .outputs
                .as_ref()
                .and_then(|outputs| outputs.link_media.as_ref())
                .is_some_and(|media| !media.previews.is_empty());
            let has_article_hops = self.crawl.scope.discovery.is_some()
                && document
                    .article
                    .as_ref()
                    .is_some_and(|article| !article.discovery.is_empty());
            if has_previews || has_article_hops {
                let policy = self.crawl.acquisition.clone().unwrap_or_default();
                let mut auxiliary = if self.crawl.acquisition.is_some() && !self.crawl.cache_only() {
                    let allowance = self
                        .deps
                        .frontier
                        .reserve_acquisition_fenced(self.run, entry.id, fence)
                        .await?;
                    crate::acquisition::AcquisitionBudgetV1::from_allowance(&policy, &allowance)?
                } else {
                    crate::acquisition::AcquisitionBudgetV1::new(&policy)?
                };
                let primary = record.metadata["acquisition"].clone();
                Box::pin(self.follow_article_intents(
                    &entry,
                    &document,
                    html.as_bytes(),
                    &mut record,
                    Some(&mut auxiliary),
                    &rc.cancel,
                ))
                .await?;
                // Auxiliary HTTP receipts never replace the settled browser representation.
                record.metadata["acquisition"] = primary;
                record.metadata["browser_auxiliary_budget"] = serde_json::json!(auxiliary.usage());
                self.settle_native_allowance(&entry, Some(&auxiliary)).await?;
            }
            if self.crawl.extract.xhr {
                let requests = rc.xhr.requests_for(&bundle.url.key);
                if !requests.is_empty() {
                    record.metadata["xhr_requests"] = serde_json::json!(requests);
                }
            }
            rc.captcha_secrets
                .redact_json(&mut record.metadata)
                .map_err(|_| {
                    StoreError::RetentionDenied("browser page secret projection unavailable".into())
                })?;
            if rc.hard_cancel.is_cancelled()
                || self.authorization_lost().await
                || self.held.lock().get(&entry.id).copied() != Some(fence)
            {
                return Err(WorkerError::Store(StoreError::LeaseLost));
            }
            let mut commit = crawlx_core::orchestration::RequestCommitV1::terminal(
                self.run,
                entry.id,
                fence,
                queued.state_version,
                FrontierStatus::Succeeded,
                None,
            );
            commit.page = Some(record);
            if self.durable_dedupe {
                commit.content_dedupe =
                    content_dedupe_claim(run.tenant, self.run, dedupe_scope.as_ref(), &document)?;
            }
            match self
                .deps
                .request_commits
                .commit_observed_fenced(commit, session_lease.clone(), bundle.epoch)
                .await?
            {
                crawlx_core::orchestration::ObservedCommitV1::Committed => {}
                _ => {
                    return Err(StoreError::AccessDenied("unsupported observed commit outcome".into()).into())
                }
            }
            if !self.durable_dedupe {
                if let Some(commit) = dedupe_commit {
                    commit.record();
                }
            }
            let mut written = self.pages_written.lock();
            *written = written.saturating_add(1);
            Ok::<(), WorkerError>(())
        };
        let publication = crawlx_core::custody::with_producer(producer, Box::pin(publication));
        let result = tokio::select! {
            result = publication => result,
            heartbeat = self.keep_browser_page_alive(entry.id, fence) => match heartbeat {
                Ok(never) => match never {},
                Err(error) => Err(error),
            },
        };
        self.held.lock().remove(&entry.id);
        if result.is_err() {
            // Parsing never grants another browser acquisition. Return only this exact row.
            let _ = self.deps.frontier.give_back(entry.id, fence).await;
        }
        result?;
        Ok(links.into_values().collect())
    }

    /// Keep local browser auxiliary traffic on the same admitted governor and capture path.
    pub(crate) fn rebind_browser_fetcher(&mut self, fetcher: Arc<Fetcher>, durable_dedupe: bool) {
        self.robots = self.robots.with_fetcher(Arc::clone(&fetcher));
        self.fetcher = fetcher;
        self.durable_dedupe = durable_dedupe;
    }

    /// Select fenced registry authority instead of local two-phase cache admission.
    #[must_use]
    pub fn with_durable_dedupe(mut self, durable: bool) -> Self {
        self.durable_dedupe = durable;
        self
    }

    /// Renew only this publication's exact row; a lost fence cancels its auxiliary work.
    async fn keep_browser_page_alive(
        &self,
        id: i64,
        fence: i64,
    ) -> Result<std::convert::Infallible, WorkerError> {
        let period = lease_heartbeat_period(self.deps.leases.url_batch_ttl());
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let renewed = self
                .deps
                .leases
                .heartbeat_frontier(self.worker, &[(id, fence)])
                .await?;
            if !renewed.contains(&id) {
                return Err(StoreError::LeaseLost.into());
            }
        }
    }
}

impl UrlPlaneRunner {
    /// New.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub fn new(
        run: CrawlRunId,
        crawl: CreateCrawl,
        worker: WorkerId,
        deps: UrlPlaneDeps,
        fetcher: Arc<Fetcher>,
        counters: RunCounters,
        canon: CanonicalizeOptions,
    ) -> Result<Self, WorkerError> {
        let crawl = scrape_plane::adapt(crawl);
        if let Some(policy) = &crawl.acquisition {
            policy
                .validate()
                .map_err(|e| WorkerError::Config(e.to_string()))?;
            crawl
                .protocol
                .validate_acquisition(policy)
                .map_err(|e| WorkerError::Config(e.to_string()))?;
            crawlx_extract::validation::compile_policy(&policy.validation)
                .map_err(|e| WorkerError::Config(e.to_string()))?;
            crawl
                .validate_meta_refresh()
                .map_err(|error| WorkerError::Config(error.to_string()))?;
            if crawl.scrape.is_none()
                && policy.backend_ids.iter().any(|id| id != "native_http")
                && !crawl
                    .protocol
                    .routes
                    .iter()
                    .any(|route| route.backend == crawlx_core::protocol::ProtocolBackendV1::Browser)
            {
                return Err(WorkerError::Config(
                    "native browser acquisition requires a scrape job or an explicit browser protocol route"
                        .to_owned(),
                ));
            }
        }
        let scope = ScopePolicy::new(&crawl)?;
        let exclusion = crawl
            .extract
            .content
            .as_ref()
            .and_then(|policy| policy.excluded_urls.as_ref())
            .map(crawlx_url::UrlExclusionFilter::from_policy)
            .transpose()
            .map_err(|error| WorkerError::Config(error.to_string()))?
            .unwrap_or_default();
        let prefetch = exclusion;
        let content_dedupe = Arc::new(std::sync::Mutex::new(crawlx_core::extraction::DedupeCache::new(
            65_536,
        )?));
        let budget = Budget::new(&crawl.limits, deps.clock.now())
            .with_max_pages_per_host(crawl.scope.max_pages_per_host);
        // one gate decides for this plane and, through `with_surface_services`, for the run's
        // browser plane too
        let robots = RobotsGate::for_crawl(&crawl, Arc::clone(&fetcher), Arc::clone(&deps.clock));
        let custom_fields =
            crawlx_extract::custom_fields::CustomField::compile_all(&crawl.extract.custom_fields)
                .map_err(|e| WorkerError::Config(format!("extract.customFields: {e}")))?;
        DiscoveryOptions {
            javascript_mode: crawl.extract.javascript.mode,
            ..DiscoveryOptions::default()
        }
        .validate()
        .map_err(|e| WorkerError::Config(e.to_string()))?;
        let mut extract = ExtractOptions {
            only_main_content: crawl.output.only_main_content,
            include_tags: crawl.output.include_tags.clone(),
            exclude_tags: crawl.output.exclude_tags.clone(),
            discover_endpoints: true,
            javascript_mode: crawl.extract.javascript.mode,
            custom_fields,
            forms: crawl.extract.forms || crawl.extract.form_fill.enabled,
            page_type: crawl.extract.page_type,
            content: crawl.extract.content.clone(),
            ..ExtractOptions::default()
        };
        crate::acquisition::configure_extract(&mut extract, &crawl.extract)?;
        if extract.decode.is_none() {
            extract.decode = crawl
                .fetch
                .declaration
                .as_ref()
                .and_then(|policy| policy.charset.as_deref())
                .map(crawlx_extract::decode::DecodeOptions::with_charset);
        }
        crate::acquisition::fetch_options(&crawl.fetch)
            .declaration
            .validate()?;
        let mut frontier = Frontier::new()
            .with_max_depth(u32::from(crawl.scope.max_discovery_depth))
            .with_strategy(crawl.scope.strategy)
            .with_content_dedupe(!crawl.scope.disable_unique_filter);
        if crawl.scope.filter_similar {
            frontier = frontier.with_similar_filter(
                crawl.scope.filter_similar_threshold,
                crawl.scope.filter_similar_budget,
            );
        }
        if let Some(max) = crawl.scope.max_pages_per_host {
            frontier = frontier.with_max_pages_per_host(max);
        }
        let similarity = (crawl.scope.content_similarity.mode != SimilarityMode::Off).then(|| {
            Mutex::new(SimilarityIndex::new(SimilarityConfig::from_request(
                &crawl.scope.content_similarity,
            )))
        });
        let secrets_key = crawl
            .extract
            .detect_secrets
            .then(|| crawl.effective_seed().derive("secrets", &[]));
        let validators = (crawl.extract.detect_secrets && crawl.extract.validate_secrets)
            .then(|| Arc::new(SecretValidators::builtin()));
        let classifier = DynamicClassifier::new(&crawl.dynamic.always_browser_paths)?;
        let scrape = ScrapeEngine::for_run(run, &crawl, &deps, Arc::clone(&fetcher))
            .map(|engine| engine.with_robots_gate(robots.clone()));
        let protocol_browser = if scrape.is_none()
            && crawl
                .protocol
                .routes
                .iter()
                .any(|route| route.backend == crawlx_core::protocol::ProtocolBackendV1::Browser)
        {
            let mut browser_crawl = crawl.clone();
            browser_crawl.scrape = Some(crawlx_core::scrape::ScrapeJob::new(
                crawlx_core::scrape::JobKind::Crawl,
                crawlx_core::scrape::ScrapeOptions::default(),
            ));
            ScrapeEngine::for_run(run, &browser_crawl, &deps, Arc::clone(&fetcher))
                .map(|engine| engine.with_robots_gate(robots.clone()))
        } else {
            None
        };
        if let Some(orchestration) = &crawl.orchestration {
            orchestration.validate()?;
            fetcher.governor().set_pacing_dialect(
                orchestration.pacing_dialect,
                u32::from(crawl.politeness.max_in_flight_per_origin.max(1)),
            );
        }
        let admission_hard_limit = BATCH.min(u32::from(crawl.politeness.max_concurrency.max(1)));
        let protocol_routes = crawl
            .protocol
            .compile()
            .map_err(|e| WorkerError::Config(e.to_string()))?;
        Ok(Self {
            run,
            crawl: Box::new(crawl),
            worker,
            deps,
            fetcher,
            http_sessions: None,
            scope,
            routes: RouteLearner::new(Arc::clone(&canon.templater)),
            canon,
            robots,
            counters,
            budget: Mutex::new(budget),
            extract,
            prefetch,
            content_dedupe,
            durable_dedupe: false,
            frontier: Mutex::new(frontier),
            similarity,
            secrets_key,
            sources: Mutex::new(BTreeMap::new()),
            classifier,
            protocol_routes,
            protocol_runtime: Ok(None),
            request_identity_key: None,
            pages_written: Mutex::new(0),
            cpu_pool: CpuPool::default(),
            captcha_secrets: None,
            admission_browser: None,
            admission_ceiling: std::sync::atomic::AtomicU32::new(admission_hard_limit),
            scrape,
            protocol_browser,
            form_ai: None,
            validators,
            validated: Mutex::new(BTreeMap::new()),
            traffic: None,
            ledger: Mutex::new(ResumeLedger::default()),
            resume_seed: Mutex::new(None),
            authorization: None,
            graceful_drain: None,
            hard_cancel: None,
            held: Mutex::new(BTreeMap::new()),
        })
    }

    /// Bind the plane to the run's authorization record: every URL it discovers
    /// must lie inside the record's target (`policy_blocked: authorization_scope` otherwise), and
    /// a record that is revoked, expired or removed ends the run with
    /// [`TerminalReason::AuthorizationRevoked`]: the batch in hand is abandoned like a cancelled
    /// one. `None` leaves the plane unbound.
    #[must_use]
    pub fn with_authorization(mut self, guard: Option<Arc<AuthorizationGuard>>) -> Self {
        self.scrape = self
            .scrape
            .take()
            .map(|engine| engine.with_authorization(guard.clone()));
        self.protocol_browser = self
            .protocol_browser
            .take()
            .map(|engine| engine.with_authorization(guard.clone()));
        if let Some(guard) = guard {
            self.scope = self.scope.with_record_scope(guard.scope());
            self.authorization = Some(guard);
        }
        self
    }

    /// Identify graceful shutdown separately from hard caller or authorization cancellation.
    ///
    /// Only static coordinators finish an already-started response during drain. Hybrid
    /// cancellation also represents role-lease loss, so unfinished work is handed back instead.
    /// Supply the independent hard caller token for local runs; queued API stops use run state.
    #[must_use]
    pub fn with_graceful_drain(
        mut self,
        drain: CancellationToken,
        hard_cancel: Option<CancellationToken>,
    ) -> Self {
        self.graceful_drain = Some(drain);
        self.hard_cancel = hard_cancel;
        self
    }

    fn is_draining(&self) -> bool {
        self.crawl.mode == CrawlMode::Static && self.shutdown_checkpoint_requested()
    }

    /// Handing back an unfinished URL is not permission to finish its response. A hybrid
    /// role-lease loss may coincide with worker shutdown; only its next fenced owner may retry.
    fn shutdown_checkpoint_requested(&self) -> bool {
        self.graceful_drain
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
            && !self
                .hard_cancel
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
    }

    fn stop_requested(&self, cancel: &CancellationToken) -> bool {
        cancel.is_cancelled()
            || self
                .graceful_drain
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            || self
                .hard_cancel
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
    }

    /// Has the run lost its authorization record? Re-reads the record at most once per recheck
    /// interval; a run without a record never has.
    async fn authorization_lost(&self) -> bool {
        match &self.authorization {
            Some(guard) => guard.check_now().await.is_err(),
            None => false,
        }
    }

    /// Run the extraction step on `pool` (the worker's shared CPU pool) instead of a
    /// pool private to this runner.
    #[must_use]
    pub fn with_cpu_pool(mut self, pool: CpuPool) -> Self {
        self.cpu_pool = pool;
        self
    }

    /// Route strict HTTP generations through an already registered, fenced session manager.
    /// The authority must verify the original live lease; request metadata never creates a jar.
    #[must_use]
    pub fn with_http_sessions(
        mut self,
        sessions: Arc<crate::http_sessions::NamedHttpSessions>,
        authority: Arc<dyn crate::http_sessions::HttpSessionAuthority>,
    ) -> Self {
        self.set_http_sessions(sessions, authority);
        self
    }

    /// Attach the coordinator's manager without moving its already-owned URL runner.
    pub(crate) fn set_http_sessions(
        &mut self,
        sessions: Arc<crate::http_sessions::NamedHttpSessions>,
        authority: Arc<dyn crate::http_sessions::HttpSessionAuthority>,
    ) {
        self.http_sessions = Some((sessions, authority));
    }

    async fn strict_http_binding(
        &self,
        queued: &crawlx_core::orchestration::QueuedRequestV1,
    ) -> Result<Option<crawlx_core::session_binding::SessionBindingV1>, FetchError> {
        let Some(generation) = queued.envelope.session_generation else {
            return Ok(None);
        };
        let (sessions, authority) = self
            .http_sessions
            .as_ref()
            .ok_or(FetchError::AcquisitionUnavailable)?;
        let binding = sessions
            .binding(crate::http_sessions::DEFAULT_HTTP_SESSION)
            .map_err(|_| FetchError::AcquisitionUnavailable)?;
        let run = self
            .deps
            .runs
            .get_metadata(self.run)
            .await
            .map_err(FetchError::OriginAdmission)?;
        if binding.generation != generation
            || binding.identity.tenant != run.tenant
            || binding.identity.run != self.run
            || binding.identity.principal.0 != queued.principal
        {
            return Err(FetchError::AcquisitionUnavailable);
        }
        authority.verify(&binding).await?;
        Ok(Some(binding))
    }

    /// Share the run's route learner (what the browser plane feeds too) instead of a
    /// learner private to this runner.
    #[must_use]
    pub fn with_route_learner(mut self, routes: RouteLearner) -> Self {
        self.routes = routes;
        self
    }

    /// Use the run's operator-level services: the traffic exporter, the form-field decider
    /// and the secret validators (replacing the embedded list, which lists no provider).
    #[must_use]
    pub fn with_surface_services(mut self, rc: &RunContext) -> Self {
        self.traffic.clone_from(&rc.traffic_export);
        self.request_identity_key = rc.request_identity_key.clone();
        self.captcha_secrets = Some(rc.captcha_secrets.clone());
        self.content_dedupe = Arc::clone(&rc.extract_dedupe);
        self.durable_dedupe = rc.durable_dedupe;
        self.protocol_runtime = rc
            .protocol_registry
            .as_ref()
            .map(|registry| {
                crate::protocol::ProtocolRuntime::new(
                    Arc::clone(registry),
                    &rc.egress,
                    &rc.crawl,
                    rc.authorization.as_deref().map(|guard| guard.record()),
                    Arc::clone(self.fetcher.governor()),
                )
                .map(Arc::new)
            })
            .transpose()
            .map_err(|e| e.to_string());
        self.admission_browser = Some(rc.pool.clone());
        // the browser plane's navigations and this plane's frontier share one `robots.txt` cache
        self.robots = rc.robots.with_fetcher(Arc::clone(&self.fetcher));
        self.scrape = self
            .scrape
            .take()
            .map(|engine| engine.with_robots_gate(self.robots.clone()));
        self.protocol_browser = self
            .protocol_browser
            .take()
            .map(|engine| engine.with_robots_gate(self.robots.clone()));
        self.form_ai.clone_from(&rc.form_ai);
        if let (Some(operator), Some(_)) = (&rc.secret_validators, &self.validators) {
            self.validators = Some(Arc::clone(operator));
        }
        self
    }

    /// Continue a stopped run (the `-resume` compatibility flag): the URLs in `state.visited` are never
    /// fetched or discovered again, and [`Self::seed`] discovers `state.pending` at its
    /// depths instead of enumerating sitemaps and robots paths again.
    ///
    /// # Errors
    /// Refuses an unsupported state version or a corrupt, oversized or foreign-tenant dedupe
    /// snapshot before changing the frontier, ledger or shared extraction cache.
    pub async fn seed_resume(&self, state: &ResumeState) -> Result<(), crate::surface::resume::ResumeError> {
        use crate::surface::resume::{ResumeError, RESUME_VERSION};
        if state.version != RESUME_VERSION {
            return Err(ResumeError::Version { found: state.version });
        }
        if let Some(snapshot) = &state.dedupe {
            let tenant = self.deps.runs.get(self.run).await?.tenant;
            let mut cache = self
                .content_dedupe
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let restored = crawlx_core::extraction::DedupeCache::restore(
                snapshot,
                cache.capacity(),
                &tenant.to_string(),
                &self.run.to_string(),
            )?;
            *cache = restored;
        }
        let mut ledger = self.ledger.lock();
        ledger.carried.extend(state.visited.iter().cloned());
        ledger.visited.extend(state.visited.iter().cloned());
        drop(ledger);
        *self.resume_seed.lock() = Some(state.clone());
        Ok(())
    }

    /// URL-only GET continuation: fetched/carried URLs and pending GET requests.
    ///
    /// Method-aware requests resume from durable frontier envelopes instead. This
    /// projection omits HEAD rather than reconstructing it as GET.
    ///
    /// # Errors
    /// Returns the source storage error when the authoritative current run cannot be read.
    pub async fn resume_state(&self) -> Result<ResumeState, crate::surface::resume::ResumeError> {
        let tenant = self.deps.runs.get(self.run).await?.tenant;
        let ledger = self.ledger.lock();
        let mut state = ResumeState::new(
            ledger.visited.iter().cloned(),
            ledger
                .pending
                .values()
                .filter(|entry| entry.is_get)
                .map(|entry| entry.resume.clone()),
        );
        drop(ledger);
        let cache = self
            .content_dedupe
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Empty caches need no tenant binding, preserving legacy URL-only resume behavior.
        if !cache.is_empty() {
            state.dedupe = Some(cache.snapshot(&tenant.to_string(), &self.run.to_string()));
        }
        Ok(state)
    }

    /// Pages written so far.
    #[must_use]
    pub fn pages_written(&self) -> u64 {
        *self.pages_written.lock()
    }

    /// Dedupe counts by reason (`fingerprint`, `content_exact`, `content_similar`, ...).
    #[must_use]
    pub fn dedupe_counts(&self) -> BTreeMap<DedupeReason, u64> {
        self.frontier.lock().dedupe_counts().clone()
    }

    fn canonicalize(&self, url: &Url) -> Option<(CanonicalUrl, bool)> {
        Canonicalizer::canonicalize_detailed(url.as_str(), url, &self.canon)
            .ok()
            .map(|c| (c.url, c.action_bearing))
    }

    // ---- robots -------------------------------------------------------------------------

    /// The shared robots decision ([`RobotsGate::decide`]): the browser plane asks the same
    /// gate before it loads a document.
    async fn robots_decision(&self, url: &CanonicalUrl) -> RobotsDecision {
        if self.crawl.cache_only() {
            return RobotsDecision::Blocked("robots_unobserved_replay");
        }
        self.robots.decide(&url.origin, &url.url).await
    }

    // ---- discovery ----------------------------------------------------------------------

    /// Scope, robots, the in-memory admission filter, then `FrontierRepo::discover`.
    /// Counts the discovery; dedupe refusals (`fingerprint`) are recorded on the frontier
    /// as `policy_blocked` rows with a `dedupe:` reason and counted as `deduplicated`. The
    /// `reason` label of a policy block is the bounded denial code (never the pattern the
    /// frontier row carries).
    async fn discover(
        &self,
        url: CanonicalUrl,
        depth: u16,
        from: Option<i64>,
        action_bearing: bool,
        source: Option<RequestSource>,
    ) -> Result<DiscoveryOutcome, StoreError> {
        if self.ledger.lock().carried.contains(url.url.as_str()) {
            // a stopped run already fetched it (`seed_resume`)
            self.counters
                .discovery_with_reason(Plane::Urls, DiscoveryOutcome::Duplicate, "resume_visited");
            return Ok(DiscoveryOutcome::Duplicate);
        }
        let (denial, counted_as, code) = self.discovery_admission(&url, depth, from, action_bearing).await;
        let (mut outcome, id) = if let Some(parent) = from {
            let fence = self
                .held
                .lock()
                .get(&parent)
                .copied()
                .ok_or(StoreError::LeaseLost)?;
            let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
            let request = crawlx_core::request::RequestEnvelopeV1::get(url.clone(), depth, from);
            // A canonical key alone can recur with different envelopes or admission outcomes.
            // Bind retries to their full content and live parent fence; identity dedupe stays in storage.
            let batch_id = crawlx_core::hash::Digest::of_value(
                "crawlx/child-discovery/v1",
                &(tenant, self.run, (parent, fence), &request, &denial),
            )
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
            let outcome = match &denial {
                Some((FrontierStatus::RobotsBlocked, _)) => DiscoveryOutcome::RobotsBlocked,
                Some(_) => DiscoveryOutcome::PolicyBlocked,
                None => DiscoveryOutcome::Admitted,
            };
            let mut batch = crawlx_core::orchestration::RequestBatchV1::new(
                tenant,
                self.run,
                "anonymous".into(),
                batch_id,
                vec![request],
            );
            batch.parent_fence = Some((parent, fence));
            batch.initial_denial = denial;
            let receipt = self.deps.frontier.append_batch(batch).await?;
            if let Some(id) = receipt.inserted.first() {
                (outcome, Some(*id))
            } else {
                (DiscoveryOutcome::Duplicate, None)
            }
        } else {
            self.deps
                .frontier
                .discover(self.run, &url, depth, None, denial)
                .await?
        };
        if let (DiscoveryOutcome::Admitted, Some(id)) = (outcome, id) {
            let mut ledger = self.ledger.lock();
            // An identical child batch replays its original inserted ids. A later
            // sighting is still a duplicate, not a second admission or pending entry.
            if ledger.pending.contains_key(&id) || ledger.visited.contains(url.url.as_str()) {
                outcome = DiscoveryOutcome::Duplicate;
            } else {
                ledger.pending.insert(
                    id,
                    PendingUrl {
                        resume: ResumeEntry::new(url.url.to_string(), depth),
                        is_get: true,
                    },
                );
            }
        }
        let counted = match (outcome, counted_as) {
            (DiscoveryOutcome::PolicyBlocked, Some(as_)) => as_,
            (o, _) => o,
        };
        self.counters.discovery_with_reason(Plane::Urls, counted, code);
        if let (DiscoveryOutcome::Admitted, Some(id), Some(src)) = (outcome, id, source) {
            self.sources.lock().insert(id, src);
        }
        if outcome == DiscoveryOutcome::Admitted {
            if let Some(snapshot) = self.routes.observe(url.url.path()) {
                if let Err(e) = RouteLearner::persist(self.deps.events.as_ref(), self.run, &snapshot).await {
                    tracing::warn!(error = %e, "route templates not persisted");
                }
            }
        }
        Ok(outcome)
    }

    /// The single admission gate used by legacy discovery and atomic source loaders.
    async fn discovery_admission(
        &self,
        url: &CanonicalUrl,
        depth: u16,
        from: Option<i64>,
        action_bearing: bool,
    ) -> (
        Option<(FrontierStatus, String)>,
        Option<DiscoveryOutcome>,
        &'static str,
    ) {
        if let Some(reason) = self.prefetch.check(&url.url) {
            return (
                Some((FrontierStatus::PolicyBlocked, reason.code().into())),
                None,
                reason.code(),
            );
        }
        let known = {
            let ledger = self.ledger.lock();
            ledger.pending.len().saturating_add(ledger.visited.len())
        };
        if known >= usize::try_from(self.crawl.scope.max_known_urls).unwrap_or(usize::MAX) {
            return (
                Some((FrontierStatus::PolicyBlocked, "known_url_limit".into())),
                None,
                "known_url_limit",
            );
        }
        if action_bearing {
            return (
                Some((FrontierStatus::PolicyBlocked, "action_bearing_query".into())),
                None,
                "action_bearing_query",
            );
        }
        let discovery_only = self.discovery_only(url, depth, from).is_some();
        let verdict = if discovery_only {
            ScopeVerdict::Admitted { leaf_only: false }
        } else {
            self.scope.decide(url, depth)
        };
        match verdict {
            ScopeVerdict::Denied(reason) => (
                Some((FrontierStatus::PolicyBlocked, denial_label(&reason))),
                None,
                reason.as_str(),
            ),
            ScopeVerdict::Admitted { leaf_only: true } if !self.scope.fetch_leaves() => (
                Some((FrontierStatus::PolicyBlocked, "leaf_only".into())),
                None,
                "leaf_only",
            ),
            ScopeVerdict::Admitted { .. } => {
                if !self.crawl.cache_only() {
                    match self.robots_decision(url).await {
                        RobotsDecision::Allowed => {}
                        RobotsDecision::Blocked(reason) => {
                            return (
                                Some((FrontierStatus::RobotsBlocked, reason.into())),
                                None,
                                "robots",
                            );
                        }
                        RobotsDecision::EgressDenied => {
                            return (
                                Some((FrontierStatus::PolicyBlocked, "egress_denied".into())),
                                None,
                                "egress_denied",
                            );
                        }
                    }
                }
                if discovery_only {
                    return (None, None, crate::counters::UNSPECIFIED_REASON);
                }
                let mut mirror = self.frontier.lock();
                match mirror.push(url.clone(), u32::from(depth), LinkSource::Body, None) {
                    PushOutcome::Admitted => {
                        let _ = mirror.pop();
                        (None, None, crate::counters::UNSPECIFIED_REASON)
                    }
                    PushOutcome::Duplicate => (None, None, crate::counters::UNSPECIFIED_REASON),
                    PushOutcome::FilteredSimilar => (
                        Some((FrontierStatus::PolicyBlocked, "dedupe:fingerprint".into())),
                        Some(DiscoveryOutcome::Duplicate),
                        "dedupe",
                    ),
                    PushOutcome::HostPageLimit => (
                        Some((
                            FrontierStatus::PolicyBlocked,
                            DenialReason::HostPageLimit.as_str().into(),
                        )),
                        None,
                        DenialReason::HostPageLimit.as_str(),
                    ),
                    PushOutcome::DepthExceeded => {
                        let reason = DenialReason::DepthExceeded {
                            depth,
                            max: self.crawl.scope.max_discovery_depth,
                        }
                        .as_str();
                        (Some((FrontierStatus::PolicyBlocked, reason.into())), None, reason)
                    }
                    PushOutcome::ExtensionFiltered => (
                        Some((
                            FrontierStatus::PolicyBlocked,
                            DenialReason::ExtensionFiltered.as_str().into(),
                        )),
                        None,
                        DenialReason::ExtensionFiltered.as_str(),
                    ),
                }
            }
        }
    }

    /// [`Self::seed`] unless the frontier already holds rows (a resumed run, whose
    /// admission filter and budgets are rebuilt from the durable rows: the pages already
    /// fetched stay charged to `limits.urls` and `scope.maxPagesPerHost`, and
    /// `limits.durationSeconds` counts from the start of the run, not of this worker).
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn seed_if_empty(&self) -> Result<(), WorkerError> {
        let mut existing = self.deps.frontier.page(self.run, 0, 1000).await?;
        let finite =
            self.crawl.orchestration.as_ref().is_none_or(|cfg| {
                cfg.queue.producer_mode == crawlx_core::orchestration::ProducerModeV1::Finite
            });
        if existing.is_empty() {
            self.seed().await?;
            if finite {
                self.deps.frontier.seal(self.run, 1).await?;
            }
            return Ok(());
        }
        // the previous holder may have died after it finished rows and before it flushed the
        // counters: the frontier rows are authoritative, so the stored snapshot is
        // re-derived and flushed before this plane leases its first batch
        let repaired = self
            .counters
            .recover_from_frontier(self.deps.frontier.as_ref(), self.deps.runs.as_ref(), self.run)
            .await?;
        if repaired > 0 {
            tracing::info!(run = %self.run, repaired, "url counters re-derived from the frontier");
        }
        let row = self.deps.runs.get_metadata(self.run).await?;
        let mut budget = Budget::new(&self.crawl.limits, row.started_at.unwrap_or(row.created_at))
            .with_max_pages_per_host(self.crawl.scope.max_pages_per_host);
        let seed = self.canonicalize(&self.crawl.seed_url).map(|(seed, _)| seed);
        let mut seed_get_seen = false;
        loop {
            let after = existing.last().map_or(0, |entry| entry.id);
            let ids: Vec<_> = existing.iter().map(|entry| entry.id).collect();
            let methods = self.deps.frontier.request_methods(self.run, &ids).await?;
            if methods.len() != ids.len() {
                return Err(StoreError::Conflict("incomplete frontier method projection".into()).into());
            }
            {
                let mut f = self.frontier.lock();
                let mut ledger = self.ledger.lock();
                for e in existing {
                    let is_get = methods.get(&e.id).is_some_and(|method| method == "GET");
                    if is_get
                        && seed.as_ref().is_some_and(|seed| seed.url == e.url.url)
                        && !matches!(
                            e.status,
                            FrontierStatus::PolicyBlocked | FrontierStatus::RobotsBlocked
                        )
                    {
                        seed_get_seen = true;
                    }
                    match e.status {
                        FrontierStatus::Succeeded | FrontierStatus::Failed | FrontierStatus::Unreachable => {
                            let _ = budget.try_consume(BudgetKind::Urls, 1);
                            let _ = budget.try_consume_host(e.url.url.host_str().unwrap_or(""));
                            if is_get {
                                ledger.visited.insert(e.url.url.to_string());
                            }
                        }
                        FrontierStatus::Pending | FrontierStatus::Leased | FrontierStatus::Abandoned => {
                            ledger.pending.insert(
                                e.id,
                                PendingUrl {
                                    resume: ResumeEntry::new(e.url.url.to_string(), e.depth),
                                    is_get,
                                },
                            );
                        }
                        FrontierStatus::PolicyBlocked | FrontierStatus::RobotsBlocked => continue,
                    }
                    if is_get
                        && f.push(e.url, u32::from(e.depth), LinkSource::Body, None) == PushOutcome::Admitted
                    {
                        let _ = f.pop();
                    }
                }
            }
            existing = self.deps.frontier.page(self.run, after, 1000).await?;
            if existing.is_empty() {
                break;
            }
        }
        *self.budget.lock() = budget;
        // An API import may precede worker startup; it must not suppress the run's seed.
        let seed_missing = seed.is_some() && !seed_get_seen;
        if seed_missing {
            self.seed().await?;
        }
        if finite {
            self.deps.frontier.seal(self.run, 1).await?;
        }
        Ok(())
    }

    /// Discover the seed (depth 0) and, per `scope.sitemap`/`scope.knownFiles`, the sitemap
    /// URLs and robots paths (depth 1).
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn seed(&self) -> Result<(), WorkerError> {
        self.validate_discovery_providers()?;
        let Some((seed, bearing)) = self.canonicalize(&self.crawl.seed_url) else {
            return Err(WorkerError::Config(format!(
                "seed URL {} cannot be canonicalized",
                self.crawl.seed_url
            )));
        };
        let resumed = self.resume_seed.lock().take();
        let seed_excluded = self.prefetch.check(&seed.url).is_some();
        self.discover(seed.clone(), 0, None, bearing, None).await?;
        self.seed_batch_urls().await?;
        if !seed_excluded {
            self.climb(&seed, 0, None, &seed.url).await?;
        }
        if let Some(state) = resumed {
            // the stopped run already enumerated the sitemap and robots paths: every URL
            // they named is in its visited or pending list
            for pending in &state.pending {
                let Ok(url) = Url::parse(&pending.url) else {
                    continue;
                };
                let Some((canon, bearing)) = self.canonicalize(&url) else {
                    continue;
                };
                let source = RequestSource {
                    tag: "resume",
                    attribute: "pending",
                    source: seed.origin.clone(),
                };
                self.discover(canon, pending.depth, None, bearing, Some(source))
                    .await?;
            }
            return self.persist_counters().await;
        }
        // A refused seed cannot authorize automatic requests for its origin's sources.
        // Explicit batch and continuation URLs still pass their own admission gates above.
        if self.crawl.cache_only() || seed_excluded {
            return self.persist_counters().await;
        }
        let known = &self.crawl.scope.known_files;
        if self.source_enabled(crawlx_core::discovery::DiscoverySourceV1::Sitemap)
            && self.crawl.scope.discovery.is_none()
            && self.crawl.scope.sitemap != SitemapMode::Skip
            && known.contains(&KnownFile::Sitemap)
        {
            self.discover_sitemaps(&seed).await?;
        }
        if known.contains(&KnownFile::RobotsPaths) {
            self.discover_robots_paths(&seed).await?;
        }
        self.persist_counters().await
    }

    /// `scope.knownFiles: robots_paths`: `Allow:` paths always; `Disallow:`
    /// paths only when robots are not respected under an authorization record.
    async fn discover_robots_paths(&self, seed: &CanonicalUrl) -> Result<(), WorkerError> {
        if self.robots.body(&seed.origin).is_none() {
            self.robots.fetch(&seed.origin, &seed.url).await;
        }
        let Some(body) = self.robots.body(&seed.origin) else {
            return Ok(());
        };
        let robots = RobotsTxt::parse(&body);
        let authorized = self.crawl.safety.authorization_record_ref.is_some();
        let urls = crawlx_policy::known_files::seeds(
            &robots,
            &seed.url,
            &[KnownFile::RobotsPaths],
            self.crawl.safety.respect_robots_txt,
            authorized,
        );
        for url in urls {
            let Some((canon, bearing)) = self.canonicalize(&url) else {
                continue;
            };
            let source = RequestSource {
                tag: "robots",
                attribute: "path",
                source: format!("{}/robots.txt", seed.origin),
            };
            self.discover(canon, 1, None, bearing, Some(source)).await?;
        }
        Ok(())
    }

    async fn discover_sitemaps(&self, seed: &CanonicalUrl) -> Result<(), WorkerError> {
        if self.crawl.safety.respect_robots_txt {
            // makes `Sitemap:` directives available
            let _ = self.robots_decision(seed).await;
        }
        let mut roots: Vec<String> = self.robots.sitemaps(&seed.origin);
        if roots.is_empty() {
            if let Ok(default) = seed.url.join("/sitemap.xml") {
                roots.push(default.to_string());
            }
        }
        let mut traversal = SitemapTraversal::new();
        let mut queue: Vec<(String, usize, bool)> = roots.into_iter().map(|r| (r, 0, true)).collect();
        let mut fetched = 0usize;
        while let Some((loc, depth, root)) = queue.pop() {
            let source_cap = self
                .crawl
                .scope
                .discovery
                .as_ref()
                .map_or(MAX_SITEMAP_DOCUMENTS, |policy| policy.max_source_documents);
            if fetched >= source_cap || !traversal.has_room() {
                break;
            }
            let Ok(url) = Url::parse(&loc) else { continue };
            let Some((canon, _)) = self.canonicalize(&url) else {
                continue;
            };
            if !self.scope.decide(&canon, 0).is_admitted() {
                continue; // an off-scope sitemap host is not fetched
            }
            fetched += 1;
            let fetched_response = if let Some(policy) = &self.crawl.scope.discovery {
                let acquisition = self.crawl.acquisition.clone().unwrap_or_default();
                let mut budget = crate::acquisition::AcquisitionBudgetV1::new(&acquisition)?;
                self.fetch_discovery_auxiliary(
                    &url,
                    0,
                    policy.max_feed_bytes,
                    &mut budget,
                    &CancellationToken::new(),
                    crawlx_policy::robots::HopKind::Feed,
                )
                .await
            } else {
                self.fetcher.fetch(&url, &FetchOptions::default()).await
            };
            let Ok(resp) = fetched_response else {
                continue;
            };
            if !resp.status.is_success() || resp.truncated {
                continue;
            }
            let byte_limit = self.fetcher.config().max_body_bytes;
            let body = resp.body.clone();
            let location = loc.clone();
            let (next_traversal, pending) = self
                .cpu_pool
                .run(move || {
                    let pending = discovery::decode_sitemap(&body, byte_limit)
                        .map_err(discovery::SitemapIngestError::from)
                        .and_then(|decoded| {
                            let pending = if root {
                                traversal.ingest_root(&location, &decoded)
                            } else {
                                traversal.ingest(&decoded, depth)
                            };
                            pending.map_err(discovery::SitemapIngestError::from)
                        });
                    (traversal, pending)
                })
                .await
                .map_err(|error| WorkerError::Other(error.to_string()))?;
            traversal = next_traversal;
            match pending {
                Ok(nested) => queue.extend(nested.into_iter().map(|p| (p.loc, p.depth, false))),
                Err(e) => tracing::warn!(sitemap = %loc, error = %e, "sitemap not usable"),
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in traversal.into_urls() {
            let variants = std::iter::once((entry.loc, "loc", None)).chain(
                entry
                    .hreflang
                    .into_iter()
                    .map(|variant| (variant.loc, "hreflang", Some(variant.language))),
            );
            for (loc, attribute, language) in variants {
                let Ok(url) = Url::parse(&loc) else { continue };
                if !matches!(url.scheme(), "http" | "https") {
                    continue;
                }
                let Some((canon, bearing)) = self.canonicalize(&url) else {
                    continue;
                };
                if !seen.insert(canon.key) {
                    self.counters.discovery(Plane::Urls, DiscoveryOutcome::Duplicate);
                    continue;
                }
                let source = RequestSource {
                    tag: "sitemap",
                    attribute,
                    source: language.map_or_else(
                        || seed.origin.clone(),
                        |language| format!("{};hreflang={language}", seed.origin),
                    ),
                };
                self.discover(canon, 1, None, bearing, Some(source)).await?;
            }
        }
        Ok(())
    }

    // ---- processing ---------------------------------------------------------------------

    /// Preserve an in-flight response only for an explicit graceful static-plane drain.
    async fn fetch_legacy(
        &self,
        entry: &FrontierEntry,
        options: &FetchOptions,
        cancel: &CancellationToken,
    ) -> Result<FetchResponse, FetchError> {
        let authority = NativeHopAdmission::new(self, entry)?;
        let check = || async {
            // Drain may finish a send that started, never start another redirect or retry.
            if self.stop_requested(cancel) {
                return Err(FetchError::AcquisitionCancelled);
            }
            authority.authority().await?;
            if self.stop_requested(cancel) {
                return Err(FetchError::AcquisitionCancelled);
            }
            Ok(())
        };
        let cancelled = async {
            cancel.cancelled().await;
            if !self.is_draining() {
                return Err(FetchError::AcquisitionCancelled);
            }
            // The composite token is already cancelled. Keep checking the original lease
            // and API run state rather than treating that token as renewed authority.
            let stop_period = self
                .authorization
                .as_ref()
                .map_or(Duration::from_millis(100), |guard| {
                    let recheck = guard.recheck_interval();
                    if recheck.is_zero() {
                        Duration::from_millis(10)
                    } else {
                        recheck.min(Duration::from_millis(100))
                    }
                });
            loop {
                authority.check_run_stop().await?;
                tokio::time::sleep(stop_period).await;
            }
        };
        let revoked = async {
            match &self.authorization {
                Some(guard) => guard.stopped_token().cancelled_owned().await,
                None => std::future::pending::<()>().await,
            }
        };
        let hard_cancelled = async {
            match &self.hard_cancel {
                Some(cancel) => cancel.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            () = hard_cancelled => Err(FetchError::AcquisitionCancelled),
            () = revoked => Err(FetchError::AcquisitionCancelled),
            cancelled = cancelled => cancelled,
            fetched = self.fetcher.fetch_with_authority(&entry.url.url, options, &check) => fetched,
        }
    }

    /// Fetch, extract and store every entry of `entries`, the rows [`Self::run`] has just leased
    /// (they are in `held`, with the fencing token of their leases); discover their links. A row
    /// whose lease is lost on the way is left to its next holder.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    async fn process_batch(
        &self,
        entries: &[FrontierEntry],
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        // A cancel through the API flips the run row, not this token: re-read it before every
        // fetch so a cancelled crawl goes quiet instead of draining the leased batch (found by
        // the wire CANCEL family: the facade kept requesting pages after `DELETE /crawl/{id}`).
        let mut cancelled = false;
        for entry in entries {
            let run_row = self.deps.runs.get_metadata(self.run).await?;
            cancelled = cancelled || run_row.status == RunStatus::Cancelled;
            // Every artifact this row retains publishes under its own frontier lease.
            // A row whose lease is already gone fails inside `process_leased` with `LeaseLost`.
            let held = self.held.lock().get(&entry.id).copied();
            // Boxed: the row future is large and a producer scope must not copy it onto this frame.
            let leased = Box::pin(self.process_leased(entry, cancel, cancelled));
            let processed = match held {
                Some(fence) => {
                    let producer = crawlx_core::custody::CustodyLease::for_url(
                        run_row.tenant,
                        self.run,
                        entry.id,
                        self.worker,
                        fence,
                    );
                    crawlx_core::custody::with_producer(producer, leased).await
                }
                None => leased.await,
            };
            match processed {
                Ok(()) => {}
                // the lease ran out before the row was finished (the heartbeat could not renew
                // it): the reaper returned the row, and whoever leases it next attempts it
                Err(WorkerError::Store(StoreError::LeaseLost)) => {
                    self.held.lock().remove(&entry.id);
                    tracing::warn!(run = %self.run, row = entry.id, "url lease lost; the row is left to its next holder");
                }
                Err(e) => return Err(e),
            }
        }
        self.persist_counters().await
    }

    /// One row of a leased batch.
    async fn process_leased(
        &self,
        entry: &FrontierEntry,
        cancel: &CancellationToken,
        cancelled: bool,
    ) -> Result<(), WorkerError> {
        if !self.held.lock().contains_key(&entry.id) {
            // the heartbeat found the lease gone: nothing is fetched or counted for this row
            return Err(StoreError::LeaseLost.into());
        }
        // a revoked or expired record stops the run like a cancel, a spent
        // budget ends it: the rows of the batch in hand are abandoned with the run
        if cancelled
            || self.authorization_lost().await
            || self.budget.lock().exhausted(self.deps.clock.now()).is_some()
        {
            self.finish(entry, FrontierStatus::Abandoned, Some("run_stopped".to_owned()))
                .await?;
            self.counters
                .attempt_with_reason(Plane::Urls, Attempt::Abandoned, "run_stopped");
            return Ok(());
        }
        // The worker drains (SIGTERM, operator drain) but the run goes on: a row never
        // fetched returns to `pending` unattempted, for the worker that takes the run over.
        // Abandoned rows are never leased again.
        if self.stop_requested(cancel) {
            let fence = self.held.lock().remove(&entry.id).ok_or(StoreError::LeaseLost)?;
            self.deps.frontier.give_back(entry.id, fence).await?;
            return Ok(());
        }
        if self.admission_ceiling.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            let fence = self.held.lock().remove(&entry.id).ok_or(StoreError::LeaseLost)?;
            self.deps.frontier.give_back(entry.id, fence).await?;
            return Ok(());
        }
        let cooldown = if self.crawl.cache_only() {
            Duration::ZERO
        } else {
            self.fetcher
                .governor()
                .shared_cooldown_remaining(&crawlx_fetch::Origin::from_url(&entry.url.url))
                .await?
        };
        if !cooldown.is_zero() {
            let delay = chrono::Duration::from_std(cooldown)
                .map_err(|_| WorkerError::Config("origin cooldown exceeds timestamp range".into()))?;
            let not_before = self
                .deps
                .clock
                .now()
                .checked_add_signed(delay)
                .ok_or_else(|| WorkerError::Config("origin cooldown timestamp overflow".into()))?;
            let fence = self.held.lock().remove(&entry.id).ok_or(StoreError::LeaseLost)?;
            self.deps
                .frontier
                .defer_fenced(entry.id, fence, not_before)
                .await?;
            return Ok(());
        }
        let resources = crate::runtime_admission::TaskResourceSample::start().await;
        let result = self.process_entry(entry, cancel).await;
        let observation = resources.finish(entry.id, result.is_ok()).await;
        let recorded = self
            .deps
            .events
            .append(self.run, "runtime.task", observation)
            .await;
        match result {
            Err(error) => {
                if let Err(recording) = recorded {
                    tracing::warn!(error = %recording, "task resource observation could not be recorded");
                }
                Err(error)
            }
            Ok(()) => recorded.map(|_| ()).map_err(WorkerError::from),
        }
    }

    /// Release a real 429 attempt while preserving durable effect/deadline charges.
    pub(super) async fn defer_rate_limited(
        &self,
        entry: &FrontierEntry,
        final_url: &Url,
    ) -> Result<(), WorkerError> {
        let cooldown = self
            .fetcher
            .governor()
            .cooldown_remaining(&crawlx_fetch::Origin::from_url(final_url))
            .max(Duration::from_millis(1));
        let delay = chrono::Duration::from_std(cooldown)
            .map_err(|_| WorkerError::Config("origin cooldown exceeds timestamp range".into()))?;
        let not_before = self
            .deps
            .clock
            .now()
            .checked_add_signed(delay)
            .ok_or_else(|| WorkerError::Config("origin cooldown timestamp overflow".into()))?;
        let fence = self.held.lock().remove(&entry.id).ok_or(StoreError::LeaseLost)?;
        let pending = self
            .deps
            .frontier
            .retry_fenced(entry.id, fence, not_before)
            .await?;
        if !pending {
            self.counters
                .attempt_with_reason(Plane::Urls, Attempt::Failed, "effect_budget_exhausted");
        }
        self.deps
            .events
            .append(
                self.run,
                "request.rate_limited",
                serde_json::json!({
                    "frontierId": entry.id,
                    "status": 429,
                    "pending": pending,
                    "notBefore": not_before,
                }),
            )
            .await?;
        Ok(())
    }

    /// Complete `entry` as failed or unreachable; `reason` is the code of the frontier row
    /// and `label` the bounded `reason` label of the metric (a status class rather than a
    /// status code).
    async fn fail(
        &self,
        entry: &FrontierEntry,
        reason: &str,
        label: &str,
        attempt: Attempt,
        payload: serde_json::Value,
    ) -> Result<(), WorkerError> {
        let status = if attempt == Attempt::Unreachable {
            FrontierStatus::Unreachable
        } else {
            FrontierStatus::Failed
        };
        self.finish(entry, status, Some(reason.to_owned())).await?;
        self.counters.attempt_with_reason(Plane::Urls, attempt, label);
        self.event("page.failed", payload).await;
        Ok(())
    }

    /// Complete `entry` as `policy_blocked` with the denial reason `authorization_scope`: the
    /// fetch was refused because a redirect hop left the authorization record's target. The URL
    /// was admitted when it was discovered, so the counters move it to `policy_blocked`.
    async fn block_by_authorization_scope(&self, entry: &FrontierEntry) -> Result<(), WorkerError> {
        let reason = DenialReason::AuthorizationScope.as_str();
        self.finish(entry, FrontierStatus::PolicyBlocked, Some(reason.to_owned()))
            .await?;
        self.counters
            .reclassify_admitted(Plane::Urls, DiscoveryOutcome::PolicyBlocked, reason);
        tracing::info!(url = %entry.url.url, reason, "redirect left the authorization record's target");
        Ok(())
    }

    /// Complete `entry` on the durable frontier and keep the resume ledger in step: a URL
    /// that was fetched (succeeded, failed or unreachable) is visited, a blocked one is
    /// forgotten, an abandoned one stays pending for the next run.
    fn finish<'a>(
        &'a self,
        entry: &'a FrontierEntry,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> impl Future<Output = Result<(), WorkerError>> + Send + 'a {
        self.finish_with_results(
            entry,
            status,
            reason,
            Vec::new(),
            Vec::new(),
            RequestPublication::default(),
        )
    }

    /// Atomically commit terminal request, accepted items and extension state.
    fn finish_with_results<'a>(
        &'a self,
        entry: &'a FrontierEntry,
        status: FrontierStatus,
        reason: Option<String>,
        accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
        state_deltas: Vec<crawlx_core::dataset::KvCasV1>,
        publication: RequestPublication,
    ) -> impl Future<Output = Result<(), WorkerError>> + Send + 'a {
        // Publication owns a large fenced transaction. Callers retain only its heap pin,
        // including dispatch branches that never publish a result.
        Box::pin(self.finish_with_results_inner(entry, status, reason, accepted, state_deltas, publication))
    }

    async fn finish_with_results_inner(
        &self,
        entry: &FrontierEntry,
        status: FrontierStatus,
        reason: Option<String>,
        accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
        state_deltas: Vec<crawlx_core::dataset::KvCasV1>,
        publication: RequestPublication,
    ) -> Result<(), WorkerError> {
        let RequestPublication {
            outbox,
            page,
            head_response,
            content_dedupe,
            local_dedupe,
        } = publication;
        let (status, reason, accepted, state_deltas) = if (status == FrontierStatus::Succeeded
            || head_response.is_some())
            && self.authorization_lost().await
        {
            (
                FrontierStatus::PolicyBlocked,
                Some("authorization_revoked".into()),
                Vec::new(),
                Vec::new(),
            )
        } else {
            (status, reason, accepted, state_deltas)
        };
        let fence = *self.held.lock().get(&entry.id).ok_or(StoreError::LeaseLost)?;
        // Terminal rows never reopen. Retries preserve this version until the single commit.
        let mut commit = crawlx_core::orchestration::RequestCommitV1::terminal(
            self.run, entry.id, fence, 1, status, reason,
        );
        commit.accepted = accepted;
        commit.state_deltas = state_deltas;
        commit.page = page.filter(|_| status == FrontierStatus::Succeeded);
        commit.content_dedupe = content_dedupe.filter(|_| status == FrontierStatus::Succeeded);
        commit.outbox = if status == FrontierStatus::Succeeded {
            outbox
        } else {
            Vec::new()
        };
        commit.head_response =
            head_response.filter(|_| matches!(status, FrontierStatus::Succeeded | FrontierStatus::Failed));
        self.deps.request_commits.commit_fenced(commit).await?;
        if status == FrontierStatus::Succeeded {
            if let Some(local_dedupe) = local_dedupe {
                local_dedupe.record();
            }
        }
        self.held.lock().remove(&entry.id);
        let mut ledger = self.ledger.lock();
        match status {
            FrontierStatus::Succeeded | FrontierStatus::Failed | FrontierStatus::Unreachable => {
                if ledger
                    .pending
                    .remove(&entry.id)
                    .is_none_or(|pending| pending.is_get)
                {
                    ledger.visited.insert(entry.url.url.to_string());
                }
            }
            FrontierStatus::PolicyBlocked | FrontierStatus::RobotsBlocked => {
                ledger.pending.remove(&entry.id);
            }
            FrontierStatus::Pending | FrontierStatus::Leased | FrontierStatus::Abandoned => {}
        }
        Ok(())
    }

    /// `Some(reason)` when `url` is the crawl's entry URL (depth 0, found on no page) and only
    /// the include filters (`includePaths`, `urlInclude`) refuse it. Such a URL is fetched once,
    /// to start discovery, but is not a page of the crawl: its row ends `policy_blocked` with
    /// `reason` ([`Self::finish_discovery_only`]). A refusal by `excludePaths`, `urlExclude`,
    /// the host rules, the extension filter, robots or the egress policy keeps the URL out.
    fn discovery_only(&self, url: &CanonicalUrl, depth: u16, from: Option<i64>) -> Option<DenialReason> {
        if depth != 0 || from.is_some() {
            return None;
        }
        let reason = self.scope.entry_include_denial(url)?;
        let (seed, _) = self.canonicalize(&self.crawl.seed_url)?;
        (seed.key == url.key).then_some(reason)
    }

    /// Complete the entry URL fetched for discovery only: the row ends `policy_blocked` with the
    /// include denial `reason`, and no page is stored. The URL counts as discovered and
    /// `policy_blocked` (the accounting of a denied seed), never as attempted or succeeded;
    /// the resume ledger knows it as fetched.
    async fn finish_discovery_only(
        &self,
        entry: &FrontierEntry,
        reason: &DenialReason,
    ) -> Result<(), WorkerError> {
        let fence = self.held.lock().remove(&entry.id).ok_or(StoreError::LeaseLost)?;
        self.deps
            .frontier
            .complete_fenced(
                entry.id,
                fence,
                FrontierStatus::PolicyBlocked,
                Some(reason.as_str().to_owned()),
            )
            .await?;
        {
            let mut ledger = self.ledger.lock();
            ledger.pending.remove(&entry.id);
            ledger.visited.insert(entry.url.url.to_string());
        }
        self.counters
            .reclassify_admitted(Plane::Urls, DiscoveryOutcome::PolicyBlocked, reason.as_str());
        Ok(())
    }

    /// Reenter native scope, robots and frontier admission for a changed request.
    /// The already-leased identity is never patched or fetched under new settings.
    async fn admit_extension_replacement(
        &self,
        entry: &FrontierEntry,
        mut proposal: crawlx_core::request::RequestEnvelopeV1,
    ) -> Result<bool, WorkerError> {
        // This URL plane owns anonymous GET only. Writes remain kernel/journal effects.
        if proposal.method != "GET"
            || proposal.body.is_some()
            || proposal.header_control.is_some()
            || proposal.session_generation.is_some()
        {
            return Ok(false);
        }
        let Some((url, action_bearing)) = self.canonicalize(&proposal.url.url) else {
            return Ok(false);
        };
        if url.url != proposal.url.url {
            return Ok(false);
        }
        let Some(depth) = entry.depth.checked_add(1) else {
            return Ok(false);
        };
        if action_bearing
            || !self.scope.decide(&url, depth).is_admitted()
            || (!self.crawl.cache_only()
                && !matches!(self.robots_decision(&url).await, RobotsDecision::Allowed))
        {
            return Ok(false);
        }
        let admitted = matches!(
            self.frontier
                .lock()
                .push(url.clone(), u32::from(depth), LinkSource::Body, None),
            PushOutcome::Admitted | PushOutcome::Duplicate
        );
        if !admitted {
            return Ok(false);
        }
        let _ = self.frontier.lock().pop();
        proposal.url = url;
        proposal.parent = Some(entry.id);
        proposal.depth = depth;
        proposal
            .validate()
            .map_err(|e| WorkerError::Config(e.to_string()))?;
        self.crawl
            .extensions
            .route(&proposal.route)
            .map_err(|e| WorkerError::Config(e.to_string()))?;
        let fence = self
            .held
            .lock()
            .get(&entry.id)
            .copied()
            .ok_or(StoreError::LeaseLost)?;
        let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
        let batch_id = crawlx_core::hash::Digest::of_value(
            "crawlx/extension-replacement/v1",
            &(self.run, entry.id, &proposal),
        )
        .map_err(|_| WorkerError::Config("invalid replacement identity".into()))?;
        let mut batch = crawlx_core::orchestration::RequestBatchV1::new(
            tenant,
            self.run,
            "anonymous".into(),
            batch_id,
            vec![proposal],
        );
        batch.parent_fence = Some((entry.id, fence));
        let receipt = self.deps.frontier.append_batch(batch).await?;
        for id in receipt.inserted {
            let queued = self.deps.frontier.get_request(self.run, id).await?;
            self.ledger.lock().pending.insert(
                id,
                PendingUrl {
                    resume: ResumeEntry::new(queued.envelope.url.url.to_string(), depth),
                    is_get: queued.envelope.method == "GET",
                },
            );
            self.counters.discovery_with_reason(
                Plane::Urls,
                DiscoveryOutcome::Admitted,
                "extension_replacement",
            );
        }
        Ok(true)
    }

    async fn process_entry(
        &self,
        entry: &FrontierEntry,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        if let Some(reason) = self.prefetch.check(&entry.url.url) {
            return self
                .finish(entry, FrontierStatus::PolicyBlocked, Some(reason.code().into()))
                .await;
        }
        let queued = self.deps.frontier.get_request(self.run, entry.id).await?;
        self.ledger
            .lock()
            .pending
            .entry(entry.id)
            .or_insert_with(|| PendingUrl {
                resume: ResumeEntry::new(entry.url.url.to_string(), entry.depth),
                is_get: queued.envelope.method == "GET",
            });
        if self
            .crawl
            .acquisition
            .as_ref()
            .is_some_and(|policy| policy.meta_refresh.is_some())
            && (queued.envelope.method != "GET"
                || queued.envelope.body.is_some()
                || queued.envelope.header_control.is_some())
        {
            return self
                .finish(
                    entry,
                    FrontierStatus::PolicyBlocked,
                    Some("meta_refresh_request_unsupported".into()),
                )
                .await;
        }
        // Append/import and recrawl are proposals, not admission receipts. Recheck
        // current canonicalization, scope and robots before extensions can propose work.
        let Some((canonical, action_bearing)) = self.canonicalize(&entry.url.url) else {
            return self
                .finish(
                    entry,
                    FrontierStatus::PolicyBlocked,
                    Some("invalid_request_url".into()),
                )
                .await;
        };
        if action_bearing || canonical.key != entry.url.key || canonical.url != entry.url.url {
            return self
                .finish(
                    entry,
                    FrontierStatus::PolicyBlocked,
                    Some("request_readmission_denied".into()),
                )
                .await;
        }
        if queued.envelope.method == "HEAD"
            || self
                .discovery_only(&entry.url, entry.depth, entry.discovered_from)
                .is_none()
        {
            match self.scope.decide(&entry.url, entry.depth) {
                ScopeVerdict::Denied(_) => {
                    return self
                        .finish(
                            entry,
                            FrontierStatus::PolicyBlocked,
                            Some("request_scope_denied".into()),
                        )
                        .await
                }
                ScopeVerdict::Admitted { leaf_only: true } if !self.scope.fetch_leaves() => {
                    return self
                        .finish(entry, FrontierStatus::PolicyBlocked, Some("leaf_only".into()))
                        .await
                }
                ScopeVerdict::Admitted { .. } => {}
            }
        }
        if !self.crawl.cache_only() {
            match self.robots_decision(&entry.url).await {
                RobotsDecision::Allowed => {}
                RobotsDecision::Blocked(_) => {
                    return self
                        .finish(
                            entry,
                            FrontierStatus::RobotsBlocked,
                            Some("robots_blocked".into()),
                        )
                        .await;
                }
                RobotsDecision::EgressDenied => {
                    return self
                        .finish(entry, FrontierStatus::PolicyBlocked, Some("egress_denied".into()))
                        .await;
                }
            }
        }
        let mut lifecycle = crate::extensions::RequestLifecycle::new(&self.crawl.extensions)
            .map_err(|e| WorkerError::Config(e.to_string()))?;
        let prepared = match lifecycle.before_acquisition(&queued.envelope, cancel) {
            Ok(prepared) => prepared,
            Err(crawlx_core::extensions::ExtensionError::PolicyDenied) => {
                let _ = lifecycle.finalize(true);
                return self
                    .finish(
                        entry,
                        FrontierStatus::PolicyBlocked,
                        Some("extension_policy_denied".into()),
                    )
                    .await;
            }
            Err(error) => {
                let _ = lifecycle.finalize(false);
                return self
                    .fail(
                        entry,
                        "extension_rejected",
                        "extension_rejected",
                        Attempt::Failed,
                        serde_json::json!({"reason":error.to_string()}),
                    )
                    .await;
            }
        };
        if let Some(replacement) = prepared.replacement {
            let admitted = self.admit_extension_replacement(entry, replacement).await?;
            let _ = lifecycle.finalize(!admitted);
            return self
                .finish(
                    entry,
                    if admitted {
                        FrontierStatus::Failed
                    } else {
                        FrontierStatus::PolicyBlocked
                    },
                    Some(
                        if admitted {
                            "extension_request_replaced"
                        } else {
                            "extension_replacement_denied"
                        }
                        .into(),
                    ),
                )
                .await;
        }
        if prepared.route == crawlx_core::extensions::HandlerV1::Skip {
            let _ = lifecycle.finalize(false);
            return self
                .finish(entry, FrontierStatus::Failed, Some("extension_skipped".into()))
                .await;
        }
        if queued.envelope.session_generation.is_some()
            && (self.strict_http_binding(&queued).await.is_err()
                || self.scrape.is_some()
                || crate::protocol::select_route(&self.protocol_routes, &entry.url.url)
                    .is_some_and(|route| route.backend != crawlx_core::protocol::ProtocolBackendV1::Http))
        {
            return self
                .fail(
                    entry,
                    "session_unavailable",
                    "session_unavailable",
                    Attempt::Failed,
                    serde_json::json!({"reason":"strict HTTP session generation or backend unavailable"}),
                )
                .await;
        }
        if queued.principal != "anonymous" && queued.envelope.session_generation.is_none() {
            return self
                .fail(
                    entry,
                    "request_principal_unavailable",
                    "request_principal_unavailable",
                    Attempt::Failed,
                    serde_json::json!({"reason":"URL acquisition requires its admitted anonymous principal"}),
                )
                .await;
        }
        if !matches!(queued.envelope.method.as_str(), "GET" | "HEAD")
            || queued.envelope.body.is_some()
            || queued.envelope.header_control.is_some()
        {
            return self.fail(entry, "unsupported_request_method", "unsupported_request_method", Attempt::Failed,
                serde_json::json!({ "reason": "body-bearing requests require journalled action admission" })).await;
        }
        let method_head = queued.envelope.method == "HEAD";
        if method_head
            && (self.scrape.is_some()
                || crate::protocol::select_route(&self.protocol_routes, &entry.url.url)
                    .is_some_and(|route| route.backend != crawlx_core::protocol::ProtocolBackendV1::Http))
        {
            return self
                .fail(
                    entry,
                    "request_backend_unavailable",
                    "request_backend_unavailable",
                    Attempt::Failed,
                    serde_json::json!({"reason":"HEAD requires native HTTP acquisition"}),
                )
                .await;
        }
        let discovery = (!method_head)
            .then(|| self.discovery_only(&entry.url, entry.depth, entry.discovered_from))
            .flatten();
        if discovery.is_none() {
            // a fetch for discovery only is not a page: it spends neither the URL nor the host budget
            let _ = self.budget.lock().try_consume(BudgetKind::Urls, 1);
            let host = entry.url.url.host_str().unwrap_or("").to_ascii_lowercase();
            if self.budget.lock().try_consume_host(&host).is_err() {
                // only reachable on a resumed run whose admission mirror was rebuilt partially
                self.finish(
                    entry,
                    FrontierStatus::PolicyBlocked,
                    Some(DenialReason::HostPageLimit.as_str().to_owned()),
                )
                .await?;
                self.counters.reclassify_admitted(
                    Plane::Urls,
                    DiscoveryOutcome::PolicyBlocked,
                    DenialReason::HostPageLimit.as_str(),
                );
                return Ok(());
            }
        }
        let mut legacy_reserved_effects = None;
        if self.crawl.orchestration.is_some() && self.crawl.acquisition.is_none() {
            let effects = if self.scrape.as_ref().is_some_and(ScrapeEngine::needs_browser) {
                return self.fail(entry, "finite_acquisition_required", "finite_acquisition_required", Attempt::Failed,
                    serde_json::json!({"reason":"render orchestration requires explicit native acquisition bounds"})).await;
            } else {
                let hops = u32::try_from(self.fetcher.config().max_redirects)
                    .unwrap_or(u32::MAX)
                    .saturating_add(1);
                let attempts = if self
                    .crawl
                    .scrape
                    .as_ref()
                    .is_some_and(|job| job.options.proxy == crawlx_core::scrape::ProxyMode::Auto)
                {
                    2
                } else {
                    self.fetcher.config().retry.max_retries.saturating_add(1)
                };
                hops.saturating_mul(attempts)
            };
            let fence = *self.held.lock().get(&entry.id).ok_or(StoreError::LeaseLost)?;
            match self
                .deps
                .frontier
                .reserve_effects_fenced(self.run, entry.id, fence, effects)
                .await
            {
                Ok(()) => {}
                Err(StoreError::Conflict(_)) => return self
                    .fail(
                        entry,
                        "request_effect_budget",
                        "request_effect_budget",
                        Attempt::Failed,
                        serde_json::json!({"reason":"durable request effect or elapsed allowance exhausted"}),
                    )
                    .await,
                Err(error) => return Err(error.into()),
            }
            legacy_reserved_effects = Some(effects);
        }
        if let Some(engine) = &self.scrape {
            // Each backend owns a separate acquisition state machine. Keep unused
            // scrape/protocol futures out of static dispatch and its nested robots checks.
            return self
                .process_scrape_entry(engine, entry, discovery.as_ref(), cancel, legacy_reserved_effects)
                .await;
        }
        let cache_only = self.crawl.cache_only();
        if cache_only && !self.crawl.protocol.routes.is_empty() {
            return self.fail(entry, "cache_miss", "cache_miss", Attempt::Failed,
                serde_json::json!({"reason":"protocol cache capability unavailable; offline dispatch forbidden"})).await;
        }
        if let Some(route) = crate::protocol::select_route(&self.protocol_routes, &entry.url.url) {
            match route.backend {
                crawlx_core::protocol::ProtocolBackendV1::Delegate => {
                    return self
                        .process_protocol_entry(
                            entry,
                            route,
                            &queued.envelope.route,
                            discovery.as_ref(),
                            cancel,
                        )
                        .await;
                }
                crawlx_core::protocol::ProtocolBackendV1::Browser => {
                    if let Some(engine) = &self.protocol_browser {
                        return self
                            .process_scrape_entry(
                                engine,
                                entry,
                                discovery.as_ref(),
                                cancel,
                                legacy_reserved_effects,
                            )
                            .await;
                    }
                    return self
                        .fail(
                            entry,
                            "protocol_capability_unavailable",
                            "protocol_capability_unavailable",
                            Attempt::Failed,
                            serde_json::json!({"reason":"native browser renderer unavailable"}),
                        )
                        .await;
                }
                crawlx_core::protocol::ProtocolBackendV1::Http => {}
                _ => {
                    return self
                        .fail(
                            entry,
                            "protocol_capability_unavailable",
                            "protocol_capability_unavailable",
                            Attempt::Failed,
                            serde_json::json!({"reason":"unknown protocol backend"}),
                        )
                        .await
                }
            }
        }
        // Static parsing/caching has a large independent state machine. Keep it out
        // of the scrape/protocol dispatch frame, including when those branches return
        // early; otherwise its unused locals still exhaust ordinary executor stacks.
        self.process_static_entry(
            entry,
            cancel,
            queued,
            discovery,
            lifecycle,
            legacy_reserved_effects,
        )
        .await
    }

    // Construct a selected phase outside its caller's poll frame. Box::pin at the
    // await site alone leaves the full future's construction temporary on that stack.
    fn phase_future<F: Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
        Box::pin(make())
    }

    fn process_static_entry<'a>(
        &'a self,
        entry: &'a FrontierEntry,
        cancel: &'a CancellationToken,
        queued: crawlx_core::orchestration::QueuedRequestV1,
        discovery: Option<DenialReason>,
        lifecycle: crate::extensions::RequestLifecycle,
        legacy_reserved_effects: Option<u32>,
    ) -> impl Future<Output = Result<(), WorkerError>> + Send + 'a {
        // Allocate in this synchronous boundary: constructing a large future in the
        // caller's poll frame keeps its temporary stack space live while polling it.
        Box::pin(self.process_static_entry_inner(
            entry,
            cancel,
            queued,
            discovery,
            lifecycle,
            legacy_reserved_effects,
        ))
    }

    fn conditional_baseline<'a>(
        &'a self,
        queued: &'a crawlx_core::orchestration::QueuedRequestV1,
        max_bytes: u64,
    ) -> impl Future<Output = Result<Option<crate::archive_recorder::ArchiveBaseline>, WorkerError>> + Send + 'a
    {
        // Only conditional revisits need the full operational run snapshot. Keep that
        // large return value and archive state out of every ordinary static poll frame.
        Box::pin(async move {
            let run = self.deps.runs.get(self.run).await?;
            crate::archive_recorder::conditional_baseline(
                self.deps.archives.as_ref(),
                self.deps.artifacts.as_ref(),
                &run,
                queued,
                self.deps.clock.now(),
                max_bytes,
            )
            .await
        })
    }

    async fn process_static_entry_inner(
        &self,
        entry: &FrontierEntry,
        cancel: &CancellationToken,
        queued: crawlx_core::orchestration::QueuedRequestV1,
        discovery: Option<DenialReason>,
        mut lifecycle: crate::extensions::RequestLifecycle,
        legacy_reserved_effects: Option<u32>,
    ) -> Result<(), WorkerError> {
        let cache_only = self.crawl.cache_only();
        let method_head = queued.envelope.method == "HEAD";
        let http_session_binding = self
            .strict_http_binding(&queued)
            .await
            .map_err(|_| WorkerError::Config("session_unavailable".into()))?;
        if http_session_binding.is_some() && cache_only {
            return self.fail(entry, "session_cache_unavailable", "session_cache_unavailable", Attempt::Failed,
                serde_json::json!({"reason":"live HTTP session cookie state cannot use an unbound retained response"})).await;
        }
        let mut prepared_document = None;
        let mut acquisition_metadata = None;
        let auxiliary_enabled = self.crawl.scope.discovery.is_some()
            || self
                .extract
                .outputs
                .as_ref()
                .and_then(|outputs| outputs.link_media.as_ref())
                .is_some_and(|options| options.max_previews > 0);
        let selected_http_route = crate::protocol::select_route(&self.protocol_routes, &entry.url.url);
        let validator_mode = self
            .crawl
            .orchestration
            .as_ref()
            .and_then(|policy| policy.recrawl.as_ref())
            .map_or(
                crawlx_core::orchestration::RecrawlValidatorModeV1::Disabled,
                |policy| policy.validator_mode,
            );
        let conditional_visit = !method_head
            && queued.identity.revisit_generation > 0
            && validator_mode != crawlx_core::orchestration::RecrawlValidatorModeV1::Disabled;
        let mut acquisition_policy = self.crawl.acquisition.clone().or_else(|| {
            (method_head
                || http_session_binding.is_some()
                || auxiliary_enabled
                || self.crawl.cache.is_some()
                || selected_http_route.is_some()
                || conditional_visit)
                .then(crawlx_core::acquisition::AcquisitionPolicyV1::default)
        });
        if (method_head || http_session_binding.is_some()) && self.crawl.acquisition.is_none() {
            if let Some(policy) = acquisition_policy.as_mut() {
                let effects = legacy_reserved_effects.unwrap_or(8);
                policy.max_attempts = u8::try_from(effects.min(8)).unwrap_or(8);
                policy.max_network_requests = policy.max_network_requests.min(effects);
            }
        }
        if let (Some(policy), Some(route)) = (acquisition_policy.as_mut(), selected_http_route) {
            policy.backend_ids = vec!["native_http".to_owned()];
            policy.fallback_backend_ids.clear();
            policy.max_elapsed_ms = policy.max_elapsed_ms.min(route.max_elapsed_ms);
            policy.max_decoded_bytes = policy.max_decoded_bytes.min(u64::from(route.max_body_bytes));
        }
        let mut shared_acquisition_budget = if let Some(policy) = acquisition_policy.as_ref() {
            if self.crawl.acquisition.is_some() && !self.crawl.cache_only() {
                let fence = *self.held.lock().get(&entry.id).ok_or(StoreError::LeaseLost)?;
                let allowance = self
                    .deps
                    .frontier
                    .reserve_acquisition_fenced(self.run, entry.id, fence)
                    .await?;
                Some(crate::acquisition::AcquisitionBudgetV1::from_allowance(
                    policy, &allowance,
                )?)
            } else {
                Some(crate::acquisition::AcquisitionBudgetV1::new(policy)?)
            }
        } else {
            None
        };
        let mut primary_options = crate::acquisition::fetch_options(&self.crawl.fetch);
        if method_head {
            primary_options.method = http::Method::HEAD;
        }
        if let Some(value) = queued.envelope.metadata.get("autothrottle_dont_adjust_delay") {
            primary_options.dont_adjust_delay = value.as_bool().ok_or_else(|| {
                WorkerError::Config("autothrottle_dont_adjust_delay must be boolean".into())
            })?;
        }
        if let Some(policy) = self.crawl.scope.discovery.as_ref().filter(|_| !method_head) {
            if http_session_binding.is_none()
                && acquisition_policy
                    .as_ref()
                    .is_none_or(|policy| policy.meta_refresh.is_none())
            {
                primary_options.follow_redirects = false;
            }
            primary_options.max_body_bytes = Some(policy.max_feed_bytes);
        }
        let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
        let mut scoped_extract = self.extract.clone();
        if scoped_extract
            .content
            .as_ref()
            .is_some_and(|policy| policy.dedupe.is_some())
        {
            let representation = crawlx_core::hash::Digest::of_value(
                "crawlx/extraction-representation/v1",
                &(
                    queued.envelope.header_control.as_ref(),
                    queued.envelope.session_generation,
                ),
            )
            .map_err(|error| WorkerError::Config(error.to_string()))?;
            let namespace = if self.durable_dedupe {
                format!("{}:{}", self.run, entry.id)
            } else {
                self.run.to_string()
            };
            let scope = crawlx_core::extraction::DedupeScopeV1::new(
                &tenant.to_string(),
                &namespace,
                &representation.to_hex(),
            )?;
            scoped_extract.dedupe_cache = Some(crawlx_extract::DedupeHandle::new(
                scope,
                if self.durable_dedupe {
                    Arc::new(std::sync::Mutex::new(crawlx_core::extraction::DedupeCache::new(
                        65_536,
                    )?))
                } else {
                    Arc::clone(&self.content_dedupe)
                },
            ));
        }
        let credential_identity = self
            .request_identity_key
            .as_ref()
            .map(|root| {
                crawlx_core::cache::credential_digest(root.expose(), tenant, &self.fetcher.config().controls)
            })
            .transpose()?;
        let cache_identity_unavailable = credential_identity.is_none()
            && (!self.fetcher.config().controls.headers().is_empty()
                || !self.fetcher.config().controls.cookies().is_empty());
        if cache_only && cache_identity_unavailable {
            return self.fail(entry, "cache_identity_unavailable", "cache_identity_unavailable", Attempt::Failed,
                serde_json::json!({"reason":"credential-bearing cache identity requires an operator request identity key"})).await;
        }
        let mut cached_source = None;
        let mut cached_response = None;
        if http_session_binding.is_none() && !method_head && self.crawl.retention.mode != RetentionMode::Zdr {
            match crate::scrape::cache::lookup_native(
                self.deps.pages.as_ref(),
                self.deps.runs.as_ref(),
                self.deps.artifacts.as_ref(),
                tenant,
                &self.crawl,
                &queued.envelope,
                self.run,
                credential_identity,
                self.deps.clock.now(),
            )
            .await
            {
                Ok(Some(hit)) => {
                    let cache_options = crawlx_core::scrape::ScrapeOptions {
                        cache: self.crawl.cache.clone(),
                        ..crawlx_core::scrape::ScrapeOptions::default()
                    };
                    let fresh = if let Some(budget) = shared_acquisition_budget.as_mut() {
                        let observe = |url: &Url, fetched: &Result<FetchResponse, FetchError>| {
                            self.record_exchange(url, fetched)
                        };
                        crate::scrape::cache::validate_freshness(
                            &self.fetcher,
                            &hit.page,
                            &cache_options,
                            budget,
                            cancel,
                            &observe,
                        )
                        .await?
                    } else {
                        true
                    };
                    if fresh {
                        cached_source = Some((hit.page.run, hit.page.fetched_at));
                        acquisition_metadata = Some(hit.metadata);
                        cached_response = Some(hit.response);
                    }
                }
                Ok(None) => {}
                Err(crate::scrape::cache::CacheError::BodyUnavailable) => {
                    return self
                        .fail(
                            entry,
                            "stored_body_unavailable",
                            "stored_body_unavailable",
                            Attempt::Failed,
                            serde_json::json!({"reason":"stored response body unavailable"}),
                        )
                        .await
                }
                Err(crate::scrape::cache::CacheError::Store(error)) => return Err(error.into()),
            }
        }
        if cache_only && cached_response.is_none() {
            return self.fail(entry, "cache_miss", "cache_miss", Attempt::Failed,
                serde_json::json!({"reason":"cache-only request has no retained response; network dispatch forbidden"})).await;
        }
        let mut archive_baseline: Option<crate::archive_recorder::ArchiveBaseline> = None;
        if cached_response.is_none() && conditional_visit {
            let default_limit = u64::try_from(
                primary_options
                    .max_body_bytes
                    .unwrap_or(self.fetcher.config().max_body_bytes),
            )
            .map_err(|_| WorkerError::Config("conditional body bound overflow".into()))?;
            let max_bytes = acquisition_policy
                .as_ref()
                .map_or(default_limit, |policy| policy.max_decoded_bytes)
                .min(default_limit);
            archive_baseline = self.conditional_baseline(&queued, max_bytes).await?;
            if let Some(baseline) = &archive_baseline {
                primary_options.validators = Some(baseline.validators.clone());
            } else if validator_mode == crawlx_core::orchestration::RecrawlValidatorModeV1::RequireHistory {
                self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                    .await?;
                return self
                    .fail(
                        entry,
                        "archive_baseline_unavailable",
                        "archive_baseline_unavailable",
                        Attempt::Failed,
                        serde_json::json!({"reason":"no compatible retained validator baseline"}),
                    )
                    .await;
            }
        }
        let fetched = if let Some(response) = cached_response {
            Ok(response)
        } else if let (Some(policy), Some(budget)) =
            (acquisition_policy.as_ref(), shared_acquisition_budget.as_mut())
        {
            let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
            let mut extract = scoped_extract.clone();
            extract.depth = u32::from(entry.depth);
            let observe = |url: &Url, fetched: &Result<FetchResponse, FetchError>| {
                self.record_exchange_method(&queued.envelope.method, url, fetched);
            };
            match crate::acquisition::fetch_native(
                &self.fetcher,
                &entry.url.url,
                &primary_options,
                policy,
                budget,
                cancel,
                &extract,
                &self.cpu_pool,
                self.run,
                tenant,
                &observe,
                false,
                self.captcha_secrets.as_ref(),
                Some(&NativeHopAdmission::new(self, entry)?.with_session(http_session_binding.clone())),
            )
            .await
            {
                Ok(acquired) => {
                    prepared_document = acquired.document;
                    acquisition_metadata = Some(acquired.metadata);
                    Ok(acquired.response)
                }
                Err(error) => Err(error),
            }
        } else {
            let fetched = self.fetch_legacy(entry, &primary_options, cancel).await;
            self.record_exchange_method(&queued.envelope.method, &entry.url.url, &fetched);
            fetched
        };
        let fetched = match (fetched, shared_acquisition_budget.as_mut()) {
            (Ok(response), Some(budget))
                if !method_head
                    && http_session_binding.is_none()
                    && self.crawl.scope.discovery.is_some()
                    && !self.crawl.cache_only()
                    && response.status.is_redirection()
                    && self.fetcher.config().follow_redirects =>
            {
                let next = response
                    .headers
                    .get(http::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|location| response.final_url.join(location).ok());
                acquisition_metadata = None;
                prepared_document = None;
                match next {
                    Some(next) => self
                        .fetch_discovery_auxiliary(
                            &next,
                            entry.depth,
                            primary_options
                                .max_body_bytes
                                .unwrap_or(self.fetcher.config().max_body_bytes),
                            budget,
                            cancel,
                            crawlx_policy::robots::HopKind::Redirect,
                        )
                        .await
                        .map(|mut final_response| {
                            final_response.redirects.insert(0, response.final_url.to_string());
                            final_response
                        }),
                    None => Err(FetchError::AcquisitionUnavailable),
                }
            }
            (fetched, _) => fetched,
        };
        // Transfer acquisition state into response processing instead of retaining its
        // large future-construction temporary throughout response polling.
        Self::phase_future(|| async move {
        let mut resp = match fetched {
            Ok(r) => r,
            Err(FetchError::EgressDenied(denied)) if denied.rule == DenyRule::AuthorizationScope => {
                // a redirect hop left the record's target: the page is blocked, never fetched
                self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                    .await?;
                return self.block_by_authorization_scope(entry).await;
            }
            Err(FetchError::AcquisitionCancelled)
                if self.stop_requested(cancel)
                    && self.shutdown_checkpoint_requested()
                    && !self.authorization_lost().await
                    && self.deps.runs.get_metadata(self.run).await?.status != RunStatus::Cancelled =>
            {
                self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                    .await?;
                let fence = self.held.lock().remove(&entry.id).ok_or(StoreError::LeaseLost)?;
                self.deps.frontier.give_back(entry.id, fence).await?;
                return Ok(());
            }
            Err(FetchError::AcquisitionCancelled) => {
                self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                    .await?;
                self.finish(
                    entry,
                    FrontierStatus::Abandoned,
                    Some("acquisition_cancelled".to_owned()),
                )
                .await?;
                self.counters
                    .attempt_with_reason(Plane::Urls, Attempt::Abandoned, "acquisition_cancelled");
                return Ok(());
            }
            Err(e) => {
                self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                    .await?;
                let attempt = match &e {
                    FetchError::Resolve { .. }
                    | FetchError::Transport(_)
                    | FetchError::Timeout(_)
                    | FetchError::PeerNotPinned { .. } => Attempt::Unreachable,
                    _ => Attempt::Failed,
                };
                return self
                    .fail(
                        entry,
                        e.code(),
                        e.code(),
                        attempt,
                        serde_json::json!({ "url": entry.url.url.as_str(), "reason": e.code(),
                            "cause": match &e { FetchError::MetaRefresh { source, .. } => source.code(), _ => e.code() },
                            "metaRefresh": match &e { FetchError::MetaRefresh { evidence, .. } => Some(evidence.as_ref()), _ => None } }),
                    )
                    .await;
            }
        };
        if cached_source.is_none()
            && resp.status.as_u16() == 429
            && self.fetcher.governor().defers_source_throttle()
        {
            self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                .await?;
            if let Some(reserved) = legacy_reserved_effects {
                let fence = *self.held.lock().get(&entry.id).ok_or(StoreError::LeaseLost)?;
                self.deps
                    .frontier
                    .settle_effects_fenced(
                        self.run,
                        entry.id,
                        fence,
                        reserved,
                        if method_head {
                            shared_acquisition_budget
                                .as_ref()
                                .map_or(resp.attempts, |budget| budget.usage().network_requests_reserved)
                        } else {
                            resp.attempts
                        },
                    )
                    .await?;
            }
            let _ = lifecycle.finalize(false);
            return self.defer_rate_limited(entry, &resp.final_url).await;
        }
        let tenant = self.deps.runs.get_metadata(self.run).await?.tenant;
        let mut acquisition_metadata = acquisition_metadata.unwrap_or_else(|| {
            crate::acquisition::http_metadata(self.run, tenant, &entry.url.url, &resp, &self.fetcher)
        });
        let mut accepted_not_modified = false;
        if !method_head && resp.not_modified() {
            let Some(baseline) = archive_baseline.take() else {
                self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                    .await?;
                return self.fail(entry, "archive_baseline_unavailable", "archive_baseline_unavailable",
                    Attempt::Failed, serde_json::json!({"targetStatus":304,"reason":"304 has no compatible retained body"})).await;
            };
            let header_mismatch = !baseline.matches_response(&resp.headers);
            if header_mismatch
                || !self
                    .deps
                    .archives
                    .artifact_visible(tenant, &baseline.record.artifact, self.deps.clock.now())
                    .await?
            {
                self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                    .await?;
                return self.fail(entry, "archive_baseline_incompatible", "archive_baseline_incompatible",
                    Attempt::Failed, serde_json::json!({"targetStatus":304,"reason":"validator context changed or baseline expired"})).await;
            }
            resp.body = bytes::Bytes::from(baseline.body);
            resp.content_type = Some(baseline.record.mime.clone());
            // Acquisition parsed the live 304, not these retained bytes. Re-extract the
            // approved baseline with its MIME type and cached-body validation context.
            prepared_document = None;
            acquisition_metadata.representation =
                crawlx_core::acquisition::RepresentationV1::RetainedResponse;
            acquisition_metadata.wire_body = None;
            acquisition_metadata.retained_baseline =
                Some(crawlx_core::archive_catalog::ArchiveDependencyV1::new(
                    baseline.record.export,
                    baseline.record.ordinal,
                ));
            accepted_not_modified = true;
        }
        if let Some(budget) = shared_acquisition_budget.as_ref() {
            budget.stamp(&mut acquisition_metadata);
        }
        if self.crawl.scope.discovery.is_some()
            && !resp.redirects.is_empty()
            && acquisition_policy
                .as_ref()
                .is_none_or(|policy| policy.meta_refresh.is_none())
        {
            acquisition_metadata.redirects = resp
                .redirects
                .iter()
                .filter_map(|value| Url::parse(value).ok())
                .map(|url| crawlx_core::acquisition::AcquisitionRedirectV1::observed(url, None))
                .collect();
            let policy = acquisition_policy.as_ref().cloned().unwrap_or_default();
            let mut context =
                crate::acquisition::context(&policy, Some(resp.status.as_u16()), resp.truncated);
            context.cached_body_available = accepted_not_modified;
            context.method_head = method_head;
            let validation_headers = header_pairs(&resp.headers);
            acquisition_metadata.validation = crawlx_extract::validation::validate_acquisition(
                &crawlx_extract::validation::ValidationInput {
                    context: &context,
                    content_type: resp.content_type.as_deref(),
                    headers: &validation_headers,
                    body: &resp.body,
                    document: None,
                },
            );
        }
        if self.crawl.acquisition.is_none() || accepted_not_modified {
            let policy = self.crawl.acquisition.clone().unwrap_or_default();
            let mut context =
                crate::acquisition::context(&policy, Some(resp.status.as_u16()), resp.truncated);
            context.cached_body_available = accepted_not_modified;
            context.method_head = method_head;
            let headers = header_pairs(&resp.headers);
            acquisition_metadata.validation = crawlx_extract::validation::validate_acquisition(
                &crawlx_extract::validation::ValidationInput {
                    context: &context,
                    content_type: resp.content_type.as_deref(),
                    headers: &headers,
                    body: &resp.body,
                    document: None,
                },
            );
        }
        if let Some(route) = selected_http_route {
            acquisition_metadata
                .backend
                .limitations
                .push(format!("protocol_route:{}", route.id));
            acquisition_metadata
                .backend
                .limitations
                .push(format!("policy_revision:{}", route.policy_revision));
        }
        acquisition_metadata
            .bound()
            .map_err(|e| WorkerError::Config(e.to_string()))?;
        if !method_head
            && self.crawl.acquisition.as_ref().is_some_and(|policy| {
                policy.validation.on_content_mismatch
                    == crawlx_core::acquisition::ContentMismatchActionV1::Fail
            })
            && !acquisition_metadata.validation.content_accepted
        {
            self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                .await?;
            return self
                .fail(
                    entry,
                    "content_validation_failed",
                    "content_validation_failed",
                    Attempt::Failed,
                    serde_json::json!({ "acquisition": acquisition_metadata }),
                )
                .await;
        }
        if method_head {
            acquisition_metadata.request_digest = queued.identity.key;
            let body_bytes =
                u64::try_from(resp.body.len()).map_err(|_| FetchError::AcquisitionUnavailable)?;
            if body_bytes != 0 {
                return Err(FetchError::AcquisitionUnavailable.into());
            }
            self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                .await?;
            if let Some(reserved) = legacy_reserved_effects {
                let fence = *self.held.lock().get(&entry.id).ok_or(StoreError::LeaseLost)?;
                self.deps
                    .frontier
                    .settle_effects_fenced(
                        self.run,
                        entry.id,
                        fence,
                        reserved,
                        shared_acquisition_budget
                            .as_ref()
                            .map_or(resp.attempts, |budget| budget.usage().network_requests_reserved),
                    )
                    .await?;
            }
            let headers = header_pairs(&resp.headers);
            let findings = self.detect_secrets(&headers, resp.content_type.as_deref(), &[]);
            let flagged = findings
                .iter()
                .filter_map(|(finding, _)| match &finding.location {
                    SecretLocation::Header { name } => Some(name.as_str()),
                    SecretLocation::Body { .. } => None,
                })
                .collect();
            let validation_failed = self.crawl.acquisition.as_ref().is_some_and(|policy| {
                policy.validation.on_content_mismatch
                    == crawlx_core::acquisition::ContentMismatchActionV1::Fail
            }) && !acquisition_metadata.validation.content_accepted;
            let success = (resp.status.is_success() || resp.not_modified()) && !validation_failed;
            let redactor = crawlx_core::secret::Redactor::new();
            let mut response_headers = headers_json(&headers, &flagged, &self.fetcher.config().controls);
            if let Some(headers) = response_headers.as_object_mut() {
                for (name, value) in headers {
                    *value = redactor.redact_field(name, value.take());
                }
            }
            let payload = serde_json::json!({
                "requestId":entry.id, "method":"HEAD", "status":resp.status.as_u16(),
                "bodyBytes":body_bytes,
                "response_headers":response_headers,
                "acquisition":acquisition_metadata,
            });
            let encoded =
                serde_json::to_vec(&payload).map_err(|error| StoreError::Serialization(error.to_string()))?;
            redactor.check_canonical(&encoded)?;
            crate::capture::check_run_secrets(
                &encoded,
                &self.fetcher.config().controls,
                self.captcha_secrets.as_ref(),
            )?;
            let _ = lifecycle.finalize(false);
            self.finish_with_results(
                entry,
                if success {
                    FrontierStatus::Succeeded
                } else {
                    FrontierStatus::Failed
                },
                Some(if validation_failed {
                    "content_validation_failed".into()
                } else {
                    format!("http_{}", resp.status.as_u16())
                }),
                Vec::new(),
                Vec::new(),
                RequestPublication {
                    head_response: Some(payload),
                    ..RequestPublication::default()
                },
            )
            .await?;
            self.counters.attempt(
                Plane::Urls,
                if success {
                    Attempt::Succeeded
                } else {
                    Attempt::Failed
                },
            );
            // HEAD is an acquisition result, not a document. In particular, never
            // replace the GET page projection or manufacture an empty article.
            return Ok(());
        }
        let code = resp.status.as_u16();
        let headers = header_pairs(&resp.headers);
        let leaf_only = matches!(
            self.scope.decide(&entry.url, entry.depth),
            ScopeVerdict::Admitted { leaf_only: true }
        );
        let expand = !leaf_only && self.crawl.scope.sitemap != SitemapMode::Only;
        let declared_allowed =
            primary_options.declaration.statuses.verdict(code) == crawlx_fetch::StatusVerdict::Allow;
        if !resp.status.is_success() && !accepted_not_modified && !declared_allowed {
            if resp.status.is_redirection()
                && expand
                && self.source_enabled(crawlx_core::discovery::DiscoverySourceV1::Html)
                && self.crawl.scope.discovery.is_none()
            {
                // a redirect that was not followed: its `Location` is still an endpoint
                let report = crawlx_extract::endpoints::discover_report(
                    &DiscoveryInput {
                        url: &resp.final_url,
                        status: code,
                        headers: &headers,
                        content_type: resp.content_type.as_deref(),
                        body: &resp.body,
                        depth: u32::from(entry.depth),
                    },
                    &DiscoveryOptions {
                        javascript_mode: self.extract.javascript_mode,
                        ..DiscoveryOptions::default()
                    },
                )
                .map_err(|e| WorkerError::Config(e.to_string()))?;
                self.expand_endpoints(entry, &resp.final_url, &[], report.endpoints)
                    .await?;
            }
            self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                .await?;
            return self
                .fail(
                    entry,
                    &format!("http_{code}"),
                    http_status_class(code),
                    Attempt::Failed,
                    serde_json::json!({
                        "url": entry.url.url.as_str(),
                        "status": code,
                        "response_body_capture": response_body_capture_metadata(&resp),
                        "acquisition": acquisition_metadata,
                    }),
                )
                .await;
        }
        let content_type = resp.content_type.clone();
        let is_html = content_type
            .as_deref()
            .is_none_or(|c| c.contains("html") || c.contains("xhtml"));
        let content_digest = crawlx_core::hash::Digest::of("crawlx/page-body/v1", &resp.body);
        let (secrets, tokens): (Vec<SecretFinding>, Vec<Option<SecretToken>>) = self
            .detect_secrets(&headers, content_type.as_deref(), &resp.body)
            .into_iter()
            .unzip();
        let flagged: BTreeSet<&str> = secrets
            .iter()
            .filter_map(|f| match &f.location {
                SecretLocation::Header { name } => Some(name.as_str()),
                SecretLocation::Body { .. } => None,
            })
            .collect();
        let public_final = if acquisition_metadata.meta_refresh_policy.is_some() {
            acquisition_metadata
                .final_url
                .as_ref()
                .ok_or(FetchError::AcquisitionUnavailable)?
        } else {
            &resp.final_url
        };
        let public_redirects: std::borrow::Cow<'_, [String]> =
            if acquisition_metadata.meta_refresh_policy.is_some() {
                std::borrow::Cow::Owned(
                    acquisition_metadata
                        .redirects
                        .iter()
                        .map(|hop| hop.url.to_string())
                        .collect(),
                )
            } else {
                std::borrow::Cow::Borrowed(&resp.redirects)
            };
        let mut record = PageRecord {
            run: self.run,
            frontier_id: entry.id,
            url: entry.url.clone(),
            status: code,
            content_type: content_type.clone(),
            content_digest,
            title: None,
            markdown: None,
            html: None,
            metadata: serde_json::json!({
                "final_url": public_final.as_str(),
                "redirects": public_redirects,
                "response_headers": headers_json(&headers, &flagged, &self.fetcher.config().controls),
                "fingerprint": crawlx_url::fingerprint_url(&entry.url.url, None).0,
                "acquisition": acquisition_metadata,
            }),
            links: Vec::new(),
            fetched_at: self.deps.clock.now(),
            lane: TrustLane::Diagnostic,
        };
        if let Some(src) = self.sources.lock().remove(&entry.id) {
            record.metadata["request"] = serde_json::json!({
                "tag": src.tag, "attribute": src.attribute, "source": src.source,
            });
        }
        if cache_identity_unavailable && self.crawl.cache.is_some() {
            record.metadata["cacheUnavailableReason"] = serde_json::json!("request_identity_key_unavailable");
        }
        if let Some((source_run, source_fetched_at)) = cached_source {
            record.fetched_at = source_fetched_at;
            record.metadata["cache"] = serde_json::json!({"version":1,"state":"hit",
            "sourceRun":source_run,"sourceFetchedAt":source_fetched_at,
            "provenance":"retained_redacted_wire","currentNetworkRequests":shared_acquisition_budget.as_ref().map_or(0, |_| {
                record.metadata["acquisition"]["networkRequests"].as_u64().unwrap_or(0)
            })});
            if self.crawl.cache.as_ref().is_some_and(|p| p.development_replay) {
                record.metadata["developmentReplay"] = serde_json::json!({"version":1,
                    "provenance":"retained_artifacts","sourceRun":source_run,"networkRequests":0});
            }
        }
        let source_response = self
            .discover_source_response(
                entry,
                &resp,
                &mut record,
                expand,
                shared_acquisition_budget.as_ref(),
            )
            .await?;
        let mut links: Vec<Url> = Vec::new();
        let mut page_type: Option<PageType> = None;
        let mut accepted_items = Vec::new();
        let mut extension_outbox = Vec::new();
        let mut content_dedupe = None;
        let mut local_dedupe = None;
        let endpoints: Vec<DiscoveredEndpoint> = if source_response {
            Vec::new()
        } else if is_html {
            let opts = ExtractOptions {
                status: code,
                headers: headers.clone(),
                content_type: content_type.clone(),
                depth: u32::from(entry.depth),
                acquisition_validation: Some({
                    let policy = self.crawl.acquisition.clone().unwrap_or_default();
                    let mut context = crate::acquisition::context(&policy, Some(code), resp.truncated);
                    context.cached_body_available = accepted_not_modified;
                    context
                }),
                ..scoped_extract.clone()
            };
            let body = resp.body.clone();
            let controls = self.fetcher.config().controls.clone();
            let captcha = self.captcha_secrets.clone();
            let base = resp.final_url.clone();
            let extracted = match prepared_document.take() {
                Some(document) => Ok(document),
                None => self
                    .cpu_pool
                    .run(move || {
                        let document = match &captcha {
                            Some(captcha) => crate::acquisition::extract_document_with_secrets(
                                &body, &base, &opts, &controls, captcha,
                            ),
                            None if opts.content.is_none() => {
                                crate::acquisition::extract_document(&body, &base, &opts, &controls)
                            }
                            None => Err(crawlx_extract::ExtractError::InvalidContentPolicy(
                                crawlx_core::CoreError::Invalid {
                                    field: "extract.privacy",
                                    reason: "dynamic-secret registry unavailable".into(),
                                },
                            )),
                        };
                        document.map(Box::new)
                    })
                    .await
                    .map_err(|e| WorkerError::Other(format!("extraction task failed: {e}")))?,
            };
            match extracted {
                Ok(mut doc) => {
                    if self.durable_dedupe {
                        content_dedupe = content_dedupe_claim(
                            tenant,
                            self.run,
                            scoped_extract.dedupe_cache.as_ref(),
                            &doc,
                        )?;
                    } else {
                        local_dedupe = doc.dedupe_commit.take();
                    }
                    let pipeline = self.crawl.extensions.clone();
                    let label = queued.envelope.route.clone();
                    let token = cancel.clone();
                    let transformed = self
                        .cpu_pool
                        .run(move || {
                            let invalid_item = doc
                                .item
                                .as_ref()
                                .is_some_and(|item| !item.valid || item.schema_valid == Some(false));
                            let result = if invalid_item {
                                Err(crawlx_core::extensions::ExtensionError::Rejected)
                            } else if pipeline.configured() {
                                if doc.validation.as_ref().is_some_and(|v| !v.content_accepted) {
                                    Err(crawlx_core::extensions::ExtensionError::Rejected)
                                } else {
                                    doc.article
                                        .as_ref()
                                        .map(|article| {
                                            crate::extensions::transform_document(
                                                &pipeline, &label, article, &token,
                                            )
                                        })
                                        .transpose()
                                }
                            } else {
                                Ok(None)
                            };
                            (doc, result)
                        })
                        .await
                        .map_err(|e| WorkerError::Other(format!("extension task failed: {e}")))?;
                    let (mut doc, candidate) = transformed;
                    let candidate = match candidate {
                        Ok(candidate) => candidate.flatten(),
                        Err(crawlx_core::extensions::ExtensionError::Rejected) => {
                            record.metadata["extensions"] =
                                serde_json::json!({"version":1,"outcome":"rejected"});
                            record.metadata["itemPipeline"] = serde_json::json!({
                                "accepted": 0, "rejected": 1, "reason": "extension_item_rejected",
                            });
                            None
                        }
                        Err(_) => {
                            self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                                .await?;
                            return self
                                .fail(
                                    entry,
                                    "extension_item_rejected",
                                    "extension_item_rejected",
                                    Attempt::Failed,
                                    serde_json::json!({"reason":"extension_item_rejected"}),
                                )
                                .await;
                        }
                    };
                    if let Some(candidate) = candidate {
                        record.metadata["itemPipeline"] = serde_json::json!({
                            "accepted": 1, "rejected": 0,
                        });
                        // Keep the full run configuration off the ordinary acquisition poll stack.
                        let (content, accepted, outbox) = Box::pin(async {
                            let run = self.deps.runs.get(self.run).await?;
                            let extractor = doc.article.as_ref().map_or("unknown", |a| a.extractor.as_str());
                            crate::extensions::store_candidate(
                                self.deps.artifacts.as_ref(),
                                &self.cpu_pool,
                                &run,
                                entry.id,
                                &candidate,
                                extractor,
                                &self.fetcher.config().controls,
                                self.captcha_secrets.as_ref().ok_or_else(|| {
                                    StoreError::RetentionDenied(
                                        "item dynamic-secret registry unavailable".into(),
                                    )
                                })?,
                            )
                            .await
                        })
                        .await?;
                        record.metadata["extensions"] = serde_json::json!({"version":1,"content":content,
                                "pipeline":self.crawl.extensions.publication().map_err(|e| WorkerError::Config(e.to_string()))?});
                        accepted_items.extend(accepted);
                        extension_outbox = outbox;
                    } else if self.crawl.extensions.requires_document() && doc.article.is_none() {
                        self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                            .await?;
                        return self
                            .fail(
                                entry,
                                "extension_document_unavailable",
                                "extension_document_unavailable",
                                Attempt::Failed,
                                serde_json::json!({"reason":"extension_document_unavailable"}),
                            )
                            .await;
                    }
                    record.metadata["acquisition"]["extractionSucceeded"] = serde_json::json!(true);
                    if let Some(validation) = &doc.validation {
                        record.metadata["acquisition"]["validation"] = serde_json::to_value(validation)
                            .map_err(|e| WorkerError::Other(format!("validation metadata: {e}")))?;
                    }
                    if self.crawl.datasets.article_store()?.is_some() {
                        let (returned, article_items, article_feeds) = Box::pin(async {
                            let run = self.deps.runs.get(self.run).await?;
                            let acquisition_accepted =
                                doc.validation.as_ref().is_some_and(|v| v.content_accepted);
                            crate::delivery::prepare_article_acceptance(
                                self.deps.artifacts.as_ref(),
                                &self.cpu_pool,
                                &run,
                                entry.id,
                                doc,
                                acquisition_accepted,
                            )
                            .await
                        })
                        .await?;
                        doc = returned;
                        accepted_items.extend(article_items);
                        extension_outbox.extend(article_feeds);
                    }
                    self.fill_record(&mut record, &doc, &resp.final_url).await;
                    self.discover_article_sources(
                        entry,
                        &resp,
                        &doc,
                        &mut record,
                        expand,
                        shared_acquisition_budget.as_mut(),
                        cancel,
                    )
                    .await?;
                    self.follow_article_intents(
                        entry,
                        &doc,
                        &resp.body,
                        &mut record,
                        shared_acquisition_budget.as_mut(),
                        cancel,
                    )
                    .await?;
                    page_type = doc.page_type;
                    if !cache_only
                        && self.crawl.mode == CrawlMode::Hybrid
                        && crate::protocol::select_route(&self.protocol_routes, &entry.url.url).is_none()
                    {
                        let html = String::from_utf8_lossy(&resp.body);
                        if let Some(signal) =
                            self.classifier
                                .classify(entry.url.url.path(), &html, doc.word_count)
                        {
                            record.metadata["dynamic_signal"] = serde_json::json!(signal.as_str());
                        }
                    }
                    links = doc.links.iter().map(|l| l.url.clone()).collect();
                    let filled = if !cache_only && self.crawl.extract.form_fill.enabled {
                        Some(self.fill_forms(&doc, entry.depth).await)
                    } else {
                        None
                    };
                    let mut found = doc.discovered_endpoints;
                    if let Some(filled) = filled {
                        // the filler replaces the extractor's own guess for every form
                        found.retain(|e| e.source != FORM_ACTION);
                        found.extend(filled);
                    }
                    found
                }
                Err(e) => {
                    tracing::warn!(url = %entry.url, error = %e, "extraction failed");
                    self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                        .await?;
                    return self
                        .fail(
                            entry,
                            "extract_failed",
                            "extract_failed",
                            Attempt::Failed,
                            serde_json::json!({ "url": entry.url.url.as_str(), "reason": "extract_failed" }),
                        )
                        .await;
                }
            }
        } else {
            // scripts, stylesheets, JSON and other textual bodies are mined for endpoints
            // (binary bodies never are: the textual guard decides)
            if !self.extract.custom_fields.is_empty()
                && crawlx_extract::endpoints::textual::is_textual(content_type.as_deref(), &resp.body)
            {
                let text = String::from_utf8_lossy(&resp.body);
                record.metadata["custom_fields"] = serde_json::json!(crawlx_extract::custom_fields::extract(
                    &self.extract.custom_fields,
                    &headers,
                    &text
                ));
            }
            let report = crawlx_extract::endpoints::discover_report(
                &DiscoveryInput {
                    url: &resp.final_url,
                    status: code,
                    headers: &headers,
                    content_type: content_type.as_deref(),
                    body: &resp.body,
                    depth: u32::from(entry.depth),
                },
                &DiscoveryOptions {
                    javascript_mode: self.extract.javascript_mode,
                    ..DiscoveryOptions::default()
                },
            )
            .map_err(|e| WorkerError::Config(e.to_string()))?;
            record.metadata["endpointDiscovery"] = serde_json::json!({
                "unresolved": report.unresolved,
                "unresolvedDropped": report.unresolved_dropped,
            });
            report.endpoints
        };
        if !source_response {
            self.settle_native_allowance(entry, shared_acquisition_budget.as_ref())
                .await?;
        }
        if let Some(reason) = &discovery {
            // not a page of the crawl: no stored page, no secret validation, no content dedupe
            let fetchable = endpoints
                .into_iter()
                .filter(|e| e.method == http::Method::GET && e.body.is_none())
                .collect();
            if expand
                && self.crawl.scope.discovery.is_none()
                && self.source_enabled(crawlx_core::discovery::DiscoverySourceV1::Html)
            {
                self.follow_page(entry, &resp.final_url, &links, fetchable)
                    .await?;
            }
            self.finish_discovery_only(entry, reason).await?;
            return Ok(());
        }
        let validations = self.validate_secrets(&secrets, tokens).await;
        match self
            .describe_request(entry, &mut record, &resp, &flagged, cancel)
            .await
        {
            Ok(()) => {}
            Err(WorkerError::Fetch(FetchError::AcquisitionCancelled)) => {
                self.finish(
                    entry,
                    FrontierStatus::Abandoned,
                    Some("acquisition_cancelled".to_owned()),
                )
                .await?;
                self.counters
                    .attempt_with_reason(Plane::Urls, Attempt::Abandoned, "acquisition_cancelled");
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        if !secrets.is_empty() {
            let mut value = serde_json::json!(secrets);
            if let Some(items) = value.as_array_mut() {
                for (item, validation) in items.iter_mut().zip(&validations) {
                    if let Some(validation) = validation {
                        item["validation"] = serde_json::json!(validation);
                    }
                }
            }
            record.metadata["secrets"] = value;
        }
        if self.crawl.extract.kb_endpoints {
            record.metadata["endpoints"] = classify_endpoints(&endpoints);
        }
        // non-GET and body-bearing endpoints are metadata only
        let (fetchable, recorded): (Vec<_>, Vec<_>) = endpoints
            .into_iter()
            .partition(|e| e.method == http::Method::GET && e.body.is_none());
        if !recorded.is_empty() {
            record.metadata["discovered_endpoints"] = serde_json::json!(recorded
                .iter()
                .map(|e| {
                    let mut item = serde_json::json!({
                        "url": e.url.as_str(),
                        "method": e.method.as_str(),
                        "tag": e.source.tag,
                        "attribute": e.source.attribute,
                        "body": e.body,
                        "content_type": e.content_type,
                        "headers": e.headers,
                        "confidence": e.confidence,
                    });
                    if self.crawl.output.capture_raw {
                        item["raw"] = serde_json::json!(self.raw_recorded_request(e));
                    }
                    item
                })
                .collect::<Vec<_>>());
        }

        // dedupe: exact body first, then the content-similarity index
        let dedupe = self.dedupe(&entry.url.key, &resp.body, content_digest)?;
        match &dedupe {
            Some(Dedupe::Exact) => {
                record.metadata["dedupe"] =
                    serde_json::json!({ "reason": DedupeReason::ContentExact.as_str(), "cluster": null });
            }
            Some(Dedupe::Similar(cluster)) => {
                record.metadata["dedupe"] = serde_json::json!({ "reason": DedupeReason::ContentSimilar.as_str(), "cluster": cluster });
            }
            None => {}
        }
        let filtered_type = page_type.is_some_and(|t| self.crawl.scope.filter_page_types.contains(&t));
        if filtered_type {
            record.metadata["filtered_page_type"] = serde_json::json!(true);
        }
        if cached_source.is_none()
            && http_session_binding.is_none()
            && self.crawl.cache.as_ref().is_some_and(|p| p.writes())
            && crate::scrape::cache::native_eligible(&self.crawl, credential_identity)
            && self.crawl.retention.mode != RetentionMode::Zdr
            && !resp.truncated
            && record.metadata["acquisition"]["validation"]["contentAccepted"].as_bool() == Some(true)
        {
            let redactor = crawlx_core::secret::Redactor::new();
            let controls = &self.fetcher.config().controls;
            let text = crate::capture::is_text_artifact(
                resp.content_type.as_deref().unwrap_or("application/octet-stream"),
            ) && std::str::from_utf8(&resp.body).is_ok();
            let bytes = if text {
                redactor.scrub_bytes(&resp.body, controls.secret_values())
            } else {
                crate::capture::check_run_secrets(&resp.body, controls, self.captcha_secrets.as_ref())?;
                std::borrow::Cow::Borrowed(resp.body.as_ref())
            };
            let redacted = if text {
                redactor.redact_artifact(bytes.as_ref())?
            } else {
                redactor.verify_binary(bytes.as_ref())?
            };
            let wire = ArtifactSink::over(self.deps.artifacts.as_ref())
                .put_page(
                    self.run,
                    entry.id,
                    Sensitivity::Content,
                    resp.content_type.as_deref().unwrap_or("application/octet-stream"),
                    &redacted,
                )
                .await?;
            record.metadata["nativeCache"] = serde_json::json!({"version":1,
                "key":crate::scrape::cache::native_key(&self.crawl,&queued.envelope,self.run,credential_identity).digest(),
                "wire":wire,"redacted":true});
        }

        let reason = match (&dedupe, filtered_type) {
            (Some(Dedupe::Exact), _) => Some(format!("dedupe:{}", DedupeReason::ContentExact.as_str())),
            (Some(Dedupe::Similar(_)), _) => {
                Some(format!("dedupe:{}", DedupeReason::ContentSimilar.as_str()))
            }
            (None, true) => Some("filtered_page_type".to_owned()),
            (None, false) => None,
        };
        if expand
            && dedupe.is_none()
            && !filtered_type
            && self.crawl.scope.discovery.is_none()
            && self.source_enabled(crawlx_core::discovery::DiscoverySourceV1::Html)
        {
            self.follow_page(entry, &resp.final_url, &links, fetchable)
                .await?;
        }
        let event = serde_json::json!({
            "pageId": entry.id, "url": entry.url.url.as_str(), "status": code, "title": record.title
        });
        self.finish_with_results(
            entry,
            FrontierStatus::Succeeded,
            reason,
            accepted_items,
            Vec::new(),
            RequestPublication {
                outbox: extension_outbox,
                page: Some(record),
                content_dedupe,
                local_dedupe,
                ..RequestPublication::default()
            },
        )
        .await?;
        *self.pages_written.lock() += 1;
        // counted once the row is finished: a holder that lost its lease leaves the counting to
        // the next one
        if let Some(d) = &dedupe {
            self.counters.reclassify_admitted(
                Plane::Urls,
                DiscoveryOutcome::Duplicate,
                match d {
                    Dedupe::Exact => DedupeReason::ContentExact.as_str(),
                    Dedupe::Similar(_) => DedupeReason::ContentSimilar.as_str(),
                },
            );
        }
        self.counters.attempt(Plane::Urls, Attempt::Succeeded);
        self.event("page", event).await;
        Ok(())
        })
        .await
    }

    /// Discover the redirect target of a fetched page (a page of its own), then its links and
    /// the fetchable `endpoints` it names.
    async fn follow_page(
        &self,
        entry: &FrontierEntry,
        final_url: &Url,
        links: &[Url],
        endpoints: Vec<DiscoveredEndpoint>,
    ) -> Result<(), WorkerError> {
        if *final_url != entry.url.url {
            if let Some((canon, bearing)) = self.canonicalize(final_url) {
                let source = RequestSource {
                    tag: "header",
                    attribute: "location",
                    source: entry.url.url.to_string(),
                };
                self.discover(
                    canon,
                    entry.depth.saturating_add(1),
                    Some(entry.id),
                    bearing,
                    Some(source),
                )
                .await?;
            }
        }
        self.expand_endpoints(entry, final_url, links, endpoints).await
    }

    /// Exact-content dedupe, then the content-similarity index.
    fn dedupe(
        &self,
        key: &crawlx_core::hash::Digest,
        body: &[u8],
        digest: crawlx_core::hash::Digest,
    ) -> Result<Option<Dedupe>, WorkerError> {
        if !self.frontier.lock().note_content(key, digest) {
            return Ok(Some(Dedupe::Exact));
        }
        let Some(index) = self.similarity.as_ref() else {
            return Ok(None);
        };
        // `accept` parses HTML; a refused charge is a typed error, never "accepted low signal".
        // Taken before the index lock and held until `accept` has dropped its DOM.
        let _charge = crawlx_extract::parse_budget::charge(body.len())
            .map_err(|refused| WorkerError::Extraction(refused.into()))?;
        let accept = index.lock().accept(body);
        if accept.filtered {
            self.frontier.lock().note_content_similar(key);
            return Ok(Some(Dedupe::Similar(accept.cluster_id)));
        }
        Ok(None)
    }

    /// Discover the page's navigational links (document order), then every fetchable
    /// endpoint not already among them: `Structural` always, JavaScript-mined ones
    /// (`Regex` confidence, or the AST pass's `js` sources) only under `scope.jsEndpoints`.
    async fn expand_endpoints(
        &self,
        entry: &FrontierEntry,
        page_url: &Url,
        links: &[Url],
        endpoints: Vec<DiscoveredEndpoint>,
    ) -> Result<(), WorkerError> {
        let depth = entry.depth.saturating_add(1);
        for link in links {
            if !matches!(link.scheme(), "http" | "https") {
                continue;
            }
            let Some((canon, bearing)) = self.canonicalize(link) else {
                continue;
            };
            let source = RequestSource {
                tag: "a",
                attribute: "href",
                source: page_url.to_string(),
            };
            self.discover(canon.clone(), depth, Some(entry.id), bearing, Some(source))
                .await?;
            self.climb(&canon, depth, Some(entry.id), page_url).await?;
        }
        for e in endpoints {
            if links.contains(&e.url) || !matches!(e.url.scheme(), "http" | "https") {
                continue;
            }
            let js_mined = e.confidence == Confidence::Regex || e.source.tag == "js";
            if js_mined && !self.crawl.scope.js_endpoints {
                continue;
            }
            let Some((canon, bearing)) = self.canonicalize(&e.url) else {
                continue;
            };
            let source = RequestSource {
                tag: e.source.tag,
                attribute: e.source.attribute,
                source: page_url.to_string(),
            };
            self.discover(canon.clone(), depth, Some(entry.id), bearing, Some(source))
                .await?;
            self.climb(&canon, depth, Some(entry.id), page_url).await?;
        }
        Ok(())
    }

    /// `scope.pathClimb` (the `-pc` compatibility flag): when `child` is in scope, also discover its parent
    /// directories (`/a/b/c.html` gives `/a/b/`, `/a/`, `/`) at the child's `depth`. Each
    /// parent passes scope, robots and dedupe like any other discovery.
    async fn climb(
        &self,
        child: &CanonicalUrl,
        depth: u16,
        from: Option<i64>,
        found_on: &Url,
    ) -> Result<(), WorkerError> {
        if !self.crawl.scope.path_climb || !self.scope.decide(child, depth).is_admitted() {
            return Ok(());
        }
        for parent in parent_paths(&child.url) {
            let Some((canon, bearing)) = self.canonicalize(&parent) else {
                continue;
            };
            let source = RequestSource {
                tag: "path-climb",
                attribute: "path",
                source: found_on.to_string(),
            };
            self.discover(canon, depth, from, bearing, Some(source)).await?;
        }
        Ok(())
    }

    /// Secrets over headers and the raw textual body (scripts and comments are stripped
    /// from the extracted document): kind, location and keyed hash only; the value never
    /// leaves the extractor. Under `extract.validateSecrets` each finding also carries the
    /// token, transiently, for [`Self::validate_secrets`].
    fn detect_secrets(
        &self,
        headers: &[(String, String)],
        content_type: Option<&str>,
        body: &[u8],
    ) -> Vec<(SecretFinding, Option<SecretToken>)> {
        let Some(key) = &self.secrets_key else {
            return Vec::new();
        };
        if !crawlx_extract::endpoints::textual::is_textual(content_type, body) {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(body);
        if self.validators.is_some() {
            Extractor::detect_secret_tokens(key, headers, &text)
                .into_iter()
                .map(|(finding, token)| (finding, Some(token)))
                .collect()
        } else {
            Extractor::detect_secrets(key, headers, &text)
                .into_iter()
                .map(|finding| (finding, None))
                .collect()
        }
    }

    /// The `validation` of every finding (`valid`, `invalid` or `unknown`), parallel to
    /// `findings`; `None` entries when `extract.validateSecrets` is off. The tokens are
    /// consumed: they reach the validator request and nothing else.
    async fn validate_secrets(
        &self,
        findings: &[SecretFinding],
        tokens: Vec<Option<SecretToken>>,
    ) -> Vec<Option<&'static str>> {
        if self.crawl.cache_only() {
            return vec![None; findings.len()];
        }
        let Some(validators) = &self.validators else {
            return vec![None; findings.len()];
        };
        let mut verdicts = Vec::with_capacity(findings.len());
        for (finding, token) in findings.iter().zip(tokens) {
            let verdict = match token {
                Some(token) => self.validate_token(validators, finding, &token).await,
                None => Validity::Unknown,
            };
            verdicts.push(Some(verdict.as_str()));
        }
        verdicts
    }

    /// Ask the operator-listed provider endpoint about one token (once per distinct token
    /// per run). The request goes through the egress-checked fetcher under its politeness
    /// and rate limits, never follows a redirect, stays off the capture channel and the
    /// traffic export, and is neither a page nor a counted attempt. Neither the token nor
    /// the planned URL is logged; a failed request is `unknown`.
    async fn validate_token(
        &self,
        validators: &SecretValidators,
        finding: &SecretFinding,
        token: &SecretToken,
    ) -> Validity {
        let kind = finding.kind.as_str();
        let memo = (kind, finding.value_hash.to_hex());
        if let Some(known) = self.validated.lock().get(&memo) {
            return *known;
        }
        let Some(request) = validators.plan(kind, token.as_str()) else {
            return Validity::Unknown;
        };
        if self.validated.lock().len() >= MAX_SECRET_VALIDATIONS {
            return Validity::Unknown;
        }
        let Ok(method) = http::Method::from_bytes(request.method.as_bytes()) else {
            return Validity::Unknown;
        };
        let mut headers = http::HeaderMap::new();
        for (name, value) in &request.headers {
            let (Ok(name), Ok(mut value)) = (
                http::HeaderName::from_bytes(name.as_bytes()),
                http::HeaderValue::from_str(value),
            ) else {
                return Validity::Unknown;
            };
            value.set_sensitive(true);
            headers.append(name, value);
        }
        let opts = FetchOptions {
            method,
            headers,
            max_body_bytes: Some(MAX_VALIDATION_BODY),
            follow_redirects: false,
            capture: false,
            ..FetchOptions::default()
        };
        let verdict = match self.fetcher.fetch(&request.url, &opts).await {
            Ok(resp) => validators.interpret(kind, resp.status.as_u16(), &resp.body),
            Err(e) => {
                tracing::debug!(kind, code = e.code(), "secret validation request failed");
                Validity::Unknown
            }
        };
        self.validated.lock().insert(memo, verdict);
        verdict
    }

    /// The headers this plane sends to `url`, as metadata: the `User-Agent`, the names of
    /// the configured extra headers (when `url` is within their scope) and the cookie header,
    /// every configured value shown as `[redacted]`.
    fn request_headers(&self, url: &Url) -> BTreeMap<String, String> {
        let config = self.fetcher.config();
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let mut headers = BTreeMap::new();
        headers.insert("user-agent".to_owned(), config.user_agent());
        if config.controls.applies_to(&host) {
            for name in config.controls.headers().keys() {
                headers.insert(name.to_ascii_lowercase(), REDACTED_PLACEHOLDER.to_owned());
            }
        }
        if config.controls.cookie_header(&host, url.path()).is_some() {
            headers.insert("cookie".to_owned(), REDACTED_PLACEHOLDER.to_owned());
        }
        headers
    }

    /// Response headers for the traffic export: a configured header value, or a header that
    /// echoes one, is masked; repeated names are joined with `, `.
    fn response_header_map(&self, mut pairs: Vec<(String, String)>) -> BTreeMap<String, String> {
        self.fetcher.config().controls.mask_headers(&mut pairs);
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        for (name, value) in pairs {
            match map.get_mut(&name) {
                Some(joined) => {
                    joined.push_str(", ");
                    joined.push_str(&value);
                }
                None => {
                    map.insert(name, value);
                }
            }
        }
        map
    }

    /// Hand the fetch of `url` to the traffic exporter: one exchange per redirect hop and
    /// one for the final answer, or one with the error code when nothing answered. Robots,
    /// sitemap and secret-validation requests never come through here.
    fn record_exchange(&self, url: &Url, fetched: &Result<FetchResponse, FetchError>) {
        self.record_exchange_method("GET", url, fetched);
    }

    fn record_exchange_method(&self, method: &str, url: &Url, fetched: &Result<FetchResponse, FetchError>) {
        let Some(exporter) = &self.traffic else {
            return;
        };
        let now = self.deps.clock.now();
        match fetched {
            Ok(resp) => {
                for hop in &resp.hops {
                    exporter.record(
                        Exchange::new("url", now, method, hop.url.as_str(), hop.status.as_u16())
                            .with_request(self.request_headers(&hop.url), None)
                            .with_response(self.response_header_map(header_pairs(&hop.headers)), None),
                    );
                }
                let body = (method != "HEAD"
                    && crawlx_extract::endpoints::textual::is_textual(
                        resp.content_type.as_deref(),
                        &resp.body,
                    ))
                .then(|| String::from_utf8_lossy(&resp.body).into_owned());
                exporter.record(
                    Exchange::new("url", now, method, resp.final_url.as_str(), resp.status.as_u16())
                        .with_request(self.request_headers(&resp.final_url), None)
                        .with_response(self.response_header_map(header_pairs(&resp.headers)), body),
                );
            }
            Err(e) => exporter.record(
                Exchange::new("url", now, method, url.as_str(), 0)
                    .with_request(self.request_headers(url), None)
                    .with_error(e.code()),
            ),
        }
    }

    /// `request.method`, `request.headers`, `request.custom_fields`, `content_length` and,
    /// under `output.captureRaw`, `request.raw` and the `raw_artifact` of the page. Runs
    /// after extraction, which rebuilds the metadata.
    async fn describe_request(
        &self,
        entry: &FrontierEntry,
        record: &mut PageRecord,
        resp: &FetchResponse,
        flagged: &BTreeSet<&str>,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        if self.crawl.cache_only() {
            record.metadata["robots_observation"] = serde_json::json!("unobserved_replay");
        }
        let headers = self.request_headers(&record.url.url);
        let mut request = match record.metadata.get("request") {
            Some(v) if v.is_object() => v.clone(),
            _ => serde_json::json!({}),
        };
        request["method"] = serde_json::json!("GET");
        request["headers"] = serde_json::json!(headers);
        if let Some(fields) = record.metadata.get("custom_fields") {
            request["custom_fields"] = fields.clone();
        }
        record.metadata["content_length"] =
            serde_json::json!(u64::try_from(resp.body.len()).unwrap_or(u64::MAX));
        // Exported bodies are text projections, not original encoded HTTP wire bytes.
        record.metadata["output_fidelity"] = serde_json::json!({
            "response_body": {
                "representation": "decoded_text",
                "truncated": resp.truncated
            }
        });
        if let Some(capture) = response_body_capture_metadata(resp) {
            record.metadata["response_body_capture"] = capture;
        }
        if self.crawl.output.capture_raw {
            request["raw"] = serde_json::json!(raw_request_text("GET", &record.url.url, &headers, None));
            let authority = NativeHopAdmission::new(self, entry)?;
            let (raw, binary_lossy) = self.raw_response(resp, flagged).await?;
            record.metadata["output_fidelity"]["request_raw"] = serde_json::json!({
                "representation": "reconstructed",
                "redacted": true,
                "binary_lossy": false,
                "truncated": false
            });
            record.metadata["output_fidelity"]["response_raw"] = serde_json::json!({
                "representation": "reconstructed",
                "redacted": true,
                "binary_lossy": binary_lossy,
                "truncated": resp.truncated
            });
            if self.stop_requested(cancel) && !self.is_draining() {
                return Err(FetchError::AcquisitionCancelled.into());
            }
            authority.authority().await?;
            if let Some(artifact) = self
                .store(
                    record.frontier_id,
                    Sensitivity::Content,
                    "message/http",
                    raw.as_bytes(),
                )
                .await
            {
                record.metadata["raw_artifact"] = serde_json::json!(artifact);
            }
        }
        record.metadata["request"] = request;
        Ok(())
    }

    /// A redacted HTTP/1.1 diagnostic, not byte-faithful wire evidence. Credential headers,
    /// flagged headers and configured-secret echoes are masked. The standalone body passes
    /// JSON-aware masking before text embedding, so escapes and duplicate members cannot hide it.
    async fn raw_response(
        &self,
        resp: &FetchResponse,
        flagged: &BTreeSet<&str>,
    ) -> Result<(String, bool), WorkerError> {
        let controls = &self.fetcher.config().controls;
        let mut out = format!(
            "HTTP/1.1 {} {}\r\n",
            resp.status.as_u16(),
            resp.status.canonical_reason().unwrap_or("")
        );
        let mut binary_lossy = false;
        for (name, value) in &resp.headers {
            let text = String::from_utf8_lossy(value.as_bytes());
            binary_lossy |= matches!(&text, std::borrow::Cow::Owned(_));
            let hide = CREDENTIAL_HEADERS.contains(&name.as_str())
                || flagged.contains(name.as_str())
                || controls.echoes_secret(&text);
            out.push_str(name.as_str());
            out.push_str(": ");
            out.push_str(if hide { REDACTED_PLACEHOLDER } else { &text });
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        let body = resp.body.clone();
        let declared_json = resp.content_type.as_deref().is_some_and(|content_type| {
            let mime = content_type.split(';').next().unwrap_or("").trim();
            mime.eq_ignore_ascii_case("application/json")
                || mime
                    .rsplit_once('+')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
        });
        let controls = controls.clone();
        let registry = self.captcha_secrets.clone().ok_or_else(|| {
            StoreError::RetentionDenied("raw response dynamic-secret registry unavailable".into())
        })?;
        self.cpu_pool
            .run(move || {
                let redactor = crawlx_core::secret::Redactor::new();
                let text = String::from_utf8_lossy(&body);
                binary_lossy |= matches!(&text, std::borrow::Cow::Owned(_));
                // Decode keys and values, and mask duplicate-member documents, before
                // any textual replacement can change the standalone JSON grammar.
                let json =
                    declared_json || text.trim_start().starts_with('{') || text.trim_start().starts_with('[');
                let decoded = if json
                    && text.contains('\\')
                    && serde_json::from_str::<serde_json::Value>(&text).is_err()
                {
                    // An escaped incomplete key/value cannot be semantically inspected.
                    crawlx_core::secret::REDACTED.to_owned()
                } else {
                    redactor.redact_text(&text).into_inner()
                };
                let controlled = redactor.scrub_bytes(decoded.as_bytes(), controls.secret_values());
                let controlled = std::str::from_utf8(controlled.as_ref()).map_err(|_| {
                    StoreError::Serialization("raw response projection encoding failed".into())
                })?;
                let scoped = registry.redact_if_present(controlled).map_err(|_| {
                    StoreError::RetentionDenied("raw response secret projection unavailable".into())
                })?;
                // Refuse unresolved scoped JSON escapes rather than retain an unsafe envelope.
                crate::capture::check_run_secrets(scoped.as_bytes(), &controls, Some(&registry))?;
                let projected = redactor.scrub(&scoped);
                crate::capture::check_run_secrets(projected.as_bytes(), &controls, Some(&registry))?;
                out.push_str(&projected);
                Ok::<_, StoreError>((out, binary_lossy))
            })
            .await
            .map_err(WorkerError::RawCaptureTask)?
            .map_err(WorkerError::from)
    }

    /// `raw` of a recorded (never sent) form request: what it would look like on the wire.
    fn raw_recorded_request(&self, e: &DiscoveredEndpoint) -> String {
        let mut headers = self.request_headers(&e.url);
        if let Some(content_type) = &e.content_type {
            headers.insert("content-type".to_owned(), content_type.clone());
        }
        if let Some(body) = &e.body {
            headers.insert("content-length".to_owned(), body.len().to_string());
        }
        raw_request_text(e.method.as_str(), &e.url, &headers, e.body.as_deref())
    }

    /// `extract.formFill`: every static form of the page as the request a user would send
    /// (the `-aff` compatibility flag). Fields the deterministic filler could not resolve go to the
    /// operator's [`FormAi`] when there is one, and the form is filled a second time with its
    /// answers. A GET form becomes a fetchable endpoint; any other method is only recorded.
    /// Field values are never logged.
    async fn fill_forms(&self, doc: &Document, depth: u16) -> Vec<DiscoveredEndpoint> {
        let config = &self.crawl.extract.form_fill;
        let seed = self.crawl.effective_seed();
        let mut out = Vec::with_capacity(doc.forms.len());
        for form in &doc.forms {
            let mut filled = fill_form(form, &doc.base_url, config, &seed, &BTreeMap::new());
            if let (false, Some(ai)) = (filled.unresolved.is_empty(), &self.form_ai) {
                let decided = ai.decide(&doc.base_url, &filled.action, &filled.unresolved).await;
                if !decided.is_empty() {
                    filled = fill_form(form, &doc.base_url, config, &seed, &decided);
                }
            }
            let Ok(method) = http::Method::from_bytes(filled.method.as_bytes()) else {
                continue;
            };
            out.push(DiscoveredEndpoint {
                url: filled.action,
                method,
                source: FORM_ACTION,
                body: filled.body,
                content_type: filled.content_type,
                confidence: Confidence::Structural,
                depth: u32::from(depth).saturating_add(1),
                headers: Vec::new(),
            });
        }
        out
    }

    async fn fill_record(&self, record: &mut PageRecord, doc: &Document, final_url: &Url) {
        record.title.clone_from(&doc.title);
        // StripAll is a lossy frontier identity rule, not document-link provenance. Cached maps
        // may later keep query parameters, so retain functional values without retaining session
        // or tracking parameters. Canonicalization still removes userinfo and unsafe fragments.
        let mut link_canon = self.canon.clone();
        if link_canon.query_policy == QueryPolicy::StripAll {
            link_canon.query_policy = QueryPolicy::Classify;
        }
        record.links = doc
            .links
            .iter()
            .filter_map(|link| {
                Canonicalizer::canonicalize_url(&link.url, &link_canon)
                    .ok()
                    .map(|url| url.url.to_string())
            })
            .collect();
        let mut meta = serde_json::to_value(&doc.metadata).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(obj) = meta.as_object_mut() {
            obj.insert("title".to_owned(), serde_json::json!(doc.title));
            obj.insert("description".to_owned(), serde_json::json!(doc.description));
            obj.insert("language".to_owned(), serde_json::json!(doc.language));
            obj.insert(
                "canonical_url".to_owned(),
                serde_json::json!(doc.canonical_url.as_ref().map(Url::as_str)),
            );
            obj.insert("word_count".to_owned(), serde_json::json!(doc.word_count));
            let public_final = if record
                .metadata
                .pointer("/acquisition/metaRefreshPolicy")
                .is_some()
            {
                record.metadata.get("final_url").cloned()
            } else {
                None
            };
            obj.insert(
                "final_url".to_owned(),
                public_final.unwrap_or_else(|| serde_json::json!(final_url.as_str())),
            );
            for key in [
                "redirects",
                "response_headers",
                "fingerprint",
                "request",
                "acquisition",
                "cache",
                "cacheUnavailableReason",
                "developmentReplay",
                "itemPipeline",
                "extensions",
            ] {
                if let Some(v) = record.metadata.get(key) {
                    obj.insert(key.to_owned(), v.clone());
                }
            }
            if self.crawl.extract.page_type {
                obj.insert("page_type".to_owned(), serde_json::json!(doc.page_type));
            }
            if self.crawl.extract.forms {
                obj.insert("forms".to_owned(), serde_json::json!(doc.forms));
            }
            obj.insert("technologies".to_owned(), serde_json::json!(doc.technologies));
            if !self.extract.custom_fields.is_empty() {
                obj.insert("custom_fields".to_owned(), serde_json::json!(doc.custom_fields));
            }
        }
        record.metadata = meta;
        if let Ok(pipeline) = crate::acquisition::parser_pipeline() {
            record.metadata["parserPipeline"] = serde_json::json!({
                "recordVersion": pipeline.record_version(),
                "digest": pipeline.digest(),
            });
        }
        record.metadata["endpointDiscovery"] = serde_json::json!({
            "unresolved": doc.discovery_unresolved,
            "unresolvedDropped": doc.discovery_unresolved_dropped,
        });
        if let Some(article) = &doc.article {
            let mut content = Vec::new();
            let artifact = match crawlx_extract::serialize::write_article(
                &mut content,
                doc,
                crawlx_extract::serialize::ArticleFormat::Json,
            ) {
                Ok(()) => {
                    if article.privacy_projection_version != Some(1) {
                        tracing::warn!("article privacy finalization unavailable");
                        return;
                    }
                    let stored = match crawlx_core::secret::Redactor::new().verify_canonical(&content) {
                        Ok(content) => {
                            ArtifactSink::over(self.deps.artifacts.as_ref())
                                .put_dataset(
                                    self.run,
                                    record.frontier_id,
                                    "article_json",
                                    "application/vnd.crawlx.article+json",
                                    &content,
                                )
                                .await
                        }
                        Err(error) => Err(error),
                    };
                    match stored {
                        Ok(reference) => Some(reference),
                        Err(_) => {
                            tracing::debug!("article content sink refused rendition");
                            None
                        }
                    }
                }
                Err(_) => {
                    tracing::warn!("article serialization failed");
                    None
                }
            };
            // Only bounded structural outcomes and retention-approved references enter page
            // metadata. Authors, source ranges, summary, keywords and main digest stay in the
            // content artifact, including under ZDR's volatile sink.
            if let Some(obj) = record.metadata.as_object_mut() {
                obj.insert(
                    "extraction".to_owned(),
                    serde_json::json!({
                        "version": article.version,
                        "extractor": article.extractor,
                        "strategy": article.strategy,
                        "quality": article.quality,
                        "content": artifact,
                    }),
                );
            }
        }
        let formats = &self.crawl.output.formats;
        if formats.contains(&OutputFormat::Markdown) {
            record.markdown = self
                .store(
                    record.frontier_id,
                    Sensitivity::Content,
                    "text/markdown",
                    doc.markdown.as_bytes(),
                )
                .await;
        }
        if formats.contains(&OutputFormat::Html) || formats.contains(&OutputFormat::RawHtml) {
            record.html = self
                .store(
                    record.frontier_id,
                    Sensitivity::Content,
                    "text/html",
                    doc.html.as_bytes(),
                )
                .await;
        }
    }

    /// Store one rendition of page `page`; under zero data retention the store keeps `content`
    /// in the delivery buffer when one is attached and refuses it otherwise.
    async fn store(
        &self,
        page: i64,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Option<crawlx_core::ArtifactRef> {
        let registry = self.captcha_secrets.as_ref()?;
        let redactor = crawlx_core::secret::Redactor::new();
        let controls = &self.fetcher.config().controls;
        let text = crate::capture::is_text_artifact(content_type) && std::str::from_utf8(bytes).is_ok();
        let bytes = if text {
            redactor.scrub_bytes(bytes, controls.secret_values())
        } else {
            crate::capture::check_run_secrets(bytes, controls, Some(registry)).ok()?;
            std::borrow::Cow::Borrowed(bytes)
        };
        let bytes = if text && registry.has_values().ok()? {
            let json = content_type.split(';').next().is_some_and(|mime| {
                mime.trim().eq_ignore_ascii_case("application/json")
                    || mime
                        .trim()
                        .rsplit_once('+')
                        .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
            });
            if json {
                let mut value: serde_json::Value = serde_json::from_slice(bytes.as_ref()).ok()?;
                registry.redact_json(&mut value).ok()?;
                std::borrow::Cow::Owned(serde_json::to_vec(&value).ok()?)
            } else {
                let text = std::str::from_utf8(bytes.as_ref()).ok()?;
                std::borrow::Cow::Owned(registry.redact(text).ok()?.into_bytes())
            }
        } else {
            bytes
        };
        let bytes = if text {
            redactor.redact_artifact(bytes.as_ref()).ok()?
        } else {
            redactor.verify_binary(bytes.as_ref()).ok()?
        };
        crate::capture::check_run_secrets(bytes.as_ref(), controls, Some(registry)).ok()?;
        match ArtifactSink::over(self.deps.artifacts.as_ref())
            .put_page(self.run, page, class, content_type, &bytes)
            .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                // ZDR without a delivery buffer refuses content artifacts; the page row is still written
                tracing::debug!(error = %e, "page artifact not stored");
                None
            }
        }
    }

    async fn event(&self, kind: &str, payload: serde_json::Value) {
        if let Err(e) = self.deps.events.append(self.run, kind, payload).await {
            tracing::warn!(error = %e, kind, "event not recorded");
        }
    }

    pub(crate) async fn persist_counters(&self) -> Result<(), WorkerError> {
        self.counters.persist(self.deps.runs.as_ref(), self.run).await?;
        Ok(())
    }

    /// Rebuild the bounded hybrid handoff from committed native evidence, including prior holders.
    async fn dynamic_start_requests(
        &self,
    ) -> Result<Vec<crawlx_core::request::RequestEnvelopeV1>, WorkerError> {
        let mut requests = Vec::new();
        if self.crawl.mode != CrawlMode::Hybrid {
            return Ok(requests);
        }
        let queue = self
            .crawl
            .orchestration
            .as_ref()
            .map_or_else(crawlx_core::orchestration::QueueConfigV1::default, |config| {
                config.queue.clone()
            });
        let max_entries = queue.max_pending_entries.min(u64::from(self.crawl.limits.urls));
        let mut bytes = 0u64;
        let mut after = 0;
        loop {
            let pages = self.deps.pages.committed_page_keyset(self.run, after, 64).await?;
            if pages.is_empty() {
                break;
            }
            for page in pages {
                after = page.frontier_id;
                if page
                    .metadata
                    .get("dynamic_signal")
                    .and_then(serde_json::Value::as_str)
                    .is_none()
                {
                    continue;
                }
                let request = self
                    .deps
                    .frontier
                    .get_request(self.run, page.frontier_id)
                    .await?
                    .envelope;
                self.crawl
                    .extensions
                    .route(&request.route)
                    .map_err(|error| WorkerError::Config(error.to_string()))?;
                let size = crawlx_core::extensions::json_size(&request)
                    .map_err(|error| WorkerError::Config(error.to_string()))?;
                bytes = bytes
                    .checked_add(
                        u64::try_from(size)
                            .map_err(|_| WorkerError::Config("hybrid request size overflow".into()))?,
                    )
                    .ok_or_else(|| WorkerError::Config("hybrid request size overflow".into()))?;
                if u64::try_from(requests.len()).unwrap_or(u64::MAX) >= max_entries
                    || bytes > queue.max_pending_envelope_bytes
                {
                    return Err(WorkerError::Config(
                        "hybrid request handoff exceeds queue bounds".into(),
                    ));
                }
                requests.push(request);
            }
        }
        Ok(requests)
    }

    /// Lease and process work until the frontier is exhausted, a limit or the deadline
    /// is reached, or the run is cancelled. Durable selection applies explicit request
    /// priority and the configured strategy before limiting the leased set. DFS and
    /// surface-priority dispatch reconsider the frontier after each response.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn run(&self, cancel: &CancellationToken) -> Result<UrlPlaneOutcome, WorkerError> {
        let hard_limit = BATCH.min(u32::from(self.crawl.politeness.max_concurrency.max(1)));
        let policy = self
            .crawl
            .orchestration
            .as_ref()
            .map_or_else(Default::default, |config| config.admission.clone());
        let mut admission = crate::runtime_admission::RuntimeAdmission::new(policy, hard_limit)?;
        for record in crate::runtime_admission::load_recorded(
            self.deps.events.as_ref(),
            self.run,
            self.deps.clock.now(),
        )
        .await?
        {
            if record.worker == self.worker {
                admission.replay(&record.decision)?;
            }
        }
        let terminal = loop {
            if self.authorization_lost().await {
                break TerminalReason::AuthorizationRevoked;
            }
            if self.stop_requested(cancel) {
                break TerminalReason::Cancelled;
            }
            let store_started = tokio::time::Instant::now();
            let run = self.deps.runs.get_metadata(self.run).await?;
            match run.status {
                RunStatus::Cancelled => break TerminalReason::Cancelled,
                RunStatus::Paused => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                _ => {}
            }
            let store_latency = store_started.elapsed();
            self.observe_admission(&mut admission, store_latency).await?;
            let pending = self.deps.frontier.pending_count(self.run).await?;
            Metrics::global().gauge(names::FRONTIER_DEPTH).set(
                u32::try_from(pending).map_or(f64::MAX, f64::from),
                &[("plane", Plane::Urls.as_str())],
            );
            // Remote leases, future eligibility and open producers are never exhaustion.
            if self.deps.frontier.activity(self.run).await?
                == crawlx_core::orchestration::FrontierActivityV1::Terminal
            {
                break TerminalReason::FrontierExhausted;
            }
            let (remaining, exhausted) = {
                let b = self.budget.lock();
                (
                    b.remaining(self.deps.clock.now()).urls,
                    b.exhausted(self.deps.clock.now()),
                )
            };
            if let Some(reason) = exhausted {
                break reason;
            }
            // Reserve worker-local stage capacity before taking any remote leases.
            // This lane creates no per-URL tasks and commits synchronously in lease order.
            // DFS and surface priority must reconsider children discovered by each response
            // before reserving siblings. Equal-priority BFS children cannot outrank their depth.
            let prefetch = match self.crawl.scope.strategy {
                crawlx_core::config::CrawlStrategy::BreadthFirst => BATCH,
                _ => 1,
            };
            let limit = prefetch.min(remaining.max(1)).min(admission.available(0)).min(
                self.crawl
                    .orchestration
                    .as_ref()
                    .map_or(BATCH, |config| config.queue.batch_size),
            );
            if limit == 0 {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    () = cancel.cancelled() => {}
                }
                continue;
            }
            let leased = self
                .deps
                .frontier
                .lease_batch_fenced(self.run, self.worker, limit)
                .await?;
            if leased.is_empty() {
                // retries wait out their backoff; rows leased to another worker wait for it to
                // finish them or for their lease to expire and the reaper to return them
                let wait = if pending == 0 { LEASE_WAIT } else { RETRY_WAIT };
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = cancel.cancelled() => {}
                }
                continue;
            }
            let mut entries = Vec::with_capacity(leased.len());
            {
                let mut held = self.held.lock();
                for (entry, fence) in leased {
                    held.insert(entry.id, fence);
                    entries.push(entry);
                }
            }
            // The leases run out after the batch TTL unless renewed (the reaper returns a row
            // whose holder stopped heartbeating): a batch that outlasts it keeps its rows for as
            // long as this plane is alive and working on them.
            let processing = self.process_batch(&entries, cancel);
            let renewing = self.keep_leases_alive();
            let observing = self.observe_admission_every_second(&mut admission);
            tokio::pin!(processing, renewing, observing);
            let processed = tokio::select! {
                result = &mut processing => result,
                never = &mut renewing => match never {},
                failed = &mut observing => match failed {
                    Err(error) => return Err(error),
                    Ok(never) => match never {},
                },
            };
            // nothing is renewed for a row nobody works on
            self.held.lock().clear();
            processed?;
        };
        // A stop/deadline closes continuous input too; already accepted rows remain durable.
        self.deps.frontier.seal(self.run, 1).await?;
        self.persist_counters().await?;
        Ok(UrlPlaneOutcome {
            terminal,
            pages_written: self.pages_written(),
            dynamic_requests: self.dynamic_start_requests().await?,
        })
    }

    /// Persist every sample before it can change new lease/task admission.
    async fn observe_admission(
        &self,
        admission: &mut crate::runtime_admission::RuntimeAdmission,
        store_latency: Duration,
    ) -> Result<(), WorkerError> {
        if let Some(decision) = admission
            .tick(
                &self.cpu_pool,
                self.deps.artifacts.as_ref(),
                self.admission_browser.as_ref(),
                Some(store_latency),
                Some(true),
            )
            .await?
        {
            let ceiling = decision.ceiling;
            let record =
                crawlx_core::runtime_admission::AdmissionRecordV1::new(self.run, self.worker, decision);
            let payload =
                serde_json::to_value(record).map_err(|error| StoreError::Serialization(error.to_string()))?;
            self.deps
                .events
                .append(self.run, "runtime.admission", payload)
                .await?;
            self.admission_ceiling
                .store(ceiling, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Sample the store round trip and observe admission once a second, for as long as the
    /// future is polled. It is polled beside the batch: a sample taken in the body of a
    /// `select!` arm would leave the pinned batch suspended inside its open transaction while
    /// the sample waits for the row locks that transaction holds.
    async fn observe_admission_every_second(
        &self,
        admission: &mut crate::runtime_admission::RuntimeAdmission,
    ) -> Result<std::convert::Infallible, WorkerError> {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let started = tokio::time::Instant::now();
            self.deps.runs.get(self.run).await?;
            self.observe_admission(admission, started.elapsed()).await?;
        }
    }

    /// Renew the leases of the rows in hand at the heartbeat period, for as long as the future is
    /// polled: a plane that dies takes its heartbeat with it, and the reaper returns its rows
    /// once the lease has expired.
    async fn keep_leases_alive(&self) -> std::convert::Infallible {
        let period = lease_heartbeat_period(self.deps.leases.url_batch_ttl());
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            self.renew_leases().await;
        }
    }

    /// One heartbeat: renew every row in hand under its fencing token. A row the heartbeat does
    /// not find under this worker's lease is no longer ours (its lease expired and the reaper
    /// returned it, or another worker leased it since): it leaves the held rows, so it is
    /// neither fetched nor completed any more.
    async fn renew_leases(&self) {
        let leases: Vec<(i64, i64)> = self.held.lock().iter().map(|(&id, &fence)| (id, fence)).collect();
        if leases.is_empty() {
            return;
        }
        match self.deps.leases.heartbeat_frontier(self.worker, &leases).await {
            Ok(renewed) => {
                let mut held = self.held.lock();
                for (id, _) in &leases {
                    // a row finished since the snapshot is not held (nor renewed) any more
                    if !renewed.contains(id) && held.remove(id).is_some() {
                        tracing::warn!(run = %self.run, row = id, "url lease lost: the row is not leased to this worker any more");
                    }
                }
            }
            // retried at the next tick: the lease lives on until its TTL
            Err(e) => tracing::warn!(run = %self.run, error = %e, "url leases not renewed"),
        }
    }
}

/// Period of the URL lease heartbeat for leases that live `ttl` without one: the session
/// heartbeat period (10 s against a 60 s TTL), and at most a third of the TTL so
/// that two renewals can fail before a live holder loses its rows.
fn lease_heartbeat_period(ttl: Duration) -> Duration {
    HEARTBEAT_INTERVAL.min(ttl / 3).max(Duration::from_millis(10))
}

fn denial_label(reason: &DenialReason) -> String {
    match reason {
        DenialReason::Excluded(pattern) => format!("excluded_path:{pattern}"),
        DenialReason::UrlExcluded(pattern) => format!("url_excluded:{pattern}"),
        DenialReason::HostExcluded(entry) => format!("host_excluded:{entry}"),
        other => other.as_str().to_owned(),
    }
}

/// Bounded `reason` label of a page that answered with a non-success status.
const fn http_status_class(code: u16) -> &'static str {
    match code / 100 {
        1 => "http_1xx",
        2 => "http_2xx",
        3 => "http_3xx",
        4 => "http_4xx",
        5 => "http_5xx",
        _ => "http_other",
    }
}

/// `pages.metadata.endpoints` (`extract.kbEndpoints`): every discovered endpoint with its
/// class, once per `(url, method, class)`, in discovery order.
fn classify_endpoints(endpoints: &[DiscoveredEndpoint]) -> serde_json::Value {
    let mut seen = BTreeSet::new();
    let items: Vec<serde_json::Value> = endpoints
        .iter()
        .filter_map(|e| {
            let class = classify_discovered(e).as_str();
            seen.insert((e.url.as_str(), e.method.as_str(), class)).then(
                || serde_json::json!({ "url": e.url.as_str(), "method": e.method.as_str(), "class": class }),
            )
        })
        .collect();
    serde_json::json!(items)
}

/// Request-target of `url` (`/path?query`).
fn request_target(url: &Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    }
}

/// HTTP/1.1 text of a request: request line, `host`, `headers` (lowercase names, already
/// redacted), a blank line and the optional body.
fn raw_request_text(
    method: &str,
    url: &Url,
    headers: &BTreeMap<String, String>,
    body: Option<&str>,
) -> String {
    let host = url.host_str().unwrap_or_default();
    let mut out = format!("{method} {} HTTP/1.1\r\n", request_target(url));
    match url.port() {
        Some(port) => out.push_str(&format!("host: {host}:{port}\r\n")),
        None => out.push_str(&format!("host: {host}\r\n")),
    }
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    if let Some(body) = body {
        out.push_str(body);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn head_refuses_selected_delegate_and_browser_routes_without_get_fallback() {
        use crawlx_core::orchestration::RequestBatchV1;
        use crawlx_core::request::RequestEnvelopeV1;

        for mode in [CrawlMode::Static, CrawlMode::Hybrid] {
            for backend in ["delegate", "browser"] {
                let directory = tempfile::tempdir().unwrap();
                let stores = crate::Stores::over_memory(
                    Arc::new(crawlx_storage::MemoryStore::new()),
                    directory.path(),
                )
                .await
                .unwrap();
                let target = Url::parse("https://head-route.invalid/head").unwrap();
                let mut crawl = CreateCrawl::new(target);
                crawl.mode = mode;
                crawl.safety.respect_robots_txt = false;
                crawl.protocol.routes.push(
                    serde_json::from_value(serde_json::json!({
                        "id": "required-head-route",
                        "schemes": ["https"],
                        "origin": null,
                        "pathPattern": "^/head$",
                        "schedulerMetadata": {},
                        "backend": backend,
                        "delegateId": (backend == "delegate").then_some("owned-head-service"),
                        "requiredCapabilities": [],
                        "maxBodyBytes": 1024,
                        "maxElapsedMs": 1000,
                        "policyRevision": "owned-v1"
                    }))
                    .unwrap(),
                );
                let run = crawlx_storage::testkit::crawl_run(stores.tenant, crawl.clone());
                stores.runs.create(&run, None).await.unwrap();
                let request = RequestEnvelopeV1::new(
                    crawlx_storage::testkit::canonical_url("https://head-route.invalid/head"),
                    "HEAD".into(),
                    0,
                    None,
                );
                stores
                    .frontier
                    .append_batch(RequestBatchV1::new(
                        stores.tenant,
                        run.id,
                        "anonymous".into(),
                        crawlx_core::hash::Digest::of("test/head-route", backend.as_bytes()),
                        vec![request],
                    ))
                    .await
                    .unwrap();
                let worker = WorkerId::new();
                let (entry, fence) = stores
                    .frontier
                    .lease_batch_fenced(run.id, worker, 1)
                    .await
                    .unwrap()
                    .pop()
                    .unwrap();
                let fetcher = Arc::new(
                    Fetcher::new(
                        crawlx_fetch::FetchConfig::default(),
                        Arc::new(crawlx_policy::EgressPolicy::default()),
                        Arc::new(crawlx_fetch::StaticResolver::new()),
                    )
                    .unwrap(),
                );
                let runner = UrlPlaneRunner::new(
                    run.id,
                    crawl,
                    worker,
                    UrlPlaneDeps {
                        runs: stores.runs.clone(),
                        frontier: stores.frontier.clone(),
                        request_commits: stores.request_commits.clone(),
                        source_memo: stores.source_memo.clone(),
                        leases: stores.leases.clone(),
                        pages: stores.pages.clone(),
                        events: stores.events.clone(),
                        artifacts: stores.artifacts.clone(),
                        archives: stores.archives.clone(),
                        clock: Arc::new(crawlx_core::SystemClock),
                    },
                    fetcher,
                    RunCounters::default(),
                    CanonicalizeOptions::default(),
                )
                .unwrap();
                runner.held.lock().insert(entry.id, fence);
                runner
                    .process_entry(&entry, &CancellationToken::new())
                    .await
                    .unwrap();
                let queued = stores.frontier.get_request(run.id, entry.id).await.unwrap();
                assert_eq!(queued.envelope.method, "HEAD");
                assert_eq!(queued.entry.status, FrontierStatus::Failed);
                assert_eq!(
                    queued.entry.denial_reason.as_deref(),
                    Some("request_backend_unavailable")
                );
                assert!(stores.pages.list(run.id).await.unwrap().is_empty());
                assert!(stores
                    .events
                    .list_after(run.id, 0, 100)
                    .await
                    .unwrap()
                    .iter()
                    .all(|event| event.kind != "head_response"));
            }
        }
    }

    #[tokio::test]
    async fn dispatch_futures_remain_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let stores =
            crate::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), directory.path())
                .await
                .unwrap();
        let mut crawl = CreateCrawl::new(Url::parse("https://dispatch-fixture.invalid/").unwrap());
        crawl.mode = CrawlMode::Static;
        let canonical =
            Canonicalizer::canonicalize_url(&crawl.seed_url, &CanonicalizeOptions::default()).unwrap();
        let run = crawlx_storage::testkit::crawl_run(stores.tenant, crawl.clone());
        stores.runs.create(&run, None).await.unwrap();
        stores
            .frontier
            .discover(run.id, &canonical, 0, None, None)
            .await
            .unwrap();
        let entry = stores.frontier.list(run.id).await.unwrap().pop().unwrap();
        let fetcher = Arc::new(
            Fetcher::new(
                crawlx_fetch::FetchConfig::default(),
                Arc::new(crawlx_policy::EgressPolicy::default()),
                Arc::new(crawlx_fetch::StaticResolver::new()),
            )
            .unwrap(),
        );
        let runner = UrlPlaneRunner::new(
            run.id,
            crawl,
            WorkerId::new(),
            UrlPlaneDeps {
                runs: stores.runs.clone(),
                frontier: stores.frontier.clone(),
                request_commits: stores.request_commits.clone(),
                source_memo: stores.source_memo.clone(),
                leases: stores.leases.clone(),
                pages: stores.pages.clone(),
                events: stores.events.clone(),
                artifacts: stores.artifacts.clone(),
                archives: stores.archives.clone(),
                clock: Arc::new(crawlx_core::SystemClock),
            },
            fetcher,
            RunCounters::default(),
            CanonicalizeOptions::default(),
        )
        .unwrap();
        let cancel = CancellationToken::new();
        for (name, size) in [
            (
                "entry",
                std::mem::size_of_val(&runner.process_entry(&entry, &cancel)),
            ),
            (
                "leased",
                std::mem::size_of_val(&runner.process_leased(&entry, &cancel, false)),
            ),
        ] {
            assert!(size <= 8 * 1024, "{name} future uses {size} bytes");
        }
    }

    #[tokio::test]
    async fn artifact_storage_rechecks_scoped_secrets_created_by_final_json_projection() {
        let directory = tempfile::tempdir().unwrap();
        let stores =
            crate::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), directory.path())
                .await
                .unwrap();
        let mut crawl = CreateCrawl::new(Url::parse("https://artifact-fixture.invalid/").unwrap());
        crawl.mode = CrawlMode::Static;
        let run = crawlx_storage::testkit::crawl_run(stores.tenant, crawl.clone());
        stores.runs.create(&run, None).await.unwrap();
        let fetcher = Arc::new(
            Fetcher::new(
                crawlx_fetch::FetchConfig::default(),
                Arc::new(crawlx_policy::EgressPolicy::default()),
                Arc::new(crawlx_fetch::StaticResolver::new()),
            )
            .unwrap(),
        );
        let deps = UrlPlaneDeps {
            runs: stores.runs.clone(),
            frontier: stores.frontier.clone(),
            request_commits: stores.request_commits.clone(),
            source_memo: stores.source_memo.clone(),
            leases: stores.leases.clone(),
            pages: stores.pages.clone(),
            events: stores.events.clone(),
            artifacts: stores.artifacts.clone(),
            archives: stores.archives.clone(),
            clock: Arc::new(crawlx_core::SystemClock),
        };
        let mut runner = UrlPlaneRunner::new(
            run.id,
            crawl,
            WorkerId::new(),
            deps,
            fetcher,
            RunCounters::default(),
            CanonicalizeOptions::default(),
        )
        .unwrap();
        let registry = crawlx_core::captcha::CaptchaSecrets::default();
        registry
            .register(crawlx_core::secret::SecretOr::secret("AA[REDACTED]BB".into()))
            .unwrap();
        runner.captcha_secrets = Some(registry);
        assert!(crawlx_core::secret::register_secret("origCanaryRawStore9742"));
        // JSON decoding happens after the first literal scrub. Final core projection then
        // creates the scoped token, which must not reach the real artifact backend.
        let unsafe_body = br#"{"data":"AAorig\u0043anaryRawStore9742BB"}"#;
        assert!(runner
            .store(0, Sensitivity::Content, "application/json", unsafe_body)
            .await
            .is_none());
        let public = br#"{"message":"public-artifact-marker"}"#;
        let artifact = runner
            .store(0, Sensitivity::Content, "application/json", public)
            .await
            .expect("the same real backend retains public JSON");
        assert_eq!(stores.artifacts.get(&artifact).await.unwrap(), public);
    }

    struct PausedAuthorizationRead {
        inner: crate::authorization::StaticAuthorizationSource,
        pause: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl crate::authorization::AuthorizationSource for PausedAuthorizationRead {
        async fn fetch(
            &self,
            record: crawlx_core::AuthorizationRecordId,
        ) -> Result<Option<crawlx_policy::AuthorizationRecord>, WorkerError> {
            if self.pause.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            crate::authorization::AuthorizationSource::fetch(&self.inner, record).await
        }
    }

    #[tokio::test]
    async fn a_drain_crossing_the_pre_dispatch_authority_await_never_sends() {
        use crawlx_core::repo::CrawlRun;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base = Url::parse(&format!("http://{address}/")).unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&requests);
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    "ordinary response"
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let directory = tempfile::tempdir().unwrap();
        let stores =
            crate::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), directory.path())
                .await
                .unwrap();
        let clock: Arc<dyn Clock> = Arc::new(crawlx_core::SystemClock);
        let mut record = crawlx_policy::testkit::sample_record(stores.tenant, clock.now(), &[base.as_str()]);
        record.verified_at = Some(clock.now());
        record.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
        let source = Arc::new(PausedAuthorizationRead {
            inner: crate::authorization::StaticAuthorizationSource::new(record.clone()),
            pause: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let mut crawl = CreateCrawl::new(base.clone());
        crawl.mode = CrawlMode::Static;
        crawl.seed = Some(42);
        crawl.politeness.delay_ms = 0;
        crawl.safety.allow_private_networks = true;
        crawl.safety.authorization_record_ref = Some(record.id);
        crawl.normalize().unwrap();
        let run = CrawlRun {
            id: CrawlRunId::new(),
            tenant: stores.tenant,
            status: RunStatus::Running,
            terminal_reason: None,
            config_digest: crawl.digest().unwrap(),
            seed: crawl.effective_seed(),
            policy_version: 1,
            counters: Default::default(),
            created_at: clock.now(),
            started_at: Some(clock.now()),
            finished_at: None,
            trace_id: None,
            config: crawl.clone(),
        };
        stores.runs.create(&run, None).await.unwrap();
        let canonical = Canonicalizer::canonicalize_url(&base, &CanonicalizeOptions::default()).unwrap();
        stores
            .frontier
            .discover(run.id, &canonical, 0, None, None)
            .await
            .unwrap();
        let worker = WorkerId::new();
        let (entry, fence) = stores
            .frontier
            .lease_batch_fenced(run.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let guard = AuthorizationGuard::admit(
            run.id,
            None,
            Some(record.id),
            source.clone(),
            clock.clone(),
            stores.events.clone(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        let drain = CancellationToken::new();
        let cancel = drain.child_token();
        guard.cancels(cancel.clone());
        let mut policy = crawlx_policy::EgressPolicy::new(false);
        policy.extra_allow = vec!["127.0.0.1/32".parse().unwrap()];
        policy.extra_ports = vec![address.port()];
        let fetcher = Arc::new(
            Fetcher::new(
                crawlx_fetch::FetchConfig::default(),
                Arc::new(policy),
                Arc::new(crawlx_fetch::StaticResolver::new()),
            )
            .unwrap(),
        );
        let deps = UrlPlaneDeps {
            runs: stores.runs.clone(),
            frontier: stores.frontier.clone(),
            request_commits: stores.request_commits.clone(),
            source_memo: stores.source_memo.clone(),
            leases: stores.leases.clone(),
            pages: stores.pages.clone(),
            events: stores.events.clone(),
            artifacts: stores.artifacts.clone(),
            archives: stores.archives.clone(),
            clock,
        };
        let runner = UrlPlaneRunner::new(
            run.id,
            crawl,
            worker,
            deps,
            fetcher,
            RunCounters::default(),
            CanonicalizeOptions::default(),
        )
        .unwrap()
        .with_authorization(Some(guard))
        .with_graceful_drain(drain.clone(), None);
        runner.held.lock().insert(entry.id, fence);
        source.pause.store(true, std::sync::atomic::Ordering::SeqCst);
        let fetching = tokio::spawn(async move {
            runner
                .fetch_legacy(&entry, &FetchOptions::default(), &cancel)
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), source.entered.notified())
            .await
            .unwrap();
        drain.cancel();
        source.release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(3), fetching)
            .await
            .unwrap()
            .unwrap();
        server.abort();
        assert!(
            matches!(result, Err(FetchError::AcquisitionCancelled)),
            "{result:?}"
        );
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn graceful_static_drain_finishes_one_response_but_hard_cancel_and_fence_loss_interrupt_it() {
        use crawlx_core::repo::CrawlRun;

        for stop in ["graceful", "hard", "fence"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let base = Url::parse(&format!("http://{address}/")).unwrap();
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let app = axum::Router::new().route(
                "/",
                axum::routing::get({
                    let entered = Arc::clone(&entered);
                    let release = Arc::clone(&release);
                    move || {
                        let entered = Arc::clone(&entered);
                        let release = Arc::clone(&release);
                        async move {
                            entered.notify_one();
                            release.notified().await;
                            "one completed response"
                        }
                    }
                }),
            );
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let directory = tempfile::tempdir().unwrap();
            let stores =
                crate::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), directory.path())
                    .await
                    .unwrap();
            let clock: Arc<dyn Clock> = Arc::new(crawlx_core::SystemClock);
            let mut crawl = CreateCrawl::new(base.clone());
            crawl.mode = CrawlMode::Static;
            crawl.seed = Some(42);
            crawl.normalize().unwrap();
            let run = CrawlRun {
                id: CrawlRunId::new(),
                tenant: stores.tenant,
                status: RunStatus::Running,
                terminal_reason: None,
                config_digest: crawl.digest().unwrap(),
                seed: crawl.effective_seed(),
                policy_version: 1,
                counters: Default::default(),
                created_at: clock.now(),
                started_at: Some(clock.now()),
                finished_at: None,
                trace_id: None,
                config: crawl.clone(),
            };
            stores.runs.create(&run, None).await.unwrap();
            let canonical = Canonicalizer::canonicalize_url(&base, &CanonicalizeOptions::default()).unwrap();
            stores
                .frontier
                .discover(run.id, &canonical, 0, None, None)
                .await
                .unwrap();
            let worker = WorkerId::new();
            let (entry, fence) = stores
                .frontier
                .lease_batch_fenced(run.id, worker, 1)
                .await
                .unwrap()
                .pop()
                .unwrap();
            let mut policy = crawlx_policy::EgressPolicy::new(false);
            policy.extra_allow = vec!["127.0.0.1/32".parse().unwrap()];
            policy.extra_ports = vec![address.port()];
            let fetcher = Arc::new(
                Fetcher::new(
                    crawlx_fetch::FetchConfig::default(),
                    Arc::new(policy),
                    Arc::new(crawlx_fetch::StaticResolver::new()),
                )
                .unwrap(),
            );
            let drain = CancellationToken::new();
            let hard = CancellationToken::new();
            let cancel = hard.child_token();
            let runner = Arc::new(
                UrlPlaneRunner::new(
                    run.id,
                    crawl,
                    worker,
                    UrlPlaneDeps {
                        runs: stores.runs.clone(),
                        frontier: stores.frontier.clone(),
                        request_commits: stores.request_commits.clone(),
                        source_memo: stores.source_memo.clone(),
                        leases: stores.leases.clone(),
                        pages: stores.pages.clone(),
                        events: stores.events.clone(),
                        artifacts: stores.artifacts.clone(),
                        archives: stores.archives.clone(),
                        clock,
                    },
                    fetcher,
                    RunCounters::default(),
                    CanonicalizeOptions::default(),
                )
                .unwrap()
                .with_graceful_drain(drain.clone(), Some(hard.clone())),
            );
            runner.held.lock().insert(entry.id, fence);
            let fetching = tokio::spawn({
                let runner = Arc::clone(&runner);
                let entry = entry.clone();
                let cancel = cancel.clone();
                async move {
                    runner
                        .fetch_legacy(&entry, &FetchOptions::default(), &cancel)
                        .await
                }
            });
            tokio::time::timeout(Duration::from_secs(3), entered.notified())
                .await
                .unwrap();
            drain.cancel();
            cancel.cancel();
            assert!(runner.is_draining());
            match stop {
                "graceful" => release.notify_one(),
                "hard" => {
                    hard.cancel();
                    assert!(!runner.is_draining());
                }
                "fence" => {
                    stores.frontier.give_back(entry.id, fence).await.unwrap();
                    let successor = WorkerId::new();
                    let (_, next_fence) = stores
                        .frontier
                        .lease_batch_fenced(run.id, successor, 1)
                        .await
                        .unwrap()
                        .pop()
                        .unwrap();
                    runner.renew_leases().await;
                    assert!(!runner.held.lock().contains_key(&entry.id));
                    assert_eq!(
                        stores
                            .leases
                            .heartbeat_frontier(successor, &[(entry.id, next_fence)])
                            .await
                            .unwrap(),
                        [entry.id]
                    );
                }
                _ => unreachable!(),
            }
            let result = tokio::time::timeout(Duration::from_secs(3), fetching)
                .await
                .unwrap()
                .unwrap();
            if stop == "graceful" {
                assert!(result.is_ok(), "{result:?}");
            } else {
                assert!(
                    matches!(result, Err(FetchError::AcquisitionCancelled)),
                    "{stop}: {result:?}"
                );
            }
            server.abort();
        }
    }

    #[test]
    fn the_lease_heartbeat_is_the_session_heartbeat_and_at_most_a_third_of_the_ttl() {
        assert_eq!(
            lease_heartbeat_period(Duration::from_secs(60)),
            Duration::from_secs(10),
            "10 s heartbeat, 60 s URL batch TTL"
        );
        assert_eq!(
            lease_heartbeat_period(Duration::from_secs(2)),
            Duration::from_secs(2) / 3
        );
        assert_eq!(
            lease_heartbeat_period(Duration::ZERO),
            Duration::from_millis(10),
            "never a zero period"
        );
    }

    #[test]
    fn spa_markers_are_detected() {
        let spa =
            r#"<html><body><div id="app"></div><script type="module" src="/a.js"></script></body></html>"#;
        assert_eq!(classify_dynamic(spa, 0), Some(DynamicSignal::SpaRoot));
        // a real page that happens to use id="root" with lots of text is static
        assert_eq!(classify_dynamic(r#"<div id="root">text</div>"#, 400), None);
        let modules = r#"<script type="module" src="a.js"></script><script type="module" src="b.js"></script><script type=module src=c.js></script>"#;
        assert_eq!(classify_dynamic(modules, 500), Some(DynamicSignal::ModuleScripts));
        let hashes = r##"<a href="#/one">1</a><a href="#!/two">2</a>"##;
        assert_eq!(classify_dynamic(hashes, 500), Some(DynamicSignal::HashRoutes));
        assert_eq!(classify_dynamic("<p>plain</p><a href=\"#top\">t</a>", 5), None);
    }

    /// One page of the labelled promotion corpus: `(name, html, extracted word count,
    /// needs a browser)`.
    type Labelled = (&'static str, String, usize, bool);

    fn words(n: usize) -> String {
        (0..n).map(|i| format!("word{i}")).collect::<Vec<_>>().join(" ")
    }

    /// Twenty synthetic pages, ten per label.
    fn promotion_corpus() -> Vec<Labelled> {
        let controls: String = (0..30)
            .map(|i| format!(r#"<button onclick="go({i})">B{i}</button>"#))
            .collect();
        let dynamic: Vec<Labelled> = vec![
            (
                "react-root",
                r#"<html><body><div id="root"></div><script src="/static/js/main.3f2a.js"></script></body></html>"#.into(),
                0,
                true,
            ),
            (
                "nextjs-ssr",
                format!(r#"<html><body><div id="__next"><article>{}</article></div><script id="__NEXT_DATA__" type="application/json">{{"props":{{}}}}</script></body></html>"#, words(400)),
                400,
                true,
            ),
            (
                "nuxt",
                format!(r#"<html><body><div id="__nuxt" data-server-rendered="true">{}</div><script>window.__NUXT__={{}}</script></body></html>"#, words(120)),
                120,
                true,
            ),
            (
                "angular",
                r#"<html><body><app-root ng-version="17.0.0"></app-root><script src="runtime.js"></script><script src="main.js"></script></body></html>"#.into(),
                0,
                true,
            ),
            (
                "noscript-warning",
                format!(r#"<html><body><noscript>You need to enable JavaScript to run this app.</noscript><div id="shell">{}</div></body></html>"#, words(60)),
                60,
                true,
            ),
            (
                "pushstate-router",
                format!(r#"<html><body><nav><a href="/a">A</a></nav><main>{}</main><script>document.addEventListener('click', e => {{ history.pushState({{}}, '', e.target.href); render(); }});</script></body></html>"#, words(200)),
                200,
                true,
            ),
            (
                "hash-router",
                r##"<html><body><a href="#/inbox">Inbox</a><a href="#!/sent">Sent</a><div id="view"></div></body></html>"##.into(),
                2,
                true,
            ),
            (
                "module-bundle",
                format!(r#"<html><body><div class="mount"><p>{}</p></div><script type="module" src="/a.js"></script><script type="module" src="/b.js"></script><script type=module src=/c.js></script></body></html>"#, words(200)),
                200,
                true,
            ),
            (
                "xhr-dashboard",
                format!(r#"<html><body><h1>Dashboard</h1><div id="widgets">{}</div><script>fetch('/api/kpis').then(r=>r.json()).then(draw); fetch('/api/alerts').then(r=>r.json()).then(list); const x = new XMLHttpRequest(); x.open('GET','/api/me'); x.send();</script></body></html>"#, words(40)),
                40,
                true,
            ),
            (
                "control-heavy-app",
                format!(r#"<html><body><div class="toolbar">{controls}</div><p>{}</p></body></html>"#, words(80)),
                80,
                true,
            ),
        ];
        let static_pages: Vec<Labelled> = vec![
            (
                "blog-post-with-analytics",
                format!(
                    r#"<html><head><script async src="https://analytics.example/ga.js"></script></head><body><article><h1>Title</h1><p>{}</p></article></body></html>"#,
                    words(900)
                ),
                900,
                false,
            ),
            (
                "docs-page",
                format!(
                    r#"<html><body><nav><a href="/docs/a">A</a><a href="/docs/b">B</a></nav><main>{}</main><script src="/highlight.js"></script></body></html>"#,
                    words(600)
                ),
                600,
                false,
            ),
            (
                "product-page",
                format!(
                    r#"<html><body><h1>Lamp</h1><p>{}</p><form action="/cart" method="post"><input type="hidden" name="sku" value="1"><button>Add to cart</button></form><script src="/gallery.js"></script><script src="/reviews.js"></script></body></html>"#,
                    words(350)
                ),
                350,
                false,
            ),
            (
                "landing-with-contact-form",
                format!(
                    r#"<html><body><section>{}</section><form><input name="email"><textarea name="msg"></textarea><button>Send</button></form></body></html>"#,
                    words(250)
                ),
                250,
                false,
            ),
            (
                "static-table",
                format!(
                    r#"<html><body><table>{}</table></body></html>"#,
                    (0..40)
                        .map(|i| format!("<tr><td>row {i}</td><td>{}</td></tr>", words(6)))
                        .collect::<String>()
                ),
                320,
                false,
            ),
            (
                "ssr-with-root-id-and-text",
                format!(
                    r#"<html><body><div id="root"><article>{}</article></div></body></html>"#,
                    words(400)
                ),
                400,
                false,
            ),
            (
                "noscript-tracking-pixel",
                format!(
                    r#"<html><body><noscript><img src="https://px.example/p.gif" alt=""></noscript><main>{}</main></body></html>"#,
                    words(300)
                ),
                300,
                false,
            ),
            (
                "newsletter-single-fetch",
                format!(
                    r#"<html><body><article>{}</article><script>document.querySelector('form').onsubmit = e => {{ e.preventDefault(); fetch('/subscribe', {{method:'POST'}}); }};</script></body></html>"#,
                    words(500)
                ),
                500,
                false,
            ),
            (
                "plain-html",
                format!("<html><body><h1>About</h1><p>{}</p></body></html>", words(150)),
                150,
                false,
            ),
            (
                "link-heavy-index",
                format!(
                    "<html><body><ul>{}</ul></body></html>",
                    (0..80)
                        .map(|i| format!(r#"<li><a href="/p/{i}">Page {i} {}</a></li>"#, words(3)))
                        .collect::<String>()
                ),
                400,
                false,
            ),
        ];
        dynamic.into_iter().chain(static_pages).collect()
    }

    #[test]
    fn promotion_recall_and_false_promotion_meet_the_promotion_targets() {
        let corpus = promotion_corpus();
        assert_eq!(corpus.len(), 20);
        let classifier = DynamicClassifier::new(&[]).unwrap();
        let (mut tp, mut fn_, mut fp_, mut tn) = (0usize, 0usize, 0usize, 0usize);
        let mut misses = Vec::new();
        let mut false_promotions = Vec::new();
        for (name, html, words, needs_browser) in &corpus {
            let promoted = classifier.classify("/x", html, *words);
            match (needs_browser, promoted.is_some()) {
                (true, true) => tp += 1,
                (true, false) => {
                    fn_ += 1;
                    misses.push(*name);
                }
                (false, true) => {
                    fp_ += 1;
                    false_promotions.push((*name, promoted));
                }
                (false, false) => tn += 1,
            }
        }
        let recall = tp as f64 / (tp + fn_) as f64;
        let false_promotion = fp_ as f64 / (fp_ + tn) as f64;
        assert!(recall >= 0.95, "recall {recall} < 0.95; missed {misses:?}");
        assert!(
            false_promotion <= 0.20,
            "false-promotion rate {false_promotion} > 0.20: {false_promotions:?}"
        );
    }

    #[test]
    fn each_signal_is_attributed_to_its_marker() {
        let c = DynamicClassifier::new(&[]).unwrap();
        let by_name: std::collections::BTreeMap<&str, (String, usize)> = promotion_corpus()
            .into_iter()
            .map(|(n, h, w, _)| (n, (h, w)))
            .collect();
        let signal = |n: &str| {
            let (h, w) = &by_name[n];
            c.classify("/p", h, *w)
        };
        assert_eq!(signal("react-root"), Some(DynamicSignal::SpaRoot));
        assert_eq!(signal("nextjs-ssr"), Some(DynamicSignal::FrameworkMarkers));
        assert_eq!(signal("angular"), Some(DynamicSignal::FrameworkMarkers));
        assert_eq!(signal("noscript-warning"), Some(DynamicSignal::NoscriptFallback));
        assert_eq!(signal("pushstate-router"), Some(DynamicSignal::PushStateRouting));
        assert_eq!(signal("hash-router"), Some(DynamicSignal::HashRoutes));
        assert_eq!(signal("module-bundle"), Some(DynamicSignal::ModuleScripts));
        assert_eq!(signal("xhr-dashboard"), Some(DynamicSignal::XhrHeavy));
        assert_eq!(
            signal("control-heavy-app"),
            Some(DynamicSignal::InteractiveControlsHeavy)
        );
        assert_eq!(signal("plain-html"), None);
    }

    #[test]
    fn always_browser_paths_win_over_the_heuristics() {
        let c = DynamicClassifier::new(&["/app/.*".to_owned(), "/admin".to_owned()]).unwrap();
        let plain = "<html><body><p>plain</p></body></html>";
        assert_eq!(
            c.classify("/app/settings", plain, 300),
            Some(DynamicSignal::AlwaysBrowserPath)
        );
        assert_eq!(
            c.classify("/admin", plain, 300),
            Some(DynamicSignal::AlwaysBrowserPath)
        );
        assert_eq!(c.classify("/docs", plain, 300), None);
        assert!(c.always_browser("/app/x") && !c.always_browser("/application"));
        assert_eq!(DynamicSignal::AlwaysBrowserPath.as_str(), "always_browser_path");
        assert!(
            DynamicClassifier::new(&["(".to_owned()]).is_err(),
            "bad patterns are rejected"
        );
    }

    #[test]
    fn static_response_capture_metadata_preserves_real_ref_and_explicit_policy_outcome() {
        let artifact = crawlx_core::ArtifactRef {
            id: crawlx_core::ArtifactId::new(),
            digest: crawlx_core::hash::Digest::of("capture-test", b"retained prefix"),
        };
        let mut response = FetchResponse {
            final_url: Url::parse("https://example.test/static").unwrap(),
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::from_static(b"retained prefix"),
            truncated: false,
            redirects: Vec::new(),
            hops: Vec::new(),
            resolved_ip: std::net::IpAddr::from([127, 0, 0, 1]),
            peer_observed: true,
            content_type: Some("text/plain".to_owned()),
            attempts: 1,
            duration: Duration::ZERO,
        };
        assert!(response_body_capture_metadata(&response).is_none());
        for (name, value) in [
            ("x-crawlx-stream-body-mode", "text_capped".to_owned()),
            ("x-crawlx-stream-body-capture", "stored_prefix".to_owned()),
            ("x-crawlx-stream-body-truncated", "true".to_owned()),
            ("x-crawlx-stream-body-limit", "65536".to_owned()),
            ("x-crawlx-stream-response-artifact-id", artifact.id.to_string()),
            (
                "x-crawlx-stream-response-artifact-digest",
                artifact.digest.to_hex(),
            ),
        ] {
            response
                .headers
                .insert(http::HeaderName::from_static(name), value.parse().unwrap());
        }
        let capture = response_body_capture_metadata(&response).unwrap();
        assert_eq!(capture["artifact"], serde_json::to_value(&artifact).unwrap());
        assert_eq!(capture["outcome"], "stored_prefix");
        assert_eq!(capture["mode"], "text_capped");
        assert_eq!(capture["truncated"], true);
        assert_eq!(capture["limit"], 65536);
        response.headers.remove("x-crawlx-stream-response-artifact-id");
        response
            .headers
            .remove("x-crawlx-stream-response-artifact-digest");
        response.headers.insert(
            "x-crawlx-stream-body-capture",
            http::HeaderValue::from_static("policy_denied"),
        );
        let denied = response_body_capture_metadata(&response).unwrap();
        assert_eq!(denied["artifact"], serde_json::Value::Null);
        assert_eq!(denied["outcome"], "policy_denied");
    }
}
