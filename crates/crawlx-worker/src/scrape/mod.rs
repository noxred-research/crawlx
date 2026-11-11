//! The compatibility-API scrape engine: turns the pages of a run whose
//! [`crawlx_core::config::CreateCrawl::scrape`] is set into compatibility documents.
//!
//! * [`ScrapeEngine`] – one engine per run; the URL plane ([`crate::UrlPlaneRunner`]) hands it
//!   every frontier row of a `crawl`, `batch` or `scrape` job ([`JobKind::Map`] runs fetch and
//!   extract like any other run and never reach the engine).
//! * [`cache`] – `maxAge`, `minAge` and `lockdown`: which stored scrape answers a request.
//! * [`render`] – the browser leg (`waitFor`, `actions`, `mobile`, screenshots, PDF).
//!
//! # What the engine stores
//!
//! For every page it is given, the engine produces one [`PageRecord`] (written by the URL plane)
//! plus artifacts of the run. HTTP status never fails a page: a `404` or `500` answer is stored
//! as a document whose `statusCode` says so. Only transport, timeout, egress, render, LLM and
//! content-type failures end the frontier row as failed, with the reason codes of
//! [`FailReason`] and a `page.failed` event `{url, reason, message}` (the message never contains
//! a configured header or cookie value).
//!
//! | Where | What |
//! |---|---|
//! | `PageRecord::url` | the requested canonical URL |
//! | `PageRecord::status`, `content_type`, `title` | of the final response (`title` of the HTML, or the PDF's `/Title`) |
//! | `PageRecord::markdown` | artifact `text/markdown`, stored when `markdown` **or** `changeTracking` is requested (the latter compares markdown); the API shows it only for `markdown` |
//! | `PageRecord::html` | artifact `text/html`: the cleaned HTML of the selected content, stored when `html` is requested |
//! | `PageRecord::links` | absolute URLs of the whole document, only when `links` is requested |
//! | `PageRecord::fetched_at` | when the content was fetched; a cache hit keeps the original time |
//! | `metadata["final_url"]`, `["redirects"]`, `["response_headers"]`, `["fingerprint"]`, `["request"]` | as on any static-plane page (credential headers are dropped, echoes of configured secrets redacted) |
//! | `metadata["scrape"]` | the serialized [`ScrapeDocument`](crawlx_core::scrape::ScrapeDocument) |
//!
//! Inside the document: `statusCode`, `finalUrl`, `meta` (compatibility metadata keys),
//! `numPages`/`totalPages` (PDF), `pages` and `blocks` (the `pdf` parser's options), `warning`
//! (a skipped or degraded step, e.g. `ocr_unavailable`), `cacheState` + `cachedAt`, `optionsDigest` (what a stored
//! scrape must match to be served again), `notCacheable`, and one field per requested format
//! (`images`, `attributes`, `branding`, `summary`, `json`, `answer`, `highlights`, `query`,
//! `changeTracking`, `actions`, `llmTokens`, `transcript`). Binary results are [`BlobRef`]s to
//! `content` artifacts of the run: `rawHtml` (the body verbatim, on the browser plane the
//! serialized DOM), `rawBase64` (the body bytes), `screenshot`, `audio` and `video` (the media
//! files, see `media`), and the screenshots and PDFs of the `actions`.
//!
//! Native articles keep their typed envelope separate from page-authored metadata. CPU-bound
//! composition jointly verifies finalized main/comment sources, effective policy and source-only
//! ranges; storage preserves the approved schema vocabulary and generated source/cache references.
//! Content metadata still receives privacy checks; arbitrary metadata keys remain redacted.
//! Retained cache reads reapprove the exact saved bytes and revalidate source and policy lineage.
//!
//! # Pipeline
//!
//! 1. **Cache.** `lockdown` and `minAge` answer from stored scrapes only (a miss ends the row as
//!    `lockdown_cache_miss` / `no_cached_data`); otherwise a scrape younger than `maxAge` is
//!    served unless the request asks for `changeTracking` (which always fetches) or belongs to a
//!    crawl without the `links` format (the crawl needs the live links to follow). A hit writes a
//!    new page row that references the stored artifacts.
//! 2. **Acquire.** The HTTP plane fetches through the run's [`Fetcher`] (egress policy, request
//!    controls, politeness); when the options need a browser (`waitFor`, `actions`, `mobile`,
//!    `screenshot`) the [`PageRenderer`] renders the page instead and its DOM is the body.
//!    `timeout` bounds the whole page: fetch or render, extraction and every LLM call.
//! 3. **Compose.** HTML goes through the extractor on the worker's CPU pool (`onlyMainContent`,
//!    `includeTags`, `excludeTags`), other textual bodies are their own markdown, and the
//!    `parsers` list decides the rest (absent means `[pdf, image]`):
//!    * `application/pdf` with a `pdf` parser goes through the PDF parser (`maxPages`,
//!      `pageMarkers`; `pages: true` fills `pages`, `blocks: true` fills `blocks`); `mode: ocr`
//!      and pages without a text layer add an `ocr_unavailable` warning, because crawlx has no
//!      OCR engine; unreadable PDFs end the row as `unsupported_content`;
//!    * without a `pdf` parser (`parsers: []`) the PDF is not parsed: its markdown is the base64
//!      text of the file and `numPages` stays absent;
//!    * a raster image (PNG, JPEG, JPEG 2000, TIFF, GIF, BMP, WebP, AVIF) with the `image` parser
//!      on is an empty markdown with an `ocr_unavailable` warning; with it off, and for every
//!      other binary body, the row ends as `unsupported_content` (`rawBase64` always works).
//!    * a body that is itself audio or video (`audio/*`, `video/*`, Ogg) is an empty markdown when
//!      `audio` or `video` is requested, and `unsupported_content` otherwise;
//! 4. **Formats.** Pure formats (`links`, `images`, `attributes`, `branding`) are computed from
//!    the page (`branding` from the markup and stylesheets, and, when the page rendered in a
//!    browser, from the computed styles the renderer read, see [`Rendered::computed_styles`]);
//!    `summary`, `json`, `question`, `highlights` and `query` call
//!    [`WorkerConfig::llm`](crate::WorkerConfig::llm) on the markdown (no LLM: `llm_not_configured`;
//!    an LLM error: `llm_failed`); `changeTracking` compares the markdown with the previous
//!    stored scrape of the same URL and tag.
//!    `audio` and `video` store the media file the page is or references (downloaded through the
//!    run's fetcher, at most [`WorkerConfig::media_max_bytes`](crate::WorkerConfig::media_max_bytes)),
//!    and the `transcript` when the LLM endpoint transcribes; a missing, oversize or untranscribed
//!    media file is a document `warning` (`audio_not_found:`, `video_not_found:`,
//!    `media_too_large:`, `transcription_unavailable:`, `transcription_failed:`), never a failure.
//! 5. **Store.** Artifacts, then the page row.
//!
//! Credits are not computed here; `numPages` and `llmTokens` in the document are their inputs.

mod branding_llm;
mod change;
mod compose;
mod guard;
mod llm;
mod media;
mod store;
mod visibility;

pub mod cache;
pub mod render;

/// Span names of one scraped page of a compatibility crawl or scrape (the `crawl_id` and
/// `frontier_id` fields identify the run and the page row, never the URL): the API's
/// `admission` span covers the run's admission, then each page opens `fetch` (acquisition: HTTP
/// or browser), `extract` (the CPU-pool composition of markdown, HTML and links) and `persist`
/// (artifacts and page row).
pub mod span {
    /// Acquiring the body of one page.
    pub const FETCH: &str = "fetch";
    /// Composing the content of one page.
    pub const EXTRACT: &str = "extract";
    /// Storing the page and its artifacts.
    pub const PERSIST: &str = "persist";
}

pub use media::DEFAULT_MEDIA_MAX_BYTES;
pub use render::{ActionOutputs, BrowserRenderer, PageRenderer, RenderError, RenderRequest, Rendered, Shot};

use crate::error::WorkerError;
use crate::runtime::CpuPool;
use crate::url_plane::{header_pairs, UrlPlaneDeps};
use crate::WorkerConfig;
use bytes::Bytes;
use chrono::SecondsFormat;
use compose::{BodyKind, ComposeInput, Composed};
use crawlx_core::config::{CreateCrawl, RetentionMode};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{FrontierEntry, PageRecord};
use crawlx_core::scrape::{ChangeMode, FormatSpec, JobKind, ScrapeDocument, ScrapeOptions};
use crawlx_core::{CrawlRunId, TenantId, Timestamp};
use crawlx_extract::branding::{self, BrandingInput, ComputedStyles};
use crawlx_extract::ExtractOptions;
use crawlx_fetch::{FetchError, FetchOptions, FetchResponse, Fetcher};
use crawlx_model::llm::{ExtractionRouter, LlmExtractor};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument as _;
use url::Url;

/// Stylesheets fetched for the `branding` format.
const BRANDING_STYLESHEETS: usize = 8;
/// Total bytes of stylesheet text read for the `branding` format.
const BRANDING_CSS_BYTES: usize = 512 * 1024;

/// Told about every page fetch of the HTTP plane (the URL plane feeds the traffic export with
/// it): the requested URL and what the fetcher answered.
pub type FetchObserver<'a> = dyn Fn(&Url, &Result<FetchResponse, FetchError>) + Send + Sync + 'a;

/// Why a page of a scrape run ended as a failed frontier row.
///
/// [`Self::code`] is the frontier row's reason and the `reason` of the `page.failed` event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum FailReason {
    /// The page did not finish within `timeout`.
    ScrapeTimeout,
    /// The host could not be reached (DNS, connection, TLS, navigation, redirect loop).
    Unreachable,
    /// The egress policy refused the page.
    EgressDenied,
    /// A redirect hop left the authorization record's target (`policy_blocked`, never fetched).
    AuthorizationScope,
    /// The browser failed or none is available.
    RenderFailed,
    /// A caller-specified `actions[]` entry did not run.
    ActionFailed,
    /// A format needs an LLM and the worker has none.
    LlmNotConfigured,
    /// The host name could not be resolved.
    DnsFailed,
    /// `checkPromptInjection` found injection phrasing in the page.
    PromptInjectionDetected,
    /// The LLM call failed.
    LlmFailed,
    /// The body is neither HTML, PDF nor text (or the PDF cannot be read).
    UnsupportedContent,
    /// The extractor refused the document (too large, invalid `includeTags` selector).
    ExtractFailed,
    /// `minAge` asked for a stored scrape and none is old enough.
    NoCachedData,
    /// `lockdown` asked for a stored scrape and none exists.
    LockdownCacheMiss,
    /// A matching retained response lost one of its content artifacts.
    CachedBodyUnavailable,
    /// Credential-bearing cache identity needs an operator correlation key.
    CacheIdentityUnavailable,
    /// A source-dialect 429 must leave the dispatch slot and wait on the shared origin cooldown.
    RateLimited,
    /// The run was cancelled while the page was in flight; the row is abandoned, not failed.
    Cancelled,
    /// The ProxyX pool gateway refused the tunnel for a cause another attempt cannot clear (bad
    /// or disabled org key, option denied, destination or port refused, provider credential rejected,
    /// daily budget spent), or
    /// the pool configuration is unusable. Transient pool refusals end as `unreachable`.
    ProxyRefused,
}

impl FailReason {
    /// The stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ScrapeTimeout => "scrape_timeout",
            Self::Unreachable => "unreachable",
            Self::EgressDenied => "egress_denied",
            Self::AuthorizationScope => "authorization_scope",
            Self::DnsFailed => "dns_failed",
            Self::PromptInjectionDetected => "prompt_injection_detected",
            Self::RenderFailed => "render_failed",
            Self::ActionFailed => "action_failed",
            Self::LlmNotConfigured => "llm_not_configured",
            Self::LlmFailed => "llm_failed",
            Self::UnsupportedContent => "unsupported_content",
            Self::ExtractFailed => "extract_failed",
            Self::NoCachedData => "no_cached_data",
            Self::LockdownCacheMiss => "lockdown_cache_miss",
            Self::CachedBodyUnavailable => "stored_body_unavailable",
            Self::CacheIdentityUnavailable => "cache_identity_unavailable",
            Self::RateLimited => "rate_limited",
            Self::Cancelled => "run_stopped",
            Self::ProxyRefused => "proxy_refused",
        }
    }

    /// Does the frontier row end `unreachable` (the target did not answer in time or at all)
    /// rather than `failed`?
    #[must_use]
    pub const fn is_unreachable(self) -> bool {
        matches!(self, Self::ScrapeTimeout | Self::Unreachable | Self::DnsFailed)
    }

    /// Was the page cut short by the run being cancelled (the row ends `abandoned`)?
    #[must_use]
    pub const fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

/// A page the engine could not turn into a document.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ScrapeFailure {
    /// Why.
    pub reason: FailReason,
    /// Human-readable detail; never contains a configured header or cookie value.
    pub message: String,
    /// Trusted body-free acquisition facts when a response exists; absent for unknown outcomes.
    /// Boxed so failures without a response do not carry the full acquisition result inline.
    pub acquisition: Option<Box<crawlx_core::acquisition::AcquisitionResultV1>>,
}

impl ScrapeFailure {
    fn new(reason: FailReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
            acquisition: None,
        }
    }
    fn with_acquisition(mut self, acquisition: crawlx_core::acquisition::AcquisitionResultV1) -> Self {
        self.acquisition = Some(Box::new(acquisition));
        self
    }
}

/// A page ready to be written.
#[derive(Debug)]
#[non_exhaustive]
pub struct Scraped {
    /// The row to write (artifacts are already stored).
    pub record: PageRecord,
    /// Links to follow when the job is a crawl; empty otherwise and for non-HTML pages.
    pub links: Vec<Url>,
    /// URL after redirects.
    pub final_url: Url,
    /// Accepted article refs committed with the request fence, never as a second transaction.
    pub accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
    /// Immutable feed intents committed beside those accepted refs.
    pub outbox: Vec<crawlx_core::dataset::DeliveryBatchV1>,
}

/// What the engine concluded for one frontier row.
#[derive(Debug)]
#[non_exhaustive]
pub enum Outcome {
    /// A document (any HTTP status, or a cache hit).
    Page(Box<Scraped>),
    /// No document.
    Failed(ScrapeFailure),
}

/// The scrape engine of one run. See the [module documentation](self) for the stored layout.
pub struct ScrapeEngine {
    run: CrawlRunId,
    kind: JobKind,
    options: Arc<ScrapeOptions>,
    request_identity_key: Option<crawlx_core::secret::SecretOr<[u8; 32]>>,
    cache_reusable: bool,
    zdr: bool,
    deps: UrlPlaneDeps,
    fetcher: Arc<Fetcher>,
    extract: ExtractOptions,
    acquisition: Option<crawlx_core::acquisition::AcquisitionPolicyV1>,
    extensions: crawlx_core::extensions::ExtensionPipelineV1,
    captcha_secrets: Option<crawlx_core::captcha::CaptchaSecrets>,
    protocol_routes:
        Result<crawlx_core::protocol::CompiledProtocolRoutes, crawlx_core::protocol::ProtocolPolicyError>,
    protocol_runtime: Result<Option<Arc<crate::protocol::ProtocolRuntime>>, String>,
    protocol_needs_browser: bool,
    tenant: Mutex<Option<TenantId>>,
    renderer: Option<Arc<dyn PageRenderer>>,
    llm: Option<Arc<dyn LlmExtractor>>,
    ocr: Option<Arc<crawlx_extract::parse::ocr::Ocr>>,
    /// What each origin's sitemaps and front page point at (`changeTracking.visibility`).
    reach: Mutex<BTreeMap<String, Arc<visibility::OriginReach>>>,
    /// Routes the `json` format to an extraction provider (`EXTRACTION_PROVIDER_*`).
    extraction: Option<Arc<ExtractionRouter>>,
    /// Refines the markup-derived `branding` profile (`BRANDING_LLM_*`).
    branding_llm: Option<Arc<dyn LlmExtractor>>,
    /// Largest media file the `audio` / `video` formats download (see [`media`]).
    media_max_bytes: usize,
}

/// A fetched or rendered page, before composition.
struct Acquired {
    final_url: Url,
    status: u16,
    proxy_used: crawlx_core::scrape::ProxyMode,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body: Bytes,
    redirects: Vec<String>,
    render: Option<RenderExtras>,
    metadata: crawlx_core::acquisition::AcquisitionResultV1,
    document: Option<Box<crawlx_extract::Document>>,
    budget: Option<(
        crate::acquisition::AcquisitionBudgetV1,
        tokio_util::sync::CancellationToken,
    )>,
}

/// What only the browser leg produces.
struct RenderExtras {
    screenshot: Option<Shot>,
    actions: ActionOutputs,
    /// What `getComputedStyle` reported (requested with the `branding` format).
    computed: Option<ComputedStyles>,
}

/// Does a run need the production browser renderer: a scrape job that renders and no renderer
/// override in `cfg`?
#[must_use]
pub(crate) fn needs_browser_renderer(crawl: &CreateCrawl, cfg: &WorkerConfig) -> bool {
    cfg.renderer.is_none()
        && (crawl
            .protocol
            .routes
            .iter()
            .any(|route| route.backend == crawlx_core::protocol::ProtocolBackendV1::Browser)
            || crawl.scrape.as_ref().is_some_and(|j| {
                j.kind != JobKind::Map
                    && (j.options.needs_browser()
                        || crawl
                            .acquisition
                            .as_ref()
                            .is_some_and(|policy| policy.backend_ids.iter().any(|id| id == "native_browser")))
            }))
}

/// RFC 3339 with millisecond precision and a `Z` suffix.
pub(crate) fn rfc3339(t: Timestamp) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

impl ScrapeEngine {
    /// The engine of `crawl`, or `None` when the run has no scrape job or is a
    /// [`JobKind::Map`] (which fetches and extracts like any other run).
    #[must_use]
    pub fn for_run(
        run: CrawlRunId,
        crawl: &CreateCrawl,
        deps: &UrlPlaneDeps,
        fetcher: Arc<Fetcher>,
    ) -> Option<Self> {
        let job = crawl.scrape.as_ref().filter(|j| j.kind != JobKind::Map)?;
        let options = &job.options;
        let extract = ExtractOptions {
            only_main_content: options.only_main_content,
            include_tags: options.include_tags.clone(),
            exclude_tags: options.exclude_tags.clone(),
            discover_endpoints: false,
            keep_data_images: !options.remove_base64_images,
            forms: false,
            page_type: false,
            technologies: false,
            content: options
                .content_policy
                .clone()
                .or_else(|| crawl.extract.content.clone()),
            content_redaction: options.redact_pii.as_ref().map(guard::redact_options),
            image_references: options.wants("images"),
            attribute_selectors: match options.format("attributes") {
                Some(FormatSpec::Attributes { selectors }) => selectors.clone(),
                _ => Vec::new(),
            },
            ..ExtractOptions::default()
        };
        Some(Self {
            run,
            kind: job.kind,
            request_identity_key: None,
            cache_reusable: crawl.protocol.routes.is_empty(),
            options: Arc::new(options.clone()),
            zdr: crawl.retention.mode == RetentionMode::Zdr,
            deps: deps.clone(),
            fetcher,
            extract,
            acquisition: crawl.acquisition.clone().or_else(|| {
                (options.cache.is_some() && !options.needs_browser() && crawl.protocol.routes.is_empty())
                    .then(crawlx_core::acquisition::AcquisitionPolicyV1::default)
            }),
            extensions: crawl.extensions.clone(),
            captcha_secrets: None,
            protocol_routes: crawl.protocol.compile(),
            protocol_runtime: Ok(None),
            protocol_needs_browser: crawl
                .protocol
                .routes
                .iter()
                .any(|route| route.backend == crawlx_core::protocol::ProtocolBackendV1::Browser),
            tenant: Mutex::new(None),
            renderer: None,
            llm: None,
            ocr: None,
            reach: Mutex::new(BTreeMap::new()),
            extraction: None,
            branding_llm: None,
            media_max_bytes: DEFAULT_MEDIA_MAX_BYTES,
        })
    }

    /// Inject one immutable worker-local language capability into the existing extraction step.
    #[must_use]
    pub fn with_article_language(
        mut self,
        detector: Option<crawlx_core::article_language::ArticleLanguageHandle>,
    ) -> Self {
        self.extract.language_detector = detector;
        self
    }

    /// Render pages that need a browser with `renderer`.
    #[must_use]
    pub fn with_renderer(mut self, renderer: Arc<dyn PageRenderer>) -> Self {
        self.renderer = Some(renderer);
        self
    }

    /// Answer the LLM formats (`json`, `summary`, `question`, `highlights`, `query`, the
    /// `json` mode of `changeTracking`) with `llm`.
    #[must_use]
    pub fn with_llm(mut self, llm: Arc<dyn LlmExtractor>) -> Self {
        self.llm = Some(llm);
        self
    }

    /// Answer the `json` format with whichever of the default LLM and an extraction provider
    /// `router` picks for the run's tenant; every other LLM format keeps the default LLM.
    #[must_use]
    pub fn with_extraction_router(mut self, router: Arc<ExtractionRouter>) -> Self {
        self.extraction = Some(router);
        self
    }

    /// Refine the profile of the `branding` format with `llm` (see [`branding_llm`]).
    #[must_use]
    pub fn with_branding_llm(mut self, llm: Arc<dyn LlmExtractor>) -> Self {
        self.branding_llm = Some(llm);
        self
    }

    /// The LLM for the formats of a page with `input_bytes` of text: the default one, except that
    /// the `json` step may be answered by the extraction provider.
    fn step_llm(&self, tenant: TenantId, input_bytes: usize) -> Option<Arc<dyn LlmExtractor>> {
        match (&self.llm, &self.extraction) {
            (Some(_), Some(router)) => Some(router.per_step(&tenant.to_string(), self.zdr, input_bytes)),
            (llm, _) => llm.clone(),
        }
    }

    /// Read scanned PDF pages and images with `ocr` (the `image` parser, PDF `mode: ocr` / `auto`).
    #[must_use]
    pub fn with_ocr(mut self, ocr: Arc<crawlx_extract::parse::ocr::Ocr>) -> Self {
        self.ocr = Some(ocr);
        self
    }

    /// Download at most `bytes` of media per `audio` / `video` format (default
    /// [`DEFAULT_MEDIA_MAX_BYTES`]); a larger file is a `media_too_large:` warning, not a failure.
    #[must_use]
    pub const fn with_media_limit(mut self, bytes: usize) -> Self {
        self.media_max_bytes = bytes;
        self
    }

    /// The compatibility-API product the run serves.
    #[must_use]
    pub const fn kind(&self) -> JobKind {
        self.kind
    }

    /// Do the options render in a browser?
    #[must_use]
    pub fn needs_browser(&self) -> bool {
        self.options.needs_browser()
            || self
                .acquisition
                .as_ref()
                .is_some_and(|policy| policy.backend_ids.iter().any(|id| id == "native_browser"))
            || self.protocol_needs_browser
    }

    /// Produce the document of `entry`, bounded by the `timeout` option.
    ///
    /// # Errors
    /// [`WorkerError`] when storage fails (a page that cannot be scraped is an
    /// [`Outcome::Failed`], not an error).
    pub async fn scrape(
        &self,
        entry: &FrontierEntry,
        cpu: &CpuPool,
        observe: &FetchObserver<'_>,
    ) -> Result<Outcome, WorkerError> {
        self.scrape_with_cancel(entry, cpu, observe, &tokio_util::sync::CancellationToken::new())
            .await
    }

    /// Produce a page with the run's cancellation token propagated into every native attempt.
    ///
    /// # Errors
    /// Returns storage failures; acquisition refusals become typed failed outcomes.
    pub(crate) async fn scrape_with_cancel(
        &self,
        entry: &FrontierEntry,
        cpu: &CpuPool,
        observe: &FetchObserver<'_>,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Outcome, WorkerError> {
        self.scrape_with_budget(entry, cpu, observe, cancel, None, None)
            .await
    }

    /// Execute using the remaining allowance escrowed by the durable frontier.
    ///
    /// # Errors
    /// Returns storage failures; acquisition failures carry known usage for fenced settlement.
    pub(crate) async fn scrape_with_budget(
        &self,
        entry: &FrontierEntry,
        cpu: &CpuPool,
        observe: &FetchObserver<'_>,
        cancel: &tokio_util::sync::CancellationToken,
        initial_budget: Option<crate::acquisition::AcquisitionBudgetV1>,
        admission: Option<&dyn crate::acquisition::HopAdmission>,
    ) -> Result<Outcome, WorkerError> {
        let cancel = cancel.child_token();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let budget = Duration::from_millis(u64::from(self.options.timeout_ms));
        // The producer owns the HTTP/browser/parser branch state. Heap-isolate it once
        // per scrape so URL/lease orchestration does not inline that state in every
        // parent future and overflow an ordinary executor stack while polling.
        let producer = Box::pin(self.produce(entry, cpu, observe, &cancel, initial_budget, admission));
        let outcome = match tokio::time::timeout(budget, producer).await {
            Ok(outcome) => outcome?,
            Err(_) => Outcome::Failed(ScrapeFailure::new(
                FailReason::ScrapeTimeout,
                format!("scrape did not finish within {} ms", self.options.timeout_ms),
            )),
        };
        Ok(match outcome {
            Outcome::Failed(mut f) => {
                f.message = self.redact(&f.message);
                Outcome::Failed(f)
            }
            page @ Outcome::Page(_) => page,
        })
    }

    async fn tenant(&self) -> Result<TenantId, WorkerError> {
        if let Some(t) = *self.tenant.lock() {
            return Ok(t);
        }
        let tenant = self.deps.runs.get(self.run).await?.tenant;
        *self.tenant.lock() = Some(tenant);
        Ok(tenant)
    }

    async fn produce(
        &self,
        entry: &FrontierEntry,
        cpu: &CpuPool,
        observe: &FetchObserver<'_>,
        cancel: &tokio_util::sync::CancellationToken,
        initial_budget: Option<crate::acquisition::AcquisitionBudgetV1>,
        admission: Option<&dyn crate::acquisition::HopAdmission>,
    ) -> Result<Outcome, WorkerError> {
        let tenant = self.tenant().await?;
        let controls = &self.fetcher.config().controls;
        let has_credentials = !controls.headers().is_empty() || !controls.cookies().is_empty();
        let mut scoped_options = std::borrow::Cow::Borrowed(self.options.as_ref());
        if has_credentials
            || scoped_options.cache_header_identity.is_some()
            || scoped_options.cache_execution_context.is_some()
        {
            scoped_options.to_mut().cache_header_identity = if has_credentials {
                self.request_identity_key
                    .as_ref()
                    .map(|key| crawlx_core::cache::credential_digest(key.expose(), tenant, controls))
                    .transpose()?
            } else {
                None
            };
            scoped_options.to_mut().cache_execution_context = None;
        }
        if self.extensions.configured()
            || self.fetcher.config().tls_impersonation != crawlx_core::tls::TlsImpersonation::Off
        {
            let route = if self.extensions.configured() {
                self.deps
                    .frontier
                    .get_request(self.run, entry.id)
                    .await?
                    .envelope
                    .route
            } else {
                "default".into()
            };
            let encoded =
                serde_json::to_vec(&(&self.extensions, route, self.fetcher.config().tls_impersonation))
                    .map_err(|e| WorkerError::Other(e.to_string()))?;
            scoped_options.to_mut().cache_execution_context =
                Some(Digest::of("crawlx/cache-extraction-context/v1", &encoded));
        }
        let credentials_available = !has_credentials || scoped_options.cache_header_identity.is_some();
        let opts = scoped_options.as_ref();
        let mut formats = opts.formats.clone();
        for format in &mut formats {
            match format {
                FormatSpec::Json { schema, prompt } | FormatSpec::ChangeTracking { schema, prompt, .. } => {
                    if let Some(schema) = schema {
                        self.redact_value(schema);
                    }
                    if let Some(prompt) = prompt {
                        *prompt = self.redact(prompt);
                    }
                }
                FormatSpec::Question { question } => *question = self.redact(question),
                FormatSpec::Highlights { query } => *query = self.redact(query),
                FormatSpec::Query { prompt, .. } => *prompt = self.redact(prompt),
                _ => {}
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(u64::from(opts.timeout_ms));
        let cache_identity = cache::key(opts, self.acquisition.as_ref(), self.run);
        let cache_capability_available = cache_identity.backend_capability != "browser-build-unavailable";
        let options_digest = cache_identity.digest();
        let cache_only = cache::cache_only(opts);
        let tracking = formats.iter().find(|format| format.name() == "changeTracking");
        let mut acquisition_budget =
            match initial_budget.map_or_else(|| self.acquisition_budget(), |budget| Ok(Some(budget))) {
                Ok(budget) => budget,
                Err(failure) => return Ok(Outcome::Failed(failure)),
            };
        let serve_fresh = cache::reads(opts)
            && (opts.cache.is_some() || tracking.is_none())
            && (opts.cache.is_some() || self.kind != JobKind::Crawl || opts.wants("links"));
        if (!self.zdr || cache_only)
            && credentials_available
            && self.cache_reusable
            && (cache_only || serve_fresh)
        {
            let replay = opts.cache.as_ref().is_some_and(|p| p.development_replay);
            let found = if replay {
                cache::replay(
                    self.deps.pages.as_ref(),
                    self.deps.runs.as_ref(),
                    self.deps.artifacts.as_ref(),
                    tenant,
                    &entry.url,
                    opts,
                    self.acquisition.as_ref(),
                    self.run,
                    self.deps.clock.now(),
                )
                .await
            } else {
                cache::lookup(
                    self.deps.pages.as_ref(),
                    self.deps.runs.as_ref(),
                    self.deps.artifacts.as_ref(),
                    tenant,
                    &entry.url,
                    opts,
                    self.acquisition.as_ref(),
                    self.run,
                    self.deps.clock.now(),
                )
                .await
            };
            match found {
                Ok(Some(mut stored)) => {
                    let fresh = if let Some(budget) = acquisition_budget.as_mut() {
                        match cache::validate_freshness(&self.fetcher, &stored, opts, budget, cancel, observe)
                            .await
                        {
                            Ok(valid) => valid,
                            Err(error) => return Ok(Outcome::Failed(fetch_failure(&error))),
                        }
                    } else {
                        true
                    };
                    if fresh {
                        if let Some(budget) = acquisition_budget.as_ref() {
                            if let Some(value) = stored.metadata.get_mut("acquisition") {
                                if let Ok(mut metadata) = serde_json::from_value::<
                                    crawlx_core::acquisition::AcquisitionResultV1,
                                >(value.clone())
                                {
                                    budget.stamp(&mut metadata);
                                    *value = serde_json::to_value(metadata)
                                        .map_err(|e| WorkerError::Other(e.to_string()))?;
                                }
                            }
                        }
                        if let Some(page) = self.serve_cached(stored, entry, cpu).await? {
                            return Ok(Outcome::Page(Box::new(page)));
                        }
                    }
                }
                Ok(None) => {}
                Err(cache::CacheError::BodyUnavailable) => {
                    return Ok(Outcome::Failed(ScrapeFailure::new(
                        FailReason::CachedBodyUnavailable,
                        "stored response body unavailable",
                    )))
                }
                Err(cache::CacheError::Store(error)) => return Err(error.into()),
            }
        }
        if cache_only && !credentials_available {
            return Ok(Outcome::Failed(ScrapeFailure::new(
                FailReason::CacheIdentityUnavailable,
                "credential-bearing cache identity requires an operator request identity key",
            )));
        }
        if cache_only {
            return Ok(Outcome::Failed(ScrapeFailure::new(
                if opts.cache.is_none() && opts.lockdown {
                    FailReason::LockdownCacheMiss
                } else {
                    FailReason::NoCachedData
                },
                "cache-only request has no matching retained response; network dispatch forbidden",
            )));
        }
        if self.needs_llm() && self.llm.is_none() {
            return Ok(Outcome::Failed(ScrapeFailure::new(
                FailReason::LlmNotConfigured,
                "a requested format needs an LLM and this worker has none configured",
            )));
        }

        let request = self.deps.frontier.get_request(self.run, entry.id).await?.envelope;
        let mut acq = match self
            .acquire(
                &request,
                entry.id,
                observe,
                cpu,
                tenant,
                cancel,
                acquisition_budget,
                admission,
            )
            .instrument(tracing::info_span!(span::FETCH, crawl_id = %self.run, frontier_id = entry.id))
            .await
        {
            Ok(a) => a,
            Err(f) => return Ok(Outcome::Failed(f)),
        };
        if acq.status == 429 && self.fetcher.governor().defers_source_throttle() {
            return Ok(Outcome::Failed(
                ScrapeFailure::new(
                    FailReason::RateLimited,
                    "origin rate limit requires the shared cooldown",
                )
                .with_acquisition(acq.metadata),
            ));
        }
        if self.acquisition.as_ref().is_some_and(|policy| {
            policy.validation.on_content_mismatch == crawlx_core::acquisition::ContentMismatchActionV1::Fail
        }) && !acq.metadata.validation.content_accepted
        {
            return Ok(Outcome::Failed(
                ScrapeFailure::new(
                    FailReason::UnsupportedContent,
                    format!(
                        "acquisition validation rejected content: {:?}",
                        acq.metadata.validation.category
                    ),
                )
                .with_acquisition(acq.metadata),
            ));
        }
        let status = acq.status;
        let kind = compose::classify(acq.content_type.as_deref(), &acq.body, acq.render.is_some());
        let raw_only = opts.wants("rawBase64");
        let media_body = media::is_media_body(opts, &acq, kind);
        let skip_compose =
            raw_only || media_body || (matches!(kind, BodyKind::Binary | BodyKind::Image) && status >= 400);
        if kind == BodyKind::Binary && !skip_compose {
            return Ok(Outcome::Failed(ScrapeFailure::new(
                FailReason::UnsupportedContent,
                format!(
                    "{} bodies cannot be converted; request `rawBase64` for the bytes",
                    acq.content_type.as_deref().unwrap_or("untyped binary")
                ),
            )));
        }
        let (article_accepted, article_outbox, article_cache) = if let Some(document) = acq.document.take() {
            let run = self.deps.runs.get(self.run).await?;
            let accepted = acq.metadata.validation.content_accepted;
            let (document, items, outbox) = crate::delivery::prepare_article_acceptance(
                self.deps.artifacts.as_ref(),
                cpu,
                &run,
                entry.id,
                document,
                accepted,
            )
            .await?;
            // Raw-only and other uncomposed consumers have no native source/envelope
            // pair to attach to scrape metadata. Do not publish an orphan cache reference.
            let (document, cache) =
                if !skip_compose && cache::writes(opts) && self.cache_reusable && !self.zdr {
                    crate::delivery::store_article_cache(
                        self.deps.artifacts.as_ref(),
                        cpu,
                        &run,
                        entry.id,
                        document,
                        accepted,
                    )
                    .await?
                } else {
                    (document, None)
                };
            acq.document = Some(document);
            (items, outbox, cache)
        } else {
            (Vec::new(), Vec::new(), None)
        };
        let mut composed = if skip_compose {
            Composed::default()
        } else {
            let mut input = ComposeInput {
                body: acq.body.clone(),
                base: acq.final_url.clone(),
                kind,
                status,
                headers: acq.headers.clone(),
                content_type: acq.content_type.clone(),
                options: Arc::clone(&self.options),
                extract: self.extract.clone(),
                ocr: self.ocr.clone(),
                document: acq.document.take(),
                controls: self.fetcher.config().controls.clone(),
                captcha_secrets: self.captcha_secrets.clone(),
                extensions: self.extensions.clone(),
                route_label: request.route,
                cancel: cancel.clone(),
            };
            match cpu
                .run(move || {
                    compose::compose(&mut input).map(|mut composed| {
                        let verified = composed.verify_article(&input);
                        (composed, verified)
                    })
                })
                .instrument(tracing::info_span!(span::EXTRACT, crawl_id = %self.run, frontier_id = entry.id))
                .await
            {
                Ok(Ok((composed, verified))) => {
                    verified?;
                    composed
                }
                Ok(Err(e)) => return Ok(Outcome::Failed(e.into_failure())),
                Err(e) => return Err(WorkerError::Other(format!("scrape composition task failed: {e}"))),
            }
        };
        if !skip_compose {
            acq.metadata.extraction_succeeded = Some(true);
        }

        // Credential echoes must be removed before any cleanup or model format sees them,
        // including text extracted from PDFs rather than directly from the response body.
        if let Some(markdown) = &mut composed.markdown {
            *markdown = self.redact(markdown);
        }
        if let Some(html) = &mut composed.html {
            *html = self.redact(html);
        }

        let mut doc = ScrapeDocument::new(
            entry.url.url.to_string(),
            acq.final_url.to_string(),
            status,
            options_digest,
        );
        doc.proxy_used = acq.proxy_used;
        doc.content_type.clone_from(&acq.content_type);
        if status >= 400 {
            doc.error = Some(
                http::StatusCode::from_u16(status)
                    .ok()
                    .and_then(|s| s.canonical_reason())
                    .map_or_else(|| format!("HTTP {status}"), str::to_owned),
            );
        }
        doc.not_cacheable = !cache::writes(opts)
            || !credentials_available
            || !self.cache_reusable
            || !cache_capability_available
            || self.zdr
            || !(200..300).contains(&status)
            || acq.metadata.truncated;
        doc.meta = std::mem::take(&mut composed.meta);
        composed.article_cache = article_cache;
        if !credentials_available && opts.cache.is_some() {
            doc.meta.insert(
                "cacheUnavailableReason".into(),
                serde_json::json!("request_identity_key_unavailable"),
            );
        }
        if (!cache_capability_available || !self.cache_reusable) && opts.cache.is_some() {
            doc.meta.insert(
                "cacheUnavailableReason".into(),
                serde_json::json!("backend_capability_unavailable"),
            );
        }
        doc.num_pages = composed.num_pages;
        doc.total_pages = composed.total_pages;
        doc.images = composed.images.take();
        doc.attributes = composed.attributes.take();
        doc.pages = composed.pages.take();
        doc.blocks = composed.blocks.take();
        if let Some(FormatSpec::ChangeTracking { tag, .. }) = tracking {
            doc.change_tag.clone_from(tag);
        }
        if opts.wants("branding") && kind == BodyKind::Html && !skip_compose {
            let branded = self.branding(&mut acq, cpu, observe).await?;
            doc.branding = Some(branded.profile);
            llm::charge(&mut doc, branded.usage);
            if let Some(w) = branded.warning {
                guard::push_warning(&mut composed.warning, w);
            }
        }
        let media = self
            .media(&mut acq, kind, cpu, deadline, observe, &mut doc)
            .await?;

        // content guards, in this order: injection check on the markdown as composed, PII
        // redaction of every returned text, the optional cleanup pass
        if opts.check_prompt_injection && !skip_compose {
            let text = composed.markdown.take();
            let (text, verdict) = cpu
                .run(move || {
                    let verdict = guard::scan_injection(text.as_deref().unwrap_or(""));
                    (text, verdict)
                })
                .await
                .map_err(|e| WorkerError::Other(format!("prompt injection scan failed: {e}")))?;
            composed.markdown = text;
            match verdict {
                Err(f) => return Ok(Outcome::Failed(f)),
                Ok(guard::Scan::Clean) => doc.prompt_injection_checked = true,
                Ok(guard::Scan::Incomplete) => guard::push_warning(
                    &mut composed.warning,
                    "prompt_injection_check_incomplete: the page is too long to scan completely; the check is not billed"
                        .to_owned(),
                ),
            }
        }
        if let Some(spec) = &opts.redact_pii {
            let redact_opts = guard::redact_options(spec);
            let for_pool = redact_opts.clone();
            let raw = (opts.wants("rawHtml") && matches!(kind, BodyKind::Html | BodyKind::Text))
                .then(|| acq.body.clone());
            let input = guard::Redactable {
                markdown: composed.markdown.take(),
                html: composed.html.take(),
                pages: doc.pages.take(),
                blocks: doc.blocks.take(),
                raw,
            };
            let out = cpu
                .run(move || guard::redact_content(&for_pool, input))
                .await
                .map_err(|e| WorkerError::Other(format!("PII redaction failed: {e}")))?;
            composed.markdown = out.content.markdown;
            composed.html = out.content.html;
            doc.pages = out.content.pages;
            doc.blocks = out.content.blocks;
            if let Some(raw) = out.content.raw {
                acq.body = raw;
            }
            if let Some(render) = acq.render.as_mut() {
                // the `scrape` actions captured the DOM at their step: redact those too
                for captured in &mut render.actions.scrapes {
                    captured.html = crawlx_extract::parse::redact::redact(&captured.html, &redact_opts).text;
                }
            }
            doc.pii_redacted = true;
            if let Some(w) = guard::unsupported_warning(&out.unsupported) {
                guard::push_warning(&mut composed.warning, w);
            }
        }
        if opts.only_clean_content && !skip_compose && composed.markdown.is_some() {
            let md = composed.markdown.take().unwrap_or_default();
            match guard::clean_markdown(self.llm.as_deref(), &md).await {
                guard::Cleaned::Done(cleaned, usage) => {
                    composed.markdown = Some(self.redact(&cleaned));
                    llm::charge(&mut doc, usage);
                }
                guard::Cleaned::Skipped(warning, usage) => {
                    composed.markdown = Some(md);
                    llm::charge(&mut doc, usage);
                    guard::push_warning(&mut composed.warning, warning);
                }
            }
        }

        let markdown = composed.markdown.as_deref().unwrap_or("");
        let step_llm = self.step_llm(tenant, markdown.len());
        if let Some(llm) = step_llm.as_deref() {
            if let Err(f) = llm::run_formats(llm, &formats, markdown, &mut doc).await {
                return Ok(Outcome::Failed(f));
            }
        }
        if let Some(FormatSpec::ChangeTracking {
            modes,
            schema,
            prompt,
            tag,
        }) = tracking
        {
            let baseline = change::baseline(
                self.deps.pages.as_ref(),
                self.deps.artifacts.as_ref(),
                self.deps.runs.as_ref(),
                tenant,
                &entry.url,
                tag.as_deref(),
                options_digest,
                self.deps.clock.now(),
            )
            .await?;
            let visible = self.is_visible(entry, &mut acq, observe).await;
            let result = change::track(
                self.llm.as_deref(),
                baseline,
                status,
                visible,
                markdown,
                &change::Request {
                    modes,
                    schema: schema.as_ref(),
                    prompt: prompt.as_deref(),
                },
                &mut doc,
            )
            .await;
            match result {
                Ok(r) => doc.change_tracking = Some(r),
                Err(f) => return Ok(Outcome::Failed(f)),
            }
        }

        let mut scraped = store::assemble(self, cpu, entry, acq, composed, doc, media)
            .instrument(tracing::info_span!(span::PERSIST, crawl_id = %self.run, frontier_id = entry.id))
            .await?;
        scraped.accepted = article_accepted;
        scraped.outbox = article_outbox;
        Ok(Outcome::Page(Box::new(scraped)))
    }

    /// Request options of the HTTP leg: `location` becomes an `Accept-Language` header unless
    /// the run's configured request headers (`headers`) already set one, which then wins.
    fn http_options(&self) -> FetchOptions {
        let mut opts = FetchOptions::default();
        let configured = self
            .fetcher
            .config()
            .controls
            .headers()
            .keys()
            .any(|n| n.eq_ignore_ascii_case("accept-language"));
        if !configured {
            if let Some(value) = self
                .options
                .location
                .as_ref()
                .and_then(render::locale::http_accept_language)
                .and_then(|v| http::HeaderValue::from_str(&v).ok())
            {
                opts.headers.insert(http::header::ACCEPT_LANGUAGE, value);
            }
        }
        opts
    }

    fn effective_acquisition_policy(
        &self,
    ) -> Result<crawlx_core::acquisition::AcquisitionPolicyV1, ScrapeFailure> {
        let mut effective = self
            .acquisition
            .clone()
            .ok_or_else(|| fetch_failure(&FetchError::AcquisitionUnavailable))?;
        effective.max_elapsed_ms = effective.max_elapsed_ms.min(self.options.timeout_ms);
        effective.max_decoded_bytes = effective
            .max_decoded_bytes
            .min(u64::try_from(self.fetcher.config().max_body_bytes).unwrap_or(u64::MAX));
        Ok(effective)
    }

    fn acquisition_budget(&self) -> Result<Option<crate::acquisition::AcquisitionBudgetV1>, ScrapeFailure> {
        if self.acquisition.is_none() {
            return Ok(None);
        }
        crate::acquisition::AcquisitionBudgetV1::new(&self.effective_acquisition_policy()?)
            .map(Some)
            .map_err(|e| fetch_failure(&e))
    }

    /// Reconstruct only the remaining allowance granted by the current fenced request lease.
    ///
    /// # Errors
    /// Refuses missing policy, exhausted allowance or invalid evidence before any dispatch.
    pub(crate) fn budget_from_allowance(
        &self,
        allowance: &crawlx_core::acquisition::AcquisitionAllowanceV1,
    ) -> Result<crate::acquisition::AcquisitionBudgetV1, ScrapeFailure> {
        crate::acquisition::AcquisitionBudgetV1::from_allowance(
            &self.effective_acquisition_policy()?,
            allowance,
        )
        .map_err(|e| fetch_failure(&e))
    }

    /// Fetch or render the page.
    #[allow(clippy::too_many_arguments)]
    async fn acquire_delegate(
        &self,
        url: &Url,
        route: &crawlx_core::protocol::ProtocolRouteV1,
        entry_id: i64,
        cpu: &CpuPool,
        tenant: TenantId,
        cancel: &tokio_util::sync::CancellationToken,
        budget: Option<crate::acquisition::AcquisitionBudgetV1>,
    ) -> Result<Acquired, ScrapeFailure> {
        let runtime = self
            .protocol_runtime
            .as_ref()
            .map_err(|_| fetch_failure(&FetchError::AcquisitionUnavailable))?
            .as_ref()
            .ok_or_else(|| fetch_failure(&FetchError::AcquisitionUnavailable))?;
        // Interactive writes, session state and unrepresented render extras still require the native actor.
        if self.options.needs_browser() {
            return Err(fetch_failure(&FetchError::AcquisitionUnavailable));
        }
        let default = crawlx_core::acquisition::AcquisitionPolicyV1::default();
        let policy = self.acquisition.as_ref().unwrap_or(&default);
        let mut budget = match budget {
            Some(budget) => budget,
            None => crate::acquisition::AcquisitionBudgetV1::new(policy).map_err(|e| fetch_failure(&e))?,
        };
        budget.constrain(
            std::time::Duration::from_millis(u64::from(route.max_elapsed_ms)),
            u64::from(route.max_body_bytes)
                .min(u64::try_from(self.fetcher.config().max_body_bytes).unwrap_or(u64::MAX)),
        );
        let remaining = budget.reserve(cancel).map_err(|e| fetch_failure(&e))?;
        let mut route = route.clone();
        route.max_elapsed_ms = route
            .max_elapsed_ms
            .min(u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX));
        route.max_body_bytes = route
            .max_body_bytes
            .min(u32::try_from(budget.remaining_bytes()).unwrap_or(u32::MAX));
        let requests = budget
            .options(&FetchOptions::default(), self.fetcher.config().max_body_bytes)
            .request_allowance
            .ok_or_else(|| fetch_failure(&FetchError::AcquisitionUnavailable))?;
        let attempt = entry_id.to_string();
        let resource = runtime
            .acquire(
                &route, url, self.run, tenant, &attempt, self.zdr, &requests, cancel,
            )
            .await
            .map_err(|error| match error {
                crawlx_fetch::protocol::ProtocolError::Cancelled => {
                    fetch_failure(&FetchError::AcquisitionCancelled)
                }
                crawlx_fetch::protocol::ProtocolError::Deadline => {
                    fetch_failure(&FetchError::AcquisitionDeadline)
                }
                crawlx_fetch::protocol::ProtocolError::Limit => {
                    fetch_failure(&FetchError::AcquisitionAllowance)
                }
                _ => fetch_failure(&FetchError::AcquisitionUnavailable),
            })?;
        budget.charge_bytes(resource.decoded_bytes);
        let mut metadata = crate::protocol::resource_metadata(&resource, &route, url, self.run, tenant);
        let context = crate::acquisition::context(policy, resource.target_status, false);
        let base = resource.final_url.clone().unwrap_or_else(|| url.clone());
        let body = crate::acquisition::extraction_body(
            &resource.body,
            &self.fetcher.config().controls,
            &self.extract,
        );
        let validation = crate::acquisition::validate_body(
            body,
            base.clone(),
            resource.media_type.clone(),
            Vec::new(),
            context,
            self.extract.clone(),
            cpu,
            &self.fetcher.config().controls,
            self.captcha_secrets.as_ref(),
        );
        let (outcome, mut document) =
            tokio::time::timeout_at(budget.render_allowance(cancel).deadline, validation)
                .await
                .map_err(|_| fetch_failure(&FetchError::AcquisitionDeadline))?
                .map_err(|e| fetch_failure(&e))?;
        metadata.validation = outcome;
        if let Some(article) = document.as_mut().and_then(|document| document.article.as_mut()) {
            article.acquisition_request_digest = Some(metadata.request_digest);
        }
        budget.record(
            &metadata.backend.backend_id,
            metadata.target_status,
            metadata.validation.category,
        );
        budget.stamp(&mut metadata);
        metadata
            .bound()
            .map_err(|_| fetch_failure(&FetchError::AcquisitionUnavailable))?;
        let Some(status) = resource.target_status else {
            return Err(ScrapeFailure::new(FailReason::UnsupportedContent,
                "target HTTP status unavailable; use the operator protocol resource command, not HTTP page storage")
                .with_acquisition(metadata));
        };
        Ok(Acquired {
            final_url: base,
            status,
            proxy_used: crawlx_core::scrape::ProxyMode::Basic,
            headers: Vec::new(),
            content_type: resource.media_type,
            body: resource.body,
            redirects: Vec::new(),
            render: None,
            metadata,
            document,
            budget: Some((budget, cancel.clone())),
        })
    }

    /// Bind the operator registry and checked run policy. Failure remains a refusal, not native fallback.
    pub(crate) fn with_protocol_services(mut self, rc: &crate::run::RunContext) -> Self {
        self.request_identity_key = rc.request_identity_key.clone();
        self.captcha_secrets = Some(rc.captcha_secrets.clone());
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
        self
    }

    #[allow(clippy::too_many_arguments)]
    async fn acquire(
        &self,
        request: &crawlx_core::request::RequestEnvelopeV1,
        entry_id: i64,
        observe: &FetchObserver<'_>,
        cpu: &CpuPool,
        tenant: TenantId,
        cancel: &tokio_util::sync::CancellationToken,
        budget: Option<crate::acquisition::AcquisitionBudgetV1>,
        admission: Option<&dyn crate::acquisition::HopAdmission>,
    ) -> Result<Acquired, ScrapeFailure> {
        let url = &request.url.url;
        let routes = self
            .protocol_routes
            .as_ref()
            .map_err(|_| fetch_failure(&FetchError::AcquisitionUnavailable))?;
        if let Some(route) = crate::protocol::select_route(routes, url) {
            use crawlx_core::protocol::ProtocolBackendV1;
            match route.backend {
                ProtocolBackendV1::Delegate => {
                    return Box::pin(self.acquire_delegate(url, route, entry_id, cpu, tenant, cancel, budget))
                        .await
                }
                ProtocolBackendV1::Http | ProtocolBackendV1::Browser => {
                    let mut policy = self.acquisition.clone().unwrap_or_default();
                    let selected_backend = if route.backend == ProtocolBackendV1::Http {
                        "native_http"
                    } else {
                        "native_browser"
                    };
                    if self
                        .acquisition
                        .as_ref()
                        .is_some_and(|admitted| !admitted.backend_ids.iter().any(|id| id == selected_backend))
                    {
                        return Err(fetch_failure(&FetchError::AcquisitionUnavailable));
                    }
                    policy.backend_ids = vec![selected_backend.to_owned()];
                    policy.fallback_backend_ids.clear();
                    policy.max_elapsed_ms = policy.max_elapsed_ms.min(route.max_elapsed_ms);
                    policy.max_decoded_bytes = policy.max_decoded_bytes.min(u64::from(route.max_body_bytes));
                    if route.backend == ProtocolBackendV1::Http && self.options.needs_browser() {
                        return Err(fetch_failure(&FetchError::AcquisitionUnavailable));
                    }
                    let mut budget = match budget {
                        Some(budget) => budget,
                        None => crate::acquisition::AcquisitionBudgetV1::new(&policy)
                            .map_err(|e| fetch_failure(&e))?,
                    };
                    budget.constrain(
                        std::time::Duration::from_millis(u64::from(route.max_elapsed_ms)),
                        u64::from(route.max_body_bytes),
                    );
                    let mut acquired = self
                        .acquire_native(request, observe, cpu, tenant, &policy, cancel, budget, admission)
                        .await?;
                    acquired
                        .metadata
                        .backend
                        .limitations
                        .push(format!("protocol_route:{}", route.id));
                    acquired
                        .metadata
                        .backend
                        .limitations
                        .push(format!("policy_revision:{}", route.policy_revision));
                    return Ok(acquired);
                }
                _ => return Err(fetch_failure(&FetchError::AcquisitionUnavailable)),
            }
        }
        if let Some(policy) = &self.acquisition {
            let budget = budget.ok_or_else(|| fetch_failure(&FetchError::AcquisitionUnavailable))?;
            return self
                .acquire_native(request, observe, cpu, tenant, policy, cancel, budget, admission)
                .await;
        }
        // Legacy facade escalation and native acquisition are independent branch state
        // machines. Inlining both reserves the legacy HTTP/browser poll frame even for
        // an explicitly native request and exhausts the caller's executor stack.
        Box::pin(self.acquire_legacy(request, observe, cpu, tenant)).await
    }

    async fn acquire_legacy(
        &self,
        request: &crawlx_core::request::RequestEnvelopeV1,
        observe: &FetchObserver<'_>,
        cpu: &CpuPool,
        tenant: TenantId,
    ) -> Result<Acquired, ScrapeFailure> {
        let url = &request.url.url;
        use crawlx_core::scrape::ProxyMode;
        let legacy_started = tokio::time::Instant::now();
        let mut proxy_used = if self.options.proxy == ProxyMode::Enhanced {
            ProxyMode::Enhanced
        } else {
            ProxyMode::Basic
        };
        if self.options.needs_browser() {
            let Some(renderer) = &self.renderer else {
                return Err(ScrapeFailure::new(
                    FailReason::RenderFailed,
                    "the options need a browser and this worker has no renderer",
                ));
            };
            let mut rendered = renderer
                .render(&RenderRequest {
                    request,
                    options: &self.options,
                })
                .await
                .map_err(|e| render_failure(&e))?;
            let mut prior_requests = 0u32;
            let mut prior_bytes = 0u64;
            let mut navigation_attempts = 1u8;
            // Never replay caller actions: only an action-free GET navigation can escalate.
            if self.options.proxy.escalates(rendered.status)
                && self.options.actions.is_empty()
                && !(rendered.status == 429 && self.fetcher.governor().defers_source_throttle())
            {
                prior_requests = self.render_metadata(url, &rendered, tenant).network_requests;
                prior_bytes = u64::try_from(rendered.html.len()).unwrap_or(u64::MAX);
                navigation_attempts = 2;
                let mut enhanced = self.options.as_ref().clone();
                enhanced.proxy = crawlx_core::scrape::ProxyMode::Enhanced;
                rendered = renderer
                    .render(&RenderRequest {
                        request,
                        options: &enhanced,
                    })
                    .await
                    .map_err(|e| render_failure(&e))?;
                proxy_used = ProxyMode::Enhanced;
            }
            let mut metadata = self.render_metadata(url, &rendered, tenant);
            let redirects = rendered
                .evidence
                .as_ref()
                .map_or_else(Vec::new, |e| e.redirects.clone());
            let body = Bytes::from(rendered.html);
            let policy = crawlx_core::acquisition::AcquisitionPolicyV1::default();
            let (validation, document) = crate::acquisition::validate_body(
                crate::acquisition::extraction_body(&body, &self.fetcher.config().controls, &self.extract),
                rendered.final_url.clone(),
                rendered.content_type.clone(),
                rendered.headers.clone(),
                crate::acquisition::context(&policy, metadata.target_status, metadata.truncated),
                self.extract.clone(),
                cpu,
                &self.fetcher.config().controls,
                self.captcha_secrets.as_ref(),
            )
            .await
            .map_err(|e| fetch_failure(&e))?;
            metadata.validation = validation;
            metadata.attempts = navigation_attempts;
            metadata.network_requests = metadata.network_requests.saturating_add(prior_requests);
            metadata.decoded_bytes = u64::try_from(body.len())
                .unwrap_or(u64::MAX)
                .saturating_add(prior_bytes);
            metadata.elapsed_ms = u64::try_from(legacy_started.elapsed().as_millis()).unwrap_or(u64::MAX);
            metadata.network_requests_observed = None;
            metadata
                .backend
                .limitations
                .push("subresource_request_evidence_unavailable".to_owned());
            Ok(Acquired {
                final_url: rendered.final_url,
                status: rendered.status,
                proxy_used,
                headers: rendered.headers,
                content_type: rendered.content_type,
                body,
                redirects,
                render: Some(RenderExtras {
                    screenshot: rendered.screenshot,
                    actions: rendered.actions,
                    computed: rendered.computed_styles,
                }),
                metadata,
                document,
                budget: None,
            })
        } else {
            let fetched = if self.options.proxy == ProxyMode::Auto {
                self.fetcher.fetch_once(url, &self.http_options()).await
            } else {
                self.fetcher.fetch(url, &self.http_options()).await
            };
            observe(url, &fetched);
            let mut resp = fetched.map_err(|e| fetch_failure(&e))?;
            let mut prior_requests = 0u32;
            let mut prior_bytes = 0u64;
            let mut prior_attempts = 0u8;
            let mut effective_fetcher = self.fetcher.as_ref();
            if self.options.proxy.escalates(resp.status.as_u16())
                && !(resp.status.as_u16() == 429 && self.fetcher.governor().defers_source_throttle())
            {
                prior_requests = resp.attempts;
                prior_bytes = u64::try_from(resp.body.len()).unwrap_or(u64::MAX);
                prior_attempts =
                    crate::acquisition::http_metadata(self.run, tenant, url, &resp, &self.fetcher).attempts;
                let enhanced = self.fetcher.enhanced().ok_or_else(|| {
                    ScrapeFailure::new(
                        FailReason::Unreachable,
                        "enhanced proxy requested but no enhanced route is configured",
                    )
                })?;
                effective_fetcher = enhanced;
                let fetched = enhanced.fetch_once(url, &self.http_options()).await;
                observe(url, &fetched);
                resp = fetched.map_err(|e| fetch_failure(&e))?;
                proxy_used = ProxyMode::Enhanced;
            }
            let mut metadata =
                crate::acquisition::http_metadata(self.run, tenant, url, &resp, effective_fetcher);
            let policy = crawlx_core::acquisition::AcquisitionPolicyV1::default();
            let (validation, document) = crate::acquisition::validate_body(
                crate::acquisition::extraction_body(
                    &resp.body,
                    &self.fetcher.config().controls,
                    &self.extract,
                ),
                resp.final_url.clone(),
                resp.content_type.clone(),
                header_pairs(&resp.headers),
                crate::acquisition::context(&policy, Some(resp.status.as_u16()), resp.truncated),
                self.extract.clone(),
                cpu,
                &self.fetcher.config().controls,
                self.captcha_secrets.as_ref(),
            )
            .await
            .map_err(|e| fetch_failure(&e))?;
            metadata.validation = validation;
            metadata.attempts = metadata.attempts.saturating_add(prior_attempts);
            metadata.network_requests = metadata.network_requests.saturating_add(prior_requests);
            metadata.network_requests_observed = Some(metadata.network_requests);
            metadata.decoded_bytes = u64::try_from(resp.body.len())
                .unwrap_or(u64::MAX)
                .saturating_add(prior_bytes);
            metadata.elapsed_ms = u64::try_from(legacy_started.elapsed().as_millis()).unwrap_or(u64::MAX);
            Ok(Acquired {
                final_url: resp.final_url,
                status: resp.status.as_u16(),
                headers: header_pairs(&resp.headers),
                content_type: resp.content_type,
                body: resp.body,
                redirects: resp.redirects,
                render: None,
                proxy_used,
                metadata,
                document,
                budget: None,
            })
        }
    }

    fn render_metadata(
        &self,
        requested: &Url,
        rendered: &Rendered,
        tenant: TenantId,
    ) -> crawlx_core::acquisition::AcquisitionResultV1 {
        use crawlx_core::acquisition::{
            AcquisitionRedirectV1, AcquisitionResultV1, BackendCapabilitiesV1, RepresentationV1,
            UrlEvidenceV1,
        };
        let backend = rendered.evidence.as_ref().map_or_else(
            || BackendCapabilitiesV1::native_browser_unavailable("legacy_backend_evidence_unavailable"),
            |evidence| evidence.backend.clone(),
        );
        let mut metadata = AcquisitionResultV1::new(
            self.run,
            tenant,
            requested.clone(),
            Digest::of("crawlx/canonical-url/v1", requested.as_str().as_bytes()),
            backend,
        );
        metadata.representation = crawlx_core::acquisition::RepresentationV1::RenderedDom;
        metadata.decoded_bytes = u64::try_from(rendered.html.len()).unwrap_or(u64::MAX);
        metadata
            .backend
            .limitations
            .push("browser_wire_bytes_unobserved".to_owned());
        metadata
            .backend
            .limitations
            .push("decoded_allowance_counts_serialized_dom".to_owned());
        metadata.content_type.clone_from(&rendered.content_type);
        metadata.content_encoding = rendered
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
            .map(|(_, value)| value.clone());
        metadata.attempts = 1;
        if let Some(evidence) = &rendered.evidence {
            metadata.session = Some(evidence.session);
            metadata.session_generation = evidence.session_generation;
            metadata.transport_succeeded = evidence.target_status.is_some();
            if evidence.final_url_observed {
                metadata.connection.checked_origin = Some(rendered.final_url.origin().ascii_serialization());
            }
            metadata.target_status = evidence.target_status;
            metadata.truncated = evidence.truncated;
            if evidence.final_url_observed {
                metadata.final_url = Some(rendered.final_url.clone());
                metadata.final_url_evidence = UrlEvidenceV1::Observed;
            }
            metadata.redirects = evidence
                .redirects
                .iter()
                .take(20)
                .filter_map(|url| Url::parse(url).ok())
                .map(|url| AcquisitionRedirectV1::observed(url, None))
                .collect();
            metadata.evidence_truncated = evidence.redirects.len() > 20;
            metadata.network_requests = u32::try_from(evidence.redirects.len())
                .unwrap_or(u32::MAX)
                .saturating_add(1);
        }
        // Legacy HTML-only adapters have neither target status nor final-URL evidence.
        if rendered.evidence.is_none() {
            metadata.representation = RepresentationV1::SuppliedHtml;
        }
        metadata
    }

    #[allow(clippy::too_many_arguments)]
    fn acquire_native<'a>(
        &'a self,
        request: &'a crawlx_core::request::RequestEnvelopeV1,
        observe: &'a FetchObserver<'a>,
        cpu: &'a CpuPool,
        tenant: TenantId,
        policy: &'a crawlx_core::acquisition::AcquisitionPolicyV1,
        cancel: &'a tokio_util::sync::CancellationToken,
        budget: crate::acquisition::AcquisitionBudgetV1,
        admission: Option<&'a dyn crate::acquisition::HopAdmission>,
    ) -> impl Future<Output = Result<Acquired, ScrapeFailure>> + 'a {
        // Construct and heap-place the entire retry state outside the dispatcher's poll
        // frame. Boxing at the await site still reserves a full native future temporary
        // there, alongside producer and URL orchestration frames in unoptimized builds.
        // This boundary allocates once per acquisition, never once per attempt or hop.
        Box::pin(self.acquire_native_inner(request, observe, cpu, tenant, policy, cancel, budget, admission))
    }

    #[allow(clippy::too_many_arguments)]
    async fn acquire_native_inner(
        &self,
        request: &crawlx_core::request::RequestEnvelopeV1,
        observe: &FetchObserver<'_>,
        cpu: &CpuPool,
        tenant: TenantId,
        policy: &crawlx_core::acquisition::AcquisitionPolicyV1,
        cancel: &tokio_util::sync::CancellationToken,
        mut budget: crate::acquisition::AcquisitionBudgetV1,
        admission: Option<&dyn crate::acquisition::HopAdmission>,
    ) -> Result<Acquired, ScrapeFailure> {
        let url = &request.url.url;
        use crate::acquisition::fetch_native;
        use crawlx_core::acquisition::{RetryClassV1, ValidationCategoryV1};
        use crawlx_core::scrape::ProxyMode;
        // Presence is checked for every explicitly permitted backend before the first I/O.
        if policy.backend_ids.iter().any(|id| id == "native_browser") && self.renderer.is_none() {
            return Err(fetch_failure(&FetchError::AcquisitionUnavailable));
        }
        let mut policy = policy.clone();
        policy.max_elapsed_ms = policy.max_elapsed_ms.min(self.options.timeout_ms);
        policy.max_decoded_bytes = policy
            .max_decoded_bytes
            .min(u64::try_from(self.fetcher.config().max_body_bytes).unwrap_or(u64::MAX));
        let mut backend = policy.backend_ids.first().map(String::as_str).unwrap_or("");
        if self.options.needs_browser() && backend != "native_browser" {
            return Err(fetch_failure(&FetchError::AcquisitionUnavailable));
        }
        let mut fallbacks = policy.fallback_backend_ids.iter();
        let mut options = self.options.as_ref().clone();
        // Native policy never inherits facade automatic identity rotation.
        if options.proxy == ProxyMode::Auto {
            options.proxy = ProxyMode::Basic;
        }
        loop {
            let acquired = if backend == "native_http" {
                match fetch_native(
                    &self.fetcher,
                    url,
                    &self.http_options(),
                    &policy,
                    &mut budget,
                    cancel,
                    &self.extract,
                    cpu,
                    self.run,
                    tenant,
                    observe,
                    true,
                    self.captcha_secrets.as_ref(),
                    admission,
                )
                .await
                {
                    Ok(acquired) => {
                        let resp = acquired.response;
                        Acquired {
                            final_url: resp.final_url,
                            status: resp.status.as_u16(),
                            proxy_used: options.proxy,
                            headers: header_pairs(&resp.headers),
                            content_type: resp.content_type,
                            body: resp.body,
                            redirects: resp.redirects,
                            render: None,
                            metadata: acquired.metadata,
                            document: acquired.document,
                            budget: None,
                        }
                    }
                    Err(error) => {
                        let transport = matches!(
                            error,
                            FetchError::Transport(_) | FetchError::Timeout(_) | FetchError::Resolve { .. }
                        );
                        if transport
                            && options.actions.is_empty()
                            && policy.retry_on.contains(&RetryClassV1::Transport)
                            && budget.can_retry()
                        {
                            if let Some(next) = fallbacks.next() {
                                backend = next;
                            }
                            continue;
                        }
                        let mut failure = fetch_failure(&error);
                        let mut metadata = crawlx_core::acquisition::AcquisitionResultV1::new(
                            self.run,
                            tenant,
                            url.clone(),
                            Digest::of("crawlx/canonical-url/v1", url.as_str().as_bytes()),
                            crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
                                "crawlx-fetch/native",
                                env!("CARGO_PKG_VERSION"),
                            ),
                        );
                        if let FetchError::MetaRefresh { evidence, .. } = &error {
                            metadata.meta_refresh = Some(evidence.as_ref().clone());
                        }
                        budget.stamp(&mut metadata);
                        failure.acquisition = Some(Box::new(metadata));
                        return Err(failure);
                    }
                }
            } else if backend == "native_browser" {
                let renderer = self
                    .renderer
                    .as_ref()
                    .ok_or_else(|| fetch_failure(&FetchError::AcquisitionUnavailable))?;
                let remaining = budget.reserve(cancel).map_err(|e| fetch_failure(&e))?;
                options.timeout_ms = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX).max(1);
                let allowance = budget.render_allowance(cancel);
                let rendered = renderer
                    .render_bounded(
                        &RenderRequest {
                            request,
                            options: &options,
                        },
                        &allowance,
                    )
                    .await
                    .map_err(|e| render_failure(&e))?;
                let mut metadata = self.render_metadata(url, &rendered, tenant);
                let redirects = rendered
                    .evidence
                    .as_ref()
                    .map_or_else(Vec::new, |e| e.redirects.clone());
                if rendered.evidence.is_none() {
                    return Err(fetch_failure(&FetchError::AcquisitionUnavailable));
                }
                let body = Bytes::from(rendered.html);
                budget.charge_bytes(body.len());
                let (validation, document) = crate::acquisition::validate_body(
                    crate::acquisition::extraction_body(
                        &body,
                        &self.fetcher.config().controls,
                        &self.extract,
                    ),
                    rendered.final_url.clone(),
                    rendered.content_type.clone(),
                    rendered.headers.clone(),
                    crate::acquisition::context(&policy, metadata.target_status, metadata.truncated),
                    self.extract.clone(),
                    cpu,
                    &self.fetcher.config().controls,
                    self.captcha_secrets.as_ref(),
                )
                .await
                .map_err(|e| fetch_failure(&e))?;
                metadata.validation = validation;
                metadata.extraction_succeeded = document.as_ref().map(|_| true);
                budget.record(
                    "native_browser",
                    metadata.target_status,
                    metadata.validation.category,
                );
                budget.stamp(&mut metadata);
                metadata
                    .bound()
                    .map_err(|_| fetch_failure(&FetchError::AcquisitionUnavailable))?;
                Acquired {
                    final_url: rendered.final_url,
                    status: rendered.status,
                    proxy_used: options.proxy,
                    headers: rendered.headers,
                    content_type: rendered.content_type,
                    body,
                    redirects,
                    render: Some(RenderExtras {
                        screenshot: rendered.screenshot,
                        actions: rendered.actions,
                        computed: rendered.computed_styles,
                    }),
                    metadata,
                    document,
                    budget: None,
                }
            } else {
                return Err(fetch_failure(&FetchError::AcquisitionUnavailable));
            };
            let mut acquired = acquired;
            if let Some(article) = acquired
                .document
                .as_mut()
                .and_then(|document| document.article.as_mut())
            {
                article.acquisition_request_digest = Some(acquired.metadata.request_digest);
                article.source_artifact = acquired
                    .metadata
                    .wire_body
                    .as_ref()
                    .or(acquired.metadata.rendered_dom.as_ref())
                    .cloned();
            }
            let outcome = &acquired.metadata.validation;
            let retry = options.actions.is_empty()
                && outcome
                    .retry_disposition
                    .is_some_and(|class| policy.retry_on.contains(&class));
            if retry
                && budget.can_retry()
                && !(outcome.category == ValidationCategoryV1::RateLimited
                    && self.fetcher.governor().defers_source_throttle())
            {
                // Shared cooldown is not permission to change backend or identity.
                if outcome.category != ValidationCategoryV1::RateLimited {
                    if let Some(next) = fallbacks.next() {
                        backend = next;
                    }
                }
                continue;
            }
            acquired.budget = Some((budget, cancel.clone()));
            return Ok(acquired);
        }
    }

    /// Auxiliary requests share the same attempt, request, byte and monotonic deadline limits.
    async fn fetch_auxiliary(
        &self,
        url: &Url,
        original: &FetchOptions,
        acq: &mut Acquired,
        observe: &FetchObserver<'_>,
    ) -> Result<FetchResponse, FetchError> {
        let Some((budget, cancel)) = &mut acq.budget else {
            let fetched = self.fetcher.fetch(url, original).await;
            observe(url, &fetched);
            return fetched;
        };
        let remaining = budget.reserve(cancel)?;
        let options = budget.options(original, self.fetcher.config().max_body_bytes);
        let fetched = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
            result = tokio::time::timeout(remaining, self.fetcher.fetch_once(url, &options)) => result.unwrap_or(Err(FetchError::AcquisitionDeadline)),
        };
        observe(url, &fetched);
        if let Ok(response) = &fetched {
            budget.charge_bytes(response.body.len());
            let category = if response.status.is_client_error() || response.status.is_server_error() {
                crawlx_core::acquisition::ValidationCategoryV1::TargetError
            } else {
                crawlx_core::acquisition::ValidationCategoryV1::Indeterminate
            };
            budget.record("native_http", Some(response.status.as_u16()), category);
        } else {
            if let Err(error) = &fetched {
                budget.on_fetch_failure(
                    error,
                    options
                        .max_body_bytes
                        .unwrap_or(self.fetcher.config().max_body_bytes),
                );
            }
            budget.record(
                "native_http",
                None,
                crawlx_core::acquisition::ValidationCategoryV1::TransportError,
            );
        }
        budget.stamp(&mut acq.metadata);
        fetched
    }

    /// The `branding` format: up to [`BRANDING_STYLESHEETS`] linked stylesheets read through
    /// the run's fetcher (so egress policy and request controls apply) within a total of
    /// [`BRANDING_CSS_BYTES`], then the heuristics over HTML and CSS. A page rendered in a
    /// browser also brings what `getComputedStyle` reported, which the profile reads over the
    /// declared styles (browser leg); a page fetched over HTTP has the heuristics alone (HTTP
    /// leg). A stylesheet that cannot be fetched is skipped.
    async fn branding(
        &self,
        acq: &mut Acquired,
        cpu: &CpuPool,
        observe: &FetchObserver<'_>,
    ) -> Result<branding_llm::Branded, WorkerError> {
        let html = self.redact(&String::from_utf8_lossy(&acq.body));
        let mut sheets: Vec<String> = Vec::new();
        let mut used = 0usize;
        let stylesheets = {
            // `stylesheet_urls` parses the page on this task; hold a charge for that DOM
            let _charge = crawlx_extract::parse_budget::charge(html.len())
                .map_err(|e| WorkerError::Extraction(e.into()))?;
            branding::stylesheet_urls(&html, &acq.final_url)
        };
        for sheet in stylesheets.into_iter().take(BRANDING_STYLESHEETS) {
            let remaining = BRANDING_CSS_BYTES.saturating_sub(used);
            if remaining == 0 {
                break;
            }
            let opts = FetchOptions {
                max_body_bytes: Some(remaining),
                ..FetchOptions::default()
            };
            match self.fetch_auxiliary(&sheet, &opts, acq, observe).await {
                Ok(r) if r.status.is_success() => {
                    used = used.saturating_add(r.body.len());
                    sheets.push(self.redact(&String::from_utf8_lossy(&r.body)));
                }
                Ok(r) => tracing::debug!(status = r.status.as_u16(), "stylesheet not usable"),
                Err(e) => tracing::debug!(code = e.code(), "stylesheet not fetched"),
            }
        }
        let base = acq.final_url.clone();
        let computed = acq.render.as_ref().and_then(|r| r.computed.clone());
        let excerpts = self
            .branding_llm
            .as_ref()
            .map(|_| branding_llm::excerpts(&sheets));
        let mut profile = cpu
            .run(move || {
                let _charge = crawlx_extract::parse_budget::charge(html.len())
                    .map_err(|e| WorkerError::Extraction(e.into()))?;
                let input = BrandingInput {
                    html: &html,
                    base: &base,
                    stylesheets: &sheets,
                };
                Ok::<_, WorkerError>(match &computed {
                    Some(styles) => branding::branding_computed(&input, styles),
                    None => branding::branding(&input),
                })
            })
            .await
            .map_err(|e| WorkerError::Other(format!("branding task failed: {e}")))??;
        self.redact_value(&mut profile);
        Ok(match (&self.branding_llm, excerpts) {
            (Some(_), _) if self.zdr => branding_llm::Branded::zero_data_retention(profile),
            (Some(llm), Some(excerpts)) => {
                branding_llm::refine(
                    llm.as_ref(),
                    profile,
                    &self.redact(acq.final_url.as_str()),
                    &excerpts,
                )
                .await
            }
            _ => branding_llm::Branded::plain(profile),
        })
    }

    /// Does any requested format need the LLM (including `changeTracking`'s `json` mode)?
    fn needs_llm(&self) -> bool {
        self.options.formats.iter().any(|f| {
            f.needs_llm()
                || matches!(f, FormatSpec::ChangeTracking { modes, .. } if modes.contains(&ChangeMode::Json))
        })
    }

    /// A page row that serves the stored scrape `stored` to `entry`: same artifacts, same
    /// `fetched_at`, `cacheState: hit` and `cachedAt`.
    async fn serve_cached(
        &self,
        stored: PageRecord,
        entry: &FrontierEntry,
        cpu: &CpuPool,
    ) -> Result<Option<Scraped>, WorkerError> {
        let run = self.deps.runs.get(self.run).await?;
        let mut accepted = Vec::new();
        let mut outbox = Vec::new();
        if run.config.datasets.article_store()?.is_some()
            || (!self.options.wants("rawBase64")
                && self
                    .extract
                    .content
                    .as_ref()
                    .is_some_and(|policy| policy.chunks.is_some()))
            || ScrapeDocument::from_page_metadata(&stored.metadata)
                .and_then(|document| document.meta.get("article").cloned())
                .is_some_and(|article| article.get("chunks").is_some_and(|chunks| !chunks.is_null()))
        {
            let Some(doc) = ScrapeDocument::from_page_metadata(&stored.metadata) else {
                return Ok(None);
            };
            let Some(reference) = doc.meta.get("articleDocumentRef") else {
                return Ok(None);
            };
            let reference: crawlx_core::scrape::BlobRef = serde_json::from_value(reference.clone())
                .map_err(|_| WorkerError::Config("invalid retained article reference".into()))?;
            let source = doc
                .meta
                .get("articleCacheSourceRun")
                .cloned()
                .map(serde_json::from_value::<CrawlRunId>)
                .transpose()
                .map_err(|_| WorkerError::Config("invalid retained article source".into()))?
                .unwrap_or(stored.run);
            let source = self.deps.runs.get(source).await?;
            if source.tenant != run.tenant {
                return Err(
                    crawlx_core::StoreError::AccessDenied("article cache tenant mismatch".into()).into(),
                );
            }
            let (document, deadline, source_id) = match crate::delivery::load_article_cache(
                self.deps.artifacts.as_ref(),
                cpu,
                &source,
                &reference,
                self.deps.clock.now(),
                self.extract.content.as_ref(),
            )
            .await
            {
                Ok(saved) => saved,
                Err(
                    crawlx_core::StoreError::RetentionDenied(_) | crawlx_core::StoreError::NotFound { .. },
                ) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if doc.meta.get("article") != serde_json::to_value(document.article.as_ref()).ok().as_ref() {
                return Ok(None);
            }
            let (_, items, deliveries) = crate::delivery::prepare_article_acceptance_retained(
                self.deps.artifacts.as_ref(),
                cpu,
                &run,
                entry.id,
                Box::new(document),
                true,
                Some(deadline),
                &source_id,
            )
            .await?;
            accepted = items;
            outbox = deliveries;
        }
        let mut record = stored;
        let cached_at = rfc3339(record.fetched_at);
        let mut final_url = entry.url.url.clone();
        if let Some(mut doc) = ScrapeDocument::from_page_metadata(&record.metadata) {
            doc.cache_state = crawlx_core::scrape::CacheState::Hit;
            doc.cached_at = Some(cached_at);
            if self.zdr || self.options.cache.as_ref().is_some_and(|p| !p.writes()) {
                doc.not_cacheable = true;
            }
            if let Ok(u) = Url::parse(&doc.final_url) {
                final_url = u;
            }
            if let Ok(v) = serde_json::to_value(&doc) {
                record.metadata[ScrapeDocument::METADATA_KEY] = v;
            }
        }
        record.run = self.run;
        record.frontier_id = entry.id;
        record.url = entry.url.clone();
        let links = if self.kind == JobKind::Crawl {
            record.links.iter().filter_map(|l| Url::parse(l).ok()).collect()
        } else {
            Vec::new()
        };
        Ok(Some(Scraped {
            record,
            links,
            final_url,
            accepted,
            outbox,
        }))
    }

    /// Scrub configured credentials, registered secrets and recognizable secret shapes.
    fn redact(&self, message: &str) -> String {
        crawlx_telemetry::Redactor::new().scrub(&self.redact_literals(message))
    }

    fn redact_literals(&self, message: &str) -> String {
        let mut out = message.to_owned();
        for secret in self.fetcher.config().controls.secret_values() {
            out = out.replace(secret, crawlx_telemetry::REDACTED);
        }
        crawlx_telemetry::Redactor::new().scrub_known(&out)
    }

    /// Scrub every string, including object keys, without changing JSON value types.
    fn redact_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(text) => *text = self.redact_literals(text),
            serde_json::Value::Array(values) => {
                for value in values {
                    self.redact_value(value);
                }
            }
            serde_json::Value::Object(fields) => {
                *fields = std::mem::take(fields)
                    .into_iter()
                    .map(|(key, mut value)| {
                        self.redact_value(&mut value);
                        (self.redact_literals(&key), value)
                    })
                    .collect();
            }
            _ => {}
        }
    }

    fn redact_bytes<'a>(&self, bytes: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        crawlx_telemetry::Redactor::new().scrub_bytes(bytes, self.fetcher.config().controls.secret_values())
    }
}

/// Fetch failure to page failure: a timeout is `scrape_timeout`, an egress refusal
/// `egress_denied`, a terminal ProxyX pool refusal `proxy_refused`, everything else
/// `unreachable`.
fn fetch_failure(e: &FetchError) -> ScrapeFailure {
    let reason = match e {
        FetchError::Pool(_) => FailReason::ProxyRefused,
        FetchError::PoolRefused { cause, .. } if cause.is_some_and(|c| !c.is_retryable()) => {
            FailReason::ProxyRefused
        }
        FetchError::EgressDenied(denied) if denied.rule == crawlx_policy::DenyRule::AuthorizationScope => {
            FailReason::AuthorizationScope
        }
        FetchError::EgressDenied(_) => FailReason::EgressDenied,
        FetchError::Timeout(_) => FailReason::ScrapeTimeout,
        FetchError::AcquisitionDeadline => FailReason::ScrapeTimeout,
        FetchError::AcquisitionCancelled => FailReason::Cancelled,
        FetchError::Resolve { .. } => FailReason::DnsFailed,
        _ => FailReason::Unreachable,
    };
    ScrapeFailure::new(reason, e.to_string())
}

/// Render failure to page failure.
fn render_failure(e: &RenderError) -> ScrapeFailure {
    let reason = match e {
        RenderError::Timeout(_) => FailReason::ScrapeTimeout,
        RenderError::Navigation(m) if m.contains("ERR_NAME_NOT_RESOLVED") => FailReason::DnsFailed,
        RenderError::Navigation(_) => FailReason::Unreachable,
        RenderError::EgressDenied(_) => FailReason::EgressDenied,
        RenderError::Action { .. } => FailReason::ActionFailed,
        RenderError::Cancelled => FailReason::Cancelled,
        RenderError::Browser(_) | RenderError::Unavailable(_) => FailReason::RenderFailed,
    };
    ScrapeFailure::new(reason, e.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn failures_and_outcomes_keep_acquisition_metadata_out_of_line() {
        assert!(std::mem::size_of::<ScrapeFailure>() <= 128);
        assert!(std::mem::size_of::<Outcome>() <= 128);
    }

    #[test]
    fn reason_codes_are_the_contract_codes() {
        let all = [
            (FailReason::ScrapeTimeout, "scrape_timeout", true),
            (FailReason::Unreachable, "unreachable", true),
            (FailReason::EgressDenied, "egress_denied", false),
            (FailReason::AuthorizationScope, "authorization_scope", false),
            (FailReason::RenderFailed, "render_failed", false),
            (FailReason::ActionFailed, "action_failed", false),
            (FailReason::LlmNotConfigured, "llm_not_configured", false),
            (FailReason::LlmFailed, "llm_failed", false),
            (FailReason::UnsupportedContent, "unsupported_content", false),
            (FailReason::ExtractFailed, "extract_failed", false),
            (FailReason::NoCachedData, "no_cached_data", false),
            (FailReason::LockdownCacheMiss, "lockdown_cache_miss", false),
            (FailReason::Cancelled, "run_stopped", false),
        ];
        for (reason, code, unreachable) in all {
            assert_eq!(reason.code(), code);
            assert_eq!(reason.is_unreachable(), unreachable, "{code}");
        }
    }

    #[test]
    fn render_errors_map_to_reason_codes() {
        let cases = [
            (RenderError::Timeout(5), FailReason::ScrapeTimeout),
            (RenderError::Navigation("dns".to_owned()), FailReason::Unreachable),
            (
                RenderError::EgressDenied("private".to_owned()),
                FailReason::EgressDenied,
            ),
            (
                RenderError::Action {
                    index: 1,
                    kind: "click",
                    reason: "no_match".to_owned(),
                },
                FailReason::ActionFailed,
            ),
            (RenderError::Browser("crash".to_owned()), FailReason::RenderFailed),
            (
                RenderError::Unavailable("none".to_owned()),
                FailReason::RenderFailed,
            ),
            (RenderError::Cancelled, FailReason::Cancelled),
        ];
        for (error, reason) in cases {
            assert_eq!(render_failure(&error).reason, reason, "{error}");
        }
    }
}
