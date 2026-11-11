//! Shared application state: repositories, policy, clock, limiter, deployment build.

use crate::auth::{KeyCache, RateLimiter};
use crate::config::{ApiConfig, Settings};
use crate::intel::jobs::JobRegistry;
use crate::intel::rank::PageRanker;
use crate::intel::search::SearchProvider;
use crate::intel::tools::PageTools;
use crate::intel::webhook::JobWebhookSink;
use crate::memory::MemoryApiStore;
use crate::store::{ApiStore, ArtifactSource, Eraser, StoreResult};
use crate::streams::StreamLimiter;
use async_trait::async_trait;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::{ActionJournal, EventRepo, FrontierRepo, LedgerRepo, PageRepo, RunRepo, StateRepo};
use crawlx_core::{ArtifactId, ArtifactRef, Clock, CrawlRunId, SystemClock};
use crawlx_model::llm::{ExtractionRouter, LlmExtractor};
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::{ArtifactReaper, ArtifactRow, DeliveryBuffer, ObjectArtifactStore};
use crawlx_worker::{chromium_pin, ChromiumPin};
use std::ops::Deref;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// The browser build this deployment runs: the pinned build the worker verifies at launch.
///
/// `POST /v1/replays` refuses a source run whose sessions were recorded on another build
/// (or on no recorded build) unless the request sets `allowBuildMismatch`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeploymentBuild {
    /// Four-part Chromium version, e.g. `155.0.8059.84`.
    pub chromium_version: String,
    /// CDP protocol revision, e.g. `1.3`.
    pub cdp_revision: String,
}

impl DeploymentBuild {
    /// The build a pin describes.
    #[must_use]
    pub fn from_pin(pin: &ChromiumPin) -> Self {
        Self {
            chromium_version: pin.version.clone(),
            cdp_revision: pin.cdp_revision.clone(),
        }
    }

    /// The pin the worker resolves at launch (`CRAWLX_PIN_FILE`, else the nearest
    /// `chromium-pin.toml`), falling back to the copy embedded at build time. When neither
    /// parses the build is empty and matches no recorded session, so replays need
    /// `allowBuildMismatch`.
    #[must_use]
    pub fn resolve() -> Self {
        match ChromiumPin::load_default().or_else(|_| chromium_pin::repository_pin()) {
            Ok(pin) => Self::from_pin(&pin),
            Err(e) => {
                tracing::error!(error = %e, "no usable chromium pin; every replay needs allowBuildMismatch");
                Self {
                    chromium_version: String::new(),
                    cdp_revision: String::new(),
                }
            }
        }
    }

    /// Does a session's recorded build equal this deployment's (version compared numerically,
    /// CDP revision textually)?
    #[must_use]
    pub fn matches(&self, recorded: &BrowserBuildInfo) -> bool {
        let same_version = matches!(
            (
                chromium_pin::parse_version(&self.chromium_version),
                chromium_pin::parse_version(&recorded.chromium_version),
            ),
            (Some(a), Some(b)) if a == b
        );
        same_version && recorded.cdp_revision == self.cdp_revision
    }

    /// `<version> / <cdp revision>`, the shape `GET /v1/crawls/{id}` reports per session.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} / {}", self.chromium_version, self.cdp_revision)
    }
}

/// Every repository the routes use.
#[derive(Clone)]
pub struct Repos {
    /// Crawl runs (`crawl_runs`): creation, status, counters.
    pub runs: Arc<dyn RunRepo>,
    /// Fetched and rendered pages (`pages`).
    pub pages: Arc<dyn PageRepo>,
    /// Observed UI states, clusters and transitions.
    pub states: Arc<dyn StateRepo>,
    /// Action-context coverage ledger.
    pub ledger: Arc<dyn LedgerRepo>,
    /// Append-only run events (`crawl_events`) behind SSE and webhooks.
    pub events: Arc<dyn EventRepo>,
    /// Journal of browser actions, including traffic records.
    pub journal: Arc<dyn ActionJournal>,
    /// URL frontier the worker leases from.
    pub frontier: Arc<dyn FrontierRepo>,
    /// Run-scoped accepted-item keyset reads.
    pub datasets: Arc<dyn crawlx_core::dataset::DatasetRepo>,
    /// Existing request result transaction authority, shared with the frontier store.
    pub request_commits: Arc<dyn crawlx_core::orchestration::RequestCommitRepo>,
    /// Tenant-scoped measured report history under existing custody.
    pub report_history: Arc<dyn crawlx_core::report_history::ReportHistoryRepo>,
    /// Scoped versioned URL graph, separate from browser action state.
    pub url_graph: Arc<dyn crawlx_core::url_graph::UrlGraphRepo>,
    /// Typed versioned KV, under the request's existing tenant scope.
    pub kv: Arc<dyn crawlx_core::dataset::KvRepo>,
    /// Tenant-scoped seen ledger and category metadata reset authority.
    pub source_memo: Arc<dyn crawlx_core::dataset::memo::SourceMemoRepo>,
    /// Scoped structural descriptors with fixed run retention and shared volatile ZDR delivery.
    pub adaptive_selectors: Arc<dyn crawlx_core::cache::AdaptiveSelectorRepo>,
    /// Tenant-scoped archive progress, committed records and final manifests.
    pub archives: Arc<dyn crawlx_core::archive_catalog::ArchiveRepo>,
    /// Existing worker registry; request paths read only fresh structural capability projections.
    pub worker_registry: Arc<dyn crawlx_storage::WorkerRegistry>,
    /// Artifact metadata and bytes.
    pub artifacts: Arc<dyn ArtifactSource>,
    /// API-owned tables: keys, idempotency, approvals, webhooks, audit.
    pub api: Arc<dyn ApiStore>,
    /// Purge of a run's data across every store (erasure path).
    pub eraser: Arc<dyn Eraser>,
    /// Jobs, monitors, checks and the usage ledger of the compatibility-API LLM products.
    pub intel: Arc<dyn crawlx_storage::IntelRepo>,
}

impl Repos {
    /// All repositories over one shared [`crawlx_storage::MemoryStore`] and an in-memory
    /// artifact store. Share `store` with the worker for in-process runs.
    #[must_use]
    pub fn memory(store: Arc<crawlx_storage::MemoryStore>) -> Self {
        let artifacts = Arc::new(
            crawlx_storage::MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock))
                .with_index(store.clone()),
        );
        Self::memory_with(store, artifacts)
    }

    /// As [`Self::memory`] with an explicit artifact source.
    /// The artifact source must mirror rows through the same store's `ArtifactIndex`.
    /// ZDR callers must also attach the same `DeliveryBuffer` with `set_dataset_delivery`.
    #[must_use]
    pub fn memory_with(store: Arc<crawlx_storage::MemoryStore>, artifacts: Arc<dyn ArtifactSource>) -> Self {
        let api = Arc::new(MemoryApiStore::new(store.clone()));
        let eraser = Arc::new(MemoryEraser {
            store: store.clone(),
            api: api.clone(),
            artifacts: artifacts.clone(),
        });
        Self::assemble(store, api, artifacts, eraser)
    }

    /// As [`Self::memory_with`] but also returning the concrete [`MemoryApiStore`] (tests seed
    /// approvals and read audit events through it).
    #[must_use]
    pub fn memory_with_api(
        store: Arc<crawlx_storage::MemoryStore>,
        artifacts: Arc<dyn ArtifactSource>,
    ) -> (Self, Arc<MemoryApiStore>) {
        let api = Arc::new(MemoryApiStore::new(store.clone()));
        let eraser = Arc::new(MemoryEraser {
            store: store.clone(),
            api: api.clone(),
            artifacts: artifacts.clone(),
        });
        (Self::assemble(store, api.clone(), artifacts, eraser), api)
    }

    fn assemble(
        store: Arc<crawlx_storage::MemoryStore>,
        api: Arc<dyn ApiStore>,
        artifacts: Arc<dyn ArtifactSource>,
        eraser: Arc<dyn Eraser>,
    ) -> Self {
        Self {
            runs: store.clone(),
            pages: store.clone(),
            states: store.clone(),
            ledger: store.clone(),
            events: store.clone(),
            journal: store.clone(),
            datasets: store.clone(),
            request_commits: store.clone(),
            report_history: store.clone(),
            url_graph: store.clone(),
            kv: store.clone(),
            source_memo: store.clone(),
            adaptive_selectors: store.clone(),
            archives: store.clone(),
            worker_registry: store.clone(),
            frontier: store,
            artifacts,
            api,
            eraser,
            intel: Arc::new(crawlx_storage::MemoryIntel::new()),
        }
    }

    /// All repositories over PostgreSQL.
    #[must_use]
    pub fn pg(pg: &crawlx_storage::Pg, artifacts: Arc<dyn ArtifactSource>) -> Self {
        let pg_arc = Arc::new(pg.clone());
        Self {
            runs: pg_arc.clone(),
            pages: pg_arc.clone(),
            states: pg_arc.clone(),
            ledger: pg_arc.clone(),
            events: pg_arc.clone(),
            journal: pg_arc.clone(),
            frontier: pg_arc.clone(),
            datasets: pg_arc.clone(),
            request_commits: pg_arc.clone(),
            report_history: pg_arc.clone(),
            url_graph: pg_arc.clone(),
            kv: pg_arc.clone(),
            source_memo: pg_arc.clone(),
            adaptive_selectors: pg_arc.clone(),
            archives: pg_arc.clone(),
            worker_registry: pg_arc.clone(),
            api: Arc::new(crate::pg::PgApiStore::new(pg.clone())),
            eraser: Arc::new(crate::pg::PgEraser::new(pg.clone(), Some(artifacts.clone()))),
            intel: pg_arc,
            artifacts,
        }
    }
}

struct MemoryEraser {
    store: Arc<crawlx_storage::MemoryStore>,
    api: Arc<MemoryApiStore>,
    artifacts: Arc<dyn ArtifactSource>,
}

#[async_trait]
impl Eraser for MemoryEraser {
    async fn erase(&self, run: CrawlRunId) -> StoreResult<u64> {
        let metadata = crawlx_core::repo::RunRepo::get_metadata(self.store.as_ref(), run).await?;
        crate::store::erase_archives(
            self.store.as_ref(),
            self.artifacts.as_ref(),
            metadata.tenant,
            run.0,
        )
        .await?;
        let mut n = self.artifacts.purge_run(run).await?;
        n += self.store.purge_run(run).await?;
        n += self.api.purge_run(run);
        Ok(n)
    }
}

#[async_trait]
impl<B: crawlx_storage::ArtifactBlobs> ArtifactSource for ObjectArtifactStore<B> {
    fn artifact_store(&self) -> Option<&dyn crawlx_core::repo::ArtifactStore> {
        Some(self)
    }

    async fn row(&self, id: ArtifactId) -> StoreResult<Option<ArtifactRow>> {
        ObjectArtifactStore::row(self, id).await
    }

    async fn read(&self, artifact: &ArtifactRef) -> StoreResult<Vec<u8>> {
        crawlx_core::repo::ArtifactStore::get(self, artifact).await
    }
    async fn read_limited(&self, artifact: &ArtifactRef, max_bytes: u64) -> StoreResult<Vec<u8>> {
        self.read_content_limited(artifact, max_bytes).await
    }
    async fn stream(
        &self,
        artifact: &ArtifactRef,
        max_bytes: u64,
    ) -> StoreResult<futures::stream::BoxStream<'static, StoreResult<bytes::Bytes>>> {
        self.stream_content(artifact, max_bytes).await
    }
    async fn stream_archive(
        &self,
        artifact: &ArtifactRef,
        max_bytes: u64,
        custody: &crawlx_core::archive_catalog::ArchiveCustodyV1,
    ) -> StoreResult<futures::stream::BoxStream<'static, StoreResult<bytes::Bytes>>> {
        self.stream_archive_with_custody(artifact, max_bytes, custody)
            .await
    }
    async fn erase_artifact(&self, artifact: &ArtifactRef) -> StoreResult<()> {
        ObjectArtifactStore::erase_artifact(self, artifact)
            .await
            .map(|_| ())
    }

    async fn put_evidence(&self, run: CrawlRunId, bytes: &[u8]) -> StoreResult<ArtifactRef> {
        self.put_kind(
            run,
            crawlx_core::repo::Sensitivity::Sensitive,
            "evidence",
            "text/plain; charset=utf-8",
            bytes,
        )
        .await
    }

    async fn put_login_flow(
        &self,
        run: CrawlRunId,
        bytes: &crawlx_core::secret::Redacted<Vec<u8>>,
        deadline: crawlx_core::Timestamp,
    ) -> StoreResult<ArtifactRef> {
        crawlx_core::secret::ArtifactSink::over(self)
            .put_until(
                run,
                crawlx_core::repo::Sensitivity::Content,
                "application/json",
                bytes,
                deadline,
            )
            .await
    }

    async fn purge_run(&self, run: CrawlRunId) -> StoreResult<u64> {
        ArtifactReaper::purge_run(self, run).await
    }

    async fn presign(
        &self,
        artifact: &ArtifactRef,
        ttl: std::time::Duration,
    ) -> StoreResult<Option<url::Url>> {
        crawlx_core::repo::ArtifactStore::presign(self, artifact, ttl).await
    }
}

/// Everything a handler needs. Cheap to clone.
pub struct Shared {
    /// Every repository the routes use.
    pub repos: Repos,
    /// Admission policy applied to create requests (URL scope, egress, limits).
    pub policy: AdmissionPolicy,
    /// Startup configuration (rate limit, bootstrap keys, webhook secret).
    pub config: ApiConfig,
    /// Runtime tunables (page limits, SSE timing and caps).
    pub settings: Settings,
    /// Time source for rate limiting, retention and written timestamps.
    pub clock: Arc<dyn Clock>,
    /// Independent fixture evidence supplied by a trusted benchmark harness; absent in production.
    pub fixture_ground_truth: Option<Arc<dyn crate::resources::FixtureGroundTruthSource>>,
    /// Optional control registry shared with the exact in-process local worker.
    pub interactive_profiles: Option<Arc<crawlx_worker::interactive_profiles::InteractiveProfiles>>,
    /// Cancelled when the server shuts down; open SSE streams end on it.
    pub shutdown: CancellationToken,
    /// Browser build replays are admitted against (the pinned build).
    pub build: DeploymentBuild,
    /// Page content of zero-data-retention runs awaiting delivery; `/pages`
    /// serves ZDR runs from it and the webhook sender acknowledges into it.
    pub zdr: Arc<DeliveryBuffer>,
    /// Document LLM, when one is configured.
    pub llm: Option<Arc<dyn LlmExtractor>>,
    /// OCR engine for `/parse` images and scanned PDF pages, when `ocr.backend` is set.
    pub ocr: Option<Arc<crawlx_extract::parse::ocr::Ocr>>,
    /// Chooses the LLM of the `/extract` step between the default model and the extraction
    /// provider (`EXTRACTION_PROVIDER_*`); `None` answers it with [`Self::llm`].
    pub extraction: Option<Arc<ExtractionRouter>>,
    /// Embedding ranking of the pages `/extract` reads (`CRAWLX_EMBEDDING_MODEL`); `None` sends
    /// every page in scrape order.
    pub embeddings: Option<Arc<PageRanker>>,
    /// Search backend, when one is configured.
    pub search: Option<Arc<dyn SearchProvider>>,
    /// Scrape and map tools the LLM products call, when wired.
    pub tools: Option<Arc<dyn PageTools>>,
    /// Delivery of job webhooks (`extract.*`, `agent.*`, `monitor.*`).
    pub job_webhooks: JobWebhookSink,
    /// Toolkit provider behind the agent's `exchange` tools, when one is plugged in.
    pub exchange: Option<Arc<dyn crate::intel::exchange::ExchangeProvider>>,
    /// Background `extract`/`agent`/`monitor` jobs of this process.
    pub jobs: Arc<JobRegistry>,
    /// Documentation search index, built on first use (`/support/*`).
    pub docs_index: tokio::sync::OnceCell<Arc<crate::intel::docs_search::DocsIndex>>,
    /// In-memory store of zero-data-retention agent results (24 h).
    pub agent_vault: Arc<crate::intel::zdr_vault::ZdrVault>,
    /// How the ownership challenges of authorization records are checked
    /// ([`ApiConfig::ownership_probe`], else the network probe).
    pub ownership: Arc<dyn crate::ownership::OwnershipProbe>,
    pub(crate) limiter: RateLimiter,
    pub(crate) streams: StreamLimiter,
    pub(crate) keys: KeyCache,
}

/// Shared handler state (`Arc` inside).
#[derive(Clone)]
pub struct AppState(Arc<Shared>);

impl Deref for AppState {
    type Target = Shared;
    fn deref(&self) -> &Shared {
        &self.0
    }
}

/// Builder for non-default clock/settings.
pub struct AppStateBuilder {
    repos: Repos,
    policy: AdmissionPolicy,
    config: ApiConfig,
    settings: Settings,
    clock: Arc<dyn Clock>,
    fixture_ground_truth: Option<Arc<dyn crate::resources::FixtureGroundTruthSource>>,
    interactive_profiles: Option<Arc<crawlx_worker::interactive_profiles::InteractiveProfiles>>,
    shutdown: CancellationToken,
    build: DeploymentBuild,
    zdr: Option<Arc<DeliveryBuffer>>,
    llm: Option<Arc<dyn LlmExtractor>>,
    ocr: Option<Arc<crawlx_extract::parse::ocr::Ocr>>,
    extraction: Option<Arc<ExtractionRouter>>,
    embeddings: Option<Arc<PageRanker>>,
    search: Option<Arc<dyn SearchProvider>>,
    tools: Option<Arc<dyn PageTools>>,
    job_webhooks: Option<JobWebhookSink>,
    exchange: Option<Arc<dyn crate::intel::exchange::ExchangeProvider>>,
}

impl AppStateBuilder {
    /// Share the exact local worker's interactive control registry.
    /// Separate API and worker processes must not create independent registries.
    #[must_use]
    pub fn interactive_profiles(
        mut self,
        registry: Arc<crawlx_worker::interactive_profiles::InteractiveProfiles>,
    ) -> Self {
        self.interactive_profiles = Some(registry);
        self
    }

    /// Replace the default [`Settings`].
    #[must_use]
    pub fn settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    /// Clock for rate limiting, retention windows and timestamps the API writes.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Attach a trusted fixture-manifest and exercise-evidence source.
    ///
    /// Ordinary runs, and deployments without a source, return `null` ground truth.
    /// This is server-side harness input, never a crawl request field or a client-supplied score.
    #[must_use]
    pub fn fixture_ground_truth(
        mut self,
        source: Arc<dyn crate::resources::FixtureGroundTruthSource>,
    ) -> Self {
        self.fixture_ground_truth = Some(source);
        self
    }

    /// Token whose cancellation ends open SSE streams so graceful shutdown can finish.
    #[must_use]
    pub fn shutdown(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Browser build replays are admitted against; defaults to [`DeploymentBuild::resolve`].
    #[must_use]
    pub fn deployment_build(mut self, build: DeploymentBuild) -> Self {
        self.build = build;
        self
    }

    /// Share `buffer` with the artifact store the worker writes through
    /// ([`ObjectArtifactStore::with_zdr_buffer`]); defaults to a fresh buffer with the planning
    /// limits on this state's clock.
    #[must_use]
    pub fn zdr_buffer(mut self, buffer: Arc<DeliveryBuffer>) -> Self {
        self.zdr = Some(buffer);
        self
    }

    /// The document LLM behind the `json`/`summary`/`question`/`highlights` formats, `/extract`,
    /// `/agent` and `/monitor` judging. Without one those operations answer `503`.
    #[must_use]
    pub fn llm(mut self, llm: Arc<dyn LlmExtractor>) -> Self {
        self.llm = Some(llm);
        self
    }

    /// Route the `/extract` LLM step between the default LLM and an extraction provider.
    #[must_use]
    pub fn extraction_router(mut self, router: Arc<ExtractionRouter>) -> Self {
        self.extraction = Some(router);
        self
    }

    /// Rank the pages `/extract` reads by embedding similarity to the prompt before the LLM
    /// sees them.
    #[must_use]
    pub fn page_ranker(mut self, ranker: Arc<PageRanker>) -> Self {
        self.embeddings = Some(ranker);
        self
    }

    /// The search backend of `/search`, `/extract` (`enableWebSearch`) and the agent. Without
    /// one those operations answer `503`.
    #[must_use]
    pub fn search_provider(mut self, search: Arc<dyn SearchProvider>) -> Self {
        self.search = Some(search);
        self
    }

    /// The OCR engine behind `POST /v2/parse` image uploads and scanned PDF pages. Without one
    /// images are refused (`415`) and scanned pages stay empty.
    #[must_use]
    pub fn ocr(mut self, ocr: Arc<crawlx_extract::parse::ocr::Ocr>) -> Self {
        self.ocr = Some(ocr);
        self
    }

    /// The page tools (scrape, map) the LLM products call.
    #[must_use]
    pub fn page_tools(mut self, tools: Arc<dyn PageTools>) -> Self {
        self.tools = Some(tools);
        self
    }

    /// The sender of job webhooks (`extract.*`, `agent.*`, `monitor.*`); the default signs with
    /// `webhook_secret` through [`crate::webhooks::ReqwestTransport`].
    #[must_use]
    pub fn job_webhooks(mut self, sink: JobWebhookSink) -> Self {
        self.job_webhooks = Some(sink);
        self
    }

    /// The toolkit provider behind the agent's `exchange` tools.
    #[must_use]
    pub fn exchange_provider(mut self, provider: Arc<dyn crate::intel::exchange::ExchangeProvider>) -> Self {
        self.exchange = Some(provider);
        self
    }

    /// Finish the state: builds the rate limiter and SSE limiter from the configuration.
    #[must_use]
    pub fn build(self) -> AppState {
        let limiter = RateLimiter::new(self.config.rate_limit_per_minute);
        let streams = StreamLimiter::new(self.settings.sse_max_per_tenant, self.settings.sse_max_per_run);
        let zdr = self
            .zdr
            .unwrap_or_else(|| Arc::new(DeliveryBuffer::with_defaults(self.clock.clone())));
        let job_webhooks = self.job_webhooks.unwrap_or_else(|| {
            JobWebhookSink::new(
                Arc::new(crate::webhooks::ReqwestTransport),
                &self.config.webhook_secret,
            )
        });
        let jobs = Arc::new(JobRegistry::new(self.shutdown.clone()));
        let ownership: Arc<dyn crate::ownership::OwnershipProbe> = match &self.config.ownership_probe {
            Some(probe) => probe.clone(),
            None => Arc::new(crate::ownership::NetworkProbe::new()),
        };
        AppState(Arc::new(Shared {
            repos: self.repos,
            policy: self.policy,
            config: self.config,
            settings: self.settings,
            clock: self.clock,
            fixture_ground_truth: self.fixture_ground_truth,
            interactive_profiles: self.interactive_profiles,
            shutdown: self.shutdown,
            build: self.build,
            zdr,
            llm: self.llm,
            ocr: self.ocr,
            extraction: self.extraction,
            embeddings: self.embeddings,
            search: self.search,
            tools: self.tools,
            job_webhooks,
            exchange: self.exchange,
            jobs,
            docs_index: tokio::sync::OnceCell::new(),
            agent_vault: Arc::new(crate::intel::zdr_vault::ZdrVault::new()),
            ownership,
            limiter,
            streams,
            keys: KeyCache::default(),
        }))
    }
}

impl AppState {
    /// Start a builder.
    #[must_use]
    pub fn builder(repos: Repos, policy: AdmissionPolicy, config: ApiConfig) -> AppStateBuilder {
        AppStateBuilder {
            repos,
            policy,
            config,
            settings: Settings::default(),
            clock: Arc::new(SystemClock),
            fixture_ground_truth: None,
            interactive_profiles: None,
            shutdown: CancellationToken::new(),
            build: DeploymentBuild::resolve(),
            zdr: None,
            llm: None,
            ocr: None,
            extraction: None,
            embeddings: None,
            search: None,
            tools: None,
            job_webhooks: None,
            exchange: None,
        }
    }

    /// State with default settings on the wall clock.
    #[must_use]
    pub fn new(repos: Repos, policy: AdmissionPolicy, config: ApiConfig) -> Self {
        Self::builder(repos, policy, config).build()
    }

    pub(crate) async fn load_fixture_ground_truth(
        &self,
        run: CrawlRunId,
    ) -> StoreResult<Option<crate::resources::FixtureGroundTruth>> {
        match &self.fixture_ground_truth {
            Some(source) => source.ground_truth(run).await,
            None => Ok(None),
        }
    }

    /// Drop cached API-key lookups.
    pub fn clear_key_cache(&self) {
        self.0.keys.clear();
    }
}
