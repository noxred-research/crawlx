#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A rig for the compat crawl, map and webhook tests: the API router and a REAL worker lease
//! loop over one `MemoryStore`, a fixture site served for several host names (the injected
//! resolver maps them all to 127.0.0.1; admission denies literal loopback), a recording webhook
//! transport and a [`WebhookSender`] over the same stores.
//! The worker resolves a stable, operator-verified authorization from the API store. Its scope
//! covers only the fixture origins and loopback network; existing record references stay intact.
//!
//! Include it next to `mod common;` with `#[path = "common/crawl_rig.rs"] mod crawl_rig;`.

use crate::common::Env;
use async_trait::async_trait;
use axum::extract::State;
use axum::http::{header, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::ownership::{verify_ownership, OwnershipOutcome, StaticProbe};
use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookSender, WebhookTransport};
use crawlx_api::{ApiConfig, AppState, CompatConfig, Repos, Scope, Settings};
use crawlx_core::counters::PlaneCounters;
use crawlx_core::orchestration::{RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{CrawlRun, CrawlSession, RunRepo};
use crawlx_core::{AuthorizationRecordId, Clock, CrawlRunId, SessionId, StoreError, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_model::llm::LlmExtractor;
use crawlx_policy::attestation::OperatorKeys;
use crawlx_policy::authorization::{AuthorizationRecord, OwnershipProof};
use crawlx_storage::{DeliveryBuffer, MemoryArtifactStore, MemoryStore};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{AuthorizationSource, EgressConfig, Stores, WorkerConfig, WorkerError};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The fixture site's own host.
pub const HOST: &str = "site.example.test";
/// A subdomain of [`HOST`].
pub const SUB_HOST: &str = "blog.site.example.test";
/// A host of another registrable domain.
pub const EXT_HOST: &str = "far.elsewhere.test";
/// The secret that signs webhook deliveries.
pub const WEBHOOK_SECRET: &str = "whsec_rig";

/// A result store that atomically refuses a page whose URL contains `needle`.
struct FailingPageCommits {
    inner: Arc<MemoryStore>,
    needle: String,
}

#[async_trait]
impl crawlx_core::digest_registry::DigestRegistryRepo for FailingPageCommits {
    async fn digest_outcome(
        &self,
        run: crawlx_core::CrawlRunId,
        frontier_id: i64,
    ) -> Result<Option<crawlx_core::digest_registry::DigestOutcomeV1>, StoreError> {
        crawlx_core::digest_registry::DigestRegistryRepo::digest_outcome(
            self.inner.as_ref(),
            run,
            frontier_id,
        )
        .await
    }
}

#[async_trait]
impl RequestCommitRepo for FailingPageCommits {
    async fn begin_feed_finalization(
        &self,
        run: crawlx_core::CrawlRunId,
        reason: Option<crawlx_core::counters::TerminalReason>,
    ) -> Result<Option<crawlx_core::counters::TerminalReason>, StoreError> {
        self.inner.begin_feed_finalization(run, reason).await
    }
    async fn stage_feed_batches(
        &self,
        run: crawlx_core::CrawlRunId,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.inner.stage_feed_batches(run, batches).await
    }
    async fn staged_feed_batch(
        &self,
        run: crawlx_core::CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<crawlx_core::dataset::DeliveryBatchV1>, StoreError> {
        self.inner.staged_feed_batch(run, feed, idempotency_key).await
    }
    async fn finalize_run_feeds(
        &self,
        run: crawlx_core::CrawlRunId,
        status: crawlx_core::counters::RunStatus,
        reason: crawlx_core::counters::TerminalReason,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.inner.finalize_run_feeds(run, status, reason, batches).await
    }
    async fn lease_observed_fenced(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
        epoch: crawlx_core::ObservationEpoch,
        request_id: i64,
    ) -> Result<Option<(crawlx_core::repo::FrontierEntry, i64)>, StoreError> {
        self.inner.lease_observed_fenced(lease, epoch, request_id).await
    }
    async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError> {
        if commit
            .page
            .as_ref()
            .is_some_and(|page| page.url.to_string().contains(&self.needle))
        {
            return Err(StoreError::Backend("page store refused the write".to_owned()));
        }
        self.inner.commit_fenced(commit).await
    }
}

/// What the rig runs besides the fixture site.
#[derive(Default)]
pub struct RigConfig {
    /// Document LLM for the worker AND the API.
    pub llm: Option<Arc<dyn LlmExtractor>>,
    /// `compat.prefixedKeys`.
    pub prefixed_keys: bool,
    /// API settings.
    pub settings: Option<Settings>,
    /// The worker's atomic result store refuses pages whose URL contains this text.
    /// The URL plane then fails with a storage error and the run ends `failed`.
    pub fail_page_writes: Option<String>,
}

/// Requests the fixture site served, by path (query ignored).
#[derive(Clone, Default)]
pub struct Seen {
    pub hits: Arc<Mutex<BTreeMap<String, usize>>>,
}

impl Seen {
    /// Requests served for `path` on any host.
    pub fn hits(&self, path: &str) -> usize {
        self.hits.lock().get(path).copied().unwrap_or(0)
    }
}

#[derive(Clone)]
struct SiteState {
    seen: Seen,
    port: u16,
}

fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

fn record(s: &SiteState, uri: &Uri) {
    *s.seen.hits.lock().entry(uri.path().to_owned()).or_insert(0) += 1;
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<html lang=\"en\"><head><title>{title}</title><meta name=\"description\" content=\"{title} description\"></head><body><main><h1>{title}</h1>{body}</main></body></html>"
    )
}

/// The fixture site: one listener answers every host name.
///
/// `/` links to `/a`, `/b`, `/docs/guide`, `/docs/old/x`, `/page?id=1`, the subdomain page,
/// an external article and the external homepage; `/sitemap.xml` lists `/a`, `/c`,
/// `/blog-post`, `/docs/guide`, `/page?id=2` and a subdomain page.
async fn start_site(seen: Seen) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let st = SiteState {
        seen,
        port: addr.port(),
    };
    let app = Router::new()
        .route(
            "/",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                let p = s.port;
                html(format!(
                    "<html lang=\"en\"><head><title>Fixture Home</title><meta name=\"description\" content=\"The fixture home page\"><meta property=\"og:image\" content=\"/og.png\"></head><body><main><h1>Fixture Home</h1><p>Welcome. The answer is forty-two.</p>\
<a href=\"/a\">A</a> <a href=\"/b\">B</a> <a href=\"/docs/guide\">Guide</a> <a href=\"/docs/old/x\">Old</a> <a href=\"/page?id=1\">Page 1</a>\
<a href=\"http://{SUB_HOST}:{p}/sub-post\">Sub</a>\
<a href=\"http://{EXT_HOST}:{p}/article\">Ext article</a> <a href=\"http://{EXT_HOST}:{p}/\">Ext home</a>\
<img src=\"/logo.png\" alt=\"logo\"></main></body></html>"
                ))
            }),
        )
        .route(
            "/a",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Page A", "<p>Text of A.</p><a href=\"/\">Home</a><a href=\"/c\">C</a>"))
            }),
        )
        .route(
            "/b",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Page B", "<p>Text of B.</p>"))
            }),
        )
        .route(
            "/boom",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Boom", "<p>The page the store refuses to keep.</p>"))
            }),
        )
        .route(
            "/c",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Page C", "<p>Text of C.</p>"))
            }),
        )
        .route(
            "/blog-post",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Blog Post", "<p>A post about blogging.</p>"))
            }),
        )
        .route(
            "/docs/guide",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Guide", "<p>The guide.</p><a href=\"/docs/deeper\">Deeper</a>"))
            }),
        )
        .route(
            "/docs/deeper",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Deeper", "<p>Deeper docs.</p>"))
            }),
        )
        .route(
            "/docs/old/x",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Old", "<p>Old docs.</p>"))
            }),
        )
        .route(
            "/page",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Query page", "<p>Query page.</p>"))
            }),
        )
        .route(
            "/sub-post",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Sub post", "<p>On the subdomain.</p>"))
            }),
        )
        .route(
            "/article",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page(
                    "External article",
                    "<p>An article on another site.</p><a href=\"/deep-ext\">Deeper on the external site</a>",
                ))
            }),
        )
        .route(
            "/deep-ext",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                html(page("Deep external", "<p>Never fetched.</p>"))
            }),
        )
        .route(
            "/robots.txt",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                "User-agent: firebot\nDisallow: /b\n\nUser-agent: *\nDisallow: /private/\n"
            }),
        )
        .route(
            "/sitemap.xml",
            get(|State(s): State<SiteState>, u: Uri| async move {
                record(&s, &u);
                let p = s.port;
                (
                    [(header::CONTENT_TYPE, "application/xml")],
                    format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\
<url><loc>http://{HOST}:{p}/a</loc></url>\
<url><loc>http://{HOST}:{p}/c</loc></url>\
<url><loc>http://{HOST}:{p}/blog-post</loc></url>\
<url><loc>http://{HOST}:{p}/docs/guide</loc></url>\
<url><loc>http://{HOST}:{p}/page?id=2</loc></url>\
<url><loc>http://{SUB_HOST}:{p}/sub-post</loc></url>\
<url><loc>http://{EXT_HOST}:{p}/elsewhere</loc></url>\
</urlset>"
                    ),
                )
            }),
        )
        .with_state(st);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr.port(), task)
}

/// Read authorization lifecycle state from the same tenant-scoped store as the API.
struct FixtureAuthorizations {
    api: Arc<crawlx_api::MemoryApiStore>,
    tenant: TenantId,
}

#[async_trait]
impl AuthorizationSource for FixtureAuthorizations {
    async fn fetch(&self, id: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError> {
        Ok(crawlx_api::ApiStore::authorization_get(self.api.as_ref(), self.tenant, id).await?)
    }
}

/// Worker-only view of API-admitted runs: authorize the owned loopback destination and remove
/// fixture pacing. Never replace an explicit authorization reference or widen its record.
struct PrivateNetworks(Arc<MemoryStore>, AuthorizationRecordId);

#[async_trait]
impl RunRepo for PrivateNetworks {
    async fn create(&self, run: &CrawlRun, key: Option<&str>) -> Result<(), StoreError> {
        self.0.create(run, key).await
    }
    async fn create_replay(
        &self,
        run: &CrawlRun,
        sessions: &[CrawlSession],
        spec: &serde_json::Value,
    ) -> Result<(), StoreError> {
        self.0.create_replay(run, sessions, spec).await
    }
    async fn replay_spec(&self, run: CrawlRunId) -> Result<Option<serde_json::Value>, StoreError> {
        self.0.replay_spec(run).await
    }
    async fn get(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let mut run = RunRepo::get(self.0.as_ref(), id).await?;
        run.config.safety.allow_private_networks = true;
        run.config.safety.authorization_record_ref.get_or_insert(self.1);
        run.config.politeness.delay_ms = 0;
        Ok(run)
    }
    async fn get_for_execution(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let mut run = self.get(id).await?;
        run.config.fetch = self.0.get_for_execution(id).await?.config.fetch;
        Ok(run)
    }
    async fn set_status(
        &self,
        id: CrawlRunId,
        status: crawlx_core::counters::RunStatus,
        reason: Option<crawlx_core::counters::TerminalReason>,
    ) -> Result<(), StoreError> {
        self.0.set_status(id, status, reason).await
    }
    async fn update_counters(&self, id: CrawlRunId, counters: PlaneCounters) -> Result<(), StoreError> {
        self.0.update_counters(id, counters).await
    }
    async fn create_sessions(&self, sessions: &[CrawlSession]) -> Result<(), StoreError> {
        self.0.create_sessions(sessions).await
    }
    async fn list_sessions(&self, run: CrawlRunId) -> Result<Vec<CrawlSession>, StoreError> {
        self.0.list_sessions(run).await
    }
    async fn set_session_status(
        &self,
        id: SessionId,
        status: crawlx_core::repo::SessionStatus,
    ) -> Result<(), StoreError> {
        self.0.set_session_status(id, status).await
    }
    async fn set_session_browser(
        &self,
        id: SessionId,
        info: &crawlx_core::observation::BrowserBuildInfo,
    ) -> Result<(), StoreError> {
        self.0.set_session_browser(id, info).await
    }
    async fn set_trace_id(&self, run: CrawlRunId, trace_id: crawlx_core::TraceId) -> Result<(), StoreError> {
        self.0.set_trace_id(run, trace_id).await
    }
}

/// A webhook transport that records every request and answers `status`.
pub struct Receiver {
    pub seen: Mutex<Vec<WebhookRequest>>,
    status: Mutex<u16>,
}

impl Receiver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            status: Mutex::new(200),
        })
    }

    /// The status the receiver answers from now on.
    pub fn respond(&self, status: u16) {
        *self.status.lock() = status;
    }

    /// The JSON bodies received so far, oldest first.
    pub fn bodies(&self) -> Vec<Value> {
        self.seen
            .lock()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }

    /// The `type` of every body received so far.
    pub fn types(&self) -> Vec<String> {
        self.bodies()
            .iter()
            .map(|b| b["type"].as_str().unwrap().to_owned())
            .collect()
    }
}

#[async_trait]
impl WebhookTransport for Receiver {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        self.seen.lock().push(req);
        Ok(*self.status.lock())
    }
}

/// The value of header `name` (case-insensitive) of `req`.
pub fn header_of<'a>(req: &'a WebhookRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The API, a worker and a fixture site wired to each other.
pub struct Rig {
    pub env: Env,
    pub seen: Seen,
    pub receiver: Arc<Receiver>,
    pub sender: Arc<WebhookSender>,
    /// Stable, operator-verified record used by the worker for fixture-only runs.
    pub authorization: AuthorizationRecordId,
    port: u16,
    site: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
    worker: Option<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Rig {
    /// Start everything with `cfg`.
    pub async fn start(cfg: RigConfig) -> Self {
        let seen = Seen::default();
        let (port, site) = start_site(seen.clone()).await;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let store = Arc::new(MemoryStore::new());
        let zdr = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
        store.set_dataset_delivery(zdr.clone());
        let artifacts = Arc::new(
            MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock)).with_zdr_buffer(zdr.clone()),
        );
        let (repos, api) = Repos::memory_with_api(store.clone(), artifacts.clone());
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            webhook_secret: WEBHOOK_SECRET.to_owned(),
            compat: CompatConfig {
                prefixed_keys: cfg.prefixed_keys,
                ..CompatConfig::default()
            },
            ..ApiConfig::default()
        };
        let mut builder = AppState::builder(
            repos,
            crawlx_api::admission_policy(&config, clock.clone()),
            config,
        )
        .settings(cfg.settings.unwrap_or_default())
        .clock(clock.clone())
        .zdr_buffer(zdr);
        if let Some(llm) = &cfg.llm {
            builder = builder.llm(llm.clone());
        }
        let state = builder.build();
        let app = crawlx_api::router(state.clone());
        let tenant = tenant_id_for("acme");
        let key = generate_key();
        let rec = key_record(&key, tenant, Scope::all_set()).unwrap();
        crawlx_api::ApiStore::key_insert(api.as_ref(), &rec, "acme")
            .await
            .unwrap();

        let now = clock.now();
        let origins = [HOST, SUB_HOST, EXT_HOST].map(|host| format!("http://{host}:{port}"));
        let origin_refs = origins.each_ref().map(String::as_str);
        let mut authorization = crawlx_policy::testkit::sample_record(tenant, now, &origin_refs);
        authorization.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
        let keys = OperatorKeys::parse("fixture 00112233445566778899aabbccddeeff").unwrap();
        authorization.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "fixture".to_owned(),
            signature: String::new(),
        });
        authorization.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "fixture".to_owned(),
            signature: keys.sign("fixture", &authorization).unwrap(),
        });
        authorization.validate().unwrap();
        assert!(matches!(
            verify_ownership(&authorization, &keys, &StaticProbe::new(), now).await,
            OwnershipOutcome::Verified { .. }
        ));
        authorization.verified_at = Some(now);
        let authorization_id = authorization.id;
        api.add_authorization(authorization);

        let receiver = Receiver::new();
        let sender = Arc::new(
            WebhookSender::new(
                state.repos.api.clone(),
                state.repos.runs.clone(),
                state.repos.events.clone(),
                receiver.clone(),
                WEBHOOK_SECRET.to_owned(),
                clock,
            )
            .with_documents(state.clone()),
        );

        let dir = tempfile::tempdir().unwrap();
        let mut resolver = StaticResolver::new();
        for host in [HOST, SUB_HOST, EXT_HOST] {
            resolver = resolver.with(host, ["127.0.0.1".parse().unwrap()]);
        }
        let wcfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(resolver)),
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                extra_ports: vec![port],
                ..EgressConfig::default()
            },
            idle_exit_after: None,
            llm: cfg.llm.clone(),
            gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            ..WorkerConfig::default()
        };
        let mut stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
        stores.artifacts = artifacts.clone();
        stores.runs = Arc::new(PrivateNetworks(store.clone(), authorization_id));
        stores = stores.with_authorization_source(Arc::new(FixtureAuthorizations {
            api: Arc::clone(&api),
            tenant,
        }));
        if let Some(needle) = cfg.fail_page_writes.clone() {
            stores.request_commits = Arc::new(FailingPageCommits {
                inner: store.clone(),
                needle,
            });
        }
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let worker = tokio::spawn(async move {
            if let Err(e) = run_with(wcfg, stores, None, token).await {
                eprintln!("worker ended: {e}");
            }
        });
        Self {
            env: Env {
                app,
                state,
                store,
                api,
                artifacts,
                key,
                tenant,
            },
            seen,
            receiver,
            sender,
            authorization: authorization_id,
            port,
            site,
            cancel,
            worker: Some(worker),
            _dir: dir,
        }
    }

    /// `http://site.example.test:PORT` + `path`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{HOST}:{}{path}", self.port)
    }

    /// `http://far.elsewhere.test:PORT` + `path`.
    pub fn ext_url(&self, path: &str) -> String {
        format!("http://{EXT_HOST}:{}{path}", self.port)
    }

    /// `http://blog.site.example.test:PORT` + `path`.
    pub fn sub_url(&self, path: &str) -> String {
        format!("http://{SUB_HOST}:{}{path}", self.port)
    }

    /// Poll the facade status of crawl `id` until it is no longer `scraping`; returns the body.
    pub async fn wait_crawl(&self, id: &str) -> Value {
        let uri = format!("/compat/v2/crawl/{id}?limit=1000");
        for _ in 0..600 {
            let (_, _, v) = self.env.get(&uri).await;
            if v["status"] != "scraping" {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("crawl {id} did not finish in 30 s");
    }

    /// Run the webhook sender until its outbox is drained (at most 20 ticks).
    pub async fn drain_webhooks(&self) {
        for _ in 0..20 {
            let r = self.sender.tick().await.unwrap();
            if r.enqueued == 0 && r.delivered == 0 && r.retried == 0 {
                break;
            }
        }
    }

    /// Stop the worker and wait for it.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        if let Some(w) = self.worker.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), w).await;
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.site.abort();
    }
}
