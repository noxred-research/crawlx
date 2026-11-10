//! In-process rig for `sdk_python.rs`: the compatibility API on real TCP ports, a REAL worker lease
//! loop over the same `MemoryStore`, a fixture HTTP site reached through the host name
//! `site.example.test` (an injected resolver maps it to 127.0.0.1; admission denies literal
//! loopback), a `MockLlm` on both sides and a wiremock metasearch endpoint wired through
//! `IntelConfig.search` (the way `crawlx serve` configures it).
//!
//! Two listeners serve the same router:
//!
//! * `facade`: the router as mounted, `/compat/v2/...`;
//! * `rewritten`: the router behind a `/v2/*` to `/compat/v2/*` rewrite, which is what a
//!   reverse proxy in front of the compatibility API does. The Python SDK needs it: its v2 client joins
//!   `/v2/scrape` onto `api_url` with `urllib.parse.urljoin`, and a rooted path replaces the
//!   `/compat` prefix of `api_url`.

use async_trait::async_trait;
use axum::extract::{Request, State};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use crawlx_api::auth::{generate_compat_key, key_record_for, tenant_id_for};
use crawlx_api::config::{CompatConfig, IntelConfig, SearchSettings};
use crawlx_api::{ApiConfig, AppState, Repos, Scope};
use crawlx_core::counters::PlaneCounters;
use crawlx_core::repo::{CrawlRun, CrawlSession, RunRepo};
use crawlx_core::{AuthorizationRecordId, Clock, CrawlRunId, SessionId, StoreError, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_model::llm::{LlmError, MockLlm};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::{DeliveryBuffer, MemoryArtifactStore, MemoryStore};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{EgressConfig, StaticAuthorizationSource, Stores, WorkerConfig};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

/// The host name every fixture URL uses.
pub const HOST: &str = "site.example.test";

/// The JSON schema the SDK `extract` rows send, and the answer the mock LLM gives for it.
pub fn extract_answer() -> serde_json::Value {
    json!({"headline": "Fixture Home", "answer": 42})
}

fn html(body: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body.to_owned(),
    )
        .into_response()
}

/// The fixture site on 127.0.0.1 (random port): a home page with metadata, two linked pages and a
/// page behind those. [`Site::external`] names an already running site instead (the CrawlerGym
/// server of the SDK shape diff).
pub struct Site {
    /// Listening port.
    pub port: u16,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Site {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Site {
    /// `http://site.example.test:PORT` + `path`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{HOST}:{}{path}", self.port)
    }

    /// A site somebody else serves on `127.0.0.1:port` (the rig only maps [`HOST`] to it and lets
    /// the worker reach that port); nothing is started and nothing is stopped.
    #[allow(dead_code)]
    pub fn external(port: u16) -> Self {
        Self { port, task: None }
    }
}

/// Start the fixture site.
pub async fn start_site() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                html(
                    r#"<!doctype html><html lang="en"><head><title>Fixture Home</title>
<meta name="description" content="The fixture home page"></head><body>
<main><h1>Fixture Home</h1><p>Welcome to the fixture site. The answer is forty-two.</p>
<a href="/a">Page A</a> <a href="/b">Page B</a></main></body></html>"#,
                )
            }),
        )
        .route(
            "/a",
            get(|| async {
                html(r#"<html><head><title>Page A</title></head><body><main><h1>Page A</h1><p>Text of A.</p><a href="/">Home</a></main></body></html>"#)
            }),
        )
        .route(
            "/b",
            get(|| async {
                html(r#"<html><head><title>Page B</title></head><body><main><h1>Page B</h1><p>Text of B.</p><a href="/c">Page C</a></main></body></html>"#)
            }),
        )
        .route(
            "/c",
            get(|| async {
                html(r#"<html><head><title>Page C</title></head><body><main><h1>Page C</h1><p>Text of C.</p></main></body></html>"#)
            }),
        )
        .route(
            "/robots.txt",
            get(|| async { "User-agent: *\nDisallow: /private/\n" }),
        );
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        port,
        task: Some(task),
    }
}

/// A `RunRepo` that lets the worker reach the loopback fixture: it reads every run with
/// `allowPrivateNetworks` and the verified fixture authorization record. Admission in the
/// API still ran on the unmodified request.
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
        run.config.safety.authorization_record_ref = Some(self.1);
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

/// Forward `/v2/...` to `/compat/v2/...` of `api`; every other path is passed on as is.
async fn rewrite_v2(State(api): State<Router>, mut req: Request) -> Response {
    if req.uri().path().starts_with("/v2/") {
        let pq = req
            .uri()
            .path_and_query()
            .map_or("/", axum::http::uri::PathAndQuery::as_str);
        match format!("/compat{pq}").parse::<Uri>() {
            Ok(uri) => *req.uri_mut() = uri,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    }
    match api.oneshot(req).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    }
}

/// The compatibility API, a worker, a fixture site, a mock LLM and a mock metasearch endpoint, wired to each other.
pub struct SdkRig {
    /// The fixture site.
    pub site: Site,
    /// `http://127.0.0.1:PORT`: the compatibility API as mounted (`/compat/v2/...`).
    pub facade_root: String,
    /// `http://127.0.0.1:PORT`: the same router behind the `/v2/*` rewrite.
    pub rewritten_root: String,
    /// The `fc-` key of tenant `acme` (all scopes).
    pub key: String,
    /// The document LLM of the worker and the API.
    pub llm: Arc<MockLlm>,
    /// The metasearch stand-in behind `IntelConfig.search`.
    pub metasearch: wiremock::MockServer,
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl SdkRig {
    /// Start everything.
    pub async fn start() -> Self {
        Self::start_with_site(start_site().await).await
    }

    /// Start everything around `site` (the facade and the worker reach it as `site.url(..)`).
    pub async fn start_with_site(site: Site) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let store = Arc::new(MemoryStore::new());
        let zdr = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
        let artifacts = Arc::new(
            MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock)).with_zdr_buffer(zdr.clone()),
        );
        let (repos, api) = Repos::memory_with_api(store.clone(), artifacts.clone());

        // the mock LLM answers every structured-output call with the extract answer
        let llm = Arc::new(MockLlm::from_fn(|call| {
            if call.schema.is_some() {
                Ok(extract_answer())
            } else {
                Err(LlmError::InvalidOutput("unexpected call".into()))
            }
        }));

        // a metasearch-shaped endpoint: the same two hits on the fixture site for every page
        let metasearch = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/search"))
            .and(wiremock::matchers::query_param("format", "json"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(json!({"results": [
                    {"url": site.url("/a"), "title": "Page A", "content": "the first hit"},
                    {"url": site.url("/b"), "title": "Page B", "content": "the second hit"},
                ]})),
            )
            .mount(&metasearch)
            .await;
        let intel = IntelConfig {
            search: Some(SearchSettings::Metasearch {
                endpoint: metasearch.uri(),
                engines: Vec::new(),
                categories: Vec::new(),
            }),
            ..IntelConfig::default()
        };
        let search = crawlx_api::intel::backends(&intel).unwrap().search;

        let config = ApiConfig {
            rate_limit_per_minute: 0,
            compat: CompatConfig {
                prefixed_keys: true,
                ..CompatConfig::default()
            },
            intel,
            ..ApiConfig::default()
        };
        let mut builder = AppState::builder(repos, AdmissionPolicy::new(clock.clone()), config)
            .clock(clock)
            .zdr_buffer(zdr)
            .llm(llm.clone());
        if let Some(search) = search {
            builder = builder.search_provider(search);
        }
        let state = builder.build();
        let router = crawlx_api::router(state);

        // the `fc-` key, as `crawlx serve --api-key acme=fc-...` bootstraps it
        let key = generate_compat_key();
        let rec = key_record_for(&key, tenant_id_for("acme"), Scope::all_set(), true).unwrap();
        crawlx_api::ApiStore::key_insert(api.as_ref(), &rec, "acme")
            .await
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let resolver = StaticResolver::new().with(HOST, ["127.0.0.1".parse().unwrap()]);
        let wcfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(resolver)),
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                extra_ports: vec![site.port],
                ..EgressConfig::default()
            },
            idle_exit_after: None,
            llm: Some(llm.clone()),
            ..WorkerConfig::default()
        };
        let mut stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
        let now = SystemClock.now();
        let mut authorization = sample_record(tenant_id_for("acme"), now, &[&site.url("/")]);
        authorization.verified_at = Some(now);
        authorization.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
        stores.tenant = authorization.tenant;
        stores.runs = Arc::new(PrivateNetworks(store, authorization.id));
        stores = stores.with_authorization_source(Arc::new(StaticAuthorizationSource::new(authorization)));
        stores.artifacts = artifacts;
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let worker = tokio::spawn(async move {
            if let Err(e) = run_with(wcfg, stores, None, token).await {
                eprintln!("worker ended: {e}");
            }
        });

        let mut tasks = vec![worker];
        let facade_root = serve(&mut tasks, router.clone()).await;
        let rewrite = Router::new().fallback(rewrite_v2).with_state(router);
        let rewritten_root = serve(&mut tasks, rewrite).await;
        Self {
            site,
            facade_root,
            rewritten_root,
            key,
            llm,
            metasearch,
            cancel,
            tasks,
            _dir: dir,
        }
    }

    /// Stop the worker and the listeners.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        for t in self.tasks.drain(..) {
            t.abort();
            let _ = tokio::time::timeout(Duration::from_secs(10), t).await;
        }
    }
}

impl Drop for SdkRig {
    fn drop(&mut self) {
        self.cancel.cancel();
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Serve `app` on a random loopback port; returns `http://127.0.0.1:PORT`.
async fn serve(tasks: &mut Vec<tokio::task::JoinHandle<()>>, app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tasks.push(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));
    format!("http://{addr}")
}
