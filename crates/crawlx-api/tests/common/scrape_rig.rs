#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A scrape rig for the compat facade tests: the API router and a REAL worker lease loop
//! over one `MemoryStore` and one artifact store, a fixture HTTP site reached through the host
//! name `site.example.test` (an injected resolver maps it to 127.0.0.1; admission denies literal
//! loopback), an optional `MockLlm` on both sides and an optional scripted `PageRenderer` (or
//! real Chromium when `CRAWLX_CHROMIUM_PATH` is set). Optional deployment proxy tiers use
//! loopback upstreams and the same guarded worker egress path.
//!
//! Include it next to `mod common;` with `#[path = "common/scrape_rig.rs"] mod scrape_rig;`.

use crate::common::Env;
use async_trait::async_trait;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::{ApiConfig, AppState, Repos, Scope, Settings};
use crawlx_core::counters::PlaneCounters;
use crawlx_core::repo::{CrawlRun, CrawlSession, RunRepo};
use crawlx_core::{AuthorizationRecordId, Clock, CrawlRunId, SessionId, StoreError, SystemClock, TenantId};
use crawlx_fetch::{ProxyRoutes, StaticResolver};
use crawlx_model::llm::LlmExtractor;
use crawlx_storage::{DeliveryBuffer, MemoryArtifactStore, MemoryStore};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::scrape::PageRenderer;
use crawlx_worker::{
    AuthorizationSource, EgressConfig, StaticAuthorizationSource, Stores, WorkerConfig, WorkerError,
};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The host name every fixture URL uses.
pub const HOST: &str = "site.example.test";

/// What the rig runs besides the fixture site.
#[derive(Default)]
pub struct RigConfig {
    /// Document LLM for the worker AND the API pre-flight.
    pub llm: Option<Arc<dyn LlmExtractor>>,
    /// Scripted renderer replacing the browser for runs that need one.
    pub renderer: Option<Arc<dyn PageRenderer>>,
    /// Launch the real Chromium named by `CRAWLX_CHROMIUM_PATH` (the rig is skipped by
    /// [`Rig::start_chromium`] when it is not set).
    pub chromium: Option<std::path::PathBuf>,
    /// API settings.
    pub settings: Option<Settings>,
    /// Extra routes merged into the fixture site (they bring their own hit counters).
    pub site_routes: Option<Router>,
    /// Facade settings of the API (`compat.robotsAuthorization`, ...).
    pub compat: crawlx_api::CompatConfig,
    /// Start the worker this long after the API (a run created meanwhile waits in the queue).
    pub worker_start_delay: Option<Duration>,
    /// Additional HTTP hosts authorized only at this fixture site's port; DNS stays unchanged.
    /// Empty by default so unrelated origins remain outside the worker's fixture record.
    pub additional_authorization_hosts: Vec<String>,
    /// Deployment-owned upstreams; their ports are added to the fixture egress allowlist.
    pub proxy_routes: ProxyRoutes,
}

/// The fixture site: pages, a mutable version, and per-path request counts.
pub struct Site {
    pub port: u16,
    /// Requests served by path (query ignored).
    pub hits: Arc<Mutex<BTreeMap<String, usize>>>,
    /// Request headers of the newest request per path (lower-case names).
    pub headers: Arc<Mutex<BTreeMap<String, BTreeMap<String, String>>>>,
    /// Number shown by `/versioned`.
    pub version: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    /// Requests served for `path`.
    pub fn hits(&self, path: &str) -> usize {
        self.hits.lock().get(path).copied().unwrap_or(0)
    }

    /// Change the number `/versioned` shows.
    pub fn set_version(&self, n: usize) {
        self.version.store(n, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct SiteState {
    hits: Arc<Mutex<BTreeMap<String, usize>>>,
    headers: Arc<Mutex<BTreeMap<String, BTreeMap<String, String>>>>,
    version: Arc<AtomicUsize>,
}

fn html(body: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body.to_owned(),
    )
        .into_response()
}

async fn record(State(s): State<SiteState>, uri: Uri, headers: HeaderMap) {
    *s.hits.lock().entry(uri.path().to_owned()).or_insert(0) += 1;
    let map = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    s.headers.lock().insert(uri.path().to_owned(), map);
}

/// A PDF with one Helvetica text page per entry of `pages` (a real xref table).
pub fn pdf(pages: &[&str]) -> Vec<u8> {
    let n = pages.len();
    let mut objects: Vec<Vec<u8>> = vec![b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()];
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 4 + 2 * i)).collect();
    objects.push(format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).into_bytes());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());
    for (i, text) in pages.iter().enumerate() {
        let contents = 5 + 2 * i;
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {contents} 0 R /Resources << /Font << /F1 3 0 R >> >> >>"
            )
            .into_bytes(),
        );
        let stream = format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET");
        objects.push(format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len()).into_bytes());
    }
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// Start the fixture site on 127.0.0.1 (random port).
pub async fn start_site() -> Site {
    start_site_with(None).await
}

/// [`start_site`] with `extra` routes merged into the fixture router.
pub async fn start_site_with(extra: Option<Router>) -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let state = SiteState {
        hits: Arc::default(),
        headers: Arc::default(),
        version: Arc::new(AtomicUsize::new(1)),
    };
    let app = Router::new()
        .route(
            "/",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                html(
                    r#"<!doctype html><html lang="en"><head><title>Fixture Home</title>
<meta name="description" content="The fixture home page">
<meta name="keywords" content="alpha, beta">
<meta property="og:title" content="OG Home">
<meta property="og:image" content="/og.png">
<link rel="icon" href="/favicon.ico"></head><body>
<nav><a href="/nav-only">Nav</a></nav>
<main><h1>Fixture Home</h1><p>Welcome to the fixture site. The answer is forty-two.</p>
<a href="/a">Page A</a> <a href="/b" data-kind="primary">Page B</a> <a href="https://other.example/out" data-kind="external">Out</a>
<img src="/logo.png" alt="logo"><img src="data:image/png;base64,AAAA" alt="inline"></main>
<footer>Footer text</footer></body></html>"#,
                )
            }),
        )
        .route(
            "/a",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                html(r#"<html><head><title>Page A</title></head><body><main><h1>Page A</h1><p>Text of A.</p><a href="/">Home</a></main></body></html>"#)
            }),
        )
        .route(
            "/b",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                html(r#"<html><head><title>Page B</title></head><body><main><h1>Page B</h1><p>Text of B.</p></main></body></html>"#)
            }),
        )
        .route(
            "/c",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                html(r#"<html><head><title>Page C</title></head><body><main><h1>Page C</h1><p>Text of C.</p></main></body></html>"#)
            }),
        )
        .route(
            "/versioned",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                let n = s.version.load(Ordering::SeqCst);
                record(s, u, h).await;
                html(&format!(
                    r#"<html><head><title>Versioned</title></head><body><main><h1>Pricing</h1><p>Price version {n}</p></main></body></html>"#
                ))
            }),
        )
        .route(
            "/echo-headers",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u.clone(), h.clone()).await;
                let rows: String = h
                    .iter()
                    .map(|(k, v)| format!("<li>{}: {}</li>", k, v.to_str().unwrap_or("")))
                    .collect();
                html(&format!(
                    "<html><head><title>Echo</title></head><body><main><h1>Echo</h1><ul>{rows}</ul></main></body></html>"
                ))
            }),
        )
        .route(
            "/slow",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
                html("<html><body>late</body></html>")
            }),
        )
        .route(
            "/status/{code}",
            get(
                |s: State<SiteState>,
                 u: Uri,
                 h: HeaderMap,
                 axum::extract::Path(code): axum::extract::Path<u16>| async move {
                    record(s, u, h).await;
                    (
                        StatusCode::from_u16(code).unwrap(),
                        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        format!("<html><head><title>Status {code}</title></head><body><main><h1>Status {code}</h1></main></body></html>"),
                    )
                },
            ),
        )
        .route("/redirect", get(|| async { Redirect::temporary("/a") }))
        .route(
            "/robots.txt",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                "User-agent: *\nDisallow: /private/\n"
            }),
        )
        .route(
            "/private/x",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                html("<html><body><main>secret</main></body></html>")
            }),
        )
        .route(
            "/interactive",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                html(
                    r##"<!doctype html><html><head><title>Interactive</title></head><body><main>
<h1>Interactive</h1><p id="out">idle</p><div id="log"></div>
<button id="go" onclick="document.getElementById('out').textContent='clicked'">Go</button>
<input id="q" type="text" aria-label="Query">
<button id="danger" onclick="fetch('/delete',{method:'POST'})">Delete account</button>
<script>
var q=document.getElementById('q');
q.addEventListener('input',function(){document.getElementById('log').textContent='typed:'+q.value;});
q.addEventListener('keydown',function(e){if(e.key==='Enter'){document.getElementById('out').textContent='entered';}});
</script></main></body></html>"##,
                )
            }),
        )
        .route(
            "/delete",
            axum::routing::post(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                "deleted"
            }),
        )
        .route(
            "/docs/a",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                html(r#"<html><head><title>Docs A</title></head><body><main><h1>Docs A</h1>
<a href="/docs/b">B</a> <a href="/other/c">C elsewhere</a> <a href="/">Home</a></main></body></html>"#)
            }),
        )
        .route(
            "/doc.pdf",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                (
                    [(header::CONTENT_TYPE, "application/pdf")],
                    pdf(&["Alpha page one", "Beta page two", "Gamma page three"]),
                )
            }),
        )
        .route(
            "/binary",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                ([(header::CONTENT_TYPE, "application/octet-stream")], vec![0u8, 1, 2, 3])
            }),
        )
        .route(
            "/raw.txt",
            get(|s: State<SiteState>, u: Uri, h: HeaderMap| async move {
                record(s, u, h).await;
                ([(header::CONTENT_TYPE, "text/plain")], "plain text body")
            }),
        )
        .with_state(state.clone());
    let app = match extra {
        Some(routes) => app.merge(routes),
        None => app,
    };
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        port: addr.port(),
        hits: state.hits,
        headers: state.headers,
        version: state.version,
        task,
    }
}

/// Worker-only authorization source for owned loopback fixtures, plus live API records.
struct FixtureAuthorizations {
    fixtures: StaticAuthorizationSource,
    api: Arc<crawlx_api::MemoryApiStore>,
    tenants: Mutex<BTreeMap<AuthorizationRecordId, TenantId>>,
    installed: Mutex<BTreeSet<CrawlRunId>>,
    additional_origins: Vec<String>,
}

#[async_trait]
impl AuthorizationSource for FixtureAuthorizations {
    async fn fetch(
        &self,
        id: AuthorizationRecordId,
    ) -> Result<Option<crawlx_policy::AuthorizationRecord>, WorkerError> {
        if let Some(record) = self.fixtures.fetch(id).await? {
            return Ok(Some(record));
        }
        let tenant = self.tenants.lock().get(&id).copied();
        match tenant {
            Some(tenant) => Ok(crawlx_api::ApiStore::authorization_get(self.api.as_ref(), tenant, id).await?),
            None => Ok(None),
        }
    }
}

/// Worker view of API-admitted fixture runs. Records cover the owned fixture origin and
/// configured proxy listeners; only their actual resolver destinations (loopback) are authorized.
struct PrivateNetworks(Arc<MemoryStore>, Arc<FixtureAuthorizations>);

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
        let id = match run.config.safety.authorization_record_ref {
            Some(id) => {
                self.1.tenants.lock().insert(id, run.tenant);
                id
            }
            None => {
                let id = AuthorizationRecordId(run.id.0);
                let mut installed = self.1.installed.lock();
                if installed.insert(run.id) {
                    let now = SystemClock.now();
                    let origin = run.config.seed_url.origin().ascii_serialization();
                    let mut origins = vec![origin.as_str()];
                    origins.extend(self.1.additional_origins.iter().map(String::as_str));
                    origins.sort_unstable();
                    origins.dedup();
                    let mut record = crawlx_policy::testkit::sample_record(run.tenant, now, &origins);
                    record.id = id;
                    record.verified_at = Some(now);
                    record.profile_cap = run.config.safety.profile;
                    record.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
                    self.1.fixtures.insert(record);
                }
                id
            }
        };
        run.config.safety.authorization_record_ref = Some(id);
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

/// The API, a worker and a fixture site, wired to each other.
pub struct Rig {
    pub env: Env,
    pub site: Site,
    pub cancel: CancellationToken,
    worker: Option<tokio::task::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Rig {
    /// Start everything with `cfg`.
    pub async fn start(mut cfg: RigConfig) -> Self {
        let site = start_site_with(cfg.site_routes.take()).await;
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
            compat: cfg.compat,
            ..ApiConfig::default()
        };
        let mut builder = AppState::builder(
            repos,
            crawlx_api::admission_policy(&config, clock.clone()),
            config,
        )
        .settings(cfg.settings.unwrap_or_default())
        .clock(clock)
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

        let dir = tempfile::tempdir().unwrap();
        let resolver = StaticResolver::new().with(HOST, ["127.0.0.1".parse().unwrap()]);
        let mut extra_ports = vec![site.port];
        extra_ports.extend(
            [&cfg.proxy_routes.basic, &cfg.proxy_routes.enhanced]
                .into_iter()
                .flatten()
                .filter_map(url::Url::port_or_known_default),
        );
        let mut wcfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(resolver)),
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                extra_ports,
                proxy_routes: cfg.proxy_routes,
                ..EgressConfig::default()
            },
            idle_exit_after: None,
            llm: cfg.llm.clone(),
            renderer: cfg.renderer.clone(),
            ..WorkerConfig::default()
        };
        if let Some(exe) = &cfg.chromium {
            wcfg.launch.executable = exe.clone();
            wcfg.launch.allow_unpinned = true;
            wcfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |u| u == "root");
        }
        let mut stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
        stores.artifacts = artifacts.clone();
        let authorizations = Arc::new(FixtureAuthorizations {
            fixtures: StaticAuthorizationSource::default(),
            api: Arc::clone(&api),
            tenants: Mutex::new(BTreeMap::new()),
            installed: Mutex::new(BTreeSet::new()),
            additional_origins: cfg
                .additional_authorization_hosts
                .iter()
                .map(|host| format!("http://{host}:{}", site.port))
                // Upstream hosts pass the same record-scope check as the target. Authorize
                // only the configured listener origins, without credentials or broad prefixes.
                .chain(
                    [
                        &wcfg.egress.proxy_routes.basic,
                        &wcfg.egress.proxy_routes.enhanced,
                    ]
                    .into_iter()
                    .flatten()
                    .map(|url| url.origin().ascii_serialization()),
                )
                .collect(),
        });
        stores.runs = Arc::new(PrivateNetworks(store.clone(), Arc::clone(&authorizations)));
        stores = stores.with_authorization_source(authorizations);
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let delay = cfg.worker_start_delay;
        let worker = tokio::spawn(async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
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
            site,
            cancel,
            worker: Some(worker),
            _dir: dir,
        }
    }

    /// Start with the Chromium of `CRAWLX_CHROMIUM_PATH`, or `None` (the test skips).
    pub async fn start_chromium(mut cfg: RigConfig) -> Option<Self> {
        let exe = std::env::var_os("CRAWLX_CHROMIUM_PATH").map(std::path::PathBuf::from)?;
        cfg.chromium = Some(exe);
        Some(Self::start(cfg).await)
    }

    /// `http://site.example.test:PORT` + `path`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{HOST}:{}{path}", self.site.port)
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
    }
}

#[cfg(test)]
mod authorization_regression {
    use super::*;

    #[tokio::test]
    async fn worker_fixture_reads_share_a_verified_tenant_and_origin_bound_record() {
        let env = crate::common::env();
        let source = Arc::new(FixtureAuthorizations {
            fixtures: StaticAuthorizationSource::default(),
            api: Arc::clone(&env.api),
            tenants: Mutex::new(BTreeMap::new()),
            installed: Mutex::new(BTreeSet::new()),
            additional_origins: Vec::new(),
        });
        let view = PrivateNetworks(Arc::clone(&env.store), Arc::clone(&source));
        let crawl = crawlx_core::CreateCrawl::new(format!("http://{HOST}:8123/article").parse().unwrap());
        let run = crawlx_storage::testkit::crawl_run(env.tenant, crawl);
        RunRepo::create(env.store.as_ref(), &run, None).await.unwrap();
        let first = view.get(run.id).await.unwrap();
        let second = view.get(run.id).await.unwrap();
        let id = first.config.safety.authorization_record_ref.unwrap();
        assert_eq!(second.config.safety.authorization_record_ref, Some(id));
        let record = source.fetch(id).await.unwrap().unwrap();
        assert_eq!(record.tenant, env.tenant);
        assert!(record.verified_at.is_some());
        assert_eq!(record.origins, vec![format!("http://{HOST}:8123")]);
        assert_eq!(record.authorized_networks.len(), 1);
        assert_eq!(record.authorized_networks[0].to_string(), "127.0.0.0/8");
        let guard = crawlx_worker::AuthorizationGuard::admit(
            run.id,
            None,
            Some(id),
            source,
            Arc::new(SystemClock),
            env.store.clone(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        guard.check_tenant(env.tenant).unwrap();
        assert!(guard.check_tenant(TenantId::new()).is_err());
    }
}
