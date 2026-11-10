//! Deployment proxy tiers through real loopback upstreams and persisted scrape documents.
//! Crawl jobs enforce robots before either proxy tier; scrape jobs retain the compatibility API's explicit-URL behavior.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::scrape::{
    FormatSpec, JobKind, ProxyMode, ScrapeAction, ScrapeDocument, ScrapeJob, ScrapeOptions,
};
use crawlx_core::{CreateCrawl, SafetyProfile};
use crawlx_fetch::{ProxyRoutes, StaticResolver};
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};
use url::Url;

#[derive(Clone, Debug)]
struct Hit {
    path: String,
    origin_auth: Option<String>,
    proxy_auth: Option<String>,
}

struct Provider {
    url: Url,
    hits: Arc<Mutex<Vec<Hit>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Provider {
    fn count(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.path == path)
            .count()
    }
    fn authenticated_url(&self) -> Url {
        let mut url = self.url.clone();
        url.set_username("proxy-user").unwrap();
        url.set_password(Some("proxy-secret")).unwrap();
        url
    }
}

#[derive(Clone)]
struct ResponseState {
    name: &'static str,
    status: u16,
    hits: Arc<Mutex<Vec<Hit>>>,
}

async fn answer(State(state): State<ResponseState>, req: Request) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    state.hits.lock().unwrap().push(Hit {
        path: path.clone(),
        origin_auth: req
            .headers()
            .get(header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap().to_owned()),
        proxy_auth: req
            .headers()
            .get(header::PROXY_AUTHORIZATION)
            .map(|v| v.to_str().unwrap().to_owned()),
    });
    if path == "/robots.txt" {
        return (StatusCode::OK, "User-agent: *\nDisallow: /forbidden\n").into_response();
    }
    let body = format!(
        "<!doctype html><html><head><title>{}</title></head><body><main><h1>{}</h1><p>route {} at {path}</p><a href='/child'>child</a><input id='field'></main></body></html>",
        state.name, state.name, state.name,
    );
    (
        StatusCode::from_u16(state.status).unwrap(),
        [(header::CONTENT_TYPE, "text/html")],
        body,
    )
        .into_response()
}

async fn provider(name: &'static str, status: u16) -> Provider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = ResponseState {
        name,
        status,
        hits: Arc::clone(&hits),
    };
    let app = Router::new().fallback(answer).with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Provider { url, hits, task }
}

struct Rig {
    origin: Provider,
    basic: Provider,
    enhanced: Provider,
    stores: Stores,
    dir: tempfile::TempDir,
}

impl Rig {
    async fn new(basic_status: u16, enhanced_status: u16) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        Self {
            origin: provider("direct-must-not-be-used", 200).await,
            basic: provider("basic-route", basic_status).await,
            enhanced: provider("enhanced-route", enhanced_status).await,
            stores,
            dir,
        }
    }

    fn crawl(&self, mode: ProxyMode, kind: JobKind, browser: bool) -> CreateCrawl {
        let mut options = ScrapeOptions {
            proxy: mode,
            formats: vec![FormatSpec::Markdown, FormatSpec::Links],
            max_age_ms: 0,
            wait_for_ms: u32::from(browser),
            ..ScrapeOptions::default()
        };
        // Static pages do not need Chromium; browser pages must exercise the real renderer.
        options.block_ads = false;
        let mut job = ScrapeJob::new(kind, options);
        if kind == JobKind::Batch {
            job.urls = vec![self.origin.url.join("/second").unwrap()];
        }
        let mut crawl = CreateCrawl::new(self.origin.url.join("/page").unwrap());
        crawl.seed = Some(20_261_104);
        crawl.mode = CrawlMode::Static;
        crawl.safety.profile = SafetyProfile::TestEnvironment;
        crawl.safety.allow_private_networks = true;
        crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        crawl.scope.host_scope = HostScope::None;
        // The fixture's /child link is a sibling of the /page seed, not its descendant.
        crawl.scope.crawl_entire_domain = true;
        crawl.scope.sitemap = SitemapMode::Skip;
        crawl.scope.known_files.clear();
        crawl.scope.max_discovery_depth = u16::from(kind == JobKind::Crawl);
        crawl.politeness.delay_ms = 0;
        crawl.fetch.retries = 0;
        crawl
            .fetch
            .set_header("Authorization", "Bearer origin-secret")
            .unwrap();
        crawl.scrape = Some(job);
        crawl
    }

    fn config(&self, browser: bool) -> WorkerConfig {
        let mut routes = ProxyRoutes::default();
        routes.basic = Some(self.basic.authenticated_url());
        routes.enhanced = Some(self.enhanced.authenticated_url());
        let mut cfg = WorkerConfig {
            artifacts_dir: self.dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(StaticResolver::new())),
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                extra_ports: vec![self.basic.url.port().unwrap(), self.enhanced.url.port().unwrap()],
                proxy_routes: routes,
                ..EgressConfig::default()
            },
            ..WorkerConfig::default()
        };
        if browser {
            cfg.launch.executable = crawlx_browser::launch::find_executable().unwrap();
            cfg.launch.allow_unpinned = true;
            if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_err() && std::env::var_os("CI").is_none() {
                cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |u| u == "root");
            }
        }
        cfg
    }

    async fn run(&self, crawl: CreateCrawl, cfg: WorkerConfig) -> RunReport {
        run_local_with(LocalRun::new(crawl, cfg).with_stores(self.stores.clone()))
            .await
            .unwrap()
    }

    async fn assert_document(&self, report: &RunReport, path: &str, status: u16, marker: &str) {
        let page = report
            .pages
            .iter()
            .find(|p| p.url.url.path() == path)
            .expect("stored page");
        let document = ScrapeDocument::from_page_metadata(&page.metadata).unwrap();
        assert_eq!(document.status_code, status);
        assert_eq!(
            document.proxy_used,
            if marker == "enhanced-route" {
                ProxyMode::Enhanced
            } else {
                ProxyMode::Basic
            },
        );
        let markdown = self
            .stores
            .artifacts
            .get(page.markdown.as_ref().unwrap())
            .await
            .unwrap();
        assert!(String::from_utf8(markdown).unwrap().contains(marker));
        let events = self
            .stores
            .events
            .list_after(report.run_id, 0, 10_000)
            .await
            .unwrap();
        let output = format!("{report:?}{events:?}{:?}", page.metadata);
        for secret in ["proxy-secret", "proxy-user", "Bearer origin-secret"] {
            assert!(!output.contains(secret), "stored output leaked credentials");
        }
    }
}

#[tokio::test]
async fn enhanced_selects_configured_provider_and_auto_escalates_exact_block_statuses() {
    for status in [401, 403, 429] {
        let rig = Rig::new(status, 200).await;
        let report = rig
            .run(
                rig.crawl(ProxyMode::Auto, JobKind::Scrape, false),
                rig.config(false),
            )
            .await;
        rig.assert_document(&report, "/page", 200, "enhanced-route").await;
        assert_eq!(rig.basic.count("/page"), 1);
        assert_eq!(rig.enhanced.count("/page"), 1);
        assert_eq!(rig.origin.count("/page"), 0);
        for upstream in [&rig.basic, &rig.enhanced] {
            let hits = upstream.hits.lock().unwrap();
            let page = hits.iter().find(|hit| hit.path == "/page").unwrap();
            assert_eq!(page.origin_auth.as_deref(), Some("Bearer origin-secret"));
            assert!(page.proxy_auth.as_deref().unwrap().starts_with("Basic "));
        }
    }
    let rig = Rig::new(403, 200).await;
    let report = rig
        .run(
            rig.crawl(ProxyMode::Enhanced, JobKind::Scrape, false),
            rig.config(false),
        )
        .await;
    rig.assert_document(&report, "/page", 200, "enhanced-route").await;
    assert_eq!(rig.basic.count("/page"), 0);
    assert_eq!(rig.enhanced.count("/page"), 1);
}

#[tokio::test]
async fn auto_does_not_escalate_other_statuses_or_retry_enhanced_again() {
    for status in [200, 400, 404, 408, 500, 503] {
        let rig = Rig::new(status, 200).await;
        let report = rig
            .run(
                rig.crawl(ProxyMode::Auto, JobKind::Scrape, false),
                rig.config(false),
            )
            .await;
        rig.assert_document(&report, "/page", status, "basic-route").await;
        assert_eq!(rig.basic.count("/page"), 1);
        assert_eq!(rig.enhanced.count("/page"), 0);
    }
    let rig = Rig::new(429, 429).await;
    let mut crawl = rig.crawl(ProxyMode::Auto, JobKind::Scrape, false);
    crawl.fetch.retries = 3;
    let report = rig.run(crawl, rig.config(false)).await;
    rig.assert_document(&report, "/page", 429, "enhanced-route").await;
    assert_eq!(rig.basic.count("/page"), 1);
    assert_eq!(rig.enhanced.count("/page"), 1);
}

#[tokio::test]
async fn batch_and_crawl_keep_proxy_mode_for_every_page() {
    for kind in [JobKind::Batch, JobKind::Crawl] {
        let rig = Rig::new(403, 200).await;
        let report = rig
            .run(rig.crawl(ProxyMode::Auto, kind, false), rig.config(false))
            .await;
        let second = if kind == JobKind::Batch {
            "/second"
        } else {
            "/child"
        };
        rig.assert_document(&report, "/page", 200, "enhanced-route").await;
        rig.assert_document(&report, second, 200, "enhanced-route").await;
        for path in ["/page", second] {
            assert_eq!(rig.basic.count(path), 1);
            assert_eq!(rig.enhanced.count(path), 1);
        }
    }
}

#[tokio::test]
async fn missing_enhanced_fails_without_sending_page_and_private_policy_stays_enforced() {
    for mode in [ProxyMode::Enhanced, ProxyMode::Auto] {
        let rig = Rig::new(200, 200).await;
        let mut cfg = rig.config(false);
        cfg.egress.proxy_routes.enhanced = None;
        let result = run_local_with(
            LocalRun::new(rig.crawl(mode, JobKind::Scrape, false), cfg).with_stores(rig.stores.clone()),
        )
        .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("enhanced proxy requested"));
        assert_eq!(rig.basic.count("/page"), 0);
        assert_eq!(rig.origin.count("/page"), 0);
    }
    let rig = Rig::new(403, 200).await;
    let mut crawl = rig.crawl(ProxyMode::Auto, JobKind::Scrape, false);
    crawl.safety.allow_private_networks = false;
    let report = rig.run(crawl, rig.config(false)).await;
    assert!(report.pages.is_empty());
    assert_eq!(rig.basic.count("/page"), 0);
    assert_eq!(rig.enhanced.count("/page"), 0);
}

fn chromium_available() -> bool {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        eprintln!("skipped: CRAWLX_CHROMIUM_PATH is not set");
        false
    } else {
        true
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_proxy_tiers_switch_real_provider_and_never_replay_actions() {
    if !chromium_available() {
        return;
    }
    for (mode, basic_status, expected, basic_hits, enhanced_hits) in [
        (ProxyMode::Enhanced, 200, "enhanced-route", 0, 1),
        (ProxyMode::Auto, 401, "enhanced-route", 1, 1),
        (ProxyMode::Auto, 403, "enhanced-route", 1, 1),
        (ProxyMode::Auto, 429, "enhanced-route", 1, 1),
        (ProxyMode::Auto, 404, "basic-route", 1, 0),
        (ProxyMode::Auto, 500, "basic-route", 1, 0),
    ] {
        let rig = Rig::new(basic_status, 200).await;
        let report = rig
            .run(rig.crawl(mode, JobKind::Scrape, true), rig.config(true))
            .await;
        let status = if enhanced_hits == 1 { 200 } else { basic_status };
        rig.assert_document(&report, "/page", status, expected).await;
        assert_eq!(rig.basic.count("/page"), basic_hits);
        assert_eq!(rig.enhanced.count("/page"), enhanced_hits);
        assert_eq!(rig.origin.count("/page"), 0);
    }
    let rig = Rig::new(403, 200).await;
    let mut crawl = rig.crawl(ProxyMode::Auto, JobKind::Scrape, true);
    crawl.scrape.as_mut().unwrap().options.actions = vec![ScrapeAction::ExecuteJavascript {
        script: "fetch('/effect', {method: 'POST'}).then(() => true)".to_owned(),
    }];
    let report = rig.run(crawl, rig.config(true)).await;
    rig.assert_document(&report, "/page", 403, "basic-route").await;
    assert_eq!(rig.basic.count("/page"), 1);
    assert_eq!(rig.basic.count("/effect"), 1);
    assert_eq!(rig.enhanced.count("/page"), 0);
    assert_eq!(rig.enhanced.count("/effect"), 0);
}

#[tokio::test]
async fn basic_retains_request_proxy_fallback_and_robots_block_both_tiers() {
    let rig = Rig::new(200, 200).await;
    let mut crawl = rig.crawl(ProxyMode::Basic, JobKind::Scrape, false);
    crawl.fetch.proxy = Some(rig.basic.authenticated_url());
    let mut cfg = rig.config(false);
    cfg.egress.proxy_routes.basic = None;
    let report = rig.run(crawl, cfg).await;
    rig.assert_document(&report, "/page", 200, "basic-route").await;
    assert_eq!(rig.basic.count("/page"), 1);
    assert_eq!(rig.enhanced.count("/page"), 0);
    let rig = Rig::new(403, 200).await;
    // Only crawl jobs obey robots; scrape and batch jobs fetch their explicitly requested URLs.
    let mut crawl = rig.crawl(ProxyMode::Auto, JobKind::Crawl, false);
    crawl.seed_url = rig.origin.url.join("/forbidden").unwrap();
    let report = rig.run(crawl, rig.config(false)).await;
    assert!(report.pages.is_empty());
    assert_eq!(report.counters.urls.robots_blocked, 1);
    assert_eq!(rig.basic.count("/robots.txt"), 1);
    assert_eq!(rig.basic.count("/forbidden"), 0);
    assert_eq!(rig.enhanced.count("/forbidden"), 0);
    assert_eq!(rig.origin.count("/forbidden"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_batch_and_crawl_escalate_each_page_independently() {
    if !chromium_available() {
        return;
    }
    for kind in [JobKind::Batch, JobKind::Crawl] {
        let rig = Rig::new(403, 200).await;
        let report = rig
            .run(rig.crawl(ProxyMode::Auto, kind, true), rig.config(true))
            .await;
        let second = if kind == JobKind::Batch {
            "/second"
        } else {
            "/child"
        };
        for path in ["/page", second] {
            rig.assert_document(&report, path, 200, "enhanced-route").await;
            assert_eq!(rig.basic.count(path), 1);
            assert_eq!(rig.enhanced.count(path), 1);
        }
    }
}
