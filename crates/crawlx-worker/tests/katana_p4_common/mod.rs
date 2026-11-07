//! Shared rig of the katana P4 worker tests: an in-process site that records every request,
//! and the worker and crawl configuration the tests start from.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/authorization.rs"]
mod authorization_fixture;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Router;
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_worker::{EgressConfig, RunReport, WorkerConfig};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Every request the site served, in order: `(method, path and query)`.
type Ledger = Arc<Mutex<Vec<(String, String)>>>;

/// A site on `127.0.0.1:<ephemeral>` that records what it is asked for.
pub struct Site {
    pub base: String,
    pub addr: SocketAddr,
    ledger: Ledger,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn record(
    State(ledger): State<Ledger>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let target = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path().to_owned(), ToString::to_string);
    ledger.lock().unwrap().push((req.method().to_string(), target));
    next.run(req).await
}

impl Site {
    /// Serve the routes `build` returns; it receives the site's own address.
    pub async fn start(build: impl FnOnce(SocketAddr) -> Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ledger: Ledger = Arc::new(Mutex::new(Vec::new()));
        let app = build(addr).layer(axum::middleware::from_fn_with_state(Arc::clone(&ledger), record));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base: format!("http://{addr}"),
            addr,
            ledger,
            task,
        }
    }

    /// `(method, path and query)` of every request, in arrival order.
    pub fn requests(&self) -> Vec<(String, String)> {
        self.ledger.lock().unwrap().clone()
    }

    /// Path and query of every `GET`, in arrival order, without `robots.txt`.
    pub fn gets(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|(m, p)| m == "GET" && p != "/robots.txt")
            .map(|(_, p)| p)
            .collect()
    }

    /// Number of requests whose path and query start with `prefix`.
    pub fn count(&self, prefix: &str) -> usize {
        self.requests()
            .iter()
            .filter(|(_, p)| p.starts_with(prefix))
            .count()
    }
}

/// An HTML response.
pub fn html(body: impl Into<String>) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body.into()).into_response()
}

/// A page with `body` inside `<main>`.
pub fn page(title: &str, body: &str) -> Response {
    html(format!(
        "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>Text of {title}.</p>{body}</main></body></html>"
    ))
}

/// Worker configuration with a static resolver and the test's artifact directory.
pub fn config(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

/// A static crawl of `base` on the loopback interface, no politeness delay, no sitemap.
pub fn static_crawl(base: &str) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_027);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c.scope.sitemap = SitemapMode::Skip;
    c
}

/// Paths (without query) of the report's pages, sorted.
pub fn page_paths(report: &RunReport) -> Vec<String> {
    let mut v: Vec<String> = report.pages.iter().map(|p| p.url.url.path().to_owned()).collect();
    v.sort();
    v
}

/// The page of `report` whose URL path is `path`.
pub fn page_at<'a>(report: &'a RunReport, path: &str) -> &'a crawlx_core::repo::PageRecord {
    report
        .pages
        .iter()
        .find(|p| p.url.url.path() == path)
        .unwrap_or_else(|| panic!("no page at {path}: {:?}", page_paths(report)))
}

/// A finished run with the stores it ran against (frontier rows survive the run).
pub struct Crawled {
    pub report: RunReport,
    pub stores: crawlx_worker::Stores,
    pub dir: tempfile::TempDir,
}

impl Crawled {
    /// Every frontier row of the run.
    pub async fn frontier(&self) -> Vec<crawlx_core::repo::FrontierEntry> {
        self.stores.frontier.list(self.report.run_id).await.unwrap()
    }
}

/// Crawl `base` with the default worker configuration after `tweak`.
pub async fn crawl(base: &str, tweak: impl FnOnce(&mut CreateCrawl)) -> Crawled {
    crawl_with(base, tweak, |_| {}, |run| run).await
}

/// Crawl `base`, with `tweak` applied to the request, `worker` to the worker configuration
/// and `local` to the run description.
pub async fn crawl_with(
    base: &str,
    tweak: impl FnOnce(&mut CreateCrawl),
    worker: impl FnOnce(&mut WorkerConfig),
    local: impl FnOnce(crawlx_worker::LocalRun) -> crawlx_worker::LocalRun,
) -> Crawled {
    let dir = tempfile::tempdir().unwrap();
    let mut c = static_crawl(base);
    tweak(&mut c);
    let mut cfg = config(dir.path());
    worker(&mut cfg);
    let stores = crawlx_worker::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let run = local(crawlx_worker::LocalRun::new(c, cfg).with_stores(stores.clone()));
    let report = authorization_fixture::run_authorized_local_with(run)
        .await
        .unwrap();
    Crawled { report, stores, dir }
}

/// A traffic collector: accepts the exporter's batched `POST`s and keeps the events.
pub struct Collector {
    pub url: url::Url,
    batches: Arc<Mutex<Vec<serde_json::Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Collector {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let batches: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&batches);
        let app = Router::new().route(
            "/ingest",
            axum::routing::post(move |body: String| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().unwrap().push(serde_json::from_str(&body).unwrap());
                    axum::http::StatusCode::NO_CONTENT
                }
            }),
        );
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: url::Url::parse(&format!("http://{addr}/ingest")).unwrap(),
            batches,
            task,
        }
    }

    /// Every event received so far, in arrival order.
    pub fn events(&self) -> Vec<serde_json::Value> {
        self.batches
            .lock()
            .unwrap()
            .iter()
            .flat_map(|b| b["events"].as_array().cloned().unwrap_or_default())
            .collect()
    }

    /// `(status, path and query of the request URL)` of every event, in arrival order.
    pub fn exchanges(&self) -> Vec<(u64, String)> {
        self.events()
            .iter()
            .map(|e| {
                let url = url::Url::parse(e["request"]["full_url"].as_str().unwrap()).unwrap();
                let target = match url.query() {
                    Some(q) => format!("{}?{q}", url.path()),
                    None => url.path().to_owned(),
                };
                (e["response"]["status"].as_u64().unwrap(), target)
            })
            .collect()
    }
}
