//! The `basic` and `enhanced` proxy tiers backed by a ProxyX pool gateway, through a fake gateway
//! (`CONNECT` with Basic auth, `X-ProxyX-Pool-Session` and `X-ProxyX-Exit-IP` on the `200`, or
//! `HTTP/1.1 <status> <cause_code>`) and persisted scrape documents. In the style of
//! `scrape_proxy.rs`: real loopback upstreams, no mocks of crawlx itself.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::scrape::{FormatSpec, JobKind, ProxyMode, ScrapeDocument, ScrapeJob, ScrapeOptions};
use crawlx_core::secret::SecretOr;
use crawlx_core::{CreateCrawl, SafetyProfile};
use crawlx_fetch::proxyx::{PoolSelector, ProxyxRoute};
use crawlx_fetch::{ProxyRoutes, StaticResolver};
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

const KEY: &str = "ak_worker-fixture-key_0123456789abcdefghijklmnopqrstu";

/// What the origin saw.
#[derive(Clone, Debug)]
struct Hit {
    path: String,
    proxy_auth: Option<String>,
    host: Option<String>,
}

/// The origin: answers `status_of(path, nth request of that path)`.
struct Origin {
    url: Url,
    hits: Arc<Mutex<Vec<Hit>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Origin {
    fn count(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.path == path)
            .count()
    }
}

/// `status(path, nth request of that path)`.
type StatusFn = Arc<dyn Fn(&str, usize) -> u16 + Send + Sync>;

#[derive(Clone)]
struct OriginState {
    hits: Arc<Mutex<Vec<Hit>>>,
    status_of: StatusFn,
}

async fn answer(State(state): State<OriginState>, req: Request) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    let nth = {
        let mut hits = state.hits.lock().unwrap();
        let nth = hits.iter().filter(|h| h.path == path).count();
        hits.push(Hit {
            path: path.clone(),
            proxy_auth: req
                .headers()
                .get(header::PROXY_AUTHORIZATION)
                .map(|v| v.to_str().unwrap().to_owned()),
            host: req
                .headers()
                .get(header::HOST)
                .map(|v| v.to_str().unwrap().to_owned()),
        });
        nth
    };
    if path == "/robots.txt" {
        return (StatusCode::OK, "User-agent: *\nAllow: /\n").into_response();
    }
    let status = (state.status_of)(&path, nth);
    let body = if status == 403 {
        "<html><head><title>Just a moment...</title></head><body>cf-chl-bypass</body></html>".to_owned()
    } else {
        format!(
            "<!doctype html><html><head><title>origin</title></head><body><main><h1>origin page</h1><p>answered {path}</p></main></body></html>"
        )
    };
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "text/html")],
        body,
    )
        .into_response()
}

async fn origin(status_of: impl Fn(&str, usize) -> u16 + Send + Sync + 'static) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = OriginState {
        hits: Arc::clone(&hits),
        status_of: Arc::new(status_of),
    };
    let app = Router::new().fallback(answer).with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Origin { url, hits, task }
}

/// What the gateway saw on one `CONNECT`.
#[derive(Clone, Debug)]
struct Connect {
    target: String,
    username: String,
    password: String,
}

#[derive(Clone)]
enum Mode {
    Accept,
    Refuse(u16, &'static str),
}

struct Gateway {
    url: Url,
    seen: Arc<Mutex<Vec<Connect>>>,
    mode: Arc<Mutex<Mode>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gateway {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(Mutex::new(Mode::Accept));
        let counter = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn({
            let (seen, mode) = (Arc::clone(&seen), Arc::clone(&mode));
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve(
                        stream,
                        Arc::clone(&seen),
                        Arc::clone(&mode),
                        counter.fetch_add(1, Ordering::Relaxed),
                    ));
                }
            }
        });
        Self {
            url,
            seen,
            mode,
            task,
        }
    }

    fn seen(&self) -> Vec<Connect> {
        self.seen.lock().unwrap().clone()
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
}

async fn serve(mut stream: TcpStream, seen: Arc<Mutex<Vec<Connect>>>, mode: Arc<Mutex<Mode>>, n: u64) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default().to_owned();
    let mut parts = first.split(' ');
    let (verb, target) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let auth = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, v)| v.trim().to_owned())
        .unwrap_or_default();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth.trim_start_matches("Basic "))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let (username, password) = decoded.split_once(':').unwrap_or(("", ""));
    seen.lock().unwrap().push(Connect {
        target: target.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
    });
    if verb != "CONNECT" {
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }
    let current = mode.lock().unwrap().clone();
    if let Mode::Refuse(status, reason) = current {
        let _ = stream
            .write_all(format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await;
        return;
    }
    if password != KEY {
        let _ = stream
            .write_all(b"HTTP/1.1 407 auth_required\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        let _ = stream
            .write_all(b"HTTP/1.1 502 upstream_error\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };
    let reply = format!(
        "HTTP/1.1 200 Connection established\r\nX-ProxyX-Pool-Session: {:032x}\r\nX-ProxyX-Exit-IP: 203.0.113.{}\r\n\r\n",
        0xfeed_0000_u128 + u128::from(n),
        n % 200 + 1
    );
    if stream.write_all(reply.as_bytes()).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
}

/// Batches the control API received, with the `Authorization` header of each.
type Batches = Arc<Mutex<Vec<(serde_json::Value, String)>>>;

/// The control API: records every batch and answers `200`.
struct Control {
    url: Url,
    batches: Batches,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Control {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn control() -> Control {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let batches: Batches = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::clone(&batches);
    let app = Router::new()
        .route(
            "/v1/block-signals",
            post(
                |State(batches): State<Batches>,
                 headers: axum::http::HeaderMap,
                 Json(body): Json<serde_json::Value>| async move {
                    let auth = headers
                        .get(header::AUTHORIZATION)
                        .map(|v| v.to_str().unwrap().to_owned())
                        .unwrap_or_default();
                    let n = body.as_array().map_or(0, Vec::len);
                    batches.lock().unwrap().push((body, auth));
                    Json(serde_json::json!({"accepted": n, "ignored": 0}))
                },
            ),
        )
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Control { url, batches, task }
}

struct Rig {
    origin: Origin,
    gateway: Gateway,
    stores: Stores,
    dir: tempfile::TempDir,
}

impl Rig {
    async fn new(status_of: impl Fn(&str, usize) -> u16 + Send + Sync + 'static) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        Self {
            origin: origin(status_of).await,
            gateway: Gateway::start().await,
            stores,
            dir,
        }
    }

    fn crawl(&self, mode: ProxyMode, kind: JobKind) -> CreateCrawl {
        let options = ScrapeOptions {
            proxy: mode,
            formats: vec![FormatSpec::Markdown],
            max_age_ms: 0,
            block_ads: false,
            ..ScrapeOptions::default()
        };
        let mut job = ScrapeJob::new(kind, options);
        if kind == JobKind::Batch {
            job.urls = vec![self.origin.url.join("/second").unwrap()];
        }
        let mut crawl = CreateCrawl::new(self.origin.url.join("/page").unwrap());
        crawl.seed = Some(20_261_110);
        crawl.mode = CrawlMode::Static;
        crawl.safety.profile = SafetyProfile::TestEnvironment;
        crawl.safety.allow_private_networks = true;
        crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        crawl.scope.host_scope = HostScope::None;
        crawl.scope.sitemap = SitemapMode::Skip;
        crawl.scope.known_files.clear();
        crawl.scope.max_discovery_depth = 0;
        crawl.politeness.delay_ms = 0;
        crawl.fetch.retries = 0;
        crawl.scrape = Some(job);
        crawl
    }

    fn route(&self, selector: &str, control: Option<&Url>) -> ProxyxRoute {
        ProxyxRoute::new(
            &self.gateway.url,
            control,
            SecretOr::secret(KEY.to_owned()),
            PoolSelector::from_spec(selector).unwrap(),
        )
        .unwrap()
    }

    fn config(&self, basic: Option<ProxyxRoute>, enhanced: Option<ProxyxRoute>) -> WorkerConfig {
        let mut routes = ProxyRoutes::default();
        routes.basic_pool = basic;
        routes.enhanced_pool = enhanced;
        WorkerConfig {
            artifacts_dir: self.dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(StaticResolver::new())),
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                extra_ports: vec![self.gateway.url.port().unwrap()],
                proxy_routes: routes,
                ..EgressConfig::default()
            },
            ..WorkerConfig::default()
        }
    }

    async fn run(&self, crawl: CreateCrawl, cfg: WorkerConfig) -> RunReport {
        run_local_with(LocalRun::new(crawl, cfg).with_stores(self.stores.clone()))
            .await
            .unwrap()
    }

    /// Everything the run stored or emitted, rendered: no secret may be in it.
    async fn output(&self, report: &RunReport) -> String {
        let events = self
            .stores
            .events
            .list_after(report.run_id, 0, 10_000)
            .await
            .unwrap();
        let mut out = format!("{report:?}{events:?}");
        for page in &report.pages {
            out.push_str(&format!("{:?}", page.metadata));
        }
        out
    }

    fn page_metadata(report: &RunReport, path: &str) -> String {
        let page = report
            .pages
            .iter()
            .find(|p| p.url.url.path() == path)
            .expect("stored page");
        format!("{:?}", page.metadata)
    }
}

/// The sticky identity carries its tier and all 64 digest hex digits when the username budget fits.
fn sid_of(username: &str) -> &str {
    username.rsplit_once("-sid-").map_or("", |(_, sid)| sid)
}

#[tokio::test]
async fn the_basic_tier_tunnels_through_the_pool_with_a_sticky_identity_and_records_route_metadata() {
    let rig = Rig::new(|_, _| 200).await;
    let route = rig.route("kind=rotating,cc=fr", None);
    let report = rig
        .run(
            rig.crawl(ProxyMode::Basic, JobKind::Batch),
            rig.config(Some(route), None),
        )
        .await;

    let seen = rig.gateway.seen();
    let page_target = format!("127.0.0.1:{}", rig.origin.url.port().unwrap());
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|c| c.target == page_target), "{seen:?}");
    assert!(seen.iter().all(|c| c.password == KEY));
    // one crawl, one identity: every tunnel carries the same typed username and sid
    let first = &seen[0].username;
    assert!(seen.iter().all(|c| &c.username == first), "{seen:?}");
    assert!(first.starts_with("px-kind-rotating-cc-fr-sid-cx_b_"), "{first}");
    assert_eq!(sid_of(first).len(), "cx_b_".len() + 64);

    // the origin was reached through CONNECT tunnels, never with proxy credentials
    assert_eq!(rig.origin.count("/page"), 1);
    assert_eq!(rig.origin.count("/second"), 1);
    {
        let hits = rig.origin.hits.lock().unwrap();
        assert!(hits.iter().all(|h| h.proxy_auth.is_none()), "{hits:?}");
        assert!(
            hits.iter()
                .all(|h| h.host.as_deref() == Some(page_target.as_str())),
            "{hits:?}"
        );
    }

    for path in ["/page", "/second"] {
        let page = report.pages.iter().find(|p| p.url.url.path() == path).unwrap();
        let document = ScrapeDocument::from_page_metadata(&page.metadata).unwrap();
        assert_eq!(document.status_code, 200);
        assert_eq!(document.proxy_used, ProxyMode::Basic);
        let metadata = Rig::page_metadata(&report, path);
        assert!(metadata.contains("proxyx_pool"), "{metadata}");
        assert!(metadata.contains("203.0.113."), "{metadata}");
        assert!(
            metadata.contains(&format!("{:032x}", 0xfeed_0000_u128).get(..24).unwrap().to_owned()),
            "{metadata}"
        );
    }
    let output = rig.output(&report).await;
    for secret in [KEY, "px-kind-rotating"] {
        assert!(!output.contains(secret), "stored output leaked {secret}");
    }
}

#[tokio::test]
async fn auto_escalates_from_the_basic_pool_to_the_enhanced_pool_of_the_same_run() {
    // the origin blocks the first request of /page and answers the retry on the other tier
    let rig = Rig::new(|path, nth| if path == "/page" && nth == 0 { 403 } else { 200 }).await;
    let basic = rig.route("cc=fr", None);
    let enhanced = rig.route("kind=static,cc=de", None);
    let report = rig
        .run(
            rig.crawl(ProxyMode::Auto, JobKind::Scrape),
            rig.config(Some(basic), Some(enhanced)),
        )
        .await;
    let page = report.pages.iter().find(|p| p.url.url.path() == "/page").unwrap();
    let document = ScrapeDocument::from_page_metadata(&page.metadata).unwrap();
    assert_eq!(document.status_code, 200);
    assert_eq!(document.proxy_used, ProxyMode::Enhanced);
    assert_eq!(rig.origin.count("/page"), 2);

    let seen: Vec<_> = rig
        .gateway
        .seen()
        .into_iter()
        .filter(|c| c.target.ends_with(&rig.origin.url.port().unwrap().to_string()))
        .collect();
    let basic_ids: Vec<_> = seen
        .iter()
        .filter(|c| c.username.starts_with("px-cc-fr-sid-cx_b_"))
        .collect();
    let enhanced_ids: Vec<_> = seen
        .iter()
        .filter(|c| c.username.starts_with("px-kind-static-cc-de-sid-cx_e_"))
        .collect();
    assert!(!basic_ids.is_empty(), "{seen:?}");
    assert!(!enhanced_ids.is_empty(), "{seen:?}");
    // the two tiers of one run share the run part and never the lease
    let run_part = |u: &str| sid_of(u).split_at("cx_b_".len()).1.to_owned();
    assert_eq!(
        run_part(&basic_ids[0].username),
        run_part(&enhanced_ids[0].username)
    );
    assert_ne!(sid_of(&basic_ids[0].username), sid_of(&enhanced_ids[0].username));
    let metadata = Rig::page_metadata(&report, "/page");
    assert!(metadata.contains("proxyx_pool"), "{metadata}");
}

#[tokio::test]
async fn rot_each_sends_no_sid_and_a_fresh_tunnel_per_request() {
    let rig = Rig::new(|_, _| 200).await;
    let route = rig.route("rot=each", None);
    let report = rig
        .run(
            rig.crawl(ProxyMode::Basic, JobKind::Batch),
            rig.config(Some(route), None),
        )
        .await;
    assert_eq!(report.pages.len(), 2);
    let seen = rig.gateway.seen();
    assert!(seen.len() >= 2);
    assert!(seen.iter().all(|c| c.username == "px-rot-each"), "{seen:?}");
}

#[tokio::test]
async fn terminal_refusals_fail_as_proxy_refused_and_transient_ones_as_unreachable() {
    for (status, reason, expected) in [
        (403, "option_denied", "proxy_refused"),
        (407, "auth_required", "proxy_refused"),
        (503, "org_budget", "proxy_refused"),
        (503, "cache_empty", "unreachable"),
        (504, "lease_timeout", "unreachable"),
        (502, "provider_unavailable", "unreachable"),
    ] {
        let rig = Rig::new(|_, _| 200).await;
        rig.gateway.set_mode(Mode::Refuse(status, reason));
        let route = rig.route("", None);
        let report = rig
            .run(
                rig.crawl(ProxyMode::Basic, JobKind::Scrape),
                rig.config(Some(route), None),
            )
            .await;
        assert!(report.pages.is_empty(), "{reason}");
        assert_eq!(
            rig.origin.count("/page"),
            0,
            "{reason}: nothing may reach the origin"
        );
        let output = rig.output(&report).await;
        assert!(output.contains(expected), "{reason}: {output}");
        // a terminal refusal ends the page `failed`, a transient one `unreachable`
        let urls = &report.counters.urls;
        if expected == "unreachable" {
            assert_eq!((urls.unreachable, urls.failed), (1, 0), "{reason}: {urls:?}");
            assert!(!output.contains("proxy_refused"), "{reason}");
        } else {
            assert_eq!((urls.unreachable, urls.failed), (0, 1), "{reason}: {urls:?}");
        }
        assert!(!output.contains(KEY));
    }
}

#[tokio::test]
async fn the_egress_policy_and_the_missing_enhanced_route_are_still_enforced() {
    // a private target without an authorization-backed allowance is refused before the gateway
    let rig = Rig::new(|_, _| 200).await;
    let mut crawl = rig.crawl(ProxyMode::Basic, JobKind::Scrape);
    crawl.safety.allow_private_networks = false;
    let route = rig.route("", None);
    let report = rig.run(crawl, rig.config(Some(route), None)).await;
    assert!(report.pages.is_empty());
    assert!(rig.gateway.seen().is_empty());
    assert_eq!(rig.origin.count("/page"), 0);

    // enhanced and auto without an enhanced route fail closed and name both ways to configure it
    for mode in [ProxyMode::Enhanced, ProxyMode::Auto] {
        let rig = Rig::new(|_, _| 200).await;
        let route = rig.route("", None);
        let result = run_local_with(
            LocalRun::new(rig.crawl(mode, JobKind::Scrape), rig.config(Some(route), None))
                .with_stores(rig.stores.clone()),
        )
        .await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("enhanced proxy requested"), "{error}");
        assert!(error.contains("fetch.proxyx.enhanced"), "{error}");
        assert!(rig.gateway.seen().is_empty());
    }
}

#[tokio::test]
async fn a_block_is_reported_to_the_control_api_with_the_tunnels_session_and_exit_ip() {
    // the origin rate-limits every /page request
    let rig = Rig::new(|path, _| if path == "/page" { 429 } else { 200 }).await;
    let control = control().await;
    let route = rig.route("cc=fr", Some(&control.url));
    let report = rig
        .run(
            rig.crawl(ProxyMode::Basic, JobKind::Scrape),
            rig.config(Some(route), None),
        )
        .await;
    let page = report.pages.iter().find(|p| p.url.url.path() == "/page").unwrap();
    assert_eq!(
        ScrapeDocument::from_page_metadata(&page.metadata)
            .unwrap()
            .status_code,
        429
    );

    let deadline = Instant::now() + Duration::from_secs(15);
    while control.batches.lock().unwrap().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let batches = control.batches.lock().unwrap().clone();
    assert!(!batches.is_empty(), "no block signal reached the control API");
    let (body, auth) = &batches[0];
    let event = &body.as_array().unwrap()[0];
    assert_eq!(event["type"], "rate_limited");
    assert_eq!(
        event["target"],
        format!("127.0.0.1:{}", rig.origin.url.port().unwrap())
    );
    assert!(event["session"].as_str().unwrap().len() == 32);
    assert!(event["exit_ip"].as_str().unwrap().starts_with("203.0.113."));
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth.trim_start_matches("Basic "))
        .unwrap();
    assert!(String::from_utf8(decoded).unwrap().ends_with(&format!(":{KEY}")));
    let output = rig.output(&report).await;
    assert!(!output.contains(KEY));
}
