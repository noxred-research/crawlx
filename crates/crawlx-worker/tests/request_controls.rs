//! Request controls through the worker: `fetch.extraHeaders`, `fetch.cookies`,
//! `fetch.userAgent` and `fetch.robotsUserAgent` on the static plane, credential references
//! resolved once per run, and no configured value in the report, events or page metadata.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::error::CoreError;
use crawlx_core::request_controls::FetchCookie;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

const KEY: &str = "k-worker-1234567";
const SID: &str = "s-worker-7654321";
const UA: &str = "e2e-ua/1";
const ROBOTS_TOKEN: &str = "crawlx-robots-token";

/// One request the fixture received.
#[derive(Clone, Debug)]
struct Hit {
    host: String,
    path: String,
    key: Option<String>,
    cookie: Option<String>,
    user_agent: Option<String>,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

struct Site {
    port: u16,
    hits: Hits,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }

    fn fetched(&self, path: &str) -> bool {
        self.hits().iter().any(|h| h.path == path)
    }
}

/// The headers of a request as the fixture saw them.
fn hit_of(req: &Request) -> Hit {
    let h = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    Hit {
        host: h("host")
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_owned(),
        path: req.uri().path().to_owned(),
        key: h("x-api-key"),
        cookie: h("cookie"),
        user_agent: h("user-agent"),
    }
}

async fn record(State(hits): State<Hits>, req: Request, next: Next) -> Response {
    let hit = hit_of(&req);
    hits.lock().unwrap().push(hit);
    next.run(req).await
}

fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

fn page(title: &'static str) -> axum::routing::MethodRouter {
    get(move || async move {
        html(format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>{title} text.</p></main></body></html>"
        ))
    })
}

async fn start(robots: &'static str) -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits: Hits = Arc::default();
    let app = Router::new()
        .route(
            "/",
            get(move || async move {
                html(format!(
                    r#"<html><head><title>Home</title></head><body><main><h1>Home</h1><p>Welcome.</p>
                    <a href="/p1">p1</a> <a href="/blocked-by-token">token</a> <a href="/blocked-by-ua">ua</a>
                    <a href="http://www.a.test:{port}/sub">sub</a>
                    <a href="http://other.test:{port}/away">away</a></main></body></html>"#
                ))
            }),
        )
        .route(
            "/p1",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/html; charset=utf-8".to_owned()),
                        // a server that echoes a request header or cookie back
                        (header::HeaderName::from_static("x-echo"), format!("seen {KEY}")),
                        (header::HeaderName::from_static("x-echo-cookie"), SID.to_owned()),
                    ],
                    "<html><head><title>P1</title></head><body><main><h1>P1</h1><p>First page.</p></main></body></html>",
                )
                    .into_response()
            }),
        )
        .route("/sub", page("Sub"))
        .route("/away", page("Away"))
        .route("/blocked-by-token", page("Token"))
        .route("/blocked-by-ua", page("Ua"))
        .route(
            "/robots.txt",
            get(move || async move { ([(header::CONTENT_TYPE, "text/plain")], robots) }),
        )
        .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { port, hits, task }
}

/// Resolves `env://NAME` references from a fixed map and records the lookups.
struct MapResolver {
    values: BTreeMap<String, String>,
    lookups: Mutex<Vec<String>>,
}

impl MapResolver {
    fn new(values: &[(&str, &str)]) -> Arc<Self> {
        Arc::new(Self {
            values: values
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            lookups: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl SecretResolver for MapResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        self.lookups.lock().unwrap().push(reference.0.clone());
        self.values
            .get(&reference.0)
            .map(|v| SecretOr::secret(v.clone()))
            .ok_or_else(|| CoreError::CredentialUnavailable(reference.0.clone()))
    }
}

fn config(dir: &std::path::Path) -> WorkerConfig {
    let resolver = StaticResolver::new();
    for host in ["a.test", "www.a.test", "other.test"] {
        resolver.set(host, [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(resolver)),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn crawl(site: &Site, edit: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(&format!("http://a.test:{}/", site.port)).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_027);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c.scope.sitemap = SitemapMode::Skip;
    // every host, so the other registrable domain is crawled too
    c.scope.host_scope = HostScope::None;
    edit(&mut c);
    c
}

struct Crawled {
    report: RunReport,
    stores: Stores,
    resolver: Arc<MapResolver>,
}

async fn run(c: CreateCrawl) -> Crawled {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let resolver = MapResolver::new(&[("env://E2E_KEY", KEY)]);
    let mut record = authorization_fixture::verified_record(&c, stores.tenant);
    for host in ["www.a.test", "other.test"] {
        let mut target = c.seed_url.clone();
        target.set_host(Some(host)).unwrap();
        record.origins.push(target.origin().ascii_serialization());
    }
    let report = run_local_with(
        LocalRun::new(c, config(dir.path()))
            .with_stores(stores.clone())
            .with_secrets(Arc::clone(&resolver) as Arc<dyn SecretResolver>)
            .with_authorization(record),
    )
    .await
    .unwrap();
    Crawled {
        report,
        stores,
        resolver,
    }
}

const OPEN_ROBOTS: &str = "User-agent: *\nDisallow:\n";

/// Header (a credential reference), cookie and User-Agent on every request to the seed's
/// domain, robots.txt included; another registrable domain gets only the User-Agent.
#[tokio::test]
async fn controls_reach_in_scope_requests_and_never_leave_the_seed_domain() {
    let site = start(OPEN_ROBOTS).await;
    let c = crawl(&site, |c| {
        c.fetch.extra_headers.insert("x-api-key", "env://E2E_KEY");
        c.fetch.cookies.push(FetchCookie::new("sid", SID));
        c.fetch.user_agent = Some(UA.to_owned());
    });
    let crawled = run(c).await;

    let hits = site.hits();
    for path in ["/robots.txt", "/", "/p1", "/sub"] {
        let h = hits
            .iter()
            .find(|h| h.path == path && h.host != "other.test")
            .unwrap_or_else(|| panic!("{path} was not requested: {hits:?}"));
        assert_eq!(h.key.as_deref(), Some(KEY), "{h:?}");
        assert_eq!(h.cookie.as_deref(), Some(&*format!("sid={SID}")), "{h:?}");
        assert_eq!(h.user_agent.as_deref(), Some(UA), "{h:?}");
    }
    assert!(
        hits.iter().any(|h| h.path == "/sub" && h.host == "www.a.test"),
        "{hits:?}"
    );
    let away = hits
        .iter()
        .find(|h| h.host == "other.test" && h.path == "/away")
        .unwrap_or_else(|| panic!("the other domain was not crawled: {hits:?}"));
    assert_eq!(
        (away.key.as_deref(), away.cookie.as_deref()),
        (None, None),
        "{away:?}"
    );
    assert_eq!(away.user_agent.as_deref(), Some(UA));
    assert!(crawled.report.pages.iter().any(|p| p.url.url.path() == "/p1"));

    // the reference was looked up exactly once for the run, and audited without its value
    assert_eq!(*crawled.resolver.lookups.lock().unwrap(), ["env://E2E_KEY"]);
    let events = crawled
        .stores
        .events
        .list_after(crawled.report.run_id, 0, 10_000)
        .await
        .unwrap();
    let audit: Vec<_> = events.iter().filter(|e| e.kind == "secret.resolved").collect();
    assert_eq!(audit.len(), 1, "{events:?}");
    assert_eq!(audit[0].payload["purpose"], "request_header");
    assert_eq!(audit[0].payload["name"], "x-api-key");
    assert_eq!(audit[0].payload["scheme"], "env");
    assert!(audit[0].payload["reference_hash"]
        .as_str()
        .is_some_and(|h| h.len() == 64));
}

/// A configured value never appears in what a run reports, stores or emits: page metadata
/// (a server may echo a value in a response header), events, the report and the stored
/// request once redacted; the stored request holds the reference, not the resolved value.
#[tokio::test]
async fn no_configured_value_appears_in_reports_metadata_or_events() {
    let site = start(OPEN_ROBOTS).await;
    let c = crawl(&site, |c| {
        c.fetch.extra_headers.insert("x-api-key", "env://E2E_KEY");
        c.fetch.cookies.push(FetchCookie::new("sid", SID));
        c.fetch.user_agent = Some(UA.to_owned());
    });
    let crawled = run(c).await;
    assert!(site.fetched("/p1"));

    let p1 = crawled
        .report
        .pages
        .iter()
        .find(|p| p.url.url.path() == "/p1")
        .unwrap();
    let headers = &p1.metadata["response_headers"];
    assert_eq!(headers["x-echo"], "[redacted]", "{headers}");
    assert_eq!(headers["x-echo-cookie"], "[redacted]", "{headers}");
    assert!(headers["content-type"]
        .as_str()
        .is_some_and(|v| v.starts_with("text/html")));

    let metadata = serde_json::to_string(
        &crawled
            .report
            .pages
            .iter()
            .map(|p| &p.metadata)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let events = crawled
        .stores
        .events
        .list_after(crawled.report.run_id, 0, 10_000)
        .await
        .unwrap();
    let events_json =
        serde_json::to_string(&events.iter().map(|e| (&e.kind, &e.payload)).collect::<Vec<_>>()).unwrap();
    let debug = format!("{:?}", crawled.report);
    for (what, text) in [
        ("metadata", &metadata),
        ("events", &events_json),
        ("report", &debug),
    ] {
        assert!(!text.contains(KEY), "{what} leaks the header value");
        assert!(!text.contains(SID), "{what} leaks the cookie value");
    }

    // the stored request holds the reference; every outward view of it is redacted
    let stored = crawled.stores.runs.get(crawled.report.run_id).await.unwrap();
    assert_eq!(
        stored.config.fetch.extra_headers.get("x-api-key"),
        Some("env://E2E_KEY")
    );
    let redacted = serde_json::to_string(&stored.config.redacted()).unwrap();
    assert!(!redacted.contains(KEY) && !redacted.contains(SID), "{redacted}");
    assert!(redacted.contains("[redacted]"));
    assert!(!format!("{:?}", stored.config).contains(SID));
}

/// `fetch.robotsUserAgent` selects the robots.txt group; without it `fetch.userAgent` does.
#[tokio::test]
async fn robots_user_agent_selects_the_robots_group() {
    let robots: &'static str = "User-agent: crawlx-robots-token\nDisallow: /blocked-by-token\n\n\
                                User-agent: e2e-ua\nDisallow: /blocked-by-ua\n\n\
                                User-agent: *\nDisallow:\n";
    // the robots token wins over the User-Agent header's product token
    let site = start(robots).await;
    let crawled = run(crawl(&site, |c| {
        c.fetch.user_agent = Some(UA.to_owned());
        c.fetch.robots_user_agent = Some(ROBOTS_TOKEN.to_owned());
    }))
    .await;
    assert!(site.fetched("/p1"));
    assert!(!site.fetched("/blocked-by-token"), "{:?}", site.hits());
    assert!(site.fetched("/blocked-by-ua"), "{:?}", site.hits());
    assert!(
        crawled.report.counters.urls.robots_blocked >= 1,
        "{:?}",
        crawled.report.counters
    );
    // every request still carries the configured User-Agent header
    assert!(
        site.hits().iter().all(|h| h.user_agent.as_deref() == Some(UA)),
        "{:?}",
        site.hits()
    );

    // without a robots token the User-Agent's product token selects the group
    let site = start(robots).await;
    let _ = run(crawl(&site, |c| c.fetch.user_agent = Some(UA.to_owned()))).await;
    assert!(site.fetched("/p1"));
    assert!(!site.fetched("/blocked-by-ua"), "{:?}", site.hits());
    assert!(site.fetched("/blocked-by-token"), "{:?}", site.hits());
}

/// A reference nobody can resolve fails the run before any request is sent.
#[tokio::test]
async fn an_unresolvable_reference_fails_the_run_before_the_first_request() {
    let site = start(OPEN_ROBOTS).await;
    let dir = tempfile::tempdir().unwrap();
    let c = crawl(&site, |c| {
        c.fetch.extra_headers.insert("x-api-key", "env://MISSING");
    });
    let err = authorization_fixture::run_authorized_local_with(
        LocalRun::new(c, config(dir.path())).with_secrets(MapResolver::new(&[])),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        crawlx_worker::WorkerError::Core(CoreError::CredentialUnavailable(_))
    ));
    assert!(site.hits().is_empty(), "{:?}", site.hits());
}
