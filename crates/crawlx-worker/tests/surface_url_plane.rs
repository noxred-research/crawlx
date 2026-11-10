//! Surface discovery on the static plane: endpoint discovery, URL-shape and content dedupe, page
//! types, known files and the counters invariants, against an in-process fixture site.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Router;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::{CrawlMode, KnownFile, PageType, SimilarityMode};
use crawlx_core::repo::FrontierStatus;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Every request the fixture served, in order: `(method, path)`.
type Ledger = Arc<Mutex<Vec<(String, String)>>>;
/// Seeded cloud-key-style and GitHub-style tokens (never real), assembled from parts so the
/// source holds no contiguous token.
const SECRET_TOKEN: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");
const GITHUB_TOKEN: &str = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345");

struct Site {
    base: String,
    ledger: Ledger,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn ops(&self) -> Vec<(String, String)> {
        self.ledger.lock().unwrap().clone()
    }
    fn fetched(&self, path: &str) -> bool {
        self.ops().iter().any(|(m, p)| m == "GET" && p == path)
    }
}

fn html(body: impl Into<String>) -> axum::response::Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body.into()).into_response()
}

fn simple(title: &str) -> String {
    format!(
        r#"<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>Some {title} text here.</p></main></body></html>"#
    )
}

fn template_page(n: usize) -> String {
    let filler = (0..40)
        .map(|i| format!("shared template sentence number {i} about the product catalogue"))
        .collect::<Vec<_>>()
        .join(". ");
    format!(
        r#"<html><head><title>Product {n}</title></head><body><nav><a href="/">Home</a></nav>
        <main><h1>Product {n}</h1><p>{filler}</p><p>SKU-{n}</p><a href="/t/leaf-{n}">more</a></main>
        <footer>footer</footer></body></html>"#
    )
}

fn home_page() -> String {
    let users: String = (1..=15)
        .map(|i| format!(r#"<a href="/users/{i}">user {i}</a> "#))
        .collect();
    let slugs: String = (1..=15)
        .map(|i| format!(r#"<a href="/p/n{i}">slug {i}</a> "#))
        .collect();
    format!(
        r#"<html><head><title>Home</title></head><body><main><h1>Home</h1><p>Welcome home.</p>
        <a href="/a">A</a> <a href="/a?utm_source=news">A again</a>
        <iframe src="/frame"></iframe>
        <script src="/app.js"></script>
        <script>fetch('/api/items').then(r => r.json());</script>
        <form method="post" action="/submit"><input name="q" value="x"><button>go</button></form>
        <img srcset="/img/a.png 1x, /img/b.png 2x" src="/img/a.png">
        <a href="/logo">logo</a>
        <div hx-get="/hx/partial" hx-trigger="load"></div>
        {users}{slugs}
        <a href="/t/1">t1</a> <a href="/t/2">t2</a> <a href="/t/3">t3</a> <a href="/t/4">t4</a>
        <a href="/dup-a">dup a</a> <a href="/dup-b">dup b</a>
        <a href="/login">login</a> <a href="/secret">secret</a>
        </main></body></html>"#
    )
}

fn page(title: &'static str) -> axum::routing::MethodRouter {
    get(move || async move { html(simple(title)) })
}

async fn record(
    State(ledger): State<Ledger>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    ledger
        .lock()
        .unwrap()
        .push((req.method().to_string(), req.uri().path().to_owned()));
    next.run(req).await
}

/// The fixture: `/` carries one construct per reference parser family plus 15 numeric and
/// 15 slug detail links; a PNG without extension; a POST form; template pages; a login
/// page; a page carrying seeded secrets in a header and a script.
async fn start() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let ledger: Ledger = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                        (header::LINK, "</linked>; rel=preload"),
                    ],
                    home_page(),
                )
                    .into_response()
            }),
        )
        .route("/a", page("A"))
        .route("/frame", page("Frame"))
        .route("/linked", page("Linked"))
        .route("/hx/partial", page("Partial"))
        .route("/robots-allowed", page("Allowed"))
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/javascript")],
                    "const api = \"/api/from-js\"; function go(){ fetch(api); }",
                )
            }),
        )
        .route(
            "/api/items",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], r#"{"items":[]}"#) }),
        )
        .route(
            "/api/from-js",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], r#"{"ok":true}"#) }),
        )
        .route(
            "/logo",
            get(|| async {
                // a PNG served without an extension; the bytes contain a tempting relative path
                let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
                png.extend_from_slice(b"\"/png-trap\" '/png-trap-2'");
                ([(header::CONTENT_TYPE, "image/png")], png)
            }),
        )
        .route("/users/{id}", page("User"))
        .route("/p/{slug}", page("Slug"))
        .route(
            "/t/{n}",
            get(|uri: Uri| async move {
                let n: usize = uri.path().trim_start_matches("/t/").parse().unwrap_or(0);
                html(template_page(n))
            }),
        )
        .route("/t/leaf-{n}", page("Leaf"))
        .route("/dup-a", page("Dup"))
        .route("/dup-b", page("Dup"))
        .route(
            "/login",
            get(|| async {
                html(
                    r#"<html><head><title>Sign in</title></head><body><main><h1>Sign in</h1>
                <form method="post" action="/session"><input name="user"><input type="password" name="pass"><button>Sign in</button></form>
                <a href="/login-only">forgot</a></main></body></html>"#,
                )
            }),
        )
        .route("/login-only", page("Forgot"))
        .route(
            "/secret",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                        (header::HeaderName::from_static("x-api-key"), SECRET_TOKEN),
                    ],
                    format!(
                        r#"<html><body><main><h1>Config</h1><p>token {SECRET_TOKEN}</p><script>var k = "{GITHUB_TOKEN}";</script></main></body></html>"#
                    ),
                )
                    .into_response()
            }),
        )
        .route(
            "/robots.txt",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/plain")],
                    "User-agent: *\nAllow: /robots-allowed\nDisallow: /private/\n",
                )
            }),
        )
        .route("/submit", any(|| async { (StatusCode::OK, "submitted") }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&ledger), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, ledger, task }
}

fn config(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    }
}

fn static_crawl(base: &str) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_019);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    c
}

struct Crawled {
    report: RunReport,
    stores: Stores,
}

impl Crawled {
    fn page(&self, path: &str) -> &crawlx_core::repo::PageRecord {
        self.report
            .pages
            .iter()
            .find(|p| p.url.url.path() == path)
            .unwrap_or_else(|| panic!("no page row for {path}"))
    }
    fn paths(&self) -> BTreeSet<String> {
        self.report
            .pages
            .iter()
            .map(|p| p.url.url.path().to_owned())
            .collect()
    }
    async fn frontier(&self) -> Vec<crawlx_core::repo::FrontierEntry> {
        self.stores.frontier.list(self.report.run_id).await.unwrap()
    }
}

async fn crawl(site: &Site, tweak: impl FnOnce(&mut CreateCrawl)) -> Crawled {
    let dir = tempfile::tempdir().unwrap();
    let mut c = static_crawl(&site.base);
    tweak(&mut c);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(LocalRun::new(c, config(dir.path())).with_stores(stores.clone()))
        .await
        .unwrap();
    Crawled { report, stores }
}

#[tokio::test]
async fn structural_endpoints_are_admitted_and_binary_bodies_are_never_mined() {
    let site = start().await;
    let c = crawl(&site, |c| c.scope.known_files = vec![KnownFile::RobotsPaths]).await;
    let paths = c.paths();
    for expected in [
        "/",
        "/a",
        "/frame",
        "/app.js",
        "/api/items",
        "/api/from-js",
        "/linked",
        "/hx/partial",
        "/logo",
        "/robots-allowed",
    ] {
        assert!(paths.contains(expected), "{expected} missing from {paths:?}");
    }
    // the PNG was fetched (it is a plain link) but nothing inside it was mined
    assert!(site.fetched("/logo"));
    assert!(!site.fetched("/png-trap") && !site.fetched("/png-trap-2"));
    let logo = c.page("/logo");
    assert_eq!(logo.content_type.as_deref(), Some("image/png"));
    assert!(logo.metadata.get("discovered_endpoints").is_none());
    // the POST form is recorded on the home page, never fetched
    let home = c.page("/");
    let recorded = home.metadata["discovered_endpoints"].as_array().unwrap();
    assert!(
        recorded
            .iter()
            .any(|e| e["method"] == "POST" && e["url"].as_str().unwrap().ends_with("/submit")),
        "{recorded:?}"
    );
    assert!(
        !site.ops().iter().any(|(_, p)| p == "/submit"),
        "{:?}",
        site.ops()
    );
    // extension-filtered images are policy_blocked, not fetched
    let frontier = c.frontier().await;
    let png = frontier
        .iter()
        .find(|e| e.url.url.path() == "/img/a.png")
        .unwrap();
    assert_eq!(png.status, FrontierStatus::PolicyBlocked);
    assert_eq!(png.denial_reason.as_deref(), Some("extension_filtered"));
    assert!(!site.fetched("/img/a.png"));
    // request provenance of endpoint-discovered pages
    assert_eq!(c.page("/frame").metadata["request"]["tag"], "iframe");
    assert_eq!(c.page("/api/from-js").metadata["request"]["tag"], "js");
    assert_eq!(c.page("/robots-allowed").metadata["request"]["tag"], "robots");
    assert_eq!(
        home.metadata["response_headers"]["link"],
        "</linked>; rel=preload"
    );
    assert!(home.metadata["page_type"].is_string());
    assert_eq!(home.metadata["forms"].as_array().unwrap().len(), 1);
    assert_eq!(c.page("/login").metadata["page_type"], "login");
    // the `Disallow: /private/` path was never seeded under robots respect
    assert!(!site.ops().iter().any(|(_, p)| p.starts_with("/private")));
    let u = c.report.counters.urls;
    assert!(u.invariants_hold(), "{u:?}");
    assert!(u.deduplicated >= 1, "tracking-parameter variant is a duplicate");
    assert!(c.report.counters.interactions.invariants_hold());
}

#[tokio::test]
async fn js_endpoints_can_be_switched_off() {
    let site = start().await;
    let c = crawl(&site, |c| c.scope.js_endpoints = false).await;
    let paths = c.paths();
    assert!(paths.contains("/app.js") && paths.contains("/frame"));
    assert!(
        !paths.contains("/api/from-js") && !paths.contains("/api/items"),
        "{paths:?}"
    );
}

#[tokio::test]
async fn fingerprint_budget_filters_similar_urls_as_deduplicated() {
    let site = start().await;
    let c = crawl(&site, |c| c.scope.filter_similar = true).await;
    let paths = c.paths();
    // numeric ids collapse to `{num}` at once: one page per shape
    assert!(paths.contains("/users/1"));
    for i in 2..=15 {
        assert!(!paths.contains(&format!("/users/{i}")), "{paths:?}");
    }
    // slugs promote after `filterSimilarThreshold` (10) distinct values
    for i in 1..=11 {
        assert!(paths.contains(&format!("/p/n{i}")), "{paths:?}");
    }
    for i in 12..=15 {
        assert!(!paths.contains(&format!("/p/n{i}")), "{paths:?}");
    }
    let frontier = c.frontier().await;
    let filtered: Vec<_> = frontier
        .iter()
        .filter(|e| e.denial_reason.as_deref() == Some("dedupe:fingerprint"))
        .collect();
    let filtered_paths: BTreeSet<&str> = filtered.iter().map(|e| e.url.url.path()).collect();
    for i in 2..=15 {
        assert!(
            filtered_paths.contains(format!("/users/{i}").as_str()),
            "{filtered_paths:?}"
        );
    }
    for i in 12..=15 {
        assert!(
            filtered_paths.contains(format!("/p/n{i}").as_str()),
            "{filtered_paths:?}"
        );
    }
    assert!(filtered.len() >= 18);
    assert!(filtered.iter().all(|e| e.status == FrontierStatus::PolicyBlocked));
    let u = c.report.counters.urls;
    assert!(u.invariants_hold(), "{u:?}");
    assert!(u.deduplicated >= 18, "{u:?}");
    assert_eq!(
        c.page("/users/1").metadata["fingerprint"].as_str().unwrap(),
        format!("{}/users/{{num}}", site.base)
    );
}

#[tokio::test]
async fn content_similarity_filters_template_pages_but_records_them() {
    let site = start().await;
    let c = crawl(&site, |c| {
        c.scope.content_similarity.mode = SimilarityMode::Simhash;
        c.scope.content_similarity.distance = 3;
    })
    .await;
    let templates: Vec<_> = c
        .report
        .pages
        .iter()
        .filter(|p| p.url.url.path().starts_with("/t/") && !p.url.url.path().contains("leaf"))
        .collect();
    assert_eq!(templates.len(), 4, "every fetch is recorded");
    let filtered: Vec<_> = templates
        .iter()
        .filter(|p| p.metadata["dedupe"]["reason"] == "content_similar")
        .collect();
    assert_eq!(filtered.len(), 3, "{templates:?}");
    assert!(filtered
        .iter()
        .all(|p| p.metadata["dedupe"]["cluster"].is_string()));
    // filtered pages are not expanded: only one leaf was fetched
    let leaves = c
        .paths()
        .into_iter()
        .filter(|p| p.starts_with("/t/leaf-"))
        .count();
    assert_eq!(leaves, 1);
    // identical bodies are exact duplicates
    let dups: Vec<_> = c
        .report
        .pages
        .iter()
        .filter(|p| p.url.url.path().starts_with("/dup-"))
        .collect();
    assert_eq!(dups.len(), 2);
    assert_eq!(
        dups.iter()
            .filter(|p| p.metadata["dedupe"]["reason"] == "content_exact")
            .count(),
        1
    );
    let frontier = c.frontier().await;
    assert!(frontier
        .iter()
        .any(|e| e.denial_reason.as_deref() == Some("dedupe:content_similar")));
    let u = c.report.counters.urls;
    assert!(u.invariants_hold(), "{u:?}");
    assert!(u.deduplicated >= 4);
}

#[tokio::test]
async fn filtered_page_types_are_recorded_but_not_expanded() {
    let site = start().await;
    let c = crawl(&site, |c| c.scope.filter_page_types = vec![PageType::Login]).await;
    let login = c.page("/login");
    assert_eq!(login.metadata["page_type"], "login");
    assert_eq!(login.metadata["filtered_page_type"], true);
    assert!(!c.paths().contains("/login-only"));
    assert!(!site.fetched("/login-only"));
    let frontier = c.frontier().await;
    let row = frontier.iter().find(|e| e.url.url.path() == "/login").unwrap();
    assert_eq!(row.denial_reason.as_deref(), Some("filtered_page_type"));
    assert!(c.report.counters.urls.invariants_hold());
    // without the filter the link is followed
    let open = crawl(&site, |_| {}).await;
    assert!(open.paths().contains("/login-only"));
}

#[tokio::test]
async fn max_pages_per_host_and_depth_first_are_honoured() {
    let site = start().await;
    let c = crawl(&site, |c| {
        c.scope.max_pages_per_host = Some(3);
        c.scope.strategy = crawlx_core::config::CrawlStrategy::DepthFirst;
    })
    .await;
    assert_eq!(c.report.pages.len(), 3, "{:?}", c.paths());
    let frontier = c.frontier().await;
    assert!(frontier
        .iter()
        .any(|e| e.denial_reason.as_deref() == Some("host_page_limit")));
    let u = c.report.counters.urls;
    assert!(u.invariants_hold(), "{u:?}");
    assert_eq!(u.admitted, 3);
}

#[tokio::test]
async fn out_of_scope_endpoints_are_recorded_as_leaves_when_requested() {
    let site = start().await;
    let c = crawl(&site, |c| {
        c.output.include_out_of_scope = true;
        c.scope.exclude_paths = vec!["^/frame".to_owned()];
    })
    .await;
    let frontier = c.frontier().await;
    let frame = frontier.iter().find(|e| e.url.url.path() == "/frame").unwrap();
    assert_eq!(frame.status, FrontierStatus::PolicyBlocked);
    assert!(frame
        .denial_reason
        .as_deref()
        .unwrap()
        .starts_with("excluded_path"));
    assert!(!site.fetched("/frame"));
}

#[tokio::test]
async fn secrets_are_stored_as_kind_and_hash_only() {
    let site = start().await;
    let c = crawl(&site, |c| {
        c.extract.detect_secrets = true;
        c.extract.custom_fields = vec![crawlx_core::config::CustomField {
            name: "sku".to_owned(),
            regex: vec!["SKU-([0-9]+)".to_owned()],
            part: crawlx_core::config::CustomFieldPart::Body,
            group: 1,
        }];
    })
    .await;
    let t = c.page("/t/1");
    assert_eq!(t.metadata["custom_fields"]["sku"], serde_json::json!(["1"]));
    let secret = c.page("/secret");
    let findings = secret.metadata["secrets"].as_array().unwrap();
    assert!(!findings.is_empty(), "{:?}", secret.metadata);
    assert!(findings
        .iter()
        .all(|f| f["value_hash"].is_string() && f["kind"].is_string()));
    let dump = serde_json::to_string(&c.report.pages).unwrap();
    assert!(!dump.contains(SECRET_TOKEN) && !dump.contains(GITHUB_TOKEN));
    let events = c
        .stores
        .events
        .list_after(c.report.run_id, 0, 10_000)
        .await
        .unwrap();
    let dump = serde_json::to_string(&events).unwrap();
    assert!(!dump.contains(SECRET_TOKEN) && !dump.contains(GITHUB_TOKEN));
    // without detection nothing is stored
    let off = crawl(&site, |_| {}).await;
    assert!(off.page("/secret").metadata.get("secrets").is_none());
}
