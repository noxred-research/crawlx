//! The scrape engine through real runs: `run_local_with` over in-memory stores,
//! a fixture HTTP site on 127.0.0.1, a scripted browser renderer and a scripted LLM. Every
//! test asserts the stored result (`PageRecord` + `metadata["scrape"]` + artifacts) and the
//! frontier rows, never the engine's internals.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use chrono::SecondsFormat;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::{CrawlMode, HostScope, RetentionMode, SitemapMode};
use crawlx_core::repo::{FrontierEntry, FrontierStatus, PageRecord};
use crawlx_core::scrape::{
    AttributeSelector, CacheState, ChangeMode, ChangeStatus, FormatSpec, JobKind, ParserSpec, PdfMode,
    ScrapeAction, ScrapeDocument, ScrapeJob, ScrapeOptions,
};
use crawlx_core::{ArtifactRef, CreateCrawl};
use crawlx_fetch::StaticResolver;
use crawlx_model::llm::{LlmError, LlmExtractor, MockLlm};
use crawlx_storage::MemoryStore;
use crawlx_worker::scrape::{ActionOutputs, PageRenderer, RenderError, RenderRequest, Rendered, Shot};
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

// ---- the fixture site ---------------------------------------------------------------------

/// Served verbatim by `/raw`: odd whitespace, a comment and no trailing normalisation.
const RAW: &str = "<!DOCTYPE html>\n<html>\n  <head><title>Raw</title></head>\n\n<body>  <p>spaced   out</p>  <!-- comment kept -->\n</body></html>\n";

/// `/page`: head metadata, chrome around `<main>`, links, a normal and an inline image.
const PAGE: &str = r#"<!doctype html><html lang="en"><head><title>Pricing</title>
<meta name="description" content="All the plans">
<meta property="og:title" content="OG Pricing">
<link rel="stylesheet" href="/site.css"></head>
<body><header class="top">Site header chrome</header>
<nav><a href="/nav-link">Nav</a></nav>
<main><h1>Pricing</h1><p class="keep">Main text here.</p><p>price: 10</p>
<a href="/more">More</a> <a href="https://other.example/ext">Ext</a>
<img src="/img/a.png" alt="a"><img src="data:image/png;base64,iVBORw0KGgo=" alt="inline"></main>
<footer>Footer chrome</footer></body></html>"#;

const TAGS: &str = r#"<html><head><title>Tags</title></head><body>
<article class="keep">Kept words</article><aside class="ad">Advert words</aside>
<div class="other">Other words</div></body></html>"#;

const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 1, 2, 3, 255];

const SITE_CSS: &str =
    ":root{--brand:#ff5500} body{font-family:'Inter',sans-serif;color:#111111;background:#fafafa}";

struct Mutable {
    status: u16,
    body: String,
}

struct Site {
    base: String,
    hits: Arc<Mutex<Vec<String>>>,
    mutable: Arc<Mutex<Mutable>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
    /// Requests for `path` (robots.txt aside).
    fn count(&self, path: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| *p == path).count()
    }
    fn set_page(&self, status: u16, body: &str) {
        *self.mutable.lock().unwrap() = Mutable {
            status,
            body: body.to_owned(),
        };
    }
}

fn html(body: impl Into<String>) -> axum::response::Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body.into()).into_response()
}

fn simple(title: &'static str) -> axum::routing::MethodRouter<Arc<Mutex<Mutable>>> {
    get(move || async move {
        html(format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>Some {title} text.</p></main></body></html>"
        ))
    })
}

async fn record(
    State(hits): State<Arc<Mutex<Vec<String>>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.lock().unwrap().push(req.uri().path().to_owned());
    next.run(req).await
}

/// A PDF with one text page per entry of `pages` (a real xref table, Helvetica, 12 pt).
fn pdf(pages: &[&str]) -> Vec<u8> {
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

async fn start() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mutable = Arc::new(Mutex::new(Mutable {
        status: 200,
        body: "<html><body><main><h1>Mutable</h1><p>first</p></main></body></html>".to_owned(),
    }));
    let sheet_page = |dir: &str| {
        let links: String = (0..10)
            .map(|i| format!(r#"<link rel="stylesheet" href="/{dir}/{i}.css">"#))
            .collect();
        format!("<html><head><title>Sheets</title>{links}</head><body><main>x</main></body></html>")
    };
    let many_sheets = sheet_page("s");
    let small_sheets = sheet_page("t");
    let app = Router::new()
        .route("/page", get(|| async { html(PAGE) }))
        .route("/tags", get(|| async { html(TAGS) }))
        .route("/more", simple("More"))
        .route("/nav-link", simple("Nav"))
        .route("/raw", get(|| async { html(RAW) }))
        .route(
            "/missing",
            get(|| async {
                (
                    StatusCode::NOT_FOUND,
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html><body><main><h1>Gone</h1><p>Nothing here.</p></main></body></html>",
                )
            }),
        )
        .route(
            "/boom",
            get(|| async {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html><body><main><h1>Oops</h1><p>Server broke.</p></main></body></html>",
                )
            }),
        )
        .route(
            "/mutable",
            get(|State(m): State<Arc<Mutex<Mutable>>>| async move {
                let g = m.lock().unwrap();
                (
                    StatusCode::from_u16(g.status).unwrap(),
                    [(header::CONTENT_TYPE, "text/html")],
                    g.body.clone(),
                )
            }),
        )
        .route("/cache-validator", get(|State(m): State<Arc<Mutex<Mutable>>>, headers: axum::http::HeaderMap| async move {
            let page = m.lock().unwrap();
            let etag = format!("\"{}\"", crawlx_core::hash::Digest::of("cache-fixture", page.body.as_bytes()));
            let unchanged = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(etag.as_str());
            let mut response_headers = axum::http::HeaderMap::new();
            response_headers.insert(header::CONTENT_TYPE, axum::http::HeaderValue::from_static("text/html"));
            response_headers.insert(header::ETAG, axum::http::HeaderValue::from_str(&etag).unwrap());
            (if unchanged { StatusCode::NOT_MODIFIED } else { StatusCode::OK }, response_headers,
                if unchanged { String::new() } else { page.body.clone() })
        }))
        .route("/native-header-challenge", get(|| async {
            ([(header::CONTENT_TYPE, "text/html"), (header::HeaderName::from_static("cf-mitigated"), "challenge")],
                "<main>Checking browser</main>")
        }))
        .route("/native-wrong-mime", get(|| async {
            ([(header::CONTENT_TYPE, "application/json")], "<html><main>HTML, not JSON</main></html>")
        }))
        .route("/native-redirect", get(|| async {
            (StatusCode::FOUND, [(header::LOCATION, "/mutable")])
        }))
        .route("/native-forbidden-redirect", get(|| async {
            (StatusCode::FOUND, [(header::LOCATION, "http://169.254.169.254/latest/meta-data/")])
        }))
        .route("/native-switch", get(|headers: axum::http::HeaderMap| async move {
            let browser = headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("Chrome/"));
            if browser {
                html("<article id=expected><h1>Ordinary article</h1><p>Browser content arrived.</p></article>")
            } else {
                html("<form id=challenge-form>Check your browser</form>")
            }
        }))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                html("<html><body>late</body></html>")
            }),
        )
        .route(
            "/data.json",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"plan":"pro","seats":3}"#,
                )
            }),
        )
        .route(
            "/data.csv",
            get(|| async { ([(header::CONTENT_TYPE, "text/csv")], "a,b\n1,2\n") }),
        )
        .route(
            "/pic.png",
            get(|| async { ([(header::CONTENT_TYPE, "image/png")], PNG.to_vec()) }),
        )
        .route(
            "/blob.zip",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/zip")],
                    b"PK\x03\x04zip".to_vec(),
                )
            }),
        )
        .route(
            "/blank.pdf",
            get(|| async { ([(header::CONTENT_TYPE, "application/pdf")], pdf(&[""])) }),
        )
        .route(
            "/doc.pdf",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/pdf")],
                    pdf(&["Quarterly revenue grew", "Second page costs fell"]),
                )
            }),
        )
        .route(
            "/bad.pdf",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/pdf")],
                    b"%PDF-1.4 truncated".to_vec(),
                )
            }),
        )
        .route(
            "/site.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], SITE_CSS) }),
        )
        .route(
            "/many-sheets",
            get(move || {
                let page = many_sheets.clone();
                async move { html(page) }
            }),
        )
        .route(
            "/small-sheets",
            get(move || {
                let page = small_sheets.clone();
                async move { html(page) }
            }),
        )
        .route(
            "/t/{n}",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], "a{color:#654321}") }),
        )
        .route(
            "/s/{n}",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css")],
                    "a{color:#123456}".repeat(6_667),
                )
            }),
        )
        .with_state(Arc::clone(&mutable))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        base: format!("http://{addr}"),
        hits,
        mutable,
        task,
    }
}

// ---- scripted collaborators ---------------------------------------------------------------

type RenderFn = dyn Fn(&RenderRequest<'_>) -> Result<Rendered, RenderError> + Send + Sync;

/// A renderer whose answer is a function of the request; remembers `(url, waitFor, actions)`.
struct Scripted {
    answer: Box<RenderFn>,
    calls: Mutex<Vec<(String, u32, usize)>>,
}

impl Scripted {
    fn new(
        answer: impl Fn(&RenderRequest<'_>) -> Result<Rendered, RenderError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            answer: Box::new(answer),
            calls: Mutex::new(Vec::new()),
        })
    }
    fn calls(&self) -> Vec<(String, u32, usize)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl PageRenderer for Scripted {
    async fn render(&self, req: &RenderRequest<'_>) -> Result<Rendered, RenderError> {
        self.calls.lock().unwrap().push((
            req.request.url.url.to_string(),
            req.options.wait_for_ms,
            req.options.actions.len(),
        ));
        (self.answer)(req)
    }
}

fn rendered(url: &Url, html: &str) -> Rendered {
    Rendered {
        final_url: url.clone(),
        status: 200,
        headers: vec![("content-type".to_owned(), "text/html".to_owned())],
        content_type: Some("text/html".to_owned()),
        html: html.to_owned(),
        screenshot: None,
        actions: ActionOutputs::default(),
        computed_styles: None,
        evidence: None,
    }
}

/// Answers by task: summary, question/query, highlights and json (the `price: N` of the page).
fn mock_llm() -> Arc<MockLlm> {
    Arc::new(MockLlm::from_fn(|call| {
        let user = &call.user;
        if user.contains("Summarize the page") {
            return Ok(json!({"summary": "A pricing page."}));
        }
        if user.contains("Answer the question") {
            let q = user
                .split("Question: ")
                .nth(1)
                .and_then(|s| s.lines().next())
                .unwrap_or_default();
            return Ok(json!({"answer": format!("re: {q}")}));
        }
        if user.contains("Return the passages") {
            return Ok(json!({"highlights": ["Main text here."]}));
        }
        let price = user
            .split("price: ")
            .nth(1)
            .map(|s| s.chars().take_while(char::is_ascii_digit).collect::<String>());
        Ok(match price {
            Some(p) if !p.is_empty() => json!({"price": p}),
            _ => json!({"title": "Pricing"}),
        })
    }))
}

// ---- the rig --------------------------------------------------------------------------------

struct Rig {
    stores: Stores,
    dir: tempfile::TempDir,
}

impl Rig {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        Self { stores, dir }
    }
}

type Tweak = Box<dyn FnOnce(&mut CreateCrawl)>;

struct Spec {
    kind: JobKind,
    seed: String,
    urls: Vec<String>,
    options: ScrapeOptions,
    llm: Option<Arc<MockLlm>>,
    renderer: Option<Arc<Scripted>>,
    tweak: Option<Tweak>,
}

impl Spec {
    fn new(seed: String, options: ScrapeOptions) -> Self {
        Self {
            kind: JobKind::Scrape,
            seed,
            urls: Vec::new(),
            options,
            llm: None,
            renderer: None,
            tweak: None,
        }
    }
    fn kind(mut self, kind: JobKind) -> Self {
        self.kind = kind;
        self
    }
    fn urls(mut self, urls: &[String]) -> Self {
        self.urls = urls.to_vec();
        self
    }
    fn llm(mut self, llm: &Arc<MockLlm>) -> Self {
        self.llm = Some(Arc::clone(llm));
        self
    }
    fn renderer(mut self, renderer: &Arc<Scripted>) -> Self {
        self.renderer = Some(Arc::clone(renderer));
        self
    }
    fn tweak(mut self, f: impl FnOnce(&mut CreateCrawl) + 'static) -> Self {
        self.tweak = Some(Box::new(f));
        self
    }
}

struct Done {
    report: RunReport,
    stores: Stores,
}

impl Done {
    async fn frontier(&self) -> Vec<FrontierEntry> {
        self.stores.frontier.list(self.report.run_id).await.unwrap()
    }
    async fn row(&self, path: &str) -> FrontierEntry {
        self.frontier()
            .await
            .into_iter()
            .find(|e| e.url.url.path() == path)
            .unwrap_or_else(|| panic!("no frontier row for {path}"))
    }
    fn page(&self, path: &str) -> &PageRecord {
        self.report
            .pages
            .iter()
            .find(|p| p.url.url.path() == path)
            .unwrap_or_else(|| panic!("no page row for {path}"))
    }
    fn doc(&self, path: &str) -> ScrapeDocument {
        ScrapeDocument::from_page_metadata(&self.page(path).metadata)
            .unwrap_or_else(|| panic!("{path} carries no scrape document"))
    }
    async fn events(&self, kind: &str) -> Vec<Value> {
        self.stores
            .events
            .list_after(self.report.run_id, 0, 10_000)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.payload)
            .collect()
    }
    async fn text(&self, artifact: &ArtifactRef) -> String {
        String::from_utf8(self.stores.artifacts.get(artifact).await.unwrap()).unwrap()
    }
    async fn markdown(&self, path: &str) -> String {
        let page = self.page(path);
        self.text(page.markdown.as_ref().expect("markdown artifact"))
            .await
    }
    async fn blob(&self, blob: &crawlx_core::scrape::BlobRef) -> Vec<u8> {
        self.stores.artifacts.get(&blob.artifact).await.unwrap()
    }
}

fn config(dir: &std::path::Path, llm: Option<Arc<MockLlm>>, renderer: Option<Arc<Scripted>>) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        llm: llm.map(|l| l as Arc<dyn LlmExtractor>),
        renderer: renderer.map(|r| r as Arc<dyn PageRenderer>),
        ..WorkerConfig::default()
    }
}

fn crawl_of(spec: &mut Spec) -> CreateCrawl {
    let mut job = ScrapeJob::new(spec.kind, spec.options.clone());
    job.urls = spec.urls.iter().map(|u| Url::parse(u).unwrap()).collect();
    let mut c = CreateCrawl::new(Url::parse(&spec.seed).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_027);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c.scope.sitemap = SitemapMode::Skip;
    c.scope.known_files = Vec::new();
    c.scope.host_scope = HostScope::None;
    c.scope.max_discovery_depth = if spec.kind == JobKind::Crawl { 1 } else { 0 };
    c.scrape = Some(job);
    if let Some(tweak) = spec.tweak.take() {
        tweak(&mut c);
    }
    c
}

async fn try_go(rig: &Rig, mut spec: Spec) -> Result<Done, crawlx_worker::WorkerError> {
    let crawl = crawl_of(&mut spec);
    let mut cfg = config(rig.dir.path(), spec.llm.take(), spec.renderer.take());
    if crawl
        .acquisition
        .as_ref()
        .is_some_and(|policy| policy.backend_ids.iter().any(|id| id == "native_browser"))
    {
        cfg.launch.allow_unpinned = true;
        if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_err() && std::env::var_os("CI").is_none() {
            cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |user| user == "root");
        }
    }
    // the policy admits 80/443 and the seed's port; a batch URL on another test port is allowed
    cfg.egress.extra_ports = spec
        .urls
        .iter()
        .filter_map(|u| Url::parse(u).ok()?.port())
        .collect();
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(rig.stores.clone())).await?;
    Ok(Done {
        report,
        stores: rig.stores.clone(),
    })
}

async fn go(rig: &Rig, spec: Spec) -> Done {
    try_go(rig, spec).await.unwrap()
}

fn opts(formats: Vec<FormatSpec>) -> ScrapeOptions {
    ScrapeOptions {
        formats,
        cache_principal: Some(uuid::Uuid::from_u128(1)),
        ..ScrapeOptions::default()
    }
}

fn md() -> ScrapeOptions {
    opts(vec![FormatSpec::Markdown])
}

fn rfc3339(page: &PageRecord) -> String {
    page.fetched_at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// `host:port/path depth status reason` per frontier row, for assertion messages.
fn summary(rows: &[FrontierEntry]) -> String {
    rows.iter()
        .map(|r| format!("{} d{} {:?} {:?}", r.url.url, r.depth, r.status, r.denial_reason))
        .collect::<Vec<_>>()
        .join("\n")
}

fn schema() -> Value {
    json!({"type": "object", "properties": {"price": {"type": "string"}}})
}

// ---- formats ------------------------------------------------------------------------------

#[tokio::test]
async fn markdown_html_links_images_rawhtml_and_metadata_are_stored() {
    let (site, rig) = (start().await, Rig::new().await);
    let options = opts(vec![
        FormatSpec::Markdown,
        FormatSpec::Html,
        FormatSpec::Links,
        FormatSpec::Images,
        FormatSpec::RawHtml,
    ]);
    let done = go(&rig, Spec::new(site.url("/page"), options.clone())).await;

    assert_eq!(done.row("/page").await.status, FrontierStatus::Succeeded);
    let page = done.page("/page");
    assert_eq!(page.status, 200);
    assert_eq!(page.content_type.as_deref(), Some("text/html; charset=utf-8"));
    assert!(page.title.is_some());
    let markdown = done.markdown("/page").await;
    assert!(
        markdown.contains("# Pricing") && markdown.contains("Main text here."),
        "{markdown}"
    );
    let cleaned = done.text(page.html.as_ref().unwrap()).await;
    assert!(cleaned.contains("Main text here."), "{cleaned}");
    assert!(page.links.contains(&site.url("/more")), "{:?}", page.links);
    assert!(page.links.contains(&"https://other.example/ext".to_owned()));

    let doc = done.doc("/page");
    assert_eq!((doc.version, doc.status_code), (ScrapeDocument::VERSION, 200));
    assert_eq!(doc.source_url, site.url("/page"));
    assert_eq!(doc.final_url, site.url("/page"));
    assert_eq!(doc.cache_state, CacheState::Miss);
    assert!(doc.cached_at.is_none() && !doc.not_cacheable && doc.error.is_none());
    assert_eq!(
        doc.options_digest,
        crawlx_worker::scrape::cache::key(&options, None, done.report.run_id).digest()
    );
    assert_eq!(doc.meta["description"], json!("All the plans"));
    assert_eq!(doc.meta["ogTitle"], json!("OG Pricing"));
    let images = doc.images.unwrap();
    assert!(images.contains(&site.url("/img/a.png")), "{images:?}");
    assert!(images.iter().all(|i| !i.starts_with("data:")));
    let raw = done.blob(doc.raw_html.as_ref().unwrap()).await;
    assert_eq!(raw, PAGE.as_bytes(), "rawHtml is the body verbatim");
    assert_eq!(doc.raw_html.unwrap().content_type, "text/html");
    // the stored row keeps the static plane's metadata keys
    assert_eq!(page.metadata["final_url"], json!(site.url("/page")));
    assert!(page.metadata["response_headers"].is_object());
}

#[tokio::test]
async fn only_the_requested_formats_are_stored() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(&rig, Spec::new(site.url("/page"), md())).await;
    let page = done.page("/page");
    assert!(page.markdown.is_some());
    assert!(page.html.is_none() && page.links.is_empty());
    let doc = done.doc("/page");
    assert!(doc.raw_html.is_none() && doc.images.is_none() && doc.attributes.is_none());
    assert!(doc.screenshot.is_none() && doc.actions.is_none() && doc.branding.is_none());
    assert!(doc.change_tracking.is_none() && doc.json.is_none() && doc.llm_tokens == 0);
}

#[tokio::test]
async fn rawhtml_is_verbatim_even_for_odd_markup() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(&rig, Spec::new(site.url("/raw"), opts(vec![FormatSpec::RawHtml]))).await;
    let blob = done.doc("/raw").raw_html.unwrap();
    assert_eq!(done.blob(&blob).await, RAW.as_bytes());
    assert_eq!(blob.size, RAW.len() as u64);
    assert!(done.page("/raw").markdown.is_none(), "markdown was not requested");
}

#[tokio::test]
async fn rawbase64_keeps_the_body_bytes_of_any_content_type() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/pic.png"), opts(vec![FormatSpec::RawBase64])),
    )
    .await;
    assert_eq!(done.row("/pic.png").await.status, FrontierStatus::Succeeded);
    let doc = done.doc("/pic.png");
    assert_eq!(doc.content_type.as_deref(), Some("image/png"));
    let blob = doc.raw_base64.unwrap();
    assert_eq!(blob.content_type, "image/png");
    assert_eq!(done.blob(&blob).await, PNG);
    assert!(done.page("/pic.png").markdown.is_none());
}

#[tokio::test]
async fn binary_bodies_without_rawbase64_fail_as_unsupported_content() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(&rig, Spec::new(site.url("/blob.zip"), md())).await;
    let row = done.row("/blob.zip").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("unsupported_content"))
    );
    assert!(done.report.pages.is_empty());
    let failed = done.events("page.failed").await;
    assert_eq!(failed[0]["reason"], "unsupported_content");
    assert!(failed[0]["message"].as_str().unwrap().contains("application/zip"));
}

#[tokio::test]
async fn raster_images_need_the_image_parser_and_without_ocr_answer_with_a_warning() {
    let (site, rig) = (start().await, Rig::new().await);
    // `image` is on by default: no OCR engine, so an empty document that says so
    let done = go(&rig, Spec::new(site.url("/pic.png"), md())).await;
    assert_eq!(done.row("/pic.png").await.status, FrontierStatus::Succeeded);
    assert_eq!(done.markdown("/pic.png").await, "");
    let doc = done.doc("/pic.png");
    assert!(
        doc.warning.as_deref().unwrap().contains("ocr_unavailable"),
        "{:?}",
        doc.warning
    );
    assert_eq!(doc.content_type.as_deref(), Some("image/png"));
    // a `parsers` list without `image` turns it off: image URLs are unsupported files
    let off = go(
        &rig,
        Spec::new(site.url("/pic.png"), pdf_options(vec![ParserSpec::pdf()])),
    )
    .await;
    let row = off.row("/pic.png").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("unsupported_content"))
    );
    assert!(off.events("page.failed").await[0]["message"]
        .as_str()
        .unwrap()
        .contains("image"));
}

#[tokio::test]
async fn text_bodies_are_their_own_markdown() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(&rig, Spec::new(site.url("/data.json"), md())).await;
    assert_eq!(done.markdown("/data.json").await, r#"{"plan":"pro","seats":3}"#);
    assert_eq!(
        done.page("/data.json").content_type.as_deref(),
        Some("application/json")
    );
    let csv = go(&rig, Spec::new(site.url("/data.csv"), md())).await;
    assert_eq!(csv.markdown("/data.csv").await, "a,b\n1,2\n");
}

#[tokio::test]
async fn attributes_return_the_values_of_matching_elements() {
    let (site, rig) = (start().await, Rig::new().await);
    let selectors = vec![AttributeSelector {
        selector: "a".to_owned(),
        attribute: "href".to_owned(),
    }];
    let done = go(
        &rig,
        Spec::new(
            site.url("/page"),
            opts(vec![FormatSpec::Attributes { selectors }]),
        ),
    )
    .await;
    let result = done.doc("/page").attributes.unwrap();
    assert_eq!(
        (result[0].selector.as_str(), result[0].attribute.as_str()),
        ("a", "href")
    );
    for href in ["/nav-link", "/more", "https://other.example/ext"] {
        assert!(
            result[0].values.iter().any(|v| v == href),
            "{href} in {:?}",
            result[0].values
        );
    }
}

#[tokio::test]
async fn branding_reads_the_linked_stylesheets_through_the_fetcher() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/page"), opts(vec![FormatSpec::Branding])),
    )
    .await;
    assert_eq!(site.count("/site.css"), 1, "the stylesheet was fetched");
    let branding = done.doc("/page").branding.unwrap();
    assert!(branding.is_object());
    assert!(
        branding.to_string().contains("Inter"),
        "the font of the fetched CSS reaches the profile: {branding}"
    );
    assert!(done.page("/page").markdown.is_none());
}

#[tokio::test]
async fn branding_fetches_at_most_eight_stylesheets() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/small-sheets"), opts(vec![FormatSpec::Branding])),
    )
    .await;
    assert_eq!(done.row("/small-sheets").await.status, FrontierStatus::Succeeded);
    let fetched: usize = (0..10).map(|i| site.count(&format!("/t/{i}.css"))).sum();
    assert_eq!(fetched, 8, "{:?}", site.hits.lock().unwrap());
}

#[tokio::test]
async fn branding_reads_at_most_512_kib_of_stylesheet_text() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/many-sheets"), opts(vec![FormatSpec::Branding])),
    )
    .await;
    assert_eq!(done.row("/many-sheets").await.status, FrontierStatus::Succeeded);
    let fetched: usize = (0..10).map(|i| site.count(&format!("/s/{i}.css"))).sum();
    // every sheet is 106 672 bytes: the fifth is cut at the budget (524 288) and ends the reading
    assert_eq!(fetched, 5, "{:?}", site.hits.lock().unwrap());
}

// ---- content selection ----------------------------------------------------------------------

#[tokio::test]
async fn only_main_content_drops_the_chrome_around_main() {
    let (site, rig) = (start().await, Rig::new().await);
    let main = go(&rig, Spec::new(site.url("/page"), md())).await;
    let all = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                only_main_content: false,
                ..md()
            },
        ),
    )
    .await;
    let main_md = main.markdown("/page").await;
    let all_md = all.markdown("/page").await;
    assert!(
        main_md.contains("Main text here.") && !main_md.contains("Footer chrome"),
        "{main_md}"
    );
    assert!(
        all_md.contains("Footer chrome") && all_md.contains("Site header chrome"),
        "{all_md}"
    );
}

#[tokio::test]
async fn include_and_exclude_tags_select_content() {
    let (site, rig) = (start().await, Rig::new().await);
    let included = go(
        &rig,
        Spec::new(
            site.url("/tags"),
            ScrapeOptions {
                only_main_content: false,
                include_tags: vec![".keep".to_owned()],
                ..md()
            },
        ),
    )
    .await;
    let inc = included.markdown("/tags").await;
    assert!(
        inc.contains("Kept words") && !inc.contains("Other words") && !inc.contains("Advert words"),
        "{inc}"
    );
    let excluded = go(
        &rig,
        Spec::new(
            site.url("/tags"),
            ScrapeOptions {
                only_main_content: false,
                exclude_tags: vec![".ad".to_owned()],
                ..md()
            },
        ),
    )
    .await;
    let exc = excluded.markdown("/tags").await;
    assert!(
        exc.contains("Other words") && exc.contains("Kept words") && !exc.contains("Advert words"),
        "{exc}"
    );
}

#[tokio::test]
async fn an_invalid_include_selector_fails_the_page_as_extract_failed() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(
            site.url("/tags"),
            ScrapeOptions {
                include_tags: vec!["div[".to_owned()],
                ..md()
            },
        ),
    )
    .await;
    assert_eq!(
        done.row("/tags").await.denial_reason.as_deref(),
        Some("extract_failed")
    );
}

#[tokio::test]
async fn base64_images_are_removed_by_default_and_kept_on_request() {
    let (site, rig) = (start().await, Rig::new().await);
    let both = || vec![FormatSpec::Markdown, FormatSpec::Html];
    let stripped = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                only_main_content: false,
                ..opts(both())
            },
        ),
    )
    .await;
    let md = stripped.markdown("/page").await;
    let html = stripped.text(stripped.page("/page").html.as_ref().unwrap()).await;
    assert!(
        !md.contains("data:image") && !html.contains("data:image"),
        "{md}\n{html}"
    );
    let kept = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                only_main_content: false,
                remove_base64_images: false,
                ..opts(both())
            },
        ),
    )
    .await;
    let md = kept.markdown("/page").await;
    let html = kept.text(kept.page("/page").html.as_ref().unwrap()).await;
    assert!(
        md.contains("data:image/png;base64") && html.contains("data:image/png;base64"),
        "{md}\n{html}"
    );
}

// ---- HTTP statuses ----------------------------------------------------------------------------

#[tokio::test]
async fn every_http_status_is_stored_as_a_document() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/page"), md())
            .kind(JobKind::Batch)
            .urls(&[site.url("/missing"), site.url("/boom")]),
    )
    .await;
    assert_eq!(done.report.pages.len(), 3);
    for (path, status, text) in [
        ("/missing", 404, "Nothing here."),
        ("/boom", 500, "Server broke."),
    ] {
        assert_eq!(done.row(path).await.status, FrontierStatus::Succeeded, "{path}");
        assert_eq!(done.page(path).status, status);
        let doc = done.doc(path);
        assert_eq!(doc.status_code, status);
        assert!(doc.error.is_some(), "metadata.error names the status");
        assert!(doc.not_cacheable, "an error page is never served from the cache");
        assert!(done.markdown(path).await.contains(text));
    }
    assert!(done.report.failures.is_empty());
    // not cacheable: scraping it again fetches again
    let again = go(&rig, Spec::new(site.url("/missing"), md())).await;
    assert_eq!(again.doc("/missing").cache_state, CacheState::Miss);
    assert_eq!(site.count("/missing"), 2);
}

// ---- cache ------------------------------------------------------------------------------------

fn native_cache(mode: crawlx_core::cache::CacheModeV1) -> ScrapeOptions {
    let mut options = md();
    let mut policy = crawlx_core::cache::CachePolicyV1::default();
    policy.mode = mode;
    options.cache = Some(policy);
    options
}

#[tokio::test]
async fn native_cache_modes_principals_and_development_replay_use_real_stored_pages() {
    use crawlx_core::cache::CacheModeV1;
    let (site, rig) = (start().await, Rig::new().await);
    let missing = go(
        &rig,
        Spec::new(site.url("/page"), native_cache(CacheModeV1::ReadOnly)),
    )
    .await;
    assert_eq!(
        missing.row("/page").await.denial_reason.as_deref(),
        Some("no_cached_data")
    );
    assert_eq!(site.count("/page"), 0);
    let written = go(
        &rig,
        Spec::new(site.url("/page"), native_cache(CacheModeV1::Bypass)),
    )
    .await;
    assert_eq!(written.doc("/page").cache_state, CacheState::Miss);
    assert_eq!(site.count("/page"), 1);
    let hit = go(
        &rig,
        Spec::new(site.url("/page"), native_cache(CacheModeV1::ReadOnly)),
    )
    .await;
    assert_eq!(hit.doc("/page").cache_state, CacheState::Hit);
    assert_eq!(site.count("/page"), 1);
    let mut foreign = native_cache(CacheModeV1::ReadOnly);
    foreign.cache_principal = Some(uuid::Uuid::from_u128(2));
    let denied = go(&rig, Spec::new(site.url("/page"), foreign)).await;
    assert_eq!(
        denied.row("/page").await.denial_reason.as_deref(),
        Some("no_cached_data")
    );
    assert_eq!(
        site.count("/page"),
        1,
        "a foreign principal neither reads nor fetches"
    );
    let mut replay = native_cache(CacheModeV1::ReadWrite);
    replay.cache.as_mut().unwrap().development_replay = true;
    let replayed = go(&rig, Spec::new(site.url("/page"), replay)).await;
    assert_eq!(
        replayed.page("/page").metadata["developmentReplay"]["networkRequests"],
        0
    );
    assert_eq!(site.count("/page"), 1);
    assert_eq!(replayed.markdown("/page").await, written.markdown("/page").await);
}

#[tokio::test]
async fn native_disabled_does_not_write_and_missing_artifacts_fail_without_fetching() {
    use crawlx_core::cache::CacheModeV1;
    use crawlx_storage::ArtifactReaper;
    let (site, rig) = (start().await, Rig::new().await);
    go(
        &rig,
        Spec::new(site.url("/page"), native_cache(CacheModeV1::Disabled)),
    )
    .await;
    let missed = go(
        &rig,
        Spec::new(site.url("/page"), native_cache(CacheModeV1::ReadOnly)),
    )
    .await;
    assert!(missed.report.pages.is_empty());
    assert_eq!(site.count("/page"), 1);
    let written = go(
        &rig,
        Spec::new(site.url("/page"), native_cache(CacheModeV1::WriteOnly)),
    )
    .await;
    let artifacts = crawlx_storage::FsArtifactStore::open(
        rig.dir.path(),
        rig.stores.runs.clone(),
        Arc::new(crawlx_core::SystemClock),
    )
    .await
    .unwrap();
    artifacts.purge_run(written.report.run_id).await.unwrap();
    let unavailable = go(
        &rig,
        Spec::new(site.url("/page"), native_cache(CacheModeV1::ReadOnly)),
    )
    .await;
    assert_eq!(
        unavailable.row("/page").await.denial_reason.as_deref(),
        Some("stored_body_unavailable")
    );
    assert_eq!(
        site.count("/page"),
        2,
        "missing stored bytes never trigger a cache-only fetch"
    );
}

#[tokio::test]
async fn native_freshness_conditional_get_and_changed_head_share_the_parent_allowance() {
    use crawlx_core::cache::{CacheFreshnessV1, CacheModeV1};
    let (site, rig) = (start().await, Rig::new().await);
    go(
        &rig,
        Spec::new(site.url("/cache-validator"), native_cache(CacheModeV1::ReadWrite)),
    )
    .await;
    let mut conditional = native_cache(CacheModeV1::ReadWrite);
    conditional.cache.as_mut().unwrap().freshness = CacheFreshnessV1::ConditionalGet;
    let reused = go(&rig, Spec::new(site.url("/cache-validator"), conditional)).await;
    assert_eq!(reused.doc("/cache-validator").cache_state, CacheState::Hit);
    assert_eq!(
        site.count("/cache-validator"),
        2,
        "one owned conditional GET, no second body fetch"
    );
    assert_eq!(
        reused.page("/cache-validator").metadata["acquisition"]["networkRequests"],
        1
    );
    site.set_page(
        200,
        "<main><h1>Changed validator</h1><p>New retained body</p></main>",
    );
    let mut head = native_cache(CacheModeV1::ReadWrite);
    head.cache.as_mut().unwrap().freshness = CacheFreshnessV1::Head;
    let changed = go(&rig, Spec::new(site.url("/cache-validator"), head)).await;
    assert_eq!(changed.doc("/cache-validator").cache_state, CacheState::Miss);
    assert_eq!(
        site.count("/cache-validator"),
        4,
        "changed HEAD consumes one of the same two attempts"
    );
    assert_eq!(
        changed.page("/cache-validator").metadata["acquisition"]["networkRequests"],
        2
    );
    assert!(changed
        .markdown("/cache-validator")
        .await
        .contains("New retained body"));
}

#[tokio::test]
async fn max_age_serves_a_stored_scrape_and_reports_cached_at() {
    let (site, rig) = (start().await, Rig::new().await);
    let first = go(&rig, Spec::new(site.url("/page"), md())).await;
    assert_eq!(first.doc("/page").cache_state, CacheState::Miss);
    assert_eq!(site.count("/page"), 1);

    let second = go(&rig, Spec::new(site.url("/page"), md())).await;
    assert_eq!(site.count("/page"), 1, "served from the stored scrape");
    let doc = second.doc("/page");
    assert_eq!(doc.cache_state, CacheState::Hit);
    assert_eq!(
        doc.cached_at.as_deref(),
        Some(rfc3339(first.page("/page")).as_str())
    );
    assert_eq!(second.row("/page").await.status, FrontierStatus::Succeeded);
    let (a, b) = (first.page("/page"), second.page("/page"));
    assert_eq!(b.run, second.report.run_id);
    assert_ne!(a.run, b.run, "a hit writes a page row of its own run");
    assert_eq!(a.markdown, b.markdown, "the row references the stored artifacts");
    assert_eq!(a.fetched_at, b.fetched_at);
    assert_eq!(second.markdown("/page").await, first.markdown("/page").await);

    // maxAge 0 disables the cache; other options never share a stored scrape
    let off = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                max_age_ms: 0,
                ..md()
            },
        ),
    )
    .await;
    assert_eq!(off.doc("/page").cache_state, CacheState::Miss);
    assert_eq!(site.count("/page"), 2);
    let other = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                only_main_content: false,
                ..md()
            },
        ),
    )
    .await;
    assert_eq!(other.doc("/page").cache_state, CacheState::Miss);
    assert_eq!(site.count("/page"), 3);
}

#[tokio::test]
async fn a_stored_scrape_older_than_max_age_is_not_served() {
    let (site, rig) = (start().await, Rig::new().await);
    go(&rig, Spec::new(site.url("/page"), md())).await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let done = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                max_age_ms: 1,
                ..md()
            },
        ),
    )
    .await;
    assert_eq!(done.doc("/page").cache_state, CacheState::Miss);
    assert_eq!(site.count("/page"), 2);
}

#[tokio::test]
async fn a_cache_hit_serves_llm_formats_without_calling_the_llm_again() {
    let (site, rig) = (start().await, Rig::new().await);
    let llm = mock_llm();
    let options = opts(vec![FormatSpec::Markdown, FormatSpec::Summary]);
    go(&rig, Spec::new(site.url("/page"), options.clone()).llm(&llm)).await;
    let calls = llm.calls().len();
    let hit = go(&rig, Spec::new(site.url("/page"), options).llm(&llm)).await;
    assert_eq!(llm.calls().len(), calls);
    let doc = hit.doc("/page");
    assert_eq!(doc.cache_state, CacheState::Hit);
    assert_eq!(doc.summary.as_deref(), Some("A pricing page."));
}

#[tokio::test]
async fn min_age_serves_only_old_enough_stored_scrapes_and_never_fetches() {
    let (site, rig) = (start().await, Rig::new().await);
    let none = ScrapeOptions {
        min_age_ms: Some(0),
        ..md()
    };
    let empty = go(&rig, Spec::new(site.url("/page"), none.clone())).await;
    let row = empty.row("/page").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("no_cached_data"))
    );
    assert!(empty.report.pages.is_empty());
    assert_eq!(site.count("/page"), 0, "minAge never fetches");
    assert_eq!(empty.events("page.failed").await[0]["reason"], "no_cached_data");

    go(&rig, Spec::new(site.url("/page"), md())).await;
    let too_young = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                min_age_ms: Some(3_600_000),
                ..md()
            },
        ),
    )
    .await;
    assert_eq!(
        too_young.row("/page").await.denial_reason.as_deref(),
        Some("no_cached_data")
    );
    assert_eq!(site.count("/page"), 1);

    let old_enough = go(&rig, Spec::new(site.url("/page"), none)).await;
    assert_eq!(old_enough.doc("/page").cache_state, CacheState::Hit);
    assert_eq!(site.count("/page"), 1);
}

#[tokio::test]
async fn lockdown_serves_stored_scrapes_of_any_age_and_misses_fail() {
    let (site, rig) = (start().await, Rig::new().await);
    let lockdown = || ScrapeOptions {
        lockdown: true,
        max_age_ms: 1,
        ..md()
    };
    let miss = go(&rig, Spec::new(site.url("/page"), lockdown())).await;
    let row = miss.row("/page").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("lockdown_cache_miss"))
    );
    assert_eq!(site.count("/page"), 0);

    go(&rig, Spec::new(site.url("/page"), md())).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let hit = go(&rig, Spec::new(site.url("/page"), lockdown())).await;
    assert_eq!(
        hit.doc("/page").cache_state,
        CacheState::Hit,
        "age does not matter under lockdown"
    );
    assert_eq!(site.count("/page"), 1);
}

#[tokio::test]
async fn store_in_cache_false_writes_the_row_but_it_is_never_served() {
    let (site, rig) = (start().await, Rig::new().await);
    let first = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                store_in_cache: false,
                ..md()
            },
        ),
    )
    .await;
    assert!(first.doc("/page").not_cacheable);
    assert!(
        first.page("/page").markdown.is_some(),
        "the page row is still written"
    );
    let second = go(&rig, Spec::new(site.url("/page"), md())).await;
    assert_eq!(second.doc("/page").cache_state, CacheState::Miss);
    assert_eq!(site.count("/page"), 2);
    // and lockdown cannot see the unstored scrape either
    let fresh = Rig::new().await;
    go(
        &fresh,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                store_in_cache: false,
                ..md()
            },
        ),
    )
    .await;
    let locked = go(
        &fresh,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                lockdown: true,
                ..md()
            },
        ),
    )
    .await;
    assert_eq!(
        locked.row("/page").await.denial_reason.as_deref(),
        Some("lockdown_cache_miss")
    );
}

#[tokio::test]
async fn native_article_sources_use_distinct_typed_sinks_in_retained_modes() {
    use crawlx_core::extraction::{CommentPolicyV1, ExtractionPolicyV1};
    let source = include_str!("../../crawlx-bench/fixtures/ext-article/comments.html");
    for mode in [RetentionMode::Standard, RetentionMode::Extended] {
        let (site, rig) = (start().await, Rig::new().await);
        site.set_page(200, source);
        let mut policy = ExtractionPolicyV1::default();
        policy.comments = CommentPolicyV1::Separate;
        let mut options = md();
        options.content_policy = Some(policy);
        let done = go(
            &rig,
            Spec::new(site.url("/mutable"), options).tweak(move |crawl| {
                crawl.retention.mode = mode;
                crawl.retention.days = if mode == RetentionMode::Extended { 31 } else { 7 };
            }),
        )
        .await;
        assert_eq!(done.row("/mutable").await.status, FrontierStatus::Succeeded);
        let doc = done.doc("/mutable");
        assert_eq!(doc.meta["article"]["quality"]["status"], "accepted");
        let main: crawlx_core::scrape::BlobRef =
            serde_json::from_value(doc.meta["articleTextRef"].clone()).unwrap();
        let comments: crawlx_core::scrape::BlobRef =
            serde_json::from_value(doc.meta["articleCommentsRef"].clone()).unwrap();
        assert_ne!(main.artifact.id, comments.artifact.id);
        let main_text = String::from_utf8(done.blob(&main).await).unwrap();
        let comment_text = String::from_utf8(done.blob(&comments).await).unwrap();
        assert!(main_text.contains("The library will open later"));
        assert!(!main_text.contains("I appreciate"));
        assert!(comment_text.contains("I appreciate"));
        for range in doc.meta["article"]["metadata"]["summary"].as_array().unwrap() {
            let start = usize::try_from(range["start"].as_u64().unwrap()).unwrap();
            let end = usize::try_from(range["end"].as_u64().unwrap()).unwrap();
            assert!(main_text.get(start..end).is_some_and(|s| !s.is_empty()));
        }
        assert_eq!(
            site.count("/mutable"),
            1,
            "extracting an article must not fetch it again"
        );
    }
}

#[tokio::test]
async fn native_quality_rejection_keeps_real_successful_acquisition_accounted() {
    let (site, rig) = (start().await, Rig::new().await);
    site.set_page(
        200,
        include_str!("../../crawlx-bench/fixtures/ext-article/main.html"),
    );
    let mut options = md();
    let mut policy = crawlx_core::extraction::ExtractionPolicyV1::default();
    policy.min_main_chars = 10_000;
    options.content_policy = Some(policy);
    let done = go(&rig, Spec::new(site.url("/mutable"), options)).await;
    assert_eq!(done.page("/mutable").status, 200);
    assert_eq!(done.row("/mutable").await.status, FrontierStatus::Succeeded);
    let doc = done.doc("/mutable");
    assert_eq!(doc.meta["article"]["quality"]["status"], "rejected");
    assert!(doc.meta["article"]["quality"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "too_short"));
    assert!(done.markdown("/mutable").await.contains("river has returned"));
    assert_eq!(site.count("/mutable"), 1);
}

// ---- change tracking ----------------------------------------------------------------------------

fn tracking(tag: Option<&str>) -> ScrapeOptions {
    opts(vec![FormatSpec::ChangeTracking {
        modes: vec![ChangeMode::GitDiff],
        schema: None,
        prompt: None,
        tag: tag.map(str::to_owned),
    }])
}

fn mutable_page(body: &str) -> String {
    format!("<html><body><main><h1>Plans</h1><p>{body}</p></main></body></html>")
}

#[tokio::test]
async fn change_tracking_walks_new_same_changed_removed() {
    let (site, rig) = (start().await, Rig::new().await);
    site.set_page(200, &mutable_page("old text"));
    let one = go(&rig, Spec::new(site.url("/mutable"), tracking(None))).await;
    let t1 = one.doc("/mutable").change_tracking.unwrap();
    assert_eq!(t1.change_status, ChangeStatus::New);
    assert!(t1.previous_scrape_at.is_none() && t1.diff.is_none());
    // the fixture's front page does not link to `/mutable` and there is no sitemap
    assert_eq!(t1.visibility, "hidden");
    assert!(
        one.page("/mutable").markdown.is_some(),
        "markdown is kept as the baseline"
    );
    assert!(one.doc("/mutable").raw_html.is_none());

    let two = go(&rig, Spec::new(site.url("/mutable"), tracking(None))).await;
    let t2 = two.doc("/mutable").change_tracking.unwrap();
    assert_eq!(t2.change_status, ChangeStatus::Same);
    assert_eq!(t2.previous_scrape_at.unwrap(), rfc3339(one.page("/mutable")));
    assert_eq!(
        two.doc("/mutable").cache_state,
        CacheState::Miss,
        "changeTracking bypasses maxAge"
    );
    assert_eq!(site.count("/mutable"), 2);

    site.set_page(200, &mutable_page("new text"));
    let three = go(&rig, Spec::new(site.url("/mutable"), tracking(None))).await;
    let t3 = three.doc("/mutable").change_tracking.unwrap();
    assert_eq!(t3.change_status, ChangeStatus::Changed);
    assert_eq!(t3.previous_scrape_at.unwrap(), rfc3339(two.page("/mutable")));
    let diff = t3.diff.unwrap();
    let text = diff["text"].as_str().unwrap();
    assert!(text.contains("-old text") && text.contains("+new text"), "{text}");
    assert!(diff["json"]["files"].is_array());
    assert!(t3.json.is_none());

    site.set_page(404, "<html><body><main><h1>Gone</h1></main></body></html>");
    let four = go(&rig, Spec::new(site.url("/mutable"), tracking(None))).await;
    let t4 = four.doc("/mutable").change_tracking.unwrap();
    assert_eq!(t4.change_status, ChangeStatus::Removed);
    assert_eq!(four.page("/mutable").status, 404);
    assert_eq!(t4.previous_scrape_at.unwrap(), rfc3339(three.page("/mutable")));
}

#[tokio::test]
async fn change_tracking_tags_keep_independent_histories() {
    let (site, rig) = (start().await, Rig::new().await);
    site.set_page(200, &mutable_page("same text"));
    go(&rig, Spec::new(site.url("/mutable"), tracking(Some("a")))).await;
    let a = go(&rig, Spec::new(site.url("/mutable"), tracking(Some("a")))).await;
    assert_eq!(
        a.doc("/mutable").change_tracking.unwrap().change_status,
        ChangeStatus::Same
    );
    assert_eq!(a.doc("/mutable").change_tag.as_deref(), Some("a"));
    let b = go(&rig, Spec::new(site.url("/mutable"), tracking(Some("b")))).await;
    assert_eq!(
        b.doc("/mutable").change_tracking.unwrap().change_status,
        ChangeStatus::New
    );
    let untagged = go(&rig, Spec::new(site.url("/mutable"), tracking(None))).await;
    assert_eq!(
        untagged.doc("/mutable").change_tracking.unwrap().change_status,
        ChangeStatus::New
    );
}

#[tokio::test]
async fn change_tracking_json_mode_diffs_the_llm_extraction_of_both_versions() {
    let (site, rig) = (start().await, Rig::new().await);
    let llm = mock_llm();
    let options = opts(vec![
        FormatSpec::Markdown,
        FormatSpec::ChangeTracking {
            modes: vec![ChangeMode::Json],
            schema: Some(schema()),
            prompt: Some("extract the price".to_owned()),
            tag: None,
        },
    ]);
    site.set_page(200, &mutable_page("price: 10"));
    go(&rig, Spec::new(site.url("/mutable"), options.clone()).llm(&llm)).await;
    assert!(
        llm.calls().is_empty(),
        "nothing to compare with on the first scrape"
    );

    site.set_page(200, &mutable_page("price: 12"));
    let changed = go(&rig, Spec::new(site.url("/mutable"), options.clone()).llm(&llm)).await;
    let result = changed.doc("/mutable").change_tracking.unwrap();
    assert_eq!(result.change_status, ChangeStatus::Changed);
    assert_eq!(
        result.json.unwrap(),
        json!({"price": {"previous": "10", "current": "12"}})
    );
    assert!(result.diff.is_none(), "git-diff was not requested");
    let calls = llm.calls();
    assert_eq!(calls.len(), 2, "previous and current markdown");
    assert_eq!(calls[0].schema, Some(schema()));
    assert!(calls[0].user.contains("price: 10") && calls[1].user.contains("price: 12"));
    assert!(changed.doc("/mutable").llm_tokens > 0);
    // markdown was requested here, so the response keeps it
    assert!(changed.markdown("/mutable").await.contains("price: 12"));

    // both modes at once
    let both = ScrapeOptions {
        formats: vec![FormatSpec::ChangeTracking {
            modes: vec![ChangeMode::GitDiff, ChangeMode::Json],
            schema: Some(schema()),
            prompt: None,
            tag: Some("both".to_owned()),
        }],
        ..md()
    };
    site.set_page(200, &mutable_page("price: 12"));
    go(&rig, Spec::new(site.url("/mutable"), both.clone()).llm(&llm)).await;
    site.set_page(200, &mutable_page("price: 15"));
    let r = go(&rig, Spec::new(site.url("/mutable"), both).llm(&llm)).await;
    let result = r.doc("/mutable").change_tracking.unwrap();
    assert!(result.diff.is_some() && result.json.is_some());
}

#[tokio::test]
async fn change_tracking_json_mode_without_an_llm_fails_the_page() {
    let (site, rig) = (start().await, Rig::new().await);
    let options = opts(vec![FormatSpec::ChangeTracking {
        modes: vec![ChangeMode::Json],
        schema: Some(schema()),
        prompt: None,
        tag: None,
    }]);
    let done = go(&rig, Spec::new(site.url("/mutable"), options)).await;
    assert_eq!(
        done.row("/mutable").await.denial_reason.as_deref(),
        Some("llm_not_configured")
    );
}

// ---- LLM formats ----------------------------------------------------------------------------------

#[tokio::test]
async fn llm_formats_answer_from_the_page_markdown_and_count_tokens() {
    let (site, rig) = (start().await, Rig::new().await);
    let llm = mock_llm();
    let options = opts(vec![
        FormatSpec::Summary,
        FormatSpec::Question {
            question: "What is the plan?".to_owned(),
        },
        FormatSpec::Highlights {
            query: "pricing".to_owned(),
        },
        FormatSpec::Query {
            prompt: "Name the price".to_owned(),
            mode: crawlx_core::scrape::QueryMode::Freeform,
        },
        FormatSpec::Json {
            schema: Some(schema()),
            prompt: Some("extract the price".to_owned()),
        },
    ]);
    let done = go(&rig, Spec::new(site.url("/page"), options).llm(&llm)).await;
    let doc = done.doc("/page");
    assert_eq!(doc.summary.as_deref(), Some("A pricing page."));
    assert_eq!(doc.answer.as_deref(), Some("re: What is the plan?"));
    assert_eq!(doc.highlights, Some(vec!["Main text here.".to_owned()]));
    assert_eq!(doc.query.as_deref(), Some("re: Name the price"));
    assert_eq!(doc.json, Some(json!({"price": "10"})));
    let calls = llm.calls();
    assert_eq!(calls.len(), 5);
    assert!(
        calls.iter().all(|c| c.user.contains("Main text here.")),
        "the markdown is the input"
    );
    assert_eq!(calls[4].schema, Some(schema()));
    assert!(doc.llm_tokens >= 5, "{}", doc.llm_tokens);
    assert!(
        done.page("/page").markdown.is_none(),
        "markdown was not requested"
    );
}

#[tokio::test]
async fn llm_formats_without_an_llm_fail_before_anything_is_fetched() {
    let (site, rig) = (start().await, Rig::new().await);
    for format in [
        FormatSpec::Summary,
        FormatSpec::Json {
            schema: Some(schema()),
            prompt: None,
        },
        FormatSpec::Question {
            question: "q".to_owned(),
        },
    ] {
        let done = go(
            &rig,
            Spec::new(site.url("/page"), opts(vec![FormatSpec::Markdown, format])),
        )
        .await;
        let row = done.row("/page").await;
        assert_eq!(
            (row.status, row.denial_reason.as_deref()),
            (FrontierStatus::Failed, Some("llm_not_configured"))
        );
        assert!(done.report.pages.is_empty());
        assert_eq!(
            done.events("page.failed").await[0]["reason"],
            "llm_not_configured"
        );
    }
    assert_eq!(site.count("/page"), 0);
}

#[tokio::test]
async fn an_llm_error_fails_the_page_as_llm_failed() {
    let (site, rig) = (start().await, Rig::new().await);
    let llm = Arc::new(MockLlm::scripted(vec![Err(LlmError::Status { status: 503 })]));
    let done = go(
        &rig,
        Spec::new(site.url("/page"), opts(vec![FormatSpec::Summary])).llm(&llm),
    )
    .await;
    let row = done.row("/page").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("llm_failed"))
    );
    assert!(done.report.pages.is_empty());
    assert!(done.events("page.failed").await[0]["message"]
        .as_str()
        .unwrap()
        .contains("503"));
}

// ---- job kinds -----------------------------------------------------------------------------------------

#[tokio::test]
async fn batch_urls_are_seeded_at_depth_zero_across_hosts() {
    let (one, two, rig) = (start().await, start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(one.url("/page"), md())
            .kind(JobKind::Batch)
            .urls(&[two.url("/more"), one.url("/nav-link")]),
    )
    .await;
    let rows = done.frontier().await;
    assert_eq!(rows.len(), 3, "{}", summary(&rows));
    assert!(
        rows.iter()
            .all(|r| r.depth == 0 && r.status == FrontierStatus::Succeeded),
        "{}",
        summary(&rows)
    );
    assert_eq!(done.report.pages.len(), 3);
    let batch_page = done.page("/more");
    assert!(batch_page.url.url.as_str().starts_with(&two.base));
    assert_eq!(batch_page.metadata["request"]["tag"], "batch");
    assert_eq!(two.count("/more"), 1);
    assert_eq!(one.count("/nav-link"), 1);
    // a batch scrape follows no links: /more of the first site was never requested
    assert_eq!(one.count("/more"), 0);
}

#[tokio::test]
async fn crawl_jobs_follow_links_and_store_every_page_as_a_document() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/page"), md())
            .kind(JobKind::Crawl)
            .tweak(|c| c.scope.crawl_entire_domain = true),
    )
    .await;
    for path in ["/page", "/more", "/nav-link"] {
        assert_eq!(done.doc(path).status_code, 200, "{path}");
    }
    let ext = done
        .frontier()
        .await
        .into_iter()
        .find(|e| e.url.url.host_str() == Some("other.example"))
        .unwrap();
    assert_eq!(ext.depth, 1);
    assert!(done
        .report
        .egress
        .dialed_hosts
        .iter()
        .all(|(host, _)| host != "other.example"));
    // a crawl needs the live links: without the `links` format it never serves the cache
    let again = go(
        &rig,
        Spec::new(site.url("/page"), md())
            .kind(JobKind::Crawl)
            .tweak(|c| c.scope.crawl_entire_domain = true),
    )
    .await;
    assert_eq!(again.doc("/page").cache_state, CacheState::Miss);
    assert_eq!(site.count("/page"), 2);
}

/// The entry URL outside `includePaths` goes through the engine like any page, but only to start
/// discovery: its row ends `policy_blocked` `not_included`, no document is stored for it, and
/// the links that match are crawled.
#[tokio::test]
async fn a_crawl_job_scrapes_a_seed_outside_include_paths_for_its_links_only() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/page"), md())
            .kind(JobKind::Crawl)
            .tweak(|c| c.scope.include_paths = vec!["^/more$".to_owned()]),
    )
    .await;
    let stored: Vec<&str> = done.report.pages.iter().map(|p| p.url.url.path()).collect();
    assert_eq!(stored, ["/more"]);
    assert_eq!(site.count("/page"), 1, "the seed is scraped exactly once");
    assert_eq!(site.count("/nav-link"), 0);
    let seed = done.row("/page").await;
    assert_eq!(
        (seed.status, seed.depth, seed.denial_reason.as_deref()),
        (FrontierStatus::PolicyBlocked, 0, Some("not_included"))
    );
    let nav = done.row("/nav-link").await;
    assert_eq!(
        (nav.status, nav.denial_reason.as_deref()),
        (FrontierStatus::PolicyBlocked, Some("not_included"))
    );
    assert_eq!(done.row("/more").await.status, FrontierStatus::Succeeded);
    let u = done.report.counters.urls;
    assert_eq!((u.attempted, u.succeeded, u.policy_blocked), (1, 1, 3), "{u:?}");
    assert!(u.invariants_hold(), "{u:?}");
}

#[tokio::test]
async fn map_jobs_use_the_plain_static_plane_and_end_discoveries_as_depth_exceeded() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/page"), md())
            .kind(JobKind::Map)
            .tweak(|c| c.scope.crawl_entire_domain = true),
    )
    .await;
    let rows = done.frontier().await;
    let blocked: Vec<&FrontierEntry> = rows.iter().filter(|r| r.depth == 1).collect();
    assert!(blocked.len() >= 3, "{}", summary(&rows));
    assert!(
        blocked.iter().all(|r| r.status == FrontierStatus::PolicyBlocked),
        "{}",
        summary(&rows)
    );
    let reason = |path: &str| {
        blocked
            .iter()
            .find(|r| r.url.url.path() == path)
            .and_then(|r| r.denial_reason.clone())
    };
    for page in ["/more", "/nav-link"] {
        assert_eq!(
            reason(page).as_deref(),
            Some("depth_exceeded"),
            "{}",
            summary(&rows)
        );
    }
    // the plain plane's other filters keep working: media extensions are refused first
    assert_eq!(reason("/img/a.png").as_deref(), Some("extension_filtered"));
    assert!(blocked.iter().any(|r| r.url.url.path() == "/more"));
    assert_eq!(site.count("/more"), 0, "map lists links, it does not scrape them");
    let seed = done.page("/page");
    assert!(
        seed.metadata.get("scrape").is_none(),
        "no scrape document: the engine is not involved"
    );
    assert!(seed.links.contains(&site.url("/more")));
    // a failing seed keeps the static plane's `http_404` row
    let missing = go(&rig, Spec::new(site.url("/missing"), md()).kind(JobKind::Map)).await;
    let row = missing.row("/missing").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("http_404"))
    );
    assert!(missing.report.pages.is_empty());
}

#[tokio::test]
async fn scrape_runs_start_no_browser_sessions_whatever_their_mode() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/page"), md()).tweak(|c| c.mode = CrawlMode::Hybrid),
    )
    .await;
    assert_eq!(done.doc("/page").status_code, 200);
    assert!(done.report.sessions.is_empty());
    assert_eq!(done.report.browser_launches, 0);
}

// ---- time and failures ---------------------------------------------------------------------------------------

#[tokio::test]
async fn timeout_bounds_the_whole_page() {
    let (site, rig) = (start().await, Rig::new().await);
    let started = std::time::Instant::now();
    let done = go(
        &rig,
        Spec::new(
            site.url("/slow"),
            ScrapeOptions {
                timeout_ms: 1_000,
                ..md()
            },
        ),
    )
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    let row = done.row("/slow").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Unreachable, Some("scrape_timeout"))
    );
    assert!(done.report.pages.is_empty());
    let failed = done.events("page.failed").await;
    assert_eq!(failed[0]["reason"], "scrape_timeout");
    assert!(failed[0]["message"].as_str().unwrap().contains("1000"));
}

#[tokio::test]
async fn an_unreachable_host_fails_the_row_as_unreachable() {
    let rig = Rig::new().await;
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let done = go(&rig, Spec::new(format!("http://127.0.0.1:{port}/page"), md())).await;
    let row = done.row("/page").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Unreachable, Some("unreachable"))
    );
    assert_eq!(done.events("page.failed").await[0]["reason"], "unreachable");
}

#[tokio::test]
async fn a_private_target_without_authorization_fails_as_egress_denied() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/page"), md()).tweak(|c| {
            c.safety.allow_private_networks = false;
            c.safety.authorization_record_ref = None;
        }),
    )
    .await;
    let row = done.row("/page").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("egress_denied"))
    );
    assert_eq!(site.count("/page"), 0);
}

// ---- renderer --------------------------------------------------------------------------------------------------

fn shot_options() -> ScrapeOptions {
    ScrapeOptions {
        formats: vec![
            FormatSpec::Markdown,
            FormatSpec::RawHtml,
            FormatSpec::Screenshot {
                full_page: true,
                quality: None,
                viewport: None,
            },
        ],
        wait_for_ms: 250,
        actions: vec![
            ScrapeAction::Screenshot {
                full_page: false,
                quality: Some(80),
                viewport: None,
            },
            ScrapeAction::Scrape,
            ScrapeAction::ExecuteJavascript {
                script: "document.title".to_owned(),
            },
            ScrapeAction::Pdf {
                format: None,
                landscape: false,
                scale: None,
            },
        ],
        ..ScrapeOptions::default()
    }
}

#[tokio::test]
async fn rendered_pages_store_the_dom_screenshot_and_action_results() {
    let (site, rig) = (start().await, Rig::new().await);
    let dom = "<html><head><title>Rendered</title></head><body><main><h1>Rendered</h1><p>Hydrated text.</p></main></body></html>";
    let renderer = Scripted::new(move |req| {
        let mut r = rendered(&req.request.url.url, dom);
        r.final_url = Url::parse(&format!("{}#after", req.request.url.url)).unwrap();
        r.screenshot = Some(Shot {
            bytes: PNG.to_vec(),
            content_type: "image/png",
        });
        r.actions = ActionOutputs {
            screenshots: vec![Shot {
                bytes: b"\xFF\xD8jpeg".to_vec(),
                content_type: "image/jpeg",
            }],
            scrapes: vec![crawlx_core::scrape::ActionScrape {
                url: req.request.url.url.to_string(),
                html: "<p>mid</p>".to_owned(),
            }],
            javascript_returns: vec![crawlx_core::scrape::JavascriptReturn {
                kind: "string".to_owned(),
                value: json!("Rendered"),
            }],
            pdfs: vec![Shot {
                bytes: pdf(&["Visible safe marker"]),
                content_type: "application/pdf",
            }],
            ..ActionOutputs::default()
        };
        Ok(r)
    });
    let done = go(
        &rig,
        Spec::new(site.url("/page"), shot_options()).renderer(&renderer),
    )
    .await;
    assert_eq!(renderer.calls(), vec![(site.url("/page"), 250, 4)]);
    assert_eq!(
        site.count("/page"),
        0,
        "the HTTP plane did not fetch: the renderer did"
    );
    assert!(done.markdown("/page").await.contains("Hydrated text."));
    let doc = done.doc("/page");
    assert_eq!(doc.final_url, format!("{}#after", site.url("/page")));
    let raw = done.blob(doc.raw_html.as_ref().unwrap()).await;
    assert_eq!(
        raw,
        dom.as_bytes(),
        "rawHtml of the browser plane is the serialized DOM"
    );
    let shot = doc.screenshot.unwrap();
    assert_eq!(shot.content_type, "image/png");
    assert_eq!(done.blob(&shot).await, PNG);
    let actions = doc.actions.unwrap();
    assert_eq!(actions.screenshots.len(), 1);
    assert_eq!(actions.screenshots[0].content_type, "image/jpeg");
    assert_eq!(done.blob(&actions.screenshots[0]).await, b"\xFF\xD8jpeg");
    assert_eq!(actions.pdfs.len(), 1);
    assert_eq!(actions.pdfs[0].content_type, "application/pdf");
    let native = done.blob(&actions.pdfs[0]).await;
    let parsed =
        crawlx_extract::parse::pdf::extract_pdf(&native, &crawlx_extract::parse::pdf::PdfOptions::default())
            .unwrap();
    assert_eq!(parsed.total_pages, 1);
    assert!(parsed.text.contains("Visible safe marker"));
    assert_eq!(actions.scrapes[0].html, "<p>mid</p>");
    assert_eq!(actions.javascript_returns[0].value, json!("Rendered"));
}

#[tokio::test]
async fn rendered_pages_keep_the_browsers_status_and_headers() {
    let (site, rig) = (start().await, Rig::new().await);
    let renderer = Scripted::new(|req| {
        let mut r = rendered(
            &req.request.url.url,
            "<html><body><main><h1>Nope</h1></main></body></html>",
        );
        r.status = 404;
        r.headers = vec![("x-served-by".to_owned(), "edge-1".to_owned())];
        Ok(r)
    });
    let done = go(
        &rig,
        Spec::new(
            site.url("/page"),
            ScrapeOptions {
                wait_for_ms: 10,
                ..md()
            },
        )
        .renderer(&renderer),
    )
    .await;
    assert_eq!(done.row("/page").await.status, FrontierStatus::Succeeded);
    assert_eq!(done.page("/page").status, 404);
    assert_eq!(done.doc("/page").status_code, 404);
    assert_eq!(
        done.page("/page").metadata["response_headers"]["x-served-by"],
        "edge-1"
    );
}

#[tokio::test]
async fn render_errors_map_to_the_reason_codes() {
    let (site, rig) = (start().await, Rig::new().await);
    type Make = fn() -> RenderError;
    let cases: [(Make, FrontierStatus, &str); 6] = [
        (
            || RenderError::Timeout(900),
            FrontierStatus::Unreachable,
            "scrape_timeout",
        ),
        (
            || RenderError::Navigation("dns".to_owned()),
            FrontierStatus::Unreachable,
            "unreachable",
        ),
        (
            || RenderError::EgressDenied("private".to_owned()),
            FrontierStatus::Failed,
            "egress_denied",
        ),
        (
            || RenderError::Action {
                index: 2,
                kind: "click",
                reason: "no_match".to_owned(),
            },
            FrontierStatus::Failed,
            "action_failed",
        ),
        (
            || RenderError::Browser("crash".to_owned()),
            FrontierStatus::Failed,
            "render_failed",
        ),
        (
            || RenderError::Unavailable("no chromium".to_owned()),
            FrontierStatus::Failed,
            "render_failed",
        ),
    ];
    for (make, status, code) in cases {
        let renderer = Scripted::new(move |_| Err(make()));
        let options = ScrapeOptions {
            wait_for_ms: 10,
            ..md()
        };
        let done = go(&rig, Spec::new(site.url("/page"), options).renderer(&renderer)).await;
        let row = done.row("/page").await;
        assert_eq!(
            (row.status, row.denial_reason.as_deref()),
            (status, Some(code)),
            "{code}"
        );
        assert!(done.report.pages.is_empty());
        let failed = done.events("page.failed").await;
        assert_eq!(failed[0]["reason"], code);
        assert_eq!(failed[0]["url"], site.url("/page"));
        assert!(failed[0]["message"].is_string());
    }
}

#[tokio::test]
async fn a_cancelled_render_abandons_the_row() {
    let (site, rig) = (start().await, Rig::new().await);
    let renderer = Scripted::new(|_| Err(RenderError::Cancelled));
    let options = ScrapeOptions {
        wait_for_ms: 10,
        ..md()
    };
    let done = go(&rig, Spec::new(site.url("/page"), options).renderer(&renderer)).await;
    let row = done.row("/page").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Abandoned, Some("run_stopped"))
    );
    assert!(done.events("page.failed").await.is_empty());
}

#[tokio::test]
async fn failure_messages_never_contain_configured_header_or_cookie_values() {
    let (site, rig) = (start().await, Rig::new().await);
    let header_secret = "tok-4f9a8b2c71d0";
    let cookie_secret = "sess-9e8d7c6b5a40";
    let renderer = Scripted::new(move |_| {
        Err(RenderError::Navigation(format!(
            "net::ERR_FAILED while sending X-Api-Token: {header_secret} and cookie sid={cookie_secret}"
        )))
    });
    let options = ScrapeOptions {
        wait_for_ms: 10,
        ..md()
    };
    let done = go(
        &rig,
        Spec::new(site.url("/page"), options)
            .renderer(&renderer)
            .tweak(move |c| {
                c.fetch.set_header("X-Api-Token", header_secret).unwrap();
                c.fetch
                    .cookies
                    .push(crawlx_core::request_controls::FetchCookie::new(
                        "sid",
                        cookie_secret,
                    ));
            }),
    )
    .await;
    let failed = done.events("page.failed").await;
    let message = failed[0]["message"].as_str().unwrap();
    assert!(message.contains("net::ERR_FAILED"), "{message}");
    assert!(
        !message.contains(header_secret) && !message.contains(cookie_secret),
        "{message}"
    );
    assert!(!failed[0].to_string().contains(header_secret));
}

// ---- PDF ------------------------------------------------------------------------------------------------------

fn pdf_options(parsers: Vec<ParserSpec>) -> ScrapeOptions {
    ScrapeOptions { parsers, ..md() }
}

fn pdf_with(f: impl FnOnce(&mut ParserSpec)) -> ParserSpec {
    let mut p = ParserSpec::pdf();
    f(&mut p);
    p
}

#[tokio::test]
async fn pdf_bodies_are_parsed_into_markdown_with_page_counts() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(&rig, Spec::new(site.url("/doc.pdf"), md())).await;
    assert_eq!(done.row("/doc.pdf").await.status, FrontierStatus::Succeeded);
    let markdown = done.markdown("/doc.pdf").await;
    assert!(
        markdown.contains("Quarterly revenue grew") && markdown.contains("Second page costs fell"),
        "{markdown}"
    );
    let doc = done.doc("/doc.pdf");
    assert_eq!((doc.num_pages, doc.total_pages), (Some(2), Some(2)));
    assert_eq!(doc.content_type.as_deref(), Some("application/pdf"));
    assert_eq!(
        done.page("/doc.pdf").content_type.as_deref(),
        Some("application/pdf")
    );
}

#[tokio::test]
async fn pdf_parser_options_limit_and_mark_pages() {
    let (site, rig) = (start().await, Rig::new().await);
    let first_only = go(
        &rig,
        Spec::new(
            site.url("/doc.pdf"),
            pdf_options(vec![ParserSpec::Pdf {
                mode: PdfMode::Fast,
                max_pages: Some(1),
                pages: false,
                blocks: false,
                page_markers: false,
            }]),
        ),
    )
    .await;
    let md1 = first_only.markdown("/doc.pdf").await;
    assert!(
        md1.contains("Quarterly revenue grew") && !md1.contains("Second page"),
        "{md1}"
    );
    let doc = first_only.doc("/doc.pdf");
    assert_eq!((doc.num_pages, doc.total_pages), (Some(1), Some(2)));
    assert!(doc.pages.is_none() && doc.blocks.is_none());
    assert!(
        doc.warning
            .as_deref()
            .unwrap()
            .contains("only the first 1 were parsed"),
        "{:?}",
        doc.warning
    );

    let marked = go(
        &rig,
        Spec::new(
            site.url("/doc.pdf"),
            pdf_options(vec![pdf_with(|p| {
                if let ParserSpec::Pdf { page_markers, .. } = p {
                    *page_markers = true;
                }
            })]),
        ),
    )
    .await;
    let text = marked.markdown("/doc.pdf").await;
    assert!(
        text.contains("\n\n---\n\n<!-- page 2 -->\n\n") && !text.contains("<!-- page 1 -->"),
        "markers sit between pages only: {text}"
    );
}

#[tokio::test]
async fn the_pages_option_returns_the_markdown_of_every_physical_page() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(
            site.url("/doc.pdf"),
            pdf_options(vec![pdf_with(|p| {
                if let ParserSpec::Pdf { pages, .. } = p {
                    *pages = true;
                }
            })]),
        ),
    )
    .await;
    let pages = done.doc("/doc.pdf").pages.unwrap();
    assert_eq!(
        pages.iter().map(|p| p.page_number).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(pages[0].markdown.contains("Quarterly revenue grew") && !pages[0].markdown.contains("Second"));
    assert!(pages[1].markdown.contains("Second page costs fell"));
    let first = go(&rig, Spec::new(site.url("/doc.pdf"), md())).await;
    assert!(first.doc("/doc.pdf").pages.is_none(), "absent unless asked for");
}

#[tokio::test]
async fn the_blocks_option_returns_typed_layout_blocks_in_the_compatibility_shape() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(
            site.url("/doc.pdf"),
            pdf_options(vec![pdf_with(|p| {
                if let ParserSpec::Pdf { blocks, .. } = p {
                    *blocks = true;
                }
            })]),
        ),
    )
    .await;
    let blocks = done.doc("/doc.pdf").blocks.unwrap();
    let pages = blocks.as_array().unwrap();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0]["pageNumber"], 1);
    assert_eq!(pages[1]["pageNumber"], 2);
    assert_eq!(pages[0]["status"], "ok");
    assert!(pages[0]["width"].is_number() && pages[0]["height"].is_number());
    let item = &pages[0]["items"][0];
    assert_eq!(item["id"], "p1.b0");
    assert!(
        item["type"].is_string()
            && item["content"]
                .as_str()
                .unwrap()
                .contains("Quarterly revenue grew")
    );
    assert_eq!(item["readingOrder"], 0);
    assert_eq!(item["bbox"].as_array().unwrap().len(), 4);
    assert!(item["markdownSpan"].is_array());
    assert!(item["confidence"].is_object());
    assert!(done.markdown("/doc.pdf").await.contains("Second page costs fell"));
}

#[tokio::test]
async fn ocr_mode_extracts_the_text_layer_and_says_ocr_is_unavailable() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(
            site.url("/doc.pdf"),
            pdf_options(vec![pdf_with(|p| {
                if let ParserSpec::Pdf { mode, .. } = p {
                    *mode = PdfMode::Ocr;
                }
            })]),
        ),
    )
    .await;
    assert_eq!(done.row("/doc.pdf").await.status, FrontierStatus::Succeeded);
    assert!(done.markdown("/doc.pdf").await.contains("Quarterly revenue grew"));
    let doc = done.doc("/doc.pdf");
    assert!(
        doc.warning.as_deref().unwrap().contains("ocr_unavailable"),
        "{:?}",
        doc.warning
    );
    assert_eq!(doc.num_pages, Some(2));
}

#[tokio::test]
async fn a_pdf_without_a_text_layer_is_a_document_with_a_warning() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(&rig, Spec::new(site.url("/blank.pdf"), md())).await;
    assert_eq!(done.row("/blank.pdf").await.status, FrontierStatus::Succeeded);
    assert_eq!(done.markdown("/blank.pdf").await.trim(), "");
    let doc = done.doc("/blank.pdf");
    assert!(
        doc.warning.as_deref().unwrap().contains("ocr_unavailable"),
        "{:?}",
        doc.warning
    );
    assert_eq!(doc.total_pages, Some(1));
}

#[tokio::test]
async fn without_a_pdf_parser_the_pdf_is_returned_as_base64_markdown() {
    use base64::Engine as _;
    let (site, rig) = (start().await, Rig::new().await);
    let bytes = pdf(&["Quarterly revenue grew", "Second page costs fell"]);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    for parsers in [Vec::new(), vec![ParserSpec::Image]] {
        let done = go(&rig, Spec::new(site.url("/doc.pdf"), pdf_options(parsers))).await;
        assert_eq!(done.row("/doc.pdf").await.status, FrontierStatus::Succeeded);
        assert_eq!(done.markdown("/doc.pdf").await, encoded);
        let doc = done.doc("/doc.pdf");
        assert_eq!(
            (doc.num_pages, doc.total_pages),
            (None, None),
            "nothing was parsed"
        );
        assert!(doc.pages.is_none() && doc.blocks.is_none());
    }
    // an empty list keeps HTML working
    let html = go(&rig, Spec::new(site.url("/page"), pdf_options(Vec::new()))).await;
    assert!(html.markdown("/page").await.contains("Main text here."));
}

#[tokio::test]
async fn an_unreadable_pdf_fails_as_unsupported_content() {
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(&rig, Spec::new(site.url("/bad.pdf"), md())).await;
    let row = done.row("/bad.pdf").await;
    assert_eq!(
        (row.status, row.denial_reason.as_deref()),
        (FrontierStatus::Failed, Some("unsupported_content"))
    );
}

// ---- the worker lease loop --------------------------------------------------------------------------------------

#[tokio::test]
async fn the_lease_loop_executes_a_queued_scrape_run_through_the_engine() {
    use crawlx_core::counters::{PlaneCounters, RunStatus};
    use crawlx_core::repo::CrawlRun;
    use crawlx_core::{Clock, CrawlRunId, SystemClock};
    use crawlx_worker::lease_loop::run_with;
    use tokio_util::sync::CancellationToken;

    let (site, rig) = (start().await, Rig::new().await);
    // the mode is whatever the creator wrote: a scrape run is executed as a static run
    let mut spec = Spec::new(
        site.url("/page"),
        opts(vec![FormatSpec::Markdown, FormatSpec::Summary]),
    )
    .tweak(|c| c.mode = CrawlMode::Hybrid);
    let llm = mock_llm();
    let mut crawl = crawl_of(&mut spec);
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: rig.stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    rig.stores.runs.create(&run, None).await.unwrap();
    rig.stores
        .runs
        .create_sessions(&crawlx_scheduler::RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    let mut cfg = config(rig.dir.path(), Some(Arc::clone(&llm)), None);
    cfg.idle_exit_after = Some(Duration::from_millis(600));
    let record = common::authorization::verified_record(&crawl, rig.stores.tenant);
    let stores = rig
        .stores
        .clone()
        .with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    run_with(cfg, stores, None, CancellationToken::new())
        .await
        .unwrap();
    let row = rig.stores.runs.get(run.id).await.unwrap();
    assert_eq!(row.status, RunStatus::Completed);
    let pages = rig.stores.pages.list(run.id).await.unwrap();
    assert_eq!(pages.len(), 1);
    let doc = ScrapeDocument::from_page_metadata(&pages[0].metadata).unwrap();
    assert_eq!(doc.summary.as_deref(), Some("A pricing page."));
    assert!(pages[0].markdown.is_some());
    assert_eq!(row.counters.urls.succeeded, 1);
}

#[test]
fn local_acquisition_entry_does_not_embed_orchestration_state_in_caller_future() {
    let crawl = CreateCrawl::new(Url::parse("http://127.0.0.1:1/not-dispatched").unwrap());
    let pending = crawlx_worker::run_local_with(LocalRun::new(crawl, WorkerConfig::default()));
    // No polling or I/O: the public run future must stay pointer-sized regardless of
    // enabled acquisition, extraction, protocol and session orchestration branches.
    assert_eq!(std::mem::size_of_val(&pending), std::mem::size_of::<usize>());
    drop(pending);
}

fn native_policy(crawl: &mut CreateCrawl) {
    crawl.acquisition = Some(crawlx_core::acquisition::AcquisitionPolicyV1::default());
}

#[tokio::test]
async fn native_acquisition_validates_real_http_without_keyword_false_positives() {
    let site = start().await;
    for (status, body, expected) in [
        (200, "<form id=challenge-form>Verify you are human</form>", "challenge"),
        (200, "<article><h1>Edge CAPTCHA research</h1><p>An ordinary article about challenge detection.</p></article>", "valid"),
        (200, "<main><h1>Contact us</h1><form><div class=g-recaptcha></div></form></main>", "valid"), // wire-compat: widget marker
        (200, "<article>News</article><input type=password>", "valid"),
        (401, "<main>Authentication required</main>", "auth_required"),
        (429, "<form id=challenge-form>Verify you are human</form>", "rate_limited"),
        (503, "<main>Unavailable</main>", "target_error"),
        (204, "", "valid"),
    ] {
        let rig = Rig::new().await;
        site.set_page(status, body);
        let before = site.count("/mutable");
        let done = go(&rig, Spec::new(site.url("/mutable"), md()).tweak(native_policy)).await;
        let receipt = &done.page("/mutable").metadata["acquisition"];
        assert_eq!(site.count("/mutable") - before, 1, "{status}/{expected}");
        assert_eq!(receipt["targetStatus"], status);
        assert_eq!(receipt["validation"]["category"], expected);
        assert_eq!(receipt["transportSucceeded"], true);
        assert_eq!(receipt["validation"]["contentAccepted"], expected == "valid");
        assert_eq!(receipt["representation"], "wire_response");
        assert_eq!(receipt["renderedDom"], Value::Null);
        assert_eq!(receipt["backend"]["implementation"], "crawlx-fetch/reqwest-rustls");
        assert_eq!(receipt["backend"]["buildDigest"], Value::Null);
        assert!(receipt["backend"]["limitations"].as_array().unwrap().contains(&json!("build_digest_unavailable")));
    }
}

#[tokio::test]
async fn native_acquisition_checks_mime_selectors_completeness_and_redirect_truth() {
    let site = start().await;
    let rig = Rig::new().await;
    let done = go(
        &rig,
        Spec::new(site.url("/native-header-challenge"), md()).tweak(native_policy),
    )
    .await;
    assert_eq!(
        done.page("/native-header-challenge").metadata["acquisition"]["validation"]["category"],
        "challenge"
    );

    let rig = Rig::new().await;
    let done = go(
        &rig,
        Spec::new(site.url("/native-wrong-mime"), md()).tweak(|crawl| {
            native_policy(crawl);
            crawl
                .acquisition
                .as_mut()
                .unwrap()
                .validation
                .expected_content_types = vec!["text/html".into()];
        }),
    )
    .await;
    assert_eq!(
        done.page("/native-wrong-mime").metadata["acquisition"]["validation"]["category"],
        "content_mismatch"
    );

    let rig = Rig::new().await;
    let done = go(
        &rig,
        Spec::new(site.url("/mutable"), md()).tweak(|crawl| {
            native_policy(crawl);
            crawl.acquisition.as_mut().unwrap().validation.required_selectors = vec!["#expected".into()];
        }),
    )
    .await;
    assert_eq!(
        done.page("/mutable").metadata["acquisition"]["validation"]["category"],
        "content_mismatch"
    );

    let rig = Rig::new().await;
    site.set_page(200, &format!("<main>{}</main>", "long document ".repeat(100)));
    let done = go(
        &rig,
        Spec::new(site.url("/mutable"), md()).tweak(|crawl| {
            native_policy(crawl);
            let policy = crawl.acquisition.as_mut().unwrap();
            policy.max_decoded_bytes = 64;
            policy.validation.required_selectors = vec!["#not-in-prefix".into()];
        }),
    )
    .await;
    let receipt = &done.page("/mutable").metadata["acquisition"];
    assert_eq!(receipt["truncated"], true);
    assert_eq!(receipt["decodedBytes"], 64);
    assert_eq!(receipt["validation"]["category"], "indeterminate");

    let rig = Rig::new().await;
    let done = go(
        &rig,
        Spec::new(site.url("/native-redirect"), md()).tweak(native_policy),
    )
    .await;
    let receipt = &done.page("/native-redirect").metadata["acquisition"];
    assert_eq!(receipt["finalUrl"], site.url("/mutable"));
    assert_eq!(receipt["finalUrlEvidence"], "observed");
    assert_eq!(receipt["redirects"][0]["status"], 302);
    assert_eq!(receipt["networkRequests"], 2);
}

#[tokio::test]
async fn native_acquisition_global_attempt_cap_stops_status_retries_and_auth_rotation() {
    let site = start().await;
    site.set_page(503, "<main>Unavailable</main>");
    let rig = Rig::new().await;
    let done = go(
        &rig,
        Spec::new(site.url("/mutable"), md()).tweak(|crawl| {
            native_policy(crawl);
            let policy = crawl.acquisition.as_mut().unwrap();
            policy.max_attempts = 2;
            policy.retry_on = vec![crawlx_core::acquisition::RetryClassV1::Target5xx];
            crawl.fetch.retries = 8;
        }),
    )
    .await;
    assert_eq!(site.count("/mutable"), 2);
    let receipt = &done.page("/mutable").metadata["acquisition"];
    assert_eq!(receipt["attempts"], 2);
    assert_eq!(receipt["networkRequests"], 2);
    assert_eq!(receipt["attemptSummaries"].as_array().unwrap().len(), 2);

    let rig = Rig::new().await;
    site.set_page(401, "<main>Sign in</main>");
    let before = site.count("/mutable");
    let mut options = md();
    options.proxy = crawlx_core::scrape::ProxyMode::Auto;
    let done = go(
        &rig,
        Spec::new(site.url("/mutable"), options).tweak(|crawl| {
            native_policy(crawl);
            crawl.acquisition.as_mut().unwrap().retry_on = vec![
                crawlx_core::acquisition::RetryClassV1::Target5xx,
                crawlx_core::acquisition::RetryClassV1::Challenge,
                crawlx_core::acquisition::RetryClassV1::RateLimit,
            ];
        }),
    )
    .await;
    assert_eq!(site.count("/mutable") - before, 1);
    assert_eq!(
        done.page("/mutable").metadata["acquisition"]["validation"]["category"],
        "auth_required"
    );
}

#[tokio::test]
async fn native_acquisition_deadline_and_forbidden_redirect_never_restart_allowance() {
    let site = start().await;
    let rig = Rig::new().await;
    let done = go(
        &rig,
        Spec::new(site.url("/slow"), md()).tweak(|crawl| {
            native_policy(crawl);
            crawl.acquisition.as_mut().unwrap().max_elapsed_ms = 100;
        }),
    )
    .await;
    assert_eq!(site.count("/slow"), 1);
    assert_eq!(
        done.row("/slow").await.denial_reason.as_deref(),
        Some("scrape_timeout")
    );
    let rig = Rig::new().await;
    let done = go(
        &rig,
        Spec::new(site.url("/native-forbidden-redirect"), md()).tweak(native_policy),
    )
    .await;
    assert_eq!(site.count("/native-forbidden-redirect"), 1);
    assert!(done.report.pages.is_empty());
    assert!(matches!(
        done.row("/native-forbidden-redirect").await.status,
        FrontierStatus::PolicyBlocked | FrontierStatus::Failed
    ));
}

#[tokio::test]
async fn native_invalid_selector_and_unattested_browser_refuse_before_target_io() {
    let (site, rig) = (start().await, Rig::new().await);
    let mut spec = Spec::new(site.url("/mutable"), md()).tweak(|crawl| {
        native_policy(crawl);
        crawl.acquisition.as_mut().unwrap().validation.required_selectors = vec!["[".into()];
    });
    let crawl = crawl_of(&mut spec);
    let cfg = config(rig.dir.path(), None, None);
    assert!(
        run_local_with(LocalRun::new(crawl, cfg).with_stores(rig.stores.clone()))
            .await
            .is_err()
    );
    assert_eq!(site.count("/mutable"), 0);
    assert_eq!(site.count("/robots.txt"), 0);

    let rig = Rig::new().await;
    let mut spec = Spec::new(site.url("/mutable"), md()).tweak(|crawl| {
        native_policy(crawl);
        crawl.acquisition.as_mut().unwrap().backend_ids = vec!["native_browser".into()];
    });
    let crawl = crawl_of(&mut spec);
    let renderer = Scripted::new(|request| Ok(rendered(&request.request.url.url, PAGE)));
    let cfg = config(rig.dir.path(), None, Some(Arc::clone(&renderer)));
    assert!(
        run_local_with(LocalRun::new(crawl, cfg).with_stores(rig.stores.clone()))
            .await
            .is_err()
    );
    assert!(renderer.calls().is_empty());
    assert_eq!(site.count("/mutable"), 0);
    assert_eq!(site.count("/robots.txt"), 0);
}

#[tokio::test]
async fn native_inflight_cancel_stops_real_request_without_a_fresh_attempt() {
    let (site, rig) = (start().await, Rig::new().await);
    let mut spec = Spec::new(site.url("/slow"), md()).tweak(native_policy);
    let crawl = crawl_of(&mut spec);
    let cfg = config(rig.dir.path(), None, None);
    let mut local = LocalRun::new(crawl, cfg).with_stores(rig.stores.clone());
    let cancel = tokio_util::sync::CancellationToken::new();
    local.cancel = cancel.clone();
    let hits = Arc::clone(&site.hits);
    let cancellation = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if hits.lock().unwrap().iter().any(|path| path == "/slow") {
                    cancel.cancel();
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    });
    let report = run_local_with(local).await.unwrap();
    cancellation.await.unwrap();
    assert_eq!(site.count("/slow"), 1);
    assert!(report.pages.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_browser_forbidden_redirect_preserves_egress_gate() {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        return;
    }
    let (site, rig) = (start().await, Rig::new().await);
    let done = go(
        &rig,
        Spec::new(site.url("/native-forbidden-redirect"), md()).tweak(|crawl| {
            native_policy(crawl);
            let policy = crawl.acquisition.as_mut().unwrap();
            policy.backend_ids = vec!["native_browser".into()];
            policy.max_attempts = 1;
            policy.max_network_requests = 2;
        }),
    )
    .await;
    assert_eq!(site.count("/native-forbidden-redirect"), 1);
    assert!(done.report.pages.is_empty());
    assert!(matches!(
        done.row("/native-forbidden-redirect").await.status,
        FrontierStatus::PolicyBlocked | FrontierStatus::Failed
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_http_browser_fallback_shares_two_real_navigation_attempts() {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        eprintln!("skipped: CRAWLX_CHROMIUM_PATH is not set");
        return;
    }
    let (site, rig) = (start().await, Rig::new().await);
    let options = opts(vec![FormatSpec::Markdown, FormatSpec::RawHtml]);
    let done = go(
        &rig,
        Spec::new(site.url("/native-switch"), options).tweak(|crawl| {
            native_policy(crawl);
            let policy = crawl.acquisition.as_mut().unwrap();
            policy.backend_ids = vec!["native_http".into(), "native_browser".into()];
            policy.fallback_backend_ids = vec!["native_browser".into()];
            policy.max_attempts = 2;
            policy.max_network_requests = 2;
            policy.retry_on = vec![crawlx_core::acquisition::RetryClassV1::Challenge];
            policy.validation.required_selectors = vec!["article#expected".into()];
        }),
    )
    .await;
    let receipt = &done.page("/native-switch").metadata["acquisition"];
    assert_eq!(site.count("/native-switch"), 2);
    assert_eq!(receipt["attempts"], 2);
    assert_eq!(receipt["networkRequests"], 2);
    assert_eq!(receipt["attemptSummaries"][0]["category"], "challenge");
    assert_eq!(receipt["attemptSummaries"][1]["category"], "valid");
    assert_eq!(receipt["representation"], "rendered_dom");
    assert_eq!(receipt["validation"]["contentAccepted"], true);
    assert_eq!(receipt["wireBody"], Value::Null);
    assert!(receipt["renderedDom"].is_object());
    assert_eq!(receipt["backend"]["backendId"], "native_browser");
    // BrowserBuildInfo uses its existing snake_case serialization, not configured version labels.
    assert!(receipt["backend"]["browser"]["chromium_version"]
        .as_str()
        .is_some_and(|version| !version.is_empty()));
    assert!(receipt["backend"]["browser"]["cdp_revision"]
        .as_str()
        .is_some_and(|version| !version.is_empty()));
    assert_eq!(receipt["backend"]["buildDigest"], Value::Null);
    assert_eq!(receipt["targetStatus"], 200);
    assert_eq!(receipt["finalUrlEvidence"], "observed");
}

#[tokio::test]
async fn native_article_finalizes_after_split_secret_and_pii_redaction_before_source_hashes() {
    const SECRET: &str = "article_secret_Q7v9N4x2";
    let (site, rig) = (start().await, Rig::new().await);
    site.set_page(200, "<html><head><title>Private report</title><meta name='author' content='article_secret_Q7v9N4x2'><meta name='keywords' content='fixed, implementation, public'><meta name='private_fixed_key' content='article_secret_Q7v9N4x2'></head><body><article><h1>Private report</h1><p>The access phrase is <span>article_secret_</span><span>Q7v9N4x2</span>, and the report keeps the town informed today.</p><p>Write to reader<span>@example.test</span> for a copy of the public notice after the meeting.</p></article><section id='comments'><p>A reader saw <span>article_secret_</span><b>Q7v9N4x2</b> before the archive removed it from this comment.</p></section></body></html>");
    let mut policy = crawlx_core::extraction::ExtractionPolicyV1::default();
    policy.comments = crawlx_core::extraction::CommentPolicyV1::Separate;
    let mut chunks = crawlx_core::extraction::WordChunkPolicyV1::default();
    chunks.strategy = crawlx_core::extraction::WordChunkStrategyV1::Fixed { window: 8 };
    policy.chunks = Some(chunks);
    let mut options = opts(vec![FormatSpec::Markdown, FormatSpec::Html]);
    options.content_policy = Some(policy);
    options.redact_pii = Some(crawlx_core::scrape::RedactPii {
        entities: vec![crawlx_core::scrape::PiiEntity::Email],
        ..crawlx_core::scrape::RedactPii::default()
    });
    let done = go(
        &rig,
        Spec::new(site.url("/mutable"), options).tweak(|crawl| {
            crawl.fetch.set_header("X-Api-Token", SECRET).unwrap();
            // Request-local literal redaction must not rewrite finalized enum vocabulary.
            crawl.fetch.set_header("X-Mode", "fixed").unwrap();
        }),
    )
    .await;
    let document = done.doc("/mutable");
    let main: crawlx_core::scrape::BlobRef =
        serde_json::from_value(document.meta["articleTextRef"].clone()).unwrap();
    let comments: crawlx_core::scrape::BlobRef =
        serde_json::from_value(document.meta["articleCommentsRef"].clone()).unwrap();
    let main = String::from_utf8(done.blob(&main).await).unwrap();
    let comments = String::from_utf8(done.blob(&comments).await).unwrap();
    let html = done.text(done.page("/mutable").html.as_ref().unwrap()).await;
    let markdown = done.markdown("/mutable").await;
    let metadata = serde_json::to_string(&document.meta).unwrap();
    for retained in [&main, &comments, &html, &markdown, &metadata] {
        assert!(!retained.contains(SECRET));
        assert!(
            !retained.contains("article_secret_"),
            "old split inline fragments must not survive finalization"
        );
        assert!(!retained.contains("reader@example.test"));
    }
    assert!(!metadata.contains("private_fixed_key"));
    let article = &document.meta["article"];
    let cached: crawlx_core::scrape::BlobRef =
        serde_json::from_value(document.meta["articleDocumentRef"].clone()).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&done.blob(&cached).await).unwrap();
    assert_eq!(saved["article"], *article);
    assert_eq!(saved["text"], main);
    assert_eq!(saved["comments"], comments);
    assert!(!serde_json::to_string(&saved).unwrap().contains(SECRET));
    let chunks: crawlx_core::extraction::WordChunkEnvelopeV1 =
        serde_json::from_value(article["chunks"].clone()).unwrap();
    chunks.validate(&main, &chunks.policy).unwrap();
    assert!(chunks.ranges.len() > 1);
    for range in &chunks.ranges {
        let chunk = main.get(range.start..range.end).unwrap();
        assert!(!chunk.contains(SECRET) && !chunk.contains("reader@example.test"));
    }
    assert_eq!(article["privacyProjectionVersion"], 1);
    assert_eq!(article["sourceMappingRedacted"], true);
    assert!(article["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|block| block["source"].is_null()));
    assert_eq!(
        article["mainDigest"],
        crawlx_core::hash::Digest::of("crawlx.extract.main.unicode_rules_v1", main.as_bytes()).to_hex()
    );
    assert_eq!(
        article["quality"]["mainChars"],
        u64::try_from(main.chars().count()).unwrap()
    );
    assert!(!article["metadata"]["summary"].as_array().unwrap().is_empty());
    for range in article["metadata"]["summary"].as_array().unwrap() {
        let start = usize::try_from(range["start"].as_u64().unwrap()).unwrap();
        let end = usize::try_from(range["end"].as_u64().unwrap()).unwrap();
        let sentence = main
            .get(start..end)
            .expect("summary range must slice actual retained final source");
        assert!(!sentence.contains(SECRET) && !sentence.contains("reader@example.test"));
    }
    assert_eq!(site.count("/mutable"), 1);
}

#[tokio::test]
async fn page_metadata_cannot_forge_native_article_or_retained_source_references() {
    let (site, rig) = (start().await, Rig::new().await);
    site.set_page(
        200,
        "<html><head><meta name='article' content='forged-envelope'><meta name='articleTextRef' content='forged-source'><meta name='articleCommentsRef' content='forged-comments'><meta name='articleDocumentRef' content='forged-cache'><meta name='articleCacheSourceRun' content='forged-run'><meta name='private_fixed_key' content='private fixed content'></head><body><p>A page without native article extraction.</p></body></html>",
    );
    let done = go(
        &rig,
        Spec::new(site.url("/mutable"), md()).tweak(|crawl| {
            crawl.fetch.set_header("X-Mode", "fixed").unwrap();
        }),
    )
    .await;
    let document = done.doc("/mutable");
    for key in [
        "article",
        "articleTextRef",
        "articleCommentsRef",
        "articleDocumentRef",
        "articleCacheSourceRun",
    ] {
        assert!(!document.meta.contains_key(key));
    }
    let metadata = serde_json::to_string(&document.meta).unwrap();
    assert!(!metadata.contains("private_fixed_key"));
    assert!(!metadata.contains("private fixed content"));
}

#[tokio::test]
async fn raw_only_native_chunk_policy_keeps_real_raw_content_without_orphan_article_cache_metadata() {
    let (site, rig) = (start().await, Rig::new().await);
    const SOURCE: &str = "<html><body><article><h1>Public meeting report</h1><p>The council published a complete public report with enough meaningful words for native article acceptance and several source-only word windows. Residents can read the original report after the meeting and consult the public archive for more information.</p></article></body></html>";
    site.set_page(200, SOURCE);
    let mut options = opts(vec![FormatSpec::RawBase64]);
    options.cache = Some(crawlx_core::cache::CachePolicyV1::default());
    let mut policy = crawlx_core::extraction::ExtractionPolicyV1::default();
    let mut chunks = crawlx_core::extraction::WordChunkPolicyV1::default();
    chunks.strategy = crawlx_core::extraction::WordChunkStrategyV1::Sliding { window: 8, step: 4 };
    policy.chunks = Some(chunks);
    options.content_policy = Some(policy);
    for attempt in 0..3 {
        if attempt == 2 {
            options.cache.as_mut().unwrap().mode = crawlx_core::cache::CacheModeV1::ReadOnly;
        }
        let done = go(&rig, Spec::new(site.url("/mutable"), options.clone())).await;
        assert_eq!(done.row("/mutable").await.status, FrontierStatus::Succeeded);
        let document = done.doc("/mutable");
        assert_eq!(
            document.cache_state,
            if attempt == 0 {
                CacheState::Miss
            } else {
                CacheState::Hit
            }
        );
        assert_eq!(site.count("/mutable"), 1, "raw-only cache reuse must not refetch");
        let raw = document.raw_base64.as_ref().unwrap();
        assert_eq!(done.blob(raw).await, SOURCE.as_bytes());
        for key in [
            "article",
            "articleTextRef",
            "articleCommentsRef",
            "articleDocumentRef",
            "articleCacheSourceRun",
        ] {
            assert!(!document.meta.contains_key(key));
        }
    }
}

#[tokio::test]
async fn virtual_rows_consumer_projects_request_and_provider_secrets_before_dedupe_and_artifact_identity() {
    const REQUEST_SECRET: &str = "virtual_request_N8m4F2q9";
    const PROVIDER_SECRET: &str = "virtual_provider_R6v3C8p2";
    assert!(crawlx_core::secret::register_secret(PROVIDER_SECRET));
    let (site, rig) = (start().await, Rig::new().await);
    let renderer = Scripted::new(|request| {
        let mut rendered = rendered(
            &request.request.url.url,
            "<html><body><main>Final DOM only.</main></body></html>",
        );
        rendered.actions.virtual_rows_max_bytes = Some(65536);
        rendered.actions.virtual_rows.push(serde_json::from_value(json!({
            "windows": [{
                "epoch": {"navigation_seq":1,"document_seq":1,"mutation_seq":10},
                "rows": ["C++","C#","東京","historic-only virtual marker", REQUEST_SECRET, PROVIDER_SECRET, "reader@example.test",
                    r#"{"\u0074oken":"virtual-json-credential"}"#,
                    r#"{"x":"duplicate-hidden-canary","x":"visible"}"#],
                "bottom":false,"capped":false,"scrollStep":99,"transportBytes":2048
            }, {
                "epoch": {"navigation_seq":1,"document_seq":1,"mutation_seq":20},
                "rows":["C#","東京",REQUEST_SECRET,"🙂","first line\nsecond line"],
                "bottom":false,"capped":false,"scrollStep":99,"transportBytes":2048
            }],
            "steps":1,"stop":"step_cap","restoration":"restored","maxBytes":65536
        })).unwrap());
        Ok(rendered)
    });
    let mut options = md();
    options.redact_pii = Some(crawlx_core::scrape::RedactPii::default());
    options.actions = vec![serde_json::from_value(json!({
        "type":"collectVirtualRows","spec":{
            "container":"#virtual","rows":".row","maxSteps":1,"settleMs":50,
            "maxRowsPerWindow":10,"maxRows":100,"maxBytes":65536
        }
    }))
    .unwrap()];
    let done = go(
        &rig,
        Spec::new(site.url("/page"), options)
            .renderer(&renderer)
            .tweak(|crawl| {
                crawl.fetch.set_header("X-Api-Token", REQUEST_SECRET).unwrap();
            }),
    )
    .await;
    let doc = done.doc("/page");
    let actions = doc.actions.as_ref().unwrap();
    assert_eq!(actions.virtual_rows.len(), 1);
    let bytes = done.blob(&actions.virtual_rows[0]).await;
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains(REQUEST_SECRET));
    assert!(!text.contains(PROVIDER_SECRET));
    assert!(!text.contains("reader@example.test"));
    assert!(
        !text.contains("virtual-json-credential"),
        "escaped JSON keys still receive decoded secret policy"
    );
    assert!(
        !text.contains("duplicate-hidden-canary"),
        "duplicate JSON members still fail closed"
    );
    let report: crawlx_core::dom_ops::VirtualRowsReport = serde_json::from_slice(&bytes).unwrap();
    let rows: Vec<&str> = report
        .windows
        .iter()
        .flat_map(|w| &w.rows)
        .map(String::as_str)
        .collect();
    assert_eq!(rows.iter().filter(|row| **row == "C#").count(), 1);
    assert_eq!(rows.iter().filter(|row| **row == "東京").count(), 1);
    assert!(rows.contains(&"C++") && rows.contains(&"🙂"));
    assert!(rows.contains(&"first line\nsecond line"));
    assert_eq!(
        rows.iter().filter(|row| **row == "[REDACTED]").count(),
        1,
        "distinct private rows must collapse only after privacy projection"
    );
    let metadata = serde_json::to_string(&done.page("/page").metadata).unwrap();
    for canary in [REQUEST_SECRET, PROVIDER_SECRET, "historic-only virtual marker"] {
        assert!(
            !metadata.contains(canary),
            "diagnostic content must not enter durable structural metadata"
        );
    }
    assert!(!done.markdown("/page").await.contains("historic-only"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn virtual_rows_native_consumer_bounds_combined_finalized_privacy_expansion() {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        return;
    }
    let (site, rig) = (start().await, Rig::new().await);
    site.set_page(
        200,
        r#"<!doctype html><html><body>
        <div id="first"><pre class="row"></pre></div>
        <div id="second"><pre class="row"></pre></div>
        <script>
        document.querySelector('#first .row').textContent = 'qqqq'.repeat(5000);
        document.querySelector('#second .row').textContent = 'qqqq'.repeat(3000);
        </script></body></html>"#,
    );
    let mut options = md();
    options.actions = ["#first", "#second"]
        .into_iter()
        .map(|container| {
            serde_json::from_value(json!({
                "type":"collectVirtualRows", "spec":{
                    "container":container, "rows":".row", "maxSteps":0, "settleMs":50,
                    "maxRowsPerWindow":1, "maxRows":1, "maxBytes":65536
                }
            }))
            .unwrap()
        })
        .collect();
    let result = try_go(
        &rig,
        Spec::new(site.url("/mutable"), options).tweak(|crawl| {
            native_policy(crawl);
            let policy = crawl.acquisition.as_mut().unwrap();
            policy.backend_ids = vec!["native_browser".into()];
            policy.max_attempts = 1;
            policy.max_decoded_bytes = 65536;
            crawl.fetch.set_header("X-Api-Token", "qqqq").unwrap();
        }),
    )
    .await;
    match result {
        Err(crawlx_worker::WorkerError::VirtualRowsOutputLimit(source)) => assert!(source.is_io()),
        Err(error) => panic!("unexpected failure instead of finalized output limit: {error}"),
        Ok(_) => panic!(
            "two individually valid 50KB/30KB approved reports must not publish under one 64KiB allowance"
        ),
    }
}
