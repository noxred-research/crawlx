//! Real Chromium through the scrape engine: block lists with their version and completeness in
//! the stored document, requested versus measured device pixel ratio and geolocation, and
//! shadow-DOM / iframe flattening with per-frame provenance. Skipped when `CRAWLX_CHROMIUM_PATH`
//! is not set.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::page_op::{BlockClass, FlattenSpec, FrameStatus, GeoPosition};
use crawlx_core::scrape::{
    FormatSpec, JobKind, Location, ResourceBlocking, ScrapeDocument, ScrapeJob, ScrapeOptions,
};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};
use url::Url;

/// Host name that resolves to the fixture server but is another origin than `127.0.0.1`.
const OTHER_HOST: &str = "other.example.test";

struct Site {
    port: u16,
    hits: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn count(&self, path: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| *p == path).count()
    }
}

fn page(body: String) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
}

fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, content_type)], body)
}

async fn start() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let assets = format!(
        r#"<!doctype html><html><head><title>Assets</title><link rel="stylesheet" href="/style.css"></head><body>
<main><h1>Assets</h1><p>A page with text that uses the web font and enough words to be the content.</p></main>
<script src="/app.js"></script><script src="/pagead/ad.js"></script>
<video preload="auto" src="/clip.mp4"></video>
<img src="http://{OTHER_HOST}:{port}/extra/x.png">
</body></html>"#
    );
    let plain = r#"<!doctype html><html><head><title>Plain</title></head><body><main><h1>Plain</h1>
<p>A plain page with a few words so that it is the main content of the document.</p></main></body></html>"#
        .to_owned();
    let flat = format!(
        r#"<!doctype html><html><head><title>Flat</title></head><body><main>
<h1>Flat</h1><p>light paragraph that is part of the main content of this page.</p>
<div id="host"></div>
<script>
const root = document.getElementById('host').attachShadow({{ mode: 'open' }});
root.innerHTML = '<p>shadow paragraph in the same article text.</p><slot></slot>';
const slotted = document.createElement('span');
slotted.textContent = 'slotted words';
document.getElementById('host').appendChild(slotted);
</script>
<iframe src="/inner"></iframe>
<iframe src="http://{OTHER_HOST}:{port}/other"></iframe>
</main></body></html>"#
    );
    let app = Router::new()
        .route("/assets", get(move || async move { page(assets.clone()) }))
        .route("/plain", get(move || async move { page(plain.clone()) }))
        .route("/flat", get(move || async move { page(flat.clone()) }))
        .route(
            "/inner",
            get(|| async { page("<!doctype html><html><body><p>inner frame paragraph.</p></body></html>".to_owned()) }),
        )
        .route(
            "/other",
            get(|| async {
                page("<!doctype html><html><body><p>other origin paragraph.</p></body></html>".to_owned())
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                asset(
                    "text/css",
                    "@font-face { font-family: F; src: url(/font.woff2) format('woff2'); } body { font-family: F, serif; }",
                )
            }),
        )
        .route("/font.woff2", get(|| async { asset("font/woff2", "not a font") }))
        .route("/app.js", get(|| async { asset("text/javascript", "window.app = 1;") }))
        .route("/pagead/ad.js", get(|| async { asset("text/javascript", "window.ad = 1;") }))
        .route("/clip.mp4", get(|| async { asset("video/mp4", "not a video") }))
        .route(
            "/extra/x.png",
            get(|| async { asset("image/svg+xml", "<svg xmlns='http://www.w3.org/2000/svg'/>") }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&hits),
            |axum::extract::State(hits): axum::extract::State<Arc<Mutex<Vec<String>>>>,
             req: axum::extract::Request,
             next: axum::middleware::Next| async move {
                hits.lock().unwrap().push(req.uri().path().to_owned());
                next.run(req).await
            },
        ));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { port, hits, task }
}

fn skip() -> bool {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        eprintln!("skipped: CRAWLX_CHROMIUM_PATH is not set");
        return true;
    }
    false
}

async fn scrape(site: &Site, path: &str, options: ScrapeOptions) -> (RunReport, ScrapeDocument, Stores) {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(Url::parse(&site.url(path)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_111);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.max_discovery_depth = 0;
    let mut policy = crawlx_core::acquisition::AcquisitionPolicyV1::default();
    policy.backend_ids = vec!["native_browser".into()];
    policy.max_attempts = 1;
    crawl.acquisition = Some(policy);
    crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
    let mut cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(
                StaticResolver::new().with(OTHER_HOST, [std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]),
            )),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    cfg.launch.allow_unpinned = true;
    if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_err() && std::env::var_os("CI").is_none() {
        cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |user| user == "root");
    }
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone()))
        .await
        .unwrap();
    let record = report
        .pages
        .iter()
        .find(|p| p.url.url.path() == path)
        .unwrap_or_else(|| panic!("no page for {path}: {:?}", report.terminal_reason));
    let document = ScrapeDocument::from_page_metadata(&record.metadata).expect("a scrape document");
    // keep the tempdir alive as long as the stores
    std::mem::forget(dir);
    (report, document, stores)
}

fn options(formats: Vec<FormatSpec>) -> ScrapeOptions {
    ScrapeOptions {
        formats,
        cache_principal: Some(uuid::Uuid::from_u128(7)),
        max_age_ms: 0,
        store_in_cache: false,
        ..ScrapeOptions::default()
    }
}

async fn text(stores: &Stores, artifact: &crawlx_core::ArtifactRef) -> String {
    String::from_utf8(stores.artifacts.get(artifact).await.unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_fonts_media_ads_and_hosts_stay_out_of_the_access_log_and_the_result_says_which_list() {
    if skip() {
        return;
    }
    let site = start().await;
    let mut blocked = options(vec![FormatSpec::Markdown]);
    // the device scale forces the browser leg; `blockAds` is on by default
    blocked.device_scale_milli = Some(1_500);
    blocked.resource_blocking = Some(ResourceBlocking {
        resource_types: vec![BlockClass::Font, BlockClass::Media],
        domains: vec![OTHER_HOST.to_owned()],
    });
    let (_, document, _) = scrape(&site, "/assets", blocked).await;
    assert_eq!(site.count("/assets"), 1);
    assert!(site.count("/style.css") >= 1, "the allowed stylesheet loads");
    assert!(site.count("/app.js") >= 1, "the allowed script loads");
    // let anything that escaped the block list reach the server before judging
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(site.count("/font.woff2"), 0, "font");
    assert_eq!(site.count("/clip.mp4"), 0, "media");
    assert_eq!(site.count("/pagead/ad.js"), 0, "ad rule");
    // the caller-named host rule is covered by the browser-level access-log test

    let report = document
        .browser_page
        .expect("a browser render carries its page report")
        .block_list
        .expect("a block list was installed");
    assert_eq!(report.list_version, crawlx_extract::blocklist::list_version());
    assert!(report.ads);
    assert_eq!(report.resource_types, [BlockClass::Font, BlockClass::Media]);
    assert_eq!(report.custom_domains, 1);
    assert!(report.patterns_installed > 100, "{report:?}");
    assert!(report.sessions_applied >= 1, "{report:?}");
    assert_eq!(report.sessions_failed, 0, "{report:?}");
    // fonts and media are matched by extension: that is stated, not hidden
    assert!(!report.complete, "{report:?}");
    assert_eq!(
        report.gaps,
        ["type_by_url_extension:font", "type_by_url_extension:media"],
        "{report:?}"
    );

    // the same page with nothing blocked fetches every one of them
    let mut open = options(vec![FormatSpec::Markdown]);
    open.device_scale_milli = Some(1_500);
    open.block_ads = false;
    let (_, document, _) = scrape(&site, "/assets", open).await;
    // the caller-named host is unreachable through the render's egress policy either way, so
    // only the three same-origin resources show that the lists held them back
    for path in ["/font.woff2", "/clip.mp4", "/pagead/ad.js"] {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while site.count(path) == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(site.count(path) >= 1, "{path} is fetched when nothing is blocked");
    }
    assert!(document.browser_page.unwrap().block_list.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_page_reports_the_requested_pixel_ratio_and_geolocation_and_the_result_says_so() {
    if skip() {
        return;
    }
    let site = start().await;
    let munich = GeoPosition::new(48_137_154, 11_576_124, 25).unwrap();
    let mut requested = options(vec![FormatSpec::Markdown]);
    requested.device_scale_milli = Some(2_625);
    requested.location = Some(Location {
        geolocation: Some(munich),
        ..Location::default()
    });
    let (_, document, _) = scrape(&site, "/plain", requested).await;
    let device = document
        .browser_page
        .expect("a browser render carries its page report")
        .device
        .expect("a device profile was requested");
    assert_eq!(device.requested_scale_milli, Some(2_625));
    assert_eq!(device.requested_geolocation, Some(munich));
    let measured = device.measured.expect("the page answered the measurement");
    assert_eq!(measured.device_pixel_ratio_milli, 2_625, "{measured:?}");
    assert_eq!(measured.geolocation, Some(munich), "{measured:?}");
    assert_eq!(measured.geolocation_error, None, "{measured:?}");

    // a request that asks for neither has no device report and ratio 1
    let (_, document, _) = scrape(&site, "/plain", {
        let mut mobile = options(vec![FormatSpec::Markdown]);
        mobile.mobile = true;
        mobile
    })
    .await;
    assert!(document.browser_page.is_none_or(|report| report.device.is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flattened_text_carries_shadow_and_frame_content_with_provenance_in_the_result() {
    if skip() {
        return;
    }
    let site = start().await;
    // without the option the text lacks shadow and frame content
    let (plain_report, plain_doc, plain_stores) = scrape(&site, "/flat", {
        let mut o = options(vec![FormatSpec::Markdown]);
        o.only_main_content = false;
        o.mobile = true;
        o
    })
    .await;
    assert!(plain_doc
        .browser_page
        .is_none_or(|report| report.flatten.is_none()));
    let plain = text(&plain_stores, plain_report.pages[0].markdown.as_ref().unwrap()).await;
    assert!(plain.contains("light paragraph"), "{plain}");
    assert!(!plain.contains("shadow paragraph"), "{plain}");
    assert!(!plain.contains("inner frame paragraph"), "{plain}");

    let mut flat = options(vec![FormatSpec::Markdown, FormatSpec::RawHtml]);
    flat.only_main_content = false;
    flat.flatten = Some(FlattenSpec::default());
    let (report, document, stores) = scrape(&site, "/flat", flat).await;
    let markdown = text(&stores, report.pages[0].markdown.as_ref().unwrap()).await;
    for part in [
        "light paragraph",
        "shadow paragraph",
        "slotted words",
        "inner frame paragraph",
    ] {
        assert!(
            markdown.contains(part),
            "{part} is missing from the text: {markdown}"
        );
    }
    assert!(
        !markdown.contains("other origin paragraph"),
        "a cross-origin document is never folded in: {markdown}"
    );
    let flatten = document
        .browser_page
        .expect("a browser render carries its page report")
        .flatten
        .expect("flattening was requested");
    assert_eq!(flatten.spec, FlattenSpec::default());
    assert_eq!(flatten.frames_omitted, 0);
    let origin = format!("http://127.0.0.1:{}", site.port);
    let frames = &flatten.frames;
    assert_eq!(frames.len(), 3, "{frames:#?}");
    assert_eq!((frames[0].ordinal, frames[0].parent), (0, None));
    assert_eq!(frames[0].origin, origin);
    assert_eq!(frames[0].shadow_roots, 1);
    assert_eq!(
        (frames[1].parent, frames[1].status),
        (Some(0), FrameStatus::Flattened)
    );
    assert_eq!(frames[1].origin, origin);
    assert_eq!(frames[1].url, format!("{origin}/inner"));
    assert_eq!(
        (frames[2].parent, frames[2].status),
        (Some(0), FrameStatus::CrossOrigin)
    );
    assert_eq!(frames[2].origin, format!("http://{OTHER_HOST}:{}", site.port));
    assert!(!frames[2].origin_observed);
    // the raw serialization has the markers the provenance list explains
    let raw = document.raw_html.as_ref().expect("rawHtml was requested");
    let raw = String::from_utf8(stores.artifacts.get(&raw.artifact).await.unwrap()).unwrap();
    assert!(
        raw.contains(&format!(
            "<crawlx-frame data-crawlx-frame=\"1\" data-crawlx-origin=\"{origin}\" data-crawlx-status=\"flattened\">"
        )),
        "{raw}"
    );
}
