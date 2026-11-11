//! Real URL-plane feed, auxiliary, provider and crash-resume fixtures. No public targets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod resume_rig;

#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use crawlx_core::{
    config::{CrawlMode, SitemapMode},
    discovery::{DiscoveryErrorV1, DiscoveryProviderV1, DiscoverySourceV1, SourceDiscoveryPolicyV1},
    CreateCrawl,
};
use crawlx_fetch::StaticResolver;
use crawlx_worker::{EgressConfig, WorkerConfig, WorkerError};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct StateData {
    hits: Mutex<Vec<String>>,
    gzip_sitemap: AtomicBool,
    gzip_body: Mutex<Option<Vec<u8>>>,
    park_article: AtomicBool,
    article_started: Notify,
    release: Notify,
}
struct Site {
    base: String,
    state: Arc<StateData>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Site {
    fn count(&self, path: &str) -> usize {
        self.state
            .hits
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.as_str() == path)
            .count()
    }
}
async fn count_hit(
    State(state): State<Arc<StateData>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    state.hits.lock().unwrap().push(request.uri().path().to_owned());
    next.run(request).await
}
fn html(title: &str, head: &str, links: &str) -> axum::response::Response {
    ([(header::CONTENT_TYPE, "text/html")], format!("<html><head><title>{title}</title>{head}</head><body><main><h1>{title}</h1><p>{}</p>{links}</main></body></html>",
        "Reporting follows verifiable events, public documents and careful editorial analysis. ".repeat(20))).into_response()
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn sitemap_body(base: &str) -> Vec<u8> {
    format!(
        "<urlset><url><loc>{base}/article</loc></url><url><loc>{base}/article</loc></url>\
         <url><loc>{base}/fr</loc></url></urlset>"
    )
    .into_bytes()
}

/// Authored dates exercise URL-entry filtering, not inferred article publication dates.
fn dated_sitemap_body(base: &str) -> Vec<u8> {
    format!(
        r#"<urlset xmlns:h="http://www.w3.org/1999/xhtml">
        <url><loc>{base}/dated/lower</loc><lastmod>2026-01-02T02:00:00+02:00</lastmod>
          <h:link rel="alternate" hreflang="fr" href="{base}/dated/variant-in"/></url>
        <url><loc>{base}/dated/inside</loc><lastmod>2026-01-02T12:00:00Z</lastmod></url>
        <url><loc>{base}/dated/upper</loc><lastmod>2026-01-02T19:00:00-05:00</lastmod></url>
        <url><loc>{base}/dated/date-only</loc><lastmod>2026-01-02</lastmod></url>
        <url><loc>{base}/dated/before</loc><lastmod>2026-01-01T23:59:59Z</lastmod>
          <h:link rel="alternate" hreflang="de" href="{base}/dated/variant-out"/></url>
        <url><loc>{base}/dated/after</loc><lastmod>2026-01-03T00:00:01Z</lastmod></url>
        <url><loc>{base}/dated/missing</loc></url>
        <url><loc>{base}/dated/invalid</loc><lastmod>not-a-date</lastmod></url>
        <url><loc>{base}/dated/no-zone</loc><lastmod>2026-01-02T12:00:00</lastmod></url>
        <url><loc>{base}/outside</loc><lastmod>2026-01-02T12:00:00Z</lastmod></url>
        <url><loc>{base}/robots-private</loc><lastmod>2026-01-02T12:00:00Z</lastmod></url>
    </urlset>"#
    )
    .into_bytes()
}

fn lastmod_policy(unknown: &str) -> crawlx_core::discovery::SitemapLastmodPolicyV1 {
    serde_json::from_value(serde_json::json!({
        "lower":"2026-01-02T00:00:00Z", "upper":"2026-01-03T00:00:00Z",
        "missingOrUnparseable":unknown
    }))
    .unwrap()
}

async fn site(park: bool) -> Site {
    const SIMPLE_FEED: &str =
        r#"<rss><channel><item><title>Article</title><link>/article</link></item></channel></rss>"#;
    let state = Arc::new(StateData::default());
    state.park_article.store(park, Ordering::SeqCst);
    let app = Router::new()
        .route("/", get(|| async { html("Publisher", r#"<link rel="alternate" type="application/rss+xml" href="/feed">"#, r#"<a href="/category/outside">Category</a><a href="/fallback">Focused fallback</a>"#) }))
        .route("/anchor-home", get(|| async { html("Anchor publisher", "", r#"<a type="application/rss+xml" href="/opaque-feed">Subscribe</a><a rel="nofollow" type="application/rss+xml" href="/robots-private">RSS</a><a href="/outside">Feedback</a>"#) }))
        .route("/label-home", get(|| async { html("Labeled publisher", "", r#"<a href="/labeled-feed">RSS</a><a href="/outside">Feedback</a>"#) }))
        .route("/story", get(|| async { html("Article without feed links", "", r#"<a href="/outside">Feedback</a>"#) }))
        .route("/opaque-feed", get(|| async { ([(header::CONTENT_TYPE, "application/rss+xml")], SIMPLE_FEED) }))
        .route("/labeled-feed", get(|| async { ([(header::CONTENT_TYPE, "application/rss+xml")], SIMPLE_FEED) }))
        .route("/robots.txt", get(|| async { "User-agent: *\nDisallow: /robots-private\n" }))
        .route("/feed", get(|| async { ([(header::CONTENT_TYPE, "application/rss+xml")], r#"<rss xmlns:a="http://www.w3.org/2005/Atom"><channel><a:link rel="next" href="/feed"/><item><title>Article</title><link>/article</link></item><item><link>/article</link></item><item><link>/outside</link></item><item><link>/robots-private</link></item><item><link>http://169.254.169.254/latest/meta-data/</link></item></channel></rss>"#) }))
        .route("/private-feed", get(|headers: axum::http::HeaderMap| async move {
            let secret = headers.get("x-qa-token").unwrap().to_str().unwrap();
            let title = format!("{secret} {}", "abcdef0123456789".repeat(4));
            let item = format!("<item><title>{title}</title><link>/article</link></item>");
            ([(header::CONTENT_TYPE, "application/rss+xml")],
                format!("<rss><channel>{}</channel></rss>", item.repeat(5)))
        }))
        .route("/article", get(|State(state): State<Arc<StateData>>| async move {
            if state.park_article.load(Ordering::SeqCst) {
                state.article_started.notify_one();
                while state.park_article.load(Ordering::SeqCst) { state.release.notified().await; }
            }
            html("Verified article", r#"<meta property="og:image" content="/image-redirect"><meta name="twitter:image" content="/image-bomb">"#, r#"<a class="teaser" href="/more">Read more</a>"#)
        }))
        .route("/more", get(|| async { html("More article", "", r#"<a rel="next" href="/article">Cycle</a>"#) }))
        .route("/image-redirect", get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/outside")]) }))
        .route("/image-bomb", get(|| async {
            let mut header = Vec::from(&b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"[..]);
            header.extend_from_slice(&100_000u32.to_be_bytes());
            header.extend_from_slice(&100_000u32.to_be_bytes());
            ([(header::CONTENT_TYPE, "image/png")], header)
        }))
        .route("/news-provider", get(|| async { ([(header::CONTENT_TYPE, "application/rss+xml")], r#"<rss><channel><item><title>Recorded news</title><link>/article</link><source>Recorded publisher</source></item></channel></rss>"#) }))
        .route("/trends-provider", get(|| async { ([(header::CONTENT_TYPE, "application/json")], r#"{"default":{"trendingSearchesDays":[{"trendingSearches":[{"title":{"query":"recorded trend"},"articles":[{"url":"/article"}]}]}]}}"#) }))
        .route("/cdx-provider", get(|| async { ([(header::CONTENT_TYPE, "application/json")], r#"[["timestamp","original","statuscode"],["20260101120000","https://original.test/missing","404"]]"#) }))
        .route("/web/{*capture}", get(|| async { html("Archived missing page", "", "") }))
        .route("/sitemap.xml", get(|State(state): State<Arc<StateData>>, headers: axum::http::HeaderMap| async move {
            let host = headers.get(header::HOST).unwrap().to_str().unwrap();
            let xml = if state.gzip_sitemap.load(Ordering::SeqCst) {
                format!("<sitemapindex><sitemap><loc>http://{host}/gzip.xml.gz</loc>\
                    <lastmod>2000-01-01</lastmod></sitemap>\
                    <sitemap><loc>http://{host}/gzip.xml.gz</loc></sitemap></sitemapindex>")
            } else {
                format!(r#"<urlset xmlns:h="http://www.w3.org/1999/xhtml"><url><loc>http://{host}/article</loc><h:link rel="alternate" hreflang="fr" href="http://{host}/fr"/></url></urlset>"#)
            };
            ([(header::CONTENT_TYPE, "application/xml")], xml)
        }))
        .route("/gzip.xml.gz", get(|State(state): State<Arc<StateData>>, headers: axum::http::HeaderMap| async move {
            let host = headers.get(header::HOST).unwrap().to_str().unwrap();
            let body = state.gzip_body.lock().unwrap().clone()
                .unwrap_or_else(|| gzip(&sitemap_body(&format!("http://{host}"))));
            ([(header::CONTENT_TYPE, "application/gzip")], body)
        }))
        .route("/fr", get(|| async { html("French article", "", "") }))
        .route("/dated/{name}", get(|| async { html("Dated sitemap article", "", "") }))
        .route("/fallback", get(|| async { html("Focused fallback", "", "") }))
        .route("/outside", get(|| async { "must not be fetched" }))
        .route("/category/outside", get(|| async { "category cannot grant scope" }))
        .route("/robots-private", get(|| async { "robots must deny this" }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "missing") })
        .with_state(Arc::clone(&state))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&state), count_hit));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, state, task }
}
fn enable_discovery(crawl: &mut CreateCrawl) {
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files.clear();
    crawl.scope.sources = vec![
        DiscoverySourceV1::Html,
        DiscoverySourceV1::Feeds,
        DiscoverySourceV1::Categories,
    ];
    crawl.scope.include_paths = vec![
        "^/$".into(),
        "^/feed$".into(),
        "^/article$".into(),
        "^/more$".into(),
        "^/image-(redirect|bomb)$".into(),
        "^/robots-private$".into(),
    ];
    let mut policy = SourceDiscoveryPolicyV1::default();
    policy.sufficient_main_chars = 100_000;
    policy.read_more_hops = 2;
    policy.media_probes = 2;
    crawl.scope.discovery = Some(policy);
    let mut acquisition = crawlx_core::acquisition::AcquisitionPolicyV1::default();
    acquisition.max_attempts = 8;
    acquisition.max_network_requests = 8;
    crawl.acquisition = Some(acquisition);
    let mut content = crawlx_core::extraction::ExtractionPolicyV1::default();
    content
        .selectors
        .read_more
        .push(crawlx_core::selectors::SelectorV1::Xpath {
            expression: "//a[@class='teaser']/@href".into(),
        });
    crawl.extract.content = Some(content);
}
fn crawl(site: &Site) -> CreateCrawl {
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_104);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    enable_discovery(&mut crawl);
    crawl
}
fn config(path: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: path.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    }
}

#[tokio::test]
async fn actual_worker_denies_feed_cycle_scope_robots_private_and_media_redirect_escape() {
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = crawlx_worker::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = common::authorization::run_authorized_local_with(
        crawlx_worker::LocalRun::new(crawl(&site), config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(site.count("/feed"), 1);
    assert_eq!(site.count("/article"), 1);
    assert_eq!(
        site.count("/more"),
        1,
        "read-more follows once, and cycle cannot escape hop accounting"
    );
    assert_eq!(site.count("/image-redirect"), 1);
    assert_eq!(site.count("/image-bomb"), 1);
    for denied in [
        "/outside",
        "/category/outside",
        "/robots-private",
        "/latest/meta-data/",
    ] {
        assert_eq!(site.count(denied), 0);
    }
    let article = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/article")
        .unwrap();
    assert!(article.metadata.get("discovery_auxiliary").is_some());
    assert_eq!(article.metadata["acquisition"]["targetStatus"], 200);
    assert!(
        article.metadata["acquisition"]["networkRequests"]
            .as_u64()
            .unwrap()
            <= 8
    );
    let reference: crawlx_core::ArtifactRef =
        serde_json::from_value(article.metadata["discovery_auxiliary"]["content"].clone()).unwrap();
    let reports: serde_json::Value =
        serde_json::from_slice(&stores.artifacts.get(&reference).await.unwrap()).unwrap();
    assert!(reports
        .as_array()
        .unwrap()
        .iter()
        .any(|report| report["outcome"] == "pixel_limit"));
    assert!(reports
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|report| report["boundedBytes"].as_u64())
        .all(|bytes| bytes <= 65_536));
    assert!(
        !report.pages.iter().any(|page| page.url.url.path() == "/more"),
        "read-more is an explicit child artifact, not an unbudgeted second frontier fetch"
    );
}

#[tokio::test]
async fn actual_feed_only_discovery_follows_typed_and_labeled_anchors_not_unrelated_links() {
    for (seed, feed) in [("/anchor-home", "/opaque-feed"), ("/label-home", "/labeled-feed")] {
        let site = site(false).await;
        let dir = tempfile::tempdir().unwrap();
        let mut request = crawl(&site);
        request.seed_url = url::Url::parse(&format!("{}{seed}", site.base)).unwrap();
        request.scope.sources = vec![DiscoverySourceV1::Feeds];
        request.scope.include_paths = vec![
            "^/$".into(),
            "^/anchor-home$".into(),
            "^/label-home$".into(),
            "^/(opaque-feed|labeled-feed|article|outside|robots-private)$".into(),
        ];
        let policy = request.scope.discovery.as_mut().unwrap();
        policy.media_probes = 0;
        policy.read_more_hops = 0;
        let report = common::authorization::run_authorized_local(request, config(dir.path()))
            .await
            .unwrap();
        assert_eq!(site.count(feed), 1, "the advertised feed must be acquired");
        assert_eq!(site.count("/article"), 1);
        assert_eq!(
            site.count("/"),
            0,
            "an advertised feed needs no homepage fallback"
        );
        assert_eq!(site.count("/outside"), 0, "feed-only mode cannot follow Feedback");
        assert_eq!(
            site.count("/robots-private"),
            0,
            "nofollow cannot advertise a candidate"
        );
        assert!(report.pages.iter().any(|page| page.url.url.path() == "/article"));
    }
}

#[tokio::test]
async fn actual_feed_homepage_fallback_obeys_scope_and_source_depth() {
    for (home_allowed, depth, home_hits, feed_hits, article_hits) in
        [(false, 5, 0, 0, 0), (true, 1, 1, 0, 0), (true, 5, 1, 1, 1)]
    {
        let site = site(false).await;
        let dir = tempfile::tempdir().unwrap();
        let mut request = crawl(&site);
        request.seed_url = url::Url::parse(&format!("{}/story", site.base)).unwrap();
        request.scope.sources = vec![DiscoverySourceV1::Feeds];
        request.scope.include_paths = vec!["^/story$".into(), "^/(feed|article)$".into()];
        if home_allowed {
            request.scope.include_paths.push("^/$".into());
        }
        let policy = request.scope.discovery.as_mut().unwrap();
        policy.max_source_depth = depth;
        policy.media_probes = 0;
        policy.read_more_hops = 0;
        let report = common::authorization::run_authorized_local(request, config(dir.path()))
            .await
            .unwrap();
        assert_eq!(site.count("/"), home_hits);
        assert_eq!(site.count("/feed"), feed_hits);
        assert_eq!(site.count("/article"), article_hits);
        assert_eq!(site.count("/outside"), 0);
        assert_eq!(
            report.pages.iter().any(|page| page.url.url.path() == "/article"),
            article_hits == 1,
        );
    }
}

#[tokio::test]
async fn actual_missing_provider_is_typed_before_any_http_including_robots() {
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let mut request = crawl(&site);
    request.scope.sources = vec![DiscoverySourceV1::NewsSearch];
    let result = common::authorization::run_authorized_local(request, config(dir.path())).await;
    assert!(matches!(
        result,
        Err(WorkerError::Discovery(DiscoveryErrorV1::ProviderUnavailable(
            DiscoveryProviderV1::NewsSearch
        )))
    ));
    assert!(site.state.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cache_only_rejects_explicit_providers_before_any_http() {
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let mut request = crawl(&site);
    let mut cache = crawlx_core::cache::CachePolicyV1::default();
    cache.development_replay = true;
    request.cache = Some(cache);
    request.scope.sources = vec![DiscoverySourceV1::TrendsSearch];
    let result = common::authorization::run_authorized_local(request, config(dir.path())).await;
    assert!(matches!(
        result,
        Err(WorkerError::Discovery(
            DiscoveryErrorV1::ProviderForbiddenInReplay(DiscoveryProviderV1::TrendsSearch)
        ))
    ));
    assert!(site.state.hits.lock().unwrap().is_empty());
}

struct FeedCommitGate {
    inner: Arc<dyn crawlx_core::repo::EventRepo>,
    reached: Notify,
    paused: Notify,
    once: AtomicBool,
}
#[async_trait::async_trait]
impl crawlx_core::repo::EventRepo for FeedCommitGate {
    async fn append(
        &self,
        run: crawlx_core::CrawlRunId,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<u64, crawlx_core::StoreError> {
        let pause = kind == "page"
            && payload["url"].as_str().is_some_and(|url| url.ends_with("/feed"))
            && !self.once.swap(true, Ordering::SeqCst);
        let sequence = self.inner.append(run, kind, payload).await?;
        if pause {
            self.reached.notify_one();
            self.paused.notified().await;
        }
        Ok(sequence)
    }
    async fn list_after(
        &self,
        run: crawlx_core::CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<crawlx_core::repo::RunEvent>, crawlx_core::StoreError> {
        self.inner.list_after(run, after_seq, limit).await
    }
}

struct CrashRuntime(Option<tokio::runtime::Runtime>);
impl Drop for CrashRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killed_after_feed_cursor_commit_resumes_same_article_set_without_replaying_source() {
    use crawlx_core::hash::Digest;
    use resume_rig::{enqueue, finish, fleet_reaper, page_paths, Rig};
    let rig = Rig::memory();
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let mut stores = rig.stores(dir.path()).await;
    let gate = Arc::new(FeedCommitGate {
        inner: Arc::clone(&stores.events),
        reached: Notify::new(),
        paused: Notify::new(),
        once: AtomicBool::new(false),
    });
    stores.events = gate.clone();
    let run = enqueue(&rig, &stores, &site.base, |crawl| {
        enable_discovery(crawl);
        let policy = crawl.scope.discovery.as_mut().unwrap();
        policy.read_more_hops = 0;
        policy.media_probes = 0;
    })
    .await;
    let runtime = CrashRuntime(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
    ));
    let mut worker = runtime
        .0
        .as_ref()
        .unwrap()
        .spawn(crawlx_worker::lease_loop::run_with(
            resume_rig::worker_cfg(dir.path(), None),
            stores.clone(),
            None,
            CancellationToken::new(),
        ));
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::select! {
            () = gate.reached.notified() => {}
            result = &mut worker => panic!("worker exited before feed commit: {result:?}"),
        }
    })
    .await
    .unwrap();
    assert_eq!(
        site.count("/article"),
        0,
        "crash boundary precedes child acquisition, not an unknown in-flight effect"
    );
    let rows = stores.frontier.list(run).await.unwrap();
    let feed = rows.iter().find(|entry| entry.url.url.path() == "/feed").unwrap();
    assert_eq!(feed.status, crawlx_core::repo::FrontierStatus::Succeeded);
    let article = rows
        .iter()
        .find(|entry| entry.url.url.path() == "/article")
        .unwrap();
    assert_eq!(article.status, crawlx_core::repo::FrontierStatus::Pending);
    let source = format!(
        "discovery:{}",
        Digest::of_value("crawlx/discovery-source/v1", &(feed.url.key, "feed"))
            .unwrap()
            .to_hex()
    );
    let committed = stores
        .frontier
        .loader_cursor(run, &source)
        .await
        .unwrap()
        .unwrap();
    assert!(committed.position > 0);
    drop(runtime);
    rig.expire_session_leases(&stores, run).await;
    let reaper = fleet_reaper(&stores);
    finish(&rig, dir.path()).await;
    let _ = reaper.stop().await;
    assert_eq!(page_paths(&stores, run).await, vec!["/", "/article", "/feed"]);
    assert_eq!(site.count("/feed"), 1);
    assert_eq!(
        stores.frontier.loader_cursor(run, &source).await.unwrap(),
        Some(committed)
    );
    rig.teardown().await;
}

#[tokio::test]
async fn cache_only_miss_skips_robots_sitemap_conventional_sources_and_auxiliary_http() {
    use crawlx_worker::{LocalRun, Stores};
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut request = crawl(&site);
    let mut cache = crawlx_core::cache::CachePolicyV1::default();
    cache.development_replay = true;
    request.cache = Some(cache);
    request.scope.sitemap = SitemapMode::Include;
    request.scope.known_files = vec![
        crawlx_core::config::KnownFile::Sitemap,
        crawlx_core::config::KnownFile::RobotsPaths,
    ];
    request.scope.sources.push(DiscoverySourceV1::Conventional);
    request.scope.discovery.as_mut().unwrap().conventional_paths = vec!["/feed".into()];
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(request, config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let rows = stores.frontier.list(report.run_id).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].denial_reason.as_deref(), Some("cache_miss"));
    assert!(
        site.state.hits.lock().unwrap().is_empty(),
        "cache-only must not request even robots.txt"
    );
}

#[tokio::test]
async fn actual_explicit_local_provider_connectors_preserve_archive_target_status() {
    use crawlx_worker::{LocalRun, Stores};
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut request = crawl(&site);
    request.scope.sources = vec![
        DiscoverySourceV1::NewsSearch,
        DiscoverySourceV1::TrendsSearch,
        DiscoverySourceV1::Archive,
    ];
    request.scope.include_paths = vec![
        "^/$".into(),
        "^/(news|trends|cdx)-provider$".into(),
        "^/article$".into(),
        "^/web/".into(),
    ];
    let policy = request.scope.discovery.as_mut().unwrap();
    policy.media_probes = 0;
    policy.read_more_hops = 0;
    policy.connectors = serde_json::from_value(serde_json::json!([
        {"provider":"news_search","endpoint":format!("{}/news-provider",site.base),"archiveBase":null},
        {"provider":"trends_search","endpoint":format!("{}/trends-provider",site.base),"archiveBase":null},
        {"provider":"web_archive_index","endpoint":format!("{}/cdx-provider",site.base),"archiveBase":format!("{}/web/",site.base)}
    ])).unwrap();
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(request, config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    for endpoint in ["/news-provider", "/trends-provider", "/cdx-provider"] {
        assert_eq!(site.count(endpoint), 1);
    }
    assert_eq!(
        site.count("/article"),
        1,
        "news and trends share canonical frontier identity"
    );
    let cdx = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/cdx-provider")
        .unwrap();
    let reference: crawlx_core::ArtifactRef =
        serde_json::from_value(cdx.metadata["source_discovery"]["content"].clone()).unwrap();
    let evidence: serde_json::Value =
        serde_json::from_slice(&stores.artifacts.get(&reference).await.unwrap()).unwrap();
    assert_eq!(evidence["captures"][0]["recordedTargetStatus"], 404);
    assert_eq!(
        evidence["captures"][0]["originalUrl"],
        "https://original.test/missing"
    );
    assert_ne!(
        evidence["captures"][0]["originalUrl"],
        evidence["captures"][0]["archiveUrl"]
    );
    let replay = report
        .pages
        .iter()
        .find(|page| page.url.url.path().starts_with("/web/"))
        .unwrap();
    assert_eq!(
        replay.status, 200,
        "archive provider response does not invent original target status"
    );
    assert!(!report
        .pages
        .iter()
        .any(|page| page.url.url.host_str() == Some("original.test")));
}

#[tokio::test]
async fn actual_sitemap_seed_and_homepage_traversal_keep_language_variants_before_focused_fallback() {
    use crawlx_worker::{LocalRun, Stores};
    for direct in [false, true] {
        let site = site(false).await;
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let mut request = crawl(&site);
        request.scope.sitemap = SitemapMode::Include;
        request.scope.sources = if direct {
            vec![DiscoverySourceV1::Sitemap]
        } else {
            vec![DiscoverySourceV1::Sitemap, DiscoverySourceV1::Html]
        };
        request.scope.include_paths = vec![
            "^/$".into(),
            "^/sitemap.xml$".into(),
            "^/article$".into(),
            "^/fr$".into(),
            "^/fallback$".into(),
        ];
        if direct {
            request.seed_url = url::Url::parse(&format!("{}/sitemap.xml", site.base)).unwrap();
        }
        let policy = request.scope.discovery.as_mut().unwrap();
        policy.media_probes = 0;
        policy.read_more_hops = 0;
        let report = common::authorization::run_authorized_local_with(
            LocalRun::new(request, config(dir.path())).with_stores(stores.clone()),
        )
        .await
        .unwrap();
        assert!(report.pages.iter().any(|page| page.url.url.path() == "/article"));
        assert!(report.pages.iter().any(|page| page.url.url.path() == "/fr"));
        assert_eq!(site.count("/sitemap.xml"), 1);
        assert_eq!(site.count("/fallback"), 0);
        let source = report
            .pages
            .iter()
            .find(|page| page.url.url.path() == if direct { "/sitemap.xml" } else { "/" })
            .unwrap();
        let key = if direct {
            "source_discovery"
        } else {
            "sitemap_discovery"
        };
        let reference: crawlx_core::ArtifactRef =
            serde_json::from_value(source.metadata[key]["content"].clone()).unwrap();
        let evidence: serde_json::Value =
            serde_json::from_slice(&stores.artifacts.get(&reference).await.unwrap()).unwrap();
        assert!(evidence["variants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|variant| variant["languageHint"] == "fr"));
    }
}

fn enable_gzip_sitemap(crawl: &mut CreateCrawl) {
    enable_discovery(crawl);
    crawl.scope.sources = vec![DiscoverySourceV1::Sitemap];
    crawl.scope.sitemap = SitemapMode::Include;
    crawl.scope.include_paths = vec!["^/$".into(), "^/(sitemap.xml|gzip.xml.gz|article|fr)$".into()];
    // Gzip documents still obey the ordinary extension policy. Authorize this
    // fixture's source types without disabling filters for unrelated resources.
    crawl.scope.extension_match = vec!["none".into(), "xml".into(), "gz".into()];
    let policy = crawl.scope.discovery.as_mut().unwrap();
    policy.media_probes = 0;
    policy.read_more_hops = 0;
}

#[tokio::test]
async fn actual_sitemap_lastmod_filters_entries_and_variants_in_both_worker_paths() {
    use crawlx_worker::{LocalRun, Stores};
    for seed in ["/", "/sitemap.xml", "/gzip.xml.gz"] {
        for unknown in [None, Some("include"), Some("exclude"), Some("empty")] {
            let site = site(false).await;
            site.state.gzip_sitemap.store(true, Ordering::SeqCst);
            *site.state.gzip_body.lock().unwrap() = Some(gzip(&dated_sitemap_body(&site.base)));
            let dir = tempfile::tempdir().unwrap();
            let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
                .await
                .unwrap();
            let mut request = crawl(&site);
            enable_gzip_sitemap(&mut request);
            request.seed_url = url::Url::parse(&format!("{}{seed}", site.base)).unwrap();
            request.scope.include_paths = vec![
                "^/$".into(),
                "^/(sitemap.xml|gzip.xml.gz)$".into(),
                "^/dated/".into(),
                "^/robots-private$".into(),
            ];
            request.scope.discovery.as_mut().unwrap().sitemap_lastmod = unknown.map(|mode| {
                if mode == "empty" {
                    serde_json::from_value(serde_json::json!({
                        "lower":"2030-01-01T00:00:00Z", "missingOrUnparseable":"exclude"
                    }))
                    .unwrap()
                } else {
                    lastmod_policy(mode)
                }
            });
            // Exercise the native serialized contract, not a worker-only configuration shortcut.
            let request: CreateCrawl =
                serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
            let report = common::authorization::run_authorized_local_with(
                LocalRun::new(request, config(dir.path())).with_stores(stores.clone()),
            )
            .await
            .unwrap();
            let mut paths: Vec<_> = report
                .pages
                .iter()
                .map(|page| page.url.url.path().to_owned())
                .filter(|path| path.starts_with("/dated/"))
                .collect();
            paths.sort();
            let mut expected = vec![
                "/dated/date-only",
                "/dated/inside",
                "/dated/lower",
                "/dated/upper",
                "/dated/variant-in",
            ];
            if unknown != Some("exclude") {
                expected.extend(["/dated/invalid", "/dated/missing", "/dated/no-zone"]);
            }
            if unknown.is_none() {
                expected.extend(["/dated/after", "/dated/before", "/dated/variant-out"]);
            }
            if unknown == Some("empty") {
                expected.clear();
            }
            expected.sort();
            assert_eq!(paths, expected, "seed={seed}, policy={unknown:?}");
            assert_eq!(site.count("/outside"), 0, "a selected date cannot grant scope");
            assert_eq!(
                site.count("/robots-private"),
                0,
                "a selected date cannot override robots"
            );
            assert_eq!(site.count("/gzip.xml.gz"), 1);
            assert_eq!(site.count("/sitemap.xml"), usize::from(seed != "/gzip.xml.gz"));
            let source = report
                .pages
                .iter()
                .find(|page| page.url.url.path() == if seed == "/" { "/" } else { "/gzip.xml.gz" })
                .unwrap();
            let key = if seed == "/" {
                "sitemap_discovery"
            } else {
                "source_discovery"
            };
            let reference: crawlx_core::ArtifactRef =
                serde_json::from_value(source.metadata[key]["content"].clone()).unwrap();
            let evidence: serde_json::Value =
                serde_json::from_slice(&stores.artifacts.get(&reference).await.unwrap()).unwrap();
            if unknown == Some("empty") {
                assert_eq!(evidence["variants"], serde_json::json!([]));
                let rows = stores.frontier.list(report.run_id).await.unwrap();
                let parent = rows.iter().find(|entry| entry.url.key == source.url.key).unwrap();
                let source_id = format!(
                    "discovery:{}",
                    crawlx_core::hash::Digest::of_value(
                        "crawlx/discovery-source/v1",
                        &(parent.url.key, "sitemap")
                    )
                    .unwrap()
                    .to_hex()
                );
                let cursor = stores
                    .frontier
                    .loader_cursor(report.run_id, &source_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    cursor.position, 0,
                    "an empty selected set still commits its policy pin"
                );
            } else {
                let variant = evidence["variants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|variant| variant["languageHint"] == "fr")
                    .unwrap();
                assert_eq!(variant["lastmodHint"], "2026-01-02T00:00:00Z");
            }
        }
    }
}

#[tokio::test]
async fn actual_gzip_sitemap_nested_and_explicit_seed_deduplicate_articles() {
    for direct in [false, true] {
        let site = site(false).await;
        site.state.gzip_sitemap.store(true, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let mut request = crawl(&site);
        enable_gzip_sitemap(&mut request);
        if direct {
            request.seed_url = url::Url::parse(&format!("{}/gzip.xml.gz", site.base)).unwrap();
        }
        let report = common::authorization::run_authorized_local(request, config(dir.path()))
            .await
            .unwrap();
        assert_eq!(site.count("/gzip.xml.gz"), 1);
        assert_eq!(site.count("/sitemap.xml"), usize::from(!direct));
        for path in ["/article", "/fr"] {
            assert_eq!(site.count(path), 1);
            assert_eq!(
                report
                    .pages
                    .iter()
                    .filter(|page| page.url.url.path() == path)
                    .count(),
                1
            );
        }
        let source = report
            .pages
            .iter()
            .find(|page| page.url.url.path() == if direct { "/gzip.xml.gz" } else { "/" })
            .unwrap();
        if direct {
            assert_eq!(source.metadata["source_discovery"]["status"], "parsed");
        } else {
            assert_eq!(source.metadata["sitemap_discovery"]["failedDocuments"], 0);
            assert_eq!(source.metadata["sitemap_discovery"]["documentsAttempted"], 2);
        }
    }
}

#[tokio::test]
async fn default_sitemap_discovery_without_policy_decodes_nested_gzip_with_response_bound() {
    for bounded in [false, true] {
        let site = site(false).await;
        site.state.gzip_sitemap.store(true, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let mut request = crawl(&site);
        enable_gzip_sitemap(&mut request);
        request.scope.discovery = None;
        request.scope.known_files = vec![crawlx_core::config::KnownFile::Sitemap];
        if bounded {
            // Both wire documents fit; the expanded urlset does not.
            let mut body = sitemap_body(&site.base);
            body.extend(std::iter::repeat_n(b' ', 4096));
            *site.state.gzip_body.lock().unwrap() = Some(gzip(&body));
            request.fetch.max_response_bytes = 1024;
        }
        let report = common::authorization::run_authorized_local(request, config(dir.path()))
            .await
            .unwrap();
        assert_eq!(site.count("/gzip.xml.gz"), 1);
        assert_eq!(site.count("/article"), usize::from(!bounded));
        assert_eq!(site.count("/fr"), usize::from(!bounded));
        assert_eq!(
            report.pages.iter().any(|page| page.url.url.path() == "/article"),
            !bounded
        );
    }
}

#[tokio::test]
async fn gzip_sitemap_sources_still_obey_default_extension_denial() {
    for direct in [false, true] {
        let site = site(false).await;
        site.state.gzip_sitemap.store(true, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let mut request = crawl(&site);
        enable_gzip_sitemap(&mut request);
        request.scope.extension_match.clear();
        if direct {
            request.seed_url = url::Url::parse(&format!("{}/gzip.xml.gz", site.base)).unwrap();
        }
        let report = common::authorization::run_authorized_local(request, config(dir.path()))
            .await
            .unwrap();
        assert_eq!(site.count("/gzip.xml.gz"), 0);
        assert_eq!(site.count("/article"), 0);
        assert_eq!(site.count("/fr"), 0);
        if !direct {
            let parent = report
                .pages
                .iter()
                .find(|page| page.url.url.path() == "/")
                .unwrap();
            assert_eq!(parent.metadata["sitemap_discovery"]["failedDocuments"], 1);
        }
    }
}

#[tokio::test]
async fn actual_gzip_sitemap_rejects_bombs_checksum_truncation_and_trailing_junk_before_prefix() {
    for nested in [false, true] {
        for invalid in ["ratio", "bytes", "checksum", "truncated", "trailing", "member"] {
            let site = site(false).await;
            site.state.gzip_sitemap.store(true, Ordering::SeqCst);
            let mut xml = sitemap_body(&site.base);
            if matches!(invalid, "ratio" | "bytes") {
                xml.extend(std::iter::repeat_n(b' ', 256 * 1024));
            }
            let mut body = gzip(&xml);
            match invalid {
                "checksum" => {
                    let crc = body.len() - 8;
                    body[crc] ^= 1;
                }
                "truncated" => body.truncate(body.len() - 4),
                "trailing" => body.extend_from_slice(b"trailing junk"),
                "member" => {
                    let mut member = gzip(b" ");
                    member.truncate(member.len() - 4);
                    body.extend_from_slice(&member);
                }
                _ => {}
            }
            *site.state.gzip_body.lock().unwrap() = Some(body);
            let dir = tempfile::tempdir().unwrap();
            let mut request = crawl(&site);
            enable_gzip_sitemap(&mut request);
            if !nested {
                request.seed_url = url::Url::parse(&format!("{}/gzip.xml.gz", site.base)).unwrap();
            }
            if invalid == "bytes" {
                request.scope.discovery.as_mut().unwrap().max_feed_bytes = 4096;
            }
            let report = common::authorization::run_authorized_local(request, config(dir.path()))
                .await
                .unwrap();
            for child in ["/article", "/fr"] {
                assert_eq!(site.count(child), 0, "{invalid}, nested={nested}");
                assert!(!report.pages.iter().any(|page| page.url.url.path() == child));
            }
            let source = report
                .pages
                .iter()
                .find(|page| page.url.url.path() == if nested { "/" } else { "/gzip.xml.gz" })
                .unwrap();
            if nested {
                assert_eq!(source.metadata["sitemap_discovery"]["failedDocuments"], 1);
                assert_eq!(source.metadata["sitemap_discovery"]["partial"], true);
            } else {
                assert_eq!(
                    source.metadata["source_discovery"]["reason"],
                    if matches!(invalid, "ratio" | "bytes") {
                        "sitemap_gzip_expansion"
                    } else {
                        "sitemap_gzip_invalid"
                    }
                );
            }
        }
    }
}

#[tokio::test]
async fn actual_gzip_sitemap_accepts_complete_concatenated_members() {
    let site = site(false).await;
    let xml = sitemap_body(&site.base);
    let split = xml.len() / 2;
    let mut body = gzip(&xml[..split]);
    body.extend_from_slice(&gzip(&xml[split..]));
    *site.state.gzip_body.lock().unwrap() = Some(body);
    let dir = tempfile::tempdir().unwrap();
    let mut request = crawl(&site);
    enable_gzip_sitemap(&mut request);
    request.seed_url = url::Url::parse(&format!("{}/gzip.xml.gz", site.base)).unwrap();
    let report = common::authorization::run_authorized_local(request, config(dir.path()))
        .await
        .unwrap();
    assert_eq!(site.count("/article"), 1);
    assert_eq!(site.count("/fr"), 1);
    assert!(report.pages.iter().any(|page| page.url.url.path() == "/article"));
}

/// Pause after the fenced source cursor and children commit, before the source page
/// becomes terminal. A killed worker must therefore acquire the source again.
struct SitemapCommitGate {
    inner: Arc<dyn crawlx_core::repo::ArtifactStore>,
    reached: Notify,
    paused: Notify,
    once: AtomicBool,
}

impl SitemapCommitGate {
    async fn pause(&self, content_type: &str) {
        if content_type == "application/vnd.crawlx.discovery+json" && !self.once.swap(true, Ordering::SeqCst)
        {
            self.reached.notify_one();
            self.paused.notified().await;
        }
    }
}

#[async_trait::async_trait]
impl crawlx_core::repo::ArtifactStore for SitemapCommitGate {
    async fn put(
        &self,
        run: crawlx_core::CrawlRunId,
        class: crawlx_core::repo::Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<crawlx_core::ArtifactRef, crawlx_core::StoreError> {
        self.pause(content_type).await;
        self.inner.put(run, class, content_type, bytes).await
    }

    async fn put_page(
        &self,
        run: crawlx_core::CrawlRunId,
        page: i64,
        class: crawlx_core::repo::Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<crawlx_core::ArtifactRef, crawlx_core::StoreError> {
        self.pause(content_type).await;
        self.inner.put_page(run, page, class, content_type, bytes).await
    }

    async fn put_until(
        &self,
        run: crawlx_core::CrawlRunId,
        class: crawlx_core::repo::Sensitivity,
        content_type: &str,
        bytes: &[u8],
        deadline: crawlx_core::Timestamp,
    ) -> Result<crawlx_core::ArtifactRef, crawlx_core::StoreError> {
        self.pause(content_type).await;
        self.inner
            .put_until(run, class, content_type, bytes, deadline)
            .await
    }

    async fn erase_run_credentials(
        &self,
        run: crawlx_core::CrawlRunId,
    ) -> Result<u64, crawlx_core::StoreError> {
        self.inner.erase_run_credentials(run).await
    }

    async fn get(&self, artifact: &crawlx_core::ArtifactRef) -> Result<Vec<u8>, crawlx_core::StoreError> {
        self.inner.get(artifact).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_gzip_sitemap_pins_wire_digest_and_conflicts_on_changed_compressed_bytes() {
    use crawlx_core::hash::Digest;
    use resume_rig::{enqueue, finish, fleet_reaper, page_paths, Rig};
    for changed in [false, true] {
        let rig = Rig::memory();
        let site = site(false).await;
        let wire = gzip(
            format!(
                "<urlset><url><loc>{}/article</loc><lastmod>2026-01-02T00:00:00Z</lastmod></url>\
             <url><loc>{}/article</loc><lastmod>2026-01-02T12:00:00Z</lastmod></url>\
             <url><loc>{}/fr</loc><lastmod>2026-01-03T00:00:00Z</lastmod></url>\
             <url><loc>{}/outside</loc><lastmod>2025-01-01</lastmod></url></urlset>",
                site.base, site.base, site.base, site.base,
            )
            .as_bytes(),
        );
        *site.state.gzip_body.lock().unwrap() = Some(wire.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut stores = rig.stores(dir.path()).await;
        let gate = Arc::new(SitemapCommitGate {
            inner: Arc::clone(&stores.artifacts),
            reached: Notify::new(),
            paused: Notify::new(),
            once: AtomicBool::new(false),
        });
        stores.artifacts = gate.clone();
        let run = enqueue(&rig, &stores, &site.base, |crawl| {
            enable_gzip_sitemap(crawl);
            crawl.scope.discovery.as_mut().unwrap().sitemap_lastmod = Some(lastmod_policy("exclude"));
            crawl.seed_url = url::Url::parse(&format!("{}/gzip.xml.gz", site.base)).unwrap();
        })
        .await;
        let runtime = CrashRuntime(Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        ));
        let mut worker = runtime
            .0
            .as_ref()
            .unwrap()
            .spawn(crawlx_worker::lease_loop::run_with(
                resume_rig::worker_cfg(dir.path(), None),
                stores.clone(),
                None,
                CancellationToken::new(),
            ));
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::select! {
                () = gate.reached.notified() => {}
                result = &mut worker => panic!("worker exited before sitemap cursor commit: {result:?}"),
            }
        })
        .await
        .unwrap();
        let rows = stores.frontier.list(run).await.unwrap();
        let parent = rows
            .iter()
            .find(|entry| entry.url.url.path() == "/gzip.xml.gz")
            .unwrap();
        assert_eq!(parent.status, crawlx_core::repo::FrontierStatus::Leased);
        assert_eq!(site.count("/article"), 0);
        assert_eq!(site.count("/fr"), 0);
        let source = format!(
            "discovery:{}",
            Digest::of_value("crawlx/discovery-source/v1", &(parent.url.key, "sitemap"))
                .unwrap()
                .to_hex()
        );
        let committed = stores
            .frontier
            .loader_cursor(run, &source)
            .await
            .unwrap()
            .unwrap();
        let stored = stores.runs.get(run).await.unwrap();
        let expected = Digest::of_value(
            "crawlx/discovery-representation/v1",
            &(
                Digest::of("crawlx/discovery-bytes/v1", &wire),
                stored.config.scope.discovery.as_ref().unwrap(),
                &stored.config.scope.sources,
            ),
        )
        .unwrap();
        assert_eq!(committed.source_digest, expected);
        let mut changed_policy = stored.config.scope.discovery.clone().unwrap();
        changed_policy.sitemap_lastmod.as_mut().unwrap().upper =
            Some("2026-01-04T00:00:00Z".parse().unwrap());
        let changed_identity = Digest::of_value(
            "crawlx/discovery-representation/v1",
            &(
                Digest::of("crawlx/discovery-bytes/v1", &wire),
                &changed_policy,
                &stored.config.scope.sources,
            ),
        )
        .unwrap();
        assert_ne!(
            committed.source_digest, changed_identity,
            "changing date bounds cannot reuse the committed source identity"
        );
        assert_eq!(
            committed.position, 3,
            "cursor includes the duplicate input position"
        );
        drop(runtime);
        if changed {
            // Change only gzip mtime, not XML or its checksum. Decoded identity would
            // incorrectly accept this different captured representation on resume.
            let mut different = wire.clone();
            different[4] ^= 1;
            *site.state.gzip_body.lock().unwrap() = Some(different);
        }
        rig.expire_session_leases(&stores, run).await;
        let reaper = fleet_reaper(&stores);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while reaper.reaped().requeued == 0 {
                tokio::time::sleep(resume_rig::REAP_EVERY).await;
            }
        })
        .await
        .unwrap();
        finish(&rig, dir.path()).await;
        let _ = reaper.stop().await;
        assert_eq!(
            site.count("/gzip.xml.gz"),
            2,
            "the interrupted parent is acquired again"
        );
        assert_eq!(
            stores.frontier.loader_cursor(run, &source).await.unwrap(),
            Some(committed)
        );
        let result = stores.runs.get(run).await.unwrap();
        if changed {
            assert_eq!(
                result.terminal_reason,
                Some(crawlx_core::counters::TerminalReason::FatalError)
            );
            assert!(!page_paths(&stores, run)
                .await
                .contains(&"/gzip.xml.gz".to_owned()));
        } else {
            assert_eq!(
                page_paths(&stores, run).await,
                vec!["/article", "/fr", "/gzip.xml.gz"]
            );
            assert_eq!(site.count("/article"), 1);
            assert_eq!(site.count("/fr"), 1);
            let source_page = stores
                .pages
                .list(run)
                .await
                .unwrap()
                .into_iter()
                .find(|page| page.url.url.path() == "/gzip.xml.gz")
                .unwrap();
            assert_eq!(
                source_page.metadata["acquisition"]["networkRequests"], 2,
                "resume keeps the first acquisition charged instead of resetting the shared budget"
            );
        }
        rig.teardown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_unknown_fetch_still_forfeits_unsettled_acquisition_allowance() {
    use crawlx_core::counters::TerminalReason;
    use resume_rig::{enqueue, finish, fleet_reaper, page_paths, Doomed, Rig};
    let rig = Rig::memory();
    let site = site(true).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |crawl| {
        enable_gzip_sitemap(crawl);
        crawl.seed_url = url::Url::parse(&format!("{}/article", site.base)).unwrap();
    })
    .await;
    let worker = Doomed::start(&rig, dir.path().to_path_buf(), CancellationToken::new());
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        site.state.article_started.notified(),
    )
    .await
    .unwrap();
    assert_eq!(site.count("/article"), 1);
    assert!(page_paths(&stores, run).await.is_empty());
    let parent = stores
        .frontier
        .list(run)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(parent.status, crawlx_core::repo::FrontierStatus::Leased);
    worker.kill();
    // The target may finish after the crash, but the killed worker never observed
    // that response. Its escrow must remain fully charged, not refunded on resume.
    site.state.park_article.store(false, Ordering::SeqCst);
    site.state.release.notify_waiters();
    rig.expire_session_leases(&stores, run).await;
    let reaper = fleet_reaper(&stores);
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while reaper.reaped().requeued == 0 {
            tokio::time::sleep(resume_rig::REAP_EVERY).await;
        }
    })
    .await
    .unwrap();
    finish(&rig, dir.path()).await;
    let _ = reaper.stop().await;
    assert_eq!(
        site.count("/article"),
        1,
        "unknown in-flight effects forfeit escrow and cannot authorize a second acquisition"
    );
    assert!(page_paths(&stores, run).await.is_empty());
    assert_eq!(
        stores.runs.get(run).await.unwrap().terminal_reason,
        Some(TerminalReason::FatalError)
    );
    rig.teardown().await;
}

#[tokio::test]
async fn actual_xml_feed_commits_physical_row_cursor_and_bounded_evidence_chain() {
    use crawlx_core::hash::Digest;
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = crawlx_worker::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut request = crawl(&site);
    request.seed_url = url::Url::parse(&format!("{}/feed", site.base)).unwrap();
    request.scope.discovery.as_mut().unwrap().media_probes = 0;
    request.scope.discovery.as_mut().unwrap().read_more_hops = 0;
    let report = common::authorization::run_authorized_local_with(
        crawlx_worker::LocalRun::new(request, config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let feed = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/feed")
        .unwrap();
    let metadata = &feed.metadata["source_discovery"];
    assert_eq!(metadata["streamed"], true);
    assert_eq!(metadata["rows"], 5);
    assert_eq!(metadata["malformed"], 0);
    assert_eq!(metadata["contentLayout"], "reverse_batch_chain_v1");
    let source = format!(
        "discovery:{}",
        Digest::of_value("crawlx/discovery-source/v1", &(feed.url.key, "feed"))
            .unwrap()
            .to_hex(),
    );
    let cursor = stores
        .frontier
        .loader_cursor(report.run_id, &source)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cursor.position, 5,
        "denied and duplicate rows still advance the source cursor"
    );
    let mut next = metadata["content"].clone();
    let mut rows = 0;
    let mut batches = 0;
    while !next.is_null() {
        let reference: crawlx_core::ArtifactRef = serde_json::from_value(next).unwrap();
        let bytes = stores.artifacts.get(&reference).await.unwrap();
        assert_eq!(reference.digest, Digest::of("crawlx/artifact/v1", &bytes));
        let batch: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let entries = batch["entries"].as_array().unwrap();
        assert!(entries.len() <= 4);
        rows += entries.len();
        batches += 1;
        next = batch["previous"].clone();
    }
    assert_eq!(rows, 5);
    assert_eq!(batches, 2);
    assert_eq!(site.count("/article"), 1);
    assert_eq!(site.count("/outside"), 0);
    assert_eq!(site.count("/robots-private"), 0);
}

#[tokio::test]
async fn xml_feed_evidence_redacts_source_hints_without_corrupting_generated_references() {
    const SECRET: &str = "feedHintCanary718";
    let site = site(false).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = crawlx_worker::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut request = crawl(&site);
    request.seed_url = url::Url::parse(&format!("{}/private-feed", site.base)).unwrap();
    request.scope.include_paths.push("^/private-feed$".into());
    request.fetch.extra_headers.insert("x-qa-token", SECRET);
    request.scope.discovery.as_mut().unwrap().media_probes = 0;
    request.scope.discovery.as_mut().unwrap().read_more_hops = 0;
    let mut worker = config(dir.path());
    worker.request_identity_key = Some(crawlx_core::secret::SecretOr::secret([71; 32]));
    let report = common::authorization::run_authorized_local_with(
        crawlx_worker::LocalRun::new(request, worker).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let feed = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/private-feed")
        .unwrap();
    let mut next = feed.metadata["source_discovery"]["content"].clone();
    let mut rows = 0;
    let mut batches = 0;
    while !next.is_null() {
        let reference: crawlx_core::ArtifactRef = serde_json::from_value(next).unwrap();
        let bytes = stores.artifacts.get(&reference).await.unwrap();
        let batch: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let entries = batch["entries"].as_array().unwrap();
        assert!(entries.len() <= 4);
        for entry in entries {
            let title = entry["titleHint"].as_str().unwrap();
            assert!(
                !title.contains(SECRET),
                "request-secret echoes must remain redacted"
            );
            assert!(
                !title.contains(&"abcdef0123456789".repeat(4)),
                "source-authored bare hexadecimal values must still take generic redaction"
            );
            assert!(title.contains("[REDACTED]"));
        }
        rows += entries.len();
        batches += 1;
        next = batch["previous"].clone();
    }
    assert_eq!(rows, 5);
    assert_eq!(batches, 2);
}
