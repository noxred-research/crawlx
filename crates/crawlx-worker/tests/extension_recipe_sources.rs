//! Real source-response and auxiliary-sitemap recipe paths, using only an owned local server.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
use axum::{
    extract::State,
    http::{header, HeaderMap},
    response::IntoResponse,
    routing::get,
    Router,
};
use crawlx_core::{
    config::{CrawlMode, RetentionMode, SitemapMode},
    discovery::{DiscoverySourceV1, SourceDiscoveryPolicyV1},
    extension_recipes::{DiscoveryRuleV1, ExtensionRecipeV1, RecipeSourceV1},
    extensions::HandlerV1,
    hash::Digest,
    CreateCrawl,
};
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Hits(Mutex<Vec<String>>);

struct Site {
    base: String,
    hits: Arc<Hits>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn count(&self, path: &str) -> usize {
        self.hits
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.as_str() == path)
            .count()
    }
}

async fn record(
    State(hits): State<Arc<Hits>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.0.lock().unwrap().push(request.uri().path().into());
    next.run(request).await
}

fn index(base: &str) -> String {
    format!("<sitemapindex><sitemap><loc>{base}/nested.xml</loc></sitemap><sitemap><loc>{base}/nested.xml</loc></sitemap></sitemapindex>")
}

fn entries(base: &str) -> String {
    format!(
        r#"<urlset xmlns:h="http://www.w3.org/1999/xhtml">
        <url><loc>{base}/article</loc><lastmod>2026-01-02</lastmod>
            <h:link rel="alternate" hreflang="fr" href="{base}/fr"/></url>
        <url><loc>{base}/blocked</loc><lastmod>2026-01-02</lastmod></url>
        <url><loc>{base}/robots-private</loc><lastmod>2026-01-02</lastmod></url>
        <url><loc>{base}/outside</loc><lastmod>2026-01-02</lastmod></url>
        <url><loc>{base}/drop</loc><lastmod>2026-01-02</lastmod></url>
        <url><loc>{base}/old</loc><lastmod>2025-01-02</lastmod>
            <h:link rel="alternate" hreflang="fr" href="{base}/old-fr"/></url>
        </urlset>"#
    )
}

fn article() -> axum::response::Response {
    ([(header::CONTENT_TYPE, "text/html")], format!(
        "<html><head><title>Verified source fixture</title></head><body><main><h1>Verified source fixture</h1><p>{}</p></main></body></html>",
        "Public records provide independent facts and careful reporting about local events. ".repeat(24),
    )).into_response()
}

async fn site() -> Site {
    let hits = Arc::new(Hits::default());
    let app = Router::new()
        .route("/", get(|| async { article() }))
        .route(
            "/robots.txt",
            get(|headers: HeaderMap| async move {
                let host = headers.get(header::HOST).unwrap().to_str().unwrap();
                format!("User-agent: *\nDisallow: /robots-private\nSitemap: http://{host}/sitemap.xml\n")
            }),
        )
        .route(
            "/sitemap.xml",
            get(|headers: HeaderMap| async move {
                let host = headers.get(header::HOST).unwrap().to_str().unwrap();
                (
                    [(header::CONTENT_TYPE, "application/xml")],
                    index(&format!("http://{host}")),
                )
            }),
        )
        .route(
            "/nested.xml",
            get(|headers: HeaderMap| async move {
                let host = headers.get(header::HOST).unwrap().to_str().unwrap();
                (
                    [(header::CONTENT_TYPE, "application/xml")],
                    entries(&format!("http://{host}")),
                )
            }),
        )
        .route("/article", get(|| async { article() }))
        .route("/fr", get(|| async { article() }))
        .route("/blocked", get(|| async { "must not be fetched" }))
        .route("/robots-private", get(|| async { "must not be fetched" }))
        .route("/outside", get(|| async { "must not be fetched" }))
        .route("/drop", get(|| async { "must not be fetched" }))
        .route("/old", get(|| async { "must not be fetched" }))
        .route("/old-fr", get(|| async { "must not be fetched" }))
        .with_state(Arc::clone(&hits))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Site { base, hits, task }
}

fn crawl(site: &Site, direct: bool) -> CreateCrawl {
    let seed = format!("{}{}", site.base, if direct { "/sitemap.xml" } else { "/" });
    let mut crawl = CreateCrawl::new(seed.parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_111);
    crawl.retention.mode = RetentionMode::Standard;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Include;
    crawl.scope.known_files.clear();
    crawl.scope.sources = vec![DiscoverySourceV1::Sitemap, DiscoverySourceV1::Html];
    crawl.scope.include_paths = vec![
        "^/$".into(),
        "^/(sitemap|nested)\\.xml$".into(),
        "^/(article|fr|blocked|robots-private|drop|old|old-fr)$".into(),
    ];
    let mut policy = SourceDiscoveryPolicyV1::default();
    policy.max_source_documents = 8;
    policy.max_source_depth = 4;
    policy.sufficient_main_chars = 100_000;
    policy.read_more_hops = 0;
    policy.media_probes = 0;
    policy.sitemap_lastmod = Some(
        serde_json::from_value(serde_json::json!({
            "lower":"2026-01-01T00:00:00Z", "missingOrUnparseable":"exclude",
        }))
        .unwrap(),
    );
    crawl.scope.discovery = Some(policy);
    let mut acquisition = crawlx_core::acquisition::AcquisitionPolicyV1::default();
    acquisition.max_attempts = 8;
    acquisition.max_network_requests = 16;
    crawl.acquisition = Some(acquisition);
    crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
    let mut recipe = ExtensionRecipeV1::new("source-fixture".into(), 3);
    recipe.follow_sitemaps = true;
    recipe.sitemap_alternates = true;
    recipe
        .pipeline
        .routes
        .insert("article".into(), HandlerV1::DocumentItem);
    recipe
        .pipeline
        .routes
        .insert("french".into(), HandlerV1::DocumentItem);
    recipe.pipeline.routes.insert("skip".into(), HandlerV1::Skip);
    let mut french = DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "french".into());
    french.allow.push("/fr$".into());
    let mut skip = DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "skip".into());
    skip.allow.push("/drop$".into());
    let fallback = DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "article".into());
    let mut denial = DiscoveryRuleV1::new(RecipeSourceV1::Html, "default".into());
    denial.allow.push("never-matches".into());
    denial.deny.push("/blocked$".into());
    recipe.rules = vec![french, skip, fallback, denial];
    crawl.extension_recipe = Some(recipe);
    crawl
}

#[tokio::test]
async fn actual_source_and_auxiliary_paths_preserve_handlers_lastmod_and_native_denials() {
    for direct in [true, false] {
        let site = site().await;
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let config = WorkerConfig {
            artifacts_dir: dir.path().to_owned(),
            egress: EgressConfig {
                resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
                ..EgressConfig::default()
            },
            ..WorkerConfig::default()
        };
        let report = common::authorization::run_authorized_local_with(
            LocalRun::new(crawl(&site, direct), config).with_stores(stores.clone()),
        )
        .await
        .unwrap();
        assert_eq!(site.count("/sitemap.xml"), 1);
        assert_eq!(site.count("/nested.xml"), 1);
        assert_eq!(site.count("/article"), 1);
        assert_eq!(site.count("/fr"), 1);
        for denied in [
            "/blocked",
            "/robots-private",
            "/outside",
            "/drop",
            "/old",
            "/old-fr",
        ] {
            assert_eq!(site.count(denied), 0, "{denied}, direct={direct}");
        }
        let rows = stores.frontier.list(report.run_id).await.unwrap();
        for (path, route) in [("/article", "article"), ("/fr", "french")] {
            let row = rows.iter().find(|row| row.url.url.path() == path).unwrap();
            let queued = stores.frontier.get_request(report.run_id, row.id).await.unwrap();
            assert_eq!(queued.envelope.route, route);
            if path == "/fr" {
                assert_eq!(queued.envelope.metadata["recipe_language_hint"], "fr");
            }
        }
        if direct {
            let nested = rows
                .iter()
                .find(|row| row.url.url.path() == "/nested.xml")
                .unwrap();
            let queued = stores
                .frontier
                .get_request(report.run_id, nested.id)
                .await
                .unwrap();
            assert_eq!(queued.envelope.route, "default");
            assert_eq!(queued.envelope.metadata["recipe_sitemap_depth"], 1);
        }
        let source_path = if direct { "/sitemap.xml" } else { "/" };
        let page = report
            .pages
            .iter()
            .find(|page| page.url.url.path() == source_path)
            .unwrap();
        let key = if direct {
            "source_discovery"
        } else {
            "sitemap_discovery"
        };
        assert_eq!(page.metadata[key]["recipe"]["revision"], 3);
        let source_id = format!(
            "discovery:{}",
            Digest::of_value("crawlx/discovery-source/v1", &(page.url.key, "sitemap"),)
                .unwrap()
                .to_hex()
        );
        let cursor = stores
            .frontier
            .loader_cursor(report.run_id, &source_id)
            .await
            .unwrap()
            .unwrap();
        let run = stores.runs.get(report.run_id).await.unwrap();
        let recipe_pin = run.config.extension_recipe.as_ref().unwrap().pin().unwrap();
        if direct {
            let expected = Digest::of_value(
                "crawlx/discovery-recipe-representation/v1",
                &(
                    Digest::of("crawlx/discovery-bytes/v1", index(&site.base).as_bytes()),
                    run.config.scope.discovery.as_ref().unwrap(),
                    &run.config.scope.sources,
                    recipe_pin,
                ),
            )
            .unwrap();
            assert_eq!(cursor.source_digest, expected);
        }
    }
}
