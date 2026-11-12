//! The scrape `clusters` option through real runs: the chunks of the final article text are
//! embedded by the operator-configured model and grouped, and a worker without a model fails the
//! page as `llm_not_configured` before it fetches anything. In-memory stores, a fixture HTTP site
//! on 127.0.0.1 and a mock embeddings client: no network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::extraction::{ClusterPolicyV1, ExtractionPolicyV1};
use crawlx_core::scrape::{JobKind, ScrapeDocument, ScrapeJob, ScrapeOptions};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_model::llm::MockEmbeddings;
use crawlx_storage::MemoryStore;
use crawlx_worker::{ClusterEmbeddings, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use url::Url;

const PAGE: &str =
    "<!doctype html><html lang=\"en\"><head><title>Three subjects</title></head><body><article>\
<p>The river water flows past the river bank and the lake water meets the river shore every morning.</p>\
<p>Market price trade and stock market rally lift every trade price as the market opens higher today.</p>\
<p>Mountain trail hiking leads to a summit trail where the hiking path climbs the mountain slowly.</p>\
<p>Lake water and river water move along the river bank while the river shore stays calm and wet.</p>\
<p>Stock trade price falls in the market and the market price of every trade drops by the close.</p>\
<p>Hiking the summit trail on the mountain takes the mountain hiking trail past a high summit view.</p>\
</article></body></html>";

struct Site {
    base: String,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start() -> Site {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = Router::new().route(
        "/page",
        get(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response() }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Site { base, hits, task }
}

fn options(clusters: usize) -> ScrapeOptions {
    let content: ExtractionPolicyV1 = serde_json::from_value(serde_json::json!({
        "version": 1,
        "minMainChars": 1,
        "chunks": { "strategy": { "kind": "regex", "pattern": "\\n\\s*\\n" } },
    }))
    .unwrap();
    let mut policy = ClusterPolicyV1::default();
    policy.clusters = clusters;
    ScrapeOptions {
        content_policy: Some(content),
        clusters: Some(policy),
        ..ScrapeOptions::default()
    }
}

/// One scrape run of `/page`; the stored document of the page, and the reason of its failed row.
async fn scrape(
    site: &Site,
    options: ScrapeOptions,
    embeddings: Option<ClusterEmbeddings>,
) -> (Option<ScrapeDocument>, Option<String>) {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(Url::parse(&format!("{}/page", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_112);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.max_discovery_depth = 0;
    crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        embeddings,
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let report = run_local_with(LocalRun::new(crawl, config).with_stores(stores.clone()))
        .await
        .unwrap();
    let document = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/page")
        .and_then(|page| ScrapeDocument::from_page_metadata(&page.metadata));
    let failed = stores
        .frontier
        .list(report.run_id)
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.url.url.path() == "/page")
        .and_then(|entry| entry.denial_reason);
    (document, failed)
}

#[tokio::test]
async fn the_page_chunks_are_embedded_once_and_grouped_by_subject() {
    let site = start().await;
    let mock = Arc::new(MockEmbeddings::new(256));
    let embeddings = ClusterEmbeddings::new(mock.clone(), "mock-embed");
    let (document, failed) = scrape(&site, options(3), Some(embeddings)).await;
    assert_eq!(failed, None);
    let clusters = document.unwrap().clusters.expect("clusters were requested");
    assert_eq!(clusters.model, "mock-embed");
    assert_eq!(clusters.clusters.len(), 3);
    assert!(
        clusters.clusters.iter().all(|cluster| cluster.members.len() == 2),
        "two paragraphs per subject: {clusters:?}"
    );
    // one call, one vector per chunk, nothing but page text
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].len(), 6);
}

#[tokio::test]
async fn a_worker_without_an_embedding_model_fails_the_page_before_fetching_it() {
    let site = start().await;
    let (document, failed) = scrape(&site, options(3), None).await;
    assert!(document.is_none());
    assert_eq!(failed.as_deref(), Some("llm_not_configured"));
    assert_eq!(
        site.hits.load(Ordering::SeqCst),
        0,
        "the page was never requested"
    );
}

#[tokio::test]
async fn a_page_without_the_requested_clusters_option_carries_none() {
    let site = start().await;
    let mut plain = options(3);
    plain.clusters = None;
    let (document, failed) = scrape(&site, plain, None).await;
    assert_eq!(failed, None);
    assert!(document.unwrap().clusters.is_none());
}
