//! `scope.jsonEndpoints` on the static plane: the same-origin paths named by a JSON endpoint the
//! crawl already fetched become `json_endpoint` links under the usual scope and robots gates.
//! Owned loopback fixture only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};

struct Site {
    base: String,
    hits: Arc<Mutex<Vec<String>>>,
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
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.as_str() == path)
            .count()
    }
}

fn page(title: &str) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html")],
        format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>{}</p></main></body></html>",
            "A listed page with enough text to be extracted as content. ".repeat(8)
        ),
    )
}

/// `/` links only `/api/app-index.json`; its values name the items. `/private/` is disallowed by
/// robots, `/excluded/` by `excludePaths`; `/api/plain.json` is JSON served as `text/plain`.
async fn site() -> Site {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    // a path nested far below the depth bound
    let deep = format!("{}\"/app/item/99\"{}", "[".repeat(40), "]".repeat(40));
    let index = format!(
        r#"{{"title":"index","items":[{{"href":"/app/item/01"}},{{"href":"{base}/app/item/02#frag"}},
          {{"href":"/app/item/03","alt":"/app/item/03"}},{{"href":"/private/hidden"}},{{"href":"/excluded/x"}},
          {{"href":"https://elsewhere.invalid/app/item/off-origin"}},{{"href":"//elsewhere.invalid/x"}},
          {{"id":"relative/item/04"}},{{"count":7}}],
          "deep":{deep}}}"#
    );
    let plain = r#"{"href":"/app/item/from-plain-text"}"#;
    let app = {
        let hits = Arc::clone(&hits);
        Router::new()
            .route(
                "/",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/html")],
                        r#"<html><head><title>Home</title></head><body><main><h1>Home</h1>
                        <p>An application shell whose route table is a JSON document.</p>
                        <a href="/api/app-index.json">index</a> <a href="/api/plain.json">plain</a></main></body></html>"#,
                    )
                }),
            )
            .route(
                "/robots.txt",
                get(|| async { "User-agent: *\nDisallow: /private/\n" }),
            )
            .route(
                "/api/app-index.json",
                get(move || async move { ([(header::CONTENT_TYPE, "application/json")], index) }),
            )
            .route(
                "/api/plain.json",
                get(move || async move { ([(header::CONTENT_TYPE, "text/plain")], plain) }),
            )
            .route("/app/item/{name}", get(|| async { page("Item") }))
            .route("/private/hidden", get(|| async { page("Private") }))
            .route("/excluded/x", get(|| async { page("Excluded") }))
            .layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.lock().unwrap().push(request.uri().path().to_owned());
                        next.run(request).await
                    }
                },
            ))
    };
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, hits, task }
}

async fn crawl(site: &Site, tweak: impl FnOnce(&mut CreateCrawl)) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_121);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.exclude_paths = vec!["^/excluded/".into()];
    tweak(&mut crawl);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    run_local_with(LocalRun::new(crawl, config).with_stores(stores))
        .await
        .unwrap()
}

#[tokio::test]
async fn json_values_become_links_under_scope_robots_and_bounds() {
    let site = site().await;
    let report = crawl(&site, |_| {}).await;
    // admitted: root-relative and same-origin absolute values, once each
    for path in ["/app/item/01", "/app/item/02", "/app/item/03"] {
        assert_eq!(site.count(path), 1, "{path}");
        let page = report
            .pages
            .iter()
            .find(|page| page.url.url.path() == path)
            .unwrap_or_else(|| panic!("no page for {path}"));
        // an absolute URL may already have been mined from the document text as a script string
        let tag = page.metadata["request"]["tag"].as_str().unwrap();
        if path == "/app/item/02" {
            assert!(matches!(tag, "js" | "json_endpoint"), "{path}: {tag}");
        } else {
            assert_eq!(tag, "json_endpoint", "{path}");
        }
    }
    // refused by scope or robots: never requested
    assert_eq!(site.count("/excluded/x"), 0, "excludePaths still applies");
    assert_eq!(site.count("/private/hidden"), 0, "robots.txt still applies");
    // not paths of this origin, or not values at all
    for path in ["/app/item/off-origin", "/x", "/relative/item/04"] {
        assert_eq!(site.count(path), 0, "{path}");
    }
    // deeper than the depth bound
    assert_eq!(site.count("/app/item/99"), 0);
    // JSON that is not declared `application/json` is not read
    assert_eq!(site.count("/api/plain.json"), 1);
    assert_eq!(site.count("/app/item/from-plain-text"), 0);
}

#[tokio::test]
async fn json_endpoints_can_be_switched_off() {
    let site = site().await;
    let report = crawl(&site, |crawl| crawl.scope.json_endpoints = false).await;
    assert_eq!(
        site.count("/api/app-index.json"),
        1,
        "the endpoint itself is still fetched"
    );
    // `/app/item/02` is an absolute URL: the existing script miner (`scope.jsEndpoints`) already
    // reads it out of the document text. Root-relative values are what `jsonEndpoints` adds.
    for path in ["/app/item/01", "/app/item/03"] {
        assert_eq!(site.count(path), 0, "{path}");
    }
    assert!(report
        .pages
        .iter()
        .all(|page| page.metadata["request"]["tag"] != "json_endpoint"));
}
