//! Real URL-plane source response without an operator source dispatcher: typed unavailable,
//! no archive interpretation and no child fetch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::{http::header, routing::get, Router};
use crawlx_core::{
    config::CrawlMode,
    discovery::{DiscoverySourceV1, SourceDiscoveryPolicyV1},
    CreateCrawl,
};
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Hits(Mutex<Vec<String>>);

async fn record(
    axum::extract::State(hits): axum::extract::State<Arc<Hits>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.0.lock().unwrap().push(request.uri().path().into());
    next.run(request).await
}

#[tokio::test]
async fn archive_source_without_operator_dispatcher_is_typed_unavailable_and_not_followed() {
    let hits = Arc::new(Hits::default());
    // A stored ZIP header whose entry name is a URL: a parser would have a child to propose.
    let mut archive = b"PK\x03\x04".to_vec();
    archive.extend_from_slice(b"http://127.0.0.1/child-from-archive");
    let app = Router::new()
        .route(
            "/archive.zip",
            get(move || {
                let archive = archive.clone();
                async move { ([(header::CONTENT_TYPE, "application/zip")], archive) }
            }),
        )
        .route("/child-from-archive", get(|| async { "must not be fetched" }))
        .with_state(Arc::clone(&hits))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut crawl = CreateCrawl::new(format!("{base}/archive.zip").parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_111);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.known_files.clear();
    crawl.scope.sources = vec![DiscoverySourceV1::Feeds];
    crawl.scope.extension_match = vec!["zip".into()];
    crawl.scope.discovery = Some(SourceDiscoveryPolicyV1::default());
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
    let report =
        common::authorization::run_authorized_local_with(LocalRun::new(crawl, config).with_stores(stores))
            .await
            .unwrap();
    let page = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/archive.zip")
        .unwrap();
    assert_eq!(page.metadata["source_dispatch"]["status"], "unavailable");
    assert_eq!(
        page.metadata["source_dispatch"]["reason"],
        "operator_policy_missing"
    );
    assert!(page.metadata.get("source_discovery").is_none());
    assert_eq!(
        hits.0
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.as_str() == "/child-from-archive")
            .count(),
        0,
    );
    task.abort();
}

#[tokio::test]
async fn configured_dispatcher_admits_children_through_fenced_append_and_stores_evidence() {
    let hits = Arc::new(Hits::default());
    let app = Router::new()
        .route(
            "/feed",
            get(|headers: axum::http::HeaderMap| async move {
                let host = headers.get(header::HOST).unwrap().to_str().unwrap().to_owned();
                let body = format!(
                    "<rss><channel><item><title>One</title><link>http://{host}/a</link></item>\
                 <item><title>Two</title><link>http://{host}/b</link></item>\
                 <item><title>Outside</title><link>http://{host}/outside</link></item>\
                 </channel></rss>"
                );
                ([(header::CONTENT_TYPE, "application/rss+xml")], body)
            }),
        )
        .route(
            "/a",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html><body>a</body></html>",
                )
            }),
        )
        .route(
            "/b",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html><body>b</body></html>",
                )
            }),
        )
        .route("/outside", get(|| async { "must not be fetched" }))
        .with_state(Arc::clone(&hits))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut crawl = CreateCrawl::new(format!("{base}/feed").parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_112);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.known_files.clear();
    crawl.scope.sources = vec![DiscoverySourceV1::Feeds];
    crawl.scope.include_paths = vec!["^/(feed|a|b)$".into()];
    crawl.scope.discovery = Some(SourceDiscoveryPolicyV1::default());
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
        source_dispatch: Some(Arc::new(
            crawlx_worker::source_dispatch::SourceDispatcher::from_json(br#"{"version":1}"#).unwrap(),
        )),
        ..WorkerConfig::default()
    };
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl, config).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let count = |path: &str| {
        hits.0
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.as_str() == path)
            .count()
    };
    // The dispatcher reads only the stored body: one feed fetch, each in-scope child once.
    assert_eq!(
        (count("/feed"), count("/a"), count("/b"), count("/outside")),
        (1, 1, 1, 0)
    );
    let feed = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/feed")
        .unwrap();
    let dispatch = &feed.metadata["source_dispatch"];
    assert_eq!(dispatch["status"], "parsed");
    assert_eq!(dispatch["references"], 3);
    assert!(dispatch.get("freshness").is_some() && dispatch.get("policyDigest").is_some());
    let reference: crawlx_core::ArtifactRef = serde_json::from_value(dispatch["content"].clone()).unwrap();
    let evidence: serde_json::Value =
        serde_json::from_slice(&stores.artifacts.get(&reference).await.unwrap()).unwrap();
    // One feed container record plus one child per item.
    assert_eq!(evidence["children"].as_array().unwrap().len(), 4);
    assert!(evidence["references"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["route"] == "default"));
    let rows = stores.frontier.list(report.run_id).await.unwrap();
    for path in ["/a", "/b"] {
        assert!(
            rows.iter().any(|row| row.url.url.path() == path),
            "{path} admitted"
        );
    }
    let outside = rows
        .iter()
        .find(|row| row.url.url.path() == "/outside")
        .map(|row| row.status);
    assert_ne!(outside, Some(crawlx_core::repo::FrontierStatus::Succeeded));
    task.abort();
}
