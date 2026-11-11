//! Real URL-plane ZIP source response with a configured operator dispatcher: the archive is
//! parsed natively from its stored body, in-scope children are admitted and fetched once, and
//! the evidence record is stored.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::{http::header, routing::get, Router};
use crawlx_core::{
    config::CrawlMode,
    discovery::{DiscoverySourceV1, SourceDiscoveryPolicyV1},
    CreateCrawl,
};
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::io::{Cursor, Write};
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

fn archive(entries: &[(&str, String)]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[tokio::test]
async fn configured_dispatcher_admits_zip_children_once_and_stores_evidence() {
    let hits = Arc::new(Hits::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let bytes = archive(&[
        (
            "first.html",
            format!("<html><body><a href=\"{base}/a\">a</a></body></html>"),
        ),
        (
            "second.html",
            format!("<html><body><a href=\"{base}/b\">b</a><a href=\"{base}/outside\">o</a></body></html>"),
        ),
    ]);
    let app = Router::new()
        .route(
            "/archive.zip",
            get(move || {
                let bytes = bytes.clone();
                async move { ([(header::CONTENT_TYPE, "application/zip")], bytes) }
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
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut crawl = CreateCrawl::new(format!("{base}/archive.zip").parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_113);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.known_files.clear();
    crawl.scope.sources = vec![DiscoverySourceV1::Feeds];
    crawl.scope.include_paths = vec!["^/(archive\\.zip|a|b)$".into()];
    crawl.scope.extension_match = vec!["zip".into(), "none".into()];
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
    // The dispatcher reads only the stored body: one archive fetch, each in-scope child once,
    // and the out-of-scope reference is never fetched.
    assert_eq!(
        (count("/archive.zip"), count("/a"), count("/b"), count("/outside")),
        (1, 1, 1, 0)
    );
    let root = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/archive.zip")
        .unwrap();
    let dispatch = &root.metadata["source_dispatch"];
    assert_eq!(dispatch["status"], "parsed");
    assert_eq!(dispatch["references"], 3);
    assert!(dispatch.get("policyDigest").is_some());
    let reference: crawlx_core::ArtifactRef = serde_json::from_value(dispatch["content"].clone()).unwrap();
    let evidence: serde_json::Value =
        serde_json::from_slice(&stores.artifacts.get(&reference).await.unwrap()).unwrap();
    // The archive container record plus one child per entry.
    assert_eq!(evidence["children"].as_array().unwrap().len(), 3);
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
