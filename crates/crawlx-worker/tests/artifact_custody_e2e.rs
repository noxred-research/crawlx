//! Artifact custody, end to end: a real in-process static crawl over an owned loopback
//! fixture with `Standard` retention publishes its page content through run-wide artifact
//! custody. No artifact object on disk holds plaintext; the report and every store read return
//! the plaintext.
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
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Unique text no log line, metadata or key can contain by accident.
const MARKER: &str = "custodyMarkerQ7Z4xk29Lw";

async fn fixture() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let page = format!(
        r#"<html><head><title>Custody</title></head><body><main><h1>Custody</h1>
        <p>The unique fixture sentence is {MARKER} and it must never reach the disk in clear.</p>
        <a href="/second">second</a></main></body></html>"#
    );
    let second = format!(
        r#"<html><head><title>Second</title></head><body><main><h1>Second</h1>
        <p>A second page repeats {MARKER} for a second retained artifact.</p></main></body></html>"#
    );
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let page = page.clone();
                async move { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response() }
            }),
        )
        .route(
            "/second",
            get(move || {
                let second = second.clone();
                async move { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], second).into_response() }
            }),
        );
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, task)
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

#[tokio::test]
async fn retained_page_content_is_ciphertext_on_disk_and_plaintext_through_reads() {
    let (base, server) = fixture().await;
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_107);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    // The memory store the CLI's local mode uses: a single-process custody authority and an
    // in-memory key provider, both `Required` for every worker write.
    let stores = Stores::over_memory_with_local_custody(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone()))
        .await
        .unwrap();

    // The run succeeded and retained both pages.
    assert_eq!(report.pages.len(), 2, "{:?}", report.pages);
    for page in &report.pages {
        assert!(
            page.markdown.is_some(),
            "no markdown artifact for {}",
            page.url.url
        );
    }

    // Every object on disk is ciphertext: the marker occurs in no file, in no encoding of the
    // bytes the store wrote.
    let files = files_under(dir.path());
    assert!(
        files
            .iter()
            .any(|file| file.strip_prefix(dir.path()).unwrap().starts_with("encrypted")),
        "expected sealed objects under encrypted/, found {files:?}"
    );
    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        assert!(
            !bytes
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes()),
            "plaintext fixture text found in {}",
            file.display()
        );
    }
    assert!(
        !files
            .iter()
            .any(|file| file.strip_prefix(dir.path()).unwrap().starts_with("content")),
        "a plaintext content/ object was written: {files:?}"
    );

    // Reads decrypt: the report's page contents and a direct artifact read return the text.
    let rebuilt = crawlx_worker::run::build_report(&stores, report.run_id)
        .await
        .unwrap();
    assert_eq!(rebuilt.page_contents.len(), 2);
    for content in &rebuilt.page_contents {
        let markdown = content.markdown.as_deref().expect("markdown decrypts");
        assert!(markdown.contains(MARKER), "{markdown}");
    }
    let artifact = report.pages[0].markdown.clone().unwrap();
    let bytes = stores.artifacts.get(&artifact).await.unwrap();
    assert!(String::from_utf8(bytes).unwrap().contains(MARKER));

    server.abort();
}
