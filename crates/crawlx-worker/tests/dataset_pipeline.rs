//! Item-pipeline rejection accounting and accepted-item/outbox transaction regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::{routing::get, Router};
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::extensions::{ExtensionConfigV1, ExtensionFailurePolicyV1, ExtensionSpecV1, HandlerV1};
use crawlx_core::{AuthorizationRecordId, CreateCrawl};
use crawlx_storage::MemoryStore;
use crawlx_worker::{LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

#[tokio::test]
async fn item_rejection_records_one_reason_and_never_creates_a_dataset_or_outbox_item() {
    let valid = include_str!("../../crawlx-bench/fixtures/ext-article/main.html");
    let missing_title = valid
        .replace("<title>River report</title>", "")
        .replace("<h1>River report</h1>", "");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/accepted",
                get(move || async move { axum::response::Html(valid) }),
            )
            .route(
                "/invalid-item",
                get(move || async move { axum::response::Html(valid) }),
            )
            .route(
                "/rejected",
                get(move || async move { axum::response::Html(missing_title.clone()) }),
            );
        axum::serve(listener, app).await.unwrap();
    });
    for (path, accepted, invalid_item) in [
        ("accepted", true, false),
        ("rejected", false, false),
        ("invalid-item", false, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryStore::new());
        let stores = Stores::over_memory(store, dir.path()).await.unwrap();
        let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/{path}")).unwrap());
        crawl.mode = CrawlMode::Static;
        crawl.seed = Some(23);
        crawl.scope.max_discovery_depth = 0;
        crawl.scope.sitemap = SitemapMode::Skip;
        crawl.limits.urls = 1;
        crawl.safety.allow_private_networks = true;
        crawl.safety.respect_robots_txt = false;
        crawl.safety.authorization_record_ref = Some(AuthorizationRecordId::new());
        crawl.politeness.delay_ms = 0;
        crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
        if invalid_item {
            crawl.extract.content.as_mut().unwrap().item_loader = Some(
                serde_json::from_value(serde_json::json!({
                    "version":1,
                    "fields":[{
                        "name":"required",
                        "selectors":[{"kind":"css","expression":"#absent"}],
                        "extraction":{"kind":"text"},
                        "cardinality":"one",
                        "required":true
                    }]
                }))
                .unwrap(),
            );
        }
        crawl
            .extensions
            .routes
            .insert("default".into(), HandlerV1::DocumentItem);
        crawl.extensions.dataset = Some("items".into());
        let mut required = ExtensionSpecV1::new(ExtensionConfigV1::RequireTitle {}, 1);
        required.failure_policy = ExtensionFailurePolicyV1::Reject;
        crawl.extensions.extensions =
            vec![ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0), required];
        crawl.datasets.stores.push(
            serde_json::from_value(serde_json::json!({
                "name":"items", "schemaVersion":"document_item_v1", "maxItems":10, "maxBytes":1048576
            }))
            .unwrap(),
        );
        let mut authorization = common::authorization::verified_record(&crawl, stores.tenant);
        authorization.robots_override_acknowledged = true;
        let report = crawlx_worker::run_local_with(
            LocalRun::new(
                crawl,
                WorkerConfig {
                    artifacts_dir: dir.path().to_path_buf(),
                    ..WorkerConfig::default()
                },
            )
            .with_stores(stores.clone())
            .with_authorization(authorization),
        )
        .await
        .unwrap();
        let pages = stores.pages.list(report.run_id).await.unwrap();
        assert_eq!(pages.len(), 1);
        let expected = if accepted {
            serde_json::json!({"accepted":1,"rejected":0})
        } else {
            serde_json::json!({"accepted":0,"rejected":1,"reason":"extension_item_rejected"})
        };
        assert_eq!(pages[0].metadata["itemPipeline"], expected);
        let items = stores
            .datasets
            .items(report.run_id, "items", 0, 10)
            .await
            .unwrap();
        assert_eq!(items.len(), usize::from(accepted));
        let worker = crawlx_core::WorkerId::new();
        assert!(stores
            .delivery
            .claim(report.run_id, worker, 10, 30)
            .await
            .unwrap()
            .is_empty());
    }
    server.abort();
}
