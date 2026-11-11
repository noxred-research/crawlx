//! Safe JSON imports exercise the authenticated router and real in-memory storage composition.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use axum::http::{Method, StatusCode};
use common::env;
use crawlx_api::Scope;
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{ArtifactStore, FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::{CrawlRunId, WorkerId};
use crawlx_storage::{testkit::canonical_url, WorkerRegistry};
use serde_json::json;

fn export() -> serde_json::Value {
    json!({
        "version":1,
        "source":{"backend":"filesystem","version":"1.0","experimental":false,"dedupe":"exact"},
        "policy":{"purgeOnStart":false,"sharedFilesystemQueue":false,"authoritativeBackend":"postgre_sql"},
        "dataset":"records","schemaVersion":"json_object_v1","batch":"export-1",
        "items":[{"key":"one","value":{"text":"accepted-import-object","password":"import-secret-canary"}}]
    })
}

#[tokio::test]
async fn authenticated_import_uses_live_fence_and_never_publishes_unapproved_bytes() {
    for zdr in [false, true] {
        let e = env();
        let worker = WorkerId::new();
        e.store
            .register_worker(worker, "dataset-import-fixture", "1")
            .await
            .unwrap();
        e.store
            .publish_acquisition_capabilities(
                worker,
                &[crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
                    "fixture", "1",
                )],
            )
            .await
            .unwrap();
        e.store
            .publish_data_capabilities(worker, &Default::default())
            .await
            .unwrap();
        let create = json!({"seedUrl":"https://example.test/",
        "retention":{"mode":if zdr {"zdr"} else {"standard"}},
        "datasets":{"version":1,"stores":[{
            "name":"records","schemaVersion":"json_object_v1","maxItems":10,"maxBytes":1048576
        }]}});
        let (status, _, created) = e.post("/v1/crawls", &create).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{created}");
        let id = created["id"].as_str().unwrap();
        let run: CrawlRunId = id.parse().unwrap();
        e.store.set_status(run, RunStatus::Running, None).await.unwrap();
        let (_, request) = e
            .store
            .discover(run, &canonical_url("https://example.test/import"), 0, None, None)
            .await
            .unwrap();
        let request = request.unwrap();
        let (_, fence) = e
            .store
            .lease_batch_fenced(run, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let path =
            format!("/v1/crawls/{id}/datasets/import?requestId={request}&fence={fence}&stateVersion=1");
        let input = export();
        assert_eq!(
            e.send(Method::POST, &path, None, &[], Some(&input)).await.0,
            StatusCode::UNAUTHORIZED
        );
        let read_only = e.key_for("acme", &[Scope::CrawlsRead]).await;
        assert_eq!(
            e.send(Method::POST, &path, Some(&read_only), &[], Some(&input))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let foreign = e.key_for("foreign", &[Scope::CrawlsWrite]).await;
        assert_eq!(
            e.send(Method::POST, &path, Some(&foreign), &[], Some(&input))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let mut destructive = input.clone();
        destructive["policy"]["purgeOnStart"] = true.into();
        assert_eq!(
            e.post(&path, &destructive).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let stale = format!(
            "/v1/crawls/{id}/datasets/import?requestId={request}&fence={}&stateVersion=1",
            fence + 1
        );
        assert_eq!(e.post(&stale, &input).await.0, StatusCode::CONFLICT);
        assert!(e
            .state
            .repos
            .datasets
            .items(run, "records", 0, 10)
            .await
            .unwrap()
            .is_empty());
        let (status, _, receipt) = e.post(&path, &input).await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["data"]["itemCount"], 1);
        assert_eq!(receipt["data"]["completeCoverage"], false);
        let items = e.state.repos.datasets.items(run, "records", 0, 10).await.unwrap();
        assert_eq!(items.len(), 1);
        let bytes = ArtifactStore::get(e.artifacts.as_ref(), items[0].item.content.artifact())
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("import-secret-canary"));
        assert!(String::from_utf8_lossy(&bytes).contains("accepted-import-object"));
        assert_eq!(
            e.store.get_request(run, request).await.unwrap().entry.status,
            FrontierStatus::Succeeded
        );
        if zdr {
            assert!(matches!(
                items[0].item.content,
                crawlx_core::dataset::DatasetContentV1::Volatile { .. }
            ));
            assert!(e
                .artifacts
                .row(items[0].item.content.artifact().id)
                .await
                .unwrap()
                .is_none());
        }
        assert_eq!(e.post(&path, &input).await.0, StatusCode::CONFLICT);
        assert_eq!(
            e.state
                .repos
                .datasets
                .items(run, "records", 0, 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
