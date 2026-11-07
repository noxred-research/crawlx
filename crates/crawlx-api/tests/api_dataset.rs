//! Native authenticated dataset and exact-version KV endpoint consumers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use axum::http::{Method, StatusCode};
use common::{env, json};
use crawlx_api::Scope;
use crawlx_core::{
    dataset::{AcceptedBatchV1, AcceptedItemV1},
    orchestration::{RequestCommitRepo, RequestCommitV1},
    repo::{ArtifactStore, FrontierRepo, FrontierStatus, RunRepo},
    WorkerId,
};
use crawlx_storage::{testkit::canonical_url, WorkerRegistry};
use serde_json::json as value;

#[tokio::test]
async fn native_dataset_keysets_artifact_links_and_kv_etags_enforce_scopes_and_tenant() {
    let e = env();
    let worker = WorkerId::new();
    e.store
        .register_worker(worker, "api-dataset-fixture", "1")
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
    let body = value!({"seedUrl":"https://example.test/","datasets":{"version":1,
        "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":1048576}],
        "kvStores":[{"name":"state","maxKeys":10,"maxValueBytes":1048576,"maxBytes":1048576}]}});
    let (status, _, created) = e.post("/v1/crawls", &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    let id = created["id"].as_str().unwrap();
    let run_id: crawlx_core::CrawlRunId = id.parse().unwrap();
    let run = e.store.get(run_id).await.unwrap();
    let (_, request) = e
        .store
        .discover(run_id, &canonical_url("https://example.test/item"), 0, None, None)
        .await
        .unwrap();
    let request = request.unwrap();
    let lease = e
        .store
        .lease_batch_fenced(run_id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(lease.0.id, request);
    let bytes = b"{\"title\":\"actual accepted item\"}\n";
    let artifact = e
        .artifacts
        .put_dataset(run_id, request, "api_fixture", "application/json", bytes)
        .await
        .unwrap();
    let content = e
        .artifacts
        .dataset_content(run_id, request, &artifact, u64::try_from(bytes.len()).unwrap())
        .await
        .unwrap();
    let deadline = e.artifacts.row(artifact.id).await.unwrap().unwrap().expires_at;
    let mut item = AcceptedItemV1::new(
        "one".into(),
        "fixture_v1".into(),
        "document_item_v1".into(),
        "fixture_v1".into(),
        content.clone(),
        u64::try_from(bytes.len()).unwrap(),
    );
    item.expires_at = deadline;
    let mut commit = RequestCommitV1::terminal(run_id, request, lease.1, 1, FrontierStatus::Succeeded, None);
    commit
        .accepted
        .push(AcceptedBatchV1::new("items".into(), vec![item]));
    e.store.commit_fenced(commit).await.unwrap();
    let path = format!("/v1/crawls/{id}/datasets/items/items?limit=1");
    let (status, _, items) = e.get(&path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(items["data"][0]["item"]["ordinal"], 1);
    assert_eq!(items["nextCursor"], "1");
    let (status, _, content) = e.get(items["data"][0]["contentUrl"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content["title"], "actual accepted item");
    let (status, _, next) = e.get(&format!("{path}&cursor=1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next["data"], value!([]));
    assert_eq!(
        e.send(Method::GET, &path, None, &[], None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let foreign = e.key_for("foreign", &[Scope::CrawlsRead]).await;
    assert_eq!(e.get_as(&foreign, &path).await.0, StatusCode::NOT_FOUND);
    let read_only = e.key_for("acme", &[Scope::CrawlsRead]).await;
    let delta = value!({"store":"state","key":"checkpoint","expectedVersion":0,"content":content_handle(&artifact),
        "contentType":"application/json","sizeBytes":bytes.len(),"expiresAt":deadline});
    let kv = format!("/v1/crawls/{id}/kv/state/checkpoint");
    assert_eq!(
        e.send(
            Method::PUT,
            &kv,
            Some(&read_only),
            &[("if-match", "\"0\"")],
            Some(&delta)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, headers, body) = e
        .send(
            Method::PUT,
            &kv,
            Some(&e.key),
            &[("if-match", "\"0\"")],
            Some(&delta),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers["etag"], "\"1\"");
    assert_eq!(json(&body)["version"], 1);
    assert_eq!(
        e.send(
            Method::PUT,
            &kv,
            Some(&e.key),
            &[("if-match", "\"0\"")],
            Some(&delta)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, headers, _) = e
        .send(Method::DELETE, &kv, Some(&e.key), &[("if-match", "\"1\"")], None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["etag"], "\"2\"");
    let (status, _, tombstone) = e.get(&kv).await;
    assert_eq!(status, StatusCode::OK);
    assert!(tombstone["value"]["content"].is_null());
    let namespace = format!("/v1/crawls/{id}/kv/state");
    assert_eq!(
        e.send(Method::DELETE, &namespace, Some(&read_only), &[], None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        e.send(Method::DELETE, &namespace, Some(&e.key), &[], None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        e.send(
            Method::PUT,
            &kv,
            Some(&e.key),
            &[("if-match", "\"0\"")],
            Some(&delta)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(run.tenant, e.tenant);
}
fn content_handle(artifact: &crawlx_core::ArtifactRef) -> serde_json::Value {
    serde_json::to_value(crawlx_core::dataset::DatasetContentV1::Durable {
        artifact: artifact.clone(),
    })
    .unwrap()
}
