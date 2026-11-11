//! Authenticated source-memo reset uses the same repository authority as workers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use axum::http::{Method, StatusCode};
use common::{env, json};
use crawlx_api::Scope;
use crawlx_core::dataset::memo::{MemoScopeV1, SourceMemoRepo};
use crawlx_core::hash::Digest;
use crawlx_core::repo::RunRepo;
use serde_json::json as value;

#[tokio::test]
async fn reset_requires_write_scope_and_owned_run_then_permits_seen_re_admission() {
    let e = env();
    let (status, _, created) = e
        .post("/v1/crawls", &value!({"seedUrl":"https://fixture.test/"}))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    let id = created["id"].as_str().unwrap();
    let run = e.store.get(id.parse().unwrap()).await.unwrap();
    let key = Digest::of("api-source-memo-test/v1", b"article");
    let scope = MemoScopeV1::new(run.tenant, run.id, key, key, key);
    let now = run.created_at;
    e.store.record_seen(&scope, &[key], 20_000, now).await.unwrap();
    let path = format!("/v1/crawls/{id}/source-memo");
    assert_eq!(
        e.send(Method::DELETE, &path, None, &[], None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let read_only = e.key_for("acme", &[Scope::CrawlsRead]).await;
    assert_eq!(
        e.send(Method::DELETE, &path, Some(&read_only), &[], None).await.0,
        StatusCode::FORBIDDEN
    );
    let foreign = e.key_for("foreign", &[Scope::CrawlsWrite]).await;
    assert_eq!(
        e.send(Method::DELETE, &path, Some(&foreign), &[], None).await.0,
        StatusCode::NOT_FOUND
    );
    assert!(e.store.seen(&scope, key, now).await.unwrap());
    let (status, headers, body) = e.send(Method::DELETE, &path, Some(&e.key), &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "private, no-store");
    assert_eq!(json(&body)["reset"], true);
    assert_eq!(json(&body)["frontierUnchanged"], true);
    assert!(!e.store.seen(&scope, key, now).await.unwrap());
    e.store.record_seen(&scope, &[key], 20_000, now).await.unwrap();
    assert!(e.store.seen(&scope, key, now).await.unwrap());
}
