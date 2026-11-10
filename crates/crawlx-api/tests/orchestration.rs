//! Native request authority, bounded append and metadata/cursor endpoint regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use axum::http::StatusCode;
use common::{env, env_with, simple_body};
use crawlx_api::{ApiConfig, Scope, Settings};
use crawlx_core::{
    hash::Digest,
    orchestration::{OrchestrationConfigV1, RequestBatchV1},
    repo::{FrontierRepo, RunRepo},
    request::{import, MAX_REQUEST_BATCH},
    SecretOr, SystemClock,
};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn native_append_is_retryable_redacted_scoped_and_sealable() {
    let env = env();
    let id = env.create_run(&simple_body()).await;
    let endpoint = format!("/v1/crawls/{id}/requests");
    let body =
        json!({"producerEpoch":1,"requests":[{"url":"https://app.example.test/article","priority":4}]});
    let (status, _, first) = env
        .post_with(&endpoint, &[("Idempotency-Key", "batch-1")], &body)
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, _, second) = env
        .post_with(&endpoint, &[("Idempotency-Key", "batch-1")], &body)
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(first["data"], second["data"]);
    let (status, _, page) = env.get(&format!("{endpoint}?limit=1")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["data"].as_array().unwrap().len(), 1);
    assert!(!page.to_string().contains("app.example.test"));
    assert!(!page.to_string().contains("article"));
    let foreign = env.key_for("another-tenant", &[Scope::CrawlsRead]).await;
    assert_eq!(env.get_as(&foreign, &endpoint).await.0, StatusCode::NOT_FOUND);
    let seal = format!("{endpoint}/seal");
    assert_ne!(
        env.post(&seal, &json!({"producerEpoch":2})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        env.post(&seal, &json!({"producerEpoch":1})).await.0,
        StatusCode::OK
    );
    let later = json!({"producerEpoch":1,"requests":[{"url":"https://app.example.test/later"}]});
    assert_ne!(
        env.post_with(&endpoint, &[("Idempotency-Key", "batch-2")], &later)
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn caller_cannot_supply_authority_unknown_methods_or_scope_escape() {
    let env = env();
    let id = env.create_run(&simple_body()).await;
    let endpoint = format!("/v1/crawls/{id}/requests");
    for body in [
        json!({"producerEpoch":1,"tenant":"forged","requests":[]}),
        json!({"producerEpoch":1,"requests":[{"url":"https://app.example.test/","method":"POST"}]}),
        json!({"producerEpoch":1,"requests":[{"url":"https://outside.invalid/"}]}),
        json!({"producerEpoch":1,"requests":[{"url":"https://app.example.test/","sessionGeneration":3}]}),
        json!({"producerEpoch":1,"requests":[{"url":"https://user:secret@app.example.test/"}]}),
    ] {
        let (status, _, response) = env
            .post_with(&endpoint, &[("Idempotency-Key", "invalid")], &body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    }
    assert_eq!(
        env.post(&endpoint, &json!({"producerEpoch":1,"requests":[]}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        env.get(&format!("{endpoint}?limit=1001")).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn pinned_import_requires_operator_key_and_hashes_raw_unique_keys() {
    let source = json!({"producerEpoch":1,"export":{"version":1,
        "source":{"dialect":"js_actor_3_18","release":"3.18.2","commit":"78da0622762e1b569b5cb0b56e8eb06a0a010d93"},
        "requests":[{"url":"https://app.example.test/imported","sourceKey":"private-canary-unique-key"}]}});
    let absent = env();
    let id = absent.create_run(&simple_body()).await;
    assert_eq!(
        absent
            .post_with(
                &format!("/v1/crawls/{id}/requests/import"),
                &[("Idempotency-Key", "import-1")],
                &source
            )
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let configured = env_with(
        ApiConfig {
            rate_limit_per_minute: 0,
            request_identity_key: Some(SecretOr::secret([9; 32])),
            ..ApiConfig::default()
        },
        Settings::default(),
        Arc::new(SystemClock),
    );
    let id = configured.create_run(&simple_body()).await;
    let endpoint = format!("/v1/crawls/{id}/requests/import");
    let (status, _, response) = configured
        .post_with(&endpoint, &[("Idempotency-Key", "import-1")], &source)
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(!response.to_string().contains("private-canary-unique-key"));
    let (status, _, again) = configured
        .post_with(&endpoint, &[("Idempotency-Key", "import-1")], &source)
        .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(response["data"], again["data"]);
}

fn import_env() -> common::Env {
    env_with(
        ApiConfig {
            rate_limit_per_minute: 0,
            request_identity_key: Some(SecretOr::secret([9; 32])),
            ..ApiConfig::default()
        },
        Settings::default(),
        Arc::new(SystemClock),
    )
}

#[tokio::test]
async fn import_bypass_uses_batch_identity_and_keeps_normal_dedupe_and_conflicts() {
    let env = import_env();
    for (pin, flag) in [
        (import::SOURCE_PINS[1], "alwaysEnqueue"),
        (import::SOURCE_PINS[2], "dontFilter"),
        (import::SOURCE_PINS[3], "allowUrlRevisit"),
    ] {
        let id = env.create_run(&simple_body()).await;
        let run_id = id.parse().unwrap();
        let endpoint = format!("/v1/crawls/{id}/requests/import");
        let mut bypass =
            json!({"url":"https://app.example.test/imported","sourceKey":"private-canary-source"});
        bypass[flag] = json!(true);
        let normal = json!({"url":"https://app.example.test/imported","sourceKey":"private-canary-source"});
        let body = json!({"producerEpoch":1,"export":{"version":1,
            "source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
            "requests":[bypass.clone(),bypass,normal.clone(),normal]}});
        let (status, _, first) = env
            .post_with(&endpoint, &[("Idempotency-Key", "private-canary-batch-1")], &body)
            .await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["data"]["inserted"].as_array().unwrap().len(), 3);
        assert_eq!(first["data"]["duplicates"], 1);
        let first_id = first["data"]["inserted"][0].as_i64().unwrap();
        let accepted = env.store.get_request(run_id, first_id).await.unwrap();
        let encoded = serde_json::to_string(&accepted.envelope).unwrap();
        assert!(!encoded.contains("private-canary-source"));
        assert!(!encoded.contains("private-canary-batch"));
        assert!(accepted.envelope.metadata.is_empty());
        let (status, _, retry) = env
            .post_with(&endpoint, &[("Idempotency-Key", "private-canary-batch-1")], &body)
            .await;
        assert_eq!(status, StatusCode::OK, "{retry}");
        assert_eq!(first["data"], retry["data"]);
        let (status, _, next) = env
            .post_with(&endpoint, &[("Idempotency-Key", "private-canary-batch-2")], &body)
            .await;
        assert_eq!(status, StatusCode::OK, "{next}");
        assert_eq!(next["data"]["inserted"].as_array().unwrap().len(), 2);
        assert_eq!(next["data"]["duplicates"], 2);
        for new_id in next["data"]["inserted"].as_array().unwrap() {
            assert!(!first["data"]["inserted"].as_array().unwrap().contains(new_id));
        }
        let mut changed = body.clone();
        changed["export"]["requests"][0]["priority"] = json!(9);
        let (status, _, conflict) = env
            .post_with(
                &endpoint,
                &[("Idempotency-Key", "private-canary-batch-1")],
                &changed,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
        assert_eq!(conflict["error"]["code"], "invalid_state");
        assert_eq!(
            env.store.get_request(run_id, first_id).await.unwrap().envelope,
            accepted.envelope
        );
        let (status, _, retry) = env
            .post_with(&endpoint, &[("Idempotency-Key", "private-canary-batch-1")], &body)
            .await;
        assert_eq!(status, StatusCode::OK, "{retry}");
        assert_eq!(first["data"], retry["data"]);
        let (status, _, page) = env.get(&format!("/v1/crawls/{id}/requests")).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["data"].as_array().unwrap().len(), 5);
    }
}

#[tokio::test]
async fn import_bypass_preserves_hard_and_configured_row_limits() {
    let env = import_env();
    let id = env.create_run(&simple_body()).await;
    let endpoint = format!("/v1/crawls/{id}/requests/import");
    let pin = import::SOURCE_PINS[2];
    let row = json!({"url":"https://app.example.test/imported","sourceKey":"same","dontFilter":true});
    let mut body = json!({"producerEpoch":1,"export":{"version":1,
        "source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
        "requests":vec![row.clone(); MAX_REQUEST_BATCH + 1]}});
    let (status, _, response) = env
        .post_with(&endpoint, &[("Idempotency-Key", "bounded")], &body)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    let configured = usize::try_from(OrchestrationConfigV1::default().queue.batch_size).unwrap();
    body["export"]["requests"] = json!(vec![row.clone(); configured + 1]);
    let (status, _, response) = env
        .post_with(&endpoint, &[("Idempotency-Key", "bounded")], &body)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    assert!(env
        .store
        .page(id.parse().unwrap(), 0, 1000)
        .await
        .unwrap()
        .is_empty());
    body["export"]["requests"] = json!([row]);
    for headers in [vec![], vec![("Idempotency-Key", "invalid key")]] {
        let (status, _, response) = env.post_with(&endpoint, &headers, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    }
    let (status, _, response) = env
        .post_with(&endpoint, &[("Idempotency-Key", "bounded")], &body)
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["data"]["inserted"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn pre_batch_identity_bypass_receipt_conflicts_without_mutating_accepted_request() {
    let env = import_env();
    let id = env.create_run(&simple_body()).await;
    let run_id = id.parse().unwrap();
    let run = env.store.get(run_id).await.unwrap();
    let pin = import::SOURCE_PINS[2];
    let body = json!({"producerEpoch":1,"export":{"version":1,
        "source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
        "requests":[{"url":"https://app.example.test/imported","sourceKey":"same","dontFilter":true}]}});
    let tenant_key = Digest::keyed(&[9; 32], "crawlx/tenant-request-key/v1", run.tenant.0.as_bytes());
    let batch_id = Digest::keyed(&tenant_key.0, "crawlx/import-request-batch/v1", b"pre-upgrade");
    let source = serde_json::to_vec(&body["export"]).unwrap();
    let canonical = crawlx_url::CanonicalizeOptions::from_scope(
        &run.config.scope,
        run.seed.derive("resource-id-key", &[run.id.0.as_bytes()]),
    );
    let mut requests = import::decode_export(&source, &tenant_key.0, batch_id, |url| {
        crawlx_url::Canonicalizer::canonicalize_url(url, &canonical).map_err(|_| import::ImportError::Request)
    })
    .unwrap();
    // Reproduce the old immutable accepted envelope, not a production decoder fallback.
    let source_digest = Digest::keyed(&tenant_key.0, "crawlx/source-request-export/v1", &source);
    let material = serde_json::to_vec(&(source_digest, 0_usize, "same")).unwrap();
    requests[0].source_key = Some(Digest::keyed(
        &tenant_key.0,
        "crawlx/imported-request-key/v1",
        &material,
    ));
    let accepted = requests[0].clone();
    let batch = RequestBatchV1::new(run.tenant, run.id, "anonymous".into(), batch_id, requests);
    let receipt = env.store.append_batch(batch.clone()).await.unwrap();
    let endpoint = format!("/v1/crawls/{id}/requests/import");
    let (status, _, response) = env
        .post_with(&endpoint, &[("Idempotency-Key", "pre-upgrade")], &body)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    assert_eq!(
        env.store
            .get_request(run_id, receipt.inserted[0])
            .await
            .unwrap()
            .envelope,
        accepted
    );
    assert_eq!(env.store.append_batch(batch).await.unwrap(), receipt);
    assert_eq!(env.store.page(run_id, 0, 1000).await.unwrap().len(), 1);
}
