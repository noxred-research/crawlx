//! Intake of admitted writes: retained bodies, attribution to the calling key, typed refusals.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use common::{env_with, simple_body, Env};
use crawlx_api::{ApiConfig, Scope, Settings};
use crawlx_core::orchestration::OrchestrationConfigV1;
use crawlx_core::repo::FrontierRepo;
use crawlx_core::request::{keyed_body_digest, MAX_WRITE_BODY_BYTES};
use crawlx_core::safety::RiskClass;
use crawlx_core::{SecretOr, SystemClock};
use serde_json::{json, Value};
use std::sync::Arc;

const KEY: [u8; 32] = [9; 32];

fn write_env(key: Option<[u8; 32]>) -> Env {
    env_with(
        ApiConfig {
            rate_limit_per_minute: 0,
            request_identity_key: key.map(SecretOr::secret),
            ..ApiConfig::default()
        },
        Settings::default(),
        Arc::new(SystemClock),
    )
}

fn write_run(profile: &str, orchestration: bool) -> Value {
    let mut body = simple_body();
    body["safety"] = json!({"profile": profile, "destructiveActions": "approval"});
    if orchestration {
        body["orchestration"] = serde_json::to_value(OrchestrationConfigV1::default()).unwrap();
    }
    body
}

async fn append(env: &Env, id: &str, label: &str, requests: Value) -> (StatusCode, Value) {
    let (status, _, body) = env
        .post_with(
            &format!("/v1/crawls/{id}/requests"),
            &[("Idempotency-Key", label)],
            &json!({"producerEpoch":1,"requests":requests}),
        )
        .await;
    (status, body)
}

#[tokio::test]
async fn write_bodies_are_retained_exactly_attributed_to_the_key_and_never_listed() {
    let env = write_env(Some(KEY));
    let id = env.create_run(&write_run("test_environment", true)).await;
    let run = id.parse().unwrap();
    let json_body = json!({"z":[1,2,{"k":"v"}],"a":"naïve"});
    let binary: Vec<u8> = (0..=255u8).collect();
    let (status, response) = append(
        &env,
        &id,
        "bodies",
        json!([
            {"url":"https://app.example.test/form","method":"POST",
             "body":{"text":"a=1&b=two+words&c=%E2%9C%93","mediaType":"application/x-www-form-urlencoded"}},
            {"url":"https://app.example.test/item","method":"PUT","body":{"json":json_body}},
            {"url":"https://app.example.test/blob","method":"PATCH",
             "body":{"base64":base64::engine::general_purpose::STANDARD.encode(&binary)}},
            {"url":"https://app.example.test/item/7","method":"DELETE"}
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let inserted: Vec<i64> = response["data"]["inserted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_i64().unwrap())
        .collect();
    assert_eq!(inserted.len(), 4);

    let expected: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "POST",
            b"a=1&b=two+words&c=%E2%9C%93".to_vec(),
            "application/x-www-form-urlencoded",
        ),
        ("PUT", serde_json::to_vec(&json_body).unwrap(), "application/json"),
        ("PATCH", binary, "application/octet-stream"),
    ];
    let mut principals = std::collections::BTreeSet::new();
    for (id, (method, bytes, media_type)) in inserted.iter().zip(&expected) {
        let queued = env.store.get_request(run, *id).await.unwrap();
        assert_eq!(queued.envelope.method, *method);
        assert_eq!(queued.principal, "anonymous");
        principals.insert(queued.principal.clone());
        let body = queued.envelope.body.as_ref().expect("retained body");
        assert_eq!(body.media_type, *media_type);
        assert_eq!(body.length, u64::try_from(bytes.len()).unwrap());
        assert_eq!(body.digest, keyed_body_digest(&KEY, env.tenant, bytes));
        let artifact = body.artifact().expect("artifact handle");
        assert_eq!(&env.state.repos.artifacts.read(&artifact).await.unwrap(), bytes);
        // The handle never carries the keyed digest, and the queue row never holds content.
        assert!(!body.handle.contains(&body.digest.to_hex()));
        assert!(queued.envelope.approval.is_none());
    }
    assert_eq!(principals.len(), 1);
    assert!(principals.contains("anonymous"));
    // A DELETE without a body is a write with no body.
    let delete = env.store.get_request(run, inserted[3]).await.unwrap();
    assert!(delete.envelope.body.is_none());
    assert_eq!(delete.envelope.method, "DELETE");

    let (status, _, page) = env.get(&format!("/v1/crawls/{id}/requests")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let listing = page.to_string();
    for leaked in ["two+words", "naïve", "api_key:", "app.example.test"] {
        assert!(!listing.contains(leaked), "{leaked}: {listing}");
    }
}

#[tokio::test]
async fn different_bodies_do_not_dedupe_while_an_identical_write_does() {
    let env = write_env(Some(KEY));
    let id = env.create_run(&write_run("test_environment", true)).await;
    let write = |text: &str| {
        json!([{"url":"https://app.example.test/api","method":"POST",
                "body":{"text":text,"mediaType":"text/plain"}}])
    };
    let (_, first) = append(&env, &id, "one", write("a=1")).await;
    assert_eq!(first["data"]["inserted"].as_array().unwrap().len(), 1);
    // Same key, body, method and target in a new batch: the same request.
    let (_, repeat) = append(&env, &id, "two", write("a=1")).await;
    assert!(
        repeat["data"]["inserted"].as_array().unwrap().is_empty(),
        "{repeat}"
    );
    assert_eq!(repeat["data"]["duplicates"], 1);
    // A different body is a different request.
    let (_, body) = append(&env, &id, "three", write("a=2")).await;
    assert_eq!(body["data"]["inserted"].as_array().unwrap().len(), 1, "{body}");
    // The queue principal is always anonymous: another key submitting the same bytes is the same request.
    let other = env
        .key_for("acme", &Scope::all_set().into_iter().collect::<Vec<_>>())
        .await;
    let (status, _, response) = env
        .send(
            axum::http::Method::POST,
            &format!("/v1/crawls/{id}/requests"),
            Some(&other),
            &[("Idempotency-Key", "four")],
            Some(&json!({"producerEpoch":1,"requests":write("a=1")})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let response = common::json(&response);
    assert!(
        response["data"]["inserted"].as_array().unwrap().is_empty(),
        "{response}"
    );
}

#[tokio::test]
async fn read_only_runs_and_unconfigured_deployments_refuse_writes_with_typed_reasons() {
    let write = json!([{"url":"https://app.example.test/api","method":"POST","body":{"text":"a=1"}}]);

    let env = write_env(Some(KEY));
    let id = env.create_run(&simple_body()).await; // default profile: read_only
    let (status, response) = append(&env, &id, "ro", write.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.to_string().contains("write_read_only"), "{response}");

    let id = env.create_run(&write_run("test_environment", false)).await;
    let (status, response) = append(&env, &id, "no-limits", write.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.to_string().contains("attempt limits"), "{response}");

    let keyless = write_env(None);
    let id = keyless.create_run(&write_run("test_environment", true)).await;
    let (status, response) = append(&keyless, &id, "no-key", write).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
    assert!(
        response.to_string().contains("request_writes_unavailable"),
        "{response}"
    );
}

#[tokio::test]
async fn malformed_write_intake_is_refused_before_any_row_exists() {
    let env = write_env(Some(KEY));
    let id = env.create_run(&write_run("test_environment", true)).await;
    let oversize = "x".repeat(usize::try_from(MAX_WRITE_BODY_BYTES).unwrap() + 1);
    let cases = [
        (
            "mixed batch",
            json!([
                {"url":"https://app.example.test/a"},
                {"url":"https://app.example.test/b","method":"POST","body":{"text":"x"}}
            ]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "body on a safe method",
            json!([{"url":"https://app.example.test/a","method":"GET","body":{"text":"x"}}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "approval on a safe method",
            json!([{"url":"https://app.example.test/a","method":"HEAD","approval":{"riskClass":"destructive"}}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "two body kinds",
            json!([{"url":"https://app.example.test/a","method":"POST","body":{"text":"x","json":{}}}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "empty body object",
            json!([{"url":"https://app.example.test/a","method":"POST","body":{}}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "invalid base64",
            json!([{"url":"https://app.example.test/a","method":"POST","body":{"base64":"***"}}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "control byte in media type",
            json!([{"url":"https://app.example.test/a","method":"POST","body":{"text":"x","mediaType":"text/plain\r\nx: 1"}}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "unsupported method",
            json!([{"url":"https://app.example.test/a","method":"TRACE"}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "oversize body",
            json!([{"url":"https://app.example.test/a","method":"POST","body":{"text":oversize}}]),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "write outside scope",
            json!([{"url":"https://outside.invalid/a","method":"POST","body":{"text":"x"}}]),
            StatusCode::BAD_REQUEST,
        ),
        (
            "session binding",
            json!([{"url":"https://app.example.test/a","method":"POST","sessionGeneration":3}]),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (label, requests, expected) in cases {
        let (status, response) = append(&env, &id, "bad", requests).await;
        assert_eq!(status, expected, "{label}: {response}");
    }
    let (_, _, page) = env.get(&format!("/v1/crawls/{id}/requests")).await;
    assert!(page["data"].as_array().unwrap().is_empty(), "{page}");
}

#[tokio::test]
async fn an_approval_needs_the_reviewer_scope_and_the_methods_own_class() {
    let env = write_env(Some(KEY));
    let id = env.create_run(&write_run("test_environment", true)).await;
    let run = id.parse().unwrap();
    let delete = |class: &str| json!([{"url":"https://app.example.test/api/7","method":"DELETE","approval":{"riskClass":class}}]);
    let writer = env.key_for("acme", &[Scope::CrawlsWrite]).await;
    let (status, _, response) = env
        .send(
            axum::http::Method::POST,
            &format!("/v1/crawls/{id}/requests"),
            Some(&writer),
            &[("Idempotency-Key", "no-scope")],
            Some(&json!({"producerEpoch":1,"requests":delete("destructive")})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{}", common::json(&response));

    let (status, response) = append(&env, &id, "wrong-class", delete("persistent_write_own")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");

    let (status, response) = append(&env, &id, "approved", delete("destructive")).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let row = response["data"]["inserted"][0].as_i64().unwrap();
    let queued = env.store.get_request(run, row).await.unwrap();
    let approval = queued.envelope.approval.expect("approval is recorded");
    assert_eq!(approval.risk, RiskClass::Destructive);
    assert!(
        approval.approved_by.starts_with("api_key:"),
        "{}",
        approval.approved_by
    );
    assert!(env
        .api
        .audit_entries()
        .iter()
        .any(|entry| entry.event == "requests.write_submitted"));
}

#[tokio::test]
async fn the_openapi_document_names_the_write_fields() {
    let env = write_env(Some(KEY));
    let (_, _, doc) = env.get("/v1/openapi.json").await;
    let item = &doc["paths"]["/v1/crawls/{id}/requests"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"]["requests"]["items"]["properties"];
    for field in ["body", "approval"] {
        assert!(item[field].is_object(), "{field}");
    }
    assert_eq!(
        item["approval"]["properties"]["riskClass"]["enum"],
        json!(["persistent_write_own", "destructive"])
    );
}
