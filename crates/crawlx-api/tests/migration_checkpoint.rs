//! Authenticated checkpoint import acceptance using the unchanged shared API fixture.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use axum::http::StatusCode;
use common::{env_with, simple_body};
use crawlx_api::{ApiConfig, Settings};
use crawlx_core::{repo::FrontierRepo, request::import::SOURCE_PINS, SecretOr, SystemClock};
use serde_json::{json, Value};
use std::sync::Arc;

fn fixture() -> common::Env {
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

fn checkpoint() -> Value {
    let pin = SOURCE_PINS[2];
    json!({"format":"checkpoint_export_v1","producerEpoch":1,"export":{
        "version":1,"source":"fixture","producerEpoch":1,
        "expectedCursor":null,"endPosition":1,
        "export":{"version":1,"source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
            "requests":[
                {"url":"https://app.example.test/a?resource=1","sourceKey":"row-one"},
                {"url":"https://app.example.test/b?resource=2","sourceKey":"row-two","method":"HEAD"}
            ]}
    }})
}

#[tokio::test]
async fn authenticated_checkpoint_replays_after_router_restart_and_appends_only_next_interval() {
    let mut env = fixture();
    let id = env.create_run(&simple_body()).await;
    let endpoint = format!("/v1/crawls/{id}/requests/import");
    let mut body = checkpoint();
    let (status, _, first) = env
        .post_with(&endpoint, &[("Idempotency-Key", "first")], &body)
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["data"]["inserted"].as_array().unwrap().len(), 1);
    env.app = crawlx_api::router(env.state.clone());
    let (status, _, replay) = env
        .post_with(&endpoint, &[("Idempotency-Key", "first")], &body)
        .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(first["data"], replay["data"]);
    assert_ne!(
        env.post_with(&endpoint, &[("Idempotency-Key", "stale")], &body)
            .await
            .0,
        StatusCode::OK
    );
    body["export"]["expectedCursor"] = first["data"]["cursor"].clone();
    body["export"]["endPosition"] = json!(2);
    let (status, _, second) = env
        .post_with(&endpoint, &[("Idempotency-Key", "second")], &body)
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let row = env
        .store
        .get_request(
            id.parse().unwrap(),
            second["data"]["inserted"][0].as_i64().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(row.envelope.method, "HEAD");
    assert_eq!(row.envelope.url.url.query(), Some("resource=2"));
    assert_eq!(second["data"]["cursor"]["position"], 2);
    assert!(!second.to_string().contains("row-two"));
}

#[tokio::test]
async fn epoch_source_foreign_cursor_and_outer_overrides_fail_without_mutation() {
    let env = fixture();
    let id = env.create_run(&simple_body()).await;
    let endpoint = format!("/v1/crawls/{id}/requests/import");
    let original = checkpoint();
    let (_, _, first) = env
        .post_with(&endpoint, &[("Idempotency-Key", "first")], &original)
        .await;
    let cursor = first["data"]["cursor"].clone();
    for variant in 0..5 {
        let mut body = original.clone();
        body["export"]["expectedCursor"] = cursor.clone();
        body["export"]["endPosition"] = json!(2);
        match variant {
            0 => body["producerEpoch"] = json!(2),
            1 => body["export"]["export"]["requests"][1]["url"] = json!("https://app.example.test/changed"),
            2 => body["nextCursor"] = cursor.clone(),
            3 => body["expectedCursor"] = cursor.clone(),
            _ => body["format"] = json!("unknown_export"),
        }
        assert_ne!(
            env.post_with(&endpoint, &[("Idempotency-Key", "invalid")], &body)
                .await
                .0,
            StatusCode::OK
        );
    }
    let foreign = fixture();
    let foreign_id = foreign.create_run(&simple_body()).await;
    let mut body = original;
    body["export"]["expectedCursor"] = cursor;
    body["export"]["endPosition"] = json!(2);
    assert_ne!(
        foreign
            .post_with(
                &format!("/v1/crawls/{foreign_id}/requests/import"),
                &[("Idempotency-Key", "foreign")],
                &body
            )
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        env.store
            .metadata_page(id.parse().unwrap(), 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        foreign
            .store
            .metadata_page(foreign_id.parse().unwrap(), 0, 10)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn advertised_schema_accepts_checkpoint_format_and_keeps_append_format_free() {
    let document = crawlx_api::openapi::document();
    let import = &document["paths"]["/v1/crawls/{id}/requests/import"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    let mut schema = import.clone();
    schema
        .as_object_mut()
        .unwrap()
        .insert("components".into(), document["components"].clone());
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    assert!(validator.is_valid(&checkpoint()));
    assert_eq!(
        import["properties"]["format"]["enum"],
        json!(["request_export_v1", "checkpoint_export_v1"])
    );
    assert_eq!(import["properties"]["format"]["default"], "request_export_v1");
    let mut unknown = checkpoint();
    unknown["format"] = json!("unsupported_export");
    assert!(!validator.is_valid(&unknown));
    let legacy = json!({"producerEpoch":1,"export":checkpoint()["export"]["export"]});
    assert!(validator.is_valid(&legacy));
    let append = &document["paths"]["/v1/crawls/{id}/requests"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"];
    assert!(append["properties"].get("format").is_none());
}
