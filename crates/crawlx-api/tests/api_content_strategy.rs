#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The opt-in `contentStrategy` scrape option through the compat API: strict request parsing,
//! ZDR and consent refusal before any provider I/O, the native default (no provider call), and the
//! `modelV1` path through a real loopback chat-completions provider into `data.modelContent` and
//! `data.markdown`.

mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use axum::http::StatusCode;
use crawlx_model::llm::{ChatCompletionsClient, LlmConfig, LlmExtractor};
use scrape_rig::{Rig, RigConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SCRAPE: &str = "/compat/v2/scrape";

fn envelope(value: &Value) -> Value {
    json!({
        "choices": [{"finish_reason": "stop", "message": {"content": value.to_string()}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18}
    })
}

fn generated() -> Value {
    json!({
        "version": 1,
        "markdown": "Generated A.",
        "tables": [{"headers": ["Name", "Value"], "rows": [["a", "1"]], "ambiguous": false}]
    })
}

fn strategy() -> Value {
    json!({
        "strategy": "modelV1",
        "target": "tablesAndContent",
        "maxOutputTokens": 512,
        "maxResponseBytes": 65536,
        "externalProcessingConsent": true
    })
}

/// A loopback provider that must see exactly `calls` bounded, non-streamed requests.
async fn provider(calls: u64) -> (MockServer, Arc<dyn LlmExtractor>) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"max_tokens": 512, "stream": false})))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(&generated())))
        .expect(calls)
        .mount(&server)
        .await;
    let client = ChatCompletionsClient::new(LlmConfig::new(&server.uri(), "fixture-model")).unwrap();
    (server, Arc::new(client))
}

async fn rig_with(llm: Arc<dyn LlmExtractor>) -> Rig {
    Rig::start(RigConfig {
        llm: Some(llm),
        ..RigConfig::default()
    })
    .await
}

#[tokio::test]
async fn model_strategy_returns_generated_model_content_and_markdown() {
    let (_server, llm) = provider(1).await;
    let rig = rig_with(llm).await;
    let (s, _, v) = rig
        .env
        .post(
            SCRAPE,
            &json!({"url": rig.url("/a"), "contentStrategy": strategy()}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"]["modelContent"], generated(), "{v}");
    assert_eq!(v["data"]["markdown"], "Generated A.", "{v}");
    rig.stop().await;
}

#[tokio::test]
async fn native_strategy_and_omission_never_call_a_provider() {
    let (server, llm) = provider(0).await;
    let rig = rig_with(llm).await;
    let native = json!({"strategy": "nativeV1"});
    let mut markdown = Vec::new();
    for body in [
        json!({"url": rig.url("/a")}),
        json!({"url": rig.url("/a"), "contentStrategy": native}),
    ] {
        let (s, _, v) = rig.env.post(SCRAPE, &body).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(v["data"].get("modelContent").is_none(), "{v}");
        markdown.push(v["data"]["markdown"].clone());
    }
    assert_eq!(markdown[0], markdown[1], "native strategy is the omitted default");
    assert!(server.received_requests().await.unwrap().is_empty());
    rig.stop().await;
}

#[tokio::test]
async fn zero_data_retention_and_lockdown_refuse_before_any_provider_io() {
    let (server, llm) = provider(0).await;
    let rig = rig_with(llm).await;
    for extra in [json!({"zeroDataRetention": true}), json!({"lockdown": true})] {
        let mut body = json!({"url": rig.url("/a"), "contentStrategy": strategy()});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (s, _, v) = rig.env.post(SCRAPE, &body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(v.to_string().contains("unsupported_with_zdr"), "{v}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    rig.stop().await;
}

#[tokio::test]
async fn malformed_unknown_or_unconsented_strategies_are_rejected() {
    let (server, llm) = provider(0).await;
    let rig = rig_with(llm).await;
    let cases = [
        json!({"strategy": "modelV2"}),
        json!({"strategy": "nativeV1", "target": "tables"}),
        json!({"strategy": "modelV1", "target": "tables", "maxOutputTokens": 512,
               "maxResponseBytes": 65536, "externalProcessingConsent": false}),
        json!({"strategy": "modelV1", "target": "tables", "maxOutputTokens": 512,
               "maxResponseBytes": 65536}),
        json!({"strategy": "modelV1", "target": "tables", "maxOutputTokens": 0,
               "maxResponseBytes": 65536, "externalProcessingConsent": true}),
        json!({"strategy": "modelV1", "target": "tables", "maxOutputTokens": 65537,
               "maxResponseBytes": 65536, "externalProcessingConsent": true}),
        json!({"strategy": "modelV1", "target": "tables", "maxOutputTokens": 512,
               "maxResponseBytes": 8388609, "externalProcessingConsent": true}),
        json!({"strategy": "modelV1", "target": "rows", "maxOutputTokens": 512,
               "maxResponseBytes": 65536, "externalProcessingConsent": true}),
        json!({"strategy": "modelV1", "target": "tables", "maxOutputTokens": 512,
               "maxResponseBytes": 65536, "externalProcessingConsent": true, "retries": 3}),
        json!("modelV1"),
    ];
    for case in cases {
        let (s, _, v) = rig
            .env
            .post(SCRAPE, &json!({"url": rig.url("/a"), "contentStrategy": case}))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{case}: {v}");
    }
    // two model content strategies at once are refused
    let (s, _, v) = rig
        .env
        .post(
            SCRAPE,
            &json!({"url": rig.url("/a"), "contentStrategy": strategy(), "onlyCleanContent": true}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(server.received_requests().await.unwrap().is_empty());
    rig.stop().await;
}

#[tokio::test]
async fn model_strategy_without_a_configured_model_is_an_explicit_failure() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = rig
        .env
        .post(
            SCRAPE,
            &json!({"url": rig.url("/a"), "contentStrategy": strategy()}),
        )
        .await;
    assert_ne!(s, StatusCode::OK, "never a silent native success: {v}");
    assert!(v["data"].get("modelContent").is_none(), "{v}");
    rig.stop().await;
}
