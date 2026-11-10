#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Strangler gateway pieces: the tenant `engine` flag, `X-Crawlx-Shadow: 1`
//! handling and the shadow router (sampling, ZDR exclusion, request rewrite, `run_kind`).
mod common;

use axum::http::StatusCode;
use common::{env_with, Env};
use crawlx_api::{ApiConfig, Settings};
use crawlx_core::config::OutputFormat;
use crawlx_core::repo::RunRepo;
use crawlx_core::SystemClock;
use crawlx_storage::TenantEngine;
use serde_json::{json, Value};
use std::sync::Arc;

const PATH: &str = "/compat/v2/crawl";

fn env_sampling(percent: u8) -> Env {
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let settings = Settings {
        shadow_sample_percent: percent,
        ..Settings::default()
    };
    env_with(config, settings, Arc::new(SystemClock))
}

fn body() -> Value {
    json!({
        "url": "https://docs.example.test/",
        "limit": 5000,
        "maxConcurrency": 8,
        "webhook": "https://hooks.example.test/fc",
        "scrapeOptions": { "formats": ["markdown"] }
    })
}

async fn shadow_post(e: &Env, key: &str, body: &Value) -> (StatusCode, Value) {
    let (s, _, v) = e
        .post_with(PATH, &[("x-crawlx-shadow", "1"), ("idempotency-key", key)], body)
        .await;
    (s, v)
}

#[tokio::test]
async fn sampled_shadow_request_is_mirrored_and_rewritten() {
    let e = env_sampling(100);
    let (s, v) = shadow_post(&e, "tee-1", &body()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    assert_eq!(v["shadow"], true);
    assert_eq!(v["mirrored"], true);
    let id = v["id"].as_str().unwrap();
    assert!(v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w["code"] == "shadow_rewritten"));

    let run = e.store.get(id.parse().unwrap()).await.unwrap();
    let c = &run.config;
    assert_eq!(c.limits.urls, 200, "limit clamped to 200 pages");
    assert_eq!(
        c.politeness.max_in_flight_per_origin, 4,
        "maxConcurrency 8 reaches the run as per-origin in-flight 8, and the shadow halves it"
    );
    assert!(
        c.output.webhook.is_none(),
        "shadow crawls never deliver customer webhooks"
    );
    assert!(
        c.output.formats.contains(&OutputFormat::RawHtml),
        "rawHtml added for source-change isolation"
    );
    assert_eq!(c.retention.days, 1, "24 h retention");
    assert!(e.api.is_shadow(run.id), "run_kind = 'shadow'");
    assert!(e
        .api
        .audit_entries()
        .iter()
        .any(|a| a.event == "shadow.mirrored" && a.run == Some(run.id)));

    // the gateway's retry with the same derived key replays, it does not create a second run
    let (s2, v2) = shadow_post(&e, "tee-1", &body()).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(v2["id"], v["id"]);
}

#[tokio::test]
async fn zero_data_retention_requests_are_never_mirrored() {
    let e = env_sampling(100);
    let mut b = body();
    b["zeroDataRetention"] = json!(true);
    let (s, v) = shadow_post(&e, "tee-zdr", &b).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["mirrored"], false);
    assert_eq!(v["reason"], "zero_data_retention");
    assert!(v.get("id").is_none());
    assert_eq!(e.api.audit_entries().len(), 0, "nothing recorded");
}

#[tokio::test]
async fn sampling_percent_zero_mirrors_nothing_and_is_deterministic_per_key() {
    let e = env_sampling(0);
    let (s, v) = shadow_post(&e, "tee-2", &body()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["mirrored"], false);
    assert_eq!(v["reason"], "not_sampled");

    // at 50 % the decision for one key is stable across environments (hash of tenant + key)
    let mut outcomes = Vec::new();
    for _ in 0..2 {
        let e = env_sampling(50);
        let (_, v) = shadow_post(&e, "tee-stable", &body()).await;
        outcomes.push(v["mirrored"].as_bool().unwrap());
    }
    assert_eq!(outcomes[0], outcomes[1]);
    // and across keys both outcomes occur
    // a fresh environment per key keeps the per-tenant active-run quota out of the picture
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..40 {
        let e = env_sampling(50);
        let (_, v) = shadow_post(&e, &format!("tee-{i}"), &body()).await;
        seen.insert(v["mirrored"].as_bool().unwrap());
    }
    assert_eq!(
        seen.len(),
        2,
        "50 % sampling must mirror some and skip some of 40 keys"
    );
}

#[tokio::test]
async fn shadow_without_idempotency_key_is_not_mirrored() {
    let e = env_sampling(100);
    let (s, _, v) = e.post_with(PATH, &[("x-crawlx-shadow", "1")], &body()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["mirrored"], false);
    assert_eq!(v["reason"], "not_sampled");
}

#[tokio::test]
async fn tenant_engine_flag_routes_compat_requests() {
    let e = env_sampling(100);
    // default engine: crawlx serves non-shadow requests
    let (s, _, v) = e.post(PATH, &body()).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    e.api.set_tenant_engine(e.tenant, TenantEngine::Upstream);
    let (s, _, v) = e.post(PATH, &body()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "engine_mismatch");
    let (s, v) = shadow_post(&e, "tee-fc", &body()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "engine_mismatch");

    e.api.set_tenant_engine(e.tenant, TenantEngine::Shadow);
    let (s, _, v) = e.post(PATH, &body()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, v) = shadow_post(&e, "tee-shadow", &body()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["mirrored"], true);

    // existing runs stay readable whatever the flag (sticky per crawl id)
    let id = v["id"].as_str().unwrap();
    e.api.set_tenant_engine(e.tenant, TenantEngine::Upstream);
    let (s, _, _) = e.get(&format!("{PATH}/{id}")).await;
    assert_eq!(s, StatusCode::OK);
}
