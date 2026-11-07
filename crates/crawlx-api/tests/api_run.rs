#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `run(ApiConfig)` end to end over a real socket (in-memory repositories).

use crawlx_api::auth::generate_key;
use crawlx_api::{run, run_until, ApiConfig, ApiKeyBootstrap};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn run_serves_bootstrap_keys_over_http() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let key = generate_key();
    let cfg = ApiConfig {
        bind: ([127, 0, 0, 1], port).into(),
        database_url: None,
        artifacts_dir: dir.path().to_path_buf(),
        api_keys: vec![ApiKeyBootstrap::new("acme", &key)],
        rate_limit_per_minute: 600,
        webhook_secret: "whsec_x".to_owned(),
        metrics_bind: None,
        ..ApiConfig::default()
    };
    let server = tokio::spawn(run(cfg));
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let mut up = false;
    for _ in 0..100 {
        if client.get(format!("{base}/v1/openapi.json")).send().await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "server did not come up");

    let doc: serde_json::Value = client
        .get(format!("{base}/v1/openapi.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(doc["paths"]["/v1/crawls"].is_object());

    let unauth = client
        .post(format!("{base}/v1/crawls"))
        .json(&json!({"seedUrl": "https://a.example.test/"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);
    let created = client
        .post(format!("{base}/v1/crawls"))
        .bearer_auth(&key)
        .json(&json!({"seedUrl": "https://a.example.test/"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 202);
    let location = created.headers()["location"].to_str().unwrap().to_owned();
    assert!(created.headers().contains_key("ratelimit-remaining"));
    let got: serde_json::Value = client
        .get(format!("{base}{location}"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got["status"], "queued");
    server.abort();

    // malformed bootstrap keys are a configuration error, not a panic
    let bad = ApiConfig {
        bind: ([127, 0, 0, 1], 0).into(),
        artifacts_dir: dir.path().to_path_buf(),
        api_keys: vec![ApiKeyBootstrap::new("acme", "not-a-key")],
        ..ApiConfig::default()
    };
    let err = run(bad).await.unwrap_err();
    assert!(matches!(err, crawlx_api::ApiError::Config(_)), "{err}");
}

#[tokio::test]
async fn run_until_drains_when_the_token_is_cancelled() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let cfg = ApiConfig {
        bind: ([127, 0, 0, 1], port).into(),
        artifacts_dir: dir.path().to_path_buf(),
        ..ApiConfig::default()
    };
    let shutdown = tokio_util::sync::CancellationToken::new();
    let server = tokio::spawn(run_until(cfg, shutdown.clone()));
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/v1/openapi.json");
    let mut up = false;
    for _ in 0..100 {
        if client.get(&url).send().await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "server did not come up");
    shutdown.cancel();
    let done = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server drains within 5 s")
        .unwrap();
    assert!(done.is_ok(), "{done:?}");
}
