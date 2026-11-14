#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Scoped bootstrap API keys (`ApiKeyBootstrap::parse_spec`) through `run` over a real socket
//! (in-memory repositories): an `agent` key works on the agent routes and gets the typed `403
//! scope_missing` on every operator route, while the plain and `operator` forms keep all scopes.

use crawlx_api::auth::generate_key;
use crawlx_api::{run, ApiConfig, ApiKeyBootstrap};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

const MISSING: &str = "00000000-0000-4000-8000-0000000000aa";

#[allow(
    clippy::disallowed_types,
    reason = "test client speaks HTTP to an owned local fixture server"
)]
struct Rig {
    base: String,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<Result<(), crawlx_api::ApiError>>,
    _dir: tempfile::TempDir,
}

#[allow(
    clippy::disallowed_types,
    reason = "test client speaks HTTP to an owned local fixture server"
)]
async fn serve(specs: &[String]) -> Rig {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let cfg = ApiConfig {
        bind: ([127, 0, 0, 1], port).into(),
        artifacts_dir: dir.path().to_path_buf(),
        api_keys: specs
            .iter()
            .map(|s| ApiKeyBootstrap::parse_spec(s).unwrap())
            .collect(),
        rate_limit_per_minute: 0,
        webhook_secret: "whsec_x".to_owned(),
        ..ApiConfig::default()
    };
    let server = tokio::spawn(run(cfg));
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    for _ in 0..100 {
        if client.get(format!("{base}/v1/openapi.json")).send().await.is_ok() {
            return Rig {
                base,
                client,
                server,
                _dir: dir,
            };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not come up");
}

impl Rig {
    async fn call(&self, method: Method, path: &str, key: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(key);
        if let Some(body) = body {
            req = req.json(&body);
        }
        let res = req.send().await.unwrap();
        let status = res.status();
        (status, res.json().await.unwrap_or(Value::Null))
    }
}

/// Every route that needs an operator scope, with a body the extractor accepts so the scope
/// check is what answers.
fn operator_routes() -> Vec<(Method, String, Option<Value>, &'static str)> {
    vec![
        (
            Method::POST,
            "/v1/authorizations".to_owned(),
            Some(json!({})),
            "authorizations:write",
        ),
        (
            Method::POST,
            "/v1/authorizations/evidence".to_owned(),
            Some(json!({})),
            "authorizations:write",
        ),
        (
            Method::POST,
            format!("/v1/authorizations/{MISSING}/verify"),
            None,
            "authorizations:write",
        ),
        (
            Method::POST,
            format!("/v1/authorizations/{MISSING}/revoke"),
            Some(json!({})),
            "authorizations:write",
        ),
        (
            Method::POST,
            format!("/v1/crawls/{MISSING}/approvals/{MISSING}:approve"),
            Some(json!({})),
            "approvals:decide",
        ),
        (
            Method::POST,
            format!("/v1/crawls/{MISSING}/approvals/{MISSING}:deny"),
            Some(json!({})),
            "approvals:decide",
        ),
        (
            Method::POST,
            format!("/v1/agent-plans/{MISSING}/approve"),
            Some(json!({})),
            "approvals:decide",
        ),
        (Method::GET, "/metrics".to_owned(), None, "metrics:read"),
    ]
}

#[tokio::test]
async fn an_agent_key_is_refused_on_every_operator_route_and_works_on_the_agent_routes() {
    let agent = generate_key();
    let rig = serve(&[format!("acme={agent}:agent")]).await;

    for (method, path, body, scope) in operator_routes() {
        let (status, v) = rig.call(method.clone(), &path, &agent, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {v}");
        assert_eq!(v["error"]["code"], "scope_missing", "{method} {path}: {v}");
        assert!(
            v["error"]["message"].as_str().unwrap().contains(scope),
            "{method} {path}: {v}"
        );
    }

    let (status, v) = rig
        .call(
            Method::POST,
            "/v1/crawls",
            &agent,
            Some(json!({"seedUrl": "https://a.example.test/"})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    let id = v["id"]
        .as_str()
        .or_else(|| v["runId"].as_str())
        .unwrap()
        .to_owned();
    let (status, v) = rig
        .call(Method::GET, &format!("/v1/crawls/{id}"), &agent, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "queued");
    for path in [
        format!("/v1/crawls/{id}/approvals"),
        format!("/v1/crawls/{id}/errors"),
        format!("/v1/authorizations/{MISSING}"),
        format!("/v1/crawls/{id}/artifacts/{MISSING}"),
    ] {
        let (status, v) = rig.call(Method::GET, &path, &agent, None).await;
        assert_ne!(status, StatusCode::FORBIDDEN, "{path}: {v}");
    }
    let (status, _) = rig
        .call(
            Method::GET,
            &format!("/v1/crawls/{id}/artifacts/{MISSING}"),
            &agent,
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "artifact reads pass the scope check"
    );
    rig.server.abort();
}

#[tokio::test]
async fn plain_and_operator_keys_keep_every_scope() {
    let plain = generate_key();
    let operator = generate_key();
    let rig = serve(&[format!("acme={plain}"), format!("globex={operator}:operator")]).await;
    for key in [&plain, &operator] {
        for (method, path, body, _) in operator_routes() {
            let (status, v) = rig.call(method.clone(), &path, key, body).await;
            assert_ne!(status, StatusCode::FORBIDDEN, "{method} {path}: {v}");
        }
        let (status, v) = rig
            .call(
                Method::POST,
                &format!("/v1/authorizations/{MISSING}/verify"),
                key,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
    }
    rig.server.abort();
}

#[tokio::test]
async fn an_explicit_scope_list_grants_exactly_those_scopes() {
    let key = generate_key();
    let rig = serve(&[format!("acme={key}:authorizations:read,crawls:read")]).await;
    let (status, v) = rig
        .call(Method::GET, &format!("/v1/authorizations/{MISSING}"), &key, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
    let (status, v) = rig
        .call(
            Method::POST,
            "/v1/crawls",
            &key,
            Some(json!({"seedUrl": "https://a.example.test/"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"]["code"], "scope_missing");
    rig.server.abort();
}
