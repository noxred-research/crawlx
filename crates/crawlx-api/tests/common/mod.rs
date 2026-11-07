#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Shared fixtures: an in-memory API environment and request helpers.

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use bytes::Bytes;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::{ApiConfig, AppState, MemoryApiStore, Repos, Scope, Settings};
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_storage::{DeliveryBuffer, MemoryArtifactStore, MemoryStore};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

pub struct Env {
    pub app: Router,
    pub state: AppState,
    pub store: Arc<MemoryStore>,
    pub api: Arc<MemoryApiStore>,
    pub artifacts: Arc<MemoryArtifactStore>,
    /// All scopes, tenant `acme`.
    pub key: String,
    pub tenant: TenantId,
}

pub fn env() -> Env {
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    env_with(config, Settings::default(), Arc::new(SystemClock))
}

pub fn env_with(config: ApiConfig, settings: Settings, clock: Arc<dyn Clock>) -> Env {
    env_with_zdr(config, settings, clock).0
}

/// As [`env_with`], also returning the zero-data-retention delivery buffer shared by the
/// artifact store, the routes and the webhook sender.
pub fn env_with_zdr(
    config: ApiConfig,
    settings: Settings,
    clock: Arc<dyn Clock>,
) -> (Env, Arc<DeliveryBuffer>) {
    let store = Arc::new(MemoryStore::new());
    let zdr = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
    store.set_dataset_delivery(zdr.clone());
    let artifacts = Arc::new(
        MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock))
            .with_index(store.clone())
            .with_zdr_buffer(zdr.clone()),
    );
    let (repos, api) = Repos::memory_with_api(store.clone(), artifacts.clone());
    let state = AppState::builder(
        repos,
        crawlx_api::admission_policy(&config, clock.clone()),
        config,
    )
    .settings(settings)
    .clock(clock)
    .zdr_buffer(zdr.clone())
    .build();
    let app = crawlx_api::router(state.clone());
    let tenant = tenant_id_for("acme");
    let key = generate_key();
    let rec = key_record(&key, tenant, Scope::all_set()).unwrap();
    futures::executor::block_on(async {
        crawlx_api::ApiStore::key_insert(api.as_ref(), &rec, "acme")
            .await
            .unwrap()
    });
    (
        Env {
            app,
            state,
            store,
            api,
            artifacts,
            key,
            tenant,
        },
        zdr,
    )
}

impl Env {
    /// A key of `tenant` limited to `scopes`.
    pub async fn key_for(&self, tenant: &str, scopes: &[Scope]) -> String {
        let key = generate_key();
        let set: BTreeSet<Scope> = scopes.iter().copied().collect();
        let rec = key_record(&key, tenant_id_for(tenant), set).unwrap();
        crawlx_api::ApiStore::key_insert(self.api.as_ref(), &rec, tenant)
            .await
            .unwrap();
        key
    }

    pub async fn send(
        &self,
        method: Method,
        uri: &str,
        key: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(k) = key {
            b = b.header("authorization", format!("Bearer {k}"));
        }
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024).await.unwrap();
        (parts.status, parts.headers, bytes)
    }

    pub async fn get(&self, uri: &str) -> (StatusCode, HeaderMap, Value) {
        self.get_as(&self.key, uri).await
    }

    pub async fn get_as(&self, key: &str, uri: &str) -> (StatusCode, HeaderMap, Value) {
        let (s, h, b) = self.send(Method::GET, uri, Some(key), &[], None).await;
        (s, h, json(&b))
    }

    pub async fn post(&self, uri: &str, body: &Value) -> (StatusCode, HeaderMap, Value) {
        self.post_with(uri, &[], body).await
    }

    pub async fn post_with(
        &self,
        uri: &str,
        headers: &[(&str, &str)],
        body: &Value,
    ) -> (StatusCode, HeaderMap, Value) {
        let (s, h, b) = self
            .send(Method::POST, uri, Some(&self.key), headers, Some(body))
            .await;
        (s, h, json(&b))
    }

    pub async fn post_empty(&self, uri: &str) -> (StatusCode, HeaderMap, Value) {
        let (s, h, b) = self.send(Method::POST, uri, Some(&self.key), &[], None).await;
        (s, h, json(&b))
    }

    pub async fn delete(&self, uri: &str) -> (StatusCode, HeaderMap, Value) {
        let (s, h, b) = self.send(Method::DELETE, uri, Some(&self.key), &[], None).await;
        (s, h, json(&b))
    }

    /// Create a run through the API and return its id string.
    pub async fn create_run(&self, body: &Value) -> String {
        let (s, _, v) = self.post("/v1/crawls", body).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        v["id"].as_str().unwrap().to_owned()
    }
}

pub fn json(b: &Bytes) -> Value {
    if b.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(b).into_owned()))
    }
}

pub fn simple_body() -> Value {
    serde_json::json!({ "seedUrl": "https://app.example.test/", "seed": 7 })
}
