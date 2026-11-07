#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Recorded-flow upload contracts exercised through the authenticated HTTP router.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::{ApiConfig, AppState, ArtifactSource, Repos, Scope, Settings};
use crawlx_core::repo::Sensitivity;
use crawlx_core::time::ManualClock;
use crawlx_core::{ArtifactRef, CrawlRunId};
use crawlx_storage::{ArtifactBlobs, FsArtifactStore, MemoryStore, Pg, PgConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const ORIGIN: &str = "https://app.example.test/";
const FLOW: &str = r##"{ "steps": [
 {"action":"navigate","value":"https://app.example.test/"},
 {"action":"fill","selector":"#username","value":"{{username}}"},
 {"action":"fill","selector":"[type=\"password\"]","value":"{{password}}"},
 {"action":"click","selector":"#submit"}
] }"##;
const RECORDER: &str = r##"{"title":"Member","steps":[
 {"type":"navigate","url":"https://app.example.test/"},
 {"type":"change","selectors":[["#username"]],"value":"{{username}}"},
 {"type":"change","selectors":[["[type=\"password\"]"]],"value":"{{password}}"},
 {"type":"click","selectors":[["#submit"]]}
]}"##;

struct Rig {
    state: AppState,
    app: axum::Router,
    artifacts: Arc<FsArtifactStore>,
    clock: Arc<ManualClock>,
    key: String,
    _dir: tempfile::TempDir,
}

impl Rig {
    async fn new(postgres: bool) -> Option<Self> {
        let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
        let delivery = Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(clock.clone()));
        let dir = tempfile::Builder::new()
            .prefix("crawlx-api-login-")
            .tempdir()
            .unwrap();
        let (repos, artifacts) = if postgres {
            let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
            let pg = Pg::connect(
                &url,
                PgConfig {
                    schema: Some(format!("api_login_{}", CrawlRunId::new().0.simple())),
                    max_connections: 8,
                    ..PgConfig::default()
                },
            )
            .await
            .unwrap();
            pg.migrate().await.unwrap();
            let pg = pg.with_delivery_buffer(delivery.clone());
            let artifacts = Arc::new(
                FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
                    .await
                    .unwrap()
                    .with_index(Arc::new(pg.clone()))
                    .with_zdr_buffer(delivery.clone()),
            );
            (Repos::pg(&pg, artifacts.clone()), artifacts)
        } else {
            let store = Arc::new(MemoryStore::with_clock(clock.clone()));
            let artifacts = Arc::new(
                FsArtifactStore::open(dir.path(), store.clone(), clock.clone())
                    .await
                    .unwrap()
                    .with_index(store.clone()),
            );
            (Repos::memory_with(store, artifacts.clone()), artifacts)
        };
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            ..ApiConfig::default()
        };
        let state = AppState::builder(
            repos,
            crawlx_api::admission_policy(&config, clock.clone()),
            config,
        )
        .clock(clock.clone())
        .zdr_buffer(delivery)
        .settings(Settings {
            max_body_bytes: 2 * 1024 * 1024,
            ..Settings::default()
        })
        .build();
        let key = Self::key(&state, "acme", &Scope::ALL).await;
        Some(Self {
            app: crawlx_api::router(state.clone()),
            state,
            artifacts,
            clock,
            key,
            _dir: dir,
        })
    }

    async fn key(state: &AppState, tenant: &str, scopes: &[Scope]) -> String {
        let key = generate_key();
        let record = key_record(&key, tenant_id_for(tenant), scopes.iter().copied().collect()).unwrap();
        state.repos.api.key_insert(&record, tenant).await.unwrap();
        key
    }

    async fn raw(&self, path: &str, key: Option<&str>, body: &str) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(key) = key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.raw(path, Some(&self.key), &body.to_string()).await
    }

    async fn source(&self, retention: Value) -> CrawlRunId {
        let (status, created) = self
            .post(
                "/v1/crawls",
                json!({"seedUrl":ORIGIN,"mode":"static","seed":19,"retention":retention}),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{created}");
        created["id"].as_str().unwrap().parse().unwrap()
    }

    async fn objects(&self) -> usize {
        self.artifacts.blobs().list("").await.unwrap().len()
    }

    async fn rejected(&self, path: &str, key: Option<&str>, body: &str, expected: StatusCode) {
        let objects = self.objects().await;
        let runs = self
            .state
            .repos
            .api
            .active_runs(tenant_id_for("acme"))
            .await
            .unwrap();
        let (status, response) = self.raw(path, key, body).await;
        assert_eq!(status, expected, "{response}");
        assert_eq!(self.objects().await, objects, "rejected upload created an object");
        assert_eq!(
            self.state
                .repos
                .api
                .active_runs(tenant_id_for("acme"))
                .await
                .unwrap(),
            runs,
            "rejected upload created or changed target runs"
        );
    }
}

async fn upload_contract(postgres: bool) {
    let Some(rig) = Rig::new(postgres).await else {
        return;
    };
    let source = rig.source(json!({"mode":"standard","days":2})).await;
    let before = rig.state.repos.runs.get(source).await.unwrap();
    let path = format!("/v1/crawls/{source}/login-flows");
    rig.clock.advance_ms(24 * 60 * 60 * 1000);
    let mut referenced_target = Value::Null;
    for flow in [FLOW, RECORDER] {
        let (status, uploaded) = rig.post(&path, json!({"flow":flow})).await;
        assert_eq!(status, StatusCode::CREATED, "{uploaded}");
        let artifact: ArtifactRef = serde_json::from_value(uploaded["artifact"].clone()).unwrap();
        let row = rig.artifacts.row(artifact.id).await.unwrap().unwrap();
        let deadline = before.created_at + chrono::Duration::days(2);
        assert_eq!(row.run, source);
        assert_eq!(row.tenant, before.tenant);
        assert_eq!(row.sensitivity, Sensitivity::Content);
        assert_eq!(row.expires_at, Some(deadline));
        assert_eq!(uploaded["expiresAt"], json!(deadline));
        assert_eq!(
            artifact.digest,
            crawlx_core::hash::Digest::of("crawlx/artifact/v1", flow.as_bytes())
        );
        assert_eq!(rig.artifacts.read(&artifact).await.unwrap(), flow.as_bytes());
        let login_plan = uploaded["loginPlan"].as_str().unwrap();
        let descriptor: Value =
            serde_json::from_str(login_plan.strip_prefix("recorded:artifact://").unwrap()).unwrap();
        assert_eq!(
            descriptor,
            json!({"tenant":before.tenant,"run":source,"sensitivity":"content","artifact":artifact})
        );
        let (status, target) = rig
            .post(
                "/v1/crawls",
                json!({"seedUrl":ORIGIN,"mode":"dynamic","seed":20,
                "roles":[{"name":"member","loginPlan":login_plan}]}),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{target}");
        let target_id: CrawlRunId = target["id"].as_str().unwrap().parse().unwrap();
        let accepted = rig.state.repos.runs.get(target_id).await.unwrap();
        assert_ne!(target_id, source);
        assert_eq!(accepted.config.roles[0].login_plan.as_deref(), Some(login_plan));
        referenced_target = json!({"seedUrl":ORIGIN,"mode":"dynamic","seed":21,
            "roles":[{"name":"member","loginPlan":login_plan}]});
        let writer = Rig::key(&rig.state, "acme", &[Scope::CrawlsWrite]).await;
        rig.rejected(
            "/v1/crawls",
            Some(&writer),
            &referenced_target.to_string(),
            StatusCode::FORBIDDEN,
        )
        .await;
        let foreign = Rig::key(&rig.state, "foreign", &Scope::ALL).await;
        rig.rejected(
            "/v1/crawls",
            Some(&foreign),
            &referenced_target.to_string(),
            StatusCode::NOT_FOUND,
        )
        .await;
        for (field, value, status) in [
            ("tenant", json!(tenant_id_for("foreign")), StatusCode::NOT_FOUND),
            ("run", json!(target_id), StatusCode::NOT_FOUND),
            (
                "sensitivity",
                json!("sensitive"),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let mut forged = descriptor.clone();
            forged[field] = value;
            let mut target = referenced_target.clone();
            target["roles"][0]["loginPlan"] = json!(format!("recorded:artifact://{forged}"));
            rig.rejected("/v1/crawls", Some(&rig.key), &target.to_string(), status)
                .await;
        }
        let mut forged = descriptor.clone();
        forged["artifact"]["digest"] = json!("00".repeat(32));
        let mut target = referenced_target.clone();
        target["roles"][0]["loginPlan"] = json!(format!("recorded:artifact://{forged}"));
        rig.rejected(
            "/v1/crawls",
            Some(&rig.key),
            &target.to_string(),
            StatusCode::NOT_FOUND,
        )
        .await;
        let request = Request::builder()
            .uri(format!("/v1/crawls/{source}/artifacts/{}", artifact.id))
            .header("authorization", format!("Bearer {}", rig.key))
            .body(Body::empty())
            .unwrap();
        let response = rig.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
                .await
                .unwrap()
                .as_ref(),
            flow.as_bytes()
        );
        assert_eq!(rig.state.repos.runs.get(target_id).await.unwrap(), accepted);
        rig.artifacts
            .blobs()
            .put(&row.object_key, b"corrupt flow")
            .await
            .unwrap();
        assert!(
            rig.artifacts.read(&artifact).await.is_err(),
            "corrupt source bytes passed fixity"
        );
        rig.rejected(
            "/v1/crawls",
            Some(&rig.key),
            &referenced_target.to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
        rig.artifacts
            .blobs()
            .put(&row.object_key, flow.as_bytes())
            .await
            .unwrap();
    }
    assert_eq!(rig.state.repos.runs.get(source).await.unwrap(), before);
    let valid = json!({"flow":FLOW}).to_string();
    rig.rejected(&path, None, &valid, StatusCode::UNAUTHORIZED).await;
    for scopes in [&[Scope::CrawlsRead][..], &[Scope::CrawlsWrite][..]] {
        let limited = Rig::key(&rig.state, "acme", scopes).await;
        rig.rejected(&path, Some(&limited), &valid, StatusCode::FORBIDDEN)
            .await;
    }
    let foreign = Rig::key(&rig.state, "foreign", &Scope::ALL).await;
    rig.rejected(&path, Some(&foreign), &valid, StatusCode::NOT_FOUND)
        .await;
    rig.rejected(
        &format!("/v1/crawls/{}/login-flows", CrawlRunId::new()),
        Some(&rig.key),
        &valid,
        StatusCode::NOT_FOUND,
    )
    .await;
    for malformed in [
        "{}",
        "[]",
        "{",
        r#"{"flow":42}"#,
        r#"{"flow":"{}","extra":true}"#,
        r#"{"flow":"{}","flow":"{}"}"#,
    ] {
        rig.rejected(&path, Some(&rig.key), malformed, StatusCode::BAD_REQUEST)
            .await;
    }
    crawlx_core::secret::register_secret("api-upload-literal-canary-Q7m2");
    for flow in [
        "not JSON".to_owned(),
        r#"{"steps":[{"action":"unsupported","value":"safe"}]}"#.to_owned(),
        r##"{"steps":[{"action":"fill","selector":"#password","value":"unknown-literal"}]}"##.to_owned(),
        r##"{"steps":[{"type":"change","selectors":[["#username"]],"value":"literal-user"}]}"##.to_owned(),
        r##"{"steps":[{"action":"fill","selector":"#search","value":"api-upload-literal-canary-Q7m2"}]}"##
            .to_owned(),
        r##"{"steps":[{"action":"click","selector":"#safe","selector":"#other"}]}"##.to_owned(),
    ] {
        rig.rejected(
            &path,
            Some(&rig.key),
            &json!({"flow":flow}).to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }
    rig.rejected(
        &path,
        Some(&rig.key),
        &json!({"flow":"x".repeat(1024 * 1024 + 1)}).to_string(),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;
    rig.rejected(
        &path,
        Some(&rig.key),
        &" ".repeat(2 * 1024 * 1024 + 1),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;
    let zdr = rig.source(json!({"mode":"zdr","days":0})).await;
    rig.rejected(
        &format!("/v1/crawls/{zdr}/login-flows"),
        Some(&rig.key),
        &valid,
        StatusCode::CONFLICT,
    )
    .await;
    rig.clock.advance_ms(24 * 60 * 60 * 1000);
    rig.rejected(&path, Some(&rig.key), &valid, StatusCode::GONE)
        .await;
    rig.rejected(
        "/v1/crawls",
        Some(&rig.key),
        &referenced_target.to_string(),
        StatusCode::GONE,
    )
    .await;
    let request = Request::builder()
        .uri(format!("/v1/crawls/{source}"))
        .header("authorization", format!("Bearer {}", rig.key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        rig.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
}

async fn purge_contract(postgres: bool) {
    let Some(rig) = Rig::new(postgres).await else {
        return;
    };
    let source = rig.source(json!({"mode":"standard","days":1})).await;
    let path = format!("/v1/crawls/{source}/login-flows");
    let (_, uploaded) = rig.post(&path, json!({"flow":FLOW})).await;
    let artifact: ArtifactRef = serde_json::from_value(uploaded["artifact"].clone()).unwrap();
    assert_eq!(rig.artifacts.read(&artifact).await.unwrap(), FLOW.as_bytes());
    rig.clock.advance_ms(24 * 60 * 60 * 1000);
    assert!(
        rig.artifacts.read(&artifact).await.is_err(),
        "source expiry must revoke readability"
    );
    let request = Request::builder()
        .uri(format!("/v1/crawls/{source}/artifacts/{}", artifact.id))
        .header("authorization", format!("Bearer {}", rig.key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        rig.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::GONE
    );
    let (status, cancelled) = rig
        .raw(&format!("/v1/crawls/{source}:cancel"), Some(&rig.key), "{}")
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{cancelled}");
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/v1/crawls/{source}"))
        .header("authorization", format!("Bearer {}", rig.key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        rig.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::ACCEPTED
    );
    assert!(rig.state.repos.runs.get_metadata(source).await.is_err());
    assert!(rig.artifacts.row(artifact.id).await.unwrap().is_none());
    assert!(rig.artifacts.read(&artifact).await.is_err());
    assert_eq!(rig.objects().await, 0);
}

#[tokio::test]
async fn memory_login_flow_http_contract() {
    upload_contract(false).await;
    purge_contract(false).await;
}

#[tokio::test]
async fn postgres_login_flow_http_contract() {
    upload_contract(true).await;
    purge_contract(true).await;
}
