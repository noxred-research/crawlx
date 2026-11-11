//! Operational report schema drift against authenticated, retained in-process responses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{key_record, tenant_id_for};
use crawlx_api::{ApiConfig, ApiStore, AppState, Repos, Scope};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{EventRepo, FrontierRepo, FrontierStatus, PageRecord, RunRepo};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, CrawlRunId, TenantId, Timestamp, WorkerId};
use crawlx_storage::{testkit, MemoryArtifactStore, MemoryStore, WorkerRegistry};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

const KEY: &str = "cx_live_aaaaaaaaaaaaaaaaaaaaaaaaaa";
const INVENTORY: &str = "/v1/crawls/{id}/reports";
const SEARCH: &str = "/v1/crawls/{id}/reports/{report}";

struct Fixture {
    app: Router,
    store: Arc<MemoryStore>,
    clock: Arc<ManualClock>,
    tenant: TenantId,
}

impl Fixture {
    async fn new() -> Self {
        let clock = Arc::new(ManualClock::new(
            Timestamp::from_timestamp(1_700_000_000, 0).unwrap(),
        ));
        let store = Arc::new(MemoryStore::with_clock(clock.clone()));
        let artifacts = Arc::new(MemoryArtifactStore::in_memory(store.clone(), clock.clone()));
        let (repos, api) = Repos::memory_with_api(store.clone(), artifacts);
        let tenant = tenant_id_for("report-schema-owner");
        let key = key_record(KEY, tenant, [Scope::CrawlsRead].into_iter().collect()).unwrap();
        ApiStore::key_insert(api.as_ref(), &key, "report-schema-owner")
            .await
            .unwrap();
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
        .build();
        Self {
            app: crawlx_api::router(state),
            store,
            clock,
            tenant,
        }
    }

    async fn populate(&self) -> CrawlRunId {
        let mut config = testkit::create_crawl("https://report.example.test/", &[], 1);
        config.retention.days = 1;
        let mut run = testkit::crawl_run(self.tenant, config);
        run.id = CrawlRunId(uuid::Uuid::from_u128(1));
        run.created_at = self.clock.now();
        self.store.create(&run, None).await.unwrap();
        let worker = WorkerId(uuid::Uuid::from_u128(2));
        self.store
            .register_worker(worker, "report-schema-fixture", "1")
            .await
            .unwrap();
        let url = testkit::canonical_url("https://report.example.test/");
        let (_, id) = self.store.discover(run.id, &url, 0, None, None).await.unwrap();
        let id = id.unwrap();
        let lease = self
            .store
            .lease_batch_fenced(run.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let page = PageRecord {
            run: run.id,
            frontier_id: id,
            url,
            status: 200,
            content_type: Some("text/html; charset=utf-8".into()),
            content_digest: Digest::of("crawlx/report-schema-fixture", b"retained facts"),
            title: None,
            markdown: None,
            html: None,
            metadata: json!({}),
            links: Vec::new(),
            fetched_at: self.clock.now(),
            lane: crawlx_core::TrustLane::Diagnostic,
        };
        let mut commit = RequestCommitV1::terminal(run.id, id, lease.1, 1, FrontierStatus::Succeeded, None);
        commit.page = Some(page);
        self.store.commit_fenced(commit).await.unwrap();
        let blocked = testkit::canonical_url("https://report.example.test/blocked");
        self.store
            .discover(
                run.id,
                &blocked,
                1,
                Some(id),
                Some((FrontierStatus::RobotsBlocked, "robots".into())),
            )
            .await
            .unwrap();
        let failed = testkit::canonical_url("https://report.example.test/failed");
        let (_, failed) = self
            .store
            .discover(run.id, &failed, 1, Some(id), None)
            .await
            .unwrap();
        let failed = failed.unwrap();
        let lease = self
            .store
            .lease_batch_fenced(run.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        self.store
            .commit_fenced(RequestCommitV1::terminal(
                run.id,
                failed,
                lease.1,
                1,
                FrontierStatus::Failed,
                Some("content_validation_failed".into()),
            ))
            .await
            .unwrap();
        self.store
            .append(run.id, "page", json!({"secret":"must-not-be-projected"}))
            .await
            .unwrap();
        self.store
            .append(run.id, "unknown-private-event-name", json!({}))
            .await
            .unwrap();
        run.id
    }

    async fn bytes(&self, path: &str, authenticated: bool) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder().uri(path);
        if authenticated {
            request = request.header("authorization", format!("Bearer {KEY}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        (
            parts.status,
            parts.headers,
            axum::body::to_bytes(body, 256 * 1024).await.unwrap().to_vec(),
        )
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let (status, _, bytes) = self.bytes(path, true).await;
        (status, serde_json::from_slice(&bytes).unwrap())
    }
}

fn validator(document: &Value, schema: &Value) -> jsonschema::Validator {
    let mut root = schema.clone();
    root.as_object_mut()
        .unwrap()
        .insert("components".into(), document["components"].clone());
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&root)
        .unwrap()
}

fn assert_valid(document: &Value, schema: &Value, value: &Value) {
    let validation = validator(document, schema);
    let errors: Vec<_> = validation
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "schema drift: {errors:?}\n{value}");
}

fn response_schema<'a>(document: &'a Value, path: &str, status: &str) -> &'a Value {
    &document["paths"][path]["get"]["responses"][status]["content"]["application/json"]["schema"]
}

#[tokio::test]
async fn real_inventory_and_all_eight_row_variants_match_finite_report_schemas() {
    let fixture = Fixture::new().await;
    let run = fixture.populate().await;
    let root = format!("/v1/crawls/{run}/reports");
    let document = crawlx_api::openapi::document();
    let (status, inventory) = fixture.get(&root).await;
    assert_eq!(status, StatusCode::OK);
    assert_valid(
        &document,
        response_schema(&document, INVENTORY, "200"),
        &inventory,
    );
    let mut row_types = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for entry in inventory["reports"].as_array().unwrap() {
        let kind = entry["name"].as_str().unwrap();
        kinds.insert(kind.to_owned());
        let (status, page) = fixture.get(&format!("{root}/{kind}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_valid(&document, response_schema(&document, SEARCH, "200"), &page);
        for row in page["rows"].as_array().unwrap() {
            row_types.insert(row["rowType"].as_str().unwrap().to_owned());
        }
    }
    assert_eq!(kinds.len(), 17);
    let mut duplicate_kind = inventory.clone();
    duplicate_kind["reports"][1] = duplicate_kind["reports"][0].clone();
    assert!(!validator(&document, response_schema(&document, INVENTORY, "200")).is_valid(&duplicate_kind));
    assert_eq!(
        row_types,
        [
            "summary",
            "provenance",
            "frontier",
            "host",
            "source",
            "mime_status",
            "page",
            "event"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    let (_, mut page) = fixture.get(&format!("{root}/frontier")).await;
    page["rows"][0]["authorization"] = json!("unexpected secret-bearing field");
    assert!(!validator(&document, response_schema(&document, SEARCH, "200")).is_valid(&page));
    page["rows"][0].as_object_mut().unwrap().remove("authorization");
    page["report"] = json!("events");
    assert!(!validator(&document, response_schema(&document, SEARCH, "200")).is_valid(&page));
    let (_, mut page) = fixture.get(&format!("{root}/uri_log")).await;
    for field in ["status", "mime", "mimeKey", "hostKey"] {
        page["rows"][0][field] = Value::Null;
    }
    assert_valid(&document, response_schema(&document, SEARCH, "200"), &page);
}

#[tokio::test]
async fn documented_report_kinds_and_query_allowlists_match_runtime_inventory() {
    let fixture = Fixture::new().await;
    let run = fixture.populate().await;
    let root = format!("/v1/crawls/{run}/reports");
    let document = crawlx_api::openapi::document();
    let operation = &document["paths"][SEARCH]["get"];
    let report_parameter = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parameter| parameter["in"] == "path" && parameter["name"] == "report")
        .unwrap();
    let kind_validator = validator(&document, &report_parameter["schema"]);
    assert!(!kind_validator.is_valid(&json!("arbitrary-script")));
    let (_, inventory) = fixture.get(&root).await;
    let query_schemas = operation["x-report-query-schemas"].as_object().unwrap();
    assert_eq!(query_schemas.len(), 17);
    for entry in inventory["reports"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        assert!(kind_validator.is_valid(&json!(name)));
        let query = &query_schemas[name];
        let documented: BTreeSet<_> = query["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<_> = entry["filters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .chain(["after", "limit", "format"])
            .collect();
        assert_eq!(documented, expected, "{name}");
        let validation = validator(&document, query);
        assert!(
            validation.is_valid(&json!({"after":0,"limit":64,"format":"json"})),
            "{name}"
        );
        for invalid in [
            json!({"limit":0}),
            json!({"limit":65}),
            json!({"after":9223372036854775808_u64}),
            json!({"q":"SELECT"}),
            json!({"script":"execute"}),
            json!({"minBytes":1}),
            json!({"minDurationMs":1}),
        ] {
            assert!(!validation.is_valid(&invalid), "{name}: {invalid}");
        }
    }
    let parameters: BTreeSet<_> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|parameter| parameter["in"] == "query")
        .map(|parameter| parameter["name"].as_str().unwrap())
        .collect();
    let expected: BTreeSet<_> = [
        "after", "limit", "format", "state", "status", "minDepth", "maxDepth", "class", "urlKey", "hostKey",
        "event", "since", "until",
    ]
    .into_iter()
    .collect();
    assert_eq!(parameters, expected);
    let (status, error) = fixture.get(&format!("{root}/events?status=200")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_valid(&document, response_schema(&document, SEARCH, "422"), &error);
}

#[tokio::test]
async fn finite_jsonl_lines_and_native_error_responses_match_their_schemas() {
    let fixture = Fixture::new().await;
    let run = fixture.populate().await;
    let document = crawlx_api::openapi::document();
    let operation = &document["paths"][SEARCH]["get"];
    let media = &operation["responses"]["200"]["content"]["application/x-ndjson"];
    let path = format!("/v1/crawls/{run}/reports/events?limit=1&format=jsonl");
    let (status, headers, bytes) = fixture.bytes(&path, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/x-ndjson");
    assert_eq!(headers["cache-control"], "private, no-store");
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert_valid(&document, &media["x-jsonl-line-schema"], line);
    }
    assert_valid(&document, &media["x-envelope-schema"], lines.last().unwrap());
    assert!(lines.last().unwrap()["rows"].as_array().unwrap().is_empty());
    let (status, _, bytes) = fixture.bytes(&path, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_valid(
        &document,
        response_schema(&document, SEARCH, "401"),
        &serde_json::from_slice(&bytes).unwrap(),
    );
    fixture.clock.advance_ms(86_400_001);
    let (status, error) = fixture.get(&path.replace("&format=jsonl", "")).await;
    assert_eq!(status, StatusCode::GONE);
    assert_valid(&document, response_schema(&document, SEARCH, "410"), &error);
}
