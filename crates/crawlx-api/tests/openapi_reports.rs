//! Operational report schema drift against authenticated, retained in-process responses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{key_record, tenant_id_for};
use crawlx_api::{ApiConfig, ApiStore, AppState, Repos, Scope};
use crawlx_core::custody::CustodyLease;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{EventRepo, FrontierRepo, FrontierStatus, PageRecord, RunRepo};
use crawlx_core::report_history::{
    AlertCodeV1, AlertContextV1, AlertSeverityV1, DnsOutcomeV1, PipelineStageV1, PipelineStateV1,
    ProcessorIdentityV1, ProcessorStageV1, ReportDataV1, ReportFactV1, ReportHistoryRepo, StageOutcomeV1,
};
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
        self.record_facts(run.id, worker, id).await;
        run.id
    }

    /// Record one measured fact of every class under a live producer lease of a fresh URL.
    async fn record_facts(&self, run: CrawlRunId, worker: WorkerId, parent: i64) {
        let url = testkit::canonical_url("https://report.example.test/measured");
        let (_, id) = self
            .store
            .discover(run, &url, 1, Some(parent), None)
            .await
            .unwrap();
        let (entry, fence) = self
            .store
            .lease_batch_fenced(run, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(Some(entry.id), id);
        let lease = CustodyLease::for_url(self.tenant, run, entry.id, worker, fence);
        let recheck = self.clock.now() + chrono::Duration::hours(1);
        let facts = [
            ReportDataV1::Dns {
                outcome: DnsOutcomeV1::Resolved,
                duration_us: 1_200,
                recheck_at: Some(recheck),
            },
            ReportDataV1::Dns {
                outcome: DnsOutcomeV1::Timeout,
                duration_us: 5_000,
                recheck_at: None,
            },
            ReportDataV1::Stage {
                stage: ProcessorStageV1::Fetch,
                outcome: StageOutcomeV1::Succeeded,
                duration_us: 3_000,
                processor: ProcessorIdentityV1::NativeHttp,
                processor_version: 1,
            },
            ReportDataV1::Stage {
                stage: ProcessorStageV1::Parse,
                outcome: StageOutcomeV1::Failed,
                duration_us: 800,
                processor: ProcessorIdentityV1::Parser,
                processor_version: 2,
            },
            ReportDataV1::Wire {
                received_bytes: Some(4_096),
                sent_bytes: Some(512),
                duration_us: Some(900),
            },
            ReportDataV1::Wire {
                received_bytes: None,
                sent_bytes: None,
                duration_us: None,
            },
            ReportDataV1::Alert {
                severity: AlertSeverityV1::Warning,
                code: AlertCodeV1::ProcessorFailure,
                context: AlertContextV1::Processing,
            },
            ReportDataV1::Loss { dropped: 7 },
            ReportDataV1::Pipeline {
                stage: PipelineStageV1::Fetch,
                state: PipelineStateV1::Succeeded,
            },
        ];
        for (ordinal, data) in (1_i64..).zip(facts) {
            let mut fact = ReportFactV1::new(
                &lease,
                Digest::of("crawlx/report-schema-fixture", &ordinal.to_le_bytes()),
                self.clock.now() + chrono::Duration::seconds(ordinal),
                data,
            );
            fact.request_id = Some(entry.id);
            fact.url_key = Some(url.key);
            fact.host_key = Some(Digest::of("crawlx/report-host/v1", b"report.example.test"));
            self.store.append_fact(&lease, &fact).await.unwrap();
        }
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
    let inventory_schema = response_schema(&document, INVENTORY, "200");
    assert_valid(&document, inventory_schema, &inventory);
    let mut row_types = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    let mut fact_kinds = BTreeSet::new();
    for entry in inventory["reports"].as_array().unwrap() {
        let kind = entry["name"].as_str().unwrap();
        kinds.insert(kind.to_owned());
        let (status, page) = fixture.get(&format!("{root}/{kind}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_valid(&document, response_schema(&document, SEARCH, "200"), &page);
        let rows = page["rows"].as_array().unwrap();
        let facts = page["facts"].as_array().unwrap();
        match entry["facts"]["role"].as_str() {
            Some("primary") => {
                assert!(!rows.is_empty() && facts.is_empty(), "{kind}");
                assert_eq!(page["factsPage"]["facts"], rows.len(), "{kind}");
            }
            Some("companion") => {
                assert!(!facts.is_empty(), "{kind}");
                assert_eq!(page["factsPage"]["facts"], facts.len(), "{kind}");
            }
            _ => assert!(facts.is_empty() && page["factsPage"].is_null(), "{kind}"),
        }
        for row in rows {
            row_types.insert(row["rowType"].as_str().unwrap().to_owned());
            if row["rowType"] == "fact" {
                fact_kinds.insert(row["fact"]["data"]["kind"].as_str().unwrap().to_owned());
            }
        }
    }
    assert_eq!(kinds.len(), 21);
    assert_eq!(
        fact_kinds,
        ["dns", "stage", "wire", "alert", "loss", "pipeline"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    let mut duplicate_kind = inventory.clone();
    duplicate_kind["reports"][1] = duplicate_kind["reports"][0].clone();
    assert!(!validator(&document, inventory_schema).is_valid(&duplicate_kind));
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
            "event",
            "fact"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    // Inventory drift: the fact relationship, cursors and not-recorded vocabulary are finite.
    let history = inventory["reports"]
        .as_array()
        .unwrap()
        .iter()
        .position(|entry| entry["name"] == "history")
        .unwrap();
    let inventory_validator = validator(&document, inventory_schema);
    let mut broken = inventory.clone();
    broken["reports"][history]["facts"]["crossRun"] = json!(false);
    assert!(!inventory_validator.is_valid(&broken));
    let mut broken = inventory.clone();
    broken["reports"][0]["facts"] = broken["reports"][history]["facts"].clone();
    assert!(!inventory_validator.is_valid(&broken));
    let mut broken = inventory.clone();
    broken["reports"][history]["notRecorded"] = json!(["legacy_runs_without_report_facts"]);
    assert!(!inventory_validator.is_valid(&broken));
    let mut broken = inventory.clone();
    broken["notRecorded"] = json!(["wire_size_bytes", "unmeasured_fact_fields_stay_null"]);
    assert!(!inventory_validator.is_valid(&broken));
    let mut broken = inventory.clone();
    broken["instrumentedFacts"]["unavailable"] = json!(["summary"]);
    assert!(!inventory_validator.is_valid(&broken));
    let mut broken = inventory.clone();
    broken["maxFactsPerPage"] = json!(65);
    assert!(!inventory_validator.is_valid(&broken));
    let mut broken = inventory.clone();
    broken.as_object_mut().unwrap().remove("factCursors");
    assert!(!inventory_validator.is_valid(&broken));

    let page_validator = validator(&document, response_schema(&document, SEARCH, "200"));
    let (_, mut page) = fixture.get(&format!("{root}/frontier")).await;
    page["rows"][0]["authorization"] = json!("unexpected secret-bearing field");
    assert!(!page_validator.is_valid(&page));
    page["rows"][0].as_object_mut().unwrap().remove("authorization");
    page["report"] = json!("events");
    assert!(!page_validator.is_valid(&page));
    let (_, mut page) = fixture.get(&format!("{root}/uri_log")).await;
    for field in ["status", "mime", "mimeKey", "hostKey"] {
        page["rows"][0][field] = Value::Null;
    }
    assert_valid(&document, response_schema(&document, SEARCH, "200"), &page);

    // Fact pages: primary reports serve typed facts, legacy reports a companion fact page.
    let (_, history_page) = fixture.get(&format!("{root}/history")).await;
    let entry = json!({
        "sequence": history_page["rows"][0]["sequence"],
        "fact": history_page["rows"][0]["fact"],
    });
    for (field, bad) in [
        ("/rows/0/fact/data/extra", json!(1)),
        ("/rows/0/fact/payload", json!("raw")),
        ("/rows/0/fact/version", json!(2)),
        ("/rows/0/fact/attempt", json!(0)),
        ("/rows/0/fact/fence", json!(0)),
        ("/rows/0/fact/data/kind", json!("bogus")),
        ("/rows/0/fact/source", json!({"url": 0})),
        ("/rows/0/fact/source", json!({"unknown": 1})),
        ("/rows/0/fact/hostKey", json!("report.example.test")),
        ("/facts", json!([entry])),
        ("/factNext", json!(1)),
        ("/rows/0/rowType", json!("companion_fact")),
        ("/factsPage", Value::Null),
        ("/factsPage/durations/0/kind", json!("alert")),
        ("/factsPage/scope", json!("source_page")),
    ] {
        let mut page = history_page.clone();
        let (parent, key) = field.rsplit_once('/').unwrap();
        page.pointer_mut(parent).unwrap()[key] = bad;
        assert!(!page_validator.is_valid(&page), "{field}");
    }
    let uuid = "00000000-0000-7000-8000-000000000009";
    for source in [
        json!({"session": uuid}),
        json!({"url": 7}),
        json!({"authenticated_producer": uuid}),
        json!({"archive_export": uuid}),
        json!({"bootstrap": uuid}),
    ] {
        let mut page = history_page.clone();
        page["rows"][0]["fact"]["source"] = source;
        assert_valid(&document, response_schema(&document, SEARCH, "200"), &page);
    }
    let mut page = history_page.clone();
    page["crossRun"] = json!(true);
    assert_valid(&document, response_schema(&document, SEARCH, "200"), &page);
    let (_, wire) = fixture.get(&format!("{root}/wire_history")).await;
    for (field, bad) in [
        ("/crossRun", json!(true)),
        ("/rows/0/fact/data", json!({"kind": "loss", "dropped": 1})),
    ] {
        let mut page = wire.clone();
        *page.pointer_mut(field).unwrap() = bad;
        assert!(!page_validator.is_valid(&page), "{field}");
    }
    let (_, summary) = fixture.get(&format!("{root}/summary")).await;
    let mut page = summary.clone();
    page["facts"] = json!([entry]);
    assert!(!page_validator.is_valid(&page));
    let mut page = summary;
    page["factsPage"] = history_page["factsPage"].clone();
    assert!(!page_validator.is_valid(&page));
    let (_, mut companion) = fixture.get(&format!("{root}/frontier")).await;
    assert!(!companion["facts"].as_array().unwrap().is_empty());
    companion["factsPage"] = Value::Null;
    assert!(!page_validator.is_valid(&companion));
    let (_, mut companion) = fixture.get(&format!("{root}/frontier")).await;
    companion["facts"][0]["fact"]["data"]["secret"] = json!("raw");
    assert!(!page_validator.is_valid(&companion));
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
    assert!(report_parameter["description"]
        .as_str()
        .unwrap()
        .contains("twenty-one"));
    let (_, inventory) = fixture.get(&root).await;
    let query_schemas = operation["x-report-query-schemas"].as_object().unwrap();
    assert_eq!(query_schemas.len(), 21);
    assert_eq!(inventory["reports"].as_array().unwrap().len(), 21);
    let digest = "a".repeat(64);
    let samples = BTreeSet::from([
        ("state", "pending".to_owned()),
        ("status", "200".to_owned()),
        ("minDepth", "0".to_owned()),
        ("maxDepth", "5".to_owned()),
        ("class", "unknown".to_owned()),
        ("urlKey", digest.clone()),
        ("hostKey", digest),
        ("event", "page".to_owned()),
        ("since", "2000-01-01T00:00:00Z".to_owned()),
        ("until", "2100-01-01T00:00:00Z".to_owned()),
        ("kind", "wire".to_owned()),
        ("factKind", "wire".to_owned()),
        ("factsAfter", "0".to_owned()),
        ("minDurationUs", "0".to_owned()),
        ("maxDurationUs", "100000".to_owned()),
        ("minWireBytes", "0".to_owned()),
        ("maxWireBytes", "100000".to_owned()),
        ("crossRun", "false".to_owned()),
    ]);
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
        // Fact filters: valid values pass where documented, every other report rejects the key.
        for (field, good, bad) in [
            ("kind", json!("wire"), json!("bogus")),
            ("factKind", json!("dns"), json!("bogus")),
            ("factsAfter", json!(0), json!(9223372036854775808_u64)),
            ("minDurationUs", json!(0), json!(-1)),
            (
                "maxDurationUs",
                json!(9223372036854775807_u64),
                json!(9223372036854775808_u64),
            ),
            ("minWireBytes", json!(0), json!(-1)),
            (
                "maxWireBytes",
                json!(9223372036854775807_u64),
                json!(9223372036854775808_u64),
            ),
            ("crossRun", json!(true), json!("maybe")),
        ] {
            if expected.contains(field) {
                assert!(validation.is_valid(&json!({field: good})), "{name}: {field}");
                assert!(
                    !validation.is_valid(&json!({field: bad})),
                    "{name}: {field}={bad}"
                );
            } else {
                assert!(!validation.is_valid(&json!({field: good})), "{name}: {field}");
            }
        }
        // The runtime accepts exactly the documented allowlist, together, with a valid page back.
        let params: Vec<_> = samples
            .iter()
            .filter(|(key, _)| expected.contains(key))
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        let (status, page) = fixture.get(&format!("{root}/{name}?{}", params.join("&"))).await;
        assert_eq!(status, StatusCode::OK, "{name}: {params:?}");
        assert_valid(&document, response_schema(&document, SEARCH, "200"), &page);
    }
    let parameters: BTreeSet<_> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|parameter| parameter["in"] == "query")
        .map(|parameter| parameter["name"].as_str().unwrap())
        .collect();
    let expected: BTreeSet<_> = [
        "after",
        "limit",
        "format",
        "state",
        "status",
        "minDepth",
        "maxDepth",
        "class",
        "urlKey",
        "hostKey",
        "event",
        "since",
        "until",
        "kind",
        "factKind",
        "factsAfter",
        "minDurationUs",
        "maxDurationUs",
        "minWireBytes",
        "maxWireBytes",
        "crossRun",
    ]
    .into_iter()
    .collect();
    assert_eq!(parameters, expected);
    for path in [
        "events?status=200",
        "events?crossRun=true",
        "wire_history?crossRun=true",
        "alert_log?kind=wire",
        "frontier?minWireBytes=1",
    ] {
        let (status, error) = fixture.get(&format!("{root}/{path}")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path}");
        assert_valid(&document, response_schema(&document, SEARCH, "422"), &error);
    }
}

#[tokio::test]
async fn finite_jsonl_lines_and_native_error_responses_match_their_schemas() {
    let fixture = Fixture::new().await;
    let run = fixture.populate().await;
    let document = crawlx_api::openapi::document();
    let operation = &document["paths"][SEARCH]["get"];
    let media = &operation["responses"]["200"]["content"]["application/x-ndjson"];
    assert_eq!(media["x-max-lines"], 129);
    let jsonl = |path: String| {
        let fixture = &fixture;
        async move {
            let (status, headers, bytes) = fixture.bytes(&path, true).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(headers["content-type"], "application/x-ndjson");
            assert_eq!(headers["cache-control"], "private, no-store");
            String::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>()
        }
    };
    let path = format!("/v1/crawls/{run}/reports/events?limit=1&format=jsonl");
    // One source row, one companion fact, then the envelope.
    let lines = jsonl(path.clone()).await;
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["rowType"], "event");
    assert_eq!(lines[1]["rowType"], "companion_fact");
    for line in &lines {
        assert_valid(&document, &media["x-jsonl-line-schema"], line);
    }
    let envelope = lines.last().unwrap();
    assert_valid(&document, &media["x-envelope-schema"], envelope);
    assert!(envelope["rows"].as_array().unwrap().is_empty());
    assert!(envelope["facts"].as_array().unwrap().is_empty());
    assert_eq!(envelope["factsPage"]["facts"], 1);
    // A primary history page streams its facts as rows, then the envelope.
    let lines = jsonl(format!("/v1/crawls/{run}/reports/history?limit=3&format=jsonl")).await;
    assert_eq!(lines.len(), 4);
    for line in &lines[..3] {
        assert_eq!(line["rowType"], "fact");
    }
    for line in &lines {
        assert_valid(&document, &media["x-jsonl-line-schema"], line);
    }
    assert_valid(&document, &media["x-envelope-schema"], lines.last().unwrap());
    assert_eq!(lines.last().unwrap()["factsPage"]["facts"], 3);
    assert!(!lines.last().unwrap()["next"].is_null());
    // The widest streams (source rows plus companion facts) stay within the documented bound.
    for report in ["frontier", "uri_log", "events", "hosts"] {
        let lines = jsonl(format!("/v1/crawls/{run}/reports/{report}?format=jsonl")).await;
        assert!(lines.len() <= 129, "{report}");
        for line in &lines {
            assert_valid(&document, &media["x-jsonl-line-schema"], line);
        }
    }
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
