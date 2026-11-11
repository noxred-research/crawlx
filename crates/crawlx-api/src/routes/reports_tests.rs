//! In-process authenticated report consumers over the real memory repositories.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::auth::{key_record, tenant_id_for};
use crate::{ApiConfig, ApiStore, MemoryApiStore, Repos};
#[allow(
    clippy::disallowed_types,
    reason = "owned in-process HTTP report route fixture boundary"
)]
use axum::http::Request;
use axum::Router;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::custody::CustodyLease;
use crawlx_core::orchestration::{RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{EventRepo, FrontierRepo, PageRepo, RunRepo};
use crawlx_core::report_history::{
    AlertCodeV1, AlertContextV1, AlertSeverityV1, DnsOutcomeV1, PipelineStageV1, PipelineStateV1,
    ProcessorIdentityV1, ProcessorStageV1, ReportFactV1, ReportHistoryRepo,
};
use crawlx_core::time::ManualClock;
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{Clock, TenantId, WorkerId};
use crawlx_storage::{testkit, MemoryArtifactStore, MemoryStore, WorkerRegistry};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const KEY: &str = "cx_live_aaaaaaaaaaaaaaaaaaaaaaaaaa";
const FOREIGN: &str = "cx_live_bbbbbbbbbbbbbbbbbbbbbbbbbb";
const WRITER: &str = "cx_live_cccccccccccccccccccccccccc";

struct Env {
    app: Router,
    store: Arc<MemoryStore>,
    clock: Arc<ManualClock>,
    tenant: TenantId,
}

impl Env {
    async fn new() -> Self {
        let now = Timestamp::from_timestamp(1_700_000_000, 0).unwrap();
        let clock = Arc::new(ManualClock::new(now));
        let store = Arc::new(MemoryStore::with_clock(clock.clone()));
        let artifacts = Arc::new(MemoryArtifactStore::in_memory(store.clone(), clock.clone()));
        let (repos, api): (Repos, Arc<MemoryApiStore>) = Repos::memory_with_api(store.clone(), artifacts);
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            ..ApiConfig::default()
        };
        let tenant = tenant_id_for("report-owner");
        for (key, name, scopes) in [
            (KEY, "report-owner", vec![Scope::CrawlsRead]),
            (FOREIGN, "other-report-owner", vec![Scope::CrawlsRead]),
            (WRITER, "report-owner", vec![Scope::CrawlsWrite]),
        ] {
            let record = key_record(key, tenant_id_for(name), scopes.into_iter().collect()).unwrap();
            ApiStore::key_insert(api.as_ref(), &record, name).await.unwrap();
        }
        let state = AppState::builder(repos, crate::admission_policy(&config, clock.clone()), config)
            .clock(clock.clone())
            .build();
        Self {
            app: crate::router(state),
            store,
            clock,
            tenant,
        }
    }

    async fn run(&self, zdr: bool, expired: bool) -> crawlx_core::repo::CrawlRun {
        let mut config = testkit::create_crawl("https://report.example.test/private-token", &[], 1);
        config.retention.days = 1;
        if zdr {
            config.retention.mode = RetentionMode::Zdr;
        }
        let mut run = testkit::crawl_run(self.tenant, config);
        run.created_at = self.clock.now();
        if expired {
            run.created_at -= chrono::Duration::days(3);
            run.started_at = Some(run.created_at);
            run.finished_at = Some(run.created_at + chrono::Duration::hours(1));
            run.status = RunStatus::Completed;
            run.terminal_reason = Some(TerminalReason::FrontierExhausted);
        }
        RunRepo::create(self.store.as_ref(), &run, None).await.unwrap();
        run
    }

    async fn get(&self, path: &str, key: Option<&str>) -> (StatusCode, Value, String) {
        let mut request = Request::builder().uri(path);
        if let Some(key) = key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value, text)
    }

    async fn run_with(&self, tenant: TenantId, zdr: bool, age_hours: i64) -> crawlx_core::repo::CrawlRun {
        let mut config = testkit::create_crawl("https://report.example.test/private-token", &[], 1);
        config.retention.days = 1;
        if zdr {
            config.retention.mode = RetentionMode::Zdr;
        }
        let mut run = testkit::crawl_run(tenant, config);
        run.created_at = self.clock.now() - chrono::Duration::hours(age_hours);
        RunRepo::create(self.store.as_ref(), &run, None).await.unwrap();
        run
    }

    /// Discover and lease one real frontier URL, returning its exact producer lease.
    async fn leased(
        &self,
        run: &crawlx_core::repo::CrawlRun,
        path: &str,
    ) -> (CustodyLease, i64, CanonicalUrl) {
        let worker = WorkerId::new();
        self.store
            .register_worker(worker, "report-fact-fixture", "1")
            .await
            .unwrap();
        let url = testkit::canonical_url(&format!(
            "https://report.example.test/{path}?key=secret-query-canary"
        ));
        let (_, id) = self.store.discover(run.id, &url, 0, None, None).await.unwrap();
        let id = id.unwrap();
        let (entry, fence) = self
            .store
            .lease_batch_fenced(run.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(entry.id, id);
        (
            CustodyLease::for_url(run.tenant, run.id, id, worker, fence),
            id,
            url,
        )
    }

    fn at(&self, seconds: i64) -> Timestamp {
        self.clock.now() + chrono::Duration::seconds(seconds)
    }

    /// Deterministic fact whose observation time is `ordinal` seconds after the injected clock.
    fn fact(
        &self,
        lease: &CustodyLease,
        url: &CanonicalUrl,
        ordinal: u64,
        data: ReportDataV1,
    ) -> ReportFactV1 {
        let mut fact = ReportFactV1::new(
            lease,
            Digest::of("crawlx/report-route-fixture", &ordinal.to_le_bytes()),
            self.at(i64::try_from(ordinal).unwrap()),
            data,
        );
        fact.url_key = Some(url.key);
        fact.host_key = host_key(url);
        fact
    }

    /// Append through the real memory repository under the live leased URL.
    async fn put(&self, lease: &CustodyLease, url: &CanonicalUrl, ordinal: u64, data: ReportDataV1) -> u64 {
        let fact = self.fact(lease, url, ordinal, data);
        self.store.append_fact(lease, &fact).await.unwrap()
    }

    fn root(run: &crawlx_core::repo::CrawlRun) -> String {
        format!("/v1/crawls/{}/reports", run.id)
    }
}

#[tokio::test]
async fn every_report_enforces_auth_tenant_and_read_permission() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let root = format!("/v1/crawls/{}/reports", run.id);
    let (status, inventory, _) = env.get(&root, Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inventory["reports"].as_array().unwrap().len(), Kind::ALL.len());
    for path in std::iter::once(root.clone()).chain(
        Kind::ALL
            .into_iter()
            .map(|kind| format!("{root}/{}", kind.name())),
    ) {
        assert_eq!(env.get(&path, None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(env.get(&path, Some(FOREIGN)).await.0, StatusCode::NOT_FOUND);
        assert_eq!(env.get(&path, Some(WRITER)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(env.get(&path, Some(KEY)).await.0, StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn reports_refuse_expired_and_zero_retention_sources_without_content() {
    let env = Env::new().await;
    for (zdr, expired) in [(false, true), (true, false)] {
        let run = env.run(zdr, expired).await;
        for kind in Kind::ALL {
            let path = format!("/v1/crawls/{}/reports/{}", run.id, kind.name());
            let (status, _, text) = env.get(&path, Some(KEY)).await;
            assert_eq!(status, StatusCode::GONE, "{path}");
            assert!(!text.contains("private-token"));
            assert!(!text.contains("configDigest"));
        }
        // Content-free inventory remains discoverable, like ordinary run metadata.
        assert_eq!(
            env.get(&format!("/v1/crawls/{}/reports", run.id), Some(KEY))
                .await
                .0,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn query_parser_rejects_unbounded_scripts_ranges_and_unavailable_fact_filters() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let root = format!("/v1/crawls/{}/reports/frontier", run.id);
    for query in [
        "limit=0",
        "limit=65",
        "limit=-1",
        "limit=18446744073709551616",
        "after=-1",
        "after=9223372036854775808",
        "state=not_a_state",
        "minDepth=5&maxDepth=1",
        "minDepth=65536",
        "class=not_a_class",
        "q=SELECT",
        "script=execute",
        "format=html",
        "urlKey=not_a_digest",
        "minBytes=0",
        "minDurationMs=1",
        "status=200",
    ] {
        assert_eq!(
            env.get(&format!("{root}?{query}"), Some(KEY)).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{query}"
        );
    }
    let huge = "a".repeat(MAX_QUERY_BYTES + 1);
    assert_eq!(
        env.get(&format!("{root}?state={huge}"), Some(KEY)).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    for query in [
        "status=99",
        "status=600",
        "since=not_a_date",
        "since=2025-01-02T00:00:00Z&until=2025-01-01T00:00:00Z",
    ] {
        let path = format!("/v1/crawls/{}/reports/mime_status?{query}", run.id);
        assert_eq!(
            env.get(&path, Some(KEY)).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{query}"
        );
    }
}

#[tokio::test]
async fn filtered_pages_advance_by_scanned_identity_and_classify_only_stored_codes() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    for (suffix, state, reason) in [
        ("scope", FrontierStatus::PolicyBlocked, "host_scope"),
        ("limit", FrontierStatus::PolicyBlocked, "host_page_limit"),
        (
            "robots",
            FrontierStatus::RobotsBlocked,
            "secret-diagnostic-canary",
        ),
        ("redirect", FrontierStatus::PolicyBlocked, "invalid_redirect"),
        ("duplicate", FrontierStatus::PolicyBlocked, "dedupe:fingerprint"),
        (
            "unknown",
            FrontierStatus::PolicyBlocked,
            "secret-diagnostic-canary",
        ),
    ] {
        let url = testkit::canonical_url(&format!(
            "https://report.example.test/private-token/{suffix}?key=secret-query-canary"
        ));
        env.store
            .discover(run.id, &url, 1, None, Some((state, reason.to_owned())))
            .await
            .unwrap();
    }
    let root = format!("/v1/crawls/{}/reports/skipped_pages", run.id);
    let (status, first, text) = env.get(&format!("{root}?limit=2&class=robots"), Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["scanned"], 2);
    assert!(first["rows"].as_array().unwrap().is_empty());
    let cursor = first["next"].as_u64().unwrap();
    let (_, second, _) = env
        .get(&format!("{root}?limit=2&class=robots&after={cursor}"), Some(KEY))
        .await;
    assert_eq!(second["rows"][0]["class"], "robots");
    assert_eq!(second["rows"][0]["depth"], 1);
    assert!(!text.contains("secret-query-canary"));
    let (_, all, text) = env.get(&root, Some(KEY)).await;
    let classes: Vec<_> = all["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["class"].as_str().unwrap())
        .collect();
    assert_eq!(
        classes,
        [
            "out_of_scope",
            "limit",
            "robots",
            "redirect",
            "duplicate",
            "unknown"
        ]
    );
    for canary in [
        "private-token",
        "secret-query-canary",
        "secret-diagnostic-canary",
        "report.example.test",
    ] {
        assert!(!text.contains(canary));
    }
    let (_, hosts, _) = env
        .get(&format!("/v1/crawls/{}/reports/hosts", run.id), Some(KEY))
        .await;
    let count: u64 = hosts["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["count"].as_u64().unwrap())
        .sum();
    assert_eq!(count, 6);
    assert_eq!(hosts["aggregationScope"], "source_page");
}

#[tokio::test]
async fn finite_jsonl_events_withhold_payloads_context_and_unknown_names() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    for kind in ["page", "secret-event-canary", "page.failed"] {
        env.store
            .append(
                run.id,
                kind,
                json!({"authorization":"secret-payload-canary","url":"https://private.example.test/"}),
            )
            .await
            .unwrap();
    }
    let path = format!("/v1/crawls/{}/reports/events?limit=2&format=jsonl", run.id);
    let (status, _, text) = env.get(&path, Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["event"], "page");
    assert_eq!(lines[1]["event"], "other");
    assert_eq!(lines[2]["scanned"], 2);
    assert_eq!(lines[2]["next"], 2);
    assert!(lines[2]["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("dropped_event_count")));
    assert!(lines[2]["withheld"]
        .as_array()
        .unwrap()
        .contains(&json!("event_payload")));
    for canary in [
        "secret-event-canary",
        "secret-payload-canary",
        "private.example.test",
    ] {
        assert!(!text.contains(canary));
    }
    let (_, empty, _) = env
        .get(
            &format!("/v1/crawls/{}/reports/events?limit=1&event=page.failed", run.id),
            Some(KEY),
        )
        .await;
    assert_eq!(empty["next"], 1);
    assert!(empty["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn committed_page_reports_preserve_known_and_missing_facts() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let worker = WorkerId::new();
    env.store
        .register_worker(worker, "report-fixture", "1")
        .await
        .unwrap();
    let url = testkit::canonical_url("https://report.example.test/private-token");
    let (_, id) = env.store.discover(run.id, &url, 0, None, None).await.unwrap();
    let id = id.unwrap();
    let lease = env
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
        content_type: Some("text/html; secret=secret-mime-canary".to_owned()),
        content_digest: Digest::of("crawlx/report-fixture", b"real retained generation"),
        title: Some("secret-title-canary".to_owned()),
        markdown: None,
        html: None,
        metadata: json!({"password":"secret-metadata-canary"}),
        links: vec!["https://private.example.test/".to_owned()],
        fetched_at: env.clock.now(),
        lane: crawlx_core::TrustLane::Diagnostic,
    };
    let mut commit = RequestCommitV1::terminal(run.id, id, lease.1, 1, FrontierStatus::Succeeded, None);
    commit.page = Some(page);
    env.store.commit_fenced(commit).await.unwrap();
    let path = format!("/v1/crawls/{}/reports/mime_status?status=200", run.id);
    let (status, result, text) = env.get(&path, Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["rows"][0]["count"], 1);
    assert_eq!(result["rows"][0]["status"], 200);
    assert_eq!(result["rows"][0]["mime"], "text/html");
    assert!(result["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("wire_size_bytes")));
    for canary in [
        "secret-mime-canary",
        "secret-title-canary",
        "secret-metadata-canary",
        "private-token",
    ] {
        assert!(!text.contains(canary));
    }
    let (_, uri, uri_text) = env
        .get(&format!("/v1/crawls/{}/reports/uri_log", run.id), Some(KEY))
        .await;
    assert_eq!(uri["rows"][0]["frontierId"], id);
    assert_eq!(uri["rows"][0]["status"], 200);
    assert!(uri["rows"][0]["contentDigest"].is_string());
    assert!(uri["rows"][0]["fetchedAt"].is_string());
    assert!(!uri_text.contains("private-token"));
    let (_, filtered, _) = env
        .get(
            &format!("/v1/crawls/{}/reports/mime_status?status=404", run.id),
            Some(KEY),
        )
        .await;
    assert!(filtered["rows"].as_array().unwrap().is_empty());
    let query = Query::parse(Kind::MimeStatus, &Params(BTreeMap::new())).unwrap();
    let mut absent = env.store.get_committed(run.id, id).await.unwrap().unwrap();
    absent.status = 0;
    absent.content_type = None;
    let rows = serde_json::to_value(page_rows(Kind::MimeStatus, vec![absent], &query)).unwrap();
    assert!(rows[0]["status"].is_null());
    assert!(rows[0]["mime"].is_null());
    assert!(rows[0]["mimeKey"].is_null());
}

fn wire(received: Option<u64>, sent: Option<u64>, duration: Option<u64>) -> ReportDataV1 {
    ReportDataV1::Wire {
        received_bytes: received,
        sent_bytes: sent,
        duration_us: duration,
    }
}

fn stage(duration_us: u64, outcome: StageOutcomeV1) -> ReportDataV1 {
    ReportDataV1::Stage {
        stage: ProcessorStageV1::Fetch,
        outcome,
        duration_us,
        processor: ProcessorIdentityV1::NativeHttp,
        processor_version: 2,
    }
}

fn alert() -> ReportDataV1 {
    ReportDataV1::Alert {
        severity: AlertSeverityV1::Warning,
        code: AlertCodeV1::DnsFailure,
        context: AlertContextV1::Acquisition,
    }
}

fn dns(duration_us: u64, recheck_at: Option<Timestamp>) -> ReportDataV1 {
    ReportDataV1::Dns {
        outcome: DnsOutcomeV1::Resolved,
        duration_us,
        recheck_at,
    }
}

fn stamp(at: Timestamp) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn unrecorded(page: &Value, field: &str) -> bool {
    page["notRecorded"].as_array().unwrap().contains(&json!(field))
}

fn sequences(entries: &Value) -> Vec<u64> {
    entries
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["sequence"].as_u64().unwrap())
        .collect()
}

fn report<'a>(inventory: &'a Value, name: &str) -> &'a Value {
    inventory["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|report| report["name"] == name)
        .unwrap()
}

const CANARIES: [&str; 3] = ["private-token", "secret-query-canary", "report.example.test"];

#[tokio::test]
async fn legacy_runs_report_empty_measured_history_while_threads_stay_unavailable() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let root = Env::root(&run);
    for kind in [
        "host_dns_health",
        "alert_log",
        "history",
        "wire_history",
        "processor_history",
        "pipeline_history",
    ] {
        let (status, result, _) = env.get(&format!("{root}/{kind}"), Some(KEY)).await;
        assert_eq!(status, StatusCode::OK, "{kind}");
        assert_eq!(result["source"], "report_history", "{kind}");
        assert_eq!(result["aggregationScope"], "facts_page", "{kind}");
        assert_eq!(result["scanned"], 0);
        assert!(result["rows"].as_array().unwrap().is_empty());
        assert!(result["next"].is_null());
        assert_eq!(result["factsPage"]["facts"], 0);
        assert!(result["factsPage"]["durations"].as_array().unwrap().is_empty());
        assert!(!result["notRecorded"].as_array().unwrap().is_empty(), "{kind}");
    }
    let (_, dns_health, _) = env.get(&format!("{root}/host_dns_health"), Some(KEY)).await;
    for field in ["dns_health_history", "dns_recheck_schedule", "dns_percentiles"] {
        assert!(unrecorded(&dns_health, field));
    }
    let (_, alerts, _) = env.get(&format!("{root}/alert_log"), Some(KEY)).await;
    assert!(unrecorded(&alerts, "typed_alert_history"));
    assert!(unrecorded(&alerts, "alert_severity"));
    let (_, threads, _) = env.get(&format!("{root}/threads"), Some(KEY)).await;
    assert_eq!(threads["source"], "unavailable");
    assert_eq!(threads["scanned"], 0);
    assert!(threads["rows"].as_array().unwrap().is_empty());
    assert!(threads["factsPage"].is_null());
    assert!(unrecorded(&threads, "per_run_live_threads"));
    // A legacy source row without any instrumented fact keeps every unrecorded field.
    let url = testkit::canonical_url("https://report.example.test/legacy");
    env.store.discover(run.id, &url, 0, None, None).await.unwrap();
    let (_, frontier, _) = env.get(&format!("{root}/frontier"), Some(KEY)).await;
    assert_eq!(frontier["rows"].as_array().unwrap().len(), 1);
    assert!(frontier["facts"].as_array().unwrap().is_empty());
    assert!(frontier["factNext"].is_null());
    assert_eq!(frontier["factsPage"]["scope"], "facts_page");
    for field in ["wire_size_bytes", "response_duration_ms", "discovery_timestamp"] {
        assert!(unrecorded(&frontier, field));
    }
}

#[tokio::test]
async fn history_reports_serve_measured_facts_and_keep_unknown_fields_null() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease, _, url) = env.leased(&run, "measured").await;
    env.put(&lease, &url, 1, wire(Some(4096), Some(512), Some(250)))
        .await;
    env.put(&lease, &url, 2, wire(None, None, None)).await;
    env.put(&lease, &url, 3, stage(900, StageOutcomeV1::Failed)).await;
    env.put(&lease, &url, 4, dns(40, Some(env.at(3600)))).await;
    env.put(&lease, &url, 5, alert()).await;
    env.put(&lease, &url, 6, ReportDataV1::Loss { dropped: 7 }).await;
    let root = Env::root(&run);

    let (status, wire_page, text) = env.get(&format!("{root}/wire_history"), Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wire_page["scanned"], 2);
    assert_eq!(wire_page["rows"][0]["rowType"], "fact");
    assert_eq!(wire_page["rows"][0]["sequence"], 1);
    assert_eq!(wire_page["rows"][0]["fact"]["urlKey"], json!(url.key));
    assert_eq!(wire_page["rows"][0]["fact"]["data"]["received_bytes"], 4096);
    assert!(wire_page["rows"][1]["fact"]["data"]["received_bytes"].is_null());
    assert!(wire_page["rows"][1]["fact"]["data"]["duration_us"].is_null());
    assert!(!unrecorded(&wire_page, "wire_size_bytes"));
    assert!(!unrecorded(&wire_page, "response_duration_ms"));
    assert!(!wire_page["crossRun"].as_bool().unwrap());

    let (_, processors, _) = env.get(&format!("{root}/processor_history"), Some(KEY)).await;
    assert_eq!(processors["rows"][0]["fact"]["data"]["processor"], "native_http");
    assert_eq!(processors["rows"][0]["fact"]["data"]["processor_version"], 2);
    assert!(!unrecorded(&processors, "processor_identity"));
    assert!(!unrecorded(&processors, "failure_stage"));

    let (_, health, _) = env.get(&format!("{root}/host_dns_health"), Some(KEY)).await;
    assert_eq!(health["rows"][0]["fact"]["data"]["outcome"], "resolved");
    assert!(health["rows"][0]["fact"]["data"]["recheck_at"].is_string());
    for field in ["dns_health_history", "dns_recheck_schedule", "dns_percentiles"] {
        assert!(!unrecorded(&health, field), "{field}");
    }

    let (_, alerts, _) = env.get(&format!("{root}/alert_log"), Some(KEY)).await;
    assert_eq!(alerts["rows"][0]["fact"]["data"]["severity"], "warning");
    assert_eq!(alerts["rows"][0]["fact"]["data"]["code"], "dns_failure");
    assert_eq!(alerts["rows"][0]["fact"]["data"]["context"], "acquisition");
    assert!(!unrecorded(&alerts, "typed_alert_history"));
    assert!(!unrecorded(&alerts, "alert_severity"));

    let (_, losses, _) = env.get(&format!("{root}/history?kind=loss"), Some(KEY)).await;
    assert_eq!(losses["rows"].as_array().unwrap().len(), 1);
    assert_eq!(losses["rows"][0]["fact"]["data"]["dropped"], 7);
    assert!(!unrecorded(&losses, "dropped_event_count"));
    assert!(unrecorded(&losses, "wire_size_bytes"));
    let (_, typed, _) = env.get(&format!("{root}/history?kind=alert"), Some(KEY)).await;
    assert_eq!(typed["rows"][0]["fact"]["data"]["severity"], "warning");

    let (_, everything, all_text) = env.get(&format!("{root}/history"), Some(KEY)).await;
    assert_eq!(sequences(&everything["rows"]), [1, 2, 3, 4, 5, 6]);
    for text in [&text, &all_text] {
        for canary in CANARIES {
            assert!(!text.contains(canary), "{canary}");
        }
    }

    // Unknown observations never become measured successes.
    let other = env.run(false, false).await;
    let (lease, _, url) = env.leased(&other, "unknown").await;
    env.put(&lease, &url, 1, wire(None, None, None)).await;
    env.put(&lease, &url, 2, stage(10, StageOutcomeV1::Succeeded))
        .await;
    env.put(&lease, &url, 3, dns(5, None)).await;
    let root = Env::root(&other);
    let (_, unknown, _) = env.get(&format!("{root}/wire_history"), Some(KEY)).await;
    assert_eq!(unknown["rows"].as_array().unwrap().len(), 1);
    assert!(unrecorded(&unknown, "wire_size_bytes"));
    assert!(unrecorded(&unknown, "response_duration_ms"));
    let (_, succeeded, _) = env.get(&format!("{root}/processor_history"), Some(KEY)).await;
    assert!(!unrecorded(&succeeded, "processor_identity"));
    assert!(unrecorded(&succeeded, "failure_stage"));
    let (_, unscheduled, _) = env.get(&format!("{root}/host_dns_health"), Some(KEY)).await;
    assert!(!unrecorded(&unscheduled, "dns_health_history"));
    assert!(unrecorded(&unscheduled, "dns_recheck_schedule"));
}

#[tokio::test]
async fn pipeline_history_reports_committed_checkpoints_only() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease, id, url) = env.leased(&run, "pipeline").await;
    for (ordinal, stage, state) in [
        (1, PipelineStageV1::Fetch, PipelineStateV1::Succeeded),
        (2, PipelineStageV1::Parse, PipelineStateV1::Succeeded),
        (3, PipelineStageV1::Index, PipelineStateV1::Failed),
    ] {
        let mut fact = env.fact(&lease, &url, ordinal, ReportDataV1::Pipeline { stage, state });
        fact.request_id = Some(id);
        env.store.append_fact(&lease, &fact).await.unwrap();
    }
    let (_, pipeline, _) = env
        .get(&format!("{}/pipeline_history", Env::root(&run)), Some(KEY))
        .await;
    assert_eq!(sequences(&pipeline["rows"]), [1, 2, 3]);
    assert_eq!(pipeline["rows"][2]["fact"]["data"]["stage"], "index");
    assert_eq!(pipeline["rows"][2]["fact"]["data"]["state"], "failed");
    assert_eq!(pipeline["rows"][2]["fact"]["requestId"], id);
    assert!(!unrecorded(&pipeline, "pipeline_checkpoints"));
}

#[tokio::test]
async fn companion_facts_use_independent_cursors_and_matching_lookahead() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let mut leases = Vec::new();
    for path in ["a", "b", "c"] {
        leases.push(env.leased(&run, path).await);
    }
    for ordinal in 1..=3 {
        env.put(
            &leases[0].0,
            &leases[0].2,
            ordinal,
            wire(Some(ordinal * 10), None, Some(ordinal)),
        )
        .await;
    }
    for ordinal in 4..=5 {
        env.put(
            &leases[1].0,
            &leases[1].2,
            ordinal,
            wire(Some(ordinal * 10), None, Some(ordinal)),
        )
        .await;
    }
    let root = format!("{}/frontier", Env::root(&run));
    let (_, first, _) = env.get(&format!("{root}?limit=2"), Some(KEY)).await;
    assert_eq!(first["rows"].as_array().unwrap().len(), 2);
    let cursor = first["next"].as_u64().unwrap();
    assert_eq!(sequences(&first["facts"]), [1, 2]);
    assert_eq!(first["factNext"], 2);
    assert_eq!(first["factsPage"]["scope"], "facts_page");
    assert_eq!(first["factsPage"]["facts"], 2);

    // The source cursor alone never advances the fact cursor.
    let (_, second, _) = env
        .get(&format!("{root}?limit=2&after={cursor}"), Some(KEY))
        .await;
    assert_eq!(second["rows"].as_array().unwrap().len(), 1);
    assert!(second["next"].is_null());
    assert_eq!(sequences(&second["facts"]), [1, 2]);
    assert_eq!(second["factNext"], 2);

    // The fact cursor alone never advances the source cursor.
    let (_, third, _) = env.get(&format!("{root}?limit=2&factsAfter=2"), Some(KEY)).await;
    assert_eq!(third["next"].as_u64(), Some(cursor));
    assert_eq!(sequences(&third["facts"]), [3, 4]);
    assert_eq!(third["factNext"], 4);
    let (_, fourth, _) = env.get(&format!("{root}?limit=2&factsAfter=4"), Some(KEY)).await;
    assert_eq!(sequences(&fourth["facts"]), [5]);
    assert!(fourth["factNext"].is_null());
    // Exactly full page: lookahead sees no further matching fact, so no cursor is offered.
    let (_, full, _) = env.get(&format!("{root}?limit=5"), Some(KEY)).await;
    assert_eq!(sequences(&full["facts"]), [1, 2, 3, 4, 5]);
    assert!(full["factNext"].is_null());

    let (_, other_class, _) = env.get(&format!("{root}?factKind=stage"), Some(KEY)).await;
    assert!(other_class["facts"].as_array().unwrap().is_empty());
    assert!(other_class["factNext"].is_null());
    assert_eq!(
        env.get(&format!("{root}?factKind=bogus"), Some(KEY)).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn companion_reports_clear_not_recorded_only_for_facts_they_return() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease, _, url) = env.leased(&run, "proof").await;
    env.put(&lease, &url, 1, wire(Some(2048), None, None)).await;
    env.put(&lease, &url, 2, stage(5, StageOutcomeV1::Succeeded))
        .await;
    env.put(&lease, &url, 3, dns(9, None)).await;
    env.put(&lease, &url, 4, alert()).await;
    env.put(&lease, &url, 5, ReportDataV1::Loss { dropped: 3 }).await;
    let root = Env::root(&run);
    for report in ["frontier", "mime_status", "uri_log"] {
        let (_, page, text) = env.get(&format!("{root}/{report}"), Some(KEY)).await;
        assert_eq!(sequences(&page["facts"]), [1], "{report}");
        assert_eq!(page["facts"][0]["fact"]["data"]["kind"], "wire");
        assert!(!unrecorded(&page, "wire_size_bytes"), "{report}");
        assert!(unrecorded(&page, "response_duration_ms"), "{report}");
        for canary in CANARIES {
            assert!(!text.contains(canary), "{canary}");
        }
    }
    let (_, failures, _) = env.get(&format!("{root}/processor_failures"), Some(KEY)).await;
    assert_eq!(sequences(&failures["facts"]), [2]);
    assert!(!unrecorded(&failures, "processor_identity"));
    assert!(unrecorded(&failures, "failure_stage"));
    let (_, hosts, _) = env.get(&format!("{root}/hosts"), Some(KEY)).await;
    assert_eq!(sequences(&hosts["facts"]), [3]);
    assert!(!unrecorded(&hosts, "dns_health_history"));
    assert!(!unrecorded(&hosts, "dns_percentiles"));
    let (_, errors, _) = env.get(&format!("{root}/error_log"), Some(KEY)).await;
    assert_eq!(sequences(&errors["facts"]), [4]);
    assert!(unrecorded(&errors, "failure_stage"));
    assert!(unrecorded(&errors, "failure_timestamp"));
    for report in ["events", "crawl_log"] {
        let (_, page, _) = env.get(&format!("{root}/{report}"), Some(KEY)).await;
        assert_eq!(sequences(&page["facts"]), [4]);
        assert!(!unrecorded(&page, "log_level"));
        assert!(!unrecorded(&page, "log_context"));
        assert!(unrecorded(&page, "dropped_event_count"));
        let (_, loss, _) = env
            .get(&format!("{root}/{report}?factKind=loss"), Some(KEY))
            .await;
        assert_eq!(sequences(&loss["facts"]), [5]);
        assert!(!unrecorded(&loss, "dropped_event_count"));
        assert!(unrecorded(&loss, "log_level"));
    }
}

#[tokio::test]
async fn page_scoped_percentiles_and_wire_sums_are_exact_and_overflow_checked() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease, _, url) = env.leased(&run, "stats").await;
    for (ordinal, duration) in [(1, 50), (2, 10), (3, 40), (4, 20), (5, 30)] {
        env.put(&lease, &url, ordinal, stage(duration, StageOutcomeV1::Succeeded))
            .await;
    }
    for (ordinal, received, sent, duration) in [
        (6, 1000, Some(5), 100),
        (7, 2000, None, 200),
        (8, 3000, Some(7), 300),
        (9, 4000, None, 400),
    ] {
        env.put(&lease, &url, ordinal, wire(Some(received), sent, Some(duration)))
            .await;
    }
    env.put(&lease, &url, 10, wire(None, None, None)).await;
    let root = Env::root(&run);

    let (_, processors, _) = env.get(&format!("{root}/processor_history"), Some(KEY)).await;
    let durations = &processors["factsPage"]["durations"];
    assert_eq!(durations.as_array().unwrap().len(), 1);
    assert_eq!(durations[0]["kind"], "stage");
    assert_eq!(durations[0]["count"], 5);
    assert_eq!(durations[0]["p50Us"], 30);
    assert_eq!(durations[0]["p95Us"], 50);

    let (_, wires, _) = env.get(&format!("{root}/wire_history"), Some(KEY)).await;
    let stats = &wires["factsPage"];
    assert_eq!(stats["scope"], "facts_page");
    assert_eq!(stats["facts"], 5);
    assert_eq!(stats["durations"][0]["count"], 4);
    assert_eq!(stats["durations"][0]["p50Us"], 200);
    assert_eq!(stats["durations"][0]["p95Us"], 400);
    assert_eq!(stats["wire"]["receivedCount"], 4);
    assert_eq!(stats["wire"]["receivedBytes"], 10_000);
    assert_eq!(stats["wire"]["sentCount"], 2);
    assert_eq!(stats["wire"]["sentBytes"], 12);
    assert!(!stats["wire"]["overflow"].as_bool().unwrap());

    // Mixed classes are grouped; no cross-class percentile is invented.
    let (_, mixed, _) = env.get(&format!("{root}/history"), Some(KEY)).await;
    let groups = mixed["factsPage"]["durations"].as_array().unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0]["kind"], "stage");
    assert_eq!(groups[1]["kind"], "wire");
    assert_eq!(mixed["factsPage"]["facts"], 10);

    // A page whose sums exceed u64 reports overflow explicitly instead of wrapping.
    let big = env.run(false, false).await;
    let (lease, _, url) = env.leased(&big, "overflow").await;
    let max = u64::try_from(i64::MAX).unwrap();
    for ordinal in 1..=3 {
        env.put(&lease, &url, ordinal, wire(Some(max), Some(1), Some(max)))
            .await;
    }
    let (_, overflow, _) = env
        .get(&format!("{}/wire_history", Env::root(&big)), Some(KEY))
        .await;
    let wire_stats = &overflow["factsPage"]["wire"];
    assert!(wire_stats["overflow"].as_bool().unwrap());
    assert_eq!(wire_stats["receivedCount"], 3);
    assert!(wire_stats["receivedBytes"].is_null());
    assert_eq!(wire_stats["sentBytes"], 3);
    assert_eq!(overflow["factsPage"]["durations"][0]["p50Us"], max);
}

#[tokio::test]
async fn size_duration_time_and_key_filters_apply_before_limit_and_cursor() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease_a, _, url_a) = env.leased(&run, "a").await;
    let (lease_b, _, url_b) = env.leased(&run, "b").await;
    for ordinal in 1..=5 {
        env.put(
            &lease_a,
            &url_a,
            ordinal,
            wire(Some(ordinal * 10), None, Some(ordinal)),
        )
        .await;
    }
    env.put(&lease_b, &url_b, 6, wire(Some(35), None, Some(100)))
        .await;
    env.put(&lease_b, &url_b, 7, wire(None, None, None)).await;
    let root = format!("{}/wire_history", Env::root(&run));

    let (_, first, _) = env
        .get(
            &format!("{root}?minWireBytes=30&maxWireBytes=50&limit=2"),
            Some(KEY),
        )
        .await;
    assert_eq!(sequences(&first["rows"]), [3, 4]);
    assert_eq!(first["next"], 4);
    assert_eq!(first["scanned"], 2);
    let (_, second, _) = env
        .get(
            &format!("{root}?minWireBytes=30&maxWireBytes=50&limit=2&after=4"),
            Some(KEY),
        )
        .await;
    assert_eq!(sequences(&second["rows"]), [5, 6]);
    assert!(second["next"].is_null());

    // Unknown wire counters never satisfy a size bound.
    let (_, sized, _) = env.get(&format!("{root}?minWireBytes=0"), Some(KEY)).await;
    assert_eq!(sequences(&sized["rows"]), [1, 2, 3, 4, 5, 6]);
    let (_, by_url, _) = env
        .get(&format!("{root}?urlKey={}", url_b.key.to_hex()), Some(KEY))
        .await;
    assert_eq!(sequences(&by_url["rows"]), [6, 7]);
    let (_, by_url_size, _) = env
        .get(
            &format!("{root}?urlKey={}&minWireBytes=0", url_b.key.to_hex()),
            Some(KEY),
        )
        .await;
    assert_eq!(sequences(&by_url_size["rows"]), [6]);
    let host = host_key(&url_a).unwrap().to_hex();
    let (_, by_host, _) = env.get(&format!("{root}?hostKey={host}"), Some(KEY)).await;
    assert_eq!(sequences(&by_host["rows"]), [1, 2, 3, 4, 5, 6, 7]);
    let (_, by_duration, _) = env
        .get(&format!("{root}?minDurationUs=2&maxDurationUs=4"), Some(KEY))
        .await;
    assert_eq!(sequences(&by_duration["rows"]), [2, 3, 4]);
    let window = format!("since={}&until={}", stamp(env.at(3)), stamp(env.at(5)));
    let (_, by_time, _) = env.get(&format!("{root}?{window}"), Some(KEY)).await;
    assert_eq!(sequences(&by_time["rows"]), [3, 4, 5]);

    let history = format!("{}/history", Env::root(&run));
    let (_, kinded, _) = env
        .get(&format!("{history}?kind=wire&minWireBytes=30&limit=1"), Some(KEY))
        .await;
    assert_eq!(sequences(&kinded["rows"]), [3]);
    assert_eq!(kinded["next"], 3);
    let (_, empty, _) = env
        .get(&format!("{history}?kind=alert&minWireBytes=1"), Some(KEY))
        .await;
    assert!(empty["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn legacy_time_bounds_stay_exclusive_while_history_bounds_are_inclusive() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease, _, url) = env.leased(&run, "bounds").await;
    for ordinal in 1..=5 {
        env.put(&lease, &url, ordinal, wire(Some(ordinal), None, Some(ordinal)))
            .await;
    }
    let window = format!("since={}&until={}", stamp(env.at(2)), stamp(env.at(4)));
    let root = Env::root(&run);
    let (_, legacy, _) = env.get(&format!("{root}/uri_log?{window}"), Some(KEY)).await;
    assert_eq!(sequences(&legacy["facts"]), [2, 3]);
    let (_, history, _) = env.get(&format!("{root}/wire_history?{window}"), Some(KEY)).await;
    assert_eq!(sequences(&history["rows"]), [2, 3, 4]);
    // A single-instant inclusive history window is valid; the legacy window is empty.
    let instant = format!("since={0}&until={0}", stamp(env.at(3)));
    let (_, one, _) = env
        .get(&format!("{root}/wire_history?{instant}"), Some(KEY))
        .await;
    assert_eq!(sequences(&one["rows"]), [3]);
    assert_eq!(
        env.get(&format!("{root}/uri_log?{instant}"), Some(KEY)).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Facts never predate the epoch, so earlier legacy bounds clamp instead of failing.
    let (status, clamped, _) = env
        .get(&format!("{root}/uri_log?since=1969-12-31T23:59:59Z"), Some(KEY))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(clamped["facts"].as_array().unwrap().len(), 5);
    let (status, before, _) = env
        .get(&format!("{root}/uri_log?until=1969-12-31T23:59:59Z"), Some(KEY))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(before["facts"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn cross_run_history_is_history_only_tenant_scoped_and_retention_checked() {
    let env = Env::new().await;
    let foreign_tenant = tenant_id_for("other-report-owner");
    let first = env.run_with(env.tenant, false, 0).await;
    let aging = env.run_with(env.tenant, false, 12).await;
    let volatile = env.run_with(env.tenant, true, 0).await;
    let foreign = env.run_with(foreign_tenant, false, 0).await;
    for run in [&first, &aging, &volatile, &foreign] {
        let (lease, _, url) = env.leased(run, "timeline").await;
        env.put(&lease, &url, 1, alert()).await;
    }
    let runs = |page: &Value| -> Vec<Value> {
        page["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["fact"]["run"].clone())
            .collect()
    };
    let own = format!("{}/history", Env::root(&first));
    let (_, local, _) = env.get(&own, Some(KEY)).await;
    assert_eq!(runs(&local), [json!(first.id)]);
    assert!(!local["crossRun"].as_bool().unwrap());

    let (status, timeline, text) = env.get(&format!("{own}?crossRun=true"), Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(timeline["crossRun"].as_bool().unwrap());
    assert_eq!(runs(&timeline), [json!(first.id), json!(aging.id)]);
    for hidden in [volatile.id, foreign.id] {
        assert!(!text.contains(&hidden.to_string()));
    }
    for canary in CANARIES {
        assert!(!text.contains(canary));
    }

    // The foreign tenant cannot reach this run and only sees its own timeline elsewhere.
    assert_eq!(env.get(&own, Some(FOREIGN)).await.0, StatusCode::NOT_FOUND);
    let (_, theirs, _) = env
        .get(
            &format!("{}/history?crossRun=true", Env::root(&foreign)),
            Some(FOREIGN),
        )
        .await;
    assert_eq!(runs(&theirs), [json!(foreign.id)]);

    // Cross-run reads exist for history only and require an explicit boolean.
    for path in [
        format!("{}/frontier?crossRun=true", Env::root(&first)),
        format!("{}/wire_history?crossRun=true", Env::root(&first)),
        format!("{}/alert_log?crossRun=false", Env::root(&first)),
        format!("{own}?crossRun=maybe"),
    ] {
        assert_eq!(
            env.get(&path, Some(KEY)).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{path}"
        );
    }

    // Each source row keeps its own storage retention, even when the authorizing run is live.
    env.clock.advance_ms(13 * 3_600_000);
    let (status, later, _) = env.get(&format!("{own}?crossRun=true"), Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(runs(&later), [json!(first.id)]);
}

#[tokio::test]
async fn expired_and_zdr_runs_never_return_fact_content_from_any_fact_report() {
    let env = Env::new().await;
    let live = env.run(false, false).await;
    let zdr = env.run_with(env.tenant, true, 0).await;
    let mut keys = Vec::new();
    for run in [&live, &zdr] {
        let (lease, _, url) = env.leased(run, "expiring").await;
        env.put(&lease, &url, 1, wire(Some(1), Some(2), Some(3))).await;
        keys.push(url.key.to_hex());
    }
    let (status, current, _) = env.get(&format!("{}/history", Env::root(&live)), Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["rows"].as_array().unwrap().len(), 1);
    let reports = [
        "history",
        "wire_history",
        "processor_history",
        "pipeline_history",
        "host_dns_health",
        "alert_log",
        "frontier",
        "uri_log",
        "mime_status",
        "events",
        "crawl_log",
        "hosts",
        "processor_failures",
        "error_log",
    ];
    let mut paths = Vec::new();
    for report in reports {
        paths.push(format!("{}/{report}", Env::root(&zdr)));
    }
    env.clock.advance_ms(86_400_001);
    for report in reports {
        paths.push(format!("{}/{report}", Env::root(&live)));
    }
    paths.push(format!("{}/history?crossRun=true", Env::root(&live)));
    for path in paths {
        let (status, _, text) = env.get(&path, Some(KEY)).await;
        assert_eq!(status, StatusCode::GONE, "{path}");
        for secret in keys.iter().map(String::as_str).chain(CANARIES) {
            assert!(!text.contains(secret), "{path}");
        }
    }
}

#[tokio::test]
async fn jsonl_emits_typed_primary_and_companion_facts_within_bounds() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease, _, url) = env.leased(&run, "jsonl").await;
    for ordinal in 1..=70 {
        env.put(&lease, &url, ordinal, wire(Some(ordinal), None, Some(ordinal)))
            .await;
    }
    let root = Env::root(&run);
    let lines = |text: &str| -> Vec<Value> {
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    };

    let (status, _, text) = env.get(&format!("{root}/history?format=jsonl"), Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let primary = lines(&text);
    assert_eq!(primary.len(), 65);
    assert!(primary[..64].iter().all(|line| line["rowType"] == "fact"));
    assert_eq!(primary[0]["fact"]["data"]["kind"], "wire");
    assert_eq!(primary[63]["sequence"], 64);
    let envelope = &primary[64];
    assert_eq!(envelope["report"], "history");
    assert_eq!(envelope["scanned"], 64);
    assert_eq!(envelope["next"], 64);
    assert!(envelope["rows"].as_array().unwrap().is_empty());
    assert_eq!(envelope["factsPage"]["facts"], 64);
    assert!(envelope["withheld"]
        .as_array()
        .unwrap()
        .contains(&json!("raw_url")));

    for index in 0..69 {
        let extra = testkit::canonical_url(&format!("https://report.example.test/extra/{index}"));
        env.store.discover(run.id, &extra, 1, None, None).await.unwrap();
    }
    let (_, _, text) = env.get(&format!("{root}/frontier?format=jsonl"), Some(KEY)).await;
    let legacy = lines(&text);
    assert_eq!(legacy.len(), 64 + 64 + 1);
    assert_eq!(
        legacy.iter().filter(|line| line["rowType"] == "frontier").count(),
        64
    );
    assert_eq!(
        legacy
            .iter()
            .filter(|line| line["rowType"] == "companion_fact")
            .count(),
        64
    );
    let envelope = legacy.last().unwrap();
    assert_eq!(envelope["scanned"], 64);
    assert!(envelope["next"].is_u64());
    assert_eq!(envelope["factNext"], 64);
    assert!(envelope["facts"].as_array().unwrap().is_empty());
    assert_eq!(envelope["factsPage"]["facts"], 64);
    for canary in CANARIES {
        assert!(!text.contains(canary), "{canary}");
    }
}

#[tokio::test]
async fn fact_filters_reject_unknown_unsupported_and_out_of_range_values() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let root = Env::root(&run);
    for (report, query) in [
        ("history", "kind=bogus"),
        ("history", "kind=ALERT"),
        ("history", "minDurationUs=-1"),
        ("history", "minWireBytes=9223372036854775808"),
        ("history", "maxWireBytes=18446744073709551616"),
        ("history", "minDurationUs=5&maxDurationUs=1"),
        ("history", "minWireBytes=2&maxWireBytes=1"),
        ("history", "since=2025-01-02T00:00:00Z&until=2025-01-01T00:00:00Z"),
        ("history", "since=1969-12-31T23:59:59Z"),
        ("history", "urlKey=not_a_digest"),
        ("history", "severity=error"),
        ("history", "script=execute"),
        ("history", "q=SELECT"),
        ("wire_history", "kind=wire"),
        ("wire_history", "minWireBytes=1&maxWireBytes=0"),
        ("alert_log", "minWireBytes=1"),
        ("alert_log", "minDurationUs=1"),
        ("alert_log", "kind=alert"),
        ("pipeline_history", "minDurationUs=1"),
        ("frontier", "factsAfter=-1"),
        ("frontier", "factsAfter=9223372036854775808"),
        ("frontier", "factKind=bogus"),
        ("frontier", "kind=wire"),
        ("frontier", "minWireBytes=1"),
        ("summary", "factsAfter=0"),
        ("seeds", "factKind=wire"),
        ("threads", "factsAfter=0"),
    ] {
        assert_eq!(
            env.get(&format!("{root}/{report}?{query}"), Some(KEY)).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{report}?{query}"
        );
    }
    for (report, query) in [
        ("history", "kind=alert&minWireBytes=1"),
        ("history", "since=2025-01-01T00:00:00Z&until=2025-01-01T00:00:00Z"),
        ("frontier", "factKind=pipeline&factsAfter=0"),
    ] {
        assert_eq!(
            env.get(&format!("{root}/{report}?{query}"), Some(KEY)).await.0,
            StatusCode::OK,
            "{report}?{query}"
        );
    }
}

#[tokio::test]
async fn source_page_limit_is_a_scan_cap_and_active_sources_expire() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    for index in 0..70 {
        let url = testkit::canonical_url(&format!("https://report.example.test/{index}"));
        env.store
            .discover(
                run.id,
                &url,
                1,
                None,
                Some((FrontierStatus::PolicyBlocked, "host_scope".into())),
            )
            .await
            .unwrap();
    }
    let root = format!("/v1/crawls/{}/reports/frontier", run.id);
    let (_, first, _) = env.get(&format!("{root}?limit=64"), Some(KEY)).await;
    assert_eq!(first["scanned"], 64);
    assert_eq!(first["rows"].as_array().unwrap().len(), 64);
    let cursor = first["next"].as_u64().unwrap();
    let (_, last, _) = env
        .get(&format!("{root}?after={cursor}&limit=64"), Some(KEY))
        .await;
    assert_eq!(last["scanned"], 6);
    assert_eq!(last["rows"].as_array().unwrap().len(), 6);
    assert!(last["next"].is_null());
    env.clock.advance_ms(86_400_001);
    assert_eq!(env.get(&root, Some(KEY)).await.0, StatusCode::GONE);
}

#[tokio::test]
async fn retry_failure_cancel_and_summary_remain_distinct_stored_facts() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let worker = WorkerId::new();
    env.store
        .register_worker(worker, "report-retry-fixture", "1")
        .await
        .unwrap();
    let url = testkit::canonical_url("https://report.example.test/failure");
    let (_, id) = env.store.discover(run.id, &url, 0, None, None).await.unwrap();
    let id = id.unwrap();
    let first = env
        .store
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(env
        .store
        .retry_fenced(id, first.1, env.clock.now())
        .await
        .unwrap());
    let second = env
        .store
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    env.store
        .commit_fenced(RequestCommitV1::terminal(
            run.id,
            id,
            second.1,
            1,
            FrontierStatus::Failed,
            Some("content_validation_failed".into()),
        ))
        .await
        .unwrap();
    let url = testkit::canonical_url("https://report.example.test/cancelled");
    let (_, cancelled) = env.store.discover(run.id, &url, 1, Some(id), None).await.unwrap();
    let cancelled = cancelled.unwrap();
    let lease = env
        .store
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    env.store
        .commit_fenced(RequestCommitV1::terminal(
            run.id,
            cancelled,
            lease.1,
            1,
            FrontierStatus::Abandoned,
            Some("cancelled".into()),
        ))
        .await
        .unwrap();
    let mut counters = run.counters;
    counters.urls.discovered = 2;
    counters.urls.admitted = 2;
    counters.urls.attempted = 2;
    counters.urls.failed = 1;
    counters.urls.abandoned = 1;
    env.store.update_counters(run.id, counters).await.unwrap();
    env.store
        .set_status(run.id, RunStatus::Cancelled, Some(TerminalReason::Cancelled))
        .await
        .unwrap();
    let root = format!("/v1/crawls/{}/reports", run.id);
    let (_, failures, _) = env.get(&format!("{root}/processor_failures"), Some(KEY)).await;
    assert_eq!(failures["rows"].as_array().unwrap().len(), 1);
    assert_eq!(failures["rows"][0]["attempts"], 2);
    assert_eq!(failures["rows"][0]["class"], "failed");
    assert!(failures["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("processor_identity")));
    let (_, skipped, _) = env.get(&format!("{root}/skipped_pages"), Some(KEY)).await;
    assert_eq!(skipped["rows"].as_array().unwrap().len(), 1);
    assert_eq!(skipped["rows"][0]["class"], "cancelled");
    let (_, summary, _) = env.get(&format!("{root}/summary"), Some(KEY)).await;
    assert_eq!(summary["rows"][0]["status"], "cancelled");
    assert_eq!(summary["rows"][0]["terminalReason"], "cancelled");
    assert_eq!(summary["rows"][0]["counters"]["urls"]["attempted"], 2);
    assert_eq!(summary["rows"][0]["counters"]["urls"]["failed"], 1);
    assert_eq!(summary["rows"][0]["counters"]["urls"]["abandoned"], 1);
    let (_, provenance, _) = env.get(&format!("{root}/provenance"), Some(KEY)).await;
    assert_eq!(provenance["rows"][0]["configDigest"], json!(run.config_digest));
    assert_eq!(provenance["rows"][0]["policyVersion"], run.policy_version);
}

#[test]
fn mime_groups_ignore_parameters_without_inventing_unknown_types() {
    assert_eq!(
        mime_facts(Some("Text/HTML; charset=utf-8")),
        mime_facts(Some("text/html"))
    );
    assert_eq!(mime_facts(None), (None, None));
    let (key, mime) = mime_facts(Some("application/private-canary; secret=another-canary"));
    assert!(key.is_some());
    assert!(mime.is_none());
}

#[tokio::test]
async fn report_host_keys_are_the_identity_producers_store_on_facts() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let (lease, _, url) = env.leased(&run, "a").await;
    let host = url.url.host_str().unwrap();
    assert_eq!(host_key(&url), Some(report_host_key(host)));
    // a fact stored by a producer with the shared identity answers the digest a row of the
    // `hosts` report shows
    let mut fact = ReportFactV1::new(
        &lease,
        Digest::of("crawlx/report-route-fixture", b"shared-host"),
        env.at(1),
        wire(Some(1), None, Some(1)),
    );
    fact.url_key = Some(url.key);
    fact.host_key = Some(report_host_key(host));
    env.store.append_fact(&lease, &fact).await.unwrap();
    let (_, hosts, _) = env.get(&format!("{}/hosts", Env::root(&run)), Some(KEY)).await;
    let shown = hosts["rows"][0]["hostKey"].as_str().unwrap().to_owned();
    assert_eq!(shown, report_host_key(host).to_hex());
    let (_, facts, _) = env
        .get(
            &format!("{}/wire_history?hostKey={shown}", Env::root(&run)),
            Some(KEY),
        )
        .await;
    assert_eq!(facts["rows"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn availability_separates_missing_instrumentation_from_intentional_redaction() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    let root = format!("/v1/crawls/{}/reports", run.id);
    let (_, inventory, _) = env.get(&root, Some(KEY)).await;
    let hosts = inventory["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|report| report["name"] == "hosts")
        .unwrap();
    assert!(hosts["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("dns_health_history")));
    assert!(hosts["withheld"]
        .as_array()
        .unwrap()
        .contains(&json!("hostnames")));
    assert!(!hosts["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("hostnames")));
    let top = inventory["notRecorded"].as_array().unwrap();
    assert!(top.contains(&json!("legacy_runs_without_report_facts")));
    for stale in ["cross_run_history", "wire_size_bytes", "response_duration_ms"] {
        assert!(!top.contains(&json!(stale)), "{stale}");
    }
    let instrumented = &inventory["instrumentedFacts"];
    assert_eq!(instrumented["crossRun"]["report"], "history");
    assert_eq!(instrumented["unavailable"], json!(["threads"]));
    assert_eq!(instrumented["pageScope"], "facts_page");
    assert_eq!(inventory["factCursors"]["companion"]["request"], "factsAfter");
    for class in ["dns", "stage", "wire", "alert", "loss", "pipeline"] {
        assert!(instrumented["kinds"].as_array().unwrap().contains(&json!(class)));
    }
    for primary in [
        "history",
        "wire_history",
        "processor_history",
        "pipeline_history",
        "host_dns_health",
        "alert_log",
    ] {
        assert!(instrumented["primaryReports"]
            .as_array()
            .unwrap()
            .contains(&json!(primary)));
        assert_eq!(report(&inventory, primary)["source"], "report_history");
        assert_eq!(report(&inventory, primary)["facts"]["role"], "primary");
    }
    let history = report(&inventory, "history");
    assert_eq!(history["facts"]["crossRun"], true);
    assert!(history["filters"]
        .as_array()
        .unwrap()
        .contains(&json!("crossRun")));
    let wire_history = report(&inventory, "wire_history");
    assert!(wire_history["filters"]
        .as_array()
        .unwrap()
        .contains(&json!("minWireBytes")));
    assert!(!wire_history["filters"]
        .as_array()
        .unwrap()
        .contains(&json!("crossRun")));
    let frontier = report(&inventory, "frontier");
    assert_eq!(frontier["facts"]["role"], "companion");
    assert_eq!(frontier["facts"]["cursor"], "factsAfter");
    assert_eq!(frontier["facts"]["next"], "factNext");
    assert!(frontier["filters"]
        .as_array()
        .unwrap()
        .contains(&json!("factsAfter")));
    let threads = report(&inventory, "threads");
    assert_eq!(threads["source"], "unavailable");
    assert!(threads["facts"].is_null());
    for kind in Kind::ALL {
        assert!(kind
            .not_recorded()
            .iter()
            .all(|fact| !kind.withheld().contains(fact)));
    }
    let (_, failures, _) = env.get(&format!("{root}/processor_failures"), Some(KEY)).await;
    assert!(failures["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("processor_identity")));
    assert!(failures["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("failure_stage")));
    assert!(failures["withheld"]
        .as_array()
        .unwrap()
        .contains(&json!("exception_text")));
    assert!(!failures["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("exception_text")));
}
