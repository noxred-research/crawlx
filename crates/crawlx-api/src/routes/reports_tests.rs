//! In-process authenticated report consumers over the real memory repositories.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::auth::{key_record, tenant_id_for};
use crate::{ApiConfig, ApiStore, MemoryApiStore, Repos};
use axum::http::Request;
use axum::Router;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::orchestration::{RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{EventRepo, FrontierRepo, PageRepo, RunRepo};
use crawlx_core::time::ManualClock;
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

#[tokio::test]
async fn unavailable_reports_never_fabricate_dns_threads_or_alerts() {
    let env = Env::new().await;
    let run = env.run(false, false).await;
    for kind in ["threads", "host_dns_health", "alert_log"] {
        let (_, result, _) = env
            .get(&format!("/v1/crawls/{}/reports/{kind}", run.id), Some(KEY))
            .await;
        assert_eq!(result["source"], "unavailable");
        assert_eq!(result["scanned"], 0);
        assert!(result["rows"].as_array().unwrap().is_empty());
        assert!(!result["notRecorded"].as_array().unwrap().is_empty());
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
    assert!(inventory["notRecorded"]
        .as_array()
        .unwrap()
        .contains(&json!("cross_run_history")));
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
