#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! SDK wire-contract test for the compat facade (level C0).
//!
//! The published MIT reference SDK crate (2.21.6) declares no cargo features and depends on
//! `reqwest` with its default features, which pull `openssl-sys`; `deny.toml` bans that
//! crate, so this test does not link the SDK. Instead the SDK's wire shapes are reproduced
//! here as *data*: the endpoint set, the idempotency header name, the `JobStatus`,
//! `SitemapMode` and `WebhookEvent` values and the camelCase response structs the SDK
//! deserializes into, taken from the SDK crate's declared types (facts re-verified on 2026-10-16). The facade's responses must
//! deserialize into these mirrors with no field missing; extra fields are ignored exactly as serde does in the SDK.
//!
//! When the SDK can build on rustls alone, the mirrors below are replaced by the crate's
//! types and this test becomes the SDK-in-the-loop suite.
mod common;

use axum::http::StatusCode;
use chrono::Utc;
use common::env;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{FrontierRepo, FrontierStatus, PageRecord, PageRepo, RunRepo, Sensitivity};
use crawlx_core::{CrawlRunId, TrustLane};
use crawlx_storage::testkit;
use serde::Deserialize;
use serde_json::{json, Value};

/// The SDK's idempotency header.
const IDEMPOTENCY_HEADER: &str = "x-idempotency-key";

/// Endpoints the SDK calls, relative to `api_url` (`api_url + "/v2" + path`).
const ENDPOINTS: [(&str, &str); 4] = [
    ("POST", "/v2/crawl"),
    ("GET", "/v2/crawl/{id}"),
    ("DELETE", "/v2/crawl/{id}"),
    ("GET", "/v2/crawl/{id}/errors"),
];

/// SDK `JobStatus`.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum JobStatus {
    Scraping,
    Completed,
    Failed,
    Cancelled,
}

/// SDK `SitemapMode` values accepted on `CrawlOptions.sitemap`.
const SITEMAP_MODES: [&str; 3] = ["skip", "include", "only"];

/// SDK `WebhookEvent` values accepted on `WebhookConfig.events`.
const WEBHOOK_EVENTS: [&str; 4] = ["completed", "failed", "page", "started"];

/// SDK `CrawlResponse`.
#[derive(Debug, Deserialize)]
struct CrawlResponse {
    success: bool,
    id: String,
    url: String,
}

/// SDK `DocumentMetadata` (the subset every document carries).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocumentMetadata {
    title: Option<String>,
    description: Option<String>,
    language: Option<String>,
    #[serde(rename = "sourceURL")]
    source_url: Option<String>,
    status_code: Option<u16>,
    error: Option<String>,
}

/// SDK `Document`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    markdown: Option<String>,
    html: Option<String>,
    raw_html: Option<String>,
    links: Option<Vec<String>>,
    screenshot: Option<String>,
    metadata: DocumentMetadata,
}

/// SDK `CrawlJob` (the `GET /v2/crawl/{id}` body).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CrawlJob {
    success: bool,
    status: JobStatus,
    total: u32,
    completed: u32,
    credits_used: i64,
    expires_at: Option<String>,
    next: Option<String>,
    data: Vec<Document>,
}

/// SDK `CancelCrawlResponse`.
#[derive(Debug, Deserialize)]
struct CancelCrawlResponse {
    success: bool,
    status: JobStatus,
}

/// SDK `CrawlError`.
#[derive(Debug, Deserialize)]
struct CrawlError {
    id: String,
    timestamp: Option<String>,
    url: String,
    code: String,
    error: String,
}

/// SDK `CrawlErrorsResponse`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CrawlErrorsResponse {
    errors: Vec<CrawlError>,
    robots_blocked: Vec<String>,
}

/// SDK error envelope on non-2xx: `{success: false, error}`.
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    success: bool,
    error: String,
}

const MOUNT: &str = "/compat";

fn de<T: for<'de> Deserialize<'de>>(v: &Value) -> T {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{e}: {v}"))
}

#[tokio::test]
async fn facade_endpoints_and_responses_match_the_sdk_shapes() {
    let e = env();
    // POST /v2/crawl with the SDK's idempotency header and option enums
    let body = json!({
        "url": "https://docs.example.test/",
        "limit": 10,
        "sitemap": "include",
        "webhook": {"url": "https://hooks.example.test/fc", "events": WEBHOOK_EVENTS},
        "scrapeOptions": {"formats": ["markdown", "links"]},
    });
    let h = [(IDEMPOTENCY_HEADER, "sdk-contract-1")];
    let (s, _, v) = e.post_with(&format!("{MOUNT}/v2/crawl"), &h, &body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let created: CrawlResponse = de(&v);
    assert!(created.success);
    assert!(created.url.ends_with(&format!("{MOUNT}/v2/crawl/{}", created.id)));
    let (_, h2, v2) = e.post_with(&format!("{MOUNT}/v2/crawl"), &h, &body).await;
    assert_eq!(h2["idempotent-replayed"], "true");
    assert_eq!(de::<CrawlResponse>(&v2).id, created.id);

    // GET /v2/crawl/{id}: a queued run is `scraping`, creditsUsed is the real credit sum (0 so far)
    let uri = format!("{MOUNT}/v2/crawl/{}", created.id);
    let (s, _, v) = e.get(&uri).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let job: CrawlJob = de(&v);
    assert!(job.success);
    assert_eq!(job.status, JobStatus::Scraping);
    assert_eq!(job.credits_used, 0);
    assert_eq!((job.total, job.completed), (0, 0));
    assert!(job.data.is_empty() && job.next.is_none());

    // documents deserialize into the SDK `Document`, `next` is an absolute URL back at the facade
    let run_id: CrawlRunId = created.id.parse().unwrap();
    e.store
        .set_status(run_id, RunStatus::Running, None)
        .await
        .unwrap();
    for n in 1..=3i64 {
        let md = e
            .artifacts
            .put_kind(
                run_id,
                Sensitivity::Content,
                "markdown",
                "text/markdown",
                format!("# {n}").as_bytes(),
            )
            .await
            .unwrap();
        e.store
            .put(&PageRecord {
                run: run_id,
                frontier_id: n,
                url: testkit::canonical_url(&format!("https://docs.example.test/{n}")),
                status: 200,
                content_type: Some("text/html".to_owned()),
                content_digest: Digest::of("t", &[u8::try_from(n).unwrap()]),
                title: Some(format!("T{n}")),
                markdown: Some(md),
                html: None,
                metadata: json!({"description": "d", "language": "en"}),
                links: vec![format!("https://docs.example.test/{}", n + 1)],
                fetched_at: Utc::now(),
                lane: TrustLane::Diagnostic,
            })
            .await
            .unwrap();
    }
    let (_, _, v) = e.get(&format!("{uri}?limit=2")).await;
    let job: CrawlJob = de(&v);
    assert_eq!(job.data.len(), 2);
    let d = &job.data[0];
    assert_eq!(d.markdown.as_deref(), Some("# 1"));
    assert_eq!(
        d.metadata.source_url.as_deref(),
        Some("https://docs.example.test/1")
    );
    assert_eq!(d.metadata.status_code, Some(200));
    assert_eq!(d.metadata.title.as_deref(), Some("T1"));
    assert_eq!(d.metadata.description.as_deref(), Some("d"));
    assert_eq!(d.metadata.language.as_deref(), Some("en"));
    assert!(d.metadata.error.is_none());
    assert_eq!(
        d.links.as_deref(),
        Some(&["https://docs.example.test/2".to_owned()][..])
    );
    assert!(d.html.is_none() && d.raw_html.is_none() && d.screenshot.is_none());
    // with a Host header (any real deployment) `next` is absolute and pinned to the API origin
    let (_, _, b) = e
        .send(
            axum::http::Method::GET,
            &format!("{uri}?limit=2"),
            Some(&e.key),
            &[("host", "api.example.test"), ("x-forwarded-proto", "https")],
            None,
        )
        .await;
    let next = de::<CrawlJob>(&common::json(&b)).next.expect("next page");
    assert!(
        next.starts_with(&format!(
            "https://api.example.test{MOUNT}/v2/crawl/{}",
            created.id
        )),
        "SDK follows `next` as an absolute URL: {next}"
    );
    let (_, _, v) = e.get(next.trim_start_matches("https://api.example.test")).await;
    let page2: CrawlJob = de(&v);
    assert_eq!(page2.data.len(), 1);
    assert!(page2.next.is_none());

    // GET /v2/crawl/{id}/errors
    e.store
        .discover(
            run_id,
            &testkit::canonical_url("https://docs.example.test/robots"),
            1,
            None,
            Some((FrontierStatus::RobotsBlocked, "robots".to_owned())),
        )
        .await
        .unwrap();
    e.store
        .discover(
            run_id,
            &testkit::canonical_url("https://docs.example.test/bad"),
            1,
            None,
            None,
        )
        .await
        .unwrap();
    let leased = e
        .store
        .lease_batch(run_id, crawlx_core::WorkerId::new(), 10)
        .await
        .unwrap();
    e.store
        .complete(leased[0].id, FrontierStatus::Failed, Some("http_500".to_owned()))
        .await
        .unwrap();
    let (s, _, v) = e.get(&format!("{uri}/errors")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let errors: CrawlErrorsResponse = de(&v);
    assert_eq!(errors.robots_blocked, vec!["https://docs.example.test/robots"]);
    assert_eq!(errors.errors.len(), 1);
    assert_eq!(errors.errors[0].url, "https://docs.example.test/bad");
    assert_eq!(errors.errors[0].code, "SCRAPE_SITE_ERROR");
    assert!(!errors.errors[0].id.is_empty() && !errors.errors[0].error.is_empty());
    assert!(errors.errors[0].timestamp.is_some());

    // DELETE /v2/crawl/{id}
    let (s, _, v) = e.delete(&uri).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let cancelled: CancelCrawlResponse = de(&v);
    assert!(cancelled.success);
    assert_eq!(cancelled.status, JobStatus::Cancelled);
    let (_, _, v) = e.get(&uri).await;
    assert_eq!(de::<CrawlJob>(&v).status, JobStatus::Cancelled);
    assert!(de::<CrawlJob>(&v).expires_at.is_some());

    // every endpoint the SDK uses exists under the mount (no 404/405 for a well-formed call)
    for (method, path) in ENDPOINTS {
        let p = path.replace("{id}", &created.id);
        let (s, _, _) = e
            .send(
                method.parse().unwrap(),
                &format!("{MOUNT}{p}"),
                Some(&e.key),
                &[],
                (method == "POST")
                    .then(|| json!({"url": "https://docs.example.test/"}))
                    .as_ref(),
            )
            .await;
        assert!(
            s != StatusCode::NOT_FOUND && s != StatusCode::METHOD_NOT_ALLOWED,
            "{method} {p} -> {s}"
        );
    }
}

#[tokio::test]
async fn every_facade_status_is_an_sdk_job_status() {
    let e = env();
    for (st, reason, want) in [
        (
            RunStatus::Completed,
            TerminalReason::FrontierExhausted,
            JobStatus::Completed,
        ),
        (
            RunStatus::Completed,
            TerminalReason::LimitReached,
            JobStatus::Completed,
        ),
        (RunStatus::Failed, TerminalReason::FatalError, JobStatus::Failed),
        (
            RunStatus::Cancelled,
            TerminalReason::Cancelled,
            JobStatus::Cancelled,
        ),
    ] {
        let (_, _, c) = e
            .post(
                &format!("{MOUNT}/v2/crawl"),
                &json!({"url": "https://docs.example.test/"}),
            )
            .await;
        let rid: CrawlRunId = de::<CrawlResponse>(&c).id.parse().unwrap();
        e.store.set_status(rid, st, Some(reason)).await.unwrap();
        let (_, _, v) = e.get(&format!("{MOUNT}/v2/crawl/{rid}")).await;
        assert_eq!(de::<CrawlJob>(&v).status, want, "{v}");
    }
    // non-terminal native statuses all map to `scraping`
    let (_, _, c) = e
        .post(
            &format!("{MOUNT}/v2/crawl"),
            &json!({"url": "https://docs.example.test/"}),
        )
        .await;
    let rid: CrawlRunId = de::<CrawlResponse>(&c).id.parse().unwrap();
    for st in [RunStatus::Queued, RunStatus::Running] {
        e.store.set_status(rid, st, None).await.unwrap();
        let (_, _, v) = e.get(&format!("{MOUNT}/v2/crawl/{rid}")).await;
        assert_eq!(de::<CrawlJob>(&v).status, JobStatus::Scraping, "{v}");
    }
}

#[tokio::test]
async fn sdk_option_enums_are_accepted_and_errors_use_the_sdk_envelope() {
    let e = env();
    for mode in SITEMAP_MODES {
        let (s, _, v) = e
            .post(
                &format!("{MOUNT}/v2/crawl"),
                &json!({"url": "https://docs.example.test/", "sitemap": mode}),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "sitemap {mode}: {v}");
        de::<CrawlResponse>(&v);
    }
    let (s, _, v) = e
        .post(
            &format!("{MOUNT}/v2/crawl"),
            &json!({"url": "https://docs.example.test/", "webhook": {"url": "https://hooks.example.test/", "events": WEBHOOK_EVENTS}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // the SDK surfaces `{success:false, error}` on non-2xx
    let (s, _, v) = e.post(&format!("{MOUNT}/v2/crawl"), &json!({"limit": 0})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let err: ErrorEnvelope = de(&v);
    assert!(!err.success && !err.error.is_empty());
    let (s, _, v) = e.get(&format!("{MOUNT}/v2/crawl/{}", CrawlRunId::new())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(!de::<ErrorEnvelope>(&v).success);
}
