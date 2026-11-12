//! End-to-end recrawl completeness: a browser-rendered crawl visits one page five times. The
//! render measures the page's subresources on every visit, so a revisit of an unchanged page with
//! unchanged images reports `complete`, and the visit during which one image changed reports
//! `incomplete` with that image listed, in the scheduling decision and in the archive manifest.
//! Real Chromium runs only when `CRAWLX_CHROMIUM_PATH` is set.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::run_authorized_local_with;
use crawlx_core::archive::ArchiveConfigV1;
use crawlx_core::archive_catalog::{ArchiveExportState, ArchiveReadV1};
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::counters::RunStatus;
use crawlx_core::orchestration::{
    OrchestrationConfigV1, RecrawlCompletenessV1, RecrawlCoverageV1, RecrawlResourceStateV1,
    RECRAWL_COMPLETENESS_KEY, RECRAWL_RESOURCES_POINTER,
};
use crawlx_core::repo::FrontierStatus;
use crawlx_core::scrape::{FormatSpec, JobKind, ScrapeJob, ScrapeOptions};
use crawlx_core::{Clock, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const PAGE: &str = r#"<!doctype html><html><head><title>Recrawl fixture</title></head>
<body><main><h1>Recrawl fixture</h1><p>A document that never changes, with two images.</p>
<img src="/img/a.svg" width="8" height="8"><img src="/img/b.svg" width="8" height="8"></main></body></html>"#;

/// The visit during which `/img/b.svg` changes (the second request for the page), counted from 1.
const CHANGING_VISIT: usize = 2;
/// Visits of the page: the first and four revisits.
const VISITS: u32 = 5;

fn svg(tag: &str) -> String {
    format!(r#"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><title>{tag}</title></svg>"#)
}

/// What one revisit of the page was told about its subresources, and what the archive says.
struct Outcome {
    /// Completeness a scheduled revisit carries, by the generation of that revisit: what the
    /// visit before it established.
    carried: BTreeMap<u32, RecrawlCompletenessV1>,
    /// `(reason, path of the target)` of every recrawl omission of the archive manifest.
    omissions: Vec<(String, String)>,
    /// Paths and digests each visit recorded in its page metadata, by revisit generation.
    recorded: BTreeMap<u32, Vec<(String, bool)>>,
    page_requests: usize,
}

async fn run() -> Option<Outcome> {
    let executable = std::env::var_os("CRAWLX_CHROMIUM_PATH")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let page_requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&page_requests);
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let counter = Arc::clone(&counter);
        async move {
            let no_store = |content_type: &'static str, body: String| {
                (
                    [("content-type", content_type), ("cache-control", "no-store")],
                    body,
                )
            };
            match uri.path() {
                "/page" => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    no_store("text/html", PAGE.to_owned())
                }
                "/img/a.svg" => no_store("image/svg+xml", svg("a")),
                "/img/b.svg" => {
                    let changed = counter.load(Ordering::SeqCst) >= CHANGING_VISIT;
                    no_store("image/svg+xml", svg(if changed { "b-v2" } else { "b-v1" }))
                }
                _ => no_store("text/plain", "not found".to_owned()),
            }
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(format!("http://127.0.0.1:{port}/page").parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(26_111_202);
    crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.max_discovery_depth = 0;
    crawl.scope.disable_unique_filter = true;
    crawl.limits.duration_seconds = 240;
    // `waitFor` makes the scrape a browser render; the page cache must never answer a revisit
    let options = ScrapeOptions {
        formats: vec![FormatSpec::Markdown],
        wait_for_ms: 1,
        max_age_ms: 0,
        ..ScrapeOptions::default()
    };
    crawl.scrape = Some(ScrapeJob::new(JobKind::Crawl, options));
    // an orchestrated render runs under explicit native acquisition bounds: one browser navigation
    let mut acquisition = crawlx_core::acquisition::AcquisitionPolicyV1::default();
    acquisition.backend_ids = vec!["native_browser".into()];
    acquisition.max_attempts = 1;
    crawl.acquisition = Some(acquisition);
    let mut orchestration = OrchestrationConfigV1::default();
    orchestration.recrawl = Some(
        serde_json::from_value(serde_json::json!({
            "version": 1, "minIntervalMs": 50, "maxIntervalMs": 50, "maxVisits": VISITS,
            "endAt": SystemClock.now() + chrono::Duration::minutes(10),
        }))
        .unwrap(),
    );
    crawl.orchestration = Some(orchestration);
    crawl.output.archive = Some(ArchiveConfigV1::default());
    let mut config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            extra_allow: vec!["127.0.0.1/32".parse().unwrap()],
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    config.launch.executable = executable.into();
    config.launch.allow_unpinned = true;
    let report = run_authorized_local_with(LocalRun::new(crawl, config).with_stores(stores.clone()))
        .await
        .unwrap();
    server.abort();
    if report.status != RunStatus::Completed {
        for event in stores.events.list_after(report.run_id, 0, 1000).await.unwrap() {
            eprintln!("{} {}", event.kind, event.payload);
        }
    }
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?} {:?} {:?}",
        report.terminal_reason,
        report.terminal_detail,
        report.counters
    );

    let mut carried = BTreeMap::new();
    let mut after = 0;
    let mut generations = BTreeMap::new();
    loop {
        let rows = stores.frontier.page(report.run_id, after, 100).await.unwrap();
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = row.id;
            assert_eq!(row.status, FrontierStatus::Succeeded, "{}", row.url.url);
            let request = stores.frontier.get_request(report.run_id, row.id).await.unwrap();
            let generation = request.identity.revisit_generation;
            generations.insert(row.id, generation);
            if let Some(value) = request.envelope.metadata.get(RECRAWL_COMPLETENESS_KEY) {
                carried.insert(generation, serde_json::from_value(value.clone()).unwrap());
            }
        }
    }
    let mut recorded = BTreeMap::new();
    let mut committed = Vec::new();
    let mut after = 0;
    loop {
        let batch = stores
            .pages
            .committed_page_keyset(report.run_id, after, 8)
            .await
            .unwrap();
        let Some(last) = batch.last() else {
            break;
        };
        after = last.frontier_id;
        committed.extend(batch);
    }
    for page in committed {
        let resources = page
            .metadata
            .pointer(RECRAWL_RESOURCES_POINTER)
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        recorded.insert(
            generations[&page.frontier_id],
            resources
                .iter()
                .map(|resource| {
                    let target = url::Url::parse(resource["target"].as_str().unwrap()).unwrap();
                    (target.path().to_owned(), resource["digest"].is_string())
                })
                .collect(),
        );
    }

    let run = stores.runs.get(report.run_id).await.unwrap();
    let ArchiveReadV1::Available(export) = stores
        .archives
        .get(run.tenant, run.id.0, SystemClock.now())
        .await
        .unwrap()
    else {
        panic!("the archive was not published");
    };
    assert_eq!(export.state, ArchiveExportState::Published);
    let mut omissions: Vec<(String, String)> = export
        .manifest
        .unwrap()
        .omissions
        .into_iter()
        .filter(|omission| omission.reason.starts_with("recrawl_"))
        .map(|omission| {
            let path = omission
                .target
                .map(|target| url::Url::parse(&target).unwrap().path().to_owned())
                .unwrap_or_default();
            (omission.reason, path)
        })
        .collect();
    omissions.sort();
    Some(Outcome {
        carried,
        omissions,
        recorded,
        page_requests: page_requests.load(Ordering::SeqCst),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revisit_is_complete_only_while_every_measured_subresource_is_unchanged() {
    let Some(outcome) = run().await else {
        return;
    };
    assert_eq!(
        outcome.page_requests, VISITS as usize,
        "one page request per visit"
    );

    // every visit measured both images, each with a digest
    let measured = vec![("/img/a.svg".to_owned(), true), ("/img/b.svg".to_owned(), true)];
    for generation in 0..VISITS {
        let mut recorded = outcome.recorded[&generation].clone();
        recorded.sort();
        assert_eq!(recorded, measured, "visit {generation}");
    }

    // the first visit has no baseline: everything it measured is new
    let first = &outcome.carried[&1];
    assert_eq!(first.coverage, RecrawlCoverageV1::Incomplete);
    assert!(first
        .resources
        .iter()
        .all(|fact| fact.state == RecrawlResourceStateV1::Added));

    // the second visit saw `/img/b.svg` change while the document stayed the same
    let changed = &outcome.carried[&2];
    assert_eq!(changed.coverage, RecrawlCoverageV1::Incomplete);
    assert_eq!(changed.resources.len(), 1, "{changed:?}");
    assert_eq!(changed.resources[0].state, RecrawlResourceStateV1::Changed);
    assert!(changed.resources[0].target.ends_with("/img/b.svg"));
    assert!(!changed.truncated);

    // the third and the fourth saw an unchanged page and unchanged images: complete
    for generation in [3, 4] {
        let complete = &outcome.carried[&generation];
        assert_eq!(
            complete.coverage,
            RecrawlCoverageV1::Complete,
            "revisit {generation}"
        );
        assert!(
            complete.resources.is_empty() && !complete.truncated,
            "revisit {generation}"
        );
    }

    // the archive lists the changed image of the second visit, and nothing for a complete revisit
    assert_eq!(
        outcome.omissions,
        [("recrawl_resource_changed".to_owned(), "/img/b.svg".to_owned())]
    );
}
