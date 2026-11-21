//! The `robots-edge` family against the production planes: the origin's own request log is
//! compared with the request set RFC 9309 prescribes for each case.
//!
//! The static plane runs in every `cargo test`. The browser plane needs Chromium and is skipped,
//! with a note, unless `CRAWLX_CHROMIUM_PATH` names one (the same gate as the other
//! real-browser tests).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::robots_edge::{cases, Case, EdgeServer, SEED};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request_for_url, worker_config_with};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, SafetyProfile, SitemapMode};
use crawlx_storage::MemoryStore;
use crawlx_url::TrailingSlash;
use crawlx_worker::{run_local_with, LocalRun, RunReport, Stores};
use std::collections::BTreeSet;
use std::sync::Arc;

async fn crawl(case: &Case, mode: CrawlMode) -> (EdgeServer, RunReport) {
    let server = EdgeServer::start(case).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut request = crawl_request_for_url(
        url::Url::parse(&format!("{}/", server.base)).unwrap(),
        SEED,
        SafetyProfile::TestEnvironment,
    );
    request.mode = mode;
    request.politeness.delay_ms = 0;
    request.scope.sitemap = SitemapMode::Include;
    request.fetch.robots_user_agent = Some("crawlx".to_owned());
    if mode != CrawlMode::Static {
        request.limits.states = 12;
        request.limits.interactions = 12;
        request.limits.duration_seconds = 30;
    }
    let mut config = worker_config_with(TrailingSlash::Keep, dir.path()).unwrap();
    config.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(request, config).with_stores(stores),
    ))
    .await
    .unwrap();
    (server, report)
}

fn show(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(" ")
}

/// The table must agree with itself before it judges a crawler.
#[test]
fn the_expected_sets_are_consistent() {
    let all = cases();
    assert!(all.len() >= 10, "{} cases", all.len());
    let mut ids = BTreeSet::new();
    for case in &all {
        assert!(ids.insert(case.id), "duplicate case id {}", case.id);
        let clash: BTreeSet<_> = case.static_requests.intersection(&case.never).collect();
        assert!(clash.is_empty(), "{}: expects and forbids {clash:?}", case.id);
        let clash: BTreeSet<_> = case.browser_reaches.intersection(&case.never).collect();
        assert!(
            clash.is_empty(),
            "{}: browser expects and forbids {clash:?}",
            case.id
        );
        assert!(
            case.static_requests.contains("/robots.txt"),
            "{}: every crawl reads robots.txt first",
            case.id
        );
    }
}

#[tokio::test]
async fn the_static_plane_requests_exactly_what_rfc_9309_allows() {
    let mut failures = Vec::new();
    for case in cases() {
        let (server, report) = crawl(&case, CrawlMode::Static).await;
        let got = server.requested();
        if got != case.static_requests {
            failures.push(format!(
                "{} (RFC 9309 {}):\n  expected: {}\n  received: {}\n  log: {:?}",
                case.id,
                case.rfc,
                show(&case.static_requests),
                show(&got),
                server.log()
            ));
        }
        let forbidden: BTreeSet<_> = got.intersection(&case.never).collect();
        if !forbidden.is_empty() {
            failures.push(format!(
                "{}: forbidden paths were requested: {forbidden:?}",
                case.id
            ));
        }
        assert!(
            report.counters.urls.invariants_hold(),
            "{}: {:?}",
            case.id,
            report.counters.urls
        );
    }
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[tokio::test]
async fn a_crawl_that_ignores_robots_reaches_what_the_rules_close() {
    // The oracle must be able to fail: with robots off the closed paths are requested, so the
    // comparison above is not vacuous.
    let case = cases()
        .into_iter()
        .find(|case| case.id == "longest-match-allow-carves-out-a-disallow")
        .unwrap();
    let server = EdgeServer::start(&case).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut request = crawl_request_for_url(
        url::Url::parse(&format!("{}/", server.base)).unwrap(),
        SEED,
        SafetyProfile::TestEnvironment,
    );
    request.mode = CrawlMode::Static;
    request.politeness.delay_ms = 0;
    request.safety.respect_robots_txt = false;
    let config = worker_config_with(TrailingSlash::Keep, dir.path()).unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    run_local_with(authorize_fixture(
        LocalRun::new(request, config).with_stores(stores),
    ))
    .await
    .unwrap();
    assert!(server.requested().contains("/p/closed"), "{:?}", server.log());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_browser_plane_never_requests_a_closed_path() {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let mut failures = Vec::new();
    for case in cases() {
        let (server, _report) = crawl(&case, CrawlMode::Dynamic).await;
        let got = server.requested();
        let forbidden: BTreeSet<_> = got.intersection(&case.never).collect();
        if !forbidden.is_empty() {
            failures.push(format!(
                "{} (RFC 9309 {}): requested {forbidden:?}; log {:?}",
                case.id,
                case.rfc,
                server.log()
            ));
        }
        let missing: BTreeSet<_> = case.browser_reaches.difference(&got).collect();
        if !missing.is_empty() {
            failures.push(format!(
                "{}: never reached {missing:?}; log {:?}",
                case.id,
                server.log()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
