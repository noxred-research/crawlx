//! A page the browser plane cannot load is a failed state, not the end of the run.
//!
//! One refused redirect target, one network error page or one unreachable seed used to end the
//! whole session as `fatal_error`; the URL plane records the same situations per URL and goes
//! on. These tests drive the exploration driver over the scripted browser: the failed page is
//! counted in `states.failed` with its reason, the egress denial is never retried and keeps its
//! counter, the rest of the frontier is explored, and a run that loses every page still fails.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::EventRepo;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

const CHROME_ERROR: &str =
    "no observable document (chrome-error://chromewebdata/): unsupported scheme `chrome-error`";

fn link(page: FakePage, key: &str, name: &str, to: &str) -> FakePage {
    page.node(FakeAxSpec::link(key, name, to))
        .on_click(key, vec![FakeEffect::Navigate(to.to_owned())])
}

/// `/` links to `/first`, `/second` and `/ok`; `/ok` links back to `/`.
fn site(first: FakePage, second: Option<FakePage>) -> FakeScript {
    let mut home = FakePage::new("https://example.test/").title("Home");
    home = link(home, "lnk-first", "First", "/first");
    if second.is_some() {
        home = link(home, "lnk-second", "Second", "/second");
    }
    home = link(home, "lnk-ok", "Fine", "/ok");
    let ok = link(
        FakePage::new("https://example.test/ok").title("Fine"),
        "lnk-home",
        "Home",
        "/",
    );
    let mut script = FakeScript::new().page(home).page(first).page(ok);
    if let Some(second) = second {
        script = script.page(second);
    }
    script
}

fn crawl(mode_observe_only: bool) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    c.mode = CrawlMode::Dynamic;
    c.seed = Some(20_261_121);
    c.limits.interactions = 60;
    c.limits.states = 100;
    c.dynamic.observe_only = mode_observe_only;
    c
}

struct Run {
    report: RunReport,
    backend: Arc<FakeBackend>,
    store: Arc<MemoryStore>,
}

impl Run {
    fn paths(&self) -> BTreeSet<String> {
        self.report
            .states
            .iter()
            .map(|s| s.url.url.path().to_owned())
            .collect()
    }

    /// `(reason)` of every `state_failed` run event.
    async fn failed_reasons(&self) -> Vec<String> {
        EventRepo::list_after(self.store.as_ref(), self.report.run_id, 0, 5000)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "state_failed")
            .map(|e| e.payload["reason"].as_str().unwrap().to_owned())
            .collect()
    }
}

async fn run(script: FakeScript, crawl: CreateCrawl) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend.clone())
            .with_stores(stores),
    )
    .await
    .unwrap();
    Run {
        report,
        backend,
        store,
    }
}

/// Navigation 1 is refused by the egress policy (a redirect out of the authorization record),
/// navigation 2 loads: the run explores the rest, ends `frontier_exhausted` and counts one
/// failed state. The denial is not retried and keeps its policy counter.
#[tokio::test]
async fn an_egress_denied_navigation_fails_one_state_and_the_run_goes_on() {
    let script = site(FakePage::new("https://example.test/first").title("First"), None)
        .deny_egress("https://example.test/first");
    let run = run(script, crawl(false)).await;
    let report = &run.report;

    assert_eq!(
        report.terminal_reason,
        Some(TerminalReason::FrontierExhausted),
        "{report:?}"
    );
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.counters.states.failed, 1, "{:?}", report.counters.states);
    assert!(report.counters.states.invariants_hold());
    assert!(
        run.paths().contains("/ok"),
        "the next page is still explored: {:?}",
        run.paths()
    );
    assert!(!run.paths().contains("/first"), "the denied page is never loaded");
    assert_eq!(run.failed_reasons().await, ["egress_denied"]);
    // deny-first: refused once, never retried, and the denial is counted
    let refused: Vec<_> = run
        .backend
        .context_handles()
        .iter()
        .flat_map(|h| h.refused_navigations())
        .collect();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(
        report.counters.urls.policy_blocked, 1,
        "{:?}",
        report.counters.urls
    );
}

/// A link whose target loads as a network error page (nothing observable) fails that one state:
/// the session goes back to the page it came from, never takes the same link again and
/// explores the next one.
#[tokio::test]
async fn an_unobservable_error_page_fails_one_state_and_the_run_goes_on() {
    let script = site(
        FakePage::new("https://example.test/first")
            .title("First")
            .unobservable(CHROME_ERROR),
        None,
    );
    let run = run(script, crawl(false)).await;
    let report = &run.report;

    assert_eq!(
        report.terminal_reason,
        Some(TerminalReason::FrontierExhausted),
        "{report:?}"
    );
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.counters.states.failed, 1, "{:?}", report.counters.states);
    assert!(report.counters.states.invariants_hold());
    assert!(run.paths().contains("/ok"), "{:?}", run.paths());
    assert!(!run.paths().contains("/first"));
    assert_eq!(run.failed_reasons().await, ["navigation_failed"]);
}

/// Two broken pages in a row do not stop the walk either.
#[tokio::test]
async fn several_failed_pages_are_each_counted_and_the_walk_ends_normally() {
    let script = site(
        FakePage::new("https://example.test/first")
            .title("First")
            .unobservable(CHROME_ERROR),
        Some(FakePage::new("https://example.test/second").title("Second")),
    )
    .deny_egress("https://example.test/second");
    let run = run(script, crawl(false)).await;
    let report = &run.report;

    assert_eq!(
        report.terminal_reason,
        Some(TerminalReason::FrontierExhausted),
        "{report:?}"
    );
    assert_eq!(report.counters.states.failed, 2, "{:?}", report.counters.states);
    assert!(run.paths().contains("/ok"), "{:?}", run.paths());
    let mut reasons = run.failed_reasons().await;
    reasons.sort();
    assert_eq!(reasons, ["egress_denied", "navigation_failed"]);
}

/// The observe-only walk navigates itself: a refused or failing page is counted and skipped.
#[tokio::test]
async fn the_observe_only_walk_counts_a_failed_page_and_visits_the_rest() {
    let script = site(FakePage::new("https://example.test/first").title("First"), None)
        .deny_egress("https://example.test/first");
    let run = run(script, crawl(true)).await;
    let report = &run.report;

    assert_eq!(
        report.terminal_reason,
        Some(TerminalReason::FrontierExhausted),
        "{report:?}"
    );
    assert_eq!(report.counters.states.failed, 1, "{:?}", report.counters.states);
    assert!(run.paths().contains("/ok"), "{:?}", run.paths());
}

/// A seed the browser cannot load is the only page there is: the run does not abort mid-way,
/// but it loses every page, so it ends as a failure (non-zero exit of `crawlx crawl`).
#[tokio::test]
async fn a_run_that_loses_every_page_still_fails() {
    let script = FakeScript::new()
        .page(FakePage::new("https://example.test/").title("Home"))
        .deny_egress("https://example.test/");
    let run = run(script, crawl(false)).await;
    let report = &run.report;

    assert_eq!(report.counters.states.failed, 1, "{:?}", report.counters.states);
    assert_eq!(report.counters.states.succeeded, 0);
    assert!(report.states.is_empty());
    assert_eq!(report.terminal_reason, Some(TerminalReason::FatalError));
    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(run.failed_reasons().await, ["egress_denied"]);
}

/// The seed itself loads as an error page: also a failed state, also a failed run.
#[tokio::test]
async fn an_unobservable_seed_is_a_failed_state_and_a_failed_run() {
    let script = FakeScript::new().page(
        FakePage::new("https://example.test/")
            .title("Home")
            .unobservable(CHROME_ERROR),
    );
    let run = run(script, crawl(false)).await;
    let report = &run.report;

    assert_eq!(report.counters.states.failed, 1, "{:?}", report.counters.states);
    assert_eq!(report.terminal_reason, Some(TerminalReason::FatalError));
    assert_eq!(report.status, RunStatus::Failed);
}
