//! Browser-plane flags through the worker, over `FakeBackend` + `MemoryStore`:
//! `dynamic.maxFailureCount`, `enableDiagnostics`, `interactionSelector` / `interactionExclude`,
//! `interactionDepth`, `interactionSettleMs`, `interactionDurationSeconds`, `timeStableMs`,
//! `maxScrollSteps`, `blockConsentBanners` and `extract.xhr`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use crawlx_browser::fake::{FakeAxSpec, FakeContextHandle, FakePage, FakeScript};
use crawlx_browser::{consent, FakeBackend};
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::TerminalReason;
use crawlx_core::hash::Digest;
use crawlx_core::repo::PageRecord;
use crawlx_core::{CreateCrawl, SafetyProfile, SystemClock, TrustLane};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::diagnostics::SessionDiagnostics;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig, XhrSink};
use std::sync::Arc;
use std::time::Duration;

const HOME: &str = "https://example.test/";

fn cfg(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn crawl(mutate: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(HOME).unwrap());
    c.mode = CrawlMode::Dynamic;
    c.seed = Some(20_261_027);
    c.safety.profile = SafetyProfile::TestEnvironment;
    c.limits.interactions = 60;
    c.limits.states = 100;
    mutate(&mut c);
    c
}

struct Outcome {
    diagnostics: Vec<SessionDiagnostics>,
    handle: FakeContextHandle,
}

impl Outcome {
    /// The distinct controls clicked, sorted (a control may be exercised more than once, e.g.
    /// once per state cluster).
    fn clicked(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .handle
            .performed_keys()
            .into_iter()
            .filter_map(|k| k.strip_prefix("click:").map(str::to_owned))
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }
}

async fn run_with(script: FakeScript, crawl: CreateCrawl, hold: Option<Duration>) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::new(script));
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let local = LocalRun::new(crawl, cfg(dir.path()))
        .with_backend(backend.clone())
        .with_stores(stores);
    let report = match hold {
        None => run_local_with(local).await.unwrap(),
        Some(wait) => {
            backend.hold_performs();
            let task = tokio::spawn(run_local_with(local));
            tokio::time::sleep(wait).await;
            backend.release_performs();
            task.await.unwrap().unwrap()
        }
    };
    let handle = backend.context_handles().remove(0);
    Outcome {
        diagnostics: report.diagnostics,
        handle,
    }
}

async fn run(script: FakeScript, crawl: CreateCrawl) -> Outcome {
    run_with(script, crawl, None).await
}

fn buttons(page: FakePage, names: &[(&str, &str)]) -> FakePage {
    names.iter().fold(page, |p, (key, name)| {
        p.node(FakeAxSpec::button(*key, *name).attr("class", "go"))
    })
}

#[tokio::test]
async fn max_failure_count_ends_the_session_after_that_many_consecutive_drops() {
    let script = || {
        let page = buttons(
            FakePage::new(HOME),
            &[("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")],
        );
        FakeScript::new().page(page).stale("a").stale("b").stale("c")
    };
    let limited = run(
        script(),
        crawl(|c| {
            c.dynamic.max_failure_count = 3;
            c.dynamic.enable_diagnostics = true;
        }),
    )
    .await;
    let d = &limited.diagnostics[0];
    assert_eq!((d.drops, d.steps, d.actions), (3, 3, 0), "{d:?}");
    assert_eq!(d.stop_reason, TerminalReason::FrontierExhausted.as_str());

    // 0 keeps the driver default of 30 consecutive drops
    let default = run(script(), crawl(|c| c.dynamic.enable_diagnostics = true)).await;
    assert_eq!(default.diagnostics[0].drops, 30, "{:?}", default.diagnostics[0]);
}

#[tokio::test]
async fn diagnostics_are_recorded_per_session_only_when_enabled() {
    let script = || FakeScript::new().page(buttons(FakePage::new(HOME), &[("a", "Alpha"), ("b", "Beta")]));
    let off = run(script(), crawl(|_| {})).await;
    assert!(off.diagnostics.is_empty());

    let on = run(script(), crawl(|c| c.dynamic.enable_diagnostics = true)).await;
    assert_eq!(on.diagnostics.len(), 1);
    let d = &on.diagnostics[0];
    assert!(d.steps >= 2, "{d:?}");
    assert_eq!(
        d.steps,
        d.actions + d.drops,
        "every step ran or was dropped: {d:?}"
    );
    assert_eq!((d.drops, d.recoveries, d.tab_evictions), (0, 0, 0), "{d:?}");
    assert!(d.states >= 1, "{d:?}");
    assert_eq!(d.stop_reason, "frontier_exhausted");
    assert_eq!(d.run_index, 1);
    assert!(!d.role.is_empty());
}

#[tokio::test]
async fn interaction_selector_and_exclude_restrict_the_clicked_candidates() {
    let script = || {
        let page = FakePage::new(HOME)
            .node(FakeAxSpec::button("ba", "Alpha").attr("class", "go"))
            .node(FakeAxSpec::button("bb", "Beta").attr("class", "go"))
            .node(FakeAxSpec::button("bc", "Gamma"));
        FakeScript::new().page(page)
    };
    let all = run(script(), crawl(|_| {})).await;
    let mut every = all.clicked();
    every.sort();
    assert_eq!(every, ["ba", "bb", "bc"]);
    assert!(
        all.handle.css_filters().is_empty(),
        "no filter configured, nothing evaluated"
    );

    let only = run(
        script(),
        crawl(|c| c.dynamic.interaction_selector = vec![".go".to_owned()]),
    )
    .await;
    let mut clicked = only.clicked();
    clicked.sort();
    assert_eq!(
        clicked,
        ["ba", "bb"],
        "only elements matching the selector are candidates"
    );
    assert!(only
        .handle
        .css_filters()
        .iter()
        .all(|f| f.include == [".go"] && f.exclude.is_empty()));

    let both = run(
        script(),
        crawl(|c| {
            c.dynamic.interaction_selector = vec![".go".to_owned()];
            c.dynamic.interaction_exclude = vec!["#bb".to_owned()];
        }),
    )
    .await;
    assert_eq!(both.clicked(), ["ba"], "excluded elements are never candidates");

    let none = run(
        script(),
        crawl(|c| c.dynamic.interaction_exclude = vec!["[class=go]".to_owned()]),
    )
    .await;
    assert_eq!(none.clicked(), ["bc"]);
}

#[tokio::test]
async fn interaction_depth_returns_to_the_page_url_after_that_many_interactions() {
    let script = || {
        FakeScript::new().page(buttons(
            FakePage::new(HOME),
            &[("a", "Alpha"), ("b", "Beta"), ("c", "Gamma")],
        ))
    };
    let free = run(script(), crawl(|_| {})).await;
    assert_eq!(
        free.handle.navigations(),
        [HOME],
        "unlimited depth never leaves the state"
    );

    let limited = run(script(), crawl(|c| c.dynamic.interaction_depth = 1)).await;
    assert_eq!(limited.clicked(), ["a", "b", "c"]);
    let navigations = limited.handle.navigations();
    assert_eq!(
        navigations.len(),
        1 + limited.handle.performed().len(),
        "the seed plus one return to the page URL after every interaction: {navigations:?}"
    );
    assert!(navigations.iter().all(|u| u == HOME));
}

#[tokio::test]
async fn interaction_settle_and_time_stable_shape_the_settle_policies() {
    let script = || FakeScript::new().page(buttons(FakePage::new(HOME), &[("a", "Alpha")]));
    let plain = run(script(), crawl(|_| {})).await;
    assert!(plain
        .handle
        .settle_policies()
        .iter()
        .all(|p| p.fixed_wait_ms == 0));

    let tuned = run(
        script(),
        crawl(|c| {
            c.dynamic.interaction_settle_ms = 250;
            c.dynamic.time_stable_ms = 700;
        }),
    )
    .await;
    let policies = tuned.handle.settle_policies();
    assert!(
        policies.iter().any(|p| p.fixed_wait_ms == 250),
        "the action settles after an unconditional 250 ms: {policies:?}"
    );
    assert!(
        policies
            .iter()
            .all(|p| p.network_idle_window_ms >= 700 && p.mutation_idle_window_ms >= 700),
        "every settle requires 700 ms of quiet: {policies:?}"
    );
}

#[tokio::test]
async fn interaction_duration_stops_exploring_after_the_budget() {
    let script = || {
        FakeScript::new().page(buttons(
            FakePage::new(HOME),
            &[
                ("a", "Alpha"),
                ("b", "Beta"),
                ("c", "Gamma"),
                ("d", "Delta"),
                ("e", "Epsilon"),
            ],
        ))
    };
    let free = run(script(), crawl(|c| c.dynamic.enable_diagnostics = true)).await;
    assert!(free.diagnostics[0].actions > 1, "{:?}", free.diagnostics[0]);

    // the first action is held for longer than the one-second budget
    let limited = run_with(
        script(),
        crawl(|c| {
            c.dynamic.interaction_duration_seconds = 1;
            c.dynamic.enable_diagnostics = true;
        }),
        Some(Duration::from_millis(1_400)),
    )
    .await;
    let d = &limited.diagnostics[0];
    assert_eq!(d.actions, 1, "{d:?}");
    assert_eq!(d.stop_reason, TerminalReason::LimitReached.as_str());
}

#[tokio::test]
async fn max_scroll_steps_reveals_lazy_content_before_the_page_is_observed() {
    let script = || {
        let page = FakePage::new(HOME)
            .node(FakeAxSpec::link("home", "Home", "/"))
            .lazy_step([FakeAxSpec::link("late1", "Late one", "/late1")])
            .lazy_step([FakeAxSpec::link("late2", "Late two", "/late2")]);
        FakeScript::new()
            .page(page)
            .page(FakePage::new("https://example.test/late1"))
            .page(FakePage::new("https://example.test/late2"))
    };
    let off = run(script(), crawl(|_| {})).await;
    assert!(off.handle.lazy_scrolls().is_empty());
    assert_eq!(off.clicked(), ["home"], "0 steps: the lazy links never exist");

    let one = run(script(), crawl(|c| c.dynamic.max_scroll_steps = 1)).await;
    let mut clicked = one.clicked();
    clicked.sort();
    assert_eq!(clicked, ["home", "late1"], "1 step reveals the first batch only");
    assert_eq!(one.handle.lazy_scrolls()[0].max_steps, 1);

    let many = run(
        script(),
        crawl(|c| {
            c.dynamic.max_scroll_steps = 5;
            c.dynamic.enable_diagnostics = true;
        }),
    )
    .await;
    let mut clicked = many.clicked();
    clicked.sort();
    assert_eq!(clicked, ["home", "late1", "late2"]);
    assert!(many.diagnostics[0].scroll_steps >= 2, "{:?}", many.diagnostics[0]);
    assert_eq!(many.handle.lazy_scrolls()[0].max_steps, 5);
}

#[tokio::test]
async fn block_consent_banners_hands_the_bundled_list_to_the_browser() {
    let script = || FakeScript::new().page(FakePage::new(HOME).node(FakeAxSpec::button("a", "Alpha")));
    let on = run(script(), crawl(|c| c.dynamic.block_consent_banners = true)).await;
    assert_eq!(on.handle.blocked_url_patterns(), consent::patterns());
    assert!(!on.handle.blocked_url_patterns().is_empty());

    let off = run(script(), crawl(|_| {})).await;
    assert!(off.handle.blocked_url_patterns().is_empty());
}

#[tokio::test]
async fn xhr_requests_reach_the_actor_and_merge_into_page_metadata() {
    // browser -> actor: the requests a page issued come out of the session handle, per page
    let script = FakeScript::new().page(
        FakePage::new(common::SEED)
            .xhr("POST", "https://example.test/api/save", 201)
            .xhr("GET", "https://example.test/api/list", 200),
    );
    let rig = common::rig(script, SafetyProfile::TestEnvironment).await;
    let records = rig.handle.drain_xhr().await.unwrap();
    assert_eq!(records.len(), 2, "{records:?}");
    assert!(records.iter().all(|r| r.page_url == common::SEED));
    assert!(rig.handle.drain_xhr().await.unwrap().is_empty());

    // sink -> page record: `metadata.xhr_requests` of the page that issued them
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let canon = crawlx_url::CanonicalizeOptions::default();
    let page = PageRecord {
        run: rig.run,
        frontier_id: 0,
        url: common::canonical(common::SEED),
        status: 200,
        content_type: None,
        content_digest: Digest::of("test", b"page"),
        title: None,
        markdown: None,
        html: None,
        metadata: serde_json::json!({ "title": "Home" }),
        links: Vec::new(),
        fetched_at: crawlx_core::Clock::now(&SystemClock),
        lane: TrustLane::Diagnostic,
    };
    let other = PageRecord {
        url: common::canonical("https://example.test/other"),
        ..page.clone()
    };
    stores.pages.put(&page).await.unwrap();
    stores.pages.put(&other).await.unwrap();
    let sink = XhrSink::default();
    sink.record(records, &canon);
    assert_eq!(sink.apply(stores.pages.as_ref(), rig.run).await.unwrap(), 1);
    assert_eq!(
        sink.apply(stores.pages.as_ref(), rig.run).await.unwrap(),
        0,
        "idempotent"
    );
    let stored = stores.pages.list(rig.run).await.unwrap();
    let home = stored.iter().find(|p| p.url.url.path() == "/").unwrap();
    assert_eq!(home.metadata["title"], "Home", "existing metadata stays");
    assert_eq!(
        home.metadata["xhr_requests"],
        serde_json::json!([
            {"method":"GET","url":"https://example.test/api/list","resource_type":"xhr","endpoint_class":"rest","status":200},
            {"method":"POST","url":"https://example.test/api/save","resource_type":"xhr","endpoint_class":"rest","status":201},
        ])
    );
    let untouched = stored.iter().find(|p| p.url.url.path() == "/other").unwrap();
    assert!(untouched.metadata.get("xhr_requests").is_none());
}

/// A collector that keeps every posted batch (katana `KATANA_TRAFFIC_ENDPOINT` stand-in).
async fn collector() -> (url::Url, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
    let batches: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
    let sink = Arc::clone(&batches);
    let app = axum::Router::new().route(
        "/ingest",
        axum::routing::post(move |body: String| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(serde_json::from_str(&body).unwrap());
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = url::Url::parse(&format!("http://{}/ingest", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, batches)
}

#[tokio::test]
async fn browser_plane_exchanges_are_exported_with_the_browser_plane_tag() {
    let (endpoint, batches) = collector().await;
    let dir = tempfile::tempdir().unwrap();
    let mut worker = cfg(dir.path());
    let mut export = crawlx_worker::katana::traffic_export::TrafficExportConfig::new(endpoint);
    export.flush_interval = Duration::from_secs(3600); // only the end-of-run flush delivers
    export.retry_delays = Vec::new();
    worker.traffic_export = Some(export);

    let backend = Arc::new(FakeBackend::new(
        FakeScript::new().page(buttons(FakePage::new(HOME), &[("a", "Alpha")])),
    ));
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    run_local_with(
        LocalRun::new(crawl(|_| {}), worker)
            .with_backend(backend)
            .with_stores(stores),
    )
    .await
    .unwrap();

    let events: Vec<serde_json::Value> = batches
        .lock()
        .unwrap()
        .iter()
        .flat_map(|b| b["events"].as_array().cloned().unwrap_or_default())
        .collect();
    assert!(
        !events.is_empty(),
        "the browser's page load reached the collector"
    );
    assert!(events.iter().all(|e| e["plane"] == "browser"), "{events:?}");
    let home = events
        .iter()
        .find(|e| e["request"]["full_url"] == HOME)
        .unwrap_or_else(|| panic!("no exchange for {HOME}: {events:?}"));
    assert_eq!(home["response"]["status"], 200);
    assert_eq!(home["request"]["method"], "GET");
}
