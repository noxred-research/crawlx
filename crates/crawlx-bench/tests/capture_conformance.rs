//! Capture conformance: the same gym fixtures
//! crawled by the worker through the CDP backend and through the proxy backend
//! (`capture.backend = "proxy"`), asserting the rows of the capture contract that do not
//! need a specific protocol origin: raw stream order, lane exclusion of non-page origins,
//! `late` attribution to the previous action's epoch and the proxy's `protocols_disabled`.
//! Skipped without a Chromium executable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CaptureBackend, CrawlMode, SafetyProfile};
use crawlx_core::ids::{ActionId, NetworkEpochId};
use crawlx_core::traffic::{Protocol, TrafficEvent, TrafficOrigin, TrustLane, UnattributedReason};
use crawlx_core::ActionProposal;
use crawlx_storage::MemoryStore;
use crawlx_strategies::{DecisionContext, Strategy, StrategyError};
use crawlx_worker::{build_strategies, run_local_with, DriverConfig, LocalRun, RunReport, Stores};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Idle time between actions for the `late` fixture: longer than the fixture's 2 s timer,
/// so timer- and push-driven requests start after the previous epoch settled and before
/// the next action's intent (the definition of `late`). The strategy is a test
/// pacer only: production strategies never sleep or read the clock.
const ACTION_GAP: Duration = Duration::from_millis(2_600);

/// A strategy that proposes nothing and takes [`ACTION_GAP`] to say so.
struct Pacer;

#[async_trait]
impl Strategy for Pacer {
    async fn propose(&self, _: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        tokio::time::sleep(ACTION_GAP).await;
        Ok(Vec::new())
    }
    fn name(&self) -> &'static str {
        "test_pacer"
    }
    fn version(&self) -> u32 {
        1
    }
}

/// Chromium instances running at once (see `tests/browser.rs`).
static BROWSER_SLOTS: Semaphore = Semaphore::const_new(2);

async fn browser_slot() -> SemaphorePermit<'static> {
    BROWSER_SLOTS
        .acquire()
        .await
        .expect("the semaphore is never closed")
}

fn have_chromium() -> bool {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return false;
    }
    true
}

async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

/// What one worker crawl left behind.
struct Crawled {
    report: RunReport,
    /// `(action, event)` in journal order.
    traffic: Vec<(ActionId, TrafficEvent)>,
    /// Lane per epoch from the `network_epochs` mirror.
    epoch_lane: BTreeMap<NetworkEpochId, TrustLane>,
    /// Receipt epoch per action, in action order (the previous action's epoch is the one
    /// before an action's own in this list).
    action_epochs: Vec<(ActionId, NetworkEpochId)>,
}

async fn crawl(fixture: &str, backend: CaptureBackend, interactions: u32, seed: u64, paced: bool) -> Crawled {
    let gym = gym().await;
    let manifest = FixtureManifest::embedded(fixture).unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, seed, SafetyProfile::TestEnvironment).unwrap();
    req.mode = CrawlMode::Dynamic;
    req.limits.interactions = interactions;
    if paced {
        req.limits.duration_seconds = 90;
    }
    req.capture.backend = backend;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    if fixture == "g28" {
        // The tracker is a distinct origin, but still the same controlled gym listener.
        cfg.egress.resolver = Some(Arc::new(
            crawlx_fetch::StaticResolver::new().with("localhost", [std::net::Ipv4Addr::LOCALHOST.into()]),
        ));
    }
    let memory = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(Arc::clone(&memory), dir.path())
        .await
        .unwrap();
    let mut local = LocalRun::new(req.clone(), cfg).with_stores(stores);
    if paced {
        let mut strategies = build_strategies(&req.dynamic).unwrap();
        strategies.push(Arc::new(Pacer));
        let mut driver = DriverConfig::default();
        driver.deadlines.deterministic = ACTION_GAP + Duration::from_secs(1);
        local = local.with_strategies(strategies).with_driver(driver);
    }
    let mut local = authorize_fixture(local);
    if fixture == "g28" {
        let mut tracker = req.seed_url.clone();
        tracker.set_host(Some("localhost")).unwrap();
        local
            .authorization
            .as_mut()
            .expect("the fixture has a verified authorization record")
            .origins
            .push(tracker.origin().ascii_serialization());
    }
    let report = run_local_with(local).await.unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    let traffic = memory.traffic_of_run(report.run_id);
    let epochs = memory.network_epochs(report.run_id);
    let epoch_lane = epochs.iter().map(|e| (e.id, e.lane)).collect();
    let by_action: BTreeMap<ActionId, NetworkEpochId> = epochs.iter().map(|e| (e.action, e.id)).collect();
    let action_epochs = report
        .actions
        .iter()
        .filter_map(|a| by_action.get(&a.id).map(|e| (a.id, *e)))
        .collect();
    gym.shutdown().await;
    Crawled {
        report,
        traffic,
        epoch_lane,
        action_epochs,
    }
}

/// Raw-stream invariant: per action the events are in `seq` order and no
/// `seq` repeats; nothing is deduplicated (repeated polls stay distinct events).
fn assert_raw_stream(c: &Crawled) {
    let mut per_action: BTreeMap<ActionId, Vec<u64>> = BTreeMap::new();
    for (a, ev) in &c.traffic {
        per_action.entry(*a).or_default().push(ev.seq);
    }
    for (a, seqs) in &per_action {
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            &sorted, seqs,
            "action {a}: traffic not in capture order or duplicated"
        );
    }
    for (_, ev) in &c.traffic {
        // an event without an epoch names the reason, an attributed one does not
        assert_eq!(ev.epoch_id.is_none(), ev.unattributed_reason.is_some(), "{ev:?}");
    }
}

/// Lane test: service-worker and fetch-plane traffic never sits on
/// a `trusted_ui` epoch; events without an epoch are never trusted by construction.
fn assert_non_page_origins_are_not_trusted(c: &Crawled) {
    assert!(
        c.traffic.iter().any(|(_, event)| {
            event.origin == TrafficOrigin::Page
                && event.status == Some(200)
                && (event.url.ends_with("/g28/api/balance") || event.url.ends_with("/g28/api/notes"))
                && event.epoch_id.and_then(|id| c.epoch_lane.get(&id)) == Some(&TrustLane::TrustedUi)
        }),
        "no trusted page operation to contrast with background traffic"
    );
    for (_, ev) in &c.traffic {
        if matches!(
            ev.origin,
            TrafficOrigin::ServiceWorker | TrafficOrigin::FetchPlane
        ) {
            let lane = ev.epoch_id.and_then(|e| c.epoch_lane.get(&e));
            assert_ne!(lane, Some(&TrustLane::TrustedUi), "{ev:?}");
        }
    }
}

fn capture_source(event: &TrafficEvent) -> Option<&str> {
    event
        .response_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-crawlx-capture-source"))
        .map(|(_, value)| value.as_str())
}

fn assert_fixture_origins_observed(c: &Crawled) {
    for path in ["/g28/api/sw/activate", "/g28/api/sw/sync"] {
        assert!(
            c.traffic.iter().any(|(_, event)| {
                event.origin == TrafficOrigin::ServiceWorker
                    && event.url.ends_with(path)
                    && event.status == Some(200)
                    && event.epoch_id.is_none()
                    && event.unattributed_reason == Some(UnattributedReason::NotApplicable)
            }),
            "no completed epochless service-worker request for {path}: {:?}",
            c.traffic
        );
    }
    assert!(
        c.traffic.iter().any(|(_, event)| {
            event.origin == TrafficOrigin::Page
                && event.url.contains("/g28/tracker.js")
                && event.third_party
                && event.status == Some(200)
        }),
        "no completed third-party page request: {:?}",
        c.traffic
    );
}

/// Compare operations, not capture records: duplicates and opaque tunnels stay raw.
fn derived_operations(c: &Crawled) -> BTreeSet<(String, String)> {
    c.traffic
        .iter()
        .filter_map(|(_, event)| operation_key(&event.method, &event.url))
        .collect()
}

fn operation_key(method: &str, raw_url: &str) -> Option<(String, String)> {
    if method == "CONNECT" {
        return None;
    }
    let url = url::Url::parse(raw_url).ok()?;
    Some((method.to_owned(), url.path().to_owned()))
}

#[test]
fn derived_operation_keys_exclude_opaque_connect_and_collapse_poll_queries_only_in_the_view() {
    let raw = [
        ("CONNECT", "127.0.0.1:443"),
        ("GET", "https://127.0.0.1:443/data?n=1"),
        ("GET", "https://127.0.0.1:443/data?n=2"),
    ];
    let operations: BTreeSet<_> = raw
        .iter()
        .filter_map(|(method, url)| operation_key(method, url))
        .collect();
    assert_eq!(
        operations,
        BTreeSet::from([("GET".to_owned(), "/data".to_owned())])
    );
    assert_eq!(raw.len(), 3, "deriving the view never mutates raw observations");
}

fn polls(c: &Crawled) -> usize {
    c.traffic
        .iter()
        .filter(|(_, event)| capture_source(event) != Some("cdp_supplement"))
        .filter(|(_, ev)| ev.url.contains("/g28/api/poll"))
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g28_cdp_backend_keeps_the_raw_stream_and_excludes_background_origins_from_trusted_lane() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    let c = crawl("g28", CaptureBackend::Cdp, 6, 28, false).await;
    assert_eq!(c.report.capture.backend, CaptureBackend::Cdp);
    assert!(c.report.capture.protocols_disabled.is_empty());
    assert!(!c.traffic.is_empty(), "the CDP backend recorded no traffic");
    assert_raw_stream(&c);
    assert_non_page_origins_are_not_trusted(&c);
    assert_fixture_origins_observed(&c);
    assert!(
        c.traffic.iter().any(|(_, ev)| ev.origin == TrafficOrigin::Page),
        "{:?}",
        c.traffic
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g28_proxy_backend_records_page_flows_with_quic_disabled() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    let c = crawl("g28", CaptureBackend::Proxy, 6, 28, false).await;
    assert_eq!(c.report.capture.backend, CaptureBackend::Proxy);
    assert_eq!(c.report.capture.protocols_disabled, vec![Protocol::H3]);
    let stats = c.report.capture.proxy.expect("proxy counters");
    assert!(stats.flows > 0, "{stats:?}");
    assert!(!c.traffic.is_empty(), "the proxy backend journaled no traffic");
    assert_raw_stream(&c);
    assert_non_page_origins_are_not_trusted(&c);
    assert_fixture_origins_observed(&c);
    // Raw proxy flows and CDP supplements remain distinct observations. Only the proxy
    // claims wire protocol metadata; the supplement supplies browser-only origin data.
    let mut proxy_flows = 0;
    let mut supplements = 0;
    for (_, ev) in &c.traffic {
        let source = capture_source(ev);
        if source == Some("cdp_supplement") {
            supplements += 1;
            continue;
        }
        assert_eq!(source, Some("proxy"), "{ev:?}");
        proxy_flows += 1;
        if ev.origin == TrafficOrigin::ServiceWorker {
            assert!(
                ev.response_headers
                    .iter()
                    .any(|(name, value)| { name == "x-crawlx-stream-cdp-correlated" && value == "true" }),
                "proxy inferred worker origin without native CDP evidence: {ev:?}"
            );
            assert!(ev.epoch_id.is_none(), "{ev:?}");
            assert_eq!(
                ev.unattributed_reason,
                Some(UnattributedReason::NotApplicable),
                "{ev:?}"
            );
        } else {
            assert_eq!(ev.origin, TrafficOrigin::Page, "{ev:?}");
        }
        assert!(
            matches!(ev.protocol, Some(Protocol::Http11 | Protocol::H2)),
            "{ev:?}"
        );
        // the source leaves `unmatched_proxy_flow`; the actor turns the seed navigation's
        // epoch (no `network_epochs` row) into `before_first_epoch`
        if let Some(r) = ev
            .unattributed_reason
            .filter(|_| ev.origin != TrafficOrigin::ServiceWorker)
        {
            assert!(
                matches!(
                    r,
                    UnattributedReason::UnmatchedProxyFlow | UnattributedReason::BeforeFirstEpoch
                ),
                "{ev:?}"
            );
        }
    }
    assert!(proxy_flows > 0, "no raw proxy observations");
    assert!(supplements > 0, "no browser supplements");
    // the polling loop produces repeated identical requests that stay distinct events
    assert!(polls(&c) >= 2, "polls: {} of {:?}", polls(&c), c.traffic);
    let operations: BTreeSet<String> = c
        .traffic
        .iter()
        .map(|(_, ev)| format!("{} {}", ev.method, ev.url))
        .collect();
    assert!(
        operations.len() < c.traffic.len(),
        "the derived view dedupes, the stream does not"
    );
    eprintln!(
        "g28 proxy capture: {stats:?}, unmatched share {:.3}",
        stats.unmatched as f64 / stats.flows as f64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g28_cdp_and_proxy_derive_the_same_controlled_background_operations() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    let cdp = crawl("g28", CaptureBackend::Cdp, 6, 28, false).await;
    let proxy = crawl("g28", CaptureBackend::Proxy, 6, 28, false).await;
    let expected: BTreeSet<_> = [
        "/g28/",
        "/g28/tracker.js",
        "/g28/api/tracker/pixel.gif",
        "/g28/api/poll",
        "/g28/api/sw/activate",
        "/g28/api/sw/sync",
    ]
    .into_iter()
    .map(|path| ("GET".to_owned(), path.to_owned()))
    .collect();
    // Actions and timer counts may vary with browser scheduling. The fixture always
    // performs these background operations; neither transport may lose any of them.
    for captured in [&cdp, &proxy] {
        assert_raw_stream(captured);
        assert_fixture_origins_observed(captured);
        let actual = derived_operations(captured);
        assert!(expected.is_subset(&actual), "{expected:?} not in {actual:?}");
        assert!(polls(captured) >= 2, "repeated polls were lost");
    }
    // Chromium can attach the worker target after the initial script request started.
    // The proxy must retain that bootstrap wire request; CDP cannot reconstruct it.
    assert!(
        proxy.traffic.iter().any(|(_, event)| {
            capture_source(event) == Some("proxy")
                && event.method == "GET"
                && event.url.ends_with("/g28/sw.js")
                && event.status == Some(200)
        }),
        "proxy lost the worker bootstrap request"
    );
    let fixture_operations = |captured: &Crawled| {
        derived_operations(captured)
            .into_iter()
            .filter(|(_, path)| path.starts_with("/g28/") && path != "/g28/sw.js")
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(fixture_operations(&cdp), fixture_operations(&proxy));
    assert!(
        proxy.traffic.len() > derived_operations(&proxy).len(),
        "derived operations replaced the raw stream"
    );
}

/// `late` attribution: a request that starts after its action's
/// epoch settled is journaled under a later action, tagged `late`, and still carries the
/// epoch of the action that caused it (an earlier action's receipt epoch).
fn assert_late_events_point_at_an_earlier_epoch(c: &Crawled) -> usize {
    let order: BTreeMap<ActionId, usize> = c
        .action_epochs
        .iter()
        .enumerate()
        .map(|(i, (a, _))| (*a, i))
        .collect();
    let epoch_index: BTreeMap<NetworkEpochId, usize> = c
        .action_epochs
        .iter()
        .enumerate()
        .map(|(i, (_, e))| (*e, i))
        .collect();
    let mut late = 0;
    for (action, ev) in &c.traffic {
        if !ev.late {
            continue;
        }
        let Some(epoch) = ev.epoch_id else {
            // a push that landed after the seed navigation settled and before the first
            // action: late, but its epoch has no `network_epochs` row
            assert_eq!(
                ev.unattributed_reason,
                Some(UnattributedReason::BeforeFirstEpoch),
                "{ev:?}"
            );
            continue;
        };
        late += 1;
        let (Some(journaled_under), Some(caused_by)) = (order.get(action), epoch_index.get(&epoch)) else {
            panic!("late event under an action without a receipt epoch: {ev:?}");
        };
        assert!(
            caused_by <= journaled_under,
            "late event attributed to a later action than it was journaled under: {ev:?}"
        );
    }
    late
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_late_cdp_backend_tags_delayed_requests_late_under_the_causing_epoch() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    let c = crawl("async-late", CaptureBackend::Cdp, 6, 12, true).await;
    assert_raw_stream(&c);
    let late = assert_late_events_point_at_an_earlier_epoch(&c);
    assert!(late >= 1, "no late event: {:?}", c.traffic);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_late_proxy_backend_tags_flows_after_settle_late_under_the_previous_epoch() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    let c = crawl("async-late", CaptureBackend::Proxy, 6, 12, true).await;
    assert_eq!(c.report.capture.protocols_disabled, vec![Protocol::H3]);
    assert_raw_stream(&c);
    let late = assert_late_events_point_at_an_earlier_epoch(&c);
    let stats = c.report.capture.proxy.expect("proxy counters");
    assert!(late >= 1, "no late event: {stats:?} {:?}", c.traffic);
    // These counters describe raw proxy flows, not the extra browser observations.
    let raw_late = c
        .traffic
        .iter()
        .filter(|(_, event)| event.late && capture_source(event) == Some("proxy"))
        .count();
    assert!(raw_late > 0, "no late raw proxy flow: {stats:?}");
    assert!(stats.late >= u64::try_from(raw_late).unwrap(), "{stats:?}");
}
