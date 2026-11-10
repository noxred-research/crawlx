//! Capture-backend parity: the same gym fixtures crawled through the CDP backend and through
//! the proxy backend (`capture.backend = "proxy"`) must derive the same views.
//!
//! `capture_conformance.rs` checks each backend against the capture contract and compares the
//! two backends' operation sets for g28 as a whole. This test compares the *derived views*
//! per network epoch, because that is what the trail stores and the strategies read:
//!
//! * per exercised control: the epoch's derived operations (`crawlx_observe::capture::operations`,
//!   the production derivation) restricted to the control's declared backend effect, with the
//!   attribution origin, `third_party`, the epoch's trust lane and, for timer-driven controls,
//!   the `late` flag;
//! * fixture-wide: the page, tracker, worker and push operations that no action causes, with
//!   their origin class and `third_party`.
//!
//! Actions are keyed by the control they exercised (read from the gym's `__gym/click`
//! report inside the epoch), never by ordinal: scheduling decides how many actions run and in
//! which order, and each backend is only compared on the controls both exercised (at least two).
//!
//! Documented tolerances, fields that legitimately differ between the backends:
//! * the raw stream: the proxy journals each wire flow next to its browser-side supplement,
//!   so it holds more events (and different header sets, `protocol`, `seq` and timestamps)
//!   than CDP; only the derived (deduplicated) view is compared;
//! * `/<fixture>/sw.js`: the worker bootstrap request starts before Chromium attaches the
//!   worker target, so only the proxy sees it;
//! * `late` outside timer-driven controls: it follows when each backend observes a request
//!   settle, which differs by a settle window; the timer request (`2 s` after the click) is late
//!   under both;
//! * query strings (polls carry a counter), ports and hosts of the loopback listener.
//!
//! Skipped without a Chromium executable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CaptureBackend, CrawlMode, SafetyProfile};
use crawlx_core::ids::NetworkEpochId;
use crawlx_core::traffic::{TrafficEvent, TrafficOrigin, TrustLane};
use crawlx_core::ActionProposal;
use crawlx_observe::capture::operations;
use crawlx_storage::MemoryStore;
use crawlx_strategies::{DecisionContext, Strategy, StrategyError};
use crawlx_worker::{build_strategies, run_local_with, DriverConfig, LocalRun, Stores};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Idle time between actions for fixtures with timer- and push-driven traffic: longer than the
/// fixture's 2 s timer, so that traffic starts after the previous epoch settled. A test pacer
/// only: production strategies never sleep or read the clock.
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

/// What one worker crawl journaled.
struct Crawled {
    traffic: Vec<TrafficEvent>,
    epoch_lane: BTreeMap<NetworkEpochId, TrustLane>,
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
    let traffic = memory
        .traffic_of_run(report.run_id)
        .into_iter()
        .map(|(_, event)| event)
        .collect();
    let epoch_lane = memory
        .network_epochs(report.run_id)
        .iter()
        .map(|e| (e.id, e.lane))
        .collect();
    gym.shutdown().await;
    Crawled { traffic, epoch_lane }
}

// ---- derived views --------------------------------------------------------------------------

/// `(method, path, origin, third_party, lane)` of one operation of a control's epochs.
type EpochOp = (String, String, String, bool, String);

/// The derived view of every epoch one control caused.
#[derive(PartialEq, Eq, Debug, Default)]
struct ControlView {
    /// The control's declared effect as the derived operations show it.
    ops: BTreeSet<EpochOp>,
    /// Of those, the `(method, path)` pairs journaled `late` at least once.
    late: BTreeSet<(String, String)>,
}

/// Attribution of an operation no action causes.
#[derive(PartialEq, Eq, Debug, Default)]
struct BackgroundOp {
    /// `service_worker` if any event of the operation had that origin, else the page-side origin.
    origin: String,
    third_party: BTreeSet<bool>,
}

#[derive(PartialEq, Eq, Debug, Default)]
struct Views {
    controls: BTreeMap<String, ControlView>,
    background: BTreeMap<(String, String), BackgroundOp>,
    /// Size of the raw stream, for the report only (the backends differ here by design).
    raw_events: usize,
}

/// `(method, path)` with WebSocket frame methods folded into one `WS` operation.
fn op_key(method: &str, raw_url: &str) -> Option<(String, String)> {
    let url = url::Url::parse(raw_url).ok()?;
    let method = if method.starts_with("WS_") { "WS" } else { method };
    Some((method.to_owned(), url.path().to_owned()))
}

/// `control id -> (method, path)` of every control with a declared HTTP or WebSocket effect.
fn declared_effects(manifest: &FixtureManifest) -> BTreeMap<String, (String, String)> {
    manifest
        .controls
        .iter()
        .filter_map(|c| {
            let (method, path) = c.effect.as_deref()?.split_once(' ')?;
            Some((c.id.clone(), (method.to_owned(), path.to_owned())))
        })
        .collect()
}

/// The control a gym `__gym/click` report names.
fn clicked_control(event: &TrafficEvent) -> Option<String> {
    let url = url::Url::parse(&event.url).ok()?;
    if url.path() != "/__gym/click" {
        return None;
    }
    url.query_pairs()
        .find(|(name, _)| name == "control")
        .map(|(_, value)| value.into_owned())
}

fn views(
    fixture: &str,
    events: &[TrafficEvent],
    epoch_lane: &BTreeMap<NetworkEpochId, TrustLane>,
    effects: &BTreeMap<String, (String, String)>,
) -> Views {
    let mut out = Views {
        raw_events: events.len(),
        ..Views::default()
    };
    let mut by_epoch: BTreeMap<NetworkEpochId, Vec<TrafficEvent>> = BTreeMap::new();
    for event in events {
        if let Some(epoch) = event.epoch_id {
            by_epoch.entry(epoch).or_default().push(event.clone());
        }
    }
    let declared: Vec<&(String, String)> = effects.values().collect();
    for (epoch, in_epoch) in &by_epoch {
        let controls: BTreeSet<String> = in_epoch.iter().filter_map(clicked_control).collect();
        // an epoch two controls reported in cannot be attributed to either
        let mut reported = controls.into_iter();
        let (Some(control), None) = (reported.next(), reported.next()) else {
            continue;
        };
        let Some(effect) = effects.get(&control) else {
            continue;
        };
        let lane = epoch_lane
            .get(epoch)
            .map_or_else(|| "none".to_owned(), |l| format!("{l:?}"));
        let view = out.controls.entry(control).or_default();
        // the production derived view: deduplicated `METHOD url`, first-seen order
        for operation in operations(in_epoch) {
            let Some((method, url)) = operation.split_once(' ') else {
                continue;
            };
            let Some(key) = op_key(method, url) else { continue };
            if &key != effect {
                continue;
            }
            for event in in_epoch
                .iter()
                .filter(|e| op_key(&e.method, &e.url).as_ref() == Some(&key))
            {
                view.ops.insert((
                    key.0.clone(),
                    key.1.clone(),
                    origin_name(event.origin),
                    event.third_party,
                    lane.clone(),
                ));
                if event.late {
                    view.late.insert(key.clone());
                }
            }
        }
    }
    let prefix = format!("/{fixture}/");
    let worker_bootstrap = format!("/{fixture}/sw.js");
    for event in events {
        let Some(key) = op_key(&event.method, &event.url) else {
            continue;
        };
        if !key.1.starts_with(&prefix) || key.1 == worker_bootstrap || declared.contains(&&key) {
            continue;
        }
        let entry = out.background.entry(key).or_default();
        if event.origin == TrafficOrigin::ServiceWorker || entry.origin.is_empty() {
            entry.origin = origin_name(event.origin);
        }
        entry.third_party.insert(event.third_party);
    }
    out
}

fn origin_name(origin: TrafficOrigin) -> String {
    format!("{origin:?}")
}

/// Every difference between the two backends' views, empty when they are equal. Controls only
/// one backend exercised are not compared; `late_controls` also compare their `late` sets.
fn parity_diff(cdp: &Views, proxy: &Views, late_controls: &[&str]) -> Vec<String> {
    let mut diffs = Vec::new();
    for (control, a) in &cdp.controls {
        let Some(b) = proxy.controls.get(control) else {
            continue;
        };
        if a.ops != b.ops {
            diffs.push(format!(
                "control {control}: operations cdp {:?} != proxy {:?}",
                a.ops, b.ops
            ));
        }
        if late_controls.contains(&control.as_str()) && a.late != b.late {
            diffs.push(format!(
                "control {control}: late cdp {:?} != proxy {:?}",
                a.late, b.late
            ));
        }
    }
    if cdp.background != proxy.background {
        diffs.push(format!(
            "background operations cdp {:?} != proxy {:?}",
            cdp.background, proxy.background
        ));
    }
    diffs
}

/// Controls both views exercised with their declared effect observed.
fn common_controls(a: &Views, b: &Views) -> Vec<String> {
    a.controls
        .iter()
        .filter(|(id, view)| !view.ops.is_empty() && b.controls.get(*id).is_some_and(|v| !v.ops.is_empty()))
        .map(|(id, _)| id.clone())
        .collect()
}

// ---- unit tests of the comparison ----------------------------------------------------------

fn event(
    epoch: Option<NetworkEpochId>,
    origin: &str,
    method: &str,
    url: &str,
    third_party: bool,
    late: bool,
    source: Option<&str>,
) -> TrafficEvent {
    let headers: Vec<(&str, &str)> = source
        .map(|s| ("x-crawlx-capture-source", s))
        .into_iter()
        .collect();
    serde_json::from_value(serde_json::json!({
        "seq": 1,
        "epoch_id": epoch,
        "unattributed_reason": epoch.is_none().then_some("not_applicable"),
        "origin": origin,
        "method": method,
        "url": url,
        "status": 200,
        "request_headers": [],
        "response_headers": headers,
        "request_body": null,
        "response_body": null,
        "third_party": third_party,
        "late": late,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
    }))
    .unwrap()
}

fn effects() -> BTreeMap<String, (String, String)> {
    BTreeMap::from([
        (
            "refresh".to_owned(),
            ("GET".to_owned(), "/fx/api/balance".to_owned()),
        ),
        ("timer".to_owned(), ("GET".to_owned(), "/fx/api/timer".to_owned())),
    ])
}

struct Synthetic {
    events: Vec<TrafficEvent>,
    lanes: BTreeMap<NetworkEpochId, TrustLane>,
}

/// One refresh epoch, one timer epoch whose request lands late, plus a poll and a worker sync
/// outside any epoch. The proxy flavor journals every request twice (wire flow and browser
/// supplement, different sources and ports) and also sees the worker bootstrap.
fn synthetic(proxy: bool, port: u16, tweak: impl Fn(&mut Synthetic)) -> Synthetic {
    let (refresh, timer) = (NetworkEpochId::new(), NetworkEpochId::new());
    let url = |path: &str| format!("http://127.0.0.1:{port}{path}");
    let mut events = Vec::new();
    let mut push = |e: TrafficEvent| {
        if proxy {
            let mut wire = e.clone();
            wire.response_headers = vec![("x-crawlx-capture-source".into(), "proxy".into())];
            wire.protocol = Some(crawlx_core::traffic::Protocol::Http11);
            events.push(wire);
            let mut supplement = e;
            supplement.response_headers = vec![("x-crawlx-capture-source".into(), "cdp_supplement".into())];
            events.push(supplement);
        } else {
            events.push(e);
        }
    };
    push(event(
        Some(refresh),
        "page",
        "POST",
        &url("/__gym/click?fixture=fx&control=refresh&trusted=1"),
        false,
        false,
        None,
    ));
    push(event(
        Some(refresh),
        "page",
        "GET",
        &url("/fx/api/balance"),
        false,
        false,
        None,
    ));
    push(event(
        Some(refresh),
        "page",
        "GET",
        &url("/fx/api/poll?n=1"),
        false,
        false,
        None,
    ));
    push(event(
        Some(timer),
        "page",
        "POST",
        &url("/__gym/click?fixture=fx&control=timer&trusted=1"),
        false,
        false,
        None,
    ));
    push(event(
        Some(timer),
        "page",
        "GET",
        &url("/fx/api/timer"),
        false,
        true,
        None,
    ));
    push(event(
        None,
        "page",
        "GET",
        &url("/fx/tracker.js"),
        true,
        false,
        None,
    ));
    push(event(
        None,
        "service_worker",
        "GET",
        &url("/fx/api/sw/sync"),
        false,
        false,
        None,
    ));
    if proxy {
        events.push(event(
            None,
            "page",
            "GET",
            &url("/fx/sw.js"),
            false,
            false,
            Some("proxy"),
        ));
    }
    let lanes = BTreeMap::from([(refresh, TrustLane::TrustedUi), (timer, TrustLane::TrustedUi)]);
    let mut s = Synthetic { events, lanes };
    tweak(&mut s);
    s
}

fn synthetic_views(s: &Synthetic) -> Views {
    views("fx", &s.events, &s.lanes, &effects())
}

#[test]
fn equal_derived_views_pass_despite_different_raw_streams_and_ports() {
    let cdp = synthetic_views(&synthetic(false, 4001, |_| {}));
    let proxy = synthetic_views(&synthetic(true, 5002, |_| {}));
    assert!(
        proxy.raw_events > cdp.raw_events,
        "the proxy journals more raw events"
    );
    assert_eq!(common_controls(&cdp, &proxy), ["refresh", "timer"]);
    assert_eq!(parity_diff(&cdp, &proxy, &["timer"]), Vec::<String>::new());
    // the poll, the tracker script and the worker sync are background; the declared effects are not
    let background: Vec<&str> = cdp.background.keys().map(|(_, p)| p.as_str()).collect();
    assert_eq!(background, ["/fx/api/poll", "/fx/api/sw/sync", "/fx/tracker.js"]);
    assert_eq!(
        cdp.background[&("GET".to_owned(), "/fx/api/sw/sync".to_owned())].origin,
        "ServiceWorker"
    );
}

fn assert_detected(what: &str, tweak: impl Fn(&mut Synthetic)) {
    let cdp = synthetic_views(&synthetic(false, 4001, |_| {}));
    let proxy = synthetic_views(&synthetic(true, 5002, tweak));
    assert!(
        !parity_diff(&cdp, &proxy, &["timer"]).is_empty(),
        "a proxy backend that {what} must not compare equal"
    );
}

#[test]
fn a_backend_that_loses_changes_or_misattributes_an_operation_is_detected() {
    assert_detected("drops the control's declared request", |s| {
        s.events.retain(|e| !e.url.ends_with("/fx/api/balance"));
    });
    assert_detected("flags a same-origin request third party", |s| {
        for e in s.events.iter_mut().filter(|e| e.url.ends_with("/fx/api/balance")) {
            e.third_party = true;
        }
    });
    assert_detected("attributes the epoch to another lane", |s| {
        for lane in s.lanes.values_mut() {
            *lane = TrustLane::Diagnostic;
        }
    });
    assert_detected("loses the late tag of the timer request", |s| {
        for e in s.events.iter_mut().filter(|e| e.url.ends_with("/fx/api/timer")) {
            e.late = false;
        }
    });
    assert_detected("attributes the worker sync to the page", |s| {
        for e in s.events.iter_mut().filter(|e| e.url.ends_with("/fx/api/sw/sync")) {
            e.origin = TrafficOrigin::Page;
        }
    });
    assert_detected("loses a background request", |s| {
        s.events.retain(|e| !e.url.ends_with("/fx/tracker.js"));
    });
    assert_detected("attributes the request to the wrong epoch's control", |s| {
        let (refresh, timer) = {
            let mut ids = s.lanes.keys().copied();
            (ids.next().unwrap(), ids.next().unwrap())
        };
        for e in s.events.iter_mut().filter(|e| e.url.ends_with("/fx/api/balance")) {
            e.epoch_id = Some(if e.epoch_id == Some(refresh) {
                timer
            } else {
                refresh
            });
        }
    });
}

#[test]
fn controls_only_one_backend_exercised_are_not_compared() {
    let cdp = synthetic_views(&synthetic(false, 4001, |_| {}));
    let proxy = synthetic_views(&synthetic(true, 5002, |s| {
        s.events
            .retain(|e| !e.url.contains("control=timer") && !e.url.ends_with("/fx/api/timer"));
    }));
    assert_eq!(common_controls(&cdp, &proxy), ["refresh"]);
    assert_eq!(parity_diff(&cdp, &proxy, &["timer"]), Vec::<String>::new());
}

// ---- Chromium parity ------------------------------------------------------------------------

async fn assert_backends_derive_the_same_views(
    fixture: &str,
    interactions: u32,
    seed: u64,
    paced: bool,
    late_controls: &[&str],
) {
    let manifest = FixtureManifest::embedded(fixture).unwrap();
    let effects = declared_effects(&manifest);
    let cdp = crawl(fixture, CaptureBackend::Cdp, interactions, seed, paced).await;
    let proxy = crawl(fixture, CaptureBackend::Proxy, interactions, seed, paced).await;
    let cdp_views = views(fixture, &cdp.traffic, &cdp.epoch_lane, &effects);
    let proxy_views = views(fixture, &proxy.traffic, &proxy.epoch_lane, &effects);
    eprintln!(
        "{fixture}: raw events cdp {} / proxy {}; controls cdp {:?} / proxy {:?}; background {} / {}",
        cdp_views.raw_events,
        proxy_views.raw_events,
        cdp_views.controls.keys().collect::<Vec<_>>(),
        proxy_views.controls.keys().collect::<Vec<_>>(),
        cdp_views.background.len(),
        proxy_views.background.len(),
    );
    let common = common_controls(&cdp_views, &proxy_views);
    assert!(
        common.len() >= 2,
        "only {common:?} were exercised with their effect observed under both backends"
    );
    for control in &common {
        for (name, v) in [("cdp", &cdp_views), ("proxy", &proxy_views)] {
            assert!(
                v.controls[control]
                    .ops
                    .iter()
                    .all(|(_, _, _, _, lane)| lane == "TrustedUi"),
                "{name}: control {control} ran on a lane other than trusted_ui: {:?}",
                v.controls[control]
            );
        }
    }
    for control in late_controls {
        assert!(
            cdp_views
                .controls
                .get(*control)
                .is_some_and(|v| !v.late.is_empty()),
            "cdp: no late request attributed to control {control}"
        );
    }
    assert!(!cdp_views.background.is_empty() && !proxy_views.background.is_empty());
    let diffs = parity_diff(&cdp_views, &proxy_views, late_controls);
    assert!(
        diffs.is_empty(),
        "{fixture}: CDP and proxy derived views differ:\n{}",
        diffs.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_g28_cdp_and_proxy_derive_equal_epoch_and_background_views() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    assert_backends_derive_the_same_views("g28", 6, 28, false, &[]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_async_late_cdp_and_proxy_derive_equal_epoch_views_and_late_tags() {
    if !have_chromium() {
        return;
    }
    let _slot = browser_slot().await;
    assert_backends_derive_the_same_views("async-late", 6, 12, true, &["timer"]).await;
}
