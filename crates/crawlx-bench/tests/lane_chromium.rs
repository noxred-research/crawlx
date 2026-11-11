//! G1 lane regressions through real Chromium: interactions on the link fixtures G06 (cards
//! with `open-N` links) and G07 (the self-filling feed with header links) use trusted native input,
//! while independent URL acquisition stays diagnostic. Skipped (with a message) without a
//! Chromium executable; set `CRAWLX_CHROMIUM_PATH`.
//!
//! Two defects put scripted `Navigate` actions on the diagnostic lane here: the live `href` of an
//! anchor was its resolved URL while the observed descriptor carried it as written, so the kernel
//! dropped the first click on every relative link (`confirm.identity_changed`) and the lane-blind
//! arbiter then picked the `url_plane` navigation to the same destination; and `url_plane` raced
//! the trusted click in the greedy phase. Both are asserted away below.
//!
//! The `url_plane` strategy is the recovery phases' link-element fallback. It must not precede
//! the trusted click on its own link. Separately, the worker's `discovered_urls` frontier acquires
//! rendered links and hook destinations using URL-derived identities, including URLs with no
//! clickable element. Those independent navigations legitimately run on the diagnostic lane;
//! they are not `url_plane` fallbacks and have no same-element click prerequisite.
//! Every genuine interaction strategy must still run on the trusted lane.
//! The run ends on its interaction budget or an exhausted frontier, never on the clock: a
//! wall-clock end decided how many actions ran (and whether the greedy phase was left at all), so
//! the same build passed or failed with the speed of the machine, and it could leave an admitted
//! action unexecuted at the cut.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::ablation;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::scorecard::Scorecard;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, rows_from_report, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::{ActionStatus, TerminalReason};
use crawlx_core::identity::ActionKind;
use crawlx_core::repo::ActionRecord;
use crawlx_core::traffic::{Fidelity, TrustLane};
use crawlx_storage::MemoryStore;
use crawlx_worker::driver::DISCOVERED_URLS_STRATEGY;
use crawlx_worker::{run_local_with, DriverConfig, LocalRun, RunReport, Stores};
use std::sync::Arc;

const SEED: u64 = 7;
const VARIANT: &str = "A4";
/// The scripted-navigation strategy: a diagnostic-lane fallback, never a rival of the trusted click.
const URL_PLANE: &str = "url_plane";
/// Interaction budget; the run ends here, never on the clock.
const INTERACTIONS: u32 = 40;
/// Wall-clock limit, far above what [`INTERACTIONS`] actions need on a slow machine, so that the
/// interaction budget ends the run.
const DURATION_SECONDS: u32 = 900;

async fn crawl(gym: &GymHandle, id: &str) -> (FixtureManifest, RunReport) {
    let manifest = FixtureManifest::embedded(id).unwrap();
    let variant = ablation::find(VARIANT).unwrap();
    gym.reset(SEED);
    let mut req = crawl_request(&manifest, &gym.base_url, SEED, SafetyProfile::TestEnvironment).unwrap();
    variant.apply(&mut req);
    req.limits.interactions = INTERACTIONS;
    req.limits.duration_seconds = DURATION_SECONDS;
    req.limits.urls = 200;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut driver = DriverConfig::default();
    driver.exploration.queue = variant.queue_cfg();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(req, cfg).with_driver(driver).with_stores(stores),
    ))
    .await
    .unwrap();
    (manifest, report)
}

fn describe(actions: &[&ActionRecord]) -> Vec<String> {
    actions
        .iter()
        .map(|a| {
            format!(
                "{} {} {:?} {:?} {:?} {:?} {}",
                a.seq,
                a.strategy,
                a.status,
                a.fidelity,
                a.key.action_kind,
                a.key.element,
                a.key.route_template.0
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_fixtures_run_entirely_on_the_trusted_lane() {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    for id in ["g06", "g07"] {
        let (manifest, report) = crawl(&gym, id).await;
        let mut actions: Vec<&ActionRecord> = report.actions.iter().collect();
        actions.sort_by_key(|a| a.seq);
        let detail = || describe(&actions);
        assert!(!actions.is_empty(), "{id}: the run executed nothing");
        // the run ended on its own terms (the interaction budget, or nothing left to do), never
        // on the clock: a deadline would make how far the run got a race with machine speed
        assert!(
            matches!(
                report.terminal_reason,
                Some(TerminalReason::LimitReached | TerminalReason::FrontierExhausted)
            ),
            "{id}: the run ended on {:?}: {:#?}",
            report.terminal_reason,
            detail()
        );
        // a click dropped at confirmation never ran: a relative link must confirm like any other
        assert!(
            actions.iter().all(|a| a.status != ActionStatus::Proposed),
            "{id}: an admitted action was dropped before it ran: {:#?}",
            detail()
        );
        // every action of the click-driven strategies ran on the trusted lane
        assert!(
            actions
                .iter()
                .filter(|a| a.strategy != URL_PLANE && a.strategy != DISCOVERED_URLS_STRATEGY)
                .all(|a| a.lane == Some(TrustLane::TrustedUi)),
            "{id}: a click-driven action ran on the diagnostic lane: {:#?}",
            detail()
        );
        // Independent URL acquisition must remain diagnostic and cannot masquerade as a click.
        assert!(
            actions
                .iter()
                .filter(|a| a.strategy == DISCOVERED_URLS_STRATEGY)
                .all(|a| {
                    a.key.action_kind == ActionKind::Navigate
                        && a.fidelity == Some(Fidelity::ScriptedNavigation)
                        && a.lane == Some(TrustLane::Diagnostic)
                }),
            "{id}: discovered URL acquisition crossed the lane boundary: {:#?}",
            detail()
        );
        // url_plane never races the trusted click: a scripted navigation to a link comes only
        // after the trusted click on that very link
        for (i, a) in actions
            .iter()
            .enumerate()
            .filter(|(_, a)| a.strategy == URL_PLANE)
        {
            let clicked_first = actions[..i].iter().any(|b| {
                b.strategy != URL_PLANE
                    && b.strategy != DISCOVERED_URLS_STRATEGY
                    && b.lane == Some(TrustLane::TrustedUi)
                    && b.key.action_kind == ActionKind::Click
                    && b.key.route_template == a.key.route_template
                    && b.key.element == a.key.element
            });
            assert!(
                clicked_first,
                "{id}: url_plane navigated before the trusted click on its link (action {}): {:#?}",
                a.seq,
                detail()
            );
        }
        let rows = rows_from_report(
            &report,
            &manifest,
            SEED,
            VARIANT,
            SafetyProfile::TestEnvironment,
            &gym,
        );
        let card = Scorecard::compute(&manifest, &rows, &gym.ledger());
        let lanes = card.lanes.expect("the run recorded lanes");
        let scripted = u64::try_from(
            actions
                .iter()
                .filter(|a| a.strategy == URL_PLANE || a.strategy == DISCOVERED_URLS_STRATEGY)
                .count(),
        )
        .unwrap();
        assert!(lanes.trusted > 0, "{id}: no trusted action ran: {lanes:?}");
        assert!(
            lanes.diagnostic == scripted,
            "{id}: exactly URL acquisition and the url_plane fallback use the diagnostic lane: {lanes:?}"
        );
    }
    gym.shutdown().await;
}
