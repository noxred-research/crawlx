//! G24 `server-validation`: run-twice determinism of the value partitions through a real worker
//! crawl. Two crawls with the same seed perform the same ordered actions with the same
//! generated values and submit the same forms to the server; another seed changes the values,
//! so the equality cannot hold vacuously. Skips without a Chromium executable.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::gym::ledger::LedgerEvent;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_worker::action_trace::{ActionTrace, TraceStep};
use crawlx_worker::{run_local_with, LocalRun};
use std::sync::Arc;

/// Interactions each crawl performs: enough to fill and submit several of the eight forms.
const INTERACTIONS: u32 = 14;

/// What one crawl did: the actions actually sent to the browser in perform order, and what the
/// fixture server's ledger recorded in arrival order (clicks, form submissions, probes and
/// backend effects; request lines are left out because the browser's own background requests
/// are not part of the crawl's decisions).
struct Observed {
    trace: Vec<TraceStep>,
    server: Vec<LedgerEvent>,
}

async fn crawl(gym: &GymHandle, manifest: &FixtureManifest, seed: u64) -> Observed {
    gym.reset(seed);
    let mut req = crawl_request(manifest, &gym.base_url, seed, SafetyProfile::TestEnvironment).unwrap();
    req.mode = CrawlMode::Dynamic;
    req.limits.interactions = INTERACTIONS;
    // The interaction budget ends the crawl, not the wall clock, so the action count cannot
    // depend on how fast the host is.
    req.limits.duration_seconds = 240;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let trace = Arc::new(ActionTrace::default());
    cfg.action_trace = Some(Arc::clone(&trace));
    let report = run_local_with(authorize_fixture(LocalRun::new(req, cfg)))
        .await
        .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    Observed {
        trace: trace.take().into_iter().map(|performed| performed.step).collect(),
        server: gym
            .ledger()
            .entries_for("g24")
            .into_iter()
            .map(|entry| entry.event)
            .filter(|event| !matches!(event, LedgerEvent::Op { .. }))
            .collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g24_value_generation_is_deterministic_per_seed_and_varies_across_seeds() {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded("g24").unwrap();

    let first = crawl(&gym, &manifest, 24).await;
    let second = crawl(&gym, &manifest, 24).await;

    // Non-vacuity: the crawl really performed actions, typed generated values and the server
    // saw the page's reports.
    assert!(
        first.trace.len() >= 3,
        "the crawl must perform actions: {:?}",
        first.trace
    );
    let typed = |observed: &Observed| {
        observed
            .trace
            .iter()
            .filter(|step| step.parameters_digest.is_some())
            .count()
    };
    assert!(
        typed(&first) > 0,
        "at least one action must carry generated parameters: {:?}",
        first.trace
    );
    assert!(
        !first.server.is_empty(),
        "the server ledger must hold the page's reports"
    );

    // Same seed: identical ordered action keys and parameter digests, identical server ledger.
    assert_eq!(
        first.trace, second.trace,
        "the same seed must perform the same ordered actions with the same values"
    );
    assert_eq!(
        first.server, second.server,
        "the same seed must produce the same ordered server-side ledger (clicks, submissions, probes, effects)"
    );

    // Another seed: the generated values differ, so the equality above is not a constant.
    let other = crawl(&gym, &manifest, 25).await;
    assert_ne!(
        other.trace, first.trace,
        "a different seed must change the generated values"
    );
    gym.shutdown().await;
}
