//! API coverage contract over a real crawl: the figures `GET /v1/crawls/{id}/coverage` serves for
//! a worker run equal an offline calculation over the same run's journal, transitions and
//! ledger, every key lands in exactly one bucket of the stated denominator, and the scorecard's
//! ground-truth recall is computed beside them from the gym's server-side ledger. Skips without
//! a Chromium executable.
//!
//! Ground truth: the coverage response has a `groundTruth` member and the run resource a
//! `coverage.groundTruthRecall`. `crawlx-api` serves both as `null` and has no input through
//! which a fixture manifest could reach them, so the API's recall can only be checked here as
//! `exercised / discovered` over the action-context denominator, which is what it can state.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::{ApiConfig, AppState, Repos, Scope, Settings};
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::scorecard::Scorecard;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, rows_from_report, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_core::counters::ActionStatus;
use crawlx_core::ids::StateId;
use crawlx_core::{Clock, SystemClock, TrustLane};
use crawlx_storage::{MemoryArtifactStore, MemoryStore};
use crawlx_worker::{run_local_with, LocalRun, Stores};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;

/// An API over `store`, served on a loopback port; returns its base URL and an all-scopes key
/// of tenant `acme`.
async fn serve_api(store: Arc<MemoryStore>) -> (String, String) {
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let artifacts = Arc::new(MemoryArtifactStore::in_memory(
        store.clone(),
        Arc::new(SystemClock),
    ));
    let (repos, api) = Repos::memory_with_api(store, artifacts);
    let state = AppState::builder(
        repos,
        crawlx_api::admission_policy(&config, clock.clone()),
        config,
    )
    .settings(Settings::default())
    .clock(clock)
    .build();
    let key = generate_key();
    let record = key_record(&key, tenant_id_for("acme"), Scope::all_set()).unwrap();
    crawlx_api::ApiStore::key_insert(api.as_ref(), &record, "acme")
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, crawlx_api::router(state)).await.unwrap();
    });
    (base, key)
}

async fn get(client: &reqwest::Client, key: &str, url: &str) -> Value {
    let response = client.get(url).bearer_auth(key).send().await.unwrap();
    assert!(response.status().is_success(), "{url}: {}", response.status());
    response.json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_coverage_equals_the_offline_calculation_for_a_real_run() {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded("g21").unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, 7, SafetyProfile::TestEnvironment).unwrap();
    req.mode = CrawlMode::Dynamic;
    req.limits.interactions = 40;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let memory = Arc::new(MemoryStore::new());
    let mut stores = Stores::over_memory(memory.clone(), dir.path()).await.unwrap();
    // The run belongs to the tenant the API key authenticates as.
    stores.tenant = tenant_id_for("acme");
    let report = run_local_with(authorize_fixture(LocalRun::new(req, cfg).with_stores(stores)))
        .await
        .unwrap();
    assert!(report.status.is_terminal(), "{:?}", report.status);
    assert!(
        !report.ledger.is_empty(),
        "the crawl must have discovered action contexts: {report:?}"
    );

    // Offline: the scorecard's ground-truth recall from the gym's server-side ledger.
    let rows = rows_from_report(
        &report,
        &manifest,
        7,
        "worker",
        SafetyProfile::TestEnvironment,
        &gym,
    );
    let scorecard = Scorecard::compute(&manifest, &rows, &gym.ledger());
    assert!(scorecard.coverage.gt_total > 0);
    assert!((0.0..=1.0).contains(&scorecard.coverage.trusted));

    let (base, key) = serve_api(memory.clone()).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let coverage = get(
        &client,
        &key,
        &format!("{base}/v1/crawls/{}/coverage", report.run_id),
    )
    .await;

    // The denominator is always present and named.
    assert_eq!(coverage["unit"], "ActionContextKey", "{coverage}");
    assert_eq!(coverage["denominator"], "discovered", "{coverage}");
    assert_eq!(coverage["lane"], "trusted_ui", "{coverage}");
    assert!(coverage.get("groundTruth").is_some(), "{coverage}");
    for role in coverage["roles"].as_array().unwrap() {
        assert_eq!(role["denominator"], "discovered", "{role}");
    }

    // Offline: `exercised` counts keys with a successful trusted-lane action taken from a state
    // reachable through trusted transitions only (a state without an incoming transition is a
    // root). Re-derived here from the persisted journal and transitions.
    let transitions = memory.transitions(report.run_id);
    let afters: BTreeSet<StateId> = transitions.iter().filter_map(|t| t.after).collect();
    let mut reachable: BTreeSet<StateId> = transitions
        .iter()
        .map(|t| t.before)
        .filter(|state| !afters.contains(state))
        .collect();
    loop {
        let known = reachable.len();
        for t in transitions.iter().filter(|t| t.lane == TrustLane::TrustedUi) {
            if let Some(after) = t.after.filter(|_| reachable.contains(&t.before)) {
                reachable.insert(after);
            }
        }
        if reachable.len() == known {
            break;
        }
    }
    let reaches = |state: StateId| !afters.contains(&state) || reachable.contains(&state);
    let offline_exercised = report
        .ledger
        .iter()
        .filter(|row| row.trusted_exercised > 0)
        .filter(|row| {
            report.actions.iter().any(|a| {
                a.key == row.key
                    && a.status == ActionStatus::Succeeded
                    && a.lane == Some(TrustLane::TrustedUi)
                    && a.before_state.is_some_and(reaches)
            })
        })
        .count() as u64;
    let offline_discovered = report.ledger.len() as u64;
    assert!(
        offline_discovered > 0 && offline_exercised > 0,
        "the comparison must not be over empty counts: {offline_discovered} keys, {offline_exercised} exercised"
    );

    let total = &coverage["total"];
    assert_eq!(total["discovered"], offline_discovered, "{coverage}");
    assert_eq!(total["exercised"], offline_exercised, "{coverage}");
    // The worker's own report counts at least as many exercised keys: it does not drop keys
    // exercised only from states the trusted lane cannot reach.
    assert_eq!(
        total["discovered"],
        u64::from(report.coverage.keys_total),
        "{coverage} vs {:?}",
        report.coverage
    );
    assert!(
        total["exercised"].as_u64().unwrap() <= u64::from(report.coverage.keys_exercised_trusted),
        "{coverage} vs {:?}",
        report.coverage
    );
    // Every key lands in exactly one bucket of the denominator.
    let buckets: u64 = [
        "exercised",
        "diagnosticOnly",
        "notObservable",
        "pending",
        "denied",
        "unknown",
    ]
    .iter()
    .map(|name| total[name].as_u64().unwrap())
    .sum();
    assert_eq!(buckets, total["discovered"], "{coverage}");
    let role_discovered: u64 = coverage["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|role| role["discovered"].as_u64().unwrap())
        .sum();
    assert_eq!(
        role_discovered, total["discovered"],
        "the per-role denominators must add up to the total"
    );
    let api_recall = total["exercised"].as_f64().unwrap() / total["discovered"].as_f64().unwrap();
    let offline_recall = offline_exercised as f64 / offline_discovered as f64;
    assert!(
        (api_recall - offline_recall).abs() < f64::EPSILON,
        "API {api_recall} vs offline {offline_recall}"
    );

    // The run resource states the same denominator.
    let resource = get(&client, &key, &format!("{base}/v1/crawls/{}", report.run_id)).await;
    assert_eq!(resource["coverage"]["unit"], "ActionContextKey", "{resource}");
    assert_eq!(
        resource["coverage"]["discovered"], offline_discovered,
        "{resource}"
    );
    gym.shutdown().await;
}
