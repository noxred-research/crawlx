//! API coverage equals an offline recount over the same run, and fixture-manifest ground-truth
//! recall equals the benchmark's independent server-ledger calculation.
//!
//! The real-worker test skips without Chromium. The fixture-input contract also has a
//! browser-free regression with duplicate, diagnostic, hidden and unsupported observations.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::resources::{FixtureGroundTruth, FixtureGroundTruthSource};
use crawlx_api::{ApiConfig, AppState, Repos, Scope, Settings};
use crawlx_bench::gym::ledger::Ledger;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::scorecard::{RunRows, Scorecard};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, rows_from_report, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_core::counters::ActionStatus;
use crawlx_core::ids::StateId;
use crawlx_core::repo::RunRepo;
use crawlx_core::{Clock, CrawlRunId, StoreError, SystemClock, TrustLane};
use crawlx_storage::{MemoryArtifactStore, MemoryStore};
use crawlx_worker::{run_local_with, LocalRun, Stores};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Only this run's independent fixture evidence can enter its coverage response.
struct GymGroundTruth {
    run: CrawlRunId,
    manifest: FixtureManifest,
    stealth: bool,
    ledger: Arc<Ledger>,
}

#[async_trait::async_trait]
impl FixtureGroundTruthSource for GymGroundTruth {
    async fn ground_truth(&self, run: CrawlRunId) -> Result<Option<FixtureGroundTruth>, StoreError> {
        if run != self.run {
            return Ok(None);
        }
        let manifest = serde_json::to_string(&self.manifest)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        FixtureGroundTruth::from_manifest(
            &manifest,
            self.stealth,
            self.ledger
                .clicks(&self.manifest.id)
                .into_iter()
                .filter_map(|(id, trusted)| trusted.then_some(id)),
        )
        .map(Some)
        .map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

/// An API over `store`, served on a loopback port; returns its base URL and an all-scopes key
/// of tenant `acme`.
async fn serve_api(
    store: Arc<MemoryStore>,
    source: Option<Arc<dyn FixtureGroundTruthSource>>,
) -> (String, String) {
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
    let mut builder = AppState::builder(
        repos,
        crawlx_api::admission_policy(&config, clock.clone()),
        config,
    )
    .settings(Settings::default())
    .clock(clock);
    if let Some(source) = source {
        builder = builder.fixture_ground_truth(source);
    }
    let state = builder.build();
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

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
async fn get(client: &reqwest::Client, key: &str, url: &str) -> Value {
    let response = client.get(url).bearer_auth(key).send().await.unwrap();
    assert!(response.status().is_success(), "{url}: {}", response.status());
    response.json().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
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

    let source = Arc::new(GymGroundTruth {
        run: report.run_id,
        manifest: manifest.clone(),
        stealth: rows.stealth,
        ledger: gym.ledger(),
    });
    let (base, key) = serve_api(memory.clone(), Some(source)).await;
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
    assert_eq!(coverage["groundTruth"]["fixture"], manifest.id);
    assert_eq!(coverage["groundTruth"]["keys"], scorecard.coverage.gt_total);
    assert!(
        (coverage["groundTruth"]["recall"].as_f64().unwrap() - scorecard.coverage.trusted).abs()
            < f64::EPSILON,
        "{coverage} vs {:?}",
        scorecard.coverage
    );
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
    assert_eq!(
        resource["coverage"]["exercisedTrusted"], total["exercised"],
        "{resource} vs {coverage}"
    );
    assert_eq!(
        resource["coverage"]["groundTruthRecall"], coverage["groundTruth"]["recall"],
        "{resource} vs {coverage}"
    );
    gym.shutdown().await;
}

#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
async fn fixture_manifest_input_matches_bench_recall_without_a_browser() {
    let manifest = FixtureManifest::from_json(
        r##"{"id":"truth","url_path":"/truth/","controls":[
            {"id":"first","selector":"#first","role":"button"},
            {"id":"second","selector":"#second","role":"button"},
            {"id":"stealth","selector":"#stealth","role":"button","stealth_only":true},
            {"id":"hidden","selector":"#hidden","role":"button","expected":"not_actionable"},
            {"id":"unsupported","selector":"#unsupported","role":"generic","mechanism":"unsupported"}
        ]}"##,
    )
    .unwrap();
    let memory = Arc::new(MemoryStore::new());
    let mut run = crawlx_storage::testkit::crawl_run(
        tenant_id_for("acme"),
        crawlx_storage::testkit::create_crawl("https://fixture.test/truth/", &["anonymous"], 1),
    );
    run.id = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    run.created_at = crawlx_core::Timestamp::default();
    memory.create(&run, None).await.unwrap();
    let mut ordinary = run.clone();
    ordinary.id = "00000000-0000-0000-0000-000000000002".parse().unwrap();
    memory.create(&ordinary, None).await.unwrap();
    for stealth in [false, true] {
        let ledger = Arc::new(Ledger::default());
        for (id, trusted) in [
            ("first", true),
            ("first", true),
            ("second", false),
            ("stealth", true),
            ("hidden", true),
            ("unsupported", true),
            ("outside-manifest", true),
        ] {
            ledger.click(&manifest.id, id, trusted);
        }
        let source = Arc::new(GymGroundTruth {
            run: run.id,
            manifest: manifest.clone(),
            stealth,
            ledger: ledger.clone(),
        });
        let (base, key) = serve_api(memory.clone(), Some(source)).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut rows = RunRows::new(&manifest.id, 7, "fixture-input", SafetyProfile::ReadOnly);
        rows.stealth = stealth;
        let offline = Scorecard::compute(&manifest, &rows, &ledger);
        let coverage_url = format!("{base}/v1/crawls/{}/coverage", run.id);
        let coverage = get(&client, &key, &coverage_url).await;
        assert_eq!(coverage["groundTruth"]["fixture"], manifest.id);
        assert_eq!(coverage["groundTruth"]["keys"], offline.coverage.gt_total);
        assert_eq!(coverage["groundTruth"]["keys"], if stealth { 3 } else { 2 });
        let expected_recall = if stealth { 2.0 / 3.0 } else { 0.5 };
        assert!((coverage["groundTruth"]["recall"].as_f64().unwrap() - expected_recall).abs() < f64::EPSILON);
        assert!(
            (coverage["groundTruth"]["recall"].as_f64().unwrap() - offline.coverage.trusted).abs()
                < f64::EPSILON
        );
        let resource = get(&client, &key, &format!("{base}/v1/crawls/{}", run.id)).await;
        assert_eq!(
            resource["coverage"]["groundTruthRecall"],
            coverage["groundTruth"]["recall"]
        );
        assert_eq!(
            resource["coverage"]["exercisedTrusted"],
            coverage["total"]["exercised"]
        );
        // A fixture can observe new evidence while its API remains live.
        ledger.click(&manifest.id, "second", true);
        let updated = get(&client, &key, &coverage_url).await;
        let offline = Scorecard::compute(&manifest, &rows, &ledger);
        assert!(
            (updated["groundTruth"]["recall"].as_f64().unwrap() - offline.coverage.trusted).abs()
                < f64::EPSILON
        );
        for suffix in ["?role=anonymous", "?lane=diagnostic"] {
            let filtered = get(&client, &key, &format!("{coverage_url}{suffix}")).await;
            assert!(filtered["groundTruth"].is_null(), "{filtered}");
        }
        // Other runs cannot inherit this run's fixture observations.
        let other = get(
            &client,
            &key,
            &format!("{base}/v1/crawls/{}/coverage", ordinary.id),
        )
        .await;
        assert!(other["groundTruth"].is_null(), "{other}");
    }
    let (base, key) = serve_api(memory, None).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let coverage = get(&client, &key, &format!("{base}/v1/crawls/{}/coverage", run.id)).await;
    assert!(coverage["groundTruth"].is_null());
    let resource = get(&client, &key, &format!("{base}/v1/crawls/{}", run.id)).await;
    assert!(resource["coverage"]["groundTruthRecall"].is_null());
}
