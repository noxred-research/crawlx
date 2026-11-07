//! The live-model rig against PostgreSQL and real Chromium with a stub model endpoint: shadow
//! recording joins shortlists with `model_decisions` under the endpoint's own identity, and the
//! paired protocol scores A9 against A10. Skips without `CRAWLX_TEST_DATABASE_URL` or Chromium.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::routing::{get, post};
use axum::{Json, Router};
use crawlx_bench::ablation;
use crawlx_bench::decision_eval::analyze_shadow;
use crawlx_bench::decision_rig::{paired_runs, DecisionRig, RigConfig, RigExecutor};
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{SafetyProfile, System1Mode};
use crawlx_worker::ShortlistRecording;
use serde_json::{json, Value};
use std::time::Duration;

/// A decision endpoint that puts 0.85 on the first option of every choice question.
async fn stub_endpoint() -> String {
    async fn decide(Json(req): Json<Value>) -> Json<Value> {
        let answers: Vec<Value> = req["questions"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|q| {
                let options: Vec<u64> = q["options"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(Value::as_u64)
                    .collect();
                let rest = options.len().saturating_sub(1).max(1) as f64;
                let probs: Vec<Value> = options
                    .iter()
                    .enumerate()
                    .map(|(i, o)| json!({ "option": o, "p": if i == 0 { 0.85 } else { 0.10 / rest } }))
                    .collect();
                json!({ "kind": "choice", "id": q["id"], "probs": probs, "none": 0.05 })
            })
            .collect();
        Json(json!({ "answers": answers }))
    }
    async fn health() -> Json<Value> {
        Json(json!({
            "provider": "onnx-ranker",
            "model": "stub-ranker",
            "checkpoint_digest": "stub-digest",
            "calibration_version": "cal-stub",
        }))
    }
    let app = Router::new()
        .route("/v1/decide", post(decide))
        .route("/health", get(health));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/v1/decide")
}

fn config(endpoint: String, database_url: String) -> (RigConfig, tempfile::TempDir) {
    let scratch = tempfile::tempdir().unwrap();
    (
        RigConfig {
            database_url,
            endpoint,
            timeout: Duration::from_millis(1500),
            forced_choice: false,
            scratch: scratch.path().join("rig"),
        },
        scratch,
    )
}

// Test-only signed G1 fixture. It grants no G3 status and is not a measured benchmark artifact.
fn authenticated_g1(dir: &std::path::Path) -> crawlx_worker::Gates {
    use crawlx_bench::gates::{evaluate_g1, gate_file, ChaosEvidence, G1Report, G1RunEvidence};
    use crawlx_bench::scorecard::{RunRows, Scorecard};
    use crawlx_core::hash::Digest;
    use crawlx_core::identity::{ActionContextKey, ActionKind, InputClass, ResourceContext};
    use crawlx_core::{ElementIdentityHash, PrincipalId, RouteTemplate, StateClusterId};
    use crawlx_strategies::registry::{scope_digest, Gate, GateKeys};
    std::fs::create_dir_all(dir).unwrap();
    let mut card = Scorecard::compute(
        &FixtureManifest::embedded("g01").unwrap(),
        &RunRows::new("g01", 7, "A4", SafetyProfile::TestEnvironment),
        &crawlx_bench::gym::Ledger::default(),
    );
    card.lanes = Some(
        serde_json::from_value(json!({
            "trusted": 1, "diagnostic": 0, "trusted_share": 1.0, "diagnostic_share": 0.0
        }))
        .unwrap(),
    );
    card.run_to_run_jaccard = Some(1.0);
    let key = ActionContextKey {
        principal: PrincipalId::anonymous(),
        route_template: RouteTemplate("/g01/".to_owned()),
        element: ElementIdentityHash(Digest::of("test/element", b"test-only")),
        action_kind: ActionKind::Click,
        input_class: InputClass("none".to_owned()),
        resource_context: ResourceContext::None,
        state_cluster: StateClusterId(uuid::Uuid::nil()),
    };
    let mut run = G1RunEvidence::new("g01".to_owned(), 7);
    run.first.push(
        serde_json::from_value(json!({
            "key": key, "parameters_digest": Digest::of("test/parameters", b"test-only")
        }))
        .unwrap(),
    );
    run.second.clone_from(&run.first);
    run.first_performed = 1;
    run.second_performed = 1;
    run.replay_recorded = 1;
    run.replay_attempted = 1;
    run.replay_matched = 1;
    let chaos: ChaosEvidence = serde_json::from_value(json!({
        "scope_digest": scope_digest(),
        "suites": (["crawlx-worker/chaos_failpoints", "crawlx-cli/chaos"].map(|suite| json!({
            "suite": suite, "exit_code": 0, "stderr": "",
            "stdout": "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s\n"
        })))
    })).unwrap();
    let report = G1Report {
        scorecards: vec![card],
        runs: vec![run],
        chaos: Some(chaos),
    };
    let bytes = serde_json::to_vec(&report).unwrap();
    let keys = GateKeys::parse(&format!("test-only {}", "42".repeat(32))).unwrap();
    let file = gate_file(
        &evaluate_g1(&report),
        &bytes,
        "test-only",
        "2026-11-04",
        &keys,
        "test-only",
    )
    .unwrap();
    std::fs::write(dir.join(Gate::G1.report_name()), bytes).unwrap();
    std::fs::write(dir.join(Gate::G1.file_name()), file.to_toml().unwrap()).unwrap();
    let gates = crawlx_worker::Gates::load_with_keys(dir, &keys);
    assert!(gates.status().g1 && !gates.status().g3 && gates.g3_token().is_none());
    gates
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadow_runs_and_paired_runs_over_postgres_with_a_served_model() {
    let Ok(database_url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("SKIP: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let endpoint = stub_endpoint().await;
    let (cfg, _scratch) = config(endpoint, database_url);
    let gym = GymServer::start_evaluation().await.unwrap();
    let rig = DecisionRig::open_with_checkpoint_keys(
        &cfg,
        &gym,
        std::sync::Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap()),
    )
    .await
    .unwrap();
    let gates = authenticated_g1(&_scratch.path().join("gates"));
    assert_eq!(rig.model_id().calibration_version, "cal-stub");
    assert_eq!(rig.model_id().checkpoint_digest, "stub-digest");
    let manifest = FixtureManifest::embedded("g21").unwrap();

    // shadow recording: the arbiter executes, the model is recorded
    let mut shadow_variant = ablation::find("A10").unwrap();
    shadow_variant.model = System1Mode::Shadow;
    let mut ex = RigExecutor::new(&rig, &gym, SafetyProfile::TestEnvironment, 25, 40);
    ex.ceiling = System1Mode::Shadow;
    ex.gates = Some(gates.clone());
    ex.recording = Some(ShortlistRecording::recording_only());
    ex.verify_trail = true;
    ablation::VariantExecutor::execute(&ex, &shadow_variant, &manifest, 7)
        .await
        .unwrap();
    let decisions = ex.take_shadow();
    let captures = ex.take_captures();
    assert_eq!(captures.len(), 1);
    let actual_origin = gym.evaluation_origin().unwrap().origin().ascii_serialization();
    assert_eq!(
        captures[0].evaluation_origin.as_deref(),
        Some(actual_origin.as_str())
    );
    assert!(!ex.gates.as_ref().unwrap().status().g3);
    assert_eq!(captures[0].trail_violations, Some(0), "{captures:?}");
    assert!(captures[0].model_calls > 0, "{captures:?}");
    assert!(
        captures[0].model_selected > 0,
        "the stub is above the gate: {captures:?}"
    );
    assert_eq!(
        captures[0].influenced, 0,
        "shadow mode must not influence actions"
    );
    let report = analyze_shadow(&decisions).unwrap();
    assert_eq!(report.calibration_version_missing, 0);
    assert!(report.calibration_versions.contains("cal-stub"));
    assert_eq!(report.fixtures, 1);
    assert!(
        decisions.iter().all(|d| d.top() == Some(0)),
        "the stub favours option 0"
    );
    assert!(rig.engine().stats().calls >= captures[0].model_calls);

    // The listener-bound permit allows advisory evaluation, never promotion or Active.
    let a9 = ablation::find("A9").unwrap();
    let a10 = ablation::find("A10").unwrap();
    let mut paired = RigExecutor::new(&rig, &gym, SafetyProfile::TestEnvironment, 20, 40);
    paired.ceiling = System1Mode::Advisory;
    paired.gates = Some(gates);
    let (runs, failed) = paired_runs(&paired, &a9, &a10, &manifest, &[1, 2]).await;
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(runs.len(), 2);
    for r in &runs {
        assert_eq!(r.fixture, "g21");
        assert!((0.0..=1.0).contains(&r.baseline) && (0.0..=1.0).contains(&r.candidate));
        assert_eq!(r.candidate_unauthorized, 0);
    }
    let captures = paired.take_captures();
    assert_eq!(captures.len(), 4);
    assert!(captures
        .iter()
        .all(|capture| capture.evaluation_origin.as_deref() == Some(actual_origin.as_str())));
    assert!(!paired.gates.as_ref().unwrap().status().g3);
    assert!(captures
        .iter()
        .filter(|c| c.variant == "A9")
        .all(|c| c.model_calls == 0));
    assert!(captures
        .iter()
        .filter(|c| c.variant == "A10")
        .all(|c| c.model_calls > 0));

    gym.shutdown().await;
    rig.close().await.unwrap();
}
