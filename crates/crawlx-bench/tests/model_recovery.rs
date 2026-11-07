//! Real decision-service transport/CallGuard outage and recovery through the worker and server ledger.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, SafetyProfile, StrategyName, System1Mode};
use crawlx_core::counters::ActionStatus;
use crawlx_model::decision_http::{DecisionHttpConfig, DecisionHttpEngine};
use crawlx_model::{BreakerState, DecisionEngine, ModelError, ModelId, TypedDecision, TypedDecisionRequest};
use crawlx_worker::{run_local_with, EngineConfig, LocalRun, ModelConfig, ProvidedEngine, RunReport};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const SEED: u64 = 21;
const BUDGET: u32 = 60;
// Absolute trusted target coverage loss, fixed before execution: five percentage points.
const COVERAGE_TOLERANCE: f64 = 0.05;

struct Outage {
    requests: AtomicUsize,
    engine: Arc<Mutex<Option<Arc<DecisionHttpEngine>>>>,
    signals: Arc<Mutex<Vec<String>>>,
}
impl Respond for Outage {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let n = self.requests.fetch_add(1, Ordering::SeqCst);
        if n < 5 {
            return ResponseTemplate::new(503);
        }
        if self.engine.lock().as_ref().unwrap().breaker_state() == Some(BreakerState::HalfOpen) {
            self.signals
                .lock()
                .push("half_open_probe_reached_provider".into());
        }
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let question = &body["questions"][0];
        let options = question["options"].as_array().unwrap();
        let probabilities: Vec<_> = options
            .iter()
            .enumerate()
            .map(|(index, option)| json!({"option": option, "p": if index == 0 { 1.0 } else { 0.0 }}))
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({"answers": [{
            "kind": "choice", "id": question["id"], "probs": probabilities, "none": 0.0
        }]}))
    }
}

struct ObservedEngine {
    inner: Arc<DecisionHttpEngine>,
    outputs: Arc<Mutex<Vec<TypedDecision>>>,
    signals: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl DecisionEngine for ObservedEngine {
    async fn decide(&self, request: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
        let answer = self.inner.decide(request.clone()).await;
        let already_probed = self
            .signals
            .lock()
            .iter()
            .any(|signal| signal == "open_refused_without_provider_call");
        if matches!(self.inner.breaker_state(), Some(BreakerState::Open { .. })) && !already_probed {
            // Probe immediately, before the cooldown; production CallGuard must refuse it.
            assert_eq!(
                self.inner.decide(request).await.unwrap_err(),
                ModelError::BreakerOpen
            );
            self.signals
                .lock()
                .push("open_refused_without_provider_call".into());
            // Test-only cooldown. The five-failure opening threshold stays at its production value.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Ok(output) = &answer {
            assert_eq!(self.inner.breaker_state(), Some(BreakerState::Closed));
            self.signals.lock().push(format!(
                "recovered_output:{}:{}",
                output.model.model,
                output.answers.len()
            ));
            self.outputs.lock().push(output.clone());
        } else {
            self.signals.lock().push("provider_failure_fell_back".into());
        }
        answer
    }
    fn id(&self) -> &ModelId {
        self.inner.id()
    }
    fn breaker_state(&self) -> Option<BreakerState> {
        self.inner.breaker_state()
    }
}

async fn crawl(gym: &GymHandle, engine: Option<Arc<dyn DecisionEngine>>) -> (RunReport, BTreeSet<String>) {
    gym.reset(SEED);
    let manifest = FixtureManifest::embedded("g02").unwrap();
    let mut request = crawl_request(&manifest, &gym.base_url, SEED, SafetyProfile::TestEnvironment).unwrap();
    request.mode = CrawlMode::Dynamic;
    request.limits.urls = 1;
    request.limits.interactions = BUDGET;
    request.limits.duration_seconds = 180;
    request.dynamic.system1_mode = if engine.is_some() {
        System1Mode::Advisory
    } else {
        System1Mode::Off
    };
    request.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::System1];
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    cfg.model = engine.map(|engine| ModelConfig {
        engine: EngineConfig::Provided(ProvidedEngine(engine)),
        mode: System1Mode::Advisory,
    });
    let report = run_local_with(authorize_fixture(LocalRun::new(request, cfg)))
        .await
        .unwrap();
    let trusted: BTreeSet<_> = gym
        .ledger()
        .clicks("g02")
        .into_iter()
        .filter_map(|(control, trusted)| trusted.then_some(control))
        .collect();
    let known: BTreeSet<_> = manifest
        .controls
        .iter()
        .map(|control| control.id.as_str())
        .collect();
    assert!(
        trusted.iter().all(|control| known.contains(control.as_str())),
        "unmanifested handler would inflate coverage"
    );
    assert!(!trusted.is_empty(), "no server-grounded coverage");
    (report, trusted)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "paired real Chromium coverage workload; no network provider credentials"]
async fn breaker_outage_recovers_without_exceeding_five_point_coverage_loss() {
    assert!(find_executable().is_some(), "set CRAWLX_CHROMIUM_PATH");
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (baseline, baseline_targets) = crawl(&gym, None).await;
    let signals = Arc::new(Mutex::new(Vec::new()));
    let slot = Arc::new(Mutex::new(None));
    let provider = MockServer::start().await;
    let outputs = Arc::new(Mutex::new(Vec::new()));
    Mock::given(method("POST"))
        .respond_with(Outage {
            requests: AtomicUsize::new(0),
            engine: slot.clone(),
            signals: signals.clone(),
        })
        .mount(&provider)
        .await;
    let mut config = DecisionHttpConfig::new(
        &provider.uri(),
        ModelId::new("decision-http", "outage-recovery-fixture", "fixture", "fixture"),
    );
    config.guard.breaker.open_base = Duration::from_millis(50);
    config.guard.breaker.open_max = Duration::from_millis(50);
    let inner = Arc::new(DecisionHttpEngine::new(config).unwrap());
    *slot.lock() = Some(inner.clone());
    let engine = Arc::new(ObservedEngine {
        inner,
        signals: signals.clone(),
        outputs: outputs.clone(),
    });
    let (recovered, recovery_targets) = crawl(&gym, Some(engine)).await;
    let signals = signals.lock().clone();
    assert_eq!(
        signals
            .iter()
            .filter(|signal| *signal == "provider_failure_fell_back")
            .count(),
        5,
        "{signals:?}"
    );
    assert!(
        signals
            .iter()
            .any(|signal| signal == "open_refused_without_provider_call"),
        "{signals:?}"
    );
    assert!(
        signals
            .iter()
            .any(|signal| signal == "half_open_probe_reached_provider"),
        "{signals:?}"
    );
    assert!(
        signals
            .iter()
            .any(|signal| signal.starts_with("recovered_output:")),
        "{signals:?}"
    );
    let outputs = outputs.lock().clone();
    let provider_requests = provider.received_requests().await.unwrap();
    assert_eq!(
        provider_requests.len(),
        outputs.len() + 5,
        "open-breaker refusal contacted the provider"
    );
    let successful: Vec<_> = recovered
        .actions
        .iter()
        .filter(|action| action.status == ActionStatus::Succeeded)
        .collect();
    assert!(
        successful
            .iter()
            .any(|action| action.model_decision.is_none() && action.strategy != "system1"),
        "no deterministic fallback action executed"
    );
    assert!(
        successful
            .iter()
            .any(|action| action.model_decision.is_some() && action.strategy == "system1"),
        "recovered model never influenced an executed safe action"
    );
    let first_model_seq = successful
        .iter()
        .filter(|action| action.model_decision.is_some())
        .map(|action| action.seq)
        .min()
        .expect("no recovered model-backed action");
    assert!(
        successful
            .iter()
            .any(|action| action.seq < first_model_seq && action.model_decision.is_none()),
        "no deterministic success before model recovery"
    );
    assert!(baseline
        .actions
        .iter()
        .all(|action| action.model_decision.is_none()));
    let total = u32::try_from(FixtureManifest::embedded("g02").unwrap().controls.len()).unwrap();
    let baseline_coverage = f64::from(u32::try_from(baseline_targets.len()).unwrap()) / f64::from(total);
    assert!(!outputs.is_empty());
    let recovery_coverage = f64::from(u32::try_from(recovery_targets.len()).unwrap()) / f64::from(total);
    assert!(recovery_coverage + COVERAGE_TOLERANCE >= baseline_coverage,
        "same seed={SEED}, budget={BUDGET}: baseline={baseline_coverage}, recovered={recovery_coverage}, tolerance={COVERAGE_TOLERANCE}");
    eprintln!(
        "{}",
        json!({"seed": SEED, "budget": BUDGET, "tolerance": COVERAGE_TOLERANCE,
        "baselineCoverage": baseline_coverage, "recoveredCoverage": recovery_coverage,
        "baselineTargets": baseline_targets, "recoveredTargets": recovery_targets, "signals": signals,
        "actualRecoveredOutputs": outputs})
    );
    gym.shutdown().await;
}
