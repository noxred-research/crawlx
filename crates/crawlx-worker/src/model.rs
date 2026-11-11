//! Model services of a worker: the System 1 decision engine and the LLM planner client, and how they join a session's strategy set.
//!
//! Nothing here can authorize an action. System 1 and the planner are ordinary strategies whose
//! proposals go through the arbiter, the safety kernel and the Session Actor like every other.

use crate::error::WorkerError;
use crawlx_core::config::{Dynamic, LlmPlannerMode, StrategyName, System1Mode};
use crawlx_core::repo::{ModelDecisionKind, ModelDecisionRecord, SafetyContext, SafetyGate};
use crawlx_core::secret::SecretOr;
use crawlx_core::{CrawlRunId, Timestamp};
use crawlx_model::calibration::{DriftMonitor, DriftReading};
use crawlx_model::decision_http::{DecisionHttpConfig, DecisionHttpEngine};
use crawlx_model::llm::PlannerClient;
use crawlx_model::{
    DecisionEngine, G3Token, HttpPlanner, HttpPlannerConfig, MockEngine, ModelError, ModelId,
};
use crawlx_strategies::{
    Gates, LlmPlanner, LlmPlannerConfig, Strategy, System1, System1Config, System1Record,
};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::mpsc;

/// Where the typed-decision engine lives.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum EngineConfig {
    /// A typed-question service over HTTP.
    DecisionHttp {
        /// `http://` or `https://` endpoint of the typed-decision API.
        base_url: String,
        /// Name of the environment variable holding the bearer key; `None` sends no credential.
        /// The key itself is never part of the configuration, so it cannot be logged with it.
        api_key_env: Option<String>,
        /// Per-call time budget in milliseconds.
        timeout_ms: u64,
    },
    /// The deterministic in-process engine of `crawlx_model::MockEngine` (demos and tests).
    Mock,
    /// An engine the embedding process built itself, e.g. the bench harness serving a model
    /// bundle in-process (`OnnxRankerEngine`), so decisions record the bundle's own identity.
    Provided(ProvidedEngine),
}

/// A [`DecisionEngine`] handed to the worker by the embedding process. Equality is identity of
/// the shared engine.
#[derive(Clone)]
pub struct ProvidedEngine(pub Arc<dyn DecisionEngine>);

impl PartialEq for ProvidedEngine {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ProvidedEngine {}

impl std::fmt::Debug for ProvidedEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ProvidedEngine").field(self.0.id()).finish()
    }
}

/// System 1 settings of a worker.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModelConfig {
    /// The engine to ask.
    pub engine: EngineConfig,
    /// The most a run may let the model influence selection. A request's
    /// `dynamic.system1Mode` can ask for less, never for more; `active` is rejected until
    /// gate G3 has passed.
    pub mode: System1Mode,
}

/// The LLM planner endpoint of a worker.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlannerConfig {
    /// `http://` or `https://` endpoint that accepts planner requests.
    pub base_url: String,
    /// Name of the environment variable holding the bearer key; `None` sends no credential.
    pub api_key_env: Option<String>,
    /// Per-call time budget in milliseconds.
    pub timeout_ms: u64,
}

/// The model clients of one run, built once so the circuit breakers are shared by its sessions.
#[derive(Clone, Default)]
pub struct ModelServices {
    engine: Option<Arc<dyn DecisionEngine>>,
    ceiling: Option<System1Mode>,
    planner: Option<Arc<dyn PlannerClient>>,
    g3: Option<G3Token>,
}

impl std::fmt::Debug for ModelServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelServices")
            .field("engine", &self.engine.as_ref().map(|e| e.id().to_string()))
            .field("ceiling", &self.ceiling)
            .field("planner", &self.planner.is_some())
            .finish()
    }
}

fn api_key(env: Option<&str>) -> Result<Option<SecretOr<String>>, WorkerError> {
    let Some(name) = env else { return Ok(None) };
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(Some(SecretOr::secret(v))),
        _ => Err(WorkerError::Config(format!(
            "api key variable {name} is not set or empty"
        ))),
    }
}

impl ModelServices {
    /// No model clients: System 1 and the planner are skipped.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Build the clients a worker is configured with.
    ///
    /// # Errors
    /// [`WorkerError::Config`] for model authority without verified G3 evidence,
    /// a malformed endpoint or a missing key variable.
    pub fn from_config(
        model: Option<&ModelConfig>,
        planner: Option<&PlannerConfig>,
        gates: &Gates,
    ) -> Result<Self, WorkerError> {
        Self::from_effective_config(
            model,
            planner,
            gates,
            model.map_or(System1Mode::Off, |m| m.mode),
            None,
        )
    }

    /// Build only the authority this request can actually use, not the worker's full ceiling.
    pub(crate) fn from_request_config(
        model: Option<&ModelConfig>,
        planner: Option<&PlannerConfig>,
        gates: &Gates,
        requested: System1Mode,
        evaluation: Option<&crate::fixture_evaluation::BoundFixtureEvaluation>,
    ) -> Result<Self, WorkerError> {
        let effective = model.map_or(System1Mode::Off, |m| lesser(requested, m.mode));
        if requested == System1Mode::Active && effective != System1Mode::Active {
            return Err(WorkerError::Config(
                "active request needs a configured Active engine".to_owned(),
            ));
        }
        Self::from_effective_config(model, planner, gates, effective, evaluation)
    }

    fn from_effective_config(
        model: Option<&ModelConfig>,
        planner: Option<&PlannerConfig>,
        gates: &Gates,
        mode: System1Mode,
        evaluation: Option<&crate::fixture_evaluation::BoundFixtureEvaluation>,
    ) -> Result<Self, WorkerError> {
        let mut out = Self::none();
        if let Some(m) = model.filter(|_| mode != System1Mode::Off) {
            // The design permits controlled pre-promotion fixture experiments,
            // not production authority. This run-bound capability never grants Active or G3.
            let fixture_advisory =
                mode == System1Mode::Advisory && evaluation.is_some_and(|permit| permit.scope().is_live());
            if matches!(mode, System1Mode::Advisory | System1Mode::Active)
                && !gates.status().g3
                && !fixture_advisory
            {
                return Err(WorkerError::Config(
                    "model authority above shadow requires gate G3".to_owned(),
                ));
            }
            if mode == System1Mode::Active && gates.g3_token().is_none() {
                return Err(WorkerError::Config(
                    "model.mode active requires authenticated G3 evidence".to_owned(),
                ));
            }
            out.g3 = gates.g3_token().copied();
            let engine: Arc<dyn DecisionEngine> = match &m.engine {
                EngineConfig::Mock => Arc::new(MockEngine::default()),
                EngineConfig::Provided(p) => Arc::clone(&p.0),
                EngineConfig::DecisionHttp {
                    base_url,
                    api_key_env,
                    timeout_ms,
                } => {
                    let mut cfg = DecisionHttpConfig::new(
                        base_url,
                        ModelId::new("decision-http", "decision-http", "", "service"),
                    );
                    cfg.api_key = api_key(api_key_env.as_deref())?;
                    cfg.guard.timeout = Duration::from_millis(*timeout_ms);
                    Arc::new(
                        (if evaluation.is_some() {
                            DecisionHttpEngine::for_loopback_fixture(cfg)
                        } else {
                            DecisionHttpEngine::new(cfg)
                        })
                        .map_err(|e| WorkerError::Config(format!("model engine: {e}")))?,
                    )
                }
            };
            out.engine = Some(engine);
            out.ceiling = Some(mode);
        }
        if let Some(p) = planner {
            let mut cfg = HttpPlannerConfig::new(&p.base_url);
            cfg.api_key = api_key(p.api_key_env.as_deref())?;
            cfg.guard.timeout = Duration::from_millis(p.timeout_ms);
            out.planner = Some(Arc::new(
                HttpPlanner::new(cfg).map_err(|e| WorkerError::Config(format!("planner: {e}")))?,
            ));
        }
        Ok(out)
    }

    /// Use `planner` as the LLM planner client.
    #[must_use]
    pub fn with_planner(mut self, planner: Arc<dyn PlannerClient>) -> Self {
        self.planner = Some(planner);
        self
    }

    /// The mode System 1 runs in for a request asking for `requested`: the lesser of the request
    /// and the worker's ceiling, `off` without an engine.
    #[must_use]
    pub fn system1_mode(&self, requested: System1Mode) -> System1Mode {
        match (&self.engine, self.ceiling) {
            (Some(_), Some(ceiling)) => lesser(requested, ceiling),
            _ => System1Mode::Off,
        }
    }

    /// The planner mode in force: the request's, `off` without a planner client.
    #[must_use]
    pub fn planner_mode(&self, requested: LlmPlannerMode) -> LlmPlannerMode {
        if self.planner.is_some() {
            requested
        } else {
            LlmPlannerMode::Off
        }
    }

    /// Identity of the System 1 engine (`provider`/`model` labels); `None` without one.
    #[must_use]
    pub fn engine_id(&self) -> Option<&ModelId> {
        self.engine.as_deref().map(DecisionEngine::id)
    }

    /// Set `crawlx.model.breaker.state` from the engine's circuit breaker (0 closed, 1
    /// half-open, 2 open); nothing without an engine or for engines without a guard (mocks).
    pub fn observe_breaker(&self) {
        let Some(engine) = &self.engine else { return };
        if let Some(state) = engine.breaker_state() {
            Metrics::global()
                .gauge(names::MODEL_BREAKER_STATE)
                .set(f64::from(state.gauge()), &[("provider", &engine.id().provider)]);
        }
    }
}

/// The `mode` label of a System 1 call.
#[must_use]
pub const fn system1_mode_label(mode: System1Mode) -> &'static str {
    match mode {
        System1Mode::Off => "off",
        System1Mode::Shadow => "shadow",
        System1Mode::Advisory => "advisory",
        System1Mode::Active => "active",
    }
}

/// Count one model request that ended in an engine error instead of a [`System1Record`]
/// (`StrategyError::ModelUnavailable`, `Timeout`, ...): `crawlx.model.requests` with
/// `outcome` a bounded error code (`unavailable`, `timeout`, ...).
pub fn record_model_error(provider: &str, model: &str, mode: System1Mode, outcome: &str) {
    Metrics::global().counter(names::MODEL_REQUESTS).inc_by(
        1,
        &[
            ("provider", provider),
            ("model", model),
            ("mode", system1_mode_label(mode)),
            ("outcome", outcome),
        ],
    );
}

const fn rank(m: System1Mode) -> u8 {
    match m {
        System1Mode::Off => 0,
        System1Mode::Shadow => 1,
        System1Mode::Advisory => 2,
        System1Mode::Active => 3,
    }
}

fn lesser(a: System1Mode, b: System1Mode) -> System1Mode {
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

/// What the driver keeps from the model strategies it did not hand to the arbiter loop.
#[derive(Default)]
pub struct ModelOverlay {
    /// Records of System 1 calls, drained into `model_decisions`.
    pub records: Option<mpsc::Receiver<System1Record>>,
    /// The planner, so the driver can report executed steps and merge finished plans.
    pub planner: Option<Arc<LlmPlanner>>,
}

/// A session's strategies plus the handles the driver needs from the model-backed ones.
pub struct StrategySet {
    /// Every strategy, in fan-out order.
    pub strategies: Vec<Arc<dyn Strategy>>,
    /// The model-backed strategies' side channels.
    pub overlay: ModelOverlay,
    /// Whether System 1 is part of the set (the switching policy engages its overlay phase).
    pub system1: bool,
    /// Configured deterministic arms selected for this session, persisted before exploration.
    pub arm_assignments: Vec<crawlx_core::config::StrategyArmSelection>,
}

/// The kernel and run-level context that filter what model-backed strategies may see.
pub type SafetyView = (Arc<dyn SafetyGate>, SafetyContext);

impl ModelServices {
    /// Add System 1 and the planner to `base` as `dynamic` and the worker's clients allow.
    ///
    /// System 1 needs `system1` in `dynamic.strategies`, a configured engine and an effective
    /// mode other than `off`. The planner needs `dynamic.llmPlanner` other than `off` and a
    /// configured client. `capture_rendered` keeps the rendered request on every System 1
    /// record (the shortlist dataset, [`crate::driver::ShortlistRecording`]).
    #[must_use]
    pub fn extend(
        &self,
        base: Vec<Arc<dyn Strategy>>,
        dynamic: &Dynamic,
        safety: Option<SafetyView>,
        capture_rendered: bool,
    ) -> StrategySet {
        let mut strategies = base;
        let mut overlay = ModelOverlay::default();
        let mut system1 = false;
        let mode = self.system1_mode(dynamic.system1_mode);
        if dynamic.strategies.contains(&StrategyName::System1) && mode != System1Mode::Off {
            if let Some(engine) = &self.engine {
                let cfg = System1Config {
                    mode,
                    capture_rendered,
                    ..System1Config::default()
                };
                match System1::new(Arc::clone(engine), cfg, self.g3.as_ref()) {
                    Ok(mut s) => {
                        if let Some((gate, base)) = &safety {
                            s = s.with_safety(Arc::clone(gate), base.clone());
                        }
                        overlay.records = s.take_records();
                        system1 = true;
                        strategies.push(Arc::new(s));
                        self.observe_breaker();
                    }
                    Err(e) => tracing::warn!(error = %e, "system1 not started"),
                }
            }
        } else if dynamic.strategies.contains(&StrategyName::System1) {
            tracing::info!(
                requested = ?dynamic.system1_mode,
                "system1 is listed but its effective mode is off (no engine or mode off); skipped"
            );
        }
        let planner_mode = self.planner_mode(dynamic.llm_planner);
        if planner_mode != LlmPlannerMode::Off {
            if let Some(client) = &self.planner {
                let cfg = LlmPlannerConfig {
                    mode: planner_mode,
                    ..LlmPlannerConfig::default()
                };
                let mut p = LlmPlanner::new(Arc::clone(client), cfg);
                if let Some((gate, base)) = &safety {
                    p = p.with_safety(Arc::clone(gate), base.clone());
                }
                let p = Arc::new(p);
                overlay.planner = Some(Arc::clone(&p));
                strategies.push(p);
            }
        }
        StrategySet {
            strategies,
            overlay,
            system1,
            arm_assignments: Vec::new(),
        }
    }
}

/// The `model_decisions` row of one System 1 call. Also the producer of the per-call model
/// metrics (`crawlx.model.requests`, `abstentions`, `latency`, `shortlist_size`), so every
/// record the driver flushes is counted exactly once.
#[must_use]
pub fn decision_record(run: CrawlRunId, rec: &System1Record, at: Timestamp) -> ModelDecisionRecord {
    observe_decision(rec);
    let confidence = rec
        .probs
        .iter()
        .copied()
        .fold(None, |best: Option<f32>, p| Some(best.map_or(p, |b| b.max(p))));
    ModelDecisionRecord {
        id: rec.decision_id,
        run,
        session: Some(rec.session),
        kind: ModelDecisionKind::Rank,
        mode: rec.mode,
        provider: rec.model.provider.clone(),
        model: rec.model.model.clone(),
        model_version: rec.model.checkpoint_digest.clone(),
        calibration_version: (!rec.model.calibration_version.is_empty())
            .then(|| rec.model.calibration_version.clone()),
        confidence,
        output: serde_json::json!({
            "decisionIndex": rec.decision_index,
            "shortlist": rec.shortlist.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "probs": rec.probs,
            "none": rec.none_p,
            "selected": rec.selected.map(|s| s.to_string()),
            "deterministicTop": rec.deterministic_top.map(|s| s.to_string()),
            "agrees": rec.agrees(),
        }),
        prompt_digest: rec.prompt_digest,
        latency_ms: Some(u32::try_from(rec.latency_ms).unwrap_or(u32::MAX)),
        breaker_state: None,
        created_at: at,
    }
}

/// Rolling calibration windows of the System 1 models in this process, one per provider and
/// model. A model whose calibration version changes starts a fresh window: a new fit is judged on
/// its own outcomes, not on the previous fit's.
static CALIBRATION: LazyLock<Mutex<CalibrationWindows>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Calibration windows keyed by `(provider, model)`, each with the calibration version it
/// belongs to.
type CalibrationWindows = BTreeMap<(String, String), (String, DriftMonitor)>;

/// Run `f` on the model's window; the reading afterwards and whether the window was just reset.
fn with_window<R>(model: &ModelId, f: impl FnOnce(&mut DriftMonitor) -> R) -> (R, DriftReading, bool) {
    let mut windows = CALIBRATION.lock();
    let slot = windows
        .entry((model.provider.clone(), model.model.clone()))
        .or_insert_with(|| (model.calibration_version.clone(), DriftMonitor::default()));
    let reset = slot.0 != model.calibration_version;
    if reset {
        *slot = (model.calibration_version.clone(), DriftMonitor::default());
    }
    let out = f(&mut slot.1);
    (out, slot.1.reading(), reset)
}

/// Publish a window: the ECE gauge exists only while the window is mature, so a young or reset
/// window never reports (or keeps reporting) a number it cannot back.
fn publish_calibration(model: &ModelId, reading: &DriftReading, reset: bool) {
    let labels = [
        ("provider", model.provider.as_str()),
        ("model", model.model.as_str()),
    ];
    let m = Metrics::global();
    if reset {
        m.gauge(names::MODEL_CALIBRATION_ECE).remove(&labels);
    }
    m.gauge(names::MODEL_CALIBRATION_SAMPLES)
        .set(u32::try_from(reading.graded).map_or(f64::MAX, f64::from), &labels);
    if let Some(ece) = reading.ece {
        m.gauge(names::MODEL_CALIBRATION_ECE).set(ece, &labels);
    }
    if let Some(rate) = reading.abstention_rate {
        m.gauge(names::MODEL_ABSTENTION_RATE).set(rate, &labels);
    }
}

/// Record one graded outcome of a model decision: the calibrated probability of the option the
/// model ranked first and whether that option turned out right. The outcome enters the model's
/// rolling window, and `crawlx.model.calibration.ece` follows once the window is mature (a window
/// above the 0.05 release ceiling raises `CrawlxModelCalibrationDrift`).
///
/// Only an outcome that was actually observed belongs here; agreement with the deterministic
/// leader is not an outcome.
///
/// # Errors
/// [`ModelError::Calibration`] for a confidence that is not a probability; nothing is recorded.
pub fn record_calibration_outcome(
    model: &ModelId,
    confidence: f32,
    correct: bool,
) -> Result<DriftReading, ModelError> {
    let (result, reading, reset) = with_window(model, |window| window.observe_outcome(confidence, correct));
    result?;
    publish_calibration(model, &reading, reset);
    Ok(reading)
}

/// Record that the gate accepted or abstained on one decision (`crawlx.model.abstention.rate`).
/// Every flushed System 1 record does this through [`decision_record`].
pub fn record_gate_decision(model: &ModelId, abstained: bool) {
    let ((), reading, reset) = with_window(model, |window| window.observe_decision(abstained));
    publish_calibration(model, &reading, reset);
}

/// The model's current calibration window, `None` before its first decision or outcome.
#[must_use]
pub fn calibration_reading(model: &ModelId) -> Option<DriftReading> {
    let windows = CALIBRATION.lock();
    let (version, window) = windows.get(&(model.provider.clone(), model.model.clone()))?;
    (*version == model.calibration_version).then(|| window.reading())
}

/// Emit the metrics of one System 1 call: `outcome` is `ok` when the gate accepted a
/// candidate and `abstain` otherwise.
fn observe_decision(rec: &System1Record) {
    let m = Metrics::global();
    let provider = rec.model.provider.as_str();
    let model = rec.model.model.as_str();
    let mode = system1_mode_label(rec.mode);
    let abstained = rec.selected.is_none();
    record_gate_decision(&rec.model, abstained);
    m.counter(names::MODEL_REQUESTS).inc_by(
        1,
        &[
            ("provider", provider),
            ("model", model),
            ("mode", mode),
            ("outcome", if abstained { "abstain" } else { "ok" }),
        ],
    );
    if abstained {
        m.counter(names::MODEL_ABSTENTIONS)
            .inc_by(1, &[("provider", provider), ("model", model), ("mode", mode)]);
    }
    m.histogram(names::MODEL_LATENCY).observe_duration(
        Duration::from_millis(rec.latency_ms),
        &[("provider", provider), ("model", model)],
    );
    m.histogram(names::MODEL_SHORTLIST_SIZE).observe_with(
        u32::try_from(rec.shortlist.len()).map_or(f64::MAX, f64::from),
        &[("mode", mode)],
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn mock_services(ceiling: System1Mode) -> ModelServices {
        ModelServices::from_config(
            Some(&ModelConfig {
                engine: EngineConfig::Mock,
                mode: ceiling,
            }),
            None,
            &Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        )
        .unwrap()
    }

    #[test]
    fn the_request_can_ask_for_less_than_the_ceiling_never_more() {
        let s = mock_services(System1Mode::Shadow);
        assert_eq!(s.system1_mode(System1Mode::Advisory), System1Mode::Shadow);
        assert_eq!(s.system1_mode(System1Mode::Shadow), System1Mode::Shadow);
        assert_eq!(s.system1_mode(System1Mode::Off), System1Mode::Off);
        let s = mock_services(System1Mode::Advisory);
        assert_eq!(s.system1_mode(System1Mode::Advisory), System1Mode::Advisory);
    }

    #[test]
    fn without_an_engine_system1_is_off_and_without_a_planner_so_is_the_planner() {
        let s = ModelServices::none();
        assert_eq!(s.system1_mode(System1Mode::Advisory), System1Mode::Off);
        assert_eq!(s.planner_mode(LlmPlannerMode::Enabled), LlmPlannerMode::Off);
    }

    #[test]
    fn model_authority_without_g3_is_rejected_at_construction() {
        for mode in [System1Mode::Advisory, System1Mode::Active] {
            let err = ModelServices::from_config(
                Some(&ModelConfig {
                    engine: EngineConfig::Mock,
                    mode,
                }),
                None,
                &Gates::none(),
            )
            .unwrap_err();
            assert!(err.to_string().contains("G3"), "{err}");
        }
    }

    #[test]
    fn active_mode_needs_evidence_not_only_a_status_flag() {
        let err = ModelServices::from_config(
            Some(&ModelConfig {
                engine: EngineConfig::Mock,
                mode: System1Mode::Active,
            }),
            None,
            &Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        )
        .unwrap_err();
        assert!(err.to_string().contains("authenticated G3 evidence"), "{err}");
    }

    #[test]
    fn authenticated_g3_allows_active_model_and_strategy_construction() {
        use crawlx_strategies::registry::{G3Report, Gate, GateFile, GateKeys};

        let dir = tempfile::tempdir().unwrap();
        let keys = GateKeys::parse(&format!("test {}\n", "42".repeat(32))).unwrap();
        let report = serde_json::to_vec(&G3Report {
            calibration_samples: 10_000,
            ece: 0.03,
            seeds: 5,
            coverage_gain_ci_low: 0.01,
            unauthorized_action_rate: 0.0,
            warm_p95_ms: 50.0,
            consecutive_nightly_improvements: 2,
        })
        .unwrap();
        let file = GateFile::signed(Gate::G3, &report, "test-commit", "2026-11-04", &keys, "test").unwrap();
        std::fs::write(dir.path().join(Gate::G3.file_name()), file.to_toml().unwrap()).unwrap();
        std::fs::write(dir.path().join(Gate::G3.report_name()), &report).unwrap();
        let gates = Gates::load_with_keys(dir.path(), &keys);
        let mut crawl = crawlx_core::CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.dynamic.system1_mode = System1Mode::Active;
        let mut worker = crate::WorkerConfig {
            gates: gates.clone(),
            ..crate::WorkerConfig::default()
        };
        assert!(worker
            .check_gates(&crawl)
            .unwrap_err()
            .to_string()
            .contains("configured Active model"));
        worker.model = Some(ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Shadow,
        });
        assert!(
            worker.check_gates(&crawl).is_err(),
            "Active cannot silently degrade to Shadow"
        );
        worker.model = Some(ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Active,
        });
        assert!(worker.check_gates(&crawl).is_ok());
        assert_eq!(
            crate::WorkerConfig::default().gates.status(),
            crawlx_core::gates::GateStatus::NONE
        );
        let services = ModelServices::from_config(
            Some(&ModelConfig {
                engine: EngineConfig::Mock,
                mode: System1Mode::Active,
            }),
            None,
            &gates,
        )
        .unwrap();
        assert_eq!(services.system1_mode(System1Mode::Active), System1Mode::Active);
        let dynamic = Dynamic {
            system1_mode: System1Mode::Active,
            strategies: vec![StrategyName::System1],
            ..Dynamic::default()
        };
        let set = services.extend(Vec::new(), &dynamic, None, false);
        assert!(set.system1);
        assert_eq!(set.strategies.len(), 1);
        assert!(set.overlay.records.is_some());
    }

    #[test]
    fn a_missing_key_variable_is_a_config_error_that_never_prints_a_key() {
        let err = ModelServices::from_config(
            None,
            Some(&PlannerConfig {
                base_url: "http://127.0.0.1:1/".to_owned(),
                api_key_env: Some("CRAWLX_TEST_SURELY_UNSET_KEY".to_owned()),
                timeout_ms: 100,
            }),
            &Gates::none(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("CRAWLX_TEST_SURELY_UNSET_KEY"));
    }

    #[test]
    fn a_malformed_endpoint_is_a_config_error() {
        let err = ModelServices::from_config(
            Some(&ModelConfig {
                engine: EngineConfig::DecisionHttp {
                    base_url: "not a url".to_owned(),
                    api_key_env: None,
                    timeout_ms: 100,
                },
                mode: System1Mode::Shadow,
            }),
            None,
            &Gates::none(),
        )
        .unwrap_err();
        assert!(matches!(err, WorkerError::Config(_)));
    }

    #[test]
    fn system1_needs_the_strategy_a_mode_and_an_engine() {
        let services = mock_services(System1Mode::Shadow);
        let mut dynamic = Dynamic {
            system1_mode: System1Mode::Shadow,
            ..Dynamic::default()
        };
        // listed neither: nothing
        let none = services.extend(Vec::new(), &dynamic, None, false);
        assert!(none.strategies.is_empty() && !none.system1);
        dynamic.strategies.push(StrategyName::System1);
        let set = services.extend(Vec::new(), &dynamic, None, false);
        assert_eq!(set.strategies.len(), 1);
        assert!(set.system1 && set.overlay.records.is_some());
        dynamic.system1_mode = System1Mode::Off;
        assert!(services
            .extend(Vec::new(), &dynamic, None, false)
            .strategies
            .is_empty());
    }

    fn ece_gauge(model: &ModelId) -> Option<f64> {
        Metrics::global()
            .gauge(names::MODEL_CALIBRATION_ECE)
            .get(&[("provider", &model.provider), ("model", &model.model)])
    }

    /// Ten outcomes per confidence tenth in `tenths`, `c * 10` of them right: ECE of zero.
    fn feed_calibrated(model: &ModelId, rounds: usize) {
        for round in 0..rounds {
            for tenths in [6_usize, 8, 10] {
                #[allow(clippy::cast_precision_loss)]
                let confidence = tenths as f32 / 10.0;
                record_calibration_outcome(model, confidence, round % 10 < tenths).unwrap();
            }
        }
    }

    #[test]
    fn synthetic_outcomes_push_the_published_ece_over_the_ceiling_and_back() {
        let model = ModelId::new("drift-test", "ranker-a", "", "fit-1");
        // a young window publishes no ECE: 150 outcomes are below the 200 minimum
        feed_calibrated(&model, 50);
        assert_eq!(ece_gauge(&model), None);
        assert_eq!(calibration_reading(&model).unwrap().graded, 150);
        // calibrated outcomes read as calibrated
        feed_calibrated(&model, 100);
        let calibrated = ece_gauge(&model).unwrap();
        assert!(calibrated < 0.05, "{calibrated}");
        // the model turns overconfident: answers at 0.9, right six times in ten
        for i in 0..1000 {
            record_calibration_outcome(&model, 0.9, i % 10 < 6).unwrap();
        }
        let drifted = ece_gauge(&model).unwrap();
        assert!(drifted > 0.05, "{drifted}");
        assert!(calibration_reading(&model).unwrap().drifted());
        // a malformed confidence is refused and leaves the published value alone
        assert!(record_calibration_outcome(&model, 1.5, true).is_err());
        assert_eq!(ece_gauge(&model), Some(drifted));
        // recovery fills the window with calibrated outcomes again
        feed_calibrated(&model, 400);
        assert!(ece_gauge(&model).unwrap() < 0.05);
    }

    #[test]
    fn a_new_calibration_version_starts_a_fresh_window_and_retires_the_stale_gauge() {
        let first = ModelId::new("drift-test", "ranker-b", "", "fit-1");
        for i in 0..300 {
            record_calibration_outcome(&first, 0.95, i % 2 == 0).unwrap();
        }
        assert!(ece_gauge(&first).unwrap() > 0.05);
        let refit = ModelId::new("drift-test", "ranker-b", "", "fit-2");
        record_calibration_outcome(&refit, 0.95, true).unwrap();
        assert_eq!(
            ece_gauge(&refit),
            None,
            "the old fit's number must not describe the new one"
        );
        assert_eq!(calibration_reading(&refit).unwrap().graded, 1);
        assert!(calibration_reading(&first).is_none());
    }

    #[test]
    fn gate_decisions_publish_the_abstention_rate() {
        let model = ModelId::new("drift-test", "ranker-c", "", "fit-1");
        for abstained in [true, false, false, false] {
            record_gate_decision(&model, abstained);
        }
        let rate = Metrics::global()
            .gauge(names::MODEL_ABSTENTION_RATE)
            .get(&[("provider", "drift-test"), ("model", "ranker-c")]);
        assert_eq!(rate, Some(0.25));
    }
}
