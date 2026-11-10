//! The live-model rig for gate G3: worker runs on real Chromium
//! against PostgreSQL with a served model bundle as the System 1 engine.
//!
//! * [`DecisionRig`]: one PostgreSQL schema (set up as the soak harness does), the worker stores
//!   over it and the System 1 engine, a [`DecisionHttpEngine`] speaking to a `decision-serve` endpoint under
//!   the served bundle's own identity (`/health`), wrapped in a [`MeteredEngine`]. Decisions in
//!   `model_decisions` therefore carry the bundle's checkpoint digest and calibration version,
//!   and their latency is what the worker waits for over HTTP.
//! * [`RigExecutor`]: a [`VariantExecutor`] that runs an ablation row through the worker with
//!   the rig's stores and engine, optionally with shortlist recording, and keeps a
//!   [`RunCapture`] per run.
//! * [`shadow_decisions`]: the join of a run's recorded shortlists and `model_decisions` rows
//!   into the [`ShadowDecision`]s that [`crate::decision_eval::analyze_shadow`] analyses.
//! * [`paired_runs`]: the paired A9-vs-A10 protocol as [`PairedRun`]s.

use crate::ablation::{AblationVariant, Executed, VariantExecutor};
use crate::decision_dataset::{rows_from_events, DatasetRow};
use crate::decision_eval::{MeteredEngine, PairedRun, ShadowDecision};
use crate::error::BenchError;
use crate::gym::manifest::FixtureManifest;
use crate::gym::server::GymHandle;
use crate::scorecard::Scorecard;
use crate::soak::loopback_record;
use crate::trail::{verify_trail, TrailStore};
use crate::worker_exec::{crawl_request, rows_from_report, worker_config};
use async_trait::async_trait;
use crawlx_core::config::{SafetyProfile, System1Mode};
use crawlx_core::counters::ActionStatus;
use crawlx_core::repo::{ModelDecisionKind, ModelDecisionRecord, RunRepo};
use crawlx_core::SystemClock;
use crawlx_model::breaker::BreakerState;
use crawlx_model::decision_http::{DecisionHttpConfig, DecisionHttpEngine};
use crawlx_model::{DecisionEngine, ModelError, ModelId, TypedAnswer, TypedDecision, TypedDecisionRequest};
use crawlx_policy::authorization::AuthorizationRecord;
use crawlx_storage::{FsArtifactStore, Pg, PgConfig};
use crawlx_worker::{
    run_local_with, DriverConfig, EngineConfig, LocalRun, ModelConfig, ProvidedEngine, ShortlistRecording,
    Stores,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Probability the [`ForcedChoice`] wrapper puts on the model's top candidate.
const FORCED_TOP_P: f32 = 0.95;

/// Stress wrapper for the safety and ablation phases: the inner model's top candidate of every
/// choice question is accepted and presented at [`FORCED_TOP_P`], the other options share the
/// rest and `none of these` gets nothing, so every confidence gate on the way (the engine's and
/// System 1's own) lets the model's pick through. In `advisory` mode the model then influences
/// every selection it is consulted on, which is the demanding setting for the safety run: the
/// shipped gate answers too rarely for the model to exercise the kernel at all. The probabilities
/// are no longer calibrated; only the model's ranking is.
pub struct ForcedChoice {
    inner: Arc<dyn DecisionEngine>,
}

impl ForcedChoice {
    /// Wrap `inner`.
    #[must_use]
    pub fn new(inner: Arc<dyn DecisionEngine>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl DecisionEngine for ForcedChoice {
    async fn decide(&self, req: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
        let mut decision = self.inner.decide(req).await?;
        for answer in &mut decision.answers {
            let TypedAnswer::Choice {
                probs,
                none_p,
                selected,
                ..
            } = answer
            else {
                continue;
            };
            let top = probs
                .iter()
                .enumerate()
                .fold(None, |best: Option<(usize, f32)>, (i, (_, p))| match best {
                    Some((_, b)) if *p <= b => best,
                    _ => Some((i, *p)),
                })
                .map(|(i, _)| i);
            let Some(top) = top else { continue };
            #[allow(clippy::cast_precision_loss)] // shortlists have at most 20 entries
            let rest = (1.0 - FORCED_TOP_P) / probs.len().saturating_sub(1).max(1) as f32;
            for (i, (_, p)) in probs.iter_mut().enumerate() {
                *p = if i == top { FORCED_TOP_P } else { rest };
            }
            *none_p = 0.0;
            *selected = probs.get(top).map(|(option, _)| *option);
        }
        decision.abstained.clear();
        Ok(decision)
    }

    fn id(&self) -> &ModelId {
        self.inner.id()
    }

    fn breaker_state(&self) -> Option<BreakerState> {
        self.inner.breaker_state()
    }
}

/// Where the rig runs and which model it asks.
#[derive(Clone, PartialEq, Debug)]
pub struct RigConfig {
    /// PostgreSQL URL; the rig creates (and on [`DecisionRig::close`] drops) its own schema.
    pub database_url: String,
    /// `http://host:port/v1/decide` of a running `decision-serve`.
    pub endpoint: String,
    /// Per-call time budget of the model engine.
    pub timeout: Duration,
    /// Wrap the engine in [`ForcedChoice`]: the model's top candidate is accepted on every decision.
    pub forced_choice: bool,
    /// Scratch directory of the artifact store.
    pub scratch: PathBuf,
}

/// The identity a `decision-serve` endpoint reports on `/health`.
#[derive(Deserialize)]
struct Health {
    provider: String,
    model: String,
    checkpoint_digest: String,
    calibration_version: String,
}

fn rig_error(what: &str, e: &dyn std::error::Error) -> BenchError {
    BenchError::Ablation(format!("{what}: {}", crate::error::chain(e)))
}

/// Identity of the model behind `endpoint` (`/v1/decide` of a `decision-serve`).
async fn served_identity(endpoint: &str) -> Result<ModelId, BenchError> {
    let mut health = url::Url::parse(endpoint)?;
    health.set_path("/health");
    health.set_query(None);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|e| rig_error("health client", &e))?;
    let body: Health = client
        .get(health.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| rig_error(&format!("GET {health}"), &e))?
        .json()
        .await
        .map_err(|e| rig_error(&format!("GET {health}"), &e))?;
    Ok(ModelId::new(
        &body.provider,
        &body.model,
        &body.checkpoint_digest,
        &body.calibration_version,
    ))
}

/// One PostgreSQL schema, the worker stores over it and the metered System 1 engine.
pub struct DecisionRig {
    pg: Pg,
    stores: Stores,
    record: AuthorizationRecord,
    engine: Arc<MeteredEngine>,
    scratch: PathBuf,
}

impl DecisionRig {
    /// Connect, migrate a fresh schema, register the authorization record for `gym` and build
    /// the engine for `cfg.endpoint`.
    ///
    /// # Errors
    /// The model endpoint is unreachable or malformed, PostgreSQL setup fails,
    /// or operator-managed checkpoint encryption is unavailable.
    pub async fn open(cfg: &RigConfig, gym: &GymHandle) -> Result<Self, BenchError> {
        let mut worker = crawlx_worker::WorkerConfig::default();
        worker
            .load_checkpoint_keys_from_lookup(&|name| std::env::var(name).ok())
            .await?;
        let keys = worker.checkpoint_keys.ok_or_else(|| {
            BenchError::Gate("durable evaluation checkpoints require CRAWLX_CHECKPOINT_KMS_KEY_ID".into())
        })?;
        Self::open_with_checkpoint_keys(cfg, gym, keys).await
    }

    /// Open an owned evaluation fixture with explicitly supplied checkpoint custody.
    /// Process-local providers cannot establish cross-process recovery or cloud acceptance.
    ///
    /// # Errors
    /// Rejects absent custody, invalid fixture/model origins, or failed model/database setup.
    pub async fn open_with_checkpoint_keys(
        cfg: &RigConfig,
        gym: &GymHandle,
        keys: Arc<dyn crawlx_storage::checkpoint_crypto::CheckpointKeys>,
    ) -> Result<Self, BenchError> {
        if !keys.is_available() {
            return Err(BenchError::Gate(
                "evaluation checkpoint encryption unavailable".into(),
            ));
        }
        let endpoint = url::Url::parse(&cfg.endpoint)?;
        if endpoint.scheme() != "http"
            || endpoint.host_str() != Some("127.0.0.1")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(BenchError::Ablation(
                "fixture evaluation requires a local controlled model endpoint".to_owned(),
            ));
        }
        let origin = gym.evaluation_origin().ok_or_else(|| {
            BenchError::Gate("decision rig requires an owned evaluation Gym listener".to_owned())
        })?;
        let identity = served_identity(&cfg.endpoint).await?;
        let mut decision = DecisionHttpConfig::new(&cfg.endpoint, identity);
        decision.guard.timeout = cfg.timeout;
        let engine: Arc<dyn DecisionEngine> = Arc::new(
            DecisionHttpEngine::for_loopback_fixture(decision).map_err(|e| rig_error("model engine", &e))?,
        );
        let engine = if cfg.forced_choice {
            Arc::new(ForcedChoice::new(engine))
        } else {
            engine
        };
        let engine = Arc::new(MeteredEngine::new(engine));

        std::fs::create_dir_all(&cfg.scratch).map_err(|e| BenchError::io(&cfg.scratch, e))?;
        let schema = format!("decision_eval_{}", uuid::Uuid::now_v7().simple());
        let pg = Pg::connect(
            &cfg.database_url,
            PgConfig {
                schema: Some(schema),
                max_connections: 8,
                ..PgConfig::default()
            },
        )
        .await?;
        pg.migrate().await?;
        let record = loopback_record(&origin.origin().ascii_serialization())?;
        pg.ensure_tenant(record.tenant, "decision-eval").await?;
        let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
        let artifacts = FsArtifactStore::open(&cfg.scratch.join("artifacts"), runs, Arc::new(SystemClock))
            .await?
            .with_index(Arc::new(pg.clone()));
        let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), record.tenant);
        stores.checkpoint_keys = keys;
        Ok(Self {
            pg,
            stores,
            record,
            engine,
            scratch: cfg.scratch.clone(),
        })
    }

    /// The metered engine every run asks.
    #[must_use]
    pub fn engine(&self) -> &Arc<MeteredEngine> {
        &self.engine
    }

    /// Identity of the served model.
    #[must_use]
    pub fn model_id(&self) -> &ModelId {
        self.engine.id()
    }

    /// The worker stores over the rig's schema.
    #[must_use]
    pub const fn stores(&self) -> &Stores {
        &self.stores
    }

    /// Drop the schema and the scratch directory.
    ///
    /// # Errors
    /// [`BenchError::Store`] when dropping the schema fails.
    pub async fn close(self) -> Result<(), BenchError> {
        let scratch = self.scratch;
        self.pg.drop_schema().await?;
        // best effort: the artifacts of finished runs are not needed again
        let _ = std::fs::remove_dir_all(scratch);
        Ok(())
    }
}

/// What one run left behind, beyond the rows the scorecard is computed from.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RunCapture {
    /// Ablation row.
    pub variant: String,
    /// Fixture.
    pub fixture: String,
    /// Actual controlled listener origin; presence marks experiment evidence, not production promotion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_origin: Option<String>,
    /// Seed.
    pub seed: u64,
    /// Run id.
    pub run: String,
    /// Executed actions: journal rows past `proposed`.
    pub executed: u64,
    /// Executed actions a model decision influenced (`actions.model_decision_id` set).
    pub influenced: u64,
    /// Discovered interactions the policy kernel rejected.
    pub policy_blocked: u64,
    /// `model_decisions` rows of the run.
    pub model_calls: u64,
    /// Rows where the confidence gate accepted a candidate.
    pub model_selected: u64,
    /// Rows without a calibration version (`calibration_version IS NULL`; must be 0).
    pub uncalibrated: u64,
    /// Violations the trail verifier found; `None` when it was not run.
    pub trail_violations: Option<u64>,
}

/// Executes ablation rows through the worker over the rig's PostgreSQL stores with the served
/// model as System 1 engine.
pub struct RigExecutor<'a> {
    rig: &'a DecisionRig,
    gym: &'a GymHandle,
    /// Safety profile of the crawl requests.
    pub profile: SafetyProfile,
    /// Interaction budget of each run.
    pub interactions: u32,
    /// Wall-clock limit of each run in seconds (the budget, not the clock, should end runs).
    pub duration_seconds: u32,
    /// Most the model may influence this controlled experiment. Off/Shadow/Advisory are
    /// supported; Active has no fixture exception, even when a caller supplies that ceiling.
    pub ceiling: System1Mode,
    /// Record shortlists (and their outcomes) and keep the joined [`ShadowDecision`]s.
    pub recording: Option<ShortlistRecording>,
    /// Run the trail verifier on every run.
    pub verify_trail: bool,
    /// Explicit authenticated gates for an operator/test harness; defaults to the deployment gate directory.
    /// A boolean G1 override cannot authorize gated strategies in a controlled experiment.
    pub gates: Option<crawlx_worker::Gates>,
    captures: Mutex<Vec<RunCapture>>,
    shadow: Mutex<Vec<ShadowDecision>>,
}

impl<'a> RigExecutor<'a> {
    /// Executor over `rig` and `gym`; `profile`, `interactions` and `duration_seconds` as given,
    /// ceiling `advisory`, no recording, no trail verification.
    #[must_use]
    pub fn new(
        rig: &'a DecisionRig,
        gym: &'a GymHandle,
        profile: SafetyProfile,
        interactions: u32,
        duration_seconds: u32,
    ) -> Self {
        Self {
            rig,
            gym,
            profile,
            interactions,
            duration_seconds,
            ceiling: System1Mode::Advisory,
            recording: None,
            verify_trail: false,
            gates: None,
            captures: Mutex::new(Vec::new()),
            shadow: Mutex::new(Vec::new()),
        }
    }

    /// The captures of the runs since the last call.
    pub fn take_captures(&self) -> Vec<RunCapture> {
        std::mem::take(&mut self.captures.lock())
    }

    /// The shadow decisions of the recorded runs since the last call.
    pub fn take_shadow(&self) -> Vec<ShadowDecision> {
        std::mem::take(&mut self.shadow.lock())
    }
}

#[async_trait]
impl VariantExecutor for RigExecutor<'_> {
    async fn execute(
        &self,
        variant: &AblationVariant,
        manifest: &FixtureManifest,
        seed: u64,
    ) -> Result<Executed, BenchError> {
        self.gym.reset(seed);
        let mut req = crawl_request(manifest, &self.gym.base_url, seed, self.profile)?;
        variant.apply(&mut req);
        req.limits.interactions = self.interactions;
        req.limits.duration_seconds = self.duration_seconds;
        req.limits.urls = 200;
        req.safety.authorization_record_ref = Some(self.rig.record.id);
        req.normalize().map_err(|errors| {
            BenchError::Ablation(
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        })?;
        let permit = self.gym.evaluation_permit(manifest, &req, &self.rig.record)?;
        let artifacts = self
            .rig
            .scratch
            .join(format!("run-{}-{}-{seed}", manifest.id, variant.id));
        let mut cfg = worker_config(manifest, &artifacts)?;
        if let Some(gates) = &self.gates {
            cfg.gates = gates.clone();
        }
        cfg.model = Some(ModelConfig {
            engine: EngineConfig::Provided(ProvidedEngine(self.rig.engine.clone())),
            mode: self.ceiling,
        });
        let mut driver = DriverConfig::default();
        driver.exploration.queue = variant.queue_cfg();
        driver.record_shortlists = self.recording;
        let local = LocalRun::new(req, cfg)
            .with_driver(driver)
            .with_stores(self.rig.stores.clone())
            .with_authorization(self.rig.record.clone())
            .with_fixture_evaluation(permit);
        let report = run_local_with(local).await;
        // best effort: the scratch artifacts of a finished run are not needed again
        let _ = std::fs::remove_dir_all(&artifacts);
        let report = report?;

        let records = self.rig.stores.model_decisions.list(report.run_id).await?;
        let trail_violations = if self.verify_trail {
            let trail = verify_trail(
                report.run_id,
                TrailStore::Pg {
                    pg: &self.rig.pg,
                    artifacts: Some(self.rig.stores.artifacts.as_ref()),
                },
            )
            .await?;
            Some(u64::try_from(trail.violations.len()).unwrap_or(u64::MAX))
        } else {
            None
        };
        if self.recording.is_some() {
            let events = self
                .rig
                .stores
                .events
                .list_after(report.run_id, 0, u32::MAX)
                .await?;
            let rows = rows_from_events(&manifest.id, seed, &report.run_id.to_string(), &events);
            self.shadow.lock().extend(shadow_decisions(&rows, &records));
        }
        self.captures.lock().push(RunCapture {
            variant: variant.id.to_owned(),
            fixture: manifest.id.clone(),
            evaluation_origin: self
                .gym
                .evaluation_origin()
                .map(|url| url.origin().ascii_serialization()),
            seed,
            run: report.run_id.to_string(),
            executed: count(
                report
                    .actions
                    .iter()
                    .filter(|a| a.status != ActionStatus::Proposed),
            ),
            influenced: count(
                report
                    .actions
                    .iter()
                    .filter(|a| a.status != ActionStatus::Proposed && a.model_decision.is_some()),
            ),
            policy_blocked: report.counters.interactions.policy_blocked,
            model_calls: count(records.iter()),
            model_selected: count(records.iter().filter(|r| r.output["selected"].is_string())),
            uncalibrated: count(records.iter().filter(|r| r.calibration_version.is_none())),
            trail_violations,
        });
        let rows = rows_from_report(&report, manifest, seed, variant.id, self.profile, self.gym);
        Ok(Executed {
            rows,
            ledger: self.gym.ledger(),
            url_counters: None,
        })
    }
}

fn count<T>(items: impl Iterator<Item = T>) -> u64 {
    u64::try_from(items.count()).unwrap_or(u64::MAX)
}

/// The paired protocol over `seeds`: for every seed run `baseline` then
/// `candidate` back to back (the executor restores the gym before each call) and score both.
/// A pair whose runs fail is returned in the second element with the failure, not dropped
/// silently.
pub async fn paired_runs(
    executor: &RigExecutor<'_>,
    baseline: &AblationVariant,
    candidate: &AblationVariant,
    manifest: &FixtureManifest,
    seeds: &[u64],
) -> (Vec<PairedRun>, Vec<(u64, String)>) {
    let mut runs = Vec::with_capacity(seeds.len());
    let mut failed = Vec::new();
    for &seed in seeds {
        let pair = async {
            let b = executor.execute(baseline, manifest, seed).await?;
            let c = executor.execute(candidate, manifest, seed).await?;
            Ok::<_, BenchError>((b, c))
        }
        .await;
        match pair {
            Ok((b, c)) => {
                let sb = Scorecard::compute(manifest, &b.rows, &b.ledger);
                let sc = Scorecard::compute(manifest, &c.rows, &c.ledger);
                runs.push(PairedRun {
                    fixture: manifest.id.clone(),
                    seed,
                    baseline: sb.coverage.trusted,
                    candidate: sc.coverage.trusted,
                    baseline_auc: sb.coverage.auc,
                    candidate_auc: sc.coverage.auc,
                    candidate_executed: count(
                        c.rows
                            .actions
                            .iter()
                            .filter(|a| a.status != ActionStatus::Proposed),
                    ),
                    candidate_unauthorized: sc.safety.unauthorized,
                    candidate_safety_executed: sc.safety.executed,
                });
            }
            Err(e) => failed.push((seed, e.chain())),
        }
    }
    (runs, failed)
}

/// Join the shortlist `rows` of one run with its `model_decisions` into shadow decisions, by
/// session and decision index. A decision without a matching `rank` record, with another
/// shortlist than the record's or with probabilities of another length is left out.
#[must_use]
pub fn shadow_decisions(rows: &[DatasetRow], records: &[ModelDecisionRecord]) -> Vec<ShadowDecision> {
    let mut by_key: BTreeMap<(String, u64), &ModelDecisionRecord> = BTreeMap::new();
    for r in records.iter().filter(|r| r.kind == ModelDecisionKind::Rank) {
        let (Some(session), Some(index)) = (r.session, r.output["decisionIndex"].as_u64()) else {
            continue;
        };
        by_key.insert((session.0.to_string(), index), r);
    }
    rows.iter()
        .filter_map(|row| {
            let rec = by_key.get(&(row.session.clone(), row.decision))?;
            let ids: Vec<&str> = rec.output["shortlist"]
                .as_array()?
                .iter()
                .map(|v| v.as_str())
                .collect::<Option<_>>()?;
            if ids.len() != row.ids.len() || ids.iter().zip(&row.ids).any(|(a, b)| *a != b.as_str()) {
                return None;
            }
            #[allow(clippy::cast_possible_truncation)] // probabilities are f32 on the wire
            let probs: Vec<f32> = rec.output["probs"]
                .as_array()?
                .iter()
                .map(|v| v.as_f64().map(|p| p as f32))
                .collect::<Option<_>>()?;
            if probs.len() != ids.len() {
                return None;
            }
            let position =
                |id: &serde_json::Value| id.as_str().and_then(|s| ids.iter().position(|i| *i == s));
            #[allow(clippy::cast_possible_truncation)]
            let none_p = rec.output["none"].as_f64().map_or(0.0, |p| p as f32);
            Some(ShadowDecision {
                fixture: row.fixture.clone(),
                run: row.run.clone(),
                probs,
                none_p,
                selected: position(&rec.output["selected"]),
                deterministic_top: position(&rec.output["deterministicTop"]).unwrap_or(0),
                executed: row.chosen,
                hindsight: row.hindsight.clone(),
                outcome: row.outcome,
                latency_ms: rec.latency_ms,
                calibration_version: rec.calibration_version.clone(),
                breaker_state: rec.breaker_state.clone(),
            })
        })
        .collect()
}

/// Directory helper for the rig's per-process scratch space.
#[must_use]
pub fn scratch_dir(root: &Path, tag: &str) -> PathBuf {
    root.join(format!("crawlx-decision-eval-{tag}-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::decision_dataset::{Hindsight, SCHEMA};
    use crawlx_core::hash::Digest;
    use crawlx_core::ids::{CrawlRunId, ModelDecisionId, SessionId};
    use serde_json::json;

    fn row(session: SessionId, decision: u64, ids: &[&str], chosen: Option<usize>) -> DatasetRow {
        let mut rows = vec!["none of these".to_owned()];
        rows.extend(ids.iter().map(|i| format!("button {i}")));
        DatasetRow {
            schema: SCHEMA.to_owned(),
            fixture: "g21".to_owned(),
            family: "g21".to_owned(),
            seed: 1,
            run: "run-1".to_owned(),
            session: session.0.to_string(),
            decision,
            context: "goal".to_owned(),
            rows,
            ids: ids.iter().map(|s| (*s).to_owned()).collect(),
            chosen,
            propensity: None,
            explored: false,
            outcome: None,
            hindsight: ids
                .iter()
                .enumerate()
                .map(|(i, _)| (i == 1).then_some(Hindsight { decision, gain: 2 }))
                .collect(),
            split: None,
        }
    }

    #[allow(clippy::cast_possible_truncation)] // test probabilities are small decimals
    fn record(
        session: SessionId,
        decision: u64,
        ids: &[&str],
        probs: &[f64],
        selected: Option<&str>,
    ) -> ModelDecisionRecord {
        ModelDecisionRecord {
            id: ModelDecisionId::new(),
            run: CrawlRunId::new(),
            session: Some(session),
            kind: ModelDecisionKind::Rank,
            mode: System1Mode::Shadow,
            provider: "onnx-ranker".to_owned(),
            model: "ranker".to_owned(),
            model_version: "abc".to_owned(),
            calibration_version: Some("cal-1".to_owned()),
            confidence: probs.iter().copied().reduce(f64::max).map(|p| p as f32),
            output: json!({
                "decisionIndex": decision,
                "shortlist": ids,
                "probs": probs,
                "none": 0.1,
                "selected": selected,
                "deterministicTop": ids[0],
            }),
            prompt_digest: Digest::of("test", b"x"),
            latency_ms: Some(7),
            breaker_state: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn decisions_join_by_session_and_index_and_map_ids_to_positions() {
        let s = SessionId::new();
        let rows = [row(s, 0, &["a", "b", "c"], Some(2)), row(s, 1, &["a", "b"], None)];
        let records = [
            record(s, 0, &["a", "b", "c"], &[0.2, 0.5, 0.2], Some("b")),
            record(s, 1, &["a", "b"], &[0.6, 0.3], None),
        ];
        let out = shadow_decisions(&rows, &records);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].selected, Some(1));
        assert_eq!(out[0].executed, Some(2));
        assert_eq!(out[0].deterministic_top, 0);
        assert_eq!(out[0].top(), Some(1));
        assert_eq!(out[0].calibration_version.as_deref(), Some("cal-1"));
        assert_eq!(out[0].latency_ms, Some(7));
        assert_eq!(out[1].selected, None);
        assert!((out[1].none_p - 0.1).abs() < 1e-6);
    }

    #[test]
    fn a_decision_is_dropped_when_the_records_disagree_with_the_shortlist() {
        let s = SessionId::new();
        let rows = [
            row(s, 0, &["a", "b"], None),
            row(s, 1, &["a", "b"], None),
            row(s, 2, &["a", "b"], None),
        ];
        let records = [
            // other id order than the dataset row
            record(s, 0, &["b", "a"], &[0.5, 0.5], None),
            // probabilities of another length
            record(s, 1, &["a", "b"], &[1.0], None),
            // another session
            record(SessionId::new(), 2, &["a", "b"], &[0.5, 0.5], None),
        ];
        assert!(shadow_decisions(&rows, &records).is_empty());
    }

    struct Fixed(TypedDecision);

    #[async_trait]
    impl DecisionEngine for Fixed {
        async fn decide(&self, _req: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
            Ok(self.0.clone())
        }

        fn id(&self) -> &ModelId {
            &self.0.model
        }
    }

    #[tokio::test]
    async fn the_forced_wrapper_accepts_the_models_top_candidate_where_the_gate_abstained() {
        use crawlx_model::{CandidateRef, TypedQuestion};
        // the model puts most of its mass on `none of these` and abstained
        let inner = TypedDecision {
            answers: vec![TypedAnswer::Choice {
                id: "next_action".to_owned(),
                probs: vec![
                    (CandidateRef(0), 0.02),
                    (CandidateRef(1), 0.05),
                    (CandidateRef(2), 0.03),
                ],
                none_p: 0.9,
                selected: None,
            }],
            abstained: vec!["next_action".to_owned()],
            latency_ms: 2,
            model: ModelId::new("onnx-ranker", "m", "d", "c"),
        };
        let forced = ForcedChoice::new(Arc::new(Fixed(inner)));
        let req = TypedDecisionRequest {
            goal: crawlx_model::provenance::Instruction::from_static("pick"),
            state: crawlx_model::provenance::ProvenanceTagged::new(
                crawlx_model::provenance::Provenance::PageText,
                crawlx_model::StateView {
                    route_template: "/x".to_owned(),
                    regions: Vec::new(),
                    candidates: Vec::new(),
                },
            ),
            questions: vec![TypedQuestion::Choice {
                id: "next_action".to_owned(),
                options: vec![CandidateRef(0), CandidateRef(1), CandidateRef(2)],
            }],
        };
        let out = forced.decide(req).await.unwrap();
        assert!(out.abstained.is_empty());
        assert_eq!(
            out.selected("next_action"),
            Some(CandidateRef(1)),
            "the model's argmax"
        );
        let Some(TypedAnswer::Choice { probs, none_p, .. }) = out.answer("next_action") else {
            panic!("choice answer expected");
        };
        assert!((probs[1].1 - FORCED_TOP_P).abs() < 1e-6);
        assert!((probs[0].1 - 0.025).abs() < 1e-6 && (probs[2].1 - 0.025).abs() < 1e-6);
        assert_eq!(*none_p, 0.0);
        assert!((probs.iter().map(|(_, p)| p).sum::<f32>() - 1.0).abs() < 1e-6);
        assert_eq!(forced.id().model, "m");
    }

    #[test]
    fn non_rank_records_are_ignored() {
        let s = SessionId::new();
        let rows = [row(s, 0, &["a", "b"], None)];
        let mut other = record(s, 0, &["a", "b"], &[0.5, 0.5], None);
        other.kind = ModelDecisionKind::Plan;
        assert!(shadow_decisions(&rows, &[other]).is_empty());
    }
}
