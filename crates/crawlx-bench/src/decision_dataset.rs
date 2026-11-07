//! The shortlist dataset of the typed ranker.
//!
//! Every System 1 round of a gym crawl is one *decision*: the shortlist exactly as
//! `crawlx-model` renders it for the ranker (context string plus one text per row, row 0 being
//! the `none of these` alternative), the shortlist's action-context ids in the deterministic
//! pre-score order, the action that was executed, and the outcome of that action: did it
//! exercise a new trusted action-context key, expose new keys, or produce a new state cluster
//! or network operation. Schema v2 adds the driver's `firstTrusted` to its discovery gain.
//! The driver emits `shortlist` and `shortlist_outcome` when recording is enabled;
//! [`rows_from_events`] joins them without relabelling historical v1 shards.
//!
//! Only the executed action has an outcome at its own decision. To label the rest of the
//! shortlist, every candidate carries its *hindsight* outcome: the gain of its first successful
//! execution at or after the decision, in the same session (`null` when the run never executed
//! it, which leaves the candidate unlabelled). With the exploration draw of
//! [`ShortlistRecording::uniform_exploration`] the logged pick is independent of deterministic
//! rank. Hindsight remains censored and time-dependent; direct outcomes and propensities are
//! retained for unbiased evaluation rather than treating unseen candidates as negatives.
//!
//! Splits are by fixture family, never by row: a family is a gym fixture, which
//! is a separately generated site with its own markup, names and controls. [`SplitPlan`] assigns
//! whole families to `train`, `val` (early stopping and temperature fit) and `test` (final
//! metrics, never used to choose anything), deterministically from the family id.

use crate::ablation;
use crate::error::BenchError;
use crate::gym::manifest::FixtureManifest;
use crate::gym::server::GymHandle;
use crate::worker_exec::{crawl_request, worker_config};
use crawlx_core::config::{SafetyProfile, System1Mode};
use crawlx_core::hash::Digest;
use crawlx_core::repo::RunEvent;
use crawlx_storage::MemoryStore;
use crawlx_worker::{
    run_local_with, DriverConfig, EngineConfig, LocalRun, ModelConfig, ShortlistRecording, Stores,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

/// Schema tag for trusted-coverage plus discovery novelty labels.
pub const SCHEMA: &str = "decision-dataset/v2";

/// Historical discovery-only labels; never silently upgraded to [`SCHEMA`].
pub const LEGACY_SCHEMA: &str = "decision-dataset/v1";

/// What executing the chosen action exposed, as the driver measured it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Outcome {
    /// The browser performed the action.
    pub succeeded: bool,
    /// The action led to a state cluster the session had not visited before.
    pub new_cluster: bool,
    /// The action produced a network operation never seen before.
    pub new_operation: bool,
    /// Action-context keys the after-observation registered for the first time.
    pub new_keys: u64,
    /// Whether this action first exercised its key through the trusted UI lane.
    /// Absent only in historical discovery-only records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_trusted: Option<bool>,
    /// Discovery gain plus `first_trusted` in v2; unchanged discovery gain in v1.
    pub gain: u64,
}

/// The outcome of a candidate's first successful execution at or after a decision.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Hindsight {
    /// Decision index at which the candidate was executed.
    pub decision: u64,
    /// Novelty gain of that execution.
    pub gain: u64,
}

/// One labelled shortlist decision.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct DatasetRow {
    /// [`SCHEMA`].
    pub schema: String,
    /// Gym fixture the run crawled.
    pub fixture: String,
    /// Fixture family (see [`family_of`]).
    pub family: String,
    /// Crawl seed.
    pub seed: u64,
    /// Run id.
    pub run: String,
    /// Session id.
    pub session: String,
    /// Decision index inside the session.
    pub decision: u64,
    /// Context string the ranker tokenizes with every row.
    pub context: String,
    /// Row texts: `rows[0]` is `none of these`, `rows[i]` the candidate `i - 1`.
    pub rows: Vec<String>,
    /// Action-context id of every candidate, in the deterministic pre-score order.
    pub ids: Vec<String>,
    /// Index into `ids` of the executed action; `None` when it was not on the shortlist.
    pub chosen: Option<usize>,
    /// Probability of the logged pick under the logging policy (uniform exploration).
    pub propensity: Option<f64>,
    /// The pick was a uniform draw from the shortlist rather than the arbiter's choice.
    pub explored: bool,
    /// Outcome of the executed action, when it ran.
    pub outcome: Option<Outcome>,
    /// Per candidate: the outcome of its first execution at or after this decision.
    pub hindsight: Vec<Option<Hindsight>>,
    /// `train`, `val` or `test`; absent in the raw shards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<String>,
}

impl DatasetRow {
    /// Labels per candidate: `Some(true)` novel, `Some(false)` executed without gain, `None`
    /// never executed.
    #[must_use]
    pub fn labels(&self) -> Vec<Option<bool>> {
        self.hindsight.iter().map(|h| h.map(|h| h.gain > 0)).collect()
    }

    /// Candidates with a label.
    #[must_use]
    pub fn labelled(&self) -> usize {
        self.hindsight.iter().flatten().count()
    }
}

/// The family of `fixture`: the fixture itself.
#[must_use]
pub fn family_of(fixture: &str) -> &str {
    fixture
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShortlistEvent {
    decision_index: u64,
    session_id: String,
    context: String,
    rows: Vec<String>,
    ids: Vec<String>,
    chosen_index: Option<usize>,
    propensity: Option<f64>,
    #[serde(default)]
    explored: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OutcomeEvent {
    decision_index: u64,
    session_id: String,
    context_id: String,
    succeeded: bool,
    new_cluster: bool,
    new_operation: bool,
    new_keys: u64,
    gain: u64,
    first_trusted: bool,
}

impl OutcomeEvent {
    fn coverage_gain(&self) -> u64 {
        // A first trusted exercise grows covered K even when the UI exposes nothing new.
        // This is outcome supervision only, never a feature available to the ranker.
        self.gain
            .saturating_add(u64::from(self.first_trusted && self.succeeded))
    }
}

/// Join the `shortlist` and `shortlist_outcome` events of one run into dataset rows, in event
/// order. A shortlist with fewer than two candidates or with rows that do not match its ids is
/// skipped.
#[must_use]
pub fn rows_from_events(fixture: &str, seed: u64, run: &str, events: &[RunEvent]) -> Vec<DatasetRow> {
    let mut shortlists = Vec::new();
    let mut outcomes: BTreeMap<String, Vec<OutcomeEvent>> = BTreeMap::new();
    for e in events {
        match e.kind.as_str() {
            "shortlist" => {
                if let Ok(s) = serde_json::from_value::<ShortlistEvent>(e.payload.clone()) {
                    shortlists.push(s);
                }
            }
            "shortlist_outcome" => {
                if let Ok(o) = serde_json::from_value::<OutcomeEvent>(e.payload.clone()) {
                    outcomes.entry(o.session_id.clone()).or_default().push(o);
                }
            }
            _ => {}
        }
    }
    let mut rows = Vec::with_capacity(shortlists.len());
    for s in shortlists {
        if s.ids.len() < 2 || s.rows.len() != s.ids.len() + 1 {
            continue;
        }
        let empty = Vec::new();
        let session_outcomes = outcomes.get(&s.session_id).unwrap_or(&empty);
        let later: Vec<&OutcomeEvent> = session_outcomes
            .iter()
            .filter(|o| o.decision_index >= s.decision_index && o.succeeded)
            .collect();
        let hindsight: Vec<Option<Hindsight>> = s
            .ids
            .iter()
            .map(|id| {
                later.iter().find(|o| o.context_id == *id).map(|o| Hindsight {
                    decision: o.decision_index,
                    gain: o.coverage_gain(),
                })
            })
            .collect();
        let chosen = s.chosen_index.filter(|i| *i < s.ids.len());
        let outcome = chosen.and_then(|i| {
            session_outcomes
                .iter()
                .find(|o| o.decision_index == s.decision_index && o.context_id == s.ids[i])
                .map(|o| Outcome {
                    succeeded: o.succeeded,
                    new_cluster: o.new_cluster,
                    new_operation: o.new_operation,
                    new_keys: o.new_keys,
                    first_trusted: Some(o.first_trusted),
                    gain: o.coverage_gain(),
                })
        });
        rows.push(DatasetRow {
            schema: SCHEMA.to_owned(),
            fixture: fixture.to_owned(),
            family: family_of(fixture).to_owned(),
            seed,
            run: run.to_owned(),
            session: s.session_id,
            decision: s.decision_index,
            context: s.context,
            rows: s.rows,
            ids: s.ids,
            chosen,
            propensity: s.propensity,
            explored: s.explored,
            outcome,
            hindsight,
            split: None,
        });
    }
    rows
}

/// How a collection run crawls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CollectConfig {
    /// Safety profile of the crawl request.
    pub profile: SafetyProfile,
    /// Interaction budget of each run.
    pub interactions: u32,
    /// Wall-clock limit of each run in seconds.
    pub duration_seconds: u32,
    /// Execute a seeded uniform draw from the shortlist instead of the arbiter's pick.
    pub explore: bool,
}

impl Default for CollectConfig {
    fn default() -> Self {
        Self {
            profile: SafetyProfile::TestEnvironment,
            interactions: 120,
            duration_seconds: 90,
            explore: true,
        }
    }
}

/// Crawl `manifest` once with `seed` on the live gym under the production strategy set of the
/// A10 row (A9 plus System 1 in `shadow`, so the model overlay changes nothing), recording every
/// shortlist. `artifacts` is the scratch directory of the run's artifact store.
///
/// # Errors
/// Gym, worker or store failures of the run.
pub async fn record_run(
    gym: &GymHandle,
    manifest: &FixtureManifest,
    seed: u64,
    cfg: &CollectConfig,
    artifacts: &Path,
) -> Result<Vec<DatasetRow>, BenchError> {
    let worker = worker_config(manifest, artifacts)?;
    record_run_configured(gym, manifest, seed, cfg, worker).await
}

// Authored fixtures inject their own gate status here, never into deployment evidence.
async fn record_run_configured(
    gym: &GymHandle,
    manifest: &FixtureManifest,
    seed: u64,
    cfg: &CollectConfig,
    mut worker: crawlx_worker::WorkerConfig,
) -> Result<Vec<DatasetRow>, BenchError> {
    let mut variant = ablation::find("A10")
        .ok_or_else(|| BenchError::Ablation("the ablation matrix has no A10 row".to_owned()))?;
    variant.model = System1Mode::Shadow;
    gym.reset(seed);
    let mut req = crawl_request(manifest, &gym.base_url, seed, cfg.profile)?;
    variant.apply(&mut req);
    req.limits.interactions = cfg.interactions;
    req.limits.duration_seconds = cfg.duration_seconds;
    req.limits.urls = 200;
    worker.model = Some(ModelConfig {
        engine: EngineConfig::Mock,
        mode: System1Mode::Shadow,
    });
    let mut driver = DriverConfig::default();
    driver.exploration.queue = variant.queue_cfg();
    driver.record_shortlists = Some(if cfg.explore {
        ShortlistRecording::uniform_exploration()
    } else {
        ShortlistRecording::recording_only()
    });
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), &worker.artifacts_dir)
        .await
        .map_err(|e| BenchError::Ablation(format!("stores: {e}")))?;
    let events = Arc::clone(&stores.events);
    let run = crate::worker_exec::authorize_fixture(
        LocalRun::new(req, worker).with_driver(driver).with_stores(stores),
    );
    let report = run_local_with(run).await?;
    if report.status == crawlx_core::counters::RunStatus::Failed {
        return Err(BenchError::Ablation(format!(
            "dataset fixture {} failed: {:?}",
            manifest.id, report.terminal_reason
        )));
    }
    let events = events.list_after(report.run_id, 0, u32::MAX).await?;
    Ok(rows_from_events(
        &manifest.id,
        seed,
        &report.run_id.to_string(),
        &events,
    ))
}

/// Which families go to which split.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SplitPlan {
    /// Families of the `val` split.
    pub val: BTreeSet<String>,
    /// Families of the `test` split.
    pub test: BTreeSet<String>,
}

impl SplitPlan {
    /// Assign `val_n` and `test_n` of `families` to the held-out splits, deterministically: the
    /// families are ordered by the BLAKE3 digest of their id, the first `test_n` form `test`,
    /// the next `val_n` form `val`, the rest train.
    #[must_use]
    pub fn by_digest<'a>(families: impl IntoIterator<Item = &'a str>, val_n: usize, test_n: usize) -> Self {
        let mut ordered: Vec<(Digest, &str)> = families
            .into_iter()
            .map(|f| (Digest::of("crawlx/decision-dataset/family/v1", f.as_bytes()), f))
            .collect();
        ordered.sort();
        let test = ordered
            .iter()
            .take(test_n)
            .map(|(_, f)| (*f).to_owned())
            .collect();
        let val = ordered
            .iter()
            .skip(test_n)
            .take(val_n)
            .map(|(_, f)| (*f).to_owned())
            .collect();
        Self { val, test }
    }

    /// The split of `family`.
    #[must_use]
    pub fn split_of(&self, family: &str) -> &'static str {
        if self.test.contains(family) {
            "test"
        } else if self.val.contains(family) {
            "val"
        } else {
            "train"
        }
    }
}

/// Per-split statistics written to `manifest.json`.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct SplitStats {
    /// Decisions in the split.
    pub decisions: u64,
    /// Candidates over all decisions.
    pub candidates: u64,
    /// Candidates with a hindsight label.
    pub labelled: u64,
    /// Labelled candidates with `gain > 0`.
    pub positive: u64,
    /// Decisions whose executed action was on the shortlist and ran.
    pub with_outcome: u64,
    /// Decisions whose logged pick was a uniform draw.
    pub explored: u64,
    /// Families in the split.
    pub families: BTreeSet<String>,
    /// Distinct seeds seen.
    pub seeds: BTreeSet<u64>,
    /// Decisions per fixture.
    pub per_fixture: BTreeMap<String, u64>,
    /// BLAKE3 (`crawlx/decision-dataset/file/v1`) of the split's JSONL file, hex.
    pub digest: String,
}

impl SplitStats {
    /// Fold one row in.
    pub fn add(&mut self, row: &DatasetRow) {
        self.decisions += 1;
        self.candidates += row.ids.len() as u64;
        self.labelled += row.labelled() as u64;
        self.positive += row.hindsight.iter().flatten().filter(|h| h.gain > 0).count() as u64;
        self.with_outcome += u64::from(row.outcome.is_some());
        self.explored += u64::from(row.explored);
        self.families.insert(row.family.clone());
        self.seeds.insert(row.seed);
        *self.per_fixture.entry(row.fixture.clone()).or_default() += 1;
    }
}

/// `manifest.json` of a finalized dataset.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct DatasetManifest {
    /// Label schema shared by all rows ([`SCHEMA`] or [`LEGACY_SCHEMA`]).
    pub schema: String,
    /// Statistics per split name.
    pub splits: BTreeMap<String, SplitStats>,
    /// Families of the `val` split.
    pub val_families: BTreeSet<String>,
    /// Families of the `test` split.
    pub test_families: BTreeSet<String>,
    /// Total decisions over all splits.
    pub decisions: u64,
}

/// Digest of a dataset file's bytes.
#[must_use]
pub fn file_digest(bytes: &[u8]) -> String {
    Digest::of("crawlx/decision-dataset/file/v1", bytes).to_hex()
}

/// Assign splits to `rows` (raw shards, any order), write `train.jsonl`, `val.jsonl`,
/// `test.jsonl` and `manifest.json` under `out`, and return the manifest. Rows are sorted by
/// `(fixture, seed, session, decision)` so the files do not depend on shard order.
///
/// # Errors
/// File system and JSON failures, mixed label schemas, or missing v2 outcome provenance.
pub fn write_dataset(
    out: &Path,
    mut rows: Vec<DatasetRow>,
    plan: &SplitPlan,
) -> Result<DatasetManifest, BenchError> {
    let schema = rows.first().map_or(SCHEMA, |row| row.schema.as_str());
    if !matches!(schema, SCHEMA | LEGACY_SCHEMA) || rows.iter().any(|row| row.schema != schema) {
        return Err(BenchError::Ablation(
            "dataset label schemas differ or are unsupported; collect a separate version".to_owned(),
        ));
    }
    if schema == SCHEMA
        && rows
            .iter()
            .any(|row| row.outcome.is_some_and(|o| o.first_trusted.is_none()))
    {
        return Err(BenchError::Ablation(
            "v2 dataset outcome lacks first_trusted provenance".to_owned(),
        ));
    }
    let schema = schema.to_owned();
    rows.sort_by(|a, b| {
        (&a.fixture, a.seed, &a.session, a.decision).cmp(&(&b.fixture, b.seed, &b.session, b.decision))
    });
    std::fs::create_dir_all(out).map_err(|e| BenchError::io(out, e))?;
    let mut buffers: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    let mut stats: BTreeMap<String, SplitStats> = BTreeMap::new();
    for mut row in rows {
        let split = plan.split_of(&row.family);
        row.split = Some(split.to_owned());
        stats.entry(split.to_owned()).or_default().add(&row);
        let buf = buffers.entry(split).or_default();
        serde_json::to_writer(&mut *buf, &row)?;
        buf.push(b'\n');
    }
    for split in ["train", "val", "test"] {
        let bytes = buffers.remove(split).unwrap_or_default();
        let path = out.join(format!("{split}.jsonl"));
        std::fs::write(&path, &bytes).map_err(|e| BenchError::io(&path, e))?;
        stats.entry(split.to_owned()).or_default().digest = file_digest(&bytes);
    }
    let manifest = DatasetManifest {
        schema,
        decisions: stats.values().map(|s| s.decisions).sum(),
        splits: stats,
        val_families: plan.val.clone(),
        test_families: plan.test.clone(),
    };
    let path = out.join("manifest.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest)?).map_err(|e| BenchError::io(&path, e))?;
    Ok(manifest)
}

/// Read every `*.jsonl` shard directly under `dir` (sorted by name).
///
/// # Errors
/// File system and JSON failures.
pub fn read_shards(dir: &Path) -> Result<Vec<DatasetRow>, BenchError> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| BenchError::io(dir, e))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    let mut rows = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| BenchError::io(&f, e))?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            rows.push(serde_json::from_str::<DatasetRow>(line)?);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn event(seq: u64, kind: &str, payload: serde_json::Value) -> RunEvent {
        RunEvent {
            seq,
            kind: kind.to_owned(),
            payload,
            at: chrono::Utc::now(),
        }
    }

    fn shortlist(decision: u64, ids: &[&str], chosen: Option<usize>) -> RunEvent {
        let mut rows = vec!["none of these".to_owned()];
        rows.extend(ids.iter().map(|i| format!("button {i} ")));
        event(
            decision,
            "shortlist",
            json!({
                "decisionIndex": decision, "sessionId": "s1", "context": "goal | route /x",
                "rows": rows, "ids": ids, "chosenIndex": chosen,
                "chosen": chosen.map(|c| ids[c]), "propensity": chosen.map(|_| 0.25),
                "explored": chosen.is_some(), "latencyMs": 1,
            }),
        )
    }

    fn outcome(decision: u64, id: &str, gain: u64, succeeded: bool) -> RunEvent {
        event(
            100 + decision,
            "shortlist_outcome",
            json!({
                "decisionIndex": decision, "sessionId": "s1", "contextId": id, "succeeded": succeeded,
                "newCluster": gain > 1, "newOperation": false, "newKeys": gain.saturating_sub(1),
                "newIdentities": 0, "revealed": 0, "firstTrusted": false, "gain": gain,
            }),
        )
    }

    #[test]
    fn events_join_into_hindsight_labels() {
        let events = vec![
            shortlist(1, &["a", "b", "c"], Some(1)),
            outcome(1, "b", 3, true),
            shortlist(2, &["a", "c", "d"], Some(0)),
            outcome(2, "a", 0, true),
            shortlist(3, &["c", "d"], None),
            outcome(3, "d", 2, false),
            outcome(4, "c", 1, true),
        ];
        let rows = rows_from_events("g01", 7, "run-1", &events);
        assert_eq!(rows.len(), 3);
        let r1 = &rows[0];
        assert_eq!((r1.chosen, r1.propensity), (Some(1), Some(0.25)));
        assert_eq!(r1.outcome.map(|o| o.gain), Some(3));
        // a was executed at decision 2 (gain 0), b at decision 1 (gain 3), c at decision 4 (gain 1)
        assert_eq!(
            r1.hindsight,
            vec![
                Some(Hindsight { decision: 2, gain: 0 }),
                Some(Hindsight { decision: 1, gain: 3 }),
                Some(Hindsight { decision: 4, gain: 1 }),
            ]
        );
        assert_eq!(r1.labels(), vec![Some(false), Some(true), Some(true)]);
        let r2 = &rows[1];
        assert_eq!(r2.outcome.map(|o| (o.gain, o.succeeded)), Some((0, true)));
        assert_eq!(
            r2.hindsight[2], None,
            "d was only attempted, never executed successfully"
        );
        let r3 = &rows[2];
        assert_eq!((r3.chosen, r3.outcome), (None, None));
        assert_eq!(r3.hindsight[0], Some(Hindsight { decision: 4, gain: 1 }));
        assert_eq!(
            r3.hindsight[1], None,
            "a failed execution leaves the candidate unlabelled"
        );
        assert!(rows
            .iter()
            .all(|r| r.schema == SCHEMA && r.family == "g01" && r.seed == 7));
    }

    #[test]
    fn first_trusted_coverage_is_positive_without_discovery() {
        let mut first = outcome(1, "a", 0, true);
        first.payload["firstTrusted"] = json!(true);
        let events = vec![
            shortlist(1, &["a", "b"], Some(0)),
            first,
            shortlist(2, &["a", "b"], Some(0)),
            outcome(2, "a", 0, true),
        ];
        let rows = rows_from_events("g01", 7, "r", &events);
        assert_eq!(rows[0].schema, "decision-dataset/v2");
        assert_eq!(rows[0].labels(), vec![Some(true), None]);
        assert_eq!(rows[0].outcome.unwrap().first_trusted, Some(true));
        assert_eq!(rows[0].outcome.unwrap().new_keys, 0);
        assert_eq!(rows[1].labels(), vec![Some(false), None]);
        assert_eq!(rows[1].outcome.unwrap().first_trusted, Some(false));
    }

    #[test]
    fn missing_first_trusted_never_fabricates_new_coverage() {
        let mut old = outcome(1, "a", 0, true);
        old.payload.as_object_mut().unwrap().remove("firstTrusted");
        let rows = rows_from_events("g01", 7, "r", &[shortlist(1, &["a", "b"], Some(0)), old]);
        assert_eq!(rows[0].outcome, None);
        assert_eq!(rows[0].labels(), vec![None, None]);
    }

    #[test]
    fn finalization_preserves_legacy_labels_and_rejects_mixed_versions() {
        let events = [shortlist(1, &["a", "b"], Some(0)), outcome(1, "a", 0, true)];
        let mut rows = rows_from_events("g01", 7, "r", &events);
        let current = rows[0].clone();
        rows[0].schema = LEGACY_SCHEMA.to_owned();
        rows[0].outcome.as_mut().unwrap().first_trusted = None;
        let dir = tempfile::tempdir().unwrap();
        let plan = SplitPlan::by_digest(["g01"], 0, 0);
        let manifest = write_dataset(dir.path(), rows.clone(), &plan).unwrap();
        assert_eq!(manifest.schema, LEGACY_SCHEMA);
        assert_eq!(
            read_shards(dir.path()).unwrap()[0].labels(),
            vec![Some(false), None]
        );
        rows.push(current);
        assert!(write_dataset(dir.path(), rows, &plan).is_err());
    }

    #[test]
    fn failed_actions_do_not_gain_first_trusted_coverage() {
        let mut failed = outcome(1, "a", 0, false);
        failed.payload["firstTrusted"] = json!(true);
        let rows = rows_from_events("g01", 7, "r", &[shortlist(1, &["a", "b"], Some(0)), failed]);
        assert_eq!(rows[0].outcome.unwrap().gain, 0);
        assert_eq!(rows[0].labels(), vec![None, None]);
    }

    #[test]
    fn malformed_shortlists_are_skipped() {
        let bad = event(
            1,
            "shortlist",
            json!({
                "decisionIndex": 1, "sessionId": "s1", "context": "c", "rows": ["none of these", "x"],
                "ids": ["a", "b"], "chosenIndex": null, "chosen": null, "propensity": null, "explored": false,
            }),
        );
        let single = event(
            2,
            "shortlist",
            json!({
                "decisionIndex": 2, "sessionId": "s1", "context": "c", "rows": ["none of these", "x"],
                "ids": ["a"], "chosenIndex": null, "chosen": null, "propensity": null, "explored": false,
            }),
        );
        assert!(rows_from_events("g01", 1, "r", &[bad, single]).is_empty());
    }

    #[test]
    fn split_plan_is_deterministic_disjoint_and_family_level() {
        let families = [
            "g01", "g02", "g06", "g13", "g20", "g24", "g26", "d1", "s1", "a2", "g12",
        ];
        let plan = SplitPlan::by_digest(families.iter().copied(), 2, 5);
        assert_eq!((plan.test.len(), plan.val.len()), (5, 2));
        assert!(plan.test.is_disjoint(&plan.val));
        assert_eq!(plan, SplitPlan::by_digest(families.iter().rev().copied(), 2, 5));
        let train = families.iter().filter(|f| plan.split_of(f) == "train").count();
        assert_eq!(train, families.len() - 7);
    }

    #[test]
    fn write_dataset_splits_by_family_and_is_order_independent() {
        let row = |fixture: &str, seed: u64, decision: u64| DatasetRow {
            schema: SCHEMA.to_owned(),
            fixture: fixture.to_owned(),
            family: family_of(fixture).to_owned(),
            seed,
            run: "r".to_owned(),
            session: "s".to_owned(),
            decision,
            context: "c".to_owned(),
            rows: vec!["none of these".into(), "a".into(), "b".into()],
            ids: vec!["a".into(), "b".into()],
            chosen: Some(0),
            propensity: Some(0.5),
            explored: true,
            outcome: Some(Outcome {
                succeeded: true,
                new_cluster: true,
                new_operation: false,
                new_keys: 1,
                first_trusted: Some(false),
                gain: 2,
            }),
            hindsight: vec![Some(Hindsight { decision, gain: 2 }), None],
            split: None,
        };
        let plan = SplitPlan {
            val: BTreeSet::from(["g02".to_owned()]),
            test: BTreeSet::from(["g03".to_owned()]),
        };
        let a = vec![
            row("g01", 1, 1),
            row("g02", 1, 1),
            row("g03", 2, 5),
            row("g01", 1, 2),
        ];
        let mut b = a.clone();
        b.reverse();
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let m1 = write_dataset(d1.path(), a, &plan).unwrap();
        let m2 = write_dataset(d2.path(), b, &plan).unwrap();
        assert_eq!(m1, m2);
        assert_eq!(m1.decisions, 4);
        assert_eq!(m1.splits["train"].decisions, 2);
        assert_eq!(m1.splits["val"].families, BTreeSet::from(["g02".to_owned()]));
        assert_eq!(m1.splits["test"].seeds, BTreeSet::from([2]));
        assert_eq!((m1.splits["train"].labelled, m1.splits["train"].positive), (2, 2));
        let back = read_shards(d1.path()).unwrap();
        assert_eq!(back.len(), 4, "train, val and test files all read back");
        assert!(back
            .iter()
            .all(|r| r.split.as_deref() == Some(plan.split_of(&r.family))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn browser_collection_preserves_exploration_labels_and_family_isolation() {
        if crawlx_browser::launch::find_executable().is_none() {
            return;
        }
        let gym = crate::gym::GymServer::start("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let cfg = CollectConfig {
            interactions: 40,
            duration_seconds: 45,
            ..CollectConfig::default()
        };
        let mut collected = Vec::new();
        for fixture in ["g21", "g04"] {
            let manifest = FixtureManifest::embedded(fixture).unwrap();
            let artifacts = scratch.path().join(fixture);
            let mut worker = worker_config(&manifest, &artifacts).unwrap();
            worker.gates =
                crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus { g1: true, g3: false });
            let rows = record_run_configured(&gym, &manifest, 1001, &cfg, worker)
                .await
                .unwrap();
            assert!(
                rows.iter().any(|row| {
                    row.explored
                        && row.chosen.is_some()
                        && row.propensity.is_some_and(|p| p > 0.0 && p <= 1.0)
                        && row.outcome.as_ref().is_some_and(|outcome| outcome.succeeded)
                }),
                "{fixture}: no successful propensity-labelled exploration"
            );
            assert!(
                rows.iter()
                    .any(|row| row.hindsight.iter().flatten().any(|label| label.gain > 0)),
                "{fixture}: no positive observed hindsight"
            );
            assert!(rows
                .iter()
                .all(|row| row.fixture == fixture && row.family == fixture));
            collected.extend(rows);
        }
        let plan = SplitPlan {
            val: BTreeSet::from(["g04".to_owned()]),
            test: BTreeSet::from(["g21".to_owned()]),
        };
        let out = scratch.path().join("dataset");
        write_dataset(&out, collected, &plan).unwrap();
        let restored = read_shards(&out).unwrap();
        for row in restored {
            assert_eq!(row.split.as_deref(), Some(plan.split_of(&row.family)));
            assert!(matches!(row.family.as_str(), "g04" | "g21"));
        }
        gym.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn denied_collection_returns_failure_instead_of_an_empty_success() {
        if crawlx_browser::launch::find_executable().is_none() {
            return;
        }
        let gym = crate::gym::GymServer::start("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let manifest = FixtureManifest::embedded("g21").unwrap();
        let mut worker = worker_config(&manifest, scratch.path()).unwrap();
        worker.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::default());
        let result = record_run_configured(&gym, &manifest, 1001, &CollectConfig::default(), worker).await;
        // Admission now refuses the gated strategy before a run exists (no empty success).
        assert!(
            matches!(&result, Err(BenchError::Worker(error)) if error.to_string().contains("G1")),
            "expected a G1 admission refusal, got {:?}",
            result.as_ref().err()
        );
        gym.shutdown().await;
    }
}
