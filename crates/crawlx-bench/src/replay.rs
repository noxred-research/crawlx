//! Replay harness: recorded traces re-decided offline.
//!
//! A [`Trace`] is a sequence of `(snapshot, chosen action context, outcome)`. The harness
//! feeds every snapshot to a [`DecisionFn`] and compares its ranking with the recorded
//! choice (teacher forcing: the decision function is told the *recorded* choice and outcome
//! after each step, so its internal state follows the recorded trajectory). Agreement is 1.0
//! when the configuration that recorded the trace is replayed; other configurations show
//! where they would have decided differently.

use crate::ablation::AblationVariant;
use crate::error::BenchError;
use crate::policy::{Cand, PolicyFlags, PolicyState};
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::traffic::TrustLane;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Trace file schema version.
pub const TRACE_VERSION: u32 = 1;

/// A candidate control in a snapshot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct SnapshotControl {
    /// `ActionContextId` (hex) of clicking this control in the snapshot's state.
    pub context_id: String,
    /// `ElementIdentityHash` (hex).
    pub identity: String,
    /// Stable-path signature (`role|ancestor roles`), the `Z` family.
    pub family: String,
    /// Ground-truth control id, when the harness could label it.
    #[serde(default)]
    pub control: Option<String>,
    /// ARIA/native role of the control.
    pub role: String,
    /// Accessible name of the control, when it has one.
    #[serde(default)]
    pub name: Option<String>,
}

/// What the crawler saw when it decided (an `ObservationBundle` reduced to its candidates).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Snapshot {
    /// URL of the page the snapshot was taken on.
    pub url: String,
    /// Document title, when the page had one.
    #[serde(default)]
    pub title: Option<String>,
    /// Candidate controls in discovery (document) order.
    pub controls: Vec<SnapshotControl>,
}

/// What happened after the recorded action.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Outcome {
    /// Whether the recorded action succeeded.
    pub succeeded: bool,
    /// Identities (hex) that appeared and were never seen before.
    #[serde(default)]
    pub revealed: Vec<String>,
    /// Lane the action ran in.
    pub lane: TrustLane,
}

/// One recorded decision.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TraceStep {
    /// Candidates the crawler saw when it decided.
    pub snapshot: Snapshot,
    /// Recorded `ActionContextId` (hex).
    pub chosen: String,
    /// Effect of the recorded action on the page.
    pub outcome: Outcome,
}

/// A recorded exploration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Trace {
    /// Trace schema version; must equal [`TRACE_VERSION`].
    pub version: u32,
    /// Id of the fixture the trace was recorded on.
    pub fixture: String,
    /// Seed the fixture and the recording policy ran with.
    pub seed: u64,
    /// Variant (or free-form label) that recorded it.
    pub variant: String,
    /// Decisions in recorded order.
    pub steps: Vec<TraceStep>,
}

impl Trace {
    /// Parse and validate trace JSON.
    ///
    /// # Errors
    /// Malformed JSON, an unsupported version, or a step whose chosen context is not in its snapshot.
    pub fn from_json(json: &str) -> Result<Self, BenchError> {
        let t: Self = serde_json::from_str(json)?;
        if t.version != TRACE_VERSION {
            return Err(BenchError::Replay(format!(
                "unsupported trace version {} (expected {TRACE_VERSION})",
                t.version
            )));
        }
        for (i, s) in t.steps.iter().enumerate() {
            if !s.snapshot.controls.iter().any(|c| c.context_id == s.chosen) {
                return Err(BenchError::Replay(format!(
                    "step {i}: chosen context {} is not in the snapshot",
                    s.chosen
                )));
            }
        }
        Ok(t)
    }

    /// Load a trace file.
    ///
    /// # Errors
    /// I/O or parse failures.
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let text = std::fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
        Self::from_json(&text)
    }

    /// Pretty JSON.
    ///
    /// # Errors
    /// Serialization cannot fail for these types.
    pub fn to_json(&self) -> Result<String, BenchError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Anything that can rank the candidates of a snapshot: the in-crate queue policy, or the
/// production arbiter behind an adapter.
pub trait DecisionFn {
    /// Label for reports.
    fn name(&self) -> String;
    /// `context_id`s of `snapshot.controls` ranked best first.
    fn rank(&mut self, step: usize, snapshot: &Snapshot) -> Vec<String>;
    /// The recorded choice and outcome of `step` (teacher forcing).
    ///
    /// `next` is the snapshot after it (`None` for the last step), from which the outcome of
    /// the action can be read.
    fn observe(&mut self, step: usize, recorded: &TraceStep, next: Option<&Snapshot>);
}

/// Strategy configuration of the built-in decision function.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StrategyConfig {
    /// Queue-score terms that are active.
    pub flags: PolicyFlags,
    /// Seed of the tie-break hash among equally scored candidates.
    pub seed: u64,
    /// An identity is exercised at most this many times.
    pub max_layer: u32,
}

impl StrategyConfig {
    /// The configuration of an ablation row.
    #[must_use]
    pub const fn from_variant(v: &AblationVariant, seed: u64, max_layer: u32) -> Self {
        Self {
            flags: v.policy_flags(),
            seed,
            max_layer,
        }
    }
}

fn identity_of(hex: &str) -> ElementIdentityHash {
    Digest::from_hex(hex).map_or_else(
        |_| ElementIdentityHash(Digest::of("crawlx/bench/replay-identity", hex.as_bytes())),
        ElementIdentityHash,
    )
}

/// The layered-queue policy (`W + 0.3·Z + E`) as a [`DecisionFn`].
#[derive(Clone, Debug)]
pub struct QueueDecision {
    config: StrategyConfig,
    state: PolicyState,
}

impl QueueDecision {
    /// Decision function with an empty interaction history.
    #[must_use]
    pub fn new(config: StrategyConfig) -> Self {
        Self {
            config,
            state: PolicyState::default(),
        }
    }
}

impl DecisionFn for QueueDecision {
    fn name(&self) -> String {
        format!("queue(seed={}, {:?})", self.config.seed, self.config.flags)
    }

    fn rank(&mut self, _step: usize, snapshot: &Snapshot) -> Vec<String> {
        let cands: Vec<Cand<String>> = snapshot
            .controls
            .iter()
            .enumerate()
            .map(|(order, c)| Cand {
                hash: identity_of(&c.identity),
                label: c.control.clone(),
                family: c.family.clone(),
                locator: c.context_id.clone(),
                order,
            })
            .collect();
        self.state
            .rank(
                self.config.flags,
                &cands,
                CrawlSeed(self.config.seed),
                self.config.max_layer,
            )
            .into_iter()
            .map(|c| c.locator.clone())
            .collect()
    }

    fn observe(&mut self, _step: usize, recorded: &TraceStep, _next: Option<&Snapshot>) {
        let Some(chosen) = recorded
            .snapshot
            .controls
            .iter()
            .find(|c| c.context_id == recorded.chosen)
        else {
            return;
        };
        let novel: Vec<ElementIdentityHash> =
            recorded.outcome.revealed.iter().map(|h| identity_of(h)).collect();
        self.state
            .record(identity_of(&chosen.identity), &chosen.family, &novel);
    }
}

/// Per-step comparison.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct StepResult {
    /// 0-based position of the step in the trace.
    pub index: usize,
    /// `ActionContextId` (hex) the recording chose at this step.
    pub recorded: String,
    /// Top-ranked context, `None` when the decision function had no candidate.
    pub decided: Option<String>,
    /// Whether the decision function's top choice equals the recorded choice.
    pub agrees: bool,
    /// 1-based rank of the recorded choice in the ranking, if present.
    pub recorded_rank: Option<usize>,
    /// Number of candidates the decision function ranked at this step (dropped candidates excluded).
    pub candidates: usize,
}

/// Outcome of a replay.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct ReplayResult {
    /// Name of the decision function ([`DecisionFn::name`]).
    pub decision_fn: String,
    /// One comparison per trace step, in trace order.
    pub steps: Vec<StepResult>,
    /// Fraction of steps where the top choice equals the recorded choice.
    pub agreement: f64,
    /// Fraction where the recorded choice is in the top three.
    pub top3: f64,
    /// Cumulative fraction of the trace's distinct contexts the replayed decisions chose.
    pub coverage_curve: Vec<f64>,
    /// Steps where the decision function produced no candidate.
    pub undecided: usize,
}

impl ReplayResult {
    /// Every step decided exactly as recorded.
    #[must_use]
    pub fn identical(&self) -> bool {
        !self.steps.is_empty() && self.steps.iter().all(|s| s.agrees)
    }

    /// First step that diverged.
    #[must_use]
    pub fn first_divergence(&self) -> Option<&StepResult> {
        self.steps.iter().find(|s| !s.agrees)
    }
}

/// Replays traces through decision functions.
pub struct ReplayHarness;

impl ReplayHarness {
    /// Replay `trace` through the built-in queue policy configured by `config`.
    #[must_use]
    pub fn replay(trace: &Trace, config: StrategyConfig) -> ReplayResult {
        Self::replay_with(&mut QueueDecision::new(config), trace)
    }

    /// Replay `trace` through any decision function.
    #[must_use]
    pub fn replay_with(decision: &mut dyn DecisionFn, trace: &Trace) -> ReplayResult {
        let universe: BTreeSet<&str> = trace
            .steps
            .iter()
            .flat_map(|s| s.snapshot.controls.iter().map(|c| c.context_id.as_str()))
            .collect();
        let mut steps = Vec::with_capacity(trace.steps.len());
        let mut chosen_so_far: BTreeSet<String> = BTreeSet::new();
        let mut curve = Vec::with_capacity(trace.steps.len());
        let (mut agree, mut top3, mut undecided) = (0usize, 0usize, 0usize);
        for (i, step) in trace.steps.iter().enumerate() {
            let ranking = decision.rank(i, &step.snapshot);
            let decided = ranking.first().cloned();
            let recorded_rank = ranking.iter().position(|c| *c == step.chosen).map(|p| p + 1);
            let agrees = decided.as_deref() == Some(step.chosen.as_str());
            if agrees {
                agree += 1;
            }
            if recorded_rank.is_some_and(|r| r <= 3) {
                top3 += 1;
            }
            if decided.is_none() {
                undecided += 1;
            }
            if let Some(d) = &decided {
                chosen_so_far.insert(d.clone());
            }
            curve.push(if universe.is_empty() {
                1.0
            } else {
                chosen_so_far.len() as f64 / universe.len() as f64
            });
            steps.push(StepResult {
                index: i,
                recorded: step.chosen.clone(),
                decided,
                agrees,
                recorded_rank,
                candidates: ranking.len(),
            });
            decision.observe(i, step, trace.steps.get(i + 1).map(|n| &n.snapshot));
        }
        let n = trace.steps.len().max(1) as f64;
        ReplayResult {
            decision_fn: decision.name(),
            steps,
            agreement: agree as f64 / n,
            top3: top3 as f64 / n,
            coverage_curve: curve,
            undecided,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn ctl(id: &str, family: &str) -> SnapshotControl {
        SnapshotControl {
            context_id: format!("ctx-{id}"),
            identity: Digest::of("t", id.as_bytes()).to_hex(),
            family: family.to_owned(),
            control: Some(id.to_owned()),
            role: "button".to_owned(),
            name: Some(id.to_owned()),
        }
    }

    fn trace() -> Trace {
        let snap = |ids: &[&str]| Snapshot {
            url: "http://h/x/".to_owned(),
            title: None,
            controls: ids.iter().map(|i| ctl(i, "f")).collect(),
        };
        let step = |ids: &[&str], chosen: &str, revealed: &[&str]| TraceStep {
            snapshot: snap(ids),
            chosen: format!("ctx-{chosen}"),
            outcome: Outcome {
                succeeded: true,
                revealed: revealed
                    .iter()
                    .map(|r| Digest::of("t", r.as_bytes()).to_hex())
                    .collect(),
                lane: TrustLane::TrustedUi,
            },
        };
        Trace {
            version: TRACE_VERSION,
            fixture: "x".to_owned(),
            seed: 5,
            variant: "A4".to_owned(),
            steps: vec![
                step(&["a", "b", "c"], "a", &[]),
                step(&["a", "b", "c"], "b", &[]),
                step(&["a", "b", "c"], "c", &[]),
            ],
        }
    }

    #[test]
    fn recorded_configuration_replays_identically_and_covers_everything() {
        // Record with the queue policy itself so the replay is a fixed point.
        let config = StrategyConfig {
            flags: PolicyFlags {
                queue: true,
                ..PolicyFlags::default()
            },
            seed: 5,
            max_layer: 1,
        };
        let mut t = trace();
        let mut q = QueueDecision::new(config);
        for (i, s) in t.steps.iter_mut().enumerate() {
            let best = q.rank(i, &s.snapshot)[0].clone();
            s.chosen = best;
            q.observe(i, s, None);
        }
        let r = ReplayHarness::replay(&t, config);
        assert!(r.identical(), "{:?}", r.first_divergence());
        assert!((r.agreement - 1.0).abs() < 1e-12 && (r.top3 - 1.0).abs() < 1e-12);
        assert!((r.coverage_curve[2] - 1.0).abs() < 1e-12);
        assert_eq!(r.undecided, 0);
    }

    #[test]
    fn a_different_policy_diverges_and_reports_the_rank_of_the_recorded_choice() {
        let t = trace();
        let doc_order = StrategyConfig {
            flags: PolicyFlags::default(),
            seed: 1,
            max_layer: 1,
        };
        // Document order: a, then (a executed, layer cap 1) b, then c: identical to the recorded order.
        let same = ReplayHarness::replay(&t, doc_order);
        assert!(same.identical());
        // Reverse the recorded order: document order now disagrees at step 0.
        let mut rev = t.clone();
        rev.steps.reverse();
        let r = ReplayHarness::replay(&rev, doc_order);
        assert!(!r.identical());
        let d = r.first_divergence().unwrap();
        assert_eq!(d.index, 0);
        assert_eq!(d.recorded, "ctx-c");
        assert_eq!(d.decided.as_deref(), Some("ctx-a"));
        assert_eq!(d.recorded_rank, Some(3));
        assert!((r.top3 - 1.0).abs() < 1e-12);
        assert!(r.agreement < 1.0);
    }

    #[test]
    fn trace_json_round_trips_and_validates() {
        let t = trace();
        let back = Trace::from_json(&t.to_json().unwrap()).unwrap();
        assert_eq!(back, t);
        let bad_version = t.to_json().unwrap().replace("\"version\": 1", "\"version\": 9");
        assert!(Trace::from_json(&bad_version).is_err());
        let mut broken = t;
        broken.steps[0].chosen = "ctx-zzz".to_owned();
        assert!(Trace::from_json(&broken.to_json().unwrap()).is_err());
    }

    #[test]
    fn empty_snapshot_is_undecided() {
        let mut t = trace();
        t.steps.truncate(1);
        let config = StrategyConfig {
            flags: PolicyFlags::default(),
            seed: 1,
            max_layer: 0,
        };
        let r = ReplayHarness::replay(&t, config);
        assert_eq!(r.undecided, 1);
        assert!(!r.identical());
    }
}
