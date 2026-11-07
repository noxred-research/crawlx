//! Shard formats of the `decision-eval` rig and the assembly of its evidence (gate G3): every shard process writes one JSON file ([`AblationShard`], [`ShadowShard`],
//! [`SafetyShard`]); [`assemble`] merges the shards of a directory tree into the
//! `G3Report` (`bench/out/calibration.json`), the shadow report and the paired-ablation summary.

use crate::decision_eval::{
    analyze_shadow, assemble_g3, pooled_comparison, EngineStats, G3Inputs, PairedRun, ShadowDecision,
    ShadowReport,
};
use crate::decision_rig::RunCapture;
use crate::error::BenchError;
use crate::gates::{evaluate_g3, G3Report, GateVerdict};
use crate::stats::PairedComparison;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A run that did not finish, with the reason.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct FailedRun {
    /// Fixture.
    pub fixture: String,
    /// Seed.
    pub seed: u64,
    /// Failure chain.
    pub error: String,
}

/// Paired A9-vs-A10 runs of one fixture group in one nightly execution.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct AblationShard {
    /// Execution of the nightly suite this shard belongs to (1-based, in order).
    pub night: u32,
    /// Seed suite of `bench/seeds.toml`.
    pub suite: String,
    /// Baseline row.
    pub baseline: String,
    /// Candidate row.
    pub candidate: String,
    /// Interaction budget per run.
    pub interactions: u32,
    /// Wall-clock limit per run in seconds.
    pub duration_seconds: u32,
    /// Fixtures of the shard.
    pub fixtures: Vec<String>,
    /// Seeds of the suite.
    pub seeds: Vec<u64>,
    /// Scored pairs.
    pub runs: Vec<PairedRun>,
    /// Pairs that did not finish.
    pub failed: Vec<FailedRun>,
    /// One capture per executed run.
    pub captures: Vec<RunCapture>,
    /// What the model engine saw during the shard.
    pub engine: EngineStats,
    /// Identity of the served model.
    pub model: String,
}

/// Shadow decisions of one fixture group; the decisions themselves are in `<shard>.jsonl`.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ShadowShard {
    /// Shard name.
    pub shard: String,
    /// Fixtures of the shard.
    pub fixtures: Vec<String>,
    /// Seeds crawled.
    pub seeds: Vec<u64>,
    /// Decisions written.
    pub decisions: u64,
    /// Runs that did not finish.
    pub failed: Vec<FailedRun>,
    /// One capture per run.
    pub captures: Vec<RunCapture>,
    /// What the model engine saw during the shard.
    pub engine: EngineStats,
    /// Identity of the served model.
    pub model: String,
}

/// One model-in-the-loop run of the safety phase.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct SafetyRun {
    /// Fixture.
    pub fixture: String,
    /// Safety profile of the run.
    pub profile: String,
    /// Seed.
    pub seed: u64,
    /// Executed actions the scorecard's safety metrics count.
    pub executed: u64,
    /// Executed mutating effects the manifest forbids under the profile.
    pub unauthorized: u64,
    /// The forbidden effects, `METHOD path`.
    pub violations: Vec<String>,
    /// What the run left behind.
    pub capture: RunCapture,
}

/// Safety runs of one fixture group.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct SafetyShard {
    /// Variant that ran (A10).
    pub variant: String,
    /// The model's top candidate was accepted on every decision
    /// ([`crate::decision_rig::ForcedChoice`]) instead of going through the confidence gates.
    #[serde(default)]
    pub forced_acceptance: bool,
    /// Interaction budget per run.
    pub interactions: u32,
    /// Runs.
    pub runs: Vec<SafetyRun>,
    /// Runs that did not finish.
    pub failed: Vec<FailedRun>,
    /// What the model engine saw during the shard.
    pub engine: EngineStats,
    /// Identity of the served model.
    pub model: String,
}

/// Pooled safety totals.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct SafetyTotals {
    /// Runs.
    pub runs: u64,
    /// Executed actions counted by the safety metrics.
    pub executed: u64,
    /// Forbidden effects executed.
    pub unauthorized: u64,
    /// Interactions the kernel rejected.
    pub policy_blocked: u64,
    /// `model_decisions` rows of the runs.
    pub model_calls: u64,
    /// Rows where the gate accepted a candidate.
    pub model_selected: u64,
    /// Executed actions a model decision influenced.
    pub influenced: u64,
    /// Trail violations over the runs that were verified.
    pub trail_violations: u64,
}

/// One night of the paired ablation.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct NightSummary {
    /// Night (execution of the suite).
    pub night: u32,
    /// Pairs scored.
    pub pairs: usize,
    /// Distinct fixtures.
    pub fixtures: usize,
    /// Distinct seeds.
    pub seeds: usize,
    /// Pairs that did not finish.
    pub failed: usize,
    /// Paired comparison of trusted coverage.
    pub trusted: PairedComparison,
    /// Paired comparison of the interaction-weighted coverage AUC.
    pub auc: PairedComparison,
    /// Executed candidate actions a model decision influenced.
    pub influenced: u64,
    /// Executed candidate actions.
    pub candidate_executed: u64,
    /// Candidate-run model calls.
    pub model_calls: u64,
    /// Candidate-run calls where the gate accepted a candidate.
    pub model_selected: u64,
}

/// Calls the model engine saw, summed over every shard of every phase.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct EngineTotals {
    /// Calls made.
    pub calls: u64,
    /// Calls that failed (breaker open, timeout, malformed answer): 0 means the breaker never opened.
    pub errors: u64,
    /// Answered choice questions that abstained.
    pub abstained: u64,
    /// Answered choice questions where the gate accepted a candidate.
    pub selected: u64,
}

impl EngineTotals {
    fn add(&mut self, s: &EngineStats) {
        self.calls += s.calls;
        self.errors += s.errors;
        self.abstained += s.abstained;
        self.selected += s.selected;
    }
}

/// Everything [`assemble`] derives.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Evidence {
    /// The `G3Report` that goes to the gate binary.
    pub g3: G3Report,
    /// Per-criterion verdict of the report.
    pub verdict: GateVerdict,
    /// Paired ablation per night.
    pub nights: Vec<NightSummary>,
    /// Safety totals of the safety runs under the shipped confidence gate.
    pub safety_shipped_gate: SafetyTotals,
    /// Safety totals of the safety runs with the model's pick forced through every gate (the
    /// model influences every decision it is consulted on).
    pub safety_forced_gate: SafetyTotals,
    /// Safety totals of the model-enabled ablation runs.
    pub safety_ablation: SafetyTotals,
    /// Shadow report over all recorded decisions.
    pub shadow_all: ShadowReport,
    /// Shadow report restricted to the held-out fixtures.
    pub shadow_heldout: ShadowReport,
    /// Held-out fixtures the second shadow report covers.
    pub heldout_fixtures: BTreeSet<String>,
    /// Failed runs over all phases.
    pub failed: Vec<FailedRun>,
    /// Identities of the served model seen in the shards.
    pub models: BTreeSet<String>,
    /// `model_decisions` rows of every run of every phase.
    pub model_decision_rows: u64,
    /// Of those, rows without a calibration version.
    pub uncalibrated_rows: u64,
    /// What the engine saw over all shards.
    pub engine: EngineTotals,
}

/// Inputs of [`assemble`] besides the shard directories.
#[derive(Clone, PartialEq, Debug)]
pub struct AssembleConfig {
    /// Held-out labelled decisions behind the ECE (from `metrics.json`).
    pub calibration_samples: u64,
    /// ECE on the held-out families (from `metrics.json`).
    pub ece: f64,
    /// Warm inference p95 in milliseconds on the selected GPU (from the latency bench).
    pub warm_p95_ms: f64,
    /// Fixtures whose shadow decisions form the held-out report.
    pub heldout_fixtures: BTreeSet<String>,
}

fn json_files(dir: &Path, ext: &str) -> Result<Vec<PathBuf>, BenchError> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| BenchError::io(dir, e))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == ext))
        .collect();
    files.sort();
    Ok(files)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, BenchError> {
    let bytes = std::fs::read(path).map_err(|e| BenchError::io(path, e))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn totals<'a>(
    captures: impl Iterator<Item = &'a RunCapture>,
    executed: u64,
    unauthorized: u64,
    runs: u64,
) -> SafetyTotals {
    let mut t = SafetyTotals {
        runs,
        executed,
        unauthorized,
        ..SafetyTotals::default()
    };
    for c in captures {
        t.policy_blocked += c.policy_blocked;
        t.model_calls += c.model_calls;
        t.model_selected += c.model_selected;
        t.influenced += c.influenced;
        t.trail_violations += c.trail_violations.unwrap_or(0);
    }
    t
}

/// Merge the shards under `ablation`, `shadow` and `safety` (one JSON file per shard; the shadow
/// decisions are the `<shard>.jsonl` next to each shadow shard) into the evidence of G3.
///
/// # Errors
/// File and JSON failures, a night with fewer than two scored pairs, or no ablation shard.
pub fn assemble(
    ablation: &Path,
    shadow: &Path,
    safety: &Path,
    cfg: &AssembleConfig,
) -> Result<Evidence, BenchError> {
    let mut models = BTreeSet::new();
    let mut failed = Vec::new();
    let (mut model_rows, mut uncalibrated_rows) = (0_u64, 0_u64);
    let mut engine = EngineTotals::default();
    let mut tally = |c: &RunCapture| {
        model_rows += c.model_calls;
        uncalibrated_rows += c.uncalibrated;
    };

    // paired ablation, grouped by night
    let mut by_night: BTreeMap<u32, Vec<PairedRun>> = BTreeMap::new();
    let mut night_captures: BTreeMap<u32, Vec<RunCapture>> = BTreeMap::new();
    let mut night_failed: BTreeMap<u32, usize> = BTreeMap::new();
    for path in json_files(ablation, "json")? {
        let shard: AblationShard = read_json(&path)?;
        models.insert(shard.model.clone());
        by_night.entry(shard.night).or_default().extend(shard.runs);
        night_failed
            .entry(shard.night)
            .and_modify(|n| *n += shard.failed.len())
            .or_insert(shard.failed.len());
        engine.add(&shard.engine);
        shard.captures.iter().for_each(&mut tally);
        night_captures.entry(shard.night).or_default().extend(
            shard
                .captures
                .into_iter()
                .filter(|c| c.variant == shard.candidate),
        );
        failed.extend(shard.failed);
    }
    if by_night.is_empty() {
        return Err(BenchError::Ablation(format!(
            "no ablation shard under {}",
            ablation.display()
        )));
    }
    for runs in by_night.values_mut() {
        runs.sort_by(|a, b| (&a.fixture, a.seed).cmp(&(&b.fixture, b.seed)));
    }
    let night_slices: Vec<&[PairedRun]> = by_night.values().map(Vec::as_slice).collect();
    let mut nights = Vec::new();
    for (night, runs) in &by_night {
        let captures = night_captures.get(night).map_or(&[][..], Vec::as_slice);
        nights.push(NightSummary {
            night: *night,
            pairs: runs.len(),
            fixtures: runs
                .iter()
                .map(|r| r.fixture.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            seeds: runs.iter().map(|r| r.seed).collect::<BTreeSet<_>>().len(),
            failed: night_failed.get(night).copied().unwrap_or(0),
            trusted: pooled_comparison("coverage.trusted", runs, false)?,
            auc: pooled_comparison("coverage.auc", runs, true)?,
            influenced: captures.iter().map(|c| c.influenced).sum(),
            candidate_executed: captures.iter().map(|c| c.executed).sum(),
            model_calls: captures.iter().map(|c| c.model_calls).sum(),
            model_selected: captures.iter().map(|c| c.model_selected).sum(),
        });
    }
    let safety_ablation = totals(
        night_captures.values().flatten(),
        by_night
            .values()
            .flatten()
            .map(|r| r.candidate_safety_executed)
            .sum(),
        by_night
            .values()
            .flatten()
            .map(|r| r.candidate_unauthorized)
            .sum(),
        by_night.values().map(|r| r.len() as u64).sum(),
    );

    // safety phase, per gate
    let (mut shipped_runs, mut forced_runs) = (Vec::new(), Vec::new());
    if safety.is_dir() {
        for path in json_files(safety, "json")? {
            let shard: SafetyShard = read_json(&path)?;
            models.insert(shard.model.clone());
            failed.extend(shard.failed);
            engine.add(&shard.engine);
            shard.runs.iter().for_each(|r| tally(&r.capture));
            if shard.forced_acceptance {
                forced_runs.extend(shard.runs);
            } else {
                shipped_runs.extend(shard.runs);
            }
        }
    }
    let phase_totals = |runs: &[SafetyRun]| {
        totals(
            runs.iter().map(|r| &r.capture),
            runs.iter().map(|r| r.executed).sum(),
            runs.iter().map(|r| r.unauthorized).sum(),
            runs.len() as u64,
        )
    };
    let safety_shipped_gate = phase_totals(&shipped_runs);
    let safety_forced_gate = phase_totals(&forced_runs);

    // shadow decisions
    let mut decisions: Vec<ShadowDecision> = Vec::new();
    if shadow.is_dir() {
        for path in json_files(shadow, "json")? {
            let shard: ShadowShard = read_json(&path)?;
            models.insert(shard.model.clone());
            failed.extend(shard.failed);
            engine.add(&shard.engine);
            shard.captures.iter().for_each(&mut tally);
        }
        for path in json_files(shadow, "jsonl")? {
            let text = std::fs::read_to_string(&path).map_err(|e| BenchError::io(&path, e))?;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                decisions.push(serde_json::from_str(line)?);
            }
        }
    }
    let shadow_all = analyze_shadow(&decisions)?;
    let heldout: Vec<ShadowDecision> = decisions
        .iter()
        .filter(|d| cfg.heldout_fixtures.contains(&d.fixture))
        .cloned()
        .collect();
    let shadow_heldout = analyze_shadow(&heldout)?;

    // G3 counts every model-enabled run that executed actions: the dedicated safety phase and
    // the candidate runs of the ablation
    let g3 = assemble_g3(&G3Inputs {
        calibration_samples: cfg.calibration_samples,
        ece: cfg.ece,
        warm_p95_ms: cfg.warm_p95_ms,
        nights: &night_slices,
        safety: (
            safety_shipped_gate.unauthorized + safety_forced_gate.unauthorized + safety_ablation.unauthorized,
            safety_shipped_gate.executed + safety_forced_gate.executed + safety_ablation.executed,
        ),
    })?;
    let verdict = evaluate_g3(&g3);
    Ok(Evidence {
        g3,
        verdict,
        nights,
        safety_shipped_gate,
        safety_forced_gate,
        safety_ablation,
        shadow_all,
        shadow_heldout,
        heldout_fixtures: cfg.heldout_fixtures.clone(),
        failed,
        models,
        model_decision_rows: model_rows,
        uncalibrated_rows,
        engine,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn capture(variant: &str, fixture: &str, seed: u64) -> RunCapture {
        RunCapture {
            variant: variant.to_owned(),
            fixture: fixture.to_owned(),
            evaluation_origin: None,
            seed,
            run: format!("{fixture}-{seed}"),
            executed: 10,
            influenced: 1,
            policy_blocked: 2,
            model_calls: 8,
            model_selected: 1,
            uncalibrated: 0,
            trail_violations: Some(0),
        }
    }

    fn pairs(gain: f64) -> Vec<PairedRun> {
        (1..=6_u64)
            .map(|seed| PairedRun {
                fixture: "g02".to_owned(),
                seed,
                baseline: 0.5 + seed as f64 * 0.01,
                candidate: 0.5 + seed as f64 * 0.01 + gain + if seed % 2 == 0 { 0.001 } else { -0.001 },
                baseline_auc: 0.4,
                candidate_auc: 0.4 + gain,
                candidate_executed: 10,
                candidate_unauthorized: 0,
                candidate_safety_executed: 10,
            })
            .collect()
    }

    fn write<T: Serialize>(dir: &Path, name: &str, v: &T) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), serde_json::to_vec(v).unwrap()).unwrap();
    }

    fn ablation_shard(night: u32, gain: f64) -> AblationShard {
        AblationShard {
            night,
            suite: "nightly".to_owned(),
            baseline: "A9".to_owned(),
            candidate: "A10".to_owned(),
            interactions: 60,
            duration_seconds: 180,
            fixtures: vec!["g02".to_owned()],
            seeds: (1..=6).collect(),
            runs: pairs(gain),
            failed: Vec::new(),
            captures: vec![capture("A9", "g02", 1), capture("A10", "g02", 1)],
            engine: EngineStats::default(),
            model: "onnx-ranker/ranker@abc+cal:c1".to_owned(),
        }
    }

    #[test]
    fn assembles_nights_safety_and_the_g3_report() {
        let dir = tempfile::tempdir().unwrap();
        let (ab, sh, sf) = (
            dir.path().join("ab"),
            dir.path().join("sh"),
            dir.path().join("sf"),
        );
        write(&ab, "n1-g02.json", &ablation_shard(1, 0.05));
        write(&ab, "n2-g02.json", &ablation_shard(2, 0.05));
        write(
            &sf,
            "g25.json",
            &SafetyShard {
                variant: "A10".to_owned(),
                forced_acceptance: false,
                interactions: 40,
                runs: vec![SafetyRun {
                    fixture: "g25".to_owned(),
                    profile: "read_only".to_owned(),
                    seed: 1,
                    executed: 12,
                    unauthorized: 0,
                    violations: Vec::new(),
                    capture: capture("A10", "g25", 1),
                }],
                failed: Vec::new(),
                engine: EngineStats::default(),
                model: "onnx-ranker/ranker@abc+cal:c1".to_owned(),
            },
        );
        std::fs::create_dir_all(&sh).unwrap();
        let cfg = AssembleConfig {
            calibration_samples: 12_000,
            ece: 0.03,
            warm_p95_ms: 12.0,
            heldout_fixtures: ["g02".to_owned()].into_iter().collect(),
        };
        let ev = assemble(&ab, &sh, &sf, &cfg).unwrap();
        assert_eq!(ev.nights.len(), 2);
        assert_eq!(ev.nights[0].pairs, 6);
        assert_eq!(ev.g3.seeds, 6);
        assert!(ev.g3.coverage_gain_ci_low > 0.0, "{:?}", ev.g3);
        assert_eq!(ev.g3.consecutive_nightly_improvements, 2);
        assert_eq!(ev.g3.unauthorized_action_rate, 0.0);
        assert_eq!(ev.safety_shipped_gate.runs, 1);
        assert_eq!(ev.safety_shipped_gate.policy_blocked, 2);
        assert_eq!(ev.safety_forced_gate.runs, 0);
        assert!(ev.verdict.passed(), "{}", ev.verdict.render());
        assert_eq!(ev.shadow_all.decisions, 0);
    }

    #[test]
    fn a_missing_ablation_is_an_error_and_a_flat_night_is_red() {
        let dir = tempfile::tempdir().unwrap();
        let none = dir.path().join("none");
        std::fs::create_dir_all(&none).unwrap();
        let cfg = AssembleConfig {
            calibration_samples: 1,
            ece: 0.1,
            warm_p95_ms: 1.0,
            heldout_fixtures: BTreeSet::new(),
        };
        assert!(assemble(&none, &none, &none, &cfg).is_err());
        let ab = dir.path().join("ab");
        write(&ab, "n1.json", &ablation_shard(1, 0.0));
        let ev = assemble(&ab, &none, &none, &cfg).unwrap();
        assert!(!ev.verdict.passed());
        assert_eq!(ev.g3.consecutive_nightly_improvements, 0);
    }
}
