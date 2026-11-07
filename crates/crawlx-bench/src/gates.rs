//! Milestone gate evaluation: G1 from the gym scorecards of a run, G3 from a
//! calibration report. A passing evaluation is turned into a `gates/<id>.passed` file
//! ([`GateFile`]) that authenticates the commit, exact report, date and current workspace
//! source/dependency scope. `crawlx-strategies` verifies it before building gated strategies.
//! `crawlx-bench`'s `gate` binary is the command-line front.

use crate::error::BenchError;
use crate::scorecard::{Check, Scorecard};
use crawlx_strategies::registry::{scope_digest, G3Evidence, G3Token, Gate, GateFile, GateKeys};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Trusted-lane share every default run must reach (release gate).
pub const G1_TRUSTED_SHARE: f64 = 0.99;
/// Share of recorded paths whose replay must reach the same route and affordance digest.
pub const G1_REPLAY_MATCH: f64 = 0.95;

/// G1 evidence. Every scorecard must have its own ordered action/value and full replay evidence.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct G1Report {
    /// Scorecards of the gym runs.
    pub scorecards: Vec<Scorecard>,
    /// Evidence in the same fixture/seed order as the scorecards.
    pub runs: Vec<G1RunEvidence>,
    /// Structured output of the completed chaos suites; absent evidence fails.
    pub chaos: Option<ChaosEvidence>,
}

/// Ordered evidence for both same-seed runs and replay of every performed path.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct G1RunEvidence {
    /// Fixture whose scorecard this evidence supports.
    pub fixture: String,
    /// Seed used in both runs.
    pub seed: u64,
    /// Actual first-run perform order and parameter digests.
    pub first: Vec<crawlx_worker::action_trace::TraceStep>,
    /// Actual second-run perform order and parameter digests.
    pub second: Vec<crawlx_worker::action_trace::TraceStep>,
    /// Number of performed journal rows in the first run.
    pub first_performed: usize,
    /// Number of performed journal rows in the second run.
    pub second_performed: usize,
    /// Number of recorded paths eligible for replay, including failed actions.
    pub replay_recorded: usize,
    /// Number of paths actually replayed.
    pub replay_attempted: usize,
    /// Number of replays that matched every recorded step.
    pub replay_matched: usize,
    /// Whether the caller requested a capped informational sweep, never gate evidence.
    pub informational: bool,
}

impl G1RunEvidence {
    /// Start unmeasured evidence; fill only from actual runs and replay results.
    #[must_use]
    pub fn new(fixture: String, seed: u64) -> Self {
        Self {
            fixture,
            seed,
            first: Vec::new(),
            second: Vec::new(),
            first_performed: 0,
            second_performed: 0,
            replay_recorded: 0,
            replay_attempted: 0,
            replay_matched: 0,
            informational: false,
        }
    }
}

/// Required suites. The runner fixes the command; callers cannot supply a passing boolean.
pub const CHAOS_SUITES: [&str; 2] = ["crawlx-worker/chaos_failpoints", "crawlx-cli/chaos"];

/// Completed chaos-suite output, embedded in the authenticated G1 evidence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChaosEvidence {
    /// Scope of the build whose suites ran.
    pub scope_digest: String,
    /// One result for every required suite, in canonical order.
    pub suites: Vec<ChaosSuiteEvidence>,
}

/// Captured process result, not an assertion supplied by the report caller.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChaosSuiteEvidence {
    /// Fixed package/test target pair from [`CHAOS_SUITES`].
    pub suite: String,
    /// Completed process exit code; signals have no code and fail.
    pub exit_code: Option<i32>,
    /// Raw test stdout, retained so the evaluator can recompute the result.
    pub stdout: String,
    /// Raw test stderr, retained for diagnostics.
    pub stderr: String,
}

impl ChaosEvidence {
    /// Run the exact required suites and retain their completed process artifacts.
    ///
    /// # Errors
    /// Fails when PostgreSQL or Chromium is unavailable, or a suite cannot be launched.
    /// Failed suites are returned as failing evidence, never relabelled as passing.
    pub fn run() -> Result<Self, BenchError> {
        if std::env::var("CRAWLX_TEST_DATABASE_URL").is_err()
            || crawlx_browser::launch::find_executable().is_none()
        {
            return Err(BenchError::Gate(
                "chaos evidence requires CRAWLX_TEST_DATABASE_URL and Chromium".to_owned(),
            ));
        }
        let mut suites = Vec::with_capacity(CHAOS_SUITES.len());
        for suite in CHAOS_SUITES {
            let (package, test) = suite
                .split_once('/')
                .ok_or_else(|| BenchError::Gate("invalid built-in chaos suite".to_owned()))?;
            let output = std::process::Command::new("cargo")
                .args([
                    "test",
                    "-p",
                    package,
                    "--features",
                    "chaos",
                    "--test",
                    test,
                    "--",
                    "--nocapture",
                    "--test-threads",
                    "1",
                    "--color",
                    "never",
                ])
                .output()
                .map_err(|error| BenchError::Gate(format!("run {suite}: {error}")))?;
            suites.push(ChaosSuiteEvidence {
                suite: suite.to_owned(),
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(Self {
            scope_digest: scope_digest().to_owned(),
            suites,
        })
    }

    /// Verify every required suite completed, ran tests, and had no ignored or failed tests.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.scope_digest == scope_digest()
            && self.suites.len() == CHAOS_SUITES.len()
            && self.suites.iter().zip(CHAOS_SUITES).all(|(result, expected)| {
                result.suite == expected
                    && result.exit_code == Some(0)
                    && completed_test_count(&result.stdout).is_some()
                    && !result.stderr.lines().any(|line| line.starts_with("skipped:"))
            })
    }
}

fn completed_test_count(stdout: &str) -> Option<usize> {
    let mut summaries = stdout.lines().filter(|line| line.starts_with("test result: "));
    let summary = summaries.next()?;
    if summaries.next().is_some() {
        return None;
    }
    let rest = summary.strip_prefix("test result: ok. ")?;
    let (passed, rest) = rest.split_once(" passed; ")?;
    let passed: usize = passed.parse().ok()?;
    let rest = rest.strip_prefix("0 failed; 0 ignored; 0 measured; 0 filtered out;")?;
    // A libtest result with an empty body or filtered/ignored tests is not a suite pass.
    (passed > 0 && rest.trim_start().starts_with("finished in ")).then_some(passed)
}

/// Shared schema used by the authenticated G3 consumer and evaluator.
pub use crawlx_strategies::registry::G3Report;

/// Outcome of a gate evaluation: every criterion with its verdict.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct GateVerdict {
    /// Which gate.
    pub gate: Gate,
    /// One entry per criterion, in evaluation order.
    pub checks: Vec<Check>,
}

impl GateVerdict {
    /// Did every criterion pass?
    #[must_use]
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    /// Human-readable table of the criteria.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "gate {}: {}\n",
            self.gate.as_str(),
            if self.passed() { "PASS" } else { "FAIL" }
        );
        for c in &self.checks {
            let _ = writeln!(
                out,
                "  [{}] {:<34} expected {:<12} actual {}",
                if c.passed { "ok" } else { "FAIL" },
                c.name,
                c.expected,
                c.actual
            );
        }
        out
    }
}

fn check(name: &str, expected: String, actual: String, passed: bool) -> Check {
    Check {
        name: name.to_owned(),
        expected,
        actual,
        passed,
    }
}

/// Evaluate the G1 criteria over `report`.
#[must_use]
#[allow(clippy::cast_precision_loss)] // bounded benchmark action counts, used only for rates
pub fn evaluate_g1(report: &G1Report) -> GateVerdict {
    let mut checks = Vec::with_capacity(11);
    checks.push(check(
        "scorecards_present",
        ">= 1".to_owned(),
        report.scorecards.len().to_string(),
        !report.scorecards.is_empty(),
    ));
    let unknown_complete = report
        .scorecards
        .iter()
        .all(|card| card.unknown.is_some_and(|u| u.reconciled == u.unknown_total));
    checks.push(check(
        "unknown_left_unreconciled",
        "== 0 on every scorecard".to_owned(),
        if unknown_complete {
            "complete"
        } else {
            "missing or unreconciled"
        }
        .to_owned(),
        unknown_complete,
    ));
    let repeated_zero = report
        .scorecards
        .iter()
        .all(|card| card.unknown.is_some_and(|u| u.repeated_non_idempotent == 0));
    checks.push(check(
        "repeated_non_idempotent",
        "== 0 on every scorecard".to_owned(),
        if repeated_zero { "0" } else { "missing or repeated" }.to_owned(),
        repeated_zero,
    ));
    let chaos = report.chaos.as_ref().is_some_and(ChaosEvidence::passed);
    checks.push(check(
        "chaos_suite",
        "completed suite artifact".to_owned(),
        if chaos {
            "passed"
        } else {
            "missing, stale, incomplete or failed"
        }
        .to_owned(),
        chaos,
    ));
    let jaccard = report
        .scorecards
        .iter()
        .all(|card| card.run_to_run_jaccard == Some(1.0));
    checks.push(check(
        "run_to_run_jaccard",
        "== 1.0 on every scorecard".to_owned(),
        if jaccard { "1.0" } else { "missing or different" }.to_owned(),
        jaccard,
    ));
    let paired = report.runs.len() == report.scorecards.len()
        && report
            .runs
            .iter()
            .zip(&report.scorecards)
            .all(|(run, card)| run.fixture == card.fixture && run.seed == card.seed);
    let ordered = paired
        && report.runs.iter().all(|run| {
            !run.first.is_empty()
                && run.first.len() == run.first_performed
                && run.second.len() == run.second_performed
                && run.first.iter().all(|step| step.parameters_digest.is_some())
                && run.first == run.second
        });
    checks.push(check(
        "ordered_action_value_trace",
        "identical complete ordered traces per scorecard".to_owned(),
        if ordered {
            "identical"
        } else {
            "missing, incomplete or different"
        }
        .to_owned(),
        ordered,
    ));
    let diagnostic_zero = report
        .scorecards
        .iter()
        .all(|card| card.lanes.is_some_and(|lanes| lanes.diagnostic == 0));
    checks.push(check(
        "diagnostic_lane_actions",
        "== 0 on every scorecard".to_owned(),
        if diagnostic_zero {
            "0"
        } else {
            "missing or diagnostic"
        }
        .to_owned(),
        diagnostic_zero,
    ));
    let trusted = report.scorecards.iter().all(|card| {
        card.lanes.is_some_and(|lanes| {
            lanes
                .trusted
                .checked_add(lanes.diagnostic)
                .is_some_and(|total| total > 0 && lanes.trusted as f64 / total as f64 >= G1_TRUSTED_SHARE)
        })
    });
    checks.push(check(
        "trusted_lane_share",
        format!(">= {G1_TRUSTED_SHARE:.2} on every scorecard"),
        if trusted {
            "measured and passing"
        } else {
            "missing or below threshold"
        }
        .to_owned(),
        trusted,
    ));
    let replay_complete = paired
        && report.runs.iter().all(|run| {
            !run.informational
                && run.replay_recorded > 0
                && run.replay_recorded == run.first_performed
                && run.replay_attempted == run.replay_recorded
                && run.replay_matched <= run.replay_attempted
        });
    checks.push(check(
        "every_recorded_path_replayed",
        "no missing paths; uncapped sweep".to_owned(),
        if replay_complete {
            "complete"
        } else {
            "missing paths or informational sweep"
        }
        .to_owned(),
        replay_complete,
    ));
    let replay_matches = replay_complete
        && report
            .runs
            .iter()
            .all(|run| run.replay_matched as f64 / run.replay_attempted as f64 >= G1_REPLAY_MATCH);
    checks.push(check(
        "replay_match_rate",
        format!(">= {G1_REPLAY_MATCH:.2} on every scorecard"),
        if replay_matches {
            "measured and passing"
        } else {
            "missing or below threshold"
        }
        .to_owned(),
        replay_matches,
    ));
    let unauthorized_zero = report.scorecards.iter().all(|card| card.safety.unauthorized == 0);
    checks.push(check(
        "unauthorized_actions",
        "== 0".to_owned(),
        if unauthorized_zero {
            "0"
        } else {
            "unauthorized actions"
        }
        .to_owned(),
        unauthorized_zero,
    ));
    GateVerdict {
        gate: Gate::G1,
        checks,
    }
}

/// Evaluate the G3 criteria (the same rules as [`G3Token::verify`], reported per criterion).
#[must_use]
pub fn evaluate_g3(report: &G3Report) -> GateVerdict {
    let r = *report;
    let checks = vec![
        check(
            "calibration_samples",
            ">= 10000".to_owned(),
            r.calibration_samples.to_string(),
            r.calibration_samples >= 10_000,
        ),
        check(
            "ece",
            "<= 0.05".to_owned(),
            format!("{:.4}", r.ece),
            r.ece.is_finite() && r.ece <= 0.05,
        ),
        check("seeds", ">= 5".to_owned(), r.seeds.to_string(), r.seeds >= 5),
        check(
            "coverage_gain_ci_low",
            "> 0".to_owned(),
            format!("{:.4}", r.coverage_gain_ci_low),
            r.coverage_gain_ci_low.is_finite() && r.coverage_gain_ci_low > 0.0,
        ),
        check(
            "unauthorized_action_rate",
            "== 0".to_owned(),
            format!("{:.4}", r.unauthorized_action_rate),
            r.unauthorized_action_rate == 0.0,
        ),
        check(
            "warm_p95_ms",
            "< 100".to_owned(),
            format!("{:.1}", r.warm_p95_ms),
            r.warm_p95_ms.is_finite() && r.warm_p95_ms < 100.0,
        ),
        check(
            "consecutive_nightly_improvements",
            ">= 2".to_owned(),
            r.consecutive_nightly_improvements.to_string(),
            r.consecutive_nightly_improvements >= 2,
        ),
    ];
    let verdict = GateVerdict {
        gate: Gate::G3,
        checks,
    };
    debug_assert_eq!(
        verdict.passed(),
        G3Token::verify(&G3Evidence::from(r)).is_ok(),
        "gate-g3 and G3Token::verify must agree"
    );
    verdict
}

/// The gate file for a passing `verdict`: `report_bytes` is digested as the evidence,
/// `commit` identifies the checkout, `date` is `YYYY-MM-DD`.
///
/// # Errors
/// [`BenchError::Gate`] for missing/invalid evidence, a mismatched or failing verdict,
/// invalid metadata or an unavailable signing key.
pub fn gate_file(
    verdict: &GateVerdict,
    report_bytes: &[u8],
    commit: &str,
    date: &str,
    keys: &GateKeys,
    key_id: &str,
) -> Result<GateFile, BenchError> {
    let measured = match verdict.gate {
        Gate::G1 => serde_json::from_slice::<G1Report>(report_bytes).map(|report| evaluate_g1(&report)),
        Gate::G3 => serde_json::from_slice::<G3Report>(report_bytes).map(|report| evaluate_g3(&report)),
    }
    .map_err(|error| BenchError::Gate(format!("invalid gate evidence: {error}")))?;
    if &measured != verdict {
        return Err(BenchError::Gate(
            "verdict does not match the supplied evidence".to_owned(),
        ));
    }
    if !verdict.passed() {
        let failed: Vec<&str> = verdict
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name.as_str())
            .collect();
        return Err(BenchError::Gate(format!(
            "gate {} not met: {}",
            verdict.gate.as_str(),
            failed.join(", ")
        )));
    }
    GateFile::signed(verdict.gate, report_bytes, commit, date, keys, key_id)
        .map_err(|error| BenchError::Gate(error.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::scorecard::{LaneMetrics, UnknownMetrics};
    use crawlx_core::hash::Digest;

    fn passing_scorecard() -> Scorecard {
        let prf = serde_json::json!({"tp": 0, "fp": 0, "fn_": 0, "precision": 1.0, "recall": 1.0, "f1": 0.0});
        let json = serde_json::json!({
            "schema_version": 1, "fixture": "d1", "seed": 7, "variant": "A1", "profile": "read_only",
            "targets": {"overall": prf, "by_mechanism": {}, "unsupported_expected": 0, "unsupported_reported": 0, "missed": []},
            "coverage": {"gt_total": 0, "trusted": 1.0, "all_lanes": 1.0, "exercised": [], "missing": [], "t50": null, "t80": null, "t95": null, "auc": 1.0, "backend_operation_coverage": null, "claimed": null},
            "identity": null, "enablement": null, "stale_edge_rate": null, "states": null,
            "quiescence_timeout_rate": null, "stale_proposal_rate": null,
            "lanes": null, "network_epoch_trusted_share": null,
            "safety": {"executed": 3, "unauthorized": 0, "unauthorized_action_rate": 0.0, "violations": []},
            "unknown": null, "run_to_run_jaccard": 1.0, "checks": []
        });
        let mut sc: Scorecard = serde_json::from_value(json).expect("scorecard json");
        sc.lanes = Some(LaneMetrics {
            trusted: 12,
            diagnostic: 0,
            trusted_share: 1.0,
            diagnostic_share: 0.0,
        });
        sc.unknown = Some(UnknownMetrics {
            unknown_total: 1,
            reconciled: 1,
            resolution_rate: 1.0,
            repeated_non_idempotent: 0,
        });
        sc
    }

    fn passing_g1() -> G1Report {
        use crawlx_core::identity::{ActionContextKey, ActionKind, InputClass, ResourceContext};
        use crawlx_core::{ElementIdentityHash, PrincipalId, RouteTemplate, StateClusterId};
        let mut run = G1RunEvidence::new("d1".to_owned(), 7);
        for value in ["first", "second"] {
            let key = ActionContextKey {
                principal: PrincipalId("anonymous".to_owned()),
                route_template: RouteTemplate("/d1/".to_owned()),
                element: ElementIdentityHash(Digest::of("test/element", value.as_bytes())),
                action_kind: ActionKind::Type,
                input_class: InputClass("valid".to_owned()),
                resource_context: ResourceContext::None,
                state_cluster: StateClusterId(uuid::Uuid::nil()),
            };
            run.first.push(
                serde_json::from_value(serde_json::json!({
                    "key": key,
                    "parameters_digest": Digest::of("test/parameter", value.as_bytes()),
                }))
                .unwrap(),
            );
        }
        run.second.clone_from(&run.first);
        run.first_performed = 2;
        run.second_performed = 2;
        run.replay_recorded = 2;
        run.replay_attempted = 2;
        run.replay_matched = 2;
        G1Report {
            scorecards: vec![passing_scorecard()],
            runs: vec![run],
            chaos: Some(ChaosEvidence {
                scope_digest: scope_digest().to_owned(),
                suites: CHAOS_SUITES.into_iter().map(|suite| ChaosSuiteEvidence {
                    suite: suite.to_owned(), exit_code: Some(0),
                    stdout: "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.0s\n".to_owned(),
                    stderr: String::new(),
                }).collect(),
            }),
        }
    }

    #[test]
    fn g1_passes_only_when_every_criterion_holds() {
        let ok = evaluate_g1(&passing_g1());
        assert!(ok.passed(), "{}", ok.render());
        assert_eq!(ok.checks.len(), 11);

        let mut r = passing_g1();
        r.scorecards[0].run_to_run_jaccard = Some(0.9);
        assert!(!evaluate_g1(&r).passed());

        let mut r = passing_g1();
        r.scorecards[0].lanes.as_mut().unwrap().diagnostic = 1;
        let v = evaluate_g1(&r);
        assert!(v
            .checks
            .iter()
            .any(|c| c.name == "diagnostic_lane_actions" && !c.passed));

        let mut r = passing_g1();
        r.runs[0].replay_attempted = 1;
        assert!(!evaluate_g1(&r).passed());

        let mut r = passing_g1();
        r.chaos = None;
        assert!(!evaluate_g1(&r).passed());

        let mut r = passing_g1();
        r.scorecards[0].unknown.as_mut().unwrap().repeated_non_idempotent = 1;
        assert!(!evaluate_g1(&r).passed());

        let mut r = passing_g1();
        r.scorecards[0].safety.unauthorized = 1;
        assert!(!evaluate_g1(&r).passed());

        let r = G1Report {
            scorecards: Vec::new(),
            runs: Vec::new(),
            chaos: None,
        };
        assert!(!evaluate_g1(&r).passed());
    }

    #[test]
    fn every_scorecard_needs_unknown_lane_and_matching_run_evidence() {
        for missing in ["unknown", "lanes", "run"] {
            let mut report = passing_g1();
            report.scorecards.push(report.scorecards[0].clone());
            report.runs.push(report.runs[0].clone());
            match missing {
                "unknown" => report.scorecards[1].unknown = None,
                "lanes" => report.scorecards[1].lanes = None,
                _ => report.runs[1].seed += 1,
            }
            assert!(!evaluate_g1(&report).passed(), "{missing}");
        }
    }

    #[test]
    fn jaccard_one_cannot_hide_action_reordering_value_changes_or_missing_trace() {
        for mutation in ["reorder", "value", "missing", "count"] {
            let mut report = passing_g1();
            let run = &mut report.runs[0];
            match mutation {
                "reorder" => run.second.reverse(),
                "value" => run.second[0].parameters_digest = Some(Digest::of("test", b"changed")),
                "missing" => run.first[0].parameters_digest = None,
                _ => run.first_performed += 1,
            }
            assert_eq!(report.scorecards[0].run_to_run_jaccard, Some(1.0));
            assert!(!evaluate_g1(&report).passed(), "{mutation}");
        }
    }

    #[test]
    fn capped_replay_missing_paths_and_incomplete_chaos_refuse_the_gate() {
        let mut report = passing_g1();
        report.runs[0].informational = true;
        assert!(!evaluate_g1(&report).passed());
        let mut report = passing_g1();
        report.runs[0].replay_recorded += 1;
        assert!(!evaluate_g1(&report).passed());
        for mutation in ["scope", "suite", "exit", "output", "ignored", "skip"] {
            let mut report = passing_g1();
            let chaos = report.chaos.as_mut().unwrap();
            match mutation {
                "scope" => chaos.scope_digest = "stale".to_owned(),
                "suite" => {
                    chaos.suites.pop();
                }
                "exit" => chaos.suites[0].exit_code = Some(1),
                "output" => chaos.suites[0].stdout.clear(),
                "ignored" => {
                    chaos.suites[0].stdout = chaos.suites[0].stdout.replace("0 ignored", "1 ignored")
                }
                _ => chaos.suites[0].stderr = "skipped: prerequisite missing".to_owned(),
            }
            assert!(!evaluate_g1(&report).passed(), "{mutation}");
        }
    }

    #[test]
    fn g3_agrees_with_the_token_and_the_file_carries_this_builds_scope() {
        let good = G3Report {
            calibration_samples: 12_000,
            ece: 0.03,
            seeds: 6,
            coverage_gain_ci_low: 0.01,
            unauthorized_action_rate: 0.0,
            warm_p95_ms: 40.0,
            consecutive_nightly_improvements: 2,
        };
        let v = evaluate_g3(&good);
        assert!(v.passed(), "{}", v.render());
        let bad = G3Report { ece: 0.2, ..good };
        let v = evaluate_g3(&bad);
        assert!(!v.passed());
        let keys = GateKeys::parse(&format!("unit {}", "42".repeat(32))).unwrap();
        let bad_bytes = serde_json::to_vec(&bad).unwrap();
        assert!(matches!(
            gate_file(&v, &bad_bytes, "abc", "2026-10-19", &keys, "unit"),
            Err(BenchError::Gate(_))
        ));
        let bytes = serde_json::to_vec(&good).unwrap();
        assert!(gate_file(
            &evaluate_g3(&good),
            &bad_bytes,
            "abc",
            "2026-10-19",
            &keys,
            "unit"
        )
        .is_err());
        let file = gate_file(&evaluate_g3(&good), &bytes, "abc123", "2026-10-19", &keys, "unit").unwrap();
        assert_eq!(file.gate, Gate::G3);
        assert_eq!(file.scope_digest, scope_digest());
        assert!(file.verify(Gate::G3, &bytes, &keys).is_ok());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("g3.passed"), file.to_toml().unwrap()).unwrap();
        std::fs::write(dir.path().join(Gate::G3.report_name()), bytes).unwrap();
        let gates = crawlx_strategies::Gates::load_with_keys(dir.path(), &keys);
        assert!(gates.status().g3 && !gates.status().g1);
    }
}
