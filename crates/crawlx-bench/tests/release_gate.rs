//! `crawlx_bench::release_gate`: the checklist verdict over a tempdir evidence tree. A complete
//! tree passes; deleting the evidence of any one item blocks the release; each threshold flips
//! exactly at its boundary; waivers cover only waivable rows, only until their expiry date, and
//! only with an owner and a reason.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::NaiveDate;
use crawlx_bench::gates::CHAOS_SUITES;
use crawlx_bench::release_gate::{
    check_runbook_links, evaluate, exported_metric_names, item_ids, parse_libtest, parse_waivers,
    record_suite, states, waivable_item_ids, GateInputs, ItemState, ReleaseReport, Waiver, SUITE_IDS,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const TODAY: &str = "2026-11-10";

fn date(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
}

fn write_json(path: &Path, v: &Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

fn write_text(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn edit_json(path: &Path, f: impl FnOnce(&mut Value)) {
    let mut v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    f(&mut v);
    write_json(path, &v);
}

fn prf(tp: u64, fp: u64, fn_: u64) -> Value {
    json!({ "tp": tp, "fp": fp, "fn_": fn_, "precision": 1.0, "recall": 1.0, "f1": 1.0 })
}

/// A scorecard that satisfies every scorecard-backed item; fixtures add their own metrics.
fn card(fixture: &str, profile: &str) -> Value {
    json!({
        "schema_version": 1,
        "fixture": fixture,
        "seed": 7,
        "variant": "A8",
        "profile": profile,
        "targets": {
            "overall": prf(40, 0, 0),
            "by_mechanism": { "ax": prf(40, 0, 0) },
            "unsupported_expected": 0,
            "unsupported_reported": 0,
            "missed": []
        },
        "coverage": {
            "gt_total": 40, "trusted": 1.0, "all_lanes": 1.0, "exercised": [], "missing": [],
            "t50": null, "t80": null, "t95": null, "auc": 1.0,
            "backend_operation_coverage": null, "claimed": null
        },
        "identity": null,
        "enablement": null,
        "stale_edge_rate": null,
        "states": null,
        "quiescence_timeout_rate": 0.0,
        "stale_proposal_rate": null,
        "lanes": { "trusted": 100, "diagnostic": 0, "trusted_share": 1.0, "diagnostic_share": 0.0 },
        "network_epoch_trusted_share": null,
        "safety": { "executed": 10, "unauthorized": 0, "unauthorized_action_rate": 0.0, "violations": [] },
        "unknown": { "unknown_total": 2, "reconciled": 2, "resolution_rate": 1.0, "repeated_non_idempotent": 0 },
        "run_to_run_jaccard": 1.0,
        "checks": []
    })
}

fn suite(id: &str, tests_required: bool) -> Value {
    json!({
        "id": id,
        "command": ["run", id],
        "exit_code": 0,
        "passed": if tests_required { 5 } else { 0 },
        "failed": 0,
        "ignored": 0,
        "skipped": 0,
        "tests_required": tests_required
    })
}

fn mutants(caught: usize, missed: usize) -> Value {
    let mut outcomes = vec![json!({ "scenario": "Baseline", "summary": "Success" })];
    for i in 0..caught {
        outcomes.push(
            json!({ "scenario": { "Mutant": { "name": format!("c{i}") } }, "summary": "CaughtMutant" }),
        );
    }
    for i in 0..missed {
        outcomes.push(
            json!({ "scenario": { "Mutant": { "name": format!("m{i}") } }, "summary": "MissedMutant" }),
        );
    }
    outcomes.push(json!({ "scenario": { "Mutant": { "name": "u" } }, "summary": "Unviable" }));
    json!({ "outcomes": outcomes })
}

struct Env {
    _tmp: tempfile::TempDir,
    ev: PathBuf,
    repo: PathBuf,
}

impl Env {
    fn card(&self, name: &str) -> PathBuf {
        self.ev.join("scorecards").join(format!("{name}.json"))
    }

    fn edit_card(&self, name: &str, f: impl FnOnce(&mut Value)) {
        edit_json(&self.card(name), f);
    }

    fn edit_all_cards(&self, f: impl Fn(&mut Value)) {
        for entry in std::fs::read_dir(self.ev.join("scorecards")).unwrap() {
            edit_json(&entry.unwrap().path(), &f);
        }
    }

    fn edit_ev(&self, rel: &str, f: impl FnOnce(&mut Value)) {
        edit_json(&self.ev.join(rel), f);
    }

    fn set_ev(&self, rel: &str, v: &Value) {
        write_json(&self.ev.join(rel), v);
    }

    fn remove(&self, rel: &str) {
        if let Some(dir) = rel.strip_suffix("/*.json") {
            let _ = std::fs::remove_dir_all(self.ev.join(dir));
            return;
        }
        for root in [&self.ev, &self.repo] {
            let _ = std::fs::remove_file(root.join(rel));
        }
    }

    fn inputs(&self) -> GateInputs {
        let mut inputs = GateInputs::new(&self.ev, &self.repo, date(TODAY));
        inputs.model_tier_changed = true;
        inputs
    }

    fn report(&self) -> ReleaseReport {
        evaluate(&self.inputs()).unwrap()
    }

    fn state(&self, id: &str) -> ItemState {
        self.report().item(id).unwrap().state
    }
}

const RULES_METRIC_PLACEHOLDER: &str = "METRIC";

const RULES: &str = "groups:
  - name: crawlx-test
    rules:
      - alert: CrawlxFoo
        expr: |
          sum(rate(METRIC[5m])) > 1
        for: 1m
        labels: { severity: page }
        annotations:
          summary: \"x\"
          runbook: docs/ops/runbooks.md#rb-01, docs/ops/runbooks.md#1-crawlxfoo
";

const RUNBOOKS: &str = "# Runbooks

<a id=\"rb-01\"></a>

### RB-01 Stuck crawl

## Alert cards

## 1. CrawlxFoo
";

/// A tree under which every checklist item passes (with the model tier changing).
fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let ev = tmp.path().join("out");
    let repo = tmp.path().join("repo");
    let e = Env { _tmp: tmp, ev, repo };

    // scorecards
    let profiles = ["read_only", "test_environment", "authorized_security_test"];
    for fixture in ["g25", "a2"] {
        for p in profiles {
            write_json(&e.card(&format!("{fixture}-{p}")), &card(fixture, p));
        }
    }
    let mut g02 = card("g02", "read_only");
    g02["identity"] = json!({ "collision_rate": 0.001, "split_rate": 0.01, "key_collision_rate": 0.0 });
    write_json(&e.card("g02"), &g02);
    let mut g06 = card("g06", "read_only");
    g06["identity"] = json!({ "collision_rate": 0.002, "split_rate": 0.015, "key_collision_rate": 0.0 });
    write_json(&e.card("g06"), &g06);
    let mut g26 = card("g26", "read_only");
    g26["states"] = json!({
        "false_merge_pairs": 0, "false_split_pairs": 1, "false_merge_rate": 0.0,
        "false_split_rate": 0.02, "merges_hiding_actions": 0
    });
    write_json(&e.card("g26"), &g26);
    let enablement = |replay: Option<f64>, false_edge: Option<f64>| {
        json!({
            "replays_attempted": 10, "replays_succeeded": 10, "replay_success": replay,
            "recorded": 3, "spurious": 0, "false_edge_rate": false_edge, "recall": 1.0
        })
    };
    let mut g21 = card("g21", "read_only");
    g21["enablement"] = enablement(Some(0.95), None);
    write_json(&e.card("g21"), &g21);
    for fixture in ["g09", "g19"] {
        let mut c = card(fixture, "read_only");
        c["enablement"] = enablement(None, Some(0.05));
        write_json(&e.card(fixture), &c);
    }

    // g1 report: completed chaos suites for this build
    let pass_line =
        "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n";
    let chaos_suites: Vec<Value> = CHAOS_SUITES
        .iter()
        .map(|s| json!({ "suite": s, "exit_code": 0, "stdout": pass_line, "stderr": "" }))
        .collect();
    e.set_ev(
        "g1-report.json",
        &json!({
            "scorecards": [],
            "runs": [],
            "chaos": { "scope_digest": crawlx_strategies::registry::scope_digest(), "suites": chaos_suites }
        }),
    );

    // suites
    for id in SUITE_IDS {
        // chromium_upgrade is only read when the pin moved; recorded anyway
        let tool = matches!(id, "cargo_deny" | "criterion_gates");
        e.set_ev(&format!("suites/{id}.json"), &suite(id, !tool));
    }

    // other evidence
    e.set_ev("mutants-safety/outcomes.json", &mutants(19, 1));
    e.set_ev("findings.json", &json!({ "open_s1": 0, "open_s2": 0 }));
    e.set_ev(
        "run-to-run.json",
        &json!({ "different_seed_jaccard": 0.9, "previous_release_different_seed_jaccard": 0.9 }),
    );
    e.set_ev(
        "coverage-paired.json",
        &json!({
            "metric": "coverage.trusted",
            "seeds": [1, 2, 3],
            "baseline": [0.5, 0.5, 0.5],
            "candidate": [0.5, 0.51, 0.52],
            "direction": "higher_is_better",
            "bootstrap": { "pairs": 3, "mean_diff": 0.01, "lo": 0.0, "hi": 0.02, "level": 0.95, "resamples": 1000 },
            "wilcoxon": null
        }),
    );
    e.set_ev(
        "soak-report.json",
        &json!({
            "elapsed_s": 90000.0, "store": "postgres", "cycles": 40, "failures": 0, "actions": 800,
            "faults": [{ "t_s": 600.0 }], "verdict": { "verdict": "pass" }, "failed_cycles": []
        }),
    );
    e.set_ev(
        "flake-report.json",
        &json!({ "window_days": 30, "runs": 1000, "flaky_runs": 3 }),
    );
    e.set_ev("restore-drill.json", &json!({ "completed_on": "2026-10-01" }));
    e.set_ev(
        "g3-report.json",
        &json!({
            "calibration_samples": 10000, "ece": 0.04, "seeds": 5, "coverage_gain_ci_low": 0.01,
            "unauthorized_action_rate": 0.0, "warm_p95_ms": 50.0, "consecutive_nightly_improvements": 2
        }),
    );

    // repository files
    write_text(
        &e.repo.join("chromium-pin.toml"),
        "[chromium]\nversion = \"155.0.1\"\nsha256 = \"abc\"\nos = \"linux\"\n",
    );
    write_json(
        &e.repo.join("bench/baselines/release-base.json"),
        &json!({ "release": "v0", "chromium_pin": { "version": "155.0.1", "sha256": "abc" } }),
    );
    let metric = exported_metric_names().into_iter().next().unwrap();
    write_text(
        &e.repo.join("deploy/alerts/crawlx-rules.yaml"),
        &RULES.replace(RULES_METRIC_PLACEHOLDER, &metric),
    );
    write_text(&e.repo.join("docs/ops/runbooks.md"), RUNBOOKS);
    e
}

fn waiver(item: &str, expires: &str) -> Waiver {
    parse_waivers(&format!(
        r#"{{"waivers":[{{"item":"{item}","owner":"perf-team","reason":"shared runner noise","expires":"{expires}"}}]}}"#
    ))
    .unwrap()
    .remove(0)
}

#[test]
fn complete_evidence_makes_every_item_pass() {
    let e = env();
    let report = e.report();
    let not_passing: Vec<_> = report
        .items
        .iter()
        .filter(|i| i.state != ItemState::Pass)
        .map(|i| format!("{}: {:?} {}", i.id, i.state, i.detail))
        .collect();
    assert!(not_passing.is_empty(), "{not_passing:#?}");
    assert!(report.ready());
    assert_eq!(usize::try_from(report.counts.pass).unwrap(), report.items.len());
    assert_eq!(report.items.len(), item_ids().count());
    let md = report.markdown();
    assert!(md.contains("**READY**"), "{md}");
    for id in item_ids() {
        assert!(md.contains(&format!("`{id}`")), "{id} missing from the checklist");
    }
    // the JSON report round-trips
    let back: ReleaseReport = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    assert_eq!(back, report);
    assert_eq!(states(&report).len(), report.items.len());
}

#[test]
fn model_item_applies_only_when_the_tier_changes() {
    let e = env();
    let mut inputs = e.inputs();
    inputs.model_tier_changed = false;
    // even with no model evidence at all
    e.remove("g3-report.json");
    e.remove("suites/model_breaker_outage.json");
    let report = evaluate(&inputs).unwrap();
    assert_eq!(report.item("model_tier").unwrap().state, ItemState::NotApplicable);
    assert!(report.ready());
    assert_eq!(report.counts.not_applicable, 1);
    // when the tier changes the same tree blocks
    let report = e.report();
    assert_eq!(report.item("model_tier").unwrap().state, ItemState::Unmeasured);
    assert!(!report.ready());
}

#[test]
fn deleting_the_evidence_of_any_single_item_blocks_the_release() {
    let base = env().report();
    for item in &base.items {
        let e = env();
        for rel in &item.evidence {
            e.remove(rel);
        }
        let report = e.report();
        let after = report.item(&item.id).unwrap();
        assert!(
            matches!(after.state, ItemState::Unmeasured | ItemState::Fail),
            "{}: {:?} {}",
            item.id,
            after.state,
            after.detail
        );
        assert!(!report.ready(), "{} did not block the release", item.id);
    }
}

#[test]
fn single_failures_flip_their_item_and_the_verdict() {
    type Mutation = fn(&Env);
    fn case(id: &'static str, f: Mutation) -> (&'static str, Mutation) {
        (id, f)
    }
    macro_rules! cases {
        ($(($id:expr, $f:expr)),* $(,)?) => { vec![$(case($id, $f)),*] };
    }
    let cases = cases![
        ("unauthorized_action_rate", |e| {
            e.edit_card("a2-test_environment", |c| {
                c["safety"]["unauthorized"] = json!(1);
                c["safety"]["unauthorized_action_rate"] = json!(0.1);
            });
        }),
        ("unauthorized_action_rate", |e| e
            .remove("scorecards/g25-authorized_security_test.json")),
        ("ssrf_matrix", |e| e
            .edit_ev("suites/ssrf_matrix.json", |s| s["exit_code"] =
                json!(101))),
        ("scope_escape", |e| e
            .edit_ev("suites/scope_escape.json", |s| s["failed"] =
                json!(1))),
        ("secret_canary_zdr", |e| e
            .edit_ev("suites/secret_canary_zdr.json", |s| s["skipped"] =
                json!(1))),
        ("cargo_deny", |e| e
            .edit_ev("suites/cargo_deny.json", |s| s["exit_code"] =
                json!(1))),
        ("mutants_safety", |e| e
            .set_ev("mutants-safety/outcomes.json", &mutants(18, 2))),
        ("security_findings", |e| e
            .edit_ev("findings.json", |f| f["open_s2"] = json!(1))),
        ("repeated_non_idempotent", |e| {
            e.edit_card("g26", |c| c["unknown"]["repeated_non_idempotent"] = json!(1));
        }),
        ("worker_kill_reconciled", |e| {
            e.edit_card("g26", |c| c["unknown"]["reconciled"] = json!(1));
        }),
        ("worker_kill_reconciled", |e| {
            e.edit_ev("g1-report.json", |r| {
                r["chaos"]["scope_digest"] = json!("another-build")
            });
        }),
        ("state_false_merges", |e| {
            e.edit_card("g26", |c| c["states"]["merges_hiding_actions"] = json!(1));
        }),
        ("state_false_merges", |e| {
            e.edit_card("g26", |c| c["states"]["false_split_rate"] = json!(0.0501));
        }),
        ("identity_stability", |e| e.remove("scorecards/g06.json")),
        ("interactive_targets", |e| {
            e.edit_card("g02", |c| c["targets"]["by_mechanism"]["ax"] = prf(10, 0, 90));
        }),
        ("enablement", |e| e
            .edit_card("g21", |c| c["enablement"]["replay_success"] =
                json!(0.5))),
        ("enablement", |e| e
            .edit_card("g19", |c| c["enablement"]["false_edge_rate"] =
                json!(0.5))),
        ("stale_proposal_executions", |e| {
            e.edit_ev("suites/stale_proposal_executions.json", |s| {
                s["exit_code"] = json!(1)
            });
        }),
        ("quiescence_timeout_rate", |e| e
            .edit_card("g09", |c| c["quiescence_timeout_rate"] =
                json!(0.3))),
        ("trusted_lane_share", |e| {
            e.edit_card("g09", |c| {
                c["lanes"]["trusted"] = json!(50);
                c["lanes"]["diagnostic"] = json!(50);
            });
        }),
        ("same_seed_jaccard", |e| e
            .edit_card("g02", |c| c["run_to_run_jaccard"] = json!(0.99))),
        ("different_seed_jaccard", |e| {
            e.edit_ev("run-to-run.json", |r| r["different_seed_jaccard"] = json!(0.8));
        }),
        ("action_context_coverage", |e| {
            e.edit_ev("coverage-paired.json", |p| p["bootstrap"]["lo"] = json!(-0.01));
        }),
        ("differential_extraction", |e| {
            e.edit_ev("suites/differential_extraction.json", |s| s["passed"] = json!(0));
        }),
        ("snapshots_unchanged", |e| e
            .edit_ev("suites/snapshots_unchanged.json", |s| s["ignored"] =
                json!(2))),
        ("criterion_gates", |e| e
            .edit_ev("suites/criterion_gates.json", |s| s["exit_code"] =
                json!(1))),
        ("soak_invariants", |e| {
            e.edit_ev("soak-report.json", |s| {
                s["verdict"] = json!({ "verdict": "fail", "reasons": ["leak"] })
            });
        }),
        ("soak_invariants", |e| {
            e.edit_ev("soak-report.json", |s| {
                s["failed_cycles"] = json!([{ "stuck_intended": 1 }])
            });
        }),
        ("soak_invariants", |e| e
            .edit_ev("soak-report.json", |s| s["elapsed_s"] =
                json!(3600.0))),
        ("soak_invariants", |e| e
            .edit_ev("soak-report.json", |s| s["store"] = json!("memory"))),
        ("soak_invariants", |e| e
            .edit_ev("soak-report.json", |s| s["faults"] = json!([]))),
        ("chaos_suite", |e| {
            e.edit_ev("g1-report.json", |r| {
                r["chaos"]["suites"][0]["exit_code"] = json!(101)
            });
        }),
        ("chaos_slo", |e| e
            .edit_ev("suites/chaos_slo.json", |s| s["exit_code"] =
                json!(null))),
        ("flake_rate", |e| e
            .edit_ev("flake-report.json", |f| f["flaky_runs"] = json!(10))),
        ("flake_rate", |e| e
            .edit_ev("flake-report.json", |f| f["window_days"] = json!(7))),
        ("model_tier", |e| e
            .edit_ev("g3-report.json", |r| r["ece"] = json!(0.06))),
        ("model_tier", |e| e
            .edit_ev("suites/model_breaker_outage.json", |s| s
                ["exit_code"] =
                json!(1))),
        ("chromium_pin", |e| {
            write_text(
                &e.repo.join("chromium-pin.toml"),
                "[chromium]\nversion = \"156.0.0\"\nsha256 = \"def\"\n",
            );
            e.remove("suites/chromium_upgrade.json");
        }),
        ("migrations_tested", |e| e
            .edit_ev("suites/migrations_tested.json", |s| s["exit_code"] =
                json!(1))),
        ("restore_drill", |e| e
            .edit_ev("restore-drill.json", |d| d["completed_on"] =
                json!("2026-01-01"))),
        ("runbook_catalog", |e| {
            write_text(&e.repo.join("docs/ops/runbooks.md"), "# nothing\n");
        }),
    ];
    for (id, mutate) in cases {
        let e = env();
        mutate(&e);
        let report = e.report();
        let item = report.item(id).unwrap();
        assert!(
            matches!(item.state, ItemState::Fail | ItemState::Unmeasured),
            "{id}: {:?} {}",
            item.state,
            item.detail
        );
        assert!(!report.ready(), "{id}: the release stayed ready");
    }
}

#[test]
fn a_present_but_malformed_evidence_file_fails_the_item() {
    let e = env();
    write_text(&e.ev.join("findings.json"), "{ not json");
    write_text(&e.card("g26"), "[]");
    let report = e.report();
    assert_eq!(report.item("security_findings").unwrap().state, ItemState::Fail);
    assert_eq!(report.item("state_false_merges").unwrap().state, ItemState::Fail);
    assert!(!report.ready());
}

#[test]
fn thresholds_flip_exactly_at_their_boundary() {
    // (item, mutation of the passing tree, boundary value that passes, value just beyond)
    struct Case {
        item: &'static str,
        at: fn(&Env),
        beyond: fn(&Env),
    }
    let cases = [
        Case {
            item: "identity_stability",
            at: |e| e.edit_card("g02", |c| c["identity"]["collision_rate"] = json!(0.005)),
            beyond: |e| e.edit_card("g02", |c| c["identity"]["collision_rate"] = json!(0.0050001)),
        },
        Case {
            item: "identity_stability",
            at: |e| e.edit_card("g06", |c| c["identity"]["split_rate"] = json!(0.02)),
            beyond: |e| e.edit_card("g06", |c| c["identity"]["split_rate"] = json!(0.0200001)),
        },
        Case {
            item: "state_false_merges",
            at: |e| e.edit_card("g26", |c| c["states"]["false_split_rate"] = json!(0.05)),
            beyond: |e| e.edit_card("g26", |c| c["states"]["false_split_rate"] = json!(0.0500001)),
        },
        Case {
            item: "interactive_targets",
            at: |e| {
                e.edit_all_cards(|c| c["targets"]["by_mechanism"] = json!({}));
                e.edit_card("g02", |c| c["targets"]["by_mechanism"]["ax"] = prf(95, 0, 5));
            },
            beyond: |e| {
                e.edit_all_cards(|c| c["targets"]["by_mechanism"] = json!({}));
                e.edit_card("g02", |c| c["targets"]["by_mechanism"]["ax"] = prf(94, 0, 6));
            },
        },
        Case {
            item: "interactive_targets",
            at: |e| {
                e.edit_all_cards(|c| c["targets"]["by_mechanism"] = json!({}));
                e.edit_card("g02", |c| c["targets"]["by_mechanism"]["ax"] = prf(95, 5, 0));
            },
            beyond: |e| {
                e.edit_all_cards(|c| c["targets"]["by_mechanism"] = json!({}));
                e.edit_card("g02", |c| c["targets"]["by_mechanism"]["ax"] = prf(94, 6, 0));
            },
        },
        Case {
            item: "enablement",
            at: |e| e.edit_card("g21", |c| c["enablement"]["replay_success"] = json!(0.9)),
            beyond: |e| e.edit_card("g21", |c| c["enablement"]["replay_success"] = json!(0.8999)),
        },
        Case {
            item: "enablement",
            at: |e| e.edit_card("g09", |c| c["enablement"]["false_edge_rate"] = json!(0.1)),
            beyond: |e| e.edit_card("g09", |c| c["enablement"]["false_edge_rate"] = json!(0.1001)),
        },
        Case {
            item: "quiescence_timeout_rate",
            at: |e| e.edit_card("g06", |c| c["quiescence_timeout_rate"] = json!(0.02)),
            beyond: |e| e.edit_card("g06", |c| c["quiescence_timeout_rate"] = json!(0.0200001)),
        },
        Case {
            item: "trusted_lane_share",
            at: |e| {
                e.edit_card("g06", |c| {
                    c["lanes"]["trusted"] = json!(99);
                    c["lanes"]["diagnostic"] = json!(1);
                });
            },
            beyond: |e| {
                e.edit_card("g06", |c| {
                    c["lanes"]["trusted"] = json!(98);
                    c["lanes"]["diagnostic"] = json!(2);
                });
            },
        },
        Case {
            item: "different_seed_jaccard",
            at: |e| {
                e.set_ev(
                    "run-to-run.json",
                    &json!({ "different_seed_jaccard": 0.87, "previous_release_different_seed_jaccard": 0.90 }),
                );
            },
            beyond: |e| {
                e.set_ev(
                    "run-to-run.json",
                    &json!({ "different_seed_jaccard": 0.869, "previous_release_different_seed_jaccard": 0.90 }),
                );
            },
        },
        Case {
            item: "action_context_coverage",
            at: |e| e.edit_ev("coverage-paired.json", |p| p["bootstrap"]["lo"] = json!(0.0)),
            beyond: |e| e.edit_ev("coverage-paired.json", |p| p["bootstrap"]["lo"] = json!(-0.0001)),
        },
        Case {
            item: "mutants_safety",
            at: |e| e.set_ev("mutants-safety/outcomes.json", &mutants(95, 5)),
            beyond: |e| e.set_ev("mutants-safety/outcomes.json", &mutants(94, 6)),
        },
        Case {
            item: "flake_rate",
            at: |e| {
                e.set_ev(
                    "flake-report.json",
                    &json!({ "window_days": 30, "runs": 1000, "flaky_runs": 9 }),
                )
            },
            beyond: |e| {
                e.set_ev(
                    "flake-report.json",
                    &json!({ "window_days": 30, "runs": 1000, "flaky_runs": 10 }),
                )
            },
        },
        Case {
            item: "soak_invariants",
            at: |e| e.edit_ev("soak-report.json", |s| s["elapsed_s"] = json!(86400.0)),
            beyond: |e| e.edit_ev("soak-report.json", |s| s["elapsed_s"] = json!(86399.0)),
        },
        Case {
            item: "restore_drill",
            at: |e| e.set_ev("restore-drill.json", &json!({ "completed_on": "2026-08-12" })),
            beyond: |e| e.set_ev("restore-drill.json", &json!({ "completed_on": "2026-08-11" })),
        },
    ];
    for case in cases {
        let at = env();
        (case.at)(&at);
        assert_eq!(
            at.state(case.item),
            ItemState::Pass,
            "{} at the boundary",
            case.item
        );
        let beyond = env();
        (case.beyond)(&beyond);
        let state = beyond.state(case.item);
        assert!(
            matches!(state, ItemState::Fail | ItemState::Unmeasured),
            "{} beyond the boundary: {state:?}",
            case.item
        );
    }
}

#[test]
fn exempt_adversarial_fixtures_do_not_count_towards_quiescence() {
    let e = env();
    // G21 is `a2`: prompt-injection pages never settle
    e.edit_card("a2-read_only", |c| c["quiescence_timeout_rate"] = json!(0.9));
    assert_eq!(e.state("quiescence_timeout_rate"), ItemState::Pass);
}

#[test]
fn unmeasured_and_failed_items_are_told_apart() {
    let e = env();
    e.remove("flake-report.json");
    e.edit_ev("findings.json", |f| f["open_s1"] = json!(2));
    let report = e.report();
    assert_eq!(report.item("flake_rate").unwrap().state, ItemState::Unmeasured);
    assert_eq!(report.item("security_findings").unwrap().state, ItemState::Fail);
    assert_eq!(report.counts.unmeasured, 1);
    assert_eq!(report.counts.fail, 1);
    let md = report.markdown();
    assert!(
        md.contains("**BLOCKED**") && md.contains("- [ ] **unmeasured** `flake_rate`"),
        "{md}"
    );
}

#[test]
fn a_waiver_turns_a_failing_or_unmeasured_performance_row_into_waived() {
    let e = env();
    e.edit_ev("suites/criterion_gates.json", |s| s["exit_code"] = json!(1));
    let mut inputs = e.inputs();
    assert!(!evaluate(&inputs).unwrap().ready());
    inputs.waivers = vec![waiver("criterion_gates", "2026-12-31")];
    let report = evaluate(&inputs).unwrap();
    let item = report.item("criterion_gates").unwrap();
    assert_eq!(item.state, ItemState::Waived);
    assert_eq!(item.waiver.as_ref().unwrap().owner, "perf-team");
    assert!(
        item.detail.contains("perf-team") && item.detail.contains("was fail"),
        "{}",
        item.detail
    );
    assert!(report.ready());
    assert_eq!(report.counts.waived, 1);

    // unmeasured is waivable as well
    e.remove("suites/criterion_gates.json");
    assert_eq!(
        evaluate(&inputs).unwrap().item("criterion_gates").unwrap().state,
        ItemState::Waived
    );
}

#[test]
fn a_waiver_covers_only_its_own_row() {
    let e = env();
    e.edit_ev("suites/criterion_gates.json", |s| s["exit_code"] = json!(1));
    e.remove("flake-report.json");
    let mut inputs = e.inputs();
    inputs.waivers = vec![waiver("criterion_gates", "2026-12-31")];
    let report = evaluate(&inputs).unwrap();
    assert_eq!(report.item("criterion_gates").unwrap().state, ItemState::Waived);
    assert_eq!(report.item("flake_rate").unwrap().state, ItemState::Unmeasured);
    assert!(!report.ready());
}

#[test]
fn an_expired_waiver_does_not_apply_and_its_last_day_still_does() {
    let e = env();
    e.edit_ev("suites/criterion_gates.json", |s| s["exit_code"] = json!(1));
    let mut inputs = e.inputs();

    inputs.waivers = vec![waiver("criterion_gates", "2026-11-09")];
    let report = evaluate(&inputs).unwrap();
    assert_eq!(report.item("criterion_gates").unwrap().state, ItemState::Fail);
    assert!(!report.ready());
    assert!(
        report
            .waiver_notes
            .iter()
            .any(|n| n.contains("expired on 2026-11-09")),
        "{:?}",
        report.waiver_notes
    );

    inputs.waivers = vec![waiver("criterion_gates", TODAY)];
    let report = evaluate(&inputs).unwrap();
    assert_eq!(report.item("criterion_gates").unwrap().state, ItemState::Waived);
    assert!(report.ready());

    // an expired and a valid waiver together: the valid one applies
    inputs.waivers = vec![
        waiver("criterion_gates", "2026-01-01"),
        waiver("criterion_gates", "2027-01-01"),
    ];
    assert_eq!(
        evaluate(&inputs).unwrap().item("criterion_gates").unwrap().state,
        ItemState::Waived
    );
}

#[test]
fn a_waiver_never_hides_a_passing_row_or_a_non_performance_row() {
    let e = env();
    let mut inputs = e.inputs();
    inputs.waivers = vec![waiver("criterion_gates", "2026-12-31")];
    let report = evaluate(&inputs).unwrap();
    assert_eq!(report.item("criterion_gates").unwrap().state, ItemState::Pass);
    assert!(
        report.waiver_notes.iter().any(|n| n.contains("unused")),
        "{:?}",
        report.waiver_notes
    );

    for item in item_ids().filter(|i| !waivable_item_ids().any(|w| w == *i)) {
        inputs.waivers = vec![waiver(item, "2026-12-31")];
        let err = evaluate(&inputs).unwrap_err().to_string();
        assert!(err.contains("cannot be waived"), "{item}: {err}");
    }
}

#[test]
fn malformed_waivers_are_rejected_not_ignored() {
    let e = env();
    let mut inputs = e.inputs();
    let mut bad = waiver("criterion_gates", "2026-12-31");
    bad.item = "no_such_item".to_owned();
    inputs.waivers = vec![bad];
    assert!(evaluate(&inputs)
        .unwrap_err()
        .to_string()
        .contains("unknown item"));

    let mut bad = waiver("criterion_gates", "2026-12-31");
    bad.owner = "  ".to_owned();
    inputs.waivers = vec![bad];
    assert!(evaluate(&inputs)
        .unwrap_err()
        .to_string()
        .contains("owner and a reason"));

    let mut bad = waiver("criterion_gates", "2026-12-31");
    bad.reason = String::new();
    inputs.waivers = vec![bad];
    assert!(evaluate(&inputs).is_err());

    inputs.waivers = vec![waiver("criterion_gates", "next friday")];
    assert!(evaluate(&inputs).unwrap_err().to_string().contains("expires"));

    // the file format needs every field
    assert!(
        parse_waivers(r#"{"waivers":[{"item":"criterion_gates","owner":"a","expires":"2026-12-31"}]}"#)
            .is_err()
    );
    assert!(parse_waivers(r#"{"waivers":[]}"#).unwrap().is_empty());
}

#[test]
fn chromium_pin_change_needs_the_upgrade_suite() {
    let e = env();
    write_text(
        &e.repo.join("chromium-pin.toml"),
        "[chromium]\nversion = \"156.0.0\"\nsha256 = \"def\"\n",
    );
    e.remove("suites/chromium_upgrade.json");
    assert_eq!(e.state("chromium_pin"), ItemState::Unmeasured);
    e.set_ev("suites/chromium_upgrade.json", &suite("chromium_upgrade", true));
    assert_eq!(e.state("chromium_pin"), ItemState::Pass);
    e.edit_ev("suites/chromium_upgrade.json", |s| s["exit_code"] = json!(1));
    assert_eq!(e.state("chromium_pin"), ItemState::Fail);
}

#[test]
fn soak_pass_verdict_alone_does_not_satisfy_the_release_soak() {
    let e = env();
    e.edit_ev("soak-report.json", |s| {
        s["verdict"] = json!({ "verdict": "inconclusive", "reasons": ["short"] })
    });
    assert_eq!(e.state("soak_invariants"), ItemState::Unmeasured);
}

#[test]
fn libtest_summaries_are_summed_over_binaries() {
    let out = "running 2 tests\ntest result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\
               test result: FAILED. 4 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s\n";
    assert_eq!(parse_libtest(out), (6, 3, 1));
    assert_eq!(parse_libtest("nothing here"), (0, 0, 0));
}

#[test]
fn recorded_suites_carry_the_exit_status_and_counts_and_drive_the_verdict() {
    let tmp = tempfile::tempdir().unwrap();
    let ok = [
        "sh".to_owned(),
        "-c".to_owned(),
        "echo 'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'".to_owned(),
    ];
    let rec = record_suite(tmp.path(), "scope_escape", &ok, true).unwrap();
    assert_eq!(
        (rec.exit_code, rec.passed, rec.failed, rec.skipped),
        (Some(0), 3, 0, 0)
    );
    let stored: Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join("suites/scope_escape.json")).unwrap()).unwrap();
    assert_eq!(stored["id"], "scope_escape");
    assert_eq!(stored["passed"], 3);

    let skipped = [
        "sh".to_owned(),
        "-c".to_owned(),
        "echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'; echo 'skipped: no database' >&2".to_owned(),
    ];
    assert_eq!(
        record_suite(tmp.path(), "scope_escape", &skipped, true)
            .unwrap()
            .skipped,
        1
    );

    let failing = ["sh".to_owned(), "-c".to_owned(), "exit 3".to_owned()];
    assert_eq!(
        record_suite(tmp.path(), "cargo_deny", &failing, false)
            .unwrap()
            .exit_code,
        Some(3)
    );

    // the recorded files feed the checklist: exit 0 passes, exit 3 fails, a skip fails
    let e = env();
    std::fs::copy(
        tmp.path().join("suites/cargo_deny.json"),
        e.ev.join("suites/cargo_deny.json"),
    )
    .unwrap();
    assert_eq!(e.state("cargo_deny"), ItemState::Fail);
    std::fs::copy(
        tmp.path().join("suites/scope_escape.json"),
        e.ev.join("suites/scope_escape.json"),
    )
    .unwrap();
    assert_eq!(
        e.state("scope_escape"),
        ItemState::Fail,
        "a skipped test is not a pass"
    );

    // refused inputs
    assert!(record_suite(tmp.path(), "not_a_suite", &ok, true).is_err());
    assert!(record_suite(tmp.path(), "scope_escape", &[], true).is_err());
    assert!(record_suite(
        tmp.path(),
        "scope_escape",
        &["/nonexistent/binary".to_owned()],
        true
    )
    .is_err());
}

#[test]
fn runbook_cross_check_flags_unknown_metrics_missing_anchors_and_missing_cards() {
    let exported = exported_metric_names();
    let metric = exported.iter().next().unwrap().clone();
    let good = RULES.replace(RULES_METRIC_PLACEHOLDER, &metric);
    let ok = check_runbook_links(&good, RUNBOOKS, &exported);
    assert!(ok.problems.is_empty(), "{:?}", ok.problems);
    assert_eq!((ok.alerts, ok.metrics, ok.runbook_refs), (1, 1, 2));

    let bad_metric = RULES.replace(RULES_METRIC_PLACEHOLDER, "crawlx_no_such_metric_total");
    let r = check_runbook_links(&bad_metric, RUNBOOKS, &exported);
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("crawlx_no_such_metric_total")),
        "{:?}",
        r.problems
    );

    let r = check_runbook_links(&good, "## 1. CrawlxFoo\n", &exported);
    assert!(
        r.problems.iter().any(|p| p.contains("#rb-01")),
        "{:?}",
        r.problems
    );

    let r = check_runbook_links(&good, "<a id=\"rb-01\"></a>\n## 1. CrawlxFoo\n", &exported);
    assert!(r.problems.is_empty(), "{:?}", r.problems);

    let r = check_runbook_links(&good, "<a id=\"rb-01\"></a>\n", &exported);
    assert!(
        r.problems.iter().any(|p| p.contains("no alert card")),
        "{:?}",
        r.problems
    );

    // the metric on a comment line, a label value or an annotation is not a metric reference
    let with_noise = good.replace("summary: \"x\"", "summary: \"see crawlx_not_a_metric\"");
    let r = check_runbook_links(&format!("# crawlx_comment\n{with_noise}"), RUNBOOKS, &exported);
    assert!(r.problems.is_empty(), "{:?}", r.problems);
}

/// The shipped rules, runbooks and catalog agree, through the same code path `check` uses.
#[test]
fn shipped_alert_rules_and_runbooks_match_the_metric_catalog() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rules = std::fs::read_to_string(root.join("deploy/alerts/crawlx-rules.yaml")).unwrap();
    let runbooks = std::fs::read_to_string(root.join("docs/ops/runbooks.md")).unwrap();
    let r = check_runbook_links(&rules, &runbooks, &exported_metric_names());
    assert!(r.alerts >= 30, "{} alerts read", r.alerts);
    assert!(r.problems.is_empty(), "{:#?}", r.problems);
}
