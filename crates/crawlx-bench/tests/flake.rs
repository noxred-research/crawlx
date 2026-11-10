//! Flake tooling: junit classification, the 14-day quarantine rule, the 30-day flake rate,
//! filtersets, expiry and the history/quarantine file formats. Dates are explicit inputs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Days, NaiveDate};
use crawlx_bench::flake::{
    in_window, issue_body, report_markdown, FlakeError, FlakeSummary, History, JunitReport, Outcome,
    Quarantine, QUARANTINE_HEADER,
};

fn d(y: i32, m: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, day).unwrap()
}

fn ago(today: NaiveDate, days: u64) -> NaiveDate {
    today.checked_sub_days(Days::new(days)).unwrap()
}

/// A junit document in the shape `cargo nextest` writes with `retries = 1`.
const JUNIT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- <failure> in a comment is not a failure -->
<testsuites name="nextest-run" tests="6" failures="1" errors="0" uuid="0" timestamp="2026-11-01T00:00:00Z" time="1.5">
    <testsuite name="crawlx-bench::lane_chromium" tests="4" disabled="0" errors="0" failures="1">
        <testcase name="steady" classname="crawlx-bench::lane_chromium" timestamp="2026-11-01T00:00:00Z" time="0.1">
            <system-out><![CDATA[<failure message="forged"/> <flakyFailure/>]]></system-out>
        </testcase>
        <testcase name="intermittent" classname="crawlx-bench::lane_chromium" timestamp="2026-11-01T00:00:00Z" time="0.2">
            <flakyFailure timestamp="2026-11-01T00:00:00Z" time="0.1" type="test failure">
                <stack-trace>assertion failed</stack-trace>
                <system-out/>
            </flakyFailure>
        </testcase>
        <testcase name="broken" classname="crawlx-bench::lane_chromium" timestamp="2026-11-01T00:00:00Z" time="0.2">
            <failure message="exit code 101" type="test failure">boom</failure>
            <rerunFailure timestamp="2026-11-01T00:00:00Z" time="0.1" type="test failure">
                <stack-trace>boom</stack-trace>
            </rerunFailure>
        </testcase>
        <testcase name="ignored" classname="crawlx-bench::lane_chromium">
            <skipped/>
        </testcase>
    </testsuite>
    <testsuite name="crawlx-core" tests="2" disabled="0" errors="0" failures="0">
        <testcase name="ids::roundtrip" classname="crawlx-core" time="0.0"/>
        <testcase name="ids::lt&lt;gt&gt;&amp;&#39;q" classname="crawlx-core" time="0.0">
            <flakyError type="test failure"/>
        </testcase>
    </testsuite>
</testsuites>
"#;

fn report_of(xml: &str) -> JunitReport {
    JunitReport::parse(xml).unwrap()
}

#[test]
fn junit_classifies_pass_flaky_failed_and_skipped() {
    let report = report_of(JUNIT);
    let cases: Vec<(&str, Outcome)> = report.cases().iter().map(|(id, o)| (id.as_str(), *o)).collect();
    assert_eq!(
        cases,
        vec![
            ("crawlx-bench::lane_chromium::broken", Outcome::Failed),
            ("crawlx-bench::lane_chromium::ignored", Outcome::Skipped),
            ("crawlx-bench::lane_chromium::intermittent", Outcome::Flaky),
            ("crawlx-bench::lane_chromium::steady", Outcome::Pass),
            ("crawlx-core::ids::lt<gt>&'q", Outcome::Flaky),
            ("crawlx-core::ids::roundtrip", Outcome::Pass),
        ]
    );
    // the skipped test is not an execution
    assert_eq!(report.executions(), 5);
    assert_eq!(
        report.with_outcome(Outcome::Flaky),
        vec![
            "crawlx-bench::lane_chromium::intermittent",
            "crawlx-core::ids::lt<gt>&'q"
        ]
    );
}

#[test]
fn captured_output_and_comments_cannot_forge_a_result() {
    // `steady` carries `<failure>` and `<flakyFailure>` inside CDATA, and the document a failure
    // inside a comment: both stay Pass
    assert_eq!(
        report_of(JUNIT).cases()["crawlx-bench::lane_chromium::steady"],
        Outcome::Pass
    );
}

#[test]
fn only_direct_children_of_a_testcase_decide_the_outcome() {
    let xml = r#"<testsuite name="b"><testcase name="t" classname="b">
        <system-out><failure/></system-out></testcase></testsuite>"#;
    assert_eq!(report_of(xml).cases()["b::t"], Outcome::Pass);
}

#[test]
fn testsuite_name_stands_in_for_a_missing_classname() {
    let xml = r#"<testsuite name="crawlx-url"><testcase name="a::b"/></testsuite>"#;
    assert_eq!(report_of(xml).cases()["crawlx-url::a::b"], Outcome::Pass);
}

#[test]
fn quoted_attribute_values_may_hold_a_closing_angle_bracket() {
    let xml = r#"<testsuite name="b"><testcase name='a>b' classname="b" note="x &gt; y"/></testsuite>"#;
    assert!(report_of(xml).cases().contains_key("b::a>b"));
}

#[test]
fn malformed_junit_is_an_error() {
    for xml in [
        r#"<testsuite name="b"><testcase name="t">"#,
        r#"<testsuite name="b"><testcase name="t"></testsuite>"#,
        r#"</testsuite>"#,
        r#"<testsuite name="b"><testcase classname="b"/></testsuite>"#,
        r#"<testsuite name="b"><testcase name="t"#,
        r#"<testsuite name="b"><!-- open"#,
    ] {
        assert!(
            matches!(JunitReport::parse(xml), Err(FlakeError::Junit { .. })),
            "{xml}"
        );
    }
    assert!(report_of("").cases().is_empty());
}

#[test]
fn merge_keeps_the_worse_outcome_of_a_test_reported_twice() {
    let mut a = report_of(r#"<testsuite name="b"><testcase name="t"/><testcase name="u"/></testsuite>"#);
    let b = report_of(
        r#"<testsuite name="b"><testcase name="t"><flakyFailure/></testcase><testcase name="u"><failure/></testcase></testsuite>"#,
    );
    a.merge(b);
    assert_eq!(a.cases()["b::t"], Outcome::Flaky);
    assert_eq!(a.cases()["b::u"], Outcome::Failed);
    let c = report_of(r#"<testsuite name="b"><testcase name="u"/></testsuite>"#);
    a.merge(c);
    assert_eq!(a.cases()["b::u"], Outcome::Failed);
}

fn flaky_run(history: &mut History, date: NaiveDate, suite: &str, flaky: &[&str], executions: u64) {
    let mut xml = String::from(r#"<testsuite name="s">"#);
    for i in 0..executions.saturating_sub(u64::try_from(flaky.len()).unwrap()) {
        xml.push_str(&format!(r#"<testcase name="ok{i}" classname="s"/>"#));
    }
    for id in flaky {
        let (bin, name) = id.split_once("::").unwrap();
        xml.push_str(&format!(
            r#"<testcase name="{name}" classname="{bin}"><flakyFailure/></testcase>"#
        ));
    }
    xml.push_str("</testsuite>");
    history.record(date, suite, &report_of(&xml));
}

#[test]
fn two_flake_events_do_not_quarantine() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    flaky_run(&mut h, ago(today, 5), "ci", &["b::t"], 10);
    flaky_run(&mut h, today, "ci", &["b::t"], 10);
    assert_eq!(h.flake_events(today)["b::t"].len(), 2);
    assert!(h.quarantine_candidates(today).is_empty());
}

#[test]
fn three_flake_events_inside_14_days_quarantine() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    for age in [13, 6, 0] {
        flaky_run(&mut h, ago(today, age), "ci", &["b::t", "b::other"], 10);
    }
    flaky_run(&mut h, ago(today, 1), "ci", &["b::other"], 10);
    flaky_run(&mut h, ago(today, 2), "browser", &["b::t"], 10);
    let candidates = h.quarantine_candidates(today);
    let ids: Vec<&str> = candidates.keys().map(String::as_str).collect();
    assert_eq!(ids, vec!["b::other", "b::t"]);
    assert_eq!(candidates["b::t"].len(), 4);
    assert_eq!(candidates["b::other"].len(), 4);
}

#[test]
fn three_flake_events_spread_over_more_than_14_days_do_not() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    // 14 days ago is outside the window, so only two events count
    for age in [14, 7, 0] {
        flaky_run(&mut h, ago(today, age), "ci", &["b::t"], 10);
    }
    assert_eq!(h.flake_events(today)["b::t"].len(), 2);
    assert!(h.quarantine_candidates(today).is_empty());
}

#[test]
fn window_boundaries_are_exact() {
    let today = d(2026, 11, 10);
    assert!(in_window(today, today, 14));
    assert!(in_window(ago(today, 13), today, 14));
    assert!(!in_window(ago(today, 14), today, 14));
    assert!(!in_window(
        today.checked_add_days(Days::new(1)).unwrap(),
        today,
        14
    ));
    assert!(in_window(ago(today, 29), today, 30));
    assert!(!in_window(ago(today, 30), today, 30));
    assert!(!in_window(today, today, 0));
}

#[test]
fn one_event_per_run_even_when_a_test_is_listed_twice_in_it() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    h.runs.push(crawlx_bench::flake::Run {
        date: today,
        suite: "ci".into(),
        executions: 4,
        flaky: vec!["b::t".into(), "b::t".into()],
    });
    assert_eq!(h.flake_events(today)["b::t"], vec![today]);
    assert_eq!(h.pr_summary(today).flaky_runs, 1);
}

#[test]
fn flake_rate_arithmetic_over_the_30_day_window() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    flaky_run(&mut h, ago(today, 29), "ci", &["b::t"], 100); // in
    flaky_run(&mut h, ago(today, 10), "browser", &["b::t", "b::u"], 200); // in
    flaky_run(&mut h, ago(today, 1), "nightly", &["b::q"], 50); // not a PR suite
    let pr = h.pr_summary(today);
    assert_eq!(
        pr,
        FlakeSummary {
            window_days: 30,
            runs: 300,
            flaky_runs: 3
        }
    );
    assert!((pr.rate().unwrap() - 0.01).abs() < 1e-12);
    let all = h.summary(today, |_| true);
    assert_eq!((all.runs, all.flaky_runs), (350, 4));
    let only_ci = h.summary(today, |s| s == "ci");
    assert_eq!((only_ci.runs, only_ci.flaky_runs), (100, 1));
    // one day later the oldest run has left the window
    let later = h.pr_summary(today.checked_add_days(Days::new(1)).unwrap());
    assert_eq!((later.runs, later.flaky_runs), (200, 2));
}

#[test]
fn release_gate_needs_a_rate_strictly_below_one_percent() {
    let mk = |runs, flaky_runs| FlakeSummary {
        window_days: 30,
        runs,
        flaky_runs,
    };
    assert!(mk(10_000, 99).meets_release_gate());
    assert!(!mk(10_000, 100).meets_release_gate()); // exactly 1%
    assert!(!mk(100, 1).meets_release_gate());
    assert!(mk(100, 0).meets_release_gate());
    assert!(!mk(0, 0).meets_release_gate()); // no evidence
    assert_eq!(mk(0, 0).rate(), None);
    assert!(!mk(u64::MAX, u64::MAX).meets_release_gate());
}

#[test]
fn the_summary_file_has_exactly_the_three_fields() {
    let json = FlakeSummary {
        window_days: 30,
        runs: 7,
        flaky_runs: 1,
    }
    .to_json()
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let object = value.as_object().unwrap();
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["flaky_runs", "runs", "window_days"]);
    assert_eq!(value["window_days"], 30);
    assert_eq!(value["runs"], 7);
    assert_eq!(value["flaky_runs"], 1);
}

fn quarantine_of(ids: &[&str], since: NaiveDate) -> Quarantine {
    Quarantine {
        test: ids
            .iter()
            .map(|id| crawlx_bench::flake::QuarantineEntry {
                id: (*id).into(),
                since,
                reason: "r".into(),
            })
            .collect(),
    }
}

#[test]
fn filtersets_exclude_for_pr_and_select_only_for_nightly() {
    let empty = Quarantine::default();
    assert_eq!(empty.filterset_exclude(), "all()");
    assert_eq!(empty.filterset_only(), "none()");

    let q = quarantine_of(&["crawlx-bench::lane_chromium::link_fixtures"], d(2026, 11, 1));
    assert_eq!(
        q.filterset_only(),
        "((binary_id(=crawlx-bench) & test(=lane_chromium::link_fixtures)) | (binary_id(=crawlx-bench::lane_chromium) & test(=link_fixtures)))"
    );
    assert_eq!(q.filterset_exclude(), format!("not ({})", q.filterset_only()));

    // a two-segment id has one reading; ids are sorted; matcher arguments are escaped
    let q = quarantine_of(&["z::b", "a::t(1,2)"], d(2026, 11, 1));
    assert_eq!(
        q.filterset_only(),
        "(binary_id(=a) & test(=t(1\\,2\\))) | (binary_id(=z) & test(=b))"
    );
    assert_eq!(
        q.filterset_exclude(),
        "not ((binary_id(=a) & test(=t(1\\,2\\))) | (binary_id(=z) & test(=b)))"
    );
}

#[test]
fn quarantine_expires_after_14_days() {
    let today = d(2026, 11, 20);
    let q = Quarantine {
        test: vec![
            crawlx_bench::flake::QuarantineEntry {
                id: "b::exact".into(),
                since: ago(today, 14),
                reason: "r".into(),
            },
            crawlx_bench::flake::QuarantineEntry {
                id: "b::old".into(),
                since: ago(today, 15),
                reason: "r".into(),
            },
            crawlx_bench::flake::QuarantineEntry {
                id: "b::new".into(),
                since: today,
                reason: "r".into(),
            },
        ],
    };
    let expired: Vec<&str> = q.expired(today).iter().map(|e| e.id.as_str()).collect();
    assert_eq!(expired, vec!["b::old"]);
    let tomorrow = today.checked_add_days(Days::new(1)).unwrap();
    let expired: Vec<&str> = q.expired(tomorrow).iter().map(|e| e.id.as_str()).collect();
    assert_eq!(expired, vec!["b::exact", "b::old"]);
}

#[test]
fn quarantine_adds_new_tests_and_keeps_existing_entries() {
    let today = d(2026, 11, 10);
    let old = d(2026, 10, 30);
    let mut q = quarantine_of(&["b::kept"], old);
    let mut candidates = std::collections::BTreeMap::new();
    candidates.insert("b::kept".to_owned(), vec![today; 3]);
    candidates.insert("b::new".to_owned(), vec![ago(today, 2), ago(today, 1), today]);
    let added = q.add_candidates(&candidates, today);
    assert_eq!(added, vec!["b::new"]);
    assert_eq!(q.test.len(), 2);
    assert_eq!(q.test[0].id, "b::kept");
    assert_eq!(q.test[0].since, old, "an existing entry is not re-dated");
    assert_eq!(q.test[1].since, today);
    assert!(q.test[1].reason.starts_with("3 flake events in 14 days"));
    assert!(q.add_candidates(&candidates, today).is_empty());
}

#[test]
fn quarantine_file_round_trips_and_is_ordered() {
    let empty = Quarantine::default().to_toml().unwrap();
    assert_eq!(empty, QUARANTINE_HEADER);
    assert_eq!(Quarantine::from_toml(&empty).unwrap(), Quarantine::default());

    let q = quarantine_of(&["b::z", "a::y::x"], d(2026, 11, 1));
    let text = q.to_toml().unwrap();
    assert!(text.starts_with(QUARANTINE_HEADER));
    assert!(text.find("a::y::x").unwrap() < text.find("b::z").unwrap());
    assert!(text.contains("[[test]]"));
    assert!(text.contains("since = \"2026-11-01\""));
    let back = Quarantine::from_toml(&text).unwrap();
    assert_eq!(back.test.len(), 2);
    assert_eq!(back.to_toml().unwrap(), text);

    let parsed = Quarantine::from_toml(
        "[[test]]\nid = \"crawlx-worker::browser_robots::a_clicked_link\"\nsince = \"2026-11-02\"\nreason = \"flaky\"\n",
    )
    .unwrap();
    assert_eq!(parsed.test[0].since, d(2026, 11, 2));
}

#[test]
fn quarantine_file_rejects_bad_ids_dates_and_duplicates() {
    let entry =
        |id: &str, since: &str| format!("[[test]]\nid = \"{id}\"\nsince = \"{since}\"\nreason = \"r\"\n");
    assert!(matches!(
        Quarantine::from_toml(&entry("no_separator", "2026-11-01")),
        Err(FlakeError::InvalidTestId(_))
    ));
    assert!(matches!(
        Quarantine::from_toml(&entry("b::", "2026-11-01")),
        Err(FlakeError::InvalidTestId(_))
    ));
    assert!(matches!(
        Quarantine::from_toml(&entry("b::t", "yesterday")),
        Err(FlakeError::QuarantineParse(_))
    ));
    let twice = format!("{}{}", entry("b::t", "2026-11-01"), entry("b::t", "2026-11-02"));
    assert!(matches!(
        Quarantine::from_toml(&twice),
        Err(FlakeError::DuplicateQuarantine(id)) if id == "b::t"
    ));
}

#[test]
fn history_round_trips_and_checks_the_version() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    flaky_run(&mut h, today, "ci", &["b::t"], 3);
    let json = h.to_json().unwrap();
    assert!(json.ends_with('\n'));
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["runs"][0]["date"], "2026-11-10");
    assert_eq!(value["runs"][0]["suite"], "ci");
    assert_eq!(value["runs"][0]["executions"], 3);
    assert_eq!(value["runs"][0]["flaky"], serde_json::json!(["b::t"]));
    assert_eq!(History::from_json(&json).unwrap(), h);

    assert!(matches!(
        History::from_json(r#"{"version": 2, "runs": []}"#),
        Err(FlakeError::HistoryVersion {
            found: 2,
            expected: 1
        })
    ));
    assert!(matches!(History::from_json("{"), Err(FlakeError::Json(_))));
}

#[test]
fn history_files_load_save_and_a_missing_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/history.json");
    assert_eq!(History::load(&path).unwrap(), History::default());
    let mut h = History::default();
    flaky_run(&mut h, d(2026, 11, 10), "ci", &["b::t"], 2);
    h.save(&path).unwrap();
    assert_eq!(History::load(&path).unwrap(), h);

    let q_path = dir.path().join("ci/quarantine.toml");
    assert_eq!(Quarantine::load(&q_path).unwrap(), Quarantine::default());
    let q = quarantine_of(&["b::t"], d(2026, 11, 10));
    q.save(&q_path).unwrap();
    assert_eq!(Quarantine::load(&q_path).unwrap(), q);
}

#[test]
fn record_prunes_runs_older_than_the_rate_window_and_orders_runs() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    flaky_run(&mut h, ago(today, 31), "ci", &[], 5);
    flaky_run(&mut h, ago(today, 29), "ci", &[], 5);
    flaky_run(&mut h, today, "nightly", &[], 5);
    flaky_run(&mut h, today, "browser", &[], 5);
    flaky_run(&mut h, ago(today, 3), "ci", &[], 5);
    let order: Vec<(NaiveDate, &str)> = h.runs.iter().map(|r| (r.date, r.suite.as_str())).collect();
    assert_eq!(
        order,
        vec![
            (ago(today, 29), "ci"),
            (ago(today, 3), "ci"),
            (today, "browser"),
            (today, "nightly"),
        ]
    );
}

#[test]
fn output_does_not_depend_on_recording_order() {
    let today = d(2026, 11, 10);
    let record_all = |order: &[usize]| {
        let runs: [(u64, &str, &[&str]); 3] = [
            (2, "ci", &["b::t", "a::u"]),
            (1, "browser", &["b::t"]),
            (0, "ci", &["a::u"]),
        ];
        let mut h = History::default();
        for i in order {
            let (age, suite, flaky) = runs[*i];
            flaky_run(&mut h, ago(today, age), suite, flaky, 10);
        }
        h
    };
    let a = record_all(&[0, 1, 2]);
    let b = record_all(&[2, 0, 1]);
    assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    assert_eq!(
        report_markdown(&a, &Quarantine::default(), today),
        report_markdown(&b, &Quarantine::default(), today)
    );
    // the flaky ids inside a run are sorted regardless of the junit order
    assert_eq!(a.runs[0].flaky, vec!["a::u", "b::t"]);
    assert_eq!(
        a.flake_events(today).keys().collect::<Vec<_>>(),
        vec!["a::u", "b::t"]
    );
}

#[test]
fn issue_body_names_the_events_the_quarantine_and_the_policy() {
    let today = d(2026, 11, 10);
    let events = [ago(today, 4), ago(today, 2), today];
    let none = Quarantine::default();
    let body = issue_body("b::t", &events, &none, today);
    assert!(body.contains("`b::t` failed and then passed on the automatic rerun."));
    assert!(body.contains("ending 2026-11-10: 3"));
    assert!(body.contains("- 2026-11-06\n- 2026-11-08\n- 2026-11-10\n"));
    assert!(body.contains("flake-report quarantine"));

    let few = issue_body("b::t", &events[..2], &none, today);
    assert!(few.contains("Not quarantined"));

    let q = quarantine_of(&["b::t"], d(2026, 11, 1));
    let quarantined = issue_body("b::t", &events, &q, today);
    assert!(quarantined.contains("Quarantined since 2026-11-01"));
    assert!(quarantined.contains("Fix or delete it by 2026-11-15."));
}

#[test]
fn report_markdown_has_one_section_per_flaky_test_and_the_rate() {
    let today = d(2026, 11, 10);
    let mut h = History::default();
    assert!(report_markdown(&h, &Quarantine::default(), today).contains("n/a (no executions)"));
    flaky_run(&mut h, today, "ci", &["b::t", "a::u"], 200);
    let text = report_markdown(&h, &Quarantine::default(), today);
    assert!(text.contains("2 flaky of 200 executions (1.000%)"));
    assert!(text.find("## Flaky test: a::u").unwrap() < text.find("## Flaky test: b::t").unwrap());
    assert_eq!(text.matches("## Flaky test:").count(), 2);
}

#[test]
fn the_committed_quarantine_file_parses_and_starts_with_the_policy_header() {
    let text = include_str!("../../../ci/quarantine.toml");
    assert!(text.starts_with("# Quarantined flaky tests"));
    let q = Quarantine::from_toml(text).unwrap();
    // every committed entry carries a reason an operator can act on
    assert!(q.test.iter().all(|e| !e.reason.trim().is_empty()));
}
