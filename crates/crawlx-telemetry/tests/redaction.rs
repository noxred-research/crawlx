#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Secret shapes must never reach a log writer: no secret canary survives
//! the formatter.

mod common;

use common::Capture;
use crawlx_telemetry::{build_subscriber, spans, LogFormat, TelemetryConfig};
use proptest::prelude::*;

// Synthetic detector canary (the public jwt.io sample), assembled from parts.
const JWT: &str = concat!(
    "eyJhbGciOiJIUzI1NiJ9.",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
);
const HEX32: &str = "9f2c41aa0b7d4e1f8c3a5d6e7f801234";
const SK: &str = "sk-live_Zx81Qp0LmNaBcD";
const BEARER_TOKEN: &str = "AbCdEf123456.zyx";
const SECRETS: &[&str] = &[
    JWT,
    HEX32,
    SK,
    BEARER_TOKEN,
    "hunter2-canary",
    "cookie-canary-value",
];

fn capture(format: LogFormat, f: impl FnOnce()) -> String {
    let cap = Capture::default();
    let cfg = TelemetryConfig {
        format,
        filter: Some("trace".to_owned()),
        ..TelemetryConfig::default()
    };
    let sub = build_subscriber(&cfg, cap.clone()).unwrap();
    tracing::subscriber::with_default(sub, f);
    cap.text()
}

fn assert_clean(out: &str) {
    for s in SECRETS {
        assert!(!out.contains(s), "secret {s:?} leaked in:\n{out}");
    }
    assert!(out.contains("[REDACTED]"), "nothing was redacted:\n{out}");
}

fn emit_all() {
    let span = tracing::info_span!("action", crawl_id = "c-1", token = "hunter2-canary", note = %JWT);
    let _enter = span.enter();
    tracing::info!(password = "hunter2-canary", "login with {JWT}");
    tracing::warn!(
        authorization = format!("Bearer {BEARER_TOKEN}"),
        url = "https://example.org/a",
        "request failed"
    );
    tracing::error!(
        cookie = "cookie-canary-value",
        set_cookie = "a=b",
        secret = 42_u64,
        "cookies attached"
    );
    tracing::info!(session = HEX32, key = SK, detail = ?Some(JWT), "shapes in fields");
    tracing::info!("Authorization: Bearer {BEARER_TOKEN} and api_key={SK}");
}

#[test]
fn json_output_never_contains_secrets() {
    let out = capture(LogFormat::Json, emit_all);
    assert_clean(&out);
    for line in out.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v.get("timestamp").is_some() && v.get("level").is_some() && v.get("fields").is_some());
    }
}

#[test]
fn pretty_output_never_contains_secrets() {
    assert_clean(&capture(LogFormat::Pretty, emit_all));
}

#[test]
fn json_structure_and_ordinary_fields_survive() {
    let out = capture(LogFormat::Json, || {
        let span = spans::crawl_span(&"c-42", "hybrid", "read_only");
        let _e = span.enter();
        tracing::info!(
            count = 3_u64,
            ratio = 0.5,
            ok = true,
            url = "https://example.org/a?b=1",
            "fetched page"
        );
    });
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(v["level"], "INFO");
    assert_eq!(v["fields"]["message"], "fetched page");
    assert_eq!(v["fields"]["count"], 3);
    assert_eq!(v["fields"]["ratio"], 0.5);
    assert_eq!(v["fields"]["ok"], true);
    assert_eq!(v["fields"]["url"], "https://example.org/a?b=1");
    assert_eq!(v["spans"][0]["name"], "crawl");
    assert_eq!(v["spans"][0]["crawl_id"], "c-42");
    assert_eq!(v["spans"][0]["profile"], "read_only");
}

#[test]
fn deny_listed_field_names_are_masked_for_every_type() {
    let out = capture(LogFormat::Json, || {
        tracing::info!(password = 123_456_u64, Authorization = "plain", token = true, "x");
    });
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(v["fields"]["password"], "[REDACTED]");
    assert_eq!(v["fields"]["Authorization"], "[REDACTED]");
    assert_eq!(v["fields"]["token"], "[REDACTED]");
    assert!(!out.contains("123456"));
}

#[test]
fn span_fields_recorded_later_are_redacted() {
    let out = capture(LogFormat::Json, || {
        let span = tracing::info_span!(
            "run",
            crawl_id = "c-1",
            token = tracing::field::Empty,
            note = tracing::field::Empty
        );
        span.record("token", "hunter2-canary");
        span.record("note", JWT);
        let _e = span.enter();
        tracing::info!("inside");
    });
    assert_clean(&out);
    assert!(out.contains("\"crawl_id\":\"c-1\""));
}

#[test]
fn pretty_output_cannot_be_forged_with_newlines() {
    let out = capture(LogFormat::Pretty, || {
        tracing::info!(detail = "a\nINFO forged: line", "m\nINFO forged2");
    });
    // Header line plus the one field line; the embedded newlines stay escaped.
    assert_eq!(out.lines().count(), 2, "{out}");
}

#[test]
fn extra_redacted_fields_apply() {
    let cap = Capture::default();
    let cfg = TelemetryConfig {
        filter: Some("info".into()),
        extra_redacted_fields: vec!["session-handle".into()],
        ..TelemetryConfig::default()
    };
    tracing::subscriber::with_default(build_subscriber(&cfg, cap.clone()).unwrap(), || {
        tracing::info!(session_handle = "abc-visible-otherwise", "m");
    });
    assert!(!cap.text().contains("abc-visible-otherwise"));
}

#[test]
fn filter_directive_is_applied() {
    let out = capture(LogFormat::Json, || {});
    assert!(out.is_empty());
    let cap = Capture::default();
    let cfg = TelemetryConfig {
        filter: Some("warn".into()),
        ..TelemetryConfig::default()
    };
    tracing::subscriber::with_default(build_subscriber(&cfg, cap.clone()).unwrap(), || {
        tracing::info!("dropped");
        tracing::warn!("kept");
    });
    let text = cap.text();
    assert!(text.contains("kept") && !text.contains("dropped"));
}

#[test]
fn invalid_filter_is_a_typed_error() {
    let cfg = TelemetryConfig {
        filter: Some("info,[bad".into()),
        ..TelemetryConfig::default()
    };
    assert!(matches!(
        build_subscriber(&cfg, Capture::default()),
        Err(crawlx_telemetry::TelemetryError::InvalidFilter(_))
    ));
}

#[test]
fn span_constructors_use_the_constant_names() {
    let cap = Capture::default();
    let cfg = TelemetryConfig {
        filter: Some("trace".into()),
        ..TelemetryConfig::default()
    };
    tracing::subscriber::with_default(build_subscriber(&cfg, cap.clone()).unwrap(), || {
        let crawl = spans::crawl_span(&"c", "static", "read_only");
        let _c = crawl.enter();
        let run = spans::run_span(&"c", &"r", "anonymous", 0, 7);
        let _r = run.enter();
        let phase = spans::phase_span(&"c", "greedy");
        let _p = phase.enter();
        let obs = spans::observation_span(&"c", &"s", 1, 2, 3, "default");
        let _o = obs.enter();
        tracing::info!("in observation");
        drop(_o);
        let round = spans::policy_round_span(&"c", 4);
        let _pr = round.enter();
        tracing::info!("in round");
        drop(_pr);
        let act = spans::action_span(&"c", &"a", &"k", "click", "trusted", "high");
        let _a = act.enter();
        tracing::info!("in action");
    });
    let lines: Vec<serde_json::Value> = cap
        .text()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let names = |i: usize| -> Vec<String> {
        lines[i]["spans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        names(0),
        [spans::CRAWL, spans::RUN, spans::PHASE, spans::OBSERVATION]
    );
    assert_eq!(
        names(1),
        [spans::CRAWL, spans::RUN, spans::PHASE, spans::POLICY_ROUND]
    );
    assert_eq!(names(2), [spans::CRAWL, spans::RUN, spans::PHASE, spans::ACTION]);
    assert_eq!(lines[0]["spans"][3]["epoch.mut"], 3);
    assert_eq!(lines[2]["spans"][3]["lane"], "trusted");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn generated_secret_shapes_never_leak(
        hex in "[0-9a-f]{32,64}",
        sk in "sk-[A-Za-z0-9_]{8,32}",
        bearer in "[A-Za-z0-9._]{8,40}",
        a in "[a-z ]{0,12}",
        b in "[a-z ]{0,12}",
    ) {
        let out = capture(LogFormat::Json, || {
            tracing::info!(session = %hex, "{a}{hex}{b}");
            tracing::info!(key = %sk, "{a} {sk} {b}");
            tracing::info!("{a} Bearer {bearer} {b}");
        });
        for s in [&hex, &sk, &bearer] {
            prop_assert!(!out.contains(s.as_str()), "leaked {} in {}", s, out);
        }
    }
}
