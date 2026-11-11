//! `crawlx config check` and the LLM provider variables: the report shows what
//! `serve` and `worker` will use, and never a secret. Runs the real binary with a controlled
//! environment.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::process::{Command, Output};

const SECRETS: [&str; 7] = [
    "sk-default-1111",
    "sk-extract-2222",
    "sk-brand-3333",
    "tsk-typesafe-4444",
    "hunter2",
    "tokenInQuery",
    "sk-embed-5555",
];

fn check(format: &str, extra: &[(&str, &str)], strict: bool) -> Output {
    let dir = tempfile::tempdir().unwrap();
    // the pin file the check looks for (`browser.pin_file`), so no unrelated warning fails `--strict`
    std::fs::write(
        dir.path().join("chromium-pin.toml"),
        "[chromium]\nversion = \"1\"\n",
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("CRAWLX_ENVIRONMENT", "dev")
        .args(["config", "check", "--format", format]);
    if strict {
        cmd.arg("--strict");
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn secret_env() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "CRAWLX_LLM_BASE_URL",
            "https://svc:hunter2@llm.internal:8443/v1?token=tokenInQuery",
        ),
        ("CRAWLX_LLM_API_KEY", SECRETS[0]),
        ("CRAWLX_LLM_MODEL", "chat-model"),
        ("CRAWLX_EMBEDDING_MODEL", "embed-model"),
        ("EXTRACT_EMBEDDING_TOP_N", "4"),
        ("EXTRACTION_PROVIDER_BASE_URL", "http://llm-server:8000/v1"),
        ("EXTRACTION_PROVIDER_API_KEY", SECRETS[1]),
        ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "25"),
        ("EXTRACTION_PROVIDER_SHADOW_PERCENT", "10"),
        (
            "EXTRACTION_PROVIDER_TEAM_IDS",
            "00000000-0000-7000-8000-000000000001",
        ),
        ("BRANDING_LLM_MODEL", "vision-model"),
        ("BRANDING_LLM_API_KEY", SECRETS[2]),
        ("BRANDING_JEV_TIMEOUT_MS", "2500"),
        ("TYPESAFE_API_KEY", SECRETS[3]),
        ("BRANDING_JEV", "false"),
    ]
}

fn assert_no_secret(label: &str, text: &str) {
    for secret in SECRETS {
        assert!(!text.contains(secret), "{label} leaks {secret}:\n{text}");
    }
}

#[test]
fn the_toml_report_prints_the_providers_and_redacts_every_secret() {
    let out = check("toml", &secret_env(), false);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_no_secret("stdout", &stdout);
    assert_no_secret("stderr", &stderr);
    assert!(
        out.status.success(),
        "warnings alone do not fail:\n{stdout}\n{stderr}"
    );

    for needle in [
        "[intel.llm]",
        "endpoint = \"https://<redacted>@llm.internal:8443/v1?<redacted>\"",
        "model = \"chat-model\"",
        "[intel.llm.apiKey]",
        "ref = \"env:CRAWLX_LLM_API_KEY\"",
        "status = \"present\"",
        "[intel.embeddings]",
        "model = \"embed-model\"",
        "topN = 4",
        "[intel.extraction]",
        "model = \"extraction-v1\"",
        "rolloutPercent = 25",
        "shadowPercent = 10",
        "ref = \"env:EXTRACTION_PROVIDER_API_KEY\"",
        "[intel.branding]",
        "model = \"vision-model\"",
        "timeoutMs = 2500",
        "ref = \"env:BRANDING_LLM_API_KEY\"",
    ] {
        assert!(stdout.contains(needle), "`{needle}` missing from:\n{stdout}");
    }
    for warning in [
        "warning: TYPESAFE_API_KEY: set but has no effect",
        "warning: BRANDING_JEV: set but has no effect",
    ] {
        assert!(stdout.contains(warning), "`{warning}` missing from:\n{stdout}");
    }
}

#[test]
fn the_json_report_has_an_intel_object_without_secrets() {
    let out = check("json", &secret_env(), false);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_no_secret("json", &stdout);
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(doc["ok"], true, "{stdout}");
    let intel = &doc["intel"];
    assert_eq!(intel["llm"]["apiKey"]["status"], "present");
    assert_eq!(
        intel["extraction"]["teamIds"][0],
        "00000000-0000-7000-8000-000000000001"
    );
    assert_eq!(intel["extraction"]["maxInputBytes"], 400_000);
    assert_eq!(intel["embeddings"]["endpointFrom"], "default llm");
    assert_eq!(intel["branding"]["apiKey"]["ref"], "env:BRANDING_LLM_API_KEY");
    let unsupported: Vec<&str> = intel["unsupported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["variable"].as_str().unwrap())
        .collect();
    assert_eq!(unsupported, ["TYPESAFE_API_KEY", "BRANDING_JEV"]);
    assert!(
        doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["key"] == "TYPESAFE_API_KEY" && f["error"] == false),
        "{stdout}"
    );
}

#[test]
fn strict_mode_fails_on_a_variable_crawlx_cannot_act_on() {
    let out = check("json", &[("TYPESAFE_API_KEY", SECRETS[3])], true);
    assert_eq!(out.status.code(), Some(1));
    assert_no_secret("json", &String::from_utf8(out.stdout).unwrap());
}

#[test]
fn an_unconfigured_environment_reports_no_provider_and_passes() {
    let out = check("json", &[], true);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{stdout}");
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(doc["intel"], serde_json::json!({ "unsupported": [] }));
}

#[test]
fn a_bad_provider_setting_fails_the_check_without_echoing_the_text() {
    let out = check(
        "json",
        &[
            ("CRAWLX_LLM_BASE_URL", "http://x/v1"),
            ("EXTRACTION_PROVIDER_BASE_URL", "http://y/v1"),
            ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "sk-pasted-the-key-here"),
        ],
        false,
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("EXTRACTION_PROVIDER_ROLLOUT_PERCENT must be"),
        "{stdout}"
    );
    assert!(!stdout.contains("sk-pasted"), "{stdout}");

    let out = check("json", &[("EXTRACTION_PROVIDER_BASE_URL", "http://y/v1")], false);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("default LLM, which is not configured"),
        "{stdout}"
    );
}

#[test]
fn a_set_key_variable_is_present_and_no_key_is_not_configured() {
    // the extraction key reference is `env:EXTRACTION_PROVIDER_API_KEY`, and the variable is set
    let out = check(
        "json",
        &[
            ("CRAWLX_LLM_BASE_URL", "http://x/v1"),
            ("EXTRACTION_PROVIDER_BASE_URL", "http://y/v1"),
            ("EXTRACTION_PROVIDER_API_KEY", SECRETS[1]),
        ],
        false,
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_no_secret("json", &stdout);
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(doc["intel"]["extraction"]["apiKey"]["status"], "present");
    assert_eq!(doc["intel"]["llm"]["apiKey"]["configured"], false);
}
