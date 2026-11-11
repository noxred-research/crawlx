//! Real offline source-import command acceptance, never a source-runtime parity claim.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::CreateCrawl;
use serde_json::{json, Value};
use std::process::{Command, Output};

fn command(manifest: &Value, convert: bool) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("export.json");
    std::fs::write(&path, serde_json::to_vec(manifest).unwrap()).unwrap();
    Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .arg("source-import")
        .arg(if convert { "convert" } else { "inspect" })
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn four_pinned_dialects_emit_real_native_config_and_run_native_parser_offline() {
    for (family, release, seed_key, limit_key) in [
        ("js-actor", "3.18.2", "startUrls", "maxRequestsPerCrawl"),
        ("py-actor", "1.11.0", "start_urls", "max_requests_per_crawl"),
        ("python-spider", "2.19.0", "start_urls", "CLOSESPIDER_PAGECOUNT"),
        ("go-collector", "2.2.0", "URL", "MaxRequests"),
    ] {
        let seed = if family == "go-collector" {
            json!("https://fixture.test/article?resource=7")
        } else {
            json!(["https://fixture.test/article?resource=7"])
        };
        let output = command(
            &json!({"version":1,"source":family,"sourceVersion":release,
            "options":{seed_key:seed,limit_key:3}}),
            true,
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut native: CreateCrawl = serde_json::from_slice(&output.stdout).unwrap();
        native.normalize().unwrap();
        assert_eq!(native.limits.urls, 3);
        assert_eq!(native.seed_url.query(), Some("resource=7"));
        let document = crawlx_extract::Extractor::extract_bytes_with_projection(
            b"<html><head><title>Offline fixture</title></head><body><article><p>Owned fixture parser reads native converted settings without source execution or network access.</p></article></body></html>",
            &native.seed_url,
            &crawlx_extract::ExtractOptions::default(),
            &|_| None,
        ).unwrap();
        assert_eq!(document.title.as_deref(), Some("Offline fixture"));
    }
}

#[test]
fn unsupported_settings_print_complete_redacted_pin_report_and_exit_two() {
    let output = command(
        &json!({"version":1,"source":"python-spider","sourceVersion":"2.19.0",
        "options":{"start_urls":["https://fixture.test/"],"runspider":"private-code-value", "customCommand":"private-code-value"}}),
        false,
    );
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["sourceVersion"], "2.19.0");
    assert_eq!(
        report["sourceCommit"],
        crawlx_core::request::import::SOURCE_PINS[2].2
    );
    for key in ["runspider", "customCommand"] {
        assert!(report["dispositions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == key && row["state"] == "rejected"));
    }
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-code-value"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-code-value"));
}

#[test]
fn one_time_queue_alias_emits_no_native_legacy_alias() {
    let output = command(
        &json!({"version":1,"source":"js-actor","sourceVersion":"3.18.2",
        "options":{"startUrls":["https://fixture.test/"]},"aliases":{"RequestQueueV1":"RequestQueue"}}),
        true,
    ); // wire-compat: exported source symbols
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let native: CreateCrawl = serde_json::from_slice(&output.stdout).unwrap();
    assert!(native.orchestration.is_some());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("RequestQueue")); // wire-compat: deprecated source symbol
}
