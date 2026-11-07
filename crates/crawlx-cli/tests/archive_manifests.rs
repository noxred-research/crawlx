//! Pinned archival-family reports, refusal privacy and effective native seed scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::CreateCrawl;
use crawlx_policy::{DenialReason, ScopePolicy, ScopeVerdict};
use serde_json::{json, Value};
use std::process::{Command, Output};

const FAMILIES: [(&str, &str, &str, usize); 4] = [
    ("nutch", "1.21", "NUT", 40),
    ("stormcrawler", "3.5.1", "STC", 38),
    ("heritrix", "3.18.0", "HER", 40),
    ("browsertrix", "1.15.2", "BTR", 46),
];

fn manifest(source: &str, version: &str, options: Value) -> Value {
    json!({"version":1,"source":source,"sourceVersion":version,"options":options})
}

fn cli(command: &str, manifest: &Value) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("manifest.json");
    std::fs::write(&path, serde_json::to_vec(manifest).unwrap()).unwrap();
    Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["source-import", command])
        .arg(path)
        .output()
        .unwrap()
}

fn refused(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["convertible"], false);
    assert!(report.get("seedUrl").is_none());
    assert_eq!(report["sdkAbiCompatible"], false);
    report
}

#[test]
fn every_archival_family_reports_every_pinned_inventory_row() {
    for (source, version, prefix, count) in FAMILIES {
        let output = cli("inspect", &manifest(source, version, json!({})));
        let report = refused(&output);
        let rows = report["dispositions"].as_array().unwrap();
        let inventory: Vec<_> = rows
            .iter()
            .filter(|row| row["id"].as_str().unwrap().starts_with(&format!("{prefix}-")))
            .collect();
        assert_eq!(inventory.len(), count, "{source}");
        for number in 1..=count {
            let id = format!("{prefix}-{number:02}");
            let row = inventory.iter().find(|row| row["id"] == id).unwrap();
            assert_eq!(row["state"], "decision_needed");
            assert_eq!(row["requested"], false);
            assert!(row["target"].is_null());
        }
    }
}

#[test]
fn browsertrix_depth_zero_converts_to_effective_seed_only_native_scope() {
    for seed_key in ["url", "seeds"] {
        let input = manifest(
            "browsertrix",
            "1.15.2",
            json!({(seed_key):["https://fixture.test/section/start"],"depth":0}),
        );
        let output = cli("convert", &input);
        assert!(output.status.success(), "{output:?}");
        let crawl: CreateCrawl = serde_json::from_slice(&output.stdout).unwrap();
        let policy = ScopePolicy::new(&crawl).unwrap();
        assert!(policy.decide_url(&crawl.seed_url, 0).is_admitted());
        assert_eq!(
            policy.decide_url(&crawl.seed_url, 1),
            ScopeVerdict::Denied(DenialReason::DepthExceeded { depth: 1, max: 0 })
        );
        // Sibling paths must not inherit native host scope either.
        assert!(!policy
            .decide_url(&url::Url::parse("https://fixture.test/sibling").unwrap(), 1)
            .is_admitted());
        assert!(!policy
            .decide_url(&url::Url::parse("https://other.test/section/child").unwrap(), 1)
            .is_admitted());
        assert_eq!(crawl.limits.urls, 1);
        assert_eq!(crawl.scope.sitemap, crawlx_core::config::SitemapMode::Skip);
        assert!(crawl.scope.known_files.is_empty());
        assert_eq!(crawl.mode, crawlx_core::CrawlMode::Dynamic);
    }
}

#[test]
fn source_limits_and_runtime_options_refuse_without_disclosing_values() {
    let secret = "manifest-secret-canary";
    for (source, version, options, rejected) in [
        (
            "nutch",
            "1.21",
            json!({"-s":"/not/read/seeds", "size-fetchlist":4,"http.proxy.password":secret}),
            "size-fetchlist",
        ),
        (
            "stormcrawler",
            "3.5.1",
            json!({"fetcher.max.urls.in.queues":4,"http.protocol.implementation":secret}),
            "fetcher.max.urls.in.queues",
        ),
        (
            "heritrix",
            "3.18.0",
            json!({"maxDocumentsDownload":4,"textSource":secret,"groovy":secret}),
            "maxDocumentsDownload",
        ),
        (
            "browsertrix",
            "1.15.2",
            json!({"url":"https://fixture.test/","depth":0,"pageLimit":4,"customBehaviors":secret,
                "redisStoreUrl":format!("redis://user:{secret}@private.test:6379")}),
            "pageLimit",
        ),
    ] {
        let output = cli("convert", &manifest(source, version, options));
        let report = refused(&output);
        assert!(report["dispositions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["id"] == rejected && row["state"] == "rejected" && row["requested"] == true }));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private.test"));
    }
}

#[test]
fn unknown_options_and_required_unmapped_rows_block_every_family() {
    for (source, version, prefix, _) in FAMILIES {
        let options = if source == "browsertrix" {
            json!({"url":"https://fixture.test/","depth":0})
        } else {
            json!({})
        };
        let mut input = manifest(source, version, options);
        input["options"]["unknownOption"] = json!("not-executed");
        let output = cli("convert", &input);
        let report = refused(&output);
        assert!(report["dispositions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["id"] == "unknownOption" && row["state"] == "rejected" }));
        input["options"].as_object_mut().unwrap().remove("unknownOption");
        let id = format!("{prefix}-01");
        input["requiredInventory"] = json!([id]);
        let output = cli("convert", &input);
        let report = refused(&output);
        assert!(report["dispositions"].as_array().unwrap().iter().any(|row| {
            row["id"] == id && row["state"] == "missing_evidence" && row["requested"] == true
        }));
        input["requiredInventory"] = json!(["BTR-999-not-a-secret"]);
        let output = cli("convert", &input);
        let report = refused(&output);
        assert!(report["dispositions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| { row["id"] == "unknown-inventory-id" && row["state"] == "rejected" }));
    }
}

#[test]
fn versions_unlimited_depth_scope_changes_and_alias_mixtures_fail_closed() {
    for (source, _, _, _) in FAMILIES {
        let version = if source == "stormcrawler" {
            "4.0.0-SNAPSHOT"
        } else {
            "0.0.0"
        };
        let output = cli("inspect", &manifest(source, version, json!({})));
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported import schema/source version"));
    }
    for options in [
        json!({"url":"https://fixture.test/"}),
        json!({"url":"https://fixture.test/","depth":-1}),
        json!({"url":"https://fixture.test/","depth":1}),
        json!({"url":"https://fixture.test/","depth":0,"scopeType":"any"}),
        json!({"url":"https://fixture.test/","depth":0,"limit":0}),
        json!({"url":"https://fixture.test/","seeds":["https://other.test/"],"depth":0}),
        json!({"seeds":["https://fixture.test/","https://other.test/"],"depth":0}),
        json!({"url":"https://user:manifest-secret-canary@fixture.test/","depth":0}),
        json!({"seeds":[{"url":"https://fixture.test/","auth":"manifest-secret-canary"}],"depth":0}),
    ] {
        let output = cli("convert", &manifest("browsertrix", "1.15.2", options));
        refused(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("manifest-secret-canary"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("manifest-secret-canary"));
    }
}
