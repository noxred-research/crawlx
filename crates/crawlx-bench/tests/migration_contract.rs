//! Offline authored-fixture acceptance tests; these do not establish external runtime parity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::migration_contract::{
    compile_fixture, fixture_pin, CompiledFixture, ContractError, ExternalEvidence, Failure,
};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const CONTRACT: &[u8] = include_bytes!("../../../bench/differential/migration/contract.json");
const GOLDEN: &[u8] = include_bytes!("../../../bench/differential/migration/golden.json");
const NATIVE: &[u8] = include_bytes!("../../../bench/differential/migration/native.json");
const ITEMS: &[u8] = include_bytes!("../../../bench/differential/migration/items.json");
const EVIDENCE: &[u8] = include_bytes!("../../../bench/differential/migration/evidence.json");

fn compile(contract: &[u8], golden: &[u8]) -> Result<CompiledFixture, ContractError> {
    compile_fixture(
        contract,
        golden,
        [fixture_pin(contract), fixture_pin(golden)],
        &CancellationToken::new(),
    )
}

fn changed(bytes: &[u8], change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(bytes).unwrap();
    change(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn pinned_authored_golden_agrees_without_claiming_external_evidence() {
    let fixture = compile(CONTRACT, GOLDEN).unwrap();
    let report = fixture
        .evaluate(NATIVE, ITEMS, &CancellationToken::new())
        .unwrap();
    assert!(report.passed(), "{report:?}");
    assert_eq!((report.pages, report.items, report.schema_failures), (1, 1, 0));
    assert_eq!(report.differential_findings, 0);
    assert_eq!(report.contract_pin, fixture_pin(CONTRACT));
    assert_eq!(report.external_evidence, ExternalEvidence::ExternalRequired);
    assert!(report.evaluation_micros <= report.max_evaluation_micros);
    let evidence: Value = serde_json::from_slice(EVIDENCE).unwrap();
    assert_eq!(evidence["fixture_provenance"], "authored_local_snapshot");
    assert_eq!(evidence["external_runtime_export"], "external_required");
    assert_eq!(evidence["external_runtime_performance"], "external_required");
    for (name, bytes) in [
        ("contract.json", CONTRACT),
        ("golden.json", GOLDEN),
        ("native.json", NATIVE),
        ("items.json", ITEMS),
    ] {
        assert_eq!(evidence["pins"][name], fixture_pin(bytes).to_string());
    }
}

#[test]
fn contract_command_runs_offline_with_pinned_fixtures_and_redacted_errors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/differential/migration");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx-differential"))
        .arg("contract")
        .args(["contract.json", "golden.json", "native.json", "items.json"].map(|name| root.join(name)))
        .arg(fixture_pin(CONTRACT).to_string())
        .arg(fixture_pin(GOLDEN).to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["external_evidence"], "external_required");
    assert_eq!(report["failures"], json!([]));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx-differential"))
        .args(["contract", "private-input-value"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-input-value"));
}

#[test]
fn contract_and_golden_require_separate_trusted_exact_byte_pins() {
    for target in 0..2 {
        let mut pins = [fixture_pin(CONTRACT), fixture_pin(GOLDEN)];
        pins[target] = fixture_pin(b"different trusted bytes");
        assert_eq!(
            compile_fixture(CONTRACT, GOLDEN, pins, &CancellationToken::new()).unwrap_err(),
            ContractError::Pin
        );
    }
}

#[test]
fn declarative_schema_rejects_execution_unknown_fields_and_remote_references() {
    for key in ["command", "callback", "$ref", "import", "script"] {
        let contract = changed(CONTRACT, |value| value[key] = json!("untrusted payload"));
        assert_eq!(compile(&contract, GOLDEN).unwrap_err(), ContractError::Invalid);
    }
    let contract = changed(CONTRACT, |value| {
        value["item_schema"] = json!({"$ref": "https://fixture.invalid/schema"});
    });
    assert_eq!(compile(&contract, GOLDEN).unwrap_err(), ContractError::Invalid);
}

#[test]
fn malformed_binary_duplicate_and_deep_json_fail_without_execution() {
    let fixture = compile(CONTRACT, GOLDEN).unwrap();
    for bytes in [
        b"\x80\x04binary".as_slice(),
        b"{\"version\":1,\"version\":1}",
        b"{",
    ] {
        assert_eq!(compile(bytes, GOLDEN).unwrap_err(), ContractError::Invalid);
    }
    let duplicate = b"[{\"name\":\"first\",\"name\":\"second\",\"price\":1}]";
    assert_eq!(
        fixture
            .evaluate(NATIVE, duplicate, &CancellationToken::new())
            .unwrap_err(),
        ContractError::Invalid
    );
    let nested = format!("{}0{}", "[".repeat(25), "]".repeat(25));
    assert_eq!(
        fixture
            .evaluate(NATIVE, nested.as_bytes(), &CancellationToken::new())
            .unwrap_err(),
        ContractError::Limit
    );
    let oversized = vec![b' '; 262_145];
    assert_eq!(compile(&oversized, GOLDEN).unwrap_err(), ContractError::Limit);
    let nodes = format!("[{}0]", "0,".repeat(16_385));
    assert_eq!(
        fixture
            .evaluate(NATIVE, nodes.as_bytes(), &CancellationToken::new())
            .unwrap_err(),
        ContractError::Limit
    );
}

#[test]
fn invalid_revision_count_threshold_schema_and_urls_fail_compilation() {
    let mut cases = Vec::new();
    cases.push(changed(CONTRACT, |v| v["version"] = json!(2)));
    cases.push(changed(CONTRACT, |v| v["source_revision"] = json!("unpinned")));
    cases.push(changed(CONTRACT, |v| {
        v["item_count"] = json!({"min": 2, "max": 1})
    }));
    cases.push(changed(CONTRACT, |v| v["item_count"]["max"] = json!(1025)));
    cases.push(changed(CONTRACT, |v| v["thresholds"]["links"] = json!(1.01)));
    cases.push(changed(CONTRACT, |v| {
        v["thresholds"]["max_evaluation_micros"] = json!(0)
    }));
    cases.push(changed(CONTRACT, |v| {
        v["item_schema"]["required"] = json!(["missing"])
    }));
    cases.push(changed(CONTRACT, |v| {
        v["item_schema"]["required"] = json!(["name", "name"])
    }));
    for url in [
        "javascript:alert(1)",
        "file:///tmp/source",
        "https://other.invalid/catalog",
        "https://user:password@fixture.invalid/catalog",
        "https://fixture.invalid/catalog#fragment",
    ] {
        cases.push(changed(CONTRACT, |v| v["urls"] = json!([url])));
    }
    for bytes in cases {
        assert_eq!(compile(&bytes, GOLDEN).unwrap_err(), ContractError::Invalid);
    }
    let altered_golden = changed(GOLDEN, |v| {
        v["data"][0]["metadata"]["sourceURL"] = json!("https://fixture.invalid/not-the-contract");
    });
    assert_eq!(
        compile(CONTRACT, &altered_golden).unwrap_err(),
        ContractError::Invalid
    );
}

#[test]
fn item_count_and_closed_recursive_schema_measure_real_captures() {
    let fixture = compile(CONTRACT, GOLDEN).unwrap();
    for item in [
        json!({"name":"entry", "price":"12"}),
        json!({"name":"entry"}),
        json!({"name":"entry", "price":12, "extra":true}),
        json!({"name":"x".repeat(81), "price":12}),
        json!({"name":"entry", "price":12, "labels":[1]}),
        json!({"name":"entry", "price":12, "labels":["a","b","c","d","e"]}),
    ] {
        let bytes = serde_json::to_vec(&vec![item]).unwrap();
        let report = fixture
            .evaluate(NATIVE, &bytes, &CancellationToken::new())
            .unwrap();
        assert_eq!(report.schema_failures, 1);
        assert!(report.failures.contains(&Failure::ItemSchema));
    }
    let report = fixture
        .evaluate(NATIVE, b"[]", &CancellationToken::new())
        .unwrap();
    assert!(report.failures.contains(&Failure::ItemCount));
    assert_eq!(report.schema_failures, 0);
}

#[test]
fn query_identity_duplicate_pages_and_golden_content_drift_do_not_pass() {
    let fixture = compile(CONTRACT, GOLDEN).unwrap();
    let query_change = changed(NATIVE, |v| {
        v["pages"][0]["url"] = json!("https://fixture.invalid/catalog?edition=3");
    });
    let report = fixture
        .evaluate(&query_change, ITEMS, &CancellationToken::new())
        .unwrap();
    assert!(report.failures.contains(&Failure::UrlSet));
    assert!(report.failures.contains(&Failure::GoldenDifference));
    let duplicate = changed(NATIVE, |v| {
        let page = v["pages"][0].clone();
        v["pages"].as_array_mut().unwrap().push(page);
    });
    let report = fixture
        .evaluate(&duplicate, ITEMS, &CancellationToken::new())
        .unwrap();
    assert!(report.failures.contains(&Failure::UrlSet));
    let drift = changed(NATIVE, |v| v["pages"][0]["markdown"] = json!("Different content"));
    let report = fixture
        .evaluate(&drift, ITEMS, &CancellationToken::new())
        .unwrap();
    assert!(report.failures.contains(&Failure::GoldenDifference));
}

#[test]
fn failed_and_cancelled_capture_outcomes_do_not_fake_golden_completion() {
    let fixture = compile(CONTRACT, GOLDEN).unwrap();
    for status in ["failed", "cancelled"] {
        let native = changed(NATIVE, |v| {
            v["status"] = json!(status);
            v["terminal_reason"] = json!("fixture fault");
            v["pages"] = json!([]);
            v["counters"]["succeeded"] = json!(0);
            v["counters"]["failed"] = json!(1);
            v["frontier"][0]["status"] = json!("failed");
        });
        let report = fixture
            .evaluate(&native, b"[]", &CancellationToken::new())
            .unwrap();
        assert!(!report.passed());
        assert!(report.failures.contains(&Failure::GoldenDifference));
        assert!(report.failures.contains(&Failure::UrlSet));
    }
}

#[test]
fn cancellation_never_publishes_a_partial_report_and_fixture_remains_reusable() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        compile_fixture(
            CONTRACT,
            GOLDEN,
            [fixture_pin(CONTRACT), fixture_pin(GOLDEN)],
            &cancel
        )
        .unwrap_err(),
        ContractError::Cancelled
    );
    let fixture = compile(CONTRACT, GOLDEN).unwrap();
    assert_eq!(
        fixture.evaluate(NATIVE, ITEMS, &cancel).unwrap_err(),
        ContractError::Cancelled
    );
    assert!(fixture
        .evaluate(NATIVE, ITEMS, &CancellationToken::new())
        .unwrap()
        .passed());
}

#[test]
fn metadata_only_contract_refuses_content_and_diagnostics_do_not_echo_secrets() {
    let contract = changed(CONTRACT, |v| {
        v["privacy"] = json!("metadata_only");
        v["item_count"] = json!({"min":0,"max":0});
    });
    assert_eq!(compile(&contract, GOLDEN).unwrap_err(), ContractError::Invalid);
    let golden = changed(GOLDEN, |v| {
        let metadata = v["data"][0]["metadata"].as_object_mut().unwrap();
        metadata.remove("title");
        v["data"][0].as_object_mut().unwrap().remove("markdown");
    });
    let fixture = compile(&contract, &golden).unwrap();
    let native = changed(NATIVE, |v| {
        v["pages"][0]["title"] = Value::Null;
        v["pages"][0]["markdown"] = Value::Null;
    });
    assert!(fixture
        .evaluate(&native, b"[]", &CancellationToken::new())
        .unwrap()
        .passed());
    let canary = ["sensitive", "fixture", "sentinel"].join("-");
    let leaked = changed(&native, |v| v["pages"][0]["markdown"] = json!(&canary));
    let report = fixture
        .evaluate(&leaked, ITEMS, &CancellationToken::new())
        .unwrap();
    assert!(report.failures.contains(&Failure::Privacy));
    for text in [
        format!("{fixture:?}"),
        format!("{report:?}"),
        serde_json::to_string(&report).unwrap(),
    ] {
        assert!(!text.contains(&canary));
        assert!(!text.contains("fixture.invalid"));
    }
    let malformed = format!("{{\"{canary}\":");
    let error = fixture
        .evaluate(malformed.as_bytes(), b"[]", &CancellationToken::new())
        .unwrap_err();
    assert!(!format!("{error:?} {error}").contains(&canary));
}

#[test]
fn local_duration_is_measured_and_threshold_outcome_matches_that_measurement() {
    let contract = changed(CONTRACT, |v| {
        v["thresholds"]["max_evaluation_micros"] = json!(1);
    });
    let fixture = compile(&contract, GOLDEN).unwrap();
    let report = fixture
        .evaluate(NATIVE, ITEMS, &CancellationToken::new())
        .unwrap();
    assert_eq!(report.max_evaluation_micros, 1);
    assert_eq!(
        report.failures.contains(&Failure::EvaluationTime),
        report.evaluation_micros > report.max_evaluation_micros
    );
    assert_eq!(report.external_evidence, ExternalEvidence::ExternalRequired);
}

#[test]
fn every_scalar_schema_and_nested_object_has_typed_validation() {
    let contract = changed(CONTRACT, |v| {
        v["item_schema"] = json!({
            "type":"object",
            "properties": {
                "nested": {
                    "type":"object",
                    "properties": {
                        "enabled":{"type":"boolean"},
                        "score":{"type":"number"},
                        "nothing":{"type":"null"}
                    },
                    "required":["enabled","score","nothing"]
                }
            },
            "required":["nested"]
        });
    });
    let fixture = compile(&contract, GOLDEN).unwrap();
    let valid = br#"[{"nested":{"enabled":true,"score":1.25,"nothing":null}}]"#;
    assert!(fixture
        .evaluate(NATIVE, valid, &CancellationToken::new())
        .unwrap()
        .passed());
    for invalid in [
        br#"[{"nested":{"enabled":1,"score":1.25,"nothing":null}}]"#.as_slice(),
        br#"[{"nested":{"enabled":true,"score":"1.25","nothing":null}}]"#,
        br#"[{"nested":{"enabled":true,"score":1.25,"nothing":false}}]"#,
        br#"[{"nested":{"enabled":true,"score":1.25,"nothing":null,"extra":0}}]"#,
    ] {
        let report = fixture
            .evaluate(NATIVE, invalid, &CancellationToken::new())
            .unwrap();
        assert_eq!(report.schema_failures, 1);
    }
}

#[test]
fn page_item_and_schema_depth_caps_fail_closed() {
    let fixture = compile(CONTRACT, GOLDEN).unwrap();
    let native = changed(NATIVE, |v| {
        let page = v["pages"][0].clone();
        v["pages"] = json!(vec![page; 129]);
    });
    assert_eq!(
        fixture
            .evaluate(&native, ITEMS, &CancellationToken::new())
            .unwrap_err(),
        ContractError::Limit
    );
    let items = serde_json::to_vec(&vec![Value::Null; 1025]).unwrap();
    assert_eq!(
        fixture
            .evaluate(NATIVE, &items, &CancellationToken::new())
            .unwrap_err(),
        ContractError::Limit
    );
    let contract = changed(CONTRACT, |v| {
        let mut schema = json!({"type":"integer"});
        for _ in 0..9 {
            schema = json!({"type":"array","items":schema,"max_items":1});
        }
        v["item_schema"] = schema;
    });
    assert_eq!(compile(&contract, GOLDEN).unwrap_err(), ContractError::Limit);
}
