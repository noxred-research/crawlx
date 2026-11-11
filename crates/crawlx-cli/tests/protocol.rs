//! Operator protocol capability probes must be offline and distinguish registration from live evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde_json::{json, Value};
use std::{io::ErrorKind, net::TcpListener, process::Command};

#[test]
fn absent_registry_probe_has_no_default_delegates_or_network_work() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/forbidden", listener.local_addr().unwrap());
    let result = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["protocol", "--probe"])
        .env_remove("CRAWLX_PROTOCOL_REGISTRY")
        .env("CRAWLX_UPDATE_CHECK", "1")
        .env("CRAWLX_RELEASE_URL", &endpoint)
        .env("CRAWLX_OTLP_ENDPOINT", &endpoint)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["schemaVersion"], 1);
    assert_eq!(report["registryPresent"], false);
    assert_eq!(report["networkProbed"], false);
    assert_eq!(report["delegates"], json!([]));
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn configured_service_probe_never_contacts_service_or_claims_live_attestation() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!(
        "https://localhost:{}/acquire",
        listener.local_addr().unwrap().port()
    );
    let path = root.path().join("registry.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "schemaVersion":1, "approvedTenants":[],
            "services":{"fixture-service":{
                "endpoint":endpoint,"audience":"fixture","approvalDigest":"a".repeat(64),
                "credentialRef":"env://CRAWLX_FIXTURE_PROTOCOL_TOKEN", "policyDigests":["fixture-policy"],
                "capabilities":{"schemaVersion":1,"schemes":["https"],
                    "capabilities":["shared_origin_admission","read_only_effects","secret_free_response"],
                    "maxBytes":4096,"deadlineEnforced":true,"checkedEgress":true,"identityIsolation":true,
                    "zeroRetention":true,"buildDigest":"b".repeat(64),"bodyStreaming":true,"redirects":false,
                    "subresourceEnforcement":true,"cancellation":true,"browserBuild":null},
                "sftpHostKeys":{},"whoisRegistries":[],"originAdmissionRef":"fixture-broker",
                "serviceNetworks":["127.0.0.1/32"]
            }},
            "ftp":{"origins":["ftp://fixture.invalid"],"policyDigests":["fixture-policy"]}
        }))
        .unwrap(),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["protocol", "--probe"])
        .env("CRAWLX_PROTOCOL_REGISTRY", &path)
        .env("CRAWLX_FIXTURE_PROTOCOL_TOKEN", "fixture-private-token")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["registryPresent"], true);
    assert_eq!(report["networkProbed"], false);
    let entries = report["delegates"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["id"], "fixture-service");
    assert_eq!(entries[1]["id"], "native_ftp");
    for entry in entries {
        assert_eq!(entry["operatorConfigured"], true);
        assert_eq!(entry["liveAttested"], false);
    }
    let output = String::from_utf8(result.stdout).unwrap();
    for private in [
        "fixture-private-token",
        "localhost",
        "fixture.invalid",
        "credentialRef",
        "approvalDigest",
    ] {
        assert!(!output.contains(private));
    }
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}
