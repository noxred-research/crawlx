//! Consumer-visible offline replay CLI contract. Browser cases require the pinned installed build.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_storage::archive::{warc, Limits};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::process::Command;

const TENANT: &str = "00000000-0000-8000-8000-000000000001";

#[test]
fn zdr_replay_refuses_before_input_output_or_external_telemetry() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("must-not-exist");
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let process = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args([
            "archive",
            "replay",
            "does-not-exist.wacz",
            "--tenant",
            TENANT,
            "--out",
        ])
        .arg(&output)
        .arg("--zero-data-retention")
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://{}", listener.local_addr().unwrap()),
        )
        .output()
        .unwrap();
    assert!(!process.status.success());
    assert!(String::from_utf8_lossy(&process.stderr).contains("retention_denied"));
    assert!(!output.exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn actual_cli_replay_and_qa_report_real_baseline_and_absence() {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("fixture.warc.gz");
    let html = b"<!doctype html><html><head><link rel='icon' href='data:,'></head><body><h1>Owned retained fixture</h1></body></html>";
    let mut archive_file = std::fs::File::create(&archive).unwrap();
    for (ordinal, page) in ["index.html", "other.html", "third.html"].iter().enumerate() {
        let header = warc::RecordHeader {
            fields: BTreeMap::from([
                ("WARC-Type".into(), "resource".into()),
                (
                    "WARC-Record-ID".into(),
                    format!("<urn:uuid:00000000-0000-8000-8000-{ordinal:012}>"),
                ),
                ("WARC-Date".into(), "2026-11-04T12:34:56.789Z".into()),
                (
                    "WARC-Target-URI".into(),
                    format!("https://retained.example.test/{page}"),
                ),
                ("Content-Type".into(), "text/html".into()),
            ]),
            payload_offset: 0,
        };
        warc::write_record(
            &mut archive_file,
            &header,
            &mut Cursor::new(html),
            u64::try_from(html.len()).unwrap(),
            Limits::default(),
        )
        .unwrap();
    }
    let baseline = root.path().join("baseline");
    let invoke = |operation: &str, output: &std::path::Path, baseline: Option<&std::path::Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_crawlx"));
        command
            .args(["archive", operation])
            .arg(&archive)
            .args(["--tenant", TENANT, "--out"])
            .arg(output)
            .args(["--seed", "7", "--sample", "3", "--page-filter", r"/index\.html$"]);
        if operation == "qa" && baseline.is_some() {
            command.arg("--diff-images");
        }
        if let Some(baseline) = baseline {
            command.arg("--baseline").arg(baseline);
        }
        command.output().unwrap()
    };
    let replayed = invoke("replay", &baseline, None);
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let replay_report: serde_json::Value = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(
        replay_report["pages"], 1,
        "filter precedes the three-page sample cap"
    );
    assert!(baseline.join("bundle.json").is_file());
    let matched = root.path().join("matched");
    let compared = invoke("qa", &matched, Some(&baseline));
    assert!(
        compared.status.success(),
        "status: {}; stderr: {}; stdout: {}",
        compared.status,
        String::from_utf8_lossy(&compared.stderr),
        String::from_utf8_lossy(&compared.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&compared.stdout).unwrap();
    assert_eq!(report["failed"], 0);
    assert_eq!(report["not_evaluated"], 0);
    assert!(report["passed"].as_u64().unwrap() > 0);
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(assert_retained_difference_artifact_refs(&matched));
    let absent = invoke("qa", &root.path().join("absent"), None);
    assert_eq!(absent.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&absent.stdout).unwrap();
    assert_eq!(report["passed"], 0);
    assert_eq!(report["not_evaluated"], 8);
}

async fn assert_retained_difference_artifact_refs(matched: &std::path::Path) {
    use crawlx_core::repo::Sensitivity;
    use crawlx_storage::artifacts::FsArtifactStore;
    use crawlx_storage::memory::MemoryStore;
    use std::sync::Arc;

    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(matched.join("bundle.json")).unwrap()).unwrap();
    let run = serde_json::from_value(bundle["run"].clone()).unwrap();
    let reference = serde_json::from_value(bundle["report"].clone()).unwrap();
    let store = FsArtifactStore::open(
        matched.join("artifacts"),
        Arc::new(MemoryStore::new()),
        Arc::new(crawlx_core::time::SystemClock),
    )
    .await
    .unwrap()
    .with_read_scope(TENANT.parse().unwrap(), run);
    let bytes = store
        .get_bounded(&reference, Sensitivity::Content, 16 * 1024 * 1024)
        .await
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let differences = stored["differences"].as_object().unwrap();
    assert_eq!(differences.len(), 3);
    for (phase, reference) in differences {
        assert!(["0/viewport", "0/full_page", "0/final"].contains(&phase.as_str()));
        let reference = serde_json::from_value(reference.clone()).unwrap();
        let bytes = store
            .get_bounded(&reference, Sensitivity::Sensitive, 16 * 1024 * 1024)
            .await
            .unwrap();
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(store
            .get_bounded(&reference, Sensitivity::Content, 16 * 1024 * 1024)
            .await
            .is_err());
    }
}

#[test]
fn zdr_difference_images_refuse_before_reading_baseline_or_writing_output() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("must-not-exist");
    let process = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["archive", "qa", "missing.wacz", "--tenant", TENANT, "--out"])
        .arg(&output)
        .args([
            "--baseline",
            "missing-baseline",
            "--diff-images",
            "--zero-data-retention",
        ])
        .output()
        .unwrap();
    assert!(!process.status.success());
    assert!(String::from_utf8_lossy(&process.stderr).contains("retention_denied"));
    assert!(!output.exists());
}

#[test]
fn difference_images_require_a_baseline() {
    let result = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args([
            "archive",
            "qa",
            "missing.wacz",
            "--tenant",
            TENANT,
            "--out",
            "unused",
            "--diff-images",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--baseline"));
}

#[test]
fn missing_replay_output_parent_is_named_before_opening_input() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("missing");
    let result = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["archive", "replay", "missing.wacz", "--tenant", TENANT, "--out"])
        .arg(parent.join("output"))
        .output()
        .unwrap();
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success());
    assert!(error.contains("archive replay output directory"), "{error}");
    assert!(error.contains("create it first"), "{error}");
    assert!(!parent.exists());
}
