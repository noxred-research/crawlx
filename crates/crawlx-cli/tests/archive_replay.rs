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
    let compared = invoke("qa", &root.path().join("matched"), Some(&baseline));
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
    let absent = invoke("qa", &root.path().join("absent"), None);
    assert_eq!(absent.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&absent.stdout).unwrap();
    assert_eq!(report["passed"], 0);
    assert_eq!(report["not_evaluated"], 8);
}
