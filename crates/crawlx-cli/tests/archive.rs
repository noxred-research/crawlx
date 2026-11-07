//! Real retained-run archive CLI fixtures. No live network and no fake origin response bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::Parser;
use crawlx_cli::archive::{
    execute_with_clock, ArchiveArgs, ArchiveCommand, ArchiveExportArgs, ArchiveImportArgs,
    ArchiveInspectArgs, FormatArg,
};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{PageRecord, RunRepo, Sensitivity};
use crawlx_core::secret::ArtifactSink;
use crawlx_core::time::ManualClock;
use crawlx_core::{TenantId, TrustLane};
use crawlx_storage::archive::{wacz, warc, Limits};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{FsArtifactStore, MemoryStore};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

struct Fixture {
    dir: tempfile::TempDir,
    tenant: TenantId,
    clock: ManualClock,
    run: crawlx_core::CrawlRunId,
    html: crawlx_core::ArtifactRef,
}
impl Fixture {
    fn export(&self, name: &str) -> ArchiveArgs {
        ArchiveArgs {
            command: ArchiveCommand::Export(ArchiveExportArgs {
                source: self.dir.path().to_string_lossy().into_owned(),
                tenant: self.tenant,
                out: self.dir.path().join(name),
                format: FormatArg::Wacz,
                require_complete: false,
                artifacts_dir: None,
                database_url: None,
                max_bytes: 1_073_741_824,
            }),
        }
    }
}
async fn fixture() -> Fixture {
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-04T12:34:56.789Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let clock = ManualClock::new(now);
    let dir = tempfile::tempdir().unwrap();
    let tenant: TenantId = "00000000-0000-8000-8000-000000000001".parse().unwrap();
    let mut stored = crawl_run(tenant, create_crawl("https://example.test/Case", &[], 1));
    stored.id = "00000000-0000-8000-8000-000000000002".parse().unwrap();
    stored.created_at = now;
    let run = stored.id;
    let runs = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
    runs.create(&stored, None).await.unwrap();
    let artifacts = FsArtifactStore::open(dir.path().join("artifacts"), runs, Arc::new(clock.clone()))
        .await
        .unwrap();
    let body = "<html><h1>Actual retained page</h1><p>cookie=CANARY_COOKIE</p><p>authorization=CANARY_AUTH</p><a href='/?SESSION=CANARY_SESSION'>safe</a></html>";
    let redactor = crawlx_core::secret::Redactor::new();
    let approved_body = redactor.redact_text(body);
    assert!(!approved_body.as_inner().contains("CANARY_COOKIE"));
    assert!(!approved_body.as_inner().contains("CANARY_SESSION"));
    assert!(!approved_body.as_inner().contains("CANARY_AUTH"));
    let html = ArtifactSink::over(&artifacts)
        .put(run, Sensitivity::Content, "text/html", &approved_body)
        .await
        .unwrap();
    let md = ArtifactSink::over(&artifacts)
        .put(
            run,
            Sensitivity::Content,
            "text/markdown",
            &redactor.redact_text("# Actual retained page\n"),
        )
        .await
        .unwrap();
    let base = url::Url::parse("https://example.test/Case").unwrap();
    let url = crawlx_url::Canonicalizer::canonicalize_url(&base, &Default::default()).unwrap();
    let page = PageRecord {
        run,
        frontier_id: 7,
        url,
        status: 200,
        content_type: Some("text/html".into()),
        content_digest: Digest::of("fixture", body.as_bytes()),
        title: Some("Retained example".into()),
        markdown: Some(md),
        html: Some(html.clone()),
        metadata: serde_json::json!({}),
        links: vec![],
        fetched_at: now,
        lane: TrustLane::Diagnostic,
    };
    std::fs::write(
        dir.path().join("report.json"),
        serde_json::to_vec(&serde_json::json!({
            "run_id":run,"request":stored.config,"pages":[page]
        }))
        .unwrap(),
    )
    .unwrap();
    Fixture {
        dir,
        tenant,
        clock,
        run,
        html,
    }
}

#[test]
fn archive_commands_are_registered_as_native_offline_commands() {
    let cli =
        crawlx_cli::Cli::try_parse_from(["crawlx", "archive", "inspect", "input.wacz", "--record", "1"])
            .unwrap();
    assert!(matches!(cli.command, crawlx_cli::Command::Archive(_)));
}

#[tokio::test]
async fn real_artifact_export_import_inspect_locates_payload_and_declares_omissions() {
    let fixture = fixture().await;
    let mut output = Vec::new();
    execute_with_clock(fixture.export("first.wacz"), &mut output, &fixture.clock)
        .await
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(manifest["complete"], false);
    assert_eq!(manifest["tenant"], fixture.tenant.to_string());
    assert_eq!(manifest["records"], 2);
    assert!(manifest["omissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["reason"] == "binary_capture_not_authorized"));
    let path = fixture.dir.path().join("first.wacz");
    let inspection = wacz::inspect(File::open(&path).unwrap(), Limits::default()).unwrap();
    let records = &inspection.records["archive/data.warc.gz"];
    assert_eq!(records.len(), 3);
    assert_eq!(records[1].record_type, "resource");
    assert_eq!(records[1].status, None);
    assert_eq!(records[1].date.to_rfc3339(), "2026-11-04T12:34:56.789+00:00");
    let body = wacz::payload(
        File::open(&path).unwrap(),
        "archive/data.warc.gz",
        &records[1],
        Limits::default(),
    )
    .unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("Actual retained page"));
    assert!(!text.contains("CANARY_COOKIE"));
    assert!(!text.contains("CANARY_SESSION"));
    assert!(!text.contains("CANARY_AUTH"));
    let mut zip = zip::ZipArchive::new(File::open(&path).unwrap()).unwrap();
    for name in [
        "indexes/index.cdxj",
        "pages/pages.jsonl",
        "crawlx/manifest.json",
        "datapackage.json",
    ] {
        let mut text = String::new();
        zip.by_name(name).unwrap().read_to_string(&mut text).unwrap();
        assert!(!text.contains("CANARY_COOKIE"));
        assert!(!text.contains("CANARY_SESSION"));
        assert!(!text.contains("CANARY_AUTH"));
    }
    let imported = fixture.dir.path().join("imported.wacz");
    execute_with_clock(
        ArchiveArgs {
            command: ArchiveCommand::Import(ArchiveImportArgs {
                input: path.clone(),
                out: imported.clone(),
                zero_data_retention: false,
                dependencies: Default::default(),
            }),
        },
        &mut Vec::new(),
        &fixture.clock,
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(&imported).unwrap(), std::fs::read(&path).unwrap());
    let payload = fixture.dir.path().join("payload.html");
    execute_with_clock(
        ArchiveArgs {
            command: ArchiveCommand::Inspect(ArchiveInspectArgs {
                input: imported,
                record: Some(1),
                payload_out: Some(payload.clone()),
                dependencies: Default::default(),
            }),
        },
        &mut Vec::new(),
        &fixture.clock,
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read_to_string(payload).unwrap(), text);
    execute_with_clock(fixture.export("second.wacz"), &mut Vec::new(), &fixture.clock)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(path).unwrap(),
        std::fs::read(fixture.dir.path().join("second.wacz")).unwrap()
    );
}

#[tokio::test]
async fn zdr_and_require_complete_refuse_before_creating_any_output() {
    let fixture = fixture().await;
    let mut request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.dir.path().join("report.json")).unwrap()).unwrap();
    request["request"]["retention"]["mode"] = serde_json::Value::String("zdr".into());
    std::fs::write(
        fixture.dir.path().join("report.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let error = execute_with_clock(fixture.export("zdr.wacz"), &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("retention_denied"));
    assert!(!fixture.dir.path().join("zdr.wacz").exists());
    request["request"]["retention"]["mode"] = serde_json::Value::String("standard".into());
    std::fs::write(
        fixture.dir.path().join("report.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let mut args = fixture.export("complete.wacz");
    let ArchiveCommand::Export(export) = &mut args.command else {
        panic!()
    };
    export.require_complete = true;
    export.out = fixture.dir.path().join("absent-parent/complete.wacz");
    let error = execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("capability_unavailable"));
    assert!(!fixture.dir.path().join("absent-parent").exists());
    let import = ArchiveArgs {
        command: ArchiveCommand::Import(ArchiveImportArgs {
            input: PathBuf::from("does-not-exist.wacz"),
            out: fixture.dir.path().join("import-zdr.wacz"),
            zero_data_retention: true,
            dependencies: Default::default(),
        }),
    };
    assert!(execute_with_clock(import, &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err()
        .to_string()
        .contains("retention_denied"));
    assert!(!fixture.dir.path().join("import-zdr.wacz").exists());
}

#[tokio::test]
async fn foreign_artifact_ownership_corruption_and_expiry_never_publish() {
    let fixture = fixture().await;
    let mut args = fixture.export("foreign.wacz");
    let ArchiveCommand::Export(export) = &mut args.command else {
        panic!()
    };
    export.tenant = "00000000-0000-8000-8000-000000000099".parse().unwrap();
    assert!(execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .is_err());
    assert!(!fixture.dir.path().join("foreign.wacz").exists());
    let object = fixture.dir.path().join(format!(
        "artifacts/content/{}/{}/{}",
        fixture.tenant,
        fixture.run,
        fixture.html.digest.to_hex()
    ));
    std::fs::write(&object, b"tampered content").unwrap();
    assert!(
        execute_with_clock(fixture.export("corrupt.wacz"), &mut Vec::new(), &fixture.clock)
            .await
            .is_err()
    );
    assert!(!fixture.dir.path().join("corrupt.wacz").exists());
    fixture.clock.advance_ms(8 * 86_400_000);
    assert!(
        execute_with_clock(fixture.export("expired.wacz"), &mut Vec::new(), &fixture.clock)
            .await
            .unwrap_err()
            .to_string()
            .contains("expired")
    );
    assert!(!fixture.dir.path().join("expired.wacz").exists());
}

#[tokio::test]
async fn available_capture_preserves_missing_representation_ledger_and_warc_bundle() {
    let fixture = fixture().await;
    let mut report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.dir.path().join("report.json")).unwrap()).unwrap();
    report["pages"][0]["html"] = serde_json::Value::Null;
    std::fs::write(
        fixture.dir.path().join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let mut args = fixture.export("bundle");
    let ArchiveCommand::Export(export) = &mut args.command else {
        panic!()
    };
    export.format = FormatArg::Warc;
    let mut output = Vec::new();
    execute_with_clock(args, &mut output, &fixture.clock)
        .await
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(manifest["records"], 1);
    assert!(manifest["omissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["sourceEvent"] == "page:7:html"
            && entry["reason"] == "retained_representation_unavailable"));
    let file = File::open(fixture.dir.path().join("bundle/archive/data.warc.gz")).unwrap();
    assert_eq!(warc::inspect(file, true, Limits::default()).unwrap().len(), 2);
    assert!(fixture.dir.path().join("bundle/crawlx/manifest.json").is_file());
}

#[tokio::test]
async fn binary_or_secret_bearing_import_is_typed_refusal_not_a_successful_copy() {
    let fixture = fixture().await;
    let raw = b"WARC/1.1\r\nWARC-Type: resource\r\nWARC-Record-ID: <urn:uuid:00000000-0000-8000-8000-000000000008>\r\nWARC-Date: 2026-11-04T12:34:56Z\r\nWARC-Target-URI: https://example.test/\r\nContent-Type: text/plain\r\nContent-Length: 19\r\n\r\ncookie=CANARY_VALUE\r\n\r\n";
    let input = fixture.dir.path().join("secret.warc");
    std::fs::write(&input, raw).unwrap();
    let out = fixture.dir.path().join("must-not-exist.warc");
    let args = ArchiveArgs {
        command: ArchiveCommand::Import(ArchiveImportArgs {
            input,
            out: out.clone(),
            zero_data_retention: false,
            dependencies: Default::default(),
        }),
    };
    let error = execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("retention_denied"));
    assert!(!out.exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn explicit_cli_dependency_import_materializes_real_local_payload_and_refuses_wrong_pin() {
    let fixture = fixture().await;
    let body = b"actual independently retained baseline";
    let baseline_id = "<urn:uuid:00000000-0000-8000-8000-000000000090>";
    let revisit_id = "<urn:uuid:00000000-0000-8000-8000-000000000091>";
    let source = format!("WARC/1.1\r\nWARC-Type: resource\r\nWARC-Record-ID: {baseline_id}\r\nWARC-Date: 2026-11-04T12:34:56Z\r\nWARC-Target-URI: https://example.test/source\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}\r\n\r\n",
        body.len(), std::str::from_utf8(body).unwrap());
    let repeated = format!("WARC/1.1\r\nWARC-Type: revisit\r\nWARC-Record-ID: {revisit_id}\r\nWARC-Date: 2026-11-04T12:34:57Z\r\nWARC-Target-URI: https://example.test/revisit\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nWARC-Refers-To: {baseline_id}\r\nWARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest\r\nWARC-Payload-Digest: {}\r\n\r\n\r\n\r\n", warc::digest(body));
    let input = fixture.dir.path().join("revisit.warc");
    std::fs::write(&input, repeated).unwrap();
    std::fs::write(fixture.dir.path().join("baseline.warc"), &source).unwrap();
    let out = fixture.dir.path().join("closed.wacz");
    let arguments = |hash: String, output: &std::path::Path| {
        vec![
            "crawlx".to_owned(),
            "archive".into(),
            "import".into(),
            input.to_string_lossy().into_owned(),
            "--out".into(),
            output.to_string_lossy().into_owned(),
            "--tenant".into(),
            fixture.tenant.to_string(),
            "--dependency-root".into(),
            fixture.dir.path().to_string_lossy().into_owned(),
            "--dependency".into(),
            "baseline.warc".into(),
            "--dependency-sha256".into(),
            hash,
        ]
    };
    let cli = crawlx_cli::Cli::try_parse_from(arguments(warc::digest(source.as_bytes()), &out)).unwrap();
    let crawlx_cli::Command::Archive(args) = cli.command else {
        panic!()
    };
    let mut output = Vec::new();
    execute_with_clock(args, &mut output, &fixture.clock)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["materializedDependencies"], 1);
    assert_eq!(result["containerRewritten"], true);
    let inspection = wacz::inspect(File::open(&out).unwrap(), Limits::default()).unwrap();
    let row = inspection.records["archive/data.warc.gz"]
        .iter()
        .find(|row| row.id == revisit_id)
        .unwrap();
    assert_eq!(
        wacz::payload(
            File::open(&out).unwrap(),
            "archive/data.warc.gz",
            row,
            Limits::default()
        )
        .unwrap(),
        body
    );
    let bad = fixture.dir.path().join("wrong-pin.wacz");
    let cli = crawlx_cli::Cli::try_parse_from(arguments(warc::digest(b"wrong pin"), &bad)).unwrap();
    let crawlx_cli::Command::Archive(args) = cli.command else {
        panic!()
    };
    assert!(execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .is_err());
    assert!(!bad.exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn opaque_zip_comment_requires_tenant_rewrite_and_never_survives_import() {
    let fixture = fixture().await;
    execute_with_clock(fixture.export("source.wacz"), &mut Vec::new(), &fixture.clock)
        .await
        .unwrap();
    let input = fixture.dir.path().join("source.wacz");
    let mut bytes = std::fs::read(&input).unwrap();
    let end = bytes.windows(4).rposition(|part| part == b"PK\x05\x06").unwrap();
    let canary = b"SESSION=CANARY_CONTAINER_SECRET";
    bytes[end + 20..end + 22].copy_from_slice(&u16::try_from(canary.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(canary);
    std::fs::write(&input, bytes).unwrap();
    let denied = fixture.dir.path().join("denied.wacz");
    assert!(execute_with_clock(
        ArchiveArgs {
            command: ArchiveCommand::Import(ArchiveImportArgs {
                input: input.clone(),
                out: denied.clone(),
                zero_data_retention: false,
                dependencies: Default::default(),
            })
        },
        &mut Vec::new(),
        &fixture.clock
    )
    .await
    .is_err());
    assert!(!denied.exists());
    let out = fixture.dir.path().join("rewritten.wacz");
    let dependencies = crawlx_cli::archive::ArchiveDependencyArgs {
        tenant: Some(fixture.tenant),
        ..Default::default()
    };
    execute_with_clock(
        ArchiveArgs {
            command: ArchiveCommand::Import(ArchiveImportArgs {
                input,
                out: out.clone(),
                zero_data_retention: false,
                dependencies,
            }),
        },
        &mut Vec::new(),
        &fixture.clock,
    )
    .await
    .unwrap();
    let bytes = std::fs::read(&out).unwrap();
    assert!(!bytes.windows(canary.len()).any(|part| part == canary));
    let inspection = wacz::inspect(File::open(out).unwrap(), Limits::default()).unwrap();
    assert!(inspection.zip_metadata_retention_approved);
    assert_eq!(inspection.indexed, 2);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_archive_export_cli_refuses_fifo_and_symlink_reports_without_waiting_for_writer() {
    let directory = tempfile::tempdir().unwrap();
    let root = File::open(directory.path()).unwrap();
    rustix::fs::mknodat(
        &root,
        "report.json",
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let invoke = |source: PathBuf, output: PathBuf| async move {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"));
        command
            .args(["archive", "export"])
            .arg(source)
            .args(["--tenant", "00000000-0000-8000-8000-000000000001", "--out"])
            .arg(&output)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        let process = tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
            .await
            .expect("FIFO report admission blocked the archive CLI")
            .unwrap();
        assert!(!process.status.success());
        assert!(
            String::from_utf8_lossy(&process.stderr).contains("opening bounded regular recorded run report"),
            "{}",
            String::from_utf8_lossy(&process.stderr)
        );
        assert!(!output.exists());
    };
    invoke(
        directory.path().to_owned(),
        directory.path().join("directory.wacz"),
    )
    .await;
    invoke(
        directory.path().join("report.json"),
        directory.path().join("file.wacz"),
    )
    .await;
    std::fs::remove_file(directory.path().join("report.json")).unwrap();
    std::fs::write(directory.path().join("outside-report.json"), b"{}").unwrap();
    std::os::unix::fs::symlink(
        directory.path().join("outside-report.json"),
        directory.path().join("report.json"),
    )
    .unwrap();
    invoke(
        directory.path().to_owned(),
        directory.path().join("symlink-file.wacz"),
    )
    .await;
    let linked_root = directory.path().join("linked-store");
    std::os::unix::fs::symlink(directory.path(), &linked_root).unwrap();
    invoke(linked_root, directory.path().join("symlink-directory.wacz")).await;
}
