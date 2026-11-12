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
                rollover_bytes: None,
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

#[tokio::test]
async fn wacz_rollover_preserves_exact_ranges_fixities_and_refuses_oversized_members() {
    let fixture = fixture().await;
    execute_with_clock(fixture.export("baseline.wacz"), &mut Vec::new(), &fixture.clock)
        .await
        .unwrap();
    let baseline = wacz::inspect(
        File::open(fixture.dir.path().join("baseline.wacz")).unwrap(),
        Limits::default(),
    )
    .unwrap();
    let cap = baseline
        .records
        .values()
        .flatten()
        .map(|record| record.length)
        .max()
        .unwrap();
    for name in ["rolled.wacz", "rolled-again.wacz"] {
        let mut args = fixture.export(name);
        let ArchiveCommand::Export(export) = &mut args.command else {
            panic!("export expected")
        };
        export.rollover_bytes = Some(cap);
        execute_with_clock(args, &mut Vec::new(), &fixture.clock)
            .await
            .unwrap();
    }
    let path = fixture.dir.path().join("rolled.wacz");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(fixture.dir.path().join("rolled-again.wacz")).unwrap()
    );
    let inspected = wacz::inspect(File::open(&path).unwrap(), Limits::default()).unwrap();
    assert!(inspected.records.len() > 1);
    assert_eq!(inspected.indexed, 2);
    let mut zip = zip::ZipArchive::new(File::open(&path).unwrap()).unwrap();
    for resource in &inspected.resources {
        let mut bytes = Vec::new();
        zip.by_name(&resource.path)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(resource.bytes, u64::try_from(bytes.len()).unwrap());
        assert_eq!(resource.hash, warc::digest(&bytes));
        if resource.path.starts_with("archive/") {
            assert!(resource.bytes <= cap);
            assert!(inspected.records.contains_key(&resource.path));
        }
    }
    let mut index = String::new();
    zip.by_name("indexes/index.cdxj")
        .unwrap()
        .read_to_string(&mut index)
        .unwrap();
    for line in index.lines() {
        let entry: crawlx_storage::archive::cdxj::Entry =
            serde_json::from_str(line.splitn(3, ' ').nth(2).unwrap()).unwrap();
        let filename = format!("archive/{}", entry.filename);
        let mut bytes = Vec::new();
        zip.by_name(&filename).unwrap().read_to_end(&mut bytes).unwrap();
        let start = usize::try_from(entry.offset).unwrap();
        let end = usize::try_from(entry.offset.checked_add(entry.length).unwrap()).unwrap();
        let (record, body) =
            warc::read_member(std::io::Cursor::new(&bytes[start..end]), Limits::default()).unwrap();
        assert_eq!(record.length, entry.length);
        assert_eq!(record.payload_digest, entry.digest);
        assert_eq!(record.target.as_deref(), Some(entry.url.as_str()));
        assert!(!body.is_empty());
    }
    let mut args = fixture.export("too-small.wacz");
    let ArchiveCommand::Export(export) = &mut args.command else {
        panic!("export expected")
    };
    export.rollover_bytes = Some(cap - 1);
    let error = execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<crawlx_storage::archive::ArchiveError>(),
        Some(crawlx_storage::archive::ArchiveError::RecordExceedsRollover { .. })
    ));
    assert!(!fixture.dir.path().join("too-small.wacz").exists());
    let mut args = fixture.export("unsupported-warc");
    let ArchiveCommand::Export(export) = &mut args.command else {
        panic!("export expected")
    };
    export.format = FormatArg::Warc;
    export.rollover_bytes = Some(cap);
    assert!(execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err()
        .to_string()
        .contains("requires WACZ"));
    assert!(!fixture.dir.path().join("unsupported-warc").exists());
}

#[tokio::test]
async fn native_bundle_verify_inspect_import_and_member_paths_enforce_completeness() {
    let fixture = fixture().await;
    let mut args = fixture.export("native-complete");
    let ArchiveCommand::Export(export) = &mut args.command else {
        panic!("export expected");
    };
    export.format = FormatArg::Warc;
    execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .unwrap();
    let bundle = fixture.dir.path().join("native-complete");
    assert!(bundle.join("publication.json").is_file());
    assert!(!bundle.join(".incomplete").exists());
    let state = fixture.dir.path().join("isolated-state");
    let invoke = |operation: &str, input: &std::path::Path, output: Option<&std::path::Path>| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx"));
        command
            .args(["archive", operation])
            .arg(input)
            .env("XDG_STATE_HOME", &state);
        if let Some(output) = output {
            command.arg("--out").arg(output);
        }
        command.output().unwrap()
    };
    let verified = invoke("verify", &bundle, None);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified.stdout).unwrap()["valid"],
        true
    );
    let inspected = invoke("inspect", &bundle, None);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let imported = fixture.dir.path().join("native-import.warc.gz");
    let result = invoke("import", &bundle, Some(&imported));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(imported.is_file());

    // A foreign sentinel cannot be swept, even when every listed fixity is already complete.
    std::fs::write(bundle.join(".incomplete"), b"foreign export").unwrap();
    for input in [&bundle, &bundle.join("archive/data.warc.gz")] {
        for operation in ["verify", "inspect", "import"] {
            let out = fixture.dir.path().join(format!("denied-{operation}.warc.gz"));
            let result = invoke(operation, input, (operation == "import").then_some(out.as_path()));
            assert!(!result.status.success(), "{operation}");
            assert!(
                String::from_utf8_lossy(&result.stderr).contains("incomplete"),
                "{operation}"
            );
            assert!(!out.exists());
        }
    }
    std::fs::remove_file(bundle.join(".incomplete")).unwrap();
    std::fs::remove_file(bundle.join("publication.json")).unwrap();
    assert!(!invoke("verify", &bundle.join("archive/data.warc.gz"), None)
        .status
        .success());
}

// Explicit diagnostics builds only. The production binary has no publication-stop hook.
#[cfg(all(feature = "chaos", debug_assertions, target_os = "linux"))]
mod publication_crashes {
    use super::*;
    use crawlx_storage::archive::{publication, staging::StagedFile};
    use std::io::{BufRead as _, BufReader};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    struct Paused {
        child: Child,
        state: PathBuf,
        out: PathBuf,
    }
    impl Paused {
        fn start(base: &Path, source: &Path, checkpoint: &str) -> Self {
            let state = base.join("state");
            let out = base.join("publication");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "publication_crashes::publication_child", "--nocapture"])
                .env("XDG_STATE_HOME", &state)
                .env("CRAWLX_PUBLICATION_CLI_SOURCE", source)
                .env("CRAWLX_PUBLICATION_CLI_OUT", &out)
                .env("CRAWLX_PUBLICATION_TEST_STOP", checkpoint)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if line.unwrap().contains("publication checkpoint") {
                        sender.send(()).unwrap();
                        return;
                    }
                }
            });
            let paused = Self { child, state, out };
            receiver
                .recv_timeout(Duration::from_secs(30))
                .expect("publication checkpoint");
            paused
        }
        fn kill(&mut self) {
            use std::os::unix::process::ExitStatusExt as _;
            self.child.kill().unwrap();
            assert_eq!(self.child.wait().unwrap().signal(), Some(9));
        }
        fn cli(&self, args: &[&str]) -> std::process::Output {
            Command::new(env!("CARGO_BIN_EXE_crawlx"))
                .args(args)
                .env("XDG_STATE_HOME", &self.state)
                .env_remove("CRAWLX_PUBLICATION_TEST_STOP")
                .output()
                .unwrap()
        }
    }
    impl Drop for Paused {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn publication_child() {
        let Some(source) = std::env::var_os("CRAWLX_PUBLICATION_CLI_SOURCE") else {
            return;
        };
        let source = PathBuf::from(source);
        let out = PathBuf::from(std::env::var_os("CRAWLX_PUBLICATION_CLI_OUT").unwrap());
        let mut files = Vec::new();
        for name in [
            "archive/data.warc.gz",
            "indexes/index.cdxj",
            "pages/pages.jsonl",
            "crawlx/manifest.json",
        ] {
            let mut staged = StagedFile::new().unwrap();
            std::io::copy(&mut File::open(source.join(name)).unwrap(), staged.file_mut()).unwrap();
            files.push((name.to_owned(), staged));
        }
        publication::publish_bundle(&out, "test-export", &mut files).unwrap();
    }

    #[tokio::test]
    async fn cli_startup_and_admin_cleanup_resolve_real_sigkill_publications() {
        let fixture = fixture().await;
        let mut args = fixture.export("crash-source");
        let ArchiveCommand::Export(export) = &mut args.command else {
            panic!("export expected");
        };
        export.format = FormatArg::Warc;
        execute_with_clock(args, &mut Vec::new(), &fixture.clock)
            .await
            .unwrap();
        let source = fixture.dir.path().join("crash-source");

        for checkpoint in ["sentinel", "member", "manifest"] {
            let base = tempfile::tempdir().unwrap();
            let mut paused = Paused::start(base.path(), &source, checkpoint);
            let out = paused.out.to_str().unwrap();
            let refused = paused.cli(&["archive", "verify", out]);
            assert!(!refused.status.success());
            assert!(String::from_utf8_lossy(&refused.stderr).contains("incomplete"));
            paused.kill();
            if checkpoint == "manifest" {
                let verified = paused.cli(&["archive", "verify", paused.out.to_str().unwrap()]);
                assert!(
                    verified.status.success(),
                    "{}",
                    String::from_utf8_lossy(&verified.stderr)
                );
                assert!(!paused.out.join(".incomplete").exists());
            } else {
                let startup = paused.cli(&["config", "features"]);
                assert!(
                    startup.status.success(),
                    "{}",
                    String::from_utf8_lossy(&startup.stderr)
                );
                assert!(!paused.out.exists());
            }
        }

        // The actual admin invocation must sweep before its unavailable database is contacted.
        let base = tempfile::tempdir().unwrap();
        let mut paused = Paused::start(base.path(), &source, "manifest");
        paused.kill();
        std::fs::write(paused.out.join("archive/data.warc.gz"), b"bad fixity").unwrap();
        let admin = paused.cli(&[
            "admin",
            "sweep-retention",
            "--database-url",
            "invalid-database-url",
        ]);
        assert!(!admin.status.success());
        assert!(!paused.out.exists());
        assert!(!String::from_utf8_lossy(&admin.stderr).contains("unrecognized"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn startup_without_publication_journal_never_creates_user_state() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().unwrap();
    let app = home.path().join(".local/state/crawlx");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::set_permissions(&app, std::fs::Permissions::from_mode(0o555)).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["config", "features"])
        .env("HOME", home.path())
        .env_remove("XDG_STATE_HOME")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!app.join("archive-publications").exists());
    std::fs::set_permissions(&app, std::fs::Permissions::from_mode(0o700)).unwrap();

    let absent = home.path().join("absent-state");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["config", "features"])
        .env("XDG_STATE_HOME", &absent)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!absent.exists());
}

#[tokio::test]
async fn missing_export_parent_names_directory_before_staging() {
    let fixture = fixture().await;
    let args = fixture.export("missing/output.wacz");
    let error = execute_with_clock(args, &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("archive output directory"), "{error}");
    assert!(error.contains("missing"), "{error}");
    assert!(error.contains("create it first"), "{error}");
    assert!(!fixture.dir.path().join("missing").exists());
}

#[tokio::test]
async fn empty_export_reports_retained_object_omission() {
    let fixture = fixture().await;
    let index = fixture.dir.path().join("artifacts/_index");
    for row in std::fs::read_dir(index).unwrap() {
        std::fs::remove_file(row.unwrap().path()).unwrap();
    }
    let error = execute_with_clock(fixture.export("empty.wacz"), &mut Vec::new(), &fixture.clock)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("no retention-approved text artifacts"), "{error}");
    assert!(error.contains("retained_object_missing"), "{error}");
    assert!(!fixture.dir.path().join("empty.wacz").exists());
}

mod manage {
    //! `archive remove|cancel|commit`: every failure has its own nonzero exit code, and the
    //! catalog (not the CLI) decides what may be abandoned or erased.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use crawlx_cli::archive::{manage, ManageCommand, ManageOutcome};
    use crawlx_core::archive::{
        ArchiveCaptureFactsV1, ArchiveConfigV1, ArchiveFormat, ArchiveManifestV1, ArchiveRepresentation,
    };
    use crawlx_core::archive_catalog::{
        ArchiveDependencyV1, ArchiveExportV1, ArchiveFailureV1, ArchiveHistoryKeyV1, ArchiveHistoryV1,
        ArchiveRecordV1, ArchiveRepo,
    };
    use crawlx_core::counters::TerminalReason;
    use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
    use crawlx_core::time::ManualClock;
    use crawlx_core::{TenantId, Timestamp};
    use crawlx_storage::archive::{warc, Limits};
    use crawlx_storage::testkit::{crawl_run, create_crawl};
    use crawlx_storage::{FsArtifactStore, MemoryStore};
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Arc;

    struct Rig {
        store: Arc<MemoryStore>,
        artifacts: FsArtifactStore,
        tenant: TenantId,
        now: Timestamp,
        _dir: tempfile::TempDir,
    }

    async fn rig() -> Rig {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-08T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let clock = Arc::new(ManualClock::new(now));
        let store = Arc::new(MemoryStore::with_clock(clock.clone()));
        let dir = tempfile::tempdir().unwrap();
        let artifacts = FsArtifactStore::open(dir.path(), store.clone(), clock)
            .await
            .unwrap()
            .with_index(store.clone());
        Rig {
            store,
            artifacts,
            tenant: TenantId::new(),
            now,
            _dir: dir,
        }
    }

    fn config() -> ArchiveConfigV1 {
        let mut config = ArchiveConfigV1::default();
        config.format = ArchiveFormat::Warc;
        config
    }

    struct Staged {
        id: uuid::Uuid,
        fence: i64,
        record: ArchiveRecordV1,
        key: ArchiveHistoryKeyV1,
        shard_len: u64,
        index: crawlx_core::ArtifactRef,
    }

    /// A recording export with one committed shard; `dependency` makes it a revisit dependent.
    async fn recording(rig: &Rig, dependency: Option<(uuid::Uuid, &ArchiveHistoryKeyV1)>) -> Staged {
        let mut cfg = create_crawl("https://archive.example.test/data", &[], 1);
        cfg.retention.days = 7;
        cfg.output.archive = Some(config());
        let mut run = crawl_run(rig.tenant, cfg);
        run.created_at = rig.now;
        rig.store.create(&run, None).await.unwrap();
        let pending = ArchiveExportV1::pending(
            rig.tenant,
            run.id,
            config(),
            rig.now,
            Some(rig.now + chrono::Duration::days(7)),
            TerminalReason::FrontierExhausted,
        );
        rig.store.begin(&pending).await.unwrap();
        let claim = rig
            .store
            .claim(rig.tenant, pending.id, rig.now)
            .await
            .unwrap()
            .unwrap();
        let header = warc::RecordHeader {
            fields: BTreeMap::from([
                ("WARC-Type".into(), "resource".into()),
                (
                    "WARC-Record-ID".into(),
                    format!("<urn:uuid:{}>", uuid::Uuid::now_v7()),
                ),
                ("WARC-Date".into(), warc::date(rig.now)),
                (
                    "WARC-Target-URI".into(),
                    "https://archive.example.test/data".into(),
                ),
                ("Content-Type".into(), "text/plain".into()),
            ]),
            payload_offset: 0,
        };
        let mut encoded = Cursor::new(Vec::new());
        let summary = warc::write_record(
            &mut encoded,
            &header,
            &mut Cursor::new(b"owned retained body"),
            19,
            Limits::default(),
        )
        .unwrap();
        let shard = rig
            .artifacts
            .put(
                run.id,
                Sensitivity::Content,
                "application/warc",
                encoded.get_ref(),
            )
            .await
            .unwrap();
        let index = rig
            .artifacts
            .put(run.id, Sensitivity::Content, "application/cdxj", b"index")
            .await
            .unwrap();
        let facts = ArchiveCaptureFactsV1::retained(
            "event:1",
            rig.now,
            ArchiveRepresentation::ProtocolResource,
            "retained_native_decoded_response_body",
        );
        let mut record = ArchiveRecordV1::resource(
            run.id.0,
            1,
            summary.id,
            shard,
            summary.offset,
            summary.length,
            summary.payload_digest,
            "https://archive.example.test/data".into(),
            facts,
            "text/plain".into(),
        );
        let key = dependency.as_ref().map_or_else(
            || {
                ArchiveHistoryKeyV1::new(
                    record.target.clone(),
                    "GET".into(),
                    "anonymous".into(),
                    "variant-v1".into(),
                    "redaction-v1".into(),
                )
            },
            |(_, key)| (*key).clone(),
        );
        record.dependency = dependency.map(|(export, _)| ArchiveDependencyV1::new(export, 1));
        let history = ArchiveHistoryV1::new(
            key.clone(),
            ArchiveDependencyV1::new(record.export, 1),
            Some("\"v1\"".into()),
            None,
            rig.now,
        );
        rig.store
            .commit_record(rig.tenant, claim.fence, &record, Some(&history), rig.now)
            .await
            .unwrap();
        Staged {
            id: pending.id,
            fence: claim.fence,
            shard_len: summary.length,
            index,
            record,
            key,
        }
    }

    async fn publish(rig: &Rig, staged: &Staged) {
        let mut manifest =
            ArchiveManifestV1::available(rig.tenant, crawlx_core::CrawlRunId(staged.id), rig.now);
        manifest.records = 1;
        manifest.package_bytes = staged.shard_len;
        rig.store
            .publish(
                rig.tenant,
                staged.id,
                staged.fence,
                &staged.record.artifact,
                Some(&staged.index),
                &manifest,
                rig.now,
            )
            .await
            .unwrap();
    }

    async fn run(rig: &Rig, id: uuid::Uuid, command: ManageCommand) -> (ManageOutcome, serde_json::Value) {
        manage(rig.store.as_ref(), rig.tenant, id, command, rig.now)
            .await
            .unwrap()
    }

    #[test]
    fn every_failure_has_its_own_nonzero_exit_code() {
        use ManageOutcome::*;
        let failures = [
            NotFound,
            Expired,
            StillRecording,
            ExportFailed,
            AlreadyCommitted,
            DependentsPresent,
            ReceiptUnavailable,
        ];
        let mut codes: Vec<u8> = failures.iter().map(|outcome| outcome.exit_code()).collect();
        assert_eq!(Done.exit_code(), 0);
        assert!(
            codes.iter().all(|code| *code > 2),
            "1 and 2 stay reserved: {codes:?}"
        );
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), failures.len(), "exit codes must be distinct");
    }

    #[test]
    fn manage_commands_are_registered_with_their_arguments() {
        use clap::Parser;
        let id = "00000000-0000-8000-8000-000000000002";
        let tenant = "00000000-0000-8000-8000-000000000001";
        for command in ["remove", "cancel", "commit"] {
            let cli = crawlx_cli::Cli::try_parse_from(["crawlx", "archive", command, id, "--tenant", tenant])
                .unwrap();
            assert!(
                matches!(cli.command, crawlx_cli::Command::Archive(_)),
                "{command}"
            );
        }
        assert!(crawlx_cli::Cli::try_parse_from([
            "crawlx",
            "archive",
            "remove",
            id,
            "--tenant",
            tenant,
            "--cascade"
        ])
        .is_ok());
        assert!(crawlx_cli::Cli::try_parse_from(["crawlx", "archive", "cancel", id, "--cascade"]).is_err());
    }

    #[tokio::test]
    async fn unknown_export_is_not_found_for_every_command() {
        let rig = rig().await;
        let id = uuid::Uuid::new_v4();
        for command in [
            ManageCommand::Commit,
            ManageCommand::Cancel,
            ManageCommand::Remove { cascade: false },
        ] {
            let (outcome, body) = run(&rig, id, command).await;
            assert_eq!(outcome, ManageOutcome::NotFound, "{command:?}");
            assert_eq!(body["exit"], 20);
        }
    }

    #[tokio::test]
    async fn recording_export_is_not_committed_but_can_be_cancelled_once() {
        let rig = rig().await;
        let staged = recording(&rig, None).await;
        assert_eq!(
            run(&rig, staged.id, ManageCommand::Commit).await.0,
            ManageOutcome::StillRecording
        );
        // Removal of something not committed points at cancel instead of erasing it.
        let (outcome, body) = run(&rig, staged.id, ManageCommand::Remove { cascade: true }).await;
        assert_eq!(outcome, ManageOutcome::StillRecording);
        assert_eq!(body["exit"], 22);
        assert_eq!(
            run(&rig, staged.id, ManageCommand::Cancel).await.0,
            ManageOutcome::Done
        );
        // It is gone: a second cancel and a commit both report not found.
        assert_eq!(
            run(&rig, staged.id, ManageCommand::Cancel).await.0,
            ManageOutcome::NotFound
        );
        assert_eq!(
            run(&rig, staged.id, ManageCommand::Commit).await.0,
            ManageOutcome::NotFound
        );
        // Its shard is queued for physical erasure.
        assert!(!rig
            .store
            .erased_artifacts(rig.tenant, 64)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn failed_export_is_reported_and_never_a_receipt() {
        let rig = rig().await;
        let staged = recording(&rig, None).await;
        rig.store
            .fail(
                rig.tenant,
                staged.id,
                staged.fence,
                ArchiveFailureV1::LimitExceeded,
                rig.now,
            )
            .await
            .unwrap();
        let (outcome, body) = run(&rig, staged.id, ManageCommand::Commit).await;
        assert_eq!(outcome, ManageOutcome::ExportFailed);
        assert_eq!(body["exit"], 23);
        assert!(body.get("receipt").is_none());
        assert_eq!(
            run(&rig, staged.id, ManageCommand::Cancel).await.0,
            ManageOutcome::ExportFailed
        );
    }

    #[tokio::test]
    async fn committed_export_prints_hash_and_size_and_refuses_cancel() {
        let rig = rig().await;
        let staged = recording(&rig, None).await;
        publish(&rig, &staged).await;
        let (outcome, body) = run(&rig, staged.id, ManageCommand::Commit).await;
        assert_eq!(outcome, ManageOutcome::Done);
        let receipt = &body["receipt"];
        assert_eq!(receipt["state"], "committed");
        assert_eq!(receipt["packageBytes"], staged.shard_len);
        assert_eq!(
            receipt["package"]["digest"],
            staged.record.artifact.digest.to_hex()
        );
        let (outcome, body) = run(&rig, staged.id, ManageCommand::Cancel).await;
        assert_eq!(outcome, ManageOutcome::AlreadyCommitted);
        assert_eq!(body["exit"], 24);
        // Still committed after the refused cancel.
        assert_eq!(
            run(&rig, staged.id, ManageCommand::Commit).await.0,
            ManageOutcome::Done
        );
    }

    #[tokio::test]
    async fn published_export_without_a_size_receipt_reports_receipt_unavailable() {
        let rig = rig().await;
        let staged = recording(&rig, None).await;
        let mut manifest =
            ArchiveManifestV1::available(rig.tenant, crawlx_core::CrawlRunId(staged.id), rig.now);
        manifest.records = 1;
        rig.store
            .publish(
                rig.tenant,
                staged.id,
                staged.fence,
                &staged.record.artifact,
                Some(&staged.index),
                &manifest,
                rig.now,
            )
            .await
            .unwrap();
        let (outcome, body) = run(&rig, staged.id, ManageCommand::Commit).await;
        assert_eq!(outcome, ManageOutcome::ReceiptUnavailable);
        assert_eq!(body["exit"], 26);
    }

    #[tokio::test]
    async fn remove_refuses_an_orphaning_removal_until_cascade_and_then_erases_the_closure() {
        let rig = rig().await;
        let base = recording(&rig, None).await;
        publish(&rig, &base).await;
        let dependent = recording(&rig, Some((base.id, &base.key))).await;
        publish(&rig, &dependent).await;
        let (outcome, body) = run(&rig, base.id, ManageCommand::Remove { cascade: false }).await;
        assert_eq!(outcome, ManageOutcome::DependentsPresent);
        assert_eq!(body["exit"], 25);
        assert_eq!(body["dependents"], serde_json::json!([dependent.id.to_string()]));
        // The refusal changed nothing.
        assert_eq!(
            run(&rig, base.id, ManageCommand::Commit).await.0,
            ManageOutcome::Done
        );
        assert_eq!(
            run(&rig, dependent.id, ManageCommand::Commit).await.0,
            ManageOutcome::Done
        );
        let (outcome, body) = run(&rig, base.id, ManageCommand::Remove { cascade: true }).await;
        assert_eq!(outcome, ManageOutcome::Done);
        assert_eq!(
            body["removedDependents"],
            serde_json::json!([dependent.id.to_string()])
        );
        assert_eq!(
            run(&rig, base.id, ManageCommand::Commit).await.0,
            ManageOutcome::NotFound
        );
        assert_eq!(
            run(&rig, dependent.id, ManageCommand::Commit).await.0,
            ManageOutcome::NotFound
        );
        // A leaf can be removed without the flag.
        let leaf = recording(&rig, None).await;
        publish(&rig, &leaf).await;
        assert_eq!(
            run(&rig, leaf.id, ManageCommand::Remove { cascade: false })
                .await
                .0,
            ManageOutcome::Done
        );
    }

    #[tokio::test]
    async fn another_tenants_export_is_not_found() {
        let rig = rig().await;
        let staged = recording(&rig, None).await;
        publish(&rig, &staged).await;
        let (outcome, _) = manage(
            rig.store.as_ref(),
            TenantId::new(),
            staged.id,
            ManageCommand::Remove { cascade: true },
            rig.now,
        )
        .await
        .unwrap();
        assert_eq!(outcome, ManageOutcome::NotFound);
        assert_eq!(
            run(&rig, staged.id, ManageCommand::Commit).await.0,
            ManageOutcome::Done
        );
    }
}
