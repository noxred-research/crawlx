//! Kill a real recorder process at each local custody boundary and resume its committed generations.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, BufReader};

#[tokio::test]
async fn archive_boundary_child() {
    let Ok(schema) = std::env::var("CRAWLX_ARCHIVE_CRASH_SCHEMA") else {
        return;
    };
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init()
        .unwrap();
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").unwrap();
    let root = std::env::var("CRAWLX_ARCHIVE_CRASH_ROOT").unwrap();
    let tenant =
        TenantId(uuid::Uuid::parse_str(&std::env::var("CRAWLX_ARCHIVE_CRASH_TENANT").unwrap()).unwrap());
    let run = crawlx_core::CrawlRunId(
        uuid::Uuid::parse_str(&std::env::var("CRAWLX_ARCHIVE_CRASH_RUN").unwrap()).unwrap(),
    );
    let now = chrono::DateTime::parse_from_rfc3339(&std::env::var("CRAWLX_ARCHIVE_CRASH_CLOCK").unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc);
    let clock = Arc::new(ManualClock::new(now));
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(schema),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    let artifacts = Arc::new(
        FsArtifactStore::open(Path::new(&root), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    let stores = Stores::over_durable(crate::durable::DurableStore::Postgres(pg), artifacts, tenant);
    let run = stores.runs.get(run).await.unwrap();
    let result = finalize(
        &stores,
        &run,
        clock,
        &CancellationToken::new(),
        TerminalReason::FrontierExhausted,
    )
    .await;
    panic!("recorder escaped selected crash boundary: {result:?}");
}

#[tokio::test]
async fn sigkill_at_each_archive_boundary_recovers_one_package_without_lost_or_duplicate_records() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let schema = format!("archive_crash_{}", uuid::Uuid::now_v7().simple());
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(schema.clone()),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "archive-crash").await.unwrap();
    for boundary in [
        "archive.before_shard_commit",
        "archive.after_object_put",
        "archive.after_shard_commit",
        "archive.before_manifest_publish",
    ] {
        let staging = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(
            chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap(),
        ));
        let artifacts = Arc::new(
            FsArtifactStore::open(root.path(), Arc::new(pg.clone()), clock.clone())
                .await
                .unwrap()
                .with_index(Arc::new(pg.clone())),
        );
        let stores = Stores::over_durable(
            crate::durable::DurableStore::Postgres(pg.clone()),
            artifacts,
            tenant,
        );
        let (run, _) = generations(&stores, clock.as_ref(), Some(1024)).await;
        // The running parent's executable inode stays pinned even if another build replaces its path.
        let mut child = tokio::process::Command::new(format!("/proc/{}/exe", std::process::id()))
            .args([
                "--exact",
                "archive_recorder::tests::crash::archive_boundary_child",
                "--nocapture",
            ])
            .env("CRAWLX_ARCHIVE_CRASH_SCHEMA", &schema)
            .env("CRAWLX_ARCHIVE_CRASH_ROOT", root.path())
            .env("TMPDIR", staging.path())
            .env("CRAWLX_ARCHIVE_CRASH_TENANT", tenant.to_string())
            .env("CRAWLX_ARCHIVE_CRASH_RUN", run.id.to_string())
            .env("CRAWLX_ARCHIVE_CRASH_CLOCK", clock.now().to_rfc3339())
            .env("CRAWLX_STORAGE_PAUSE_AT", boundary)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if line.contains("failpoint: sleeping") && line.contains(boundary) {
                    return;
                }
            }
            panic!("recorder exited before selected crash boundary");
        })
        .await
        .expect("recorder did not reach selected crash boundary");
        child.kill().await.unwrap();
        assert!(!child.wait().await.unwrap().success());
        assert_no_staged_bytes(staging.path());
        let ArchiveReadV1::Available(interrupted) =
            stores.archives.get(tenant, run.id.0, clock.now()).await.unwrap()
        else {
            panic!("interrupted export missing");
        };
        assert_eq!(interrupted.state, ArchiveExportState::Recording);
        assert!(interrupted.artifact.is_none());
        assert!(interrupted.manifest.is_none());
        clock.advance_ms(121_000);
        assert_eq!(
            finalize(
                &stores,
                &run,
                clock.clone(),
                &CancellationToken::new(),
                TerminalReason::FrontierExhausted
            )
            .await
            .unwrap(),
            Finalization::Ready,
        );
        let rows = stores
            .archives
            .records(tenant, run.id.0, None, 64, clock.now())
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .map(|row| &row.record_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
        let ArchiveReadV1::Available(published) =
            stores.archives.get(tenant, run.id.0, clock.now()).await.unwrap()
        else {
            panic!("recovered export missing");
        };
        let output = root.path().join("recovered.wacz");
        stores
            .artifacts
            .copy_archive_content(
                tenant,
                run.id,
                published.artifact.as_ref().unwrap(),
                &output,
                1_048_576,
            )
            .await
            .unwrap();
        let inspected = wacz::inspect(File::open(&output).unwrap(), Limits::default()).unwrap();
        assert_eq!(inspected.indexed, 2);
        assert_eq!(inspected.records.values().map(Vec::len).sum::<usize>(), 2);
        std::fs::remove_file(output).unwrap();
    }
    pg.drop_schema().await.unwrap();
}

fn assert_no_staged_bytes(root: &Path) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        if metadata.is_dir() {
            assert_no_staged_bytes(&path);
        } else if metadata.is_file() {
            assert_eq!(metadata.len(), 0, "orphaned staged bytes: {}", path.display());
        }
    }
}

#[tokio::test]
async fn anonymous_stage_child() {
    let Ok(stage) = std::env::var("CRAWLX_ARCHIVE_ANONYMOUS_STAGE") else {
        return;
    };
    use crawlx_core::browser_capture::{
        CaptureArtifact, CaptureCompleteness, CaptureDescriptor, CaptureKind,
    };
    use image::ImageEncoder as _;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::os::unix::fs::MetadataExt as _;

    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init()
        .unwrap();
    let durable = std::env::var("CRAWLX_ARCHIVE_CRASH_ROOT").unwrap();
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    ));
    let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
    let stores = Stores::over_memory(memory, Path::new(&durable)).await.unwrap();
    let mut config = create_crawl("https://stage.example.test/", &[], 1);
    config.retention.days = 1;
    config.capture.browser.phase_resources = true;
    config.output.archive = Some(crawlx_core::archive::ArchiveConfigV1::default());
    let mut run = crawl_run(stores.tenant, config);
    run.created_at = clock.now();
    stores.runs.create(&run, None).await.unwrap();
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png)
        .write_image(
            &[0, 10, 20, 255, 30, 40, 50, 255],
            2,
            1,
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();
    let source = ArtifactSink::over(stores.artifacts.as_ref())
        .put(
            run.id,
            Sensitivity::Sensitive,
            "image/png",
            &ArtifactRedactor::new().verify_binary(&png).unwrap(),
        )
        .await
        .unwrap();
    let target = "https://stage.example.test/screenshot";
    let mut capture = CaptureArtifact::new(
        CaptureDescriptor::new(CaptureKind::Screenshot, "image/png", target),
        source.clone(),
        u64::try_from(png.len()).unwrap(),
        CaptureCompleteness::Complete,
    );
    capture.width = Some(2);
    capture.height = Some(1);
    let pending = ArchiveExportV1::pending(
        run.tenant,
        run.id,
        run.config.output.archive.as_ref().unwrap().clone(),
        run.created_at,
        Some(run.created_at + chrono::Duration::days(1)),
        TerminalReason::FrontierExhausted,
    );
    stores.archives.begin(&pending).await.unwrap();
    let export = stores
        .archives
        .claim(run.tenant, pending.id, clock.now())
        .await
        .unwrap()
        .unwrap();
    let cancel = CancellationToken::new();
    let mut recorder = resource::Recorder {
        stores: &stores,
        run: &run,
        export: &export,
        clock: clock.as_ref(),
        cancel: &cancel,
        committed_bytes: 0,
    };
    let mut facts = ArchiveCaptureFactsV1::retained(
        "screenshot:initial",
        run.created_at,
        ArchiveRepresentation::Screenshot,
        "browser_evidence_initial",
    );
    facts.redaction_revision = "browser-evidence-v1".into();
    facts.body_state = "complete".into();
    assert!(matches!(
        recorder
            .record(resource::ResourceInput {
                ordinal: 8,
                source: Some(&source),
                capture: Some(&capture),
                target,
                mime: "image/png",
                facts,
                history_source: None,
            })
            .await
            .unwrap(),
        resource::RecordOutcome::Committed
    ));
    let record = stores
        .archives
        .records(run.tenant, export.id, None, 1, clock.now())
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(record.custody.sensitivity, Sensitivity::Sensitive);
    let shard = StagedFile::new().unwrap();
    stores
        .artifacts
        .copy_archive_with_custody(
            run.tenant,
            run.id,
            &record.artifact,
            &record.custody,
            shard.path(),
            1_048_576,
        )
        .await
        .unwrap();
    assert_eq!(shard.file().metadata().unwrap().nlink(), 0);
    let mut writer = PackageWriter::open(Some(65_536), Limits::default()).unwrap();
    writer.append(&shard, &record, Limits::default()).unwrap();
    // Valid long targets force actual CDXJ spill runs while rollover keeps members bounded.
    let mut index_bytes = 0usize;
    for ordinal in 1..=1200u64 {
        let mut row = record.clone();
        row.ordinal = ordinal + 8;
        row.record_id = format!("<urn:uuid:00000000-0000-8000-8000-{ordinal:012}>");
        row.target = format!("https://stage.example.test/{ordinal}/{}", "a".repeat(1024));
        row.facts.source_event = format!("screenshot:{ordinal}");
        let header = warc::RecordHeader {
            payload_offset: 0,
            fields: BTreeMap::from([
                ("WARC-Type".into(), "resource".into()),
                ("WARC-Record-ID".into(), row.record_id.clone()),
                ("WARC-Date".into(), warc::date(row.facts.captured_at)),
                ("WARC-Target-URI".into(), row.target.clone()),
                ("Content-Type".into(), "image/png".into()),
                (
                    "Crawlx-Capture-Facts".into(),
                    serde_json::to_string(&row.facts).unwrap(),
                ),
            ]),
        };
        let mut member = StagedFile::new().unwrap();
        let summary = warc::write_record(
            member.file_mut(),
            &header,
            &mut Cursor::new(&png),
            u64::try_from(png.len()).unwrap(),
            Limits::default(),
        )
        .unwrap();
        row.offset = summary.offset;
        row.length = summary.length;
        row.payload_digest = summary.payload_digest.clone();
        index_bytes += cdxj::Entry::from_record(&summary, "data.warc.gz")
            .unwrap()
            .line(&summary)
            .unwrap()
            .len();
        writer.append(&member, &row, Limits::default()).unwrap();
    }
    assert!(index_bytes > 1_048_576);
    assert_eq!(writer.pages.file().metadata().unwrap().nlink(), 0);
    assert_eq!(writer.facts.file().metadata().unwrap().nlink(), 0);
    assert_no_staged_bytes(Path::new(&std::env::var("TMPDIR").unwrap()));
    if stage == "members" {
        eprintln!("anonymous archive staging ready: members");
        std::future::pending::<()>().await;
        drop(writer);
    } else {
        assert_eq!(stage, "package");
        let mut manifest = ArchiveManifestV1::available(run.tenant, run.id, run.created_at);
        manifest.records = 1201;
        let package = writer
            .finish(&manifest, ArchiveFormat::Wacz, Limits::default())
            .unwrap();
        assert_eq!(package.archive.file().metadata().unwrap().nlink(), 0);
        let inspected = wacz::inspect(package.archive.reader().unwrap(), Limits::default()).unwrap();
        assert_eq!(inspected.indexed, 1201);
        let (filename, records) = inspected.records.iter().next().unwrap();
        assert_eq!(
            wacz::payload(
                package.archive.reader().unwrap(),
                filename,
                &records[0],
                Limits::default()
            )
            .unwrap(),
            png
        );
        assert_no_staged_bytes(Path::new(&std::env::var("TMPDIR").unwrap()));
        eprintln!("anonymous archive staging ready: package");
        std::future::pending::<()>().await;
        drop(package);
    }
    drop(shard);
    panic!("anonymous staging child escaped kill boundary");
}

#[tokio::test]
async fn sigkill_sensitive_archive_staging_leaves_no_named_bytes() {
    use std::os::unix::process::ExitStatusExt as _;
    for stage in ["shard", "members", "package"] {
        let durable = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        assert_ne!(durable.path(), staging.path());
        let mut command = tokio::process::Command::new(format!("/proc/{}/exe", std::process::id()));
        command
            .args([
                "--exact",
                "archive_recorder::tests::crash::anonymous_stage_child",
                "--nocapture",
            ])
            .env("CRAWLX_ARCHIVE_ANONYMOUS_STAGE", stage)
            .env("CRAWLX_ARCHIVE_CRASH_ROOT", durable.path())
            .env("TMPDIR", staging.path())
            .env_remove("CRAWLX_STORAGE_PAUSE_AT")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if stage == "shard" {
            command.env("CRAWLX_STORAGE_PAUSE_AT", "archive.before_shard_commit");
        }
        let mut child = command.spawn().unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        tokio::time::timeout(Duration::from_secs(60), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if (stage == "shard"
                    && line.contains("failpoint: sleeping")
                    && line.contains("archive.before_shard_commit"))
                    || line.contains(&format!("anonymous archive staging ready: {stage}"))
                {
                    return;
                }
            }
            panic!("anonymous staging child exited before {stage}");
        })
        .await
        .expect("anonymous staging child did not reach kill boundary");
        child.kill().await.unwrap();
        assert_eq!(child.wait().await.unwrap().signal(), Some(9));
        assert_no_staged_bytes(staging.path());
        assert!(std::fs::read_dir(durable.path()).unwrap().next().is_some());
    }
}
