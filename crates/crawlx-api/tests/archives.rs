//! Authenticated catalog progress, real streamed WARC bytes, expiry and physical erasure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::{Method, StatusCode};
use crawlx_api::Scope;
use crawlx_core::archive::{
    ArchiveCaptureFactsV1, ArchiveConfigV1, ArchiveFormat, ArchiveManifestV1, ArchiveRepresentation,
};
use crawlx_core::archive_catalog::{ArchiveExportV1, ArchiveRecordV1, ArchiveRepo};
use crawlx_core::counters::TerminalReason;
use crawlx_core::repo::{RunRepo, Sensitivity};
use crawlx_core::{ArtifactRef, Clock, SystemClock};
use crawlx_storage::archive::{cdxj, warc, Limits};
use crawlx_storage::{testkit, ArtifactIndex};
use std::collections::BTreeMap;
use std::io::Cursor;

async fn put(e: &common::Env, run: crawlx_core::CrawlRunId, mime: &str, bytes: &[u8]) -> ArtifactRef {
    let artifact = e
        .artifacts
        .put_kind(run, Sensitivity::Content, "evidence", mime, bytes)
        .await
        .unwrap();
    // The fixture uses the ordinary object-first index mirror, not fabricated catalog references.
    let row = e.artifacts.row(artifact.id).await.unwrap().unwrap();
    ArtifactIndex::record(e.store.as_ref(), &row).await.unwrap();
    artifact
}

#[tokio::test]
async fn archive_routes_enforce_scopes_tenants_publication_and_erasure() {
    let e = common::env();
    let now = SystemClock.now();
    let mut config = ArchiveConfigV1::default();
    config.format = ArchiveFormat::Warc;
    let mut crawl = testkit::create_crawl("https://archive.example.test/", &[], 1);
    crawl.output.archive = Some(config.clone());
    let mut run = testkit::crawl_run(e.tenant, crawl);
    run.created_at = now;
    RunRepo::create(e.store.as_ref(), &run, None).await.unwrap();
    let expires = (run.config.retention.days != 0)
        .then(|| now + chrono::Duration::days(i64::from(run.config.retention.days)));
    let pending = ArchiveExportV1::pending(
        e.tenant,
        run.id,
        config,
        now,
        expires,
        TerminalReason::FrontierExhausted,
    );
    e.store.begin(&pending).await.unwrap();
    let root = format!("/v1/crawls/{}/archives/{}", run.id, pending.id);
    assert_eq!(e.get(&root).await.0, StatusCode::OK);
    let foreign = e
        .key_for("other-archive-tenant", &[Scope::CrawlsRead, Scope::CrawlsWrite])
        .await;
    assert_eq!(e.get_as(&foreign, &root).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        e.send(Method::GET, &root, None, &[], None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(e.get(&format!("{root}/export")).await.0, StatusCode::CONFLICT);
    let claim = e.store.claim(e.tenant, pending.id, now).await.unwrap().unwrap();
    let header = warc::RecordHeader {
        fields: BTreeMap::from([
            ("WARC-Type".into(), "resource".into()),
            (
                "WARC-Record-ID".into(),
                format!("<urn:uuid:{}>", uuid::Uuid::now_v7()),
            ),
            ("WARC-Date".into(), warc::date(now)),
            ("WARC-Target-URI".into(), "https://archive.example.test/".into()),
            ("Content-Type".into(), "text/plain".into()),
        ]),
        payload_offset: 0,
    };
    let mut file = Cursor::new(Vec::new());
    let summary = warc::write_record(
        &mut file,
        &header,
        &mut Cursor::new(b"retained fixture"),
        16,
        Limits::default(),
    )
    .unwrap();
    let artifact = put(&e, run.id, "application/warc", file.get_ref()).await;
    let index_text = cdxj::Entry::from_record(&summary, "data.warc.gz")
        .unwrap()
        .line(&summary)
        .unwrap();
    let index = put(&e, run.id, "application/cdxj", index_text.as_bytes()).await;
    let record = ArchiveRecordV1::resource(
        pending.id,
        1,
        summary.id,
        artifact.clone(),
        summary.offset,
        summary.length,
        summary.payload_digest,
        "https://archive.example.test/".into(),
        ArchiveCaptureFactsV1::retained(
            "fixture:1",
            now,
            ArchiveRepresentation::ProtocolResource,
            "retained_fixture_body",
        ),
        "text/plain".into(),
    );
    e.store
        .commit_record(e.tenant, claim.fence, &record, None, now)
        .await
        .unwrap();
    let mut manifest = ArchiveManifestV1::available(e.tenant, run.id, now);
    manifest.records = 1;
    e.store
        .publish(
            e.tenant,
            pending.id,
            claim.fence,
            &artifact,
            Some(&index),
            &manifest,
            now,
        )
        .await
        .unwrap();
    let (status, headers, body) = e
        .send(Method::GET, &format!("{root}/export"), Some(&e.key), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/warc");
    let disposition = headers["content-disposition"].to_str().unwrap();
    assert!(
        disposition.starts_with("attachment; filename=\"crawlx-archive-")
            && disposition.ends_with(".warc.gz\""),
        "{disposition}"
    );
    let (decoded, payload) = warc::read_member(Cursor::new(body), Limits::default()).unwrap();
    assert_eq!(decoded.id, record.record_id);
    assert_eq!(payload, b"retained fixture");
    let (_, _, projection) = e.get(&format!("{root}/records?limit=1")).await;
    assert!(projection.to_string().contains(&record.record_id));
    let reader = e.key_for("acme", &[Scope::CrawlsRead]).await;
    assert_eq!(
        e.send(Method::DELETE, &root, Some(&reader), &[], None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        e.send(Method::DELETE, &root, Some(&e.key), &[], None).await.0,
        StatusCode::OK
    );
    assert_eq!(e.get(&root).await.0, StatusCode::NOT_FOUND);
    assert!(e.artifacts.row(artifact.id).await.unwrap().is_none());
    assert!(e.artifacts.row(index.id).await.unwrap().is_none());
    assert_eq!(
        e.send(Method::DELETE, &root, Some(&e.key), &[], None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn expired_archive_read_returns_gone_without_content_metadata() {
    let now = SystemClock.now();
    let clock = std::sync::Arc::new(crawlx_core::time::ManualClock::new(now));
    let e = common::env_with(
        crawlx_api::ApiConfig {
            rate_limit_per_minute: 0,
            ..crawlx_api::ApiConfig::default()
        },
        crawlx_api::Settings::default(),
        clock.clone(),
    );
    let config = ArchiveConfigV1::default();
    let mut crawl = testkit::create_crawl("https://archive.example.test/", &[], 1);
    crawl.retention.days = 1;
    crawl.output.archive = Some(config.clone());
    let mut run = testkit::crawl_run(e.tenant, crawl);
    run.created_at = now;
    RunRepo::create(e.store.as_ref(), &run, None).await.unwrap();
    let pending = ArchiveExportV1::pending(
        e.tenant,
        run.id,
        config,
        now,
        Some(now + chrono::Duration::days(1)),
        TerminalReason::FrontierExhausted,
    );
    e.store.begin(&pending).await.unwrap();
    clock.advance_ms(86_400_001);
    let (status, _, body) = e
        .get(&format!("/v1/crawls/{}/archives/{}", run.id, pending.id))
        .await;
    assert_eq!(status, StatusCode::GONE);
    assert!(!body.to_string().contains("captureSource"));
}

#[tokio::test]
async fn sensitive_archive_shards_package_and_index_keep_scope_and_source_deadline() {
    use crawlx_core::archive_catalog::{ArchiveCustodyV1, ArchiveReadV1};
    use crawlx_core::repo::ArtifactStore as _;
    let now = SystemClock.now();
    let clock = std::sync::Arc::new(crawlx_core::time::ManualClock::new(now));
    let mut e = common::env_with(
        crawlx_api::ApiConfig {
            rate_limit_per_minute: 0,
            ..crawlx_api::ApiConfig::default()
        },
        crawlx_api::Settings::default(),
        clock.clone(),
    );
    // Archive file publication requires a streaming sink; the shared memory fixture
    // deliberately refuses that capability. Serve the same filesystem store we write.
    let artifact_root = tempfile::tempdir().unwrap();
    let artifacts = std::sync::Arc::new(
        crawlx_storage::FsArtifactStore::open(artifact_root.path(), e.store.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(e.store.clone()),
    );
    let mut repos = e.state.repos.clone();
    repos.artifacts = artifacts.clone();
    e.state = crawlx_api::AppState::builder(
        repos,
        crawlx_api::admission_policy(&e.state.config, clock.clone()),
        e.state.config.clone(),
    )
    .clock(clock.clone())
    .zdr_buffer(e.state.zdr.clone())
    .build();
    e.app = crawlx_api::router(e.state.clone());
    let mut config = ArchiveConfigV1::default();
    config.format = ArchiveFormat::Warc;
    let mut crawl = testkit::create_crawl("https://archive.example.test/", &[], 1);
    crawl.retention.days = 7;
    crawl.output.archive = Some(config.clone());
    let mut run = testkit::crawl_run(e.tenant, crawl);
    run.created_at = now;
    RunRepo::create(e.store.as_ref(), &run, None).await.unwrap();
    let pending = ArchiveExportV1::pending(
        e.tenant,
        run.id,
        config,
        now,
        Some(now + chrono::Duration::days(7)),
        TerminalReason::FrontierExhausted,
    );
    e.store.begin(&pending).await.unwrap();
    let claim = e.store.claim(e.tenant, pending.id, now).await.unwrap().unwrap();
    let deadline = now + chrono::Duration::minutes(10);
    let evidence = b"approved sensitive capture";
    let source = artifacts
        .put_until(run.id, Sensitivity::Sensitive, "text/plain", evidence, deadline)
        .await
        .unwrap();
    let custody = artifacts
        .archive_custody(e.tenant, run.id, &source, 1024)
        .await
        .unwrap();
    assert_eq!(custody, ArchiveCustodyV1::sensitive(deadline));
    assert!(artifacts
        .read_archive_content(e.tenant, run.id, &source, 1024)
        .await
        .is_err());
    assert_eq!(
        artifacts
            .read_archive_sensitive(e.tenant, run.id, &source, &custody, 1024,)
            .await
            .unwrap(),
        evidence
    );
    let wrong = ArchiveCustodyV1::content(Some(deadline));
    assert!(artifacts
        .read_archive_sensitive(e.tenant, run.id, &source, &wrong, 1024,)
        .await
        .is_err());
    e.store
        .narrow_custody(e.tenant, pending.id, claim.fence, &custody, now)
        .await
        .unwrap();
    // Replaying the original intent cannot reset the persisted class or deadline.
    e.store.begin(&pending).await.unwrap();
    clock.advance_ms(121_000);
    let recovered = e
        .store
        .claim(e.tenant, pending.id, clock.now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.custody, custody);
    assert_eq!(recovered.expires_at, Some(deadline));
    let header = warc::RecordHeader {
        fields: BTreeMap::from([
            ("WARC-Type".into(), "resource".into()),
            ("WARC-Record-ID".into(), format!("<urn:uuid:{}>", run.id)),
            ("WARC-Date".into(), warc::date(now)),
            ("WARC-Target-URI".into(), "https://archive.example.test/".into()),
            ("Content-Type".into(), "text/plain".into()),
        ]),
        payload_offset: 0,
    };
    let mut member = Cursor::new(Vec::new());
    let summary = warc::write_record(
        &mut member,
        &header,
        &mut Cursor::new(evidence),
        u64::try_from(evidence.len()).unwrap(),
        Limits::default(),
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let shard_path = root.path().join("shard.warc.gz");
    let package_path = root.path().join("package.warc.gz");
    let index_path = root.path().join("index.cdxj");
    tokio::fs::write(&shard_path, member.get_ref()).await.unwrap();
    let shard = artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &shard_path, 1_048_576, &custody)
        .await
        .unwrap();
    artifacts
        .copy_archive_with_custody(e.tenant, run.id, &shard, &custody, &package_path, 1_048_576)
        .await
        .unwrap();
    let package = artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &package_path, 1_048_576, &custody)
        .await
        .unwrap();
    let index_text = cdxj::Entry::from_record(&summary, "data.warc.gz")
        .unwrap()
        .line(&summary)
        .unwrap();
    tokio::fs::write(&index_path, index_text).await.unwrap();
    let index = artifacts
        .put_archive_file_with_custody(run.id, "application/cdxj", &index_path, 1_048_576, &custody)
        .await
        .unwrap();
    let mut record = ArchiveRecordV1::resource(
        pending.id,
        1,
        summary.id,
        shard.clone(),
        summary.offset,
        summary.length,
        summary.payload_digest,
        "https://archive.example.test/".into(),
        ArchiveCaptureFactsV1::retained(
            "fixture:1",
            now,
            ArchiveRepresentation::ProtocolResource,
            "approved_sensitive_capture",
        ),
        "text/plain".into(),
    );
    record.custody = custody;
    assert!(e
        .store
        .commit_record(e.tenant, recovered.fence, &record, None, clock.now())
        .await
        .is_err());
    record.source_artifact = Some(source.clone());
    e.store
        .commit_record(e.tenant, recovered.fence, &record, None, clock.now())
        .await
        .unwrap();
    let mut manifest = ArchiveManifestV1::available(e.tenant, run.id, now);
    manifest.records = 1;
    assert!(e
        .store
        .publish(
            e.tenant,
            pending.id,
            recovered.fence,
            &package,
            Some(&index),
            &manifest,
            clock.now(),
        )
        .await
        .is_err());
    manifest.custody = custody;
    let ordinary = artifacts
        .put_kind(
            run.id,
            Sensitivity::Content,
            "evidence",
            "application/warc",
            member.get_ref(),
        )
        .await
        .unwrap();
    assert!(e
        .store
        .publish(
            e.tenant,
            pending.id,
            recovered.fence,
            &ordinary,
            Some(&index),
            &manifest,
            clock.now(),
        )
        .await
        .is_err());
    let extended = artifacts
        .put_until(
            run.id,
            Sensitivity::Sensitive,
            "application/warc",
            member.get_ref(),
            deadline + chrono::Duration::seconds(1),
        )
        .await
        .unwrap();
    assert!(e
        .store
        .publish(
            e.tenant,
            pending.id,
            recovered.fence,
            &extended,
            Some(&index),
            &manifest,
            clock.now(),
        )
        .await
        .is_err());
    e.store
        .publish(
            e.tenant,
            pending.id,
            recovered.fence,
            &package,
            Some(&index),
            &manifest,
            clock.now(),
        )
        .await
        .unwrap();
    for reference in [&source, &shard, &package, &index] {
        let row = artifacts.row(reference.id).await.unwrap().unwrap();
        assert_eq!(row.sensitivity, Sensitivity::Sensitive);
        assert_eq!(row.expires_at, Some(deadline));
    }
    let reader = e.key_for("acme", &[Scope::CrawlsRead]).await;
    let sensitive_reader = e
        .key_for("acme", &[Scope::CrawlsRead, Scope::ArtifactsReadSensitive])
        .await;
    let foreign_reader = e
        .key_for(
            "other-sensitive-archive-tenant",
            &[Scope::CrawlsRead, Scope::ArtifactsReadSensitive],
        )
        .await;
    let export_root = format!("/v1/crawls/{}/archives/{}", run.id, pending.id);
    for path in [
        format!("{export_root}/export"),
        format!("{export_root}/records"),
        format!("/v1/crawls/{}/artifacts/{}", run.id, shard.id),
        format!("/v1/crawls/{}/artifacts/{}", run.id, package.id),
        format!("/v1/crawls/{}/artifacts/{}", run.id, index.id),
    ] {
        assert_eq!(e.get_as(&reader, &path).await.0, StatusCode::FORBIDDEN);
        assert_eq!(e.get_as(&sensitive_reader, &path).await.0, StatusCode::OK);
        assert_eq!(e.get_as(&foreign_reader, &path).await.0, StatusCode::NOT_FOUND);
    }
    let (_, _, progress) = e.get_as(&reader, &export_root).await;
    assert!(progress["manifest"].is_null());
    assert!(progress["artifact"].is_null());
    let ArchiveReadV1::Available(saved) =
        ArchiveRepo::get(e.store.as_ref(), e.tenant, pending.id, clock.now())
            .await
            .unwrap()
    else {
        panic!("published sensitive archive missing");
    };
    assert_eq!(saved.custody, custody);
    let mut shortened_source = artifacts.row(source.id).await.unwrap().unwrap();
    shortened_source.expires_at = Some(deadline - chrono::Duration::seconds(1));
    ArtifactIndex::record(e.store.as_ref(), &shortened_source)
        .await
        .unwrap();
    for path in [
        format!("{export_root}/export"),
        format!("{export_root}/records"),
        format!("/v1/crawls/{}/artifacts/{}", run.id, shard.id),
        format!("/v1/crawls/{}/artifacts/{}", run.id, index.id),
    ] {
        assert_eq!(e.get_as(&sensitive_reader, &path).await.0, StatusCode::GONE);
    }
    let (_, _, revoked_progress) = e.get_as(&sensitive_reader, &export_root).await;
    assert!(revoked_progress["manifest"].is_null());
    clock.advance_ms(480_000);
    assert_eq!(
        e.get_as(&sensitive_reader, &format!("{export_root}/export"))
            .await
            .0,
        StatusCode::GONE
    );
    assert_eq!(
        e.send(Method::DELETE, &export_root, Some(&e.key), &[], None)
            .await
            .0,
        StatusCode::OK
    );
    for reference in [&shard, &package, &index] {
        assert!(artifacts.row(reference.id).await.unwrap().is_none());
    }
}
