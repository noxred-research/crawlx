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
