//! Conformance cases (archive): the catalog tracks actual artifacts, fences and dependency
//! erasure; expiry and ZDR are typed; sensitive custody fails closed; history and payload-source
//! lookups; recoverable exports; erased artifacts and tenant isolation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::data::raw::{Raw, V};
use crate::rig::Rig;
use crawlx_core::archive::{
    ArchiveCaptureFactsV1, ArchiveConfigV1, ArchiveDedupe, ArchiveFormat, ArchiveManifestV1,
    ArchiveRepresentation,
};
use crawlx_core::archive_catalog::{
    ArchiveCustodyV1, ArchiveDependencyV1, ArchiveExportV1, ArchiveHistoryKeyV1, ArchiveHistoryV1,
    ArchivePayloadKeyV1, ArchiveReadV1, ArchiveRecordV1, ArchiveRepo,
};
use crawlx_core::counters::TerminalReason;
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::{ArtifactRef, Clock, StoreError, TenantId, Timestamp};
use crawlx_storage::archive::{cdxj, warc, Limits};
use crawlx_storage::sql::Sql;
use crawlx_storage::testkit::{crawl_run, create_crawl, Engine};
use crawlx_storage::{ArtifactIndex, BufferLimits, DeliveryBuffer, FsArtifactStore, Store};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

conformance! { all:
    catalog_tracks_actual_artifacts_fences_and_dependency_erasure,
    expiry_and_zdr_are_typed_without_returning_content_metadata,
    sensitive_archive_capability_rejects_changed_authority_and_expiry,
    sensitive_source_shortening_or_revocation_fails_closed,
    erased_artifacts_drain_through_acknowledge,
    history_lookup_needs_a_published_export_and_validators,
    payload_source_returns_the_standalone_approved_record,
    recoverable_lists_unfinished_exports_of_active_runs,
    exports_of_two_tenants_are_isolated,
    dependents_and_cancel_report_the_closure_and_never_touch_committed_exports,
}

conformance! { databases:
    sweeper_resumes_physical_erasure,
    sweeper_erases_sensitive_archive_objects_when_source_authority_changes,
    traffic_projection_preserves_chronology_and_never_adopts_foreign_artifacts,
}

/// The volatile store that holds the operational record of a zero-retention run.
fn delivery_buffer() -> Arc<DeliveryBuffer> {
    Arc::new(DeliveryBuffer::new(
        Arc::new(crawlx_core::SystemClock),
        BufferLimits::default(),
    ))
}

/// Run `$body` with `$repo` bound to an `Arc` of the engine's repository (the in-memory
/// store, or the `Store` of SQLite, MariaDB or PostgreSQL).
macro_rules! on_arc {
    ($rig:expr, |$repo:ident| $body:expr) => {{
        match $rig.engine() {
            Engine::Memory => {
                let $repo = $rig.store().clone();
                $body
            }
            Engine::Sqlite => {
                let $repo = Arc::new(
                    $rig.database()
                        .sqlite_store()
                        .expect("a sqlite rig has a store")
                        .clone()
                        .with_delivery_buffer(delivery_buffer()),
                );
                $body
            }
            Engine::MariaDb => {
                let $repo = Arc::new(
                    $rig.database()
                        .mariadb_store()
                        .expect("a mariadb rig has a store")
                        .clone()
                        .with_delivery_buffer(delivery_buffer()),
                );
                $body
            }
            Engine::Postgres => {
                let $repo = Arc::new(
                    $rig.database()
                        .postgres()
                        .expect("a postgres rig has a store")
                        .clone()
                        .with_delivery_buffer(delivery_buffer()),
                );
                $body
            }
            _ => panic!("every engine of the suite is handled above"),
        }
    }};
}

/// Run `$body` with `$store` bound to a `Store` of a database engine.
macro_rules! on_store {
    ($rig:expr, |$store:ident| $body:expr) => {{
        match $rig.engine() {
            Engine::Sqlite => {
                let $store = $rig
                    .database()
                    .sqlite_store()
                    .expect("a sqlite rig has a store")
                    .clone();
                $body
            }
            Engine::MariaDb => {
                let $store = $rig
                    .database()
                    .mariadb_store()
                    .expect("a mariadb rig has a store")
                    .clone();
                $body
            }
            Engine::Postgres => {
                let $store = $rig
                    .database()
                    .postgres()
                    .expect("a postgres rig has a store")
                    .clone();
                $body
            }
            _ => panic!("a database engine is required"),
        }
    }};
}

fn at() -> Timestamp {
    static START: std::sync::LazyLock<Timestamp> = std::sync::LazyLock::new(|| {
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap()
    });
    *START
}

fn config() -> ArchiveConfigV1 {
    let mut config = ArchiveConfigV1::default();
    config.format = ArchiveFormat::Warc;
    config
}

fn config_with(dedupe: ArchiveDedupe) -> ArchiveConfigV1 {
    let mut config = config();
    config.dedupe = dedupe;
    config
}

async fn tenant_of(rig: &Rig) -> TenantId {
    let tenant = TenantId::new();
    if rig.engine() != Engine::Memory {
        rig.migrate().await;
        rig.insert_tenant(tenant.0).await.unwrap();
    }
    tenant
}

async fn second_tenant(rig: &Rig) -> TenantId {
    let tenant = TenantId::new();
    if rig.engine() != Engine::Memory {
        rig.insert_tenant(tenant.0).await.unwrap();
    }
    tenant
}

fn pending(tenant: TenantId, run: &crawlx_core::repo::CrawlRun, config: ArchiveConfigV1) -> ArchiveExportV1 {
    ArchiveExportV1::pending(
        tenant,
        run.id,
        config,
        at(),
        Some(at() + chrono::Duration::days(7)),
        TerminalReason::FrontierExhausted,
    )
}

async fn artifacts_of<R>(repo: &Arc<R>, dir: &std::path::Path, clock: Arc<ManualClock>) -> FsArtifactStore
where
    R: RunRepo + ArtifactIndex + 'static,
{
    FsArtifactStore::open(dir, repo.clone(), clock)
        .await
        .unwrap()
        .with_index(repo.clone())
}

async fn source_with(
    runs: &dyn RunRepo,
    tenant: TenantId,
    config: ArchiveConfigV1,
) -> crawlx_core::repo::CrawlRun {
    let mut cfg = create_crawl("https://archive.example.test/data", &[], 1);
    cfg.retention.days = 7;
    cfg.output.archive = Some(config);
    let mut run = crawl_run(tenant, cfg);
    run.created_at = at();
    runs.create(&run, None).await.unwrap();
    run
}

async fn source(runs: &dyn RunRepo, tenant: TenantId) -> crawlx_core::repo::CrawlRun {
    source_with(runs, tenant, config()).await
}

async fn member(
    artifacts: &dyn ArtifactStore,
    run: &crawlx_core::repo::CrawlRun,
    ordinal: u64,
) -> (ArchiveRecordV1, ArtifactRef) {
    let id = format!("<urn:uuid:{}>", uuid::Uuid::now_v7());
    let header = warc::RecordHeader {
        fields: BTreeMap::from([
            ("WARC-Type".into(), "resource".into()),
            ("WARC-Record-ID".into(), id),
            ("WARC-Date".into(), warc::date(at())),
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
    let shard = artifacts
        .put(
            run.id,
            Sensitivity::Content,
            "application/warc",
            encoded.get_ref(),
        )
        .await
        .unwrap();
    let index = cdxj::Entry::from_record(&summary, "data.warc.gz")
        .unwrap()
        .line(&summary)
        .unwrap();
    let index = artifacts
        .put(run.id, Sensitivity::Content, "application/cdxj", index.as_bytes())
        .await
        .unwrap();
    let facts = ArchiveCaptureFactsV1::retained(
        format!("event:{ordinal}"),
        at(),
        ArchiveRepresentation::ProtocolResource,
        "retained_native_decoded_response_body",
    );
    (
        ArchiveRecordV1::resource(
            run.id.0,
            ordinal,
            summary.id,
            shard,
            summary.offset,
            summary.length,
            summary.payload_digest,
            "https://archive.example.test/data".into(),
            facts,
            "text/plain".into(),
        ),
        index,
    )
}

/// One export with a single committed record, optionally with validator history, an
/// approved payload key and publication.
struct Staged {
    export: ArchiveExportV1,
    fence: i64,
    record: ArchiveRecordV1,
    index: ArtifactRef,
    history: Option<ArchiveHistoryV1>,
    key: ArchiveHistoryKeyV1,
    now: Timestamp,
}

async fn stage<R: RunRepo + ArchiveRepo>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    config: ArchiveConfigV1,
    etag: Option<&str>,
    approved_payload: bool,
    publish: bool,
) -> Staged {
    let run = source_with(repo, tenant, config.clone()).await;
    let export = pending(tenant, &run, config);
    repo.begin(&export).await.unwrap();
    let claim = repo.claim(tenant, export.id, at()).await.unwrap().unwrap();
    let (mut record, index) = member(artifacts, &run, 1).await;
    if approved_payload {
        record.facts.body_state = "complete".into();
        record.payload_key = Some(ArchivePayloadKeyV1::new(
            "anonymous".into(),
            crawlx_core::hash::Digest::of("crawlx/test/variant", b"v1"),
            &record.facts,
            record.mime.clone(),
        ));
    }
    let key = ArchiveHistoryKeyV1::new(
        record.target.clone(),
        "GET".into(),
        "anonymous".into(),
        "variant-v1".into(),
        "redaction-v1".into(),
    );
    let history = ArchiveHistoryV1::new(
        key.clone(),
        ArchiveDependencyV1::new(record.export, 1),
        etag.map(|etag| format!("\"{etag}\"")),
        None,
        at(),
    );
    repo.commit_record(tenant, claim.fence, &record, Some(&history), at())
        .await
        .unwrap();
    if publish {
        let mut manifest = ArchiveManifestV1::available(tenant, run.id, at());
        manifest.records = 1;
        repo.publish(
            tenant,
            export.id,
            claim.fence,
            &record.artifact,
            Some(&index),
            &manifest,
            at(),
        )
        .await
        .unwrap();
    }
    Staged {
        export,
        fence: claim.fence,
        record,
        index,
        history: Some(history),
        key,
        now: at(),
    }
}

async fn exercise(
    runs: &dyn RunRepo,
    repo: &dyn ArchiveRepo,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
) -> Vec<ArtifactRef> {
    let first = source(runs, tenant).await;
    let pending = pending(tenant, &first, config());
    repo.begin(&pending).await.unwrap();
    let first_claim = repo.claim(tenant, pending.id, at()).await.unwrap().unwrap();
    let (record, index) = member(artifacts, &first, 1).await;
    let mut missing = record.clone();
    missing.artifact.id = crawlx_core::ArtifactId::new();
    assert!(repo
        .commit_record(tenant, first_claim.fence, &missing, None, at())
        .await
        .is_err());
    // Object committed, writer died before the catalog row. Recovery owns a newer fence.
    let recovery_time = at() + chrono::Duration::seconds(121);
    let recovered = repo
        .claim(tenant, pending.id, recovery_time)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        repo.commit_record(tenant, first_claim.fence, &record, None, recovery_time)
            .await,
        Err(StoreError::LeaseLost)
    ));
    let key = ArchiveHistoryKeyV1::new(
        record.target.clone(),
        "GET".into(),
        "anonymous".into(),
        "variant-v1".into(),
        "redaction-v1".into(),
    );
    let history = ArchiveHistoryV1::new(
        key.clone(),
        ArchiveDependencyV1::new(record.export, 1),
        Some("\"baseline-v1\"".into()),
        None,
        at(),
    );
    repo.commit_record(tenant, recovered.fence, &record, Some(&history), recovery_time)
        .await
        .unwrap();
    // A lost acknowledgement permits only the same immutable descriptor and history.
    // Matching ID/digest/length alone must not conceal changed custody or dependencies.
    let mut changed = record.clone();
    changed.artifact.id = crawlx_core::ArtifactId::new();
    let mut shifted = record.clone();
    shifted.offset = shifted.offset.saturating_add(1);
    let mut relinked = record.clone();
    relinked.dependency = Some(ArchiveDependencyV1::new(uuid::Uuid::nil(), 0));
    let mut relabeled = record.clone();
    relabeled.facts.body_state = "different".into();
    for conflict in [&changed, &shifted, &relinked, &relabeled] {
        assert!(matches!(
            repo.commit_record(tenant, recovered.fence, conflict, Some(&history), recovery_time)
                .await,
            Err(StoreError::Conflict(_))
        ));
    }
    let mut changed_history = history.clone();
    changed_history.etag = Some("\"different-validator\"".into());
    for conflict in [None, Some(&changed_history)] {
        assert!(matches!(
            repo.commit_record(tenant, recovered.fence, &record, conflict, recovery_time)
                .await,
            Err(StoreError::Conflict(_))
        ));
    }
    assert!(
        repo.history(tenant, &key, recovery_time).await.unwrap().is_none(),
        "unpublished baseline must not escape"
    );
    // Record row committed, writer died before publishing the final manifest.
    let publish_time = recovery_time + chrono::Duration::seconds(121);
    let publisher = repo
        .claim(tenant, pending.id, publish_time)
        .await
        .unwrap()
        .unwrap();
    repo.commit_record(tenant, publisher.fence, &record, Some(&history), publish_time)
        .await
        .unwrap();
    assert_eq!(
        repo.records(tenant, pending.id, None, 64, publish_time)
            .await
            .unwrap()
            .len(),
        1
    );
    let mut manifest = ArchiveManifestV1::available(tenant, first.id, at());
    manifest.records = 1;
    let mut forged = manifest.clone();
    forged.complete = true;
    assert!(repo
        .publish(
            tenant,
            pending.id,
            publisher.fence,
            &record.artifact,
            Some(&index),
            &forged,
            publish_time
        )
        .await
        .is_err());
    repo.publish(
        tenant,
        pending.id,
        publisher.fence,
        &record.artifact,
        Some(&index),
        &manifest,
        publish_time,
    )
    .await
    .unwrap();
    let Some(found) = repo.history(tenant, &key, publish_time).await.unwrap() else {
        panic!("published baseline missing");
    };
    assert_eq!(found.source, history.source);
    let mut other_principal = key.clone();
    other_principal.principal = "admin".into();
    let mut other_variant = key.clone();
    other_variant.variant = "other-vary-context".into();
    assert!(repo
        .history(tenant, &other_principal, publish_time)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .history(tenant, &other_variant, publish_time)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        repo.get(TenantId::new(), pending.id, publish_time).await.unwrap(),
        ArchiveReadV1::Missing
    ));
    let second = source(runs, tenant).await;
    let second_pending = self::pending(tenant, &second, config());
    repo.begin(&second_pending).await.unwrap();
    let second_claim = repo
        .claim(tenant, second_pending.id, publish_time)
        .await
        .unwrap()
        .unwrap();
    let (mut dependent, second_index) = member(artifacts, &second, 2).await;
    dependent.dependency = Some(history.source.clone());
    let dependent_history = ArchiveHistoryV1::new(
        key.clone(),
        ArchiveDependencyV1::new(dependent.export, 2),
        history.etag.clone(),
        None,
        at(),
    );
    repo.commit_record(
        tenant,
        second_claim.fence,
        &dependent,
        Some(&dependent_history),
        publish_time,
    )
    .await
    .unwrap();
    let mut second_manifest = ArchiveManifestV1::available(tenant, second.id, at());
    second_manifest.records = 1;
    repo.publish(
        tenant,
        second_pending.id,
        second_claim.fence,
        &dependent.artifact,
        Some(&second_index),
        &second_manifest,
        publish_time,
    )
    .await
    .unwrap();
    repo.erase(tenant, pending.id).await.unwrap();
    assert!(matches!(
        repo.get(tenant, second_pending.id, publish_time).await.unwrap(),
        ArchiveReadV1::Missing
    ));
    assert!(!repo
        .artifact_visible(tenant, &dependent.artifact, publish_time)
        .await
        .unwrap());
    assert!(repo.history(tenant, &key, publish_time).await.unwrap().is_none());
    assert!(!repo.erased_artifacts(tenant, 64).await.unwrap().is_empty());
    vec![record.artifact, index, dependent.artifact, second_index]
}

async fn catalog_tracks_actual_artifacts_fences_and_dependency_erasure(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| catalog_contract(repo, tenant).await);
}

async fn catalog_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock).await;
    let erased = exercise(repo.as_ref(), repo.as_ref(), &artifacts, tenant).await;
    assert_eq!(erased.len(), 4);
}

async fn erased_artifacts_drain_through_acknowledge(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| drain_contract(repo, tenant).await);
}

async fn drain_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock).await;
    let staged = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config(),
        Some("v1"),
        false,
        true,
    )
    .await;
    assert!(repo.erased_artifacts(tenant, 64).await.unwrap().is_empty());
    assert!(repo
        .artifact_visible(tenant, &staged.record.artifact, staged.now)
        .await
        .unwrap());
    assert!(repo
        .artifact_visible(tenant, &staged.index, staged.now)
        .await
        .unwrap());
    assert!(matches!(
        repo.erased_artifacts(tenant, 0).await,
        Err(StoreError::Conflict(_))
    ));
    repo.erase(tenant, staged.export.id).await.unwrap();
    assert!(!repo
        .artifact_visible(tenant, &staged.record.artifact, staged.now)
        .await
        .unwrap());
    let erased = repo.erased_artifacts(tenant, 64).await.unwrap();
    assert!(erased.contains(&staged.record.artifact));
    assert!(erased.contains(&staged.index));
    // Acknowledging an erased object retires its reference; the rest stay listed.
    repo.acknowledge_erased(tenant, &staged.index).await.unwrap();
    let remaining = repo.erased_artifacts(tenant, 64).await.unwrap();
    assert!(!remaining.contains(&staged.index));
    assert!(remaining.contains(&staged.record.artifact));
    repo.acknowledge_erased(tenant, &staged.record.artifact)
        .await
        .unwrap();
    assert!(repo.erased_artifacts(tenant, 64).await.unwrap().is_empty());
    assert!(repo
        .records(tenant, staged.export.id, None, 64, staged.now)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        ArchiveRepo::get(repo.as_ref(), tenant, staged.export.id, staged.now)
            .await
            .unwrap(),
        ArchiveReadV1::Missing
    ));
}

async fn history_lookup_needs_a_published_export_and_validators(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| history_contract(repo, tenant).await);
}

async fn history_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock).await;
    // recorded but unpublished: not eligible
    let recording = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config(),
        Some("v1"),
        false,
        false,
    )
    .await;
    assert!(repo
        .history(tenant, &recording.key, recording.now)
        .await
        .unwrap()
        .is_none());
    // published without any validator: not eligible
    let bare = stage(repo.as_ref(), &artifacts, tenant, config(), None, false, true).await;
    assert!(repo.history(tenant, &bare.key, bare.now).await.unwrap().is_none());
    // published with a validator: found, and only under its exact key
    let published = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config(),
        Some("v2"),
        false,
        true,
    )
    .await;
    let found = repo
        .history(tenant, &published.key, published.now)
        .await
        .unwrap()
        .expect("the published baseline is eligible");
    assert_eq!(Some(&found), published.history.as_ref());
    let mut other = published.key.clone();
    other.method = "HEAD".into();
    assert!(repo
        .history(tenant, &other, published.now)
        .await
        .unwrap()
        .is_none());
    // an expired export is not eligible
    let expired = published.now + chrono::Duration::days(8);
    assert!(repo
        .history(tenant, &published.key, expired)
        .await
        .unwrap()
        .is_none());
    // erasing the export removes its history
    repo.erase(tenant, published.export.id).await.unwrap();
    assert!(repo
        .history(tenant, &published.key, published.now)
        .await
        .unwrap()
        .is_none());
}

async fn payload_source_returns_the_standalone_approved_record(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| payload_contract(repo, tenant).await);
}

async fn payload_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock).await;
    let staged = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config_with(ArchiveDedupe::Collection),
        Some("v1"),
        true,
        false,
    )
    .await;
    let key = staged.record.payload_key.clone().unwrap();
    let digest = staged.record.payload_digest.clone();
    let found = repo
        .payload_source(tenant, staged.export.id, &key, &digest, staged.now)
        .await
        .unwrap()
        .expect("the committed standalone record is a reuse source");
    assert_eq!(found, staged.record);
    // another digest, or another variant, finds nothing
    let other_digest = format!("sha256:{}", "0".repeat(64));
    assert!(repo
        .payload_source(tenant, staged.export.id, &key, &other_digest, staged.now)
        .await
        .unwrap()
        .is_none());
    let mut other_key = key.clone();
    other_key.variant = crawlx_core::hash::Digest::of("crawlx/test/variant", b"v2");
    assert!(repo
        .payload_source(tenant, staged.export.id, &other_key, &digest, staged.now)
        .await
        .unwrap()
        .is_none());
    // an export that opted out of deduplication offers no source
    let none = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config_with(ArchiveDedupe::None),
        Some("v1"),
        true,
        false,
    )
    .await;
    let none_key = none.record.payload_key.clone().unwrap();
    assert!(repo
        .payload_source(
            tenant,
            none.export.id,
            &none_key,
            &none.record.payload_digest,
            none.now
        )
        .await
        .unwrap()
        .is_none());
    // another tenant's export id is unknown to it
    assert!(repo
        .payload_source(TenantId::new(), staged.export.id, &key, &digest, staged.now)
        .await
        .unwrap()
        .is_none());
}

async fn recoverable_lists_unfinished_exports_of_active_runs(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| recoverable_contract(repo, tenant).await);
}

async fn recoverable_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock).await;
    let run = source(repo.as_ref(), tenant).await;
    let export = pending(tenant, &run, config());
    repo.begin(&export).await.unwrap();
    let soon = at() + chrono::Duration::seconds(1);
    let listed = repo.recoverable(soon, 64).await.unwrap();
    assert_eq!(
        listed.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![export.id]
    );
    assert!(repo.recoverable(soon, 0).await.is_err());
    assert!(repo.recoverable(soon, 65).await.is_err());
    // a writer holding the lease is not recoverable until the lease lapses
    repo.claim(tenant, export.id, soon).await.unwrap().unwrap();
    assert!(repo
        .recoverable(soon + chrono::Duration::seconds(1), 64)
        .await
        .unwrap()
        .is_empty());
    let lapsed = soon + chrono::Duration::seconds(121);
    assert_eq!(repo.recoverable(lapsed, 64).await.unwrap().len(), 1);
    // an export past its expiry is not recoverable
    let expired = at() + chrono::Duration::days(8);
    assert!(repo.recoverable(expired, 64).await.unwrap().is_empty());
    // a published export stays recoverable while the run is active, lease or not
    let staged = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config(),
        Some("v1"),
        false,
        true,
    )
    .await;
    let listed: Vec<_> = repo
        .recoverable(staged.now, 64)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert!(listed.contains(&staged.export.id));
    // worker authority only: a tenant scope is refused
    assert!(matches!(
        crawlx_storage::tenant::scope(tenant, repo.recoverable(staged.now, 64)).await,
        Err(StoreError::AccessDenied(_))
    ));
}

async fn exports_of_two_tenants_are_isolated(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    let other = second_tenant(rig).await;
    on_arc!(rig, |repo| isolation_contract(repo, tenant, other).await);
}

async fn isolation_contract<R>(repo: Arc<R>, tenant: TenantId, other: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock).await;
    let staged = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config_with(ArchiveDedupe::Collection),
        Some("v1"),
        true,
        true,
    )
    .await;
    let run = crawlx_core::CrawlRunId(staged.export.run.0);
    assert!(matches!(
        ArchiveRepo::get(repo.as_ref(), other, staged.export.id, staged.now)
            .await
            .unwrap(),
        ArchiveReadV1::Missing
    ));
    assert!(repo.list(other, run, staged.now).await.unwrap().is_empty());
    assert!(repo
        .records(other, staged.export.id, None, 64, staged.now)
        .await
        .unwrap()
        .is_empty());
    assert!(repo
        .history(other, &staged.key, staged.now)
        .await
        .unwrap()
        .is_none());
    assert!(!repo
        .artifact_visible(other, &staged.record.artifact, staged.now)
        .await
        .unwrap());
    assert!(repo.erased_artifacts(other, 64).await.unwrap().is_empty());
    let claim = repo.claim(other, staged.export.id, staged.now).await;
    assert!(
        matches!(claim, Ok(None) | Err(StoreError::NotFound { .. })),
        "{claim:?}"
    );
    assert!(repo
        .commit_record(other, staged.fence, &staged.record, None, staged.now)
        .await
        .is_err());
    // the other tenant cannot open an export on this tenant's run
    let foreign = ArchiveExportV1::pending(
        other,
        run,
        config_with(ArchiveDedupe::Collection),
        at(),
        Some(at() + chrono::Duration::days(7)),
        TerminalReason::FrontierExhausted,
    );
    assert!(repo.begin(&foreign).await.is_err());
    // and its erase touches nothing of this one
    repo.erase(other, staged.export.id).await.unwrap();
    assert!(matches!(
        ArchiveRepo::get(repo.as_ref(), tenant, staged.export.id, staged.now)
            .await
            .unwrap(),
        ArchiveReadV1::Available(_)
    ));
    assert!(repo
        .artifact_visible(tenant, &staged.record.artifact, staged.now)
        .await
        .unwrap());
    assert_eq!(repo.list(tenant, run, staged.now).await.unwrap().len(), 1);
}

async fn expiry_and_zdr_are_typed_without_returning_content_metadata(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| expiry_contract(repo, tenant).await);
}

async fn expiry_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + 'static,
{
    let mut config = create_crawl("https://archive.example.test/", &[], 1);
    config.retention.days = 1;
    config.output.archive = Some(self::config());
    let mut run = crawl_run(tenant, config.clone());
    run.created_at = at();
    RunRepo::create(repo.as_ref(), &run, None).await.unwrap();
    let expiry = at() + chrono::Duration::days(1);
    let pending = ArchiveExportV1::pending(
        tenant,
        run.id,
        self::config(),
        at(),
        Some(expiry),
        TerminalReason::FrontierExhausted,
    );
    repo.begin(&pending).await.unwrap();
    assert!(matches!(
        ArchiveRepo::get(repo.as_ref(), tenant, pending.id, expiry)
            .await
            .unwrap(),
        ArchiveReadV1::Expired
    ));
    config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    config.retention.days = 0;
    let mut zdr = crawl_run(tenant, config);
    zdr.created_at = at();
    RunRepo::create(repo.as_ref(), &zdr, None).await.unwrap();
    let forbidden = ArchiveExportV1::pending(
        tenant,
        zdr.id,
        self::config(),
        at(),
        Some(expiry),
        TerminalReason::FrontierExhausted,
    );
    assert!(matches!(
        repo.begin(&forbidden).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(repo.list(tenant, zdr.id, at()).await.unwrap().is_empty());
}

async fn sensitive_archive_capability_rejects_changed_authority_and_expiry(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| capability_contract(repo, tenant).await);
}

async fn capability_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    use futures::TryStreamExt as _;
    let now = at();
    let clock = Arc::new(ManualClock::new(now));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock.clone()).await;
    let mut cfg = create_crawl("https://archive.example.test/data", &[], 1);
    cfg.retention.days = 7;
    cfg.output.archive = Some(config());
    let mut run = crawl_run(tenant, cfg);
    run.created_at = now;
    RunRepo::create(repo.as_ref(), &run, None).await.unwrap();
    let deadline = now + chrono::Duration::minutes(10);
    let body = vec![b'x'; 65_536];
    let source = artifacts
        .put_until(run.id, Sensitivity::Sensitive, "text/plain", &body, deadline)
        .await
        .unwrap();
    let custody = artifacts
        .archive_custody(tenant, run.id, &source, 65_536)
        .await
        .unwrap();
    assert_eq!(custody, ArchiveCustodyV1::sensitive(deadline));
    assert!(artifacts
        .read_archive_content(tenant, run.id, &source, 65_536)
        .await
        .is_err());
    assert!(artifacts
        .archive_custody(TenantId::new(), run.id, &source, 65_536)
        .await
        .is_err());
    assert!(artifacts
        .archive_custody(tenant, run.id, &source, 65_535)
        .await
        .is_err());
    assert!(artifacts
        .read_archive_sensitive(
            tenant,
            run.id,
            &source,
            &ArchiveCustodyV1::sensitive(deadline + chrono::Duration::seconds(1)),
            65_536,
        )
        .await
        .is_err());
    let spool = dir.path().join("copy.warc.gz");
    assert!(artifacts
        .copy_archive_with_custody(
            tenant,
            run.id,
            &source,
            &ArchiveCustodyV1::content(Some(deadline)),
            &spool,
            65_536,
        )
        .await
        .is_err());
    assert!(!spool.exists());
    artifacts
        .copy_archive_with_custody(tenant, run.id, &source, &custody, &spool, 65_536)
        .await
        .unwrap();
    let shard = artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &spool, 65_536, &custody)
        .await
        .unwrap();
    let row = artifacts.row(shard.id).await.unwrap().unwrap();
    assert_eq!(row.sensitivity, Sensitivity::Sensitive);
    assert_eq!(row.expires_at, Some(deadline));
    let unbounded: ArchiveCustodyV1 = serde_json::from_value(serde_json::json!({
        "sensitivity":"sensitive", "expiresAt":null,
    }))
    .unwrap();
    assert!(artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &spool, 65_536, &unbounded)
        .await
        .is_err());
    let mut stream = artifacts
        .stream_archive_with_custody(&shard, 65_536, &custody)
        .await
        .unwrap();
    clock.advance_ms(600_001);
    assert!(stream.try_next().await.is_err());
    assert!(artifacts
        .read_archive_sensitive(tenant, run.id, &source, &custody, 65_536)
        .await
        .is_err());
    assert!(artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &spool, 65_536, &custody)
        .await
        .is_err());
}

async fn sensitive_source_shortening_or_revocation_fails_closed(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| shortening_contract(rig, repo, tenant).await);
}

async fn shortening_contract<R>(rig: &Rig, repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    let raw = Raw(rig);
    for change in ["shorten", "revoke", "class", "digest"] {
        let clock = Arc::new(ManualClock::new(at()));
        let dir = tempfile::tempdir().unwrap();
        let artifacts = artifacts_of(&repo, dir.path(), clock.clone()).await;
        let run = source(repo.as_ref(), tenant).await;
        let pending = pending(tenant, &run, config());
        repo.begin(&pending).await.unwrap();
        let claim = repo
            .claim(tenant, pending.id, clock.now())
            .await
            .unwrap()
            .unwrap();
        let deadline = at() + chrono::Duration::minutes(10);
        let source = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "text/plain",
                b"owned retained body",
                deadline,
            )
            .await
            .unwrap();
        let custody = artifacts
            .archive_custody(tenant, run.id, &source, 1024)
            .await
            .unwrap();
        artifacts
            .read_archive_sensitive(tenant, run.id, &source, &custody, 1024)
            .await
            .unwrap();
        repo.narrow_custody(tenant, pending.id, claim.fence, &custody, clock.now())
            .await
            .unwrap();
        let (mut record, ordinary_index) = member(&artifacts, &run, 1).await;
        let shard_bytes = artifacts.get(&record.artifact).await.unwrap();
        record.artifact = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/warc",
                &shard_bytes,
                deadline,
            )
            .await
            .unwrap();
        let index_bytes = artifacts.get(&ordinary_index).await.unwrap();
        let index = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/cdxj",
                &index_bytes,
                deadline,
            )
            .await
            .unwrap();
        record.custody = custody;
        record.source_artifact = Some(source.clone());
        repo.commit_record(tenant, claim.fence, &record, None, clock.now())
            .await
            .unwrap();
        if change == "revoke" {
            repo.mark_deleted(&[source.id]).await.unwrap();
        } else {
            let mut row = artifacts.row(source.id).await.unwrap().unwrap();
            if rig.engine() == Engine::Memory {
                // the in-memory index replaces a row recorded again
                match change {
                    "shorten" => row.expires_at = Some(deadline - chrono::Duration::seconds(1)),
                    "class" => row.sensitivity = Sensitivity::Content,
                    "digest" => row.digest = crawlx_core::hash::Digest::of("crawlx/test/source", b"changed"),
                    _ => unreachable!(),
                }
                repo.record(&row).await.unwrap();
            } else {
                // a database row is changed in place
                let id = V::Uuid(source.id.0);
                let changed = match change {
                    "shorten" => {
                        raw.exec(
                            "UPDATE artifacts SET expires_at=$1 WHERE artifact_id=$2",
                            &[V::Ts(deadline - chrono::Duration::seconds(1)), id],
                        )
                        .await
                    }
                    "class" => {
                        raw.exec(
                            "UPDATE artifacts SET sensitivity=$1::text::sensitivity_class WHERE artifact_id=$2",
                            &[V::Text("content"), id],
                        )
                        .await
                    }
                    "digest" => {
                        let digest = crawlx_core::hash::Digest::of("crawlx/test/source", b"changed");
                        raw.exec(
                            "UPDATE artifacts SET content_digest=$1 WHERE artifact_id=$2",
                            &[V::Bytes(&digest.0), id],
                        )
                        .await
                    }
                    _ => unreachable!(),
                };
                assert_eq!(changed, 1);
            }
        }
        let mut manifest = ArchiveManifestV1::available(tenant, run.id, at());
        manifest.records = 1;
        manifest.custody = custody;
        assert!(repo
            .publish(
                tenant,
                pending.id,
                claim.fence,
                &record.artifact,
                Some(&index),
                &manifest,
                clock.now(),
            )
            .await
            .is_err());
        assert!(!repo
            .artifact_visible(tenant, &record.artifact, clock.now())
            .await
            .unwrap());
        assert!(repo
            .commit_record(tenant, claim.fence, &record, None, clock.now())
            .await
            .is_err());
    }
}

async fn sweeper_resumes_physical_erasure(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_store!(rig, |store| sweeper_contract(store, tenant).await);
}

async fn sweeper_contract<B: Sql>(store: Store<B>, tenant: TenantId) {
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let repo = Arc::new(store.clone());
    let artifacts = Arc::new(artifacts_of(&repo, dir.path(), clock).await);
    let erased = exercise(&store, &store, artifacts.as_ref(), tenant).await;
    // A failed DELETE may leave tombstones. The ordinary sweeper must resume physical
    // dependency cleanup even before source TTL, without reopening catalog visibility.
    let report = crawlx_storage::retention::RetentionSweeper::new(store.clone())
        .with_artifacts(artifacts.clone())
        .sweep(at())
        .await
        .unwrap();
    assert_eq!(report.artifacts_deleted, 4);
    assert!(store.erased_artifacts(tenant, 64).await.unwrap().is_empty());
    for artifact in erased {
        assert!(artifacts
            .read_content_limited(&artifact, 16 * 1024 * 1024)
            .await
            .is_err());
        assert_eq!(artifacts.erase_artifact(&artifact).await.unwrap(), 0);
    }
}

/// The sweeper erases the objects of a sensitive export whose source authority changed.
async fn sweeper_erases_sensitive_archive_objects_when_source_authority_changes(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_store!(rig, |store| authority_contract(rig, store, tenant).await);
}

async fn authority_contract<B: Sql>(rig: &Rig, pg: Store<B>, tenant: TenantId) {
    let raw = Raw(rig);
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let repo = Arc::new(pg.clone());
    let artifacts = Arc::new(artifacts_of(&repo, dir.path(), clock.clone()).await);
    for revoke in [false, true] {
        let run = source(&pg, tenant).await;
        let pending = pending(tenant, &run, config());
        pg.begin(&pending).await.unwrap();
        let claim = pg.claim(tenant, pending.id, clock.now()).await.unwrap().unwrap();
        let deadline = at() + chrono::Duration::minutes(10) + chrono::Duration::nanoseconds(123_456_789);
        let evidence = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "text/plain",
                b"owned retained body",
                deadline,
            )
            .await
            .unwrap();
        let custody = artifacts
            .archive_custody(tenant, run.id, &evidence, 1024)
            .await
            .unwrap();
        pg.narrow_custody(tenant, pending.id, claim.fence, &custody, clock.now())
            .await
            .unwrap();
        let physical = raw
            .timestamp(
                "SELECT expires_at FROM archive_exports WHERE tenant_id=$1 AND export_id=$2",
                &[V::Uuid(tenant.0), V::Uuid(pending.id)],
            )
            .await;
        let ArchiveReadV1::Available(persisted) = ArchiveRepo::get(&pg, tenant, pending.id, clock.now())
            .await
            .unwrap()
        else {
            panic!("narrowed archive missing");
        };
        assert_eq!(persisted.expires_at, physical);
        assert_eq!(persisted.custody.expires_at, physical);
        assert_eq!(physical, custody.expires_at);
        let physical = physical.unwrap();
        assert!(physical <= deadline);
        assert_eq!(physical.timestamp_subsec_nanos() % 1_000, 0);
        assert_ne!(deadline.timestamp_subsec_nanos() % 1_000, 0);
        let (mut record, ordinary_index) = member(artifacts.as_ref(), &run, 1).await;
        let shard_bytes = artifacts.get(&record.artifact).await.unwrap();
        record.artifact = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/warc",
                &shard_bytes,
                deadline,
            )
            .await
            .unwrap();
        let package = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/warc",
                &shard_bytes,
                deadline,
            )
            .await
            .unwrap();
        let index_bytes = artifacts.get(&ordinary_index).await.unwrap();
        let index = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/cdxj",
                &index_bytes,
                deadline,
            )
            .await
            .unwrap();
        record.custody = custody;
        record.source_artifact = Some(evidence.clone());
        pg.commit_record(tenant, claim.fence, &record, None, clock.now())
            .await
            .unwrap();
        let mut manifest = ArchiveManifestV1::available(tenant, run.id, at());
        manifest.records = 1;
        manifest.custody = custody;
        pg.publish(
            tenant,
            pending.id,
            claim.fence,
            &package,
            Some(&index),
            &manifest,
            clock.now(),
        )
        .await
        .unwrap();
        if revoke {
            pg.mark_deleted(&[evidence.id]).await.unwrap();
        } else {
            let updated = raw
                .exec(
                    "UPDATE artifacts SET expires_at=$1 WHERE artifact_id=$2",
                    &[
                        V::Ts(deadline - chrono::Duration::seconds(1)),
                        V::Uuid(evidence.id.0),
                    ],
                )
                .await;
            assert_eq!(updated, 1);
        }
        assert!(!pg.artifact_visible(tenant, &package, clock.now()).await.unwrap());
        let report = crawlx_storage::retention::RetentionSweeper::new(pg.clone())
            .with_artifacts(artifacts.clone())
            .sweep(clock.now())
            .await
            .unwrap();
        assert!(report.artifacts_deleted >= 3);
        assert!(matches!(
            ArchiveRepo::get(&pg, tenant, pending.id, clock.now())
                .await
                .unwrap(),
            ArchiveReadV1::Missing
        ));
        assert!(pg.erased_artifacts(tenant, 64).await.unwrap().is_empty());
        for artifact in [&record.artifact, &package, &index] {
            assert!(artifacts.row(artifact.id).await.unwrap().is_none());
            assert!(artifacts.get(artifact).await.is_err());
        }
    }
}

/// The recorded-traffic projection keeps chronology and never adopts another tenant's artifact.
async fn traffic_projection_preserves_chronology_and_never_adopts_foreign_artifacts(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    let other_tenant = second_tenant(rig).await;
    on_store!(rig, |store| traffic_contract(rig, store, tenant, other_tenant)
        .await);
}

async fn traffic_contract<B: Sql>(rig: &Rig, pg: Store<B>, tenant: TenantId, other_tenant: TenantId) {
    use crawlx_storage::archive::{recorded, retained};
    let raw = Raw(rig);
    let at = chrono::DateTime::parse_from_rfc3339("2026-11-04T12:34:56.789Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let clock = Arc::new(ManualClock::new(at));
    let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    run.created_at = at;
    pg.create(&run, None).await.unwrap();
    let mut foreign = crawl_run(other_tenant, create_crawl("https://other.test/", &[], 1));
    foreign.created_at = at;
    pg.create(&foreign, None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock)
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let body = store
        .put(
            run.id,
            Sensitivity::Content,
            "application/json",
            b"{\"actual\":true}",
        )
        .await
        .unwrap();
    let foreign_body = store
        .put(foreign.id, Sensitivity::Content, "text/plain", b"foreign-canary")
        .await
        .unwrap();
    let digest = [7u8; 32];
    for (ordinal, artifact) in [(1, body.id), (2, body.id), (3, foreign_body.id)] {
        let inserted = raw
            .exec(
                "INSERT INTO traffic_events (occurred_at,run_id,epoch_id,unattributed_reason,seq,lane,origin,method,url_redacted,url_hash,status,body_artifact_id) \
                 VALUES ($1,$2,NULL,'not_applicable',$3,'diagnostic','fetch_plane','GET','https://example.test/data',$4,200,$5)",
                &[
                    V::Ts(at),
                    V::Uuid(run.id.0),
                    V::I64(ordinal),
                    V::Bytes(&digest),
                    V::Uuid(artifact.0),
                ],
            )
            .await;
        assert_eq!(inserted, 1);
    }
    let events = crawlx_storage::tenant::scope(tenant, recorded::traffic(&pg, tenant, run.id, 3))
        .await
        .unwrap();
    assert_eq!(events.len(), 3);
    assert!(events.windows(2).all(|rows| rows[0].event_id < rows[1].event_id));
    assert_eq!(events[0].response_body, Some(body.clone()));
    assert_eq!(events[1].response_body, Some(body.clone()));
    assert_eq!(events[2].response_body, None);
    let first = recorded::traffic_keyset(&pg, tenant, run.id, 0, 1).await.unwrap();
    assert_eq!(first[0].event_id, events[0].event_id);
    let rest = recorded::traffic_keyset(&pg, tenant, run.id, first[0].event_id.try_into().unwrap(), 2)
        .await
        .unwrap();
    assert_eq!(
        rest.iter().map(|event| event.event_id).collect::<Vec<_>>(),
        events[1..].iter().map(|event| event.event_id).collect::<Vec<_>>()
    );
    assert!(recorded::traffic_keyset(&pg, tenant, run.id, 0, 0).await.is_err());
    assert!(recorded::traffic_keyset(&pg, tenant, run.id, u64::MAX, 1)
        .await
        .is_err());
    assert_eq!(
        retained::read(dir.path(), &body, tenant, run.id, at, Limits::default())
            .unwrap()
            .bytes,
        b"{\"actual\":true}"
    );
    assert!(retained::read(dir.path(), &foreign_body, tenant, run.id, at, Limits::default()).is_err());
    assert!(recorded::traffic(&pg, tenant, run.id, 2).await.is_err());
    assert!(recorded::traffic(&pg, other_tenant, run.id, 3)
        .await
        .unwrap()
        .is_empty());
}

/// `dependents` names exactly the closure `erase` tombstones, and `cancel` abandons only an
/// export that is still recording, on every engine.
async fn dependents_and_cancel_report_the_closure_and_never_touch_committed_exports(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_arc!(rig, |repo| closure_contract(repo, tenant).await);
}

async fn closure_contract<R>(repo: Arc<R>, tenant: TenantId)
where
    R: RunRepo + ArchiveRepo + ArtifactIndex + 'static,
{
    use crawlx_core::archive_catalog::{ArchiveCancelV1, ArchiveExportState};
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = artifacts_of(&repo, dir.path(), clock).await;
    let now = at();
    // A published baseline with a published dependent that revisits it.
    let base = stage(
        repo.as_ref(),
        &artifacts,
        tenant,
        config(),
        Some("v1"),
        false,
        true,
    )
    .await;
    assert!(repo.dependents(tenant, base.export.id).await.unwrap().is_empty());
    let second = source(repo.as_ref(), tenant).await;
    let second_pending = pending(tenant, &second, config());
    repo.begin(&second_pending).await.unwrap();
    let claim = repo.claim(tenant, second_pending.id, now).await.unwrap().unwrap();
    let (mut dependent, second_index) = member(&artifacts, &second, 2).await;
    dependent.dependency = Some(ArchiveDependencyV1::new(base.export.id, 1));
    let history = ArchiveHistoryV1::new(
        base.key.clone(),
        ArchiveDependencyV1::new(dependent.export, 2),
        base.history.as_ref().unwrap().etag.clone(),
        None,
        now,
    );
    repo.commit_record(tenant, claim.fence, &dependent, Some(&history), now)
        .await
        .unwrap();
    let mut manifest = ArchiveManifestV1::available(tenant, second.id, now);
    manifest.records = 1;
    repo.publish(
        tenant,
        second_pending.id,
        claim.fence,
        &dependent.artifact,
        Some(&second_index),
        &manifest,
        now,
    )
    .await
    .unwrap();
    // The reported closure is the dependent, excluding the export itself.
    assert_eq!(
        repo.dependents(tenant, base.export.id).await.unwrap(),
        vec![second_pending.id]
    );
    assert!(repo
        .dependents(tenant, second_pending.id)
        .await
        .unwrap()
        .is_empty());
    // A published export is never cancelled and keeps serving.
    assert_eq!(
        repo.cancel(tenant, base.export.id, now).await.unwrap(),
        ArchiveCancelV1::Refused(ArchiveExportState::Published)
    );
    assert!(matches!(
        ArchiveRepo::get(repo.as_ref(), tenant, base.export.id, now)
            .await
            .unwrap(),
        ArchiveReadV1::Available(_)
    ));
    // An unknown export is Missing, not an error.
    assert_eq!(
        repo.cancel(tenant, uuid::Uuid::now_v7(), now).await.unwrap(),
        ArchiveCancelV1::Missing
    );
    // A recording export with a committed shard is abandoned atomically.
    let recording = stage(repo.as_ref(), &artifacts, tenant, config(), None, false, false).await;
    let before = repo.erased_artifacts(tenant, 64).await.unwrap().len();
    assert_eq!(
        repo.cancel(tenant, recording.export.id, now).await.unwrap(),
        ArchiveCancelV1::Cancelled
    );
    assert!(matches!(
        ArchiveRepo::get(repo.as_ref(), tenant, recording.export.id, now)
            .await
            .unwrap(),
        ArchiveReadV1::Missing
    ));
    assert!(repo.erased_artifacts(tenant, 64).await.unwrap().len() > before);
    // The abandoned writer's fence is dead: it cannot commit again.
    assert!(repo
        .commit_record(tenant, recording.fence, &recording.record, None, now)
        .await
        .is_err());
    assert_eq!(
        repo.cancel(tenant, recording.export.id, now).await.unwrap(),
        ArchiveCancelV1::Missing
    );
    // The cancelled export did not disturb the published pair.
    assert_eq!(
        repo.dependents(tenant, base.export.id).await.unwrap(),
        vec![second_pending.id]
    );
}
