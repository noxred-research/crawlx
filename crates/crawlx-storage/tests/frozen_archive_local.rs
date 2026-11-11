//! Terminal archive sealing in the sealed object store, without external services.
//!
//! Under `CustodyWrites::Required` an archive export of a terminal run can only write sealed
//! ciphertext, and only inside the scope of a frozen grant bound to that exact export fence.
//! There is no plaintext terminal archive path and no registration or empty snapshot.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::archive::ArchiveConfigV1;
use crawlx_core::archive_catalog::{ArchiveCustodyV1, ArchiveExportV1};
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::custody::{current_frozen_archive, with_producer, CustodyLease, FrozenArchiveSource};
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::{ArtifactRef, CrawlRunId, SessionId, StoreError, TenantId, WorkerId};
use crawlx_storage::artifact_custody::{ArtifactCustody, CustodyWrites, LocalArtifactCustody};
use crawlx_storage::artifact_key_crypto::MemoryArtifactKeys;
use crawlx_storage::artifacts::{ArtifactBlobs, FsBlobs, MemBlobs, ObjectArtifactStore};
use crawlx_storage::custody::frozen_archive::with_terminal_grant;
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::MemoryStore;
use std::sync::Arc;

const BODY: &[u8] = b"<html>retained source page</html>";
const WARC: &[u8] = b"WARC/1.0 packaged terminal archive";

struct World {
    runs: Arc<MemoryStore>,
    clock: ManualClock,
    tenant: TenantId,
    run: CrawlRunId,
    custody: Arc<LocalArtifactCustody>,
    session: CustodyLease,
    store: ObjectArtifactStore<FsBlobs>,
    source: ArtifactRef,
    export: ArchiveExportV1,
    file: tempfile::TempDir,
}

async fn world(sensitivity: Sensitivity, terminal: bool) -> World {
    let clock = ManualClock::new(Utc::now());
    let runs = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
    let tenant = TenantId::new();
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Standard;
    config.retention.days = 7;
    let run = crawl_run(tenant, config);
    runs.create(&run, None).await.unwrap();
    runs.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let custody = Arc::new(LocalArtifactCustody::new());
    let file = tempfile::tempdir().unwrap();
    let blobs = FsBlobs::open(&file.path().join("objects")).await.unwrap();
    let store = ObjectArtifactStore::new(blobs, runs.clone(), Arc::new(clock.clone()))
        .with_index(runs.clone())
        .with_custody(
            custody.clone(),
            Arc::new(MemoryArtifactKeys::new().unwrap()),
            CustodyWrites::Required,
        );
    let session = CustodyLease::new(tenant, run.id, SessionId::new(), WorkerId::new(), 1);
    let source = with_producer(
        session.clone(),
        store.put(run.id, sensitivity, "application/json", BODY),
    )
    .await
    .unwrap();
    if terminal {
        runs.set_status(
            run.id,
            RunStatus::Completed,
            Some(TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    }
    let mut export = ArchiveExportV1::pending(
        tenant,
        run.id,
        ArchiveConfigV1::default(),
        run.created_at,
        None,
        TerminalReason::FrontierExhausted,
    );
    export.fence = 3;
    std::fs::write(file.path().join("export.warc"), WARC).unwrap();
    World {
        runs,
        clock,
        tenant,
        run: run.id,
        custody,
        session,
        store,
        source,
        export,
        file,
    }
}

impl World {
    async fn object_keys(&self) -> Vec<String> {
        self.store
            .blobs()
            .list("")
            .await
            .unwrap()
            .into_iter()
            .filter(|entry| !entry.key.starts_with("_index/"))
            .map(|entry| entry.key)
            .collect()
    }

    fn lease(&self, fence: i64) -> CustodyLease {
        CustodyLease::for_archive_export(self.tenant, self.run, self.export.id, WorkerId::new(), fence)
    }

    async fn proof(&self) -> (ArchiveCustodyV1, Vec<FrozenArchiveSource>) {
        let custody = self
            .store
            .archive_custody(self.tenant, self.run, &self.source, 1 << 20)
            .await
            .unwrap();
        (
            custody,
            vec![FrozenArchiveSource::new(self.source.clone(), custody)],
        )
    }

    /// Write the archive package as the export producer of this world's terminal run.
    async fn package(
        &self,
        fence: i64,
        content_type: &str,
        class: ArchiveCustodyV1,
    ) -> Result<Result<ArtifactRef, StoreError>, StoreError> {
        let (source_custody, sources) = self.proof().await;
        let custody: &dyn ArtifactCustody = self.custody.as_ref();
        let path = self.file.path().join("export.warc");
        with_producer(
            self.lease(fence),
            with_terminal_grant(
                Some(custody),
                true,
                &self.export,
                &source_custody,
                sources,
                self.store
                    .put_archive_file_with_custody(self.run, content_type, &path, 1 << 20, &class),
            ),
        )
        .await
    }
}

async fn encrypted_only(world: &World) -> bool {
    world
        .object_keys()
        .await
        .iter()
        .all(|key| key.starts_with("encrypted/"))
}

#[tokio::test]
async fn terminal_archive_without_a_grant_never_writes_plaintext_or_ciphertext() {
    let w = world(Sensitivity::Content, true).await;
    let objects = w.object_keys().await.len();
    let path = w.file.path().join("export.warc");
    let refused = with_producer(
        w.lease(3),
        w.store.put_archive_file_with_custody(
            w.run,
            "application/warc",
            &path,
            1 << 20,
            &ArchiveCustodyV1::default(),
        ),
    )
    .await;
    assert!(
        matches!(&refused, Err(StoreError::RetentionDenied(detail)) if detail.contains("frozen archive grant")),
        "{refused:?}"
    );
    // Bytes writes of a terminal export are refused as well.
    let refused = with_producer(
        w.lease(3),
        w.store
            .put_kind(w.run, Sensitivity::Content, "evidence", "application/warc", WARC),
    )
    .await;
    assert!(
        matches!(refused, Err(StoreError::RetentionDenied(_))),
        "{refused:?}"
    );
    assert_eq!(w.object_keys().await.len(), objects, "nothing was staged");
    assert!(encrypted_only(&w).await);
}

#[tokio::test]
async fn terminal_archive_is_sealed_under_its_grant_and_reads_back_exactly() {
    let w = world(Sensitivity::Content, true).await;
    let reference = w
        .package(3, "application/warc", ArchiveCustodyV1::default())
        .await
        .unwrap()
        .unwrap();
    assert!(
        encrypted_only(&w).await,
        "terminal archive output exists only as ciphertext"
    );
    assert_eq!(w.store.get(&reference).await.unwrap(), WARC);
    let custody = w.custody.custody(w.tenant, w.run, reference.id).await.unwrap();
    assert!(custody.is_some(), "sealed custody row was published");
    // The output deadline is never beyond the source's: reading as an archive source works
    // under the same retained authority.
    let archive = w
        .store
        .archive_custody(w.tenant, w.run, &reference, 1 << 20)
        .await
        .unwrap();
    assert_eq!(archive.sensitivity, Sensitivity::Content);
    let (source_custody, _) = w.proof().await;
    if let Some(source_deadline) = source_custody.expires_at {
        assert!(archive
            .expires_at
            .is_some_and(|deadline| deadline <= source_deadline));
    }
    // An existing terminal archive stays readable after the clock advances inside retention.
    w.clock.advance_ms(3_600_000);
    assert_eq!(w.store.get(&reference).await.unwrap(), WARC);
}

#[tokio::test]
async fn grant_binds_exact_export_fence_type_and_class() {
    let w = world(Sensitivity::Sensitive, true).await;
    // A producer with another fence cannot use the grant issued for this one.
    let (source_custody, sources) = w.proof().await;
    assert_eq!(source_custody.sensitivity, Sensitivity::Sensitive);
    let custody: &dyn ArtifactCustody = w.custody.as_ref();
    let grant = custody
        .issue_frozen_archive(&w.lease(3), &ArchiveCustodyV1::default(), &sources)
        .await
        .unwrap();
    assert_eq!(
        grant.custody.sensitivity,
        Sensitivity::Sensitive,
        "narrowed by its source"
    );
    assert_eq!(grant.fence, 3);
    let path = w.file.path().join("export.warc");
    let sensitive = ArchiveCustodyV1::sensitive(source_custody.expires_at.unwrap());
    let run_with = |lease: CustodyLease, content_type: &'static str, class: ArchiveCustodyV1| {
        let grant = grant.clone();
        let path = path.clone();
        let store = &w.store;
        let run = w.run;
        async move {
            with_producer(
                lease,
                crawlx_core::custody::with_frozen_archive(
                    grant,
                    store.put_archive_file_with_custody(run, content_type, &path, 1 << 20, &class),
                ),
            )
            .await
        }
    };
    let stale = run_with(w.lease(4), "application/warc", sensitive).await;
    assert!(matches!(stale, Err(StoreError::AccessDenied(_))), "{stale:?}");
    let session = run_with(w.session.clone(), "application/warc", sensitive).await;
    assert!(
        matches!(session, Err(StoreError::RetentionDenied(_))),
        "{session:?}"
    );
    let wrong_type = run_with(w.lease(3), "text/html", sensitive).await;
    assert!(
        matches!(wrong_type, Err(StoreError::RetentionDenied(_))),
        "{wrong_type:?}"
    );
    let downgraded = run_with(w.lease(3), "application/warc", ArchiveCustodyV1::default()).await;
    assert!(
        matches!(downgraded, Err(StoreError::RetentionDenied(_))),
        "{downgraded:?}"
    );
    assert!(encrypted_only(&w).await);
    let before = w.object_keys().await.len();
    let sealed = run_with(w.lease(3), "application/warc", sensitive).await.unwrap();
    assert_eq!(w.object_keys().await.len(), before + 1);
    assert_eq!(w.store.get(&sealed).await.unwrap(), WARC);
    assert_eq!(
        w.store
            .archive_custody(w.tenant, w.run, &sealed, 1 << 20)
            .await
            .unwrap()
            .sensitivity,
        Sensitivity::Sensitive
    );
}

#[tokio::test]
async fn grant_is_scoped_to_its_future_and_not_inherited_by_spawned_work() {
    let w = world(Sensitivity::Content, true).await;
    let (source_custody, sources) = w.proof().await;
    let custody: &dyn ArtifactCustody = w.custody.as_ref();
    let seen = with_terminal_grant(
        Some(custody),
        true,
        &w.export,
        &source_custody,
        sources.clone(),
        async {
            (
                current_frozen_archive().map(|grant| grant.fence),
                tokio::spawn(crawlx_core::custody::inherit(async {
                    current_frozen_archive().is_none()
                }))
                .await
                .unwrap(),
            )
        },
    )
    .await
    .unwrap();
    assert_eq!(seen, (Some(3), true), "not inherited across spawn");
    assert!(current_frozen_archive().is_none(), "scope ended with the future");
    // A live run is not frozen: work runs unchanged, no grant, no custody required.
    let live = with_terminal_grant(None, false, &w.export, &source_custody, sources.clone(), async {
        current_frozen_archive().is_none()
    })
    .await
    .unwrap();
    assert!(live);
    // A terminal run without any custody fails closed.
    let absent = with_terminal_grant(None, true, &w.export, &source_custody, sources, async {}).await;
    assert!(matches!(absent, Err(StoreError::Unavailable(_))), "{absent:?}");
}

#[tokio::test]
async fn terminal_archive_refuses_any_plaintext_fallback_and_missing_source_proofs() {
    let w = world(Sensitivity::Content, true).await;
    // A store whose custody does not seal writes still never writes a terminal archive in plaintext.
    let plain = ObjectArtifactStore::new(MemBlobs::default(), w.runs.clone(), Arc::new(w.clock.clone()))
        .with_index(w.runs.clone())
        .with_custody(
            w.custody.clone(),
            Arc::new(MemoryArtifactKeys::new().unwrap()),
            CustodyWrites::ReadOnly,
        );
    let path = w.file.path().join("export.warc");
    let refused = with_producer(
        w.lease(3),
        plain.put_archive_file_with_custody(
            w.run,
            "application/warc",
            &path,
            1 << 20,
            &ArchiveCustodyV1::default(),
        ),
    )
    .await;
    assert!(
        matches!(refused, Err(StoreError::RetentionDenied(_))),
        "{refused:?}"
    );
    assert!(plain.blobs().object_keys().is_empty());
    // Operator inputs without any producer keep their existing behavior.
    let operator = plain
        .put(w.run, Sensitivity::Content, "text/html", b"<p>operator</p>")
        .await
        .unwrap();
    assert_eq!(plain.get(&operator).await.unwrap(), b"<p>operator</p>");

    // No source proofs, a source from another run, and a custody weaker than its source: no grant.
    let (source_custody, _) = w.proof().await;
    let custody: &dyn ArtifactCustody = w.custody.as_ref();
    let none = custody
        .issue_frozen_archive(&w.lease(3), &source_custody, &[])
        .await;
    assert!(none.is_err(), "an empty source list proves nothing");
    let session = custody
        .issue_frozen_archive(
            &w.session,
            &source_custody,
            &[FrozenArchiveSource::new(w.source.clone(), source_custody)],
        )
        .await;
    assert!(matches!(session, Err(StoreError::AccessDenied(_))), "{session:?}");
}
