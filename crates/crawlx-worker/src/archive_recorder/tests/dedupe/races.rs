//! Committed edge races and final-package revocation retain physical erasure closure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::archive_catalog::ArchiveRepo;
use crawlx_storage::testkit::archive_races;
use crawlx_storage::ArtifactIndex;
use std::time::Duration;

const BODY: &[u8] = b"approved dependency race body";

async fn pair(stores: &Stores, clock: Arc<ManualClock>) -> (Box<ArchiveExportV1>, Box<ArchiveExportV1>) {
    let (source, _) = prepared(
        stores,
        &clock,
        ArchiveDedupe::Tenant,
        &["https://race.example.test/source"],
        BODY,
    )
    .await;
    let source = published(stores, &source, clock.clone()).await;
    let (dependent, _) = prepared(
        stores,
        &clock,
        ArchiveDedupe::Tenant,
        &["https://race.example.test/dependent"],
        BODY,
    )
    .await;
    let dependent = published(stores, &dependent, clock).await;
    (source, dependent)
}

async fn revoked(
    stores: &Stores,
    source: &ArchiveExportV1,
    dependent: &ArchiveExportV1,
    now: crawlx_core::Timestamp,
) {
    assert!(matches!(
        stores.archives.get(source.tenant, source.id, now).await.unwrap(),
        ArchiveReadV1::Missing
    ));
    assert!(matches!(
        stores
            .archives
            .get(dependent.tenant, dependent.id, now)
            .await
            .unwrap(),
        ArchiveReadV1::Missing
    ));
    assert!(!stores
        .archives
        .artifact_visible(dependent.tenant, dependent.artifact.as_ref().unwrap(), now)
        .await
        .unwrap());
    let pending = ArchiveExportV1::pending(
        dependent.tenant,
        dependent.run,
        dependent.config.clone(),
        dependent.created_at,
        dependent.expires_at,
        TerminalReason::FrontierExhausted,
    );
    assert!(
        stores.archives.begin(&pending).await.is_err(),
        "erased intent cannot become a busy resumable writer"
    );
    let erased = stores.archives.erased_artifacts(source.tenant, 64).await.unwrap();
    assert!(erased.contains(dependent.artifact.as_ref().unwrap()));
}

#[tokio::test]
async fn memory_package_revocation_tombstones_published_dependents() {
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    ));
    let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
    let mut stores = Stores::over_memory(memory.clone(), root.path()).await.unwrap();
    stores.artifacts = Arc::new(
        FsArtifactStore::open(root.path(), memory.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(memory.clone()),
    );
    let (source, dependent) = pair(&stores, clock.clone()).await;
    ArtifactIndex::mark_deleted(memory.as_ref(), &[source.artifact.as_ref().unwrap().id])
        .await
        .unwrap();
    revoked(&stores, &source, &dependent, clock.now()).await;
}

struct PgFixture {
    pg: Pg,
    stores: Stores,
    artifacts: Arc<FsArtifactStore>,
    clock: Arc<ManualClock>,
    _root: tempfile::TempDir,
}

async fn pg_fixture() -> Option<PgFixture> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let root = tempfile::tempdir().unwrap();
    let now = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let pg = Pg::connect(
        &url,
        PgConfig {
            max_connections: 4,
            schema: Some(format!(
                "archive_dependency_races_{}",
                uuid::Uuid::now_v7().simple()
            )),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "archive-dependency-races")
        .await
        .unwrap();
    let artifacts = Arc::new(
        FsArtifactStore::open(root.path(), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    let stores = Stores::over_pg(pg.clone(), artifacts.clone(), tenant);
    Some(PgFixture {
        pg,
        stores,
        artifacts,
        clock,
        _root: root,
    })
}

#[tokio::test]
async fn postgres_package_class_upgrade_revokes_and_physically_erases_dependents() {
    let Some(fixture) = pg_fixture().await else {
        return;
    };
    let (source, dependent) = pair(&fixture.stores, fixture.clock.clone()).await;
    archive_races::mark_artifact_sensitive(&fixture.pg, source.artifact.as_ref().unwrap().id.0)
        .await
        .unwrap();
    revoked(&fixture.stores, &source, &dependent, fixture.clock.now()).await;
    let references = fixture
        .stores
        .archives
        .erased_artifacts(source.tenant, 64)
        .await
        .unwrap();
    let report = crawlx_storage::retention::RetentionSweeper::new(fixture.pg.clone())
        .with_artifacts(fixture.artifacts.clone())
        .sweep(fixture.clock.now())
        .await
        .unwrap();
    assert_eq!(report.artifacts_deleted, u64::try_from(references.len()).unwrap());
    assert!(fixture
        .stores
        .archives
        .erased_artifacts(source.tenant, 64)
        .await
        .unwrap()
        .is_empty());
    for reference in references {
        assert_eq!(fixture.artifacts.erase_artifact(&reference).await.unwrap(), 0);
    }
    fixture.pg.drop_schema().await.unwrap();
}

async fn waiters(pg: &Pg, tenant: TenantId, expected: i64) {
    tokio::time::timeout(Duration::from_secs(20), async {
        for _ in 0..500 {
            if archive_races::archive_lock_waiters(pg, tenant).await.unwrap() >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("archive operations did not queue at their tenant lock");
    })
    .await
    .unwrap();
}

async fn record_native(
    stores: &Stores,
    run: &CrawlRun,
    export: &ArchiveExportV1,
    page: &PageRecord,
    clock: &ManualClock,
) -> Result<resource::RecordOutcome, WorkerError> {
    let source: crawlx_core::ArtifactRef =
        serde_json::from_value(page.metadata["acquisition"]["wireBody"].clone()).unwrap();
    let request = stores
        .frontier
        .get_request(run.id, page.frontier_id)
        .await
        .unwrap();
    let mut facts = ArchiveCaptureFactsV1::retained(
        format!("page:{}:response_body", page.frontier_id),
        page.fetched_at,
        ArchiveRepresentation::ProtocolResource,
        "retained_native_decoded_response_body",
    );
    facts.body_state = "complete".into();
    facts.transformations = vec![
        "decoded_body_not_original_wire".into(),
        "unchanged_privacy_approved_text".into(),
    ];
    let cancel = CancellationToken::new();
    let mut recorder = resource::Recorder {
        stores,
        run,
        export,
        clock,
        cancel: &cancel,
        committed_bytes: export.bytes,
    };
    recorder
        .record(resource::ResourceInput {
            ordinal: u64::try_from(page.frontier_id).unwrap().checked_mul(8).unwrap(),
            source: Some(&source),
            capture: None,
            target: page.url.url.as_str(),
            mime: "text/plain",
            facts,
            history_source: Some((&request, page)),
        })
        .await
}

enum RaceResult {
    Record(Result<resource::RecordOutcome, WorkerError>),
    Erase(Result<(), crawlx_core::StoreError>),
}

#[tokio::test]
async fn postgres_erase_waiting_for_dependency_commit_refreshes_closure_and_erases_shards() {
    let Some(fixture) = pg_fixture().await else {
        return;
    };
    let (source_run, _) = prepared(
        &fixture.stores,
        &fixture.clock,
        ArchiveDedupe::Tenant,
        &["https://race.example.test/source"],
        BODY,
    )
    .await;
    let source = published(&fixture.stores, &source_run, fixture.clock.clone()).await;
    let (dependent, mut pages) = prepared(
        &fixture.stores,
        &fixture.clock,
        ArchiveDedupe::Tenant,
        &["https://race.example.test/new-dependent"],
        BODY,
    )
    .await;
    let pending = ArchiveExportV1::pending(
        dependent.tenant,
        dependent.id,
        dependent.config.output.archive.as_ref().unwrap().clone(),
        dependent.created_at,
        Some(dependent.created_at + chrono::Duration::days(1)),
        TerminalReason::FrontierExhausted,
    );
    fixture.stores.archives.begin(&pending).await.unwrap();
    let writer = fixture
        .stores
        .archives
        .claim(dependent.tenant, dependent.id.0, fixture.clock.now())
        .await
        .unwrap()
        .unwrap();
    let held = archive_races::HeldArchiveLock::acquire(&fixture.pg, dependent.tenant)
        .await
        .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    let stores = Stores::over_pg(fixture.pg.clone(), fixture.artifacts.clone(), dependent.tenant);
    let run = dependent.clone();
    let clock = fixture.clock.clone();
    let page = pages.pop().unwrap();
    tasks
        .spawn(async move { RaceResult::Record(record_native(&stores, &run, &writer, &page, &clock).await) });
    waiters(&fixture.pg, dependent.tenant, 1).await;
    let pg = fixture.pg.clone();
    let tenant = source.tenant;
    let source_id = source.id;
    tasks.spawn(async move { RaceResult::Erase(ArchiveRepo::erase(&pg, tenant, source_id).await) });
    waiters(&fixture.pg, dependent.tenant, 2).await;
    held.release().await.unwrap();
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(20), tasks.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            RaceResult::Record(result) => {
                assert!(matches!(result.unwrap(), resource::RecordOutcome::Committed))
            }
            RaceResult::Erase(result) => result.unwrap(),
        }
    }
    let edge = archive_races::archive_dependency_source(&fixture.pg, tenant, dependent.id.0)
        .await
        .unwrap();
    assert_eq!(
        edge, source.id,
        "erase must include the edge committed while it waited"
    );
    assert!(matches!(
        fixture
            .stores
            .archives
            .get(tenant, dependent.id.0, fixture.clock.now())
            .await
            .unwrap(),
        ArchiveReadV1::Missing
    ));
    let references = fixture
        .stores
        .archives
        .erased_artifacts(tenant, 64)
        .await
        .unwrap();
    assert_eq!(
        references.len(),
        3,
        "source package and both committed shards remain in physical erase work"
    );
    let report = crawlx_storage::retention::RetentionSweeper::new(fixture.pg.clone())
        .with_artifacts(fixture.artifacts.clone())
        .sweep(fixture.clock.now())
        .await
        .unwrap();
    assert_eq!(report.artifacts_deleted, 3);
    assert!(fixture
        .stores
        .archives
        .erased_artifacts(tenant, 64)
        .await
        .unwrap()
        .is_empty());
    for reference in references {
        assert_eq!(fixture.artifacts.erase_artifact(&reference).await.unwrap(), 0);
    }
    fixture.pg.drop_schema().await.unwrap();
}
