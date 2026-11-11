//! The same run against PostgreSQL (skipped without `CRAWLX_TEST_DATABASE_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{ActionJournal, CheckpointRepo, RunRepo};
use crawlx_core::{CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys;
use crawlx_storage::{FsArtifactStore, Pg, PgConfig};
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

#[tokio::test]
async fn a_dynamic_run_over_postgres_journals_checkpoints_and_transitions() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = format!("t_worker_{}", uuid::Uuid::now_v7().simple());
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(schema),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), TenantId::new());
    stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());

    let script = FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("a", "Alpha", "/alpha"))
                .on_click("a", vec![FakeEffect::Navigate("/alpha".into())]),
        )
        .page(
            FakePage::new("https://example.test/alpha")
                .title("Alpha")
                .node(FakeAxSpec::link("h", "Home", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        );
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 6;
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    );
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend)
            .with_stores(stores),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    let actions = ActionJournal::list(&pg, report.run_id, None).await.unwrap();
    assert!(actions.len() >= 2);
    assert!(actions
        .iter()
        .all(|a| a.status == crawlx_core::counters::ActionStatus::Succeeded));
    // the T2 transaction wrote one transition per succeeded action
    let transitions: i64 = sqlx_count(&pg, "SELECT count(*) FROM transitions").await;
    assert_eq!(usize::try_from(transitions).unwrap(), actions.len());
    // Terminal retention revokes checkpoint reads and erases encrypted recovery
    // content. The durable checkpoint row still proves shutdown wrote T3.
    let shutdown_checkpoints = sqlx_count(
        &pg,
        "SELECT count(*) FROM checkpoints c JOIN artifacts a ON a.artifact_id = c.storage_artifact_id \
         WHERE c.reason = 'shutdown' AND a.deleted_at IS NOT NULL",
    )
    .await;
    assert!(shutdown_checkpoints > 0);
    let sessions = RunRepo::list_sessions(&pg, report.run_id).await.unwrap();
    let cps = CheckpointRepo::list(&pg, sessions[0].id).await.unwrap();
    assert!(
        cps.is_empty(),
        "terminal recovery content remains readable: {cps:?}"
    );
    assert!(sessions[0].browser.is_some());
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn cancellation_before_browser_admission_closes_unleased_sessions_on_postgres() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("t_worker_cancel_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), TenantId::new());
    stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());
    for mode in [CrawlMode::Dynamic, CrawlMode::Hybrid] {
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.mode = mode;
        crawl.runs_per_role = 3;
        let cfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(StaticResolver::new())),
                ..EgressConfig::default()
            },
            gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            ..WorkerConfig::default()
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let report = run_local_with(
            LocalRun::new(crawl, cfg)
                .with_stores(stores.clone())
                .with_backend(Arc::new(
                    FakeBackend::builder()
                        .script(FakeScript::new())
                        .clock(Arc::new(crawlx_core::SystemClock))
                        .build(),
                ))
                .with_cancel(cancel),
        )
        .await
        .unwrap();

        assert_eq!(report.status, RunStatus::Cancelled);
        assert_eq!(report.browser_launches, 0);
        let sessions = RunRepo::list_sessions(&pg, report.run_id).await.unwrap();
        assert_eq!(sessions.len(), 3);
        for session in sessions {
            assert_eq!(session.status, crawlx_core::repo::SessionStatus::Cancelled);
            assert!(session.browser.is_none());
            assert!(CheckpointRepo::list(&pg, session.id).await.unwrap().is_empty());
        }
        assert!(ActionJournal::list(&pg, report.run_id, None)
            .await
            .unwrap()
            .is_empty());
    }
    assert_eq!(
        sqlx_count(
            &pg,
            "SELECT count(*) FROM crawl_sessions WHERE lease_owner IS NOT NULL OR lease_expires_at IS NOT NULL",
        )
        .await,
        0
    );
    pg.drop_schema().await.unwrap();
}

async fn sqlx_count(pg: &Pg, sql: &'static str) -> i64 {
    // the schema's search_path is set on every pooled connection
    sqlx::query_scalar(sql).fetch_one(pg.pool()).await.unwrap()
}
