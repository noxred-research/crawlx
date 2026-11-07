//! PostgreSQL fault-injection acceptance for the soak auditor.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg_blackholed_journal_read_preserves_observed_trail_violation() {
    let Ok(database_url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let schema = format!("soak_audit_{}", uuid::Uuid::now_v7().simple());
    let pg = Pg::connect(
        &database_url,
        PgConfig {
            schema: Some(schema.clone()),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let record = loopback_record("https://gym.test").unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), record.tenant);
    stores.checkpoint_keys =
        Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    let mut worker = worker_config(&FixtureManifest::embedded("g01").unwrap(), dir.path()).unwrap();
    // This authored FakeBackend workload is not signed G1 or durable key custody.
    worker.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus { g1: true, g3: false });
    let rig = Rig {
        cfg: SoakConfig {
            backend: SoakBackend::Fake,
            fixtures: vec!["g01".into()],
            interactions: 8,
            cycle_seconds: 20,
            ..SoakConfig::default()
        },
        worker_config: worker,
        gym: None,
        base_url: "https://gym.test".into(),
        store: Store::Pg(Box::new(PgStore {
            pg: pg.clone(),
            stores,
            record,
        })),
        scratch: dir.path().to_path_buf(),
        started: Instant::now(),
        progress: Progress {
            cycles: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        },
        cycles: parking_lot::Mutex::new(Vec::new()),
    };
    let (report, mut stores) = rig
        .crawl(
            "g01",
            1,
            0,
            0,
            &dir.path().join("cycle"),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    let victim = ActionJournal::list(&pg, report.run_id, Some(ActionStatus::Succeeded))
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("the worker must execute an action");
    sqlx::query("CREATE TABLE audit_transition_backup AS SELECT * FROM transitions WHERE action_id = $1")
        .bind(victim.id.0)
        .execute(pg.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM transitions WHERE action_id = $1")
        .bind(victim.id.0)
        .execute(pg.pool())
        .await
        .unwrap();

    // Trail inspection keeps its direct pool. Only the subsequent journal
    // read uses the one-connection pool occupied by an actual blackholed query.
    let proxy = Proxy::start(netfault::upstream_of(&database_url).await.unwrap())
        .await
        .unwrap();
    let fault_pg = Pg::connect_existing(
        &netfault::rewrite_url(&database_url, proxy.addr()).unwrap(),
        PgConfig {
            schema: Some(schema),
            max_connections: 1,
            acquire_timeout: Duration::from_millis(100),
            test_before_acquire: false,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    let mut connection = fault_pg.pool().acquire().await.unwrap();
    proxy.set_blackhole(true);
    let mut blocked = tokio::spawn(async move { sqlx::query("SELECT 1").execute(&mut *connection).await });
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut blocked)
        .await
        .is_err());
    stores.journal = Arc::new(fault_pg.clone());
    let mut cycle = Cycle {
        index: 0,
        worker: 0,
        fixture: "g01".into(),
        seed: 1,
        started_s: 0.0,
        duration_ms: 0,
        status: Some(report.status),
        actions: u64::try_from(report.actions.len()).unwrap(),
        pages: u64::try_from(report.pages.len()).unwrap(),
        trail_violations: 0,
        stuck_intended: 0,
        unreconciled_unknown: 0,
        open_sessions: 0,
        recovering_sessions: 0,
        error: None,
    };
    let interrupted = tokio::time::timeout(Duration::from_secs(5), rig.audit(&report, &stores, &mut cycle))
        .await
        .unwrap();
    let Err(BenchError::Store(crawlx_core::StoreError::Database {
        source,
        retryable: true,
    })) = &interrupted
    else {
        panic!("audit must retain the real retryable database error");
    };
    assert!(matches!(
        source.downcast_ref::<sqlx::Error>(),
        Some(sqlx::Error::PoolTimedOut)
    ));
    assert_eq!(cycle.trail_violations, 1);
    assert!(cycle.failed());
    assert_eq!(audit_retry_delay(&interrupted, 1, cycle.failed()), None);

    proxy.set_blackhole(false);
    assert!(proxy.reset_all() > 0);
    assert!(tokio::time::timeout(Duration::from_secs(5), blocked)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    stores.journal = Arc::new(pg.clone());
    sqlx::query("INSERT INTO transitions SELECT * FROM audit_transition_backup")
        .execute(pg.pool())
        .await
        .unwrap();
    let mut later = cycle.clone();
    rig.audit(&report, &stores, &mut later).await.unwrap();
    assert_eq!(later.trail_violations, 0);
    fault_pg.pool().close().await;
    proxy.shutdown().await;
    pg.drop_schema().await.unwrap();
}
