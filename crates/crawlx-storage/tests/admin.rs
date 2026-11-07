#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `crawlx admin` operations over PostgreSQL (§7 RB-02/RB-11).
//! Needs `CRAWLX_TEST_DATABASE_URL`; without it every test returns early.

use crawlx_core::counters::{ActionStatus, RunStatus, TerminalReason};
use crawlx_core::repo::{ActionJournal, ArtifactStore, RunRepo, Sensitivity, SessionStatus};
use crawlx_core::{ActionId, CrawlRunId, SystemClock, TenantId, WorkerId};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions};
use crawlx_storage::{
    AdminOps, AdmissionMode, ArtifactBlobs, LeaseRepo, MemBlobs, MemoryArtifactStore, Pg, PgConfig,
    RetentionSweeper, RunSelector, TenantEngine, WorkerRegistry,
};
use std::sync::Arc;

struct Env {
    pg: Pg,
    tenant: TenantId,
}

async fn setup() -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let schema = format!("t_{}", CrawlRunId::new().0.simple());
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(schema),
            max_connections: 8,
            ..PgConfig::default()
        },
    )
    .await
    .expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "test").await.expect("tenant");
    Some(Env { pg, tenant })
}

impl Env {
    async fn running_run(&self) -> CrawlRunId {
        let run = crawl_run(
            self.tenant,
            create_crawl("https://example.test/", &["anonymous"], 1),
        );
        self.pg.create(&run, None).await.unwrap();
        self.pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
        self.pg
            .set_status(run.id, RunStatus::Running, None)
            .await
            .unwrap();
        run.id
    }

    async fn audit_events(&self) -> Vec<(String, String)> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT actor, event FROM audit_events ORDER BY audit_id")
                .fetch_all(self.pg.pool())
                .await
                .unwrap();
        rows
    }
}

#[tokio::test]
async fn admission_round_trips_through_cluster_settings_and_gates_leases() {
    let Some(env) = setup().await else { return };
    let ops = AdminOps::new(&env.pg, "alice");
    assert_eq!(ops.admission().await.unwrap(), AdmissionMode::Open);
    assert_eq!(
        ops.set_admission(AdmissionMode::Frozen).await.unwrap(),
        AdmissionMode::Open
    );
    assert_eq!(
        LeaseRepo::admission(&env.pg).await.unwrap(),
        AdmissionMode::Frozen
    );
    assert!(!LeaseRepo::admission(&env.pg).await.unwrap().grants_leases());

    // the scheduler consults this before claiming (crawlx-scheduler `lease_next`)
    ops.set_admission(AdmissionMode::Drain).await.unwrap();
    assert!(!LeaseRepo::admission(&env.pg).await.unwrap().grants_leases());
    ops.set_admission(AdmissionMode::Open).await.unwrap();
    assert!(LeaseRepo::admission(&env.pg).await.unwrap().grants_leases());
    // an unknown stored value is an error, not silently open
    sqlx::query("UPDATE cluster_settings SET value = 'open' WHERE key = 'scheduler.admission'")
        .execute(env.pg.pool())
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE cluster_settings SET value = 'closed' WHERE key = 'scheduler.admission'")
            .execute(env.pg.pool())
            .await
            .is_err(),
        "the CHECK constraint rejects unknown modes"
    );

    let events = env.audit_events().await;
    assert_eq!(
        events
            .iter()
            .filter(|(a, e)| a == "admin:alice" && e == "admin.admission")
            .count(),
        3
    );
}

#[tokio::test]
async fn pause_resume_cancel_by_selector_write_events_and_audit() {
    let Some(env) = setup().await else { return };
    let a = env.running_run().await;
    let b = env.running_run().await;
    let other = TenantId::new();
    env.pg.ensure_tenant(other, "other").await.unwrap();
    let c = {
        let run = crawl_run(other, create_crawl("https://other.test/", &["anonymous"], 1));
        env.pg.create(&run, None).await.unwrap();
        env.pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
        env.pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
        run.id
    };
    let ops = AdminOps::new(&env.pg, "bob");

    let paused = ops.pause(RunSelector::Crawl(a)).await.unwrap();
    assert_eq!(paused, vec![a]);
    assert_eq!(RunRepo::get(&env.pg, a).await.unwrap().status, RunStatus::Paused);
    assert_eq!(RunRepo::get(&env.pg, b).await.unwrap().status, RunStatus::Running);

    let paused = ops.pause(RunSelector::Tenant(env.tenant)).await.unwrap();
    assert_eq!(
        paused,
        vec![b],
        "a is already paused; c belongs to another tenant"
    );
    assert_eq!(RunRepo::get(&env.pg, c).await.unwrap().status, RunStatus::Running);

    let resumed = ops.resume(RunSelector::All).await.unwrap();
    assert_eq!(resumed.len(), 2);
    assert_eq!(RunRepo::get(&env.pg, a).await.unwrap().status, RunStatus::Running);

    // RB-11 level 2: freeze --all = frozen admission + pause everything
    ops.set_admission(AdmissionMode::Frozen).await.unwrap();
    let paused = ops.pause(RunSelector::All).await.unwrap();
    assert_eq!(paused.len(), 3);
    let row = RunRepo::get(&env.pg, c).await.unwrap();
    assert_eq!(row.status, RunStatus::Paused);
    let pause_requested: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT pause_requested_at FROM crawl_runs WHERE run_id = $1")
            .bind(c.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert!(pause_requested.is_some(), "the SQL fallback column is set too");

    assert!(ops.cancel(RunSelector::Crawl(a), "nope").await.is_err());
    let cancelled = ops.cancel(RunSelector::Crawl(a), "policy_stopped").await.unwrap();
    assert_eq!(cancelled, vec![a]);
    let row = RunRepo::get(&env.pg, a).await.unwrap();
    assert_eq!(row.status, RunStatus::Cancelled);
    assert_eq!(row.terminal_reason, Some(TerminalReason::PolicyStopped));
    assert!(env
        .pg
        .list_sessions(a)
        .await
        .unwrap()
        .iter()
        .all(|s| s.status == SessionStatus::Cancelled));
    assert!(
        ops.cancel(RunSelector::Crawl(a), "cancelled")
            .await
            .unwrap()
            .is_empty(),
        "idempotent"
    );

    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT type FROM crawl_events WHERE run_id = $1 ORDER BY seq")
            .bind(a.0)
            .fetch_all(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(kinds, vec!["paused", "resumed", "paused", "status", "completed"]);
    let events = env.audit_events().await;
    for e in ["admin.pause", "admin.resume", "admin.admission", "admin.cancel"] {
        assert!(
            events.iter().any(|(a, ev)| a == "admin:bob" && ev == e),
            "{e} missing in {events:?}"
        );
    }
}

#[tokio::test]
async fn drain_marks_a_registered_worker_and_heartbeat_reports_it() {
    let Some(env) = setup().await else { return };
    let worker = WorkerId::new();
    let ops = AdminOps::new(&env.pg, "carol");
    assert!(ops.drain_worker(worker).await.is_err(), "unknown worker");
    env.pg.register_worker(worker, "node-1", "0.1.0").await.unwrap();
    assert!(!env.pg.worker_heartbeat(worker).await.unwrap());
    let run = env.running_run().await;
    let lease = env.pg.claim_session(run, worker, true).await.unwrap().unwrap();
    assert_eq!(lease.session.run, run);
    assert_eq!(ops.drain_worker(worker).await.unwrap(), 1, "one lease held");
    assert!(
        env.pg.worker_heartbeat(worker).await.unwrap(),
        "heartbeat reports the drain"
    );
    let rows = ops.workers().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].draining && rows[0].leases_held == 1 && rows[0].hostname == "node-1");
    // re-registration (a restarted pod) clears the flag
    env.pg.register_worker(worker, "node-1", "0.1.1").await.unwrap();
    assert!(!env.pg.worker_heartbeat(worker).await.unwrap());
}

#[tokio::test]
async fn reconcile_lists_open_actions_and_hands_unknown_sessions_to_recovery() {
    let Some(env) = setup().await else { return };
    let run = env.running_run().await;
    let lease = env
        .pg
        .claim_session(run, WorkerId::new(), true)
        .await
        .unwrap()
        .expect("a lease");
    let session = lease.session.id;
    let cluster = crawlx_core::StateClusterId::new();
    let action = env
        .pg
        .propose(run, session, &proposal("anonymous", cluster, 1), &allow_verdict())
        .await
        .unwrap();
    let epoch = crawlx_core::epoch::ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: 0,
    };
    env.pg.intend(action, session, epoch).await.unwrap();

    let ops = AdminOps::new(&env.pg, "dave");
    let open = ops.open_actions(None).await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].status, "intended");
    assert!(
        ops.request_reconcile(action).await.is_err(),
        "an intended row is not reconciled by hand; the reaper flips it first"
    );
    sqlx::query(
        "UPDATE crawl_sessions SET lease_expires_at = now() - interval '1 minute' WHERE session_id = $1",
    )
    .bind(session.0)
    .execute(env.pg.pool())
    .await
    .unwrap();
    env.pg.mark_unknown(env.pg.db_now().await.unwrap()).await.unwrap();
    assert_eq!(
        ActionJournal::get(&env.pg, action).await.unwrap().status,
        ActionStatus::Unknown
    );
    let status = ops.request_reconcile(action).await.unwrap();
    assert_eq!(
        status, "recovering",
        "a running session without a live lease hands over"
    );
    assert!(ops.request_reconcile(ActionId::new()).await.is_err());
    assert!(env
        .audit_events()
        .await
        .iter()
        .any(|(a, e)| a == "admin:dave" && e == "admin.reconcile"));
}

#[tokio::test]
async fn tenant_engine_flag_is_stored_and_audited() {
    let Some(env) = setup().await else { return };
    let ops = AdminOps::new(&env.pg, "erin");
    assert_eq!(
        crawlx_storage::admin::tenant_engine_of(&env.pg, env.tenant)
            .await
            .unwrap(),
        Some(TenantEngine::Crawlx)
    );
    assert_eq!(
        ops.set_tenant_engine(env.tenant, TenantEngine::Firecrawl)
            .await
            .unwrap(),
        TenantEngine::Crawlx
    );
    assert_eq!(
        crawlx_storage::admin::tenant_engine_of(&env.pg, env.tenant)
            .await
            .unwrap(),
        Some(TenantEngine::Firecrawl)
    );
    assert!(ops
        .set_tenant_engine(TenantId::new(), TenantEngine::Shadow)
        .await
        .is_err());
    assert_eq!(
        crawlx_storage::admin::tenant_engine_of(&env.pg, TenantId::new())
            .await
            .unwrap(),
        None
    );
    // the shadow run kind is accepted by the constraint
    let run = env.running_run().await;
    sqlx::query("UPDATE crawl_runs SET run_kind = 'shadow' WHERE run_id = $1")
        .bind(run.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE crawl_runs SET run_kind = 'mirror' WHERE run_id = $1")
            .bind(run.0)
            .execute(env.pg.pool())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn verify_artifacts_finds_missing_objects_and_digest_mismatches() {
    let Some(env) = setup().await else { return };
    let run = env.running_run().await;
    let runs: Arc<dyn RunRepo> = Arc::new(env.pg.clone());
    let store =
        MemoryArtifactStore::in_memory(runs, Arc::new(SystemClock)).with_index(Arc::new(env.pg.clone()));
    let ok = store
        .put(run, Sensitivity::Content, "text/plain", b"fine")
        .await
        .unwrap();
    let gone = store
        .put(run, Sensitivity::Content, "text/plain", b"will vanish")
        .await
        .unwrap();
    let bad = store
        .put(run, Sensitivity::Content, "text/plain", b"will be corrupted")
        .await
        .unwrap();
    let keys: Vec<(uuid::Uuid, String)> =
        sqlx::query_as("SELECT artifact_id, object_key FROM artifacts ORDER BY artifact_id")
            .fetch_all(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(keys.len(), 3);
    let blobs: &MemBlobs = store.blobs();
    let key_of = |id: crawlx_core::ArtifactId| keys.iter().find(|(k, _)| *k == id.0).unwrap().1.clone();
    blobs.delete(&key_of(gone.id)).await.unwrap();
    blobs.put(&key_of(bad.id), b"corrupted").await.unwrap();

    let ops = AdminOps::new(&env.pg, "frank");
    let v = ops.verify_artifacts(blobs, None).await.unwrap();
    assert_eq!(v.checked, 3);
    let defects: Vec<(uuid::Uuid, &str)> = v.defects.iter().map(|d| (d.artifact_id, d.defect)).collect();
    assert!(defects.contains(&(gone.id.0, "missing")), "{defects:?}");
    assert!(defects.contains(&(bad.id.0, "digest_mismatch")), "{defects:?}");
    assert!(!defects.iter().any(|(id, _)| *id == ok.id.0));
    assert_eq!(v.orphans, 0);

    // an orphan object with no row
    blobs.put("content/orphan/x/y", b"stray").await.unwrap();
    let v = ops.verify_artifacts(blobs, None).await.unwrap();
    assert_eq!(v.orphans, 1);
    let since = env.pg.db_now().await.unwrap();
    let v = ops.verify_artifacts(blobs, Some(since)).await.unwrap();
    assert_eq!(v.checked, 0, "nothing created after `since`");
}

#[tokio::test]
async fn force_zdr_sweep_deletes_objects_then_rows_and_keeps_the_trail() {
    let Some(mut env) = setup().await else { return };
    env.pg = env
        .pg
        .clone()
        .with_delivery_buffer(Arc::new(crawlx_storage::DeliveryBuffer::new(
            Arc::new(SystemClock),
            crawlx_storage::BufferLimits::default(),
        )));
    let mut cfg = create_crawl("https://zdr.test/", &["anonymous"], 1);
    cfg.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    cfg.retention.days = 0;
    let run = crawl_run(env.tenant, cfg);
    env.pg.create(&run, None).await.unwrap();
    env.pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(env.pg.clone());
    let store = Arc::new(
        MemoryArtifactStore::in_memory(runs, Arc::new(SystemClock)).with_index(Arc::new(env.pg.clone())),
    );
    // metadata is the only class the ZDR write gate admits
    let meta = store
        .put(run.id, Sensitivity::Metadata, "application/json", b"{}")
        .await
        .unwrap();
    let key: String = sqlx::query_scalar("SELECT object_key FROM artifacts WHERE artifact_id = $1")
        .bind(meta.id.0)
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
    assert!(store.blobs().exists(&key).await.unwrap());
    let sweeper = RetentionSweeper::new(env.pg.clone()).with_artifacts(store.clone());
    let purged = crawlx_storage::admin::force_zdr_sweep(&env.pg, &sweeper, "admin:grace")
        .await
        .unwrap();
    assert_eq!(purged, vec![run.id]);
    assert!(!store.blobs().exists(&key).await.unwrap(), "object deleted first");
    let deleted: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE artifact_id = $1")
            .bind(meta.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert!(deleted.is_some(), "row marked deleted afterwards");
    assert!(
        RunRepo::get_metadata(&env.pg, run.id).await.is_ok(),
        "the run row (structural trail) stays"
    );
    assert_eq!(env.pg.list_sessions(run.id).await.unwrap().len(), 1);
    let events = env.audit_events().await;
    assert!(events
        .iter()
        .any(|(a, e)| a == "admin:grace" && e == "admin.zdr_force_sweep"));
}
