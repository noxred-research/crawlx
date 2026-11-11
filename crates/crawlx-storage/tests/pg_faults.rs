//! Fault drills and the previous-release schema snapshot.
//! Every test runs in its own schema on `CRAWLX_TEST_DATABASE_URL` and returns early
//! without it. `every_t2_statement_failing_once_leaves_nothing_behind_on_postgres` needs
//! `--features chaos` (the T2 failpoints of `crawlx_storage::chaos`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, Utc};
use crawlx_core::counters::{ActionStatus, ReconcileResolution};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{ActionReceipt, SettleReport};
use crawlx_core::repo::{
    ActionJournal, CrawlRun, NewState, OutcomeRecord, Reconciliation, RunRepo, StateRepo,
};
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin};
use crawlx_core::{
    ActionId, CrawlRunId, NetworkEpochId, SessionId, StateClusterId, StoreError, TenantId, WorkerId,
};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, new_state, proposal, sessions};
use crawlx_storage::{LeaseRepo, Pg, StoreConfig};

const SNAPSHOT_V008: &str = include_str!("../schema/v008.sql");

/// The chaos failpoints and their hit counters are process-global, and every test here that runs
/// `ActionJournal::finish` passes through them. Tests in one binary run concurrently, so they take
/// this lock to keep one test's `reset`/`arm` from clearing or bumping another test's counters.
static FAILPOINT_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Env {
    url: String,
    schema: String,
    pg: Pg,
    tenant: TenantId,
}

fn config(schema: &str, max_connections: u32) -> StoreConfig {
    StoreConfig {
        schema: Some(schema.to_owned()),
        max_connections,
        ..StoreConfig::default()
    }
}

async fn setup() -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let schema = format!("t_{}", CrawlRunId::new().0.simple());
    let pg = Pg::connect(&url, config(&schema, 8)).await.expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "test").await.expect("tenant");
    Some(Env {
        url,
        schema,
        pg,
        tenant,
    })
}

macro_rules! pg_env {
    () => {
        match setup().await {
            Some(e) => e,
            None => {
                eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

/// One intended action with a before-state, ready for T2.
struct Intended {
    run: CrawlRun,
    session: SessionId,
    cluster: StateClusterId,
    id: ActionId,
}

impl Env {
    async fn intended(&self, journal: &Pg) -> Intended {
        let run = crawl_run(self.tenant, create_crawl("https://example.test/", &[], 1));
        self.pg.create(&run, None).await.expect("create run");
        let ss = sessions(run.id, 1, 1);
        self.pg.create_sessions(&ss).await.expect("sessions");
        let lease = self
            .pg
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .expect("claim")
            .expect("a lease");
        let session = lease.session.id;
        let cluster = StateClusterId::new();
        let before = new_state(session, cluster, true, 1, epoch(1, 1, 0));
        self.pg.put_state(&before).await.unwrap();
        let id = journal
            .propose(
                run.id,
                session,
                &proposal("anonymous", cluster, 1),
                &allow_verdict(),
            )
            .await
            .unwrap();
        journal.intend(id, session, epoch(1, 1, 3)).await.unwrap();
        Intended {
            run,
            session,
            cluster,
            id,
        }
    }

    async fn count(&self, sql: &'static str, run: CrawlRunId) -> i64 {
        sqlx::query_scalar(sql)
            .bind(run.0)
            .fetch_one(self.pg.pool())
            .await
            .expect("count")
    }

    /// `(transitions, network_epochs, traffic_events, crawl_events, states)` of `run`.
    async fn t2_rows(&self, run: CrawlRunId) -> (i64, i64, i64, i64, i64) {
        (
            self.count("SELECT count(*) FROM transitions WHERE run_id = $1", run)
                .await,
            self.count("SELECT count(*) FROM network_epochs WHERE run_id = $1", run)
                .await,
            self.count("SELECT count(*) FROM traffic_events WHERE run_id = $1", run)
                .await,
            self.count("SELECT count(*) FROM crawl_events WHERE run_id = $1", run)
                .await,
            self.count("SELECT count(*) FROM states WHERE run_id = $1", run)
                .await,
        )
    }

    /// Nothing of T2 is visible: the action is `intended`, only the before-state exists,
    /// the ledger row and the run's event sequence are untouched.
    async fn assert_nothing_partial(&self, a: &Intended, what: &str) {
        let rec = ActionJournal::get(&self.pg, a.id).await.unwrap();
        assert_eq!(rec.status, ActionStatus::Intended, "{what}: action status");
        assert_eq!(rec.finished_at, None, "{what}: finished_at");
        assert_eq!(self.t2_rows(a.run.id).await, (0, 0, 0, 0, 1), "{what}: T2 rows");
        let ledger: (i32, i32, i32, Option<uuid::Uuid>) = sqlx::query_as(
            "SELECT c.succeeded, c.failed, c.unknown, c.last_action_id FROM action_contexts c JOIN actions a ON a.context_id = c.context_id WHERE a.action_id = $1",
        )
        .bind(a.id.0)
        .fetch_one(self.pg.pool())
        .await
        .unwrap();
        assert_eq!(ledger, (0, 0, 0, None), "{what}: ledger counters");
        let event_seq: i64 = sqlx::query_scalar("SELECT event_seq FROM crawl_runs WHERE run_id = $1")
            .bind(a.run.id.0)
            .fetch_one(self.pg.pool())
            .await
            .unwrap();
        assert_eq!(event_seq, 0, "{what}: event_seq");
    }

    async fn teardown(self) {
        self.pg.drop_schema().await.expect("drop schema");
    }
}

fn epoch(n: u64, d: u64, m: u64) -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: n,
        document_seq: d,
        mutation_seq: m,
    }
}

/// A succeeded outcome that reaches every T2 statement: receipt, after-state, two
/// traffic events (and the action has a before-state, so a transition is written).
fn full_outcome(session: SessionId, cluster: StateClusterId) -> OutcomeRecord {
    let now = Utc::now();
    let after: NewState = new_state(session, cluster, false, 2, epoch(1, 1, 5));
    OutcomeRecord {
        status: ActionStatus::Succeeded,
        receipt: Some(ActionReceipt {
            network_epoch: NetworkEpochId::new(),
            fidelity: Fidelity::ScriptedNavigation,
            lane: Fidelity::ScriptedNavigation.lane(),
            started_at: now,
            finished_at: now,
        }),
        settle: Some(SettleReport::default()),
        after_state: Some(after),
        traffic: (0..2)
            .map(|i| TrafficEvent {
                seq: i,
                epoch_id: None,
                unattributed_reason: None,
                protocol: None,
                origin: TrafficOrigin::Page,
                method: "GET".to_owned(),
                url: format!("https://example.test/api/{i}"),
                status: Some(200),
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                request_body: None,
                response_body: None,
                third_party: false,
                late: false,
                started_at: now,
                finished_at: Some(now),
            })
            .collect(),
        error: None,
        finished_at: now,
    }
}

/// Journal fault injection, PostgreSQL-side: the worker's only connection is
/// terminated by the server between T1 and T2. T2 fails with the typed driver error, the
/// action stays `intended` with no partial outcome rows, and after the worker reconnects
/// the reaper/reconcile path makes the action eligible again.
#[tokio::test]
async fn pg_terminated_connection_between_t1_and_t2_leaves_intended_and_nothing_partial() {
    let _serial = FAILPOINT_SERIAL.lock().await;
    let env = pg_env!();
    // One connection and no pre-acquire ping: the pool cannot hide the dead connection
    // behind a transparent reconnect, so T2's first statement meets it.
    let worker = Pg::connect(
        &env.url,
        StoreConfig {
            test_before_acquire: false,
            ..config(&env.schema, 1)
        },
    )
    .await
    .unwrap();
    let a = env.intended(&worker).await;

    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(worker.pool())
        .await
        .unwrap();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
    assert!(terminated, "the worker backend {pid} was terminated");

    let err = worker
        .finish(a.id, full_outcome(a.session, a.cluster))
        .await
        .expect_err("T2 on a terminated connection fails");
    assert!(
        matches!(err, StoreError::Database { retryable: true, .. }),
        "typed, retryable driver error: {err:?}"
    );
    assert!(err.is_retryable());
    env.assert_nothing_partial(&a, "after the terminated T2").await;
    drop(worker);

    // the worker reconnects; its lease has expired meanwhile, so the reaper flips the
    // action to `unknown` and reconciliation (`not_applied`) makes it eligible again
    let worker = Pg::connect(&env.url, config(&env.schema, 1)).await.unwrap();
    assert_eq!(
        worker
            .mark_unknown(Utc::now() + Duration::seconds(300))
            .await
            .unwrap(),
        vec![a.id]
    );
    worker
        .reconcile(
            a.id,
            Reconciliation {
                resolution: ReconcileResolution::NotApplied,
                evidence: serde_json::json!({ "probe": "absent" }),
                reconciled_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    let eligible = worker.eligible_actions(a.run.id, None, 10).await.unwrap();
    assert_eq!(
        eligible.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![a.id],
        "not_applied is re-eligible"
    );
    assert_eq!(env.t2_rows(a.run.id).await.0, 0, "still no transition");
    env.teardown().await;
}

/// Atomic outcome test: each statement of T2 (`ActionJournal::finish`) fails
/// once; nothing of T2 is visible afterwards and the next full attempt succeeds.
#[cfg(feature = "chaos")]
#[tokio::test]
async fn every_t2_statement_failing_once_leaves_nothing_behind_on_postgres() {
    use crawlx_storage::chaos;
    use std::error::Error;

    let _serial = FAILPOINT_SERIAL.lock().await;
    let env = pg_env!();
    for &point in chaos::T2_FAILPOINTS {
        let a = env.intended(&env.pg).await;
        chaos::reset();
        chaos::arm(point, 1);
        let err = env
            .pg
            .finish(a.id, full_outcome(a.session, a.cluster))
            .await
            .expect_err(point);
        assert!(matches!(err, StoreError::Database { .. }), "{point}: {err:?}");
        assert!(
            err.source().unwrap().is::<chaos::ChaosFault>(),
            "{point}: the injected fault is the source"
        );
        assert_eq!(chaos::hits(point), 1, "{point} was reached exactly once");
        env.assert_nothing_partial(&a, point).await;

        env.pg
            .finish(a.id, full_outcome(a.session, a.cluster))
            .await
            .unwrap_or_else(|e| panic!("{point}: retry after the fault: {e:?}"));
        assert_eq!(chaos::hits(point), 2, "{point}: the retry reached it again");
        let rec = ActionJournal::get(&env.pg, a.id).await.unwrap();
        assert_eq!(rec.status, ActionStatus::Succeeded, "{point}: retry");
        assert_eq!(
            env.t2_rows(a.run.id).await,
            (1, 1, 2, 1, 2),
            "{point}: full T2 after retry"
        );
    }
    chaos::reset();
    env.teardown().await;
}

/// A statement failure in the middle of T2 followed by the crash-recovery path: after each
/// failpoint the lease reaper flips the still-`intended` action to `unknown`, an `applied`
/// reconciliation closes it, no transition or epoch row exists for it, and a later full T2
/// attempt is refused because the action is no longer `intended`.
#[cfg(feature = "chaos")]
#[tokio::test]
async fn a_mid_transaction_failure_is_recovered_through_unknown_and_reconcile_on_postgres() {
    use crawlx_storage::chaos;

    let _serial = FAILPOINT_SERIAL.lock().await;
    let env = pg_env!();
    for &point in chaos::T2_FAILPOINTS {
        let a = env.intended(&env.pg).await;
        chaos::reset();
        chaos::arm(point, 1);
        env.pg
            .finish(a.id, full_outcome(a.session, a.cluster))
            .await
            .expect_err(point);
        env.assert_nothing_partial(&a, point).await;
        chaos::reset();

        let flipped = env
            .pg
            .mark_unknown(Utc::now() + Duration::seconds(300))
            .await
            .unwrap();
        assert!(
            flipped.contains(&a.id),
            "{point}: reaper flips the intended action"
        );
        let rec = ActionJournal::get(&env.pg, a.id).await.unwrap();
        assert_eq!(
            rec.status,
            ActionStatus::Unknown,
            "{point}: never failed, never succeeded"
        );
        env.pg
            .reconcile(
                a.id,
                Reconciliation {
                    resolution: ReconcileResolution::Applied,
                    evidence: serde_json::json!({ "probe": "present", "point": point }),
                    reconciled_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        let rec = ActionJournal::get(&env.pg, a.id).await.unwrap();
        assert_eq!(rec.status, ActionStatus::Reconciled, "{point}");
        assert_eq!(
            rec.reconcile_resolution,
            Some(ReconcileResolution::Applied),
            "{point}"
        );
        assert_eq!(
            env.t2_rows(a.run.id).await.0,
            0,
            "{point}: no transition was written"
        );
        assert!(
            env.pg
                .finish(a.id, full_outcome(a.session, a.cluster))
                .await
                .is_err(),
            "{point}: a stale T2 cannot overwrite the reconciled action"
        );
    }
    chaos::reset();
    env.teardown().await;
}

/// The worker-side `during_outcome_tx` failpoint drops the T2 future after it was polled once;
/// the same cancellation against the real PostgreSQL journal (the future is polled exactly
/// once, then dropped while its transaction or connection acquire is in flight) leaves nothing
/// partial and the next full T2 succeeds on the same pool.
#[tokio::test]
async fn a_t2_future_dropped_after_one_poll_leaves_nothing_partial_on_postgres() {
    let _serial = FAILPOINT_SERIAL.lock().await;
    let env = pg_env!();
    let a = env.intended(&env.pg).await;
    let fut = env.pg.finish(a.id, full_outcome(a.session, a.cluster));
    tokio::select! {
        biased;
        r = fut => { let _ = r; }
        () = std::future::ready(()) => {}
    }
    // give the server time to roll back a transaction whose connection was dropped mid-flight
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let rec = ActionJournal::get(&env.pg, a.id).await.unwrap();
    if rec.status == ActionStatus::Intended {
        env.assert_nothing_partial(&a, "dropped after one poll").await;
        env.pg
            .finish(a.id, full_outcome(a.session, a.cluster))
            .await
            .expect("the next full T2 succeeds on the same pool");
    } else {
        // the first poll can only have committed everything or nothing
        assert_eq!(rec.status, ActionStatus::Succeeded);
    }
    assert_eq!(
        env.t2_rows(a.run.id).await,
        (1, 1, 2, 1, 2),
        "T2 is all or nothing"
    );
    env.teardown().await;
}

fn migration_versions_on_disk() -> Vec<i64> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
    let mut versions: Vec<i64> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".sql"))
        .map(|n| n.split('_').next().unwrap().parse().unwrap())
        .collect();
    versions.sort_unstable();
    versions
}

/// `(table, column, data_type, is_nullable, column_default)` of every base table in the
/// connection's schema, sorted.
async fn columns(pg: &Pg) -> Vec<(String, String, String, String, Option<String>)> {
    sqlx::query_as(
        "SELECT c.table_name::text, c.column_name::text, c.data_type::text, c.is_nullable::text, c.column_default::text \
         FROM information_schema.columns c JOIN information_schema.tables t \
           ON t.table_schema = c.table_schema AND t.table_name = c.table_name \
         WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE' \
           AND c.table_name NOT LIKE 'traffic_events_2%' \
         ORDER BY 1, 2",
    )
    .fetch_all(pg.pool())
    .await
    .unwrap()
}

/// CI applies all migrations to a snapshot of the previous release.
/// `schema/v008.sql` (made by `ci/schema-snapshot.sh --through 0008`) is loaded into an
/// empty schema, then the embedded migrator runs on top: it must accept the snapshot's
/// `_sqlx_migrations` rows (same checksums), apply only the later migrations, be
/// idempotent, and end with the same columns as migrating from empty.
#[tokio::test]
async fn migrations_apply_on_top_of_the_previous_release_snapshot() {
    let env = pg_env!();
    let schema = format!("t_snap_{}", CrawlRunId::new().0.simple());
    let pg = Pg::connect(&env.url, config(&schema, 4)).await.unwrap();
    sqlx::raw_sql(SNAPSHOT_V008)
        .execute(pg.pool())
        .await
        .expect("the snapshot loads into an empty schema");
    let snapshot_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pg.pool())
            .await
            .unwrap();
    assert_eq!(snapshot_versions, (1..=8).collect::<Vec<_>>());

    pg.migrate().await.expect("migrating on top of the snapshot");
    pg.migrate().await.expect("second run is a no-op");
    let applied: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(pg.pool())
            .await
            .unwrap();
    assert_eq!(
        applied,
        migration_versions_on_disk(),
        "every embedded migration is recorded"
    );
    assert_eq!(
        columns(&pg).await,
        columns(&env.pg).await,
        "snapshot + later migrations has the columns of a from-empty migration"
    );
    pg.drop_schema().await.unwrap();
    env.teardown().await;
}
