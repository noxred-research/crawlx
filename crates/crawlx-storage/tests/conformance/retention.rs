//! Retention, the audit chain, operator commands, the worker registry and the artifact index.
//!
//! Every case runs on SQLite, MariaDB and PostgreSQL; the cases that only need a trait
//! (`WorkerRegistry`, `ArtifactIndex`) also run on the in-memory specification. Traffic
//! partitions are PostgreSQL machinery (plain tables elsewhere) and stay in `tests/pg.rs`.

use crate::rig::Rig;
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use crawlx_core::acquisition::{BackendCapabilitiesV1, WORKER_CAPABILITY_SNAPSHOT_LIMIT};
use crawlx_core::config::{LaunchProfile, RetentionMode};
use crawlx_core::counters::{ActionStatus, RunStatus, TerminalReason};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::{ActionJournal, ArtifactStore, EventRepo, RunRepo, Sensitivity, SessionStatus};
use crawlx_core::{
    ActionId, ArtifactId, CrawlRunId, StateClusterId, StoreError, SystemClock, TenantId, WorkerId,
};
use crawlx_storage::admin::{active_run_count, admission_of, force_zdr_sweep, tenant_engine_of};
use crawlx_storage::audit::{export_key, merkle_root, MerkleExport, MERKLE_DOMAIN};
use crawlx_storage::backend::strategy::{audit_entry_hash, AuditEntry, EMPTY_AUDIT_HEAD};
use crawlx_storage::retention::{append_audit, run_sweep_loop, SweepLoopConfig, SweepReport};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions};
use crawlx_storage::{
    AdminOps, AdmissionMode, ArtifactBlobs, ArtifactIndex, ArtifactRow, BackendKind, Database,
    FsArtifactStore, LeaseRepo, MemBlobs, MemoryArtifactStore, RetentionSweeper, RunSelector, SafetyAuditor,
    TenantEngine, WorkerRegistry,
};
use sqlx::Row as _;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Run `$body` with `$store` bound to the `Store` of the rig's database engine.
macro_rules! on_db {
    ($rig:expr, |$store:ident| $body:expr) => {{
        use crawlx_storage::testkit::Engine;
        match $rig.engine() {
            Engine::Sqlite => {
                let $store = $rig.database().sqlite_store().expect("a sqlite rig has a store");
                $body
            }
            Engine::MariaDb => {
                let $store = $rig
                    .database()
                    .mariadb_store()
                    .expect("a mariadb rig has a store");
                $body
            }
            Engine::Postgres => {
                let $store = $rig.database().postgres().expect("a postgres rig has a store");
                $body
            }
            _ => panic!("this case needs a database engine"),
        }
    }};
}

/// Like `on_db!`, and the in-memory store on the memory rig.
macro_rules! on_any {
    ($rig:expr, |$repo:ident| $body:expr) => {{
        use crawlx_storage::testkit::Engine;
        match $rig.engine() {
            Engine::Memory => {
                let $repo = $rig.store().as_ref();
                $body
            }
            _ => on_db!($rig, |$repo| $body),
        }
    }};
}

conformance! { databases:
    audit_chain_hashes_are_identical_on_every_engine,
    audit_events_are_append_only,
    concurrent_audit_appends_keep_one_unbroken_chain,
    merkle_export_folds_the_days_leaves_in_time_order,
    admission_round_trips_through_cluster_settings_and_gates_leases,
    pause_resume_cancel_by_selector_write_events_and_audit,
    drain_marks_a_registered_worker_and_heartbeat_reports_it,
    reconcile_lists_open_actions_and_hands_unknown_sessions_to_recovery,
    tenant_engine_flag_is_stored_and_audited,
    verify_artifacts_finds_missing_objects_and_digest_mismatches,
    force_zdr_sweep_deletes_objects_then_rows_and_keeps_the_trail,
    registry_excludes_stale_draining_and_restarted_workers,
    overdue_artifacts_count_until_the_sweeper_runs_then_zero,
    sweeper_counts_each_zdr_artifact_row_once,
    sweeper_purges_expired_runs_and_chains_the_audit_log,
    erasure_closes_the_run_before_its_rows_are_purged,
    authorization_records_are_removed_after_the_audit_horizon,
    sweep_loop_deletes_expired_rows_on_each_tick_and_stops_on_cancel,
}

conformance! { all:
    registry_never_unions_workers_and_keeps_an_eligible_worker_beyond_the_snapshot,
    local_executor_never_satisfies_queued_capability_admission,
    artifact_index_records_reads_retention_and_marks_deleted_once,
}

// ---------------------------------------------------------------------------------------------
// Raw statements: fixtures and assertions that must not depend on the code under test.
// ---------------------------------------------------------------------------------------------

/// A value bound to a raw statement.
#[derive(Clone, Debug)]
enum V {
    Uuid(Uuid),
    Text(String),
    Int(i64),
    Ts(DateTime<Utc>),
    Bytes(Vec<u8>),
}

/// `?` placeholders rewritten to `$n` for PostgreSQL.
fn pg_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0;
    for c in sql.chars() {
        if c == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(c);
        }
    }
    out
}

macro_rules! bind_all {
    ($q:expr, $args:expr, ts: $ts:expr) => {{
        let mut q = $q;
        for a in $args {
            q = match a {
                V::Uuid(v) => q.bind(*v),
                V::Text(v) => q.bind(v.clone()),
                V::Int(v) => q.bind(*v),
                V::Ts(v) => q.bind(($ts)(*v)),
                V::Bytes(v) => q.bind(v.clone()),
            };
        }
        q
    }};
}

/// Run a statement; the rows it affected.
async fn exec(db: &Database, sql: &str, args: &[V]) -> Result<u64, sqlx::Error> {
    match db.kind() {
        BackendKind::Postgres => bind_all!(sqlx::query(sqlx::AssertSqlSafe(pg_sql(sql))), args, ts: |t: DateTime<Utc>| t)
            .execute(db.postgres().unwrap().pool())
            .await
            .map(|done| done.rows_affected()),
        BackendKind::Sqlite => {
            bind_all!(sqlx::query(sqlx::AssertSqlSafe(sql.to_owned())), args, ts: |t: DateTime<Utc>| t.timestamp_micros())
                .execute(db.sqlite_pool().unwrap())
                .await
                .map(|done| done.rows_affected())
        }
        _ => bind_all!(sqlx::query(sqlx::AssertSqlSafe(sql.to_owned())), args, ts: |t: DateTime<Utc>| t.naive_utc())
            .execute(db.mariadb_pool().unwrap())
            .await
            .map(|done| done.rows_affected()),
    }
}

/// Run a query and map every row with `$body` (`$row` is the engine's own row type).
macro_rules! read_rows {
    ($db:expr, $sql:expr, $args:expr, |$row:ident| $body:expr) => {{
        match $db.kind() {
            BackendKind::Postgres => bind_all!(sqlx::query(sqlx::AssertSqlSafe(pg_sql($sql))), $args, ts: |t: DateTime<Utc>| t)
                .fetch_all($db.postgres().unwrap().pool())
                .await
                .unwrap()
                .iter()
                .map(|$row| $body)
                .collect::<Vec<_>>(),
            BackendKind::Sqlite => {
                bind_all!(sqlx::query(sqlx::AssertSqlSafe(($sql).to_owned())), $args, ts: |t: DateTime<Utc>| t.timestamp_micros())
                    .fetch_all($db.sqlite_pool().unwrap())
                    .await
                    .unwrap()
                    .iter()
                    .map(|$row| $body)
                    .collect::<Vec<_>>()
            }
            _ => bind_all!(sqlx::query(sqlx::AssertSqlSafe(($sql).to_owned())), $args, ts: |t: DateTime<Utc>| t.naive_utc())
                .fetch_all($db.mariadb_pool().unwrap())
                .await
                .unwrap()
                .iter()
                .map(|$row| $body)
                .collect::<Vec<_>>(),
        }
    }};
}

async fn count(db: &Database, sql: &str, args: &[V]) -> i64 {
    read_rows!(db, sql, args, |row| row.get::<i64, _>(0))
        .first()
        .copied()
        .unwrap()
}

/// The first column as text; a PostgreSQL `jsonb` column is read as its compact JSON text.
async fn texts(db: &Database, sql: &str, args: &[V]) -> Vec<String> {
    read_rows!(db, sql, args, |row| row
        .try_get::<String, _>(0)
        .unwrap_or_else(|_| row.get::<serde_json::Value, _>(0).to_string()))
}

async fn blob_pairs(db: &Database, sql: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    read_rows!(db, sql, &[], |row| (
        row.get::<Vec<u8>, _>(0),
        row.get::<Vec<u8>, _>(1)
    ))
}

/// `key` is reserved on MariaDB.
fn key_column(rig: &Rig) -> &'static str {
    if rig.kind() == Some(BackendKind::MariaDb) {
        "`key`"
    } else {
        "key"
    }
}

fn is_postgres(rig: &Rig) -> bool {
    rig.kind() == Some(BackendKind::Postgres)
}

async fn tenant(rig: &Rig) -> TenantId {
    let tenant = TenantId::new();
    rig.insert_tenant(tenant.0).await.unwrap();
    tenant
}

/// A queued run with one pending session, moved to `running`.
async fn running_run<R: RunRepo>(repo: &R, tenant: TenantId) -> CrawlRunId {
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["anonymous"], 1));
    repo.create(&run, None).await.unwrap();
    repo.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    repo.set_status(run.id, RunStatus::Running, None).await.unwrap();
    run.id
}

async fn audit_events(db: &Database) -> Vec<(String, String)> {
    read_rows!(
        db,
        "SELECT actor, event FROM audit_events ORDER BY audit_id",
        &[],
        |row| (row.get::<String, _>(0), row.get::<String, _>(1))
    )
}

/// Metrics are process-global: cases that read counters or gauges take turns.
static METRICS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ---------------------------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------------------------

/// The head after the series of `audit_chain_hashes_are_identical_on_every_engine`, computed
/// outside this crate (BLAKE3 over `domain || 0x00 || prev || entry text` with sorted compact
/// JSON). Every engine must reach it: the chain hashes Rust-rendered text, not database JSON.
const GOLDEN_HEAD: &str = "78efe6862a5835e349a24c8d01692dfa8c20eaf8f2d69ed9fcf97207da5660b5";

/// One audit entry of the golden series: tenant, run, actor, event and subject.
type AuditFixture<'a> = (Option<Uuid>, Option<Uuid>, &'a str, &'a str, serde_json::Value);

async fn audit_chain_hashes_are_identical_on_every_engine(rig: &Rig) {
    rig.migrate().await;
    let tenant = TenantId(Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef));
    rig.insert_tenant(tenant.0).await.unwrap();
    let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    run.id = CrawlRunId(Uuid::from_u128(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210));
    on_db!(rig, |store| RunRepo::create(store, &run, None).await.unwrap());

    let entries: Vec<AuditFixture> = vec![
        (None, None, "operator", "purge", serde_json::json!({ "k": "v" })),
        (
            Some(tenant.0),
            None,
            "admin:alice",
            "admin.pause",
            serde_json::json!({ "selector": { "all": true } }),
        ),
        (
            Some(tenant.0),
            Some(run.id.0),
            "retention_sweeper",
            "run.purged",
            serde_json::json!({ "run_id": run.id.0, "rows_deleted": 12 }),
        ),
        (
            None,
            None,
            "é𝄞",
            "unicode",
            serde_json::json!({ "nested": { "b": [1, null, "x"], "a": true }, "z": 1.5 }),
        ),
    ];
    for (entry_tenant, entry_run, actor, event, subject) in &entries {
        on_db!(rig, |store| append_audit(
            store,
            *entry_tenant,
            *entry_run,
            actor,
            event,
            subject.clone()
        )
        .await
        .unwrap());
    }

    let rows = blob_pairs(
        rig.database(),
        "SELECT prev_hash, entry_hash FROM audit_events ORDER BY audit_id",
    )
    .await;
    assert_eq!(rows.len(), entries.len());
    let mut previous = EMPTY_AUDIT_HEAD.to_vec();
    for ((entry_tenant, entry_run, actor, event, subject), (stored_prev, stored_hash)) in
        entries.iter().zip(&rows)
    {
        let expected = audit_entry_hash(
            &previous,
            &AuditEntry {
                tenant: *entry_tenant,
                run: *entry_run,
                actor,
                event,
                subject,
            },
        );
        assert_eq!(stored_prev, &previous, "{event} links to the previous hash");
        assert_eq!(
            stored_hash,
            &expected.0.to_vec(),
            "{event} hashes the Rust-rendered entry"
        );
        previous = expected.0.to_vec();
    }
    assert_eq!(
        hex::encode(&previous),
        GOLDEN_HEAD,
        "the series hashes to the same head on every engine"
    );
    if !is_postgres(rig) {
        let head = blob_pairs(
            rig.database(),
            "SELECT entry_hash, entry_hash FROM audit_chain_head WHERE id = 1",
        )
        .await;
        assert_eq!(head[0].0, previous, "the chain head row follows the last append");
        // the stored subject is the exact Rust-rendered text
        let subjects = texts(
            rig.database(),
            "SELECT subject FROM audit_events ORDER BY audit_id",
            &[],
        )
        .await;
        for ((_, _, _, _, subject), stored) in entries.iter().zip(&subjects) {
            assert_eq!(stored, &subject.to_string());
        }
    }
}

async fn audit_events_are_append_only(rig: &Rig) {
    rig.migrate().await;
    on_db!(rig, |store| append_audit(
        store,
        None,
        None,
        "operator",
        "purge",
        serde_json::json!({})
    )
    .await
    .unwrap());
    if is_postgres(rig) {
        // PostgreSQL withholds UPDATE and DELETE from the request login instead (provisioning)
        return;
    }
    let db = rig.database();
    assert!(exec(db, "UPDATE audit_events SET actor = 'x'", &[])
        .await
        .is_err());
    assert!(exec(db, "DELETE FROM audit_events", &[]).await.is_err());
    assert_eq!(count(db, "SELECT count(*) FROM audit_events", &[]).await, 1);
}

async fn concurrent_audit_appends_keep_one_unbroken_chain(rig: &Rig) {
    rig.migrate().await;
    on_db!(rig, |store| {
        let mut writers = Vec::new();
        for writer in 0..6 {
            let store = store.clone();
            writers.push(tokio::spawn(async move {
                for tick in 0..4 {
                    append_audit(
                        &store,
                        None,
                        None,
                        "load",
                        "tick",
                        serde_json::json!({ "writer": writer, "tick": tick }),
                    )
                    .await
                    .unwrap();
                }
            }));
        }
        for writer in writers {
            writer.await.unwrap();
        }
    });
    let rows = blob_pairs(
        rig.database(),
        "SELECT prev_hash, entry_hash FROM audit_events ORDER BY audit_id",
    )
    .await;
    assert_eq!(rows.len(), 24);
    assert_eq!(rows[0].0, EMPTY_AUDIT_HEAD.to_vec());
    for pair in rows.windows(2) {
        assert_eq!(pair[1].0, pair[0].1, "every entry links to the one before it");
    }
}

/// The daily export folds the tenant's `entry_hash` leaves of one UTC day in
/// `(occurred_at, audit_id)` order and writes `audit/{tenant}/{day}.json`; the root recomputes
/// from the table and from the documented tree shape.
async fn merkle_export_folds_the_days_leaves_in_time_order(rig: &Rig) {
    rig.migrate().await;
    let tenant = tenant(rig).await;
    let other = TenantId::new();
    let day = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
    let at = |d: NaiveDate, h: u32| Utc.from_utc_datetime(&d.and_hms_opt(h, 0, 0).unwrap());
    let next = day.succ_opt().unwrap();
    // inserted out of time order so the export must sort by occurred_at, not audit_id
    for (owner, when, fill) in [
        (tenant, at(day, 10), 0xa1u8),
        (tenant, at(day, 11), 0xa2),
        (tenant, at(day, 9), 0xa3),
        (tenant, at(next, 0), 0xb1),
        (other, at(day, 12), 0xc1),
    ] {
        exec(
            rig.database(),
            "INSERT INTO audit_events (tenant_id, run_id, actor, event, subject, occurred_at, prev_hash, entry_hash) \
             VALUES (?, NULL, 'test', 'run.created', '{}', ?, ?, ?)",
            &[V::Uuid(owner.0), V::Ts(when), V::Bytes(vec![0; 32]), V::Bytes(vec![fill; 32])],
        )
        .await
        .unwrap();
    }
    let ids = read_rows!(
        rig.database(),
        "SELECT audit_id FROM audit_events ORDER BY audit_id",
        &[],
        |row| row.get::<i64, _>(0)
    );
    let blobs = Arc::new(MemBlobs::default());
    on_db!(rig, |store| {
        let export = MerkleExport::new(store.clone(), blobs.clone());
        let rec = export.export_day(tenant, day).await.unwrap();
        assert_eq!(rec.count, 3);
        assert_eq!((rec.first_id, rec.last_id), (Some(ids[2]), Some(ids[1])));

        // the documented shape: H(H(a3, a1), H(a2, a2)) in occurred_at order
        let node =
            |l: [u8; 32], r: [u8; 32]| Digest::of(MERKLE_DOMAIN, &[l.as_slice(), r.as_slice()].concat());
        let (a1, a2, a3) = ([0xa1u8; 32], [0xa2u8; 32], [0xa3u8; 32]);
        assert_eq!(rec.root, Some(node(node(a3, a1).0, node(a2, a2).0)));
        let leaves: Vec<Digest> = export
            .leaves(tenant, day)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, d)| d)
            .collect();
        assert_eq!(merkle_root(&leaves), rec.root);

        let key = export_key(tenant, day);
        assert_eq!(key, format!("audit/{tenant}/2026-01-15.json"));
        let stored: serde_json::Value =
            serde_json::from_slice(&ArtifactBlobs::get(&*blobs, &key).await.unwrap().unwrap()).unwrap();
        assert_eq!(stored["count"], 3);
        assert_eq!(stored["day"], "2026-01-15");
        assert_eq!(stored["root"], rec.root.unwrap().to_hex());
        assert_eq!(export.stored(tenant, day).await.unwrap(), Some(rec.clone()));

        let mut want = vec![tenant, other];
        want.sort();
        assert_eq!(export.tenants_with_events(day).await.unwrap(), want);
        let all = export.export_all(day).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all.iter().find(|e| e.tenant == other).unwrap().count, 1);
        // the next day holds exactly the one later row
        assert_eq!(export.export_day(tenant, next).await.unwrap().count, 1);
    });
}

// ---------------------------------------------------------------------------------------------
// Operator commands
// ---------------------------------------------------------------------------------------------

async fn admission_round_trips_through_cluster_settings_and_gates_leases(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    on_db!(rig, |store| {
        let ops = AdminOps::new(store, "alice");
        assert_eq!(ops.admission().await.unwrap(), AdmissionMode::Open);
        assert_eq!(
            ops.set_admission(AdmissionMode::Frozen).await.unwrap(),
            AdmissionMode::Open
        );
        assert_eq!(LeaseRepo::admission(store).await.unwrap(), AdmissionMode::Frozen);
        assert!(!LeaseRepo::admission(store).await.unwrap().grants_leases());
        assert_eq!(admission_of(store).await.unwrap(), AdmissionMode::Frozen);

        // the scheduler consults this before claiming
        ops.set_admission(AdmissionMode::Drain).await.unwrap();
        assert!(!LeaseRepo::admission(store).await.unwrap().grants_leases());
        ops.set_admission(AdmissionMode::Open).await.unwrap();
        assert!(LeaseRepo::admission(store).await.unwrap().grants_leases());
    });
    let key = key_column(rig);
    // an unknown stored value is refused by the table, not silently open
    assert!(
        exec(
            db,
            &format!("UPDATE cluster_settings SET value = 'closed' WHERE {key} = 'scheduler.admission'"),
            &[]
        )
        .await
        .is_err(),
        "the CHECK constraint rejects unknown modes"
    );
    let events = audit_events(db).await;
    assert_eq!(
        events
            .iter()
            .filter(|(a, e)| a == "admin:alice" && e == "admin.admission")
            .count(),
        3
    );
}

async fn pause_resume_cancel_by_selector_write_events_and_audit(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    let other = TenantId::new();
    rig.insert_tenant(other.0).await.unwrap();
    on_db!(rig, |store| {
        let a = running_run(store, tenant).await;
        let b = running_run(store, tenant).await;
        let c = running_run(store, other).await;
        let ops = AdminOps::new(store, "bob");

        let paused = ops.pause(RunSelector::Crawl(a)).await.unwrap();
        assert_eq!(paused, vec![a]);
        assert_eq!(RunRepo::get(store, a).await.unwrap().status, RunStatus::Paused);
        assert_eq!(RunRepo::get(store, b).await.unwrap().status, RunStatus::Running);

        let paused = ops.pause(RunSelector::Tenant(tenant)).await.unwrap();
        assert_eq!(
            paused,
            vec![b],
            "a is already paused; c belongs to another tenant"
        );
        assert_eq!(RunRepo::get(store, c).await.unwrap().status, RunStatus::Running);

        let resumed = ops.resume(RunSelector::All).await.unwrap();
        assert_eq!(resumed.len(), 2);
        assert_eq!(RunRepo::get(store, a).await.unwrap().status, RunStatus::Running);

        // RB-11 level 2: freeze --all = frozen admission + pause everything
        ops.set_admission(AdmissionMode::Frozen).await.unwrap();
        let paused = ops.pause(RunSelector::All).await.unwrap();
        assert_eq!(paused.len(), 3);
        assert_eq!(RunRepo::get(store, c).await.unwrap().status, RunStatus::Paused);
        assert_eq!(
            count(
                db,
                "SELECT count(*) FROM crawl_runs WHERE run_id = ? AND pause_requested_at IS NOT NULL",
                &[V::Uuid(c.0)]
            )
            .await,
            1,
            "the SQL fallback column is set too"
        );
        assert_eq!(active_run_count(store).await.unwrap(), 3);

        assert!(ops.cancel(RunSelector::Crawl(a), "nope").await.is_err());
        let cancelled = ops.cancel(RunSelector::Crawl(a), "policy_stopped").await.unwrap();
        assert_eq!(cancelled, vec![a]);
        let row = RunRepo::get(store, a).await.unwrap();
        assert_eq!(row.status, RunStatus::Cancelled);
        assert_eq!(row.terminal_reason, Some(TerminalReason::PolicyStopped));
        assert!(RunRepo::list_sessions(store, a)
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
        assert_eq!(active_run_count(store).await.unwrap(), 2);

        let kinds = texts(
            db,
            "SELECT type FROM crawl_events WHERE run_id = ? ORDER BY seq",
            &[V::Uuid(a.0)],
        )
        .await;
        assert_eq!(kinds, vec!["paused", "resumed", "paused", "status", "completed"]);
        let events = audit_events(db).await;
        for e in ["admin.pause", "admin.resume", "admin.admission", "admin.cancel"] {
            assert!(
                events.iter().any(|(actor, ev)| actor == "admin:bob" && ev == e),
                "{e} missing in {events:?}"
            );
        }
    });
}

async fn drain_marks_a_registered_worker_and_heartbeat_reports_it(rig: &Rig) {
    rig.migrate().await;
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let worker = WorkerId::new();
        let ops = AdminOps::new(store, "carol");
        assert!(ops.drain_worker(worker).await.is_err(), "unknown worker");
        WorkerRegistry::register_worker(store, worker, "node-1", "0.1.0")
            .await
            .unwrap();
        assert!(!WorkerRegistry::worker_heartbeat(store, worker).await.unwrap());
        let run = running_run(store, tenant).await;
        let lease = LeaseRepo::claim_session(store, run, worker, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.session.run, run);
        assert_eq!(ops.drain_worker(worker).await.unwrap(), 1, "one lease held");
        assert!(
            WorkerRegistry::worker_heartbeat(store, worker).await.unwrap(),
            "heartbeat reports the drain"
        );
        let rows = ops.workers().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].draining && rows[0].leases_held == 1 && rows[0].hostname == "node-1");
        // re-registration (a restarted pod) clears the flag
        WorkerRegistry::register_worker(store, worker, "node-1", "0.1.1")
            .await
            .unwrap();
        assert!(!WorkerRegistry::worker_heartbeat(store, worker).await.unwrap());
        // a worker that never registered has no heartbeat to report
        assert!(!WorkerRegistry::worker_heartbeat(store, WorkerId::new())
            .await
            .unwrap());
    });
}

async fn reconcile_lists_open_actions_and_hands_unknown_sessions_to_recovery(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let run = running_run(store, tenant).await;
        let lease = LeaseRepo::claim_session(store, run, WorkerId::new(), true)
            .await
            .unwrap()
            .expect("a lease");
        let session = lease.session.id;
        let action = ActionJournal::propose(
            store,
            run,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
        let epoch = ObservationEpoch {
            navigation_seq: 1,
            document_seq: 1,
            mutation_seq: 0,
        };
        ActionJournal::intend(store, action, session, epoch)
            .await
            .unwrap();

        let ops = AdminOps::new(store, "dave");
        let open = ops.open_actions(None).await.unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].status, "intended");
        assert!(open[0].intended_at.is_some());
        assert_eq!(ops.open_actions(Some(action)).await.unwrap().len(), 1);
        assert!(ops.open_actions(Some(ActionId::new())).await.unwrap().is_empty());
        assert!(
            ops.request_reconcile(action).await.is_err(),
            "an intended row is not reconciled by hand; the reaper flips it first"
        );
        let expired = rig.database().db_now().await.unwrap() - Duration::minutes(1);
        exec(
            db,
            "UPDATE crawl_sessions SET lease_expires_at = ? WHERE session_id = ?",
            &[V::Ts(expired), V::Uuid(session.0)],
        )
        .await
        .unwrap();
        ActionJournal::mark_unknown(store, rig.database().db_now().await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            ActionJournal::get(store, action).await.unwrap().status,
            ActionStatus::Unknown
        );
        let status = ops.request_reconcile(action).await.unwrap();
        assert_eq!(
            status, "recovering",
            "a running session without a live lease hands over"
        );
        assert!(ops.request_reconcile(ActionId::new()).await.is_err());
    });
    assert!(audit_events(db)
        .await
        .iter()
        .any(|(a, e)| a == "admin:dave" && e == "admin.reconcile"));
}

async fn tenant_engine_flag_is_stored_and_audited(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let ops = AdminOps::new(store, "erin");
        assert_eq!(
            tenant_engine_of(store, tenant).await.unwrap(),
            Some(TenantEngine::Crawlx)
        );
        assert_eq!(
            ops.set_tenant_engine(tenant, TenantEngine::Upstream)
                .await
                .unwrap(),
            TenantEngine::Crawlx
        );
        assert_eq!(
            tenant_engine_of(store, tenant).await.unwrap(),
            Some(TenantEngine::Upstream)
        );
        assert!(ops
            .set_tenant_engine(TenantId::new(), TenantEngine::Shadow)
            .await
            .is_err());
        assert_eq!(tenant_engine_of(store, TenantId::new()).await.unwrap(), None);
        // the shadow run kind is accepted by the constraint, an unknown kind is not
        let run = running_run(store, tenant).await;
        exec(
            db,
            "UPDATE crawl_runs SET run_kind = 'shadow' WHERE run_id = ?",
            &[V::Uuid(run.0)],
        )
        .await
        .unwrap();
        assert!(exec(
            db,
            "UPDATE crawl_runs SET run_kind = 'mirror' WHERE run_id = ?",
            &[V::Uuid(run.0)]
        )
        .await
        .is_err());
    });
    assert!(audit_events(db)
        .await
        .iter()
        .any(|(a, e)| a == "admin:erin" && e == "admin.engine"));
}

async fn verify_artifacts_finds_missing_objects_and_digest_mismatches(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let run = running_run(store, tenant).await;
        let runs: Arc<dyn RunRepo> = Arc::new(store.clone());
        let artifacts =
            MemoryArtifactStore::in_memory(runs, Arc::new(SystemClock)).with_index(Arc::new(store.clone()));
        let ok = artifacts
            .put(run, Sensitivity::Content, "text/plain", b"fine")
            .await
            .unwrap();
        let gone = artifacts
            .put(run, Sensitivity::Content, "text/plain", b"will vanish")
            .await
            .unwrap();
        let bad = artifacts
            .put(run, Sensitivity::Content, "text/plain", b"will be corrupted")
            .await
            .unwrap();
        let keys: Vec<(Uuid, String)> = read_rows!(
            db,
            "SELECT artifact_id, object_key FROM artifacts ORDER BY artifact_id",
            &[],
            |row| (row.get::<Uuid, _>(0), row.get::<String, _>(1))
        );
        assert_eq!(keys.len(), 3);
        let blobs: &MemBlobs = artifacts.blobs();
        let key_of = |id: ArtifactId| keys.iter().find(|(k, _)| *k == id.0).unwrap().1.clone();
        blobs.delete(&key_of(gone.id)).await.unwrap();
        blobs.put(&key_of(bad.id), b"corrupted").await.unwrap();

        let ops = AdminOps::new(store, "frank");
        let v = ops.verify_artifacts(blobs, None).await.unwrap();
        assert_eq!(v.checked, 3);
        let defects: Vec<(Uuid, &str)> = v.defects.iter().map(|d| (d.artifact_id, d.defect)).collect();
        assert!(defects.contains(&(gone.id.0, "missing")), "{defects:?}");
        assert!(defects.contains(&(bad.id.0, "digest_mismatch")), "{defects:?}");
        assert!(!defects.iter().any(|(id, _)| *id == ok.id.0));
        assert_eq!(v.orphans, 0);

        // an orphan object with no row
        blobs.put("content/orphan/x/y", b"stray").await.unwrap();
        let v = ops.verify_artifacts(blobs, None).await.unwrap();
        assert_eq!(v.orphans, 1);
        let since = rig.database().db_now().await.unwrap() + Duration::seconds(1);
        let v = ops.verify_artifacts(blobs, Some(since)).await.unwrap();
        assert_eq!(v.checked, 0, "nothing created after `since`");
    });
}

async fn force_zdr_sweep_deletes_objects_then_rows_and_keeps_the_trail(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let store = store
            .clone()
            .with_delivery_buffer(Arc::new(crawlx_storage::DeliveryBuffer::new(
                Arc::new(SystemClock),
                crawlx_storage::BufferLimits::default(),
            )));
        let mut cfg = create_crawl("https://zdr.test/", &["anonymous"], 1);
        cfg.retention.mode = RetentionMode::Zdr;
        cfg.retention.days = 0;
        let run = crawl_run(tenant, cfg);
        RunRepo::create(&store, &run, None).await.unwrap();
        RunRepo::create_sessions(&store, &sessions(run.id, 1, 1))
            .await
            .unwrap();
        let runs: Arc<dyn RunRepo> = Arc::new(store.clone());
        let artifacts = Arc::new(
            MemoryArtifactStore::in_memory(runs, Arc::new(SystemClock)).with_index(Arc::new(store.clone())),
        );
        // metadata is the only class the ZDR write gate admits
        let meta = artifacts
            .put(run.id, Sensitivity::Metadata, "application/json", b"{}")
            .await
            .unwrap();
        let key = texts(
            db,
            "SELECT object_key FROM artifacts WHERE artifact_id = ?",
            &[V::Uuid(meta.id.0)],
        )
        .await
        .remove(0);
        assert!(artifacts.blobs().exists(&key).await.unwrap());
        let sweeper = RetentionSweeper::new(store.clone()).with_artifacts(artifacts.clone());
        let purged = force_zdr_sweep(&store, &sweeper, "admin:grace").await.unwrap();
        assert_eq!(purged, vec![run.id]);
        assert!(
            !artifacts.blobs().exists(&key).await.unwrap(),
            "object deleted first"
        );
        assert_eq!(
            count(
                db,
                "SELECT count(*) FROM artifacts WHERE artifact_id = ? AND deleted_at IS NOT NULL",
                &[V::Uuid(meta.id.0)]
            )
            .await,
            1,
            "row marked deleted afterwards"
        );
        assert!(
            RunRepo::get_metadata(&store, run.id).await.is_ok(),
            "the run row (structural trail) stays"
        );
        assert_eq!(RunRepo::list_sessions(&store, run.id).await.unwrap().len(), 1);
    });
    assert!(audit_events(db)
        .await
        .iter()
        .any(|(a, e)| a == "admin:grace" && e == "admin.zdr_force_sweep"));
}

// ---------------------------------------------------------------------------------------------
// Worker registry
// ---------------------------------------------------------------------------------------------

fn browser() -> BackendCapabilitiesV1 {
    BackendCapabilitiesV1::native_browser(BrowserBuildInfo {
        chromium_version: "registry-fixture-observed-build".into(),
        cdp_revision: "1.3".into(),
        user_agent: "registry-fixture".into(),
        pinned: false,
        launch_profile: LaunchProfile::Standard,
        console_capture: false,
        attached: false,
    })
}

const FRESH: StdDuration = StdDuration::from_secs(90);

async fn registry_never_unions_workers_and_keeps_an_eligible_worker_beyond_the_snapshot(rig: &Rig) {
    rig.migrate().await;
    on_any!(rig, |registry| {
        let required = vec!["native_http".to_owned(), "native_browser".to_owned()];
        assert!(registry
            .eligible_acquisition_worker(&required, FRESH)
            .await
            .unwrap()
            .is_none());
        // one worker per backend never satisfies a requirement that spans both
        let http_worker = WorkerId::new();
        let browser_worker = WorkerId::new();
        registry.register_worker(http_worker, "http", "1").await.unwrap();
        registry
            .register_worker(browser_worker, "browser", "1")
            .await
            .unwrap();
        registry
            .publish_acquisition_capabilities(
                http_worker,
                &[BackendCapabilitiesV1::native_http("fixture", "1")],
            )
            .await
            .unwrap();
        registry
            .publish_acquisition_capabilities(browser_worker, &[browser()])
            .await
            .unwrap();
        assert!(registry
            .eligible_acquisition_worker(&required, FRESH)
            .await
            .unwrap()
            .is_none());
        // unobserved evidence is refused
        let mut unobserved = BackendCapabilitiesV1::native_browser_unavailable("not_observed");
        unobserved.available = true;
        assert!(registry
            .publish_acquisition_capabilities(http_worker, &[unobserved])
            .await
            .is_err());
        // an unknown worker is not found
        assert!(matches!(
            registry
                .publish_acquisition_capabilities(WorkerId::new(), &[browser()])
                .await,
            Err(StoreError::NotFound { .. })
        ));

        // 300 more workers: the live snapshot is bounded, and the one eligible worker, ordered
        // after the snapshot, is still found
        let http = BackendCapabilitiesV1::native_http("crawlx-fetch/fixture", "1");
        for index in 1..=300u32 {
            let worker: WorkerId = format!("ffffffff-0000-0000-0000-{index:012x}").parse().unwrap();
            registry.register_worker(worker, "fixture", "1").await.unwrap();
            let capabilities = if index == 300 {
                vec![http.clone(), browser()]
            } else {
                vec![http.clone()]
            };
            registry
                .publish_acquisition_capabilities(worker, &capabilities)
                .await
                .unwrap();
        }
        let snapshot = registry.live_acquisition_workers(FRESH).await.unwrap();
        assert_eq!(snapshot.len(), WORKER_CAPABILITY_SNAPSHOT_LIMIT + 1);
        assert!(!snapshot.iter().any(|worker| worker.supports(&required)));
        let eligible = registry
            .eligible_acquisition_worker(&required, FRESH)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            eligible.worker.to_string(),
            "ffffffff-0000-0000-0000-00000000012c"
        );
        // a zero freshness window selects nothing
        assert!(registry
            .eligible_acquisition_worker(&required, StdDuration::ZERO)
            .await
            .unwrap()
            .is_none());
        assert!(registry
            .live_acquisition_workers(StdDuration::ZERO)
            .await
            .unwrap()
            .is_empty());
        // a restart clears the old build claims
        registry
            .register_worker(eligible.worker, "restarted", "2")
            .await
            .unwrap();
        assert!(
            registry
                .eligible_acquisition_worker(&required, FRESH)
                .await
                .unwrap()
                .is_none(),
            "restart must clear old build claims"
        );
        // invalid required ids are refused
        assert!(registry
            .eligible_acquisition_worker(&["bogus".to_owned()], FRESH)
            .await
            .is_err());
    });
}

async fn local_executor_never_satisfies_queued_capability_admission(rig: &Rig) {
    rig.migrate().await;
    on_any!(rig, |registry| {
        let worker = WorkerId::new();
        let required = vec!["native_http".to_owned()];
        let capabilities = [BackendCapabilitiesV1::native_http("fixture", "1")];
        registry.register_worker(worker, "local", "1").await.unwrap();
        registry
            .publish_local_acquisition_capabilities(worker, CrawlRunId::new(), &capabilities)
            .await
            .unwrap();
        assert!(registry.live_acquisition_workers(FRESH).await.unwrap().is_empty());
        assert!(registry
            .eligible_acquisition_worker(&required, FRESH)
            .await
            .unwrap()
            .is_none());
        registry
            .publish_acquisition_capabilities(worker, &capabilities)
            .await
            .unwrap();
        assert_eq!(
            registry
                .eligible_acquisition_worker(&required, FRESH)
                .await
                .unwrap()
                .unwrap()
                .worker,
            worker
        );
    });
}

async fn registry_excludes_stale_draining_and_restarted_workers(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    on_db!(rig, |store| {
        let worker = WorkerId::new();
        let required = vec!["native_http".to_owned(), "native_browser".to_owned()];
        WorkerRegistry::register_worker(store, worker, "fixture", "1")
            .await
            .unwrap();
        WorkerRegistry::publish_acquisition_capabilities(
            store,
            worker,
            &[BackendCapabilitiesV1::native_http("fixture", "1"), browser()],
        )
        .await
        .unwrap();
        assert_eq!(
            WorkerRegistry::eligible_acquisition_worker(store, &required, FRESH)
                .await
                .unwrap()
                .unwrap()
                .worker,
            worker
        );
        AdminOps::new(store, "fixture")
            .drain_worker(worker)
            .await
            .unwrap();
        assert!(
            WorkerRegistry::eligible_acquisition_worker(store, &required, FRESH)
                .await
                .unwrap()
                .is_none()
        );
        WorkerRegistry::register_worker(store, worker, "fixture", "2")
            .await
            .unwrap();
        assert!(WorkerRegistry::live_acquisition_workers(store, FRESH)
            .await
            .unwrap()
            .is_empty());
        WorkerRegistry::publish_acquisition_capabilities(
            store,
            worker,
            &[BackendCapabilitiesV1::native_http("fixture", "2"), browser()],
        )
        .await
        .unwrap();
        // data capabilities are published into the same document and read back with it
        let mut facts = crawlx_core::data_capabilities::WorkerDataCapabilitiesV1::default();
        facts.destinations.insert("sink-a".to_owned(), true);
        WorkerRegistry::publish_data_capabilities(store, worker, &facts)
            .await
            .unwrap();
        let live = WorkerRegistry::live_acquisition_workers(store, FRESH)
            .await
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].data, facts);
        let mut wanted = crawlx_core::data_capabilities::WorkerDataRequirementsV1::default();
        wanted.destinations.insert("sink-a".to_owned(), true);
        assert!(
            WorkerRegistry::eligible_data_worker(store, &required, &wanted, FRESH)
                .await
                .unwrap()
                .is_some()
        );
        wanted.destinations.insert("sink-b".to_owned(), false);
        assert!(
            WorkerRegistry::eligible_data_worker(store, &required, &wanted, FRESH)
                .await
                .unwrap()
                .is_none()
        );
        // a heartbeat older than the window removes the worker
        let stale = rig.database().db_now().await.unwrap() - Duration::seconds(91);
        exec(
            db,
            "UPDATE workers SET last_heartbeat_at = ? WHERE worker_id = ?",
            &[V::Ts(stale), V::Uuid(worker.0)],
        )
        .await
        .unwrap();
        assert!(
            WorkerRegistry::eligible_acquisition_worker(store, &required, FRESH)
                .await
                .unwrap()
                .is_none()
        );
        assert!(WorkerRegistry::live_acquisition_workers(store, FRESH)
            .await
            .unwrap()
            .is_empty());
        // and a heartbeat brings it back
        WorkerRegistry::worker_heartbeat(store, worker).await.unwrap();
        assert!(
            WorkerRegistry::eligible_acquisition_worker(store, &required, FRESH)
                .await
                .unwrap()
                .is_some()
        );
    });
}

// ---------------------------------------------------------------------------------------------
// Retention sweeps
// ---------------------------------------------------------------------------------------------

/// Retention compliance: an artifact past `expires_at` is counted until the sweeper runs; after
/// the sweep the count and the gauge are 0 and the object is gone.
async fn overdue_artifacts_count_until_the_sweeper_runs_then_zero(rig: &Rig) {
    rig.migrate().await;
    let _turn = METRICS.lock().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let t0 = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
        let clock = Arc::new(crawlx_core::time::ManualClock::new(t0));
        let run = running_run(store, tenant).await;
        let days = i64::from(RunRepo::get(store, run).await.unwrap().config.retention.days);
        assert!(days > 0, "the testkit run must have a finite retention");
        let dir = tempfile::tempdir().unwrap();
        let runs: Arc<dyn RunRepo> = Arc::new(store.clone());
        let fs = FsArtifactStore::open(dir.path(), runs, clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(store.clone()));
        let r = fs
            .put(run, Sensitivity::Content, "text/markdown", b"# overdue")
            .await
            .unwrap();
        let key = format!("content/{tenant}/{run}/{}", r.digest.to_hex());
        assert!(dir.path().join(&key).is_file());
        let sweeper = RetentionSweeper::new(store.clone()).with_artifacts(Arc::new(fs));

        // before expiry nothing is overdue
        assert!(sweeper.overdue_artifacts(t0).await.unwrap().is_empty());

        // past expiry, before any sweep: the artifact is overdue and still present
        let later = t0 + Duration::days(days) + Duration::hours(1);
        clock.advance_ms((later - t0).num_milliseconds());
        let overdue = sweeper.overdue_artifacts(later).await.unwrap();
        assert_eq!(overdue.get("standard").copied(), Some(1), "{overdue:?}");
        assert!(dir.path().join(&key).is_file(), "not swept yet");

        // the sweep removes it; the count and the published gauge drop to 0
        let report = sweeper.sweep(later).await.unwrap();
        assert_eq!(report.artifacts_deleted, 1);
        assert!(!dir.path().join(&key).exists(), "object removed by the sweep");
        assert!(sweeper.overdue_artifacts(later).await.unwrap().is_empty());
        let gauge = crawlx_telemetry::Metrics::global()
            .gauge(crawlx_telemetry::metrics::names::RETENTION_OVERDUE_ARTIFACTS);
        for kind in ["standard", "extended", "zdr"] {
            assert_eq!(gauge.get(&[("kind", kind)]), Some(0.0), "{kind}");
        }
        assert_eq!(
            count(
                db,
                "SELECT count(*) FROM artifacts WHERE run_id = ? AND deleted_at IS NULL",
                &[V::Uuid(run.0)]
            )
            .await,
            0
        );
    });
}

/// RB-08: a non-metadata artifact row of a ZDR run (one that got past the write gate) is a
/// violation. The sweeper counts it the first time it sees the row, not again on the next
/// sweep; the gate counts every refusal.
async fn sweeper_counts_each_zdr_artifact_row_once(rig: &Rig) {
    use crawlx_telemetry::metrics::names;
    rig.migrate().await;
    let _turn = METRICS.lock().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        // a zero-retention run keeps its operational record in the volatile delivery store
        let store =
            &store
                .clone()
                .with_delivery_buffer(Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(Arc::new(
                    SystemClock,
                ))));
        let mut cfg = create_crawl("https://example.test/", &[], 1);
        cfg.retention.mode = RetentionMode::Zdr;
        cfg.retention.days = 0;
        let zdr = crawl_run(tenant, cfg);
        RunRepo::create(store, &zdr, None).await.unwrap();
        let violations = crawlx_telemetry::Metrics::global().counter(names::ZDR_VIOLATIONS);
        let before = violations.get(&[]);

        let mem = MemoryArtifactStore::in_memory(Arc::new(store.clone()), Arc::new(SystemClock));
        assert!(matches!(
            mem.put(zdr.id, Sensitivity::Content, "text/html", b"x").await,
            Err(StoreError::RetentionDenied(_))
        ));
        assert_eq!(violations.get(&[]), before + 1, "the gate counts its refusal");

        let sweeper = RetentionSweeper::new(store.clone());
        sweeper.sweep(Utc::now()).await.unwrap();
        assert_eq!(
            violations.get(&[]),
            before + 1,
            "no zdr content row: nothing to count"
        );

        // a content row written behind the gate's back
        let rogue = ArtifactId::new();
        exec(
            db,
            "INSERT INTO artifacts (artifact_id, tenant_id, run_id, kind, bucket, object_key, size_bytes, content_digest, content_type, sensitivity) \
             VALUES (?, ?, ?, 'html', 'fs', ?, 1, ?, 'text/html', 'content')",
            &[
                V::Uuid(rogue.0),
                V::Uuid(tenant.0),
                V::Uuid(zdr.id.0),
                V::Text(format!("content/{tenant}/{}/rogue", zdr.id)),
                V::Bytes(vec![0]),
            ],
        )
        .await
        .unwrap();
        assert_eq!(sweeper.zdr_violations().await.unwrap(), vec![rogue]);
        sweeper.sweep(Utc::now()).await.unwrap();
        assert_eq!(
            violations.get(&[]),
            before + 2,
            "the row is counted on first sight"
        );
        sweeper.sweep(Utc::now()).await.unwrap();
        assert_eq!(violations.get(&[]), before + 2, "and not again while it lingers");
        // a fresh sweeper has no memory of it
        RetentionSweeper::new(store.clone())
            .sweep(Utc::now())
            .await
            .unwrap();
        assert_eq!(violations.get(&[]), before + 3);
    });
}

async fn sweeper_purges_expired_runs_and_chains_the_audit_log(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        run.created_at = Utc::now() - Duration::days(30);
        run.status = RunStatus::Completed;
        run.terminal_reason = Some(TerminalReason::FrontierExhausted);
        RunRepo::create(store, &run, None).await.unwrap();
        RunRepo::create_sessions(store, &sessions(run.id, 1, 1))
            .await
            .unwrap();
        EventRepo::append(store, run.id, "k", serde_json::json!({}))
            .await
            .unwrap();
        // a row of the run in a table the purge deletes before the run itself
        exec(
            db,
            "INSERT INTO idempotency_keys (tenant_id, idem_key, request_hash, state, run_id, expires_at) \
             VALUES (?, 'key-1', ?, 'done', ?, ?)",
            &[
                V::Uuid(tenant.0),
                V::Bytes(vec![1; 32]),
                V::Uuid(run.id.0),
                V::Ts(Utc::now() + Duration::days(1)),
            ],
        )
        .await
        .unwrap();
        let fresh = running_run(store, tenant).await; // not expired: must survive
        let report = RetentionSweeper::new(store.clone())
            .sweep(Utc::now())
            .await
            .unwrap();
        assert_eq!(report.runs_purged, 1);
        assert!(report.rows_deleted >= 3, "{report:?}");
        assert!(matches!(
            RunRepo::get(store, run.id).await,
            Err(StoreError::NotFound { .. })
        ));
        for table in ["crawl_sessions", "crawl_events", "idempotency_keys"] {
            assert_eq!(
                count(
                    db,
                    &format!("SELECT count(*) FROM {table} WHERE run_id = ?"),
                    &[V::Uuid(run.id.0)]
                )
                .await,
                0,
                "{table}"
            );
        }
        assert!(RunRepo::get(store, fresh).await.is_ok());
        let audit = blob_pairs(
            db,
            "SELECT prev_hash, entry_hash FROM audit_events ORDER BY audit_id",
        )
        .await;
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].0, vec![0u8; 32], "chain starts from the zero hash");
        assert_eq!(
            texts(db, "SELECT event FROM audit_events", &[]).await,
            vec!["run.purged".to_owned()]
        );
        // a second pass has nothing left to purge and appends nothing
        let again = RetentionSweeper::new(store.clone())
            .sweep(Utc::now())
            .await
            .unwrap();
        assert_eq!(again.runs_purged, 0);
        assert_eq!(count(db, "SELECT count(*) FROM audit_events", &[]).await, 1);
    });
}

/// Erasure closes HEAD publication first: the run becomes terminal before any row is deleted,
/// a missing run is not found, and two concurrent purges of one run neither deadlock nor
/// break the audit chain.
async fn erasure_closes_the_run_before_its_rows_are_purged(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    on_db!(rig, |store| {
        let run = running_run(store, tenant).await;
        let sweeper = RetentionSweeper::new(store.clone());
        assert_eq!(sweeper.begin_run_erasure(run).await.unwrap(), tenant);
        let row = RunRepo::get(store, run).await.unwrap();
        assert_eq!(row.status, RunStatus::Cancelled);
        assert_eq!(row.terminal_reason, Some(TerminalReason::Cancelled));
        assert!(row.finished_at.is_some());
        // already terminal: the state is kept, not rewritten
        assert_eq!(sweeper.begin_run_erasure(run).await.unwrap(), tenant);
        assert!(matches!(
            sweeper.begin_run_erasure(CrawlRunId::new()).await,
            Err(StoreError::NotFound { .. })
        ));
        assert_eq!(sweeper.purge_run_objects(run).await.unwrap(), 0);

        let racing = running_run(store, tenant).await;
        let first = RetentionSweeper::new(store.clone());
        let second = RetentionSweeper::new(store.clone());
        let (a, b) = tokio::join!(first.purge_run(racing), second.purge_run(racing));
        assert!(
            a.is_ok() || b.is_ok(),
            "at least one purge completes: {a:?} / {b:?}"
        );
        for outcome in [a, b] {
            if let Err(error) = outcome {
                assert!(matches!(error, StoreError::NotFound { .. }), "{error:?}");
            }
        }
        assert!(matches!(
            RunRepo::get(store, racing).await,
            Err(StoreError::NotFound { .. })
        ));
        let audit = blob_pairs(
            db,
            "SELECT prev_hash, entry_hash FROM audit_events ORDER BY audit_id",
        )
        .await;
        assert!(!audit.is_empty());
        for pair in audit.windows(2) {
            assert_eq!(pair[1].0, pair[0].1, "the chain stays unbroken");
        }
    });
}

async fn authorization_records_are_removed_after_the_audit_horizon(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    let tenant = tenant(rig).await;
    let key = Uuid::now_v7();
    let scopes = if is_postgres(rig) { "'{}'" } else { "'[]'" };
    exec(
        db,
        &format!(
            "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes) VALUES (?, ?, 'sweep_auth', ?, {scopes})"
        ),
        &[V::Uuid(key), V::Uuid(tenant.0), V::Bytes(b"hash".to_vec())],
    )
    .await
    .unwrap();
    let now = Utc::now();
    let old = now - Duration::days(1_200);
    let recent = now - Duration::days(10);
    let mut ids = Vec::new();
    for (valid_to, digest) in [(old, 0xa1u8), (recent, 0xb2)] {
        let id = Uuid::now_v7();
        ids.push(id);
        exec(
            db,
            "INSERT INTO authorization_records (record_id, tenant_id, version, body, body_digest, valid_from, valid_to, created_by, created_at) \
             VALUES (?, ?, 1, '{}', ?, ?, ?, ?, ?)",
            &[
                V::Uuid(id),
                V::Uuid(tenant.0),
                V::Bytes(vec![digest; 32]),
                V::Ts(valid_to - Duration::days(30)),
                V::Ts(valid_to),
                V::Uuid(key),
                V::Ts(valid_to - Duration::days(30)),
            ],
        )
        .await
        .unwrap();
    }
    on_db!(rig, |store| {
        let sweeper = RetentionSweeper::new(store.clone());
        assert_eq!(sweeper.sweep_authorizations(now).await.unwrap(), 1);
        assert_eq!(
            count(
                db,
                "SELECT count(*) FROM authorization_records WHERE record_id = ?",
                &[V::Uuid(ids[0])]
            )
            .await,
            0,
            "the record past the horizon is gone"
        );
        assert_eq!(
            count(
                db,
                "SELECT count(*) FROM authorization_records WHERE record_id = ?",
                &[V::Uuid(ids[1])]
            )
            .await,
            1,
            "a recent record stays"
        );
        assert_eq!(sweeper.sweep_authorizations(now).await.unwrap(), 0);
    });
    // the purge is audited atomically, with the digest and never the body
    let events = audit_events(db).await;
    assert_eq!(
        events,
        vec![("retention_sweeper".to_owned(), "authorization.purged".to_owned())]
    );
    let subject = texts(db, "SELECT subject FROM audit_events", &[]).await.remove(0);
    let subject: serde_json::Value = serde_json::from_str(&subject).unwrap();
    assert_eq!(subject["record_id"], ids[0].to_string());
    assert_eq!(subject["bodyDigest"], Digest([0xa1; 32]).to_hex());
}

/// Scheduled retention passes mutate rows at a controlled cadence.
async fn sweep_loop_deletes_expired_rows_on_each_tick_and_stops_on_cancel(rig: &Rig) {
    rig.migrate().await;
    let db = rig.database();
    // One isolated table suffices: this covers scheduling and real database I/O, not the
    // multi-table retention policy.
    exec(
        db,
        "CREATE TABLE sweep_loop_items (id BIGINT PRIMARY KEY, expires_at BIGINT NOT NULL)",
        &[],
    )
    .await
    .unwrap();
    exec(db, "INSERT INTO sweep_loop_items VALUES (1, 0), (2, 10)", &[])
        .await
        .unwrap();

    tokio::time::pause();
    let started = tokio::time::Instant::now();
    // Keep the runtime runnable while database sockets wait, preventing paused time from
    // auto-advancing to the loop's timeout during real database I/O.
    let keep_awake = CancellationToken::new();
    let awake = keep_awake.clone();
    let clock_guard = tokio::spawn(async move {
        while !awake.is_cancelled() {
            tokio::task::yield_now().await;
        }
    });
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let database = db.clone();
    let (observed, mut passes) = tokio::sync::mpsc::channel(4);
    let handle = tokio::spawn(async move {
        run_sweep_loop(
            SweepLoopConfig::every(StdDuration::from_secs(10)),
            &stop,
            || {
                let database = database.clone();
                async move {
                    let now = i64::try_from(started.elapsed().as_secs()).unwrap();
                    let deleted = exec(
                        &database,
                        "DELETE FROM sweep_loop_items WHERE expires_at <= ?",
                        &[V::Int(now)],
                    )
                    .await
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                    Ok(SweepReport {
                        rows_deleted: deleted,
                        ..SweepReport::default()
                    })
                }
            },
            |pass, outcome| {
                observed
                    .try_send((pass, outcome.as_ref().unwrap().rows_deleted))
                    .unwrap();
            },
        )
        .await
    });
    // Register the immediate interval tick, then cross the timer wheel's millisecond rounding
    // boundary explicitly; the runnable guard deliberately disables auto-advance.
    tokio::task::yield_now().await;
    tokio::time::advance(StdDuration::from_millis(1)).await;

    assert_eq!(passes.recv().await, Some((1, 1)));
    assert_eq!(started.elapsed(), StdDuration::from_millis(1));
    exec(db, "INSERT INTO sweep_loop_items VALUES (3, 5)", &[])
        .await
        .unwrap();
    tokio::time::advance(StdDuration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert!(passes.try_recv().is_err());
    let retained = read_rows!(db, "SELECT id FROM sweep_loop_items ORDER BY id", &[], |row| row
        .get::<i64, _>(
        0
    ));
    assert_eq!(retained, [2, 3]);

    tokio::time::advance(StdDuration::from_secs(1)).await;
    assert_eq!(passes.recv().await, Some((2, 2)));
    assert_eq!(count(db, "SELECT count(*) FROM sweep_loop_items", &[]).await, 0);
    cancel.cancel();
    let summary = handle.await.unwrap();
    assert_eq!((summary.passes, summary.failures), (2, 0));
    assert!(passes.recv().await.is_none());
    keep_awake.cancel();
    clock_guard.await.unwrap();
    tokio::time::resume();
}

// ---------------------------------------------------------------------------------------------
// Artifact index
// ---------------------------------------------------------------------------------------------

async fn artifact_index_records_reads_retention_and_marks_deleted_once(rig: &Rig) {
    rig.migrate().await;
    // every engine keys an artifact row to a tenant and a run that exist
    let (tenant, run) = if rig.kind().is_some() {
        let tenant = tenant(rig).await;
        let run = on_db!(rig, |store| running_run(store, tenant).await);
        (tenant, run)
    } else {
        let tenant = TenantId::new();
        (tenant, running_run(rig.store().as_ref(), tenant).await)
    };
    let micros = |value: i64| DateTime::from_timestamp_micros(value).unwrap();
    let created = micros(1_800_000_000_123_456);
    let expires = micros(1_900_000_000_654_321);
    let row = |object: &str| ArtifactRow {
        id: ArtifactId::new(),
        tenant,
        run,
        kind: "html".to_owned(),
        bucket: "fs".to_owned(),
        object_key: format!("content/{tenant}/{run}/{object}"),
        size_bytes: 11,
        digest: Digest([0x5a; 32]),
        content_type: "text/html".to_owned(),
        sensitivity: Sensitivity::Content,
        created_at: created,
        expires_at: Some(expires),
    };
    let first = row("one");
    let permanent = ArtifactRow {
        expires_at: None,
        ..row("two")
    };
    let stranger = ArtifactId::new();
    on_any!(rig, |index| {
        ArtifactIndex::record(index, &first).await.unwrap();
        ArtifactIndex::record(index, &permanent).await.unwrap();
        // the stored deadline is exactly the one written, to the microsecond
        let kept = ArtifactIndex::retention(index, first.id).await.unwrap().unwrap();
        assert_eq!(kept.expires_at, Some(expires));
        assert_eq!(kept.deleted_at, None);
        assert_eq!(
            ArtifactIndex::retention(index, permanent.id)
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            None
        );
        assert!(ArtifactIndex::retention(index, stranger).await.unwrap().is_none());

        // an empty list and an unknown id change nothing
        ArtifactIndex::mark_deleted(index, &[]).await.unwrap();
        ArtifactIndex::mark_deleted(index, &[stranger]).await.unwrap();
        assert_eq!(
            ArtifactIndex::retention(index, first.id)
                .await
                .unwrap()
                .unwrap()
                .deleted_at,
            None
        );

        ArtifactIndex::mark_deleted(index, &[first.id, stranger])
            .await
            .unwrap();
        if rig.kind().is_none() {
            // the in-memory index forgets a row it is told to delete
            assert!(ArtifactIndex::retention(index, first.id).await.unwrap().is_none());
        } else {
            let deleted = ArtifactIndex::retention(index, first.id).await.unwrap().unwrap();
            assert!(deleted.deleted_at.is_some());
            // marking again keeps the first acknowledgement
            ArtifactIndex::mark_deleted(index, &[first.id]).await.unwrap();
            assert_eq!(
                ArtifactIndex::retention(index, first.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .deleted_at,
                deleted.deleted_at
            );
        }
        assert_eq!(
            ArtifactIndex::retention(index, permanent.id)
                .await
                .unwrap()
                .unwrap()
                .deleted_at,
            None,
            "only the named uses are marked"
        );
    });
    if rig.kind().is_some() {
        on_db!(rig, |store| {
            // one row per use: the same id twice, or a run that does not exist, is a conflict
            assert!(matches!(
                ArtifactIndex::record(store, &first).await,
                Err(StoreError::Conflict(_))
            ));
            let orphan = ArtifactRow {
                run: CrawlRunId::new(),
                ..row("three")
            };
            assert!(matches!(
                ArtifactIndex::record(store, &orphan).await,
                Err(StoreError::Conflict(_))
            ));
        });
    }
}

// ---------------------------------------------------------------------------------------------
// The independent safety auditor needs two database identities
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn safety_auditor_refuses_engines_without_two_identities() {
    let sqlite = SafetyAuditor::connect("sqlite:///tmp/crawlx-reader.db", "sqlite:///tmp/crawlx-pauser.db")
        .await
        .unwrap_err();
    assert!(
        matches!(&sqlite, StoreError::Conflict(text) if text.starts_with("refused: sqlite_safety_auditor: ")),
        "{sqlite:?}"
    );
    let mariadb = SafetyAuditor::connect("mariadb://u:p@127.0.0.1:1/db", "mariadb://v:p@127.0.0.1:1/db")
        .await
        .unwrap_err();
    assert!(
        matches!(&mariadb, StoreError::Conflict(text) if text.starts_with("refused: backend_unimplemented: ")),
        "{mariadb:?}"
    );
    let unknown = SafetyAuditor::connect("ftp://h/db", "ftp://h/db")
        .await
        .unwrap_err();
    assert!(
        matches!(&unknown, StoreError::Conflict(text) if text.starts_with("refused: scheme: ")),
        "{unknown:?}"
    );
    // one SQLite URL is enough to refuse, whichever side it is on
    let mixed = SafetyAuditor::connect("postgres://u:p@127.0.0.1:1/db", "sqlite:///tmp/x.db")
        .await
        .unwrap_err();
    assert!(
        matches!(&mixed, StoreError::Conflict(text) if text.starts_with("refused: sqlite_safety_auditor: ")),
        "{mixed:?}"
    );
}
