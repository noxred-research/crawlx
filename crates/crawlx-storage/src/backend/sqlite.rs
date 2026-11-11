//! SQLite: single host, WAL, one writer.
//!
//! Every transaction that writes starts with `BEGIN IMMEDIATE` ([`Concurrency::begin_write`])
//! behind an in-process semaphore, so writers queue in this process instead of spinning on
//! `busy_timeout`; only contention with another process (API next to worker) retries, with
//! jitter, until a deadline. A deferred transaction that reads and then writes can fail
//! with `SQLITE_BUSY_SNAPSHOT` without ever invoking the busy handler, which is why no write
//! path may use a plain `BEGIN`.

use super::dialect::SqliteDialect;
use super::strategy::{
    AuditEntry, Concurrency, FenceSeq, FrontierClaim, LockMode, MonitorClaim, OutboxClaim, Query,
    SessionClaim, TrafficRow, WebhookClaim, WriteTx,
};
use super::{Backend, BackendKind, BackendRefusal, DatabaseUrl};
use crate::error::db;
use crate::store::{Store, StoreConfig};
use crawlx_core::StoreError;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Sqlite, SqliteConnection, SqlitePool, Transaction};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// The SQLite migrations, embedded at build time.
pub(crate) static MIGRATOR: Migrator = sqlx::migrate!("./migrations/sqlite");

/// SQLite is retried this many times `busy_timeout` before a write transaction gives up.
const WRITE_DEADLINE_FACTOR: u32 = 6;

/// Upper bound on `BEGIN IMMEDIATE` attempts, whatever the deadline: each attempt waits at
/// least its backoff, so the deadline normally ends the loop first.
const WRITE_MAX_ATTEMPTS: u32 = 64;

/// A SQLite pool with the in-process writer gate.
#[derive(Clone, Debug)]
pub struct SqliteHandle {
    pub(crate) pool: SqlitePool,
    writer: Arc<Semaphore>,
    write_deadline: Duration,
    path: Option<PathBuf>,
}

impl SqliteHandle {
    /// The database file, `None` for an in-memory database.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl Deref for SqliteHandle {
    type Target = SqlitePool;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

/// The SQLite backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct SqliteBackend;

impl super::sealed::Sealed for SqliteBackend {}

impl Backend for SqliteBackend {
    type Db = Sqlite;
    type Pool = SqliteHandle;
    type Dialect = SqliteDialect;
    const KIND: BackendKind = BackendKind::Sqlite;

    fn pool_in_use(pool: &Self::Pool) -> u32 {
        let idle = u32::try_from(pool.pool.num_idle()).unwrap_or(u32::MAX);
        pool.pool.size().saturating_sub(idle)
    }
}

/// Filesystems WAL cannot work on: shared memory needs one host. `statfs` magic numbers.
#[cfg(target_os = "linux")]
const NETWORK_FILESYSTEMS: &[u64] = &[
    0x0000_6969, // NFS
    0x0000_517B, // SMB
    0xFE53_4D42, // SMB2
    0xFF53_4D42, // CIFS
    0x0102_1997, // 9p
    0x5346_414F, // AFS
    0x7375_7245, // coda
    0x00C3_6400, // Ceph
    0x0BD0_0BD0, // Lustre
];

/// Refuse a database file on a network filesystem (refusal R2).
#[cfg(target_os = "linux")]
fn check_local_filesystem(path: &Path) -> Result<(), BackendRefusal> {
    // The file may not exist yet: ask the closest existing ancestor.
    let mut probe = path;
    let existing = loop {
        if probe.exists() {
            break probe;
        }
        match probe.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => probe = parent,
            _ => break Path::new("."),
        }
    };
    let Ok(stat) = rustix::fs::statfs(existing) else {
        return Ok(());
    };
    let kind = u64::try_from(stat.f_type).unwrap_or(0);
    if NETWORK_FILESYSTEMS.contains(&kind) {
        return Err(BackendRefusal::sqlite_not_local(&path.display().to_string()));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_local_filesystem(_path: &Path) -> Result<(), BackendRefusal> {
    Ok(())
}

/// Open the pool with WAL, foreign keys, `FULL` synchronous and a busy timeout.
pub(crate) async fn open(url: &DatabaseUrl, cfg: StoreConfig) -> Result<Store<SqliteBackend>, StoreError> {
    if cfg.statement_timeout.is_some() {
        return Err(StoreError::Conflict(
            "sqlite has no server-side statement timeout; remove database.statement_timeout_ms".to_owned(),
        ));
    }
    let memory = url.is_sqlite_memory();
    if memory && !cfg.allow_memory {
        return Err(BackendRefusal::sqlite_not_local(":memory:").into());
    }
    let path = url.sqlite_path();
    if let Some(path) = &path {
        check_local_filesystem(path)?;
    }
    let mut options = SqliteConnectOptions::from_str(url.expose())
        .map_err(db)?
        .create_if_missing(cfg.create_if_missing)
        .foreign_keys(true)
        .busy_timeout(cfg.busy_timeout)
        .synchronous(SqliteSynchronous::Full)
        .pragma("trusted_schema", "OFF")
        .pragma("cell_size_check", "ON");
    let mut pool_options = SqlitePoolOptions::new()
        .acquire_timeout(cfg.acquire_timeout)
        .test_before_acquire(cfg.test_before_acquire);
    if memory {
        // every connection of an in-memory database is its own database: keep exactly one
        // alive for the life of the pool
        pool_options = pool_options
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None);
    } else {
        // sqlx leaves journal_mode unset (delete); WAL persists in the file
        options = options.journal_mode(SqliteJournalMode::Wal);
        pool_options = pool_options.max_connections(cfg.max_connections);
    }
    let pool = pool_options.connect_with(options).await.map_err(db)?;
    let handle = SqliteHandle {
        pool,
        writer: Arc::new(Semaphore::new(1)),
        write_deadline: cfg.busy_timeout.saturating_mul(WRITE_DEADLINE_FACTOR),
        path,
    };
    Ok(Store::from_parts(handle, cfg))
}

/// Apply the SQLite migrations behind the in-process writer gate.
pub(crate) async fn migrate(store: &Store<SqliteBackend>) -> Result<(), StoreError> {
    let _writer = store
        .pool
        .writer
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StoreError::Unavailable("the sqlite writer gate is closed".to_owned()))?;
    MIGRATOR
        .run(&store.pool.pool)
        .await
        .map_err(|source| StoreError::Database {
            source: Box::new(source),
            retryable: true,
        })
}

/// Host time at the microsecond resolution of stored instants: SQLite runs on one host, so the
/// database clock is the process clock.
pub(crate) fn db_now() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    chrono::DateTime::from_timestamp_micros(now.timestamp_micros()).unwrap_or(now)
}

/// Exclusive claim on a SQLite database file by a worker process, held until dropped.
#[derive(Debug)]
#[must_use = "the lock is released when this value is dropped"]
pub struct WorkerLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl WorkerLock {
    /// The lock file (`<database>.worker.lock`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Take the exclusive worker lock of the database at `database` (refusal R1 when held).
pub(crate) fn acquire_worker_lock(database: &Path) -> Result<WorkerLock, StoreError> {
    let mut name = database.as_os_str().to_owned();
    name.push(".worker.lock");
    let path = PathBuf::from(name);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|error| StoreError::Backend(format!("cannot open {}: {error}", path.display())))?;
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(WorkerLock { _file: file, path }),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(BackendRefusal::sqlite_second_worker(database).into()),
        Err(error) => Err(StoreError::Backend(format!(
            "cannot lock {}: {error}",
            path.display()
        ))),
    }
}

fn is_busy(error: &sqlx::Error) -> bool {
    crate::error::sqlite_primary_code(error).is_some_and(|code| code == 5 || code == 6)
}

impl Concurrency for SqliteBackend {
    async fn begin_write(handle: &SqliteHandle) -> Result<WriteTx<Sqlite>, StoreError> {
        let permit = handle
            .writer
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| StoreError::Unavailable("the sqlite writer gate is closed".to_owned()))?;
        let deadline = Instant::now() + handle.write_deadline;
        let mut attempt: u32 = 0;
        loop {
            match handle.pool.begin_with("BEGIN IMMEDIATE").await {
                Ok(tx) => return Ok(WriteTx::new(tx, Some(permit))),
                Err(error)
                    if is_busy(&error) && attempt + 1 < WRITE_MAX_ATTEMPTS && Instant::now() < deadline =>
                {
                    // cross-process contention: back off with jitter so two tight loops do
                    // not starve each other
                    let jitter = u64::from(Uuid::now_v7().as_bytes()[15] % 32);
                    let base = 5_u64.saturating_mul(1 << attempt.min(4));
                    tokio::time::sleep(Duration::from_millis(base + jitter)).await;
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => return Err(db(error)),
            }
        }
    }

    async fn begin_read(handle: &SqliteHandle) -> Result<Transaction<'static, Sqlite>, StoreError> {
        // a deferred BEGIN: in WAL a reader sees the last commit while a writer proceeds
        handle.pool.begin().await.map_err(db)
    }

    async fn db_now(_handle: &SqliteHandle) -> Result<crate::backend::strategy::Timestamp, StoreError> {
        Ok(db_now())
    }

    async fn next_fence(conn: &mut SqliteConnection, seq: FenceSeq) -> Result<i64, StoreError> {
        sqlx::query_scalar("UPDATE crawlx_sequences SET v = v + 1 WHERE name = ?1 RETURNING v")
            .bind(seq.name())
            .fetch_one(conn)
            .await
            .map_err(db)
    }

    async fn xact_lock(_conn: &mut SqliteConnection, _key: &str, _mode: LockMode) -> Result<(), StoreError> {
        // a write transaction already holds the database write lock
        Ok(())
    }

    async fn claim_sessions(
        handle: &SqliteHandle,
        claim: SessionClaim<'_>,
    ) -> Result<Option<SqliteRow>, StoreError> {
        super::sqlite_claims::claim_sessions(handle, claim).await
    }

    async fn claim_frontier_batch(
        handle: &SqliteHandle,
        claim: FrontierClaim<'_>,
    ) -> Result<Vec<SqliteRow>, StoreError> {
        super::sqlite_claims::claim_frontier_batch(handle, claim).await
    }

    async fn claim_webhooks(
        handle: &SqliteHandle,
        claim: WebhookClaim<'_>,
    ) -> Result<Vec<SqliteRow>, StoreError> {
        super::sqlite_claims::claim_webhooks(handle, claim).await
    }

    async fn claim_monitors(
        handle: &SqliteHandle,
        claim: MonitorClaim,
    ) -> Result<Vec<SqliteRow>, StoreError> {
        super::sqlite_claims::claim_monitors(handle, claim).await
    }

    async fn claim_outbox(
        conn: &mut SqliteConnection,
        claim: OutboxClaim,
    ) -> Result<Vec<SqliteRow>, StoreError> {
        super::sqlite_claims::claim_outbox(conn, claim).await
    }

    async fn expire_outbox(handle: &SqliteHandle, tenant: Uuid, run: Uuid) -> Result<u64, StoreError> {
        super::sqlite_claims::expire_outbox(handle, tenant, run).await
    }

    async fn fenced_update_returning<'q, U, R>(
        conn: &mut SqliteConnection,
        update: &'static str,
        bind_update: U,
        _reread: Option<(&'static str, R)>,
    ) -> Result<Option<SqliteRow>, StoreError>
    where
        U: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send,
        R: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send,
    {
        // RETURNING is native; the statement runs under the write lock
        bind_update(sqlx::query(update))
            .fetch_optional(conn)
            .await
            .map_err(db)
    }

    async fn heartbeat_frontier(
        handle: &SqliteHandle,
        worker: Uuid,
        ttl_secs: f64,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError> {
        super::sqlite_claims::heartbeat_frontier(handle, worker, ttl_secs, leases).await
    }

    async fn insert_traffic(
        conn: &mut SqliteConnection,
        run: Uuid,
        lane: &str,
        rows: &[TrafficRow<'_>],
    ) -> Result<(), StoreError> {
        super::sqlite_claims::insert_traffic(conn, run, lane, rows).await
    }

    async fn append_audit_chain(
        conn: &mut SqliteConnection,
        entry: AuditEntry<'_>,
    ) -> Result<(), StoreError> {
        super::sqlite_claims::append_audit_chain(conn, entry).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use sqlx::Connection as _;

    #[test]
    fn second_worker_lock_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("crawlx.db");
        let first = acquire_worker_lock(&database).unwrap();
        assert!(first.path().ends_with("crawlx.db.worker.lock"));
        let refused = acquire_worker_lock(&database).unwrap_err();
        assert!(matches!(
            &refused,
            StoreError::Conflict(text) if text.starts_with("refused: sqlite_second_worker: another crawlx worker already holds ")
        ));
        drop(first);
        assert!(acquire_worker_lock(&database).is_ok());
    }

    #[tokio::test]
    async fn a_write_lock_held_elsewhere_ends_in_a_bounded_error() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite:{}", dir.path().join("busy.db").display());
        let config = StoreConfig {
            busy_timeout: Duration::from_millis(20),
            ..StoreConfig::default()
        };
        let store = open(&DatabaseUrl::parse(&url).unwrap(), config).await.unwrap();
        // another process: a connection outside the in-process writer gate holds the lock
        let mut holder = SqliteConnection::connect(&url).await.unwrap();
        sqlx::query("BEGIN IMMEDIATE").execute(&mut holder).await.unwrap();
        let started = Instant::now();
        let refused = <SqliteBackend as Concurrency>::begin_write(&store.pool).await;
        let elapsed = started.elapsed();
        assert!(
            refused.is_err(),
            "the held write lock must refuse the transaction"
        );
        // deadline = 6 x 20 ms; one attempt and one backoff may overrun it
        assert!(elapsed < Duration::from_secs(2), "unbounded retry: {elapsed:?}");
        sqlx::query("ROLLBACK").execute(&mut holder).await.unwrap();
        assert!(<SqliteBackend as Concurrency>::begin_write(&store.pool)
            .await
            .is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_directories_pass_the_filesystem_check() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check_local_filesystem(&dir.path().join("new.db")).is_ok());
        assert!(check_local_filesystem(Path::new("relative.db")).is_ok());
    }
}
