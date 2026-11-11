//! MariaDB: pool setup, startup refusals, migrations and the concurrency strategy.
//!
//! Sessions run `READ COMMITTED` in UTC. `PIPES_AS_CONCAT` stays in `sql_mode` (sqlx sets it
//! at connect; dropping it would turn `||` into a logical OR). The code never relies on
//! `INSERT IGNORE`, which swallows foreign key, check and `NOT NULL` errors.

use super::dialect::MariaDbDialect;
use super::strategy::{
    AuditEntry, Concurrency, FenceSeq, FrontierClaim, LockMode, MonitorClaim, OutboxClaim, Query,
    SessionClaim, TrafficRow, WebhookClaim, WriteTx,
};
use super::{Backend, BackendKind, BackendRefusal, DatabaseUrl};
use crate::error::db;
use crate::store::{Store, StoreConfig};
use crawlx_core::StoreError;
use sqlx::migrate::Migrator;
use sqlx::mysql::MySqlRow;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::SqlSafeStr as _;
use sqlx::{Executor, MySql, MySqlConnection, MySqlPool, Transaction};
use std::str::FromStr;
use uuid::Uuid;

/// The MariaDB migrations, embedded at build time.
pub(crate) static MIGRATOR: Migrator = sqlx::migrate!("./migrations/mariadb");

/// Oldest supported server, `(major, minor)`: `SKIP LOCKED` and sequences.
const MIN_VERSION: (u32, u32) = (10, 6);

/// Session settings every pooled connection runs. `PIPES_AS_CONCAT` is deliberate.
/// `lock_wait_timeout` bounds metadata lock waits (its server default is a year): a DDL or
/// `DROP DATABASE` queued behind an open transaction fails with the retryable lock timeout
/// instead of waiting for it. Row lock waits are bounded by `innodb_lock_wait_timeout`.
const SESSION_SETUP: &str = "SET SESSION sql_mode = 'PIPES_AS_CONCAT,STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION', \
     time_zone = '+00:00', \
     lock_wait_timeout = 30, \
     transaction_isolation = 'READ-COMMITTED'";

/// The MariaDB backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct MariaBackend;

impl super::sealed::Sealed for MariaBackend {}

impl Backend for MariaBackend {
    type Db = MySql;
    type Pool = MySqlPool;
    type Dialect = MariaDbDialect;
    const KIND: BackendKind = BackendKind::MariaDb;

    fn pool_in_use(pool: &Self::Pool) -> u32 {
        let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
        pool.size().saturating_sub(idle)
    }
}

/// Connect, configure sessions and refuse unsupported servers.
pub(crate) async fn open(url: &DatabaseUrl, cfg: StoreConfig) -> Result<Store<MariaBackend>, StoreError> {
    let options = MySqlConnectOptions::from_str(url.expose())
        .map_err(db)?
        .statement_cache_capacity(64);
    let statement_timeout = cfg.statement_timeout.map(|t| t.as_secs_f64());
    let pool = MySqlPoolOptions::new()
        .max_connections(cfg.max_connections)
        .acquire_timeout(cfg.acquire_timeout)
        .test_before_acquire(cfg.test_before_acquire)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute(SESSION_SETUP).await?;
                if let Some(seconds) = statement_timeout {
                    conn.execute(sqlx::AssertSqlSafe(format!(
                        "SET SESSION max_statement_time = {seconds:.3}"
                    )))
                    .await?;
                }
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .map_err(db)?;
    let mut conn = pool.acquire().await.map_err(db)?;
    check_server(&mut conn).await?;
    let packet: i64 = sqlx::query_scalar("SELECT CAST(@@max_allowed_packet AS SIGNED)")
        .fetch_one(&mut *conn)
        .await
        .map_err(db)?;
    crate::sql::note_mariadb_max_packet(u64::try_from(packet).unwrap_or(0));
    drop(conn);
    Ok(Store::from_parts(pool, cfg))
}

/// Parse the leading `major.minor` of a server version, skipping the `5.5.5-` replication
/// compatibility prefix MariaDB prepends for old clients.
pub(crate) fn parse_server_version(version: &str) -> Option<(u32, u32)> {
    let version = version.strip_prefix("5.5.5-").unwrap_or(version);
    let mut parts = version.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Refuse servers the storage code is not correct on: not MariaDB, older than 10.6,
/// multi-primary, or settings that break fencing or row locks (refusals R6, R7, R8).
async fn check_server(conn: &mut MySqlConnection) -> Result<(), StoreError> {
    let version: String = sqlx::query_scalar("SELECT VERSION()")
        .fetch_one(&mut *conn)
        .await
        .map_err(db)?;
    let supported = version.to_ascii_lowercase().contains("mariadb")
        && parse_server_version(&version).is_some_and(|found| found >= MIN_VERSION);
    if !supported {
        return Err(BackendRefusal::mariadb_unsupported_server(&version).into());
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('wsrep_on', 'innodb_default_row_format', 'binlog_format', 'log_bin')",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(db)?;
    let variable = |name: &str| {
        rows.iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let on = |value: Option<&str>| value.is_some_and(|v| v.eq_ignore_ascii_case("ON") || v == "1");
    if on(variable("wsrep_on")) {
        return Err(BackendRefusal::mariadb_multi_primary().into());
    }
    if let Some(format) = variable("innodb_default_row_format") {
        if !format.eq_ignore_ascii_case("dynamic") {
            return Err(BackendRefusal::mariadb_settings("innodb_default_row_format", "DYNAMIC").into());
        }
    }
    if on(variable("log_bin"))
        && variable("binlog_format").is_some_and(|f| f.eq_ignore_ascii_case("STATEMENT"))
    {
        return Err(BackendRefusal::mariadb_settings("binlog_format", "ROW or MIXED").into());
    }
    // `sysdate_is_now` is a startup option, not a readable variable: probe it. With the
    // option off SYSDATE() moves while the statement runs and NOW() does not.
    let frozen: i64 = sqlx::query_scalar("SELECT NOW(6) = SYSDATE(6) FROM (SELECT SLEEP(0.01)) probe")
        .fetch_one(&mut *conn)
        .await
        .map_err(db)?;
    if frozen != 0 {
        return Err(
            BackendRefusal::mariadb_settings("sysdate_is_now", "0 (the server option must be off)").into(),
        );
    }
    Ok(())
}

/// Apply the MariaDB migrations. A failed file leaves sqlx's dirty marker because DDL is not
/// transactional; the baseline files are idempotent so the marker can be cleared and the
/// file re-applied (see the operations runbook).
pub(crate) async fn migrate(store: &Store<MariaBackend>) -> Result<(), StoreError> {
    MIGRATOR
        .run(&store.pool)
        .await
        .map_err(|source| StoreError::Database {
            source: Box::new(source),
            retryable: true,
        })
}

/// `NOW(6)` of the server, in UTC.
pub(crate) async fn db_now(store: &Store<MariaBackend>) -> Result<chrono::DateTime<chrono::Utc>, StoreError> {
    sqlx::query_scalar("SELECT NOW(6)")
        .fetch_one(&store.pool)
        .await
        .map_err(db)
}

impl Concurrency for MariaBackend {
    async fn begin_write(pool: &MySqlPool) -> Result<WriteTx<MySql>, StoreError> {
        Ok(WriteTx::new(pool.begin().await.map_err(db)?, None))
    }

    async fn begin_read(pool: &MySqlPool) -> Result<Transaction<'static, MySql>, StoreError> {
        // SET TRANSACTION must precede the transaction it configures, so the connection is
        // taken from the pool first and the transaction started on it afterwards.
        let mut conn = pool.acquire().await.map_err(db)?;
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .await
            .map_err(db)?;
        Transaction::begin(conn, Some("START TRANSACTION READ ONLY".into_sql_str()))
            .await
            .map_err(db)
    }

    async fn db_now(pool: &MySqlPool) -> Result<crate::backend::strategy::Timestamp, StoreError> {
        sqlx::query_scalar("SELECT NOW(6)")
            .fetch_one(pool)
            .await
            .map_err(db)
    }

    async fn next_fence(conn: &mut MySqlConnection, seq: FenceSeq) -> Result<i64, StoreError> {
        // The sequence name is one of the `FenceSeq` literals, never caller text.
        let sql = sqlx::AssertSqlSafe(format!("SELECT NEXTVAL({})", seq.name()));
        sqlx::query_scalar(sql).fetch_one(conn).await.map_err(db)
    }

    async fn xact_lock(conn: &mut MySqlConnection, key: &str, mode: LockMode) -> Result<(), StoreError> {
        // `crawlx_locks.name` is a 64-byte key: the lock name is hashed. The row is read
        // under the requested lock first; only a missing row is inserted, never with
        // INSERT IGNORE (it deadlocks against the following lock read and hides errors).
        let name = blake3::hash(key.as_bytes()).as_bytes().to_vec();
        let select = match mode {
            LockMode::Exclusive => "SELECT 1 FROM crawlx_locks WHERE name = ? FOR UPDATE",
            LockMode::Shared => "SELECT 1 FROM crawlx_locks WHERE name = ? LOCK IN SHARE MODE",
        };
        let found = sqlx::query(select)
            .bind(name.as_slice())
            .fetch_optional(&mut *conn)
            .await
            .map_err(db)?;
        if found.is_some() {
            return Ok(());
        }
        sqlx::query("INSERT INTO crawlx_locks (name) VALUES (?) ON DUPLICATE KEY UPDATE name = name")
            .bind(name.as_slice())
            .execute(&mut *conn)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn claim_sessions(
        pool: &MySqlPool,
        claim: SessionClaim<'_>,
    ) -> Result<Option<MySqlRow>, StoreError> {
        super::mariadb_claims::claim_sessions(pool, claim).await
    }

    async fn claim_frontier_batch(
        pool: &MySqlPool,
        claim: FrontierClaim<'_>,
    ) -> Result<Vec<MySqlRow>, StoreError> {
        super::mariadb_claims::claim_frontier_batch(pool, claim).await
    }

    async fn claim_webhooks(pool: &MySqlPool, claim: WebhookClaim<'_>) -> Result<Vec<MySqlRow>, StoreError> {
        super::mariadb_claims::claim_webhooks(pool, claim).await
    }

    async fn claim_monitors(pool: &MySqlPool, claim: MonitorClaim) -> Result<Vec<MySqlRow>, StoreError> {
        super::mariadb_claims::claim_monitors(pool, claim).await
    }

    async fn claim_outbox(
        conn: &mut MySqlConnection,
        claim: OutboxClaim,
    ) -> Result<Vec<MySqlRow>, StoreError> {
        super::mariadb_claims::claim_outbox(conn, claim).await
    }

    async fn expire_outbox(pool: &MySqlPool, tenant: Uuid, run: Uuid) -> Result<u64, StoreError> {
        super::mariadb_claims::expire_outbox(pool, tenant, run).await
    }

    async fn fenced_update_returning<'q, U, R>(
        conn: &mut MySqlConnection,
        update: &'static str,
        bind_update: U,
        reread: Option<(&'static str, R)>,
    ) -> Result<Option<MySqlRow>, StoreError>
    where
        U: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send,
        R: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send,
    {
        // sqlx sets CLIENT_FOUND_ROWS: `rows_affected` counts rows the fence matched, not
        // rows whose value changed, which is the question a fenced write asks.
        let done = bind_update(sqlx::query(update))
            .execute(&mut *conn)
            .await
            .map_err(db)?;
        if done.rows_affected() == 0 {
            return Ok(None);
        }
        match reread {
            Some((sql, bind)) => bind(sqlx::query(sql)).fetch_optional(conn).await.map_err(db),
            None => Err(StoreError::Conflict(
                "a fenced update on mariadb needs a statement to read the row back".to_owned(),
            )),
        }
    }

    async fn heartbeat_frontier(
        pool: &MySqlPool,
        worker: Uuid,
        ttl_secs: f64,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError> {
        super::mariadb_claims::heartbeat_frontier(pool, worker, ttl_secs, leases).await
    }

    async fn insert_traffic(
        conn: &mut MySqlConnection,
        run: Uuid,
        lane: &str,
        rows: &[TrafficRow<'_>],
    ) -> Result<(), StoreError> {
        super::mariadb_claims::insert_traffic(conn, run, lane, rows).await
    }

    async fn append_audit_chain(conn: &mut MySqlConnection, entry: AuditEntry<'_>) -> Result<(), StoreError> {
        super::mariadb_claims::append_audit_chain(conn, entry).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn server_versions_parse() {
        assert_eq!(parse_server_version("11.8.8-MariaDB"), Some((11, 8)));
        assert_eq!(parse_server_version("10.6.12-MariaDB-log"), Some((10, 6)));
        assert_eq!(parse_server_version("5.5.5-10.11.4-MariaDB"), Some((10, 11)));
        assert_eq!(parse_server_version("8.0.36"), Some((8, 0)));
        assert_eq!(parse_server_version("garbage"), None);
        assert!(parse_server_version("10.5.29-MariaDB").unwrap() < MIN_VERSION);
        assert!(parse_server_version("10.6.0-MariaDB").unwrap() >= MIN_VERSION);
    }

    #[test]
    fn session_setup_keeps_pipes_as_concat() {
        assert!(SESSION_SETUP.contains("PIPES_AS_CONCAT"));
        assert!(SESSION_SETUP.contains("READ-COMMITTED"));
        assert!(SESSION_SETUP.contains("+00:00"));
    }
}
