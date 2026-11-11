#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Support of the lease cases: raw SQL on any engine, a second pool on the same database and
//! the small fixtures every case starts from.
//!
//! Raw probes are written once in PostgreSQL notation (`$n` placeholders, `::type` casts) and
//! expanded per engine by the statement layer of the crate, so a probe that changes a lease
//! column or provokes a trigger is the same text on every engine. Placeholders must appear
//! once each and in ascending order, because MariaDB binds positionally.

use crate::rig::Rig;
use chrono::{DateTime, Utc};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::repo::{CrawlRun, RunRepo};
use crawlx_core::TenantId;
use crawlx_storage::backend::{BackendKind, Database, DatabaseUrl, MariaBackend, PgBackend, SqliteBackend};
use crawlx_storage::sql::{Built, Sql, SqlRow};
use crawlx_storage::tenant::Tenancy;
use crawlx_storage::testkit::rig::{MARIADB_URL_VAR, POSTGRES_URL_VAR};
use crawlx_storage::testkit::{crawl_run, create_crawl, Engine};
use crawlx_storage::{LeaseRepo, SessionLease, Store, StoreConfig};
use sqlx::mysql::{MySql, MySqlRow};
use sqlx::postgres::{PgRow, Postgres};
use sqlx::sqlite::{Sqlite, SqliteRow};
use uuid::Uuid;

/// One bound value of a raw probe.
#[derive(Clone, Copy, Debug)]
pub enum V<'a> {
    /// A `uuid` / `BINARY(16)` / 16-byte `BLOB`.
    Uuid(Uuid),
    /// A 64-bit integer.
    I64(i64),
    /// A 32-bit integer.
    I32(i32),
    /// Text.
    Text(&'a str),
    /// Bytes.
    Bytes(&'a [u8]),
    /// A point in time (`timestamptz`, `DATETIME(6)` or integer microseconds).
    Ts(DateTime<Utc>),
    /// A JSON value.
    Json(&'a serde_json::Value),
}

macro_rules! binder {
    ($name:ident, $db:ty, $ts:expr, $json:expr) => {
        fn $name(
            sql: String,
            binds: &[V<'_>],
        ) -> sqlx::query::Query<'static, $db, <$db as sqlx::Database>::Arguments> {
            let mut query = sqlx::query::<$db>(sqlx::AssertSqlSafe(sql));
            for bind in binds {
                query = match bind {
                    V::Uuid(v) => query.bind(*v),
                    V::I64(v) => query.bind(*v),
                    V::I32(v) => query.bind(*v),
                    V::Text(v) => query.bind(*v),
                    V::Bytes(v) => query.bind(*v),
                    V::Ts(v) => query.bind(($ts)(*v)),
                    V::Json(v) => query.bind(($json)(*v)),
                };
            }
            query
        }
    };
}

binder!(
    bind_pg,
    Postgres,
    |t: DateTime<Utc>| t,
    |j: &serde_json::Value| j.clone()
);
binder!(
    bind_mariadb,
    MySql,
    |t: DateTime<Utc>| t.naive_utc(),
    |j: &serde_json::Value| j.to_string()
);
binder!(
    bind_sqlite,
    Sqlite,
    |t: DateTime<Utc>| t.timestamp_micros(),
    |j: &serde_json::Value| j.to_string()
);

/// A row of a raw probe, whichever engine produced it. Accessors panic on a missing,
/// null or mistyped column: a probe that cannot read its own columns is a broken test.
pub enum Row {
    /// A PostgreSQL row.
    Pg(PgRow),
    /// A MariaDB row.
    Maria(MySqlRow),
    /// A SQLite row.
    Sqlite(SqliteRow),
}

macro_rules! getters {
    ($($name:ident: $ty:ty),+ $(,)?) => {
        impl Row {$(
            #[doc = concat!("The column `col` as `", stringify!($ty), "`.")]
            pub fn $name(&self, col: &str) -> $ty {
                let read = match self {
                    Self::Pg(row) => SqlRow::$name(row, col),
                    Self::Maria(row) => SqlRow::$name(row, col),
                    Self::Sqlite(row) => SqlRow::$name(row, col),
                };
                read.unwrap_or_else(|error| panic!("column {col}: {error}"))
            }
        )+}
    };
}

getters! {
    opt_uuid: Option<Uuid>,
    i32: i32,
    i64: i64,
    opt_i64: Option<i64>,
    i16: i16,
    flag: bool,
    text: String,
    opt_text: Option<String>,
    ts: DateTime<Utc>,
    opt_ts: Option<DateTime<Utc>>,
}

/// Placeholders of `template` outside string literals, in text order.
fn placeholders(template: &str) -> Vec<usize> {
    let bytes = template.as_bytes();
    let mut found = Vec::new();
    let mut quoted = false;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\'' => quoted = !quoted,
            b'$' if !quoted && bytes.get(at + 1).is_some_and(u8::is_ascii_digit) => {
                let mut end = at + 1;
                let mut n = 0_usize;
                while let Some(digit) = bytes.get(end).filter(|c| c.is_ascii_digit()) {
                    n = n * 10 + usize::from(digit - b'0');
                    end += 1;
                }
                found.push(n);
                at = end;
                continue;
            }
            _ => {}
        }
        at += 1;
    }
    found
}

/// A held row lock: a transaction on its own connection that has locked one row and keeps
/// the lock until [`HeldLock::release`].
pub enum HeldLock {
    /// A PostgreSQL transaction.
    Pg(sqlx::Transaction<'static, Postgres>),
    /// A MariaDB transaction.
    Maria(sqlx::Transaction<'static, MySql>),
}

impl HeldLock {
    /// Roll the transaction back, releasing the lock.
    pub async fn release(self) {
        match self {
            Self::Pg(tx) => tx.rollback().await.expect("release the postgres row lock"),
            Self::Maria(tx) => tx.rollback().await.expect("release the mariadb row lock"),
        }
    }
}

/// Raw SQL on the database of a rig.
#[derive(Clone, Copy)]
pub struct Raw<'a> {
    db: &'a Database,
}

impl<'a> Raw<'a> {
    /// Raw access to the database of `rig`.
    ///
    /// # Panics
    /// Panics on the in-memory rig, which has no database.
    pub fn new(rig: &'a Rig) -> Self {
        Self { db: rig.database() }
    }

    /// The engine.
    pub fn kind(&self) -> BackendKind {
        self.db.kind()
    }

    /// The database clock.
    pub async fn now(&self) -> DateTime<Utc> {
        self.db.db_now().await.expect("read the database clock")
    }

    fn expand(&self, template: &str) -> String {
        let numbers = placeholders(template);
        let expected: Vec<usize> = (1..=numbers.len()).collect();
        assert_eq!(
            numbers, expected,
            "raw probes use each placeholder once, in ascending order: {template}"
        );
        Built::expand(self.db.kind(), template).text().to_owned()
    }

    /// Run a statement; the rows it affected.
    ///
    /// # Errors
    /// Returns the driver error, whose text carries the message of a trigger or constraint.
    pub async fn exec(&self, template: &str, binds: &[V<'_>]) -> Result<u64, sqlx::Error> {
        let sql = self.expand(template);
        match self.db.kind() {
            BackendKind::Sqlite => bind_sqlite(sql, binds)
                .execute(self.db.sqlite_pool().expect("sqlite pool"))
                .await
                .map(|done| done.rows_affected()),
            BackendKind::MariaDb => bind_mariadb(sql, binds)
                .execute(self.db.mariadb_pool().expect("mariadb pool"))
                .await
                .map(|done| done.rows_affected()),
            _ => bind_pg(sql, binds)
                .execute(self.db.postgres().expect("postgres handle").pool())
                .await
                .map(|done| done.rows_affected()),
        }
    }

    /// Run a statement that must succeed.
    ///
    /// # Panics
    /// Panics when the statement fails.
    pub async fn run(&self, template: &str, binds: &[V<'_>]) -> u64 {
        self.exec(template, binds)
            .await
            .unwrap_or_else(|error| panic!("{template}: {error}"))
    }

    /// Run a query; every row.
    ///
    /// # Errors
    /// Returns the driver error.
    pub async fn try_rows(&self, template: &str, binds: &[V<'_>]) -> Result<Vec<Row>, sqlx::Error> {
        let sql = self.expand(template);
        match self.db.kind() {
            BackendKind::Sqlite => Ok(bind_sqlite(sql, binds)
                .fetch_all(self.db.sqlite_pool().expect("sqlite pool"))
                .await?
                .into_iter()
                .map(Row::Sqlite)
                .collect()),
            BackendKind::MariaDb => Ok(bind_mariadb(sql, binds)
                .fetch_all(self.db.mariadb_pool().expect("mariadb pool"))
                .await?
                .into_iter()
                .map(Row::Maria)
                .collect()),
            _ => Ok(bind_pg(sql, binds)
                .fetch_all(self.db.postgres().expect("postgres handle").pool())
                .await?
                .into_iter()
                .map(Row::Pg)
                .collect()),
        }
    }

    /// Run a query that must succeed; every row.
    ///
    /// # Panics
    /// Panics when the query fails.
    pub async fn rows(&self, template: &str, binds: &[V<'_>]) -> Vec<Row> {
        self.try_rows(template, binds)
            .await
            .unwrap_or_else(|error| panic!("{template}: {error}"))
    }

    /// The only row of a query.
    ///
    /// # Panics
    /// Panics unless the query returns exactly one row.
    pub async fn one(&self, template: &str, binds: &[V<'_>]) -> Row {
        let mut rows = self.rows(template, binds).await;
        assert_eq!(rows.len(), 1, "{template} returns one row");
        rows.remove(0)
    }

    /// The `n` of a `SELECT count(*) AS n ...` query.
    pub async fn count(&self, template: &str, binds: &[V<'_>]) -> i64 {
        self.one(template, binds).await.i64("n")
    }

    /// Lock one session row with a transaction of its own and keep the lock, on engines that
    /// have row locks. SQLite locks the whole database for a writer instead and has no row
    /// lock to hold, so it returns `None`.
    pub async fn hold_session_lock(&self, session: Uuid) -> Option<HeldLock> {
        let lock = "SELECT session_id FROM crawl_sessions WHERE session_id = $1 FOR UPDATE";
        match self.db.kind() {
            BackendKind::Sqlite => None,
            BackendKind::MariaDb => {
                let mut tx = self
                    .db
                    .mariadb_pool()
                    .expect("mariadb pool")
                    .begin()
                    .await
                    .expect("begin the locking transaction");
                bind_mariadb(self.expand(lock), &[V::Uuid(session)])
                    .fetch_one(&mut *tx)
                    .await
                    .expect("lock the session row");
                Some(HeldLock::Maria(tx))
            }
            _ => {
                let mut tx = self
                    .db
                    .postgres()
                    .expect("postgres handle")
                    .pool()
                    .begin()
                    .await
                    .expect("begin the locking transaction");
                bind_pg(self.expand(lock), &[V::Uuid(session)])
                    .fetch_one(&mut *tx)
                    .await
                    .expect("lock the session row");
                Some(HeldLock::Pg(tx))
            }
        }
    }
}

/// A backend whose store can be taken out of any [`Database`] of that engine, so a case can
/// open further pools on the same data.
pub trait StoreOf: Sql + Tenancy {
    /// The store of `db`.
    ///
    /// # Panics
    /// Panics when `db` is another engine.
    fn store_of(db: &Database) -> &Store<Self>;
}

impl StoreOf for SqliteBackend {
    fn store_of(db: &Database) -> &Store<Self> {
        db.sqlite_store().expect("a sqlite database")
    }
}

impl StoreOf for MariaBackend {
    fn store_of(db: &Database) -> &Store<Self> {
        db.mariadb_store().expect("a mariadb database")
    }
}

impl StoreOf for PgBackend {
    fn store_of(db: &Database) -> &Store<Self> {
        db.postgres().expect("a postgres database")
    }
}

/// Another pool (`cfg`) on the data the rig's database holds: the same SQLite file, MariaDB
/// database or PostgreSQL schema. Close it with `Database::close`, never `teardown`, which
/// would drop the rig's schema.
///
/// # Panics
/// Panics when the connection fails or the environment of the engine is missing.
pub async fn open_sibling(rig: &Rig, cfg: StoreConfig) -> Database {
    let db = rig.database();
    let url = match db.kind() {
        BackendKind::Sqlite => format!(
            "sqlite://{}",
            rig.directory()
                .expect("a sqlite rig has a directory")
                .join("crawlx.db")
                .display()
        ),
        BackendKind::MariaDb => {
            let admin = std::env::var(MARIADB_URL_VAR).expect("the mariadb rig needs its server url");
            let name = db
                .target()
                .rsplit('/')
                .next()
                .expect("the target names the database");
            DatabaseUrl::parse(&admin)
                .expect("the mariadb url parses")
                .with_database(name)
                .expect("a mariadb url names a database")
                .expose()
                .to_owned()
        }
        _ => std::env::var(POSTGRES_URL_VAR).expect("the postgres rig needs its server url"),
    };
    let cfg = if db.kind() == BackendKind::Postgres {
        StoreConfig {
            schema: db.config().schema.clone(),
            ..cfg
        }
    } else {
        cfg
    };
    Database::open(&url, cfg).await.expect("open a sibling pool")
}

/// The path of the SQLite file of a SQLite rig.
///
/// # Panics
/// Panics on any other rig.
pub fn sqlite_file(rig: &Rig) -> std::path::PathBuf {
    rig.directory()
        .expect("a sqlite rig has a directory")
        .join("crawlx.db")
}

/// A tenant the runs of a case can belong to. Database rigs get a `tenants` row; the
/// in-memory store takes any tenant id.
///
/// # Panics
/// Panics when the insert fails.
pub async fn tenant(rig: &Rig) -> TenantId {
    let tenant = TenantId::new();
    if rig.engine() != Engine::Memory {
        rig.insert_tenant(tenant.0).await.expect("insert a tenant");
    }
    tenant
}

/// A queued run of `tenant` with `roles` and `runs_per_role` runs each, created in `store`.
///
/// # Panics
/// Panics when the repository refuses the run.
pub async fn new_run<S: RunRepo>(store: &S, tenant: TenantId, roles: &[&str], runs_per_role: u8) -> CrawlRun {
    let run = crawl_run(
        tenant,
        create_crawl("https://example.test/", roles, runs_per_role),
    );
    store.create(&run, None).await.expect("create the run");
    run
}

/// Create the sessions of `run` (`n_roles` roles, `runs` runs each) and lease every one of
/// them to its own worker, barrier lifted: the sessions are `running`.
///
/// # Panics
/// Panics when a claim fails or finds no session.
pub async fn lease_all<S: RunRepo + LeaseRepo>(
    store: &S,
    run: &CrawlRun,
    n_roles: u16,
    runs: u16,
) -> Vec<SessionLease> {
    let slots = crawlx_storage::testkit::sessions(run.id, n_roles, runs);
    store.create_sessions(&slots).await.expect("create the sessions");
    let mut leases = Vec::with_capacity(slots.len());
    for _ in &slots {
        leases.push(
            store
                .claim_session(run.id, crawlx_core::WorkerId::new(), true)
                .await
                .expect("claim a session")
                .expect("a session to claim"),
        );
    }
    leases
}

/// An observation epoch.
pub const fn epoch(navigation: u64, document: u64, mutation: u64) -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: navigation,
        document_seq: document,
        mutation_seq: mutation,
    }
}

/// `CRAWLX_LEASE_CLAIMERS` / `CRAWLX_LEASE_ROWS` (64 claimers over 100k rows in the scaled
/// `chaos-weekly` variant; 8 / 60 by default).
pub fn lease_scale() -> (usize, usize) {
    let env = |name: &str, default: usize| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    (env("CRAWLX_LEASE_CLAIMERS", 8), env("CRAWLX_LEASE_ROWS", 60))
}
