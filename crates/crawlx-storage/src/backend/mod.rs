//! Storage engines: PostgreSQL, MariaDB and SQLite behind one [`Database`] handle.
//!
//! The engine is chosen at runtime from the URL scheme ([`DatabaseUrl`]). Each engine is a
//! [`Backend`]: its sqlx driver, its pool type and its [`Dialect`]. Algorithms that differ
//! per engine (claiming rows, fence tokens, transaction-scoped locks, write transactions) are
//! the [`Concurrency`] strategy of the backend. [`Database::open`] is the single constructor
//! downstream crates call; it connects, applies the engine's startup checks and refuses
//! deployments the engine cannot serve correctly with a typed [`BackendRefusal`].

pub mod dialect;
pub mod mariadb;
mod mariadb_claims;
pub mod postgres;
mod refusal;
pub mod sqlite;
mod sqlite_claims;
pub mod strategy;
mod url;

pub use dialect::{Dialect, MariaDbDialect, PostgresDialect, RowLock, SqliteDialect};
pub use mariadb::MariaBackend;
pub use postgres::PgBackend;
pub use refusal::{BackendRefusal, RefusalCode, CUSTODY_MISSING_MESSAGE};
pub use sqlite::{SqliteBackend, WorkerLock};
pub use strategy::{Concurrency, FenceSeq, LockMode, WriteTx};
pub use url::DatabaseUrl;

use crate::store::{Pg, Store, StoreConfig};
use async_trait::async_trait;
use crawlx_core::origin::OriginAdmission;
use crawlx_core::StoreError;
use std::fmt;
use std::sync::Arc;

pub(crate) mod sealed {
    /// Prevents implementations outside this crate.
    pub trait Sealed {}
}

/// Which engine a database URL selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendKind {
    /// PostgreSQL: database-enforced tenancy, multiple processes, the reference engine.
    Postgres,
    /// MariaDB 10.6 or newer, READ COMMITTED, single primary.
    MariaDb,
    /// SQLite: one host, one worker process, application-enforced tenancy.
    Sqlite,
}

impl BackendKind {
    /// The canonical URL scheme.
    #[must_use]
    pub const fn scheme(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::MariaDb => "mariadb",
            Self::Sqlite => "sqlite",
        }
    }

    /// What this engine guarantees; see [`Capabilities`].
    #[must_use]
    pub const fn capabilities(self) -> Capabilities {
        match self {
            Self::Postgres => Capabilities {
                database_enforced_tenancy: true,
                multi_process_workers: true,
                global_origin_admission: true,
                independent_safety_auditor: true,
                partitioned_traffic: true,
                restricted_request_login: true,
                pending: &[],
            },
            Self::MariaDb => Capabilities {
                database_enforced_tenancy: false,
                multi_process_workers: true,
                global_origin_admission: true,
                independent_safety_auditor: false,
                partitioned_traffic: false,
                restricted_request_login: true,
                pending: PENDING_MARIADB,
            },
            Self::Sqlite => Capabilities {
                database_enforced_tenancy: false,
                multi_process_workers: false,
                global_origin_admission: false,
                independent_safety_auditor: false,
                partitioned_traffic: false,
                restricted_request_login: false,
                pending: PENDING_SQLITE,
            },
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.scheme())
    }
}

/// A storage capability an engine may not implement yet. Asking for one the engine lacks
/// yields a typed refusal ([`BackendRefusal`] with code `backend_unimplemented`), never a
/// silent no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Feature {
    /// The repository traits of `crawlx_core::repo` over this engine.
    Repositories,
    /// Registering tenants and authorization records ([`DurableAdmin`] writes).
    DurableAdmin,
    /// Claiming a session lease ([`Concurrency::claim_sessions`]).
    SessionClaims,
    /// Claiming a frontier batch ([`Concurrency::claim_frontier_batch`]).
    FrontierClaims,
    /// Claiming due webhook deliveries ([`Concurrency::claim_webhooks`]).
    WebhookClaims,
    /// Claiming due monitors ([`Concurrency::claim_monitors`]).
    MonitorClaims,
    /// Claiming and expiring dataset delivery outbox rows.
    OutboxClaims,
    /// Appending to the hash-chained audit log ([`Concurrency::append_audit_chain`]).
    AuditChain,
    /// Deployment-wide per-origin admission through the database.
    OriginAdmission,
}

impl Feature {
    /// Operator-facing name used in refusal messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Repositories => "the repositories",
            Self::DurableAdmin => "tenant and authorization registration",
            Self::SessionClaims => "session claims",
            Self::FrontierClaims => "frontier claims",
            Self::WebhookClaims => "webhook claims",
            Self::MonitorClaims => "monitor claims",
            Self::OutboxClaims => "delivery outbox claims",
            Self::AuditChain => "the audit chain",
            Self::OriginAdmission => "origin admission",
        }
    }
}

const PENDING_MARIADB: &[Feature] = &[Feature::Repositories, Feature::DurableAdmin];

const PENDING_SQLITE: &[Feature] = &[Feature::Repositories, Feature::DurableAdmin];

/// What an engine guarantees. Deployment checks read these instead of matching on the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// The database itself enforces tenant isolation (row-level security).
    pub database_enforced_tenancy: bool,
    /// More than one worker process may share the database.
    pub multi_process_workers: bool,
    /// Per-origin capacity and pacing are shared across workers through the database.
    pub global_origin_admission: bool,
    /// The independent safety auditor can run with two distinct database identities.
    pub independent_safety_auditor: bool,
    /// `traffic_events` is partitioned by month.
    pub partitioned_traffic: bool,
    /// A restricted, non-owner request login can be provisioned.
    pub restricted_request_login: bool,
    /// Features this engine does not implement yet; each is refused with a typed error.
    pub pending: &'static [Feature],
}

impl Capabilities {
    /// Whether `feature` is implemented.
    #[must_use]
    pub fn supports(&self, feature: Feature) -> bool {
        !self.pending.contains(&feature)
    }
}

/// A database engine: driver, pool and SQL dialect.
pub trait Backend: sealed::Sealed + Clone + fmt::Debug + Send + Sync + 'static {
    /// The sqlx driver.
    type Db: sqlx::Database<Row: crate::sql::SqlRow + Send + Unpin + 'static>;
    /// The connection pool (engines may wrap the driver pool with their own state).
    type Pool: Clone + fmt::Debug + Send + Sync + 'static;
    /// SQL fragments of the engine.
    type Dialect: Dialect;
    /// Which engine this is.
    const KIND: BackendKind;

    /// Connections currently checked out of `pool`.
    fn pool_in_use(pool: &Self::Pool) -> u32;
}

/// Registration of tenants and authorization records: the durable-run bookkeeping that used
/// to be inherent methods of [`Pg`]. Object safe so workers hold `Arc<dyn DurableAdmin>`.
#[async_trait]
pub trait DurableAdmin: Send + Sync {
    /// Which engine backs this handle.
    fn kind(&self) -> BackendKind;

    /// Database time; the only clock lease arithmetic uses.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the query fails.
    async fn db_now(&self) -> Result<chrono::DateTime<chrono::Utc>, StoreError>;

    /// Apply the engine's embedded migrations.
    ///
    /// # Errors
    /// Returns [`StoreError`] if a migration fails.
    async fn migrate(&self) -> Result<(), StoreError>;

    /// Insert a tenant if absent.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the insert fails, or the `backend_unimplemented` refusal on
    /// engines that do not implement [`Feature::DurableAdmin`] yet.
    async fn ensure_tenant(&self, tenant: crawlx_core::TenantId, name: &str) -> Result<(), StoreError>;

    /// Register an authorization record so a run can reference it.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the writes fail, or the `backend_unimplemented` refusal on
    /// engines that do not implement [`Feature::DurableAdmin`] yet.
    async fn ensure_authorization_record(
        &self,
        row: &crate::store::AuthorizationRow<'_>,
    ) -> Result<(), StoreError>;
}

/// Builds the deployment-wide per-origin admission service, when the engine can share it.
pub trait OriginAdmissionFactory: Send + Sync {
    /// An admission service enforcing `limit` concurrent operations per origin across every
    /// worker of the deployment, or `None` when the engine has no shared admission (the
    /// worker then falls back to its in-process cap).
    fn origin_admission(&self, limit: usize) -> Option<Arc<dyn OriginAdmission>>;
}

/// An open database of any engine; cheap to clone.
#[derive(Clone, Debug)]
pub struct Database {
    target: String,
    inner: Inner,
}

#[derive(Clone, Debug)]
enum Inner {
    Postgres(Pg),
    MariaDb(Store<MariaBackend>),
    Sqlite(Store<SqliteBackend>),
}

impl Database {
    /// Parse `url`, connect and run the engine's startup checks. Migrations are not applied;
    /// call [`Database::migrate`].
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] carrying a [`BackendRefusal`] when the scheme is
    /// unknown, the server or file system is unsupported or misconfigured, and
    /// [`StoreError::Database`] when the database is unreachable.
    pub async fn open(url: &str, cfg: StoreConfig) -> Result<Self, StoreError> {
        let parsed = DatabaseUrl::parse(url)?;
        let target = parsed.redacted();
        let inner = match parsed.kind() {
            BackendKind::Postgres => Inner::Postgres(Pg::connect(parsed.expose(), cfg).await?),
            BackendKind::MariaDb => Inner::MariaDb(mariadb::open(&parsed, cfg).await?),
            BackendKind::Sqlite => Inner::Sqlite(sqlite::open(&parsed, cfg).await?),
        };
        Ok(Self { target, inner })
    }

    /// The engine.
    #[must_use]
    pub const fn kind(&self) -> BackendKind {
        match self.inner {
            Inner::Postgres(_) => BackendKind::Postgres,
            Inner::MariaDb(_) => BackendKind::MariaDb,
            Inner::Sqlite(_) => BackendKind::Sqlite,
        }
    }

    /// What the engine guarantees.
    #[must_use]
    pub const fn capabilities(&self) -> Capabilities {
        self.kind().capabilities()
    }

    /// The URL without credentials, safe for logs.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Fail with the typed `backend_unimplemented` refusal unless the engine implements
    /// `feature`.
    ///
    /// # Errors
    /// Returns the refusal for a pending feature.
    pub fn require(&self, feature: Feature) -> Result<(), BackendRefusal> {
        if self.capabilities().supports(feature) {
            Ok(())
        } else {
            Err(BackendRefusal::unimplemented(self.kind(), feature.name()))
        }
    }

    /// The PostgreSQL handle, which implements every repository trait.
    ///
    /// # Errors
    /// Returns the `backend_unimplemented` refusal on engines whose repositories are pending.
    pub fn postgres(&self) -> Result<&Pg, BackendRefusal> {
        match &self.inner {
            Inner::Postgres(pg) => Ok(pg),
            _ => Err(BackendRefusal::unimplemented(
                self.kind(),
                Feature::Repositories.name(),
            )),
        }
    }

    /// The PostgreSQL handle, when this is a PostgreSQL database.
    #[must_use]
    pub const fn as_postgres(&self) -> Option<&Pg> {
        match &self.inner {
            Inner::Postgres(pg) => Some(pg),
            _ => None,
        }
    }

    /// The driver pool of a MariaDB database (tests and operator tooling).
    #[must_use]
    pub fn mariadb_pool(&self) -> Option<&sqlx::MySqlPool> {
        match &self.inner {
            Inner::MariaDb(store) => Some(&store.pool),
            _ => None,
        }
    }

    /// The driver pool of a SQLite database (tests and operator tooling).
    #[must_use]
    pub fn sqlite_pool(&self) -> Option<&sqlx::SqlitePool> {
        match &self.inner {
            Inner::Sqlite(store) => Some(&store.pool),
            _ => None,
        }
    }

    /// The SQLite store, when this is a SQLite database. Repository traits are implemented
    /// for `Store<B>` of every engine, so cases and downstream code call them directly.
    #[must_use]
    pub const fn sqlite_store(&self) -> Option<&Store<SqliteBackend>> {
        match &self.inner {
            Inner::Sqlite(store) => Some(store),
            _ => None,
        }
    }

    /// The MariaDB store, when this is a MariaDB database.
    #[must_use]
    pub const fn mariadb_store(&self) -> Option<&Store<MariaBackend>> {
        match &self.inner {
            Inner::MariaDb(store) => Some(store),
            _ => None,
        }
    }

    /// The SQLite store, when this is a SQLite database (mirror of [`Database::as_postgres`]).
    #[must_use]
    pub const fn as_sqlite(&self) -> Option<&Store<SqliteBackend>> {
        self.sqlite_store()
    }

    /// The MariaDB store, when this is a MariaDB database (mirror of [`Database::as_postgres`]).
    #[must_use]
    pub const fn as_mariadb(&self) -> Option<&Store<MariaBackend>> {
        self.mariadb_store()
    }

    /// Settings this handle was opened with.
    #[must_use]
    pub const fn config(&self) -> &StoreConfig {
        match &self.inner {
            Inner::Postgres(store) => &store.cfg,
            Inner::MariaDb(store) => &store.cfg,
            Inner::Sqlite(store) => &store.cfg,
        }
    }

    /// Apply the engine's embedded migrations (`migrations/`, `migrations/mariadb/` or
    /// `migrations/sqlite/`).
    ///
    /// # Errors
    /// Returns [`StoreError`] if a migration fails.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        match &self.inner {
            Inner::Postgres(pg) => pg.migrate().await,
            Inner::MariaDb(store) => mariadb::migrate(store).await,
            Inner::Sqlite(store) => sqlite::migrate(store).await,
        }
    }

    /// The newest migration version this build embeds for the engine.
    #[must_use]
    pub fn latest_migration_version(&self) -> Option<i64> {
        let migrator = match self.kind() {
            BackendKind::Postgres => &postgres::MIGRATOR,
            BackendKind::MariaDb => &mariadb::MIGRATOR,
            BackendKind::Sqlite => &sqlite::MIGRATOR,
        };
        migrator.iter().map(|migration| migration.version).max()
    }

    /// The newest migration version recorded as applied, `None` before the first migration.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the migrations table cannot be read.
    pub async fn applied_migration_version(&self) -> Result<Option<i64>, StoreError> {
        const SQL: &str = "SELECT MAX(version) FROM _sqlx_migrations WHERE success";
        let version = match &self.inner {
            Inner::Postgres(pg) => sqlx::query_scalar(SQL).fetch_one(pg.pool()).await,
            Inner::MariaDb(store) => sqlx::query_scalar(SQL).fetch_one(&store.pool).await,
            Inner::Sqlite(store) => sqlx::query_scalar(SQL).fetch_one(&store.pool.pool).await,
        };
        version.map_err(crate::error::db)
    }

    /// Database time; the only clock lease arithmetic uses. SQLite runs on one host, so its
    /// database clock is the process clock (millisecond resolution).
    ///
    /// # Errors
    /// Returns [`StoreError`] if the query fails.
    pub async fn db_now(&self) -> Result<chrono::DateTime<chrono::Utc>, StoreError> {
        match &self.inner {
            Inner::Postgres(pg) => pg.db_now().await,
            Inner::MariaDb(store) => mariadb::db_now(store).await,
            Inner::Sqlite(_) => Ok(sqlite::db_now()),
        }
    }

    /// Draw the next value of `seq` in its own transaction.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the transaction or the draw fails.
    pub async fn next_fence(&self, seq: FenceSeq) -> Result<i64, StoreError> {
        match &self.inner {
            Inner::Postgres(pg) => fence_in_write_tx::<PgBackend>(&pg.pool, seq).await,
            Inner::MariaDb(store) => fence_in_write_tx::<MariaBackend>(&store.pool, seq).await,
            Inner::Sqlite(store) => fence_in_write_tx::<SqliteBackend>(&store.pool, seq).await,
        }
    }

    /// Take the exclusive worker lock of a SQLite database file. Engines that allow several
    /// workers return `None`.
    ///
    /// # Errors
    /// Returns the `sqlite_second_worker` refusal when another worker holds the file.
    pub fn acquire_worker_lock(&self) -> Result<Option<WorkerLock>, StoreError> {
        match &self.inner {
            Inner::Sqlite(store) => store.pool.path().map(sqlite::acquire_worker_lock).transpose(),
            _ => Ok(None),
        }
    }

    /// Close every pooled connection.
    pub async fn close(&self) {
        match &self.inner {
            Inner::Postgres(pg) => pg.pool().close().await,
            Inner::MariaDb(store) => store.pool.close().await,
            Inner::Sqlite(store) => store.pool.pool.close().await,
        }
    }

    /// Drop the isolated namespace of a test database and close it: the PostgreSQL schema
    /// named by [`StoreConfig::schema`]. Other engines only close.
    ///
    /// # Errors
    /// Returns [`StoreError`] if dropping the schema fails.
    pub async fn teardown(self) -> Result<(), StoreError> {
        match self.inner {
            Inner::Postgres(pg) => pg.drop_schema().await,
            Inner::MariaDb(store) => {
                store.pool.close().await;
                Ok(())
            }
            Inner::Sqlite(store) => {
                store.pool.pool.close().await;
                Ok(())
            }
        }
    }
}

async fn fence_in_write_tx<B: Concurrency>(pool: &B::Pool, seq: FenceSeq) -> Result<i64, StoreError> {
    let mut tx = B::begin_write(pool).await?;
    let value = B::next_fence(tx.conn(), seq).await?;
    tx.commit().await?;
    Ok(value)
}

#[async_trait]
impl DurableAdmin for Pg {
    fn kind(&self) -> BackendKind {
        BackendKind::Postgres
    }

    async fn db_now(&self) -> Result<chrono::DateTime<chrono::Utc>, StoreError> {
        Self::db_now(self).await
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        Self::migrate(self).await
    }

    async fn ensure_tenant(&self, tenant: crawlx_core::TenantId, name: &str) -> Result<(), StoreError> {
        Self::ensure_tenant(self, tenant, name).await
    }

    async fn ensure_authorization_record(
        &self,
        row: &crate::store::AuthorizationRow<'_>,
    ) -> Result<(), StoreError> {
        Self::ensure_authorization_record(self, row).await
    }
}

impl OriginAdmissionFactory for Pg {
    fn origin_admission(&self, limit: usize) -> Option<Arc<dyn OriginAdmission>> {
        Some(Arc::new(crate::origin::PgOriginAdmission::new(
            self.clone(),
            limit,
        )))
    }
}

impl OriginAdmissionFactory for Database {
    fn origin_admission(&self, limit: usize) -> Option<Arc<dyn OriginAdmission>> {
        crate::origin::origin_admission(self, limit)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn capabilities_match_the_matrix() {
        let pg = BackendKind::Postgres.capabilities();
        assert!(pg.database_enforced_tenancy && pg.multi_process_workers && pg.partitioned_traffic);
        assert!(pg.pending.is_empty());
        let maria = BackendKind::MariaDb.capabilities();
        assert!(!maria.database_enforced_tenancy && maria.multi_process_workers);
        assert!(maria.restricted_request_login && !maria.independent_safety_auditor);
        let lite = BackendKind::Sqlite.capabilities();
        assert!(
            !lite.multi_process_workers && !lite.global_origin_admission && !lite.restricted_request_login
        );
        assert!(lite.supports(Feature::SessionClaims));
        assert!(pg.supports(Feature::SessionClaims));
    }

    #[test]
    fn sqlite_never_lists_origin_admission_as_pending() {
        // in-process admission is the design for one worker, not a gap
        assert!(BackendKind::Sqlite
            .capabilities()
            .supports(Feature::OriginAdmission));
        assert!(BackendKind::MariaDb
            .capabilities()
            .supports(Feature::OriginAdmission));
    }

    #[tokio::test]
    async fn unknown_schemes_are_refused_by_open() {
        let error = Database::open("oracle://h/db", StoreConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(
            &error,
            StoreError::Conflict(text) if text
                == "refused: scheme: unsupported database url scheme; expected postgres, mariadb or sqlite"
        ));
    }
}
