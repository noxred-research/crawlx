//! `Rig`: one database per test, on any engine.
//!
//! The conformance suite (`tests/conformance`) runs every case against each engine through
//! a `Rig`. SQLite always runs (a temporary file); MariaDB runs when
//! `CRAWLX_TEST_MARIADB_URL` names a server (each rig creates and drops its own database);
//! PostgreSQL runs when `CRAWLX_TEST_DATABASE_URL` is set (each rig owns a schema, as the
//! PostgreSQL tests always did); `Rig::memory` is the in-memory executable specification.
//!
//! Constructors return an unmigrated database so a case can observe the migration itself;
//! call [`Rig::migrate`] otherwise.

use crate::backend::{BackendKind, Database, DatabaseUrl};
use crate::memory::MemoryStore;
use crate::sql::{Sql, SqlRow as _, Stmt};
use crate::store::{Store, StoreConfig};
use crawlx_core::StoreError;
use sqlx::Connection;
use std::path::PathBuf;
use std::sync::Arc;

/// Environment variable naming a MariaDB server for the suite.
pub const MARIADB_URL_VAR: &str = "CRAWLX_TEST_MARIADB_URL";

/// Environment variable naming a PostgreSQL server for the suite.
pub const POSTGRES_URL_VAR: &str = "CRAWLX_TEST_DATABASE_URL";

/// Which implementation a rig drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Engine {
    /// The in-memory executable specification.
    Memory,
    /// A SQLite file.
    Sqlite,
    /// A MariaDB database.
    MariaDb,
    /// A PostgreSQL schema.
    Postgres,
}

impl Engine {
    /// The test-name prefix of the engine (`sqlite`, `mariadb`, ...).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Sqlite => "sqlite",
            Self::MariaDb => "mariadb",
            Self::Postgres => "postgres",
        }
    }
}

/// A database (or in-memory store) owned by one test.
pub struct Rig {
    engine: Engine,
    database: Option<Database>,
    memory: Option<Arc<MemoryStore>>,
    scratch: Option<MariaScratch>,
    dir: Option<tempfile::TempDir>,
    closed: bool,
}

impl std::fmt::Debug for Rig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rig")
            .field("engine", &self.engine)
            .field("database", &self.database.as_ref().map(Database::target))
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct MariaScratch {
    admin_url: String,
    database: String,
}

/// A fresh namespace name: `t_` and 32 hex digits.
fn scratch_name() -> String {
    format!("t_{}", uuid::Uuid::now_v7().simple())
}

fn skipped(var: &str) {
    eprintln!("skipped: {var} is not set");
}

fn mariadb_url_from_env() -> Option<String> {
    let url = std::env::var(MARIADB_URL_VAR).ok().filter(|url| !url.is_empty());
    if url.is_none() {
        skipped(MARIADB_URL_VAR);
    }
    url
}

fn postgres_url_from_env() -> Option<String> {
    let url = std::env::var(POSTGRES_URL_VAR).ok().filter(|url| !url.is_empty());
    if url.is_none() {
        skipped(POSTGRES_URL_VAR);
    }
    url
}

/// Run a statement of this module's own (never caller text) on a one-off MariaDB connection.
async fn mariadb_admin(admin_url: &str, statement: String) -> Result<(), StoreError> {
    let mut conn = sqlx::MySqlConnection::connect(admin_url)
        .await
        .map_err(crate::error::db)?;
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(&mut conn)
        .await
        .map_err(crate::error::db)?;
    Ok(())
}

#[allow(
    clippy::expect_used,
    reason = "the rig is test support: a failed setup must abort the test with its cause"
)]
impl Rig {
    /// A SQLite database in a fresh temporary directory. Always available.
    ///
    /// # Panics
    /// Panics when the temporary directory or the database cannot be created.
    pub async fn sqlite() -> Self {
        let dir = tempfile::tempdir().expect("temporary directory");
        let url = format!("sqlite://{}", dir.path().join("crawlx.db").display());
        let database = Database::open(&url, StoreConfig::default())
            .await
            .expect("open the sqlite test database");
        Self {
            engine: Engine::Sqlite,
            database: Some(database),
            memory: None,
            scratch: None,
            dir: Some(dir),
            closed: false,
        }
    }

    /// A MariaDB database of its own, or `None` (with a `skipped:` note on stderr) when
    /// `CRAWLX_TEST_MARIADB_URL` is not set.
    ///
    /// # Panics
    /// Panics when the server rejects the setup.
    pub async fn mariadb() -> Option<Self> {
        let admin_url = mariadb_url_from_env()?;
        let name = scratch_name();
        mariadb_admin(
            &admin_url,
            format!("CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin"),
        )
        .await
        .expect("create the mariadb test database");
        let url = DatabaseUrl::parse(&admin_url)
            .expect("CRAWLX_TEST_MARIADB_URL parses")
            .with_database(&name)
            .expect("a mariadb url names a database");
        let database = Database::open(url.expose(), StoreConfig::default())
            .await
            .expect("open the mariadb test database");
        Some(Self {
            engine: Engine::MariaDb,
            database: Some(database),
            memory: None,
            scratch: Some(MariaScratch {
                admin_url,
                database: name,
            }),
            dir: None,
            closed: false,
        })
    }

    /// A PostgreSQL schema of its own, or `None` (with a `skipped:` note on stderr) when
    /// `CRAWLX_TEST_DATABASE_URL` is not set.
    ///
    /// # Panics
    /// Panics when the server rejects the setup.
    pub async fn postgres() -> Option<Self> {
        let url = postgres_url_from_env()?;
        let cfg = StoreConfig {
            schema: Some(scratch_name()),
            ..StoreConfig::default()
        };
        let database = Database::open(&url, cfg)
            .await
            .expect("open the postgres test database");
        Some(Self {
            engine: Engine::Postgres,
            database: Some(database),
            memory: None,
            scratch: None,
            dir: None,
            closed: false,
        })
    }

    /// The in-memory store.
    #[must_use]
    pub fn memory() -> Self {
        Self {
            engine: Engine::Memory,
            database: None,
            memory: Some(Arc::new(MemoryStore::new())),
            scratch: None,
            dir: None,
            closed: false,
        }
    }

    /// The engine this rig drives.
    #[must_use]
    pub const fn engine(&self) -> Engine {
        self.engine
    }

    /// The database engine, `None` for the in-memory rig.
    #[must_use]
    pub fn kind(&self) -> Option<BackendKind> {
        self.database.as_ref().map(Database::kind)
    }

    /// The database.
    ///
    /// # Panics
    /// Panics on the in-memory rig, which has none; a case that needs one must not run there.
    #[must_use]
    pub fn database(&self) -> &Database {
        self.database.as_ref().expect("this rig has no database")
    }

    /// The in-memory store.
    ///
    /// # Panics
    /// Panics on a database rig.
    #[must_use]
    pub fn store(&self) -> &Arc<MemoryStore> {
        self.memory.as_ref().expect("this rig has no in-memory store")
    }

    /// The directory holding the SQLite file, when this is a SQLite rig.
    #[must_use]
    pub fn directory(&self) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.path().to_path_buf())
    }

    /// Apply the engine's migrations.
    ///
    /// # Panics
    /// Panics when a migration fails.
    pub async fn migrate(&self) {
        if let Some(database) = &self.database {
            database.migrate().await.expect("apply migrations");
        }
    }

    /// Base tables of the migrated schema, sorted, without the migrator's bookkeeping table
    /// and without PostgreSQL partition children.
    ///
    /// # Panics
    /// Panics when the catalog cannot be read or the rig has no database.
    pub async fn tables(&self) -> Vec<String> {
        let database = self.database();
        let mut names: Vec<String> = match database.kind() {
            BackendKind::Sqlite => sqlx::query_scalar(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .fetch_all(database.sqlite_pool().expect("sqlite pool"))
            .await,
            BackendKind::MariaDb => sqlx::query_scalar(
                "SELECT CAST(table_name AS CHAR) FROM information_schema.tables \
                 WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name",
            )
            .fetch_all(database.mariadb_pool().expect("mariadb pool"))
            .await,
            _ => sqlx::query_scalar(
                "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND NOT c.relispartition \
                 ORDER BY c.relname",
            )
            .fetch_all(database.postgres().expect("postgres handle").pool())
            .await,
        }
        .expect("list tables");
        names.retain(|name| name != "_sqlx_migrations");
        names
    }

    /// Tables of the migrated schema that have a column named `column`, sorted.
    ///
    /// # Panics
    /// Panics when the catalog cannot be read or the rig has no database.
    pub async fn tables_with_column(&self, column: &str) -> Vec<String> {
        let database = self.database();
        let mut names: Vec<String> = match database.kind() {
            BackendKind::Sqlite => sqlx::query_scalar(
                "SELECT m.name FROM sqlite_master m, pragma_table_info(m.name) p \
                 WHERE m.type = 'table' AND p.name = ?1 ORDER BY m.name",
            )
            .bind(column)
            .fetch_all(database.sqlite_pool().expect("sqlite pool"))
            .await,
            BackendKind::MariaDb => sqlx::query_scalar(
                "SELECT CAST(c.table_name AS CHAR) FROM information_schema.columns c \
                 JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name \
                 WHERE c.table_schema = DATABASE() AND t.table_type = 'BASE TABLE' AND c.column_name = ? \
                 ORDER BY c.table_name",
            )
            .bind(column)
            .fetch_all(database.mariadb_pool().expect("mariadb pool"))
            .await,
            _ => sqlx::query_scalar(
                "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 JOIN pg_attribute a ON a.attrelid = c.oid \
                 WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND NOT c.relispartition \
                 AND a.attname = $1 AND NOT a.attisdropped ORDER BY c.relname",
            )
            .bind(column)
            .fetch_all(database.postgres().expect("postgres handle").pool())
            .await,
        }
        .expect("list columns");
        names.retain(|name| name != "_sqlx_migrations");
        names
    }

    /// Insert a tenant row with raw SQL, mapping the driver error as repositories do.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] when `tenant` already exists.
    ///
    /// # Panics
    /// Panics on the in-memory rig.
    pub async fn insert_tenant(&self, tenant: uuid::Uuid) -> Result<(), StoreError> {
        let database = self.database();
        match database.kind() {
            BackendKind::Sqlite => {
                sqlx::query("INSERT INTO tenants (tenant_id, name, kms_key_id) VALUES (?1, 'rig', 'local')")
                    .bind(tenant)
                    .execute(database.sqlite_pool().expect("sqlite pool"))
                    .await
                    .map(drop)
            }
            BackendKind::MariaDb => {
                sqlx::query("INSERT INTO tenants (tenant_id, name, kms_key_id) VALUES (?, 'rig', 'local')")
                    .bind(tenant)
                    .execute(database.mariadb_pool().expect("mariadb pool"))
                    .await
                    .map(drop)
            }
            _ => sqlx::query("INSERT INTO tenants (tenant_id, name, kms_key_id) VALUES ($1, 'rig', 'local')")
                .bind(tenant)
                .execute(database.postgres().expect("postgres handle").pool())
                .await
                .map(drop),
        }
        .map_err(crate::error::db)
    }

    /// Insert an `api_keys` row of `tenant` with raw SQL; fails on a missing tenant.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] when the foreign key to `tenants` is violated.
    ///
    /// # Panics
    /// Panics on the in-memory rig.
    pub async fn insert_api_key(&self, tenant: uuid::Uuid) -> Result<(), StoreError> {
        let database = self.database();
        let key = uuid::Uuid::now_v7();
        let prefix = format!("rig_{}", key.simple());
        let hash: &[u8] = b"hash";
        match database.kind() {
            BackendKind::Sqlite => sqlx::query(
                "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes) VALUES (?1, ?2, ?3, ?4, '[]')",
            )
            .bind(key)
            .bind(tenant)
            .bind(prefix)
            .bind(hash)
            .execute(database.sqlite_pool().expect("sqlite pool"))
            .await
            .map(drop),
            BackendKind::MariaDb => sqlx::query(
                "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes) VALUES (?, ?, ?, ?, '[]')",
            )
            .bind(key)
            .bind(tenant)
            .bind(prefix)
            .bind(hash)
            .execute(database.mariadb_pool().expect("mariadb pool"))
            .await
            .map(drop),
            _ => sqlx::query(
                "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, '{}')",
            )
            .bind(key)
            .bind(tenant)
            .bind(prefix)
            .bind(hash)
            .execute(database.postgres().expect("postgres handle").pool())
            .await
            .map(drop),
        }
        .map_err(crate::error::db)
    }

    /// Write `value` into a JSON column (`tenants.plan` of a fresh tenant row) through the
    /// statement layer the repositories use and read it back: the identity the JSON column
    /// contract promises on every engine (`jsonb` on PostgreSQL, compact text elsewhere).
    ///
    /// # Errors
    /// Returns the typed storage error of the write or the read, for instance a payload the
    /// server refuses as too large.
    ///
    /// # Panics
    /// Panics on the in-memory rig.
    pub async fn json_round_trip(&self, value: &serde_json::Value) -> Result<serde_json::Value, StoreError> {
        let database = self.database();
        let id = uuid::Uuid::now_v7();
        match database.kind() {
            BackendKind::Sqlite => {
                json_probe(database.sqlite_store().expect("sqlite store"), id, value).await
            }
            BackendKind::MariaDb => {
                json_probe(database.mariadb_store().expect("mariadb store"), id, value).await
            }
            _ => json_probe(database.postgres().expect("postgres handle"), id, value).await,
        }
    }

    /// Drop the rig's namespace and close its connections.
    ///
    /// # Panics
    /// Panics when the teardown statement fails.
    pub async fn close(mut self) {
        self.closed = true;
        let database = self.database.take();
        let scratch = self.scratch.take();
        teardown(database, scratch).await;
    }
}

/// Insert `value` as the JSON `plan` of a fresh tenant and read it back.
async fn json_probe<B: Sql>(
    store: &Store<B>,
    id: uuid::Uuid,
    value: &serde_json::Value,
) -> Result<serde_json::Value, StoreError> {
    Stmt::<B>::dynamic(
        "INSERT INTO tenants (tenant_id, name, kms_key_id, plan) VALUES ($1, 'json', 'local', $2)",
    )
    .uuid(id)
    .json(value)
    .execute_write(&store.pool)
    .await?;
    Stmt::<B>::dynamic("SELECT plan FROM tenants WHERE tenant_id = $1")
        .uuid(id)
        .fetch_one_pool(&store.pool)
        .await?
        .json("plan")
}

#[allow(
    clippy::expect_used,
    reason = "teardown is test support: a failed drop must surface, not leak silently"
)]
async fn teardown(database: Option<Database>, scratch: Option<MariaScratch>) {
    if let Some(database) = database {
        database
            .clone()
            .teardown()
            .await
            .expect("tear the test database down");
        database.close().await;
    }
    if let Some(scratch) = scratch {
        let dropped = mariadb_admin(
            &scratch.admin_url,
            format!("DROP DATABASE IF EXISTS `{}`", scratch.database),
        )
        .await;
        // The server removes every table but can leave a `.TRG-`/`.TRN-` trigger backup file
        // behind, which fails the directory removal (errno 39) after the data is gone.
        if let Err(error) = dropped {
            assert!(
                format!("{error:?}").contains("errno: 39"),
                "drop the mariadb test database: {error:?}"
            );
            eprintln!(
                "note: {} keeps an empty directory on the server",
                scratch.database
            );
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // A test that panicked skips `close`: clean the shared server up from a short-lived
        // runtime on its own thread (the test's runtime may be shutting down).
        let database = self.database.take();
        let scratch = self.scratch.take();
        if database.is_none() && scratch.is_none() {
            return;
        }
        let needs_server = scratch.is_some()
            || database
                .as_ref()
                .is_some_and(|d| d.kind() == BackendKind::Postgres);
        if !needs_server {
            return;
        }
        // The pool's sockets are registered with the test's own runtime, which is blocked here:
        // awaiting them from another runtime never completes. Only a PostgreSQL schema needs the
        // pool (its drop is a statement); a MariaDB database is dropped over a fresh connection.
        let (done, finished) = std::sync::mpsc::channel();
        let _cleanup = std::thread::spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                runtime.block_on(async move {
                    if let Some(database) = database.filter(|d| d.kind() == BackendKind::Postgres) {
                        let _ = database.clone().teardown().await;
                        database.close().await;
                    }
                    if let Some(scratch) = scratch {
                        let _ = mariadb_admin(
                            &scratch.admin_url,
                            format!("DROP DATABASE IF EXISTS `{}`", scratch.database),
                        )
                        .await;
                    }
                });
            }
            let _ = done.send(());
        });
        let _ = finished.recv_timeout(std::time::Duration::from_secs(30));
    }
}

/// The highest `NNNN_*.sql` version in the migration directory of `kind`, read from the
/// source tree this crate was built from.
///
/// # Panics
/// Panics when the directory cannot be read.
#[allow(clippy::expect_used, reason = "test support")]
#[must_use]
pub fn migration_files_latest_version(kind: BackendKind) -> i64 {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
    match kind {
        BackendKind::MariaDb => dir.push("mariadb"),
        BackendKind::Sqlite => dir.push("sqlite"),
        _ => {}
    }
    std::fs::read_dir(&dir)
        .expect("migration directory")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.split_once('_')?.0.parse::<i64>().ok()
        })
        .max()
        .expect("at least one migration")
}
