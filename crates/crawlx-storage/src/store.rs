//! The generic store handle, its configuration and the PostgreSQL connection logic.
//!
//! [`Store`] carries one backend's pool, the shared settings and the optional delivery
//! buffer. Repository traits are implemented for the PostgreSQL instantiation [`Pg`]; the
//! other engines open, migrate and expose their concurrency primitives through the same
//! type.

use crate::backend::postgres::{set_pool_in_use, TenantPool, MIGRATOR};
use crate::backend::{Backend, PgBackend};
use crate::error::db;
use crawlx_core::StoreError;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgPool};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Pool, lease and engine settings.
#[derive(Clone, Debug)]
pub struct StoreConfig {
    /// Maximum number of pooled connections.
    pub max_connections: u32,
    /// How long a caller waits for a free pooled connection before the pool times out.
    pub acquire_timeout: Duration,
    /// Session lease TTL (30 s).
    pub session_ttl: Duration,
    /// URL batch lease TTL (60 s).
    pub url_batch_ttl: Duration,
    /// The namespace of a test run. PostgreSQL: every connection uses `search_path =
    /// <schema>` and the schema is created on connect, which isolates runs on a shared
    /// database. The other engines ignore it (MariaDB isolates by database name in the URL,
    /// SQLite by file).
    pub schema: Option<String>,
    /// Ping a pooled connection before handing it out, so a connection that died while
    /// idle is replaced transparently (the sqlx default). Fault-injection tests turn this
    /// off so the statement that meets the dead connection is the one that fails.
    pub test_before_acquire: bool,
    /// SQLite only: how long a connection waits for the database lock before it reports
    /// `SQLITE_BUSY`.
    pub busy_timeout: Duration,
    /// SQLite only: create the database file when it does not exist. Read-only commands
    /// turn this off so a mistyped path fails instead of creating an empty database.
    pub create_if_missing: bool,
    /// SQLite only: accept an in-memory database (tests). The pool then holds exactly one
    /// connection, since every connection of an in-memory database is its own database.
    pub allow_memory: bool,
    /// Server-side statement timeout applied to every pooled connection. PostgreSQL sets
    /// `statement_timeout`; MariaDB sets `max_statement_time` (queries that read). SQLite has
    /// no server statement timeout, so a configured value there is refused at open. `None`
    /// keeps the server default.
    pub statement_timeout: Option<Duration>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_connections: 16,
            acquire_timeout: Duration::from_secs(10),
            session_ttl: crate::leases::DEFAULT_SESSION_TTL,
            url_batch_ttl: crate::leases::DEFAULT_URL_BATCH_TTL,
            schema: None,
            test_before_acquire: true,
            busy_timeout: Duration::from_secs(5),
            create_if_missing: true,
            allow_memory: false,
            statement_timeout: None,
        }
    }
}

/// An `authorization_records` row to register (see [`Store::ensure_authorization_record`]).
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationRow<'a> {
    /// Owning tenant; also the tenant of the placeholder creator `api_keys` row.
    pub tenant: crawlx_core::TenantId,
    /// Identifier of the authorization record.
    pub record: crawlx_core::AuthorizationRecordId,
    /// Record version.
    pub version: i32,
    /// Record body as computed by `crawlx-policy`.
    pub body: &'a serde_json::Value,
    /// Digest of the body as computed by `crawlx-policy`.
    pub body_digest: &'a [u8],
    /// Start of the validity window.
    pub valid_from: chrono::DateTime<chrono::Utc>,
    /// End of the validity window.
    pub valid_to: chrono::DateTime<chrono::Utc>,
}

/// Pooled database handle of backend `B`; cheap to clone.
#[derive(Clone, Debug)]
pub struct Store<B: Backend> {
    pub(crate) pool: B::Pool,
    pub(crate) cfg: StoreConfig,
    pub(crate) delivery: Option<Arc<crate::zdr::DeliveryBuffer>>,
    pub(crate) authority: crate::tenant::Authority,
}

/// Pooled PostgreSQL handle; cheap to clone. Implements the repository traits of
/// `crawlx_core::repo` (see the `repos` and `leases` modules).
pub type Pg = Store<PgBackend>;

fn valid_schema(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Build `<prefix><schema><suffix>`. The schema is the only dynamic part and is
/// re-checked against [`valid_schema`] (ASCII alphanumerics and `_`, at most 63
/// bytes), so it can never carry SQL syntax; prefix and suffix are literals.
pub(crate) fn schema_sql(prefix: &str, schema: &str, suffix: &str) -> Result<sqlx::SqlStr, sqlx::Error> {
    use sqlx::SqlSafeStr as _;
    if !valid_schema(schema) {
        return Err(sqlx::Error::Configuration(
            format!("invalid schema name {schema:?}").into(),
        ));
    }
    Ok(sqlx::AssertSqlSafe(format!("{prefix}{schema}{suffix}")).into_sql_str())
}

/// Guard that observes `crawlx.db.query.duration{op}` for the span of a repository
/// method and then refreshes `crawlx.db.pool.in_use`. `op` is `<repo>.<method>`
/// (`journal.intend`, `run.get`, `frontier.lease_batch`, ...) so shared method names
/// stay distinguishable. Bind it to a local for the whole method body
/// (`let _timer = self.query_timer("journal.intend");`); it records on drop, so early
/// returns and `?` are covered.
#[must_use = "bind the timer to a local; dropping it at once records an empty query"]
pub(crate) struct QueryTimer<'a, B: Backend> {
    pool: &'a B::Pool,
    op: &'static str,
    started: Instant,
}

impl<B: Backend> Drop for QueryTimer<'_, B> {
    fn drop(&mut self) {
        Metrics::global()
            .histogram(names::DB_QUERY_DURATION)
            .observe_duration(self.started.elapsed(), &[("op", self.op)]);
        Metrics::global()
            .gauge(names::DB_POOL_IN_USE)
            .set(f64::from(B::pool_in_use(self.pool)), &[]);
    }
}

impl<B: Backend> Store<B> {
    /// Wrap an already connected pool.
    pub(crate) const fn from_parts(pool: B::Pool, cfg: StoreConfig) -> Self {
        Self {
            pool,
            cfg,
            delivery: None,
            authority: crate::tenant::Authority::Operator,
        }
    }

    /// Attach the shared ephemeral delivery store used to hydrate ZDR operational records.
    /// Cloned tenant/request handles retain the same store; content never enters the database.
    #[must_use]
    pub fn with_delivery_buffer(mut self, delivery: Arc<crate::zdr::DeliveryBuffer>) -> Self {
        self.delivery = Some(delivery);
        self
    }

    /// The same pools as a request handle: every request-surface statement then needs a
    /// tenant scope ([`crate::tenant::scope`]) and fails with `AccessDenied` without one, and
    /// engines without row-level security carry the tenant predicate in the statement.
    #[must_use]
    pub fn request_handle(&self) -> Self {
        Self {
            authority: crate::tenant::Authority::Request,
            ..self.clone()
        }
    }

    /// How this handle acts: unscoped operator work or a request that needs a tenant scope.
    #[must_use]
    pub const fn authority(&self) -> crate::tenant::Authority {
        self.authority
    }

    /// Settings this handle was created with.
    #[must_use]
    pub const fn config(&self) -> &StoreConfig {
        &self.cfg
    }

    /// Start timing a repository operation; see [`QueryTimer`].
    pub(crate) fn query_timer(&self, op: &'static str) -> QueryTimer<'_, B> {
        QueryTimer {
            pool: &self.pool,
            op,
            started: Instant::now(),
        }
    }
}

impl Store<PgBackend> {
    /// Connect and (if `cfg.schema` is set) create the schema. Migrations are not
    /// applied; call [`Pg::migrate`].
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] if `url` cannot be parsed or the database is
    /// unreachable, [`StoreError::Conflict`] if `cfg.schema` is not a valid identifier,
    /// and other [`StoreError`] variants if creating the schema or the pool fails.
    pub async fn connect(url: &str, cfg: StoreConfig) -> Result<Self, StoreError> {
        Self::connect_with_mode(url, cfg, true).await
    }

    /// Connect to an already provisioned schema without issuing schema DDL.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid identifiers or connection failures.
    pub async fn connect_existing(url: &str, cfg: StoreConfig) -> Result<Self, StoreError> {
        Self::connect_with_mode(url, cfg, false).await
    }

    async fn connect_with_mode(url: &str, cfg: StoreConfig, create_schema: bool) -> Result<Self, StoreError> {
        let opts = PgConnectOptions::from_str(url).map_err(db)?;
        if let Some(schema) = &cfg.schema {
            if !valid_schema(schema) {
                return Err(StoreError::Conflict(format!("invalid schema name {schema:?}")));
            }
            if create_schema {
                let mut conn = sqlx::PgConnection::connect_with(&opts).await.map_err(db)?;
                conn.execute(schema_sql("CREATE SCHEMA IF NOT EXISTS ", schema, "").map_err(db)?)
                    .await
                    .map_err(db)?;
                conn.close().await.map_err(db)?;
            }
        }
        let schema: Option<Arc<str>> = cfg.schema.as_deref().map(Arc::from);
        let statement_timeout_ms = cfg.statement_timeout.map(|t| t.as_millis());
        let pool = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .acquire_timeout(cfg.acquire_timeout)
            .test_before_acquire(cfg.test_before_acquire)
            .after_connect(move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
                    if let Some(ms) = statement_timeout_ms {
                        conn.execute(sqlx::AssertSqlSafe(format!("SET statement_timeout = {ms}")))
                            .await?;
                    }
                    if let Some(s) = schema {
                        conn.execute(schema_sql("SET search_path TO ", &s, "")?).await?;
                    }
                    Ok(())
                })
            })
            .connect_with(opts)
            .await
            .map_err(db)?;
        set_pool_in_use(&pool);
        Ok(Self::from_parts(TenantPool::new(pool), cfg))
    }

    /// Attach a separately connected, non-owner request role to these repositories.
    /// Unscoped workers and maintenance keep this handle's original pool. Scoped
    /// requests use only `url`, including the pre-authentication key lookup.
    ///
    /// # Errors
    /// Returns [`StoreError`] if connecting fails, the role can bypass RLS, can
    /// assume a table owner, has CREATEROLE, or can create application-schema objects.
    pub async fn with_api_role(&self, url: &str) -> Result<Self, StoreError> {
        let api = Self::connect_existing(url, self.cfg.clone()).await?;
        let unsafe_role: bool = sqlx::query_scalar(
            "SELECT r.rolsuper OR r.rolbypassrls OR r.rolcreaterole \
             OR EXISTS (SELECT 1 FROM pg_roles privileged \
               WHERE (privileged.rolsuper OR privileged.rolbypassrls) \
               AND pg_has_role(current_user, privileged.oid, 'MEMBER')) \
             OR has_schema_privilege(current_user, current_schema(), 'CREATE') \
             OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
               WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p', 'v') \
               AND pg_has_role(current_user, c.relowner, 'MEMBER')) \
             FROM pg_roles r WHERE r.rolname = current_user",
        )
        .fetch_one(api.pool())
        .await
        .map_err(db)?;
        if unsafe_role {
            return Err(StoreError::Conflict(
                "api database role must not own or assume an owner, bypass RLS, manage roles, or create schema objects".to_owned(),
            ));
        }
        Ok(Self {
            pool: self.pool.with_api(api.pool().clone()),
            cfg: self.cfg.clone(),
            delivery: self.delivery.clone(),
            authority: self.authority,
        })
    }

    /// Apply embedded migrations under sqlx's advisory lock, then create the upcoming
    /// `traffic_events` partitions.
    ///
    /// # Errors
    /// Returns [`StoreError`] if a migration fails or the partitions cannot be created.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        MIGRATOR
            .run(self.pool())
            .await
            .map_err(|source| StoreError::Database {
                source: Box::new(source),
                retryable: true,
            })?;
        // traffic_events needs its monthly partitions before the first outcome write
        crate::retention::ensure_traffic_partitions(self, self.db_now().await?, 2).await?;
        Ok(())
    }

    /// The underlying pool (for callers that need raw access, e.g. tests).
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Database time (`now()`); the only clock lease arithmetic uses.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the query fails.
    pub async fn db_now(&self) -> Result<chrono::DateTime<chrono::Utc>, StoreError> {
        sqlx::query_scalar("SELECT now()")
            .fetch_one(&self.pool)
            .await
            .map_err(db)
    }

    /// Drop the isolated schema this handle was created with and close the pool.
    /// No-op without `StoreConfig::schema`. Intended for test teardown.
    ///
    /// # Errors
    /// Returns [`StoreError`] if dropping the schema fails; the pool is not closed
    /// explicitly in that case (the consumed handle is dropped).
    pub async fn drop_schema(self) -> Result<(), StoreError> {
        if let Some(schema) = &self.cfg.schema {
            if valid_schema(schema) {
                self.pool
                    .execute(schema_sql("DROP SCHEMA IF EXISTS ", schema, " CASCADE").map_err(db)?)
                    .await
                    .map_err(db)?;
            }
        }
        self.pool.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn schema_names_are_restricted() {
        assert!(valid_schema("t_abc123"));
        assert!(!valid_schema("a-b"));
        assert!(!valid_schema(""));
        assert!(!valid_schema("x; drop"));
    }
}
