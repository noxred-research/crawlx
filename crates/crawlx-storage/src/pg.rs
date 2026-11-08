//! Connection pool wrapper and migrations.

use crate::error::db;
use crate::repos::authorization::without_lifecycle;
use crate::tenant::TenantPool;
use crawlx_core::StoreError;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgPool};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Pool and lease settings.
#[derive(Clone, Debug)]
pub struct PgConfig {
    /// Maximum number of pooled connections.
    pub max_connections: u32,
    /// How long a caller waits for a free pooled connection before the pool times out.
    pub acquire_timeout: Duration,
    /// Session lease TTL (30 s).
    pub session_ttl: Duration,
    /// URL batch lease TTL (60 s).
    pub url_batch_ttl: Duration,
    /// When set, every connection uses `search_path = <schema>` and the schema is
    /// created on connect. Used by tests to isolate runs on a shared database.
    pub schema: Option<String>,
    /// Ping a pooled connection before handing it out, so a connection that died while
    /// idle is replaced transparently (the sqlx default). Fault-injection tests turn this
    /// off so the statement that meets the dead connection is the one that fails.
    pub test_before_acquire: bool,
}

impl Default for PgConfig {
    fn default() -> Self {
        Self {
            max_connections: 16,
            acquire_timeout: Duration::from_secs(10),
            session_ttl: crate::leases::DEFAULT_SESSION_TTL,
            url_batch_ttl: crate::leases::DEFAULT_URL_BATCH_TTL,
            schema: None,
            test_before_acquire: true,
        }
    }
}

/// An `authorization_records` row to register (see [`Pg::ensure_authorization_record`]).
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

/// Pooled PostgreSQL handle; cheap to clone. Implements the repository traits of
/// `crawlx_core::repo` (see the `repos` and `leases` modules).
#[derive(Clone, Debug)]
pub struct Pg {
    pub(crate) pool: TenantPool,
    pub(crate) cfg: PgConfig,
    pub(crate) delivery: Option<Arc<crate::zdr::DeliveryBuffer>>,
}

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

/// Publish `crawlx.db.pool.in_use` (`size - num_idle`) for `pool`.
pub(crate) fn set_pool_in_use(pool: &PgPool) {
    let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
    let in_use = pool.size().saturating_sub(idle);
    Metrics::global()
        .gauge(names::DB_POOL_IN_USE)
        .set(f64::from(in_use), &[]);
}

/// Guard that observes `crawlx.db.query.duration{op}` for the span of a repository
/// method and then refreshes `crawlx.db.pool.in_use`. `op` is `<repo>.<method>`
/// (`journal.intend`, `run.get`, `frontier.lease_batch`, ...) so shared method names
/// stay distinguishable. Bind it to a local for the whole method body
/// (`let _timer = self.query_timer("journal.intend");`); it records on drop, so early
/// returns and `?` are covered.
#[must_use = "bind the timer to a local; dropping it at once records an empty query"]
pub(crate) struct QueryTimer<'a> {
    pool: &'a PgPool,
    op: &'static str,
    started: Instant,
}

impl Drop for QueryTimer<'_> {
    fn drop(&mut self) {
        Metrics::global()
            .histogram(names::DB_QUERY_DURATION)
            .observe_duration(self.started.elapsed(), &[("op", self.op)]);
        set_pool_in_use(self.pool);
    }
}

impl Pg {
    /// Connect and (if `cfg.schema` is set) create the schema. Migrations are not
    /// applied; call [`Pg::migrate`].
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] if `url` cannot be parsed or the database is
    /// unreachable, [`StoreError::Conflict`] if `cfg.schema` is not a valid identifier,
    /// and other [`StoreError`] variants if creating the schema or the pool fails.
    pub async fn connect(url: &str, cfg: PgConfig) -> Result<Self, StoreError> {
        Self::connect_with_mode(url, cfg, true).await
    }

    /// Connect to an already provisioned schema without issuing schema DDL.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid identifiers or connection failures.
    pub async fn connect_existing(url: &str, cfg: PgConfig) -> Result<Self, StoreError> {
        Self::connect_with_mode(url, cfg, false).await
    }

    async fn connect_with_mode(url: &str, cfg: PgConfig, create_schema: bool) -> Result<Self, StoreError> {
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
        let pool = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .acquire_timeout(cfg.acquire_timeout)
            .test_before_acquire(cfg.test_before_acquire)
            .after_connect(move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
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
        Ok(Self {
            pool: TenantPool::new(pool),
            cfg,
            delivery: None,
        })
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
        })
    }

    /// Attach the shared ephemeral delivery store used to hydrate ZDR operational records.
    /// Cloned tenant/request handles retain the same store; content never enters PostgreSQL.
    #[must_use]
    pub fn with_delivery_buffer(mut self, delivery: Arc<crate::zdr::DeliveryBuffer>) -> Self {
        self.delivery = Some(delivery);
        self
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

    /// Settings this handle was created with.
    #[must_use]
    pub fn config(&self) -> &PgConfig {
        &self.cfg
    }

    /// Start timing a repository operation; see [`QueryTimer`].
    pub(crate) fn query_timer(&self, op: &'static str) -> QueryTimer<'_> {
        QueryTimer {
            pool: &self.pool,
            op,
            started: Instant::now(),
        }
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
    /// No-op without `PgConfig::schema`. Intended for test teardown.
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

    /// Register an authorization record (`authorization_records`) so a run can reference it.
    /// The record's creator is a placeholder `api_keys` row of the tenant (`cli_<tenant>`).
    /// Idempotent. The body and digest are computed by `crawlx-policy`; the stored body never
    /// carries lifecycle state (`verifiedAt`, `revokedAt`, `revokedReason`), which lives in
    /// columns. The record stays unverified (`verified_at` NULL): only the API route checks
    /// an ownership proof.
    ///
    /// # Errors
    /// Returns [`StoreError`] if registering the tenant, the placeholder `api_keys` row
    /// or the record fails.
    pub async fn ensure_authorization_record(&self, row: &AuthorizationRow<'_>) -> Result<(), StoreError> {
        self.ensure_tenant(row.tenant, "local").await?;
        sqlx::query(
            "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes) VALUES ($1, $1, $2, '\\x'::bytea, '{}') \
             ON CONFLICT DO NOTHING",
        )
        .bind(row.tenant.0)
        .bind(format!("cli_{}", row.tenant.0.simple()))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        let body = without_lifecycle(row.body);
        sqlx::query(
            "INSERT INTO authorization_records (record_id, tenant_id, version, body, body_digest, valid_from, valid_to, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $2) ON CONFLICT (record_id) DO NOTHING",
        )
        .bind(row.record.0)
        .bind(row.tenant.0)
        .bind(row.version)
        .bind(body.as_ref())
        .bind(row.body_digest)
        .bind(row.valid_from)
        .bind(row.valid_to)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Insert a tenant if absent (runs reference `tenants`).
    ///
    /// # Errors
    /// Returns [`StoreError`] if the insert fails.
    pub async fn ensure_tenant(&self, tenant: crawlx_core::TenantId, name: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO tenants (tenant_id, name, kms_key_id) VALUES ($1, $2, 'local') ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(tenant.0)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(db)?;
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
