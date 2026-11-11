//! Fixtures of the tenancy suite: a database of any engine seeded with two tenants' worth of
//! request-surface rows, and the operator and request handles to read it back.
//!
//! The rows are written with plain statements (never through the repositories under test), so
//! the isolation cases do not depend on the engine support of other repositories. The
//! request handle is the one a deployment serves requests with: on PostgreSQL the restricted
//! non-owner login (the production grants of `docker/provision-api-role.sql` applied to the
//! test schema, row-level security enforced); on MariaDB and SQLite the application-enforced
//! tenant predicate over the same pool.

use crate::backend::{BackendKind, Database, MariaBackend, PgBackend, SqliteBackend};
use crate::codec::to_json_text;
use crate::repos::api::{ensure_tenant_on, ApiKeyRow, ApiRepo};
use crate::sql::Stmt;
use crate::store::Store;
use crate::tenant::Tenancy;
use crate::testkit::rig::Rig;
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use sqlx::Executor as _;
use std::sync::atomic::{AtomicI64, Ordering};
use uuid::Uuid;

/// A store of any engine.
#[derive(Clone, Debug)]
pub enum Handle {
    /// PostgreSQL.
    Postgres(Store<PgBackend>),
    /// MariaDB.
    MariaDb(Store<MariaBackend>),
    /// SQLite.
    Sqlite(Store<SqliteBackend>),
}

impl Handle {
    /// The same pools as a request handle.
    #[must_use]
    pub fn request(&self) -> Self {
        match self {
            Self::Postgres(store) => Self::Postgres(store.request_handle()),
            Self::MariaDb(store) => Self::MariaDb(store.request_handle()),
            Self::Sqlite(store) => Self::Sqlite(store.request_handle()),
        }
    }

    /// Which engine this is.
    #[must_use]
    pub const fn kind(&self) -> BackendKind {
        match self {
            Self::Postgres(_) => BackendKind::Postgres,
            Self::MariaDb(_) => BackendKind::MariaDb,
            Self::Sqlite(_) => BackendKind::Sqlite,
        }
    }
}

impl Handle {
    /// The unscoped operator handle over the migrated database of `rig`.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the rig holds no database.
    pub fn operator(rig: &Rig) -> Result<Self, StoreError> {
        operator_handle(rig.database())
    }

    /// SQL for the instant `at` as a literal of this engine, for raw probes.
    #[must_use]
    pub fn ts(&self, at: chrono::DateTime<chrono::Utc>) -> String {
        match self {
            Self::Postgres(_) => format!(
                "'{}'::timestamptz",
                at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
            ),
            Self::MariaDb(_) => format!("'{}'", at.naive_utc().format("%Y-%m-%d %H:%M:%S%.6f")),
            Self::Sqlite(_) => at.timestamp_micros().to_string(),
        }
    }

    /// SQL for the UUID `id` as a literal of this engine, for raw probes.
    #[must_use]
    pub fn id(&self, id: Uuid) -> String {
        match self {
            Self::Postgres(_) => format!("'{id}'::uuid"),
            _ => format!("x'{}'", id.simple()),
        }
    }

    /// SQL for `bytes` as a binary literal of this engine, for raw probes.
    #[must_use]
    pub fn bytes(&self, bytes: &[u8]) -> String {
        match self {
            Self::Postgres(_) => format!("'\\x{}'::bytea", hex::encode(bytes)),
            _ => format!("x'{}'", hex::encode(bytes)),
        }
    }

    /// `SELECT count(*) FROM table WHERE filter`, with `filter` written by the test.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the statement fails.
    pub async fn count(&self, table: &str, filter: &str) -> Result<i64, StoreError> {
        let sql = format!("SELECT count(*) AS v FROM {table} WHERE {filter}");
        crate::with_handle!(self, |store| scalar_i64(store, &sql).await)
    }

    /// One column of the single row of `table` matching `filter`, as text (`hex` renders a binary
    /// column as lower-case hexadecimal), `None` when no row matches.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the statement fails.
    pub async fn column(
        &self,
        table: &str,
        column: &str,
        filter: &str,
        hex: bool,
    ) -> Result<Option<String>, StoreError> {
        let expr = match (self, hex) {
            // works for `uuid` and `bytea` columns alike: no dashes, no `\x` prefix
            (Self::Postgres(_), true) => format!("replace(replace({column}::text, '-', ''), '\\x', '')"),
            (Self::Postgres(_), false) => format!("{column}::text"),
            (_, true) => format!("LOWER(HEX({column}))"),
            (_, false) => column.to_owned(),
        };
        let sql = format!("SELECT {expr} AS v FROM {table} WHERE {filter}");
        crate::with_handle!(self, |store| scalar_text(store, &sql).await)
    }

    /// The engine's wall clock as a SQL expression (`clock_timestamp()` and its equivalents).
    #[must_use]
    pub const fn clock_sql(&self) -> &'static str {
        match self {
            Self::Postgres(_) => "clock_timestamp()",
            Self::MariaDb(_) => "SYSDATE(6)",
            Self::Sqlite(_) => "CAST(unixepoch('subsec') * 1000000 AS INTEGER)",
        }
    }

    /// Insert `tenant` when absent.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the statement fails.
    pub async fn ensure_tenant(&self, tenant: TenantId, name: &str) -> Result<(), StoreError> {
        crate::with_handle!(self, |store| ensure_tenant_on_store(store, tenant, name).await)
    }

    /// The states whose cluster membership rows this handle reads for `tenant`, in id order.
    ///
    /// The statement runs under the tenant's request scope. With `predicate` it carries the
    /// registry's tenant predicate for the table (what MariaDB and SQLite rely on); without
    /// it only the engine filters, which on PostgreSQL is row-level security.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the statement fails.
    pub async fn visible_memberships(
        &self,
        tenant: TenantId,
        predicate: bool,
    ) -> Result<Vec<Uuid>, StoreError> {
        crate::with_handle!(self, |store| memberships_on(store, tenant, predicate).await)
    }

    /// Run a literal statement as the owner and return the error text it fails with.
    pub async fn error_of(&self, sql: &str) -> Option<String> {
        self.run(sql).await.err().map(|error| format!("{error:?}"))
    }

    /// Run a literal statement as the owner.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the statement fails.
    pub async fn run(&self, sql: &str) -> Result<u64, StoreError> {
        crate::with_handle!(self, |store| run_on(store, sql).await)
    }
}

async fn ensure_tenant_on_store<B: Tenancy>(
    store: &Store<B>,
    tenant: TenantId,
    name: &str,
) -> Result<(), StoreError> {
    let mut tx = store.begin_write().await?;
    ensure_tenant_on::<B>(tx.conn(), tenant, name).await?;
    tx.commit().await
}

async fn memberships_on<B: Tenancy>(
    store: &Store<B>,
    tenant: TenantId,
    predicate: bool,
) -> Result<Vec<Uuid>, StoreError> {
    crate::tenant::scope(tenant, async {
        let mut sql = String::from("SELECT m.state_id AS v FROM state_cluster_membership m");
        if predicate {
            let scoped = crate::tenant::TenantGuard::for_tenant(tenant).scope::<B::Dialect>(
                "state_cluster_membership",
                "m",
                "$1",
            )?;
            sql.push_str(" WHERE ");
            sql.push_str(&scoped.predicate);
        }
        sql.push_str(" ORDER BY m.state_id");
        let mut statement = Stmt::<B>::dynamic(&sql);
        if predicate {
            statement = statement.uuid(tenant.0);
        }
        statement
            .fetch_all_pool(&store.pool)
            .await?
            .iter()
            .map(|row| crate::sql::SqlRow::uuid(row, "v"))
            .collect()
    })
    .await
}

async fn scalar_i64<B: Tenancy>(store: &Store<B>, sql: &str) -> Result<i64, StoreError> {
    let row = Stmt::<B>::dynamic(sql).fetch_one_pool(&store.pool).await?;
    crate::sql::SqlRow::i64(&row, "v")
}

async fn scalar_text<B: Tenancy>(store: &Store<B>, sql: &str) -> Result<Option<String>, StoreError> {
    let row = Stmt::<B>::dynamic(sql).fetch_optional_pool(&store.pool).await?;
    row.map(|row| crate::sql::SqlRow::opt_text(&row, "v"))
        .transpose()
        .map(Option::flatten)
}

async fn run_on<B: Tenancy>(store: &Store<B>, sql: &str) -> Result<u64, StoreError> {
    Stmt::<B>::dynamic(sql).execute_write(&store.pool).await
}

/// The operator handle and the request handle of one rig.
#[derive(Debug)]
pub struct Harness {
    /// Unscoped operator authority (the table owner on PostgreSQL).
    pub operator: Handle,
    /// The handle requests are served with.
    pub request: Handle,
    role: Option<String>,
}

/// Run `$body` with `$store` bound to the concrete store of `$handle` (the body is compiled
/// once per engine).
#[macro_export]
macro_rules! with_handle {
    ($handle:expr, |$store:ident| $body:expr) => {
        match $handle {
            $crate::testkit::tenancy::Handle::Postgres($store) => $body,
            $crate::testkit::tenancy::Handle::MariaDb($store) => $body,
            $crate::testkit::tenancy::Handle::Sqlite($store) => $body,
        }
    };
}

fn operator_handle(database: &Database) -> Result<Handle, StoreError> {
    match database.kind() {
        BackendKind::Postgres => database
            .as_postgres()
            .cloned()
            .map(Handle::Postgres)
            .ok_or_else(|| StoreError::Backend("no postgres handle".to_owned())),
        BackendKind::MariaDb => database
            .as_mariadb()
            .cloned()
            .map(Handle::MariaDb)
            .ok_or_else(|| StoreError::Backend("no mariadb handle".to_owned())),
        _ => database
            .as_sqlite()
            .cloned()
            .map(Handle::Sqlite)
            .ok_or_else(|| StoreError::Backend("no sqlite handle".to_owned())),
    }
}

impl Harness {
    /// Handles over the migrated database of `rig`. On PostgreSQL this provisions the
    /// restricted login with the production grants; with the `unscoped-for-test` mutation
    /// feature the request handle is the table owner instead, which row-level security does
    /// not bind, so the proofs fail exactly when the application guard is the only barrier
    /// they test.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the handles or the PostgreSQL role cannot be set up.
    pub async fn new(rig: &Rig) -> Result<Self, StoreError> {
        let database = rig.database();
        let operator = operator_handle(database)?;
        let Handle::Postgres(pg) = &operator else {
            let request = operator.request();
            return Ok(Self {
                operator,
                request,
                role: None,
            });
        };
        if cfg!(feature = "unscoped-for-test") {
            let request = operator.request();
            return Ok(Self {
                operator,
                request,
                role: None,
            });
        }
        let url = std::env::var(crate::testkit::rig::POSTGRES_URL_VAR)
            .map_err(|_| StoreError::Backend("CRAWLX_TEST_DATABASE_URL is not set".to_owned()))?;
        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(pg.pool())
            .await
            .map_err(crate::error::db)?;
        let role = format!("tenancy_api_{}", Uuid::now_v7().simple());
        let password = Uuid::now_v7().simple().to_string();
        let create = format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
        );
        pg.pool()
            .execute(sqlx::AssertSqlSafe(create))
            .await
            .map_err(crate::error::db)?;
        // the production grant logic, against this schema and this role
        let production = include_str!("../../../../docker/provision-api-role.sql");
        let marker = "REVOKE CREATE ON SCHEMA public FROM PUBLIC;";
        let body = production
            .split_once(marker)
            .map(|(_, body)| body)
            .ok_or_else(|| StoreError::Backend("provision-api-role.sql changed shape".to_owned()))?;
        let provisioning = format!("{marker}{body}")
            .replace("public", &schema)
            .replace("crawlx_api", &role);
        sqlx::raw_sql(sqlx::AssertSqlSafe(provisioning))
            .execute(pg.pool())
            .await
            .map_err(crate::error::db)?;
        let mut restricted = url::Url::parse(&url).map_err(|e| StoreError::Backend(e.to_string()))?;
        restricted
            .set_username(&role)
            .map_err(|()| StoreError::Backend("cannot set the role name".to_owned()))?;
        restricted
            .set_password(Some(&password))
            .map_err(|()| StoreError::Backend("cannot set the role password".to_owned()))?;
        let request = pg
            .with_api_role(restricted.as_str())
            .await
            .map_err(|e| StoreError::Backend(format!("restricted login rejected: {e}")))?
            .request_handle();
        Ok(Self {
            operator: operator.clone(),
            request: Handle::Postgres(request),
            role: Some(role),
        })
    }

    /// Drop the restricted PostgreSQL login (no-op elsewhere). Call before the rig closes.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the role cannot be dropped.
    pub async fn finish(self) -> Result<(), StoreError> {
        let (Some(role), Handle::Postgres(pg)) = (self.role, &self.operator) else {
            return Ok(());
        };
        for statement in [
            format!("DROP OWNED BY {role}"),
            format!("DROP ROLE IF EXISTS {role}"),
        ] {
            pg.pool()
                .execute(sqlx::AssertSqlSafe(statement))
                .await
                .map_err(crate::error::db)?;
        }
        Ok(())
    }
}

/// The ids of one tenant's seeded rows.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TenantRows {
    /// The tenant.
    pub tenant: TenantId,
    /// Its API key.
    pub key: Uuid,
    /// The key prefix.
    pub prefix: String,
    /// Its crawl run.
    pub run: CrawlRunId,
    /// A session of the run.
    pub session: Uuid,
    /// A state of the run.
    pub state: Uuid,
    /// A second state (the transition's target).
    pub state_after: Uuid,
    /// The proposed action awaiting approval.
    pub action: Uuid,
    /// Its approval.
    pub approval: Uuid,
    /// The action's context hash.
    pub context_hash: Vec<u8>,
    /// The transition (of a second, executed action).
    pub transition: Uuid,
    /// The network epoch.
    pub epoch: Uuid,
    /// The safety decision.
    pub decision: Uuid,
    /// A live artifact of the run.
    pub artifact: Uuid,
    /// Its content digest.
    pub artifact_digest: [u8; 32],
    /// The idempotency key.
    pub idem_key: String,
    /// The authorization record.
    pub record: crawlx_core::AuthorizationRecordId,
}

/// Source of `actions.dataset_page` on engines whose schema carries it without an identity.
static DATASET_PAGE: AtomicI64 = AtomicI64::new(1);

async fn insert<'a, B: Tenancy>(
    store: &Store<B>,
    sql: &str,
    bind: impl FnOnce(Stmt<'a, B>) -> Stmt<'a, B>,
) -> Result<(), StoreError> {
    bind(Stmt::<B>::dynamic(sql)).execute_write(&store.pool).await?;
    Ok(())
}

/// Seed `tenant` with one of everything the request surface reads. `label` keeps the
/// uniquely constrained text apart between tenants.
///
/// # Errors
/// Returns [`StoreError`] when a statement fails.
pub async fn seed(handle: &Handle, tenant: TenantId, label: &str) -> Result<TenantRows, StoreError> {
    crate::with_handle!(handle, |store| seed_on(store, tenant, label).await)
}

#[allow(clippy::too_many_lines, reason = "one linear fixture")]
async fn seed_on<B: Tenancy>(
    store: &Store<B>,
    tenant: TenantId,
    label: &str,
) -> Result<TenantRows, StoreError>
where
    crate::backend::strategy::Row<B>: crate::sql::SqlRow,
{
    let now = chrono::Utc::now();
    let key = Uuid::now_v7();
    let prefix = format!("{label}_{}", key.simple());
    let repo = ApiRepo::new(store.clone());
    repo.key_insert(
        &ApiKeyRow {
            key_id: key,
            tenant,
            prefix: prefix.clone(),
            hash: [7; 32],
            scopes: vec!["crawl:read".to_owned(), "crawl:write".to_owned()],
            expires_at: None,
            revoked: false,
        },
        label,
    )
    .await?;
    let mut conn_tenant = store.begin_write().await?;
    ensure_tenant_on::<B>(conn_tenant.conn(), tenant, label).await?;
    conn_tenant.commit().await?;

    let run = CrawlRunId::new();
    let session = Uuid::now_v7();
    let state = Uuid::now_v7();
    let state_after = Uuid::now_v7();
    let decision = Uuid::now_v7();
    let action = Uuid::now_v7();
    let done_action = Uuid::now_v7();
    let approval = Uuid::now_v7();
    let transition = Uuid::now_v7();
    let epoch = Uuid::now_v7();
    let artifact = Uuid::now_v7();
    let context_hash = Uuid::now_v7().as_bytes().to_vec();
    let artifact_digest = *blake3::hash(artifact.as_bytes()).as_bytes();
    let config = serde_json::json!({ "output": { "webhook": { "url": format!("https://hooks.example.test/{label}") } } });
    let digest = [9_u8; 32];
    let cluster = Uuid::now_v7();
    let empty = serde_json::json!({});
    let no_rules: Vec<String> = Vec::new();
    let minhash = [1_u8; 64];
    let page_payload = serde_json::json!({ "url": "https://app.example.test/" });
    let approval_expiry = now + chrono::Duration::hours(1);

    insert(
        store,
        "INSERT INTO crawl_runs (run_id, tenant_id, mode, seed, safety_profile, policy_version, identity_version, \
         state_algo_version, query_classifier_version, config, config_digest, retention_mode, retention_days) \
         VALUES ($1, $2, 'static', 1, 'read_only', 1, 1, 1, 1, $3, $4, 'standard', 30)",
        |s| s.uuid(run.0).uuid(tenant.0).json(&config).bytes(&digest),
    )
    .await?;
    insert(
        store,
        "INSERT INTO crawl_sessions (session_id, run_id, role, run_index, schedule_slot) VALUES ($1, $2, 'anonymous', 0, 0)",
        |s| s.uuid(session).uuid(run.0),
    )
    .await?;
    for id in [state, state_after] {
        insert(
            store,
            "INSERT INTO states (state_id, run_id, session_id, route_key, semantic_affordance_minhash, dom_structure_simhash, \
             visible_identity_digest, frame_tree_digest, epoch_navigation, epoch_document, epoch_mutation, state_algo_version) \
             VALUES ($1, $2, $3, '/', $4, 1, $5, $5, 1, 1, 1, 1)",
            |s| s.uuid(id).uuid(run.0).uuid(session).bytes(&minhash).bytes(&digest),
        )
        .await?;
    }
    insert(
        store,
        "INSERT INTO action_contexts (run_id, context_hash, principal, route_template, identity_hash, identity_version, \
         action_kind, state_cluster_id, succeeded, succeeded_trusted) VALUES ($1, $2, 'anonymous', '/', $3, 1, 'click', $4, 1, 1)",
        |s| s.uuid(run.0).bytes(&context_hash).bytes(&digest).uuid(cluster),
    )
    .await?;
    let context_id: i64 = {
        let row = Stmt::<B>::dynamic(
            "SELECT context_id AS v FROM action_contexts WHERE run_id = $1 AND context_hash = $2",
        )
        .uuid(run.0)
        .bytes(&context_hash)
        .fetch_one_pool(&store.pool)
        .await?;
        crate::sql::SqlRow::i64(&row, "v")?
    };
    insert(
        store,
        "INSERT INTO safety_decisions (decision_id, run_id, session_id, risk_class, verdict, profile, rules, evidence, policy_version) \
         VALUES ($1, $2, $3, 'navigation_reveal', 'approval_required', 'read_only', $4, $5, 1)",
        |s| s.uuid(decision).uuid(run.0).uuid(session).text_list(&no_rules).json(&empty),
    )
    .await?;
    // two actions: one executed (it owns the transition), one proposed and held for approval
    for (id, seq, status, hold) in [
        (done_action, 1_i64, "proposed", "none"),
        (action, 2, "proposed", "awaiting_approval"),
    ] {
        let paged = B::KIND != BackendKind::Postgres;
        let columns = if paged { ", dataset_page" } else { "" };
        let value = if paged { ", $9" } else { "" };
        let sql = format!(
            "INSERT INTO actions (action_id, run_id, session_id, seq, context_id, action_kind, strategy, strategy_version, \
             epoch_navigation, epoch_document, epoch_mutation, fidelity, lane, safety_decision_id, status, hold{columns}) \
             VALUES ($1, $2, $3, $4, $5, 'click', 'seed', 1, 1, 1, 1, 'native_pointer', 'trusted_ui', $6, $7::text::action_status, $8{value})"
        );
        let page = DATASET_PAGE.fetch_add(1, Ordering::Relaxed);
        let mut statement = Stmt::<B>::dynamic(&sql)
            .uuid(id)
            .uuid(run.0)
            .uuid(session)
            .i64(seq)
            .i64(context_id)
            .uuid(decision)
            .text(status)
            .text(hold);
        if paged {
            statement = statement.i64(page);
        }
        statement.execute_write(&store.pool).await?;
    }
    // the executed action walks the legal status path to `succeeded`
    for status in ["intended", "succeeded"] {
        insert(
            store,
            "UPDATE actions SET status = $2::text::action_status WHERE action_id = $1",
            |s| s.uuid(done_action).text(status),
        )
        .await?;
    }
    insert(
        store,
        "INSERT INTO network_epochs (epoch_id, run_id, session_id, action_id, lane, started_at) \
         VALUES ($1, $2, $3, $4, 'trusted_ui', $5)",
        |s| s.uuid(epoch).uuid(run.0).uuid(session).uuid(done_action).ts(now),
    )
    .await?;
    insert(
        store,
        "INSERT INTO traffic_events (occurred_at, run_id, epoch_id, seq, lane, origin, url_hash, method, url_redacted, status) \
         VALUES ($1, $2, $3, 1, 'trusted_ui', 'page', $4, 'GET', 'https://app.example.test/', 200)",
        |s| s.ts(now).uuid(run.0).uuid(epoch).bytes(&digest),
    )
    .await?;
    insert(
        store,
        "INSERT INTO transitions (transition_id, run_id, session_id, before_state_id, action_id, network_epoch_id, after_state_id, lane, settle_report) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'trusted_ui', $8)",
        |s| {
            s.uuid(transition)
                .uuid(run.0)
                .uuid(session)
                .uuid(state)
                .uuid(done_action)
                .uuid(epoch)
                .uuid(state_after)
                .json(&empty)
        },
    )
    .await?;
    insert(
        store,
        "INSERT INTO approvals (approval_id, run_id, action_id, safety_decision_id, risk_class, summary, expires_at) \
         VALUES ($1, $2, $3, $4, 'navigation_reveal', $5, $6)",
        |s| {
            s.uuid(approval)
                .uuid(run.0)
                .uuid(action)
                .uuid(decision)
                .json(&empty)
                .ts(approval_expiry)
        },
    )
    .await?;
    for (seq, kind) in [(1_i64, "navigation"), (2, "run.created")] {
        insert(
            store,
            "INSERT INTO crawl_events (run_id, seq, type, payload) VALUES ($1, $2, $3, $4)",
            |s| s.uuid(run.0).i64(seq).text(kind).json(&page_payload),
        )
        .await?;
    }
    insert(
        store,
        "INSERT INTO artifacts (artifact_id, tenant_id, run_id, kind, bucket, object_key, size_bytes, content_digest, content_type, sensitivity) \
         VALUES ($1, $2, $3, 'markdown', 'b', $4, 1, $5, 'text/markdown', 'content')",
        |s| s.uuid(artifact).uuid(tenant.0).uuid(run.0).text(label).bytes(&artifact_digest),
    )
    .await?;
    let idem_key = format!("idem-{label}");
    repo.idem_begin(tenant, &idem_key, crawlx_core::hash::Digest([3; 32]), now)
        .await?;
    let record = crawlx_core::AuthorizationRecordId::new();
    let body = serde_json::json!({ "id": record.0, "tenant": tenant.0 });
    let verification = serde_json::json!({ "kind": "dns_txt" });
    repo.authorization_create(&crate::repos::authorization::NewAuthorization {
        tenant,
        id: record,
        version: 1,
        body: &body,
        body_digest: &[5; 32],
        valid_from: now,
        valid_to: now + chrono::Duration::days(30),
        created_by: key,
        verified_at: now,
        verification: &verification,
    })
    .await?;
    repo.webhook_enqueue(&crate::repos::api::WebhookDelivery {
        id: Uuid::now_v7(),
        run,
        event_seq: 2,
        event_type: "run.created".to_owned(),
        url: format!("https://hooks.example.test/{label}"),
        status: crate::repos::api::DeliveryStatus::Pending,
        attempts: 0,
        next_attempt_at: now,
        delivered_at: None,
        last_status: None,
        last_error: None,
    })
    .await?;
    Ok(TenantRows {
        tenant,
        key,
        prefix,
        run,
        session,
        state,
        state_after,
        action,
        approval,
        context_hash,
        transition,
        epoch,
        decision,
        artifact,
        artifact_digest,
        idem_key,
        record,
    })
}

/// The JSON text a column stores (test helper for raw probes).
#[must_use]
pub fn json_text(value: &serde_json::Value) -> String {
    to_json_text(value)
}
