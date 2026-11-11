//! Tenant scope of the current request or background job, and the application-enforced
//! tenant predicate for engines without row-level security.
//!
//! Request code scopes its future with [`scope`]. On PostgreSQL the pool executor then uses
//! the restricted API role and sets `app.tenant_id` inside each transaction (see
//! `backend::postgres`); explicit repository transactions retain their existing atomicity,
//! implicit statements receive their own transaction, and dropping a future or stream drops
//! its transaction so sqlx rolls it back before returning the connection to the pool.
//!
//! MariaDB and SQLite have no row-level security. Their request-surface repositories build
//! the tenant predicate with [`TenantGuard`] from the [`crate::tenant_tables`] registry, and
//! a request that carries no tenant scope fails closed with
//! [`StoreError::AccessDenied`] instead of reading nothing.

use crate::backend::strategy::Conn;
use crate::backend::Dialect;
use crate::sql::{Sql, Stmt};
use crate::tenant_tables::{self, TenantKey};
use crawlx_core::{StoreError, TenantId};
use std::future::Future;

tokio::task_local! {
    static TENANT: TenantId;
}

/// Tenant attached to the current request or background job, if any.
#[must_use]
pub fn current() -> Option<TenantId> {
    TENANT.try_with(|tenant| *tenant).ok()
}

/// Execute `work` with tenant-local database authority. Nested scopes restore the
/// previous tenant when they finish, including cancellation and unwinding.
pub async fn scope<F: Future>(tenant: TenantId, work: F) -> F::Output {
    TENANT.scope(tenant, work).await
}

/// Poll streaming response work under the same authority as its request.
pub fn scope_sync<R>(tenant: TenantId, work: impl FnOnce() -> R) -> R {
    TENANT.sync_scope(tenant, work)
}

/// How a [`crate::Store`] handle acts.
///
/// An [`Authority::Operator`] handle is worker, migration and maintenance code: unscoped,
/// like the table owner's pool. An [`Authority::Request`] handle serves the API: every
/// request-surface statement must run under a tenant [`scope`] and fails closed with
/// `AccessDenied` otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Authority {
    /// Unscoped operator work.
    Operator,
    /// A request handle that needs a tenant scope.
    Request,
}

/// A tenant predicate and the tenant to bind at its placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "the predicate is useless unless it joins the statement and the tenant is bound"]
pub struct TenantScope {
    /// SQL condition to `AND` into the statement's `WHERE` clause.
    pub predicate: String,
    /// The tenant to bind at the placeholder the predicate was built with.
    pub tenant: TenantId,
}

/// Builds the tenant predicate of request-surface statements on engines that enforce
/// tenancy in the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantGuard {
    tenant: TenantId,
}

impl TenantGuard {
    /// A guard for the tenant of the current [`scope`].
    ///
    /// # Errors
    /// Returns [`StoreError::AccessDenied`] when no tenant scope is active: a request
    /// handle must fail closed, never return an unscoped result.
    pub fn current() -> Result<Self, StoreError> {
        current()
            .map(|tenant| Self { tenant })
            .ok_or_else(|| StoreError::AccessDenied("tenant scope required".to_owned()))
    }

    /// A guard for an explicit tenant (operator code acting for one tenant).
    #[must_use]
    pub const fn for_tenant(tenant: TenantId) -> Self {
        Self { tenant }
    }

    /// The tenant this guard scopes to.
    #[must_use]
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }

    /// The predicate that restricts `table` (referenced as `alias`, or by its own name when
    /// `alias` is empty) to this tenant, with the tenant bound at `placeholder` (already
    /// numbered for the engine). Every column is qualified: an unqualified name inside the
    /// `EXISTS` subquery would resolve to the subquery's own table and match every row.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] when `table` is not in the registry and
    /// [`StoreError::AccessDenied`] when it is operator-only.
    pub fn scope<D: Dialect>(
        self,
        table: &str,
        alias: &str,
        placeholder: &str,
    ) -> Result<TenantScope, StoreError> {
        let entry = tenant_tables::lookup(table)
            .ok_or_else(|| StoreError::Conflict(format!("table {table} is not in the tenant registry")))?;
        let qualifier = if alias.is_empty() { table } else { alias };
        let column = |name: &str| format!("{qualifier}.{name}");
        let predicate = match entry.key {
            TenantKey::Column(name) => format!("{} = {placeholder}", column(name)),
            TenantKey::ViaRun => format!(
                "EXISTS (SELECT 1 FROM crawl_runs scope_r WHERE scope_r.run_id = {} AND scope_r.tenant_id = {placeholder})",
                column("run_id")
            ),
            TenantKey::ViaState => {
                let state_table = if alias.is_empty() { table } else { alias };
                format!(
                    "EXISTS (SELECT 1 FROM states scope_s JOIN crawl_runs scope_r ON scope_r.run_id = scope_s.run_id \
                     WHERE scope_s.state_id = {state_table}.state_id AND scope_r.tenant_id = {placeholder})"
                )
            }
            TenantKey::ViaJob => format!(
                "EXISTS (SELECT 1 FROM intel_jobs scope_j WHERE scope_j.job_id = {} AND scope_j.tenant_id = {placeholder})",
                column("job_id")
            ),
            TenantKey::ViaMonitor => format!(
                "EXISTS (SELECT 1 FROM monitors scope_m WHERE scope_m.monitor_id = {} AND scope_m.tenant_id = {placeholder})",
                column("monitor_id")
            ),
            TenantKey::ViaCheck => format!(
                "EXISTS (SELECT 1 FROM monitor_checks scope_c WHERE scope_c.check_id = {} AND scope_c.tenant_id = {placeholder})",
                column("check_id")
            ),
            TenantKey::ViaSession => format!(
                "EXISTS (SELECT 1 FROM crawl_sessions scope_s JOIN crawl_runs scope_r ON scope_r.run_id = scope_s.run_id \
                 WHERE scope_s.session_id = {} AND scope_r.tenant_id = {placeholder})",
                column("session_id")
            ),
            TenantKey::Global => {
                return Err(StoreError::AccessDenied(format!(
                    "table {table} is operator-only"
                )));
            }
            #[allow(unreachable_patterns, reason = "TenantKey is non_exhaustive")]
            _ => {
                return Err(StoreError::AccessDenied(format!(
                    "table {table} has an unknown tenant key"
                )));
            }
        };
        Ok(TenantScope {
            predicate,
            tenant: self.tenant,
        })
    }

    /// Like [`TenantGuard::scope`], numbering the placeholder for `D` from `n`.
    ///
    /// # Errors
    /// See [`TenantGuard::scope`].
    pub fn scope_at<D: Dialect>(self, table: &str, alias: &str, n: usize) -> Result<TenantScope, StoreError> {
        self.scope::<D>(table, alias, &D::placeholder(n))
    }
}

/// The tenancy one request-surface statement runs under, resolved from the handle's
/// [`Authority`], the engine and the current tenant [`scope`].
///
/// PostgreSQL enforces tenants itself (row-level security plus the restricted login), so its
/// statements stay as they are and the scope only decides whether a request may run at all.
/// MariaDB and SQLite carry the predicate of [`TenantGuard::scope`] in every statement.
#[derive(Clone, Copy, Debug)]
pub struct Scope {
    guard: Option<TenantGuard>,
}

impl<B: crate::sql::Sql> crate::Store<B> {
    /// Resolve the tenancy of a request-surface statement.
    ///
    /// # Errors
    /// Returns [`StoreError::AccessDenied`] when this is a request handle and no tenant
    /// scope is active.
    pub fn scope(&self) -> Result<Scope, StoreError> {
        if cfg!(feature = "unscoped-for-test") {
            // The mutation guard of the isolation proofs: with the guard off the tenancy
            // suite must fail. Never enabled outside tests.
            return Ok(Scope { guard: None });
        }
        match (self.authority, current()) {
            (Authority::Request, None) => Err(StoreError::AccessDenied("tenant scope required".to_owned())),
            (_, Some(tenant)) if !B::KIND.capabilities().database_enforced_tenancy => Ok(Scope {
                guard: Some(TenantGuard::for_tenant(tenant)),
            }),
            _ => Ok(Scope { guard: None }),
        }
    }
}

impl<B: crate::sql::Sql> crate::Store<B> {
    /// Operator-only operations (claims, purges and listings that span tenants) refuse a
    /// request handle.
    ///
    /// # Errors
    /// Returns [`StoreError::AccessDenied`] on a request handle.
    pub(crate) fn require_operator(&self) -> Result<(), StoreError> {
        if cfg!(feature = "unscoped-for-test") || self.authority != Authority::Request {
            return Ok(());
        }
        Err(StoreError::AccessDenied("operator authority required".to_owned()))
    }
}

impl<B: crate::sql::Sql> crate::Store<B> {
    /// The tenant and retention mode of `run`, for a run the `scope` owns. A run of another
    /// tenant is reported exactly like a missing one, so a request cannot learn that it exists.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when the run is missing or not the scope's.
    pub(crate) async fn owned_privacy_scope(
        &self,
        scope: &Scope,
        run: crawlx_core::CrawlRunId,
    ) -> Result<(TenantId, bool), StoreError> {
        let (tenant, zdr) = self.privacy_scope(run).await?;
        if scope.tenant().is_some_and(|scoped| scoped != tenant) {
            return Err(crate::error::not_found("crawl_run", run));
        }
        Ok((tenant, zdr))
    }
}

impl Scope {
    /// The tenant a predicate is bound to, `None` when the statement runs unscoped.
    pub(crate) fn tenant(&self) -> Option<TenantId> {
        self.guard.map(TenantGuard::tenant)
    }

    /// Whether rows of `tenant` are visible to this scope. A read or update that names another
    /// tenant answers as if the row did not exist; an insert that names another tenant is
    /// refused with [`Scope::authorize`] instead.
    pub(crate) fn sees(&self, tenant: TenantId) -> bool {
        self.guard.is_none_or(|guard| guard.tenant() == tenant)
    }

    /// An explicit tenant argument of a repository call must be the scope's tenant.
    ///
    /// # Errors
    /// Returns [`StoreError::AccessDenied`] when the scope is another tenant.
    pub(crate) fn authorize(&self, tenant: TenantId) -> Result<(), StoreError> {
        match self.guard {
            Some(guard) if guard.tenant() != tenant => {
                Err(StoreError::AccessDenied("tenant scope does not match".to_owned()))
            }
            _ => Ok(()),
        }
    }

    /// ` AND <predicate>` restricting `table` (referenced as `alias`, empty for none) to the
    /// scope's tenant with the tenant bound at `$n`; empty when the statement runs unscoped.
    /// Bind the tenant with [`Scope::bind`] after the statement's other values.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] for a table missing from the registry and
    /// [`StoreError::AccessDenied`] for an operator-only table.
    pub(crate) fn and(&self, table: &str, alias: &str, n: usize) -> Result<String, StoreError> {
        match self.guard {
            None => Ok(String::new()),
            Some(guard) => {
                let scoped =
                    guard.scope::<crate::backend::PostgresDialect>(table, alias, &format!("${n}"))?;
                Ok(format!(" AND {}", scoped.predicate))
            }
        }
    }

    /// ` AND EXISTS (..)` requiring that the run named by `run_expr` (a column or placeholder)
    /// belongs to the scope's tenant, tenant bound at `$n`; empty when unscoped. This is the
    /// write-side check: an insert or update can never reach another tenant's run.
    pub(crate) fn and_run_owned(&self, run_expr: &str, n: usize) -> String {
        match self.guard {
            None => String::new(),
            Some(_) => format!(
                " AND EXISTS (SELECT 1 FROM crawl_runs scope_r WHERE scope_r.run_id = {run_expr} AND scope_r.tenant_id = ${n})"
            ),
        }
    }

    /// Bind the scope's tenant as the next value when a predicate was added, and hand the
    /// statement over as a [`ScopedQuery`], the only thing a request-surface module may run.
    pub(crate) fn bind<'a, B: Sql>(&self, stmt: Stmt<'a, B>) -> ScopedQuery<'a, B> {
        ScopedQuery {
            stmt: match self.guard {
                Some(guard) => stmt.uuid(guard.tenant().0),
                None => stmt,
            },
        }
    }

    /// A statement over `table` whose tenancy is carried by values the caller already checked
    /// against this scope ([`Scope::authorize`], [`Scope::sees`]) or by a predicate it bound
    /// itself. `table` must be a registered tenant table: an unknown or operator-only table
    /// is refused, so a statement cannot be filed under a table the registry does not scope.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] for a table missing from the registry and
    /// [`StoreError::AccessDenied`] for an operator-only table.
    pub(crate) fn query<'a, B: Sql>(
        &self,
        table: &str,
        stmt: Stmt<'a, B>,
    ) -> Result<ScopedQuery<'a, B>, StoreError> {
        match tenant_tables::lookup(table) {
            None => Err(StoreError::Conflict(format!(
                "table {table} is not in the tenant registry"
            ))),
            Some(entry) if matches!(entry.key, TenantKey::Global) => Err(StoreError::AccessDenied(format!(
                "table {table} is operator-only"
            ))),
            Some(_) => Ok(ScopedQuery { stmt }),
        }
    }
}

/// A request-surface statement that carries its tenancy.
///
/// Request-surface modules (`repos/{api,authorization,intel,inspect}`, `trusted`, `trail`,
/// `approvals`) never run a [`Stmt`] directly: `clippy.toml` disallows its execution methods
/// and the raw `sqlx` query functions there. A statement becomes runnable only through
/// [`Scope::bind`] (the tenant predicate was added with [`Scope::and`] and the tenant is
/// bound), [`Scope::query`] (the caller authorized an explicit tenant argument and the table is
/// a registered tenant table), or one of the two reviewed entry points
/// [`ScopedQuery::within_scope`] and [`ScopedQuery::pre_authentication`]. A [`Scope`] only
/// comes from [`crate::Store::scope`], which fails closed on a request handle without a tenant
/// scope, so no path reaches the database without one of them.
#[must_use = "a statement does nothing until it is executed"]
pub struct ScopedQuery<'a, B: Sql> {
    stmt: Stmt<'a, B>,
}

impl<B: Sql> std::fmt::Debug for ScopedQuery<'_, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ScopedQuery").field(&self.stmt).finish()
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "ScopedQuery is the one wrapper that may run a statement of the request surface"
)]
impl<'a, B: Sql> ScopedQuery<'a, B> {
    /// A statement that runs inside a caller that already resolved the scope: the transaction
    /// helpers `tenancy_lint` lists as reviewed. The lint test refuses this entry point in any
    /// other function.
    pub(crate) fn within_scope(stmt: Stmt<'a, B>) -> Self {
        Self { stmt }
    }

    /// The pre-authentication key lookup, the one statement that carries no tenant: it finds
    /// the tenant of a presented key. `tenancy_lint` refuses this entry point anywhere else.
    pub(crate) fn pre_authentication(stmt: Stmt<'a, B>) -> Self {
        Self { stmt }
    }

    /// Run on `conn`; the rows affected.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn execute(self, conn: &mut Conn<B>) -> Result<u64, StoreError> {
        self.stmt.execute(conn).await
    }

    /// Run on `conn`; every row.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_all(self, conn: &mut Conn<B>) -> Result<Vec<B::Row>, StoreError> {
        self.stmt.fetch_all(conn).await
    }

    /// Run on `conn`; the first row, if any.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_optional(self, conn: &mut Conn<B>) -> Result<Option<B::Row>, StoreError> {
        self.stmt.fetch_optional(conn).await
    }

    /// Run on `conn`; exactly one row.
    ///
    /// # Errors
    /// See [`Stmt::fetch_one`].
    pub async fn fetch_one(self, conn: &mut Conn<B>) -> Result<B::Row, StoreError> {
        self.stmt.fetch_one(conn).await
    }

    /// Whether a statement written with [`crate::sql::returning`] matched a row.
    ///
    /// # Errors
    /// See [`Stmt::matched`].
    pub async fn matched(self, conn: &mut Conn<B>) -> Result<bool, StoreError> {
        self.stmt.matched(conn).await
    }

    /// Read on the pool; every row.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_all_pool(self, pool: &B::Pool) -> Result<Vec<B::Row>, StoreError> {
        self.stmt.fetch_all_pool(pool).await
    }

    /// Read on the pool; the first row, if any.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_optional_pool(self, pool: &B::Pool) -> Result<Option<B::Row>, StoreError> {
        self.stmt.fetch_optional_pool(pool).await
    }

    /// Read on the pool; exactly one row.
    ///
    /// # Errors
    /// See [`Stmt::fetch_one_pool`].
    pub async fn fetch_one_pool(self, pool: &B::Pool) -> Result<B::Row, StoreError> {
        self.stmt.fetch_one_pool(pool).await
    }

    /// Run one write on the pool.
    ///
    /// # Errors
    /// See [`Stmt::execute_write`].
    pub async fn execute_write(self, pool: &B::Pool) -> Result<u64, StoreError> {
        self.stmt.execute_write(pool).await
    }

    /// Run one write that returns a row on the pool.
    ///
    /// # Errors
    /// See [`Stmt::fetch_optional_write`].
    pub async fn fetch_optional_write(self, pool: &B::Pool) -> Result<Option<B::Row>, StoreError> {
        self.stmt.fetch_optional_write(pool).await
    }

    /// [`ScopedQuery::matched`] for a lone write on the pool.
    ///
    /// # Errors
    /// See [`Stmt::matched_write`].
    pub async fn matched_write(self, pool: &B::Pool) -> Result<bool, StoreError> {
        self.stmt.matched_write(pool).await
    }
}

impl crate::backend::Database {
    /// How many tenants exist, not counting `tenant`: the probe behind the refusal of a second
    /// tenant on SQLite. Operator authority; one `SELECT` on any engine.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the statement fails.
    pub async fn tenant_count_excluding(&self, tenant: Option<TenantId>) -> Result<u64, StoreError> {
        if let Some(pg) = self.as_postgres() {
            return count_tenants(pg, tenant).await;
        }
        if let Some(store) = self.as_mariadb() {
            return count_tenants(store, tenant).await;
        }
        match self.as_sqlite() {
            Some(store) => count_tenants(store, tenant).await,
            None => Err(StoreError::Backend("database has no store".to_owned())),
        }
    }
}

async fn count_tenants<B: Sql>(
    store: &crate::Store<B>,
    excluding: Option<TenantId>,
) -> Result<u64, StoreError> {
    let row = match excluding {
        Some(tenant) => {
            Stmt::<B>::dynamic("SELECT count(*) AS v FROM tenants WHERE tenant_id <> $1")
                .uuid(tenant.0)
                .fetch_one_pool(&store.pool)
                .await?
        }
        None => {
            Stmt::<B>::dynamic("SELECT count(*) AS v FROM tenants")
                .fetch_one_pool(&store.pool)
                .await?
        }
    };
    crate::codec::conv(crate::sql::SqlRow::i64(&row, "v")?, "count")
}

/// The SQL fragments of backend `B`.
pub(crate) type Dia<B> = <B as crate::backend::Backend>::Dialect;

/// An engine the request-surface repositories run on: the shared statement layer plus the
/// pool the pre-authentication key lookup uses.
pub trait Tenancy: crate::sql::Sql {
    /// The pool that may run the narrow pre-authentication key lookup, the only request
    /// statement that carries no tenant. PostgreSQL's is the restricted request role (never
    /// the owner); the other engines have one login, so it is the pool itself.
    fn pre_auth_pool(pool: &Self::Pool) -> Self::Pool;
}

impl Tenancy for crate::backend::PgBackend {
    fn pre_auth_pool(pool: &Self::Pool) -> Self::Pool {
        crate::backend::postgres::TenantPool::new(pool.authentication().clone())
    }
}

impl Tenancy for crate::backend::MariaBackend {
    fn pre_auth_pool(pool: &Self::Pool) -> Self::Pool {
        pool.clone()
    }
}

impl Tenancy for crate::backend::SqliteBackend {
    fn pre_auth_pool(pool: &Self::Pool) -> Self::Pool {
        pool.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::backend::dialect::{MariaDbDialect, PostgresDialect, SqliteDialect};

    #[tokio::test]
    async fn current_requires_a_scope() {
        assert!(matches!(
            TenantGuard::current(),
            Err(StoreError::AccessDenied(text)) if text == "tenant scope required"
        ));
        let tenant = TenantId::new();
        let seen = scope(tenant, async { TenantGuard::current().map(TenantGuard::tenant) }).await;
        assert_eq!(seen.unwrap(), tenant);
        assert!(current().is_none());
    }

    #[test]
    fn predicates_follow_the_registry() {
        let guard = TenantGuard::for_tenant(TenantId::new());
        let direct = guard.scope_at::<SqliteDialect>("crawl_runs", "r", 1).unwrap();
        assert_eq!(direct.predicate, "r.tenant_id = ?1");
        assert_eq!(direct.tenant, guard.tenant());
        let via_run = guard.scope_at::<MariaDbDialect>("pages", "p", 3).unwrap();
        assert_eq!(
            via_run.predicate,
            "EXISTS (SELECT 1 FROM crawl_runs scope_r WHERE scope_r.run_id = p.run_id AND scope_r.tenant_id = ?)"
        );
        let bare = guard.scope_at::<PostgresDialect>("intel_trace", "", 2).unwrap();
        assert_eq!(
            bare.predicate,
            "EXISTS (SELECT 1 FROM intel_jobs scope_j WHERE scope_j.job_id = intel_trace.job_id AND scope_j.tenant_id = $2)"
        );
        assert!(guard
            .scope_at::<SqliteDialect>("session_egress_pins", "e", 1)
            .unwrap()
            .predicate
            .contains("scope_s.session_id = e.session_id"));
    }

    #[test]
    fn state_memberships_correlate_to_the_outer_state() {
        let guard = TenantGuard::for_tenant(TenantId::new());
        let aliased = guard
            .scope_at::<SqliteDialect>("state_cluster_membership", "m", 3)
            .unwrap();
        assert_eq!(
            aliased.predicate,
            "EXISTS (SELECT 1 FROM states scope_s JOIN crawl_runs scope_r ON scope_r.run_id = scope_s.run_id \
             WHERE scope_s.state_id = m.state_id AND scope_r.tenant_id = ?3)"
        );
        assert_eq!(aliased.tenant, guard.tenant());
        let bare = guard
            .scope_at::<PostgresDialect>("state_cluster_membership", "", 2)
            .unwrap();
        assert_eq!(
            bare.predicate,
            "EXISTS (SELECT 1 FROM states scope_s JOIN crawl_runs scope_r ON scope_r.run_id = scope_s.run_id \
             WHERE scope_s.state_id = state_cluster_membership.state_id AND scope_r.tenant_id = $2)"
        );
        assert_eq!(bare.tenant, guard.tenant());
    }

    #[test]
    fn operator_and_unknown_tables_are_refused() {
        let guard = TenantGuard::for_tenant(TenantId::new());
        assert!(matches!(
            guard.scope_at::<SqliteDialect>("workers", "w", 1),
            Err(StoreError::AccessDenied(_))
        ));
        assert!(matches!(
            guard.scope_at::<SqliteDialect>("nope", "", 1),
            Err(StoreError::Conflict(_))
        ));
    }
}
