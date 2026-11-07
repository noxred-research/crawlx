//! Transaction-local tenant isolation for the existing PostgreSQL repositories.
//!
//! Request code scopes its future with [`scope`]. The pool executor then uses the
//! restricted API role and sets `app.tenant_id` inside each transaction. Explicit
//! repository transactions retain their existing atomicity; implicit statements
//! receive their own transaction. Dropping a future or stream drops its transaction,
//! so sqlx rolls it back before returning the connection to the pool.

use crawlx_core::TenantId;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use futures::TryStreamExt;
use sqlx::postgres::{PgQueryResult, PgRow, PgStatement, PgTypeInfo};
use sqlx::{Describe, Either, Error, Execute, Executor, PgPool, Postgres, Transaction};
use std::future::Future;
use std::ops::Deref;

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

/// Pool selection stays private to storage: only authenticated, scoped work uses
/// `api`; migrations, workers and cross-tenant maintenance retain `authority`.
#[derive(Clone, Debug)]
pub(crate) struct TenantPool {
    authority: PgPool,
    api: Option<PgPool>,
}

impl TenantPool {
    pub(crate) const fn new(authority: PgPool) -> Self {
        Self { authority, api: None }
    }

    pub(crate) fn with_api(&self, api: PgPool) -> Self {
        Self {
            authority: self.authority.clone(),
            api: Some(api),
        }
    }

    /// The only unscoped request operation is the narrow pre-authentication lookup.
    pub(crate) fn authentication(&self) -> &PgPool {
        self.api.as_ref().unwrap_or(&self.authority)
    }

    pub(crate) async fn begin(&self) -> Result<Transaction<'static, Postgres>, Error> {
        let tenant = current();
        let pool = if tenant.is_some() {
            self.authentication()
        } else {
            &self.authority
        };
        let mut tx = pool.begin().await?;
        if let Some(tenant) = tenant {
            sqlx::query("SELECT set_config('app.tenant_id', $1::uuid::text, true)")
                .bind(tenant.0)
                .execute(&mut *tx)
                .await?;
        }
        Ok(tx)
    }
}

impl Deref for TenantPool {
    type Target = PgPool;

    fn deref(&self) -> &Self::Target {
        &self.authority
    }
}

impl<'c> Executor<'c> for &'c TenantPool {
    type Database = Postgres;

    fn fetch_many<'e, 'q: 'e, E>(self, query: E) -> BoxStream<'e, Result<Either<PgQueryResult, PgRow>, Error>>
    where
        'c: 'e,
        E: 'q + Execute<'q, Postgres>,
    {
        if current().is_none() {
            return self.authority.fetch_many(query);
        }
        Box::pin(async_stream::try_stream! {
            let mut tx = self.begin().await?;
            {
                let mut rows = (&mut *tx).fetch_many(query);
                while let Some(row) = rows.try_next().await? {
                    yield row;
                }
            }
            tx.commit().await?;
        })
    }

    fn fetch_optional<'e, 'q: 'e, E>(self, query: E) -> BoxFuture<'e, Result<Option<PgRow>, Error>>
    where
        'c: 'e,
        E: 'q + Execute<'q, Postgres>,
    {
        if current().is_none() {
            return self.authority.fetch_optional(query);
        }
        Box::pin(async move {
            let mut tx = self.begin().await?;
            let row = (&mut *tx).fetch_optional(query).await?;
            tx.commit().await?;
            Ok(row)
        })
    }

    fn prepare_with<'e, 'q: 'e>(
        self,
        sql: &'q str,
        parameters: &'e [PgTypeInfo],
    ) -> BoxFuture<'e, Result<PgStatement<'q>, Error>>
    where
        'c: 'e,
    {
        if current().is_none() {
            return self.authority.prepare_with(sql, parameters);
        }
        Box::pin(async move {
            let mut tx = self.begin().await?;
            let statement = (&mut *tx).prepare_with(sql, parameters).await?;
            tx.commit().await?;
            Ok(statement)
        })
    }

    fn describe<'e, 'q: 'e>(self, sql: &'q str) -> BoxFuture<'e, Result<Describe<Postgres>, Error>>
    where
        'c: 'e,
    {
        if current().is_none() {
            return self.authority.describe(sql);
        }
        Box::pin(async move {
            let mut tx = self.begin().await?;
            let description = (&mut *tx).describe(sql).await?;
            tx.commit().await?;
            Ok(description)
        })
    }
}
