//! Fail-closed transport for operational values excluded from durable rows.

use crate::backend::strategy::Conn;
use crate::backend::Backend;
use crate::error::not_found;
use crate::sql::{stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use serde::{de::DeserializeOwned, Serialize};

fn scope_of<R: SqlRow>(row: &R) -> Result<(TenantId, bool), StoreError> {
    Ok((
        TenantId(row.uuid("tenant_id")?),
        row.text("retention_mode")? == "zdr",
    ))
}

fn scope_stmt<B: Sql>(run: CrawlRunId) -> Stmt<'static, B> {
    stmt!(
        B,
        "SELECT tenant_id, retention_mode::text AS retention_mode FROM crawl_runs WHERE run_id = $1"
    )
    .uuid(run.0)
}

impl<B: Sql> Store<B> {
    /// The tenant of `run` and whether it is a zero-data-retention run.
    pub(crate) async fn privacy_scope(&self, run: CrawlRunId) -> Result<(TenantId, bool), StoreError> {
        let row = scope_stmt::<B>(run)
            .fetch_optional_pool(&self.pool)
            .await?
            .ok_or_else(|| not_found("crawl_run", run))?;
        scope_of(&row)
    }

    /// [`Store::privacy_scope`] inside the caller's transaction.
    pub(crate) async fn privacy_scope_tx(
        conn: &mut Conn<B>,
        run: CrawlRunId,
    ) -> Result<(TenantId, bool), StoreError> {
        let row = scope_stmt::<B>(run)
            .fetch_optional(conn)
            .await?
            .ok_or_else(|| not_found("crawl_run", run))?;
        scope_of(&row)
    }
}

impl<B: Backend> Store<B> {
    /// Park a value in the volatile delivery buffer instead of a durable row.
    pub(crate) async fn ephemeral_put<T: Serialize + Sync + ?Sized>(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        kind: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let buffer = self.delivery.as_ref().ok_or_else(missing_delivery)?;
        let bytes =
            serde_json::to_vec(value).map_err(|error| StoreError::Serialization(error.to_string()))?;
        buffer
            .insert(tenant, run, page, kind, "application/json", &bytes)
            .await?;
        Ok(())
    }

    /// Read back a value parked with [`Store::ephemeral_put`].
    pub(crate) async fn ephemeral_get<T: DeserializeOwned>(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        kind: &str,
    ) -> Result<T, StoreError> {
        let buffer = self.delivery.as_ref().ok_or_else(missing_delivery)?;
        let entry = buffer
            .get(tenant, run, page)
            .await?
            .ok_or_else(missing_delivery)?;
        let blob = entry.blobs.get(kind).ok_or_else(missing_delivery)?;
        serde_json::from_slice(&blob.bytes).map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

fn missing_delivery() -> StoreError {
    StoreError::RetentionDenied("required volatile operational value is unavailable".to_owned())
}
