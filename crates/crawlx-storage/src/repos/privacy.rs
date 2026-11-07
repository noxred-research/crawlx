//! Fail-closed transport for operational values excluded from durable rows.

use crate::codec::get;
use crate::error::{db, not_found};
use crate::pg::Pg;
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use serde::{de::DeserializeOwned, Serialize};

impl Pg {
    pub(crate) async fn privacy_scope(&self, run: CrawlRunId) -> Result<(TenantId, bool), StoreError> {
        let row = sqlx::query(
            "SELECT tenant_id, retention_mode::text AS retention_mode FROM crawl_runs WHERE run_id = $1",
        )
        .bind(run.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("crawl_run", run))?;
        Ok((
            TenantId(get(&row, "tenant_id")?),
            get::<String>(&row, "retention_mode")? == "zdr",
        ))
    }

    pub(crate) async fn privacy_scope_tx(
        conn: &mut sqlx::PgConnection,
        run: CrawlRunId,
    ) -> Result<(TenantId, bool), StoreError> {
        let row = sqlx::query(
            "SELECT tenant_id, retention_mode::text AS retention_mode FROM crawl_runs WHERE run_id = $1",
        )
        .bind(run.0)
        .fetch_optional(conn)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("crawl_run", run))?;
        Ok((
            TenantId(get(&row, "tenant_id")?),
            get::<String>(&row, "retention_mode")? == "zdr",
        ))
    }

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
