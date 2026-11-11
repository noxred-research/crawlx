//! Retained, tenant/run-scoped URL graph persistence over existing producer custody.
//! SQL remains here; PostgreSQL lock and clock details are isolated in small helpers.

use crate::codec::{digest, get};
use crate::error::db;
use crate::Pg;
use async_trait::async_trait;
use crawlx_core::config::RetentionMode;
use crawlx_core::custody::CustodyLease;
use crawlx_core::url_graph::{
    UrlGraphBatchV1, UrlGraphEdgeV1, UrlGraphPolicyV1, UrlGraphRankStateV1, UrlGraphRanksV1, UrlGraphRepo,
    UrlGraphSnapshotV1, UrlHandleV1,
};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;

#[derive(Clone)]
pub(crate) struct MemoryGraph {
    pub(crate) snapshot: UrlGraphSnapshotV1,
    pub(crate) expires_at: Timestamp,
    pub(crate) ranks: Option<UrlGraphRanksV1>,
}

pub(crate) fn invalid(error: crawlx_core::url_graph::UrlGraphError) -> StoreError {
    StoreError::Conflict(error.to_string())
}
fn denied() -> StoreError {
    StoreError::AccessDenied("url graph retained authority unavailable".into())
}
fn missing(run: CrawlRunId) -> StoreError {
    StoreError::NotFound {
        entity: "url_graph",
        id: run.to_string(),
    }
}
fn tenant_scope(tenant: TenantId) -> Result<(), StoreError> {
    if crate::tenant::current().is_some_and(|current| current != tenant) {
        return Err(denied());
    }
    Ok(())
}

/// Bound retained evidence by the original run ceiling, never by read/write time.
pub(crate) fn retained_deadline(
    mode: RetentionMode,
    days: i64,
    created: Timestamp,
    expires: Option<Timestamp>,
    now: Timestamp,
) -> Result<Timestamp, StoreError> {
    if mode == RetentionMode::Zdr || !(1..=365).contains(&days) {
        return Err(denied());
    }
    let duration = chrono::Duration::try_days(days).ok_or_else(denied)?;
    let end = created.checked_add_signed(duration).ok_or_else(denied)?;
    let end = expires.map_or(end, |expiry| expiry.min(end));
    if end <= now {
        return Err(denied());
    }
    Ok(end)
}

// PostgreSQL database-clock authority; portable graph DML below needs no wall clock.
async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<Timestamp, StoreError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(db)
}

// PostgreSQL enum projection and row lock stay at the existing run authority boundary.
async fn retained_run(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<Timestamp, StoreError> {
    tenant_scope(tenant)?;
    let row = sqlx::query("SELECT tenant_id,retention_mode::text AS mode,retention_days,created_at,expires_at,purge_requested_at FROM crawl_runs WHERE run_id=$1 FOR SHARE")
        .bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?.ok_or_else(|| missing(run))?;
    if TenantId(get(&row, "tenant_id")?) != tenant
        || get::<Option<Timestamp>>(&row, "purge_requested_at")?.is_some()
    {
        return Err(denied());
    }
    let mode = match get::<String>(&row, "mode")?.as_str() {
        "standard" => RetentionMode::Standard,
        "extended" => RetentionMode::Extended,
        _ => return Err(denied()),
    };
    let clock = now(tx).await?;
    retained_deadline(
        mode,
        i64::from(get::<i32>(&row, "retention_days")?),
        get(&row, "created_at")?,
        get(&row, "expires_at")?,
        clock,
    )
}

// Header locks serialize source replacement and rank publication without a second lease.
async fn load(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
    write: bool,
) -> Result<(UrlGraphSnapshotV1, Timestamp), StoreError> {
    let sql = if write {
        "SELECT version,revision,policy,expires_at FROM url_graph_runs WHERE tenant_id=$1 AND run_id=$2 FOR UPDATE"
    } else {
        "SELECT version,revision,policy,expires_at FROM url_graph_runs WHERE tenant_id=$1 AND run_id=$2 FOR SHARE"
    };
    let row = sqlx::query(sql)
        .bind(tenant.0)
        .bind(run.0)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or_else(|| missing(run))?;
    let expiry: Timestamp = get(&row, "expires_at")?;
    if expiry <= now(tx).await? {
        return Err(denied());
    }
    let policy: UrlGraphPolicyV1 = serde_json::from_value(get(&row, "policy")?)?;
    let mut graph = UrlGraphSnapshotV1::empty(tenant, run, policy);
    graph.version = u16::try_from(get::<i32>(&row, "version")?).map_err(|_| denied())?;
    graph.revision = u64::try_from(get::<i64>(&row, "revision")?).map_err(|_| denied())?;
    let nodes = sqlx::query(
        "SELECT handle FROM url_graph_nodes WHERE tenant_id=$1 AND run_id=$2 ORDER BY handle LIMIT 2049",
    )
    .bind(tenant.0)
    .bind(run.0)
    .fetch_all(&mut **tx)
    .await
    .map_err(db)?;
    graph.nodes = nodes
        .iter()
        .map(|row| Ok(UrlHandleV1(digest(&get::<Vec<u8>>(row, "handle")?)?)))
        .collect::<Result<_, StoreError>>()?;
    let edges = sqlx::query("SELECT source_handle,target_handle,anchor_handle,cost FROM url_graph_edges WHERE tenant_id=$1 AND run_id=$2 ORDER BY source_handle,target_handle,anchor_handle LIMIT 8193")
        .bind(tenant.0).bind(run.0).fetch_all(&mut **tx).await.map_err(db)?;
    graph.edges = edges
        .iter()
        .map(|row| {
            let anchor: Vec<u8> = get(row, "anchor_handle")?;
            Ok(UrlGraphEdgeV1::new(
                UrlHandleV1(digest(&get::<Vec<u8>>(row, "source_handle")?)?),
                UrlHandleV1(digest(&get::<Vec<u8>>(row, "target_handle")?)?),
                if anchor.is_empty() {
                    None
                } else {
                    Some(digest(&anchor)?)
                },
                u32::try_from(get::<i64>(row, "cost")?).map_err(|_| denied())?,
            ))
        })
        .collect::<Result<_, StoreError>>()?;
    graph.validate().map_err(invalid)?;
    Ok((graph, expiry))
}

async fn invalidate(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM url_graph_ranks WHERE tenant_id=$1 AND run_id=$2")
        .bind(tenant.0)
        .bind(run.0)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
async fn finish(
    tx: &mut Transaction<'_, Postgres>,
    lease: &CustodyLease,
    expiry: Timestamp,
) -> Result<(), StoreError> {
    crate::custody::live(tx, lease).await?;
    if expiry <= now(tx).await? {
        return Err(denied());
    }
    lease.check_local_cancellation()
}

// PostgreSQL insert-if-absent serializes first creation through the unique run key.
async fn create_header(
    tx: &mut Transaction<'_, Postgres>,
    lease: &CustodyLease,
    policy: &UrlGraphPolicyV1,
    ceiling: Timestamp,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO url_graph_runs(tenant_id,run_id,version,revision,policy,expires_at) VALUES($1,$2,1,0,$3,$4) ON CONFLICT(tenant_id,run_id) DO NOTHING")
        .bind(lease.tenant.0).bind(lease.run.0).bind(serde_json::to_value(policy)?).bind(ceiling)
        .execute(&mut **tx).await.map_err(db)?;
    Ok(())
}

impl Pg {
    /// Erase at most 512 expired graph runs and all their child evidence/ranks.
    /// An attached tenant scope narrows maintenance; unscoped worker maintenance spans tenants.
    ///
    /// # Errors
    /// Returns the existing database error if bounded deletion fails.
    pub async fn purge_expired_url_graph(&self) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "DELETE FROM url_graph_runs WHERE (tenant_id,run_id) IN (\
             SELECT tenant_id,run_id FROM url_graph_runs \
             WHERE expires_at<=CURRENT_TIMESTAMP AND (tenant_id=$1 OR $1 IS NULL) \
             ORDER BY expires_at,tenant_id,run_id LIMIT 512)",
        )
        .bind(crate::tenant::current().map(|tenant| tenant.0))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(result.rows_affected())
    }
}

#[async_trait]
impl UrlGraphRepo for Pg {
    async fn configure(&self, lease: &CustodyLease, policy: &UrlGraphPolicyV1) -> Result<(), StoreError> {
        policy.validate().map_err(invalid)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        crate::custody::live(&mut tx, lease).await?;
        let ceiling = retained_run(&mut tx, lease.tenant, lease.run).await?;
        create_header(&mut tx, lease, policy, ceiling).await?;
        let (graph, expiry) = load(&mut tx, lease.tenant, lease.run, true).await?;
        if graph.policy != *policy {
            sqlx::query("UPDATE url_graph_runs SET policy=$3 WHERE tenant_id=$1 AND run_id=$2")
                .bind(lease.tenant.0)
                .bind(lease.run.0)
                .bind(serde_json::to_value(policy)?)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            invalidate(&mut tx, lease.tenant, lease.run).await?;
        }
        if ceiling < expiry {
            sqlx::query("UPDATE url_graph_runs SET expires_at=$3 WHERE tenant_id=$1 AND run_id=$2")
                .bind(lease.tenant.0)
                .bind(lease.run.0)
                .bind(ceiling)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        finish(&mut tx, lease, expiry.min(ceiling)).await?;
        tx.commit().await.map_err(db)
    }

    async fn replace_source(
        &self,
        lease: &CustodyLease,
        batch: &UrlGraphBatchV1,
        policy: &UrlGraphPolicyV1,
    ) -> Result<u64, StoreError> {
        batch.validate().map_err(invalid)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        crate::custody::live(&mut tx, lease).await?;
        let ceiling = retained_run(&mut tx, lease.tenant, lease.run).await?;
        let (mut graph, expiry) = load(&mut tx, lease.tenant, lease.run, true).await?;
        if graph.policy != *policy {
            return Err(StoreError::Conflict("url graph policy changed".into()));
        }
        let additional: BTreeSet<_> = std::iter::once(batch.source)
            .chain(batch.edges.iter().map(|edge| edge.target))
            .filter(|node| graph.nodes.binary_search(node).is_err())
            .collect();
        if graph.replace(batch).map_err(invalid)? {
            for node in additional {
                sqlx::query("INSERT INTO url_graph_nodes(tenant_id,run_id,handle) VALUES($1,$2,$3)")
                    .bind(lease.tenant.0)
                    .bind(lease.run.0)
                    .bind(node.0 .0.as_slice())
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            sqlx::query("DELETE FROM url_graph_edges WHERE tenant_id=$1 AND run_id=$2 AND source_handle=$3")
                .bind(lease.tenant.0)
                .bind(lease.run.0)
                .bind(batch.source.0 .0.as_slice())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            for edge in &batch.edges {
                let anchor = edge.anchor.as_ref().map_or(&[][..], |digest| digest.0.as_slice());
                sqlx::query("INSERT INTO url_graph_edges(tenant_id,run_id,version,source_handle,target_handle,anchor_handle,cost,producer_fence) VALUES($1,$2,1,$3,$4,$5,$6,$7)")
                    .bind(lease.tenant.0).bind(lease.run.0).bind(edge.source.0.0.as_slice())
                    .bind(edge.target.0.0.as_slice()).bind(anchor).bind(i64::from(edge.cost)).bind(lease.fence)
                    .execute(&mut *tx).await.map_err(db)?;
            }
            sqlx::query("UPDATE url_graph_runs SET revision=$3 WHERE tenant_id=$1 AND run_id=$2")
                .bind(lease.tenant.0)
                .bind(lease.run.0)
                .bind(i64::try_from(graph.revision).map_err(|_| denied())?)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            invalidate(&mut tx, lease.tenant, lease.run).await?;
        }
        finish(&mut tx, lease, expiry.min(ceiling)).await?;
        tx.commit().await.map_err(db)?;
        Ok(graph.revision)
    }

    async fn snapshot(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphSnapshotV1, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        retained_run(&mut tx, tenant, run).await?;
        let (graph, expiry) = load(&mut tx, tenant, run, false).await?;
        if expiry <= now(&mut tx).await? {
            return Err(denied());
        }
        tx.commit().await.map_err(db)?;
        Ok(graph)
    }

    async fn store_ranks(&self, lease: &CustodyLease, ranks: &UrlGraphRanksV1) -> Result<(), StoreError> {
        if ranks.tenant != lease.tenant || ranks.run != lease.run {
            return Err(denied());
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        crate::custody::live(&mut tx, lease).await?;
        let ceiling = retained_run(&mut tx, lease.tenant, lease.run).await?;
        let (graph, expiry) = load(&mut tx, lease.tenant, lease.run, true).await?;
        ranks.validate_for(&graph).map_err(invalid)?;
        invalidate(&mut tx, lease.tenant, lease.run).await?;
        sqlx::query(
            "INSERT INTO url_graph_ranks(tenant_id,run_id,version,revision,result) VALUES($1,$2,1,$3,$4)",
        )
        .bind(lease.tenant.0)
        .bind(lease.run.0)
        .bind(i64::try_from(ranks.revision).map_err(|_| denied())?)
        .bind(serde_json::to_value(ranks)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        finish(&mut tx, lease, expiry.min(ceiling)).await?;
        tx.commit().await.map_err(db)
    }

    async fn ranks(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphRankStateV1, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        retained_run(&mut tx, tenant, run).await?;
        let (graph, expiry) = load(&mut tx, tenant, run, false).await?;
        let row = sqlx::query("SELECT result FROM url_graph_ranks WHERE tenant_id=$1 AND run_id=$2")
            .bind(tenant.0)
            .bind(run.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let state = if let Some(row) = row {
            let ranks: UrlGraphRanksV1 = serde_json::from_value(get(&row, "result")?)?;
            if ranks.validate_for(&graph).is_ok() {
                UrlGraphRankStateV1::Current(ranks)
            } else {
                UrlGraphRankStateV1::Invalidated
            }
        } else {
            UrlGraphRankStateV1::Invalidated
        };
        if expiry <= now(&mut tx).await? {
            return Err(denied());
        }
        tx.commit().await.map_err(db)?;
        Ok(state)
    }
}
