//! Retained, tenant/run-scoped URL graph persistence over existing producer custody.
//! SQL remains here; the row lock and the database clock come from the engine's dialect.

use crate::backend::strategy::Conn;
use crate::backend::{Dialect, RowLock};
use crate::codec::digest;
use crate::sql::{db_clock, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::config::RetentionMode;
use crawlx_core::custody::CustodyLease;
use crawlx_core::url_graph::{
    UrlGraphBatchV1, UrlGraphEdgeV1, UrlGraphPolicyV1, UrlGraphRankStateV1, UrlGraphRanksV1, UrlGraphRepo,
    UrlGraphSnapshotV1, UrlHandleV1,
};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};
use std::collections::BTreeSet;
use uuid::Uuid;

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

// The database clock is the only wall clock of this module.
async fn now<B: Sql>(conn: &mut Conn<B>) -> Result<Timestamp, StoreError> {
    db_clock::<B>(conn).await
}

// The enum projection and the run row lock stay at the existing run authority boundary.
async fn retained_run<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<Timestamp, StoreError> {
    tenant_scope(tenant)?;
    let row = stmt!(
        B,
        format!(
            "SELECT tenant_id,retention_mode::text AS mode,retention_days,created_at,expires_at,purge_requested_at FROM crawl_runs WHERE run_id=$1{}",
            <B::Dialect as Dialect>::row_lock(RowLock::Share)
        )
    )
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| missing(run))?;
    if TenantId(row.uuid("tenant_id")?) != tenant || row.opt_ts("purge_requested_at")?.is_some() {
        return Err(denied());
    }
    let mode = match row.text("mode")?.as_str() {
        "standard" => RetentionMode::Standard,
        "extended" => RetentionMode::Extended,
        _ => return Err(denied()),
    };
    let clock = now::<B>(conn).await?;
    retained_deadline(
        mode,
        i64::from(row.i32("retention_days")?),
        row.ts("created_at")?,
        row.opt_ts("expires_at")?,
        clock,
    )
}

// Header locks serialize source replacement and rank publication without a second lease.
async fn load<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
    write: bool,
) -> Result<(UrlGraphSnapshotV1, Timestamp), StoreError> {
    let query = if write {
        stmt!(
            B,
            format!(
                "SELECT version,revision,policy,expires_at FROM url_graph_runs WHERE tenant_id=$1 AND run_id=$2{}",
                <B::Dialect as Dialect>::row_lock(RowLock::Update)
            )
        )
    } else {
        stmt!(
            B,
            format!(
                "SELECT version,revision,policy,expires_at FROM url_graph_runs WHERE tenant_id=$1 AND run_id=$2{}",
                <B::Dialect as Dialect>::row_lock(RowLock::Share)
            )
        )
    };
    let row = query
        .uuid(tenant.0)
        .uuid(run.0)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| missing(run))?;
    let expiry = row.ts("expires_at")?;
    if expiry <= now::<B>(conn).await? {
        return Err(denied());
    }
    let policy: UrlGraphPolicyV1 = serde_json::from_value(row.json("policy")?)?;
    let mut graph = UrlGraphSnapshotV1::empty(tenant, run, policy);
    graph.version = u16::try_from(row.i32("version")?).map_err(|_| denied())?;
    graph.revision = u64::try_from(row.i64("revision")?).map_err(|_| denied())?;
    let nodes = stmt!(
        B,
        "SELECT handle FROM url_graph_nodes WHERE tenant_id=$1 AND run_id=$2 ORDER BY handle LIMIT 2049"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_all(conn)
    .await?;
    graph.nodes = nodes
        .iter()
        .map(|row| Ok(UrlHandleV1(digest(&row.bytes("handle")?)?)))
        .collect::<Result<_, StoreError>>()?;
    let edges = stmt!(
        B,
        "SELECT source_handle,target_handle,anchor_handle,cost FROM url_graph_edges WHERE tenant_id=$1 AND run_id=$2 ORDER BY source_handle,target_handle,anchor_handle LIMIT 8193"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_all(conn)
    .await?;
    graph.edges = edges
        .iter()
        .map(|row| {
            let anchor = row.bytes("anchor_handle")?;
            Ok(UrlGraphEdgeV1::new(
                UrlHandleV1(digest(&row.bytes("source_handle")?)?),
                UrlHandleV1(digest(&row.bytes("target_handle")?)?),
                if anchor.is_empty() {
                    None
                } else {
                    Some(digest(&anchor)?)
                },
                u32::try_from(row.i64("cost")?).map_err(|_| denied())?,
            ))
        })
        .collect::<Result<_, StoreError>>()?;
    graph.validate().map_err(invalid)?;
    Ok((graph, expiry))
}

async fn invalidate<B: Sql>(conn: &mut Conn<B>, tenant: TenantId, run: CrawlRunId) -> Result<(), StoreError> {
    stmt!(B, "DELETE FROM url_graph_ranks WHERE tenant_id=$1 AND run_id=$2")
        .uuid(tenant.0)
        .uuid(run.0)
        .execute(conn)
        .await?;
    Ok(())
}

async fn finish<B: Sql>(
    conn: &mut Conn<B>,
    lease: &CustodyLease,
    expiry: Timestamp,
) -> Result<(), StoreError> {
    crate::custody::live::<B>(conn, lease).await?;
    if expiry <= now::<B>(conn).await? {
        return Err(denied());
    }
    lease.check_local_cancellation()
}

// Insert-if-absent serializes first creation through the unique run key.
async fn create_header<B: Sql>(
    conn: &mut Conn<B>,
    lease: &CustodyLease,
    policy: &UrlGraphPolicyV1,
    ceiling: Timestamp,
) -> Result<(), StoreError> {
    let policy = serde_json::to_value(policy)?;
    stmt!(
        B,
        format!(
            "INSERT INTO url_graph_runs(tenant_id,run_id,version,revision,policy,expires_at) VALUES($1,$2,1,0,$3,$4) {}",
            <B::Dialect as Dialect>::upsert_do_nothing(&["tenant_id", "run_id"])
        )
    )
    .uuid(lease.tenant.0)
    .uuid(lease.run.0)
    .json(&policy)
    .ts(ceiling)
    .execute(conn)
    .await?;
    Ok(())
}

impl<B: Sql> Store<B> {
    /// Erase at most 512 expired graph runs and all their child evidence/ranks.
    /// An attached tenant scope narrows maintenance; unscoped worker maintenance spans tenants.
    ///
    /// # Errors
    /// Returns the existing database error if bounded deletion fails.
    pub async fn purge_expired_url_graph(&self) -> Result<u64, StoreError> {
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let clock = now::<B>(tx.conn()).await?;
        let scope = crate::tenant::current();
        // MariaDB rejects LIMIT inside an IN subquery: pick the keys first, delete by key.
        let select = if scope.is_some() {
            "SELECT tenant_id,run_id FROM url_graph_runs WHERE expires_at<=$1 AND tenant_id=$2 ORDER BY expires_at,tenant_id,run_id LIMIT 512"
        } else {
            "SELECT tenant_id,run_id FROM url_graph_runs WHERE expires_at<=$1 ORDER BY expires_at,tenant_id,run_id LIMIT 512"
        };
        let mut keys = Stmt::<B>::dynamic(select).ts(clock);
        if let Some(tenant) = scope {
            keys = keys.uuid(tenant.0);
        }
        let keys = keys
            .fetch_all(tx.conn())
            .await?
            .iter()
            .map(|row| Ok((row.uuid("tenant_id")?, row.uuid("run_id")?)))
            .collect::<Result<Vec<(Uuid, Uuid)>, StoreError>>()?;
        let mut erased = 0_u64;
        if !keys.is_empty() {
            let rows = (0..keys.len())
                .map(|row| format!("(${},${})", row * 2 + 1, row * 2 + 2))
                .collect::<Vec<_>>()
                .join(",");
            let mut delete = Stmt::<B>::dynamic(&format!(
                "DELETE FROM url_graph_runs WHERE (tenant_id,run_id) IN ({rows})"
            ));
            for (tenant, run) in &keys {
                delete = delete.uuid(*tenant).uuid(*run);
            }
            erased = delete.execute(tx.conn()).await?;
        }
        tx.commit().await?;
        Ok(erased)
    }
}

#[async_trait]
impl<B: Sql> UrlGraphRepo for Store<B> {
    async fn configure(&self, lease: &CustodyLease, policy: &UrlGraphPolicyV1) -> Result<(), StoreError> {
        self.scope()?.authorize(lease.tenant)?;
        policy.validate().map_err(invalid)?;
        let mut tx = self.begin_write().await?;
        crate::custody::live::<B>(tx.conn(), lease).await?;
        let ceiling = retained_run::<B>(tx.conn(), lease.tenant, lease.run).await?;
        create_header::<B>(tx.conn(), lease, policy, ceiling).await?;
        let (graph, expiry) = load::<B>(tx.conn(), lease.tenant, lease.run, true).await?;
        if graph.policy != *policy {
            let stored = serde_json::to_value(policy)?;
            stmt!(
                B,
                "UPDATE url_graph_runs SET policy=$3 WHERE tenant_id=$1 AND run_id=$2"
            )
            .uuid(lease.tenant.0)
            .uuid(lease.run.0)
            .json(&stored)
            .execute(tx.conn())
            .await?;
            invalidate::<B>(tx.conn(), lease.tenant, lease.run).await?;
        }
        if ceiling < expiry {
            stmt!(
                B,
                "UPDATE url_graph_runs SET expires_at=$3 WHERE tenant_id=$1 AND run_id=$2"
            )
            .uuid(lease.tenant.0)
            .uuid(lease.run.0)
            .ts(ceiling)
            .execute(tx.conn())
            .await?;
        }
        finish::<B>(tx.conn(), lease, expiry.min(ceiling)).await?;
        tx.commit().await
    }

    async fn replace_source(
        &self,
        lease: &CustodyLease,
        batch: &UrlGraphBatchV1,
        policy: &UrlGraphPolicyV1,
    ) -> Result<u64, StoreError> {
        batch.validate().map_err(invalid)?;
        self.scope()?.authorize(lease.tenant)?;
        let mut tx = self.begin_write().await?;
        crate::custody::live::<B>(tx.conn(), lease).await?;
        let ceiling = retained_run::<B>(tx.conn(), lease.tenant, lease.run).await?;
        let (mut graph, expiry) = load::<B>(tx.conn(), lease.tenant, lease.run, true).await?;
        if graph.policy != *policy {
            return Err(StoreError::Conflict("url graph policy changed".into()));
        }
        let additional: BTreeSet<_> = std::iter::once(batch.source)
            .chain(batch.edges.iter().map(|edge| edge.target))
            .filter(|node| graph.nodes.binary_search(node).is_err())
            .collect();
        if graph.replace(batch).map_err(invalid)? {
            for node in additional {
                stmt!(
                    B,
                    "INSERT INTO url_graph_nodes(tenant_id,run_id,handle) VALUES($1,$2,$3)"
                )
                .uuid(lease.tenant.0)
                .uuid(lease.run.0)
                .bytes(node.0 .0.as_slice())
                .execute(tx.conn())
                .await?;
            }
            stmt!(
                B,
                "DELETE FROM url_graph_edges WHERE tenant_id=$1 AND run_id=$2 AND source_handle=$3"
            )
            .uuid(lease.tenant.0)
            .uuid(lease.run.0)
            .bytes(batch.source.0 .0.as_slice())
            .execute(tx.conn())
            .await?;
            for edge in &batch.edges {
                let anchor = edge.anchor.as_ref().map_or(&[][..], |digest| digest.0.as_slice());
                stmt!(
                    B,
                    "INSERT INTO url_graph_edges(tenant_id,run_id,version,source_handle,target_handle,anchor_handle,cost,producer_fence) VALUES($1,$2,1,$3,$4,$5,$6,$7)"
                )
                .uuid(lease.tenant.0)
                .uuid(lease.run.0)
                .bytes(edge.source.0 .0.as_slice())
                .bytes(edge.target.0 .0.as_slice())
                .bytes(anchor)
                .i64(i64::from(edge.cost))
                .i64(lease.fence)
                .execute(tx.conn())
                .await?;
            }
            let revision = i64::try_from(graph.revision).map_err(|_| denied())?;
            stmt!(
                B,
                "UPDATE url_graph_runs SET revision=$3 WHERE tenant_id=$1 AND run_id=$2"
            )
            .uuid(lease.tenant.0)
            .uuid(lease.run.0)
            .i64(revision)
            .execute(tx.conn())
            .await?;
            invalidate::<B>(tx.conn(), lease.tenant, lease.run).await?;
        }
        finish::<B>(tx.conn(), lease, expiry.min(ceiling)).await?;
        tx.commit().await?;
        Ok(graph.revision)
    }

    async fn snapshot(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphSnapshotV1, StoreError> {
        self.scope()?.authorize(tenant)?;
        let mut tx = self.begin_write().await?;
        retained_run::<B>(tx.conn(), tenant, run).await?;
        let (graph, expiry) = load::<B>(tx.conn(), tenant, run, false).await?;
        if expiry <= now::<B>(tx.conn()).await? {
            return Err(denied());
        }
        tx.commit().await?;
        Ok(graph)
    }

    async fn store_ranks(&self, lease: &CustodyLease, ranks: &UrlGraphRanksV1) -> Result<(), StoreError> {
        self.scope()?.authorize(lease.tenant)?;
        if ranks.tenant != lease.tenant || ranks.run != lease.run {
            return Err(denied());
        }
        let mut tx = self.begin_write().await?;
        crate::custody::live::<B>(tx.conn(), lease).await?;
        let ceiling = retained_run::<B>(tx.conn(), lease.tenant, lease.run).await?;
        let (graph, expiry) = load::<B>(tx.conn(), lease.tenant, lease.run, true).await?;
        ranks.validate_for(&graph).map_err(invalid)?;
        invalidate::<B>(tx.conn(), lease.tenant, lease.run).await?;
        let revision = i64::try_from(ranks.revision).map_err(|_| denied())?;
        let result = serde_json::to_value(ranks)?;
        stmt!(
            B,
            "INSERT INTO url_graph_ranks(tenant_id,run_id,version,revision,result) VALUES($1,$2,1,$3,$4)"
        )
        .uuid(lease.tenant.0)
        .uuid(lease.run.0)
        .i64(revision)
        .json(&result)
        .execute(tx.conn())
        .await?;
        finish::<B>(tx.conn(), lease, expiry.min(ceiling)).await?;
        tx.commit().await
    }

    async fn ranks(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphRankStateV1, StoreError> {
        self.scope()?.authorize(tenant)?;
        let mut tx = self.begin_write().await?;
        retained_run::<B>(tx.conn(), tenant, run).await?;
        let (graph, expiry) = load::<B>(tx.conn(), tenant, run, false).await?;
        let row = stmt!(
            B,
            "SELECT result FROM url_graph_ranks WHERE tenant_id=$1 AND run_id=$2"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .fetch_optional(tx.conn())
        .await?;
        let state = if let Some(row) = row {
            let ranks: UrlGraphRanksV1 = serde_json::from_value(row.json("result")?)?;
            if ranks.validate_for(&graph).is_ok() {
                UrlGraphRankStateV1::Current(ranks)
            } else {
                UrlGraphRankStateV1::Invalidated
            }
        } else {
            UrlGraphRankStateV1::Invalidated
        };
        if expiry <= now::<B>(tx.conn()).await? {
            return Err(denied());
        }
        tx.commit().await?;
        Ok(state)
    }
}
