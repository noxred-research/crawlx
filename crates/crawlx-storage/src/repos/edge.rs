//! `EdgeStore` over `enablement_edges`.

use crate::codec::{conv, digest, digest16, get};
use crate::error::{db, not_found};
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::repo::{EdgeRecord, EdgeStore};
use crawlx_core::{ActionContextId, CrawlRunId, EdgeId, StateClusterId, StoreError};

/// `enablement_edges.algo_version` written by this slice.
const EDGE_ALGO_VERSION: i16 = 1;

#[async_trait]
impl EdgeStore for Pg {
    /// Absolute upsert keyed by `(run, source context, context cluster, target)`.
    /// The source action context must already exist in the ledger.
    async fn upsert(&self, edge: &EdgeRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("edge.upsert");
        let (tenant, zdr) = self.privacy_scope(edge.run).await?;
        let ctx: Option<i64> = sqlx::query_scalar(
            "SELECT context_id FROM action_contexts WHERE run_id = $1 AND context_hash = $2",
        )
        .bind(edge.run.0)
        .bind(edge.source.0.to_vec())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        let ctx = ctx.ok_or_else(|| not_found("action_context", edge.source))?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO enablement_edges (edge_id, run_id, source_context_id, context_cluster_id, target_kind, target_key, support, \
               weak_support, failures, latency_ms_ewma, risk, last_observed_at, last_verified_build, algo_version) \
             VALUES ($1, $2, $3, $4, 'element', $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (run_id, source_context_id, context_cluster_id, target_kind, target_key) DO UPDATE SET \
               support = EXCLUDED.support, weak_support = EXCLUDED.weak_support, failures = EXCLUDED.failures, \
               latency_ms_ewma = EXCLUDED.latency_ms_ewma, risk = EXCLUDED.risk, last_observed_at = EXCLUDED.last_observed_at, \
               last_verified_build = EXCLUDED.last_verified_build, algo_version = EXCLUDED.algo_version RETURNING edge_id",
        )
        .bind(edge.id.0)
        .bind(edge.run.0)
        .bind(ctx)
        .bind(edge.context_cluster.map(|c| c.0))
        .bind(edge.target.0 .0.to_vec())
        .bind(conv::<u32, i32>(edge.support, "support")?)
        .bind(conv::<u32, i32>(edge.weak_support, "weak_support")?)
        .bind(conv::<u32, i32>(edge.failures, "failures")?)
        .bind(edge.latency_ms_ewma)
        .bind(edge.risk)
        .bind(edge.last_observed_at)
        .bind(if zdr { None } else { edge.last_verified_build.as_deref() })
        .bind(EDGE_ALGO_VERSION)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if zdr {
            self.ephemeral_put(
                tenant,
                edge.run,
                i64::MIN + 1,
                &format!("_edge:{}", EdgeId(id)),
                &edge.last_verified_build,
            )
            .await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<EdgeRecord>, StoreError> {
        let _timer = self.query_timer("edge.list");
        let rows = sqlx::query(
            "SELECT e.edge_id, e.run_id, c.context_hash, e.context_cluster_id, e.target_key, e.support, e.weak_support, e.failures, \
               e.latency_ms_ewma, e.risk, e.last_observed_at, e.last_verified_build \
             FROM enablement_edges e JOIN action_contexts c ON c.context_id = e.source_context_id \
             WHERE e.run_id = $1 AND e.target_kind = 'element' ORDER BY e.edge_id",
        )
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut edges = Vec::with_capacity(rows.len());
        for r in &rows {
            let id = EdgeId(get(r, "edge_id")?);
            let build = if zdr {
                self.ephemeral_get(tenant, run, i64::MIN + 1, &format!("_edge:{id}"))
                    .await?
            } else {
                get(r, "last_verified_build")?
            };
            edges.push(EdgeRecord {
                id,
                run: CrawlRunId(get(r, "run_id")?),
                source: ActionContextId(digest16(&get::<Vec<u8>>(r, "context_hash")?)?),
                context_cluster: get::<Option<uuid::Uuid>>(r, "context_cluster_id")?.map(StateClusterId),
                target: ElementIdentityHash(digest(&get::<Vec<u8>>(r, "target_key")?)?),
                support: conv(get::<i32>(r, "support")?, "support")?,
                weak_support: conv(get::<i32>(r, "weak_support")?, "weak_support")?,
                failures: conv(get::<i32>(r, "failures")?, "failures")?,
                latency_ms_ewma: get::<Option<f32>>(r, "latency_ms_ewma")?.unwrap_or_default(),
                risk: get(r, "risk")?,
                last_observed_at: get::<Option<crawlx_core::Timestamp>>(r, "last_observed_at")?
                    .unwrap_or_default(),
                last_verified_build: build,
            });
        }
        Ok(edges)
    }
}
