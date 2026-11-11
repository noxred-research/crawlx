//! `EdgeStore` over `enablement_edges`.

use crate::backend::{BackendKind, Dialect};
use crate::codec::{conv, digest, digest16};
use crate::error::not_found;
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::repo::{EdgeRecord, EdgeStore};
use crawlx_core::{ActionContextId, CrawlRunId, EdgeId, StateClusterId, StoreError};

/// `enablement_edges.algo_version` written by this slice.
const EDGE_ALGO_VERSION: i16 = 1;

#[async_trait]
impl<B: Sql> EdgeStore for Store<B> {
    /// Absolute upsert keyed by `(run, source context, context cluster, target)`.
    /// The source action context must already exist in the ledger.
    async fn upsert(&self, edge: &EdgeRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("edge.upsert");
        let (tenant, zdr) = self.privacy_scope(edge.run).await?;
        let ctx = stmt!(
            B,
            "SELECT context_id FROM action_contexts WHERE run_id = $1 AND context_hash = $2"
        )
        .uuid(edge.run.0)
        .bytes(&edge.source.0)
        .fetch_optional_pool(&self.pool)
        .await?
        .map(|row| row.i64("context_id"))
        .transpose()?;
        let ctx = ctx.ok_or_else(|| not_found("action_context", edge.source))?;
        // the cluster is part of the key even when absent: the unique key treats NULLs as equal
        // (PostgreSQL `NULLS NOT DISTINCT`, a generated key column on MariaDB, an expression
        // index on SQLite, which the conflict target must repeat)
        let cluster = if B::KIND == BackendKind::Sqlite {
            "ifnull(context_cluster_id, zeroblob(16))"
        } else {
            "context_cluster_id"
        };
        let conflict = <B::Dialect as Dialect>::upsert_update(
            &[
                "run_id",
                "source_context_id",
                cluster,
                "target_kind",
                "target_key",
            ],
            &[
                "support",
                "weak_support",
                "failures",
                "latency_ms_ewma",
                "risk",
                "last_observed_at",
                "last_verified_build",
                "algo_version",
            ],
            None,
        );
        let mut tx = self.begin_write().await?;
        let id = stmt!(
            B,
            format!(
                "INSERT INTO enablement_edges (edge_id, run_id, source_context_id, context_cluster_id, target_kind, target_key, support, \
                   weak_support, failures, latency_ms_ewma, risk, last_observed_at, last_verified_build, algo_version) \
                 VALUES ($1, $2, $3, $4, 'element', $5, $6, $7, $8, $9, $10, $11, $12, $13) \
                 {conflict} RETURNING edge_id"
            )
        )
        .uuid(edge.id.0)
        .uuid(edge.run.0)
        .i64(ctx)
        .opt_uuid(edge.context_cluster.map(|c| c.0))
        .bytes(&edge.target.0 .0)
        .i32(conv::<u32, i32>(edge.support, "support")?)
        .i32(conv::<u32, i32>(edge.weak_support, "weak_support")?)
        .i32(conv::<u32, i32>(edge.failures, "failures")?)
        .f32(edge.latency_ms_ewma)
        .f32(edge.risk)
        .ts(edge.last_observed_at)
        .opt_text(if zdr { None } else { edge.last_verified_build.as_deref() })
        .i16(EDGE_ALGO_VERSION)
        .fetch_one(tx.conn())
        .await?
        .uuid("edge_id")?;
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
        tx.commit().await?;
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<EdgeRecord>, StoreError> {
        let _timer = self.query_timer("edge.list");
        let rows = stmt!(
            B,
            "SELECT e.edge_id, e.run_id, c.context_hash, e.context_cluster_id, e.target_key, e.support, e.weak_support, e.failures, \
               e.latency_ms_ewma, e.risk, e.last_observed_at, e.last_verified_build \
             FROM enablement_edges e JOIN action_contexts c ON c.context_id = e.source_context_id \
             WHERE e.run_id = $1 AND e.target_kind = 'element' ORDER BY e.edge_id"
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut edges = Vec::with_capacity(rows.len());
        for r in &rows {
            let id = EdgeId(r.uuid("edge_id")?);
            let build = if zdr {
                self.ephemeral_get(tenant, run, i64::MIN + 1, &format!("_edge:{id}"))
                    .await?
            } else {
                r.opt_text("last_verified_build")?
            };
            edges.push(EdgeRecord {
                id,
                run: CrawlRunId(r.uuid("run_id")?),
                source: ActionContextId(digest16(&r.bytes("context_hash")?)?),
                context_cluster: r.opt_uuid("context_cluster_id")?.map(StateClusterId),
                target: ElementIdentityHash(digest(&r.bytes("target_key")?)?),
                support: conv(r.i32("support")?, "support")?,
                weak_support: conv(r.i32("weak_support")?, "weak_support")?,
                failures: conv(r.i32("failures")?, "failures")?,
                latency_ms_ewma: r.opt_f32("latency_ms_ewma")?.unwrap_or_default(),
                risk: r.f32("risk")?,
                last_observed_at: r.opt_ts("last_observed_at")?.unwrap_or_default(),
                last_verified_build: build,
            });
        }
        Ok(edges)
    }
}
