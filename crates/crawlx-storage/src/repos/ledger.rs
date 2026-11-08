//! `LedgerRepo` over `action_contexts` and the shared context helpers.

use crate::codec::{conv, digest, get, parse_label};
use crate::error::db;
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::identity::{ActionContextKey, ElementIdentityHash};
use crawlx_core::repo::{LedgerRepo, LedgerRow};
use crawlx_core::url::RouteTemplate;
use crawlx_core::{CrawlRunId, PrincipalId, StateClusterId, StoreError, Timestamp};
use sqlx::postgres::PgRow;
use sqlx::PgConnection;

/// Columns [`key_from_row`] reads, qualified with alias `c`.
pub(crate) const KEY_COLS: &str =
    "c.run_id AS context_run_id, (SELECT tenant_id FROM crawl_runs WHERE run_id = c.run_id) AS context_tenant_id, \
    (SELECT retention_mode = 'zdr' FROM crawl_runs WHERE run_id = c.run_id) AS context_zdr, c.context_hash, c.principal, c.route_template, c.identity_hash, c.action_kind::text AS action_kind, \
    c.input_class, c.resource_context::text AS resource_context, c.state_cluster_id";

pub(crate) async fn key_from_row(pg: &Pg, r: &PgRow) -> Result<ActionContextKey, StoreError> {
    let run = CrawlRunId(get(r, "context_run_id")?);
    let tenant = crawlx_core::TenantId(get(r, "context_tenant_id")?);
    let zdr: bool = get(r, "context_zdr")?;
    if zdr {
        let hash = crate::codec::digest16(&get::<Vec<u8>>(r, "context_hash")?)?;
        let id = crawlx_core::ActionContextId(hash);
        return pg
            .ephemeral_get(tenant, run, i64::MIN + 1, &format!("_context:{id}"))
            .await;
    }
    Ok(ActionContextKey {
        principal: PrincipalId(get(r, "principal")?),
        route_template: RouteTemplate(get(r, "route_template")?),
        element: ElementIdentityHash(digest(&get::<Vec<u8>>(r, "identity_hash")?)?),
        action_kind: parse_label(&get::<String>(r, "action_kind")?)?,
        input_class: crawlx_core::identity::InputClass(get(r, "input_class")?),
        resource_context: parse_label(&get::<String>(r, "resource_context")?)?,
        state_cluster: StateClusterId(get(r, "state_cluster_id")?),
    })
}

/// Insert the ledger row for `key` if absent and return its `context_id`; also
/// registers the element in the `elements` registry. `denied` bumps the `denied` counter.
pub(crate) async fn ensure_context(
    pg: &Pg,
    conn: &mut PgConnection,
    run: CrawlRunId,
    key: &ActionContextKey,
    denied: bool,
) -> Result<i64, StoreError> {
    let (tenant, zdr) = Pg::privacy_scope_tx(conn, run).await?;
    if zdr {
        pg.ephemeral_put(tenant, run, i64::MIN + 1, &format!("_context:{}", key.id()), key)
            .await?;
    }
    let identity_version: i16 =
        sqlx::query_scalar("SELECT identity_version FROM crawl_runs WHERE run_id = $1")
            .bind(run.0)
            .fetch_one(&mut *conn)
            .await
            .map_err(db)?;
    sqlx::query(
        "INSERT INTO elements (run_id, identity_hash, identity_version) VALUES ($1, $2, $3) \
         ON CONFLICT (run_id, identity_hash, identity_version) DO UPDATE SET last_seen_at = now()",
    )
    .bind(run.0)
    .bind(key.element.0 .0.to_vec())
    .bind(identity_version)
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO action_contexts (run_id, context_hash, principal, route_template, identity_hash, identity_version, action_kind, \
           input_class, resource_context, state_cluster_id, denied, coarsened) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::text::action_kind, $8, $9::text::resource_context, $10, $11, $12) \
         ON CONFLICT (run_id, context_hash) DO UPDATE SET denied = action_contexts.denied + EXCLUDED.denied, \
           coarsened = action_contexts.coarsened OR EXCLUDED.coarsened \
         RETURNING context_id",
    )
    .bind(run.0)
    .bind(key.id().0.to_vec())
    .bind(super::event::metadata_label(&key.principal.0, "crawlx/zdr-context-field/v1", zdr))
    .bind(super::event::metadata_label(&key.route_template.0, "crawlx/zdr-context-field/v1", zdr))
    .bind(key.element.0 .0.to_vec())
    .bind(identity_version)
    .bind(key.action_kind.as_str())
    .bind(super::event::metadata_label(&key.input_class.0, "crawlx/zdr-context-field/v1", zdr))
    .bind(key.resource_context.as_str())
    .bind(key.state_cluster.0)
    .bind(i32::from(denied))
    .bind(key.is_coarsened())
    .fetch_one(&mut *conn)
    .await
    .map_err(db)?;
    Ok(id)
}

#[async_trait]
impl LedgerRepo for Pg {
    async fn summary(&self, run: CrawlRunId) -> Result<crawlx_core::repo::LedgerSummary, StoreError> {
        let _timer = self.query_timer("ledger.summary");
        let row = sqlx::query(
            "SELECT count(*) AS discovered, count(*) FILTER (WHERE succeeded_trusted > 0) AS exercised_trusted \
             FROM action_contexts WHERE run_id = $1",
        )
        .bind(run.0)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        Ok(crawlx_core::repo::LedgerSummary::new(
            conv(get::<i64>(&row, "discovered")?, "discovered")?,
            conv(get::<i64>(&row, "exercised_trusted")?, "exercised_trusted")?,
        ))
    }

    /// Absolute upsert: counters are overwritten, `first_seen` keeps the earliest value.
    async fn upsert(&self, run: CrawlRunId, row: &LedgerRow) -> Result<(), StoreError> {
        let _timer = self.query_timer("ledger.upsert");
        let mut tx = self.pool.begin().await.map_err(db)?;
        let ctx = ensure_context(self, &mut tx, run, &row.key, false).await?;
        let trusted = conv::<u32, i32>(row.trusted_exercised, "trusted_exercised")?;
        let diagnostic = conv::<u32, i32>(row.diagnostic_exercised, "diagnostic_exercised")?;
        let failed = conv::<u32, i32>(row.failures, "failures")?;
        sqlx::query(
            "UPDATE action_contexts SET succeeded_trusted = $2, succeeded = $2 + $3, failed = $4, \
               attempts = GREATEST(attempts, $2 + $3 + $4), first_seen_at = LEAST(first_seen_at, $5), \
               first_exercised_at = CASE WHEN $2 + $3 + $4 > 0 THEN COALESCE(first_exercised_at, $5) ELSE first_exercised_at END, \
               last_exercised_at = $6 WHERE context_id = $1",
        )
        .bind(ctx)
        .bind(trusted)
        .bind(diagnostic)
        .bind(failed)
        .bind(row.first_seen)
        .bind(row.last_exercised)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<LedgerRow>, StoreError> {
        let _timer = self.query_timer("ledger.list");
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {KEY_COLS}, c.succeeded_trusted, c.succeeded, c.failed, c.first_seen_at, c.last_exercised_at \
         FROM action_contexts c WHERE c.run_id = $1 ORDER BY c.context_id")))
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut ledger = Vec::with_capacity(rows.len());
        for r in &rows {
            let trusted: i32 = get(r, "succeeded_trusted")?;
            let succeeded: i32 = get(r, "succeeded")?;
            let first_seen: Timestamp = get(r, "first_seen_at")?;
            ledger.push(LedgerRow {
                key: key_from_row(self, r).await?,
                trusted_exercised: conv(trusted, "succeeded_trusted")?,
                diagnostic_exercised: conv((succeeded - trusted).max(0), "diagnostic")?,
                failures: conv(get::<i32>(r, "failed")?, "failed")?,
                first_seen,
                last_exercised: get(r, "last_exercised_at")?,
            });
        }
        Ok(ledger)
    }
}
