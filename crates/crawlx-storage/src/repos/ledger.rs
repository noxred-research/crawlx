//! `LedgerRepo` over `action_contexts` and the shared context helpers.

use super::upsert_set;
use crate::backend::strategy::Conn;
use crate::backend::{BackendKind, Dialect};
use crate::codec::{conv, digest, parse_label};
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::identity::{ActionContextKey, ElementIdentityHash};
use crawlx_core::repo::{LedgerRepo, LedgerRow};
use crawlx_core::url::RouteTemplate;
use crawlx_core::{CrawlRunId, PrincipalId, StateClusterId, StoreError, Timestamp};

/// Columns [`key_from_row`] reads, qualified with alias `c`.
pub(crate) const KEY_COLS: &str =
    "c.run_id AS context_run_id, (SELECT tenant_id FROM crawl_runs WHERE run_id = c.run_id) AS context_tenant_id, \
    (SELECT retention_mode = 'zdr' FROM crawl_runs WHERE run_id = c.run_id) AS context_zdr, c.context_hash, c.principal, c.route_template, c.identity_hash, c.action_kind::text AS action_kind, \
    c.input_class, c.resource_context::text AS resource_context, c.state_cluster_id";

/// Rebuild the key of a ledger row selected with [`KEY_COLS`].
pub(crate) async fn key_from_row<B: Sql>(
    store: &Store<B>,
    r: &B::Row,
) -> Result<ActionContextKey, StoreError> {
    let run = CrawlRunId(r.uuid("context_run_id")?);
    let tenant = crawlx_core::TenantId(r.uuid("context_tenant_id")?);
    let zdr = r.flag("context_zdr")?;
    if zdr {
        let hash = crate::codec::digest16(&r.bytes("context_hash")?)?;
        let id = crawlx_core::ActionContextId(hash);
        return store
            .ephemeral_get(tenant, run, i64::MIN + 1, &format!("_context:{id}"))
            .await;
    }
    Ok(ActionContextKey {
        principal: PrincipalId(r.text("principal")?),
        route_template: RouteTemplate(r.text("route_template")?),
        element: ElementIdentityHash(digest(&r.bytes("identity_hash")?)?),
        action_kind: parse_label(&r.text("action_kind")?)?,
        input_class: crawlx_core::identity::InputClass(r.text("input_class")?),
        resource_context: parse_label(&r.text("resource_context")?)?,
        state_cluster: StateClusterId(r.uuid("state_cluster_id")?),
    })
}

/// Insert the ledger row for `key` if absent and return its `context_id`; also
/// registers the element in the `elements` registry. `denied` bumps the `denied` counter.
pub(crate) async fn ensure_context<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    run: CrawlRunId,
    key: &ActionContextKey,
    denied: bool,
) -> Result<i64, StoreError> {
    let (tenant, zdr) = Store::<B>::privacy_scope_tx(conn, run).await?;
    if zdr {
        store
            .ephemeral_put(tenant, run, i64::MIN + 1, &format!("_context:{}", key.id()), key)
            .await?;
    }
    let identity_version = stmt!(B, "SELECT identity_version FROM crawl_runs WHERE run_id = $1")
        .uuid(run.0)
        .fetch_one(&mut *conn)
        .await?
        .i16("identity_version")?;
    let seen = upsert_set::<B>(
        &["run_id", "identity_hash", "identity_version"],
        &format!("last_seen_at = {}", <B::Dialect as Dialect>::now()),
    );
    stmt!(
        B,
        format!("INSERT INTO elements (run_id, identity_hash, identity_version) VALUES ($1, $2, $3) {seen}")
    )
    .uuid(run.0)
    .bytes(&key.element.0 .0)
    .i16(identity_version)
    .execute(&mut *conn)
    .await?;
    let bump = upsert_set::<B>(
        &["run_id", "context_hash"],
        &format!(
            "denied = action_contexts.denied + {}, coarsened = action_contexts.coarsened OR {}",
            <B::Dialect as Dialect>::excluded("denied"),
            <B::Dialect as Dialect>::excluded("coarsened")
        ),
    );
    let context_hash = key.id();
    let principal = super::event::metadata_label(&key.principal.0, "crawlx/zdr-context-field/v1", zdr);
    let route = super::event::metadata_label(&key.route_template.0, "crawlx/zdr-context-field/v1", zdr);
    let input = super::event::metadata_label(&key.input_class.0, "crawlx/zdr-context-field/v1", zdr);
    let row = stmt!(
        B,
        format!(
            "INSERT INTO action_contexts (run_id, context_hash, principal, route_template, identity_hash, identity_version, action_kind, \
               input_class, resource_context, state_cluster_id, denied, coarsened) \
             VALUES ($1, $2, $3, $4, $5, $6, $7::text::action_kind, $8, $9::text::resource_context, $10, $11, $12) \
             {bump} RETURNING context_id"
        )
    )
    .uuid(run.0)
    .bytes(&context_hash.0)
    .text(&principal)
    .text(&route)
    .bytes(&key.element.0 .0)
    .i16(identity_version)
    .text(key.action_kind.as_str())
    .text(&input)
    .text(key.resource_context.as_str())
    .uuid(key.state_cluster.0)
    .i32(i32::from(denied))
    .bool(key.is_coarsened())
    .fetch_one(&mut *conn)
    .await?;
    row.i64("context_id")
}

#[async_trait]
impl<B: Sql> LedgerRepo for Store<B> {
    async fn summary(&self, run: CrawlRunId) -> Result<crawlx_core::repo::LedgerSummary, StoreError> {
        let _timer = self.query_timer("ledger.summary");
        let exercised = if B::KIND == BackendKind::Postgres {
            "count(*) FILTER (WHERE succeeded_trusted > 0)"
        } else {
            "COUNT(CASE WHEN succeeded_trusted > 0 THEN 1 END)"
        };
        let row = stmt!(
            B,
            format!(
                "SELECT count(*) AS discovered, {exercised} AS exercised_trusted \
                 FROM action_contexts WHERE run_id = $1"
            )
        )
        .uuid(run.0)
        .fetch_one_pool(&self.pool)
        .await?;
        Ok(crawlx_core::repo::LedgerSummary::new(
            conv(row.i64("discovered")?, "discovered")?,
            conv(row.i64("exercised_trusted")?, "exercised_trusted")?,
        ))
    }

    /// Absolute upsert: counters are overwritten, `first_seen` keeps the earliest value.
    async fn upsert(&self, run: CrawlRunId, row: &LedgerRow) -> Result<(), StoreError> {
        let _timer = self.query_timer("ledger.upsert");
        let mut tx = self.begin_write().await?;
        let ctx = ensure_context(self, tx.conn(), run, &row.key, false).await?;
        let trusted = conv::<u32, i32>(row.trusted_exercised, "trusted_exercised")?;
        let diagnostic = conv::<u32, i32>(row.diagnostic_exercised, "diagnostic_exercised")?;
        let failed = conv::<u32, i32>(row.failures, "failures")?;
        let attempts = <B::Dialect as Dialect>::greatest_ignoring_null(&["attempts", "$2 + $3 + $4"]);
        let first_seen = <B::Dialect as Dialect>::least_ignoring_null(&["first_seen_at", "$5"]);
        stmt!(
            B,
            format!(
                "UPDATE action_contexts SET succeeded_trusted = $2, succeeded = $2 + $3, failed = $4, \
                   attempts = {attempts}, first_seen_at = {first_seen}, \
                   first_exercised_at = CASE WHEN $2 + $3 + $4 > 0 THEN COALESCE(first_exercised_at, $5) ELSE first_exercised_at END, \
                   last_exercised_at = $6 WHERE context_id = $1"
            )
        )
        .i64(ctx)
        .i32(trusted)
        .i32(diagnostic)
        .i32(failed)
        .ts(row.first_seen)
        .opt_ts(row.last_exercised)
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<LedgerRow>, StoreError> {
        let _timer = self.query_timer("ledger.list");
        let rows = stmt!(
            B,
            format!(
                "SELECT {KEY_COLS}, c.succeeded_trusted, c.succeeded, c.failed, c.first_seen_at, c.last_exercised_at \
                 FROM action_contexts c WHERE c.run_id = $1 ORDER BY c.context_id"
            )
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?;
        let mut ledger = Vec::with_capacity(rows.len());
        for r in &rows {
            let trusted: i32 = r.i32("succeeded_trusted")?;
            let succeeded: i32 = r.i32("succeeded")?;
            let first_seen: Timestamp = r.ts("first_seen_at")?;
            ledger.push(LedgerRow {
                key: key_from_row(self, r).await?,
                trusted_exercised: conv(trusted, "succeeded_trusted")?,
                diagnostic_exercised: conv((succeeded - trusted).max(0), "diagnostic")?,
                failures: conv(r.i32("failed")?, "failed")?,
                first_seen,
                last_exercised: r.opt_ts("last_exercised_at")?,
            });
        }
        Ok(ledger)
    }
}
