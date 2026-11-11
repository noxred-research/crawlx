//! PostgreSQL: migrations, the tenant-scoped pool and the concurrency strategy.
//!
//! The SQL in this module moved here unchanged from the repositories that used to carry it.

use super::dialect::PostgresDialect;
use super::strategy::{
    audit_entry_hash, AuditEntry, Concurrency, FenceSeq, FrontierClaim, LockMode, MonitorClaim, OutboxClaim,
    Query, SessionClaim, TrafficRow, WebhookClaim, WriteTx, EMPTY_AUDIT_HEAD,
};
use super::{Backend, BackendKind};
use crate::error::db;
use crate::tenant::current;
use crawlx_core::StoreError;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use futures::TryStreamExt;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnection, PgPool, PgQueryResult, PgRow, PgStatement, PgTypeInfo};
use sqlx::{Describe, Either, Error, Execute, Executor, Postgres, SqlStr, Transaction};
use std::ops::Deref;
use uuid::Uuid;

/// The PostgreSQL migrations, embedded at build time.
pub(crate) static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// The PostgreSQL backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct PgBackend;

impl super::sealed::Sealed for PgBackend {}

impl Backend for PgBackend {
    type Db = Postgres;
    type Pool = TenantPool;
    type Dialect = PostgresDialect;
    const KIND: BackendKind = BackendKind::Postgres;

    fn pool_in_use(pool: &Self::Pool) -> u32 {
        let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
        pool.size().saturating_sub(idle)
    }
}

/// Publish `crawlx.db.pool.in_use` (`size - num_idle`) for `pool`.
pub(crate) fn set_pool_in_use(pool: &PgPool) {
    let idle = u32::try_from(pool.num_idle()).unwrap_or(u32::MAX);
    let in_use = pool.size().saturating_sub(idle);
    Metrics::global()
        .gauge(names::DB_POOL_IN_USE)
        .set(f64::from(in_use), &[]);
}

/// Pool selection stays private to storage: only authenticated, scoped work uses
/// `api`; migrations, workers and cross-tenant maintenance retain `authority`.
#[derive(Clone, Debug)]
pub struct TenantPool {
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

    fn scoped_pool(&self) -> &PgPool {
        if current().is_some() {
            self.authentication()
        } else {
            &self.authority
        }
    }

    pub(crate) async fn begin(&self) -> Result<Transaction<'static, Postgres>, Error> {
        let tenant = current();
        let mut tx = self.scoped_pool().begin().await?;
        if let Some(tenant) = tenant {
            sqlx::query("SELECT set_config('app.tenant_id', $1::uuid::text, true)")
                .bind(tenant.0)
                .execute(&mut *tx)
                .await?;
        }
        Ok(tx)
    }

    /// Like [`TenantPool::begin`], opening the transaction with `statement`.
    pub(crate) async fn begin_with(
        &self,
        statement: &'static str,
    ) -> Result<Transaction<'static, Postgres>, Error> {
        let tenant = current();
        let mut tx = self.scoped_pool().begin_with(statement).await?;
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

    fn prepare_with<'e>(
        self,
        sql: SqlStr,
        parameters: &'e [PgTypeInfo],
    ) -> BoxFuture<'e, Result<PgStatement, Error>>
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

    fn describe<'e>(self, sql: SqlStr) -> BoxFuture<'e, Result<Describe<Postgres>, Error>>
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

/// Alias the webhook claim gives `webhook_deliveries`.
const WEBHOOK_PREFIX: &str = "w.";

impl Concurrency for PgBackend {
    async fn begin_write(pool: &Self::Pool) -> Result<WriteTx<Postgres>, StoreError> {
        let tx = pool.begin().await.map_err(db)?;
        Ok(WriteTx::new(tx, None))
    }

    async fn begin_read(pool: &Self::Pool) -> Result<Transaction<'static, Postgres>, StoreError> {
        pool.begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await
            .map_err(db)
    }

    async fn db_now(pool: &Self::Pool) -> Result<crate::backend::strategy::Timestamp, StoreError> {
        sqlx::query_scalar("SELECT now()")
            .fetch_one(pool)
            .await
            .map_err(db)
    }

    async fn next_fence(conn: &mut PgConnection, seq: FenceSeq) -> Result<i64, StoreError> {
        // The sequence name is one of the `FenceSeq` literals, never caller text.
        let sql = sqlx::AssertSqlSafe(format!("SELECT nextval('{}')", seq.name()));
        sqlx::query_scalar(sql).fetch_one(conn).await.map_err(db)
    }

    async fn xact_lock(conn: &mut PgConnection, key: &str, mode: LockMode) -> Result<(), StoreError> {
        let sql = match mode {
            LockMode::Exclusive => "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            LockMode::Shared => "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))",
        };
        sqlx::query(sql).bind(key).execute(conn).await.map_err(db)?;
        Ok(())
    }

    async fn claim_sessions(pool: &TenantPool, claim: SessionClaim<'_>) -> Result<Option<PgRow>, StoreError> {
        // Parallel runs probe only claimable states and an indexed availability range.
        // Recovering holders retain their state, so live recovery leases must also leave
        // the searchable range. Serial runs inspect exactly the first unfinished slot;
        // skipping a locked head must never grant its successor.
        let candidate = if claim.parallel_roles {
            "SELECT c.session_id FROM crawl_sessions c \
             WHERE c.run_id=$2 AND c.lease_kind='role' AND c.status IN ('pending','recovering') \
               AND ($4::uuid IS NULL OR c.session_id=$4) \
               AND COALESCE(c.lease_expires_at,'-infinity'::timestamptz)<clock_timestamp() \
             ORDER BY COALESCE(c.lease_expires_at,'-infinity'::timestamptz),c.schedule_slot \
             LIMIT 1 FOR UPDATE SKIP LOCKED"
        } else {
            "SELECT c.session_id FROM crawl_sessions c \
             WHERE c.session_id=(SELECT p.session_id FROM crawl_sessions p WHERE p.run_id=$2 \
               AND p.lease_kind='role' AND p.status NOT IN ('completed','failed','cancelled') ORDER BY p.schedule_slot LIMIT 1) \
               AND ($4::uuid IS NULL OR c.session_id=$4) AND c.status IN ('pending','recovering') \
               AND COALESCE(c.lease_expires_at,'-infinity'::timestamptz)<clock_timestamp() \
             FOR UPDATE SKIP LOCKED"
        };
        let columns = claim.columns;
        let sql = format!(
            "UPDATE crawl_sessions s SET status=CASE WHEN s.status='pending' THEN 'running' ELSE s.status END, \
             lease_owner=$1,lease_expires_at=clock_timestamp()+make_interval(secs=>$3), \
             fencing_token=nextval('lease_fence_seq'),last_heartbeat_at=clock_timestamp(), \
             started_at=COALESCE(s.started_at,clock_timestamp()) \
             WHERE EXISTS(SELECT 1 FROM crawl_runs r WHERE r.run_id=$2 AND r.status IN ('queued','running') \
               AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL) \
               AND ((cardinality($5::text[])=0 AND NOT $6::boolean) OR EXISTS(SELECT 1 FROM workers w \
                 WHERE w.worker_id=$1 AND NOT w.draining AND w.last_heartbeat_at<=clock_timestamp() \
                   AND w.last_heartbeat_at>=clock_timestamp()-interval '90 seconds' \
                   AND (w.capacity->'acceptsQueued'='true'::jsonb OR w.capacity->>'localRun'=$2::text) \
                   AND NOT EXISTS(SELECT 1 FROM unnest($5::text[]) required(backend_id) \
                     WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(w.capacity->'acquisition','[]'::jsonb)) fact \
                       WHERE fact->>'backendId'=required.backend_id AND fact->'available'='true'::jsonb)))) \
               AND crawlx_worker_data_eligible($1,(SELECT data_requirements FROM crawl_runs WHERE run_id=$2)) \
               AND s.session_id=({candidate}) RETURNING {columns}"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(claim.worker)
            .bind(claim.run)
            .bind(claim.ttl_secs)
            .bind(claim.requested)
            .bind(claim.required_backends)
            .bind(claim.data_required)
            .fetch_optional(pool)
            .await
            .map_err(db)
    }

    async fn claim_frontier_batch(
        pool: &TenantPool,
        claim: FrontierClaim<'_>,
    ) -> Result<Vec<PgRow>, StoreError> {
        let sql = "WITH picked AS ( \
               SELECT frontier_id FROM url_frontier WHERE run_id = $1 AND via <> 'interaction' AND status = 'pending' AND next_attempt_at <= now() \
               AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic' \
               AND (cardinality($5::text[])=0 AND NOT $6::boolean OR EXISTS (SELECT 1 FROM workers w \
                 WHERE w.worker_id=$2 AND NOT w.draining AND w.last_heartbeat_at<=clock_timestamp() \
                   AND w.last_heartbeat_at>=clock_timestamp()-interval '90 seconds' \
                   AND (w.capacity->'acceptsQueued'='true'::jsonb OR w.capacity->>'localRun'=$1::text) \
                   AND NOT EXISTS(SELECT 1 FROM unnest($5::text[]) required(backend_id) \
                     WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(w.capacity->'acquisition','[]'::jsonb)) fact \
                       WHERE fact->>'backendId'=required.backend_id AND fact->'available'='true'::jsonb)))) \
               AND crawlx_worker_data_eligible($2,(SELECT data_requirements FROM crawl_runs WHERE run_id=$1)) \
               ORDER BY priority DESC, \
                 CASE $7::text WHEN 'depth_first' THEN -depth::integer WHEN 'priority' THEN strategy_score ELSE depth::integer END, \
                 CASE WHEN $7='priority' THEN depth::integer ELSE 0 END, \
                 CASE WHEN $7='depth_first' THEN ~frontier_id ELSE frontier_id END \
               LIMIT $3 FOR UPDATE SKIP LOCKED) \
             UPDATE url_frontier f SET status = 'leased', lease_owner = $2, lease_expires_at = now() + make_interval(secs => $4), \
               fencing_token = nextval('lease_fence_seq'), attempts = attempts + 1 \
             FROM picked WHERE f.frontier_id = picked.frontier_id \
             RETURNING f.frontier_id, f.run_id, f.query_schema, f.depth, f.status, COALESCE(f.denial_reason, f.error_code) AS denial_reason, \
               f.attempts, f.parent_id, f.priority, COALESCE(f.strategy_score,0) AS strategy_score, f.fencing_token";
        sqlx::query(sql)
            .bind(claim.run)
            .bind(claim.worker)
            .bind(claim.limit)
            .bind(claim.ttl_secs)
            .bind(claim.required_backends)
            .bind(claim.data_required)
            .bind(claim.strategy)
            .fetch_all(pool)
            .await
            .map_err(db)
    }

    async fn claim_webhooks(pool: &TenantPool, claim: WebhookClaim<'_>) -> Result<Vec<PgRow>, StoreError> {
        let columns = claim
            .columns
            .split(", ")
            .map(|c| format!("{WEBHOOK_PREFIX}{c}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH due AS (SELECT delivery_id, next_attempt_at AS due_at FROM webhook_deliveries \
                          WHERE status = 'pending' AND next_attempt_at <= $1 \
                          ORDER BY next_attempt_at, delivery_id LIMIT $2 FOR UPDATE SKIP LOCKED) \
             UPDATE webhook_deliveries w SET next_attempt_at = $1 + make_interval(secs => $3) \
             FROM due WHERE w.delivery_id = due.delivery_id \
             RETURNING {columns}, due.due_at"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(claim.now)
            .bind(claim.limit)
            .bind(claim.lease_secs)
            .fetch_all(pool)
            .await
            .map_err(db)
    }

    async fn claim_monitors(pool: &TenantPool, claim: MonitorClaim) -> Result<Vec<PgRow>, StoreError> {
        // One atomic statement: competing tickers skip rows another ticker holds locked, and a
        // row claimed by a committed ticker no longer satisfies the `claimed_until` predicate.
        let columns = claim.columns;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE monitors SET claimed_until = $2 \
         WHERE monitor_id IN ( \
           SELECT monitor_id FROM monitors \
           WHERE status = 'active' AND next_run_at <= $1 AND (claimed_until IS NULL OR claimed_until <= $1) \
           ORDER BY next_run_at, monitor_id \
           LIMIT $3 \
           FOR UPDATE SKIP LOCKED) \
         RETURNING {columns}"
        )))
        .bind(claim.now)
        .bind(claim.lease_until)
        .bind(claim.limit)
        .fetch_all(pool)
        .await
        .map_err(db)
    }

    async fn claim_outbox(conn: &mut PgConnection, claim: OutboxClaim) -> Result<Vec<PgRow>, StoreError> {
        sqlx::query("WITH picked AS (SELECT delivery_id FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND expires_at>now() AND not_before<=now() AND (NOT terminal_source OR (SELECT feed_finalized FROM crawl_runs WHERE run_id=$2)) AND (state='pending' OR (state='leased' AND lease_expires_at<=now())) ORDER BY delivery_id FOR UPDATE SKIP LOCKED LIMIT $3) UPDATE dataset_delivery_outbox o SET state='leased',attempts=o.attempts+1,fence=o.fence+1,lease_owner=$4,lease_expires_at=now()+make_interval(secs=>$5) FROM picked WHERE o.delivery_id=picked.delivery_id RETURNING o.delivery_id,o.payload,o.volatile_page,o.fence,o.attempts")
            .bind(claim.tenant)
            .bind(claim.run)
            .bind(claim.limit)
            .bind(claim.worker)
            .bind(claim.lease_secs)
            .fetch_all(conn)
            .await
            .map_err(db)
    }

    async fn expire_outbox(pool: &TenantPool, tenant: Uuid, run: Uuid) -> Result<u64, StoreError> {
        sqlx::query("WITH expired AS (SELECT delivery_id FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND state IN ('pending','leased') AND expires_at<=now() ORDER BY delivery_id LIMIT 1000 FOR UPDATE SKIP LOCKED) UPDATE dataset_delivery_outbox o SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL FROM expired WHERE o.delivery_id=expired.delivery_id")
            .bind(tenant)
            .bind(run)
            .execute(pool)
            .await
            .map(|done| done.rows_affected())
            .map_err(db)
    }

    async fn fenced_update_returning<'q, U, R>(
        conn: &mut PgConnection,
        update: &'static str,
        bind_update: U,
        _reread: Option<(&'static str, R)>,
    ) -> Result<Option<PgRow>, StoreError>
    where
        U: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send,
        R: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send,
    {
        bind_update(sqlx::query(update))
            .fetch_optional(conn)
            .await
            .map_err(db)
    }

    async fn heartbeat_frontier(
        pool: &TenantPool,
        worker: Uuid,
        ttl_secs: f64,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError> {
        use sqlx::Row as _;
        let (ids, fences): (Vec<i64>, Vec<i64>) = leases.iter().copied().unzip();
        let rows = sqlx::query(
            "UPDATE url_frontier f SET lease_expires_at = now() + make_interval(secs => $4) \
             FROM unnest($1::bigint[], $2::bigint[]) AS held(frontier_id, fencing_token) \
             WHERE f.frontier_id = held.frontier_id AND f.fencing_token = held.fencing_token \
               AND f.lease_owner = $3 AND f.status = 'leased' AND f.lease_expires_at > now() RETURNING f.frontier_id",
        )
        .bind(ids)
        .bind(fences)
        .bind(worker)
        .bind(ttl_secs)
        .fetch_all(pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| r.try_get::<i64, _>("frontier_id").map_err(db))
            .collect()
    }

    async fn insert_traffic(
        conn: &mut PgConnection,
        run: Uuid,
        lane: &str,
        rows: &[TrafficRow<'_>],
    ) -> Result<(), StoreError> {
        let n = rows.len();
        let mut occurred = Vec::with_capacity(n);
        let mut epochs: Vec<Option<Uuid>> = Vec::with_capacity(n);
        let mut reasons: Vec<Option<&str>> = Vec::with_capacity(n);
        let mut seqs = Vec::with_capacity(n);
        let mut origins = Vec::with_capacity(n);
        let mut third = Vec::with_capacity(n);
        let mut late = Vec::with_capacity(n);
        let mut methods = Vec::with_capacity(n);
        let mut urls: Vec<Option<&str>> = Vec::with_capacity(n);
        let mut hashes: Vec<&[u8]> = Vec::with_capacity(n);
        let mut statuses: Vec<Option<i32>> = Vec::with_capacity(n);
        let mut req_h: Vec<Option<&serde_json::Value>> = Vec::with_capacity(n);
        let mut resp_h: Vec<Option<&serde_json::Value>> = Vec::with_capacity(n);
        let mut bodies: Vec<Option<Uuid>> = Vec::with_capacity(n);
        let mut req_bodies: Vec<Option<Uuid>> = Vec::with_capacity(n);
        let mut finished = Vec::with_capacity(n);
        for t in rows {
            occurred.push(t.occurred_at);
            epochs.push(t.epoch);
            reasons.push(t.reason);
            seqs.push(t.seq);
            origins.push(t.origin);
            third.push(t.third_party);
            late.push(t.late);
            methods.push(t.method);
            urls.push(t.url);
            hashes.push(t.url_hash.as_slice());
            statuses.push(t.status);
            req_h.push(t.request_headers.as_ref());
            resp_h.push(t.response_headers.as_ref());
            bodies.push(t.body);
            req_bodies.push(t.request_body);
            finished.push(t.finished_at);
        }
        sqlx::query(
            "INSERT INTO traffic_events (occurred_at, run_id, epoch_id, unattributed_reason, seq, lane, origin, third_party, late, method, url_redacted, url_hash, status, \
               request_headers, response_headers, body_artifact_id, request_body_artifact_id, finished_at) \
             SELECT t.occurred_at, $1::uuid, t.epoch_id, t.reason, t.seq, \
               (CASE WHEN t.epoch_id IS NULL THEN 'diagnostic' ELSE $2::text END)::trust_lane, t.origin, t.third_party, t.late, t.method, t.url_redacted, t.url_hash, \
               t.status, t.req_h, t.resp_h, t.body, t.req_body, t.finished_at \
             FROM UNNEST($3::timestamptz[], $4::uuid[], $5::text[], $6::int[], $7::text[], $8::bool[], $9::bool[], $10::text[], $11::text[], $12::bytea[], $13::int[], \
               $14::jsonb[], $15::jsonb[], $16::uuid[], $17::uuid[], $18::timestamptz[]) \
               AS t(occurred_at, epoch_id, reason, seq, origin, third_party, late, method, url_redacted, url_hash, status, req_h, resp_h, body, req_body, finished_at)",
        )
        .bind(run)
        .bind(lane)
        .bind(occurred)
        .bind(epochs)
        .bind(reasons)
        .bind(seqs)
        .bind(origins)
        .bind(third)
        .bind(late)
        .bind(methods)
        .bind(urls)
        .bind(hashes)
        .bind(statuses)
        .bind(req_h)
        .bind(resp_h)
        .bind(bodies)
        .bind(req_bodies)
        .bind(finished)
        .execute(&mut *conn)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn append_audit_chain(conn: &mut PgConnection, entry: AuditEntry<'_>) -> Result<(), StoreError> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('crawlx_audit_chain'))")
            .execute(&mut *conn)
            .await
            .map_err(db)?;
        let prev: Option<Vec<u8>> = sqlx::query_scalar("SELECT crawlx_audit_head()")
            .fetch_one(&mut *conn)
            .await
            .map_err(db)?;
        let prev = prev.unwrap_or_else(|| EMPTY_AUDIT_HEAD.to_vec());
        let hash = audit_entry_hash(&prev, &entry);
        sqlx::query("INSERT INTO audit_events (tenant_id, run_id, actor, event, subject, prev_hash, entry_hash) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(entry.tenant)
            .bind(entry.run)
            .bind(entry.actor)
            .bind(entry.event)
            .bind(entry.subject)
            .bind(prev)
            .bind(hash.0.to_vec())
            .execute(&mut *conn)
            .await
            .map_err(db)?;
        Ok(())
    }
}
