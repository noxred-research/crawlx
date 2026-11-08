//! Deployment-global origin admission, independent of tenant-scoped repositories.
//!
//! Capacity permits hold PostgreSQL transactions until drop. A separate bounded
//! pool carries lock waiters and held permits; a second two-connection pool handles
//! short ticket/pacing transactions. Neither can exhaust the normal storage pool.

use crate::codec::conv;
use crate::error::db;
use crate::Pg;
use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::origin::{OriginAdmission, OriginPermit};
use crawlx_core::{CrawlRunId, StoreError};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Postgres, Transaction};
use std::sync::Arc;
use std::time::Duration;

/// PostgreSQL origin capacity and start-spacing authority shared by all tenants.
///
/// Clone this service rather than constructing it per request. Each instance uses
/// at most `PgConfig::max_connections` capacity connections (at least one), plus
/// two metadata connections. Calls beyond that bound wait without a connection.
/// Every worker accessing one application schema must use the same origin limit.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PgOriginAdmission {
    capacity: PgPool,
    metadata: PgPool,
    limit: usize,
    run: Option<(CrawlRunId, usize)>,
}

impl PgOriginAdmission {
    /// Create lazily connected admission pools using `pg`'s worker credentials.
    ///
    /// Zero `limit` means one slot. Pool sizes do not grow with origin count or
    /// queued callers. Dropping an acquisition future rolls back its transaction
    /// and closes its capacity connection, including a blocked advisory-lock wait.
    #[must_use]
    pub fn new(pg: Pg, limit: usize) -> Self {
        let options = pg.pool().connect_options();
        let schema: Option<Arc<str>> = pg.config().schema.as_deref().map(Arc::from);
        let pool = |max_connections, check_disconnect| {
            let schema = schema.clone();
            PgPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(pg.config().acquire_timeout)
                .test_before_acquire(pg.config().test_before_acquire)
                .after_connect(move |conn, _| {
                    let schema = schema.clone();
                    Box::pin(async move {
                        if let Some(schema) = schema {
                            conn.execute(crate::pg::schema_sql("SET search_path TO ", &schema, "")?)
                                .await?;
                        }
                        if check_disconnect {
                            // PostgreSQL 14+ detects a closed client even while
                            // blocked on a lock, rather than waiting for the
                            // predecessor to release before noticing cancellation.
                            conn.execute("SET client_connection_check_interval = '100ms'")
                                .await?;
                        }
                        Ok(())
                    })
                })
                .connect_lazy_with((*options).clone())
        };
        Self {
            capacity: pool(pg.config().max_connections.max(1), true),
            metadata: pool(2, false),
            limit: limit.max(1),
            run: None,
        }
    }

    /// Set the deployment limit while retaining the same bounded pools.
    ///
    /// All workers must agree on this value; an existing origin row with another
    /// limit causes acquisition to fail closed rather than exceed either cap.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.max(1);
        self
    }

    /// Also enforce `limit` concurrent operations for this run and origin.
    ///
    /// Clones retain the deployment pools and global limit. Run slots precede
    /// deployment slots, so a run waiting for capacity cannot consume global slots.
    #[must_use]
    pub fn for_run(mut self, run: CrawlRunId, limit: usize) -> Self {
        self.run = Some((run, limit.max(1)));
        self
    }

    async fn run_ticket(&self, run: CrawlRunId, origin: &str, limit: i64) -> Result<i64, StoreError> {
        let ticket: Option<i64> = sqlx::query_scalar(
            "INSERT INTO origin_leases (run_id, origin, admission_limit, admission_next_ticket) \
             VALUES ($1, $2, $3, 1 % $3) \
             ON CONFLICT (run_id, origin) DO UPDATE \
             SET admission_next_ticket = (origin_leases.admission_next_ticket + 1) % $3, \
                 admission_limit = $3 \
             WHERE origin_leases.admission_limit IS NULL OR origin_leases.admission_limit = $3 \
             RETURNING CASE WHEN admission_next_ticket = 0 THEN admission_limit - 1 \
                            ELSE admission_next_ticket - 1 END",
        )
        .bind(run.0)
        .bind(origin)
        .bind(limit)
        .fetch_optional(&self.metadata)
        .await
        .map_err(db)?;
        ticket
            .ok_or_else(|| StoreError::Conflict("run origin concurrency differs between workers".to_owned()))
    }

    async fn ticket(&self, origin: &str, limit: i64) -> Result<i64, StoreError> {
        // The counter wraps rather than overflowing. Cancellation can skip a slot
        // but cannot leave a ticket that another caller must explicitly release.
        let ticket: Option<i64> = sqlx::query_scalar(
            "INSERT INTO origin_admission (origin, slot_limit, next_ticket) \
             VALUES ($1, $2, 1 % $2) \
             ON CONFLICT (origin) DO UPDATE \
             SET next_ticket = (origin_admission.next_ticket + 1) % $2 \
             WHERE origin_admission.slot_limit = $2 \
             RETURNING CASE WHEN next_ticket = 0 THEN slot_limit - 1 ELSE next_ticket - 1 END",
        )
        .bind(origin)
        .bind(limit)
        .fetch_optional(&self.metadata)
        .await
        .map_err(db)?;
        ticket.ok_or_else(|| {
            StoreError::Conflict("origin admission concurrency differs between workers".to_owned())
        })
    }

    async fn try_start(&self, origin: &str, spacing_us: i64) -> Result<Option<Duration>, StoreError> {
        let mut tx = self.metadata.begin().await.map_err(db)?;
        // Read the clock only after locking the row. Transaction-start time may
        // be stale after a lock wait and cannot authorize a new network start.
        sqlx::query("SELECT origin FROM origin_admission WHERE origin = $1 FOR UPDATE")
            .bind(origin)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let wait_us: i64 = sqlx::query_scalar(
            "SELECT GREATEST(0, CEIL(EXTRACT(EPOCH FROM \
             (GREATEST(cooldown_until, \
               next_allowed_at + GREATEST($2 - last_spacing_us, 0) * INTERVAL '1 microsecond') \
              - clock_timestamp())) * 1000000))::bigint \
             FROM origin_admission WHERE origin = $1",
        )
        .bind(origin)
        .bind(spacing_us)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if wait_us > 0 {
            // No connection/row lock survives this result. The governor can drop
            // its run-global permit before waiting, so other origins stay live.
            tx.rollback().await.map_err(db)?;
            return Ok(Some(Duration::from_micros(conv(wait_us, "origin pacing wait")?)));
        }
        sqlx::query(
            "UPDATE origin_admission SET \
             next_allowed_at = clock_timestamp() + $2 * INTERVAL '1 microsecond', \
             last_spacing_us = $2 WHERE origin = $1",
        )
        .bind(origin)
        .bind(spacing_us)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if let Some((run, _)) = self.run {
            sqlx::query(
                "UPDATE origin_leases SET fencing_token = nextval('lease_fence_seq'), \
                 next_allowed_at = (SELECT next_allowed_at FROM origin_admission WHERE origin = $2), \
                 lease_expires_at = NULL WHERE run_id = $1 AND origin = $2",
            )
            .bind(run.0)
            .bind(origin)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(None)
    }
}

#[async_trait]
impl OriginAdmission for PgOriginAdmission {
    /// Reserve global capacity without advancing the database start clock.
    ///
    /// # Errors
    /// Returns a storage error when PostgreSQL fails, workers disagree on the
    /// origin limit, or a limit cannot fit PostgreSQL's numeric columns.
    async fn reserve(&self, origin: &str) -> Result<Box<dyn OriginPermit>, StoreError> {
        let limit = conv(self.limit, "origin concurrency")?;
        let mut connection = self.capacity.acquire().await.map_err(db)?;
        // SQLx normally returns canceled queries to its pool after cleanup. A
        // blocking advisory wait must instead close, so cancellation cannot leave
        // an orphan lock waiter occupying admission capacity until its predecessor
        // finishes. Transaction::begin consumes this close-on-drop pool guard.
        connection.close_on_drop();
        let mut tx = Transaction::begin(connection, None).await.map_err(db)?;
        let origin_digest = Digest::of("crawlx/origin-admission/origin/v1", origin.as_bytes());
        if let Some((run, run_limit)) = self.run {
            let run_limit = conv(run_limit, "run origin concurrency")?;
            let ticket = self.run_ticket(run, origin, run_limit).await?;
            let run_digest = Digest::keyed(
                &origin_digest.0,
                "crawlx/origin-admission/run/v1",
                run.0.as_bytes(),
            );
            lock_slot(&mut tx, &run_digest, ticket).await?;
        }
        let ticket = self.ticket(origin, limit).await?;
        // PostgreSQL queues conflicting lock waiters; distinct origins/slots do
        // not share a lock. No global origin mutex or TTL-based lease is involved.
        lock_slot(&mut tx, &origin_digest, ticket).await?;
        Ok(Box::new(PgOriginPermit {
            _transaction: tx,
            store: self.clone(),
            origin: origin.to_owned(),
        }))
    }

    async fn cooldown_remaining(&self, origin: &str) -> Result<Duration, StoreError> {
        let value: Option<i64> = sqlx::query_scalar(
            "SELECT CASE WHEN cooldown_until='infinity'::timestamptz THEN -1 ELSE \
             GREATEST(0, CEIL(EXTRACT(EPOCH FROM (cooldown_until-clock_timestamp()))*1000000))::bigint \
             END FROM origin_admission WHERE origin=$1",
        )
        .bind(origin)
        .fetch_optional(&self.metadata)
        .await
        .map_err(db)?;
        match value {
            Some(-1) => Ok(Duration::MAX),
            Some(micros) => Ok(Duration::from_micros(conv(micros, "origin cooldown remaining")?)),
            None => Ok(Duration::ZERO),
        }
    }

    async fn cooldown(
        &self,
        origin: &str,
        minimum: Duration,
        exponential: bool,
    ) -> Result<Duration, StoreError> {
        let minimum_us = i64::try_from(
            minimum
                .as_micros()
                .saturating_add(u128::from(!minimum.subsec_nanos().is_multiple_of(1000))),
        )
        .ok();
        // Ensure the row exists before taking its feedback lock. Ticket allocation
        // is not needed: feedback does not consume capacity or advance start order.
        sqlx::query(
            "INSERT INTO origin_admission (origin, slot_limit) VALUES ($1, $2) \
             ON CONFLICT (origin) DO NOTHING",
        )
        .bind(origin)
        .bind(conv::<_, i64>(self.limit, "origin concurrency")?)
        .execute(&self.metadata)
        .await
        .map_err(db)?;
        let mut tx = self.metadata.begin().await.map_err(db)?;
        sqlx::query("SELECT origin FROM origin_admission WHERE origin = $1 FOR UPDATE")
            .bind(origin)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let Some(minimum_us) = minimum_us else {
            // An unrepresentable positive Retry-After closes this origin for all
            // workers. It must not wrap, panic, or silently become a short wait.
            sqlx::query("UPDATE origin_admission SET cooldown_until='infinity'::timestamptz WHERE origin=$1")
                .bind(origin)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            tx.commit().await.map_err(db)?;
            return Ok(Duration::MAX);
        };
        // Read the operational clock after acquiring the lock. An existing wave
        // extends only for an explicit larger Retry-After; it never doubles twice.
        let remaining_us: i64 = sqlx::query_scalar(
            "WITH observed AS (SELECT clock_timestamp() AS t), proposal AS ( \
               SELECT t, cooldown_until > t AS active, CASE \
                 WHEN cooldown_until > t THEN throttle_delay_us \
                 WHEN $3 AND t >= throttle_decays_at THEN 2000000::bigint \
                 WHEN $3 THEN LEAST(60000000::bigint, GREATEST(2000000::bigint, throttle_delay_us * 2)) \
                 ELSE throttle_delay_us END AS delay_us \
               FROM origin_admission CROSS JOIN observed WHERE origin = $1 \
             ), target AS (SELECT proposal.*, GREATEST(cooldown_until, \
                 proposal.t + GREATEST($2, CASE WHEN proposal.active OR NOT $3 THEN 0 ELSE proposal.delay_us END) \
                   * INTERVAL '1 microsecond') AS deadline \
               FROM proposal CROSS JOIN origin_admission WHERE origin=$1 \
             ), updated AS (UPDATE origin_admission SET \
               throttle_delay_us=target.delay_us, cooldown_until=target.deadline, \
               throttle_decays_at=CASE WHEN $3 AND (NOT target.active OR target.deadline > cooldown_until) \
                 THEN GREATEST(target.deadline,next_allowed_at) \
                   + GREATEST($2,target.delay_us)*INTERVAL '1 microsecond' \
                 ELSE throttle_decays_at END \
               FROM target WHERE origin=$1 RETURNING cooldown_until,target.t) \
             SELECT GREATEST(0,CEIL(EXTRACT(EPOCH FROM (cooldown_until-t))*1000000))::bigint FROM updated",
        )
        .bind(origin).bind(minimum_us).bind(exponential)
        .fetch_one(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Duration::from_micros(conv(
            remaining_us,
            "origin cooldown remaining",
        )?))
    }
}

async fn lock_slot(
    tx: &mut Transaction<'_, Postgres>,
    origin_digest: &Digest,
    ticket: i64,
) -> Result<(), StoreError> {
    let digest = Digest::keyed(
        &origin_digest.0,
        "crawlx/origin-admission/slot/v1",
        &ticket.to_be_bytes(),
    );
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&digest.0[..8]);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(i64::from_be_bytes(bytes))
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}

#[derive(Debug)]
struct PgOriginPermit {
    // SQLx rolls back on drop. The close-on-drop connection also prevents reuse
    // before PostgreSQL has released this transaction's advisory lock.
    _transaction: Transaction<'static, Postgres>,
    store: PgOriginAdmission,
    origin: String,
}

#[async_trait]
impl OriginPermit for PgOriginPermit {
    async fn try_start(&mut self, spacing: Duration) -> Result<Option<Duration>, StoreError> {
        // Round up: sub-microsecond requests must not silently weaken spacing.
        let micros = spacing
            .as_micros()
            .saturating_add(u128::from(!spacing.subsec_nanos().is_multiple_of(1000)));
        self.store
            .try_start(&self.origin, conv(micros, "origin spacing")?)
            .await
    }

    async fn start(&mut self, spacing: Duration) -> Result<(), StoreError> {
        while let Some(wait) = self.try_start(spacing).await? {
            tokio::time::sleep(wait).await;
        }
        Ok(())
    }
}
