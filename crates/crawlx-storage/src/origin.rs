//! Deployment-global origin admission, independent of tenant-scoped repositories.
//!
//! Capacity permits hold PostgreSQL transactions until drop. A separate bounded
//! pool carries lock waiters and held permits; a second two-connection pool handles
//! short ticket/pacing transactions. Neither can exhaust the normal storage pool.
//! MariaDB does the same with row-lock slots ([`MariaOriginAdmission`]); SQLite holds
//! capacity in process and persists pacing and cooldown ([`SqliteOriginAdmission`]).

use crate::backend::dialect::SQLITE_POS_INFINITY_MICROS;
use crate::backend::strategy::{Conn, FenceSeq};
use crate::backend::{Concurrency as _, Database, MariaBackend, SqliteBackend, WriteTx};
use crate::codec::{conv, ts_from_micros};
use crate::custody::{database_now, frag};
use crate::error::db;
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use crate::Pg;
use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::origin::{is_physical_address_key, OriginAdmission, OriginPermit};
use crawlx_core::{CrawlRunId, StoreError};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Postgres, Transaction};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// PostgreSQL origin capacity and start-spacing authority shared by all tenants.
///
/// Clone this service rather than constructing it per request. Each instance uses
/// at most `StoreConfig::max_connections` capacity connections (at least one), plus
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
                            conn.execute(crate::store::schema_sql("SET search_path TO ", &schema, "")?)
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
        // A physical address is deployment capacity only: no run row, run slot or run limit.
        if let Some((run, run_limit)) = self.run.filter(|_| !is_physical_address_key(origin)) {
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

// ---------------------------------------------------------------------------------------
// MariaDB and SQLite
// ---------------------------------------------------------------------------------------

/// Slot rows wait this long (seconds, `innodb_lock_wait_timeout`) before the waiter looks at
/// itself again. MariaDB cannot see a client that vanished while blocked on a row lock, so a
/// cancelled acquisition may leave a waiter in the lock queue for up to one slice; it never
/// holds the slot beyond the moment it is granted, because its closed connection rolls back.
const SLOT_WAIT_SLICE_SECS: u32 = 2;

/// The earliest start an origin allows, as microseconds since the epoch.
fn ready_micros(cooldown_until: i64, next_allowed_at: i64, last_spacing_us: i64, spacing_us: i64) -> i64 {
    let spaced = next_allowed_at.saturating_add(spacing_us.saturating_sub(last_spacing_us).max(0));
    cooldown_until.max(spaced)
}

fn micros_to_duration(micros: i64) -> Result<Duration, StoreError> {
    Ok(Duration::from_micros(conv(micros.max(0), "origin pacing wait")?))
}

/// Draw the next slot number of `origin` (`0..limit`) and register `limit` as the
/// deployment-wide concurrency. Workers must agree on the limit: a row created with another
/// one fails closed.
async fn global_ticket<B: Sql>(conn: &mut Conn<B>, origin: &str, limit: i64) -> Result<i64, StoreError> {
    stmt!(
        B,
        format!(
            "INSERT INTO origin_admission (origin, slot_limit, next_ticket) VALUES ($1, $2, 0) {}",
            frag::on_conflict_nothing::<B>(&["origin"])
        )
    )
    .text(origin)
    .i64(limit)
    .execute(conn)
    .await?;
    let row = stmt!(
        B,
        format!(
            "SELECT slot_limit, next_ticket FROM origin_admission WHERE origin = $1{}",
            frag::update::<B>()
        )
    )
    .text(origin)
    .fetch_one(conn)
    .await?;
    if row.i64("slot_limit")? != limit {
        return Err(StoreError::Conflict(
            "origin admission concurrency differs between workers".to_owned(),
        ));
    }
    let ticket = row.i64("next_ticket")?;
    stmt!(
        B,
        "UPDATE origin_admission SET next_ticket = (next_ticket + 1) % $2 WHERE origin = $1"
    )
    .text(origin)
    .i64(limit)
    .execute(conn)
    .await?;
    Ok(ticket)
}

/// The run-scoped counterpart of [`global_ticket`], over `origin_leases`.
async fn run_ticket<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    origin: &str,
    limit: i64,
) -> Result<i64, StoreError> {
    stmt!(
        B,
        format!(
            "INSERT INTO origin_leases (run_id, origin, admission_limit, admission_next_ticket) VALUES ($1, $2, $3, 0) {}",
            frag::on_conflict_nothing::<B>(&["run_id", "origin"])
        )
    )
    .uuid(run.0)
    .text(origin)
    .i64(limit)
    .execute(conn)
    .await?;
    let row = stmt!(
        B,
        format!(
            "SELECT admission_limit, admission_next_ticket FROM origin_leases WHERE run_id = $1 AND origin = $2{}",
            frag::update::<B>()
        )
    )
    .uuid(run.0)
    .text(origin)
    .fetch_one(conn)
    .await?;
    if row
        .opt_i64("admission_limit")?
        .is_some_and(|stored| stored != limit)
    {
        return Err(StoreError::Conflict(
            "run origin concurrency differs between workers".to_owned(),
        ));
    }
    let ticket = row.i64("admission_next_ticket")?;
    stmt!(
        B,
        "UPDATE origin_leases SET admission_next_ticket = (admission_next_ticket + 1) % $3, admission_limit = $3 WHERE run_id = $1 AND origin = $2"
    )
    .uuid(run.0)
    .text(origin)
    .i64(limit)
    .execute(conn)
    .await?;
    Ok(ticket)
}

/// Admit a start, or return the remaining wait. The origin row is locked first and the
/// clock read afterwards, so a lock wait can never authorize a start on stale time. Nothing
/// is written when the caller must wait.
async fn try_start_on<B: Sql>(
    mut tx: WriteTx<B::Db>,
    origin: &str,
    spacing_us: i64,
    run: Option<CrawlRunId>,
) -> Result<Option<Duration>, StoreError> {
    let row = stmt!(
        B,
        format!(
            "SELECT next_allowed_at, cooldown_until, last_spacing_us FROM origin_admission WHERE origin = $1{}",
            frag::update::<B>()
        )
    )
    .text(origin)
    .fetch_one(tx.conn())
    .await?;
    let now = database_now::<B>(tx.conn()).await?.timestamp_micros();
    let ready = ready_micros(
        row.ts("cooldown_until")?.timestamp_micros(),
        row.ts("next_allowed_at")?.timestamp_micros(),
        row.i64("last_spacing_us")?,
        spacing_us,
    );
    let wait = ready.saturating_sub(now);
    if wait > 0 {
        // No lock survives this result: the governor can drop its run-global permit before
        // waiting, so other origins stay live.
        tx.rollback().await?;
        return Ok(Some(micros_to_duration(wait)?));
    }
    stmt!(
        B,
        "UPDATE origin_admission SET next_allowed_at = $2, last_spacing_us = $3 WHERE origin = $1"
    )
    .text(origin)
    .ts(ts_from_micros(now.saturating_add(spacing_us))?)
    .i64(spacing_us)
    .execute(tx.conn())
    .await?;
    if let Some(run) = run {
        let fence = B::next_fence(tx.conn(), FenceSeq::Lease).await?;
        stmt!(
            B,
            "UPDATE origin_leases SET fencing_token = $3, \
             next_allowed_at = (SELECT next_allowed_at FROM origin_admission WHERE origin = $2), \
             lease_expires_at = NULL WHERE run_id = $1 AND origin = $2"
        )
        .uuid(run.0)
        .text(origin)
        .i64(fence)
        .execute(tx.conn())
        .await?;
    }
    tx.commit().await?;
    Ok(None)
}

/// Remaining shared cooldown of `origin`: `Duration::MAX` for an indefinite one.
async fn cooldown_remaining_on<B: Sql>(conn: &mut Conn<B>, origin: &str) -> Result<Duration, StoreError> {
    let row = stmt!(
        B,
        format!(
            "SELECT cooldown_until, {} AS t FROM origin_admission WHERE origin = $1",
            frag::clock::<B>()
        )
    )
    .text(origin)
    .fetch_optional(conn)
    .await?;
    let Some(row) = row else {
        return Ok(Duration::ZERO);
    };
    let until = row.ts("cooldown_until")?.timestamp_micros();
    if until >= SQLITE_POS_INFINITY_MICROS {
        return Ok(Duration::MAX);
    }
    micros_to_duration(until.saturating_sub(row.ts("t")?.timestamp_micros()))
}

/// Publish an origin-wide cooldown (see [`OriginAdmission::cooldown`]). The row is locked
/// before the clock is read; an existing wave extends only for an explicit larger
/// `minimum`, and never doubles twice.
async fn cooldown_on<B: Sql>(
    mut tx: WriteTx<B::Db>,
    origin: &str,
    limit: i64,
    minimum_us: Option<i64>,
    exponential: bool,
) -> Result<Duration, StoreError> {
    // Ensure the row exists before taking its feedback lock. Ticket allocation is not
    // needed: feedback does not consume capacity or advance start order.
    stmt!(
        B,
        format!(
            "INSERT INTO origin_admission (origin, slot_limit) VALUES ($1, $2) {}",
            frag::on_conflict_nothing::<B>(&["origin"])
        )
    )
    .text(origin)
    .i64(limit)
    .execute(tx.conn())
    .await?;
    let row = stmt!(
        B,
        format!(
            "SELECT cooldown_until, throttle_delay_us, throttle_decays_at, next_allowed_at, {} AS t FROM origin_admission WHERE origin = $1{}",
            frag::clock::<B>(),
            frag::update::<B>()
        )
    )
    .text(origin)
    .fetch_one(tx.conn())
    .await?;
    let Some(minimum_us) = minimum_us else {
        // An unrepresentable positive Retry-After closes this origin for all workers. It
        // must not wrap, panic, or silently become a short wait.
        stmt!(
            B,
            "UPDATE origin_admission SET cooldown_until = $2 WHERE origin = $1"
        )
        .text(origin)
        .ts(ts_from_micros(SQLITE_POS_INFINITY_MICROS)?)
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
        return Ok(Duration::MAX);
    };
    let t = row.ts("t")?.timestamp_micros();
    let cooldown_until = row.ts("cooldown_until")?.timestamp_micros();
    let delay = row.i64("throttle_delay_us")?;
    let decays_at = row.ts("throttle_decays_at")?.timestamp_micros();
    let next_allowed = row.ts("next_allowed_at")?.timestamp_micros();
    let active = cooldown_until > t;
    let delay_us = if active {
        delay
    } else if exponential && t >= decays_at {
        2_000_000
    } else if exponential {
        60_000_000_i64.min(2_000_000_i64.max(delay.saturating_mul(2)))
    } else {
        delay
    };
    let step = minimum_us.max(if active || !exponential { 0 } else { delay_us });
    let deadline = cooldown_until.max(t.saturating_add(step));
    let decays = if exponential && (!active || deadline > cooldown_until) {
        deadline
            .max(next_allowed)
            .saturating_add(minimum_us.max(delay_us))
    } else {
        decays_at
    };
    stmt!(
        B,
        "UPDATE origin_admission SET throttle_delay_us = $2, cooldown_until = $3, throttle_decays_at = $4 WHERE origin = $1"
    )
    .text(origin)
    .i64(delay_us)
    .ts(ts_from_micros(deadline)?)
    .ts(ts_from_micros(decays)?)
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    micros_to_duration(deadline.saturating_sub(t))
}

/// Spacing rounded up to whole microseconds: a sub-microsecond request must not silently
/// weaken pacing.
fn spacing_micros(spacing: Duration) -> Result<i64, StoreError> {
    let micros = spacing
        .as_micros()
        .saturating_add(u128::from(!spacing.subsec_nanos().is_multiple_of(1000)));
    conv(micros, "origin spacing")
}

fn minimum_micros(minimum: Duration) -> Option<i64> {
    i64::try_from(
        minimum
            .as_micros()
            .saturating_add(u128::from(!minimum.subsec_nanos().is_multiple_of(1000))),
    )
    .ok()
}

/// Whether `error` is MariaDB's lock wait timeout (server error 1205): the statement, not
/// the transaction, was rolled back.
fn is_lock_wait_timeout(error: &StoreError) -> bool {
    let StoreError::Database { source, .. } = error else {
        return false;
    };
    let Some(sqlx::Error::Database(database)) = source.downcast_ref::<sqlx::Error>() else {
        return false;
    };
    database
        .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
        .is_some_and(|mysql| mysql.number() == 1205)
}

/// MariaDB origin capacity and start-spacing authority shared by all tenants and workers.
///
/// A permit is an open transaction that holds the row lock of one slot of `crawlx_locks`
/// until it is dropped; closing its dedicated connection rolls the transaction back, so no
/// expiring lease can free a slot while an operation still runs. Slot numbers come from a
/// per-origin ticket counter, so waiters of one origin queue on one row each and distinct
/// origins never share a lock. A bounded dedicated pool carries lock waiters and held
/// permits; a second two-connection pool handles the short ticket and pacing transactions,
/// so neither can exhaust the normal storage pool. Waits are sliced
/// ([`SLOT_WAIT_SLICE_SECS`]): MariaDB cannot notice a vanished client while it is blocked.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MariaOriginAdmission {
    capacity: sqlx::MySqlPool,
    metadata: sqlx::MySqlPool,
    limit: usize,
    run: Option<(CrawlRunId, usize)>,
}

impl MariaOriginAdmission {
    /// Create lazily connected admission pools using `store`'s worker credentials.
    ///
    /// Zero `limit` means one slot. Pool sizes do not grow with origin count or queued
    /// callers. Dropping an acquisition future closes its capacity connection.
    #[must_use]
    pub fn new(store: &Store<MariaBackend>, limit: usize) -> Self {
        let options = store.pool.connect_options();
        let pool = |max_connections: u32, wait: Option<u32>| {
            sqlx::mysql::MySqlPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(store.config().acquire_timeout)
                .test_before_acquire(store.config().test_before_acquire)
                .after_connect(move |conn, _| {
                    Box::pin(async move {
                        conn.execute("SET SESSION transaction_isolation = 'READ-COMMITTED'")
                            .await?;
                        if let Some(seconds) = wait {
                            conn.execute(sqlx::AssertSqlSafe(format!(
                                "SET SESSION innodb_lock_wait_timeout = {seconds}"
                            )))
                            .await?;
                        }
                        Ok(())
                    })
                })
                .connect_lazy_with((*options).clone())
        };
        Self {
            capacity: pool(store.config().max_connections.max(1), Some(SLOT_WAIT_SLICE_SECS)),
            metadata: pool(2, None),
            limit: limit.max(1),
            run: None,
        }
    }

    /// Set the deployment limit while retaining the same bounded pools. All workers must
    /// agree on this value; an existing origin row with another limit fails closed.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.max(1);
        self
    }

    /// Also enforce `limit` concurrent operations for this run and origin. Run slots precede
    /// deployment slots, so a run waiting for capacity cannot consume global slots.
    #[must_use]
    pub fn for_run(mut self, run: CrawlRunId, limit: usize) -> Self {
        self.run = Some((run, limit.max(1)));
        self
    }

    async fn metadata_tx(&self) -> Result<WriteTx<sqlx::MySql>, StoreError> {
        Ok(WriteTx::new(self.metadata.begin().await.map_err(db)?, None))
    }

    /// Take the row lock of the slot named by `digest` and `ticket` inside `tx`, waiting in
    /// slices until it is granted.
    async fn lock_slot(
        &self,
        tx: &mut Transaction<'static, sqlx::MySql>,
        digest: &Digest,
        ticket: i64,
    ) -> Result<(), StoreError> {
        let slot = Digest::keyed(
            &digest.0,
            "crawlx/origin-admission/slot/v1",
            &ticket.to_be_bytes(),
        );
        {
            // The row must exist for the lock to queue on it. It is created on the metadata
            // pool so the capacity connection holds nothing while it does.
            let mut conn = self.metadata.acquire().await.map_err(db)?;
            stmt!(
                MariaBackend,
                "INSERT INTO crawlx_locks (name) VALUES ($1) ON DUPLICATE KEY UPDATE name = name"
            )
            .bytes(slot.0.as_slice())
            .execute(&mut *conn)
            .await?;
        }
        loop {
            match stmt!(
                MariaBackend,
                "SELECT 1 AS v FROM crawlx_locks WHERE name = $1 FOR UPDATE"
            )
            .bytes(slot.0.as_slice())
            .fetch_optional(&mut **tx)
            .await
            {
                Ok(_) => return Ok(()),
                // A slice elapsed without the lock: wait again (the statement alone rolled back).
                Err(error) if is_lock_wait_timeout(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[async_trait]
impl OriginAdmission for MariaOriginAdmission {
    /// Reserve global capacity without advancing the database start clock.
    ///
    /// # Errors
    /// Returns a storage error when MariaDB fails, workers disagree on the origin limit, or
    /// a limit cannot fit the integer columns.
    async fn reserve(&self, origin: &str) -> Result<Box<dyn OriginPermit>, StoreError> {
        let limit: i64 = conv(self.limit, "origin concurrency")?;
        let mut connection = self.capacity.acquire().await.map_err(db)?;
        // A cancelled lock wait must close the connection instead of returning it to the
        // pool with a statement in flight.
        connection.close_on_drop();
        let mut tx = Transaction::begin(connection, None).await.map_err(db)?;
        let origin_digest = Digest::of("crawlx/origin-admission/origin/v1", origin.as_bytes());
        // A physical address is deployment capacity only: no run row, run slot or run limit.
        if let Some((run, run_limit)) = self.run.filter(|_| !is_physical_address_key(origin)) {
            let run_limit: i64 = conv(run_limit, "run origin concurrency")?;
            let mut meta = self.metadata_tx().await?;
            let ticket = run_ticket::<MariaBackend>(meta.conn(), run, origin, run_limit).await?;
            meta.commit().await?;
            let run_digest = Digest::keyed(
                &origin_digest.0,
                "crawlx/origin-admission/run/v1",
                run.0.as_bytes(),
            );
            self.lock_slot(&mut tx, &run_digest, ticket).await?;
        }
        let mut meta = self.metadata_tx().await?;
        let ticket = global_ticket::<MariaBackend>(meta.conn(), origin, limit).await?;
        meta.commit().await?;
        self.lock_slot(&mut tx, &origin_digest, ticket).await?;
        Ok(Box::new(MariaOriginPermit {
            _transaction: tx,
            admission: self.clone(),
            origin: origin.to_owned(),
        }))
    }

    async fn cooldown_remaining(&self, origin: &str) -> Result<Duration, StoreError> {
        let mut conn = self.metadata.acquire().await.map_err(db)?;
        cooldown_remaining_on::<MariaBackend>(&mut *conn, origin).await
    }

    async fn cooldown(
        &self,
        origin: &str,
        minimum: Duration,
        exponential: bool,
    ) -> Result<Duration, StoreError> {
        let tx = self.metadata_tx().await?;
        cooldown_on::<MariaBackend>(
            tx,
            origin,
            conv(self.limit, "origin concurrency")?,
            minimum_micros(minimum),
            exponential,
        )
        .await
    }
}

#[derive(Debug)]
struct MariaOriginPermit {
    // Closing the connection (it is close-on-drop) rolls the transaction back and releases
    // the slot rows.
    _transaction: Transaction<'static, sqlx::MySql>,
    admission: MariaOriginAdmission,
    origin: String,
}

#[async_trait]
impl OriginPermit for MariaOriginPermit {
    async fn try_start(&mut self, spacing: Duration) -> Result<Option<Duration>, StoreError> {
        let tx = self.admission.metadata_tx().await?;
        try_start_on::<MariaBackend>(
            tx,
            &self.origin,
            spacing_micros(spacing)?,
            self.admission.run.map(|(run, _)| run),
        )
        .await
    }

    async fn start(&mut self, spacing: Duration) -> Result<(), StoreError> {
        while let Some(wait) = self.try_start(spacing).await? {
            tokio::time::sleep(wait).await;
        }
        Ok(())
    }
}

/// In-process slot semaphores shared by every [`SqliteOriginAdmission`] of this process,
/// keyed by database file, run and origin. SQLite runs one worker process per database
/// file, so process-local capacity is the deployment-wide capacity.
static LOCAL_SLOTS: parking_lot::Mutex<BTreeMap<String, (usize, Arc<Semaphore>)>> =
    parking_lot::Mutex::new(BTreeMap::new());

/// The semaphore of `key` with `limit` slots; a different limit fails closed.
fn local_slots(key: String, limit: usize) -> Result<Arc<Semaphore>, StoreError> {
    let mut slots = LOCAL_SLOTS.lock();
    let (stored, semaphore) = slots
        .entry(key)
        .or_insert_with(|| (limit, Arc::new(Semaphore::new(limit))));
    if *stored != limit {
        return Err(StoreError::Conflict(
            "origin admission concurrency differs between workers".to_owned(),
        ));
    }
    Ok(Arc::clone(semaphore))
}

/// SQLite origin admission. Capacity is in-process (one worker process per database file
/// is enforced at open); start spacing and cooldown live in the same tables as on the other
/// engines, so the API process and the worker agree on them.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SqliteOriginAdmission {
    store: Store<SqliteBackend>,
    scope: String,
    limit: usize,
    run: Option<(CrawlRunId, usize)>,
}

impl SqliteOriginAdmission {
    /// Admission over `store`'s database file. Zero `limit` means one slot.
    #[must_use]
    pub fn new(store: &Store<SqliteBackend>, limit: usize) -> Self {
        let scope = store
            .pool
            .path()
            .map_or_else(|| "memory".to_owned(), |path| path.display().to_string());
        Self {
            store: store.clone(),
            scope,
            limit: limit.max(1),
            run: None,
        }
    }

    /// Set the limit. All users of one database file must agree on it.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit.max(1);
        self
    }

    /// Also enforce `limit` concurrent operations for this run and origin; run slots precede
    /// deployment slots.
    #[must_use]
    pub fn for_run(mut self, run: CrawlRunId, limit: usize) -> Self {
        self.run = Some((run, limit.max(1)));
        self
    }
}

#[async_trait]
impl OriginAdmission for SqliteOriginAdmission {
    async fn reserve(&self, origin: &str) -> Result<Box<dyn OriginPermit>, StoreError> {
        let limit: i64 = conv(self.limit, "origin concurrency")?;
        let mut held = Vec::new();
        // A physical address is deployment capacity only: no run row, run slot or run limit.
        if let Some((run, run_limit)) = self.run.filter(|_| !is_physical_address_key(origin)) {
            let mut tx = self.store.begin_write().await?;
            run_ticket::<SqliteBackend>(tx.conn(), run, origin, conv(run_limit, "run origin concurrency")?)
                .await?;
            tx.commit().await?;
            let slots = local_slots(
                format!("{}\u{0}run\u{0}{}\u{0}{origin}", self.scope, run.0),
                run_limit,
            )?;
            held.push(slots.acquire_owned().await.map_err(closed)?);
        }
        let mut tx = self.store.begin_write().await?;
        global_ticket::<SqliteBackend>(tx.conn(), origin, limit).await?;
        tx.commit().await?;
        let slots = local_slots(format!("{}\u{0}origin\u{0}{origin}", self.scope), self.limit)?;
        held.push(slots.acquire_owned().await.map_err(closed)?);
        Ok(Box::new(SqliteOriginPermit {
            _held: held,
            admission: self.clone(),
            origin: origin.to_owned(),
        }))
    }

    async fn cooldown_remaining(&self, origin: &str) -> Result<Duration, StoreError> {
        let mut tx = SqliteBackend::begin_read(&self.store.pool).await?;
        cooldown_remaining_on::<SqliteBackend>(&mut *tx, origin).await
    }

    async fn cooldown(
        &self,
        origin: &str,
        minimum: Duration,
        exponential: bool,
    ) -> Result<Duration, StoreError> {
        let tx = self.store.begin_write().await?;
        cooldown_on::<SqliteBackend>(
            tx,
            origin,
            conv(self.limit, "origin concurrency")?,
            minimum_micros(minimum),
            exponential,
        )
        .await
    }
}

fn closed(_: tokio::sync::AcquireError) -> StoreError {
    StoreError::Unavailable("origin admission slots are closed".to_owned())
}

#[derive(Debug)]
struct SqliteOriginPermit {
    _held: Vec<OwnedSemaphorePermit>,
    admission: SqliteOriginAdmission,
    origin: String,
}

#[async_trait]
impl OriginPermit for SqliteOriginPermit {
    async fn try_start(&mut self, spacing: Duration) -> Result<Option<Duration>, StoreError> {
        let tx = self.admission.store.begin_write().await?;
        try_start_on::<SqliteBackend>(
            tx,
            &self.origin,
            spacing_micros(spacing)?,
            self.admission.run.map(|(run, _)| run),
        )
        .await
    }

    async fn start(&mut self, spacing: Duration) -> Result<(), StoreError> {
        while let Some(wait) = self.try_start(spacing).await? {
            tokio::time::sleep(wait).await;
        }
        Ok(())
    }
}

/// The deployment's origin admission for `database`: PostgreSQL advisory-lock slots, MariaDB
/// row-lock slots, SQLite in-process slots with persisted pacing.
#[must_use]
pub(crate) fn origin_admission(database: &Database, limit: usize) -> Option<Arc<dyn OriginAdmission>> {
    if let Some(pg) = database.as_postgres() {
        return Some(Arc::new(PgOriginAdmission::new(pg.clone(), limit)));
    }
    if let Some(store) = database.mariadb_store() {
        return Some(Arc::new(MariaOriginAdmission::new(store, limit)));
    }
    database
        .sqlite_store()
        .map(|store| Arc::new(SqliteOriginAdmission::new(store, limit)) as Arc<dyn OriginAdmission>)
}
