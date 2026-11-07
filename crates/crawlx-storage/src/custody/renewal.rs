//! Read-only recovery receipts for previously applied lifetime extensions.
//!
//! New extensions are unavailable: Redis cannot atomically observe PostgreSQL
//! cancellation or producer fencing when a queued command executes. No request
//! in this module extends volatile retention. Existing exact receipts may recover
//! durable state; a missing Redis key is never rebuilt.

use super::{
    database_now, denied, live, AuthorityRow, PgSecretAuthority, EXPIRY_MARGIN_MS, MAX_AUTHORITY_TTL,
    MAX_CLOCK_SKEW_MS, MAX_EPOCH,
};
use crate::codec::get;
use crate::error::db;
use crawlx_core::custody::{CustodyLease, RunSecretSnapshot, SecretEpoch};
use crawlx_core::{StoreError, Timestamp};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

struct Renewal {
    previous: Timestamp,
    deadline: Timestamp,
    completed: bool,
}

async fn authority(
    tx: &mut Transaction<'_, Postgres>,
    lease: &CustodyLease,
) -> Result<(AuthorityRow, Option<Uuid>, Option<Timestamp>), StoreError> {
    live(tx, lease).await?;
    // Read the original deadline, not the effective pending retention deadline.
    let row = sqlx::query("SELECT * FROM run_secret_authority WHERE tenant_id=$1 AND run_id=$2 AND sealed_at IS NULL FOR UPDATE")
        .bind(lease.tenant.0).bind(lease.run.0).fetch_optional(&mut **tx).await.map_err(db)?
        .ok_or_else(|| denied("secret renewal authority missing or sealed"))?;
    if get::<Option<Uuid>>(&row, "pending_operation")?.is_some() {
        return Err(denied("secret renewal blocked by pending registration"));
    }
    Ok((
        AuthorityRow::parse(lease.tenant, lease.run, &row)?,
        get(&row, "pending_renewal_operation")?,
        get(&row, "pending_renewal_deadline")?,
    ))
}

async fn request(
    tx: &mut Transaction<'_, Postgres>,
    lease: &CustodyLease,
    expected: SecretEpoch,
    operation: Uuid,
    deadline: Timestamp,
) -> Result<Option<Renewal>, StoreError> {
    let row = sqlx::query("SELECT incarnation,secret_epoch,previous_deadline,deadline,completed_at FROM run_secret_authority_renewals WHERE tenant_id=$1 AND run_id=$2 AND operation=$3")
        .bind(lease.tenant.0).bind(lease.run.0).bind(operation)
        .fetch_optional(&mut **tx).await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    if get::<Uuid>(&row, "incarnation")? != expected.incarnation
        || get::<i64>(&row, "secret_epoch")? != expected.epoch
        || get::<Timestamp>(&row, "deadline")? != deadline
    {
        return Err(denied("secret renewal retry changed operation request"));
    }
    Ok(Some(Renewal {
        previous: get(&row, "previous_deadline")?,
        deadline,
        completed: get::<Option<Timestamp>>(&row, "completed_at")?.is_some(),
    }))
}

async fn authorized_deadline(
    tx: &mut Transaction<'_, Postgres>,
    lease: &CustodyLease,
    deadline: Timestamp,
) -> Result<(), StoreError> {
    // live() already holds the run and authorization rows against revocation,
    // cancellation and purge. The ceiling applies to retention, not lease TTL:
    // the caller must have a live producer fence on every renewal attempt.
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM crawl_runs r WHERE r.tenant_id=$1 AND r.run_id=$2 \
         AND (r.expires_at IS NULL OR r.expires_at>=$3) \
         AND (r.deadline_at IS NULL OR r.deadline_at>=$3) \
         AND NOT EXISTS(SELECT 1 FROM authorization_records a \
             WHERE a.record_id=r.authorization_record_id AND (a.revoked_at IS NOT NULL OR a.valid_to<$3)))",
    )
    .bind(lease.tenant.0)
    .bind(lease.run.0)
    .bind(deadline)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !valid {
        return Err(denied("secret renewal exceeds run or authorization deadline"));
    }
    Ok(())
}

impl PgSecretAuthority {
    /// Recover an exact, previously applied absolute-deadline renewal receipt.
    ///
    /// New or unapplied renewal requests fail closed. PostgreSQL and Redis cannot
    /// atomically revoke a queued lifetime extension after producer loss or run
    /// cancellation. Long-running renewal remains an explicit integration gap;
    /// callers must not interpret this API as production renewal support.
    ///
    /// Persist operation/deadline and retry both unchanged after an unknown
    /// historical outcome. Completed requests return the current committed
    /// snapshot, which may have a later registration epoch than `expected`.
    /// Recovery never extends Redis expiry or recreates missing state.
    ///
    /// PostgreSQL and Redis clocks must remain within one second without backward
    /// steps. Samples reject observed violations; deployment must prevent steps
    /// between samples. Redis expires two seconds before the durable deadline.
    ///
    /// # Errors
    /// Rejects new/unapplied requests, expired fences, cancellation, purge, revoked
    /// authorization, changed requests, corrupt state and unproven outcomes.
    pub async fn renew_authority(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        operation: Uuid,
        deadline: Timestamp,
    ) -> Result<RunSecretSnapshot, StoreError> {
        if operation.is_nil() || !deadline.timestamp_subsec_nanos().is_multiple_of(1_000_000) {
            return Err(denied(
                "secret renewal requires operation and millisecond deadline",
            ));
        }
        let mut tx = self.transaction().await?;
        let (row, pending, pending_deadline) = authority(&mut tx, lease).await?;
        if expected.tenant != lease.tenant
            || expected.run != lease.run
            || expected.incarnation != row.incarnation
            || !(1..=MAX_EPOCH).contains(&row.epoch)
        {
            return Err(denied("secret renewal scope or incarnation changed"));
        }
        authorized_deadline(&mut tx, lease, deadline).await?;
        let now = self.renewal_clock(&mut tx).await?;
        let remaining = deadline.signed_duration_since(now);
        let window = i64::try_from(MAX_AUTHORITY_TTL.as_millis())
            .map_err(|_| denied("secret renewal duration overflow"))?;
        if remaining <= chrono::Duration::milliseconds(EXPIRY_MARGIN_MS)
            || remaining > chrono::Duration::milliseconds(window)
        {
            return Err(denied(
                "secret renewal absolute deadline exceeds bounded live window",
            ));
        }
        if let Some(request) = request(&mut tx, lease, expected, operation, deadline).await? {
            if request.completed {
                if pending.is_some() || row.expires_at < deadline || row.expires_at <= now {
                    return Err(denied("secret renewal completed state changed or expired"));
                }
                let snapshot = self
                    .invoke(&row, "snapshot", row.epoch, Uuid::nil(), "", 0)
                    .await?;
                snapshot.check(row.commitment.as_deref())?;
                live(&mut tx, lease).await?;
                tx.commit().await.map_err(db)?;
                return Ok(snapshot.snapshot);
            }
            if expected.epoch != row.epoch
                || pending != Some(operation)
                || pending_deadline != Some(deadline)
                || row.expires_at != request.previous
            {
                return Err(denied("secret renewal pending request changed"));
            }
        } else {
            // Never queue a Redis retention mutation whose authorization could
            // become stale before execution on the independent backend.
            return Err(denied(
                "secret renewal unavailable without atomic cross-backend revocation",
            ));
        }
        tx.commit().await.map_err(db)?;
        self.complete_renewal(lease, expected, operation, deadline).await
    }

    async fn complete_renewal(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        operation: Uuid,
        deadline: Timestamp,
    ) -> Result<RunSecretSnapshot, StoreError> {
        let mut tx = self.transaction().await?;
        let (row, pending, pending_deadline) = authority(&mut tx, lease).await?;
        let request = request(&mut tx, lease, expected, operation, deadline)
            .await?
            .ok_or_else(|| denied("secret renewal durable request missing"))?;
        authorized_deadline(&mut tx, lease, deadline).await?;
        let now = self.renewal_clock(&mut tx).await?;
        if expected.tenant != lease.tenant
            || expected.run != lease.run
            || expected.incarnation != row.incarnation
            || !(1..=MAX_EPOCH).contains(&row.epoch)
            || deadline <= now
        {
            return Err(denied("secret renewal scope, epoch changed or deadline expired"));
        }
        if request.completed {
            if pending.is_some() || row.expires_at < deadline || row.expires_at <= now {
                return Err(denied("secret renewal completed state changed or expired"));
            }
            let snapshot = self
                .invoke(&row, "snapshot", row.epoch, Uuid::nil(), "", 0)
                .await?;
            snapshot.check(row.commitment.as_deref())?;
            live(&mut tx, lease).await?;
            tx.commit().await.map_err(db)?;
            return Ok(snapshot.snapshot);
        }
        if expected.epoch != row.epoch
            || pending != Some(operation)
            || pending_deadline != Some(deadline)
            || row.expires_at != request.previous
        {
            return Err(denied("secret renewal durable barrier changed"));
        }
        let previous = request
            .previous
            .timestamp_millis()
            .checked_sub(EXPIRY_MARGIN_MS)
            .ok_or_else(|| denied("secret renewal expiry overflow"))?
            .to_string();
        let target = request
            .deadline
            .timestamp_millis()
            .checked_sub(EXPIRY_MARGIN_MS)
            .ok_or_else(|| denied("secret renewal expiry overflow"))?;
        // Proof-only on every attempt, including before the previous deadline.
        // An unapplied queued command must never gain retention authority here.
        let snapshot = self
            .invoke(&row, "renew_recover", row.epoch, operation, &previous, target)
            .await?;
        snapshot.check(row.commitment.as_deref())?;
        live(&mut tx, lease).await?;
        authorized_deadline(&mut tx, lease, deadline).await?;
        if deadline <= self.renewal_clock(&mut tx).await? {
            return Err(denied("secret renewal expired before durable completion"));
        }
        sqlx::query("UPDATE run_secret_authority SET expires_at=$3,pending_renewal_operation=NULL,pending_renewal_deadline=NULL WHERE tenant_id=$1 AND run_id=$2")
            .bind(lease.tenant.0).bind(lease.run.0).bind(deadline)
            .execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE run_secret_authority_renewals SET completed_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2 AND operation=$3")
            .bind(lease.tenant.0).bind(lease.run.0).bind(operation)
            .execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(snapshot.snapshot)
    }

    // Never acquire the pool while holding its transaction: single-connection
    // deployments must have the same clock checks, not a nested-acquire deadlock.
    async fn renewal_clock(&self, tx: &mut Transaction<'_, Postgres>) -> Result<Timestamp, StoreError> {
        let before = database_now(tx).await?;
        let mut connection = self.connection()?;
        let (seconds, micros): (i64, i64) = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .map_err(|_| denied("secret renewal Redis clock unavailable"))?;
        let after = database_now(tx).await?;
        let redis_ms = seconds
            .checked_mul(1000)
            .and_then(|value| value.checked_add(micros / 1000))
            .ok_or_else(|| denied("secret renewal Redis clock overflow"))?;
        let low = after
            .timestamp_millis()
            .checked_sub(MAX_CLOCK_SKEW_MS)
            .ok_or_else(|| denied("secret renewal clock overflow"))?;
        let high = before
            .timestamp_millis()
            .checked_add(MAX_CLOCK_SKEW_MS)
            .ok_or_else(|| denied("secret renewal clock overflow"))?;
        if after < before || redis_ms < low || redis_ms > high {
            return Err(denied("secret renewal clocks exceed supported one-second skew"));
        }
        Ok(after)
    }
}
