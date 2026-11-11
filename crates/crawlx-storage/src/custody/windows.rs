//! Renewable database use windows over an immutable Redis retention ceiling.

use super::{database_now, denied, live, locked, PgSecretAuthority, EXPIRY_MARGIN_MS, MAX_AUTHORITY_TTL};
use crate::codec::get;
use crate::error::db;
use crawlx_core::custody::{CustodyLease, CustodyRenewalWindow, SecretEpoch};
use crawlx_core::{StoreError, Timestamp};
use sqlx::{Postgres, Transaction};
use std::time::Duration;

fn add_window(now: Timestamp, duration: Duration) -> Result<Timestamp, StoreError> {
    let millis =
        i64::try_from(duration.as_millis()).map_err(|_| denied("secret authority duration overflow"))?;
    now.checked_add_signed(chrono::Duration::milliseconds(millis))
        .ok_or_else(|| denied("secret authority deadline overflow"))
}

fn original_ceiling(
    now: Timestamp,
    retention: Option<Timestamp>,
    authorization: Option<Timestamp>,
    deadline: Option<Timestamp>,
    hard_max: Duration,
) -> Result<Timestamp, StoreError> {
    let mut ceiling = add_window(now, hard_max)?;
    if retention.is_none() || authorization.is_none() {
        ceiling = ceiling.min(add_window(now, MAX_AUTHORITY_TTL)?);
    }
    for limit in [retention, authorization, deadline].into_iter().flatten() {
        ceiling = ceiling.min(limit);
    }
    // Exact milliseconds are part of every idempotent renewal request.
    Timestamp::from_timestamp_millis(ceiling.timestamp_millis())
        .ok_or_else(|| denied("secret authority deadline overflow"))
}

impl PgSecretAuthority {
    pub(super) async fn initial_deadlines(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        lease: &CustodyLease,
    ) -> Result<(Timestamp, Timestamp), StoreError> {
        let row = sqlx::query("SELECT r.expires_at,r.deadline_at,a.valid_to FROM crawl_runs r LEFT JOIN authorization_records a ON a.record_id=r.authorization_record_id WHERE r.tenant_id=$1 AND r.run_id=$2")
            .bind(lease.tenant.0).bind(lease.run.0).fetch_one(&mut **tx).await.map_err(db)?;
        let now = database_now(tx).await?;
        let ceiling = original_ceiling(
            now,
            get(&row, "expires_at")?,
            get(&row, "valid_to")?,
            get(&row, "deadline_at")?,
            self.hard_max,
        )?;
        let expires_at = add_window(now, self.ttl)?.min(ceiling);
        let expires_at = Timestamp::from_timestamp_millis(expires_at.timestamp_millis())
            .ok_or_else(|| denied("secret authority deadline overflow"))?;
        if ceiling.signed_duration_since(now) <= chrono::Duration::milliseconds(EXPIRY_MARGIN_MS)
            || expires_at <= now
        {
            return Err(denied("secret authority original retention already expired"));
        }
        Ok((expires_at, ceiling))
    }

    /// Inspect a live, committed use window under the existing producer fence.
    ///
    /// This schedules renewal only; it never grants publication or plaintext access.
    /// Every actual operation must revalidate authority and its exact secret epoch.
    ///
    /// # Errors
    /// Rejects expired authority, pending operations, stale fences and legacy windows.
    pub async fn renewal_window(&self, lease: &CustodyLease) -> Result<CustodyRenewalWindow, StoreError> {
        let mut tx = self.transaction().await?;
        let row = locked(&mut tx, lease).await?;
        if row.pending.is_some() || row.epoch == 0 {
            return Err(denied(super::REGISTER_STALE));
        }
        let millis = row
            .use_window_ms
            .ok_or_else(|| denied("legacy secret authority has no renewable use window"))?;
        let use_window = Duration::from_millis(
            u64::try_from(millis).map_err(|_| denied("secret authority use window corrupt"))?,
        );
        live(&mut tx, lease).await?;
        let observed_at = database_now(&mut tx).await?;
        if row.expires_at <= observed_at {
            return Err(denied("secret authority expired during renewal inspection"));
        }
        tx.commit().await.map_err(db)?;
        lease.check_local_cancellation()?;
        Ok(CustodyRenewalWindow::new(
            SecretEpoch::new(lease.tenant, lease.run, row.incarnation, row.epoch),
            row.expires_at,
            row.retention_ceiling,
            use_window,
            observed_at,
        ))
    }

    pub(super) async fn retained_snapshot_on(
        &self,
        tenant: crawlx_core::TenantId,
        run: crawlx_core::CrawlRunId,
        expected: SecretEpoch,
    ) -> Result<crawlx_core::custody::RunSecretSnapshot, StoreError> {
        let mut tx = self.transaction().await?;
        let (row, status) = super::read_locked(&mut tx, tenant, run).await?;
        let retained: bool = sqlx::query_scalar(
            "SELECT retention_mode<>'zdr' FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2",
        )
        .bind(tenant.0)
        .bind(run.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if !retained
            || row.pending.is_some()
            || row.epoch < 1
            || expected != SecretEpoch::new(tenant, run, row.incarnation, row.epoch)
        {
            return Err(denied("retained-source privacy authority unavailable or changed"));
        }
        let terminal = matches!(status.as_str(), "completed" | "failed" | "cancelled");
        let now = database_now(&mut tx).await?;
        if row.retention_ceiling <= now || (!terminal && row.expires_at <= now) {
            return Err(denied("retained-source privacy authority expired"));
        }
        let snapshot = self
            .invoke(&row, "snapshot", row.epoch, uuid::Uuid::nil(), "", 0)
            .await?;
        snapshot.check(row.commitment.as_deref())?;
        let now = database_now(&mut tx).await?;
        let retained: bool = sqlx::query_scalar(
            "SELECT expires_at IS NULL OR expires_at>$3 FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2",
        )
        .bind(tenant.0)
        .bind(run.0)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if !retained || row.retention_ceiling <= now || (!terminal && row.expires_at <= now) {
            return Err(denied(
                "retained-source privacy authority expired during projection",
            ));
        }
        tx.commit().await.map_err(db)?;
        Ok(snapshot.snapshot)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn long_retention_needs_both_explicit_permissions_and_respects_operator_maximum() {
        let now = Timestamp::from_timestamp(1_700_000_000, 0).unwrap();
        let day = now + chrono::Duration::hours(24);
        let long = now + chrono::Duration::hours(96);
        let hard_max = Duration::from_secs(72 * 3600);
        assert_eq!(original_ceiling(now, None, None, None, hard_max).unwrap(), day);
        assert_eq!(
            original_ceiling(now, Some(long), None, None, hard_max).unwrap(),
            day
        );
        assert_eq!(
            original_ceiling(now, None, Some(long), None, hard_max).unwrap(),
            day
        );
        assert_eq!(
            original_ceiling(now, Some(long), Some(long), None, hard_max).unwrap(),
            now + chrono::Duration::hours(72)
        );
        assert_eq!(
            original_ceiling(
                now,
                Some(long),
                Some(now + chrono::Duration::hours(30)),
                None,
                hard_max
            )
            .unwrap(),
            now + chrono::Duration::hours(30)
        );
        assert_eq!(
            original_ceiling(
                now,
                Some(long),
                Some(long),
                Some(now + chrono::Duration::hours(8)),
                hard_max
            )
            .unwrap(),
            now + chrono::Duration::hours(8)
        );
        assert_eq!(
            original_ceiling(now, Some(long), Some(long), None, Duration::from_secs(6 * 3600)).unwrap(),
            now + chrono::Duration::hours(6)
        );
    }
}
