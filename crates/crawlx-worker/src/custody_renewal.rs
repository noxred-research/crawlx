//! Structured, bounded renewal of durable custody use authority.
//!
//! Renewal never extends Redis retention. Dropping the work or its lease drops
//! this loop; no detached renewal task can outlive a producer. Unknown commit
//! outcomes retry the same operation and absolute deadline, never a new grant.

use crate::durable::DurableAuthority;
use crawlx_core::custody::{CustodyLease, CustodyRenewalWindow};
use crawlx_core::{StoreError, Timestamp};
use crawlx_storage::custody::SecretAuthority;
use crawlx_storage::sql::Sql;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const MAX_ATTEMPTS: usize = 4;
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);

fn schedule(window: &CustodyRenewalWindow) -> Result<(Duration, Timestamp), StoreError> {
    let remaining = window
        .expires_at
        .signed_duration_since(window.observed_at)
        .to_std()
        .map_err(|_| StoreError::LeaseLost)?;
    if remaining.is_zero() {
        return Err(StoreError::LeaseLost);
    }
    let delta = chrono::Duration::from_std(window.use_window)
        .map_err(|_| StoreError::Unavailable("custody renewal duration overflow".into()))?;
    let target = window
        .observed_at
        .checked_add_signed(delta)
        .ok_or_else(|| StoreError::Unavailable("custody renewal deadline overflow".into()))?
        .min(window.retention_ceiling);
    let target = Timestamp::from_timestamp_millis(target.timestamp_millis())
        .ok_or_else(|| StoreError::Unavailable("custody renewal deadline overflow".into()))?;
    Ok((
        (remaining / 3)
            .min(MAX_POLL_INTERVAL)
            .max(Duration::from_millis(1)),
        target,
    ))
}

async fn renew_same_request<B: Sql>(
    authority: &SecretAuthority<B>,
    lease: &CustodyLease,
    window: &CustodyRenewalWindow,
    deadline: Timestamp,
) -> Result<(), StoreError> {
    let operation = Uuid::now_v7();
    for attempt in 0..MAX_ATTEMPTS {
        match authority
            .renew_authority(lease, window.version, operation, deadline)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) if error.is_retryable() && attempt + 1 < MAX_ATTEMPTS => {
                tokio::select! {
                    biased;
                    () = lease.cancelled() => return Err(StoreError::LeaseLost),
                    () = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(StoreError::Unavailable(
        "custody renewal outcome unresolved".into(),
    ))
}

async fn inspect_window<B: Sql>(
    authority: &SecretAuthority<B>,
    lease: &CustodyLease,
) -> Result<CustodyRenewalWindow, StoreError> {
    // Pending registration blocks renewal, not valid producer work. Every poll
    // rechecks the durable deadline; pending registration cannot extend it.
    let mut delay = Duration::from_millis(20);
    loop {
        match authority.renewal_window(lease).await {
            Err(error) if crawlx_storage::is_stale_epoch(&error) => {
                tokio::select! {
                    biased;
                    () = lease.cancelled() => return Err(StoreError::LeaseLost),
                    () = tokio::time::sleep(delay) => {}
                }
                delay = delay.saturating_mul(2).min(Duration::from_secs(1));
            }
            result => return result,
        }
    }
}

async fn renewal_loop_on<B: Sql>(
    authority: &SecretAuthority<B>,
    lease: &CustodyLease,
) -> Result<(), StoreError> {
    loop {
        let window = inspect_window(authority, lease).await?;
        let (delay, _) = schedule(&window)?;
        tokio::select! {
            biased;
            () = lease.cancelled() => return Err(StoreError::LeaseLost),
            () = tokio::time::sleep(delay) => {}
        }
        loop {
            let current = inspect_window(authority, lease).await?;
            let (_, target) = schedule(&current)?;
            if target <= current.expires_at {
                break;
            }
            match renew_same_request(authority, lease, &current, target).await {
                Ok(()) => break,
                Err(error) if crawlx_storage::is_stale_epoch(&error) => {
                    tokio::select! {
                        biased;
                        () = lease.cancelled() => return Err(StoreError::LeaseLost),
                        () = tokio::time::sleep(Duration::from_millis(20)) => {}
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
}

async fn renewal_loop(authority: &DurableAuthority, lease: &CustodyLease) -> Result<(), StoreError> {
    crate::on_authority!(authority, authority => renewal_loop_on(authority, lease).await)
}

/// Keep one producer's work and renewal inside the same structured lifetime.
///
/// The caller must supply its actual existing lease and cancellation binding.
/// Local nonpersistent stores pass `None`; they need no remote renewal.
///
/// # Errors
/// Returns the work error or a failed authority/renewal check. Renewal failure
/// cancels work by dropping its future; storage still checks every queued effect.
pub async fn with_custody_renewal<T, E, F>(
    authority: Option<Arc<DurableAuthority>>,
    lease: CustodyLease,
    work: F,
) -> Result<T, E>
where
    E: From<StoreError>,
    F: Future<Output = Result<T, E>>,
{
    let Some(authority) = authority else {
        return work.await;
    };
    let initializer = authority.custody();
    crawlx_storage::ArtifactCustody::snapshot(initializer.as_ref(), &lease)
        .await
        .map_err(E::from)?;
    // Keep database renewal state out of the work branch's polling stack,
    // including monomorphizations whose local-store branch never renews.
    let renewal = Box::pin(renewal_loop(authority.as_ref(), &lease));
    tokio::pin!(work);
    tokio::select! {
        biased;
        result = &mut work => result,
        result = renewal => {
            match result {
                Err(error) => Err(E::from(error)),
                Ok(()) => Err(E::from(StoreError::Unavailable("custody renewal ended before producer".into()))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::custody::SecretEpoch;
    use crawlx_core::{CrawlRunId, TenantId};

    #[test]
    fn renewal_schedule_is_bounded_and_never_crosses_original_ceiling() {
        let now = Timestamp::from_timestamp(1_700_000_000, 0).unwrap();
        let version = SecretEpoch::new(TenantId::new(), CrawlRunId::new(), Uuid::nil(), 1);
        let window = CustodyRenewalWindow::new(
            version,
            now + chrono::Duration::minutes(30),
            now + chrono::Duration::hours(3),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(
            schedule(&window).unwrap(),
            (Duration::from_secs(60), now + chrono::Duration::hours(1))
        );
        let narrow = CustodyRenewalWindow::new(
            version,
            now + chrono::Duration::seconds(12),
            now + chrono::Duration::seconds(20),
            Duration::from_secs(60),
            now,
        );
        assert_eq!(
            schedule(&narrow).unwrap(),
            (Duration::from_secs(4), narrow.retention_ceiling)
        );
        let expired = CustodyRenewalWindow::new(
            version,
            now,
            now + chrono::Duration::hours(1),
            Duration::from_secs(60),
            now,
        );
        assert!(schedule(&expired).is_err());
    }

    #[tokio::test]
    async fn local_work_needs_no_remote_scheduler() {
        let lease = CustodyLease::new(
            TenantId::new(),
            CrawlRunId::new(),
            crawlx_core::SessionId::new(),
            crawlx_core::WorkerId::new(),
            1,
        );
        let result: Result<u32, StoreError> = with_custody_renewal(None, lease, async { Ok(7) }).await;
        assert_eq!(result.unwrap(), 7);
    }
}
