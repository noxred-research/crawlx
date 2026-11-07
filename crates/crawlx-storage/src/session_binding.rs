//! Session binding metadata subordinate to the existing session lease, never a new lock service.

use crate::codec::{from_json, get, to_json};
use crate::error::db;
use crate::leases::SessionLease;
use crate::Pg;
use crawlx_core::repo::{EventRepo, RunRepo};
use crawlx_core::session_binding::{BindingState, SessionBindingV1, SessionIdentityV1, SessionLimits};
use crawlx_core::{StoreError, TenantId, Timestamp};
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};

/// Absolute ceiling on one initial-authentication reservation (one hour).
/// Exploration cannot spend this allowance; its actor binding is narrowed after login.
pub const MAX_LOGIN_RESERVATION_MS: u64 = 3_600_000;

/// Binding validation keeps an elapsed ceiling distinct from independent repository failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionBindingVerificationError {
    /// Lease, profile, generation or repository validation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The validated generation refused a use under its finite binding policy.
    #[error(transparent)]
    Binding(#[from] crawlx_core::session_binding::SessionBindingError),
}

#[derive(serde::Deserialize)]
struct BudgetClock {
    session_id: crawlx_core::SessionId,
    #[serde(default)]
    login_credit_ms: u64,
    #[serde(default)]
    login_allowance_ms: u64,
}

/// Lock and validate the already-granted session lease in a metadata transaction.
/// Uses the database clock after row acquisition so a blocked waiter cannot reuse stale time.
pub(crate) async fn lock_lease(
    tx: &mut Transaction<'_, Postgres>,
    lease: &SessionLease,
    tenant: TenantId,
) -> Result<Timestamp, StoreError> {
    let row = sqlx::query(
        "SELECT s.session_id FROM crawl_sessions s JOIN crawl_runs r USING(run_id) \
         WHERE s.session_id=$1 AND s.run_id=$2 AND s.role=$3 AND r.tenant_id=$4 \
         FOR UPDATE OF s",
    )
    .bind(lease.session.id.0)
    .bind(lease.session.run.0)
    .bind(&lease.session.role.0)
    .bind(tenant.0)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?;
    if row.is_none() {
        return Err(StoreError::LeaseLost);
    }
    let now: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM crawl_sessions s JOIN crawl_runs r USING(run_id) \
         WHERE s.session_id=$1 AND s.lease_owner=$2 AND s.fencing_token=$3 \
         AND s.lease_expires_at > $4 AND s.status IN ('running','recovering') \
         AND r.status IN ('queued','running') AND r.cancel_requested_at IS NULL \
         AND r.purge_requested_at IS NULL \
         AND NOT EXISTS(SELECT 1 FROM authorization_records a WHERE a.record_id=r.authorization_record_id \
           AND (a.revoked_at IS NOT NULL OR a.valid_to <= $4)))",
    )
    .bind(lease.session.id.0)
    .bind(lease.worker.0)
    .bind(lease.fencing_token)
    .bind(now)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !valid {
        return Err(StoreError::LeaseLost);
    }
    Ok(now)
}

impl Pg {
    /// Rebuild the clock ceiling from persisted worker accounting, never from a requested
    /// binding expiry. EventRepo resolves privacy-protected events for ZDR runs as well.
    async fn binding_clock_deadline(&self, lease: &SessionLease) -> Result<(Timestamp, u64), StoreError> {
        let run = RunRepo::get(self, lease.session.run).await?;
        let sessions: BTreeSet<_> = RunRepo::list_sessions(self, run.id)
            .await?
            .into_iter()
            .map(|session| session.id)
            .collect();
        let mut clocks: BTreeMap<crawlx_core::SessionId, (Timestamp, BudgetClock)> = BTreeMap::new();
        let mut after = 0;
        loop {
            let events = EventRepo::list_after(self, run.id, after, 512).await?;
            let Some(last) = events.last() else { break };
            after = last.seq;
            for event in events.iter().filter(|event| event.kind == "session.budget") {
                let clock: BudgetClock = serde_json::from_value(event.payload.clone())
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                let first = clocks.get(&clock.session_id).map_or(event.at, |(at, _)| *at);
                let elapsed =
                    u64::try_from(event.at.signed_duration_since(first).num_milliseconds()).unwrap_or(0);
                if !sessions.contains(&clock.session_id)
                    || clock.login_allowance_ms > MAX_LOGIN_RESERVATION_MS
                    || clock.login_credit_ms > elapsed
                    || clocks
                        .get(&clock.session_id)
                        .is_some_and(|(_, old)| clock.login_credit_ms < old.login_credit_ms)
                {
                    return Err(StoreError::Conflict("invalid durable login clock".into()));
                }
                clocks.insert(clock.session_id, (first, clock));
            }
        }
        let mut millis = 0_u64;
        for (_, clock) in clocks.values() {
            millis = millis
                .checked_add(clock.login_credit_ms)
                .and_then(|value| {
                    value.checked_add(if clock.session_id == lease.session.id {
                        clock.login_allowance_ms
                    } else {
                        0
                    })
                })
                .ok_or_else(|| StoreError::Conflict("session binding clock overflow".into()))?;
        }
        let allowance = clocks
            .get(&lease.session.id)
            .map_or(0, |(_, clock)| clock.login_allowance_ms);
        let deadline = run
            .started_at
            .unwrap_or(run.created_at)
            .checked_add_signed(chrono::Duration::seconds(i64::from(
                run.config.limits.duration_seconds,
            )))
            .and_then(|deadline| {
                i64::try_from(millis)
                    .ok()
                    .and_then(|millis| deadline.checked_add_signed(chrono::Duration::milliseconds(millis)))
            })
            .ok_or_else(|| StoreError::Conflict("session binding clock overflow".into()))?;
        Ok((deadline, allowance))
    }

    /// Establish/renew the same identity under the existing live session lease.
    /// A different identity requires explicit drained replacement, not implicit generation swap.
    ///
    /// # Errors
    /// Returns lease loss, `session_unavailable`, or a backend error. Existing expired/retired
    /// generations never silently allocate a different cookie jar.
    pub async fn bind_session(
        &self,
        lease: &SessionLease,
        identity: SessionIdentityV1,
        expires_at: Timestamp,
    ) -> Result<SessionBindingV1, StoreError> {
        if identity.session != lease.session.id
            || identity.run != lease.session.run
            || identity.principal != lease.session.role
        {
            return Err(StoreError::Conflict("session_unavailable".into()));
        }
        let (clock_deadline, login_allowance_ms) = self.binding_clock_deadline(lease).await?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let now = lock_lease(&mut tx, lease, identity.tenant).await?;
        // Authentication credits change only the exploration clock. Authorization and
        // secret retention stay independent absolute ceilings.
        let authority_deadline: Option<Timestamp> = sqlx::query_scalar(
            "SELECT LEAST(r.expires_at, a.valid_to) FROM crawl_runs r \
             LEFT JOIN authorization_records a ON a.record_id=r.authorization_record_id \
             WHERE r.run_id=$1",
        )
        .bind(identity.run.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let ceiling = authority_deadline.map_or(clock_deadline, |deadline| deadline.min(clock_deadline));
        let mut expiry = expires_at.min(ceiling);
        if identity.profile.is_some() {
            let profile_deadline: Timestamp = sqlx::query_scalar(
                "SELECT expires_at FROM browser_profiles WHERE session_id=$1 AND lease_fence=$2",
            )
            .bind(identity.session.0)
            .bind(lease.fencing_token)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| StoreError::Conflict("profile_unavailable: profile lease missing".into()))?;
            expiry = expiry.min(profile_deadline);
        }
        if expiry <= now {
            return Err(StoreError::Conflict("session_unavailable".into()));
        }
        let row = sqlx::query("SELECT binding FROM session_bindings WHERE session_id=$1")
            .bind(identity.session.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        let binding = if let Some(row) = row {
            let mut current: SessionBindingV1 = from_json(get(&row, "binding")?)?;
            if current.identity != identity
                || current.expires_at <= now
                || current.retirement.is_some()
                || !matches!(current.state, BindingState::Leased | BindingState::Available)
            {
                return Err(StoreError::Conflict("session_unavailable".into()));
            }
            if current.lease_fence == lease.fencing_token && current.state == BindingState::Leased {
                return Err(StoreError::Conflict(
                    "session_unavailable: binding actor collision".into(),
                ));
            }
            // A new fenced holder may need to reauthenticate after the previous actor
            // settled its reservation. Only the newly persisted bounded login window
            // can grow the old ceiling; ordinary reuse still cannot extend it.
            let recovery_allowance = if current.lease_fence != lease.fencing_token {
                i64::try_from(login_allowance_ms).unwrap_or(0)
            } else {
                0
            };
            let previous_ceiling = current
                .expires_at
                .checked_add_signed(chrono::Duration::milliseconds(recovery_allowance))
                .unwrap_or(current.expires_at);
            current.lease_fence = lease.fencing_token;
            current.state = BindingState::Leased;
            current.expires_at = previous_ceiling
                .min(current.lifetime_expires_at.unwrap_or(current.expires_at))
                .min(expiry);
            current.state_version = current
                .state_version
                .checked_add(1)
                .ok_or_else(|| StoreError::Conflict("session binding version exhausted".into()))?;
            current
        } else {
            SessionBindingV1::new(identity, lease.fencing_token, expiry)
        };
        binding
            .eligible(
                &binding.identity,
                lease.fencing_token,
                now,
                SessionLimits::default(),
            )
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        sqlx::query(
            "INSERT INTO session_bindings(session_id,run_id,binding) VALUES($1,$2,$3) \
                     ON CONFLICT(session_id) DO UPDATE SET binding=EXCLUDED.binding",
        )
        .bind(binding.identity.session.0)
        .bind(binding.identity.run.0)
        .bind(to_json(&binding)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(binding)
    }

    /// Confirm the original live lease and immutable generation before a browser command.
    /// This reads metadata only and never grants or renews authority.
    ///
    /// # Errors
    /// Returns independent lease/profile/repository failures as `Store`, or typed binding
    /// eligibility failures (including expiry) only after those checks succeed.
    pub async fn verify_session_binding(
        &self,
        lease: &SessionLease,
        binding: &SessionBindingV1,
    ) -> Result<(), SessionBindingVerificationError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let now = lock_lease(&mut tx, lease, binding.identity.tenant).await?;
        let row = sqlx::query("SELECT binding FROM session_bindings WHERE session_id=$1")
            .bind(lease.session.id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| StoreError::Conflict("session_unavailable".into()))?;
        let current: SessionBindingV1 = from_json(get(&row, "binding")?)?;
        if current.checkpoint_identity() != binding.checkpoint_identity() {
            return Err(StoreError::Conflict("session generation conflict".into()).into());
        }
        if let Some(expected) = binding.identity.profile {
            let row = sqlx::query("SELECT scope,generation FROM browser_profiles WHERE session_id=$1 AND lease_fence=$2 AND expires_at>$3")
                .bind(lease.session.id.0).bind(lease.fencing_token).bind(now)
                .fetch_optional(&mut *tx).await.map_err(db)?
                .ok_or_else(|| StoreError::Conflict("profile_unavailable: profile lease expired or revoked".into()))?;
            let scope: crate::profiles::ProfileScopeV1 = from_json(get(&row, "scope")?)?;
            let generation: i64 = get(&row, "generation")?;
            let generation = u64::try_from(generation)
                .map_err(|_| StoreError::Conflict("profile generation conflict".into()))?;
            let actual =
                crawlx_core::hash::Digest::of_value("crawlx/profile-identity/v1", &(scope, generation))
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
            if actual != expected {
                return Err(StoreError::Conflict("profile generation conflict".into()).into());
            }
        }
        // Check independent lease/profile/storage authority before reporting only expiry.
        // The transaction grants no authority and never renews any ceiling.
        tx.commit().await.map_err(db)?;
        current.eligible(
            &binding.identity,
            lease.fencing_token,
            now,
            SessionLimits::default(),
        )?;
        Ok(())
    }

    /// Compare-and-swap health/lifecycle metadata under the original session lease.
    ///
    /// # Errors
    /// Rejects stale fence/version, changed identity/generation, illegal state transitions,
    /// and any attempted replacement while intended/unknown journal writes remain.
    pub async fn update_session_binding(
        &self,
        lease: &SessionLease,
        expected_version: u64,
        next: &SessionBindingV1,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        lock_lease(&mut tx, lease, next.identity.tenant).await?;
        let row = sqlx::query("SELECT binding FROM session_bindings WHERE session_id=$1")
            .bind(lease.session.id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| StoreError::Conflict("session_unavailable".into()))?;
        let current: SessionBindingV1 = from_json(get(&row, "binding")?)?;
        let same = next.identity == current.identity && next.generation == current.generation;
        let owner_same = next.identity.tenant == current.identity.tenant
            && next.identity.run == current.identity.run
            && next.identity.principal == current.identity.principal
            && next.identity.session == current.identity.session;
        let replacing = current.generation.checked_add(1) == Some(next.generation)
            && current.state == BindingState::Retired
            && next.state == BindingState::Leased
            && owner_same;
        let legal_state = matches!(
            (current.state, next.state),
            (
                BindingState::Leased,
                BindingState::Leased | BindingState::Draining
            ) | (BindingState::Available, BindingState::Leased)
                | (
                    BindingState::Draining,
                    BindingState::Available | BindingState::Retired | BindingState::Quarantined
                )
                | (BindingState::Quarantined, BindingState::Retired)
        );
        if current.lease_fence != lease.fencing_token
            || next.lease_fence != lease.fencing_token
            || current.state_version != expected_version
            || current.state_version.checked_add(1) != Some(next.state_version)
            || (!same && !replacing)
            || (same && !legal_state)
            || next.expires_at > current.expires_at
            || next.lifetime_expires_at != current.lifetime_expires_at
        {
            return Err(StoreError::Conflict("session generation conflict".into()));
        }
        if replacing {
            let uncertain: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM actions WHERE session_id=$1 AND status IN ('intended','unknown'))")
                .bind(lease.session.id.0).fetch_one(&mut *tx).await.map_err(db)?;
            if uncertain {
                return Err(StoreError::Conflict(
                    "session generation conflict: unresolved write".into(),
                ));
            }
        }
        sqlx::query("UPDATE session_bindings SET binding=$2 WHERE session_id=$1")
            .bind(lease.session.id.0)
            .bind(to_json(next)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }
}
