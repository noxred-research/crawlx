//! Session binding metadata subordinate to the existing session lease, never a new lock service.

use crate::backend::strategy::Conn;
use crate::backend::{BackendKind, Dialect, RowLock};
use crate::codec::{from_json, to_json};
use crate::leases::SessionLease;
use crate::sql::{db_clock, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use crate::tenant::TenantGuard;
use crawlx_core::repo::{EventRepo, RunRepo};
use crawlx_core::session_binding::{
    BindingState, RetirementReason, SessionBindingError, SessionBindingV1, SessionIdentityV1, SessionLimits,
};
use crawlx_core::{StoreError, TenantId, Timestamp};
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
///
/// Engines without `FOR UPDATE OF` lock the session row alone and then check the tenant of its
/// run, which locks the same single row and validates the same ownership.
pub(crate) async fn lock_lease_on<B: Sql>(
    conn: &mut Conn<B>,
    lease: &SessionLease,
    tenant: TenantId,
) -> Result<Timestamp, StoreError> {
    let locked = if B::KIND == BackendKind::Postgres {
        stmt!(
            B,
            "SELECT s.session_id FROM crawl_sessions s JOIN crawl_runs r USING(run_id) \
             WHERE s.session_id=$1 AND s.run_id=$2 AND s.role=$3 AND r.tenant_id=$4 \
             FOR UPDATE OF s"
        )
        .uuid(lease.session.id.0)
        .uuid(lease.session.run.0)
        .text(&lease.session.role.0)
        .uuid(tenant.0)
        .fetch_optional(conn)
        .await?
        .is_some()
    } else {
        let session = stmt!(
            B,
            format!(
                "SELECT session_id FROM crawl_sessions WHERE session_id=$1 AND run_id=$2 AND role=$3{}",
                <B::Dialect as Dialect>::row_lock(RowLock::Update)
            )
        )
        .uuid(lease.session.id.0)
        .uuid(lease.session.run.0)
        .text(&lease.session.role.0)
        .fetch_optional(conn)
        .await?
        .is_some();
        session
            && stmt!(
                B,
                "SELECT run_id FROM crawl_runs WHERE run_id=$1 AND tenant_id=$2"
            )
            .uuid(lease.session.run.0)
            .uuid(tenant.0)
            .fetch_optional(conn)
            .await?
            .is_some()
    };
    if !locked {
        return Err(StoreError::LeaseLost);
    }
    let now = db_clock::<B>(conn).await?;
    let valid = stmt!(
        B,
        "SELECT EXISTS(SELECT 1 FROM crawl_sessions s JOIN crawl_runs r USING(run_id) \
         WHERE s.session_id=$1 AND s.lease_owner=$2 AND s.fencing_token=$3 \
         AND s.lease_expires_at > $4 AND s.status IN ('running','recovering') \
         AND r.status IN ('queued','running') AND r.cancel_requested_at IS NULL \
         AND r.purge_requested_at IS NULL \
         AND NOT EXISTS(SELECT 1 FROM authorization_records a WHERE a.record_id=r.authorization_record_id \
           AND (a.revoked_at IS NOT NULL OR a.valid_to <= $4))) AS valid"
    )
    .uuid(lease.session.id.0)
    .uuid(lease.worker.0)
    .i64(lease.fencing_token)
    .ts(now)
    .fetch_one(conn)
    .await?
    .flag("valid")?;
    if !valid {
        return Err(StoreError::LeaseLost);
    }
    Ok(now)
}

/// Rebuild a run's exploration ceiling from durable completed-login credits.
/// Only session binding may additionally reserve its own unfinished login allowance.
///
/// # Errors
/// Returns malformed or decreasing clock records, arithmetic overflow or repository errors.
pub(crate) async fn budget_clock_deadline<R: RunRepo + EventRepo + ?Sized>(
    repo: &R,
    run: &crawlx_core::repo::CrawlRun,
    allowance_session: Option<crawlx_core::SessionId>,
) -> Result<(Timestamp, u64), StoreError> {
    let sessions: BTreeSet<_> = repo
        .list_sessions(run.id)
        .await?
        .into_iter()
        .map(|session| session.id)
        .collect();
    let mut clocks: BTreeMap<crawlx_core::SessionId, (Timestamp, BudgetClock)> = BTreeMap::new();
    let mut after = 0;
    loop {
        let events = repo.list_after(run.id, after, 512).await?;
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
                value.checked_add(if Some(clock.session_id) == allowance_session {
                    clock.login_allowance_ms
                } else {
                    0
                })
            })
            .ok_or_else(|| StoreError::Conflict("session binding clock overflow".into()))?;
    }
    let allowance = allowance_session
        .and_then(|session| clocks.get(&session))
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

impl<B: Sql> Store<B> {
    /// Rebuild the clock ceiling from persisted worker accounting, never from a requested
    /// binding expiry. EventRepo resolves privacy-protected events for ZDR runs as well.
    async fn binding_clock_deadline(&self, lease: &SessionLease) -> Result<(Timestamp, u64), StoreError> {
        let run = RunRepo::get(self, lease.session.run).await?;
        budget_clock_deadline(self, &run, Some(lease.session.id)).await
    }

    /// Read a binding beneath its locked session lease, carrying the tenant predicate on
    /// engines without database-enforced tenancy.
    async fn stored_binding(
        conn: &mut Conn<B>,
        session: crawlx_core::SessionId,
        tenant: TenantId,
    ) -> Result<Option<SessionBindingV1>, StoreError> {
        let mut query = if B::KIND.capabilities().database_enforced_tenancy {
            stmt!(B, "SELECT binding FROM session_bindings WHERE session_id=$1")
        } else {
            let scope = TenantGuard::for_tenant(tenant).scope::<B::Dialect>("session_bindings", "", "$2")?;
            Stmt::<B>::dynamic(&format!(
                "SELECT binding FROM session_bindings WHERE session_id=$1 AND {}",
                scope.predicate
            ))
        }
        .uuid(session.0);
        if !B::KIND.capabilities().database_enforced_tenancy {
            query = query.uuid(tenant.0);
        }
        query
            .fetch_optional(conn)
            .await?
            .map(|row| from_json(row.json("binding")?))
            .transpose()
    }

    /// Persist a validated transition beneath the same locked session lease.
    async fn save_binding(conn: &mut Conn<B>, binding: &SessionBindingV1) -> Result<(), StoreError> {
        let value = to_json(binding)?;
        let mut query = if B::KIND.capabilities().database_enforced_tenancy {
            stmt!(B, "UPDATE session_bindings SET binding=$2 WHERE session_id=$1")
        } else {
            let scope = TenantGuard::for_tenant(binding.identity.tenant).scope::<B::Dialect>(
                "session_bindings",
                "",
                "$3",
            )?;
            Stmt::<B>::dynamic(&format!(
                "UPDATE session_bindings SET binding=$2 WHERE session_id=$1 AND {}",
                scope.predicate
            ))
        }
        .uuid(binding.identity.session.0)
        .json(&value);
        if !B::KIND.capabilities().database_enforced_tenancy {
            query = query.uuid(binding.identity.tenant.0);
        }
        query.execute(conn).await?;
        Ok(())
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
        self.scope()?.authorize(identity.tenant)?;
        if identity.session != lease.session.id
            || identity.run != lease.session.run
            || identity.principal != lease.session.role
        {
            return Err(StoreError::Conflict("session_unavailable".into()));
        }
        let (clock_deadline, login_allowance_ms) = self.binding_clock_deadline(lease).await?;
        let mut tx = self.begin_write().await?;
        let now = lock_lease_on::<B>(tx.conn(), lease, identity.tenant).await?;
        // Authentication credits change only the exploration clock. Authorization and
        // secret retention stay independent absolute ceilings.
        let authority_deadline = stmt!(
            B,
            format!(
                "SELECT {} AS deadline FROM crawl_runs r \
                 LEFT JOIN authorization_records a ON a.record_id=r.authorization_record_id \
                 WHERE r.run_id=$1",
                <B::Dialect as Dialect>::least_ignoring_null(&["r.expires_at", "a.valid_to"])
            )
        )
        .uuid(identity.run.0)
        .fetch_one(tx.conn())
        .await?
        .opt_ts("deadline")?;
        let ceiling = authority_deadline.map_or(clock_deadline, |deadline| deadline.min(clock_deadline));
        let mut expiry = expires_at.min(ceiling);
        if identity.profile.is_some() {
            let profile_deadline = stmt!(
                B,
                "SELECT expires_at FROM browser_profiles WHERE session_id=$1 AND lease_fence=$2"
            )
            .uuid(identity.session.0)
            .i64(lease.fencing_token)
            .fetch_optional(tx.conn())
            .await?
            .ok_or_else(|| StoreError::Conflict("profile_unavailable: profile lease missing".into()))?
            .ts("expires_at")?;
            expiry = expiry.min(profile_deadline);
        }
        if expiry <= now {
            return Err(StoreError::Conflict("session_unavailable".into()));
        }
        let binding = if let Some(mut current) =
            Self::stored_binding(tx.conn(), identity.session, identity.tenant).await?
        {
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
        let stored = to_json(&binding)?;
        stmt!(
            B,
            format!(
                "INSERT INTO session_bindings(session_id,run_id,binding) VALUES($1,$2,$3) {}",
                <B::Dialect as Dialect>::upsert_update(&["session_id"], &["binding"], None)
            )
        )
        .uuid(binding.identity.session.0)
        .uuid(binding.identity.run.0)
        .json(&stored)
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
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
        self.scope()?.authorize(binding.identity.tenant)?;
        let mut tx = self.begin_write().await?;
        let now = lock_lease_on::<B>(tx.conn(), lease, binding.identity.tenant).await?;
        let current = Self::stored_binding(tx.conn(), lease.session.id, binding.identity.tenant)
            .await?
            .ok_or_else(|| StoreError::Conflict("session_unavailable".into()))?;
        if current.checkpoint_identity() != binding.checkpoint_identity() {
            return Err(StoreError::Conflict("session generation conflict".into()).into());
        }
        if let Some(expected) = binding.identity.profile {
            let row = stmt!(
                B,
                "SELECT scope,generation FROM browser_profiles WHERE session_id=$1 AND lease_fence=$2 AND expires_at>$3"
            )
            .uuid(lease.session.id.0)
            .i64(lease.fencing_token)
            .ts(now)
            .fetch_optional(tx.conn())
            .await?
            .ok_or_else(|| StoreError::Conflict("profile_unavailable: profile lease expired or revoked".into()))?;
            let scope: crate::profiles::ProfileScopeV1 = from_json(row.json("scope")?)?;
            let generation = u64::try_from(row.i64("generation")?)
                .map_err(|_| StoreError::Conflict("profile generation conflict".into()))?;
            let identity_of = |generation: u64| {
                crawlx_core::hash::Digest::of_value("crawlx/profile-identity/v1", &(&scope, generation))
                    .map_err(|error| StoreError::Serialization(error.to_string()))
            };
            // The row is pinned to this very session and fence, so only this session's own
            // end-of-run commit can have advanced it, by exactly one generation beyond the one
            // the binding was created for. Any other drift is a conflict.
            let own_commit = match generation.checked_sub(1).filter(|previous| *previous > 0) {
                Some(previous) => Some(identity_of(previous)?),
                None => None,
            };
            if identity_of(generation)? != expected && own_commit != Some(expected) {
                return Err(StoreError::Conflict("profile generation conflict".into()).into());
            }
        }
        // Check independent lease/profile/storage authority before reporting only expiry.
        // The transaction grants no authority and never renews any ceiling.
        tx.commit().await?;
        current.eligible(
            &binding.identity,
            lease.fencing_token,
            now,
            SessionLimits::default(),
        )?;
        Ok(())
    }

    /// Read exact generation metadata beneath the existing live session lease.
    ///
    /// # Errors
    /// Returns lease loss, missing binding, stale generation fence or repository failure.
    pub async fn load_session_binding(
        &self,
        lease: &SessionLease,
        tenant: TenantId,
    ) -> Result<SessionBindingV1, StoreError> {
        self.scope()?.authorize(tenant)?;
        let mut tx = self.begin_write().await?;
        lock_lease_on::<B>(tx.conn(), lease, tenant).await?;
        let binding = Self::stored_binding(tx.conn(), lease.session.id, tenant)
            .await?
            .ok_or_else(|| StoreError::Conflict("session_unavailable".into()))?;
        if binding.lease_fence != lease.fencing_token
            || binding.schema_version != 1
            || binding.generation == 0
            || binding.state_version == 0
            || binding.identity.tenant != tenant
            || binding.identity.run != lease.session.run
            || binding.identity.session != lease.session.id
            || binding.identity.principal != lease.session.role
        {
            return Err(StoreError::Conflict("session generation conflict".into()));
        }
        tx.commit().await?;
        Ok(binding)
    }

    /// Persist the observed egress pin once for an exact live session generation.
    /// Rechecking an equal pin never changes binding metadata or extends its lifetime.
    ///
    /// # Errors
    /// Returns lease loss, stale generation/owner, observed pin drift or repository failure.
    pub async fn check_session_egress_pin(
        &self,
        lease: &SessionLease,
        tenant: TenantId,
        generation: u64,
        pin: crawlx_core::hash::Digest,
    ) -> Result<(), StoreError> {
        self.scope()?.authorize(tenant)?;
        let generation_db = i64::try_from(generation)
            .map_err(|_| StoreError::Conflict("session generation conflict".into()))?;
        let mut tx = self.begin_write().await?;
        lock_lease_on::<B>(tx.conn(), lease, tenant).await?;
        let binding = Self::stored_binding(tx.conn(), lease.session.id, tenant)
            .await?
            .ok_or_else(|| StoreError::Conflict("session_unavailable".into()))?;
        if generation == 0
            || binding.schema_version != 1
            || binding.generation != generation
            || binding.lease_fence != lease.fencing_token
            || binding.identity.tenant != tenant
            || binding.identity.run != lease.session.run
            || binding.identity.session != lease.session.id
            || binding.identity.principal != lease.session.role
        {
            return Err(StoreError::Conflict("session generation conflict".into()));
        }
        stmt!(
            B,
            format!(
                "INSERT INTO session_egress_pins(session_id,generation,pin_digest) VALUES($1,$2,$3) {}",
                <B::Dialect as Dialect>::upsert_do_nothing(&["session_id", "generation"])
            )
        )
        .uuid(lease.session.id.0)
        .i64(generation_db)
        .bytes(pin.0.as_slice())
        .execute(tx.conn())
        .await?;
        let same = stmt!(
            B,
            "SELECT EXISTS(SELECT 1 FROM session_egress_pins \
             WHERE session_id=$1 AND generation=$2 AND pin_digest=$3) AS same"
        )
        .uuid(lease.session.id.0)
        .i64(generation_db)
        .bytes(pin.0.as_slice())
        .fetch_one(tx.conn())
        .await?
        .flag("same")?;
        if !same {
            return Err(StoreError::Conflict("session egress pin changed".into()));
        }
        tx.commit().await
    }

    /// Explicitly replace a health/usage-retired anonymous generation after confirmed cleanup.
    /// Authentication, persistent profiles, identity changes and expiry extension are forbidden.
    /// The caller must separately admit replacement demand under its finite rotation budget.
    ///
    /// # Errors
    /// Returns independent lease/repository failures or a typed generation conflict for stale
    /// metadata, authenticated roles, unresolved writes, changed identity or an elapsed deadline.
    pub async fn replace_retired_session_binding(
        &self,
        lease: &SessionLease,
        expected: &SessionBindingV1,
        identity: SessionIdentityV1,
        expires_at: Timestamp,
    ) -> Result<SessionBindingV1, SessionBindingVerificationError> {
        self.scope()?.authorize(expected.identity.tenant)?;
        let run = RunRepo::get(self, lease.session.run).await?;
        let anonymous = lease.session.role == crawlx_core::PrincipalId::anonymous()
            && (run.config.roles.is_empty()
                || run.config.roles.iter().any(|role| {
                    role.name == lease.session.role.0
                        && role.credential_ref.is_none()
                        && role.login_plan.is_none()
                }));
        let rotations = run
            .config
            .orchestration
            .as_ref()
            .map_or(0, |config| config.attempts.max_session_rotations);
        let mut tx = self.begin_write().await?;
        let now = lock_lease_on::<B>(tx.conn(), lease, expected.identity.tenant).await?;
        let current = Self::stored_binding(tx.conn(), lease.session.id, expected.identity.tenant)
            .await?
            .ok_or(SessionBindingError::GenerationConflict)?;
        if !anonymous
            || rotations == 0
            || current.generation > u64::from(rotations)
            || run.tenant != expected.identity.tenant
            || current != *expected
            || current.lease_fence != lease.fencing_token
            || current.identity.session != lease.session.id
            || current.identity.run != lease.session.run
            || current.identity.principal != lease.session.role
            || current.identity.profile.is_some()
            || !matches!(
                current.retirement,
                Some(RetirementReason::UsageLimit | RetirementReason::Unhealthy)
            )
        {
            return Err(SessionBindingError::GenerationConflict.into());
        }
        // Proposal insertion already locks the session row. Lock every retryable action
        // before inspecting status so an uncommitted intent cannot hide behind its old row.
        stmt!(
            B,
            format!(
                "SELECT action_id FROM actions WHERE session_id=$1 AND \
                 (status IN ('proposed','intended','unknown') OR \
                  (status='reconciled' AND reconcile_resolution='not_applied')) \
                 ORDER BY action_id{}",
                <B::Dialect as Dialect>::row_lock(RowLock::Update)
            )
        )
        .uuid(lease.session.id.0)
        .fetch_all(tx.conn())
        .await?;
        let blocked = stmt!(
            B,
            "SELECT (EXISTS(SELECT 1 FROM actions WHERE session_id=$1 \
             AND status IN ('intended','unknown')) OR \
             EXISTS(SELECT 1 FROM browser_profiles WHERE session_id=$1)) AS blocked"
        )
        .uuid(lease.session.id.0)
        .fetch_one(tx.conn())
        .await?
        .flag("blocked")?;
        if blocked {
            return Err(SessionBindingError::GenerationConflict.into());
        }
        let next = current.replace(identity, true, expires_at)?;
        next.eligible(&next.identity, lease.fencing_token, now, SessionLimits::default())?;
        Self::save_binding(tx.conn(), &next).await?;
        tx.commit().await?;
        Ok(next)
    }

    /// Compare-and-swap health/lifecycle metadata under the original session lease.
    ///
    /// # Errors
    /// Rejects stale fence/version, changed identity/generation, illegal state transitions
    /// and expiry extension. Generation replacement requires the explicit replacement API.
    pub async fn update_session_binding(
        &self,
        lease: &SessionLease,
        expected_version: u64,
        next: &SessionBindingV1,
    ) -> Result<(), StoreError> {
        self.scope()?.authorize(next.identity.tenant)?;
        let mut tx = self.begin_write().await?;
        lock_lease_on::<B>(tx.conn(), lease, next.identity.tenant).await?;
        let current = Self::stored_binding(tx.conn(), lease.session.id, next.identity.tenant)
            .await?
            .ok_or_else(|| StoreError::Conflict("session_unavailable".into()))?;
        let same = next.identity == current.identity && next.generation == current.generation;
        let legal_state = matches!(
            (current.state, next.state),
            (
                BindingState::Leased,
                BindingState::Leased | BindingState::Draining
            ) | (BindingState::Available, BindingState::Leased)
                | (
                    BindingState::Draining,
                    BindingState::Available
                        | BindingState::Draining
                        | BindingState::Retired
                        | BindingState::Quarantined
                )
                | (BindingState::Quarantined, BindingState::Retired)
        );
        if current.lease_fence != lease.fencing_token
            || next.lease_fence != lease.fencing_token
            || current.state_version != expected_version
            || current.state_version.checked_add(1) != Some(next.state_version)
            || !same
            || !legal_state
            || current.schema_version != 1
            || next.schema_version != current.schema_version
            || current.generation == 0
            || current.state_version == 0
            || next.identity.session != lease.session.id
            || next.identity.run != lease.session.run
            || next.identity.principal != lease.session.role
            || next.usage < current.usage
            || next.usage > current.usage.saturating_add(1)
            || next.health_errors.abs_diff(current.health_errors) > 1
            || (current.state != BindingState::Leased && next.usage != current.usage)
            || next
                .lifetime_expires_at
                .is_some_and(|ceiling| next.expires_at > ceiling)
            || (next.state == BindingState::Leased && next.retirement.is_some())
            || (matches!(
                next.state,
                BindingState::Draining | BindingState::Retired | BindingState::Quarantined
            ) && next.retirement.is_none())
            || (current.retirement.is_some()
                && next.state != BindingState::Available
                && next.retirement != current.retirement)
            || next.expires_at > current.expires_at
            || next.lifetime_expires_at != current.lifetime_expires_at
        {
            return Err(StoreError::Conflict("session generation conflict".into()));
        }
        Self::save_binding(tx.conn(), next).await?;
        tx.commit().await
    }
}
