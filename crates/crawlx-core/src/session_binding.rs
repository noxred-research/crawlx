//! Strict session identity, deterministic eligibility and explicit retirement.
//! The existing session lease fence is the only ownership authority.

use crate::hash::Digest;
use crate::{CrawlRunId, PrincipalId, SessionId, TenantId, Timestamp};
use serde::{Deserialize, Serialize};

/// Immutable security and acquisition identity of one session generation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct SessionIdentityV1 {
    /// Tenant whose secrets this generation may hold.
    pub tenant: TenantId,
    /// Run owning this generation and its secret lifetime.
    pub run: CrawlRunId,
    /// Role; authenticated roles are never pooled across principals.
    pub principal: PrincipalId,
    /// Strict session slot. A missing slot never falls back to another jar.
    pub session: SessionId,
    /// Acquisition settings, including launch profile and capabilities.
    pub acquisition: Digest,
    /// Backend family and actual browser build, not a requested version.
    pub backend_build: Digest,
    /// Approved egress identity, tier and sticky reference digest.
    pub egress: Digest,
    /// Fingerprint, locale, user-agent and cookie policy digest.
    pub identity_policy: Digest,
    /// Persistent profile identity, if any.
    pub profile: Option<Digest>,
}

impl SessionIdentityV1 {
    /// Bind an existing role slot to the measured acquisition identity.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        session: &crate::repo::CrawlSession,
        acquisition: Digest,
        backend_build: Digest,
        egress: Digest,
        identity_policy: Digest,
        profile: Option<Digest>,
    ) -> Self {
        Self {
            tenant,
            run: session.run,
            principal: session.role.clone(),
            session: session.id,
            acquisition,
            backend_build,
            egress,
            identity_policy,
            profile,
        }
    }
}

/// Lifecycle of a single strict binding.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BindingState {
    /// Eligible for leasing under its original identity.
    Available,
    /// Owned by the existing live session lease.
    Leased,
    /// No new effects; journal and resource cleanup must finish.
    Draining,
    /// Permanently unavailable generation.
    Retired,
    /// Resource death cannot be proved; capacity remains charged.
    Quarantined,
}

/// Explicit reason for retiring a generation.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RetirementReason {
    /// Owning run or binding deadline reached.
    Expired,
    /// Maximum charged uses reached.
    UsageLimit,
    /// Health error threshold reached; rate limiting alone is not a health error.
    Unhealthy,
    /// Operator revoked the binding.
    Revoked,
    /// Explicit drained replacement.
    Replaced,
}

/// Durable metadata. Secret bytes never enter this value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct SessionBindingV1 {
    /// Schema revision.
    pub schema_version: u8,
    /// Strict immutable identity.
    pub identity: SessionIdentityV1,
    /// Explicit replacement generation, starting at one.
    pub generation: u64,
    /// Existing session lease token; never an independent lock.
    pub lease_fence: i64,
    /// Compare-and-swap revision of this metadata.
    pub state_version: u64,
    /// Lifecycle.
    pub state: BindingState,
    /// Deadline, capped by the owning run.
    pub expires_at: Timestamp,
    /// Immutable absolute lifetime ceiling admitted at initial acquisition. Narrowing
    /// the exploration clock never erases it. Legacy rows without it cannot renew expiry.
    #[serde(default)]
    pub lifetime_expires_at: Option<Timestamp>,
    /// Charged acquisitions/effects.
    pub usage: u64,
    /// Consecutive health failures; successful uses reduce this by one.
    pub health_errors: u16,
    /// Retirement cause, when retired.
    pub retirement: Option<RetirementReason>,
}

/// Deployment-bounded deterministic eligibility policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct SessionLimits {
    /// Finite maximum uses.
    pub max_usage: u64,
    /// Finite consecutive-error ceiling.
    pub max_health_errors: u16,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_usage: 10_000,
            max_health_errors: 5,
        }
    }
}

/// Runtime profile lease subordinate to the same session fence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct ProfileLeaseV1 {
    /// Full tenant/run/principal/backend/egress binding, not a profile name alone.
    pub identity: SessionIdentityV1,
    /// Exact profile bundle generation.
    pub generation: u64,
    /// Authorized canonical origins, applied to documents and subresources.
    pub allowed_origins: std::collections::BTreeSet<String>,
    /// Existing session fence, never a second lock authority.
    pub lease_fence: i64,
    /// Profile-secret expiry, never extended by reuse.
    pub expires_at: Timestamp,
}

impl ProfileLeaseV1 {
    /// Project an approved profile onto the existing scheduler lease.
    #[must_use]
    pub fn new(
        identity: SessionIdentityV1,
        generation: u64,
        allowed_origins: std::collections::BTreeSet<String>,
        lease_fence: i64,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            identity,
            generation,
            allowed_origins,
            lease_fence,
            expires_at,
        }
    }
}

/// Fail-closed binding error. No variant authorizes a replacement jar.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error, Debug)]
#[non_exhaustive]
pub enum SessionBindingError {
    /// Strict identity mismatch, missing generation, or retired binding.
    #[error("session_unavailable")]
    Unavailable,
    /// The binding's absolute admitted ceiling elapsed; no new use is permitted.
    #[error("session binding expired")]
    Expired,
    /// Another existing session lease owns this binding.
    #[error("session lease fence lost")]
    LeaseLost,
    /// Replacement attempted before drain and journal reconciliation.
    #[error("session generation conflict")]
    GenerationConflict,
}

impl SessionBindingV1 {
    /// Construct the initial generation under an already granted lease.
    #[must_use]
    pub fn new(identity: SessionIdentityV1, lease_fence: i64, expires_at: Timestamp) -> Self {
        Self {
            schema_version: 1,
            identity,
            generation: 1,
            lease_fence,
            state_version: 1,
            state: BindingState::Leased,
            expires_at,
            lifetime_expires_at: Some(expires_at),
            usage: 0,
            health_errors: 0,
            retirement: None,
        }
    }

    /// Check strict identity, fence and finite policy before admitting a use.
    ///
    /// # Errors
    /// Returns unavailable for any mismatch/expiry/retirement, or lease loss for a stale fence.
    pub fn eligible(
        &self,
        identity: &SessionIdentityV1,
        fence: i64,
        now: Timestamp,
        limits: SessionLimits,
    ) -> Result<(), SessionBindingError> {
        if fence != self.lease_fence {
            return Err(SessionBindingError::LeaseLost);
        }
        if self.schema_version != 1
            || self.identity != *identity
            || self
                .lifetime_expires_at
                .is_some_and(|ceiling| self.expires_at > ceiling)
            || self.state != BindingState::Leased
            || self.retirement.is_some()
            || self.usage >= limits.max_usage
            || self.health_errors >= limits.max_health_errors
        {
            return Err(SessionBindingError::Unavailable);
        }
        if self.expires_at <= now {
            return Err(SessionBindingError::Expired);
        }
        Ok(())
    }

    /// Identity projection used by checkpoint restore; renewed lease fences may differ.
    #[must_use]
    pub fn checkpoint_identity(&self) -> (&SessionIdentityV1, u64) {
        (&self.identity, self.generation)
    }

    /// Charge one completed use and update health without rotating identity.
    ///
    /// # Errors
    /// Returns unavailable when counters overflow or this generation is not leased.
    pub fn record_use(
        &mut self,
        healthy: bool,
        now: Timestamp,
        limits: SessionLimits,
    ) -> Result<(), SessionBindingError> {
        self.eligible(&self.identity, self.lease_fence, now, limits)?;
        self.usage = self
            .usage
            .checked_add(1)
            .ok_or(SessionBindingError::Unavailable)?;
        self.state_version = self
            .state_version
            .checked_add(1)
            .ok_or(SessionBindingError::Unavailable)?;
        self.health_errors = if healthy {
            self.health_errors.saturating_sub(1)
        } else {
            self.health_errors.saturating_add(1)
        };
        if self.usage >= limits.max_usage || self.health_errors >= limits.max_health_errors {
            self.state = BindingState::Draining;
            self.retirement = Some(if self.usage >= limits.max_usage {
                RetirementReason::UsageLimit
            } else {
                RetirementReason::Unhealthy
            });
        }
        Ok(())
    }

    /// Replace only a retired, reconciled generation, never an uncertain in-flight write.
    ///
    /// # Errors
    /// Returns generation conflict unless the old generation is retired and ownership is unchanged.
    pub fn replace(
        &self,
        identity: SessionIdentityV1,
        journal_reconciled: bool,
        expires_at: Timestamp,
    ) -> Result<Self, SessionBindingError> {
        if !journal_reconciled
            || self.state != BindingState::Retired
            || identity.tenant != self.identity.tenant
            || identity.run != self.identity.run
            || identity.principal != self.identity.principal
            || identity.session != self.identity.session
        {
            return Err(SessionBindingError::GenerationConflict);
        }
        let mut next = Self::new(identity, self.lease_fence, expires_at.min(self.expires_at));
        next.lifetime_expires_at = self.lifetime_expires_at;
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or(SessionBindingError::GenerationConflict)?;
        next.state_version = self
            .state_version
            .checked_add(1)
            .ok_or(SessionBindingError::GenerationConflict)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn binding() -> SessionBindingV1 {
        let digest = Digest::of("fixture", b"identity");
        SessionBindingV1::new(
            SessionIdentityV1 {
                tenant: TenantId::new(),
                run: CrawlRunId::new(),
                principal: PrincipalId("reader".into()),
                session: SessionId::new(),
                acquisition: digest,
                backend_build: digest,
                egress: digest,
                identity_policy: digest,
                profile: None,
            },
            7,
            chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap(),
        )
    }

    #[test]
    fn strict_role_and_fence_never_fall_back_to_another_identity() {
        let binding = binding();
        let now = binding.expires_at - chrono::Duration::seconds(1);
        let mut wrong = binding.identity.clone();
        wrong.principal = PrincipalId("admin".into());
        assert_eq!(
            binding.eligible(&wrong, 7, now, SessionLimits::default()),
            Err(SessionBindingError::Unavailable)
        );
        assert_eq!(
            binding.eligible(&binding.identity, 6, now, SessionLimits::default()),
            Err(SessionBindingError::LeaseLost)
        );
    }

    #[test]
    fn expiry_is_typed_only_when_identity_fence_and_policy_still_match() {
        let mut binding = binding();
        let now = binding.expires_at;
        assert_eq!(
            binding.eligible(&binding.identity, 7, now, SessionLimits::default()),
            Err(SessionBindingError::Expired),
        );
        assert_eq!(
            binding.eligible(&binding.identity, 6, now, SessionLimits::default()),
            Err(SessionBindingError::LeaseLost),
        );
        let mut wrong = binding.identity.clone();
        wrong.principal = PrincipalId("other".into());
        assert_eq!(
            binding.eligible(&wrong, 7, now, SessionLimits::default()),
            Err(SessionBindingError::Unavailable),
        );
        binding.state = BindingState::Draining;
        assert_eq!(
            binding.eligible(&binding.identity, 7, now, SessionLimits::default()),
            Err(SessionBindingError::Unavailable),
        );
    }

    #[test]
    fn health_retirement_requires_confirmed_drain_before_replacement() {
        let mut binding = binding();
        let now = binding.expires_at - chrono::Duration::seconds(1);
        binding
            .record_use(
                false,
                now,
                SessionLimits {
                    max_usage: 5,
                    max_health_errors: 1,
                },
            )
            .unwrap();
        assert_eq!(binding.state, BindingState::Draining);
        assert!(binding
            .replace(binding.identity.clone(), true, binding.expires_at)
            .is_err());
        binding.state = BindingState::Retired;
        assert!(binding
            .replace(binding.identity.clone(), false, binding.expires_at)
            .is_err());
        assert_eq!(
            binding
                .replace(binding.identity.clone(), true, binding.expires_at)
                .unwrap()
                .generation,
            2
        );
    }
}
