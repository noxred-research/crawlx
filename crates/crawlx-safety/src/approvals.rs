//! Approval workflow.
//!
//! An approval binds to `(ActionContextKey id, risk class, parameters digest)`,
//! is single use, expires 24 h after issue (never past the run deadline) and
//! does not waive the kernel: the action is re-classified at execution and a
//! changed class or parameters void the approval ([`ApprovalError::Mismatch`]).
//!
//! The store is a synchronous trait because the kernel is pure and sync; the
//! PostgreSQL-backed implementation lives with the worker/storage wiring.

use chrono::Duration;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{ActionContextId, ApprovalId};
use crawlx_core::safety::RiskClass;
use crawlx_core::time::{Clock, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Approval lifetime (planning default).
pub const APPROVAL_TTL_HOURS: i64 = 24;

/// What a reviewer is asked to approve. `summary` is redacted by construction
/// (role, redacted name, route template, action kind, resource context,
/// value partition); it never carries untrusted text verbatim.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ApprovalRequest {
    /// Identifier of this approval.
    pub approval_id: ApprovalId,
    /// Action context the approval is bound to.
    pub action_key: ActionContextId,
    /// Risk class the approval is bound to.
    pub risk: RiskClass,
    /// Digest of the non-secret action parameters.
    pub params_digest: Digest,
    /// Redacted reviewer-facing summary of the action.
    pub summary: String,
    /// Issue time.
    pub created_at: Timestamp,
    /// Expiry time (issue + 24 h, capped by the run deadline).
    pub expires_at: Timestamp,
}

impl ApprovalRequest {
    /// New request expiring 24 h after `now`, capped by `run_deadline`.
    #[must_use]
    pub fn new(
        action_key: ActionContextId,
        risk: RiskClass,
        params_digest: Digest,
        summary: String,
        now: Timestamp,
        run_deadline: Option<Timestamp>,
    ) -> Self {
        let mut expires_at = now + Duration::hours(APPROVAL_TTL_HOURS);
        if let Some(d) = run_deadline {
            expires_at = expires_at.min(d);
        }
        Self {
            approval_id: ApprovalId::new(),
            action_key,
            risk,
            params_digest,
            summary,
            created_at: now,
            expires_at,
        }
    }

    /// Has the request expired at `now`?
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }
}

/// Lifecycle state of an approval.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ApprovalState {
    /// Waiting for a reviewer.
    Pending,
    /// A reviewer granted the approval; it is not yet spent.
    Approved {
        /// Reviewer identity.
        by: String,
        /// Time of the decision.
        at: Timestamp,
    },
    /// A reviewer denied the approval.
    Denied {
        /// Reviewer identity.
        by: String,
        /// Time of the decision.
        at: Timestamp,
    },
    /// The approval was spent by an admitted action.
    Consumed {
        /// Time of consumption.
        at: Timestamp,
    },
}

/// A request with its state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ApprovalRecord {
    /// The approval request.
    pub request: ApprovalRequest,
    /// Current lifecycle state.
    pub state: ApprovalState,
}

/// Approval failures. Every variant makes the kernel deny.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ApprovalError {
    /// No approval with this id exists.
    #[error("unknown approval {0}")]
    Unknown(ApprovalId),
    /// The approval was already approved, denied or consumed.
    #[error("approval already decided or consumed")]
    NotPending,
    /// The approval has not been granted yet.
    #[error("approval not granted")]
    NotApproved,
    /// A reviewer denied the approval.
    #[error("approval was denied")]
    Denied,
    /// The approval was already spent.
    #[error("approval already consumed")]
    Consumed,
    /// The approval expired.
    #[error("approval expired")]
    Expired,
    /// The approval is bound to a different action, risk class or parameters.
    #[error("approval does not match the action ({0})")]
    Mismatch(&'static str),
    /// The backing store could not be reached.
    #[error("approval store unavailable")]
    Unavailable,
}

impl ApprovalError {
    /// Stable rule identifier for audit rows.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::Unknown(_) => "approval.unknown",
            Self::NotPending => "approval.not_pending",
            Self::NotApproved => "approval.not_granted",
            Self::Denied => "approval.denied",
            Self::Consumed => "approval.already_consumed",
            Self::Expired => "approval.expired",
            Self::Mismatch(_) => "approval.mismatch",
            Self::Unavailable => "approval.store_unavailable",
        }
    }
}

/// Persistence for approvals. Implementations MUST make `consume` atomic:
/// two concurrent calls for the same id succeed at most once.
pub trait ApprovalStore: Send + Sync {
    /// Store a new pending request.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Unavailable`] when the backing store cannot persist
    /// the request.
    fn issue(&self, request: ApprovalRequest) -> Result<(), ApprovalError>;
    /// An unexpired, unconsumed, undenied request for the same binding.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Unavailable`] when the backing store cannot be read.
    fn find_open(
        &self,
        action_key: ActionContextId,
        risk: RiskClass,
        params_digest: &Digest,
        now: Timestamp,
    ) -> Result<Option<ApprovalRecord>, ApprovalError>;
    /// The record stored under `id`, if any.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Unavailable`] when the backing store cannot be read.
    fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRecord>, ApprovalError>;
    /// Reviewer approves a pending, unexpired request.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Unknown`] for an unknown id,
    /// [`ApprovalError::NotPending`] when already decided, and
    /// [`ApprovalError::Expired`] past the expiry.
    fn approve(&self, id: ApprovalId, by: &str, now: Timestamp) -> Result<(), ApprovalError>;
    /// Reviewer denies a pending request.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Unknown`] for an unknown id and
    /// [`ApprovalError::NotPending`] when already decided.
    fn deny(&self, id: ApprovalId, by: &str, now: Timestamp) -> Result<(), ApprovalError>;
    /// Atomically spend an approved approval for exactly this binding.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Unknown`], [`ApprovalError::Consumed`],
    /// [`ApprovalError::Denied`], [`ApprovalError::NotApproved`],
    /// [`ApprovalError::Expired`] or [`ApprovalError::Mismatch`] when the
    /// approval cannot be spent for this binding.
    fn consume(
        &self,
        id: ApprovalId,
        action_key: ActionContextId,
        risk: RiskClass,
        params_digest: &Digest,
        now: Timestamp,
    ) -> Result<(), ApprovalError>;
}

/// In-memory store (tests, single-process runs). Time comes from the injected
/// clock when callers use the `*_now` helpers.
pub struct InMemoryApprovalStore {
    clock: Arc<dyn Clock>,
    records: Mutex<BTreeMap<ApprovalId, ApprovalRecord>>,
}

impl InMemoryApprovalStore {
    /// Empty store reading time from `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            records: Mutex::new(BTreeMap::new()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, BTreeMap<ApprovalId, ApprovalRecord>> {
        // A poisoned map only means another thread panicked mid-update of a
        // plain BTreeMap; the data is still structurally valid.
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `approve` at the injected clock's current time.
    ///
    /// # Errors
    ///
    /// As [`ApprovalStore::approve`].
    pub fn approve_now(&self, id: ApprovalId, by: &str) -> Result<(), ApprovalError> {
        self.approve(id, by, self.clock.now())
    }

    /// `deny` at the injected clock's current time.
    ///
    /// # Errors
    ///
    /// As [`ApprovalStore::deny`].
    pub fn deny_now(&self, id: ApprovalId, by: &str) -> Result<(), ApprovalError> {
        self.deny(id, by, self.clock.now())
    }

    /// Number of stored approvals.
    #[must_use]
    pub fn len(&self) -> usize {
        self.guard().len()
    }

    /// Whether the store holds no approvals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.guard().is_empty()
    }
}

impl ApprovalStore for InMemoryApprovalStore {
    fn issue(&self, request: ApprovalRequest) -> Result<(), ApprovalError> {
        self.guard().insert(
            request.approval_id,
            ApprovalRecord {
                request,
                state: ApprovalState::Pending,
            },
        );
        Ok(())
    }

    fn find_open(
        &self,
        action_key: ActionContextId,
        risk: RiskClass,
        params_digest: &Digest,
        now: Timestamp,
    ) -> Result<Option<ApprovalRecord>, ApprovalError> {
        Ok(self
            .guard()
            .values()
            .find(|r| {
                r.request.action_key == action_key
                    && r.request.risk == risk
                    && r.request.params_digest == *params_digest
                    && !r.request.is_expired(now)
                    && matches!(r.state, ApprovalState::Pending | ApprovalState::Approved { .. })
            })
            .cloned())
    }

    fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRecord>, ApprovalError> {
        Ok(self.guard().get(&id).cloned())
    }

    fn approve(&self, id: ApprovalId, by: &str, now: Timestamp) -> Result<(), ApprovalError> {
        let mut g = self.guard();
        let rec = g.get_mut(&id).ok_or(ApprovalError::Unknown(id))?;
        if !matches!(rec.state, ApprovalState::Pending) {
            return Err(ApprovalError::NotPending);
        }
        if rec.request.is_expired(now) {
            return Err(ApprovalError::Expired);
        }
        rec.state = ApprovalState::Approved {
            by: by.to_owned(),
            at: now,
        };
        Ok(())
    }

    fn deny(&self, id: ApprovalId, by: &str, now: Timestamp) -> Result<(), ApprovalError> {
        let mut g = self.guard();
        let rec = g.get_mut(&id).ok_or(ApprovalError::Unknown(id))?;
        if !matches!(rec.state, ApprovalState::Pending) {
            return Err(ApprovalError::NotPending);
        }
        rec.state = ApprovalState::Denied {
            by: by.to_owned(),
            at: now,
        };
        Ok(())
    }

    fn consume(
        &self,
        id: ApprovalId,
        action_key: ActionContextId,
        risk: RiskClass,
        params_digest: &Digest,
        now: Timestamp,
    ) -> Result<(), ApprovalError> {
        let mut g = self.guard();
        let rec = g.get_mut(&id).ok_or(ApprovalError::Unknown(id))?;
        match rec.state {
            ApprovalState::Consumed { .. } => return Err(ApprovalError::Consumed),
            ApprovalState::Denied { .. } => return Err(ApprovalError::Denied),
            ApprovalState::Pending => return Err(ApprovalError::NotApproved),
            ApprovalState::Approved { .. } => {}
        }
        if rec.request.is_expired(now) {
            return Err(ApprovalError::Expired);
        }
        if rec.request.action_key != action_key {
            return Err(ApprovalError::Mismatch("action_key"));
        }
        if rec.request.risk != risk {
            return Err(ApprovalError::Mismatch("risk"));
        }
        if rec.request.params_digest != *params_digest {
            return Err(ApprovalError::Mismatch("params"));
        }
        rec.state = ApprovalState::Consumed { at: now };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::TimeZone as _;
    use crawlx_core::time::ManualClock;

    fn setup() -> (ManualClock, InMemoryApprovalStore) {
        let c = ManualClock::new(chrono::Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap());
        let s = InMemoryApprovalStore::new(Arc::new(c.clone()));
        (c, s)
    }

    fn key(n: u8) -> ActionContextId {
        ActionContextId([n; 16])
    }

    fn digest(s: &str) -> Digest {
        Digest::of("t", s.as_bytes())
    }

    fn issue(c: &ManualClock, s: &InMemoryApprovalStore) -> ApprovalRequest {
        let r = ApprovalRequest::new(
            key(1),
            RiskClass::Destructive,
            digest("p"),
            "summary".into(),
            c.now(),
            None,
        );
        s.issue(r.clone()).unwrap();
        r
    }

    #[test]
    fn approval_is_single_use() {
        let (c, s) = setup();
        let r = issue(&c, &s);
        s.approve_now(r.approval_id, "reviewer").unwrap();
        s.consume(
            r.approval_id,
            key(1),
            RiskClass::Destructive,
            &digest("p"),
            c.now(),
        )
        .unwrap();
        assert_eq!(
            s.consume(
                r.approval_id,
                key(1),
                RiskClass::Destructive,
                &digest("p"),
                c.now()
            ),
            Err(ApprovalError::Consumed)
        );
    }

    #[test]
    fn pending_or_denied_cannot_be_consumed() {
        let (c, s) = setup();
        let r = issue(&c, &s);
        assert_eq!(
            s.consume(
                r.approval_id,
                key(1),
                RiskClass::Destructive,
                &digest("p"),
                c.now()
            ),
            Err(ApprovalError::NotApproved)
        );
        s.deny_now(r.approval_id, "reviewer").unwrap();
        assert_eq!(
            s.consume(
                r.approval_id,
                key(1),
                RiskClass::Destructive,
                &digest("p"),
                c.now()
            ),
            Err(ApprovalError::Denied)
        );
    }

    #[test]
    fn expires_after_24_hours_via_injected_clock() {
        let (c, s) = setup();
        let r = issue(&c, &s);
        s.approve_now(r.approval_id, "reviewer").unwrap();
        c.advance_ms(24 * 3600 * 1000 - 1);
        assert!(s
            .find_open(key(1), RiskClass::Destructive, &digest("p"), c.now())
            .unwrap()
            .is_some());
        c.advance_ms(1);
        assert_eq!(
            s.consume(
                r.approval_id,
                key(1),
                RiskClass::Destructive,
                &digest("p"),
                c.now()
            ),
            Err(ApprovalError::Expired)
        );
        assert!(s
            .find_open(key(1), RiskClass::Destructive, &digest("p"), c.now())
            .unwrap()
            .is_none());
    }

    #[test]
    fn cannot_approve_after_expiry() {
        let (c, s) = setup();
        let r = issue(&c, &s);
        c.advance_ms(25 * 3600 * 1000);
        assert_eq!(
            s.approve_now(r.approval_id, "reviewer"),
            Err(ApprovalError::Expired)
        );
    }

    #[test]
    fn expiry_is_capped_by_run_deadline() {
        let now = chrono::Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
        let deadline = now + Duration::hours(2);
        let r = ApprovalRequest::new(
            key(1),
            RiskClass::Destructive,
            digest("p"),
            String::new(),
            now,
            Some(deadline),
        );
        assert_eq!(r.expires_at, deadline);
        let r2 = ApprovalRequest::new(
            key(1),
            RiskClass::Destructive,
            digest("p"),
            String::new(),
            now,
            None,
        );
        assert_eq!(r2.expires_at, now + Duration::hours(24));
    }

    #[test]
    fn binding_mismatch_voids_approval_without_spending_it() {
        let (c, s) = setup();
        let r = issue(&c, &s);
        s.approve_now(r.approval_id, "reviewer").unwrap();
        assert_eq!(
            s.consume(
                r.approval_id,
                key(2),
                RiskClass::Destructive,
                &digest("p"),
                c.now()
            ),
            Err(ApprovalError::Mismatch("action_key"))
        );
        assert_eq!(
            s.consume(
                r.approval_id,
                key(1),
                RiskClass::SecurityChange,
                &digest("p"),
                c.now()
            ),
            Err(ApprovalError::Mismatch("risk"))
        );
        assert_eq!(
            s.consume(
                r.approval_id,
                key(1),
                RiskClass::Destructive,
                &digest("q"),
                c.now()
            ),
            Err(ApprovalError::Mismatch("params"))
        );
        // still spendable for the right binding
        s.consume(
            r.approval_id,
            key(1),
            RiskClass::Destructive,
            &digest("p"),
            c.now(),
        )
        .unwrap();
    }

    #[test]
    fn unknown_id_is_an_error() {
        let (c, s) = setup();
        let id = ApprovalId::new();
        assert_eq!(s.approve_now(id, "x"), Err(ApprovalError::Unknown(id)));
        assert_eq!(
            s.consume(id, key(1), RiskClass::Destructive, &digest("p"), c.now()),
            Err(ApprovalError::Unknown(id))
        );
    }

    #[test]
    fn double_decision_is_rejected() {
        let (c, s) = setup();
        let r = issue(&c, &s);
        s.approve_now(r.approval_id, "a").unwrap();
        assert_eq!(s.deny_now(r.approval_id, "b"), Err(ApprovalError::NotPending));
        assert_eq!(s.approve_now(r.approval_id, "b"), Err(ApprovalError::NotPending));
    }

    #[test]
    fn store_length_and_emptiness_follow_issued_requests() {
        let (c, s) = setup();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        issue(&c, &s);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
        s.issue(ApprovalRequest::new(
            key(2),
            RiskClass::Destructive,
            digest("p"),
            "summary".into(),
            c.now(),
            None,
        ))
        .unwrap();
        assert!(!s.is_empty());
        assert_eq!(s.len(), 2);
    }
}
