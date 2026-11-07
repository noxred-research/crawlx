//! Audit rows for every verdict.
//!
//! Each adjudication produces a [`SafetyVerdict`] with rule ids; the kernel
//! hands an [`AuditEntry`] to its [`AuditSink`] *before* it returns an
//! `AdmittedAction`. If the sink fails, the kernel denies (fail closed: "no
//! `safety_decisions` row, no mutation"). Summaries never embed untrusted text
//! verbatim: the accessible name and the route template are truncated and
//! hashed through [`crate::provenance::redact`].

use crate::classify::Classification;
use crate::provenance::{redact, Provenance};
use crawlx_core::config::SafetyProfile;
use crawlx_core::identity::{ActionContextKey, ActionKind};
use crawlx_core::ids::ActionContextId;
use crawlx_core::repo::SafetyContext;
use crawlx_core::safety::RiskClass;
use crawlx_core::safety::SafetyVerdict;
use crawlx_core::time::Timestamp;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Which kernel entry point produced the entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditPhase {
    /// `adjudicate` (or the `SafetyGate` path).
    Adjudicate,
    /// `confirm` on live facts.
    Confirm,
}

/// One `safety_decisions` row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuditEntry {
    /// The verdict this row records.
    pub verdict: SafetyVerdict,
    /// Kernel entry point that produced the verdict.
    pub phase: AuditPhase,
    /// Rule-set version (`KernelConfig::policy_version`).
    pub policy_version: u32,
    /// Safety profile in force when the verdict was made.
    pub profile: SafetyProfile,
    /// Kind of the adjudicated action.
    pub action_kind: ActionKind,
    /// Action context the verdict applies to.
    pub action_key: ActionContextId,
    /// Redacted human-readable summary (see [`summarize`]).
    pub summary: String,
    /// Time of the verdict.
    pub at: Timestamp,
}

/// Audit persistence failure.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AuditError {
    /// The sink could not persist the entry; carries the failure reason.
    #[error("audit sink unavailable: {0}")]
    Unavailable(String),
}

/// Destination for audit entries. Implementations MUST be durable (or must
/// buffer for a durable writer) before returning `Ok`.
pub trait AuditSink: Send + Sync {
    /// Persist `entry`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Unavailable`] when the entry could not be recorded; the
    /// kernel then denies the action.
    fn record(&self, entry: AuditEntry) -> Result<(), AuditError>;
}

/// In-memory sink for tests and single-process runs.
#[derive(Default)]
pub struct MemoryAuditLog {
    entries: Mutex<Vec<AuditEntry>>,
}

impl MemoryAuditLog {
    /// Empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn guard(&self) -> MutexGuard<'_, Vec<AuditEntry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Snapshot of all recorded entries, oldest first.
    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.guard().clone()
    }

    /// Number of recorded entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.guard().len()
    }

    /// Whether no entry was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.guard().is_empty()
    }

    /// The entry recorded for `decision_id`, if any.
    #[must_use]
    pub fn find(&self, decision_id: crawlx_core::ids::SafetyDecisionId) -> Option<AuditEntry> {
        self.guard()
            .iter()
            .find(|e| e.verdict.decision_id == decision_id)
            .cloned()
    }
}

impl AuditSink for MemoryAuditLog {
    fn record(&self, entry: AuditEntry) -> Result<(), AuditError> {
        self.guard().push(entry);
        Ok(())
    }
}

/// Build the redacted summary stored with a verdict and shown to reviewers:
/// action kind, risk class, role, redacted name, redacted route template,
/// principal, resource context and value partition. Nothing page-derived
/// appears verbatim.
#[must_use]
pub fn summarize(
    key: &ActionContextKey,
    risk: RiskClass,
    cls: &Classification,
    ctx: &SafetyContext,
) -> String {
    let route = redact(&key.route_template.0, Provenance::PageText);
    let name = cls
        .evidence
        .name
        .as_ref()
        .map_or_else(|| "none".to_owned(), ToString::to_string);
    format!(
        "kind={} risk={} role={} name={} route={} principal={} resource={} input={} profile={}",
        key.action_kind.as_str(),
        risk.as_str(),
        cls.evidence.role.as_deref().unwrap_or("none"),
        name,
        route,
        ctx.principal,
        key.resource_context.as_str(),
        key.input_class.0,
        ctx.profile.as_str(),
    )
}
