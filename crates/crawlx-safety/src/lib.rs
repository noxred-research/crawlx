//! crawlx-safety: independent hard safety kernel (see
//! `docs/design/safety-model.md`).
//!
//! Modules:
//! * [`classify`]: structural + multilingual side-effect classification.
//! * [`profiles`]: the `read_only` / `test_environment` /
//!   `authorized_security_test` decision table and raise-only model hints.
//! * [`approvals`]: single-use, 24 h approvals bound to an action context.
//! * [`sinks`]: verified test sinks for `external_communication`.
//! * [`provenance`]: `Untrusted<T>` tagging and audit redaction.
//! * [`audit`]: verdict audit entries; no admission without a row.
//! * [`kernel`]: `SafetyKernel`, sealed `AdmittedAction`, live `confirm`.
//!
//! The crate depends only on `crawlx-core` (scope decisions of `crawlx-policy` and
//! URL types of `crawlx-url` reach it through `crawlx-core` types); it must never depend on `crawlx-model`, strategies, graph or browser.

pub mod approvals;
pub mod audit;
pub mod classify;
pub mod kernel;
mod lexicon;
pub mod profiles;
pub mod provenance;
pub mod sinks;

pub use approvals::{
    ApprovalError, ApprovalRecord, ApprovalRequest, ApprovalState, ApprovalStore, InMemoryApprovalStore,
    APPROVAL_TTL_HOURS,
};
pub use audit::{AuditEntry, AuditError, AuditPhase, AuditSink, MemoryAuditLog};
pub use classify::{classify, severity, Classification, Classifier, Evidence, ScopeRules, Signal};
pub use kernel::{
    AdjudicateOptions, Adjudication, AdmittedAction, KernelConfig, KernelError, RuleHook, SafetyDenied,
    SafetyKernel,
};
pub use profiles::{
    narrow_by_record, risk_matrix_cell, risk_matrix_markdown, ProfileDecision, ProfileOptions,
    RecordNarrowing, MATRIX_CLASSES, MATRIX_PROFILES,
};
pub use provenance::{redact, Provenance, RedactedText, Untrusted};
pub use sinks::{requires_sink, SinkKind, SinkSpec, TestSinks};
