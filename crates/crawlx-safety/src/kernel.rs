//! The safety kernel: adjudication, sealed admission and live confirmation.
//!
//! * [`SafetyKernel::adjudicate`] classifies a proposal, applies the profile
//!   table, writes an audit entry and returns [`Adjudication`]. The only way
//!   to obtain an [`AdmittedAction`] is `Adjudication::Allow`; its fields are
//!   private and its seal can only be created in this module, so no other
//!   crate can fabricate one.
//! * [`SafetyKernel::confirm`] re-checks the admitted action against live
//!   facts right before the browser performs it.
//! * Fail closed: an invalid configuration refuses to construct, an audit
//!   or approval-store failure denies, and unknown inputs deny.
//!
//! The kernel is synchronous, does no I/O of its own and never depends on
//! model output: a [`ModelHint`] can only raise the class or ask for approval.

use crate::approvals::{ApprovalRequest, ApprovalState, ApprovalStore, InMemoryApprovalStore};
use crate::audit::{summarize, AuditEntry, AuditError, AuditPhase, AuditSink};
use crate::classify::{severity, Classification, Classifier, ScopeRules};
use crate::lexicon::Normalized;
use crate::profiles::{self, ProfileDecision, ProfileOptions, RecordNarrowing};
use crate::sinks::{requires_sink, TestSinks};
use crawlx_core::action::BrowserAction;
use crawlx_core::config::{DestructiveActions, ExternalCommunication, LaunchProfile, SafetyProfile};
use crawlx_core::hash::Digest;
use crawlx_core::identity::ActionKind;
use crawlx_core::ids::{ActionContextId, ApprovalId, SafetyDecisionId};
use crawlx_core::observation::{LiveTargetFacts, RuntimeLocator};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::{SafetyContext, SafetyGate};
use crawlx_core::safety::{ModelHint, RiskClass, SafetyDecision, SafetyVerdict};
use crawlx_core::secret::SecretOr;
use crawlx_core::time::{Clock, SystemClock, Timestamp};
use std::borrow::Cow;
use std::sync::Arc;
use url::Url;

/// Kernel construction parameters.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KernelConfig {
    /// The run's profile. A context asking for a *more* permissive profile is
    /// narrowed to this one.
    pub profile: SafetyProfile,
    /// `dynamic.launchProfile`. `stealth` with `read_only` is a construction
    /// error.
    pub launch_profile: LaunchProfile,
    /// The tenant has verified test sinks **and** the run opted in
    /// (`safety.externalCommunication = test_sinks`).
    pub has_test_sinks: bool,
    /// `safety.destructiveActions`.
    pub destructive_approval: DestructiveActions,
    /// Origin of the seed URL (scope root), e.g. `https://app.example.com`.
    pub seed_origin: String,
    /// Rule-set version recorded with every audit row.
    pub policy_version: u32,
}

/// Why a kernel could not be constructed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum KernelError {
    /// `stealth` launch profile combined with the `read_only` safety profile.
    #[error("profile_conflict: dynamic.launchProfile=stealth requires test_environment or authorized_security_test")]
    StealthRequiresWritableProfile,
    /// The seed origin is not an `http(s)` URL with a host.
    #[error("seed origin {0:?} is not an http(s) URL")]
    InvalidSeedOrigin(String),
}

/// Live re-confirmation failed; the browser must not perform the action.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SafetyDenied {
    /// Live role/name/href no longer match what was classified.
    #[error("live role/name/href no longer match what was classified")]
    IdentityChanged,
    /// The current URL is outside the crawl scope.
    #[error("current URL is outside the crawl scope")]
    ScopeExit,
    /// Live evidence raised the risk class above the admitted one.
    #[error("live evidence raised risk from {admitted:?} to {live:?}")]
    RiskRaised {
        /// Class the action was admitted under.
        admitted: RiskClass,
        /// Class derived from the live facts.
        live: RiskClass,
    },
    /// Live evidence tightened the decision relative to admission.
    #[error("live evidence tightened the decision from {admitted:?} to {live:?}")]
    DecisionTightened {
        /// Decision at admission.
        admitted: SafetyDecision,
        /// Decision derived from the live facts.
        live: SafetyDecision,
    },
}

impl SafetyDenied {
    /// Stable rule identifier for audit rows.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::IdentityChanged => "confirm.identity_changed",
            Self::ScopeExit => "confirm.scope_exit",
            Self::RiskRaised { .. } => "confirm.risk_raised",
            Self::DecisionTightened { .. } => "confirm.decision_tightened",
        }
    }
}

/// Per-call inputs beyond the proposal and context.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AdjudicateOptions {
    /// Raise-only model hint.
    pub hint: ModelHint,
    /// Present an approval that a reviewer granted for this action.
    pub approval: Option<ApprovalId>,
}

/// Outcome of [`SafetyKernel::adjudicate`]. The result is moved once to the
/// caller; boxing `AdmittedAction` would change the public shape
/// (`Allow(AdmittedAction)`) for no benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Adjudication {
    /// The action is admitted; the only way to obtain an [`AdmittedAction`].
    Allow(AdmittedAction),
    /// The action is denied.
    Deny(SafetyVerdict),
    /// A reviewer must approve first; carries the pending request.
    ApprovalRequired(SafetyVerdict, ApprovalRequest),
}

impl Adjudication {
    /// The verdict. Every outcome has one.
    #[must_use]
    pub const fn verdict(&self) -> &SafetyVerdict {
        match self {
            Self::Allow(a) => &a.verdict,
            Self::Deny(v) | Self::ApprovalRequired(v, _) => v,
        }
    }

    /// The decision. Every outcome has one.
    #[must_use]
    pub const fn decision(&self) -> SafetyDecision {
        self.verdict().decision
    }
}

/// Private constructor token: only this module can create one.
#[derive(Debug)]
struct Seal;

/// An action the kernel allowed. Fields are private and the seal is
/// unconstructible elsewhere, so this type cannot be built outside
/// `adjudicate`.
///
/// ```compile_fail
/// use crawlx_safety::AdmittedAction;
/// fn forge(p: crawlx_core::ActionProposal) -> AdmittedAction {
///     AdmittedAction { proposal: p }
/// }
/// ```
#[derive(Debug)]
pub struct AdmittedAction {
    proposal: ActionProposal,
    decision: SafetyDecisionId,
    _seal: Seal,
    verdict: SafetyVerdict,
    admitted_risk: RiskClass,
    hint: ModelHint,
    base_decision: SafetyDecision,
    identity: Digest,
    context: SafetyContext,
}

impl AdmittedAction {
    /// The proposal that was admitted.
    #[must_use]
    pub const fn proposal(&self) -> &ActionProposal {
        &self.proposal
    }

    /// The `safety_decisions` row this admission rests on.
    #[must_use]
    pub const fn decision(&self) -> SafetyDecisionId {
        self.decision
    }

    /// The browser action to perform.
    #[must_use]
    pub const fn browser_action(&self) -> &BrowserAction {
        &self.proposal.action
    }

    /// Primary target locator, if the action has one.
    #[must_use]
    pub fn locator(&self) -> Option<&RuntimeLocator> {
        self.proposal.action.target()
    }

    /// The verdict (`decision == Allow`) with its rule ids.
    #[must_use]
    pub const fn verdict(&self) -> &SafetyVerdict {
        &self.verdict
    }

    /// Class the action was admitted under.
    #[must_use]
    pub const fn risk(&self) -> RiskClass {
        self.admitted_risk
    }
}

/// Result of the table evaluation before approvals and auditing.
struct Evaluation {
    classification: Classification,
    risk: RiskClass,
    decision: SafetyDecision,
    rules: Vec<String>,
}

enum Resolved {
    Pending(ApprovalRequest),
    Consumed(ApprovalId),
    Denied(&'static str),
}

/// Extra deny rules evaluated after classification (tenant-specific policy).
/// Returns the rule names that apply; a non-empty result denies the action
/// and the names are appended to the verdict.
pub type RuleHook = dyn Fn(&ActionProposal, &SafetyContext) -> Vec<String> + Send + Sync;

/// The hard safety kernel.
///
/// Adjudication fails closed on a panic inside classification or a rule
/// hook: the panic is caught (`std::panic::catch_unwind`; the workspace keeps
/// `panic = "unwind"` in every profile for this and for the worker's
/// `Supervisor`), the verdict is `Deny` with rule `failclosed.kernel_panic`,
/// and the audit row is still written.
pub struct SafetyKernel {
    cfg: KernelConfig,
    seed: Url,
    classifier: Classifier,
    clock: Arc<dyn Clock>,
    approvals: Arc<dyn ApprovalStore>,
    audit: Option<Arc<dyn AuditSink>>,
    sinks: Option<TestSinks>,
    run_deadline: Option<Timestamp>,
    rule_hook: Option<Arc<RuleHook>>,
    record: Option<RecordNarrowing>,
}

impl SafetyKernel {
    /// Build a kernel on the wall clock with an in-memory approval store.
    ///
    /// # Errors
    ///
    /// [`KernelError::StealthRequiresWritableProfile`] for `stealth` with the
    /// `read_only` profile; [`KernelError::InvalidSeedOrigin`] when the seed
    /// origin is not an `http(s)` URL with a host.
    pub fn new(cfg: KernelConfig) -> Result<Self, KernelError> {
        Self::new_with_clock(cfg, Arc::new(SystemClock))
    }

    /// Build a kernel whose approval expiry and sink verification use `clock`.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn new_with_clock(cfg: KernelConfig, clock: Arc<dyn Clock>) -> Result<Self, KernelError> {
        if cfg.profile == SafetyProfile::ReadOnly && cfg.launch_profile == LaunchProfile::Stealth {
            return Err(KernelError::StealthRequiresWritableProfile);
        }
        let seed = Url::parse(cfg.seed_origin.trim())
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| KernelError::InvalidSeedOrigin(cfg.seed_origin.clone()))?;
        let approvals: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new(Arc::clone(&clock)));
        Ok(Self {
            cfg,
            seed,
            classifier: Classifier::default(),
            clock,
            approvals,
            audit: None,
            sinks: None,
            run_deadline: None,
            rule_hook: None,
            record: None,
        })
    }

    /// Use `store` for approvals.
    #[must_use]
    pub fn with_approval_store(mut self, store: Arc<dyn ApprovalStore>) -> Self {
        self.approvals = store;
        self
    }

    /// Write every verdict to `sink` before returning it.
    #[must_use]
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// The tenant's test sinks. External communication denies without a verified,
    /// unexpired sink of the required kind matching the observed destination.
    #[must_use]
    pub fn with_test_sinks(mut self, sinks: TestSinks) -> Self {
        self.sinks = Some(sinks);
        self
    }

    /// Whether this run opted in and has an unexpired verified sink now.
    #[must_use]
    pub fn has_verified_test_sinks(&self) -> bool {
        self.cfg.has_test_sinks
            && self
                .sinks
                .as_ref()
                .is_some_and(|sinks| sinks.any_verified(self.clock.now()))
    }

    /// Scope rules beyond the exact seed origin (`allowSubdomains`, extra hosts).
    #[must_use]
    pub fn with_scope(mut self, scope: ScopeRules) -> Self {
        self.classifier = Classifier::new(scope);
        self
    }

    /// Approvals never outlive the run deadline.
    #[must_use]
    pub fn with_run_deadline(mut self, deadline: Timestamp) -> Self {
        self.run_deadline = Some(deadline);
        self
    }

    /// Narrow the profile table by the run's authorization record (`permittedRiskClasses`,
    /// `approvalRequired`): a class the record does not permit is denied, a class
    /// it lists for approval needs a reviewer where the profile would allow it. The record only
    /// ever restricts; a kernel without one decides by the profile table alone.
    #[must_use]
    pub fn with_record_narrowing(mut self, record: RecordNarrowing) -> Self {
        self.record = Some(record);
        self
    }

    /// Tenant-specific deny rules evaluated on every classification, after the
    /// built-in classifier: a non-empty result denies the action and the rule
    /// names are appended to the verdict. A hook that panics does not escape
    /// [`Self::adjudicate`] or [`SafetyGate::classify`]: the verdict is `Deny`
    /// with rule `failclosed.kernel_panic`.
    #[must_use]
    pub fn with_rule_hook(mut self, hook: Arc<RuleHook>) -> Self {
        self.rule_hook = Some(hook);
        self
    }

    /// The configuration the kernel was built with.
    #[must_use]
    pub const fn config(&self) -> &KernelConfig {
        &self.cfg
    }

    /// Rule-set version recorded with every audit row.
    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.cfg.policy_version
    }

    /// The approval store reviewers decide on.
    #[must_use]
    pub fn approvals(&self) -> &Arc<dyn ApprovalStore> {
        &self.approvals
    }

    /// Evaluate `p`. `Allow` carries the only constructible [`AdmittedAction`].
    #[must_use]
    pub fn adjudicate(&self, p: ActionProposal, c: &SafetyContext) -> Adjudication {
        self.adjudicate_with(p, c, AdjudicateOptions::default())
    }

    /// [`Self::adjudicate`] with a model hint and/or a granted approval.
    #[must_use]
    pub fn adjudicate_with(
        &self,
        p: ActionProposal,
        c: &SafetyContext,
        opts: AdjudicateOptions,
    ) -> Adjudication {
        let now = self.clock.now();
        let c = self.effective_context(c);
        let action_key = p.key.id();
        let Some(ev) = self.evaluate_caught(&p, &c, opts.hint, now) else {
            return Adjudication::Deny(self.deny_panic(&p, &c, action_key, now));
        };
        let summary = summarize(&p.key, ev.risk, &ev.classification, &c);

        let mut rules = ev.rules;
        let mut decision = ev.decision;
        let mut approval = None;
        let mut pending = None;
        if decision == SafetyDecision::ApprovalRequired {
            match self.resolve_approval(&p, ev.risk, opts.approval, action_key, &summary, now) {
                Resolved::Pending(req) => {
                    approval = Some(req.approval_id);
                    pending = Some(req);
                    rules.push("approval.pending".to_owned());
                }
                Resolved::Consumed(id) => {
                    decision = SafetyDecision::Allow;
                    approval = Some(id);
                    rules.push("approval.consumed".to_owned());
                }
                Resolved::Denied(rule) => {
                    decision = SafetyDecision::Deny;
                    rules.push(rule.to_owned());
                }
            }
        }

        let verdict = SafetyVerdict {
            decision_id: SafetyDecisionId::new(),
            decision,
            risk_class: ev.risk,
            rules,
            approval,
        };
        let entry = AuditEntry {
            verdict: verdict.clone(),
            phase: AuditPhase::Adjudicate,
            policy_version: self.cfg.policy_version,
            profile: profiles::narrow(self.cfg.profile, c.profile),
            action_kind: p.action.kind(),
            action_key,
            summary,
            at: now,
        };
        if self.record(entry).is_err() {
            return Adjudication::Deny(audit_failure(verdict));
        }

        match (decision, pending) {
            (SafetyDecision::Allow, _) => Adjudication::Allow(AdmittedAction {
                decision: verdict.decision_id,
                identity: identity_digest(&c.target),
                admitted_risk: ev.risk,
                hint: opts.hint,
                base_decision: ev.decision,
                context: c.into_owned(),
                proposal: p,
                _seal: Seal,
                verdict,
            }),
            (SafetyDecision::ApprovalRequired, Some(req)) => Adjudication::ApprovalRequired(verdict, req),
            (SafetyDecision::Deny, _) => Adjudication::Deny(verdict),
            (SafetyDecision::ApprovalRequired, None) => {
                // Unreachable by construction (`pending` is set whenever the
                // decision stays `ApprovalRequired`); fail closed regardless.
                let mut v = verdict;
                v.decision = SafetyDecision::Deny;
                v.rules.push("failclosed.no_approval_request".to_owned());
                Adjudication::Deny(v)
            }
        }
    }

    /// Re-check an admitted action against the live target just before the
    /// browser performs it (after `BrowserContext::revalidate`):
    ///
    /// 1. role/name/href still match what was classified (identity digest),
    /// 2. the current URL is in scope,
    /// 3. classification re-run on the live facts does not exceed the
    ///    admitted class.
    ///
    /// # Errors
    ///
    /// A [`SafetyDenied`] variant describing which live check failed; the
    /// browser must then not perform the action.
    pub fn confirm(&self, a: &AdmittedAction, live: &LiveTargetFacts) -> Result<(), SafetyDenied> {
        let result = self.confirm_inner(a, live);
        if let Err(e) = &result {
            let verdict = SafetyVerdict {
                decision_id: SafetyDecisionId::new(),
                decision: SafetyDecision::Deny,
                risk_class: match e {
                    SafetyDenied::RiskRaised { live, .. } => *live,
                    SafetyDenied::ScopeExit => RiskClass::OutOfScope,
                    SafetyDenied::DecisionTightened { .. } => a.admitted_risk,
                    SafetyDenied::IdentityChanged => a.admitted_risk,
                },
                rules: vec![e.rule().to_owned()],
                approval: None,
            };
            // The action is already denied; a failing sink cannot make it less so.
            let _ = self.record(AuditEntry {
                verdict,
                phase: AuditPhase::Confirm,
                policy_version: self.cfg.policy_version,
                profile: profiles::narrow(self.cfg.profile, a.context.profile),
                action_kind: a.proposal.action.kind(),
                action_key: a.proposal.key.id(),
                summary: format!("confirm denied: {e}"),
                at: self.clock.now(),
            });
        }
        result
    }

    /// Verdict for an input the kernel cannot interpret (unknown action kind,
    /// unknown role string, undecodable enum): always `Deny` (fail closed).
    /// `what` names the offending field and is a static string, never
    /// page text.
    #[must_use]
    pub fn deny_unknown(&self, what: &'static str) -> SafetyVerdict {
        let verdict = SafetyVerdict {
            decision_id: SafetyDecisionId::new(),
            decision: SafetyDecision::Deny,
            risk_class: RiskClass::Unclassified,
            rules: vec!["failclosed.unknown_input".to_owned(), what.to_owned()],
            approval: None,
        };
        // Best effort: the verdict is Deny whether or not the row is written.
        let _ = self.record(AuditEntry {
            verdict: verdict.clone(),
            phase: AuditPhase::Adjudicate,
            policy_version: self.cfg.policy_version,
            profile: self.cfg.profile,
            action_kind: ActionKind::Click,
            action_key: ActionContextId([0; 16]),
            summary: format!("unknown input: {what}"),
            at: self.clock.now(),
        });
        verdict
    }

    // ---- internals -----------------------------------------------------

    /// The kernel's own configuration is authoritative for the seed origin.
    fn effective_context<'a>(&self, c: &'a SafetyContext) -> Cow<'a, SafetyContext> {
        if c.seed_origin == self.cfg.seed_origin {
            Cow::Borrowed(c)
        } else {
            let mut owned = c.clone();
            owned.seed_origin.clone_from(&self.cfg.seed_origin);
            Cow::Owned(owned)
        }
    }

    fn record(&self, entry: AuditEntry) -> Result<(), AuditError> {
        match &self.audit {
            Some(sink) => sink.record(entry),
            None => Ok(()),
        }
    }

    fn evaluate(&self, p: &ActionProposal, c: &SafetyContext, hint: ModelHint, now: Timestamp) -> Evaluation {
        let classification = self.classifier.classify(p, c);
        let mut rules: Vec<String> = classification.rules.iter().map(|r| (*r).to_owned()).collect();

        let risk = profiles::raise(classification.risk, hint.risk_floor);
        if risk != profiles::raise(classification.risk, None) {
            rules.push("hint.model_floor".to_owned());
        }

        let profile = profiles::narrow(self.cfg.profile, c.profile);
        if profile != self.cfg.profile || profile != c.profile {
            rules.push("profile.narrowed".to_owned());
        }

        let opted_in = self.cfg.has_test_sinks && c.has_test_sinks;
        let destination = c
            .target
            .attributes
            .get("form-action")
            .map(String::as_str)
            .or(c.target.href.as_deref());
        let kind = if destination.is_some_and(|url| url.starts_with("sms:")) {
            crate::sinks::SinkKind::Sms
        } else {
            requires_sink(RiskClass::ExternalCommunication, c.form_hint.as_deref())
                .unwrap_or(crate::sinks::SinkKind::Email)
        };
        let sink_verified = opted_in
            && self
                .sinks
                .as_ref()
                .is_some_and(|sinks| sinks.permits(kind, destination, &c.target.current_url, now));
        let opts = ProfileOptions {
            destructive: if self.cfg.destructive_approval == DestructiveActions::Approval
                && c.destructive_approval_allowed
            {
                DestructiveActions::Approval
            } else {
                DestructiveActions::Deny
            },
            external: if opted_in {
                ExternalCommunication::TestSinks
            } else {
                ExternalCommunication::Deny
            },
            sink_verified,
        };

        // Every class that any signal or hint points at is decided and the
        // strictest decision wins, so extra evidence or a hint can never
        // relax the outcome (the class severity order alone is not a
        // strictness order: `financial_transaction` denies where
        // `destructive` asks for approval under `test_environment`).
        // Ties go to the more severe class, whose rules are reported.
        let mut classes: Vec<RiskClass> = classification.evidence.signals.iter().map(|s| s.class).collect();
        classes.push(risk);
        classes.extend(p.hinted_risk);
        classes.extend(hint.risk_floor);
        classes.sort_by_key(|cl| severity(*cl));
        classes.dedup();
        let kind = p.action.kind();
        let mut chosen: Option<ProfileDecision> = None;
        for class in classes {
            let mut d = profiles::decide(class, profile, kind, &opts);
            if let Some(record) = &self.record {
                d = profiles::narrow_by_record(d, class, record);
            }
            if chosen
                .as_ref()
                .is_none_or(|cur| profiles::strictness(d.decision) >= profiles::strictness(cur.decision))
            {
                chosen = Some(d);
            }
        }
        let pd = chosen.unwrap_or_else(|| {
            let d = profiles::decide(risk, profile, kind, &opts);
            match &self.record {
                Some(record) => profiles::narrow_by_record(d, risk, record),
                None => d,
            }
        });
        rules.extend(pd.rules);
        let (mut decision, hint_rule) = profiles::apply_hint_decision(pd.decision, hint);
        if let Some(r) = hint_rule {
            rules.push(r.to_owned());
        }
        if let Some(hook) = &self.rule_hook {
            let extra = hook(p, c);
            if !extra.is_empty() {
                decision = SafetyDecision::Deny;
                rules.extend(extra);
            }
        }
        if decision == SafetyDecision::Allow
            && risk == RiskClass::PersistentWriteOtherPrincipal
            && profile == SafetyProfile::AuthorizedSecurityTest
        {
            rules.push("probe.cross_principal".to_owned());
        }
        Evaluation {
            classification,
            risk,
            decision,
            rules,
        }
    }

    /// [`Self::evaluate`] with panics caught: `None` when classification or
    /// the rule hook panicked. The kernel holds no state a half-run
    /// evaluation could corrupt (the classifier and hook only read), so the
    /// unwind-safety assertion is sound.
    fn evaluate_caught(
        &self,
        p: &ActionProposal,
        c: &SafetyContext,
        hint: ModelHint,
        now: Timestamp,
    ) -> Option<Evaluation> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.evaluate(p, c, hint, now))).ok()
    }

    /// `Deny` after a panic inside evaluation, audited under
    /// `failclosed.kernel_panic`. The panic payload is never recorded: it may
    /// quote page text.
    fn deny_panic(
        &self,
        p: &ActionProposal,
        c: &SafetyContext,
        action_key: ActionContextId,
        now: Timestamp,
    ) -> SafetyVerdict {
        let verdict = SafetyVerdict {
            decision_id: SafetyDecisionId::new(),
            decision: SafetyDecision::Deny,
            risk_class: RiskClass::Unclassified,
            rules: vec!["failclosed.kernel_panic".to_owned()],
            approval: None,
        };
        // Best effort: the verdict is Deny whether or not the row is written.
        let _ = self.record(AuditEntry {
            verdict: verdict.clone(),
            phase: AuditPhase::Adjudicate,
            policy_version: self.cfg.policy_version,
            profile: profiles::narrow(self.cfg.profile, c.profile),
            action_kind: p.action.kind(),
            action_key,
            summary: "kernel panic during adjudication".to_owned(),
            at: now,
        });
        verdict
    }

    fn resolve_approval(
        &self,
        p: &ActionProposal,
        risk: RiskClass,
        presented: Option<ApprovalId>,
        action_key: ActionContextId,
        summary: &str,
        now: Timestamp,
    ) -> Resolved {
        let params = params_digest(&p.action);
        let Some(id) = presented else {
            return match self.approvals.find_open(action_key, risk, &params, now) {
                Ok(Some(rec)) => Resolved::Pending(rec.request),
                Ok(None) => {
                    let req = ApprovalRequest::new(
                        action_key,
                        risk,
                        params,
                        summary.to_owned(),
                        now,
                        self.run_deadline,
                    );
                    match self.approvals.issue(req.clone()) {
                        Ok(()) => Resolved::Pending(req),
                        Err(e) => Resolved::Denied(e.rule()),
                    }
                }
                Err(e) => Resolved::Denied(e.rule()),
            };
        };
        let rec = match self.approvals.get(id) {
            Ok(Some(rec)) => rec,
            Ok(None) => return Resolved::Denied("approval.unknown"),
            Err(e) => return Resolved::Denied(e.rule()),
        };
        match rec.state {
            ApprovalState::Pending => {
                if rec.request.is_expired(now) {
                    Resolved::Denied("approval.expired")
                } else if rec.request.action_key == action_key
                    && rec.request.risk == risk
                    && rec.request.params_digest == params
                {
                    Resolved::Pending(rec.request)
                } else {
                    Resolved::Denied("approval.mismatch")
                }
            }
            ApprovalState::Approved { .. } => {
                match self.approvals.consume(id, action_key, risk, &params, now) {
                    Ok(()) => Resolved::Consumed(id),
                    Err(e) => Resolved::Denied(e.rule()),
                }
            }
            ApprovalState::Denied { .. } => Resolved::Denied("approval.denied"),
            ApprovalState::Consumed { .. } => Resolved::Denied("approval.already_consumed"),
        }
    }

    fn confirm_inner(&self, a: &AdmittedAction, live: &LiveTargetFacts) -> Result<(), SafetyDenied> {
        if a.proposal.action.target().is_some() && identity_digest(live) != a.identity {
            return Err(SafetyDenied::IdentityChanged);
        }
        let closing = a.proposal.action.kind() == ActionKind::CloseTab;
        if !closing {
            let in_scope = Url::parse(live.current_url.trim())
                .ok()
                .is_some_and(|u| self.classifier.scope().contains(&self.seed, &u));
            if !in_scope {
                return Err(SafetyDenied::ScopeExit);
            }
        }
        let mut ctx = a.context.clone();
        ctx.seed_origin.clone_from(&self.cfg.seed_origin);
        ctx.target = live.clone();
        ctx.form_hint.clone_from(&live.observed_form_hint);
        let ev = self.evaluate(&a.proposal, &ctx, a.hint, self.clock.now());
        if severity(ev.risk) > severity(a.admitted_risk) {
            return Err(SafetyDenied::RiskRaised {
                admitted: a.admitted_risk,
                live: ev.risk,
            });
        }
        if profiles::strictness(ev.decision) > profiles::strictness(a.base_decision) {
            return Err(SafetyDenied::DecisionTightened {
                admitted: a.base_decision,
                live: ev.decision,
            });
        }
        Ok(())
    }
}

impl SafetyGate for SafetyKernel {
    /// Verdict for arbiter-time filtering. No audit write, request creation or consumption.
    /// A matching granted approval makes a proposal rankable, but admission must still
    /// atomically consume that exact approval and perform the ordinary live confirmation.
    fn classify(&self, p: &ActionProposal, c: &SafetyContext) -> SafetyVerdict {
        let c = self.effective_context(c);
        let now = self.clock.now();
        match self.evaluate_caught(p, &c, ModelHint::default(), now) {
            Some(ev) => {
                let mut verdict = SafetyVerdict {
                    decision_id: SafetyDecisionId::new(),
                    decision: ev.decision,
                    risk_class: ev.risk,
                    rules: ev.rules,
                    approval: None,
                };
                if verdict.decision == SafetyDecision::ApprovalRequired {
                    let params = params_digest(&p.action);
                    match self.approvals.find_open(p.key.id(), ev.risk, &params, now) {
                        Ok(Some(record))
                            if matches!(record.state, ApprovalState::Approved { .. })
                                && !record.request.is_expired(now)
                                && record.request.action_key == p.key.id()
                                && record.request.risk == ev.risk
                                && record.request.params_digest == params =>
                        {
                            verdict.decision = SafetyDecision::Allow;
                            verdict.approval = Some(record.request.approval_id);
                            verdict.rules.push("approval.granted_preview".to_owned());
                        }
                        Err(error) => {
                            verdict.decision = SafetyDecision::Deny;
                            verdict.rules.push(error.rule().to_owned());
                        }
                        _ => {}
                    }
                }
                verdict
            }
            None => SafetyVerdict {
                decision_id: SafetyDecisionId::new(),
                decision: SafetyDecision::Deny,
                risk_class: RiskClass::Unclassified,
                rules: vec!["failclosed.kernel_panic".to_owned()],
                approval: None,
            },
        }
    }
}

fn audit_failure(mut verdict: SafetyVerdict) -> SafetyVerdict {
    verdict.decision = SafetyDecision::Deny;
    verdict.approval = None;
    verdict.rules.push("failclosed.audit_unavailable".to_owned());
    verdict
}

fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Digest of what the kernel looked at when it classified: role, name with
/// counters stripped, tag and href without fragment.
fn identity_digest(f: &LiveTargetFacts) -> Digest {
    let mut buf = Vec::with_capacity(128);
    push_field(
        &mut buf,
        f.role
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_bytes(),
    );
    push_field(
        &mut buf,
        Normalized::new(f.name.as_deref().unwrap_or_default())
            .without_digits()
            .as_bytes(),
    );
    push_field(
        &mut buf,
        f.tag
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_bytes(),
    );
    let href = f.href.as_deref().unwrap_or_default().trim();
    push_field(&mut buf, href.split('#').next().unwrap_or_default().as_bytes());
    Digest::of("crawlx/safety/live-identity/v1", &buf)
}

/// Digest of the non-secret, non-runtime parameters an approval binds to.
fn params_digest(a: &BrowserAction) -> Digest {
    let mut buf = Vec::with_capacity(64);
    push_field(&mut buf, a.kind().as_str().as_bytes());
    match a {
        BrowserAction::Click {
            button, modifiers, ..
        } => {
            push_field(&mut buf, format!("{button:?}{modifiers:?}").as_bytes());
        }
        BrowserAction::Type {
            value, clear_first, ..
        } => {
            push_field(&mut buf, &[u8::from(*clear_first)]);
            match value {
                SecretOr::Plain(v) => push_field(
                    &mut buf,
                    &Digest::of("crawlx/safety/typed-value/v1", v.as_bytes()).0,
                ),
                SecretOr::Secret(_) => push_field(&mut buf, b"secret"),
            }
        }
        BrowserAction::Select { options, .. } => {
            for o in options {
                push_field(&mut buf, format!("{o:?}").as_bytes());
            }
        }
        BrowserAction::SetChecked { checked, .. } => push_field(&mut buf, &[u8::from(*checked)]),
        BrowserAction::SetRange { value, .. } => push_field(&mut buf, &value.to_bits().to_le_bytes()),
        BrowserAction::Upload { fixture, .. } => push_field(&mut buf, fixture.0.as_bytes()),
        BrowserAction::Scroll { delta, .. } => {
            push_field(&mut buf, &delta.dx.to_bits().to_le_bytes());
            push_field(&mut buf, &delta.dy.to_bits().to_le_bytes());
        }
        BrowserAction::Keys { sequence } => {
            for k in sequence {
                push_field(&mut buf, format!("{}{:?}", k.key, k.modifiers).as_bytes());
            }
        }
        BrowserAction::Navigate { url } => push_field(&mut buf, url.as_str().as_bytes()),
        BrowserAction::SwitchTab { tab } | BrowserAction::CloseTab { tab } => {
            push_field(&mut buf, tab.0.as_bytes())
        }
        BrowserAction::KeyboardActivate { .. }
        | BrowserAction::SolveCaptcha
        | BrowserAction::Hover { .. }
        | BrowserAction::Drag { .. }
        | BrowserAction::SyntheticClick { .. } => {}
    }
    Digest::of("crawlx/safety/action-params/v1", &buf)
}
