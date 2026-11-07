//! Actions driven from outside the exploration loop: a recorded login flow
//! ([`crate::login::run_recorded_login`]) and the caller's `actions[]` of a scrape
//! ([`crate::scrape::actions`]). Both propose one native [`BrowserAction`] at a time, name a
//! strategy for the journal, let the safety kernel adjudicate it and run it through the Session
//! Actor's per-action protocol, so a driven action is as journaled and as gated as one a
//! strategy chose.

use crate::actor::{DropReason, SessionHandle};
use crate::analysis::StateAnalyzer;
use crate::counters::{Attempt, Plane};
use crate::error::SessionError;
use crate::run::RunContext;
use crawlx_core::action::BrowserAction;
use crawlx_core::config::DestructiveActions;
use crawlx_core::counters::ActionStatus;
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ElementIdentityHash, InputClass, ResourceContext};
use crawlx_core::observation::{LiveTargetFacts, ObservationBundle, QuiescencePolicy};
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::{CrawlSession, DiscoveryOutcome, SafetyContext};
use crawlx_core::safety::RiskClass;
use crawlx_core::{Classify, ErrorClass};
use crawlx_safety::{Adjudication, SafetyKernel};

/// Why a driven action did not run to success.
#[derive(Debug)]
pub(crate) enum DriveFailure {
    /// The kernel refused it; the verdict row is journaled.
    Denied,
    /// The actor dropped it before touching the browser.
    Dropped(DropReason),
    /// The browser reported a failure; the outcome row says which.
    Failed,
    /// The actor or its stores failed.
    Session(SessionError),
}

impl From<SessionError> for DriveFailure {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

/// What the journal records about who proposed a driven action.
pub(crate) struct Attribution {
    /// `ActionProposal.strategy`.
    pub strategy: &'static str,
    /// `ActionProposal.strategy_version`.
    pub strategy_version: u32,
    /// Raise-only risk hint (the kernel classifies on the live facts first).
    pub hinted_risk: Option<RiskClass>,
    /// Human-readable line of the proposal; never page text or typed input.
    pub summary: String,
    /// Element identity: a digest of what the caller addressed.
    pub element: Digest,
    /// Input class of the action.
    pub input_class: InputClass,
}

/// Everything one driven action needs besides the action itself.
pub(crate) struct Driver<'a> {
    /// The session's actor.
    pub handle: &'a SessionHandle,
    /// The run.
    pub rc: &'a RunContext,
    /// The kernel whose verdict gates the action; also the one the actor re-checks against.
    pub kernel: &'a SafetyKernel,
    /// Session row the journal attributes the action to.
    pub session: &'a CrawlSession,
    /// Persists the observed state the action starts from.
    pub analyzer: &'a StateAnalyzer,
    /// Quiescence wait after the action.
    pub settle: QuiescencePolicy,
}

impl Driver<'_> {
    /// Adjudicate `action` against `facts` (the live target, or the page for keyboard input)
    /// and execute it through the actor.
    ///
    /// The state `bundle` shows is persisted first: T2 of the action references its cluster,
    /// and an action that leaves the page in the same cluster would otherwise point the
    /// journal at a cluster no store knows (`missing_state`).
    pub(crate) async fn drive(
        &self,
        bundle: &ObservationBundle,
        action: BrowserAction,
        mut facts: LiveTargetFacts,
        who: Attribution,
    ) -> Result<(), DriveFailure> {
        facts.observed_form_hint = action.target().and_then(|target| {
            crawlx_strategies::frontier::observed_form_hints(bundle).remove(&target.backend_node_id.0)
        });
        let analyzed = self.analyzer.analyze(bundle).await;
        self.rc
            .stores
            .states
            .put_state(&analyzed.state)
            .await
            .map_err(|e| DriveFailure::Session(SessionError::Store(e)))?;
        let cluster = analyzed.state.cluster;
        let proposal = ActionProposal {
            key: ActionContextKey {
                principal: self.session.role.clone(),
                route_template: bundle.route.template.clone(),
                element: ElementIdentityHash(who.element),
                action_kind: action.kind(),
                input_class: who.input_class,
                resource_context: ResourceContext::Own,
                state_cluster: cluster,
            },
            action,
            epoch: bundle.epoch,
            strategy: who.strategy,
            strategy_version: who.strategy_version,
            confidence: 1.0,
            expected: ExpectedEffect::default(),
            hinted_risk: who.hinted_risk,
            model_decision: None,
            summary: who.summary,
        };
        let crawl = &self.rc.crawl;
        let sc = SafetyContext {
            profile: crawl.safety.profile,
            has_test_sinks: self.kernel.has_verified_test_sinks(),
            destructive_approval_allowed: crawl.safety.destructive_actions == DestructiveActions::Approval,
            principal: self.session.role.clone(),
            seed_origin: self.rc.seed_origin(),
            in_scope: true,
            form_hint: facts.observed_form_hint.clone(),
            target: facts,
        };
        let admitted = match self.kernel.adjudicate(proposal.clone(), &sc) {
            Adjudication::Allow(a) => a,
            Adjudication::Deny(v) | Adjudication::ApprovalRequired(v, _) => {
                self.rc
                    .counters
                    .discovery(Plane::Interactions, DiscoveryOutcome::PolicyBlocked);
                // the verdict row shows what the kernel stopped, as the driver does
                if let Err(e) = self
                    .rc
                    .stores
                    .journal
                    .propose(self.rc.run, self.session.id, &proposal, &v)
                    .await
                {
                    tracing::warn!(error = %e, "denied driven action not journaled");
                }
                return Err(DriveFailure::Denied);
            }
        };
        self.rc
            .counters
            .discovery(Plane::Interactions, DiscoveryOutcome::Admitted);
        let outcome = match self.handle.execute(admitted, self.settle).await {
            Ok(outcome) => outcome,
            Err(error) => {
                let attempt = if error.class() == ErrorClass::OutcomeUnknown {
                    Attempt::UnknownOutcome
                } else {
                    Attempt::Failed
                };
                self.rc.counters.attempt(Plane::Interactions, attempt);
                return Err(error.into());
            }
        };
        if let Some(reason) = outcome.dropped {
            self.rc.counters.attempt(Plane::Interactions, Attempt::Abandoned);
            tracing::debug!(
                strategy = proposal.strategy,
                reason = DropReason::as_str(reason),
                "driven action dropped"
            );
            return Err(DriveFailure::Dropped(reason));
        }
        self.rc.counters.attempt(
            Plane::Interactions,
            if outcome.status == ActionStatus::Succeeded {
                Attempt::Succeeded
            } else {
                Attempt::Failed
            },
        );
        if outcome.status != ActionStatus::Succeeded {
            return Err(DriveFailure::Failed);
        }
        Ok(())
    }
}
