//! Explicit CAPTCHA actions use the actor's normal safety and journal protocol.

use super::SessionActor;
use crate::error::SessionError;
use crawlx_core::action::BrowserAction;
use crawlx_core::captcha::CaptchaError;
use crawlx_core::config::DestructiveActions;
use crawlx_core::counters::ActionStatus;
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ElementIdentityHash, InputClass, ResourceContext};
use crawlx_core::observation::LiveTargetFacts;
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::SafetyContext;
use crawlx_core::safety::RiskClass;
use crawlx_core::BrowserError;
use crawlx_safety::Adjudication;
use std::sync::Arc;

impl SessionActor {
    pub(super) async fn solve_pending_captcha(&mut self) -> Result<bool, SessionError> {
        if self.cfg.context.captcha.is_none() || !self.ctx.captcha_pending().await? {
            return Ok(false);
        }
        // No provider billing or callback runs until the kernel and T1 both admit the action.
        let bundle = self
            .observer
            .observe_shared(&mut *self.ctx, &crawlx_observe::spec::cheap())
            .await?;
        self.last = Some(Arc::clone(&bundle));
        let analyzed = self.analyzer.analyze(&bundle).await;
        self.svc.states.put_state(&analyzed.state).await?;
        let action = BrowserAction::SolveCaptcha;
        let proposal = ActionProposal {
            key: ActionContextKey {
                principal: self.cfg.principal.clone(),
                route_template: bundle.route.template.clone(),
                element: ElementIdentityHash(Digest::of(
                    "crawlx/captcha/widget-action/v1",
                    bundle.url.url.as_str().as_bytes(),
                )),
                action_kind: action.kind(),
                input_class: InputClass::none(),
                resource_context: ResourceContext::Own,
                state_cluster: analyzed.state.cluster,
            },
            action,
            epoch: bundle.epoch,
            strategy: "captcha_solver",
            strategy_version: 1,
            confidence: 1.0,
            expected: ExpectedEffect::default(),
            hinted_risk: Some(RiskClass::Unclassified),
            model_decision: None,
            summary: "deliver a provider token to a detected challenge widget".to_owned(),
        };
        let kernel = self.svc.kernel.config();
        let safety = SafetyContext {
            profile: kernel.profile,
            has_test_sinks: self.svc.kernel.has_verified_test_sinks(),
            destructive_approval_allowed: kernel.destructive_approval == DestructiveActions::Approval,
            principal: self.cfg.principal.clone(),
            seed_origin: self.cfg.seed_origin.clone(),
            in_scope: true,
            target: LiveTargetFacts {
                current_url: bundle.url.url.to_string(),
                ..LiveTargetFacts::default()
            },
            form_hint: None,
        };
        let admitted = match self.svc.kernel.adjudicate(proposal.clone(), &safety) {
            Adjudication::Allow(action) => action,
            Adjudication::Deny(verdict) | Adjudication::ApprovalRequired(verdict, _) => {
                self.svc
                    .journal
                    .propose(self.cfg.run, self.cfg.session, &proposal, &verdict)
                    .await?;
                return Err(BrowserError::from(CaptchaError::PolicyDenied).into());
            }
        };
        let outcome = self
            .execute(admitted, self.cfg.settle, None, &tracing::Span::current())
            .await?;
        if outcome.status != ActionStatus::Succeeded || outcome.dropped.is_some() {
            return Err(BrowserError::from(CaptchaError::Delivery).into());
        }
        Ok(true)
    }
}
