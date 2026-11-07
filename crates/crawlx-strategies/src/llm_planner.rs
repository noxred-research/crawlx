//! `llm_planner`: the long-horizon fallback.
//!
//! Invoked only when the switching policy says `Planner` (deterministic
//! recovery exhausted) and the budget allows it. The model sees a
//! crawler-built, kernel-filtered shortlist as untrusted data and answers with a
//! closed-vocabulary `ActionPlan` that `crawlx_model::llm::validate` checks
//! (candidate refs in range, known routes, named value partitions, no
//! selectors/scripts/URLs/literals). Steps become ordinary proposals
//! (`strategy = "llm_planner"`) that go through the arbiter, the kernel and the
//! actor like any other; **there is no plan-level approval**.
//!
//! Only the next step of an active plan is proposed per round (its locator is
//! only valid at the current epoch). Targets are stored as durable identity
//! hashes and re-resolved against each new observation; a target that cannot
//! be found aborts the plan. The driver reports each executed step through
//! [`LlmPlanner::step_done`]; completed or aborted plans yield a
//! [`PlanOutcome`] for [`crate::plan_merge::merge`]. Plans the planner ends
//! itself (a step the arbiter never chose, a vanished target) and failed model
//! calls are queued for [`LlmPlanner::take_finished`]; the driver merges them
//! every round so failures are counted and the policy can end the run.

use crate::context::DecisionContext;
use crate::error::StrategyError;
use crate::frontier::{route_element, Intent, KeyedAction};
use crate::switching::Phase;
use crate::system1::{build_shortlist, state_view};
use crate::Strategy;
use async_trait::async_trait;
use crawlx_core::action::{BrowserAction, KeyChord, Modifiers, OptionKey};
use crawlx_core::config::LlmPlannerMode;
use crawlx_core::hash::Digest;
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::{SafetyContext, SafetyGate};
use crawlx_core::{
    ActionContextKey, ActionKind, ElementIdentityHash, InputClass, ResourceContext, RouteTemplate,
    StateClusterId, Timestamp, TrustLane,
};
use crawlx_forms::Partition;
use crawlx_model::llm::{
    plan_validated, Expectation, PlanKey, PlanStep, PlannerClient, PlannerRequest, ValueRef,
};
use crawlx_model::{Instruction, Provenance, ProvenanceTagged};
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Arc;

/// Strategy name recorded in proposal attribution.
pub const NAME: &str = "llm_planner";
/// Version of the planner strategy logic, recorded in proposal attribution.
pub const VERSION: u32 = 1;

/// Planner knobs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LlmPlannerConfig {
    /// When the planner may be invoked (off, only when stalled, ...).
    pub mode: LlmPlannerMode,
    /// `max_steps` sent to the model (≤ the DSL's 20).
    pub max_steps: usize,
    /// Candidates shown to the model.
    pub shortlist_max: usize,
    /// Rounds the planner re-proposes a step that the arbiter did not pick before aborting.
    pub max_skips: u32,
}

impl Default for LlmPlannerConfig {
    fn default() -> Self {
        Self {
            mode: LlmPlannerMode::StalledOnly,
            max_steps: 12,
            shortlist_max: 20,
            max_skips: 3,
        }
    }
}

/// What a step does, with targets already resolved to identities.
#[derive(Clone, PartialEq, Debug)]
enum Planned {
    Click(ElementIdentityHash),
    Hover(ElementIdentityHash),
    Type(ElementIdentityHash, Partition),
    Select(ElementIdentityHash, u16),
    Press(Option<ElementIdentityHash>, PlanKey),
    Navigate(RouteTemplate),
}

/// An expectation checked after the step it follows.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Expect {
    RouteIs(String),
    ElementPresent(ElementIdentityHash),
    StateChanged,
    /// `network_op` expectations are annotations only: the reconciler owns traffic.
    NetworkOp,
}

#[derive(Clone, Debug)]
struct PlannedStep {
    what: Planned,
    expect: Vec<Expect>,
}

/// One executed step as the driver reports it.
#[derive(Clone, Debug)]
pub struct PlanStepReport {
    /// Key of the executed step.
    pub key: ActionContextKey,
    /// The browser performed the step (`false`: rejected, no after-state).
    pub succeeded: bool,
    /// Trust lane the step ran in.
    pub lane: TrustLane,
    /// Cluster the step started from.
    pub before: StateClusterId,
    /// Cluster the page was in after settling.
    pub after: StateClusterId,
    /// Controls new in the after-observation that are still present after settle.
    pub revealed: Vec<ElementIdentityHash>,
    /// The key had no trusted execution before this one.
    pub first_exercised: bool,
    /// Route template of the after-observation.
    pub after_route: RouteTemplate,
    /// Identities visible after settle.
    pub visible_after: BTreeSet<ElementIdentityHash>,
    /// The after-state differs from the before-state (cluster, route or affordances).
    pub state_changed: bool,
    /// Time the step finished.
    pub now: Timestamp,
}

/// One executed step kept for merging.
#[derive(Clone, PartialEq, Debug)]
pub struct ExecutedStep {
    /// Key of the executed step.
    pub key: ActionContextKey,
    /// The browser performed the step.
    pub succeeded: bool,
    /// Trust lane the step ran in.
    pub lane: TrustLane,
    /// Cluster the step started from.
    pub before: StateClusterId,
    /// Cluster the page was in after settling.
    pub after: StateClusterId,
    /// Controls the step revealed.
    pub revealed: Vec<ElementIdentityHash>,
    /// The key had no trusted execution before this step.
    pub first_exercised: bool,
}

/// A finished (completed or aborted) plan, ready for [`crate::plan_merge::merge`].
#[derive(Clone, PartialEq, Debug)]
pub struct PlanOutcome {
    /// Plan id the model supplied, if any.
    pub plan_id: Option<String>,
    /// Content digest of the plan.
    pub digest: Digest,
    /// Annotations for `workflow_runs`; never coverage.
    pub coverage_tags: Vec<String>,
    /// Steps that ran, in order.
    pub steps: Vec<ExecutedStep>,
    /// All steps ran and at least one trusted step first-exercised a key.
    pub success: bool,
    /// Why the plan ended early, if it did.
    pub aborted: Option<AbortReason>,
    /// Time the plan finished or aborted.
    pub finished_at: Timestamp,
}

/// Why a plan stopped before its last step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AbortReason {
    /// A step's action failed in the browser.
    StepFailed,
    /// A step's expectation did not hold after it ran.
    ExpectationFailed,
    /// A step's target is no longer among the current candidates.
    TargetNotFound,
    /// The arbiter did not pick the step for more than `max_skips` rounds.
    NotChosen,
    /// The model call or its validation failed; no plan ever started.
    PlanRejected,
}

/// What [`LlmPlanner::step_done`] decided.
#[derive(Clone, PartialEq, Debug)]
pub enum PlanProgress {
    /// Not the planner's step (or no active plan); nothing changed.
    Ignored,
    /// More steps remain.
    Continue,
    /// The plan finished or aborted.
    Finished(PlanOutcome),
}

#[derive(Debug)]
struct ActivePlan {
    plan_id: Option<String>,
    digest: Digest,
    tags: Vec<String>,
    steps: Vec<PlannedStep>,
    next: usize,
    executed: Vec<ExecutedStep>,
    pending: Option<ActionContextKey>,
    skips: u32,
}

/// Counters over the planner's lifetime.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct PlannerStats {
    /// Model calls made.
    pub calls: u32,
    /// Calls whose plan failed validation or resolution.
    pub rejected: u32,
}

/// The planner strategy.
pub struct LlmPlanner {
    client: Arc<dyn PlannerClient>,
    cfg: LlmPlannerConfig,
    safety: Option<(Arc<dyn SafetyGate>, SafetyContext)>,
    active: Mutex<Option<ActivePlan>>,
    /// Plans the planner ended itself (never chosen, target vanished) and failed model calls.
    finished: Mutex<Vec<PlanOutcome>>,
    stats: Mutex<PlannerStats>,
}

impl LlmPlanner {
    /// Create a planner that asks `client` for plans under `cfg`; no safety filtering until [`Self::with_safety`].
    #[must_use]
    pub fn new(client: Arc<dyn PlannerClient>, cfg: LlmPlannerConfig) -> Self {
        Self {
            client,
            cfg,
            safety: None,
            active: Mutex::new(None),
            finished: Mutex::new(Vec::new()),
            stats: Mutex::new(PlannerStats::default()),
        }
    }

    /// Filter the candidates shown to the model through the kernel.
    #[must_use]
    pub fn with_safety(mut self, gate: Arc<dyn SafetyGate>, base: SafetyContext) -> Self {
        self.safety = Some((gate, base));
        self
    }

    /// Lifetime call counters.
    #[must_use]
    pub fn stats(&self) -> PlannerStats {
        *self.stats.lock()
    }

    /// Is a plan currently executing?
    #[must_use]
    pub fn has_active_plan(&self) -> bool {
        self.active.lock().is_some()
    }

    /// Drop the active plan (the run was restored, cancelled, ...).
    pub fn reset(&self) {
        *self.active.lock() = None;
    }

    /// Ask the model for a plan and validate it. Returns the validated steps
    /// with targets resolved to identities of the **crawler-built** shortlist.
    async fn request_plan(&self, ctx: &DecisionContext<'_>) -> Result<ActivePlan, StrategyError> {
        let (shortlist, _) = build_shortlist(ctx, self.safety.as_ref(), 1, self.cfg.shortlist_max);
        if shortlist.is_empty() {
            return Err(StrategyError::InvalidContext(
                "no candidates to plan over".to_owned(),
            ));
        }
        let acts = ctx.keyed_actions();
        let element_of: Vec<ElementIdentityHash> = shortlist.iter().map(|&i| acts[i].key.element).collect();
        let known_routes: Vec<String> = ctx.frontier.routes().keys().map(|r| r.0.clone()).collect();
        let req = PlannerRequest {
            goal: Instruction::from_static(
                "Exercise functionality that has not been exercised yet, using as few steps as possible.",
            ),
            state: ProvenanceTagged::new(Provenance::PageText, state_view(ctx, &shortlist)),
            known_routes,
            max_steps: self.cfg.max_steps,
        };
        self.stats.lock().calls += 1;
        let validated = plan_validated(&*self.client, &req).await.map_err(|e| {
            self.stats.lock().rejected += 1;
            StrategyError::from(e)
        })?;

        let resolve = |r: crawlx_model::CandidateRef| -> Result<ElementIdentityHash, StrategyError> {
            r.resolve(element_of.len())
                .and_then(|i| element_of.get(i).copied())
                .ok_or_else(|| {
                    StrategyError::InvalidContext("candidate ref outside the shortlist".to_owned())
                })
        };
        let mut steps: Vec<PlannedStep> = Vec::new();
        for step in validated.steps() {
            let what = match step {
                PlanStep::Click { target } => Planned::Click(resolve(*target)?),
                PlanStep::Hover { target } => Planned::Hover(resolve(*target)?),
                PlanStep::Type { target, value } => {
                    let ValueRef::Partition { class, partition } = value else {
                        // secret slots are resolved by the login path, never by the planner
                        return Err(StrategyError::InvalidContext(
                            "planner steps cannot type secret slots".to_owned(),
                        ));
                    };
                    let p = Partition::from_str(&format!("{class}:{partition}"))
                        .map_err(|e| StrategyError::InvalidContext(e.to_string()))?;
                    if !p.is_generated() {
                        return Err(StrategyError::InvalidContext(format!(
                            "partition {} is not generated",
                            p.as_str()
                        )));
                    }
                    Planned::Type(resolve(*target)?, p)
                }
                PlanStep::Select { target, option_index } => {
                    Planned::Select(resolve(*target)?, *option_index)
                }
                PlanStep::Press { target, key } => Planned::Press((*target).map(&resolve).transpose()?, *key),
                PlanStep::NavigateKnownRoute { route } => Planned::Navigate(RouteTemplate(route.clone())),
                PlanStep::Expect { expectation } => {
                    let e = match expectation {
                        Expectation::RouteIs { route } => Expect::RouteIs(route.clone()),
                        Expectation::ElementPresent { target } => Expect::ElementPresent(resolve(*target)?),
                        Expectation::StateChanged => Expect::StateChanged,
                        Expectation::NetworkOp { .. } => Expect::NetworkOp,
                    };
                    if let Some(last) = steps.last_mut() {
                        last.expect.push(e);
                    }
                    continue;
                }
            };
            steps.push(PlannedStep {
                what,
                expect: Vec::new(),
            });
        }
        if steps.is_empty() {
            return Err(StrategyError::InvalidContext(
                "plan has no action steps".to_owned(),
            ));
        }
        Ok(ActivePlan {
            plan_id: validated.plan_id().map(str::to_owned),
            digest: *validated.digest(),
            tags: validated.coverage_tags().to_vec(),
            steps,
            next: 0,
            executed: Vec::new(),
            pending: None,
            skips: 0,
        })
    }

    /// Proposal for the plan's next step in `ctx`, or `None` when its target is gone.
    fn step_proposal(ctx: &DecisionContext<'_>, step: &PlannedStep) -> Option<ActionProposal> {
        let by = |hash: &ElementIdentityHash, kind: ActionKind, input: InputClass, intent: Intent| {
            let idx = ctx.candidate_index(hash)?;
            let key = ActionContextKey {
                principal: ctx.principal.clone(),
                route_template: ctx.route().clone(),
                element: *hash,
                action_kind: kind,
                input_class: input,
                resource_context: ResourceContext::None,
                state_cluster: ctx.cluster,
            };
            let family = crate::frontier::stable_path_sig(&ctx.resolved.get(idx)?.identity);
            Some(KeyedAction {
                group: family,
                family,
                key,
                candidate: idx,
                intent,
            })
        };
        match &step.what {
            Planned::Click(h) => {
                let ka = by(h, ActionKind::Click, InputClass::none(), Intent::Click)?;
                ctx.proposal_for(&ka, NAME, VERSION, 0.5)
            }
            Planned::Hover(h) => {
                let ka = by(h, ActionKind::Hover, InputClass::none(), Intent::Hover)?;
                ctx.proposal_for(&ka, NAME, VERSION, 0.5)
            }
            Planned::Type(h, p) => {
                let ka = by(h, ActionKind::Type, p.input_class(), Intent::Type(*p))?;
                ctx.proposal_for(&ka, NAME, VERSION, 0.5)
            }
            Planned::Select(h, idx) => {
                let ka = by(
                    h,
                    ActionKind::Select,
                    InputClass::new("select", &format!("option_{idx}")),
                    Intent::Select,
                )?;
                let mut p = ctx.proposal_for(&ka, NAME, VERSION, 0.5)?;
                let target = ctx.candidates.get(ka.candidate)?.descriptor.locator.clone();
                p.action = BrowserAction::Select {
                    target,
                    options: vec![OptionKey::Index(u32::from(*idx))],
                };
                Some(p)
            }
            Planned::Press(target, key) => {
                let element = target.unwrap_or_else(|| route_element(ctx.route()));
                let chord = KeyChord {
                    key: plan_key_name(*key).to_owned(),
                    modifiers: Modifiers {
                        shift: matches!(key, PlanKey::ShiftTab),
                        ..Modifiers::default()
                    },
                };
                let akey = ActionContextKey {
                    principal: ctx.principal.clone(),
                    route_template: ctx.route().clone(),
                    element,
                    action_kind: ActionKind::Keys,
                    input_class: InputClass::new("keys", plan_key_name(*key)),
                    resource_context: ResourceContext::None,
                    state_cluster: ctx.cluster,
                };
                Some(ActionProposal {
                    key: akey,
                    action: BrowserAction::Keys {
                        sequence: vec![chord],
                    },
                    epoch: ctx.bundle.epoch,
                    strategy: NAME,
                    strategy_version: VERSION,
                    confidence: 0.5,
                    expected: ExpectedEffect::default(),
                    hinted_risk: None,
                    model_decision: None,
                    summary: format!("press {}", plan_key_name(*key)),
                })
            }
            Planned::Navigate(route) => ctx.navigate_proposal(route, NAME, VERSION, 0.5),
        }
    }

    /// Report one executed step. Returns the outcome when the plan finished or aborted.
    pub fn step_done(&self, r: &PlanStepReport) -> PlanProgress {
        let mut guard = self.active.lock();
        let Some(plan) = guard.as_mut() else {
            return PlanProgress::Ignored;
        };
        if plan.pending.as_ref() != Some(&r.key) {
            return PlanProgress::Ignored;
        }
        plan.pending = None;
        plan.skips = 0;
        plan.executed.push(ExecutedStep {
            key: r.key.clone(),
            succeeded: r.succeeded,
            lane: r.lane,
            before: r.before,
            after: r.after,
            revealed: r.revealed.clone(),
            first_exercised: r.first_exercised,
        });
        let step = &plan.steps[plan.next];
        let expectations_hold = r.succeeded
            && step.expect.iter().all(|e| match e {
                Expect::RouteIs(route) => r.after_route.0 == *route,
                Expect::ElementPresent(h) => r.visible_after.contains(h),
                Expect::StateChanged => r.state_changed,
                Expect::NetworkOp => true,
            });
        plan.next += 1;
        let done = plan.next >= plan.steps.len();
        if expectations_hold && !done {
            return PlanProgress::Continue;
        }
        let aborted = if !r.succeeded {
            Some(AbortReason::StepFailed)
        } else if !expectations_hold {
            Some(AbortReason::ExpectationFailed)
        } else {
            None
        };
        let Some(plan) = guard.take() else {
            return PlanProgress::Ignored;
        };
        let success = aborted.is_none()
            && plan
                .executed
                .iter()
                .any(|s| s.succeeded && s.lane == TrustLane::TrustedUi && s.first_exercised);
        PlanProgress::Finished(PlanOutcome {
            plan_id: plan.plan_id,
            digest: plan.digest,
            coverage_tags: plan.tags,
            steps: plan.executed,
            success,
            aborted,
            finished_at: r.now,
        })
    }

    /// Abort the active plan without a step result (target gone, never chosen).
    fn abort(&self, reason: AbortReason, now: Timestamp) -> Option<PlanOutcome> {
        let plan = self.active.lock().take()?;
        Some(PlanOutcome {
            plan_id: plan.plan_id,
            digest: plan.digest,
            coverage_tags: plan.tags,
            steps: plan.executed,
            success: false,
            aborted: Some(reason),
            finished_at: now,
        })
    }

    /// Outcomes of plans the planner ended on its own (a step the arbiter never
    /// chose, a target that vanished) and of failed model calls. The driver
    /// merges each with [`crate::plan_merge::merge`] once per round so failures
    /// are counted and the switching policy can end the run.
    pub fn take_finished(&self) -> Vec<PlanOutcome> {
        std::mem::take(&mut *self.finished.lock())
    }

    fn reap(&self, reason: AbortReason, now: Timestamp) {
        if let Some(o) = self.abort(reason, now) {
            self.finished.lock().push(o);
        }
    }

    /// Abort the active plan and return its outcome so the driver can merge
    /// and count the failure (cancellation, restore). `None` when no plan is active.
    pub fn abort_active(&self, reason: AbortReason, now: Timestamp) -> Option<PlanOutcome> {
        self.abort(reason, now)
    }

    /// A planner call that produced no executable plan (model or validation
    /// failure) as an outcome the driver can merge to count the failure.
    #[must_use]
    pub fn failed_outcome(now: Timestamp) -> PlanOutcome {
        PlanOutcome {
            plan_id: None,
            digest: Digest::of("crawlx/action-plan/v1", b"failed"),
            coverage_tags: Vec::new(),
            steps: Vec::new(),
            success: false,
            aborted: Some(AbortReason::PlanRejected),
            finished_at: now,
        }
    }
}

const fn plan_key_name(k: PlanKey) -> &'static str {
    match k {
        PlanKey::Enter => "Enter",
        PlanKey::Escape => "Escape",
        PlanKey::Tab | PlanKey::ShiftTab => "Tab",
        PlanKey::Space => " ",
        PlanKey::ArrowUp => "ArrowUp",
        PlanKey::ArrowDown => "ArrowDown",
        PlanKey::ArrowLeft => "ArrowLeft",
        PlanKey::ArrowRight => "ArrowRight",
    }
}

#[async_trait]
impl Strategy for LlmPlanner {
    async fn propose(&self, ctx: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        if self.cfg.mode == LlmPlannerMode::Off {
            return Ok(Vec::new());
        }
        // Continue an active plan first.
        let next_step = {
            let mut guard = self.active.lock();
            match guard.as_mut() {
                Some(plan) => {
                    if plan.pending.is_some() {
                        plan.skips += 1;
                    }
                    if plan.skips > self.cfg.max_skips {
                        None
                    } else {
                        plan.steps.get(plan.next).cloned()
                    }
                }
                None => None,
            }
        };
        if let Some(step) = next_step {
            return Ok(match Self::step_proposal(ctx, &step) {
                Some(p) => {
                    if let Some(plan) = self.active.lock().as_mut() {
                        plan.pending = Some(p.key.clone());
                    }
                    vec![p]
                }
                None => {
                    self.reap(AbortReason::TargetNotFound, ctx.clock_now);
                    Vec::new()
                }
            });
        }
        if self.has_active_plan() {
            // the arbiter never chose the step: give up on the plan
            self.reap(AbortReason::NotChosen, ctx.clock_now);
            return Ok(Vec::new());
        }
        if ctx.phase != Phase::Planner || !ctx.budget.planner_available() {
            return Ok(Vec::new());
        }
        let mut plan = match self.request_plan(ctx).await {
            Ok(p) => p,
            Err(e) => {
                self.finished.lock().push(Self::failed_outcome(ctx.clock_now));
                return Err(e);
            }
        };
        let first = plan.steps[0].clone();
        let Some(p) = Self::step_proposal(ctx, &first) else {
            self.stats.lock().rejected += 1;
            self.finished.lock().push(Self::failed_outcome(ctx.clock_now));
            return Err(StrategyError::InvalidContext(
                "first plan step has no live target".to_owned(),
            ));
        };
        plan.pending = Some(p.key.clone());
        *self.active.lock() = Some(plan);
        Ok(vec![p])
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn version(&self) -> u32 {
        VERSION
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::context::BudgetView;
    use crate::testutil::{Fixture, Spec};
    use crawlx_model::llm::MockPlanner;
    use crawlx_model::ModelError;

    fn planner(replies: Vec<Result<String, ModelError>>) -> (LlmPlanner, MockPlanner) {
        let mock = MockPlanner::new(replies);
        (
            LlmPlanner::new(Arc::new(mock.clone()), LlmPlannerConfig::default()),
            mock,
        )
    }

    fn page() -> Fixture {
        Fixture::new(&[
            Spec::button("Open settings"),
            Spec::textbox("Team email", &[("type", "email")]),
            Spec::button("Send invite"),
        ])
    }

    #[tokio::test]
    async fn only_runs_in_the_planner_phase_with_budget() {
        let f = page();
        let (p, mock) = planner(vec![Ok(
            r#"{"version":1,"steps":[{"op":"click","target":0}]}"#.into()
        )]);
        // greedy phase: nothing
        assert!(p.propose(&f.ctx()).await.unwrap().is_empty());
        // planner phase but no budget: nothing, and the model is never called
        let ctx = f.ctx_with(
            crate::switching::Phase::Planner,
            BudgetView {
                remaining_fraction: 0.05,
                ..BudgetView::default()
            },
        );
        assert!(p.propose(&ctx).await.unwrap().is_empty());
        assert!(mock.requests().is_empty());
        // planner phase with budget: one proposal
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        let props = p.propose(&ctx).await.unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(mock.requests().len(), 1);
        assert_eq!(props[0].strategy, NAME);
    }

    #[tokio::test]
    async fn proposals_only_reference_crawler_built_candidates() {
        let f = page();
        let (p, mock) = planner(vec![Ok(
            r#"{"version":1,"plan_id":"p1","steps":[
                {"op":"click","target":0},
                {"op":"type","target":1,"value":{"kind":"partition","class":"email","partition":"valid_new_user"}},
                {"op":"click","target":2}]}"#.into(),
        )]);
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        let first = p.propose(&ctx).await.unwrap();
        // the shown candidate list is what the model could refer to
        let shown = mock.requests()[0].state.value().candidates.len();
        assert!(shown > 0 && shown <= 20);
        let visible = ctx.visible_identities();
        assert_eq!(first.len(), 1);
        assert!(visible.contains(&first[0].key.element));
        let locators: Vec<_> = f
            .candidates
            .iter()
            .map(|c| c.descriptor.locator.clone())
            .collect();
        assert!(locators.contains(first[0].action.target().unwrap()));
        // the model-visible text was sanitized page data only (no locators or ids)
        let rendered = crawlx_model::llm::render_prompt(&mock.requests()[0]);
        assert!(rendered.contains("<<DATA"));
        assert!(!rendered.contains("backend"));
    }

    #[tokio::test]
    async fn out_of_range_refs_unknown_routes_and_literals_are_rejected() {
        let f = page();
        for bad in [
            r#"{"version":1,"steps":[{"op":"click","target":999}]}"#,
            r#"{"version":1,"steps":[{"op":"navigate_known_route","route":"/not/known"}]}"#,
            r#"{"version":1,"steps":[{"op":"type","target":0,"value":{"kind":"literal","text":"x"}}]}"#,
            r##"{"version":1,"steps":[{"op":"click","target":"#submit"}]}"##,
            "not json",
        ] {
            let (p, _) = planner(vec![Ok(bad.to_owned())]);
            let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
            let err = p.propose(&ctx).await.unwrap_err();
            assert!(matches!(err, StrategyError::ModelUnavailable(_)), "{bad}: {err}");
            assert!(!p.has_active_plan());
            assert_eq!(p.stats().rejected, 1);
            let failed = p.take_finished();
            assert_eq!(
                failed.len(),
                1,
                "a failed call is reported so the failure is counted"
            );
            assert_eq!(failed[0].aborted, Some(AbortReason::PlanRejected));
            assert!(!failed[0].success);
        }
        // secret slots are never typed by the planner
        let (p, _) = planner(vec![Ok(
            r#"{"version":1,"steps":[{"op":"type","target":1,"value":{"kind":"secret_slot","slot":"password"}}]}"#.into(),
        )]);
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        assert!(matches!(
            p.propose(&ctx).await,
            Err(StrategyError::InvalidContext(_))
        ));
    }

    #[tokio::test]
    async fn a_plan_proposes_one_step_per_round_and_reports_success() {
        let f = page();
        let (p, _) = planner(vec![Ok(
            r#"{"version":1,"plan_id":"p2","coverage_tags":["team.invite"],"steps":[
                {"op":"click","target":0},
                {"op":"expect","expectation":{"kind":"state_changed"}},
                {"op":"click","target":2}]}"#
                .into(),
        )]);
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        let first = p.propose(&ctx).await.unwrap();
        let k1 = first[0].key.clone();
        drop(ctx);
        // while awaiting, a different action got chosen: ignored
        let other = f.key("Send invite", ActionKind::Click);
        let stray = PlanStepReport {
            key: other,
            succeeded: true,
            lane: TrustLane::TrustedUi,
            before: f.cluster(),
            after: f.cluster(),
            revealed: vec![],
            first_exercised: true,
            after_route: f.route(),
            visible_after: BTreeSet::new(),
            state_changed: true,
            now: Timestamp::default(),
        };
        assert_eq!(p.step_done(&stray), PlanProgress::Ignored);
        let report = PlanStepReport {
            key: k1,
            ..stray.clone()
        };
        assert_eq!(p.step_done(&report), PlanProgress::Continue);
        // next round proposes step 2 (the same candidate list, still on the page)
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        let second = p.propose(&ctx).await.unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(f.name_of(&second[0].key.element), "Send invite");
        let done = p.step_done(&PlanStepReport {
            key: second[0].key.clone(),
            ..stray
        });
        let PlanProgress::Finished(out) = done else {
            panic!("expected finished");
        };
        assert!(out.success);
        assert_eq!(out.plan_id.as_deref(), Some("p2"));
        assert_eq!(out.coverage_tags, vec!["team.invite".to_owned()]);
        assert_eq!(out.steps.len(), 2);
        assert!(!p.has_active_plan());
    }

    #[tokio::test]
    async fn a_failed_expectation_or_step_aborts_the_plan() {
        let f = page();
        let (p, _) = planner(vec![Ok(r#"{"version":1,"steps":[
                {"op":"click","target":0},
                {"op":"expect","expectation":{"kind":"route_is","route":"/elsewhere"}},
                {"op":"click","target":2}]}"#
            .into())]);
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        let first = p.propose(&ctx).await.unwrap();
        let PlanProgress::Finished(out) = p.step_done(&PlanStepReport {
            key: first[0].key.clone(),
            succeeded: true,
            lane: TrustLane::TrustedUi,
            before: f.cluster(),
            after: f.cluster(),
            revealed: vec![],
            first_exercised: true,
            after_route: RouteTemplate("/app".into()),
            visible_after: BTreeSet::new(),
            state_changed: false,
            now: Timestamp::default(),
        }) else {
            panic!("expected abort");
        };
        assert!(!out.success);
        assert_eq!(out.aborted, Some(AbortReason::ExpectationFailed));
    }

    #[tokio::test]
    async fn an_unchosen_step_is_abandoned_after_max_skips() {
        let f = page();
        let (p, _) = planner(vec![Ok(
            r#"{"version":1,"steps":[{"op":"click","target":0}]}"#.into()
        )]);
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        assert_eq!(p.propose(&ctx).await.unwrap().len(), 1);
        // the arbiter keeps choosing something else
        for _ in 0..3 {
            assert_eq!(p.propose(&ctx).await.unwrap().len(), 1);
        }
        assert!(p.propose(&ctx).await.unwrap().is_empty(), "skipped too often");
        assert!(
            !p.has_active_plan(),
            "the planner reaps a plan the arbiter never chooses"
        );
        let out = p.take_finished();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].aborted, Some(AbortReason::NotChosen));
        assert!(!out[0].success);
        assert!(p.take_finished().is_empty());
        // explicit cancellation still works for a live plan
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        let _ = p.propose(&ctx).await; // no replies left: the model call fails
        assert!(p
            .abort_active(AbortReason::NotChosen, Timestamp::default())
            .is_none());
    }

    #[tokio::test]
    async fn off_mode_never_calls_the_model() {
        let f = page();
        let mock = MockPlanner::new(vec![]);
        let p = LlmPlanner::new(
            Arc::new(mock.clone()),
            LlmPlannerConfig {
                mode: LlmPlannerMode::Off,
                ..LlmPlannerConfig::default()
            },
        );
        let ctx = f.ctx_with(crate::switching::Phase::Planner, BudgetView::default());
        assert!(p.propose(&ctx).await.unwrap().is_empty());
        assert!(mock.requests().is_empty());
    }
}
