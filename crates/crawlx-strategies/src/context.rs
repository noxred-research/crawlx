//! The frozen per-round [`DecisionContext`].
//!
//! A context is built once per decision round from the newest observation and
//! the exploration state; every strategy reads the same frozen view, so a
//! recorded round replays identically. Strategies never mutate it.

use crate::error::StrategyError;
use crate::frontier::{
    build_action, enumerate_actions, modal_scope, route_nav_action_id, route_nav_key, target_facts,
    EnumInput, FrontierStats, KeyedAction,
};
use crate::ledger::LedgerView;
use crate::switching::Phase;
use crawlx_core::config::LlmPlannerMode;
use crawlx_core::counters::TerminalReason;
use crawlx_core::observation::ObservationBundle;
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::SafetyContext;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{
    ActionContextId, ActionContextKey, ElementIdentityHash, ElementIdentityV1, PrincipalId, RouteTemplate,
    SafetyProfile, SessionId, StateClusterId, Timestamp,
};
use crawlx_elements::{Candidate, ResolvedElement};
use crawlx_graph::{best_path, EnablementGraph, KnownRoute, PathGoal, PathPlan, SearchParams};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, OnceLock};

/// Remaining budget as the switching policy and the planner see it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct BudgetView {
    /// Share of the action budget still available, in `[0, 1]`.
    pub remaining_fraction: f32,
    /// Absolute actions left, when the run has a page/action limit.
    pub actions_remaining: Option<u64>,
    /// Planner invocations so far this principal-run.
    pub planner_calls: u32,
    /// Cap on planner invocations (planning default 8).
    pub planner_calls_max: u32,
    /// `dynamic.llmPlanner`.
    pub llm_planner: LlmPlannerMode,
    /// Set when the run must stop (`limit_reached`, `deadline_reached`, `cancelled`, ...).
    pub exhausted: Option<TerminalReason>,
}

impl Default for BudgetView {
    fn default() -> Self {
        Self {
            remaining_fraction: 1.0,
            actions_remaining: None,
            planner_calls: 0,
            planner_calls_max: 8,
            llm_planner: LlmPlannerMode::StalledOnly,
            exhausted: None,
        }
    }
}

impl BudgetView {
    /// Planner gate: mode not `off`, more than 10% of the budget
    /// left, and fewer than `planner_calls_max` calls so far.
    #[must_use]
    pub fn planner_available(&self) -> bool {
        self.llm_planner != LlmPlannerMode::Off
            && self.exhausted.is_none()
            && self.remaining_fraction > 0.10
            && self.planner_calls < self.planner_calls_max
            && self.actions_remaining != Some(0)
    }
}

/// Stall bookkeeping maintained by [`crate::ExplorationState`].
#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Debug)]
pub struct StallCounters {
    /// Consecutive trusted actions with no first-exercised key, no new cluster
    /// and no new network operation.
    pub stall: u32,
    /// Trusted actions executed so far (monotonic).
    pub trusted_actions: u64,
    /// Interactions spent in enablement recovery this run.
    pub enablement_used: u32,
    /// Consecutive planner failures.
    pub planner_failures: u32,
    /// Planner plans that exercised at least one new key (merged).
    pub planner_successes: u32,
    /// Never-exercised keys visible in the current observation (the paper's `Q0`).
    pub unexercised_here: u32,
    /// Never-exercised keys known anywhere in the run.
    pub unexercised_known: u32,
}

/// The frozen inputs of one decision round.
pub struct DecisionContext<'a> {
    /// Observation this round decides on; its epoch bounds which proposals are valid.
    pub bundle: Arc<ObservationBundle>,
    /// Candidates of `bundle`, from `CandidateDiscovery`.
    pub candidates: Vec<Candidate>,
    /// Resolved identities, parallel to `candidates`.
    pub resolved: Vec<ResolvedElement>,
    /// Principal the round acts as; proposals keyed to another principal are invalid.
    pub principal: PrincipalId,
    /// State cluster the observation belongs to.
    pub cluster: StateClusterId,
    /// Read-only view of the exercised-action ledger.
    pub ledger: &'a dyn LedgerView,
    /// Enablement graph (which actions unlocked which elements).
    pub graph: &'a EnablementGraph,
    /// Frontier statistics for the current run.
    pub frontier: &'a FrontierStats,
    /// Safety profile the kernel classifies proposals under.
    pub profile: SafetyProfile,
    /// Crawl seed; with the decision index it drives deterministic tie-breaks.
    pub seed: CrawlSeed,
    /// Zero-based index of this decision within the run.
    pub decision_index: u64,
    /// Remaining-budget snapshot.
    pub budget: BudgetView,
    /// Stall counters at the start of the round.
    pub stall: StallCounters,
    /// Identities known from earlier observations but not visible now.
    pub hidden_targets: Vec<ElementIdentityHash>,
    /// Identities an action or a page event exposed after the session's first observation
    /// (menus, dialogs and rows) that are still visible and still unexercised; the page may
    /// hide them again at the next action. Empty for the first observation of a session.
    pub newly_visible: BTreeSet<ElementIdentityHash>,
    /// Elements with at least one trusted execution (any key): a reveal of one of these
    /// exposes nothing the ledger still needs.
    pub exercised: BTreeSet<ElementIdentityHash>,
    /// Recently executed keys (repetition), oldest first.
    pub recent: VecDeque<ActionContextId>,
    /// Wall-clock instant used for time-dependent scoring (defaults to the capture time of `bundle`).
    pub clock_now: Timestamp,
    /// Phase chosen by the switching policy for this round.
    pub phase: Phase,
    /// Whether `Keys` chords are enumerated for tab/menu items.
    pub include_keys: bool,
    by_element: BTreeMap<ElementIdentityHash, usize>,
    keyed: OnceLock<Vec<KeyedAction>>,
    /// Action families (`ActionContextKey::family_id`) of `keyed`, computed once.
    families: OnceLock<BTreeSet<ActionContextId>>,
    form_hints: OnceLock<BTreeMap<i64, String>>,
}

impl std::fmt::Debug for DecisionContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionContext")
            .field("principal", &self.principal)
            .field("cluster", &self.cluster)
            .field("candidates", &self.candidates.len())
            .field("decision_index", &self.decision_index)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

/// Builder for [`DecisionContext`]; the required inputs are constructor arguments.
pub struct DecisionContextBuilder<'a> {
    ctx: DecisionContext<'a>,
}

impl<'a> DecisionContextBuilder<'a> {
    /// Start a builder from the required inputs; optional inputs take their defaults.
    #[must_use]
    pub fn new(
        bundle: Arc<ObservationBundle>,
        principal: PrincipalId,
        cluster: StateClusterId,
        seed: CrawlSeed,
        ledger: &'a dyn LedgerView,
        graph: &'a EnablementGraph,
        frontier: &'a FrontierStats,
    ) -> Self {
        let clock_now = bundle.captured_at;
        Self {
            ctx: DecisionContext {
                bundle,
                candidates: Vec::new(),
                resolved: Vec::new(),
                principal,
                cluster,
                ledger,
                graph,
                frontier,
                profile: SafetyProfile::ReadOnly,
                seed,
                decision_index: 0,
                budget: BudgetView::default(),
                stall: StallCounters::default(),
                hidden_targets: Vec::new(),
                newly_visible: BTreeSet::new(),
                exercised: BTreeSet::new(),
                recent: VecDeque::new(),
                clock_now,
                phase: Phase::Greedy,
                include_keys: false,
                by_element: BTreeMap::new(),
                keyed: OnceLock::new(),
                families: OnceLock::new(),
                form_hints: OnceLock::new(),
            },
        }
    }

    /// Candidates and their resolved identities (parallel vectors).
    #[must_use]
    pub fn candidates(mut self, candidates: Vec<Candidate>, resolved: Vec<ResolvedElement>) -> Self {
        self.ctx.candidates = candidates;
        self.ctx.resolved = resolved;
        self
    }

    /// Set the safety profile (default `ReadOnly`).
    #[must_use]
    pub const fn profile(mut self, profile: SafetyProfile) -> Self {
        self.ctx.profile = profile;
        self
    }

    /// Set the zero-based decision index (default 0).
    #[must_use]
    pub const fn decision_index(mut self, i: u64) -> Self {
        self.ctx.decision_index = i;
        self
    }

    /// Set the budget snapshot (default [`BudgetView::default`]).
    #[must_use]
    pub const fn budget(mut self, b: BudgetView) -> Self {
        self.ctx.budget = b;
        self
    }

    /// Set the stall counters (default all zero).
    #[must_use]
    pub const fn stall(mut self, s: StallCounters) -> Self {
        self.ctx.stall = s;
        self
    }

    /// Set identities known from earlier observations but not visible now.
    #[must_use]
    pub fn hidden_targets(mut self, h: Vec<ElementIdentityHash>) -> Self {
        self.ctx.hidden_targets = h;
        self
    }

    /// Identities the newest observation shows that the previous one did not.
    #[must_use]
    pub fn newly_visible(mut self, n: BTreeSet<ElementIdentityHash>) -> Self {
        self.ctx.newly_visible = n;
        self
    }

    /// Elements with at least one trusted execution.
    #[must_use]
    pub fn exercised(mut self, e: BTreeSet<ElementIdentityHash>) -> Self {
        self.ctx.exercised = e;
        self
    }

    /// Set recently executed keys, oldest first.
    #[must_use]
    pub fn recent(mut self, r: VecDeque<ActionContextId>) -> Self {
        self.ctx.recent = r;
        self
    }

    /// Set the clock instant used for scoring.
    #[must_use]
    pub const fn clock_now(mut self, now: Timestamp) -> Self {
        self.ctx.clock_now = now;
        self
    }

    /// Set the exploration phase for this round (default `Greedy`).
    #[must_use]
    pub const fn phase(mut self, p: Phase) -> Self {
        self.ctx.phase = p;
        self
    }

    /// Enable `Keys` chord enumeration for tab/menu items (default off).
    #[must_use]
    pub const fn include_keys(mut self, yes: bool) -> Self {
        self.ctx.include_keys = yes;
        self
    }

    /// Validate and freeze.
    ///
    /// # Errors
    /// [`StrategyError::InvalidContext`] when `candidates` and `resolved` differ in length.
    pub fn build(mut self) -> Result<DecisionContext<'a>, StrategyError> {
        let c = &mut self.ctx;
        if c.candidates.len() != c.resolved.len() {
            return Err(StrategyError::InvalidContext(format!(
                "{} candidates but {} resolved identities",
                c.candidates.len(),
                c.resolved.len()
            )));
        }
        let mut by_element = BTreeMap::new();
        for (i, r) in c.resolved.iter().enumerate() {
            by_element.entry(r.hash).or_insert(i);
        }
        c.by_element = by_element;
        Ok(self.ctx)
    }
}

impl DecisionContext<'_> {
    /// Route template of the observed page.
    #[must_use]
    pub fn route(&self) -> &RouteTemplate {
        &self.bundle.route.template
    }

    /// Session the bundle came from (arbiter seed input).
    #[must_use]
    pub fn session(&self) -> SessionId {
        self.bundle.session_id
    }

    /// Every keyed action the candidates' vocabularies support (computed once). Under an
    /// open modal (`modal_scope`) only the dialog's controls are enumerated, and its dismiss
    /// controls (or the `Escape` chord) are withheld while another control of the dialog is
    /// still unexercised and proposable: the dialog is explored before it is closed.
    #[must_use]
    pub fn keyed_actions(&self) -> &[KeyedAction] {
        self.keyed.get_or_init(|| {
            let modal = modal_scope(&self.bundle, &self.candidates);
            let mut acts = enumerate_actions(&EnumInput {
                principal: &self.principal,
                route: self.route(),
                cluster: self.cluster,
                profile: self.profile,
                candidates: &self.candidates,
                resolved: &self.resolved,
                include_keys: self.include_keys,
                modal: modal.as_ref(),
            });
            for action in &mut acts {
                self.ledger.normalize_key(&mut action.key);
            }
            if let Some(modal) = &modal {
                let pending = acts.iter().any(|ka| {
                    !modal.dismisses(ka)
                        && self.ledger.trusted_attempts(&ka.key) == 0
                        && self.frontier.is_proposable(&ka.key)
                });
                if pending {
                    acts.retain(|ka| !modal.dismisses(ka));
                }
            }
            acts
        })
    }

    /// Action families of the keyed actions on this page (computed once per context).
    #[must_use]
    pub fn families_here(&self) -> &BTreeSet<ActionContextId> {
        self.families
            .get_or_init(|| self.keyed_actions().iter().map(|ka| ka.key.family_id()).collect())
    }

    /// Index of the first candidate resolving to `hash`.
    #[must_use]
    pub fn candidate_index(&self, hash: &ElementIdentityHash) -> Option<usize> {
        self.by_element.get(hash).copied()
    }

    /// Identity of a visible element.
    #[must_use]
    pub fn identity_of(&self, hash: &ElementIdentityHash) -> Option<&ElementIdentityV1> {
        self.candidate_index(hash)
            .and_then(|i| self.resolved.get(i))
            .map(|r| &r.identity)
    }

    /// Visible identity hashes (sorted, unique).
    #[must_use]
    pub fn visible_identities(&self) -> BTreeSet<ElementIdentityHash> {
        self.by_element.keys().copied().collect()
    }

    /// Browser action for `ka` (`None` when a value cannot be generated).
    #[must_use]
    pub fn action_for(&self, ka: &KeyedAction) -> Option<crawlx_core::BrowserAction> {
        build_action(
            ka,
            &self.candidates,
            &self.bundle,
            self.seed,
            self.ledger.trusted_attempts(&ka.key),
            self.clock_now,
            self.frontier.form_values(),
        )
    }

    /// An advisory proposal for `ka` bound to the context's epoch.
    #[must_use]
    pub fn proposal_for(
        &self,
        ka: &KeyedAction,
        strategy: &'static str,
        version: u32,
        confidence: f32,
    ) -> Option<ActionProposal> {
        let cand = self.candidates.get(ka.candidate)?;
        let action = self.action_for(ka)?;
        let navigates_to = match ka.key.action_kind {
            crawlx_core::ActionKind::Click | crawlx_core::ActionKind::KeyboardActivate => {
                cand.descriptor.href.clone()
            }
            _ => None,
        };
        let hash = ka.key.element.to_string();
        Some(ActionProposal {
            key: ka.key.clone(),
            action,
            epoch: self.bundle.epoch,
            strategy,
            strategy_version: version,
            confidence: confidence.clamp(0.0, 1.0),
            expected: ExpectedEffect {
                reveals: Vec::new(),
                navigates_to,
                mutates_state: !ka.key.action_kind.is_idempotent(),
            },
            hinted_risk: None,
            model_decision: None,
            summary: format!(
                "{} {} [{}]",
                ka.key.action_kind.as_str(),
                cand.descriptor.role,
                &hash[..hash.len().min(12)]
            ),
        })
    }

    /// A `Navigate` to the first-observed URL of `route` (reset to a known route).
    /// `None` when the route is unknown or its URL does not parse.
    #[must_use]
    pub fn navigate_proposal(
        &self,
        route: &RouteTemplate,
        strategy: &'static str,
        version: u32,
        confidence: f32,
    ) -> Option<ActionProposal> {
        let entry = self.frontier.routes().get(route)?;
        let url = url::Url::parse(&entry.url).ok()?;
        let mut key = route_nav_key(&self.principal, self.route(), self.cluster, route);
        self.ledger.normalize_key(&mut key);
        Some(ActionProposal {
            key,
            action: crawlx_core::BrowserAction::Navigate { url },
            epoch: self.bundle.epoch,
            strategy,
            strategy_version: version,
            confidence: confidence.clamp(0.0, 1.0),
            expected: ExpectedEffect {
                reveals: Vec::new(),
                navigates_to: Some(entry.url.clone()),
                mutates_state: false,
            },
            hinted_risk: None,
            model_decision: None,
            summary: format!("navigate known route {route}"),
        })
    }

    /// The safety context for one proposal: `base` (profile, principal, scope)
    /// plus the structural facts of the proposal's target from the observation
    /// it was derived from.
    #[must_use]
    pub fn safety_context(&self, base: &SafetyContext, key: &ActionContextKey) -> SafetyContext {
        let mut c = base.clone();
        c.form_hint = None;
        c.target.observed_form_hint = None;
        match self
            .candidate_index(&key.element)
            .and_then(|i| self.candidates.get(i))
        {
            Some(cand) => {
                c.target = target_facts(cand, &self.bundle);
                c.form_hint = self
                    .form_hints
                    .get_or_init(|| crate::frontier::observed_form_hints(&self.bundle))
                    .get(&cand.descriptor.locator.backend_node_id.0)
                    .cloned();
                c.target.observed_form_hint.clone_from(&c.form_hint);
            }
            None => {
                if c.target.current_url.is_empty() {
                    c.target.current_url = self.bundle.url.url.to_string();
                }
            }
        }
        c
    }

    /// Known routes as reset targets for path search.
    #[must_use]
    pub fn known_routes(&self) -> Vec<KnownRoute> {
        self.frontier
            .routes()
            .iter()
            .map(|(route, entry)| KnownRoute {
                route: route.clone(),
                action: route_nav_action_id(&self.principal, route),
                landing: entry.cluster,
                cost: 0.5,
                p_success: 0.9,
            })
            .collect()
    }

    /// Cheapest path-safe plan from the current cluster to `goal`.
    #[must_use]
    pub fn path_plan(&self, goal: PathGoal) -> Option<PathPlan> {
        let routes = self.known_routes();
        let nav_ids: BTreeSet<ActionContextId> = routes.iter().map(|r| r.action).collect();
        let safe = |id: ActionContextId| nav_ids.contains(&id) || self.frontier.is_path_safe(id);
        // a generalized (route-template) edge is sourced by an action family; it starts a
        // plan only when that action is on this page
        let here = self.families_here();
        let resolvable = |family: ActionContextId| here.contains(&family);
        let params = SearchParams::new(self.clock_now, &safe)
            .with_known_routes(&routes)
            .with_resolvable(&resolvable);
        best_path(self.graph, self.cluster, goal, &params)
    }
}
