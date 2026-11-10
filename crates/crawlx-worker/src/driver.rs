//! The exploration driver: one per session. Observe, discover
//! candidates, resolve identities, fingerprint, freeze a `DecisionContext`, run the strategies
//! under deadlines, arbitrate, adjudicate with the safety kernel, execute through the actor,
//! ingest the outcome. `observe_only` runs never execute.

use crate::actor::{under, ActionOutcome, DropReason, SessionHandle, SessionState};
use crate::analysis::StateAnalyzer;
use crate::counters::{Attempt, Plane};
use crate::diagnostics::SessionDiagnostics;
use crate::error::{SessionError, WorkerError};
use crate::model::{decision_record, record_model_error, ModelOverlay, StrategySet};
use crate::robots_gate::RobotsDecision;
use crate::role_budget::RoleBudget;
use crate::routes::RouteLearner;
use crate::run::RunContext;
use async_trait::async_trait;
use crawlx_core::config::{
    CrawlMode, DestructiveActions, Dynamic, PageLoadStrategy, StrategyArmSelection, StrategyName,
};
use crawlx_core::counters::{ActionStatus, ReconcileResolution, RunStatus, TerminalReason};
use crawlx_core::dom_ops::CssFilter;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{LiveTargetFacts, ObservationBundle, QuiescencePolicy};
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::{DiscoveryOutcome, FrontierStatus, IdentityAlias, NewState, SafetyContext};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::safety::SafetyDecision;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{
    ActionContextId, ActionContextKey, ActionId, ActionKind, BrowserAction, BrowserError, CanonicalUrl,
    ElementIdentityHash, InputClass, ResourceContext, StateClusterId, StateId,
};
use crawlx_elements::{
    Candidate, CandidateDiscovery, DiscoveryConfig, IdentityBuilder, IdentityResolver, MatchDecision,
    MatchWeights, ResolvedElement,
};
use crawlx_forms::is_logout_path;
use crawlx_graph::Confounders;
use crawlx_observe::spec;
use crawlx_policy::{BudgetKind, ScopePolicy, ScopeVerdict};
use crawlx_safety::Adjudication;
use crawlx_state::OutcomeClass;
use crawlx_strategies::{
    merge_plan, registry, run_strategies, Arbiter, ArbiterConfig, ArbiterRound, BudgetView, DecisionContext,
    ExplorationConfig, ExplorationState, Gates, LedgerView, LlmPlanner, OutcomeReport, PlanProgress,
    PlanStepReport, RoundInput, Strategy, StrategyDeadlines, StrategyError, SwitchingConfig, SwitchingPolicy,
    System1Record, UrlPlane, UrlPlaneConfig,
};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::spans::{self, child};
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::Instrument as _;

/// Knobs of the driver (planning defaults).
#[derive(Clone)]
pub struct DriverConfig {
    /// Deadlines.
    pub deadlines: StrategyDeadlines,
    /// Settle.
    pub settle: QuiescencePolicy,
    /// Consecutive rounds without a chosen action before the session ends as exhausted.
    pub max_empty_rounds: u32,
    /// Never execute; only navigate and observe (also implied by `dynamic.observeOnly`).
    pub observe_only: bool,
    /// Exploration.
    pub exploration: ExplorationConfig,
    /// Switching.
    pub switching: SwitchingConfig,
    /// Arbiter.
    pub arbiter: ArbiterConfig,
    /// Consecutive `HaltedStorage` results before the session gives up (`fatal_error`).
    pub max_storage_halts: u32,
    /// Consecutive dropped actions (stale, not actionable, confirm denied) before the session
    /// concludes that nothing on the page can be acted on.
    pub max_consecutive_drops: u32,
    /// Actions spent on a popup tab before it is closed and the session returns to its
    /// opener.
    pub tab_step_budget: u32,
    /// Milliseconds an executed action waits before the page is observed again
    /// (`dynamic.interactionSettleMs`, the `-interaction-settle` compatibility flag); `0` keeps the readiness
    /// preset of [`Self::settle`].
    pub interaction_settle_ms: u32,
    /// Opt-in shortlist dataset recording: `None` (the default) records nothing
    /// and changes no decision.
    pub record_shortlists: Option<ShortlistRecording>,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            deadlines: StrategyDeadlines::default(),
            settle: QuiescencePolicy::default(),
            max_empty_rounds: 8,
            observe_only: false,
            exploration: ExplorationConfig::default(),
            switching: SwitchingConfig::default(),
            arbiter: ArbiterConfig::default(),
            max_storage_halts: 5,
            max_consecutive_drops: 30,
            tab_step_budget: 25,
            interaction_settle_ms: 0,
            record_shortlists: None,
        }
    }
}

/// Dataset recording of System 1 shortlists, one run event per decision.
///
/// With recording on, the driver emits a `shortlist` event for every round in which System 1
/// produced a record (the rendered request, the shortlist's action-context ids, the position of
/// the executed action) and a `shortlist_outcome` event for every executed action (its novelty
/// gain). Requires System 1 in the strategy set and an engine; the rendered request is
/// [`crawlx_model::onnx_ranker::render_question`] output, byte-identical to what a ranker tokenizes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct ShortlistRecording {
    /// Replace the arbiter's pick by a draw, uniform and seeded from the crawl seed, among the
    /// shortlisted actions the arbiter admitted (kernel-allowed survivors). The logged
    /// propensity is `1 / admitted shortlist size`, so the pick no longer follows the
    /// deterministic ranking and the labels of the executed actions are unbiased by it. The
    /// kernel still adjudicates the drawn action like any other.
    pub explore: bool,
}

impl ShortlistRecording {
    /// Record shortlists and outcomes; the arbiter's pick stays the executed action.
    #[must_use]
    pub const fn recording_only() -> Self {
        Self { explore: false }
    }

    /// Record shortlists and outcomes and execute a seeded uniform draw from the shortlist.
    #[must_use]
    pub const fn uniform_exploration() -> Self {
        Self { explore: true }
    }
}

/// What a round leaves for the `shortlist` event: which held System 1 record belongs to the
/// round, what the arbiter (or the exploration draw) picked, and with what probability.
struct ShortlistNote {
    record: usize,
    chosen: Option<ActionContextId>,
    propensity: Option<f64>,
}

/// Move every System 1 record waiting on `rx` into `held` and return the index of the one made
/// for `decision`, if any.
fn hold_round_record(
    rx: Option<&mut mpsc::Receiver<System1Record>>,
    held: &mut Vec<System1Record>,
    decision: u64,
) -> Option<usize> {
    if let Some(rx) = rx {
        while let Ok(rec) = rx.try_recv() {
            held.push(rec);
        }
    }
    held.iter()
        .rposition(|r| r.decision_index == decision && r.rendered.is_some())
}

/// Replace the round's chosen action by a uniform draw among the ranked survivors that are on
/// `shortlist`, seeded from the crawl seed, the principal and the decision index. Returns the
/// draw's probability, `None` (the arbiter's pick stands) when fewer than two shortlisted
/// survivors exist.
fn explore_shortlist(
    round: &mut ArbiterRound,
    shortlist: &[ActionContextId],
    seed: &CrawlSeed,
    principal: &crawlx_core::PrincipalId,
    decision: u64,
) -> Option<f64> {
    let eligible: Vec<usize> = round
        .ranked
        .iter()
        .enumerate()
        .filter(|(_, r)| shortlist.contains(&r.proposal.key.id()))
        .map(|(i, _)| i)
        .collect();
    if eligible.len() < 2 {
        return None;
    }
    let draw = seed.derive(
        "decision-dataset-explore",
        &[principal.0.as_bytes(), &decision.to_le_bytes()],
    );
    let mut first = [0_u8; 8];
    first.copy_from_slice(&draw[..8]);
    let n = u64::try_from(eligible.len()).ok()?;
    let pick = usize::try_from(u64::from_le_bytes(first) % n).ok()?;
    let at = *eligible.get(pick)?;
    round.chosen = round.ranked.get(at).cloned();
    // shortlist sizes are at most 20: the conversion is exact
    Some(1.0 / f64::from(u32::try_from(eligible.len()).ok()?))
}

impl DriverConfig {
    /// Take the driver settings of the request's `dynamic` block: `maxFailureCount` becomes
    /// [`Self::max_consecutive_drops`] (`0` keeps the current value), `interactionSettleMs`
    /// becomes [`Self::interaction_settle_ms`], and `pageLoadStrategy` / `timeStableMs`
    /// replace [`Self::settle`] unless the request keeps the heuristic default.
    /// A replay applies the recorded run's `dynamic` block the same way to settle as the
    /// recorded driver did.
    pub fn apply_dynamic(&mut self, dynamic: &Dynamic) {
        if dynamic.max_failure_count > 0 {
            self.max_consecutive_drops = dynamic.max_failure_count;
        }
        self.interaction_settle_ms = dynamic.interaction_settle_ms;
        if dynamic.page_load_strategy != PageLoadStrategy::Heuristic || dynamic.time_stable_ms > 0 {
            self.settle = QuiescencePolicy::for_dynamic(dynamic);
        }
    }

    /// The quiescence an executed action settles under: [`Self::settle`] with an unconditional
    /// wait of [`Self::interaction_settle_ms`] before the idle criteria are evaluated.
    #[must_use]
    pub fn action_settle(&self) -> QuiescencePolicy {
        let mut policy = self.settle;
        policy.fixed_wait_ms = policy.fixed_wait_ms.max(u64::from(self.interaction_settle_ms));
        policy
    }
}

/// How a driver ended.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct DriverEnd {
    /// Terminal.
    pub terminal: TerminalReason,
    /// Actions that reached a terminal journal state in this session.
    pub actions: u64,
    /// States persisted by this session.
    pub states: u64,
}

/// The deterministic strategies `dynamic.strategies` enables, plus the always-on URL recovery
/// strategy, without a gate check: for recorded-trace replay and harnesses that act on no live
/// frontier. `system1` is skipped (it needs a decision engine; see
/// [`build_strategy_set`]). Live runs go through [`build_strategies_gated`].
///
/// # Errors
/// Rejects invalid arm configuration and versions unavailable in this build.
pub fn build_strategies(dynamic: &Dynamic) -> Result<Vec<Arc<dyn Strategy>>, StrategyError> {
    build_strategies_gated(dynamic, &Gates::from_status(crawlx_core::gates::GateStatus::ALL))
}

/// [`build_strategies`] through the strategy registry: `state_novelty` and `enablement` are
/// refused unless `gates` attests G1.
/// Model-less harnesses use seed zero, an empty principal and run index zero for configured
/// arms. Live sessions use their actual identity through [`build_strategy_set`].
///
/// # Errors
/// Rejects invalid arms, unavailable versions and absent milestone gates.
pub fn build_strategies_gated(
    dynamic: &Dynamic,
    gates: &Gates,
) -> Result<Vec<Arc<dyn Strategy>>, StrategyError> {
    let strategies = build_strategy_versions_gated(dynamic, gates)?;
    let (selected, _) = select_strategy_arms(
        dynamic,
        gates,
        CrawlSeed(0),
        &crawlx_core::PrincipalId(String::new()),
        0,
        strategies,
    )?;
    Ok(selected)
}

fn build_strategy_versions_gated(
    dynamic: &Dynamic,
    gates: &Gates,
) -> Result<Vec<Arc<dyn Strategy>>, StrategyError> {
    dynamic
        .validate_strategy_arms()
        .map_err(|error| StrategyError::Internal(error.to_string()))?;
    let mut out = Vec::with_capacity(dynamic.strategies.len() + 1);
    for &name in &dynamic.strategies {
        if name == StrategyName::System1 {
            tracing::debug!("system1 needs a model engine; skipped by the model-less builder");
            continue;
        }
        if let Some(arms) = dynamic.strategy_arms.get(&name) {
            for arm in arms {
                out.push(registry::build_version(name, arm.version, gates)?);
            }
        } else {
            out.push(registry::build(name, gates)?);
        }
    }
    out.push(Arc::new(UrlPlane::new(UrlPlaneConfig::default())));
    Ok(out)
}

/// Selected strategy fan-out paired with configured assignment records.
pub type SelectedStrategyArms = (Vec<Arc<dyn Strategy>>, Vec<StrategyArmSelection>);

/// Select configured arms from real supplied implementations, retaining other strategies.
///
/// This also serves local harnesses that supply several actual versions of one strategy.
/// Registration never alters `Strategy::version()` or a proposal's attribution. With no arm
/// configuration the supplied vector is returned unchanged.
///
/// # Errors
/// Rejects invalid configuration, absent milestone gates, duplicate supplied versions and
/// configured versions missing from the supplied implementations.
pub fn select_strategy_arms(
    dynamic: &Dynamic,
    gates: &Gates,
    seed: CrawlSeed,
    role: &crawlx_core::PrincipalId,
    run_index: u16,
    strategies: Vec<Arc<dyn Strategy>>,
) -> Result<SelectedStrategyArms, StrategyError> {
    if dynamic.strategy_arms.is_empty() {
        return Ok((strategies, Vec::new()));
    }
    dynamic
        .validate_strategy_arms()
        .map_err(|error| StrategyError::Internal(error.to_string()))?;
    let mut selected = BTreeMap::new();
    let mut assignments = Vec::with_capacity(dynamic.strategy_arms.len());
    for (&name, arms) in &dynamic.strategy_arms {
        let strategy_name = registry::strategy_name(name);
        if let Some(gate) = registry::gate_for(name) {
            gates.require(strategy_name, gate)?;
        }
        let mut armed = crawlx_strategies::ArmedStrategy::new(strategy_name);
        for strategy in &strategies {
            if strategy.name() == strategy_name {
                if let Some(arm) = arms.iter().find(|arm| arm.version == strategy.version()) {
                    armed.register(Arc::clone(strategy), arm.weight)?;
                }
            }
        }
        for arm in arms {
            if !armed.versions().any(|version| version == arm.version) {
                return Err(StrategyError::UnavailableVersion {
                    strategy: strategy_name,
                    version: arm.version,
                });
            }
        }
        let (arm, strategy) = armed.pick(seed, role, run_index)?;
        assignments.push(StrategyArmSelection::new(
            strategy_name.to_owned(),
            arm.version,
            arm.weight,
        ));
        selected.insert(strategy_name, strategy);
    }
    let out = strategies
        .into_iter()
        .filter_map(|strategy| {
            if dynamic
                .strategy_arms
                .keys()
                .any(|&name| registry::strategy_name(name) == strategy.name())
            {
                selected.remove(strategy.name())
            } else {
                Some(strategy)
            }
        })
        .collect();
    Ok((out, assignments))
}

/// Strategy name of [`DiscoveredUrls`].
pub const DISCOVERED_URLS_STRATEGY: &str = "discovered_urls";
/// Proposals [`DiscoveredUrls`] makes per round.
pub const DISCOVERED_URLS_PER_ROUND: usize = 5;
/// Depth recorded on `url_frontier` for a URL the browser plane discovered (one hop from the
/// page the session showed).
pub const DISCOVERED_URL_DEPTH: u16 = 1;

/// Record a document the browser guard or discovery pre-flight refused.
/// Robots refusals count as `robots_blocked`; egress refusals count as `policy_blocked`.
/// Hybrid runs retain the same frontier status and reason as the URL plane.
/// Nothing was fetched and no page is stored.
pub(crate) async fn record_robots_blocked(
    rc: &RunContext,
    session: Option<crawlx_core::SessionId>,
    url: &CanonicalUrl,
    depth: u16,
    reason: &str,
) {
    let (status, refused_outcome, event) = if reason == "egress_denied" {
        (
            FrontierStatus::PolicyBlocked,
            DiscoveryOutcome::PolicyBlocked,
            "egress_denied",
        )
    } else {
        (
            FrontierStatus::RobotsBlocked,
            DiscoveryOutcome::RobotsBlocked,
            "robots_blocked",
        )
    };
    let outcome = if rc.crawl.mode == CrawlMode::Hybrid {
        match rc
            .stores
            .frontier
            .discover(rc.run, url, depth, None, Some((status, reason.to_owned())))
            .await
        {
            Ok((outcome, _)) => outcome,
            Err(e) => {
                tracing::warn!(error = %e, "robots-blocked url not recorded on the frontier");
                refused_outcome
            }
        }
    } else {
        refused_outcome
    };
    rc.counters.discovery(Plane::Urls, outcome);
    if let Err(e) = rc
        .stores
        .events
        .append(
            rc.run,
            event,
            serde_json::json!({
                "url": url.url.as_str(),
                "reason": reason,
                "plane": "browser",
                "depth": depth,
                "sessionId": session.map(|s| s.0),
            }),
        )
        .await
    {
        tracing::warn!(error = %e, "robots_blocked event not recorded");
    }
}

/// Strategy attribution of the tab policy's `SwitchTab`/`CloseTab` actions.
pub const TAB_POLICY: &str = "tab_policy";
/// Version of the tab policy, recorded on its actions.
pub const TAB_POLICY_VERSION: u32 = 2;

/// Synthetic element identity of "the tab showing this URL" for tab-policy keys.
#[must_use]
pub fn tab_element(url: &str) -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("crawlx/tab-nav/v1", url.as_bytes()))
}

/// Synthetic element identity of "the URL a page hook discovered" (`text` is its canonical
/// string) for [`DiscoveredUrls`] keys.
#[must_use]
pub fn discovered_url_element(text: &str) -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("crawlx/worker/discovered-url", text.as_bytes()))
}

fn popup_in_scope(
    raw: &str,
    origin: &url::Origin,
    scope: Option<&ScopePolicy>,
    canon: &crawlx_url::CanonicalizeOptions,
) -> bool {
    url::Url::parse(raw)
        .ok()
        .filter(|u| &u.origin() == origin)
        .and_then(|u| crawlx_url::Canonicalizer::canonicalize_url(&u, canon).ok())
        .is_some_and(|url| {
            !matches!(
                scope.map(|s| s.decide(&url, DISCOVERED_URL_DEPTH)),
                Some(ScopeVerdict::Denied(_))
            )
        })
}

fn eviction_victim<'a>(
    tabs: &'a [crawlx_core::observation::TabInfo],
    home: &crawlx_core::TabId,
    usefulness: &BTreeMap<String, (usize, u64)>,
) -> Option<&'a crawlx_core::observation::TabInfo> {
    tabs.iter()
        .filter(|t| !t.pending && &t.id != home)
        .min_by_key(|t| usefulness.get(&t.id.0).copied().unwrap_or((usize::MAX, 0)))
}
/// The kernel rule that denies external communication for want of a verified test sink
/// (`crawlx_safety::profiles::decide`); verdicts carrying it count as
/// `form.denied_no_sink`.
const SINK_REQUIRED_RULE: &str = "sink.required_unverified";

/// URLs the page hooks discovered, shared between the driver that fills it
/// after each observation and the [`DiscoveredUrls`] strategy that proposes them.
type DiscoveredSet = Arc<Mutex<BTreeMap<String, url::Url>>>;

/// Proposes `Navigate` to in-scope URLs the page hooks reported (`pushState`, `fetch`,
/// `WebSocket`, `window.open`, ...), the browser-plane twin of [`UrlPlane`] for destinations
/// that have no link element. Not a pure function of the round: its input is the driver's
/// discovery set (filled from `ObservationBundle::discovered_urls`, scope-checked and
/// logout-filtered), ordered by URL so a run replays identically. Keys use the URL's digest
/// as the element identity.
pub struct DiscoveredUrls {
    pending: DiscoveredSet,
}

#[async_trait]
impl Strategy for DiscoveredUrls {
    async fn propose(&self, ctx: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        let pending = self.pending.lock().clone();
        let mut out = Vec::new();
        for (text, url) in pending {
            if ctx.frontier.url_visited(&text) {
                continue;
            }
            let key = ActionContextKey {
                principal: ctx.principal.clone(),
                route_template: ctx.route().clone(),
                element: discovered_url_element(&text),
                action_kind: ActionKind::Navigate,
                input_class: InputClass::none(),
                resource_context: ResourceContext::None,
                state_cluster: ctx.cluster,
            };
            if !ctx.frontier.is_proposable(&key) {
                continue;
            }
            out.push(ActionProposal {
                key,
                action: BrowserAction::Navigate { url },
                epoch: ctx.bundle.epoch,
                strategy: DISCOVERED_URLS_STRATEGY,
                strategy_version: 1,
                confidence: 0.5,
                expected: ExpectedEffect {
                    reveals: Vec::new(),
                    navigates_to: Some(text.clone()),
                    mutates_state: false,
                },
                hinted_risk: None,
                model_decision: None,
                summary: format!("navigate discovered {text}"),
            });
            if out.len() >= DISCOVERED_URLS_PER_ROUND {
                break;
            }
        }
        Ok(out)
    }

    fn name(&self) -> &'static str {
        DISCOVERED_URLS_STRATEGY
    }

    fn version(&self) -> u32 {
        1
    }
}

/// Does the proposal navigate (or expect to navigate, e.g. a click on a link) to a logout
/// path? `page` resolves relative hrefs.
fn targets_logout(p: &ActionProposal, page: &url::Url) -> bool {
    let navigate = match &p.action {
        BrowserAction::Navigate { url } => is_logout_path(url.path()),
        _ => false,
    };
    navigate
        || p.expected
            .navigates_to
            .as_deref()
            .and_then(|u| page.join(u).ok())
            .is_some_and(|u| is_logout_path(u.path()))
}

/// Drives one session's exploration.
pub struct ExplorationDriver {
    cfg: DriverConfig,
    rc: Arc<RunContext>,
    session: crawlx_core::repo::CrawlSession,
    handle: SessionHandle,
    analyzer: Arc<StateAnalyzer>,
    strategies: Vec<Arc<dyn Strategy>>,
    state: ExplorationState,
    switching: SwitchingPolicy,
    arbiter: Arbiter,
    scope: Option<ScopePolicy>,
    decision_index: u64,
    seen_ops: BTreeSet<String>,
    retry: BTreeMap<ActionContextId, ActionId>,
    blocked_seen: BTreeSet<ActionContextId>,
    /// Records of System 1 calls waiting to be written to `model_decisions`.
    records: Option<mpsc::Receiver<System1Record>>,
    /// Records taken off the channel while the round ran (dataset recording), written to
    /// `model_decisions` by the next flush.
    held_records: Vec<System1Record>,
    /// Ambiguous-band aliases waiting to be written to `identity_aliases`.
    pending_aliases: Vec<IdentityAlias>,
    /// The LLM planner, when one is part of the strategy set.
    planner: Option<Arc<LlmPlanner>>,
    /// Keys ignored until the given decision index (cooldown after a dropped action).
    suppressed: BTreeMap<ActionContextId, u64>,
    drop_counts: BTreeMap<ActionContextId, u32>,
    /// Live evidence from a confirmation refusal; the next adjudication of the key uses it.
    live_facts: BTreeMap<ActionContextId, LiveTargetFacts>,
    consecutive_drops: u32,
    actions: u64,
    states: u64,
    /// The session logged in: logout paths are excluded.
    authenticated: bool,
    /// URLs the page hooks discovered, fed to [`DiscoveredUrls`] (`dynamic.pageHooks`).
    discovered: DiscoveredSet,
    /// Canonical keys of discovered URLs already recorded (frontier + proposals), so a URL
    /// the hooks report on every page is handled once per session.
    discovered_seen: BTreeSet<Digest>,
    /// Splits of the run's cluster index this session has already re-keyed its ledger for.
    splits_seen: usize,
    /// Identities the last trusted activation revealed that are still to be exercised
    /// (reveal follow-through).
    follow_through: BTreeSet<ElementIdentityHash>,
    /// The tab the session started on; popups are explored and closed back to it.
    home_tab: Option<crawlx_core::TabId>,
    /// Pages (canonical keys) observed on the home tab; a popup that navigates onto one of
    /// them is closed.
    home_pages: BTreeSet<Digest>,
    /// Popup tabs the session already switched to (each is explored once).
    explored_tabs: BTreeSet<String>,
    /// Actions executed on the current popup tab (reset on every switch).
    tab_steps: u32,
    /// Latest worker frontier depth and logical last-use index for each admitted tab.
    tab_usefulness: BTreeMap<String, (usize, u64)>,
    home_origin: Option<url::Origin>,
    /// Rounds whose chosen action reached the browser (`dynamic.enableDiagnostics`).
    steps: u64,
    /// Executed actions the actor dropped before they ran.
    drops: u64,
    /// Popup tabs the tab policy closed to stay within `dynamic.maxTabs`.
    tab_evictions: u64,
    role_budget: Option<RoleBudget>,
}

/// The observation a round starts from, already folded into the exploration state.
struct Prepared {
    bundle: Arc<ObservationBundle>,
    /// The persisted state of this observation (the `before_state` of the round's action).
    state: StateId,
    cluster: StateClusterId,
    /// Moved into the round's `DecisionContext` (taken once per round).
    candidates: Vec<Candidate>,
    resolved: Vec<ResolvedElement>,
    /// Identities visible in this observation (kept after the candidates were handed out).
    identities: BTreeSet<ElementIdentityHash>,
}

impl ExplorationDriver {
    #[must_use]
    /// New.
    pub fn new(
        mut cfg: DriverConfig,
        rc: Arc<RunContext>,
        session: crawlx_core::repo::CrawlSession,
        handle: SessionHandle,
        analyzer: Arc<StateAnalyzer>,
        mut strategies: Vec<Arc<dyn Strategy>>,
    ) -> Self {
        let mut exploration = cfg.exploration;
        exploration.profile = rc.crawl.safety.profile;
        exploration.target_isolation = rc.crawl.target_isolation;
        cfg.apply_dynamic(&rc.crawl.dynamic);
        let state = ExplorationState::new(
            rc.run,
            session.role.clone(),
            session_seed(rc.seed, &session),
            exploration,
        )
        .with_form_values(rc.form_values());
        // the record's target is a hard bound on every URL the browser plane discovers
        let scope = ScopePolicy::new(&rc.crawl)
            .ok()
            .map(|scope| match &rc.authorization {
                Some(guard) => scope.with_record_scope(guard.scope()),
                None => scope,
            });
        let discovered: DiscoveredSet = Arc::new(Mutex::new(BTreeMap::new()));

        if rc.crawl.dynamic.page_hooks {
            strategies.push(Arc::new(DiscoveredUrls {
                pending: Arc::clone(&discovered),
            }));
        }
        Self {
            switching: SwitchingPolicy::new(cfg.switching),
            arbiter: Arbiter::new(cfg.arbiter),
            cfg,
            rc,
            records: None,
            held_records: Vec::new(),
            pending_aliases: Vec::new(),
            planner: None,
            session,
            handle,
            analyzer,
            strategies,
            state,
            scope,
            decision_index: 0,
            seen_ops: BTreeSet::new(),
            retry: BTreeMap::new(),
            blocked_seen: BTreeSet::new(),
            suppressed: BTreeMap::new(),
            drop_counts: BTreeMap::new(),
            live_facts: BTreeMap::new(),
            consecutive_drops: 0,
            actions: 0,
            states: 0,
            authenticated: false,
            discovered,
            discovered_seen: BTreeSet::new(),
            splits_seen: 0,
            home_tab: None,
            explored_tabs: BTreeSet::new(),
            tab_steps: 0,
            tab_usefulness: BTreeMap::new(),
            home_origin: None,
            steps: 0,
            drops: 0,
            tab_evictions: 0,
            follow_through: BTreeSet::new(),
            home_pages: BTreeSet::new(),
            role_budget: None,
        }
    }

    /// The session is logged in: navigations to logout paths are excluded from proposals and
    /// from the browser plane's frontier discovery while it stays so.
    #[must_use]
    pub const fn with_authenticated(mut self, authenticated: bool) -> Self {
        self.authenticated = authenticated;
        self
    }

    #[must_use]
    pub(crate) fn with_role_budget(mut self, budget: RoleBudget) -> Self {
        self.role_budget = Some(budget);
        self
    }

    /// Attach the side channels of the model-backed strategies in `overlay`: System 1 records
    /// are written to `model_decisions`, the planner's steps are reported back and its finished
    /// plans merged into the frontier. `system1` engages the switching policy's overlay phase.
    #[must_use]
    pub fn with_model_overlay(mut self, overlay: ModelOverlay, system1: bool) -> Self {
        self.records = overlay.records;
        self.planner = overlay.planner;
        if system1 {
            self.cfg.switching.system1_enabled = true;
            self.switching = SwitchingPolicy::new(self.cfg.switching);
        }
        self
    }

    /// The exploration state (ledger, graph) for inspection after the run.
    #[must_use]
    pub const fn exploration(&self) -> &ExplorationState {
        &self.state
    }

    /// Run until the session has nothing left to do or a limit, deadline or cancel stops it.
    /// `start` lists the pages to cover: the first is the page the session already shows.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn run(&mut self, start: Vec<RequestEnvelopeV1>) -> Result<DriverEnd, WorkerError> {
        let started = Instant::now();
        let result = self.explore_session(start).await;
        self.collect_xhr().await;
        self.record_diagnostics(started, &result);
        result
    }

    async fn explore_session(&mut self, mut start: Vec<RequestEnvelopeV1>) -> Result<DriverEnd, WorkerError> {
        if let (Some((url, route)), Some(request)) = (self.resume_if_recovering().await?, start.first_mut()) {
            request.url = url;
            request.route = route;
        }
        if self.role_budget.is_none() {
            self.role_budget = Some(RoleBudget::load(&self.rc, &self.session).await?);
        }
        let observe_only = self.cfg.observe_only
            || self.rc.crawl.dynamic.observe_only
            || self.rc.crawl.limits.interactions == 0;
        let result = if observe_only {
            self.run_observe_only(start).await
        } else {
            self.run_explore(start).await
        };
        self.persist_graph().await;
        if let Err(e) = self
            .rc
            .counters
            .persist(self.rc.stores.runs.as_ref(), self.rc.run)
            .await
        {
            tracing::warn!(error = %e, "counters not persisted");
        }
        result
    }

    fn end(&self, terminal: TerminalReason) -> DriverEnd {
        DriverEnd {
            terminal,
            actions: self.actions,
            states: self.states,
        }
    }

    /// File the XHR and `fetch()` requests the browser saw since the last call under their pages
    /// (`extract.xhr`); the run attaches them to the page records when the planes are done.
    async fn collect_xhr(&self) {
        if !self.rc.crawl.extract.xhr {
            return;
        }
        match self.handle.drain_xhr().await {
            Ok(records) => self.rc.xhr.record(records, &self.rc.canon),
            Err(e) => tracing::debug!(error = %e, "xhr requests not collected"),
        }
    }

    /// Deposit this session's diagnostics (`dynamic.enableDiagnostics`) in the run's sink.
    fn record_diagnostics(&self, started: Instant, result: &Result<DriverEnd, WorkerError>) {
        if !self.rc.crawl.dynamic.enable_diagnostics {
            return;
        }
        let stats = self.handle.stats();
        self.rc.diagnostics.push(SessionDiagnostics {
            role: self.session.role.0.clone(),
            run_index: self.session.run_index,
            steps: self.steps,
            actions: self.actions,
            drops: self.drops,
            recoveries: stats.recoveries(),
            tab_evictions: self.tab_evictions,
            states: self.states,
            scroll_steps: stats.scroll_steps(),
            stop_reason: match result {
                Ok(end) => end.terminal.as_str().to_owned(),
                Err(_) => "error".to_owned(),
            },
            wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
    }

    /// A navigation the browser refused under `robots.txt`: record it like a URL the URL plane
    /// blocked ([`record_robots_blocked`]). `raw` is the URL as the browser saw it.
    async fn note_robots_blocked(&self, raw: &str, reason: &str) {
        let Ok(parsed) = url::Url::parse(raw) else {
            return;
        };
        let Ok(canon) = crawlx_url::Canonicalizer::canonicalize_url(&parsed, &self.rc.canon) else {
            return;
        };
        record_robots_blocked(
            &self.rc,
            Some(self.session.id),
            &canon,
            DISCOVERED_URL_DEPTH,
            reason,
        )
        .await;
    }

    /// Why `robots.txt` forbids the browser plane to load `canon` (`robots_disallow`,
    /// `robots_unavailable`), `None` when it may. The check the browser's own guard makes, run
    /// ahead of time so a URL it would refuse is never queued. `None` for a run whose browser
    /// plane does not obey `robots.txt` ([`RunContext::browser_guard`]).
    async fn robots_refusal(&self, canon: &CanonicalUrl) -> Option<&'static str> {
        match self.rc.browser_guard()?.decide(&canon.origin, &canon.url).await {
            RobotsDecision::Allowed => None,
            RobotsDecision::Blocked(why) => Some(why),
            RobotsDecision::EgressDenied => Some("egress_denied"),
        }
    }

    /// Go back to the admitted request's page, where a chain of interactions started
    /// (`dynamic.interactionDepth`). A crashed browser recovers first; any other failure is
    /// logged and the next round re-observes wherever the browser is.
    async fn return_to(&self, request: RequestEnvelopeV1) -> Result<(), WorkerError> {
        let url = request.url.clone();
        match self.handle.navigate(request).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_target_crash() => self.ensure_session_usable().await,
            Err(SessionError::Browser(BrowserError::RobotsBlocked { url: refused, reason })) => {
                // robots.txt now disallows the page the chain started from: stay where we are
                self.note_robots_blocked(&refused, reason).await;
                Ok(())
            }
            Err(
                error @ (SessionError::ExecutionDeadlineReached
                | SessionError::Binding(_)
                | SessionError::Store(_)
                | SessionError::HaltedStorage(_)),
            ) => Err(error.into()),
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "could not return to the page after the interaction depth");
                Ok(())
            }
        }
    }

    /// Keep the candidates `dynamic.interactionSelector` admits and `dynamic.interactionExclude`
    /// does not reject, judged in the page. When the filter cannot be evaluated nothing is
    /// explored this round: a restriction the operator asked for is never skipped.
    async fn filter_candidates(&self, discovered: Vec<Candidate>) -> Vec<Candidate> {
        let dynamic = &self.rc.crawl.dynamic;
        let filter = CssFilter {
            include: dynamic.interaction_selector.clone(),
            exclude: dynamic.interaction_exclude.clone(),
        };
        if filter.is_empty() || discovered.is_empty() {
            return discovered;
        }
        let targets = discovered.iter().map(|c| c.descriptor.locator.clone()).collect();
        match self.handle.css_filter(filter, targets).await {
            Ok(admitted) if admitted.len() == discovered.len() => discovered
                .into_iter()
                .zip(admitted)
                .filter_map(|(candidate, keep)| keep.then_some(candidate))
                .collect(),
            Ok(admitted) => {
                tracing::warn!(
                    candidates = discovered.len(),
                    verdicts = admitted.len(),
                    "interaction filter answered for a different number of elements; exploring nothing"
                );
                Vec::new()
            }
            Err(e) => {
                tracing::warn!(error = %e, "interaction filter could not be evaluated; exploring nothing");
                Vec::new()
            }
        }
    }

    // ---- shared plumbing ----------------------------------------------------------------

    async fn event(&self, kind: &str, payload: serde_json::Value) {
        if let Err(e) = self.rc.stores.events.append(self.rc.run, kind, payload).await {
            tracing::warn!(error = %e, kind, "event not recorded");
        }
    }

    /// Authorization, cancellation, run pause/cancel, the cluster freeze flag and budget checks,
    /// in that order.
    async fn stop_reason(&self) -> Result<Option<TerminalReason>, WorkerError> {
        loop {
            // A revoked or expired record ends the session (checked first, so the
            // run reports `authorization_revoked` and not the cancellation the guard raised)
            if let Some(guard) = &self.rc.authorization {
                if guard.check_now().await.is_err() {
                    return Ok(Some(TerminalReason::AuthorizationRevoked));
                }
            }
            if self.rc.cancel.is_cancelled() {
                return Ok(Some(TerminalReason::Cancelled));
            }
            let run = self.rc.stores.runs.get(self.rc.run).await?;
            // Runbook RB-11 (docs/ops/runbooks.md): `scheduler.admission = frozen` halts every actor at its next boundary
            let frozen = self.rc.stores.leases.admission().await? == crawlx_storage::AdmissionMode::Frozen;
            match run.status {
                RunStatus::Cancelled => return Ok(Some(TerminalReason::Cancelled)),
                RunStatus::Paused => {
                    let _ = self.handle.pause().await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                _ if frozen => {
                    let _ = self.handle.pause().await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                _ => break,
            }
        }
        if self.handle.state() == SessionState::Paused {
            let _ = self.handle.resume().await;
        }
        let now = self.rc.clock.now();
        Ok(self
            .rc
            .budget
            .lock()
            .exhausted(now)
            .or_else(|| self.role_budget.as_ref().and_then(|budget| budget.exhausted(now))))
    }

    /// After a crash the actor recovers on its own; wait for it and surface exhaustion.
    async fn ensure_session_usable(&self) -> Result<(), WorkerError> {
        let s = self
            .handle
            .wait_state(|s| {
                matches!(
                    s,
                    SessionState::Ready | SessionState::Authenticating | SessionState::Failed
                )
            })
            .await;
        match s {
            SessionState::Failed | SessionState::Closed => {
                self.handle.wait_state(|_| false).await;
                Err(self.handle.closed_error().into())
            }
            _ => Ok(()),
        }
    }

    async fn observe(&self) -> Result<Arc<ObservationBundle>, WorkerError> {
        let mut last: Option<SessionError> = None;
        for _ in 0..3 {
            match self.handle.observe(spec::after_action()).await {
                Ok(b) => {
                    self.collect_xhr().await;
                    return Ok(b);
                }
                Err(e) if e.is_target_crash() => {
                    last = Some(e);
                    self.ensure_session_usable().await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(WorkerError::Session(last.unwrap_or(SessionError::ActorGone)))
    }

    /// Fingerprint, cluster and persist the current page.
    async fn persist_observation(
        &mut self,
        bundle: &Arc<ObservationBundle>,
    ) -> Result<NewState, WorkerError> {
        let analyzed = self.analyzer.analyze(bundle).await;
        self.analyzer.record_metrics(&analyzed, &self.session.role.0);
        self.persist_state(&analyzed.state).await?;
        Ok(analyzed.state)
    }

    async fn persist_state(&mut self, st: &NewState) -> Result<(), WorkerError> {
        self.rc.stores.states.put_state(st).await?;
        self.states += 1;
        Metrics::global()
            .counter(names::STATES_OBSERVED)
            .inc_by(1, &[("role", &self.session.role.0)]);
        self.rc.counters.discovery(
            Plane::States,
            if st.cluster_is_new {
                DiscoveryOutcome::Admitted
            } else {
                DiscoveryOutcome::Duplicate
            },
        );
        self.rc.counters.attempt(Plane::States, Attempt::Succeeded);
        if st.cluster_is_new {
            self.charge_budget(BudgetKind::States);
        }
        self.event(
            "state",
            serde_json::json!({
                "stateId": st.id.0,
                "clusterId": st.cluster.0,
                "novel": st.cluster_is_new,
                "url": st.url.url.as_str(),
                "sessionId": self.session.id.0,
            }),
        )
        .await;
        self.learn_route(st.url.url.path()).await;
        Ok(())
    }

    /// Feed one observed path to the run's route learner; a rule
    /// change is persisted as the `route_templates` run event so a resumed run keys URLs the
    /// same way.
    async fn learn_route(&self, path: &str) {
        if let Some(snapshot) = self.rc.routes.observe(path) {
            if let Err(e) =
                RouteLearner::persist(self.rc.stores.events.as_ref(), self.rc.run, &snapshot).await
            {
                tracing::warn!(error = %e, "route templates not persisted");
            }
        }
    }

    fn safety_base(&self) -> SafetyContext {
        safety_context(&self.rc, &self.session)
    }

    /// Fold the page-hooks discoveries of `bundle` in: each URL is
    /// canonicalized, checked against the crawl scope and, while the session is
    /// authenticated, against the logout paths. In `hybrid` mode every outcome is recorded on
    /// `url_frontier` (depth [`DISCOVERED_URL_DEPTH`], denials as `policy_blocked`) and
    /// counted on the URL plane; admitted URLs also become navigation proposals through
    /// [`DiscoveredUrls`] in both `hybrid` and `dynamic` mode.
    async fn ingest_discovered(&mut self, bundle: &ObservationBundle) {
        if !self.rc.crawl.dynamic.page_hooks || bundle.discovered_urls.is_empty() {
            return;
        }
        let record = self.rc.crawl.mode == CrawlMode::Hybrid;
        for (raw, source) in &bundle.discovered_urls {
            let Ok(joined) = bundle.url.url.join(raw) else {
                continue;
            };
            if !matches!(joined.scheme(), "http" | "https") {
                continue;
            }
            let Ok(canon) = crawlx_url::Canonicalizer::canonicalize_url(&joined, &self.rc.canon) else {
                continue;
            };
            if !self.discovered_seen.insert(canon.key) {
                continue;
            }
            let denial: Option<(FrontierStatus, String)> = if canon
                .params
                .iter()
                .any(|param| param.class == crawlx_core::ParamClass::ActionBearing)
            {
                Some((FrontierStatus::PolicyBlocked, "action_bearing_query".to_owned()))
            } else if self.authenticated && is_logout_path(canon.url.path()) {
                Some((FrontierStatus::PolicyBlocked, "logout_path".to_owned()))
            } else {
                match self
                    .scope
                    .as_ref()
                    .map(|s| s.decide(&canon, DISCOVERED_URL_DEPTH))
                {
                    Some(ScopeVerdict::Denied(reason)) => {
                        Some((FrontierStatus::PolicyBlocked, reason.as_str().to_owned()))
                    }
                    _ => None,
                }
            };
            if denial.is_none() {
                // robots.txt applies to the browser plane exactly as to the URL plane
                if let Some(why) = self.robots_refusal(&canon).await {
                    record_robots_blocked(&self.rc, Some(self.session.id), &canon, DISCOVERED_URL_DEPTH, why)
                        .await;
                    continue;
                }
            }
            tracing::debug!(source, denied = denial.is_some(), "page hook discovered a url");
            if record {
                match self
                    .rc
                    .stores
                    .frontier
                    .discover(self.rc.run, &canon, DISCOVERED_URL_DEPTH, None, denial.clone())
                    .await
                {
                    Ok((outcome, _)) => self.rc.counters.discovery(Plane::Urls, outcome),
                    Err(e) => tracing::warn!(error = %e, "discovered url not recorded on the frontier"),
                }
            }
            if denial.is_none() {
                self.learn_route(canon.url.path()).await;
                self.discovered
                    .lock()
                    .insert(canon.url.to_string(), canon.url.clone());
            }
        }
    }

    // ---- observe-only -------------------------------------------------------------------

    /// Navigate and observe, never act: a breadth-first walk over in-scope links.
    async fn run_observe_only(&mut self, start: Vec<RequestEnvelopeV1>) -> Result<DriverEnd, WorkerError> {
        let mut queue: VecDeque<RequestEnvelopeV1> = start.into();
        let mut visited: BTreeMap<Digest, BTreeSet<String>> = BTreeMap::new();
        let mut first = true;
        while let Some(request) = queue.pop_front() {
            let url = &request.url;
            let depth = request.depth;
            if !visited.entry(url.key).or_default().insert(request.route.clone()) {
                continue;
            }
            if let Some(reason) = self.stop_reason().await? {
                return Ok(self.end(reason));
            }
            if !first {
                if let Err(e) = self.handle.navigate(request.clone()).await {
                    if matches!(
                        &e,
                        SessionError::ExecutionDeadlineReached
                            | SessionError::Binding(_)
                            | SessionError::Store(_)
                            | SessionError::HaltedStorage(_)
                    ) {
                        return Err(e.into());
                    }
                    if let SessionError::Browser(BrowserError::RobotsBlocked { url: refused, reason }) = &e {
                        self.note_robots_blocked(refused, reason).await;
                        continue;
                    }
                    if e.is_target_crash() {
                        self.ensure_session_usable().await?;
                    }
                    tracing::warn!(url = %url, error = %e, "navigation failed; page skipped");
                    continue;
                }
            }
            first = false;
            let bundle = self.observe().await?;
            let state = self.persist_observation(&bundle).await?;
            let _ = state;
            self.ingest_discovered(&bundle).await;
            for cand in CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default()) {
                let Some(href) = cand.descriptor.href.as_deref() else {
                    continue;
                };
                let Ok(joined) = bundle.url.url.join(href) else {
                    continue;
                };
                if !matches!(joined.scheme(), "http" | "https") {
                    continue;
                }
                let Ok(canon) = crawlx_url::Canonicalizer::canonicalize_url(&joined, &self.rc.canon) else {
                    continue;
                };
                let admitted = self
                    .scope
                    .as_ref()
                    .is_none_or(|s| s.decide(&canon, depth.saturating_add(1)).is_admitted());
                if admitted
                    && visited
                        .get(&canon.key)
                        .is_none_or(|labels| !labels.contains("default"))
                {
                    if canon
                        .params
                        .iter()
                        .any(|param| param.class == crawlx_core::ParamClass::ActionBearing)
                    {
                        visited.entry(canon.key).or_default().insert("default".into());
                        let (outcome, _) = self
                            .rc
                            .stores
                            .frontier
                            .discover(
                                self.rc.run,
                                &canon,
                                depth.saturating_add(1),
                                None,
                                Some((FrontierStatus::PolicyBlocked, "action_bearing_query".into())),
                            )
                            .await?;
                        self.rc
                            .counters
                            .discovery_with_reason(Plane::Urls, outcome, "action_bearing_query");
                        continue;
                    }
                    if let Some(why) = self.robots_refusal(&canon).await {
                        // counted once, however many pages link to it
                        visited.entry(canon.key).or_default().insert("default".into());
                        record_robots_blocked(
                            &self.rc,
                            Some(self.session.id),
                            &canon,
                            depth.saturating_add(1),
                            why,
                        )
                        .await;
                        continue;
                    }
                    queue.push_back(RequestEnvelopeV1::get(canon, depth.saturating_add(1), None));
                }
            }
        }
        Ok(self.end(TerminalReason::FrontierExhausted))
    }

    // ---- recovery of a previous holder ----------------------------------------------------

    /// A session claimed in `recovering` state: restore its newest checkpoint and reconcile
    /// every `unknown` action of its previous holder (never re-executing blindly).
    async fn resume_if_recovering(&mut self) -> Result<Option<(CanonicalUrl, String)>, WorkerError> {
        use crawlx_core::repo::SessionStatus;
        if self.session.status != SessionStatus::Recovering {
            return Ok(None);
        }
        let unknown: Vec<_> = self
            .rc
            .stores
            .journal
            .list(self.rc.run, Some(ActionStatus::Unknown))
            .await?
            .into_iter()
            .filter(|a| a.session == self.session.id)
            .collect();
        let mut restored = None;
        if let Some(cp) = self.rc.stores.checkpoints.latest(self.session.id).await? {
            match self.handle.restore(cp.id).await {
                Ok(report) => {
                    if let Some(route) = report.request_route {
                        let location = report
                            .navigation
                            .as_ref()
                            .map_or(report.url.as_str(), |navigation| navigation.final_url.as_str());
                        let url = url::Url::parse(location)
                            .map_err(|_| WorkerError::Other("invalid checkpoint resume URL".into()))?;
                        restored = Some((
                            crawlx_url::Canonicalizer::canonicalize_url(&url, &self.rc.canon)?,
                            route,
                        ));
                    }
                }
                Err(
                    error @ (SessionError::Extension(_)
                    | SessionError::CheckpointVersion
                    | SessionError::CheckpointEncoding(_)
                    | SessionError::ExecutionDeadlineReached
                    | SessionError::Binding(_)
                    | SessionError::Store(_)
                    | SessionError::HaltedStorage(_)),
                ) => return Err(error.into()),
                Err(error) => {
                    tracing::warn!(error = %error, "checkpoint restore failed; continuing from the seed");
                }
            }
        }
        for a in unknown {
            match self.handle.reconcile(a.id).await {
                Ok(r) => {
                    tracing::info!(action = %a.id, resolution = r.resolution.as_str(), "reconciled");
                    self.note_reconciled(&a.key, a.id, a.lane, r.resolution);
                }
                Err(e) => tracing::warn!(action = %a.id, error = %e, "reconcile failed"),
            }
        }
        // the previous holder may have died between a T2 commit and the flush of the run
        // counters: the journal rows are authoritative, so the stored snapshot is
        // re-derived and flushed before the session acts again
        let repaired = self
            .rc
            .counters
            .recover_from_journal(
                self.rc.stores.journal.as_ref(),
                self.rc.stores.runs.as_ref(),
                self.rc.run,
            )
            .await?;
        if repaired > 0 {
            tracing::info!(repaired, "run counters re-derived from the journal");
        }
        // reconciliation is done: the session is `running` again
        if let Err(e) = self
            .rc
            .stores
            .runs
            .set_session_status(self.session.id, crawlx_core::repo::SessionStatus::Running)
            .await
        {
            tracing::warn!(error = %e, "session status not restored to running");
        }
        Ok(restored)
    }

    // ---- exploration --------------------------------------------------------------------
    fn charge_budget(&mut self, kind: BudgetKind) {
        let _ = self.rc.budget.lock().try_consume(kind, 1);
        if let Some(budget) = &mut self.role_budget {
            budget.charge(kind);
        }
    }

    fn budget_view(&self) -> BudgetView {
        let now = self.rc.clock.now();
        let b = self.rc.budget.lock();
        let rem = b.remaining(now);
        let interactions = self
            .role_budget
            .as_ref()
            .and_then(RoleBudget::interactions_remaining)
            .map_or(rem.interactions, |n| n.min(rem.interactions));
        let limit = self.rc.crawl.limits.interactions;
        BudgetView {
            remaining_fraction: if limit == 0 {
                0.0
            } else {
                // permille in integers keeps the conversion exact and cast-free
                let permille = u64::from(interactions) * 1000 / u64::from(limit);
                f32::from(u16::try_from(permille).unwrap_or(1000)) / 1000.0
            },
            actions_remaining: (limit > 0).then_some(u64::from(interactions)),
            // without a planner in the strategy set the Planner phase must stay unreachable
            llm_planner: if self.planner.is_some() {
                self.rc.crawl.dynamic.llm_planner
            } else {
                crawlx_core::config::LlmPlannerMode::Off
            },
            planner_calls: self.planner.as_ref().map_or(0, |p| p.stats().calls),
            exhausted: b
                .exhausted(now)
                .or_else(|| self.role_budget.as_ref().and_then(|budget| budget.exhausted(now))),
            ..BudgetView::default()
        }
    }

    async fn run_explore(&mut self, start: Vec<RequestEnvelopeV1>) -> Result<DriverEnd, WorkerError> {
        let mut starts: VecDeque<RequestEnvelopeV1> = start.into();
        let Some(mut current_request) = starts.pop_front() else {
            return Ok(self.end(TerminalReason::FrontierExhausted));
        };
        let mut visited_starts: BTreeSet<(Digest, String)> = BTreeSet::new();
        let mut after: Option<Prepared> = None;
        let mut empty_rounds = 0u32;
        let depth = u32::from(self.rc.crawl.dynamic.interaction_depth);
        let mut chain = 0u32;
        let mut anchor: Option<RequestEnvelopeV1> = None;
        // the interaction phase of this session gets `dynamic.interactionDurationSeconds` of wall
        // time (read from the run's clock); `limits.durationSeconds` still bounds the whole run
        let interaction_deadline = (self.rc.crawl.dynamic.interaction_duration_seconds > 0).then(|| {
            self.rc.clock.now()
                + chrono::Duration::seconds(i64::from(self.rc.crawl.dynamic.interaction_duration_seconds))
        });
        let mut halts = 0u32;
        let mut storage_halt = None;
        let mut leave_popup = false;
        loop {
            if let Some(reason) = self.stop_reason().await? {
                if reason == TerminalReason::DeadlineReached {
                    if let Some(error) = storage_halt.take() {
                        return Err(SessionError::HaltedStorage(error).into());
                    }
                }
                return Ok(self.end(reason));
            }
            if interaction_deadline.is_some_and(|deadline| self.rc.clock.now() >= deadline) {
                tracing::info!("interaction duration reached; the session stops exploring");
                return Ok(self.end(TerminalReason::LimitReached));
            }
            let mut current = match after.take() {
                Some(p) => p,
                None => {
                    let b = self.observe().await?;
                    let st = self.persist_observation(&b).await?;
                    self.ingest_discovered(&b).await;
                    self.prepare(b, st.id, st.cluster).await
                }
            };
            if chain == 0 {
                let mut request = current_request.clone();
                request.url = current.bundle.url.clone();
                anchor = Some(request);
            }
            let now = self.rc.clock.now();
            let candidate_count = current.candidates.len();

            // phase
            let hidden = !self.state.reachable_hidden_targets().is_empty();
            let phase = {
                let budget = self.budget_view();
                self.switching
                    .next(self.state.stall(), &budget, hidden, candidate_count)
            };
            // tab policy: a popup is explored once and closed when covered or
            // when its step budget is spent; the home tab's `Done` moves to the next start page
            let done = phase == crawlx_strategies::Phase::Done || leave_popup;
            leave_popup = false;
            let tab_round = self.tab_step(&current.bundle, current.cluster, done);
            if tab_round.is_none() && phase == crawlx_strategies::Phase::Done {
                // the current page is covered: move on to the next start page, if any
                match self.next_start(&mut starts, &mut visited_starts).await? {
                    Some(request) => {
                        current_request = request;
                        self.switching = SwitchingPolicy::new(self.cfg.switching);
                        chain = 0;
                        continue;
                    }
                    None => {
                        return Ok(self.end(
                            self.switching
                                .done_reason()
                                .unwrap_or(TerminalReason::FrontierExhausted),
                        ))
                    }
                }
            }

            // decide
            self.decision_index += 1;
            self.state.begin_round(self.decision_index);
            let phase_span = spans::phase_span(&self.rc.run, phase_name(phase));
            let round_span = under(&phase_span, || {
                spans::policy_round_span(&self.rc.run, self.decision_index)
            });
            let base = self.safety_base();
            let on_popup = self.is_popup(&current.bundle.tab);
            let (chosen_admitted, chosen_proposal, parked, shortlist_note) = if let Some(p) = tab_round {
                // the tab policy bypasses the strategies, never the kernel
                let sc = SafetyContext {
                    target: LiveTargetFacts {
                        current_url: current.bundle.url.url.to_string(),
                        ..LiveTargetFacts::default()
                    },
                    ..base.clone()
                };
                let verdict = self.rc.kernel.adjudicate(p.clone(), &sc);
                (Some((p.clone(), verdict)), Some(p), Vec::new(), None)
            } else {
                async {
                    let round_input = RoundInput::new(
                        Arc::clone(&current.bundle),
                        std::mem::take(&mut current.candidates),
                        std::mem::take(&mut current.resolved),
                        current.cluster,
                        self.decision_index,
                        self.rc.crawl.safety.profile,
                        self.budget_view(),
                        now,
                    )
                    .with_phase(phase);
                    let ctx = self
                        .state
                        .context(round_input)
                        .map_err(|e| WorkerError::Other(e.to_string()))?;
                    // the runner drives every strategy concurrently, so one span covers them all
                    let strategy_round = run_strategies(&self.strategies, &ctx, &self.cfg.deadlines)
                        .instrument(child::deterministic_proposals("all", 0))
                        .await;
                    let metrics = Metrics::global();
                    for (name, err) in &strategy_round.errors {
                        tracing::debug!(strategy = name, error = %err, "strategy contributed nothing");
                        let outcome = match err {
                            StrategyError::Timeout(_) => {
                                metrics
                                    .counter(names::STRATEGY_TIMEOUTS)
                                    .inc_by(1, &[("strategy", name)]);
                                "timeout"
                            }
                            StrategyError::ModelUnavailable(_) => "unavailable",
                            _ => continue,
                        };
                        // System 1's errors are engine errors: count them as model requests that
                        // produced no record (the planner's provider is not the engine's)
                        if *name == crawlx_strategies::system1::NAME {
                            if let Some(engine) = self.rc.models.engine_id() {
                                record_model_error(
                                    &engine.provider,
                                    &engine.model,
                                    self.rc.models.system1_mode(self.rc.crawl.dynamic.system1_mode),
                                    outcome,
                                );
                            }
                        }
                    }
                    // dataset recording: take System 1's record of this round off the channel
                    // now (the strategies have finished), so the pick can be matched to it
                    let shortlist_record = if self.cfg.record_shortlists.is_some() {
                        hold_round_record(self.records.as_mut(), &mut self.held_records, self.decision_index)
                    } else {
                        None
                    };
                    let mut proposals = strategy_round.proposals;
                    for proposal in &mut proposals {
                        ctx.ledger.normalize_key(&mut proposal.key);
                    }
                    let per_strategy = metrics.counter(names::STRATEGY_PROPOSALS);
                    let proposed = metrics.counter(names::INTERACTIONS_PROPOSED);
                    for p in &proposals {
                        per_strategy.inc_by(1, &[("strategy", p.strategy)]);
                        proposed.inc_by(
                            1,
                            &[
                                ("role", &self.session.role.0),
                                ("lane", p.action.fidelity().lane().as_str()),
                                ("strategy", p.strategy),
                                ("kind", p.key.action_kind.as_str()),
                            ],
                        );
                    }
                    // `Planner` is entered once deterministic recovery is exhausted: the deterministic
                    // strategies only have repeats left, which would race the plan's coordinated steps
                    // (and win ties by name). Everything still passes the arbiter and the kernel.
                    if phase == crawlx_strategies::Phase::Planner && self.planner.is_some() {
                        proposals.retain(|p| p.strategy == crawlx_strategies::llm_planner::NAME);
                    }
                    let index = self.decision_index;
                    // an authenticated session never logs itself out
                    if self.authenticated {
                        let before = proposals.len();
                        let page = current.bundle.url.url.clone();
                        proposals.retain(|p| !targets_logout(p, &page));
                        let excluded = before - proposals.len();
                        if excluded > 0 {
                            tracing::debug!(excluded, "logout navigations excluded from the round");
                        }
                    }
                    proposals.retain(|p| {
                        self.suppressed
                            .get(&p.key.id())
                            .is_none_or(|until| *until < index)
                    });
                    // reveal follow-through: controls the previous trusted
                    // activation revealed (a menu's items, a dialog's buttons, a tree's leaves) are
                    // exercised before any other action can hide them again, which would cost a
                    // replay of their precondition per control. Still-visible, unexercised reveals
                    // with a proposal of their own restrict the round to those proposals.
                    self.follow_through
                        .retain(|h| ctx.candidate_index(h).is_some() && !ctx.exercised.contains(h));
                    if proposals
                        .iter()
                        .any(|p| self.follow_through.contains(&p.key.element))
                    {
                        proposals.retain(|p| self.follow_through.contains(&p.key.element));
                    }
                    let arbitration = child::arbitration();
                    let arbiter_started = Instant::now();
                    let mut arbiter_round = arbitration.in_scope(|| {
                        self.arbiter
                            .choose(proposals, &ctx, self.rc.kernel.as_ref(), &base)
                    });
                    let mut propensity = None;
                    if let (Some(recording), Some(idx)) = (self.cfg.record_shortlists, shortlist_record) {
                        if recording.explore {
                            if let Some(rec) = self.held_records.get(idx) {
                                propensity = explore_shortlist(
                                    &mut arbiter_round,
                                    &rec.shortlist,
                                    &ctx.seed,
                                    &ctx.principal,
                                    self.decision_index,
                                );
                            }
                        }
                    }
                    metrics
                        .histogram(names::ARBITER_DECISION_DURATION)
                        .observe_duration(arbiter_started.elapsed(), &[]);
                    if let Some(c) = &arbiter_round.chosen {
                        arbitration.record("key_id", tracing::field::display(c.proposal.key.id()));
                        arbitration.record("utility", f64::from(c.utility));
                    }
                    drop(arbitration);
                    if arbiter_round.chosen.is_none() {
                        // nothing revealed was admissible: the next round is unrestricted
                        self.follow_through.clear();
                    }
                    let mut parked: Vec<(ActionProposal, crawlx_core::SafetyVerdict)> = Vec::new();
                    for (p, v) in &arbiter_round.denied {
                        parked.push((p.clone(), v.clone()));
                    }
                    for (p, _) in &arbiter_round.approval_required {
                        if !self.blocked_seen.contains(&p.key.id()) {
                            // Bind requests to the observed target, not empty fallback facts.
                            let sc = ctx.safety_context(&base, &p.key);
                            let pending = self.rc.kernel.adjudicate(p.clone(), &sc);
                            parked.push((p.clone(), pending.verdict().clone()));
                        }
                    }
                    let adjudication = arbiter_round.chosen.as_ref().map(|c| {
                        let mut sc = ctx.safety_context(&base, &c.proposal.key);
                        // a refused confirmation taught us what the page really is: classify on that
                        if let Some(live) = self.live_facts.get(&c.proposal.key.id()) {
                            sc.target = live.clone();
                            // Retain only this round's structural channel evidence.
                            sc.target.observed_form_hint.clone_from(&sc.form_hint);
                        }
                        let classification = child::safety_classification();
                        let verdict = classification.in_scope(|| {
                            self.rc.kernel.adjudicate_with(
                                c.proposal.clone(),
                                &sc,
                                crawlx_safety::AdjudicateOptions {
                                    approval: c.verdict.approval,
                                    ..crawlx_safety::AdjudicateOptions::default()
                                },
                            )
                        });
                        let decision = verdict.decision();
                        classification.record(
                            match decision {
                                SafetyDecision::Allow => "allow",
                                SafetyDecision::Deny => "deny",
                                SafetyDecision::ApprovalRequired => "approval",
                            },
                            1_u64,
                        );
                        metrics
                            .counter(names::SAFETY_VERDICTS)
                            .inc_by(1, &[("verdict", decision.as_str())]);
                        (c.proposal.clone(), verdict)
                    });
                    let proposal = arbiter_round.chosen.as_ref().map(|c| c.proposal.clone());
                    let shortlist_note = shortlist_record.map(|record| ShortlistNote {
                        record,
                        chosen: proposal.as_ref().map(|p| p.key.id()),
                        propensity,
                    });
                    // the arbiter's view of the round is folded into the exploration state below
                    let round_for_state = arbiter_round;
                    drop(ctx);
                    self.state.ingest_round(&round_for_state);
                    self.record_coverage();
                    Ok::<_, WorkerError>((adjudication, proposal, parked, shortlist_note))
                }
                .instrument(round_span)
                .await?
            };
            if let Some(note) = &shortlist_note {
                self.emit_shortlist_event(note).await;
            }
            self.flush_model_records().await;
            self.flush_identity_aliases().await;
            self.merge_finished_plans();
            self.record_blocked(parked).await;

            let Some((proposal, adjudication)) = chosen_admitted else {
                empty_rounds += 1;
                if empty_rounds >= self.cfg.max_empty_rounds {
                    empty_rounds = 0;
                    if on_popup {
                        // nothing left to do on the popup: close it next round
                        leave_popup = true;
                        continue;
                    }
                    match self.next_start(&mut starts, &mut visited_starts).await? {
                        Some(request) => {
                            current_request = request;
                            self.switching = SwitchingPolicy::new(self.cfg.switching);
                            chain = 0;
                            continue;
                        }
                        None => return Ok(self.end(TerminalReason::FrontierExhausted)),
                    }
                }
                continue;
            };
            empty_rounds = 0;
            let _ = chosen_proposal;
            let admitted = match adjudication {
                Adjudication::Allow(a) => a,
                Adjudication::Deny(v) => {
                    self.rc
                        .counters
                        .discovery(Plane::Interactions, DiscoveryOutcome::PolicyBlocked);
                    self.journal_blocked(&proposal, &v).await;
                    self.suppressed.insert(proposal.key.id(), u64::MAX);
                    continue;
                }
                Adjudication::ApprovalRequired(v, req) => {
                    self.rc
                        .counters
                        .discovery(Plane::Interactions, DiscoveryOutcome::PolicyBlocked);
                    self.journal_blocked(&proposal, &v).await;
                    self.event(
                        "approval_required",
                        serde_json::json!({
                            "approvalId": req.approval_id.0,
                            "risk": req.risk.as_str(),
                            "summary": req.summary,
                            "sessionId": self.session.id.0,
                        }),
                    )
                    .await;
                    self.suppressed.insert(proposal.key.id(), u64::MAX);
                    continue;
                }
            };

            // execute within the interaction budget (charged once the browser was involved)
            if let Some(reason) = self.stop_reason().await? {
                return Ok(self.end(reason));
            }
            self.rc
                .counters
                .discovery(Plane::Interactions, DiscoveryOutcome::Admitted);
            let key = proposal.key.clone();
            self.steps += 1;
            let settle = self.cfg.action_settle();
            let expected = proposal.expected.clone();
            let before = current.cluster;
            let result = async {
                match self.retry.remove(&key.id()) {
                    Some(id) => self.handle.execute_retry(admitted, settle, id).await,
                    None => self.handle.execute(admitted, settle).await,
                }
            }
            .instrument(phase_span.clone())
            .await;
            match result {
                Ok(outcome) => {
                    halts = 0;
                    storage_halt = None;
                    if outcome.dropped.is_some() {
                        self.consecutive_drops += 1;
                        self.drops += 1;
                        if self.consecutive_drops >= self.cfg.max_consecutive_drops {
                            tracing::warn!(
                                drops = self.consecutive_drops,
                                "nothing on the page is actionable; ending the session"
                            );
                            self.rc.counters.attempt(Plane::Interactions, Attempt::Abandoned);
                            return Ok(self.end(TerminalReason::FrontierExhausted));
                        }
                    } else {
                        self.consecutive_drops = 0;
                        self.charge_budget(BudgetKind::Interactions);
                        self.live_facts.remove(&key.id());
                        if on_popup {
                            self.tab_steps += 1;
                        } else {
                            chain += 1;
                        }
                    }
                    after = self
                        .after_execute(&proposal, &expected, &current, before, outcome)
                        .instrument(phase_span.clone())
                        .await;
                    if depth > 0 && chain >= depth {
                        if let Some(request) = anchor.clone() {
                            // enough consecutive interactions from this state: start over from
                            // the page they began on, keeping its admitted handler identity
                            self.return_to(request).await?;
                            after = None;
                            chain = 0;
                        }
                    }
                }
                Err(error @ SessionError::ExecutionDeadlineReached) => {
                    return Err(storage_halt
                        .take()
                        .map_or(error, SessionError::HaltedStorage)
                        .into());
                }
                Err(SessionError::CrashedDuringAction(id)) => {
                    self.charge_budget(BudgetKind::Interactions);
                    self.rc
                        .counters
                        .attempt(Plane::Interactions, Attempt::UnknownOutcome);
                    self.actions += 1;
                    self.event(
                        "unknown_outcome",
                        serde_json::json!({ "actionId": id.0, "sessionId": self.session.id.0 }),
                    )
                    .await;
                    self.ensure_session_usable().await?;
                    match self.handle.reconcile(id).await {
                        Ok(r) => {
                            let lane = proposal.action.fidelity().lane();
                            self.note_reconciled(&key, id, Some(lane), r.resolution);
                        }
                        Err(e) => tracing::warn!(action = %id, error = %e, "reconcile failed"),
                    }
                }
                Err(SessionError::HaltedStorage(why)) => {
                    // intent could not be journaled (nothing ran) or T2 failed (action stays intended)
                    self.rc
                        .counters
                        .attempt(Plane::Interactions, Attempt::UnknownOutcome);
                    // A failed T2 can leave a durable intent after the browser acted.
                    // Recover its charge before another proposal can spend this slice.
                    self.role_budget = Some(RoleBudget::load(&self.rc, &self.session).await?);
                    halts += 1;
                    tracing::error!(%why, halts, "storage halted the session");
                    if halts >= self.cfg.max_storage_halts {
                        return Err(SessionError::HaltedStorage(why).into());
                    }
                    storage_halt = Some(why);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) if e.is_target_crash() => {
                    self.rc.counters.attempt(Plane::Interactions, Attempt::Abandoned);
                    self.ensure_session_usable().await?;
                }
                Err(e) => {
                    self.rc.counters.attempt(Plane::Interactions, Attempt::Failed);
                    return Err(e.into());
                }
            }
            // T2 is durable and the action is counted in memory; a kill here leaves the
            // stored counters behind the journal until recovery re-derives them
            crate::chaos::hit(crate::chaos::AFTER_OUTCOME_BEFORE_COUNTER_FLUSH).await;
            if let Err(e) = self
                .rc
                .counters
                .persist(self.rc.stores.runs.as_ref(), self.rc.run)
                .await
            {
                tracing::warn!(error = %e, "counters not persisted");
            }
        }
    }

    /// Navigate to the next uncovered start page; false when none is left.
    async fn next_start(
        &mut self,
        starts: &mut VecDeque<RequestEnvelopeV1>,
        visited: &mut BTreeSet<(Digest, String)>,
    ) -> Result<Option<RequestEnvelopeV1>, WorkerError> {
        while let Some(request) = starts.pop_front() {
            let url = &request.url;
            if !visited.insert((url.key, request.route.clone())) {
                continue;
            }
            match self.handle.navigate(request.clone()).await {
                Ok(_) => return Ok(Some(request)),
                Err(SessionError::Browser(BrowserError::RobotsBlocked { url: refused, reason })) => {
                    self.note_robots_blocked(&refused, reason).await;
                }
                Err(
                    error @ (SessionError::ExecutionDeadlineReached
                    | SessionError::Binding(_)
                    | SessionError::Store(_)
                    | SessionError::HaltedStorage(_)),
                ) => return Err(error.into()),
                Err(e) => {
                    if e.is_target_crash() {
                        self.ensure_session_usable().await?;
                    }
                    tracing::warn!(url = %url, error = %e, "start page not reachable");
                }
            }
        }
        Ok(None)
    }

    /// Denied and approval-gated proposals are journaled once per key (hold = denied /
    /// awaiting approval) so the audit trail shows what the kernel stopped.
    async fn record_blocked(&mut self, parked: Vec<(ActionProposal, crawlx_core::SafetyVerdict)>) {
        for (p, v) in parked {
            let id = p.key.id();
            if !self.blocked_seen.insert(id) {
                continue;
            }
            self.rc
                .counters
                .discovery(Plane::Interactions, DiscoveryOutcome::PolicyBlocked);
            self.journal_blocked(&p, &v).await;
        }
    }

    async fn journal_blocked(&self, p: &ActionProposal, v: &crawlx_core::SafetyVerdict) {
        if v.rules.iter().any(|r| r == SINK_REQUIRED_RULE) {
            Metrics::global().counter(names::FORM_DENIED_NO_SINK).inc();
        }
        match self
            .rc
            .stores
            .journal
            .propose(self.rc.run, self.session.id, p, v)
            .await
        {
            Ok(id) => {
                let kind = if v.decision == SafetyDecision::Deny {
                    "action"
                } else {
                    "approval_required"
                };
                self.event(
                    kind,
                    serde_json::json!({
                        "actionId": id.0,
                        "status": "proposed",
                        "decision": v.decision.as_str(),
                        "risk": v.risk_class.as_str(),
                        "rules": v.rules,
                    }),
                )
                .await;
            }
            Err(e) => tracing::warn!(error = %e, "blocked action not journaled"),
        }
    }

    /// Is `tab` a popup (not the tab the session started on)?
    fn is_popup(&self, tab: &crawlx_core::TabId) -> bool {
        self.home_tab.as_ref().is_some_and(|home| home != tab)
    }

    /// Apply popup scope/download policy before choosing exploration work. Excess targets
    /// remain pending in the browser until a journaled close frees an admission slot.
    /// Victims use the worker's latest per-tab frontier depth, then logical last use.
    fn tab_step(
        &mut self,
        bundle: &ObservationBundle,
        cluster: StateClusterId,
        done: bool,
    ) -> Option<ActionProposal> {
        let home = self.home_tab.get_or_insert_with(|| bundle.tab.clone()).clone();
        let origin = self.home_origin.get_or_insert_with(|| bundle.url.url.origin());
        // Reject before eviction: an external or download target must not displace
        // an in-scope tab. The journaled close records its URL and policy attribution.
        if let Some(rejected) = bundle.tabs.iter().find(|t| {
            t.id != home
                && (t.download || !popup_in_scope(&t.url, origin, self.scope.as_ref(), &self.rc.canon))
        }) {
            let reason = if rejected.download {
                "download_popup"
            } else {
                "out_of_scope_popup"
            };
            tracing::info!(tab = %rejected.id.0, reason, "closing recorded popup");
            return Some(self.tab_proposal(
                bundle,
                cluster,
                BrowserAction::CloseTab {
                    tab: rejected.id.clone(),
                },
                &rejected.url,
            ));
        }
        if let Some(pending) = bundle.tabs.iter().find(|t| t.pending) {
            let admitted = bundle.tabs.iter().filter(|t| !t.pending).count();
            if admitted >= usize::from(self.rc.crawl.dynamic.max_tabs.max(1)) {
                let victim = eviction_victim(&bundle.tabs, &home, &self.tab_usefulness);
                let close = victim.unwrap_or(pending);
                self.tab_evictions += 1;
                return Some(self.tab_proposal(
                    bundle,
                    cluster,
                    BrowserAction::CloseTab {
                        tab: close.id.clone(),
                    },
                    &close.url,
                ));
            }
            self.explored_tabs.insert(pending.id.0.clone());
            self.tab_steps = 0;
            return Some(self.tab_proposal(
                bundle,
                cluster,
                BrowserAction::SwitchTab {
                    tab: pending.id.clone(),
                },
                &pending.url,
            ));
        }
        let active = &bundle.tab;
        if *active == home {
            self.home_pages.insert(bundle.url.key);
        } else {
            let home_page = self.home_pages.contains(&bundle.url.key);
            if done || home_page || self.tab_steps >= self.cfg.tab_step_budget {
                tracing::debug!(tab = %active.0, steps = self.tab_steps, done, home_page, "closing explored popup");
                return Some(self.tab_proposal(
                    bundle,
                    cluster,
                    BrowserAction::CloseTab { tab: active.clone() },
                    bundle.url.url.as_ref(),
                ));
            }
            return None;
        }
        let next = bundle
            .tabs
            .iter()
            .find(|t| t.id != home && !self.explored_tabs.contains(&t.id.0))?;
        self.explored_tabs.insert(next.id.0.clone());
        self.tab_steps = 0;
        tracing::debug!(tab = %next.id.0, url = %next.url, "switching to popup");
        Some(self.tab_proposal(
            bundle,
            cluster,
            BrowserAction::SwitchTab { tab: next.id.clone() },
            &next.url,
        ))
    }

    /// A `SwitchTab`/`CloseTab` proposal keyed on the tab's URL (`tab_element`), attributed to
    /// the tab policy.
    fn tab_proposal(
        &self,
        bundle: &ObservationBundle,
        cluster: StateClusterId,
        action: BrowserAction,
        tab_url: &str,
    ) -> ActionProposal {
        let kind = action.kind();
        let navigates_to = (kind == ActionKind::SwitchTab).then(|| tab_url.to_owned());
        ActionProposal {
            key: ActionContextKey {
                principal: self.session.role.clone(),
                route_template: bundle.route.template.clone(),
                element: tab_element(tab_url),
                action_kind: kind,
                input_class: InputClass::none(),
                resource_context: ResourceContext::None,
                state_cluster: cluster,
            },
            action,
            epoch: bundle.epoch,
            strategy: TAB_POLICY,
            strategy_version: TAB_POLICY_VERSION,
            confidence: 1.0,
            expected: ExpectedEffect {
                reveals: Vec::new(),
                navigates_to,
                mutates_state: false,
            },
            hinted_risk: None,
            model_decision: None,
            summary: format!("{} {tab_url}", kind.as_str()),
        }
    }

    /// Cool a dropped key down so the next round plans something else. A refused confirmation
    /// carries live evidence: the key is retried once, classified on that evidence.
    fn note_drop(&mut self, id: ActionContextId, reason: DropReason, live: Option<LiveTargetFacts>) {
        let n = self.drop_counts.entry(id).or_insert(0);
        *n += 1;
        let n = u64::from(*n);
        let cooldown = match reason {
            DropReason::ConfirmDenied => match live {
                Some(f) => {
                    if self.live_facts.insert(id, f).is_none() {
                        0
                    } else {
                        8 * n
                    }
                }
                None => 8 * n,
            },
            DropReason::IdentityChanged => 4 * n,
            DropReason::StaleEpoch | DropReason::NotActionable => 2 * n,
        };
        self.suppressed
            .insert(id, self.decision_index.saturating_add(cooldown));
        // the strategies skip the key too, so their proposal slots go to other keys
        self.state.note_drop(id, cooldown.saturating_add(1));
    }

    /// Fold a reconciliation verdict into the exploration state:
    /// `NotApplied` queues one retry of the same `action_id`; `Applied`, and `Indeterminate`
    /// on a non-idempotent kind, count the key as exercised in the in-memory ledger so the
    /// frontier never proposes it again on a guess (the journal already excludes the row).
    /// The reconstructed outcome carries no route or cluster and is marked `unreliable`, so
    /// it never feeds the split heuristics.
    fn note_reconciled(
        &mut self,
        key: &ActionContextKey,
        id: ActionId,
        lane: Option<crawlx_core::TrustLane>,
        resolution: ReconcileResolution,
    ) {
        let exercised = match resolution {
            ReconcileResolution::NotApplied => {
                self.retry.insert(key.id(), id);
                false
            }
            ReconcileResolution::Applied => true,
            ReconcileResolution::Indeterminate => !key.action_kind.is_idempotent(),
        };
        if exercised {
            let outcome = OutcomeClass {
                after_route_template: key.route_template.clone(),
                after_cluster_family: None,
                network_operation_digest: None,
                status_class: 0,
                unreliable: true,
            };
            let lane = lane.unwrap_or(crawlx_core::TrustLane::Diagnostic);
            self.state.ledger_mut().record(key, &outcome, lane);
        }
    }

    /// Fold an executed action into counters, the exploration state and the event stream.
    /// Returns the after-observation to start the next round from, if the action produced one.
    async fn after_execute(
        &mut self,
        proposal: &ActionProposal,
        expected: &crawlx_core::proposal::ExpectedEffect,
        current: &Prepared,
        before: StateClusterId,
        outcome: ActionOutcome,
    ) -> Option<Prepared> {
        let _ = expected;
        // an attempted reveal leaves the follow-through whatever its outcome: a control whose
        // action fails or runs off the trusted lane is never exercised and must not pin the
        // rounds to itself
        self.follow_through.remove(&proposal.key.element);
        if let Some(reason) = outcome.dropped {
            self.rc.counters.attempt(Plane::Interactions, Attempt::Abandoned);
            tracing::debug!(action = %outcome.action_id, reason = reason.as_str(), "action dropped; replanning");
            self.note_drop(proposal.key.id(), reason, outcome.live);
            return None;
        }
        self.actions += 1;
        if !outcome.robots_blocked.is_empty() {
            // the browser refused to load what the action pointed at: the action did not take
            // effect, and the same control would only be refused again
            self.suppressed.insert(proposal.key.id(), u64::MAX);
            for refused in &outcome.robots_blocked {
                self.note_robots_blocked(&refused.url, refused.reason).await;
            }
        }
        let succeeded = outcome.status == ActionStatus::Succeeded;
        self.rc.counters.attempt(
            Plane::Interactions,
            if succeeded {
                Attempt::Succeeded
            } else {
                Attempt::Failed
            },
        );
        let lane = outcome
            .receipt
            .as_ref()
            .map_or_else(|| proposal.action.fidelity().lane(), |r| r.lane);
        self.event(
            "action",
            serde_json::json!({
                "actionId": outcome.action_id.0,
                "status": outcome.status.as_str(),
                "lane": lane.as_str(),
                "kind": proposal.key.action_kind.as_str(),
                "strategy": proposal.strategy,
                "contextId": proposal.key.id().to_string(),
                "sessionId": self.session.id.0,
            }),
        )
        .await;

        let (after_bundle, after_state) = match (outcome.after.clone(), outcome.after_state.clone()) {
            (Some(b), Some(s)) => (b, s),
            _ => {
                let graph_update = child::graph_update();
                graph_update.record("edges_touched", 0_u64);
                graph_update.in_scope(|| {
                    self.state.ingest_outcome(&OutcomeReport {
                        key: proposal.key.clone(),
                        outcome: unknown_outcome_class(current),
                        lane,
                        succeeded: false,
                        before,
                        after: before,
                        revealed: Vec::new(),
                        baseline_revealed: Vec::new(),
                        confounders: Confounders::default(),
                        latency_ms: u32::try_from(outcome.latency_ms).unwrap_or(u32::MAX),
                        new_operation: false,
                        now: self.rc.clock.now(),
                    });
                });
                self.report_plan_step(&PlanStepReport {
                    key: proposal.key.clone(),
                    succeeded: false,
                    lane,
                    before,
                    after: before,
                    revealed: Vec::new(),
                    first_exercised: false,
                    after_route: current.bundle.route.template.clone(),
                    visible_after: current.identities.clone(),
                    state_changed: false,
                    now: self.rc.clock.now(),
                });
                return None;
            }
        };
        // the T2 transaction persisted the state; count it
        self.states += 1;
        Metrics::global()
            .counter(names::STATES_OBSERVED)
            .inc_by(1, &[("role", &self.session.role.0)]);
        self.rc.counters.discovery(
            Plane::States,
            if after_state.cluster_is_new {
                DiscoveryOutcome::Admitted
            } else {
                DiscoveryOutcome::Duplicate
            },
        );
        self.rc.counters.attempt(Plane::States, Attempt::Succeeded);
        if after_state.cluster_is_new {
            self.charge_budget(BudgetKind::States);
        }
        self.event(
            "state",
            serde_json::json!({
                "stateId": after_state.id.0,
                "clusterId": after_state.cluster.0,
                "novel": after_state.cluster_is_new,
                "url": after_state.url.url.as_str(),
                "sessionId": self.session.id.0,
            }),
        )
        .await;
        self.learn_route(after_state.url.url.path()).await;

        // identities visible after the action but not before = revealed
        // the after-observation is ingested before its outcome (ExplorationState contract)
        let mut after_prep = self
            .prepare(Arc::clone(&after_bundle), after_state.id, after_state.cluster)
            .await;
        self.ingest_discovered(&after_bundle).await;
        let revealed: Vec<ElementIdentityHash> = after_prep
            .identities
            .difference(&current.identities)
            .copied()
            .collect();
        // an activation that revealed nothing (a menu item's own click) keeps the remaining
        // reveals of the one before it in force
        if succeeded
            && !revealed.is_empty()
            && lane == crawlx_core::TrustLane::TrustedUi
            && matches!(
                proposal.key.action_kind,
                ActionKind::Click | ActionKind::KeyboardActivate | ActionKind::Hover
            )
        {
            self.follow_through = revealed.iter().copied().collect();
        }
        let operations = &after_bundle.network.operations;
        let new_operation = operations.iter().any(|o| self.seen_ops.insert(o.clone()));
        let confounders = Confounders {
            ws_frames: u32::try_from(after_bundle.network.long_lived.len()).unwrap_or(u32::MAX),
            polling: 0,
            mutation_volatile_ratio: f32::from(after_bundle.mutation.volatile_permille) / 1000.0,
        };
        let unreliable =
            outcome.settle.as_ref().is_some_and(|s| s.settle_timeout) || after_bundle.network.late > 0;
        let first_exercised = succeeded
            && lane == crawlx_core::TrustLane::TrustedUi
            && self.state.ledger().trusted_attempts(&proposal.key) == 0;
        let plan_revealed = revealed.clone();
        let state_changed = after_state.cluster != before
            || !revealed.is_empty()
            || after_bundle.route.template != current.bundle.route.template;
        let outcome_class = OutcomeClass {
            after_route_template: after_bundle.route.template.clone(),
            after_cluster_family: Some(after_state.cluster),
            network_operation_digest: (!operations.is_empty())
                .then(|| Digest::of("crawlx/worker/operations", operations.join("\n").as_bytes())),
            status_class: 0,
            unreliable,
        };
        if self.cfg.record_shortlists.is_some() {
            let novelty = self.state.observation_novelty();
            let gain =
                novelty.new_keys + usize::from(after_state.cluster_is_new) + usize::from(new_operation);
            self.event(
                "shortlist_outcome",
                serde_json::json!({
                    "decisionIndex": self.decision_index,
                    "sessionId": self.session.id.0,
                    "contextId": proposal.key.id().to_string(),
                    "succeeded": succeeded,
                    "newCluster": after_state.cluster_is_new,
                    "newOperation": new_operation,
                    "newKeys": novelty.new_keys,
                    "newIdentities": novelty.new_identities,
                    "revealed": revealed.len(),
                    "firstTrusted": first_exercised,
                    "gain": gain,
                }),
            )
            .await;
        }
        // every revealed identity becomes an enablement edge of the executed key
        let graph_update = child::graph_update();
        graph_update.record("edges_touched", revealed.len());
        graph_update.in_scope(|| {
            self.state.ingest_outcome(&OutcomeReport {
                key: proposal.key.clone(),
                outcome: outcome_class.clone(),
                lane,
                succeeded,
                before,
                after: after_state.cluster,
                revealed,
                baseline_revealed: Vec::new(),
                confounders,
                latency_ms: u32::try_from(outcome.latency_ms).unwrap_or(u32::MAX),
                new_operation,
                now: self.rc.clock.now(),
            });
        });
        self.report_plan_step(&PlanStepReport {
            key: proposal.key.clone(),
            succeeded,
            lane,
            before,
            after: after_state.cluster,
            revealed: plan_revealed,
            first_exercised,
            after_route: after_bundle.route.template.clone(),
            visible_after: after_prep.identities.clone(),
            state_changed,
            now: self.rc.clock.now(),
        });
        // Split on contradiction: the outcome is evidence for the before-cluster; when
        // the splitter finds its members disagree in one context the split is persisted
        // (`apply_split` re-keys `action_contexts`) and the ledgers follow
        if succeeded {
            self.analyzer
                .clusters()
                .note_outcome(current.state, before, proposal.key.id(), &outcome_class);
            match self
                .analyzer
                .clusters()
                .try_split(
                    self.rc.stores.states.as_ref(),
                    self.rc.run,
                    before,
                    self.rc.clock.now(),
                )
                .await
            {
                Ok(Some(split)) => {
                    if let Some(to) = split.successor_of_state(after_prep.state) {
                        after_prep.cluster = to;
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(cluster = %before, error = %e, "state cluster split not applied"),
            }
        }
        self.apply_pending_splits();
        Some(after_prep)
    }

    /// Re-key the in-memory ledger and enablement graph for every split applied to the run's
    /// cluster index that this session has not folded in yet (by this or any other session),
    /// the way the store re-keyed `action_contexts`.
    fn apply_pending_splits(&mut self) {
        let pending = self.analyzer.clusters().splits_since(self.splits_seen);
        for split in &pending {
            let moved = self
                .state
                .ledger_mut()
                .rekey_cluster(split.source, |key| split.successor_of_context(key.id()));
            let remap: BTreeMap<ActionContextId, ActionContextId> = moved.iter().copied().collect();
            let edges: Vec<_> = self
                .state
                .graph()
                .dump()
                .into_iter()
                .filter(|e| remap.contains_key(&e.source) || e.context_cluster == Some(split.source))
                .map(|mut e| {
                    if let Some(new) = remap.get(&e.source) {
                        e.source = *new;
                    }
                    if e.context_cluster == Some(split.source) {
                        e.context_cluster = Some(split.successor_of_context(e.source));
                    }
                    e
                })
                .collect();
            let rekeyed_edges = self.state.graph_mut().load(edges);
            tracing::debug!(
                cluster = %split.source,
                ledger_keys = moved.len(),
                edges = rekeyed_edges,
                "session ledger re-keyed after a cluster split"
            );
        }
        self.splits_seen += pending.len();
    }

    /// Discover candidates, resolve their identities and fold the observation into the
    /// exploration state.
    async fn prepare(
        &mut self,
        bundle: Arc<ObservationBundle>,
        state: StateId,
        cluster: StateClusterId,
    ) -> Prepared {
        let discovered = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
        let discovered = self.filter_candidates(discovered).await;
        let identity_version = self.rc.crawl.crawl.identity.version;
        let language = crawlx_elements::locale::page_language(bundle.html.as_deref());
        let resolver = IdentityResolver::with_destination(bundle.url.url.clone(), self.rc.canon.clone())
            .with_identity_version(identity_version, language);
        let weights = MatchWeights::default();
        let mut candidates = Vec::with_capacity(discovered.len());
        let mut resolved = Vec::with_capacity(discovered.len());
        let mut splits = 0_u64;
        let mut collisions = 0_u64;
        for c in discovered {
            if let Ok(r) = resolver.resolve(&c.descriptor, self.state.identity_index(), &weights) {
                if identity_version == crawlx_core::config::IdentityVersion::Dual {
                    let destination =
                        IdentityBuilder::destination_key(&c.descriptor, &bundle.url.url, &self.rc.canon);
                    let v1 = IdentityBuilder::build(&c.descriptor, destination.clone()).hash();
                    let v2 = IdentityBuilder::build_v2(&c.descriptor, destination, language).hash();
                    if let (Ok(v1), Ok(v2)) = (v1, v2) {
                        self.pending_aliases.push(IdentityAlias {
                            alias: v2,
                            canonical: v1,
                            from_version: 2,
                            to_version: 1,
                            score: 1.0,
                        });
                    }
                }
                match r.decision {
                    MatchDecision::MintedNew {
                        best_score,
                        alias: Some(canonical),
                    } => {
                        splits += 1;
                        self.pending_aliases.push(IdentityAlias {
                            alias: r.hash,
                            canonical,
                            from_version: r.version,
                            to_version: r.version,
                            score: best_score,
                        });
                    }
                    // a fuzzy reuse whose observed name differs from the identity it landed on
                    // may have merged two controls
                    MatchDecision::Reused { score }
                        if score < 1.0
                            && IdentityBuilder::build(&c.descriptor, None).normalized_accessible_name
                                != r.identity.normalized_accessible_name =>
                    {
                        collisions += 1;
                    }
                    _ => {}
                }
                candidates.push(c);
                resolved.push(r);
            }
        }
        let metrics = Metrics::global();
        let role = &[("role", self.session.role.0.as_str())];
        if splits > 0 {
            metrics.counter(names::IDENTITY_SPLITS).inc_by(splits, role);
        }
        if collisions > 0 {
            metrics
                .counter(names::IDENTITY_COLLISION_SUSPECTED)
                .inc_by(collisions, role);
        }
        let now = self.rc.clock.now();
        let coarsened_before = self.state.ledger().coarsened_total();
        self.state
            .ingest_observation(&bundle, &candidates, &resolved, cluster, now);
        metrics.counter(names::KEYS_COARSENED).inc_by(
            u64::from(
                self.state
                    .ledger()
                    .coarsened_total()
                    .saturating_sub(coarsened_before),
            ),
            &[],
        );
        let identities: BTreeSet<_> = resolved.iter().map(|r| r.hash).collect();
        let remaining = self
            .state
            .ledger()
            .keys()
            .filter(|(key, trusted)| {
                *trusted == 0
                    && (key.state_cluster == cluster || key.is_coarsened())
                    && key.route_template == bundle.route.template
                    && identities.contains(&key.element)
                    && self.state.frontier().is_proposable(key)
            })
            .count();
        self.tab_usefulness
            .retain(|id, _| bundle.tabs.iter().any(|t| &t.id.0 == id));
        self.tab_usefulness
            .insert(bundle.tab.0.clone(), (remaining, self.decision_index));
        Prepared {
            bundle,
            state,
            cluster,
            candidates,
            resolved,
            identities,
        }
    }

    /// Tell the planner what its step did; a finished plan is merged into the frontier.
    fn report_plan_step(&mut self, report: &PlanStepReport) {
        let Some(planner) = &self.planner else { return };
        if let PlanProgress::Finished(outcome) = planner.step_done(report) {
            merge_plan(&outcome, &mut self.state);
        }
    }

    /// Per-role ledger gauges after a round: action-context coverage (`keys_exercised_trusted /
    /// keys_total`), keys exercised only in the diagnostic lane, the share of
    /// cross-principal contexts exercised on the trusted lane (`1.0` when the role
    /// has none) and the interaction-plane frontier depth (known unexercised, unblocked keys).
    fn record_coverage(&self) {
        let role = &self.session.role;
        let ledger = self.state.ledger();
        let cov = ledger.coverage(Some(role));
        let action_context = if cov.keys_total == 0 {
            0.0
        } else {
            f64::from(cov.keys_exercised_trusted) / f64::from(cov.keys_total)
        };
        let (cross, cross_trusted) = ledger
            .keys()
            .filter(|(k, _)| {
                k.principal == *role
                    && matches!(
                        k.resource_context,
                        ResourceContext::OtherUserSameRole
                            | ResourceContext::HigherRole
                            | ResourceContext::Shared
                    )
            })
            .fold((0_u32, 0_u32), |(n, t), (_, trusted)| {
                (n + 1, t + u32::from(trusted > 0))
            });
        let attribution = if cross == 0 {
            1.0
        } else {
            f64::from(cross_trusted) / f64::from(cross)
        };
        let metrics = Metrics::global();
        let labels = &[("role", role.0.as_str())];
        metrics
            .gauge(names::COVERAGE_ACTION_CONTEXT)
            .set(action_context, labels);
        metrics
            .gauge(names::COVERAGE_DIAGNOSTIC_ONLY_KEYS)
            .set(f64::from(cov.keys_diagnostic_only), labels);
        metrics
            .gauge(names::SESSION_CROSS_PRINCIPAL_ATTRIBUTION_RATE)
            .set(attribution, labels);
        metrics.gauge(names::FRONTIER_DEPTH).set(
            f64::from(self.state.stall().unexercised_known),
            &[("plane", "interactions")],
        );
    }

    /// Merge the plans the planner ended by itself (never chosen, target gone) and its failed
    /// calls, so failures are counted and the switching policy can end the run.
    fn merge_finished_plans(&mut self) {
        let Some(planner) = &self.planner else { return };
        for outcome in planner.take_finished() {
            merge_plan(&outcome, &mut self.state);
        }
    }

    /// Write the System 1 calls made since the last flush to `model_decisions`.
    async fn flush_model_records(&mut self) {
        let mut pending = std::mem::take(&mut self.held_records);
        if let Some(rx) = self.records.as_mut() {
            while let Ok(rec) = rx.try_recv() {
                pending.push(rec);
            }
        }
        for rec in pending {
            let row = decision_record(self.rc.run, &rec, self.rc.clock.now());
            if let Err(e) = self.rc.stores.model_decisions.record(&row).await {
                tracing::warn!(error = %e, decision = %rec.decision_id, "model decision not recorded");
            }
        }
    }

    /// The `shortlist` run event of a round: the rendered request System 1 saw, the shortlist's
    /// action-context ids and the position of the pick among them (dataset recording).
    async fn emit_shortlist_event(&self, note: &ShortlistNote) {
        let Some(rec) = self.held_records.get(note.record) else {
            return;
        };
        let Some(rendered) = &rec.rendered else { return };
        let ids: Vec<String> = rec.shortlist.iter().map(ToString::to_string).collect();
        let chosen_index = note
            .chosen
            .and_then(|c| rec.shortlist.iter().position(|id| *id == c));
        let recording = self.cfg.record_shortlists.unwrap_or_default();
        self.event(
            "shortlist",
            serde_json::json!({
                "decisionIndex": rec.decision_index,
                "sessionId": self.session.id.0,
                "context": rendered.context,
                "rows": rendered.rows,
                "ids": ids,
                "chosenIndex": chosen_index,
                "chosen": note.chosen.map(|c| c.to_string()),
                "propensity": note.propensity,
                "explored": recording.explore && note.propensity.is_some(),
                "latencyMs": rec.latency_ms,
            }),
        )
        .await;
    }

    /// Write the ambiguous-band aliases minted since the last flush to `identity_aliases`.
    async fn flush_identity_aliases(&mut self) {
        for alias in std::mem::take(&mut self.pending_aliases) {
            if let Err(e) = self
                .rc
                .stores
                .identity_aliases
                .record_alias(self.rc.run, &alias)
                .await
            {
                tracing::warn!(error = %e, alias = %alias.alias, "identity alias not recorded");
            }
        }
    }

    /// Persist the enablement graph (edges reference ledger rows the journal created).
    async fn persist_graph(&self) {
        for edge in self.state.graph().dump() {
            if let Err(e) = self.rc.stores.edges.upsert(&edge).await {
                tracing::debug!(error = %e, "edge not persisted");
            }
        }
    }
}

fn unknown_outcome_class(current: &Prepared) -> OutcomeClass {
    OutcomeClass {
        after_route_template: current.bundle.route.template.clone(),
        after_cluster_family: Some(current.cluster),
        network_operation_digest: None,
        status_class: 0,
        unreliable: true,
    }
}

/// The `phase` span value (one of `crawlx_telemetry::spans::PHASES`) of a switching phase.
/// `Done` never reaches a span; it is mapped to `greedy` for completeness.
const fn phase_name(phase: crawlx_strategies::Phase) -> &'static str {
    use crawlx_strategies::Phase;
    match phase {
        Phase::Greedy | Phase::System1 | Phase::Done => "greedy",
        Phase::StateRecovery | Phase::EnablementRecovery => "recovery",
        Phase::Planner => "planner",
    }
}

/// The seed of one session's decisions: the run seed folded with the role and its repetition
/// index, so two sessions never share a tie-break stream yet the same run seed always yields the
/// same stream (session and run ids are random and must never reach a decision).
fn session_seed(run_seed: CrawlSeed, session: &crawlx_core::repo::CrawlSession) -> CrawlSeed {
    let derived = run_seed.derive(
        "session-stream",
        &[session.role.0.as_bytes(), &session.run_index.to_le_bytes()],
    );
    let mut head = [0_u8; 8];
    head.copy_from_slice(&derived[..8]);
    CrawlSeed(u64::from_le_bytes(head))
}

/// The run-level facts the safety kernel classifies a session's proposals against.
fn safety_context(rc: &RunContext, session: &crawlx_core::repo::CrawlSession) -> SafetyContext {
    let c = &rc.crawl;
    SafetyContext {
        profile: c.safety.profile,
        has_test_sinks: rc.kernel.has_verified_test_sinks(),
        destructive_approval_allowed: c.safety.destructive_actions == DestructiveActions::Approval,
        principal: session.role.clone(),
        seed_origin: rc.seed_origin(),
        in_scope: true,
        target: LiveTargetFacts::default(),
        form_hint: None,
    }
}

/// Everything `dynamic` asks of a session: the deterministic strategies of
/// [`build_strategies_gated`] plus, when the run's [`ModelServices`](crate::model::ModelServices)
/// allow it, System 1 (`system1` listed, effective mode not `off`) and the LLM planner
/// (`dynamic.llmPlanner` not `off`). Model-backed strategies only see candidates the safety
/// kernel does not hard-deny. `capture_rendered` keeps System 1's rendered request on its
/// records (set by [`DriverConfig::record_shortlists`]).
///
/// # Errors
/// [`WorkerError::Config`] when a requested strategy needs a gate the run's
/// [`RunContext::gates`] lack.
pub fn build_strategy_set(
    rc: &RunContext,
    session: &crawlx_core::repo::CrawlSession,
    capture_rendered: bool,
) -> Result<StrategySet, WorkerError> {
    let gate: Arc<dyn crawlx_core::repo::SafetyGate> = rc.kernel.clone();
    let versions = build_strategy_versions_gated(&rc.crawl.dynamic, &rc.gates)
        .map_err(|e| WorkerError::Config(e.to_string()))?;
    let (deterministic, arm_assignments) = select_strategy_arms(
        &rc.crawl.dynamic,
        &rc.gates,
        rc.seed,
        &session.role,
        session.run_index,
        versions,
    )
    .map_err(|e| WorkerError::Config(e.to_string()))?;
    let mut set = rc.models.extend(
        deterministic,
        &rc.crawl.dynamic,
        Some((gate, safety_context(rc, session))),
        capture_rendered,
    );
    set.arm_assignments = arm_assignments;
    Ok(set)
}

/// Persist configured session assignments before any selected strategy can propose.
///
/// Events are visible through the existing run-event/SSE query and join to action versions
/// by session and strategy. Metrics are emitted only after the event append succeeds.
///
/// # Errors
/// Propagates event storage failures; callers must not explore without the assignment trail.
pub async fn persist_strategy_arm_assignments(
    rc: &RunContext,
    session: &crawlx_core::repo::CrawlSession,
    assignments: &[StrategyArmSelection],
) -> Result<(), WorkerError> {
    persist_strategy_arm_events(rc.stores.events.as_ref(), rc.run, session, assignments).await?;
    Ok(())
}

async fn persist_strategy_arm_events(
    events: &dyn crawlx_core::repo::EventRepo,
    run: crawlx_core::CrawlRunId,
    session: &crawlx_core::repo::CrawlSession,
    assignments: &[StrategyArmSelection],
) -> Result<(), crawlx_core::StoreError> {
    for assignment in assignments {
        events
            .append(
                run,
                "strategy_arm_assigned",
                serde_json::json!({
                    "session_id": session.id,
                    "role": session.role,
                    "run_index": session.run_index,
                    "strategy": assignment.strategy,
                    "version": assignment.version,
                    "weight": assignment.weight,
                }),
            )
            .await?;
        Metrics::global().counter(names::STRATEGY_ARM_ASSIGNMENTS).inc_by(
            1,
            &[
                ("strategy", assignment.strategy.as_str()),
                ("version", assignment.version.to_string().as_str()),
            ],
        );
    }
    Ok(())
}

#[cfg(test)]
mod strategy_arm_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::config::StrategyArm;
    use crawlx_core::gates::GateStatus;
    use crawlx_core::repo::EventRepo;
    use crawlx_core::PrincipalId;
    use crawlx_strategies::{Arm, ArmAssignment, BfsConfig, InteractionBfs};

    /// A genuinely different local candidate-order algorithm, not a relabeled builtin.
    struct ReverseCandidateOrder;

    #[async_trait]
    impl Strategy for ReverseCandidateOrder {
        async fn propose(&self, context: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
            Ok(context
                .keyed_actions()
                .iter()
                .rev()
                .filter_map(|action| context.proposal_for(action, self.name(), self.version(), 0.5))
                .collect())
        }

        fn name(&self) -> &'static str {
            "interaction_bfs"
        }

        fn version(&self) -> u32 {
            2
        }
    }

    fn custom_versions() -> Vec<Arc<dyn Strategy>> {
        vec![
            Arc::new(InteractionBfs::new(BfsConfig::default())),
            Arc::new(ReverseCandidateOrder),
            Arc::new(UrlPlane::new(UrlPlaneConfig::default())),
        ]
    }

    fn configured(weights: [u32; 2]) -> Dynamic {
        let mut dynamic = Dynamic {
            strategies: vec![StrategyName::InteractionBfs],
            ..Dynamic::default()
        };
        dynamic.strategy_arms.insert(
            StrategyName::InteractionBfs,
            vec![StrategyArm::new(1, weights[0]), StrategyArm::new(2, weights[1])],
        );
        dynamic
    }

    #[test]
    fn default_registry_is_unchanged_and_unavailable_versions_are_never_relabelled() {
        let gates = Gates::from_status(GateStatus::ALL);
        let defaults = build_strategies_gated(&Dynamic::default(), &gates).unwrap();
        let expected = vec![
            ("interaction_bfs", crawlx_strategies::interaction_bfs::VERSION),
            ("event_driven", crawlx_strategies::event_driven::VERSION),
            ("url_plane", crawlx_strategies::url_plane::VERSION),
        ];
        assert_eq!(
            defaults
                .iter()
                .map(|strategy| (strategy.name(), strategy.version()))
                .collect::<Vec<_>>(),
            expected,
        );
        // the default set needs no gate evidence
        let ungated = build_strategies_gated(&Dynamic::default(), &Gates::none()).unwrap();
        assert_eq!(ungated.len(), expected.len());
        assert!(matches!(
            build_strategies_gated(&configured([1, 1]), &gates),
            Err(StrategyError::UnavailableVersion { version: 2, .. })
        ));
        let (unchanged, assignments) = select_strategy_arms(
            &Dynamic::default(),
            &gates,
            CrawlSeed(42),
            &PrincipalId("member".into()),
            1,
            custom_versions(),
        )
        .unwrap();
        assert_eq!(unchanged.len(), 3);
        assert!(assignments.is_empty());
    }

    #[test]
    fn real_local_versions_follow_seed_role_index_and_configured_weights() {
        let gates = Gates::from_status(GateStatus::ALL);
        let role = PrincipalId("member".into());
        for weights in [[1, 1], [1, 9]] {
            let dynamic = configured(weights);
            let assignment = ArmAssignment::new(
                "interaction_bfs",
                [
                    Arm {
                        version: 1,
                        weight: weights[0],
                    },
                    Arm {
                        version: 2,
                        weight: weights[1],
                    },
                ],
            )
            .unwrap();
            let mut v2 = 0;
            for index in 1..=1000 {
                let (selected, recorded) =
                    select_strategy_arms(&dynamic, &gates, CrawlSeed(42), &role, index, custom_versions())
                        .unwrap();
                let mut reversed = custom_versions();
                reversed.reverse();
                let (_, repeated) =
                    select_strategy_arms(&dynamic, &gates, CrawlSeed(42), &role, index, reversed).unwrap();
                let expected = assignment.for_role(CrawlSeed(42), &role, index);
                assert_eq!(recorded, repeated);
                assert_eq!(recorded[0].version, expected.version);
                assert_eq!(recorded[0].weight, expected.weight);
                assert_eq!(selected[0].version(), expected.version);
                assert_eq!(selected[1].name(), "url_plane");
                assert_eq!(selected.len(), 2);
                v2 += usize::from(expected.version == 2);
            }
            let expected_range = if weights[1] == 1 { 400..=600 } else { 840..=960 };
            assert!(expected_range.contains(&v2), "v2 won {v2} sessions");
        }
    }

    #[test]
    fn custom_arms_reject_missing_versions_invalid_weights_and_missing_gates() {
        let gates = Gates::from_status(GateStatus::ALL);
        let role = PrincipalId("member".into());
        assert!(matches!(
            select_strategy_arms(
                &configured([1, 1]),
                &gates,
                CrawlSeed(1),
                &role,
                1,
                vec![Arc::new(InteractionBfs::new(BfsConfig::default()))],
            ),
            Err(StrategyError::UnavailableVersion { version: 2, .. })
        ));
        assert!(select_strategy_arms(
            &configured([0, 1]),
            &gates,
            CrawlSeed(1),
            &role,
            1,
            custom_versions(),
        )
        .is_err());
        // G1-gated strategies are opt-in: request one explicitly, then give it arms.
        let mut dynamic = Dynamic::default();
        dynamic.strategies.push(StrategyName::StateNovelty);
        dynamic.strategy_arms.insert(
            StrategyName::StateNovelty,
            vec![StrategyArm::new(crawlx_strategies::novelty::VERSION, 1)],
        );
        assert!(matches!(
            select_strategy_arms(
                &dynamic,
                &Gates::from_status(GateStatus::NONE),
                CrawlSeed(1),
                &role,
                1,
                Vec::new(),
            ),
            Err(StrategyError::Gated { gate: "G1", .. })
        ));
    }

    #[tokio::test]
    async fn live_arm_selection_executes_only_the_assigned_version_and_records_its_trail() {
        use crate::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
        use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
        use crawlx_browser::FakeBackend;
        use crawlx_core::CreateCrawl;

        for version in [1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let store = Arc::new(crawlx_storage::MemoryStore::new());
            let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
            let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
            crawl.mode = CrawlMode::Dynamic;
            crawl.seed = Some(42);
            crawl.limits.interactions = 1;
            crawl.dynamic.strategies = vec![StrategyName::InteractionBfs];
            crawl
                .dynamic
                .strategy_arms
                .insert(StrategyName::InteractionBfs, vec![StrategyArm::new(version, 1)]);
            let script = FakeScript::new()
                .page(
                    FakePage::new("https://example.test/")
                        .node(FakeAxSpec::link("next", "Next page", "/next"))
                        .on(
                            ActionKind::KeyboardActivate,
                            "next",
                            vec![FakeEffect::Navigate("https://example.test/next".into())],
                        )
                        .on_click(
                            "next",
                            vec![FakeEffect::Navigate("https://example.test/next".into())],
                        ),
                )
                .page(FakePage::new("https://example.test/next").title("Next"));
            let backend = Arc::new(FakeBackend::new(script));
            let config = WorkerConfig {
                artifacts_dir: dir.path().to_path_buf(),
                egress: EgressConfig {
                    resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
                    ..EgressConfig::default()
                },
                gates: Gates::from_status(GateStatus::ALL),
                ..WorkerConfig::default()
            };
            let report = run_local_with(
                LocalRun::new(crawl, config)
                    .with_stores(stores)
                    .with_backend(backend.clone())
                    .with_strategies(vec![
                        Arc::new(InteractionBfs::new(BfsConfig::default())),
                        Arc::new(ReverseCandidateOrder),
                    ]),
            )
            .await
            .unwrap();
            let executed: Vec<_> = report
                .actions
                .iter()
                .filter(|action| action.intended_at.is_some())
                .collect();
            assert_eq!(executed.len(), 1, "{version}: {:?}", report.actions);
            assert_eq!(executed[0].strategy, "interaction_bfs");
            assert_eq!(executed[0].strategy_version, version);
            assert_eq!(executed[0].status, ActionStatus::Succeeded);
            let browser_paths: Vec<_> = backend
                .context_handles()
                .iter()
                .map(|handle| (handle.performed_keys(), handle.navigations()))
                .collect();
            assert!(
                browser_paths.iter().any(|(_, paths)| {
                    paths.last().map(String::as_str) == Some("https://example.test/next")
                }),
                "version={version}, action={:?}, browser_paths={browser_paths:?}",
                executed[0],
            );
            let events = store.list_after(report.run_id, 0, 10_000).await.unwrap();
            let assignment = events
                .iter()
                .find(|event| event.kind == "strategy_arm_assigned")
                .unwrap();
            assert_eq!(assignment.payload["version"], version);
            assert_eq!(assignment.payload["session_id"], executed[0].session.to_string());
        }
    }
}

#[cfg(test)]
mod tab_policy_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::observation::TabInfo;
    use crawlx_core::TabId;

    #[test]
    fn eviction_uses_remaining_frontier_then_last_use_and_never_home_or_pending() {
        let tabs: Vec<_> = ["home", "older", "newer", "pending"]
            .into_iter()
            .map(|id| TabInfo {
                id: TabId(id.to_owned()),
                url: format!("https://example.test/{id}"),
                opener: (id != "home").then(|| TabId("home".to_owned())),
                active: id == "home",
                pending: id == "pending",
                download: false,
            })
            .collect();
        let mut usefulness = BTreeMap::from([
            ("home".to_owned(), (0, 0)),
            ("older".to_owned(), (2, 1)),
            ("newer".to_owned(), (1, 5)),
            ("pending".to_owned(), (0, 0)),
        ]);
        let home = TabId("home".to_owned());
        assert_eq!(eviction_victim(&tabs, &home, &usefulness).unwrap().id.0, "newer");
        usefulness.insert("newer".to_owned(), (2, 5));
        assert_eq!(eviction_victim(&tabs, &home, &usefulness).unwrap().id.0, "older");
    }

    #[test]
    fn external_origins_and_blank_urls_are_not_exploration_targets() {
        let origin = url::Url::parse("https://example.test/").unwrap().origin();
        let canon = crawlx_url::CanonicalizeOptions::default();
        assert!(popup_in_scope(
            "https://example.test/child",
            &origin,
            None,
            &canon
        ));
        assert!(!popup_in_scope(
            "https://external.test/child",
            &origin,
            None,
            &canon
        ));
        assert!(!popup_in_scope("about:blank", &origin, None, &canon));
    }
}
