//! Per-session exploration state: ledger, enablement graph, cluster index,
//! identity index and the frontier statistics behind the paper's layered queue.
//!
//! The Session Actor's exploration driver owns one `ExplorationState` per
//! principal run and calls, per round:
//!
//! 1. [`ExplorationState::ingest_observation`] with the newest bundle,
//! 2. [`ExplorationState::context`] to freeze a `DecisionContext`,
//! 3. strategies → [`crate::Arbiter::choose`] → [`ExplorationState::ingest_round`],
//! 4. after the chosen action ran: `ingest_observation` of the *after* bundle,
//!    then [`ExplorationState::ingest_outcome`] (observation first, so the
//!    novel-reveal test can tell which identities were never seen before).

use crate::arbiter::ArbiterRound;
use crate::context::{BudgetView, DecisionContext, DecisionContextBuilder, StallCounters};
use crate::error::StrategyError;
use crate::frontier::{enumerate_actions, EnumInput, FrontierStats, QueueCfg, RouteEntry};
use crate::ledger::{InMemoryLedger, LedgerView};
use crate::switching::Phase;
use crawlx_core::config::TargetIsolation;
use crawlx_core::hash::Digest;
use crawlx_core::observation::ObservationBundle;
use crawlx_core::repo::{EdgeRecord, LedgerRow};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::state::StateSignature;
use crawlx_core::{
    ActionContextId, ActionContextKey, CrawlRunId, ElementIdentityHash, PrincipalId, SafetyProfile,
    StateClusterId, StateId, Timestamp, TrustLane,
};
use crawlx_elements::{Candidate, InMemoryIdentityIndex, ResolvedElement};
use crawlx_graph::{Confounders, EnablementGraph, GraphParams, GraphSnapshot, TransitionObservation};
use crawlx_state::{Attachment, ClusterConfig, ClusterIndex, OutcomeClass, StateDiff, StateProfile};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Knobs of the exploration state.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ExplorationConfig {
    /// Frontier queue configuration (per-group queue bounds).
    pub queue: QueueCfg,
    /// Parameters of the enablement graph (decay, priors, thresholds).
    pub graph: GraphParams,
    /// State clustering configuration (matching thresholds).
    pub cluster: ClusterConfig,
    /// Profile the key enumeration (value partitions) is built under.
    pub profile: SafetyProfile,
    /// Enumerate `Keys` chords for tab/menu items.
    pub include_keys: bool,
    /// Enablement attempts on one hidden target before it is put in cooldown.
    pub target_attempts_max: u32,
    /// The run's `targetIsolation`: under `per_role_replica` cross-principal keys are
    /// `not_observable` in the ledger.
    pub target_isolation: TargetIsolation,
}

impl Default for ExplorationConfig {
    fn default() -> Self {
        Self {
            queue: QueueCfg::default(),
            graph: GraphParams::default(),
            cluster: ClusterConfig::default(),
            profile: SafetyProfile::ReadOnly,
            include_keys: false,
            target_attempts_max: 3,
            target_isolation: TargetIsolation::Shared,
        }
    }
}

/// Everything [`ExplorationState::context`] needs beyond the state itself.
#[derive(Clone, Debug)]
pub struct RoundInput {
    /// Observation the round decides on.
    pub bundle: Arc<ObservationBundle>,
    /// Candidates discovered in `bundle`.
    pub candidates: Vec<Candidate>,
    /// Parallel to `candidates`.
    pub resolved: Vec<ResolvedElement>,
    /// Cluster the observation was attached to.
    pub cluster: StateClusterId,
    /// Zero-based index of this decision within the run.
    pub decision_index: u64,
    /// Safety profile the round's actions are classified under.
    pub profile: SafetyProfile,
    /// Remaining-budget snapshot for the round.
    pub budget: BudgetView,
    /// Wall-clock instant used for time-dependent scoring.
    pub clock_now: Timestamp,
    /// Phase from `SwitchingPolicy::next` (default `Greedy`).
    pub phase: Phase,
}

impl RoundInput {
    /// A round in the `Greedy` phase; chain [`Self::with_phase`] to override.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // one field per round input; a builder would only restate them
    pub fn new(
        bundle: Arc<ObservationBundle>,
        candidates: Vec<Candidate>,
        resolved: Vec<ResolvedElement>,
        cluster: StateClusterId,
        decision_index: u64,
        profile: SafetyProfile,
        budget: BudgetView,
        clock_now: Timestamp,
    ) -> Self {
        Self {
            bundle,
            candidates,
            resolved,
            cluster,
            decision_index,
            profile,
            budget,
            clock_now,
            phase: Phase::Greedy,
        }
    }

    /// Override the phase chosen for this round.
    #[must_use]
    pub const fn with_phase(mut self, phase: Phase) -> Self {
        self.phase = phase;
        self
    }
}

/// What an observation exposed that no earlier one of the session had.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ObservationNovelty {
    /// Element identities never observed before.
    pub new_identities: usize,
    /// Action-context keys the ledger registered for the first time.
    pub new_keys: usize,
}

/// Result of one executed action, as the exploration state ingests it.
#[derive(Clone, Debug)]
pub struct OutcomeReport {
    /// Key of the executed action.
    pub key: ActionContextKey,
    /// Classified effect of the action on the page state.
    pub outcome: OutcomeClass,
    /// Trust lane the action ran in.
    pub lane: TrustLane,
    /// The browser performed the action (`false`: rejected, no after-state).
    pub succeeded: bool,
    /// Cluster the action started from.
    pub before: StateClusterId,
    /// Cluster the page was in after settling.
    pub after: StateClusterId,
    /// Controls new in the after-bundle that are still present after settle.
    pub revealed: Vec<ElementIdentityHash>,
    /// Controls the no-action control run revealed on its own.
    pub baseline_revealed: Vec<ElementIdentityHash>,
    /// Confounding signals observed around the action (concurrent changes, timers).
    pub confounders: Confounders,
    /// The action produced a network operation never seen before.
    pub new_operation: bool,
    /// Time the outcome was recorded.
    pub now: Timestamp,
}

/// Rows a run restores from storage (`LedgerRepo`, `EdgeStore`, `StateRepo`).
#[derive(Clone, PartialEq, Default, Serialize, Deserialize, Debug)]
pub struct ExplorationSnapshot {
    /// Persisted ledger rows (per-key exercise statistics).
    pub ledger_rows: Vec<LedgerRow>,
    /// Persisted enablement edges.
    pub edge_records: Vec<EdgeRecord>,
    /// `(cluster, signature, size)` as `StateRepo::list_clusters` returns them.
    pub clusters: Vec<(StateClusterId, StateSignature, u32)>,
    /// Lossless graph (also carries cluster-target and composite edges, which
    /// `EdgeRecord` cannot represent). Absent when restoring from rows only.
    pub graph: Option<GraphSnapshot>,
}

/// The state one principal's exploration accumulates.
pub struct ExplorationState {
    run: CrawlRunId,
    principal: PrincipalId,
    seed: CrawlSeed,
    cfg: ExplorationConfig,
    ledger: InMemoryLedger,
    graph: EnablementGraph,
    clusters: ClusterIndex,
    identities: InMemoryIdentityIndex,
    frontier: FrontierStats,
    stall: StallCounters,
    /// Identities visible in the newest observation.
    visible_now: BTreeSet<ElementIdentityHash>,
    /// Every identity ever observed.
    known: BTreeSet<ElementIdentityHash>,
    /// Elements with at least one trusted execution.
    exercised_elements: BTreeSet<ElementIdentityHash>,
    /// Hidden targets in cooldown after repeated failed enablement attempts.
    exhausted_targets: BTreeSet<ElementIdentityHash>,
    target_attempts: BTreeMap<ElementIdentityHash, u32>,
    /// Identities first seen in the newest observation.
    last_new: BTreeSet<ElementIdentityHash>,
    /// Action-context keys the newest observation registered that the ledger had never seen.
    last_new_keys: usize,
    /// Identities an event exposed after the session's first observation that are still
    /// visible and still unexercised (empty for the first observation).
    newly_visible: BTreeSet<ElementIdentityHash>,
    last_diff: Option<f32>,
    last_bundle: Option<ObservationBundle>,
    /// Key ids of the newest observation (for counter refresh).
    here_keys: Vec<ActionContextId>,
    group_of: BTreeMap<ActionContextId, Digest>,
    pending_enablement: bool,
    pending_targets: Vec<ElementIdentityHash>,
}

impl ExplorationState {
    /// Create an empty state for one principal of `run`; `seed` drives deterministic tie-breaks.
    #[must_use]
    pub fn new(run: CrawlRunId, principal: PrincipalId, seed: CrawlSeed, cfg: ExplorationConfig) -> Self {
        Self {
            run,
            principal,
            seed,
            cfg,
            ledger: InMemoryLedger::new().with_isolation(cfg.target_isolation),
            graph: EnablementGraph::with_params(run, cfg.graph),
            clusters: ClusterIndex::new(),
            identities: InMemoryIdentityIndex::new(),
            frontier: FrontierStats::new(cfg.queue),
            stall: StallCounters::default(),
            visible_now: BTreeSet::new(),
            known: BTreeSet::new(),
            exercised_elements: BTreeSet::new(),
            exhausted_targets: BTreeSet::new(),
            target_attempts: BTreeMap::new(),
            last_new: BTreeSet::new(),
            last_new_keys: 0,
            newly_visible: BTreeSet::new(),
            last_diff: None,
            last_bundle: None,
            here_keys: Vec::new(),
            group_of: BTreeMap::new(),
            pending_enablement: false,
            pending_targets: Vec::new(),
        }
    }

    // ---- accessors -----------------------------------------------------

    /// Crawl run this state belongs to.
    #[must_use]
    pub const fn run(&self) -> CrawlRunId {
        self.run
    }

    /// Principal whose exploration this state accumulates.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Crawl seed used for deterministic tie-breaks.
    #[must_use]
    pub const fn seed(&self) -> CrawlSeed {
        self.seed
    }

    /// Configuration the state was created with.
    #[must_use]
    pub const fn config(&self) -> &ExplorationConfig {
        &self.cfg
    }

    /// Same state with `form_values` typed into the text fields whose baseline partition has a
    /// configured value (`-form-config`, [`crate::frontier::build_action`]). Set it before the
    /// first decision round: it is not part of a snapshot.
    #[must_use]
    pub fn with_form_values(mut self, form_values: crawlx_forms::ConfiguredValues) -> Self {
        self.frontier = self.frontier.with_form_values(form_values);
        self
    }

    /// Exercised-action ledger.
    #[must_use]
    pub const fn ledger(&self) -> &InMemoryLedger {
        &self.ledger
    }

    /// Mutable ledger access (for restoring or seeding rows).
    pub fn ledger_mut(&mut self) -> &mut InMemoryLedger {
        &mut self.ledger
    }

    /// Enablement graph learned so far.
    #[must_use]
    pub const fn graph(&self) -> &EnablementGraph {
        &self.graph
    }

    /// Mutable graph access (for restoring or seeding edges).
    pub fn graph_mut(&mut self) -> &mut EnablementGraph {
        &mut self.graph
    }

    /// Index of state clusters seen so far.
    #[must_use]
    pub const fn clusters(&self) -> &ClusterIndex {
        &self.clusters
    }

    /// Identity index the `IdentityResolver` resolves against.
    #[must_use]
    pub const fn identity_index(&self) -> &InMemoryIdentityIndex {
        &self.identities
    }

    /// Frontier statistics (per-group queue state).
    #[must_use]
    pub const fn frontier(&self) -> &FrontierStats {
        &self.frontier
    }

    #[cfg(test)]
    pub(crate) fn frontier_mut(&mut self) -> &mut FrontierStats {
        &mut self.frontier
    }

    /// Stall counters.
    #[must_use]
    pub const fn stall(&self) -> &StallCounters {
        &self.stall
    }

    #[cfg(test)]
    pub(crate) fn stall_mut(&mut self) -> &mut StallCounters {
        &mut self.stall
    }

    /// Attach a fingerprinted state to a cluster (two-stage matching).
    pub fn attach(&mut self, state: StateId, profile: &StateProfile) -> Attachment {
        self.clusters.attach(state, profile, &self.cfg.cluster)
    }

    /// Mutable cluster index (splits, restores).
    pub fn clusters_mut(&mut self) -> &mut ClusterIndex {
        &mut self.clusters
    }

    /// What the newest observation exposed that no earlier one had: identities never seen
    /// before and action-context keys the ledger registers for the first time. The dataset
    /// recorder reads it right after an action's after-observation was ingested
    /// to label the action's novelty gain.
    #[must_use]
    pub fn observation_novelty(&self) -> ObservationNovelty {
        ObservationNovelty {
            new_identities: self.last_new.len(),
            new_keys: self.last_new_keys,
        }
    }

    /// Identities seen earlier but not visible now, not yet exercised and not
    /// in cooldown (sorted): the targets of enablement recovery.
    #[must_use]
    pub fn hidden_targets(&self) -> Vec<ElementIdentityHash> {
        self.known
            .iter()
            .filter(|h| {
                !self.visible_now.contains(h)
                    && !self.exercised_elements.contains(h)
                    && !self.exhausted_targets.contains(h)
            })
            .copied()
            .collect()
    }

    /// Hidden targets the enablement graph knows at least one way to reveal
    /// (an edge or hyperedge ending in the identity), sorted. These are the
    /// only targets recovery can make progress on; pass
    /// `!reachable_hidden_targets().is_empty()` to `SwitchingPolicy::next`.
    #[must_use]
    pub fn reachable_hidden_targets(&self) -> Vec<ElementIdentityHash> {
        let revealed: BTreeSet<ElementIdentityHash> = self
            .graph
            .edges()
            .filter_map(|e| match e.target {
                crawlx_graph::EdgeTarget::Identity(h) => Some(h),
                crawlx_graph::EdgeTarget::Cluster(_) => None,
            })
            .collect();
        self.hidden_targets()
            .into_iter()
            .filter(|t| revealed.contains(t) || !self.graph.hyperedges().for_target(t).is_empty())
            .collect()
    }

    // ---- ingestion -----------------------------------------------------

    /// Hidden targets with a known way to reveal them first, then the rest
    /// (each group sorted), so a bounded per-round search never starves
    /// reachable targets behind unreachable ones.
    fn ordered_hidden_targets(&self) -> Vec<ElementIdentityHash> {
        let mut out = self.reachable_hidden_targets();
        let reachable: BTreeSet<ElementIdentityHash> = out.iter().copied().collect();
        out.extend(
            self.hidden_targets()
                .into_iter()
                .filter(|t| !reachable.contains(t)),
        );
        out
    }

    /// Fold the newest observation in: identities, visible sets, routes,
    /// cluster visits and the keyed actions it exposes (registered in the
    /// ledger so the coverage denominator is exact).
    pub fn ingest_observation(
        &mut self,
        bundle: &ObservationBundle,
        candidates: &[Candidate],
        resolved: &[ResolvedElement],
        cluster: StateClusterId,
        now: Timestamp,
    ) {
        self.ledger.advance(now);
        for r in resolved {
            self.identities.record(r);
        }
        let visible: BTreeSet<ElementIdentityHash> = resolved.iter().map(|r| r.hash).collect();
        self.last_new = visible.difference(&self.known).copied().collect();
        // what an event exposed stays "newly visible" while it is still showing and still
        // unexercised: a menu's remaining items are exercised before anything closes the menu
        // (precondition replay would otherwise cost a reveal per item)
        if self.last_bundle.is_some() {
            let appeared = visible.difference(&self.visible_now).copied();
            self.newly_visible.extend(appeared);
            self.newly_visible
                .retain(|h| visible.contains(h) && !self.exercised_elements.contains(h));
        } else {
            self.newly_visible.clear();
        }
        self.known.extend(visible.iter().copied());
        self.visible_now = visible;

        *self.frontier.cluster_visits.entry(cluster).or_default() += 1;
        let mut url = bundle.url.url.clone();
        url.set_fragment(None);
        let url = url.to_string();
        self.frontier.visited_urls.insert(url.clone());
        let route = bundle.route.template.clone();
        let entry = self
            .frontier
            .routes
            .entry(route.clone())
            .or_insert_with(|| RouteEntry {
                url,
                cluster,
                visits: 0,
            });
        entry.visits += 1;

        self.graph.set_cluster_route(cluster, route.clone());
        self.graph
            .observe_visible(cluster, self.visible_now.iter().copied());

        let modal = crate::frontier::modal_scope(bundle, candidates);
        let mut keyed = enumerate_actions(&EnumInput {
            principal: &self.principal,
            route: &route,
            cluster,
            profile: self.cfg.profile,
            candidates,
            resolved,
            include_keys: self.cfg.include_keys,
            modal: modal.as_ref(),
        });
        self.here_keys.clear();
        let mut new_keys = 0_usize;
        for ka in &mut keyed {
            self.ledger.normalize_key(&mut ka.key);
            if ka.key.is_coarsened() {
                self.graph.set_cluster_route(ka.key.state_cluster, route.clone());
            }
            if self.ledger.register(&ka.key) {
                new_keys += 1;
            }
            let id = ka.key.id();
            self.group_of.insert(id, ka.group);
            self.here_keys.push(id);
        }
        self.last_new_keys = new_keys;
        self.last_diff = self
            .last_bundle
            .as_ref()
            .map(|prev| StateDiff::between(prev, bundle).novelty);
        self.last_bundle = Some(bundle.clone());
        self.refresh_counters();
    }

    /// Fold the executed action's result in (ledger, queue statistics, stall
    /// counters and the enablement graph). Call after
    /// [`Self::ingest_observation`] of the after-bundle.
    pub fn ingest_outcome(&mut self, r: &OutcomeReport) {
        let id = r.key.id();
        self.ledger.advance(r.now);
        let mut first_trusted = false;
        if r.succeeded {
            first_trusted = self.ledger.record(&r.key, &r.outcome, r.lane);
        } else {
            self.ledger.record_failure(&r.key, r.lane);
        }

        if r.succeeded && r.lane == TrustLane::TrustedUi {
            let identity = self.identities.get(&r.key.element).map(|k| k.identity.clone());
            let group = self.group_of.get(&id).copied();
            self.frontier
                .note_trusted_execution(&r.key, identity.as_ref(), group, r.after);
            self.exercised_elements.insert(r.key.element);
            self.frontier
                .revealed_by
                .entry((r.key.element, r.key.action_kind))
                .or_default()
                .extend(r.revealed.iter().copied());
            self.stall.trusted_actions += 1;

            // novel-reveal episode: a never-before-seen identity, absent from the
            // baseline, with no confounding stream traffic
            let confounded = r.confounders.present(self.cfg.graph.volatile_ratio_threshold);
            let novel: Vec<&ElementIdentityHash> = r
                .revealed
                .iter()
                .filter(|h| self.last_new.contains(h) && !r.baseline_revealed.contains(h))
                .collect();
            if !novel.is_empty() && !confounded {
                *self.frontier.reveal_episodes.entry(r.key.element).or_default() += 1;
                *self.frontier.reveal_elements.entry(r.key.element).or_default() +=
                    u32::try_from(novel.len()).unwrap_or(u32::MAX);
            }

            let new_cluster = r.after != r.before && self.frontier.cluster_visits(r.after) == 1;
            let novelty = first_trusted || new_cluster || r.new_operation;
            self.stall.stall = if novelty {
                0
            } else {
                self.stall.stall.saturating_add(1)
            };
        }
        if let Some(d) = self.last_diff.take() {
            self.frontier.key_diff.insert(id, d);
        }

        self.graph.observe_transition(&TransitionObservation {
            source: id,
            family: Some(r.key.family_id()),
            before_cluster: r.before,
            after_cluster: r.after,
            revealed: r.revealed.clone(),
            baseline_revealed: r.baseline_revealed.clone(),
            confounders: r.confounders,
            // measured latency never feeds the graph here: edge costs steer path planning, and a
            // wall-clock input would let timing change which action a seed picks
            latency_ms: None,
            lane: r.lane,
            now: r.now,
        });

        if self.pending_enablement {
            self.stall.enablement_used = self.stall.enablement_used.saturating_add(1);
            for t in std::mem::take(&mut self.pending_targets) {
                let n = self.target_attempts.entry(t).or_default();
                *n += 1;
                if *n >= self.cfg.target_attempts_max {
                    self.exhausted_targets.insert(t);
                }
            }
            self.pending_enablement = false;
        }
        self.pending_targets.clear();
        self.refresh_counters();
    }

    /// Record what the arbiter decided: kernel risk classes (path safety),
    /// keys the kernel blocked (excluded from `Q0`), and whether the chosen
    /// proposal belongs to enablement recovery (budget accounting).
    pub fn ingest_round(&mut self, round: &ArbiterRound) {
        for r in &round.ranked {
            let k = &r.proposal.key;
            self.frontier.risk.insert(k.id(), r.verdict.risk_class);
            // the family id sources generalized graph edges; it carries the latest class
            self.frontier.risk.insert(k.family_id(), r.verdict.risk_class);
            self.frontier
                .element_risk
                .insert((k.element, k.action_kind), r.verdict.risk_class);
        }
        for (p, v) in round.denied.iter().chain(round.approval_required.iter()) {
            let id = p.key.id();
            self.frontier.risk.insert(id, v.risk_class);
            self.frontier.risk.insert(p.key.family_id(), v.risk_class);
            self.frontier
                .element_risk
                .insert((p.key.element, p.key.action_kind), v.risk_class);
            if v.decision == crawlx_core::safety::SafetyDecision::Deny {
                self.frontier.blocked.insert(id);
            }
        }
        self.pending_enablement = round
            .chosen
            .as_ref()
            .is_some_and(|c| c.proposal.strategy == crate::enablement::NAME);
        self.pending_targets = round
            .chosen
            .as_ref()
            .filter(|_| self.pending_enablement)
            .map(|c| c.proposal.expected.reveals.clone())
            .unwrap_or_default();
        self.refresh_counters();
    }

    /// Start decision round `decision_index`: drop cooldowns are measured against it.
    pub fn begin_round(&mut self, decision_index: u64) {
        self.frontier.round = decision_index;
    }

    /// The actor dropped `id` (stale epoch, not actionable, identity changed): no strategy
    /// proposes it again for `cooldown` rounds, so the round plans something else instead of
    /// re-proposing the same unreachable key.
    pub fn note_drop(&mut self, id: ActionContextId, cooldown: u64) {
        self.frontier
            .dropped_until
            .insert(id, self.frontier.round.saturating_add(cooldown));
    }

    /// Planner bookkeeping used by [`crate::plan_merge`].
    pub(crate) fn note_planner_result(&mut self, success: bool) {
        if success {
            self.stall.planner_successes = self.stall.planner_successes.saturating_add(1);
            self.stall.planner_failures = 0;
            self.stall.stall = 0;
        } else {
            self.stall.planner_failures = self.stall.planner_failures.saturating_add(1);
        }
    }

    pub(crate) fn refresh_after_merge(&mut self) {
        self.refresh_counters();
    }

    #[cfg(test)]
    pub(crate) fn mark_blocked(&mut self, id: ActionContextId) {
        self.frontier.blocked.insert(id);
    }

    fn refresh_counters(&mut self) {
        let here = self
            .here_keys
            .iter()
            .filter(|id| !self.frontier.blocked.contains(id) && self.ledger.unexercised_id(**id))
            .count();
        self.stall.unexercised_here = u32::try_from(here).unwrap_or(u32::MAX);
        let blocked_unexercised = self
            .frontier
            .blocked
            .iter()
            .filter(|id| self.ledger.unexercised_id(**id))
            .count();
        let total = self.ledger.unexercised_total() as usize;
        self.stall.unexercised_known =
            u32::try_from(total.saturating_sub(blocked_unexercised)).unwrap_or(u32::MAX);
    }

    // ---- rounds --------------------------------------------------------

    /// Freeze a `DecisionContext` for one round.
    ///
    /// # Errors
    /// [`StrategyError::InvalidContext`] when candidates and identities differ in length.
    pub fn context<'a>(&'a self, round: RoundInput) -> Result<DecisionContext<'a>, StrategyError> {
        DecisionContextBuilder::new(
            round.bundle,
            self.principal.clone(),
            round.cluster,
            self.seed,
            &self.ledger,
            &self.graph,
            &self.frontier,
        )
        .candidates(round.candidates, round.resolved)
        .profile(round.profile)
        .decision_index(round.decision_index)
        .budget(round.budget)
        .stall(self.stall)
        .hidden_targets(self.ordered_hidden_targets())
        .newly_visible(self.newly_visible.clone())
        .exercised(self.exercised_elements.clone())
        .recent(self.frontier.recent_keys().clone())
        .clock_now(round.clock_now)
        .phase(round.phase)
        .include_keys(self.cfg.include_keys)
        .build()
    }

    // ---- persistence ---------------------------------------------------

    /// Rows and a lossless graph for storage.
    #[must_use]
    pub fn snapshot(&self) -> ExplorationSnapshot {
        ExplorationSnapshot {
            ledger_rows: self.ledger.rows(),
            edge_records: self.graph.dump(),
            clusters: self
                .clusters
                .iter()
                .filter(|c| c.is_active())
                .map(|c| (c.id, c.prototype.signature.clone(), c.size))
                .collect(),
            graph: Some(self.graph.snapshot()),
        }
    }

    /// Rebuild from a snapshot. The ledger is rebuilt from rows, so it cannot
    /// claim an action the journal does not show. Derived statistics are
    /// reconstructed: `w_key`/`w_element` from the trusted counts and `R(e)`
    /// from strong reveal edges; `Z`, the repetition window and the identity
    /// index start empty and refill from the next observations.
    #[must_use]
    pub fn restore(
        run: CrawlRunId,
        principal: PrincipalId,
        seed: CrawlSeed,
        cfg: ExplorationConfig,
        snap: ExplorationSnapshot,
    ) -> Self {
        let mut s = Self::new(run, principal, seed, cfg);
        let mut key_of: BTreeMap<ActionContextId, &ActionContextKey> = BTreeMap::new();
        for row in &snap.ledger_rows {
            let id = row.key.id();
            key_of.insert(id, &row.key);
            if row.trusted_exercised > 0 {
                s.frontier.w_key.insert(id, row.trusted_exercised);
                *s.frontier.w_element.entry(row.key.element).or_default() += row.trusted_exercised;
                s.exercised_elements.insert(row.key.element);
                s.stall.trusted_actions += u64::from(row.trusted_exercised);
            }
            s.known.insert(row.key.element);
        }
        match snap.graph {
            Some(g) => s.graph = EnablementGraph::from_snapshot(g, cfg.graph),
            None => {
                // records carry neither families nor cluster routes: rebuild them from the
                // ledger's keys, then the derived route-template edges
                s.graph.load(snap.edge_records.iter().cloned());
                for k in key_of.values() {
                    s.graph.set_family(k.id(), k.family_id());
                    s.graph
                        .set_cluster_route(k.state_cluster, k.route_template.clone());
                }
                if let Some(latest) = snap.edge_records.iter().map(|r| r.last_observed_at).max() {
                    s.graph.generalize_all(latest);
                }
            }
        }
        for e in s.graph.edges() {
            if let crawlx_graph::EdgeTarget::Identity(target) = e.target {
                if e.support == 0 {
                    continue;
                }
                if let Some(k) = key_of.get(&e.source) {
                    *s.frontier.reveal_episodes.entry(k.element).or_default() += 1;
                    *s.frontier.reveal_elements.entry(k.element).or_default() += 1;
                    s.frontier
                        .revealed_by
                        .entry((k.element, k.action_kind))
                        .or_default()
                        .insert(target);
                }
            }
        }
        s.ledger = InMemoryLedger::from_rows(snap.ledger_rows).with_isolation(cfg.target_isolation);
        for (id, sig, size) in snap.clusters {
            s.clusters.restore(id, 1, sig, size);
        }
        s.refresh_counters();
        s
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{Fixture, Spec};
    use crawlx_core::ActionKind;

    #[test]
    fn observation_registers_keys_and_counters() {
        let f = Fixture::new(&[Spec::button("Save"), Spec::link("Docs", "/docs")]);
        let s = f.state();
        // two controls x (click + keyboard_activate)
        assert_eq!(s.ledger().len(), 4);
        assert_eq!(s.stall().unexercised_here, 4);
        assert_eq!(s.stall().unexercised_known, 4);
        assert!(s.frontier().url_visited("https://app.example/app"));
        assert_eq!(s.frontier().routes().len(), 1);
        assert!(s.hidden_targets().is_empty());
    }

    #[test]
    fn outcome_updates_ledger_queue_and_stall() {
        let mut f = Fixture::new(&[Spec::button("Save"), Spec::button("Cancel")]);
        let key = f.key("Save", ActionKind::Click);
        assert_eq!(f.state().stall().stall, 0);
        f.exec(&key, f.cluster(), &[], TrustLane::TrustedUi);
        let s = f.state();
        assert_eq!(s.ledger().trusted_attempts(&key), 1);
        assert_eq!(s.frontier().layer(&key), 1);
        assert_eq!(s.stall().trusted_actions, 1);
        assert_eq!(s.stall().stall, 0, "first exercise of a key is novel");
        assert_eq!(s.stall().unexercised_here, 3);
        // same key again, same cluster, no new operation: stall grows
        f.exec(&key, f.cluster(), &[], TrustLane::TrustedUi);
        assert_eq!(f.state().stall().stall, 1);
        // diagnostic lane never counts
        let cancel = f.key("Cancel", ActionKind::Click);
        f.exec(&cancel, f.cluster(), &[], TrustLane::Diagnostic);
        let s = f.state();
        assert_eq!(s.ledger().trusted_attempts(&cancel), 0);
        assert_eq!(s.stall().trusted_actions, 2);
        assert_eq!(s.ledger().coverage(None).keys_diagnostic_only, 1);
    }

    #[test]
    fn novel_reveal_episode_counts_once_and_feeds_the_bonus() {
        let mut f = Fixture::new(&[Spec::button("Menu")]);
        let menu = f.key("Menu", ActionKind::Click);
        // the menu reveals two never-seen items in place
        let revealed = f.reveal_items(&["Item A", "Item B"]);
        f.exec(&menu, f.open_cluster(), &revealed, TrustLane::TrustedUi);
        assert_eq!(
            f.state().frontier().novel_reveals(&menu.element),
            1,
            "one episode, not one per element"
        );
        assert!(f.state().frontier().enablement_bonus(&menu.element) < 0.0);
        // re-opening the menu reveals nothing new
        f.exec(&menu, f.open_cluster(), &revealed, TrustLane::TrustedUi);
        assert_eq!(f.state().frontier().novel_reveals(&menu.element), 1);
    }

    #[test]
    fn hidden_targets_are_known_but_not_visible_and_unexercised() {
        let mut f = Fixture::new(&[Spec::button("Menu")]);
        let revealed = f.reveal_items(&["Item A"]);
        let item = revealed[0];
        assert_eq!(f.state().hidden_targets(), Vec::<ElementIdentityHash>::new());
        // the menu closes again: item is known but no longer visible
        f.observe(&[Spec::button("Menu")]);
        assert_eq!(f.state().hidden_targets(), vec![item]);
    }

    #[test]
    fn reachable_hidden_targets_need_a_known_way_to_reveal_them() {
        let mut f = Fixture::new(&[Spec::button("Menu")]);
        let menu = f.key("Menu", ActionKind::Click);
        let revealed = f.reveal_items(&["Item A"]);
        f.observe(&[Spec::button("Menu")]);
        // hidden, but nothing is known to reveal it
        assert_eq!(f.state().hidden_targets(), revealed);
        assert!(f.state().reachable_hidden_targets().is_empty());
        // once the menu has been seen to reveal it, recovery has a path to try
        f.reveal_items(&["Item A"]);
        f.exec(&menu, f.open_cluster(), &revealed, TrustLane::TrustedUi);
        f.observe(&[Spec::button("Menu")]);
        assert_eq!(f.state().reachable_hidden_targets(), revealed);
        let ctx = f.ctx();
        assert_eq!(ctx.hidden_targets, revealed);
    }

    #[test]
    fn snapshot_round_trip_rebuilds_ledger_graph_and_queue() {
        let mut f = Fixture::new(&[Spec::button("Menu"), Spec::button("Save")]);
        let menu = f.key("Menu", ActionKind::Click);
        let save = f.key("Save", ActionKind::Click);
        let revealed = f.reveal_items(&["Item A"]);
        f.exec(&menu, f.open_cluster(), &revealed, TrustLane::TrustedUi);
        f.exec(&save, f.cluster(), &[], TrustLane::TrustedUi);
        let snap = f.state().snapshot();
        let run = f.state().run();
        let back = ExplorationState::restore(
            run,
            PrincipalId("member".into()),
            CrawlSeed(1),
            ExplorationConfig::default(),
            snap.clone(),
        );
        assert_eq!(back.ledger().coverage(None), f.state().ledger().coverage(None));
        assert_eq!(back.frontier().layer(&save), 1);
        assert_eq!(back.graph().len(), f.state().graph().len());
        assert!(back.frontier().novel_reveals(&menu.element) >= 1);
        // row-only restore (what storage returns) keeps ledger and element edges
        let rows_only = ExplorationSnapshot { graph: None, ..snap };
        let back2 = ExplorationState::restore(
            run,
            PrincipalId("member".into()),
            CrawlSeed(1),
            ExplorationConfig::default(),
            rows_only,
        );
        assert_eq!(back2.ledger().coverage(None), f.state().ledger().coverage(None));
    }
}
