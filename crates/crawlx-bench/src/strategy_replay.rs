//! The production decision path as a [`DecisionFn`]: strategies, arbiter and safety kernel of
//! `crawlx-strategies` / `crawlx-safety`, driven offline from recorded snapshots.
//!
//! Each snapshot is rebuilt into a real `ObservationBundle` (through the scripted
//! `FakeBackend`, so the AX/DOM shapes are the ones the observer would produce), run through
//! candidate discovery and identity resolution, folded into an [`ExplorationState`], and decided
//! by the configured strategies and the arbiter with the kernel adjudicating. Teacher forcing
//! feeds the recorded outcome of every step back into the exploration state, so the production
//! state follows the recorded trajectory.

use crate::ablation::AblationVariant;
use crate::driver::cluster_of;
use crate::error::BenchError;
use crate::replay::{DecisionFn, Snapshot, TraceStep};
use crawlx_browser::fake::{FakeAxSpec, FakeBackend, FakePage, FakeScript};
use crawlx_core::browser::{BrowserBackend, ContextConfig};
use crawlx_core::config::{CreateCrawl, Dynamic, LlmPlannerMode, SafetyProfile};
use crawlx_core::identity::{ActionContextKey, ElementIdentityHash};
use crawlx_core::ids::{CrawlRunId, PrincipalId, SessionId};
use crawlx_core::observation::{LiveTargetFacts, ObservationBundle, ObservationSpec};
use crawlx_core::repo::SafetyContext;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::time::{Clock, ManualClock, Timestamp};
use crawlx_elements::{
    Candidate, CandidateDiscovery, DiscoveryConfig, IdentityResolver, MatchWeights, ResolvedElement,
};
use crawlx_graph::update::Confounders;
use crawlx_safety::SafetyKernel;
use crawlx_state::OutcomeClass;
use crawlx_strategies::{
    Arbiter, ArbiterConfig, BudgetView, ExplorationConfig, ExplorationState, OutcomeReport, RoundInput,
    Strategy, StrategyError,
};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::BTreeMap;
use std::sync::Arc;

struct Prepared {
    bundle: ObservationBundle,
    candidates: Vec<Candidate>,
    resolved: Vec<ResolvedElement>,
    /// Candidate index to snapshot `context_id`.
    context_ids: Vec<String>,
}

/// Strategies + arbiter + kernel behind the [`DecisionFn`] seam.
pub struct StrategiesDecision {
    state: ExplorationState,
    strategies: Vec<Arc<dyn Strategy>>,
    arbiter: Arbiter,
    kernel: Option<Arc<SafetyKernel>>,
    profile: SafetyProfile,
    clock: ManualClock,
    decision_index: u64,
    canon: CanonicalizeOptions,
    /// Keys proposed in the last round, by snapshot `context_id`.
    last_keys: BTreeMap<String, ActionContextKey>,
    last_cluster: Option<crawlx_core::ids::StateClusterId>,
    label: String,
}

impl StrategiesDecision {
    /// Production configuration of `variant` (its strategies and queue weights) under `profile`.
    ///
    /// # Errors
    /// Propagates invalid or unavailable strategy configuration from the worker builder.
    pub fn new(variant: &AblationVariant, seed: u64, profile: SafetyProfile) -> Result<Self, StrategyError> {
        let exploration = ExplorationConfig {
            queue: variant.queue_cfg(),
            profile,
            ..ExplorationConfig::default()
        };
        let dynamic = Dynamic {
            strategies: variant.strategies.clone(),
            ..Dynamic::default()
        };
        Ok(Self {
            state: ExplorationState::new(
                CrawlRunId::from(uuid::Uuid::nil()),
                PrincipalId::anonymous(),
                CrawlSeed(seed),
                exploration,
            ),
            strategies: crawlx_worker::build_strategies(&dynamic)?,
            arbiter: Arbiter::new(ArbiterConfig::default()),
            kernel: None,
            profile,
            clock: ManualClock::new(Timestamp::default()),
            decision_index: 0,
            canon: CanonicalizeOptions::default(),
            last_keys: BTreeMap::new(),
            last_cluster: None,
            label: format!("strategies({}, seed={seed}, {})", variant.id, profile.as_str()),
        })
    }

    fn kernel_for(&mut self, snapshot: &Snapshot) -> Option<Arc<SafetyKernel>> {
        if self.kernel.is_none() {
            let url = url::Url::parse(&snapshot.url).ok()?;
            let mut crawl = CreateCrawl::new(url);
            crawl.safety.profile = self.profile;
            let clock: Arc<dyn Clock> = Arc::new(self.clock.clone());
            self.kernel = crawlx_worker::run::build_kernel(&crawl, clock, None)
                .ok()
                .map(Arc::new);
        }
        self.kernel.clone()
    }

    /// Rebuild `snapshot` as an observation and resolve its candidates.
    fn prepare(&self, snapshot: &Snapshot) -> Result<Prepared, BenchError> {
        let mut page = FakePage::new(&snapshot.url);
        if let Some(t) = &snapshot.title {
            page = page.title(t.clone());
        }
        for (i, c) in snapshot.controls.iter().enumerate() {
            let role = if c.role == "generic" {
                "button"
            } else {
                c.role.as_str()
            };
            page = page.node(
                FakeAxSpec::new(c.context_id.clone(), role)
                    .name(c.name.clone().unwrap_or_default())
                    .attr("id", c.context_id.clone())
                    .bbox(10.0, 10.0 + 30.0 * i as f64, 120.0, 24.0),
            );
        }
        let backend = FakeBackend::new(FakeScript::new().page(page));
        let url = url::Url::parse(&snapshot.url)?;
        let canonical = Canonicalizer::canonicalize_url(&url, &self.canon)?;
        let bundle = futures::executor::block_on(async {
            let mut ctx = backend
                .new_context(ContextConfig::new(SessionId::from(uuid::Uuid::nil())))
                .await?;
            ctx.navigate(&canonical).await?;
            ctx.observe(ObservationSpec::default()).await
        })?;
        let discovered = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
        let resolver = IdentityResolver::with_destination(bundle.url.url.clone(), self.canon.clone());
        let weights = MatchWeights::default();
        let mut candidates = Vec::new();
        let mut resolved = Vec::new();
        let mut context_ids = Vec::new();
        for c in discovered {
            let Some(context_id) = c.descriptor.attributes.get("id").cloned() else {
                continue;
            };
            if let Ok(r) = resolver.resolve(&c.descriptor, self.state.identity_index(), &weights) {
                candidates.push(c);
                resolved.push(r);
                context_ids.push(context_id);
            }
        }
        Ok(Prepared {
            bundle,
            candidates,
            resolved,
            context_ids,
        })
    }

    fn base_context(&self, snapshot: &Snapshot) -> SafetyContext {
        let origin = url::Url::parse(&snapshot.url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default();
        SafetyContext {
            profile: self.profile,
            has_test_sinks: false,
            destructive_approval_allowed: false,
            principal: PrincipalId::anonymous(),
            seed_origin: origin,
            in_scope: true,
            target: LiveTargetFacts::default(),
            form_hint: None,
        }
    }
}

impl DecisionFn for StrategiesDecision {
    fn name(&self) -> String {
        self.label.clone()
    }

    fn rank(&mut self, _step: usize, snapshot: &Snapshot) -> Vec<String> {
        self.last_keys.clear();
        let Some(kernel) = self.kernel_for(snapshot) else {
            return Vec::new();
        };
        let Ok(prep) = self.prepare(snapshot) else {
            return Vec::new();
        };
        self.clock.advance_ms(1_000);
        let now = self.clock.now();
        let cluster = cluster_of(prep.bundle.url.url.path());
        self.last_cluster = Some(cluster);
        self.state
            .ingest_observation(&prep.bundle, &prep.candidates, &prep.resolved, cluster, now);
        self.decision_index += 1;
        let budget = BudgetView {
            llm_planner: LlmPlannerMode::Off,
            ..BudgetView::default()
        };
        let base = self.base_context(snapshot);
        let round_input = RoundInput::new(
            Arc::new(prep.bundle.clone()),
            prep.candidates.clone(),
            prep.resolved.clone(),
            cluster,
            self.decision_index,
            self.profile,
            budget,
            now,
        );
        let Ok(ctx) = self.state.context(round_input) else {
            return Vec::new();
        };
        let mut proposals = Vec::new();
        for s in &self.strategies {
            if let Ok(mut p) = futures::executor::block_on(s.propose(&ctx)) {
                proposals.append(&mut p);
            }
        }
        let round = self.arbiter.choose(proposals, &ctx, kernel.as_ref(), &base);
        drop(ctx);
        let mut ranking: Vec<String> = Vec::new();
        for r in &round.ranked {
            let node = r.proposal.action.target().map(|t| t.backend_node_id);
            let context = prep
                .candidates
                .iter()
                .zip(&prep.context_ids)
                .find(|(c, _)| Some(c.descriptor.locator.backend_node_id) == node)
                .map(|(_, id)| id.clone());
            if let Some(id) = context {
                self.last_keys
                    .entry(id.clone())
                    .or_insert_with(|| r.proposal.key.clone());
                if !ranking.contains(&id) {
                    ranking.push(id);
                }
            }
        }
        self.state.ingest_round(&round);
        ranking
    }

    fn observe(&mut self, _step: usize, recorded: &TraceStep, next: Option<&Snapshot>) {
        let Some(key) = self.last_keys.get(&recorded.chosen).cloned() else {
            return;
        };
        let before = self
            .last_cluster
            .unwrap_or_else(|| cluster_of(&recorded.snapshot.url));
        let (after, route, revealed) = match next.and_then(|n| self.prepare(n).ok().map(|p| (n, p))) {
            Some((n, prep)) => {
                let wanted: Vec<&str> = n
                    .controls
                    .iter()
                    .filter(|c| recorded.outcome.revealed.contains(&c.identity))
                    .map(|c| c.context_id.as_str())
                    .collect();
                let revealed: Vec<ElementIdentityHash> = prep
                    .context_ids
                    .iter()
                    .zip(&prep.resolved)
                    .filter(|(id, _)| wanted.contains(&id.as_str()))
                    .map(|(_, r)| r.hash)
                    .collect();
                (
                    cluster_of(prep.bundle.url.url.path()),
                    prep.bundle.url.route_template.clone(),
                    revealed,
                )
            }
            None => (before, key.route_template.clone(), Vec::new()),
        };
        self.clock.advance_ms(500);
        let report = OutcomeReport {
            key,
            outcome: OutcomeClass {
                after_route_template: route,
                after_cluster_family: None,
                network_operation_digest: None,
                status_class: 2,
                unreliable: false,
            },
            lane: recorded.outcome.lane,
            succeeded: recorded.outcome.succeeded,
            before,
            after,
            revealed,
            baseline_revealed: Vec::new(),
            confounders: Confounders::default(),
            new_operation: false,
            now: self.clock.now(),
        };
        self.state.ingest_outcome(&report);
    }
}
