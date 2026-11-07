//! crawlx-strategies: strategies, frontier, utility, arbiter, switching policy.
//!
//! Strategies are **advisory proposers** behind one versioned trait. They never
//! touch the browser, never write storage and never decide safety: the
//! [`Arbiter`] classifies every proposal with the safety kernel *before*
//! scoring, the exploration driver adjudicates the winner, and the Session
//! Actor revalidates it against live facts.
//!
//! # Round protocol (what the exploration driver does)
//!
//! ```text
//! state.ingest_observation(bundle, candidates, resolved, cluster, now)
//! phase = policy.next(state.stall(), &budget, !state.reachable_hidden_targets().is_empty(), candidates.len())
//! ctx   = state.context(RoundInput::new(..).with_phase(phase))?
//! round = run_strategies(&strategies, &ctx, &StrategyDeadlines::default()).await
//! out   = arbiter.choose(round.proposals, &ctx, &kernel, &safety_ctx)
//! state.ingest_round(&out)                       // risk classes, blocked keys, budget bookkeeping
//! kernel.adjudicate(out.chosen.proposal, ..) → Execute → after bundle
//! state.ingest_observation(after ..); state.ingest_outcome(&OutcomeReport { .. })
//! planner.step_done(..) / planner.take_finished() → merge_plan(&outcome, &mut state)
//! ```
//!
//! * [`context`] — the frozen [`DecisionContext`] and its builder.
//! * [`exploration`] — [`ExplorationState`]: ledger, enablement graph, cluster
//!   index, identity index, the paper's layered queue (`W`, `Z`, `E`), stall
//!   counters; snapshot/restore through core repo rows.
//! * [`ledger`] — [`InMemoryLedger`] / [`LedgerView`] / [`CoverageSummary`].
//! * [`frontier`] — key enumeration, template dedupe, queue statistics.
//! * [`utility`] — `U(k)` with the default weights.
//! * [`arbiter`] — merge, classify, score, seeded tie-break.
//! * [`switching`] — the Greedy → recovery → planner state machine.
//! * [`interaction_bfs`], [`event_driven`], [`novelty`], [`enablement`], [`url_plane`],
//!   [`system1`], [`llm_planner`] — the strategies; [`plan_merge`] folds a
//!   finished planner plan back into the deterministic frontier.
//! * [`runner`] — concurrent fan-out under per-strategy deadlines.
//! * [`trace`] — serializable round traces for golden-trace replay.
//! * [`ab`] — deterministic A/B arms over several versions of one strategy.
//!
//! Determinism: every decision path iterates `BTreeMap`s or sorted `Vec`s, all
//! randomness derives from `CrawlSeed::rng`/`derive`, and no strategy reads wall
//! time (`DecisionContext::clock_now` is injected).

// No hash-ordered containers on decision or hashing paths (`clippy.toml`).
#![deny(clippy::disallowed_types)]

pub mod ab;
pub mod arbiter;
pub mod context;
pub mod enablement;
pub mod error;
pub mod event_driven;
pub mod exploration;
pub mod frontier;
pub mod interaction_bfs;
pub mod ledger;
pub mod llm_planner;
pub mod novelty;
pub mod plan_merge;
pub mod registry;
pub mod runner;
pub mod switching;
pub mod system1;
pub mod trace;
pub mod url_plane;
pub mod utility;

#[cfg(test)]
mod golden;
#[cfg(test)]
pub(crate) mod testutil;

use async_trait::async_trait;
use crawlx_core::proposal::ActionProposal;

pub use ab::{Arm, ArmAssignment, ArmedStrategy};
pub use arbiter::{Arbiter, ArbiterConfig, ArbiterRound, InvalidReason, Ranked, ARBITER_VERSION};
pub use context::{BudgetView, DecisionContext, DecisionContextBuilder, StallCounters};
pub use enablement::{EnablementConfig, EnablementRecovery};
pub use error::StrategyError;
pub use event_driven::{EventDriven, EventDrivenConfig};
pub use exploration::{
    ExplorationConfig, ExplorationSnapshot, ExplorationState, ObservationNovelty, OutcomeReport, RoundInput,
};
pub use frontier::{
    dedupe_groups, enumerate_actions, intent_for_key, rebuild_action, resolve_href, route_element,
    target_facts, Deduped, EVariant, EnumInput, FrontierStats, Intent, KeyedAction, QueueCfg, RouteEntry,
};
pub use interaction_bfs::{BfsConfig, InteractionBfs};
pub use ledger::{CoverageStatus, CoverageSummary, InMemoryLedger, LedgerView, RouteCoverage};
pub use llm_planner::{
    AbortReason, ExecutedStep, LlmPlanner, LlmPlannerConfig, PlanOutcome, PlanProgress, PlanStepReport,
    PlannerStats,
};
pub use novelty::{NoveltyConfig, StateNovelty};
pub use plan_merge::{merge as merge_plan, MergeReport};
pub use registry::{Gate, GateFile, Gates};
pub use runner::{run_strategies, StrategyDeadlines, StrategyRound};
pub use switching::{Phase, SwitchingConfig, SwitchingPolicy};
pub use system1::{RecordedEngine, System1, System1Config, System1Record};
pub use trace::{GoldenTrace, RankedTrace, RoundTrace};
pub use url_plane::{UrlPlane, UrlPlaneConfig};
pub use utility::{risk_weight, score, KeyFeatures, Scorer, UtilityWeights};

/// A versioned, advisory action proposer.
///
/// Proposals are advisory: the arbiter scores them, the safety kernel filters
/// them. A strategy is a pure function of the `DecisionContext` and its seed:
/// no wall-clock reads, no unseeded randomness, no hidden global state
/// (model-backed strategies are not pure; their outputs are recorded).
#[async_trait]
pub trait Strategy: Send + Sync {
    /// Proposals for the frozen round.
    async fn propose(&self, context: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError>;

    /// Stable name recorded on every proposal.
    fn name(&self) -> &'static str;

    /// Recorded on every `ActionProposal` for replay and A/B attribution. Any
    /// change that can alter the proposals for the same context bumps it.
    fn version(&self) -> u32;
}
