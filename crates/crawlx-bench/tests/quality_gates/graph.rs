//! Enablement-graph gates on real Chromium.
//!
//! * Enablement replay success ≥ 0.9 on the hidden-menu (`g13`) and dialog-chain (`g21`)
//!   fixtures against a binary baseline: a worker run learns `enablement_edges`; the edges
//!   are loaded into a fresh [`EnablementGraph`], the route-template generalizations are
//!   rebuilt from the ledger's keys (families pool evidence across clusters), `best_path` plans
//!   a reveal for every target an edge applicable in the entry cluster names (exact edges, and
//!   generalized ones whose source re-resolves on the fresh page), each plan is executed in a
//!   fresh Chromium context and
//!   scored through [`ReplayValidator`]. The probabilistic rate counts plans with
//!   reliability ≥ 0.8 (the scorecard's `replay_success` rule); the binary baseline counts
//!   every plan, i.e. every edge is "known" once it was observed at all.
//! * Every hover action on `g13` runs on the trusted lane.
//! * The authored A7/A8 efficiency experiment lives in `worker_exec`'s unit tests so only
//!   that private fixture harness, not the deployment executor, supplies test-only G1 status.

use super::common::*;
use crawlx_bench::gym::GymHandle;
use crawlx_bench::scorecard::{ReplayAttempt, RunRows, Scorecard};
use crawlx_bench::worker_exec::rows_from_report;
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::BrowserContext;
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_core::counters::ActionStatus;
use crawlx_core::identity::{ActionKind, ElementIdentityHash};
use crawlx_core::{ActionContextId, StateClusterId, Timestamp, TrustLane};
use crawlx_elements::{Candidate, IdentityBuilder};
use crawlx_graph::{
    best_path, EdgeContext, EdgeTarget, EnablementGraph, PathGoal, PathPlan, ReplayValidator, SearchParams,
    StepOutcome,
};
use crawlx_url::CanonicalizeOptions;
use std::collections::{BTreeMap, BTreeSet};

/// Replay rounds per fixture; each round re-plans from the graph the previous round updated.
/// A singly observed edge starts at 2/3. Three real successes raise it above 0.8 even after
/// decay, leaving three further rounds to measure confident plans without changing the prior.
const REPLAY_ROUNDS: u32 = 6;

/// One executed reveal plan.
#[derive(Clone, Debug)]
struct Replayed {
    /// Product of the plan's step probabilities when it was chosen.
    reliability: f64,
    /// The expected target became visible after the plan ran.
    restored: bool,
    /// Steps of the plan.
    steps: usize,
}

/// Replay outcome of one fixture.
#[derive(Clone, Debug)]
struct ReplayRates {
    replays: Vec<Replayed>,
    /// `(succeeded, attempted)` over plans with reliability ≥ 0.8.
    probabilistic: (usize, usize),
    /// `(succeeded, attempted)` over every plan.
    binary: (usize, usize),
    /// Entry-cluster edge sources that resolved to a candidate on the fresh entry page.
    sources_resolved: usize,
    sources_total: usize,
    /// Edges retired by `prune` between rounds (three consecutive failures).
    retired: usize,
}

fn rate((ok, n): (usize, usize)) -> Option<f64> {
    (n > 0).then(|| ok as f64 / n as f64)
}

/// Identity hash of every candidate, as the worker computes it for a fresh page.
fn hashes(cands: &[Candidate], url: &url::Url) -> BTreeMap<ElementIdentityHash, usize> {
    let canon = CanonicalizeOptions::default();
    cands
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let destination = IdentityBuilder::destination_key(&c.descriptor, url, &canon);
            IdentityBuilder::hash(&IdentityBuilder::build(&c.descriptor, destination))
                .ok()
                .map(|h| (h, i))
        })
        .collect()
}

/// The browser action behind an action context key kind, on `cand`.
fn action_for(kind: ActionKind, cand: &Candidate) -> Option<BrowserAction> {
    let target = cand.descriptor.locator.clone();
    Some(match kind {
        ActionKind::Click => BrowserAction::Click {
            target,
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        },
        ActionKind::Hover => BrowserAction::Hover { target },
        ActionKind::KeyboardActivate => BrowserAction::KeyboardActivate { target },
        _ => return None,
    })
}

/// Cluster of the first journaled action: the entry page's cluster.
fn entry_cluster(run: &FixtureRun) -> StateClusterId {
    run.report
        .actions
        .iter()
        .min_by_key(|a| a.seq)
        .map(|a| a.key.state_cluster)
        .expect("the run journaled at least one action")
}

/// Execute `plan` from the entry page: every step resolves its source element by identity on
/// the current page, performs the recorded action kind and succeeds when the step's expected
/// target is visible afterwards. Returns one outcome per executed step (stops at the first
/// failure, like the worker).
async fn execute_plan(
    ctx: &mut dyn BrowserContext,
    entry: &url::Url,
    keys: &BTreeMap<ActionContextId, (ElementIdentityHash, ActionKind)>,
    plan: &PathPlan,
) -> Vec<StepOutcome> {
    let mut outcomes = Vec::with_capacity(plan.steps.len());
    for step in &plan.steps {
        let cands = discover(ctx).await;
        let by_hash = hashes(&cands, entry);
        let Some((source_hash, kind)) = keys.get(&step.source_action) else {
            outcomes.push(StepOutcome::failed());
            break;
        };
        let Some(action) = by_hash
            .get(source_hash)
            .and_then(|i| action_for(*kind, &cands[*i]))
        else {
            outcomes.push(StepOutcome::failed());
            break;
        };
        let started = std::time::Instant::now();
        if ctx.perform(action).await.is_err() {
            outcomes.push(StepOutcome::failed());
            break;
        }
        let after = discover(ctx).await;
        let after_hashes = hashes(&after, entry);
        let ok = match step.expected_target {
            EdgeTarget::Identity(h) => after_hashes.get(&h).is_some_and(|i| after[*i].evidence.visible),
            EdgeTarget::Cluster(_) => false,
        };
        if ok {
            let ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
            outcomes.push(StepOutcome::ok(ms));
        } else {
            outcomes.push(StepOutcome::failed());
            break;
        }
    }
    outcomes
}

/// Load the run's persisted edges, rebuild their route-template generalizations, plan a reveal
/// for every target of an edge applicable in the entry cluster and replay each plan in a fresh
/// page, feeding outcomes back through the validator.
async fn replay_learned_edges(gym: &GymHandle, run: &FixtureRun) -> ReplayRates {
    let records = run.stores.edges.list(run.report.run_id).await.unwrap();
    assert!(
        !records.is_empty(),
        "{}: the worker persisted no enablement edge",
        run.manifest.id
    );
    let now: Timestamp = records
        .iter()
        .map(|r| r.last_observed_at)
        .max()
        .expect("non-empty")
        + chrono::Duration::minutes(1);
    let mut graph = EnablementGraph::new(run.report.run_id);
    assert_eq!(graph.load(records.iter().cloned()), records.len());

    // the ledger's keys give each source its element, kind, family and cluster route; the
    // route-template edges (derived data, not persisted) are rebuilt from them
    let mut keys: BTreeMap<ActionContextId, (ElementIdentityHash, ActionKind)> = BTreeMap::new();
    for r in &run.report.ledger {
        let k = &r.key;
        keys.insert(k.id(), (k.element, k.action_kind));
        keys.insert(k.family_id(), (k.element, k.action_kind));
        graph.set_family(k.id(), k.family_id());
        graph.set_cluster_route(k.state_cluster, k.route_template.clone());
    }
    let generalized = graph.generalize_all(now).len();
    let entry_cluster = entry_cluster(run);

    let backend = launch().await.expect("have_chromium() was checked");
    let mut ctx = open_fixture(&backend, gym, &run.manifest).await;
    let entry = canonical(&run.manifest.entry_url(&gym.base_url));
    let fresh = hashes(&discover(ctx.as_mut()).await, &entry.url);
    // a generalized edge applies at the entry cluster when its source element re-resolves on
    // the fresh entry page; exact entry-cluster edges always apply
    let resolves = |source: ActionContextId| keys.get(&source).is_some_and(|(h, _)| fresh.contains_key(h));
    let corpus: Vec<_> = graph
        .applicable_edges(entry_cluster)
        .into_iter()
        .filter(|e| match e.context {
            EdgeContext::Cluster(c) => c == entry_cluster,
            EdgeContext::RouteTemplate(_) => resolves(e.source),
            EdgeContext::PrincipalGlobal => false,
        })
        .collect();
    let targets: BTreeSet<ElementIdentityHash> = corpus
        .iter()
        .filter_map(|e| match e.target {
            EdgeTarget::Identity(h) => Some(h),
            EdgeTarget::Cluster(_) => None,
        })
        .collect();
    let sources: BTreeSet<ElementIdentityHash> = corpus
        .iter()
        .filter_map(|e| keys.get(&e.source).map(|(h, _)| *h))
        .collect();
    eprintln!(
        "{}: {generalized} route-template edges rebuilt; entry corpus {} edges ({} generalized)",
        run.manifest.id,
        corpus.len(),
        corpus
            .iter()
            .filter(|e| matches!(e.context, EdgeContext::RouteTemplate(_)))
            .count()
    );
    assert!(
        !targets.is_empty(),
        "{}: no identity edge applicable in the entry cluster {entry_cluster:?}",
        run.manifest.id
    );
    let sources_resolved = sources.iter().filter(|h| fresh.contains_key(h)).count();

    // Replay rounds: every round re-plans from the graph as the validator left it, so an
    // edge's `p_success` before each attempt reflects the attempts before it (the ADR's
    // "bucket `p_success` predictions against replay outcomes"). Retirement runs between
    // rounds exactly as the worker's prune would.
    let safe = |_: ActionContextId| true;
    let validator = ReplayValidator::new();
    let mut replays = Vec::new();
    let mut retired = Vec::new();
    for round in 0..REPLAY_ROUNDS {
        let at = now + chrono::Duration::seconds(i64::from(round));
        for target in &targets {
            let params = SearchParams::new(at, &safe).with_resolvable(&resolves);
            let Some(plan) = best_path(&graph, entry_cluster, PathGoal::RevealIdentity(*target), &params)
            else {
                continue;
            };
            if plan.steps.is_empty() {
                continue;
            }
            ctx.navigate(&entry).await.unwrap();
            let outcomes = execute_plan(ctx.as_mut(), &entry.url, &keys, &plan).await;
            let report = validator.validate(&mut graph, &plan, &outcomes, at).unwrap();
            replays.push(Replayed {
                reliability: plan.reliability,
                restored: report.first_failure.is_none() && report.steps_ok == plan.steps.len(),
                steps: plan.steps.len(),
            });
        }
        retired.extend(graph.prune(at));
    }
    ctx.close().await.unwrap();
    drop(backend);

    let count = |pred: &dyn Fn(&Replayed) -> bool| -> (usize, usize) {
        let picked: Vec<&Replayed> = replays.iter().filter(|r| pred(r)).collect();
        (picked.iter().filter(|r| r.restored).count(), picked.len())
    };
    ReplayRates {
        probabilistic: count(&|r| r.reliability >= 0.8),
        binary: count(&|_| true),
        sources_resolved,
        sources_total: sources.len(),
        retired: retired.len(),
        replays,
    }
}

/// Scorecard rows of the run with the replay attempts attached, so the scorecard's own
/// `enablement.replay_success` (plans with `p_success >= 0.8`) is the asserted figure.
async fn rows_with_replays(run: &FixtureRun, gym: &GymHandle, seed: u64, rates: &ReplayRates) -> RunRows {
    let mut rows = rows_from_report(
        &run.report,
        &run.manifest,
        seed,
        "graph-gate",
        SafetyProfile::TestEnvironment,
        gym,
    );
    rows.edges = run.stores.edges.list(run.report.run_id).await.unwrap();
    rows.replays = rates
        .replays
        .iter()
        .map(|r| ReplayAttempt {
            p_success: r.reliability,
            restored: r.restored,
        })
        .collect();
    rows
}

/// Enablement replay success ≥ 0.9 on hidden-menu / dialog-chain fixtures versus a binary
/// baseline, for one fixture.
async fn replay_gate(
    id: &str,
    seed: u64,
    interactions: u32,
    duration_seconds: u32,
) -> Option<(FixtureRun, ReplayRates, Scorecard)> {
    if !have_chromium() {
        return None;
    }
    let _slot = browser_slot().await;
    let gym = gym().await;
    let run = run_fixture_with(&gym, id, CrawlMode::Dynamic, seed, interactions, |req| {
        req.limits.duration_seconds = duration_seconds;
    })
    .await;
    let rates = replay_learned_edges(&gym, &run).await;
    let rows = rows_with_replays(&run, &gym, seed, &rates).await;
    let sc = Scorecard::compute(&run.manifest, &rows, &gym.ledger());
    let e = sc.enablement.as_ref().expect("edges and replays were recorded");
    eprintln!(
        "{id}: edges={} entry-cluster sources resolved {}/{}; {} rounds, replays={} (steps {:?}), retired={}; probabilistic (p>=0.8) {}/{} = {:?}; binary baseline {}/{} = {:?}; scorecard replay_success={:?}",
        rows.edges.len(),
        rates.sources_resolved,
        rates.sources_total,
        REPLAY_ROUNDS,
        rates.replays.len(),
        rates.replays.iter().map(|r| r.steps).collect::<Vec<_>>(),
        rates.retired,
        rates.probabilistic.0,
        rates.probabilistic.1,
        rate(rates.probabilistic),
        rates.binary.0,
        rates.binary.1,
        rate(rates.binary),
        e.replay_success,
    );
    assert_eq!(
        rates.sources_resolved, rates.sources_total,
        "{id}: every learned source re-resolves on a fresh page"
    );
    assert!(
        rates.probabilistic.1 >= 3,
        "{id}: fewer than three confident plans to replay"
    );
    let probabilistic = rate(rates.probabilistic).unwrap();
    let binary = rate(rates.binary).unwrap();
    assert!(probabilistic >= 0.9, "{id}: replay success {probabilistic}");
    assert!(
        probabilistic >= binary,
        "{id}: probabilistic {probabilistic} < binary baseline {binary}"
    );
    assert_eq!(e.replays_attempted, rates.probabilistic.1 as u64);
    assert_eq!(e.replay_success, Some(probabilistic));
    gym.shutdown().await;
    Some((run, rates, sc))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g21_enablement_replay_succeeds_at_least_point_nine_vs_binary_baseline() {
    let Some((_, rates, _)) = replay_gate("g21", 21, 80, 20).await else {
        return;
    };
    // The dialog chain: `b` behind `a` is the confident plan; `y` behind `x1`+`x2` is not
    // reachable from the entry cluster in one step, so the binary baseline (which replays
    // the low-confidence `x2 -> y` edge too) sits below the probabilistic rate and that edge
    // is retired after three consecutive failures.
    assert!(rates.binary.1 > rates.probabilistic.1, "{rates:?}");
    assert!(rate(rates.binary).unwrap() < 0.9, "{rates:?}");
    assert!(rates.retired >= 1, "{rates:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g13_hover_menus_replay_at_least_point_nine_and_hover_on_the_trusted_lane() {
    let Some((run, rates, _)) = replay_gate("g13", 13, 100, 45).await else {
        return;
    };
    // 18 menu items behind 6 hover triggers: the replay corpus is the hover edges; nothing
    // learned on the hover menus is retired.
    assert!(rates.probabilistic.1 >= 6, "{:?}", rates.replays);
    assert!(
        rates.replays.len() >= 12 * REPLAY_ROUNDS as usize,
        "{:?}",
        rates.replays
    );
    assert_eq!(rates.retired, 0, "{rates:?}");
    // all hover actions on `trusted_ui`.
    let hovers: Vec<_> = run
        .report
        .actions
        .iter()
        .filter(|a| a.key.action_kind == ActionKind::Hover)
        .collect();
    let executed = hovers
        .iter()
        .filter(|a| a.status == ActionStatus::Succeeded)
        .count();
    assert!(executed >= 1, "{}: no hover action executed", run.manifest.id);
    assert!(
        hovers.iter().all(|a| a.lane == Some(TrustLane::TrustedUi)),
        "hover lanes: {:?}",
        hovers.iter().map(|a| a.lane).collect::<Vec<_>>()
    );
    eprintln!(
        "g13: {} hover actions journaled, {executed} executed, all trusted",
        hovers.len()
    );
}
