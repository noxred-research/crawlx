//! `utility_score_2k` and `novelty_by_action_context`.
//!
//! Both groups use the `arbiter_select` fixture (2,000 discovered controls → 2,668 keyed
//! proposals) over a ledger that knows 10,000 action-context keys: the page's own keys, a
//! third of them exercised one to three times in the trusted lane, plus keys of other
//! clusters so recovery has targets. `utility_score_2k` builds one [`Scorer`] (the arbiter's
//! per-round edge precomputation) and scores every proposal with the kernel's class;
//! `novelty_by_action_context` runs the `state_novelty` strategy's `propose`, which scores the
//! expected after-state novelty of every keyed action before taking its top `n`.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{bundle, cluster, context, CANDIDATES};
use crawlx_core::hash::Digest;
use crawlx_core::identity::{ActionContextKey, ActionKind, ElementIdentityHash, InputClass, ResourceContext};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::safety::RiskClass;
use crawlx_core::traffic::TrustLane;
use crawlx_core::url::RouteTemplate;
use crawlx_core::{CrawlRunId, PrincipalId, StateClusterId};
use crawlx_graph::EnablementGraph;
use crawlx_state::OutcomeClass;
use crawlx_strategies::{FrontierStats, InMemoryLedger, Scorer, StateNovelty, Strategy, UtilityWeights};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::Arc;
use uuid::Uuid;

/// Keys the ledger knows before the round.
const LEDGER_KEYS: usize = 10_000;

fn outcome(status_class: u8) -> OutcomeClass {
    OutcomeClass {
        after_route_template: RouteTemplate("/app".to_owned()),
        after_cluster_family: None,
        network_operation_digest: None,
        status_class,
        unreliable: false,
    }
}

/// A key of another cluster (`/items/:id`, cluster `c`), distinct per `i`.
fn foreign_key(i: usize, c: u128) -> ActionContextKey {
    ActionContextKey {
        principal: PrincipalId("member".into()),
        route_template: RouteTemplate("/items/:id".to_owned()),
        element: ElementIdentityHash(Digest::of("bench/foreign-key", &i.to_le_bytes())),
        action_kind: if i.is_multiple_of(4) {
            ActionKind::Type
        } else {
            ActionKind::Click
        },
        input_class: InputClass::none(),
        resource_context: ResourceContext::Own,
        state_cluster: StateClusterId(Uuid::from_u128(1000 + c)),
    }
}

/// Ledger of `LEDGER_KEYS` keys: every key of the page (a third exercised), the rest spread
/// over 16 other clusters (a tenth exercised).
fn ledger(page_keys: &[ActionContextKey]) -> InMemoryLedger {
    let mut ledger = InMemoryLedger::new();
    for (i, key) in page_keys.iter().enumerate() {
        ledger.register(key);
        if i.is_multiple_of(3) {
            for _ in 0..=((i / 3) % 3) {
                ledger.record(
                    key,
                    &outcome(if i.is_multiple_of(17) { 4 } else { 2 }),
                    TrustLane::TrustedUi,
                );
            }
        }
    }
    let mut i = 0_usize;
    while ledger.len() < LEDGER_KEYS {
        let key = foreign_key(i, u128::try_from(i % 16).unwrap());
        ledger.register(&key);
        if i.is_multiple_of(10) {
            ledger.record(&key, &outcome(2), TrustLane::TrustedUi);
        }
        i += 1;
    }
    ledger
}

fn utility_and_novelty(c: &mut Criterion) {
    let graph = EnablementGraph::new(CrawlRunId(Uuid::from_u128(1)));
    let frontier = FrontierStats::default();
    let bundle = Arc::new(bundle(CANDIDATES));

    // Enumerate the page's keys once over an empty ledger, then build the real ledger from them.
    let page_keys: Vec<ActionContextKey> = {
        let empty = InMemoryLedger::new();
        let ctx = context(Arc::clone(&bundle), &empty, &graph, &frontier);
        ctx.keyed_actions().iter().map(|ka| ka.key.clone()).collect()
    };
    let ledger = ledger(&page_keys);
    assert_eq!(ledger.len(), LEDGER_KEYS);
    let ctx = context(bundle, &ledger, &graph, &frontier);
    assert_eq!(ctx.cluster, cluster());
    let proposals: Vec<ActionProposal> = ctx
        .keyed_actions()
        .iter()
        .enumerate()
        .filter_map(|(i, ka)| ctx.proposal_for(ka, "bench", 1, 0.5 + (i % 50) as f32 / 100.0))
        .collect();
    assert!(proposals.len() >= CANDIDATES, "{} proposals", proposals.len());

    let weights = UtilityWeights::default();
    let mut g = c.benchmark_group("utility_score_2k");
    g.bench_with_input(
        BenchmarkId::new("proposals", proposals.len()),
        &proposals,
        |b, proposals| {
            b.iter(|| {
                let scorer = Scorer::new(&ctx, weights);
                proposals
                    .iter()
                    .map(|p| {
                        let risk = if p.expected.mutates_state {
                            RiskClass::PersistentWriteOwn
                        } else {
                            RiskClass::NavigationReveal
                        };
                        scorer.score(black_box(p), risk)
                    })
                    .fold(f32::NEG_INFINITY, f32::max)
            });
        },
    );
    g.finish();

    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let strategy = StateNovelty::default();
    let mut g = c.benchmark_group("novelty_by_action_context");
    g.bench_function(
        BenchmarkId::new("candidates", format!("{CANDIDATES}/ledger_keys/{LEDGER_KEYS}")),
        |b| {
            b.iter(|| {
                let out = rt.block_on(strategy.propose(black_box(&ctx))).unwrap();
                out.len()
            });
        },
    );
    g.finish();
}

criterion_group!(benches, utility_and_novelty);
criterion_main!(benches);
