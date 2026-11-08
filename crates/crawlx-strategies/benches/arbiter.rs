//! `arbiter_select`; `utility_score_2k` lives in `utility.rs`.
//!
//! Gate: deterministic action selection < 10 ms p95 over a 2k-candidate `DecisionContext`.
//! The context is built once through the real discovery and identity
//! pipeline; each iteration ranks and chooses from 2,000 proposals.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{bundle, context, safety_ctx, AllowAll, CANDIDATES};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::CrawlRunId;
use crawlx_graph::EnablementGraph;
use crawlx_strategies::{Arbiter, FrontierStats, InMemoryLedger};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::Arc;
use uuid::Uuid;

fn arbiter_select(c: &mut Criterion) {
    let ledger = InMemoryLedger::new();
    let graph = EnablementGraph::new(CrawlRunId(Uuid::from_u128(1)));
    let frontier = FrontierStats::default();
    let bundle = Arc::new(bundle(CANDIDATES));
    let ctx = context(bundle, &ledger, &graph, &frontier);
    let proposals: Vec<ActionProposal> = ctx
        .keyed_actions()
        .iter()
        .enumerate()
        .filter_map(|(i, ka)| ctx.proposal_for(ka, "bench", 1, 0.5 + (i % 50) as f32 / 100.0))
        .collect();
    assert!(proposals.len() >= CANDIDATES, "{} proposals", proposals.len());
    let arbiter = Arbiter::default();
    let gate = AllowAll;
    let sctx = safety_ctx();

    let mut g = c.benchmark_group("arbiter_select");
    g.bench_with_input(
        BenchmarkId::new("proposals", proposals.len()),
        &proposals,
        |b, proposals| {
            b.iter(|| {
                let round = arbiter.choose(black_box(proposals.clone()), &ctx, &gate, &sctx);
                round.chosen.map(|r| r.proposal.key.element)
            });
        },
    );
    g.finish();
}

criterion_group!(benches, arbiter_select);
criterion_main!(benches);
