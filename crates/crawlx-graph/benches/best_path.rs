//! `path_cost_search_10k_edges` and `edge_update_batch`.
//!
//! A synthetic graph of `CLUSTERS` clusters arranged as a grid: from cluster `(r, c)` one
//! action leads to `(r + 1, c)` and one to `(r, c + 1)`, each observed `REPS` times so the
//! edges are confident; a hidden control is revealed only from the far corner. The search
//! from the origin to the far corner traverses the full label-setting loop.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use chrono::{DateTime, Duration, TimeZone, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::{ActionContextId, CrawlRunId, StateClusterId, TrustLane};
use crawlx_graph::{best_path, Confounders, EnablementGraph, PathGoal, SearchParams, TransitionObservation};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use uuid::Uuid;

const SIDE: u32 = 50;
const REPS: u32 = 2;

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, 9, 0, 0).unwrap()
}

fn cluster(r: u32, c: u32) -> StateClusterId {
    StateClusterId(Uuid::from_u128(u128::from(r * SIDE + c) + 1))
}

fn action(r: u32, c: u32, dir: u8) -> ActionContextId {
    let d = Digest::of(
        "bench/action",
        &[r.to_le_bytes(), c.to_le_bytes(), [dir, 0, 0, 0]].concat(),
    );
    let mut b = [0u8; 16];
    b.copy_from_slice(&d.0[..16]);
    ActionContextId(b)
}

fn hidden() -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("bench/hidden", b"corner"))
}

fn observations() -> Vec<TransitionObservation> {
    let mut obs = Vec::new();
    let mut i = 0i64;
    for rep in 0..REPS {
        for r in 0..SIDE {
            for c in 0..SIDE {
                for (dir, (nr, nc)) in [(0u8, (r + 1, c)), (1u8, (r, c + 1))] {
                    if nr >= SIDE || nc >= SIDE {
                        continue;
                    }
                    let revealed = if rep == 0 && nr == SIDE - 1 && nc == SIDE - 1 {
                        vec![hidden()]
                    } else {
                        Vec::new()
                    };
                    i += 1;
                    obs.push(TransitionObservation {
                        source: action(r, c, dir),
                        family: None,
                        before_cluster: cluster(r, c),
                        after_cluster: cluster(nr, nc),
                        revealed,
                        baseline_revealed: Vec::new(),
                        confounders: Confounders::default(),
                        latency_ms: 100 + (r + c) % 50,
                        lane: TrustLane::TrustedUi,
                        now: t0() + Duration::seconds(i),
                    });
                }
            }
        }
    }
    obs
}

fn graph(obs: &[TransitionObservation]) -> EnablementGraph {
    let mut g = EnablementGraph::new(CrawlRunId(Uuid::from_u128(7)));
    for o in obs {
        g.observe_transition(o);
    }
    g
}

fn path_search(c: &mut Criterion) {
    let obs = observations();
    let g = graph(&obs);
    let edges = g.edges().count();
    let now = t0() + Duration::seconds(i64::from(SIDE * SIDE * REPS * 2) + 1);
    let safe = |_: ActionContextId| true;
    let mut params = SearchParams::new(now, &safe);
    params.max_hops = usize::try_from(2 * SIDE).unwrap();
    params.max_expansions = 200_000;
    params.min_reliability = 0.0;

    let mut g_ = c.benchmark_group("path_cost_search");
    g_.bench_with_input(BenchmarkId::new("reach_far_corner/edges", edges), &g, |b, g| {
        b.iter(|| {
            best_path(
                black_box(g),
                cluster(0, 0),
                PathGoal::ReachCluster(cluster(SIDE - 1, SIDE - 1)),
                &params,
            )
            .map(|p| p.steps.len())
        });
    });
    g_.bench_with_input(BenchmarkId::new("reveal_hidden/edges", edges), &g, |b, g| {
        b.iter(|| {
            best_path(
                black_box(g),
                cluster(0, 0),
                PathGoal::RevealIdentity(hidden()),
                &params,
            )
            .map(|p| p.steps.len())
        });
    });
    g_.bench_with_input(BenchmarkId::new("reach_neighbour/edges", edges), &g, |b, g| {
        b.iter(|| {
            best_path(
                black_box(g),
                cluster(10, 10),
                PathGoal::ReachCluster(cluster(12, 11)),
                &params,
            )
            .map(|p| p.steps.len())
        });
    });
    g_.finish();
}

fn edge_update_batch(c: &mut Criterion) {
    let obs = observations();
    let mut g = c.benchmark_group("edge_update_batch");
    g.bench_with_input(
        BenchmarkId::new("observe_transition/n", obs.len()),
        &obs,
        |b, obs| {
            b.iter(|| graph(black_box(obs)).edges().count());
        },
    );
    g.finish();
}

criterion_group!(benches, path_search, edge_update_batch);
criterion_main!(benches);
