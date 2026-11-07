//! `state_match_lsh` and `state_match_exact`.
//!
//! Gate: state candidate/merge decision < 20 ms p95 over a 5k-cluster index, excluding the
//! database.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use crawlx_state::{
    score, ClusterConfig, ClusterIndex, Fingerprinter, MaskBuilder, MaskConfig, StateProfile,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

const CLUSTERS: usize = 5_000;

/// Profiles of `n` distinct 200-node pages; every page differs in its names.
fn profiles(n: usize) -> Vec<StateProfile> {
    let fp = Fingerprinter::default();
    (0..n)
        .map(|i| {
            let bundle = common::big_page(200, i).bundle(&format!("/p/{i}"));
            let masks = MaskBuilder::build(&bundle, &[], &MaskConfig::default());
            fp.profile(&bundle, &masks)
        })
        .collect()
}

fn index_of(profiles: &[StateProfile]) -> ClusterIndex {
    let cfg = ClusterConfig::default();
    let mut idx = ClusterIndex::with_id_source(common::cluster_ids());
    for (i, p) in profiles.iter().enumerate() {
        idx.attach(common::state_id(i as u128 + 1), p, &cfg);
    }
    idx
}

fn cluster_decision(c: &mut Criterion) {
    let profiles = profiles(CLUSTERS);
    let mut idx = index_of(&profiles);
    let cfg = ClusterConfig::default();
    let probe = &profiles[CLUSTERS / 2];

    let mut g = c.benchmark_group("state_match");
    // Stage 1: LSH bands + route + Hamming prefilter.
    g.bench_with_input(BenchmarkId::new("lsh_candidates", CLUSTERS), &idx, |b, idx| {
        b.iter(|| idx.candidates_with(black_box(&probe.signature), &cfg));
    });
    // Stage 1 + 2: candidates scored against their prototypes (the pure decision, no mutation).
    g.bench_with_input(BenchmarkId::new("exact_decision", CLUSTERS), &idx, |b, idx| {
        b.iter(|| {
            idx.candidates_with(black_box(&probe.signature), &cfg)
                .into_iter()
                .filter_map(|(id, _)| idx.get(id).map(|c| (id, score(&probe.signature, &c.prototype))))
                .max_by(|a, b| a.1.total_cmp(&b.1))
        });
    });
    // Full attach of a state that matches an existing cluster (decision + membership update).
    let mut next_state = u128::from(u64::MAX);
    g.bench_function(BenchmarkId::new("attach_merge", CLUSTERS), |b| {
        b.iter(|| {
            next_state += 1;
            idx.attach(common::state_id(next_state), black_box(probe), &cfg)
        });
    });
    g.finish();
}

criterion_group!(benches, cluster_decision);
criterion_main!(benches);
