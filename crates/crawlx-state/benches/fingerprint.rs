//! `state_fingerprint_10k` and `state_mask_apply`.
//!
//! Gate: fingerprinting a 10k-node bundle < 15 ms p95. Criterion reports
//! the mean/median; `ci/bench-gate.sh` compares against the committed baseline.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use crawlx_state::{Fingerprinter, MaskBuilder, MaskConfig};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

fn fingerprint(c: &mut Criterion) {
    let fp = Fingerprinter::default();
    let mut g = c.benchmark_group("state_fingerprint");
    for nodes in [1_000usize, 10_000] {
        let bundle = common::big_page(nodes, 0).bundle("/big");
        let masks = MaskBuilder::build(&bundle, &[], &MaskConfig::default());
        g.bench_with_input(
            BenchmarkId::new("nodes", bundle.ax.nodes.len()),
            &bundle,
            |b, bundle| {
                b.iter(|| fp.fingerprint(black_box(bundle), &masks));
            },
        );
    }
    g.finish();
}

fn mask_apply(c: &mut Criterion) {
    let bundle = common::big_page(10_000, 0).bundle("/big");
    c.bench_function("state_mask_apply/nodes/10000", |b| {
        b.iter(|| MaskBuilder::build(black_box(&bundle), &[], &MaskConfig::default()));
    });
}

criterion_group!(benches, fingerprint, mask_apply);
criterion_main!(benches);
