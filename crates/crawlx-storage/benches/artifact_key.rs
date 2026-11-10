//! `artifact_key_derive`: `object_key` (`{class}/{tenant}/{run}/{blake3}`) over 1,000 fixed
//! inputs. The per-key cost is the reported time over `INPUTS`.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::hash::Digest;
use crawlx_core::repo::Sensitivity;
use crawlx_core::{CrawlRunId, TenantId};
use crawlx_storage::artifacts::object_key;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

const INPUTS: u32 = 1_000;
const CLASSES: [Sensitivity; 4] = [
    Sensitivity::Metadata,
    Sensitivity::Content,
    Sensitivity::Sensitive,
    Sensitivity::CredentialBearing,
];

/// Inputs derived from the counter only: 8 tenants × 16 runs, a digest per input.
fn inputs() -> Vec<(Sensitivity, TenantId, CrawlRunId, Digest)> {
    (0..INPUTS)
        .map(|n| {
            let tenant = TenantId::from(uuid::Uuid::from_u128(u128::from(n % 8) + 1));
            let run = CrawlRunId::from(uuid::Uuid::from_u128(u128::from(n % 16) + 1));
            let digest = Digest::of("crawlx/bench/artifact", &n.to_le_bytes());
            (CLASSES[n as usize % CLASSES.len()], tenant, run, digest)
        })
        .collect()
}

fn artifact_key_derive(c: &mut Criterion) {
    let inputs = inputs();
    let mut g = c.benchmark_group("artifact_key_derive");
    g.bench_function("object_key/1000", |b| {
        b.iter(|| {
            let mut bytes = 0usize;
            for (class, tenant, run, digest) in &inputs {
                bytes += object_key(black_box(*class), *tenant, *run, digest).len();
            }
            bytes
        });
    });
    g.finish();
}

criterion_group!(benches, artifact_key_derive);
criterion_main!(benches);
