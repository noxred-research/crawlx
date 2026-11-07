//! `lease_claim` and `role_round_robin_plan` over the in-memory lease repo.
//!
//! Gate: scheduler operation p95 < 5 ms. The PostgreSQL figure is taken
//! from the integration benchmark; this bench isolates the scheduler's own cost (planning,
//! claim ordering, barrier checks) with storage latency removed.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use chrono::Utc;
use crawlx_core::repo::{RunRepo, SessionStatus};
use crawlx_core::time::ManualClock;
use crawlx_core::{TenantId, WorkerId};
use crawlx_scheduler::{RunPlanner, Scheduler};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::MemoryStore;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::sync::Arc;

const ROLES: &[&str] = &["admin", "member", "guest", "auditor"];

async fn store(runs_per_role: u8) -> (Arc<MemoryStore>, crawlx_core::repo::CrawlRun) {
    let clock = ManualClock::new(Utc::now());
    let store = Arc::new(MemoryStore::with_clock(Arc::new(clock)));
    let cfg = create_crawl("https://example.test/", ROLES, runs_per_role);
    let run = crawl_run(TenantId::new(), cfg.clone());
    store.create(&run, None).await.unwrap();
    store
        .create_sessions(&RunPlanner::sessions(run.id, &cfg))
        .await
        .unwrap();
    (store, run)
}

fn lease_claim(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut g = c.benchmark_group("lease_claim");
    for runs_per_role in [1u8, 10] {
        let sessions = ROLES.len() * usize::from(runs_per_role);
        // One claim + complete per iteration against a fresh run (the barrier admits the first
        // slot only, so claim order is the round-robin order).
        g.bench_with_input(
            BenchmarkId::new("claim_complete/sessions", sessions),
            &runs_per_role,
            |b, rpr| {
                b.iter_batched(
                    || rt.block_on(store(*rpr)),
                    |(store, _run)| {
                        rt.block_on(async {
                            let sched = Scheduler::new(store.clone());
                            let lease = sched.lease_next(WorkerId::new()).await.unwrap().unwrap();
                            sched.complete(&lease).await.unwrap();
                            lease.fencing_token
                        })
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    // Drain a whole run in turn order: the per-op cost reported is for `sessions` operations.
    g.bench_function("drain_run/sessions/40", |b| {
        b.iter_batched(
            || rt.block_on(store(10)),
            |(store, _run)| {
                rt.block_on(async {
                    let sched = Scheduler::new(store.clone());
                    let worker = WorkerId::new();
                    let mut n = 0u32;
                    while let Some(lease) = sched.lease_next(worker).await.unwrap() {
                        sched.release(&lease, SessionStatus::Completed).await.unwrap();
                        n += 1;
                    }
                    n
                })
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

fn round_robin_plan(c: &mut Criterion) {
    let cfg = create_crawl("https://example.test/", ROLES, 10);
    let run = crawl_run(TenantId::new(), cfg.clone());
    c.bench_function("role_round_robin_plan/sessions/40", |b| {
        b.iter(|| RunPlanner::sessions(run.id, &cfg));
    });
}

criterion_group!(benches, lease_claim, round_robin_plan);
criterion_main!(benches);
