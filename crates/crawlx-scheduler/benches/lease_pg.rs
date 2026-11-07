//! `lease_claim_pg`: the scheduler's claim/complete path over the PostgreSQL lease repo.
//!
//! Mirrors `lease_memory.rs` against `crawlx_storage::Pg` in a throw-away schema: every
//! iteration starts from a fresh 40-session run (4 roles × 10 runs per role) and the previous
//! iteration's run is cancelled in the untimed setup, so `active_runs` never grows. Skips
//! (prints and returns) without `CRAWLX_TEST_DATABASE_URL`. Sample counts are low so the group
//! finishes in under two minutes on a local database.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{CrawlRun, RunRepo, SessionStatus};
use crawlx_core::{CrawlRunId, TenantId, WorkerId};
use crawlx_scheduler::{RunPlanner, Scheduler};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{Pg, PgConfig};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

const ROLES: &[&str] = &["admin", "member", "guest", "auditor"];
const RUNS_PER_ROLE: u8 = 10;
const DB_ENV: &str = "CRAWLX_TEST_DATABASE_URL";

async fn connect(url: &str) -> Pg {
    let schema = format!("bench_{}", uuid::Uuid::now_v7().simple());
    let pg = Pg::connect(
        url,
        PgConfig {
            schema: Some(schema),
            max_connections: 8,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    pg
}

/// A fresh run with its sessions planned in round-robin order.
async fn fresh_run(pg: &Pg, tenant: TenantId) -> CrawlRun {
    let cfg = create_crawl("https://example.test/", ROLES, RUNS_PER_ROLE);
    let run = crawl_run(tenant, cfg.clone());
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&RunPlanner::sessions(run.id, &cfg))
        .await
        .unwrap();
    run
}

/// Untimed per-iteration setup: retire the previous run (its leftover sessions leave the
/// partial claim index, as a finished crawl's would) and plan the next.
fn setup(rt: &Runtime, pg: &Pg, tenant: TenantId, previous: &RefCell<Option<CrawlRunId>>) -> CrawlRunId {
    let retired = previous.borrow_mut().take();
    let id = rt.block_on(async {
        if let Some(id) = retired {
            for s in pg.list_sessions(id).await.unwrap() {
                if !s.status.is_terminal() {
                    pg.set_session_status(s.id, SessionStatus::Cancelled)
                        .await
                        .unwrap();
                }
            }
            pg.set_status(id, RunStatus::Cancelled, Some(TerminalReason::Cancelled))
                .await
                .unwrap();
        }
        fresh_run(pg, tenant).await.id
    });
    *previous.borrow_mut() = Some(id);
    id
}

fn lease_claim_pg(c: &mut Criterion) {
    let Some(url) = std::env::var(DB_ENV).ok().filter(|u| !u.is_empty()) else {
        eprintln!("skipping lease_claim_pg: {DB_ENV} unset");
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let pg = rt.block_on(connect(&url));
    let tenant = TenantId::new();
    rt.block_on(pg.ensure_tenant(tenant, "bench")).unwrap();
    let sched = Scheduler::new(Arc::new(pg.clone()));
    let sessions = ROLES.len() * usize::from(RUNS_PER_ROLE);
    let previous: RefCell<Option<CrawlRunId>> = RefCell::new(None);

    let mut g = c.benchmark_group("lease_claim_pg");
    g.sample_size(20)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(15));
    // One claim + complete per iteration against a fresh run: the barrier admits the first slot
    // only, so this is the `active_runs` scan plus one `claim_session` and one `release`.
    g.bench_function(BenchmarkId::new("claim_complete/sessions", sessions), |b| {
        b.iter_batched(
            || setup(&rt, &pg, tenant, &previous),
            |_run| {
                rt.block_on(async {
                    let lease = sched.lease_next(WorkerId::new()).await.unwrap().unwrap();
                    sched.complete(&lease).await.unwrap();
                    lease.fencing_token
                })
            },
            BatchSize::PerIteration,
        );
    });
    // Drain a whole run in turn order: the per-op cost is the reported time over `sessions`
    // claim + release pairs.
    g.bench_function(BenchmarkId::new("drain_run/sessions", sessions), |b| {
        b.iter_batched(
            || setup(&rt, &pg, tenant, &previous),
            |_run| {
                rt.block_on(async {
                    let worker = WorkerId::new();
                    let mut n = 0u32;
                    while let Some(lease) = sched.lease_next(worker).await.unwrap() {
                        sched.release(&lease, SessionStatus::Completed).await.unwrap();
                        n += 1;
                    }
                    n
                })
            },
            BatchSize::PerIteration,
        );
    });
    g.finish();
    rt.block_on(pg.drop_schema()).unwrap();
}

criterion_group!(benches, lease_claim_pg);
criterion_main!(benches);
