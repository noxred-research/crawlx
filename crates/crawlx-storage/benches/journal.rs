//! `action_journal_insert` and `transition_write_batch`: the action journal's two write
//! transactions over the in-memory store and PostgreSQL.
//!
//! * `action_journal_insert`: T1, `propose` + `intend`, per action. One iteration journals
//!   `BATCH` actions into a fresh session; the per-action cost is the reported time over `BATCH`.
//! * `transition_write_batch`: T2, `finish` with a receipt, an after-state and two traffic events
//!   (the transition, network-epoch, traffic and ledger rows), over `BATCH` intended actions.
//!
//! Run, session, lease, before-state and (for T2) the intended actions are created in the
//! untimed setup, so only the journal transaction is measured. The PostgreSQL variants run in a
//! throw-away schema that is dropped afterwards, and skip (print and return) without
//! `CRAWLX_TEST_DATABASE_URL`.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use chrono::Utc;
use crawlx_core::counters::ActionStatus;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{ActionReceipt, SettleReport};
use crawlx_core::repo::{ActionJournal, OutcomeRecord, RunRepo, StateRepo};
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin};
use crawlx_core::{ActionId, NetworkEpochId, SessionId, StateClusterId, TenantId, WorkerId};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, new_state, proposal, sessions};
use crawlx_storage::{LeaseRepo, MemoryStore, Pg, PgConfig};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Actions journalled per iteration.
const BATCH: u32 = 16;
const DB_ENV: &str = "CRAWLX_TEST_DATABASE_URL";

const fn epoch(mutation_seq: u64) -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq,
    }
}

/// The store surface the journal benches drive; both backends implement it.
trait Store: RunRepo + LeaseRepo + ActionJournal + StateRepo {}
impl<T: RunRepo + LeaseRepo + ActionJournal + StateRepo> Store for T {}

/// A claimed session with a before-state, ready for actions.
#[derive(Clone, Copy)]
struct Session {
    id: SessionId,
    cluster: StateClusterId,
}

fn tenant() -> TenantId {
    TenantId::from(uuid::Uuid::from_u128(0xC0FF_EE00_0000_0000_0000_0000_0000_0001))
}

async fn open_session<S: Store>(store: &S) -> (crawlx_core::CrawlRunId, Session) {
    let run = crawl_run(tenant(), create_crawl("https://example.test/", &[], 1));
    RunRepo::create(store, &run, None).await.unwrap();
    store.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    let lease = store
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .expect("a lease");
    let session = Session {
        id: lease.session.id,
        cluster: StateClusterId::new(),
    };
    store
        .put_state(&new_state(session.id, session.cluster, true, 1, epoch(0)))
        .await
        .unwrap();
    (run.id, session)
}

/// T1 for one action: `propose` then `intend`.
async fn t1<S: Store>(store: &S, run: crawlx_core::CrawlRunId, s: Session, n: u32) -> ActionId {
    let id = store
        .propose(run, s.id, &proposal("anonymous", s.cluster, n), &allow_verdict())
        .await
        .unwrap();
    store.intend(id, s.id, epoch(3)).await.unwrap();
    id
}

/// A succeeded outcome reaching every T2 statement: receipt, after-state, two traffic events.
fn outcome(s: Session, n: u32) -> OutcomeRecord {
    let now = Utc::now();
    OutcomeRecord {
        status: ActionStatus::Succeeded,
        receipt: Some(ActionReceipt {
            network_epoch: NetworkEpochId::new(),
            fidelity: Fidelity::ScriptedNavigation,
            lane: Fidelity::ScriptedNavigation.lane(),
            started_at: now,
            finished_at: now,
        }),
        settle: Some(SettleReport::default()),
        after_state: Some(new_state(
            s.id,
            s.cluster,
            false,
            u64::from(n) + 2,
            epoch(5 + u64::from(n)),
        )),
        traffic: (0..2)
            .map(|i| TrafficEvent {
                seq: i,
                epoch_id: None,
                unattributed_reason: None,
                protocol: None,
                origin: TrafficOrigin::Page,
                method: "GET".to_owned(),
                url: format!("https://example.test/api/{n}/{i}"),
                status: Some(200),
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                request_body: None,
                response_body: None,
                third_party: false,
                late: false,
                started_at: now,
                finished_at: Some(now),
            })
            .collect(),
        error: None,
        finished_at: now,
    }
}

/// Untimed setup of the T2 bench: a session with `BATCH` intended actions and their outcomes.
async fn intended_batch<S: Store>(store: &S) -> Vec<(ActionId, OutcomeRecord)> {
    let (run, s) = open_session(store).await;
    let mut batch = Vec::new();
    for n in 0..BATCH {
        let id = t1(store, run, s, n).await;
        batch.push((id, outcome(s, n)));
    }
    batch
}

fn bench_backend<S: Store>(
    c: &mut Criterion,
    rt: &Runtime,
    backend: &'static str,
    mut fresh: impl FnMut() -> S,
) {
    let mut g = c.benchmark_group("action_journal_insert");
    g.sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(12));
    g.bench_function(BenchmarkId::new(backend, BATCH), |b| {
        b.iter_batched(
            || {
                let store = fresh();
                let (run, s) = rt.block_on(open_session(&store));
                (store, run, s)
            },
            |(store, run, s)| {
                rt.block_on(async {
                    for n in 0..BATCH {
                        t1(&store, run, s, n).await;
                    }
                })
            },
            BatchSize::PerIteration,
        );
    });
    g.finish();

    let mut g = c.benchmark_group("transition_write_batch");
    g.sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(12));
    g.bench_function(BenchmarkId::new(backend, BATCH), |b| {
        b.iter_batched(
            || {
                let store = fresh();
                let batch = rt.block_on(intended_batch(&store));
                (store, batch)
            },
            |(store, batch)| {
                rt.block_on(async {
                    for (id, record) in batch {
                        store.finish(id, record).await.unwrap();
                    }
                })
            },
            BatchSize::PerIteration,
        );
    });
    g.finish();
}

fn memory(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    bench_backend(c, &rt, "memory", MemoryStore::new);
}

fn postgres(c: &mut Criterion) {
    let Some(url) = std::env::var(DB_ENV).ok().filter(|u| !u.is_empty()) else {
        eprintln!("skipping the PostgreSQL journal benches: {DB_ENV} unset");
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let schema = format!("bench_{}", uuid::Uuid::now_v7().simple());
    let pg = rt.block_on(async {
        let pg = Pg::connect(
            &url,
            PgConfig {
                schema: Some(schema),
                max_connections: 4,
                ..PgConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        pg.ensure_tenant(tenant(), "bench").await.unwrap();
        pg
    });
    bench_backend(c, &rt, "postgres", || pg.clone());
    rt.block_on(pg.drop_schema()).unwrap();
}

criterion_group!(benches, memory, postgres);
criterion_main!(benches);
