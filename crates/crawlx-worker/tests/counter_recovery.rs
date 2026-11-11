//! Run counters are derived state: `crawl_runs.counters` is a snapshot
//! flushed after the driver counted an action, the journal rows written by T2 are the source.
//! A worker killed between the T2 commit of an action and that flush leaves the stored
//! counters behind the journal; the worker that recovers the session must re-derive them
//! before the session acts again, so the stored `interactions.*` counters equal the journal
//! counts once the run is recovered and finished (`crawlx_bench::trail` `counter_mismatch`).
//!
//! * `a_recovered_session_re_derives_*`: the dead holder's journal rows and one completed
//!   browser page (observation custody) are written directly (committed, nothing counted), on
//!   memory and PostgreSQL.
//! * `a_kill_between_t2_and_the_counter_flush_*` (`--features chaos`): a real worker is
//!   killed at the `after_outcome_before_counter_flush` failpoint, the same window the
//!   SIGKILL drill of `crawlx-cli/tests/chaos.rs` hits.
//!
//! The PostgreSQL variants skip without `CRAWLX_TEST_DATABASE_URL`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{ActionStatus, PlaneCounters, RunStatus};
use crawlx_core::custody::CustodyLease;
use crawlx_core::orchestration::{ObservedAppendV1, ObservedCommitV1, ObservedRequestV1, RequestCommitV1};
use crawlx_core::repo::{CrawlRun, OutcomeRecord, SessionStatus};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::{
    Clock, CrawlRunId, CreateCrawl, ObservationEpoch, SessionId, StateClusterId, SystemClock, TenantId,
    WorkerId,
};
use crawlx_fetch::StaticResolver;
use crawlx_scheduler::{RunPlanner, Scheduler};
use crawlx_storage::checkpoint_crypto::{CheckpointKeys, MemoryCheckpointKeys};
use crawlx_storage::{testkit, FsArtifactStore, MemoryStore, Pg, PgConfig};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{EgressConfig, Stores, WorkerConfig};
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The failpoint table of `crawlx_worker::chaos` is process-global (a drill configures it for
/// every worker of the process): tests run one at a time.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Where the run lives.
#[derive(Clone)]
enum Backing {
    Memory(Arc<MemoryStore>),
    /// One throwaway schema of the test database; `admin` owns it.
    Pg {
        url: String,
        schema: String,
        admin: Pg,
        /// Explicit process-local custody shared by the producer and every recovery wrapper.
        checkpoint_keys: Arc<dyn CheckpointKeys>,
    },
}

impl Backing {
    fn memory() -> Self {
        Self::Memory(Arc::new(MemoryStore::new()))
    }

    /// `None` without `CRAWLX_TEST_DATABASE_URL`.
    async fn pg() -> Option<Self> {
        let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
            return None;
        };
        let schema = format!("t_counters_{}", uuid::Uuid::now_v7().simple());
        let admin = Pg::connect(
            &url,
            PgConfig {
                schema: Some(schema.clone()),
                ..PgConfig::default()
            },
        )
        .await
        .unwrap();
        admin.migrate().await.unwrap();
        Some(Self::Pg {
            url,
            schema,
            admin,
            checkpoint_keys: Arc::new(MemoryCheckpointKeys::new().unwrap()),
        })
    }

    /// Stores over this backing. For PostgreSQL every call opens its own pool in the calling
    /// runtime, so a worker that runs (and is killed) on a runtime of its own leaves no
    /// connection behind that the survivors would reuse.
    async fn stores(&self, dir: &Path, tenant: TenantId) -> Stores {
        match self {
            Self::Memory(store) => {
                let mut stores = Stores::over_memory(Arc::clone(store), dir).await.unwrap();
                stores.tenant = tenant;
                stores
            }
            Self::Pg {
                url,
                schema,
                checkpoint_keys,
                ..
            } => {
                let pg = Pg::connect(
                    url,
                    PgConfig {
                        schema: Some(schema.clone()),
                        ..PgConfig::default()
                    },
                )
                .await
                .unwrap();
                pg.ensure_tenant(tenant, "counter-recovery").await.unwrap();
                let runs: Arc<dyn crawlx_core::repo::RunRepo> = Arc::new(pg.clone());
                let artifacts = FsArtifactStore::open(dir, runs, Arc::new(SystemClock))
                    .await
                    .unwrap()
                    .with_index(Arc::new(pg.clone()));
                let mut stores = Stores::over_pg(pg, Arc::new(artifacts), tenant);
                stores.checkpoint_keys = Arc::clone(checkpoint_keys);
                stores
            }
        }
    }

    /// The holder of every session of `run` stopped heartbeating an hour ago.
    async fn expire_leases(&self, run: CrawlRunId, sessions: &[SessionId]) {
        match self {
            Self::Memory(store) => {
                for s in sessions {
                    store.expire_session_lease(*s, SystemClock.now() - chrono::Duration::hours(1));
                }
            }
            Self::Pg { admin, .. } => {
                sqlx::query(
                    "UPDATE crawl_sessions SET lease_expires_at = now() - interval '1 hour' WHERE run_id = $1",
                )
                .bind(run.0)
                .execute(admin.pool())
                .await
                .unwrap();
            }
        }
    }

    async fn teardown(self) {
        if let Self::Pg { admin, .. } = self {
            admin.drop_schema().await.unwrap();
        }
    }
}

fn cfg(dir: &Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        idle_exit_after: Some(Duration::from_millis(600)),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn app() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("a", "A", "/a"))
                .on_click("a", vec![FakeEffect::Navigate("/a".into())]),
        )
        .page(
            FakePage::new("https://example.test/a")
                .title("A")
                .node(FakeAxSpec::link("h", "Home", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        )
}

fn backend() -> Arc<FakeBackend> {
    Arc::new(
        FakeBackend::builder()
            .script(app())
            .clock(Arc::new(SystemClock))
            .build(),
    )
}

/// What the API does: persist a queued dynamic run and its sessions.
async fn enqueue(stores: &Stores, interactions: u32) -> CrawlRunId {
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = interactions;
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    run.id
}

fn outcome(status: ActionStatus) -> OutcomeRecord {
    OutcomeRecord {
        status,
        receipt: None,
        settle: None,
        after_state: None,
        traffic: Vec::new(),
        error: (status == ActionStatus::Failed).then(|| "boom".to_owned()),
        finished_at: SystemClock.now(),
    }
}

/// The previous holder published a browser URL, committed T2 for `outcomes`, journaled one more
/// intent and died: none of it reached `crawl_runs.counters`.
async fn dead_holder(stores: &Stores, run: CrawlRunId, outcomes: &[ActionStatus]) -> SessionId {
    let scheduler = Scheduler::new(Arc::clone(&stores.leases));
    let lease = scheduler
        .lease_in_run(run, WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    let session = lease.session.id;
    stores
        .runs
        .set_status(run, RunStatus::Running, None)
        .await
        .unwrap();
    let epoch = ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: 0,
    };
    // Browser pages are session-observation custody, not URL work: the dead holder published
    // one under its session fence and committed it.
    let custody = CustodyLease::new(stores.tenant, run, session, lease.worker, lease.fencing_token);
    let envelope = RequestEnvelopeV1::get(
        testkit::canonical_url("https://example.test/committed-before-kill"),
        1,
        None,
    );
    let ObservedAppendV1::Appended { request_id, .. } = stores
        .request_commits
        .append_observed_fenced(ObservedRequestV1::new(
            custody.clone(),
            epoch,
            envelope,
            SystemClock.now(),
        ))
        .await
        .unwrap()
    else {
        panic!("the first rendition of the URL is appended");
    };
    let (_, fence) = stores
        .request_commits
        .lease_observed_fenced(&custody, epoch, request_id)
        .await
        .unwrap()
        .unwrap();
    let queued = stores.frontier.get_request(run, request_id).await.unwrap();
    let committed = stores
        .request_commits
        .commit_observed_fenced(
            RequestCommitV1::terminal(
                run,
                request_id,
                fence,
                queued.state_version,
                crawlx_core::repo::FrontierStatus::Succeeded,
                None,
            ),
            custody,
            epoch,
        )
        .await
        .unwrap();
    assert_eq!(committed, ObservedCommitV1::Committed);
    let cluster = StateClusterId::new();
    for (n, status) in outcomes.iter().enumerate() {
        let proposal = testkit::proposal("anonymous", cluster, u32::try_from(n + 1).unwrap());
        let id = stores
            .journal
            .propose(run, session, &proposal, &testkit::allow_verdict())
            .await
            .unwrap();
        stores.journal.intend(id, session, epoch).await.unwrap();
        stores.journal.finish(id, outcome(*status)).await.unwrap();
    }
    let proposal = testkit::proposal("anonymous", cluster, u32::try_from(outcomes.len() + 1).unwrap());
    let in_flight = stores
        .journal
        .propose(run, session, &proposal, &testkit::allow_verdict())
        .await
        .unwrap();
    stores.journal.intend(in_flight, session, epoch).await.unwrap();
    session
}

/// The stored counters of a finished run equal the journal rows (`verify_trail`'s rule).
async fn assert_counters_match_the_journal(stores: &Stores, run: CrawlRunId) {
    let derived = stores.journal.outcome_counts(run).await.unwrap();
    let stored = stores.runs.get(run).await.unwrap().counters;
    assert_eq!(
        stored.interactions.succeeded, derived.succeeded,
        "interactions.succeeded: {stored:?} vs {derived:?}"
    );
    assert_eq!(
        stored.interactions.failed, derived.failed,
        "interactions.failed: {stored:?} vs {derived:?}"
    );
    assert!(
        stored.interactions.unknown_outcome >= derived.unknown,
        "interactions.unknown_outcome: {stored:?} vs {derived:?}"
    );
    assert!(stored.interactions.invariants_hold(), "{stored:?}");
    let observed = stores
        .frontier
        .list(run)
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.status == crawlx_core::repo::FrontierStatus::Succeeded)
        .count();
    assert!(
        observed >= 1,
        "the dead holder's committed page stays visible as observation custody"
    );
    assert_eq!(
        stores.frontier.state_counts(run).await.unwrap(),
        crawlx_core::repo::FrontierStateCounts::default(),
        "observation custody is not URL work"
    );
    assert_eq!(
        stored.urls.succeeded, 0,
        "browser pages never charge the URL-plane counters"
    );
}

async fn recovered_session_re_derives_its_counters(backing: Backing) {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let stores = backing.stores(dir.path(), TenantId::new()).await;
    let run = enqueue(&stores, 10).await;
    let session = dead_holder(
        &stores,
        run,
        &[
            ActionStatus::Succeeded,
            ActionStatus::Failed,
            ActionStatus::Succeeded,
        ],
    )
    .await;
    backing.expire_leases(run, &[session]).await;
    let before = stores.runs.get(run).await.unwrap().counters;
    assert_eq!(
        before.interactions.attempted, 0,
        "the dead holder flushed nothing"
    );

    run_with(
        cfg(dir.path()),
        stores.clone(),
        Some(backend()),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(stores.runs.get(run).await.unwrap().status, RunStatus::Completed);
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    assert!(sessions.iter().all(|s| s.status == SessionStatus::Completed));
    let derived = stores.journal.outcome_counts(run).await.unwrap();
    assert_eq!(derived.failed, 1);
    assert_eq!(
        derived.unknown, 1,
        "the in-flight row went unknown, then reconciled"
    );
    assert!(derived.succeeded >= 2, "{derived:?}");
    assert_counters_match_the_journal(&stores, run).await;
    let stored = stores.runs.get(run).await.unwrap().counters.interactions;
    assert_eq!(stored.failed, 1);
    assert_eq!(stored.unknown_outcome, 1);
    backing.teardown().await;
}

#[tokio::test]
async fn a_recovered_session_re_derives_the_counters_from_the_journal_in_memory() {
    recovered_session_re_derives_its_counters(Backing::memory()).await;
}

#[tokio::test]
async fn a_recovered_session_re_derives_the_counters_from_the_journal_on_postgres() {
    let Some(backing) = Backing::pg().await else {
        return;
    };
    recovered_session_re_derives_its_counters(backing).await;
}

#[cfg(feature = "chaos")]
mod failpoint {
    use super::*;
    use crawlx_worker::chaos;

    /// A worker on a runtime of its own sleeps at `after_outcome_before_counter_flush` (T2
    /// committed, the action counted in memory, the flush not yet made); dropping that runtime
    /// is the in-process stand-in for `kill -9`: no task runs another statement. A second worker
    /// then recovers the session.
    async fn kill_between_t2_and_the_flush(backing: Backing) {
        let _serial = SERIAL.lock().await;
        chaos::reset();
        chaos::configure(&format!(
            "{}=sleep(600000)",
            chaos::AFTER_OUTCOME_BEFORE_COUNTER_FLUSH
        ));
        let dir = tempfile::tempdir().unwrap();
        let tenant = TenantId::new();
        let stores = backing.stores(dir.path(), tenant).await;
        let run = enqueue(&stores, 12).await;

        let doomed = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let worker_backing = backing.clone();
        let worker_dir = dir.path().to_path_buf();
        let _worker = doomed.spawn(async move {
            let stores = worker_backing.stores(&worker_dir, tenant).await;
            run_with(
                cfg(&worker_dir),
                stores,
                Some(backend()),
                CancellationToken::new(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(60), async {
            while chaos::hits(chaos::AFTER_OUTCOME_BEFORE_COUNTER_FLUSH) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the worker never reached the counter-flush failpoint");
        doomed.shutdown_background();
        chaos::configure("");

        // the window is open: T2 is durable, the stored counters are behind the journal
        let derived = stores.journal.outcome_counts(run).await.unwrap();
        let stored = stores.runs.get(run).await.unwrap().counters.interactions;
        assert!(derived.succeeded >= 1, "{derived:?}");
        assert!(
            stored.succeeded < derived.succeeded,
            "the kill should land before the flush: stored {stored:?}, journal {derived:?}"
        );
        let sessions = stores.runs.list_sessions(run).await.unwrap();
        let ids: Vec<SessionId> = sessions.iter().map(|s| s.id).collect();
        backing.expire_leases(run, &ids).await;

        run_with(
            cfg(dir.path()),
            stores.clone(),
            Some(backend()),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(stores.runs.get(run).await.unwrap().status, RunStatus::Completed);
        assert_counters_match_the_journal(&stores, run).await;
        chaos::reset();
        backing.teardown().await;
    }

    #[tokio::test]
    async fn a_kill_between_t2_and_the_counter_flush_is_repaired_by_recovery_in_memory() {
        kill_between_t2_and_the_flush(Backing::memory()).await;
    }

    #[tokio::test]
    async fn a_kill_between_t2_and_the_counter_flush_is_repaired_by_recovery_on_postgres() {
        let Some(backing) = Backing::pg().await else {
            return;
        };
        kill_between_t2_and_the_flush(backing).await;
    }
}
