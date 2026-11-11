//! `actions.status` model test: random command sequences run against an
//! in-memory model, `MemoryStore`, and (when `CRAWLX_TEST_DATABASE_URL` is set) PostgreSQL.
//!
//! I1 only {proposed, reconciled(not_applied)} rows are eligible
//! I2 a crash after `intended` and before an outcome yields `unknown`, never `failed`
//! I3 `unknown` is only ever left through `reconcile`
//! I5 each action reaches `perform` (intend) at most once per proposed/reconciled generation
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, Utc};
use crawlx_core::counters::{ActionStatus, ReconcileResolution};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::repo::*;
use crawlx_core::time::ManualClock;
use crawlx_core::{
    ActionId, Clock as _, CrawlRunId, SessionId, StateClusterId, SystemClock, TenantId, WorkerId,
};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions};
use crawlx_storage::{LeaseRepo, MemoryStore, Pg, StoreConfig};
use proptest::prelude::*;
use std::sync::Arc;

#[derive(Clone, Debug)]
enum Cmd {
    Propose,
    Intend(u8),
    Finish(u8, bool),
    Crash,
    Reconcile(u8, u8),
}

fn cmd() -> impl Strategy<Value = Cmd> {
    prop_oneof![
        3 => Just(Cmd::Propose),
        4 => any::<u8>().prop_map(Cmd::Intend),
        3 => (any::<u8>(), any::<bool>()).prop_map(|(i, ok)| Cmd::Finish(i, ok)),
        1 => Just(Cmd::Crash),
        3 => (any::<u8>(), 0u8..3).prop_map(|(i, r)| Cmd::Reconcile(i, r)),
    ]
}

#[derive(Clone, Copy, PartialEq, Debug)]
struct Model {
    status: ActionStatus,
    resolution: Option<ReconcileResolution>,
    attempt: u16,
}

impl Model {
    fn eligible(&self) -> bool {
        self.status == ActionStatus::Proposed
            || (self.status == ActionStatus::Reconciled
                && self.resolution == Some(ReconcileResolution::NotApplied))
    }
}

trait Backend {
    fn journal(&self) -> &dyn ActionJournal;
    fn leases(&self) -> &dyn LeaseRepo;
    fn runs(&self) -> &dyn RunRepo;
    fn sessions(&self) -> &dyn RunRepo;
}

struct Mem {
    store: Arc<MemoryStore>,
    clock: ManualClock,
}
impl Backend for Mem {
    fn journal(&self) -> &dyn ActionJournal {
        &*self.store
    }
    fn leases(&self) -> &dyn LeaseRepo {
        &*self.store
    }
    fn runs(&self) -> &dyn RunRepo {
        &*self.store
    }
    fn sessions(&self) -> &dyn RunRepo {
        &*self.store
    }
}

impl Mem {
    async fn crash(&self) {
        self.clock.advance_ms(120_000);
        self.store.reap(self.clock.now()).await.unwrap();
    }
    fn eligible(&self, run: CrawlRunId) -> Vec<ActionId> {
        self.store
            .eligible_actions(run, None)
            .into_iter()
            .map(|a| a.id)
            .collect()
    }
}

struct Pgb(Pg);
impl Backend for Pgb {
    fn journal(&self) -> &dyn ActionJournal {
        &self.0
    }
    fn leases(&self) -> &dyn LeaseRepo {
        &self.0
    }
    fn runs(&self) -> &dyn RunRepo {
        &self.0
    }
    fn sessions(&self) -> &dyn RunRepo {
        &self.0
    }
}

impl Pgb {
    async fn crash(&self) {
        self.0.reap(Utc::now() + Duration::seconds(600)).await.unwrap();
    }
    async fn eligible(&self, run: CrawlRunId) -> Vec<ActionId> {
        self.0
            .eligible_actions(run, None, 1000)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect()
    }
}

/// Run `cmds`; `crash` and `eligible` are backend specific.
async fn drive<B: Backend>(
    b: &B,
    tenant: TenantId,
    cmds: &[Cmd],
    crash: impl AsyncFn(&B),
    eligible: impl AsyncFn(&B, CrawlRunId) -> Vec<ActionId>,
) -> Result<(), TestCaseError> {
    let cfg = create_crawl("https://example.test/", &[], 1);
    let run = crawl_run(tenant, cfg);
    b.runs().create(&run, None).await.unwrap();
    let ss = sessions(run.id, 1, 1);
    b.sessions().create_sessions(&ss).await.unwrap();
    let session: SessionId = ss[0].id;
    let claim = |parallel| async move {
        b.leases()
            .claim_session(run.id, WorkerId::new(), parallel)
            .await
            .unwrap()
    };
    claim(false).await.expect("initial lease");

    let cluster = StateClusterId::new();
    let epoch = ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: 0,
    };
    let mut ids: Vec<ActionId> = Vec::new();
    let mut model: Vec<Model> = Vec::new();
    let mut crashed = false;

    for c in cmds {
        match c {
            Cmd::Propose => {
                let id = b
                    .journal()
                    .propose(
                        run.id,
                        session,
                        &proposal("anonymous", cluster, u32::try_from(ids.len()).unwrap()),
                        &allow_verdict(),
                    )
                    .await
                    .unwrap();
                ids.push(id);
                model.push(Model {
                    status: ActionStatus::Proposed,
                    resolution: None,
                    attempt: 0,
                });
            }
            Cmd::Intend(i) if !ids.is_empty() => {
                let k = usize::from(*i) % ids.len();
                let m = &mut model[k];
                let expect_ok = m.eligible();
                let res = b.journal().intend(ids[k], session, epoch).await;
                prop_assert_eq!(res.is_ok(), expect_ok, "intend({:?}) from {:?}: {:?}", k, m, res);
                if expect_ok {
                    if m.status == ActionStatus::Reconciled {
                        m.attempt += 1;
                    }
                    m.status = ActionStatus::Intended;
                }
            }
            Cmd::Finish(i, ok) if !ids.is_empty() => {
                let k = usize::from(*i) % ids.len();
                let m = &mut model[k];
                let status = if *ok {
                    ActionStatus::Succeeded
                } else {
                    ActionStatus::Failed
                };
                let res = b
                    .journal()
                    .finish(
                        ids[k],
                        OutcomeRecord {
                            status,
                            receipt: None,
                            settle: None,
                            after_state: None,
                            traffic: vec![],
                            error: None,
                            finished_at: SystemClock.now(),
                        },
                    )
                    .await;
                let expect_ok = m.status == ActionStatus::Intended;
                prop_assert_eq!(res.is_ok(), expect_ok, "finish from {:?}: {:?}", m, res);
                if expect_ok {
                    m.status = status;
                }
            }
            Cmd::Crash => {
                crash(b).await;
                crashed = true;
                for m in &mut model {
                    if m.status == ActionStatus::Intended {
                        m.status = ActionStatus::Unknown; // I2: never failed
                    }
                }
                // recovery: a new worker takes the recovering session and, after reconciling, resumes it
                claim(false).await.expect("recovering session is re-claimable");
                b.sessions()
                    .set_session_status(session, SessionStatus::Running)
                    .await
                    .unwrap();
            }
            Cmd::Reconcile(i, r) if !ids.is_empty() => {
                let k = usize::from(*i) % ids.len();
                let m = &mut model[k];
                let resolution = [
                    ReconcileResolution::Applied,
                    ReconcileResolution::NotApplied,
                    ReconcileResolution::Indeterminate,
                ][usize::from(*r)];
                let res = b
                    .journal()
                    .reconcile(
                        ids[k],
                        Reconciliation {
                            resolution,
                            evidence: serde_json::json!({}),
                            reconciled_at: SystemClock.now(),
                        },
                    )
                    .await;
                let expect_ok = m.status.can_transition_to(ActionStatus::Reconciled);
                prop_assert_eq!(res.is_ok(), expect_ok, "reconcile from {:?}: {:?}", m, res);
                if expect_ok {
                    m.status = ActionStatus::Reconciled;
                    m.resolution = Some(resolution);
                }
            }
            _ => {}
        }
        // compare with the store after every step
        let stored = b.journal().list(run.id, None).await.unwrap();
        prop_assert_eq!(stored.len(), model.len());
        for (rec, m) in stored.iter().zip(&model) {
            prop_assert_eq!((rec.status, rec.attempt), (m.status, m.attempt));
            // I3: unknown only becomes reconciled via reconcile (checked by `expect_ok` above) and never failed
            prop_assert!(
                !(crashed && rec.status == ActionStatus::Failed && m.status != ActionStatus::Failed)
            );
        }
        let mut want: Vec<ActionId> = ids
            .iter()
            .zip(&model)
            .filter(|(_, m)| m.eligible())
            .map(|(i, _)| *i)
            .collect();
        let mut got = eligible(b, run.id).await;
        want.sort();
        got.sort();
        prop_assert_eq!(got, want, "I1: eligible set");
    }
    Ok(())
}

fn block_on<F: std::future::Future>(rt: &tokio::runtime::Runtime, f: F) -> F::Output {
    rt.block_on(f)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    #[test]
    fn memory_store_follows_the_status_machine(cmds in proptest::collection::vec(cmd(), 1..40)) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let clock = ManualClock::new(Utc::now());
        let b = Mem { store: Arc::new(MemoryStore::with_clock(Arc::new(clock.clone()))), clock };
        block_on(&rt, drive(&b, TenantId::new(), &cmds, async |b: &Mem| b.crash().await, async |b: &Mem, run| b.eligible(run)))?;
    }
}

#[test]
fn postgres_follows_the_same_status_machine() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let schema = format!("t_{}", CrawlRunId::new().0.simple());
    let pg = rt.block_on(async {
        let pg = Pg::connect(
            &url,
            StoreConfig {
                schema: Some(schema),
                max_connections: 4,
                ..StoreConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        pg
    });
    let tenant = TenantId::new();
    rt.block_on(pg.ensure_tenant(tenant, "model")).unwrap();
    let b = Pgb(pg.clone());
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 24,
        ..ProptestConfig::default()
    });
    let result = runner.run(&proptest::collection::vec(cmd(), 1..24), |cmds| {
        block_on(
            &rt,
            drive(
                &b,
                tenant,
                &cmds,
                async |b: &Pgb| b.crash().await,
                async |b: &Pgb, run| b.eligible(run).await,
            ),
        )
    });
    rt.block_on(pg.drop_schema()).unwrap();
    result.unwrap();
}
