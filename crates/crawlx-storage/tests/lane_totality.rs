//! Lane totality over stored actions: for every action any journal stores, in every status it
//! can reach, `lane` is present, `fidelity` is present, and the lane is the lane of the
//! fidelity (`trusted_ui` exactly for the three native fidelities). Random action kinds and
//! receipt fidelities (including receipts whose own `lane` field lies) are written through
//! `MemoryStore` and, when `CRAWLX_TEST_DATABASE_URL` is set, PostgreSQL, whose
//! `lane_matches_fidelity` CHECK is also probed with a raw row that violates it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::counters::ActionStatus;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{ActionReceipt, RuntimeLocator};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::{ActionJournal, ActionRecord, OutcomeRecord, RunRepo};
use crawlx_core::traffic::{Fidelity, TrustLane};
use crawlx_core::{
    ActionId, AxNodeId, BackendNodeId, CrawlRunId, FrameId, NetworkEpochId, SessionId, StateClusterId,
    SystemClock, TabId, TenantId, WorkerId,
};
use crawlx_core::{BrowserAction, Clock as _};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions};
use crawlx_storage::{LeaseRepo, MemoryStore, Pg, StoreConfig};
use proptest::prelude::*;
use std::sync::Arc;

/// Every fidelity, in declaration order. The `match` makes the list exhaustive at compile
/// time: a new variant fails the build here until the lane rule below covers it.
const FIDELITIES: [Fidelity; 8] = [
    Fidelity::NativePointer,
    Fidelity::NativeKeyboard,
    Fidelity::NativeTextInput,
    Fidelity::FileChooser,
    Fidelity::ScriptedNavigation,
    Fidelity::SyntheticDomEvent,
    Fidelity::ScriptedScroll,
    Fidelity::FetchPlane,
];

/// The rule the schema enforces, written independently of `Fidelity::lane`.
const fn is_native(f: Fidelity) -> bool {
    match f {
        Fidelity::NativePointer | Fidelity::NativeKeyboard | Fidelity::NativeTextInput => true,
        Fidelity::FileChooser
        | Fidelity::ScriptedNavigation
        | Fidelity::SyntheticDomEvent
        | Fidelity::ScriptedScroll
        | Fidelity::FetchPlane => false,
    }
}

fn locator() -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId("tab-1".into()),
        frame: FrameId("frame-main".into()),
        backend_node_id: BackendNodeId(1),
        object_id: None,
        ax_node_id: Some(AxNodeId("ax1".into())),
        epoch: ObservationEpoch {
            navigation_seq: 1,
            document_seq: 1,
            mutation_seq: 0,
        },
    }
}

/// Proposals of every planned-fidelity class the testkit can build.
fn proposal_of(kind: u8, cluster: StateClusterId, n: u32) -> ActionProposal {
    let mut p = proposal("anonymous", cluster, n);
    p.action = match kind % 4 {
        0 => return p, // scripted navigation (diagnostic plan)
        1 => BrowserAction::Hover { target: locator() },
        2 => BrowserAction::KeyboardActivate { target: locator() },
        _ => BrowserAction::Keys { sequence: Vec::new() },
    };
    p
}

#[derive(Clone, Debug)]
struct Step {
    kind: u8,
    /// Receipt fidelity; `None` finishes without a receipt (the proposed lane stays).
    receipt: Option<usize>,
    /// The receipt's own, possibly lying, lane field.
    receipt_lane_lies: bool,
    ok: bool,
}

fn step() -> impl Strategy<Value = Step> {
    (
        any::<u8>(),
        proptest::option::of(0..FIDELITIES.len()),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(kind, receipt, receipt_lane_lies, ok)| Step {
            kind,
            receipt,
            receipt_lane_lies,
            ok,
        })
}

fn outcome(s: &Step) -> OutcomeRecord {
    let now = Utc::now();
    OutcomeRecord {
        status: if s.ok {
            ActionStatus::Succeeded
        } else {
            ActionStatus::Failed
        },
        receipt: s.receipt.map(|i| {
            let fidelity = FIDELITIES[i];
            let truth = fidelity.lane();
            let lane = if s.receipt_lane_lies {
                match truth {
                    TrustLane::TrustedUi => TrustLane::Diagnostic,
                    _ => TrustLane::TrustedUi,
                }
            } else {
                truth
            };
            ActionReceipt {
                network_epoch: NetworkEpochId::new(),
                fidelity,
                lane,
                started_at: now,
                finished_at: now,
            }
        }),
        settle: None,
        after_state: None,
        traffic: Vec::new(),
        error: (!s.ok).then(|| "boom".to_owned()),
        finished_at: SystemClock.now(),
    }
}

/// The totality rule for one stored row.
fn assert_total(rec: &ActionRecord, what: &str) -> Result<(), TestCaseError> {
    let fidelity = rec
        .fidelity
        .ok_or_else(|| TestCaseError::fail(format!("{what}: no fidelity")))?;
    let lane = rec
        .lane
        .ok_or_else(|| TestCaseError::fail(format!("{what}: no lane")))?;
    prop_assert_eq!(
        lane == TrustLane::TrustedUi,
        is_native(fidelity),
        "{}: lane {:?} for fidelity {:?}",
        what,
        lane,
        fidelity
    );
    prop_assert_eq!(lane, fidelity.lane(), "{}: stored lane vs derived lane", what);
    Ok(())
}

async fn drive(
    journal: &dyn ActionJournal,
    runs: &dyn RunRepo,
    leases: &dyn LeaseRepo,
    tenant: TenantId,
    steps: &[Step],
) -> Result<(), TestCaseError> {
    let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    runs.create(&run, None).await.unwrap();
    let ss = sessions(run.id, 1, 1);
    runs.create_sessions(&ss).await.unwrap();
    let session: SessionId = ss[0].id;
    leases
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap()
        .expect("lease");
    let cluster = StateClusterId::new();
    let epoch = ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: 0,
    };
    let mut ids: Vec<ActionId> = Vec::new();
    for (n, s) in steps.iter().enumerate() {
        let id = journal
            .propose(
                run.id,
                session,
                &proposal_of(s.kind, cluster, u32::try_from(n).unwrap()),
                &allow_verdict(),
            )
            .await
            .unwrap();
        ids.push(id);
        // totality holds the moment the row exists (status `proposed`) ...
        assert_total(&journal.get(id).await.unwrap(), "proposed")?;
        journal.intend(id, session, epoch).await.unwrap();
        assert_total(&journal.get(id).await.unwrap(), "intended")?;
        journal.finish(id, outcome(s)).await.unwrap();
        let rec = journal.get(id).await.unwrap();
        assert_total(&rec, "finished")?;
        // ... and a receipt decides the final lane through its fidelity, never its own lane field
        if let Some(i) = s.receipt {
            prop_assert_eq!(rec.fidelity, Some(FIDELITIES[i]));
        }
    }
    // after the whole sequence every stored row still satisfies the rule
    for rec in journal.list(run.id, None).await.unwrap() {
        assert_total(&rec, "listed")?;
    }
    prop_assert_eq!(journal.list(run.id, None).await.unwrap().len(), ids.len());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    #[test]
    fn memory_store_never_stores_an_action_without_its_fidelity_lane(
        steps in proptest::collection::vec(step(), 1..24)
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let store = Arc::new(MemoryStore::new());
        rt.block_on(drive(&*store, &*store, &*store, TenantId::new(), &steps))?;
    }
}

#[test]
fn every_fidelity_is_listed_once_and_matches_the_independent_lane_rule() {
    let mut seen = std::collections::BTreeSet::new();
    for f in FIDELITIES {
        assert!(seen.insert(f.as_str()), "{f:?} listed twice");
        assert_eq!(f.lane() == TrustLane::TrustedUi, is_native(f), "{f:?}");
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn postgres_never_stores_an_action_without_its_fidelity_lane() {
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
    rt.block_on(pg.ensure_tenant(tenant, "lane")).unwrap();
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 16,
        ..ProptestConfig::default()
    });
    let result = runner.run(&proptest::collection::vec(step(), 1..12), |steps| {
        rt.block_on(drive(&pg, &pg, &pg, tenant, &steps))
    });

    // the schema itself refuses every (lane, fidelity) pair that breaks totality, and
    // nothing stored anywhere in the schema breaks it
    let violations: i64 = rt
        .block_on(
            sqlx::query_scalar(
                "SELECT count(*) FROM actions WHERE (lane = 'trusted_ui') <> \
                 (fidelity IN ('native_pointer','native_keyboard','native_text_input'))",
            )
            .fetch_one(pg.pool()),
        )
        .unwrap();
    assert_eq!(violations, 0, "stored actions that break lane totality");
    let nulls: i64 = rt
        .block_on(
            sqlx::query_scalar("SELECT count(*) FROM actions WHERE lane IS NULL OR fidelity IS NULL")
                .fetch_one(pg.pool()),
        )
        .unwrap();
    assert_eq!(nulls, 0, "stored actions without a lane or fidelity");
    rt.block_on(async {
        let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        pg.create(&run, None).await.unwrap();
        let ss = sessions(run.id, 1, 1);
        pg.create_sessions(&ss).await.unwrap();
        pg.claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        let id = pg
            .propose(
                run.id,
                ss[0].id,
                &proposal_of(0, StateClusterId::new(), 1),
                &allow_verdict(),
            )
            .await
            .unwrap();
        // a raw statement that would store a native fidelity on the diagnostic lane is refused
        let bad = sqlx::query(
            "UPDATE actions SET lane = 'diagnostic', fidelity = 'native_pointer' WHERE action_id = $1",
        )
        .bind(id.0)
        .execute(pg.pool())
        .await
        .expect_err("lane_matches_fidelity must refuse the row");
        assert!(bad.to_string().contains("lane_matches_fidelity"), "{bad}");
        let bad = sqlx::query(
            "UPDATE actions SET lane = 'trusted_ui', fidelity = 'synthetic_dom_event' WHERE action_id = $1",
        )
        .bind(id.0)
        .execute(pg.pool())
        .await
        .expect_err("lane_matches_fidelity must refuse the row");
        assert!(bad.to_string().contains("lane_matches_fidelity"), "{bad}");
    });
    rt.block_on(pg.drop_schema()).unwrap();
    result.unwrap();
}
