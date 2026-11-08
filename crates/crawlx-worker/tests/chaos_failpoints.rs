//! Failpoints in the per-action protocol (crash drills), `--features chaos`: a
//! Session Actor that dies at any of the four boundaries leaves the journal in one of exactly
//! two states (nothing of T2 or all of T2); the reaper flips an `intended` row to `unknown`; a
//! fresh actor reconciles it; nothing is ever re-executed without that reconciliation.
#![cfg(feature = "chaos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{canonical, rig_with, Rig};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::counters::{ActionStatus, ReconcileResolution};
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::repo::{ActionJournal, ActionRecord, StateRepo};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{Clock, SafetyProfile, SystemClock};
use crawlx_scheduler::{Reaper, ReaperConfig};
use crawlx_storage::MemoryStore;
use crawlx_worker::chaos;
use crawlx_worker::{SessionError, SessionHandle, ShutdownReason, StateAnalyzer};
use rand::RngExt as _;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

/// The failpoint table is process-global: drills run one at a time.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Every failpoint with what the journal must show once the actor is dead.
const POINTS: [Point; 4] = [
    Point {
        name: chaos::AFTER_INTENT_BEFORE_PERFORM,
        performed: 0,
        committed: false,
    },
    Point {
        name: chaos::AFTER_PERFORM_BEFORE_OUTCOME,
        performed: 1,
        committed: false,
    },
    // the in-memory journal commits T2 in one synchronous step, so the failpoint inside
    // `FailingJournal::finish` fires after the commit: the "all of T2" branch
    Point {
        name: chaos::DURING_OUTCOME_TX,
        performed: 1,
        committed: true,
    },
    Point {
        name: chaos::AFTER_OUTCOME_BEFORE_NEXT_PROPOSAL,
        performed: 1,
        committed: true,
    },
];

#[derive(Clone, Copy, Debug)]
struct Point {
    name: &'static str,
    /// `perform` calls the browser saw before the crash.
    performed: usize,
    /// Whether T2 is durable when the actor dies.
    committed: bool,
}

fn site() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("about", "About", "/about"))
                .on_click("about", vec![FakeEffect::Navigate("/about".into())]),
        )
        .page(
            FakePage::new("https://example.test/about")
                .title("About")
                .node(FakeAxSpec::link("home", "Home", "/")),
        )
}

fn analyzer(r: &Rig) -> StateAnalyzer {
    StateAnalyzer::new(
        r.rc.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    )
}

/// A second actor over a fresh context of the same run and session (what recovery does).
async fn fresh_actor(r: &Rig) -> SessionHandle {
    r.fresh_actor(None).await
}

/// Journal invariants that must hold after every drill, whatever the failpoint did
/// (the crash-drill rules and the trail invariants): no open row once recovery ran, `seq` dense per
/// session, every `succeeded` row has its transition and network epoch, and the ledger
/// counts exactly the terminal rows.
async fn assert_journal_invariants(store: &MemoryStore, r: &Rig) {
    let actions: Vec<ActionRecord> = store.list(r.run, None).await.unwrap();
    assert!(
        actions.iter().all(|a| a.status != ActionStatus::Intended),
        "intended row survived recovery: {actions:?}"
    );
    let mut per_session: BTreeMap<_, Vec<u64>> = BTreeMap::new();
    for a in &actions {
        per_session.entry(a.session).or_default().push(a.seq);
    }
    for (session, mut seqs) in per_session {
        seqs.sort_unstable();
        let dense: Vec<u64> = (1..=u64::try_from(seqs.len()).unwrap()).collect();
        assert_eq!(seqs, dense, "seq not dense for session {session}");
    }
    let transitions = store.transitions(r.run);
    let epochs = store.network_epochs(r.run);
    for a in actions.iter().filter(|a| a.status == ActionStatus::Succeeded) {
        assert_eq!(
            transitions.iter().filter(|t| t.action == a.id).count(),
            1,
            "succeeded action {} without exactly one transition",
            a.id
        );
        assert_eq!(
            epochs.iter().filter(|e| e.action == a.id).count(),
            1,
            "succeeded action {} without exactly one network epoch",
            a.id
        );
    }
    let ledger = r.stores.ledger.list(r.run).await.unwrap();
    for row in ledger {
        let succeeded = actions
            .iter()
            .filter(|a| a.key == row.key && a.status == ActionStatus::Succeeded)
            .count();
        let failed = actions
            .iter()
            .filter(|a| a.key == row.key && a.status == ActionStatus::Failed)
            .count();
        assert_eq!(
            usize::try_from(row.trusted_exercised + row.diagnostic_exercised).unwrap(),
            succeeded,
            "ledger exercised count drifted for {:?}",
            row.key
        );
        assert_eq!(usize::try_from(row.failures).unwrap(), failed);
    }
}

/// Run one click through a fresh rig with `point` set to `panic`, then recover. Returns the
/// rig for further assertions.
async fn crash_and_recover(point: Point) -> Rig {
    chaos::configure(&format!("{}=panic", point.name));
    let fake = Arc::new(FakeBackend::new(site()));
    let r = rig_with(fake.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
    let bundle = r
        .handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    let state = analyzer(&r).analyze(&bundle).await.state;
    r.store.put_state(&state).await.unwrap();
    let (p, c) = r.proposal(&bundle, "About", state.cluster);
    let key = p.key.clone();

    // the actor task panics at the failpoint: the caller sees a dead actor
    let err = r
        .handle
        .execute(r.admit(p, &c), QuiescencePolicy::default())
        .await
        .unwrap_err();
    assert!(stopped_by_dead_actor(&err), "{err:?}");
    assert_eq!(chaos::hits(point.name), 1, "{point:?}");
    chaos::configure("");

    let actions = r.actions().await;
    assert_eq!(actions.len(), 1);
    let id = actions[0].id;
    assert!(r.store.eligible_actions(r.run, None).is_empty());
    let performed: Vec<ActionKind> = r.backend.context_handles()[0].performed();
    assert_eq!(performed.len(), point.performed, "{point:?}: {performed:?}");

    let transitions = store_transitions(&r, id);
    let epochs = store_epochs(&r, id);
    let ledger = r.stores.ledger.list(r.run).await.unwrap();
    let exercised: u32 = ledger
        .iter()
        .filter(|l| l.key == key)
        .map(|l| l.trusted_exercised + l.diagnostic_exercised + l.failures)
        .sum();
    if point.committed {
        // all of T2: the row is terminal with its transition, epoch and ledger count
        assert_eq!(actions[0].status, ActionStatus::Succeeded, "{point:?}");
        assert_eq!((transitions, epochs, exercised), (1, 1, 1), "{point:?}");
    } else {
        // none of T2: the row is `intended` and nothing partial is visible
        assert_eq!(actions[0].status, ActionStatus::Intended, "{point:?}");
        assert_eq!((transitions, epochs, exercised), (0, 0, 0), "{point:?}");
    }

    // the holder stopped heartbeating: the reaper flips intended -> unknown (and nothing else)
    r.store
        .expire_session_lease(r.session, SystemClock.now() - chrono::Duration::hours(1));
    let summary = Reaper::new(r.store.clone(), r.store.clone(), ReaperConfig::default())
        .run_once()
        .await
        .unwrap();
    let handle = fresh_actor(&r).await;
    if point.committed {
        assert!(summary.actions_unknown.is_empty(), "{summary:?}");
        assert_eq!(
            ActionJournal::get(r.store.as_ref(), id).await.unwrap().status,
            ActionStatus::Succeeded
        );
        let err = handle.reconcile(id).await.unwrap_err();
        assert!(matches!(err, SessionError::NotReconcilable(_)), "{err:?}");
        assert!(r.store.eligible_actions(r.run, None).is_empty());
    } else {
        assert_eq!(summary.actions_unknown, vec![id], "{summary:?}");
        assert_eq!(
            ActionJournal::get(r.store.as_ref(), id).await.unwrap().status,
            ActionStatus::Unknown
        );
        assert!(
            r.store.eligible_actions(r.run, None).is_empty(),
            "unknown is never eligible"
        );
        // recovery: a new actor reconciles by re-observation; only then may the key be retried
        let resolution = handle.reconcile(id).await.unwrap();
        let rec = ActionJournal::get(r.store.as_ref(), id).await.unwrap();
        assert_eq!(rec.status, ActionStatus::Reconciled);
        assert_eq!(rec.reconcile_resolution, Some(resolution.resolution));
        let eligible = r.store.eligible_actions(r.run, None);
        if resolution.resolution == ReconcileResolution::NotApplied {
            assert_eq!(eligible.len(), 1);
            assert_eq!(eligible[0].key, key);
        } else {
            assert!(eligible.is_empty(), "{:?}", resolution.resolution);
        }
    }
    // no context performed anything during recovery or reconciliation
    assert_eq!(r.performed_total(), point.performed, "{point:?}");
    handle.shutdown(ShutdownReason::Completed).await.unwrap();
    r
}

fn store_transitions(r: &Rig, id: crawlx_core::ActionId) -> usize {
    r.store
        .transitions(r.run)
        .iter()
        .filter(|t| t.action == id)
        .count()
}

fn store_epochs(r: &Rig, id: crawlx_core::ActionId) -> usize {
    r.store
        .network_epochs(r.run)
        .iter()
        .filter(|e| e.action == id)
        .count()
}

async fn drill(point: Point) {
    let _serial = SERIAL.lock().await;
    chaos::reset();
    let r = crash_and_recover(point).await;
    assert_journal_invariants(&r.store, &r).await;
    chaos::reset();
}

#[tokio::test]
async fn a_crash_after_intent_before_perform_leaves_intended_and_never_performs() {
    drill(POINTS[0]).await;
}

#[tokio::test]
async fn a_crash_after_perform_before_outcome_leaves_intended_and_performs_exactly_once() {
    drill(POINTS[1]).await;
}

#[tokio::test]
async fn a_crash_during_the_outcome_transaction_leaves_all_or_nothing_of_t2() {
    drill(POINTS[2]).await;
}

#[tokio::test]
async fn a_crash_after_outcome_before_the_next_proposal_keeps_the_durable_outcome() {
    drill(POINTS[3]).await;
}

#[tokio::test(start_paused = true)]
async fn cancellation_after_intent_closes_the_row_without_dispatching() {
    let _serial = SERIAL.lock().await;
    chaos::reset();
    chaos::configure(&format!("{}=sleep(1000)", chaos::AFTER_INTENT_BEFORE_PERFORM));
    let fake = Arc::new(FakeBackend::new(site()));
    let r = rig_with(fake.clone(), fake, false, SafetyProfile::ReadOnly).await;
    let bundle = r
        .handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    let state = analyzer(&r).analyze(&bundle).await.state;
    r.store.put_state(&state).await.unwrap();
    let (proposal, context) = r.proposal(&bundle, "About", state.cluster);
    let admitted = r.admit(proposal, &context);
    let handle = r.handle.clone();
    let execution = tokio::spawn(async move { handle.execute(admitted, QuiescencePolicy::default()).await });
    for _ in 0..1_000 {
        if chaos::hits(chaos::AFTER_INTENT_BEFORE_PERFORM) > 0 {
            break;
        }
        assert!(!execution.is_finished(), "actor stopped before durable intent");
        tokio::time::advance(std::time::Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(chaos::hits(chaos::AFTER_INTENT_BEFORE_PERFORM), 1);
    assert_eq!(r.actions().await[0].status, ActionStatus::Intended);
    r.rc.cancel.cancel();
    let outcome = execution.await.unwrap();
    assert!(matches!(outcome, Err(SessionError::Cancelled)));
    assert_eq!(r.performed_total(), 0);
    let actions = r.actions().await;
    assert!(matches!(actions.as_slice(), [action] if action.status == ActionStatus::Failed));
    chaos::reset();
}

/// Re-observation lands in a different cluster with no expected-effect marker: the verdict
/// is `indeterminate`, the row is `reconciled`, the key is never eligible again (treated
/// as applied: a non-idempotent kind must not be re-run on a guess) and nothing is counted
/// as exercised or failed.
#[tokio::test]
async fn reconcile_without_markers_in_another_cluster_is_indeterminate_and_never_retried() {
    let _serial = SERIAL.lock().await;
    chaos::reset();
    chaos::configure(&format!("{}=panic", chaos::AFTER_PERFORM_BEFORE_OUTCOME));
    let fake = Arc::new(FakeBackend::new(site()));
    let r = rig_with(fake.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
    let bundle = r
        .handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    let state = analyzer(&r).analyze(&bundle).await.state;
    r.store.put_state(&state).await.unwrap();
    let (p, c) = r.proposal(&bundle, "About", state.cluster);
    assert_eq!(p.expected.navigates_to, None, "no effect marker is expected");
    let key = p.key.clone();
    let err = r
        .handle
        .execute(r.admit(p, &c), QuiescencePolicy::default())
        .await
        .unwrap_err();
    assert!(stopped_by_dead_actor(&err), "{err:?}");
    chaos::configure("");
    let id = r.actions().await[0].id;
    r.store
        .expire_session_lease(r.session, SystemClock.now() - chrono::Duration::hours(1));
    Reaper::new(r.store.clone(), r.store.clone(), ReaperConfig::default())
        .run_once()
        .await
        .unwrap();

    // the recovered session is on /about (another cluster) and the proposal expected nothing
    let handle = r.fresh_actor(Some(canonical("https://example.test/about"))).await;
    let resolution = handle.reconcile(id).await.unwrap();
    assert_eq!(resolution.resolution, ReconcileResolution::Indeterminate);
    assert_eq!(resolution.evidence["same_cluster"], false);
    assert_eq!(resolution.evidence["effect_markers"].as_array().unwrap().len(), 0);
    let rec = ActionJournal::get(r.store.as_ref(), id).await.unwrap();
    assert_eq!(rec.status, ActionStatus::Reconciled);
    assert_eq!(rec.reconcile_resolution, Some(ReconcileResolution::Indeterminate));
    assert!(
        r.store.eligible_actions(r.run, None).is_empty(),
        "indeterminate is never auto-retried"
    );
    let row = r
        .stores
        .ledger
        .list(r.run)
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.key == key)
        .unwrap();
    assert_eq!(
        (row.trusted_exercised, row.diagnostic_exercised, row.failures),
        (0, 0, 0),
        "indeterminate is neither exercised nor failed"
    );
    assert_eq!(r.performed_total(), 1, "the click ran exactly once");
    handle.shutdown(ShutdownReason::Completed).await.unwrap();
    assert_journal_invariants(&r.store, &r).await;
    chaos::reset();
}

/// Random-point kill drill: a seeded RNG picks a failpoint (or none) per iteration, each
/// iteration runs on a fresh rig so a panic never leaks state, and the journal invariants
/// are asserted every time.
#[tokio::test]
async fn random_point_kills_keep_the_journal_invariants() {
    const ITERATIONS: usize = 24;
    let _serial = SERIAL.lock().await;
    let mut rng = CrawlSeed(0x0063_6861_6f73).rng("chaos.random_kill", &[]);
    let mut picked = [0usize; 5];
    for i in 0..ITERATIONS {
        chaos::reset();
        let choice = rng.random_range(0..5usize);
        picked[choice] += 1;
        let r = if choice < POINTS.len() {
            crash_and_recover(POINTS[choice]).await
        } else {
            // `off`: the action completes normally
            chaos::configure("");
            let fake = Arc::new(FakeBackend::new(site()));
            let r = rig_with(fake.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
            let bundle = r
                .handle
                .observe(crawlx_observe::spec::after_action())
                .await
                .unwrap();
            let state = analyzer(&r).analyze(&bundle).await.state;
            r.store.put_state(&state).await.unwrap();
            let (p, c) = r.proposal(&bundle, "About", state.cluster);
            let out = r
                .handle
                .execute(r.admit(p, &c), QuiescencePolicy::default())
                .await
                .unwrap();
            assert_eq!(out.status, ActionStatus::Succeeded, "iteration {i}");
            r.handle.shutdown(ShutdownReason::Completed).await.unwrap();
            r
        };
        assert_journal_invariants(&r.store, &r).await;
    }
    assert!(
        picked.iter().all(|n| *n > 0),
        "every point and `off` should be drawn at least once: {picked:?}"
    );
    chaos::reset();
}

#[tokio::test]
async fn an_unconfigured_failpoint_is_a_no_op() {
    let _serial = SERIAL.lock().await;
    chaos::reset();
    chaos::configure("");
    chaos::hit(chaos::AFTER_INTENT_BEFORE_PERFORM).await;
    assert_eq!(chaos::hits(chaos::AFTER_INTENT_BEFORE_PERFORM), 1);
    chaos::reset();
    assert_eq!(chaos::hits(chaos::AFTER_INTENT_BEFORE_PERFORM), 0);
}

/// The actor task died at the failpoint: callers see the stopped actor with its recorded
/// cause (`ActorStopped(ActorGone)`), never a retryable or unrelated error.
fn stopped_by_dead_actor(err: &SessionError) -> bool {
    matches!(err, SessionError::ActorStopped(cause) if matches!(**cause, SessionError::ActorGone))
}
