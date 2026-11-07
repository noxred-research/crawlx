//! Scheduler behavior over the in-memory lease repo:
//! killed holders are reaped, and the round-robin barrier holds under random interleavings.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::counters::ActionStatus;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::repo::{ActionJournal, CrawlRun, CrawlSession, FrontierRepo, RunRepo, SessionStatus};
use crawlx_core::time::ManualClock;
use crawlx_core::Clock as _;
use crawlx_core::{CrawlRunId, StateClusterId, StoreError, TenantId, WorkerId};
use crawlx_scheduler::{Reaper, ReaperConfig, RunPlanner, Scheduler, TurnBarrier};
use crawlx_storage::testkit::{allow_verdict, canonical_url, crawl_run, create_crawl, proposal};
use crawlx_storage::{LeaseRepo, MemoryStore, SessionLease};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

struct Fixture {
    clock: ManualClock,
    store: Arc<MemoryStore>,
    sched: Scheduler,
    run: CrawlRun,
}

async fn fixture(roles: &[&str], runs_per_role: u8) -> Fixture {
    let clock = ManualClock::new(Utc::now());
    let store = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
    let cfg = create_crawl("https://example.test/", roles, runs_per_role);
    let run = crawl_run(TenantId::new(), cfg.clone());
    store.create(&run, None).await.unwrap();
    store
        .create_sessions(&RunPlanner::sessions(run.id, &cfg))
        .await
        .unwrap();
    let sched = Scheduler::new(store.clone());
    Fixture {
        clock,
        store,
        sched,
        run,
    }
}

fn epoch() -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: 0,
    }
}

#[tokio::test]
async fn killed_holder_is_reaped_and_its_intent_becomes_unknown() {
    let f = fixture(&[], 1).await;
    let w1 = WorkerId::new();
    let lease = f.sched.lease_next(w1).await.unwrap().expect("a session to lease");
    assert_eq!(lease.session.status, SessionStatus::Running);

    let session = lease.session.id;
    let id = f
        .store
        .propose(
            f.run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    f.store.intend(id, session, epoch()).await.unwrap();

    let reaper = Reaper::new(f.store.clone(), f.store.clone(), ReaperConfig::default());
    // a live lease is left alone
    f.clock.advance_ms(29_000);
    f.sched.heartbeat(&lease).await.unwrap();
    f.clock.advance_ms(29_000);
    let idle = reaper.run_once().await.unwrap();
    assert!(
        idle.sessions_recovering.is_empty() && idle.actions_unknown.is_empty(),
        "{idle:?}"
    );

    // the holder is killed: no more heartbeats, the TTL (30 s) passes
    f.clock.advance_ms(31_000);
    let metrics = Metrics::global();
    let expired_before = metrics.counter(names::LEASE_EXPIRED).get(&[]);
    let reap_count_before = metrics
        .histogram(names::SCHEDULER_OP_DURATION)
        .snapshot(&[("op", "reap")])
        .map_or(0, |s| s.count);
    let summary = reaper.run_once().await.unwrap();
    assert_eq!(summary.sessions_recovering, vec![session]);
    assert_eq!(summary.actions_unknown, vec![id], "flipped exactly once");
    // metrics are process-global and sibling tests reap and fence concurrently: assert lower bounds
    assert!(
        metrics.counter(names::LEASE_EXPIRED).get(&[]) > expired_before,
        "one expired lease counted"
    );
    assert!(
        metrics
            .histogram(names::SCHEDULER_OP_DURATION)
            .snapshot(&[("op", "reap")])
            .map_or(0, |s| s.count)
            > reap_count_before,
        "reap pass timed"
    );
    assert_eq!(
        ActionJournal::get(&*f.store, id).await.unwrap().status,
        ActionStatus::Unknown
    );
    assert_eq!(
        f.store.list_sessions(f.run.id).await.unwrap()[0].status,
        SessionStatus::Recovering,
        "never straight back to pending"
    );

    // the dead holder is fenced
    let fenced_before = metrics.counter(names::LEASE_FENCED).get(&[]);
    let lost = f.sched.heartbeat(&lease).await.unwrap_err();
    assert!(lost.is_lease_lost());
    assert!(f.sched.complete(&lease).await.unwrap_err().is_lease_lost());
    assert!(
        metrics.counter(names::LEASE_FENCED).get(&[]) >= fenced_before + 2,
        "one fenced count per refused holder call"
    );

    // a second worker takes over the recovering session
    let again = f
        .sched
        .lease_next(WorkerId::new())
        .await
        .unwrap()
        .expect("recovering session is leased again");
    assert_eq!(again.session.id, session);
    assert_eq!(again.session.status, SessionStatus::Recovering);
    assert!(again.fencing_token > lease.fencing_token);
    assert!(
        f.sched.lease_next(WorkerId::new()).await.unwrap().is_none(),
        "exclusive while the new lease is live"
    );
    f.sched.complete(&again).await.unwrap();
}

#[tokio::test]
async fn url_leases_expire_back_to_pending_then_fail() {
    let f = fixture(&[], 1).await;
    let url = canonical_url("https://example.test/a");
    f.store.discover(f.run.id, &url, 0, None, None).await.unwrap();
    let reaper = Reaper::new(
        f.store.clone(),
        f.store.clone(),
        ReaperConfig {
            max_url_attempts: 2,
            ..ReaperConfig::default()
        },
    );
    let w = WorkerId::new();

    assert_eq!(f.store.lease_batch(f.run.id, w, 5).await.unwrap().len(), 1);
    f.clock.advance_ms(59_000);
    assert_eq!(
        reaper.run_once().await.unwrap().urls_requeued,
        0,
        "60 s TTL not yet over"
    );
    f.clock.advance_ms(2_000);
    assert_eq!(reaper.run_once().await.unwrap().urls_requeued, 1);

    assert_eq!(f.store.lease_batch(f.run.id, w, 5).await.unwrap()[0].attempts, 2);
    f.clock.advance_ms(61_000);
    let s = reaper.run_once().await.unwrap();
    assert_eq!(
        (s.urls_requeued, s.urls_failed),
        (0, 1),
        "over max attempts the row fails"
    );
    assert_eq!(f.store.pending_count(f.run.id).await.unwrap(), 0);
}

#[tokio::test]
async fn lease_next_rotates_across_runs() {
    let clock = ManualClock::new(Utc::now());
    let store = Arc::new(MemoryStore::with_clock(Arc::new(clock)));
    let mut runs = Vec::new();
    for _ in 0..2 {
        let cfg = create_crawl("https://example.test/", &[], 1);
        let run = crawl_run(TenantId::new(), cfg.clone());
        store.create(&run, None).await.unwrap();
        store
            .create_sessions(&RunPlanner::sessions(run.id, &cfg))
            .await
            .unwrap();
        runs.push(run.id);
    }
    let sched = Scheduler::new(store.clone());
    let a = sched.lease_next(WorkerId::new()).await.unwrap().unwrap();
    let b = sched.lease_next(WorkerId::new()).await.unwrap().unwrap();
    assert_ne!(a.session.run, b.session.run, "both runs are served");
    assert!(sched.lease_next(WorkerId::new()).await.unwrap().is_none());
    // paused and terminal runs are not leased
    let cfg = create_crawl("https://example.test/", &[], 1);
    let paused = crawl_run(TenantId::new(), cfg.clone());
    store.create(&paused, None).await.unwrap();
    store
        .create_sessions(&RunPlanner::sessions(paused.id, &cfg))
        .await
        .unwrap();
    store
        .set_status(paused.id, crawlx_core::counters::RunStatus::Paused, None)
        .await
        .unwrap();
    assert!(sched.lease_next(WorkerId::new()).await.unwrap().is_none());
}

#[tokio::test]
async fn keep_alive_stops_on_cancel_and_when_fenced() {
    let f = fixture(&[], 1).await;
    let lease = f.sched.lease_next(WorkerId::new()).await.unwrap().unwrap();

    let cancel = CancellationToken::new();
    let h = f
        .sched
        .keep_alive(lease.clone(), Duration::from_millis(10), cancel.clone());
    tokio::time::sleep(Duration::from_millis(40)).await;
    cancel.cancel();
    assert!(h.await.unwrap().is_ok());

    let fenced_before = Metrics::global().counter(names::LEASE_FENCED).get(&[]);
    let h = f
        .sched
        .keep_alive(lease.clone(), Duration::from_millis(10), CancellationToken::new());
    f.sched.complete(&lease).await.unwrap();
    let err = tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .expect("heartbeat loop ends")
        .unwrap()
        .unwrap_err();
    assert!(err.is_lease_lost());
    assert!(
        Metrics::global().counter(names::LEASE_FENCED).get(&[]) > fenced_before,
        "fenced heartbeat counted"
    );
}

#[tokio::test]
async fn reaper_task_reaps_on_its_interval() {
    let f = fixture(&[], 1).await;
    let lease = f.sched.lease_next(WorkerId::new()).await.unwrap().unwrap();
    f.clock.advance_ms(31_000);
    let reaper = Arc::new(Reaper::new(
        f.store.clone(),
        f.store.clone(),
        ReaperConfig {
            interval: Duration::from_millis(10),
            ..ReaperConfig::default()
        },
    ));
    let cancel = CancellationToken::new();
    let handle = reaper.spawn(cancel.clone());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let st = f.store.list_sessions(f.run.id).await.unwrap()[0].status;
        if st == SessionStatus::Recovering {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "reaper did not run");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    cancel.cancel();
    handle.await.unwrap();
    assert!(f.sched.heartbeat(&lease).await.unwrap_err().is_lease_lost());
}

#[derive(Clone, Debug)]
enum Op {
    Claim(u8),
    Finish(u8, u8),
    Heartbeat(u8),
    Kill(u8),
    Tick(u16),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => any::<u8>().prop_map(Op::Claim),
        3 => (any::<u8>(), 0u8..3).prop_map(|(i, s)| Op::Finish(i, s)),
        1 => any::<u8>().prop_map(Op::Heartbeat),
        2 => any::<u8>().prop_map(Op::Kill),
        2 => (1u16..40_000).prop_map(Op::Tick),
    ]
}

fn snapshot(rt: &tokio::runtime::Runtime, store: &MemoryStore, run: CrawlRunId) -> Vec<CrawlSession> {
    rt.block_on(store.list_sessions(run)).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Turn n+1 is never granted before every turn-n slot is terminal, whatever the interleaving
    /// of claims, completions, killed holders and clock jumps; and the lowest eligible slot is
    /// always grantable (no spurious blocking). After the chaos, everything drains.
    #[test]
    fn barrier_never_grants_a_slot_before_all_lower_slots_are_terminal(
        n_roles in 1usize..4,
        runs in 1u8..4,
        ops in proptest::collection::vec(op_strategy(), 1..80),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let names: Vec<String> = (0..n_roles).map(|i| format!("r{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let clock = ManualClock::new(Utc::now());
        let store = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
        let cfg = create_crawl("https://example.test/", &refs, runs);
        let run = crawl_run(TenantId::new(), cfg.clone());
        rt.block_on(async {
            store.create(&run, None).await.unwrap();
            store.create_sessions(&RunPlanner::sessions(run.id, &cfg)).await.unwrap();
        });
        let barrier = TurnBarrier::new(false);
        let mut held: Vec<SessionLease> = Vec::new();

        for op in ops {
            match op {
                Op::Claim(w) => {
                    let before = snapshot(&rt, &store, run.id);
                    let live: BTreeSet<_> = held.iter().map(|l| l.session.id).collect();
                    let lowest = before.iter().filter(|s| !s.status.is_terminal()).min_by_key(|s| s.schedule_slot).cloned();
                    let expect_grant = lowest.as_ref().is_some_and(|s| {
                        matches!(s.status, SessionStatus::Pending) || (s.status == SessionStatus::Recovering && !live.contains(&s.id))
                    });
                    let got = rt.block_on(store.claim_session(run.id, WorkerId(uuid::Uuid::from_u128(u128::from(w))), false)).unwrap();
                    prop_assert_eq!(got.is_some(), expect_grant);
                    if let Some(l) = got {
                        let slot = l.session.schedule_slot;
                        prop_assert!(before.iter().filter(|s| s.schedule_slot < slot).all(|s| s.status.is_terminal()),
                            "slot {} granted before every lower slot was terminal: {:?}", slot, before);
                        prop_assert!(barrier.grantable(slot, before.iter().map(|s| (s.schedule_slot, s.status))));
                        prop_assert_eq!(Some(l.session.id), lowest.map(|s| s.id));
                        held.retain(|h| h.session.id != l.session.id); // a re-claim fences the previous holder
                        held.push(l);
                    }
                }
                Op::Finish(i, how) => {
                    if !held.is_empty() {
                        let idx = usize::from(i) % held.len();
                        let to = [SessionStatus::Completed, SessionStatus::Failed, SessionStatus::Cancelled][usize::from(how)];
                        let res = rt.block_on(store.release(&held[idx], to));
                        match res {
                            Ok(()) => { held.remove(idx); }
                            Err(StoreError::LeaseLost) => { held.remove(idx); }
                            Err(e) => prop_assert!(false, "unexpected {e:?}"),
                        }
                    }
                }
                Op::Heartbeat(i) => {
                    if !held.is_empty() {
                        let idx = usize::from(i) % held.len();
                        if rt.block_on(store.heartbeat(&held[idx])).is_err() {
                            held.remove(idx);
                        }
                    }
                }
                Op::Kill(i) => {
                    // the holder stops heartbeating; the lease expires and the reaper runs
                    if !held.is_empty() {
                        let idx = usize::from(i) % held.len();
                        let killed = held.remove(idx);
                        store.expire_session_lease(killed.session.id, clock.now() - chrono::Duration::seconds(1));
                        rt.block_on(store.reap(clock.now())).unwrap();
                    }
                }
                Op::Tick(ms) => {
                    clock.advance_ms(i64::from(ms));
                    rt.block_on(store.reap(clock.now())).unwrap();
                    // live holders whose lease just expired were reaped: forget them
                    let after = snapshot(&rt, &store, run.id);
                    held.retain(|h| after.iter().any(|s| s.id == h.session.id && matches!(s.status, SessionStatus::Running | SessionStatus::Recovering)
                        && rt.block_on(store.heartbeat(h)).is_ok()));
                }
            }
        }

        // drain: every remaining slot can be granted in order and completed
        for l in held.drain(..) {
            let _ = rt.block_on(store.release(&l, SessionStatus::Completed));
        }
        clock.advance_ms(120_000);
        rt.block_on(store.reap(clock.now())).unwrap();
        for _ in 0..(n_roles * usize::from(runs) + 1) {
            if let Some(l) = rt.block_on(store.claim_session(run.id, WorkerId::new(), false)).unwrap() {
                rt.block_on(store.release(&l, SessionStatus::Completed)).unwrap();
            }
        }
        let end = snapshot(&rt, &store, run.id);
        prop_assert!(end.iter().all(|s| s.status.is_terminal()), "everything drains: {:?}", end);
    }
}
