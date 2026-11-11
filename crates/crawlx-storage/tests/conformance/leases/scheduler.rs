#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The scheduler's view of leases: workers racing for the next slot in turn order, and the
//! stale-lease reaper reclaiming dead holders within its service level.
//!
//! The scheduler crate sits above this one, so the two small pieces of it these cases need
//! (leasing the next session over the active runs, and one reaper pass) are written out here
//! against the repository traits, with the semantics the scheduler gives them.

use super::support::{epoch, lease_scale, open_sibling, tenant};
use async_trait::async_trait;
use chrono::Duration;
use crawlx_core::counters::ActionStatus;
use crawlx_core::repo::{ActionJournal, RunRepo, SessionStatus};
use crawlx_core::{CrawlRunId, SessionId, StateClusterId, StoreError, Timestamp, WorkerId};
use crawlx_storage::leases::FrontierReap;
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal};
use crawlx_storage::{ActiveRun, LeaseRepo, ReapReport, SessionLease, Store, StoreConfig};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

conformance! { databases:
    stale_session_leases_are_reclaimed_within_the_slo_for_99_9_percent,
    workers_lease_in_turn_order_and_a_killed_holder_is_reaped,
}

/// Lease the next eligible session over all active runs, trying the runs round-robin from a
/// rotating cursor so a busy run cannot starve the others; `scheduler.admission` set to
/// `drain` or `frozen` grants nothing.
async fn lease_next(
    leases: &dyn LeaseRepo,
    cursor: &AtomicUsize,
    worker: WorkerId,
) -> Result<Option<SessionLease>, StoreError> {
    if !leases.admission().await?.grants_leases() {
        return Ok(None);
    }
    let runs = leases.active_runs().await?;
    if runs.is_empty() {
        return Ok(None);
    }
    let start = cursor.fetch_add(1, Ordering::Relaxed) % runs.len();
    for offset in 0..runs.len() {
        let run = runs[(start + offset) % runs.len()];
        if let Some(lease) = leases
            .claim_session(run.run, worker, run.parallel_roles_allowed)
            .await?
        {
            return Ok(Some(lease));
        }
    }
    Ok(None)
}

/// What one reaper pass changed.
#[derive(Default)]
struct Swept {
    sessions_recovering: Vec<SessionId>,
    actions_unknown: Vec<crawlx_core::ActionId>,
}

/// One reaper pass on the clock of `leases`: expired session leases become `recovering` and
/// their `intended` actions `unknown`, actions of expired sessions the first sweep did not
/// move are flipped too, and expired URL leases return to `pending` (failed after 5
/// attempts).
async fn sweep(leases: &dyn LeaseRepo, journal: &dyn ActionJournal) -> Result<Swept, StoreError> {
    let now = leases.now().await?;
    let sessions = leases.reap(now).await?;
    let swept = journal.mark_unknown(now).await?;
    leases.reap_frontier(now, 5).await?;
    let mut actions_unknown = sessions.actions_unknown;
    actions_unknown.extend(swept);
    Ok(Swept {
        sessions_recovering: sessions.sessions_recovering,
        actions_unknown,
    })
}

/// A `LeaseRepo` whose clock runs `secs` ahead of the database, delegating everything else.
struct Shifted<S> {
    inner: S,
    secs: i64,
}

#[async_trait]
impl<S: LeaseRepo> LeaseRepo for Shifted<S> {
    async fn now(&self) -> Result<Timestamp, StoreError> {
        Ok(self.inner.now().await? + Duration::seconds(self.secs))
    }
    async fn active_runs(&self) -> Result<Vec<ActiveRun>, StoreError> {
        self.inner.active_runs().await
    }
    async fn claim_session(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError> {
        self.inner
            .claim_session(run, worker, parallel_roles_allowed)
            .await
    }
    async fn heartbeat(&self, lease: &SessionLease) -> Result<Timestamp, StoreError> {
        self.inner.heartbeat(lease).await
    }
    async fn release(&self, lease: &SessionLease, to: SessionStatus) -> Result<(), StoreError> {
        self.inner.release(lease, to).await
    }
    async fn reap(&self, now: Timestamp) -> Result<ReapReport, StoreError> {
        self.inner.reap(now).await
    }
    async fn reap_frontier(&self, now: Timestamp, max_attempts: u16) -> Result<FrontierReap, StoreError> {
        self.inner.reap_frontier(now, max_attempts).await
    }
    async fn heartbeat_frontier(
        &self,
        worker: WorkerId,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError> {
        self.inner.heartbeat_frontier(worker, leases).await
    }
    fn url_batch_ttl(&self) -> std::time::Duration {
        self.inner.url_batch_ttl()
    }
}

/// Value at quantile `q` of an ascending slice (nearest rank).
fn quantile(sorted: &[f64], q: f64) -> f64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // `q` is in [0, 1]
    let idx = ((q * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
    sorted[idx]
}

db_case! {
    /// Crash reclaim: `CRAWLX_LEASE_CLAIMERS` workers claim sessions of `CRAWLX_LEASE_ROWS / 100`
    /// runs (100 sessions each), or ONE run when `CRAWLX_LEASE_SINGLE_RUN=1`, and "die" with every
    /// lease (no heartbeat, no release) until `CRAWLX_LEASE_ROWS` leases have been granted. A
    /// reaper sweeps every 500 ms the whole time, as in production, moving each expired lease's
    /// session to `recovering`; a reclaimed session is claimable again, so one session may be
    /// leased and reaped more than once and the leases and reaps of a session alternate strictly.
    /// The statistic is the delay between a lease's `expires_at` and the sweep that reclaimed it,
    /// asserted at the reclaim SLO (99.9 % within 120 s) and printed with p50/p99/p99.9/max.
    ///
    /// The single-run variant stresses the claim index with a deep live-lease prefix, including
    /// live recovering leases after the first sweep. Its oversized session set is a storage
    /// stress fixture, not a normal `CreateCrawl` configuration.
    async fn stale_session_leases_are_reclaimed_within_the_slo_for_99_9_percent<B>(rig, primary) {
        let (claimers, rows) = lease_scale();
        let ttl = std::time::Duration::from_secs(if rows > 1_000 { 60 } else { 5 });
        let database = open_sibling(
            rig,
            StoreConfig {
                max_connections: 12,
                session_ttl: ttl,
                ..StoreConfig::default()
            },
        )
        .await;
        let store: Store<B> = B::store_of(&database).clone();
        let tenant = tenant(rig).await;
        let single_run = std::env::var("CRAWLX_LEASE_SINGLE_RUN").is_ok_and(|v| v == "1");
        let per_run = if single_run { rows } else { rows.min(100) };
        let n_runs = rows.div_ceil(per_run);
        let roles = per_run.min(10);
        let per_role = per_run.div_ceil(roles);
        let role_names: Vec<String> = (0..roles).map(|r| format!("r{r}")).collect();
        let role_refs: Vec<&str> = role_names.iter().map(String::as_str).collect();
        let started = std::time::Instant::now();
        let mut run_ids = Vec::with_capacity(n_runs);
        let mut lanes = tokio::task::JoinSet::new();
        for _ in 0..n_runs {
            let mut cfg = create_crawl(
                "https://example.test/",
                &role_refs,
                u8::try_from(per_role.min(usize::from(u8::MAX))).unwrap(),
            );
            cfg.cross_principal_attribution = false; // barrier lifted: every slot is grantable at once
            assert!(cfg.parallel_roles_allowed());
            let run = crawl_run(tenant, cfg);
            run_ids.push(run.id);
            let sessions: Vec<_> = crawlx_storage::testkit::sessions(
                run.id,
                u16::try_from(roles).unwrap(),
                u16::try_from(per_role).unwrap(),
            )
            .into_iter()
            .take(per_run)
            .collect();
            let store = primary.clone();
            lanes.spawn(async move {
                store.create(&run, None).await.unwrap();
                store.create_sessions(&sessions).await.unwrap();
            });
            if lanes.len() >= 16 {
                lanes.join_next().await.unwrap().unwrap();
            }
        }
        while let Some(r) = lanes.join_next().await {
            r.unwrap();
        }
        let total_sessions = n_runs * per_run;
        let created = started.elapsed();

        // reaper: sweeps every 500 ms from before the first claim until every lease is reaped
        let granted = Arc::new(AtomicUsize::new(0));
        let claimers_done = Arc::new(AtomicBool::new(false));
        let sweeper = {
            let store = store.clone();
            let granted = granted.clone();
            let claimers_done = claimers_done.clone();
            tokio::spawn(async move {
                let mut reaps: Vec<(Timestamp, SessionId)> = Vec::new();
                let mut passes = 0u32;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1800);
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let summary = sweep(&store, &store).await.unwrap();
                    let swept_at = LeaseRepo::now(&store).await.unwrap();
                    passes += 1;
                    reaps.extend(summary.sessions_recovering.into_iter().map(|id| (swept_at, id)));
                    let done = claimers_done.load(Ordering::SeqCst)
                        && reaps.len() >= granted.load(Ordering::SeqCst);
                    if done {
                        break;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "reaped {} of {} leases",
                        reaps.len(),
                        granted.load(Ordering::SeqCst)
                    );
                }
                (reaps, passes)
            })
        };

        // claim phase: the claimers lease round-robin over the runs until `rows` leases were
        // granted, never releasing one
        let started = std::time::Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        let run_ids = Arc::new(run_ids);
        for k in 0..claimers {
            let store = store.clone();
            let run_ids = run_ids.clone();
            let granted = granted.clone();
            tasks.spawn(async move {
                let worker = WorkerId::new();
                let mut mine = Vec::new();
                let mut claim_latencies_ms = Vec::new();
                let mut next = k % run_ids.len();
                let mut misses = 0usize;
                while granted.load(Ordering::SeqCst) < rows {
                    let run = run_ids[next];
                    next = (next + 1) % run_ids.len();
                    let claim_started = std::time::Instant::now();
                    let result = store.claim_session(run, worker, true).await.unwrap();
                    claim_latencies_ms.push(claim_started.elapsed().as_secs_f64() * 1000.0);
                    match result {
                        Some(lease) => {
                            misses = 0;
                            granted.fetch_add(1, Ordering::SeqCst);
                            mine.push((lease.session.id, lease.fencing_token, lease.expires_at));
                        }
                        None => {
                            misses += 1;
                            // every session of every run holds a live lease: wait for the reaper
                            if misses >= run_ids.len() {
                                misses = 0;
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
                (mine, claim_latencies_ms)
            });
        }
        let mut leases: BTreeMap<SessionId, Vec<(i64, Timestamp)>> = BTreeMap::new();
        let mut total = 0usize;
        let mut claim_latencies_ms = Vec::new();
        while let Some(mine) = tasks.join_next().await {
            let (mine, timings) = mine.unwrap();
            claim_latencies_ms.extend(timings);
            for (id, token, expires_at) in mine {
                total += 1;
                leases.entry(id).or_default().push((token, expires_at));
            }
        }
        claimers_done.store(true, Ordering::SeqCst);
        let claimed = started.elapsed();
        assert!(total >= rows, "{total} leases granted");
        let (mut reaps, passes) = sweeper.await.unwrap();
        assert_eq!(reaps.len(), total, "every lease was reaped exactly once");

        // pair the k-th reap of a session with its k-th lease (they alternate strictly)
        reaps.sort_by_key(|a| a.0);
        let mut reaps_by_session: BTreeMap<SessionId, Vec<Timestamp>> = BTreeMap::new();
        for (at, id) in reaps {
            reaps_by_session.entry(id).or_default().push(at);
        }
        let mut latencies_s: Vec<f64> = Vec::with_capacity(total);
        let mut sessions_leased_twice = 0usize;
        let distinct = leases.len();
        for (id, mut ls) in leases {
            ls.sort_by_key(|(token, _)| *token);
            let rs = reaps_by_session.remove(&id).unwrap_or_default();
            assert_eq!(rs.len(), ls.len(), "session {id}: leases and reaps pair up");
            if ls.len() > 1 {
                sessions_leased_twice += 1;
            }
            for ((_, expires_at), swept_at) in ls.into_iter().zip(rs) {
                #[allow(clippy::cast_precision_loss)] // a latency in milliseconds is far below 2^53
                latencies_s.push((swept_at - expires_at).num_milliseconds() as f64 / 1000.0);
            }
        }
        assert!(reaps_by_session.is_empty(), "reaps of sessions never leased here");
        latencies_s.sort_by(f64::total_cmp);
        claim_latencies_ms.sort_by(f64::total_cmp);
        eprintln!(
            "claim latency: {n_runs} runs, {} calls, p50 {:.3} ms, p99 {:.3} ms, p99.9 {:.3} ms, max {:.3} ms",
            claim_latencies_ms.len(),
            quantile(&claim_latencies_ms, 0.5),
            quantile(&claim_latencies_ms, 0.99),
            quantile(&claim_latencies_ms, 0.999),
            claim_latencies_ms[claim_latencies_ms.len() - 1],
        );
        let within_slo = latencies_s.iter().filter(|l| **l <= 120.0).count();
        #[allow(clippy::cast_precision_loss)] // lease counts are far below 2^53
        let share = within_slo as f64 / total as f64;
        #[allow(clippy::cast_precision_loss)] // lease counts are far below 2^53
        let per_claim_ms = claimed.as_secs_f64() * 1000.0 / total as f64;
        eprintln!(
            "reclaim scale: {claimers} claimers, {rows} sessions, {total} leases ({sessions_leased_twice} sessions \
             re-leased after a reclaim), ttl {ttl:?}: sessions created in {created:?}, claim phase {claimed:?} \
             ({per_claim_ms:.3} ms per claim), {passes} reaper passes; reclaim latency after expiry p50 {:.3} s, \
             p99 {:.3} s, p99.9 {:.3} s, max {:.3} s; within 120 s: {within_slo}/{total} = {:.4} %",
            quantile(&latencies_s, 0.5),
            quantile(&latencies_s, 0.99),
            quantile(&latencies_s, 0.999),
            latencies_s[latencies_s.len() - 1],
            share * 100.0
        );
        assert!(share >= 0.999, "{share}");
        assert!(latencies_s[0] >= 0.0, "a lease was reclaimed before it expired");
        // every leased session is `recovering` (never back to `pending`, never left `running`),
        // so a resumed holder is fenced out; sessions the claimers never reached stay `pending`
        let mut recovering = 0usize;
        let mut seen = 0usize;
        for run in run_ids.iter() {
            for s in RunRepo::list_sessions(&store, *run).await.unwrap() {
                seen += 1;
                match s.status {
                    SessionStatus::Recovering => recovering += 1,
                    SessionStatus::Pending => {}
                    other => panic!("session {} left {other:?}", s.id),
                }
            }
        }
        assert_eq!(seen, total_sessions);
        assert_eq!(recovering, distinct);
        database.close().await;
    }
}

db_case! {
    async fn workers_lease_in_turn_order_and_a_killed_holder_is_reaped<B>(rig, store) {
        let tenant = tenant(rig).await;
        let cfg = create_crawl("https://example.test/", &["a", "b", "c"], 2);
        let run = crawl_run(tenant, cfg);
        store.create(&run, None).await.unwrap();
        store
            .create_sessions(&crawlx_storage::testkit::sessions(run.id, 3, 2))
            .await
            .unwrap();

        let cursor = Arc::new(AtomicUsize::new(0));
        let mut order = Vec::new();
        let mut killed: Option<(SessionLease, crawlx_core::ActionId)> = None;
        for round in 0..6 {
            // `CRAWLX_LEASE_CLAIMERS` workers race for the next slot: exactly one wins, and it
            // is the next slot in order
            let mut tasks = Vec::new();
            for _ in 0..lease_scale().0 {
                let store = store.clone();
                let cursor = cursor.clone();
                tasks.push(tokio::spawn(async move {
                    lease_next(&store, &cursor, WorkerId::new()).await.unwrap()
                }));
            }
            let mut winners = Vec::new();
            for task in tasks {
                if let Some(lease) = task.await.unwrap() {
                    winners.push(lease);
                }
            }
            assert_eq!(winners.len(), 1, "round {round}");
            let lease = winners.remove(0);
            order.push(lease.session.schedule_slot);
            if round == 2 {
                // this holder dies after journaling an intent
                let id = store
                    .propose(
                        run.id,
                        lease.session.id,
                        &proposal("a", StateClusterId::new(), 1),
                        &allow_verdict(),
                    )
                    .await
                    .unwrap();
                store.intend(id, lease.session.id, epoch(1, 1, 0)).await.unwrap();
                let held = lease.clone();
                killed = Some((lease, id));
                let live = sweep(store, store).await.unwrap();
                assert!(
                    live.sessions_recovering.is_empty(),
                    "the lease is still live, nothing to reap"
                );
                // ten minutes pass on the database clock: the 30 s lease is long expired
                let later = Shifted {
                    inner: store.clone(),
                    secs: 600,
                };
                let swept = sweep(&later, store).await.unwrap();
                assert_eq!(swept.sessions_recovering, vec![held.session.id]);
                assert_eq!(swept.actions_unknown, vec![id]);
                assert!(matches!(
                    store.heartbeat(&held).await,
                    Err(StoreError::LeaseLost)
                ));
                // the recovering session is leased again (same slot), then completed
                let again = lease_next(store, &cursor, WorkerId::new())
                    .await
                    .unwrap()
                    .expect("recovering session re-leased");
                assert_eq!(again.session.schedule_slot, held.session.schedule_slot);
                assert_eq!(again.session.status, SessionStatus::Recovering);
                store.release(&again, SessionStatus::Completed).await.unwrap();
            } else {
                store.release(&lease, SessionStatus::Completed).await.unwrap();
            }
        }
        assert_eq!(
            order,
            vec![0, 1, 2, 3, 4, 5],
            "slots are granted strictly in schedule order"
        );
        let (_, id) = killed.unwrap();
        assert_eq!(
            ActionJournal::get(store, id).await.unwrap().status,
            ActionStatus::Unknown
        );
        assert!(lease_next(store, &cursor, WorkerId::new()).await.unwrap().is_none());
    }
}
