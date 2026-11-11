#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! URL leases: discovery, exclusive batch and exact claims under fencing tokens, expiry and
//! the reaper, renewal by heartbeat, and the counts that derive from the rows.

use super::support::{lease_scale, new_run, open_sibling, tenant, Raw, V};
use crate::rig::Rig;
use chrono::Duration;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{DiscoveryOutcome, FrontierRepo, FrontierStateCounts, FrontierStatus, RunRepo};
use crawlx_core::{CrawlRunId, StoreError, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run};
use crawlx_storage::{LeaseRepo, Store, StoreConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

conformance! { databases:
    discover_dedupes_and_records_denials,
    frontier_lease_is_exclusive_across_claimers,
    exact_frontier_claim_is_exclusive_and_leaves_other_rows_untouched,
    exact_frontier_claim_refuses_ineligible_rows_foreign_runs_and_non_live_runs,
    frontier_reap_requeues_then_fails_after_max_attempts,
    a_frontier_lease_is_renewed_and_finished_only_under_its_fencing_token,
}

conformance! { all:
    a_leased_row_is_open_and_a_released_row_is_pending_again,
    state_counts_tally_the_frontier_rows_of_one_run,
}

db_case! {
    async fn discover_dedupes_and_records_denials<B>(rig, store) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let u = canonical_url("https://example.test/a");
        let (o1, id1) = store.discover(run.id, &u, 0, None, None).await.unwrap();
        assert_eq!((o1, id1.is_some()), (DiscoveryOutcome::Admitted, true));
        let (o2, id2) = store.discover(run.id, &u, 1, id1, None).await.unwrap();
        assert_eq!((o2, id2), (DiscoveryOutcome::Duplicate, None));
        let blocked = canonical_url("https://example.test/admin");
        let (o3, _) = store
            .discover(
                run.id,
                &blocked,
                1,
                id1,
                Some((FrontierStatus::PolicyBlocked, "deny-list".to_owned())),
            )
            .await
            .unwrap();
        assert_eq!(o3, DiscoveryOutcome::PolicyBlocked);
        let (o4, _) = store
            .discover(
                run.id,
                &canonical_url("https://example.test/r"),
                1,
                id1,
                Some((FrontierStatus::RobotsBlocked, "robots".to_owned())),
            )
            .await
            .unwrap();
        assert_eq!(o4, DiscoveryOutcome::RobotsBlocked);
        assert!(store
            .discover(
                run.id,
                &canonical_url("https://example.test/x"),
                1,
                None,
                Some((FrontierStatus::Failed, String::new()))
            )
            .await
            .is_err());
        assert_eq!(store.pending_count(run.id).await.unwrap(), 1);
        let listed = FrontierRepo::list(store, run.id).await.unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].url, u, "the canonical URL round-trips");
        assert_eq!(listed[1].status, FrontierStatus::PolicyBlocked);
        assert_eq!(listed[1].denial_reason.as_deref(), Some("deny-list"));

        // concurrent discovery of the same URL admits exactly once
        let shared = canonical_url("https://example.test/shared");
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let shared = shared.clone();
            let run = run.id;
            tasks.push(tokio::spawn(async move {
                store.discover(run, &shared, 1, None, None).await.unwrap().0
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            if task.await.unwrap() == DiscoveryOutcome::Admitted {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 1);
    }
}

db_case! {
    /// One pool per claimer, on the same database: the exclusivity comes from the claim
    /// statement, never from one process's connection pool or write gate.
    async fn frontier_lease_is_exclusive_across_claimers<B>(rig, store) {
        let (claimers, rows) = lease_scale();
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        // discovery in 16 lanes: 100k single-row inserts would otherwise dominate the case
        let started = std::time::Instant::now();
        let mut lanes = tokio::task::JoinSet::new();
        for lane in 0..16usize {
            let store = store.clone();
            let run = run.id;
            lanes.spawn(async move {
                for i in (lane..rows).step_by(16) {
                    store
                        .discover(
                            run,
                            &canonical_url(&format!("https://example.test/p{i}")),
                            1,
                            None,
                            None,
                        )
                        .await
                        .unwrap();
                }
            });
        }
        while let Some(r) = lanes.join_next().await {
            r.unwrap();
        }
        let discovered = started.elapsed();
        let mut databases = Vec::with_capacity(claimers);
        for _ in 0..claimers {
            databases.push(
                open_sibling(
                    rig,
                    StoreConfig {
                        max_connections: 2,
                        ..StoreConfig::default()
                    },
                )
                .await,
            );
        }
        let started = std::time::Instant::now();
        let mut tasks = Vec::new();
        for database in &databases {
            let claimer: Store<B> = B::store_of(database).clone();
            let run = run.id;
            tasks.push(tokio::spawn(async move {
                let worker = WorkerId::new();
                let mut mine = Vec::new();
                let mut calls = 0u64;
                loop {
                    let batch = claimer.lease_batch_fenced(run, worker, 4).await.unwrap();
                    calls += 1;
                    if batch.is_empty() {
                        break;
                    }
                    mine.extend(batch.into_iter().map(|(e, t)| (e.id, t)));
                }
                (mine, calls)
            }));
        }
        let mut all = Vec::new();
        let mut calls = 0u64;
        for task in tasks {
            let (mine, n) = task.await.unwrap();
            all.extend(mine);
            calls += n;
        }
        let leased = started.elapsed();
        for database in databases {
            database.close().await;
        }
        let ids: BTreeSet<i64> = all.iter().map(|(i, _)| *i).collect();
        let tokens: BTreeSet<i64> = all.iter().map(|(_, t)| *t).collect();
        let duplicates = all.len() - ids.len();
        #[allow(clippy::cast_precision_loss)] // call counts are far below 2^53
        let per_call_ms = leased.as_secs_f64() * 1000.0 / calls as f64;
        eprintln!(
            "lease scale: {claimers} claimers, {rows} rows: discovered in {discovered:?}, leased in {leased:?} \
             ({calls} lease calls, {per_call_ms:.3} ms per call), duplicates = {duplicates}"
        );
        assert_eq!(all.len(), rows, "every row leased");
        assert_eq!(duplicates, 0, "no row leased twice");
        assert_eq!(tokens.len(), rows, "fencing tokens are unique");

        // fenced completion: a stale token cannot complete a re-leased row
        let (id, token) = all[0];
        assert!(matches!(
            store
                .complete_fenced(id, token + 10_000, FrontierStatus::Succeeded, None)
                .await,
            Err(StoreError::LeaseLost)
        ));
        store
            .complete_fenced(id, token, FrontierStatus::Succeeded, None)
            .await
            .unwrap();
        assert!(matches!(
            store.complete(id, FrontierStatus::Failed, None).await,
            Err(StoreError::IllegalTransition { .. })
        ));
    }
}

/// The columns an exact claim must leave alone on a row it refuses, as one comparable text.
async fn frontier_row(raw: &Raw<'_>, id: i64) -> String {
    let row = raw
        .one(
            "SELECT status, attempts, lease_owner, lease_expires_at, fencing_token, next_attempt_at, \
             finished_at, error_code, denial_reason, depth FROM url_frontier WHERE frontier_id = $1",
            &[V::I64(id)],
        )
        .await;
    format!(
        "{} {} {:?} {:?} {:?} {} {:?} {:?} {:?} {}",
        row.text("status"),
        row.i16("attempts"),
        row.opt_uuid("lease_owner"),
        row.opt_ts("lease_expires_at"),
        row.opt_i64("fencing_token"),
        row.ts("next_attempt_at"),
        row.opt_ts("finished_at"),
        row.opt_text("error_code"),
        row.opt_text("denial_reason"),
        row.i16("depth"),
    )
}

async fn assert_exact_claim_refused<S: FrontierRepo>(raw: &Raw<'_>, store: &S, run: CrawlRunId, id: i64) {
    let before = frontier_row(raw, id).await;
    assert!(store
        .lease_one_fenced(run, WorkerId::new(), id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(frontier_row(raw, id).await, before);
}

db_case! {
    async fn exact_frontier_claim_is_exclusive_and_leaves_other_rows_untouched<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let mut ids = Vec::new();
        for path in ["requested", "untouched"] {
            ids.push(
                store
                    .discover(
                        run.id,
                        &canonical_url(&format!("https://example.test/{path}")),
                        0,
                        None,
                        None,
                    )
                    .await
                    .unwrap()
                    .1
                    .unwrap(),
            );
        }
        let before = frontier_row(&raw, ids[1]).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            let run = run.id;
            let id = ids[0];
            tasks.spawn(async move {
                let worker = WorkerId::new();
                barrier.wait().await;
                (worker, store.lease_one_fenced(run, worker, id).await.unwrap())
            });
        }
        barrier.wait().await;
        let mut winners = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let (worker, claim) = result.unwrap();
            if let Some(claim) = claim {
                winners.push((worker, claim));
            }
        }
        assert_eq!(winners.len(), 1);
        let (worker, (entry, token)) = &winners[0];
        assert_eq!(
            (entry.id, entry.status, entry.attempts),
            (ids[0], FrontierStatus::Leased, 1)
        );
        let held = raw
            .one(
                "SELECT lease_owner, fencing_token, lease_expires_at FROM url_frontier WHERE frontier_id = $1",
                &[V::I64(entry.id)],
            )
            .await;
        assert_eq!(held.opt_uuid("lease_owner"), Some(worker.0));
        assert_eq!(held.opt_i64("fencing_token"), Some(*token));
        assert!(held.opt_ts("lease_expires_at").unwrap() > raw.now().await);
        assert_eq!(frontier_row(&raw, ids[1]).await, before);
    }
}

db_case! {
    async fn exact_frontier_claim_refuses_ineligible_rows_foreign_runs_and_non_live_runs<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let id = store
            .discover(
                run.id,
                &canonical_url("https://example.test/requested"),
                0,
                None,
                None,
            )
            .await
            .unwrap()
            .1
            .unwrap();
        for status in [
            FrontierStatus::Leased,
            FrontierStatus::Succeeded,
            FrontierStatus::Failed,
            FrontierStatus::Abandoned,
            FrontierStatus::Unreachable,
            FrontierStatus::PolicyBlocked,
            FrontierStatus::RobotsBlocked,
        ] {
            raw.run(
                "UPDATE url_frontier SET status = $1, attempts = 3, fencing_token = 43 WHERE frontier_id = $2",
                &[V::Text(status.as_str()), V::I64(id)],
            )
            .await;
            assert_exact_claim_refused(&raw, store, run.id, id).await;
        }
        let day_ahead = raw.now().await + Duration::days(1);
        raw.run(
            "UPDATE url_frontier SET status = 'pending', next_attempt_at = $1 WHERE frontier_id = $2",
            &[V::Ts(day_ahead), V::I64(id)],
        )
        .await;
        assert_exact_claim_refused(&raw, store, run.id, id).await;
        let second_ago = raw.now().await - Duration::seconds(1);
        raw.run(
            "UPDATE url_frontier SET next_attempt_at = $1 WHERE frontier_id = $2",
            &[V::Ts(second_ago), V::I64(id)],
        )
        .await;
        let other = super::support::tenant(rig).await;
        let foreign = crawl_run(other, run.config.clone());
        store.create(&foreign, None).await.unwrap();
        assert_exact_claim_refused(&raw, store, foreign.id, id).await;
        assert!(store
            .lease_one_fenced(run.id, WorkerId::new(), i64::MAX)
            .await
            .unwrap()
            .is_none());
        store.set_status(run.id, RunStatus::Paused, None).await.unwrap();
        assert_exact_claim_refused(&raw, store, run.id, id).await;
        store.set_status(run.id, RunStatus::Running, None).await.unwrap();
        for column in ["deadline_at", "cancel_requested_at", "purge_requested_at"] {
            let second_ago = raw.now().await - Duration::seconds(1);
            raw.run(
                &format!("UPDATE crawl_runs SET {column} = $1 WHERE run_id = $2"),
                &[V::Ts(second_ago), V::Uuid(run.id.0)],
            )
            .await;
            assert_exact_claim_refused(&raw, store, run.id, id).await;
            raw.run(
                &format!("UPDATE crawl_runs SET {column} = NULL WHERE run_id = $1"),
                &[V::Uuid(run.id.0)],
            )
            .await;
        }
        store
            .set_status(run.id, RunStatus::Cancelled, Some(TerminalReason::Cancelled))
            .await
            .unwrap();
        assert_exact_claim_refused(&raw, store, run.id, id).await;
    }
}

db_case! {
    async fn frontier_reap_requeues_then_fails_after_max_attempts<B>(rig, store) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        store
            .discover(run.id, &canonical_url("https://example.test/a"), 0, None, None)
            .await
            .unwrap();
        let w = WorkerId::new();
        for attempt in 1..=2u16 {
            let batch = store.lease_batch(run.id, w, 1).await.unwrap();
            assert_eq!(batch[0].attempts, attempt);
            let later = store.now().await.unwrap() + Duration::seconds(120);
            let r = store.reap_frontier(later, 2).await.unwrap();
            assert_eq!((r.requeued, r.failed), if attempt < 2 { (1, 0) } else { (0, 1) });
        }
        assert_eq!(
            FrontierRepo::list(store, run.id).await.unwrap()[0].status,
            FrontierStatus::Failed
        );

        store
            .discover(run.id, &canonical_url("https://example.test/b"), 0, None, None)
            .await
            .unwrap();
        let b = store.lease_batch_fenced(run.id, w, 1).await.unwrap();
        let backoff = store.now().await.unwrap() + Duration::seconds(360);
        assert!(store.retry_fenced(b[0].0.id, b[0].1, backoff).await.unwrap());
        assert!(
            store.lease_batch(run.id, w, 1).await.unwrap().is_empty(),
            "backoff delays the retry"
        );
    }
}

async fn a_leased_row_is_open_and_a_released_row_is_pending_again(rig: &Rig) {
    async fn run<S: RunRepo + FrontierRepo>(rig: &Rig, store: &S) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        for page in ["a", "b"] {
            store
                .discover(
                    run.id,
                    &canonical_url(&format!("https://example.test/{page}")),
                    0,
                    None,
                    None,
                )
                .await
                .unwrap();
        }
        let counts = || async {
            (
                store.pending_count(run.id).await.unwrap(),
                store.open_count(run.id).await.unwrap(),
            )
        };
        assert_eq!(counts().await, (2, 2));

        let w = WorkerId::new();
        let batch = store.lease_batch_fenced(run.id, w, 2).await.unwrap();
        assert_eq!(counts().await, (0, 2), "leased rows are open, not pending");
        assert!(batch.iter().all(|(e, _)| e.attempts == 1));

        store.give_back(batch[0].0.id, batch[0].1).await.unwrap();
        assert_eq!(counts().await, (1, 2));
        let again = store.lease_batch(run.id, w, 1).await.unwrap();
        assert_eq!(
            (again[0].id, again[0].attempts),
            (batch[0].0.id, 1),
            "a release is not an attempt"
        );

        store
            .complete(batch[1].0.id, FrontierStatus::Succeeded, None)
            .await
            .unwrap();
        assert!(matches!(
            store.give_back(batch[1].0.id, batch[1].1).await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(
            store.give_back(i64::MAX, 1).await,
            Err(StoreError::NotFound { .. })
        ));
        assert_eq!(counts().await, (0, 1));
        store
            .complete(again[0].id, FrontierStatus::Failed, Some("http_500".to_owned()))
            .await
            .unwrap();
        assert_eq!(
            counts().await,
            (0, 0),
            "nothing left in flight: the frontier is exhausted"
        );
    }
    rig.migrate().await;
    on_store!(rig, run);
}

db_case! {
    /// A URL lease lives as long as its holder renews it, and only its holder (the fencing
    /// token it was granted) renews, completes or hands the row back: once the reaper has
    /// returned the row, a stalled holder can touch nothing, whoever leases the row next.
    async fn a_frontier_lease_is_renewed_and_finished_only_under_its_fencing_token<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        for page in ["a", "b"] {
            store
                .discover(
                    run.id,
                    &canonical_url(&format!("https://example.test/{page}")),
                    0,
                    None,
                    None,
                )
                .await
                .unwrap();
        }
        assert_eq!(store.url_batch_ttl(), std::time::Duration::from_secs(60));
        let holder = WorkerId::new();
        let batch = store.lease_batch_fenced(run.id, holder, 2).await.unwrap();
        let ((a, fa), (b, fb)) = (&batch[0], &batch[1]);
        let (a, b) = (a.id, b.id);
        assert_ne!(fa, fb, "every lease has a token of its own");
        let expiry = |id: i64| {
            async move {
                raw.one(
                    "SELECT lease_expires_at FROM url_frontier WHERE frontier_id = $1",
                    &[V::I64(id)],
                )
                .await
                .opt_ts("lease_expires_at")
                .unwrap()
            }
        };
        // both leases are about to run out
        let soon_at = raw.now().await + Duration::seconds(10);
        raw.run(
            "UPDATE url_frontier SET lease_expires_at = $1 WHERE run_id = $2",
            &[V::Ts(soon_at), V::Uuid(run.id.0)],
        )
        .await;
        let soon = expiry(a).await;

        // a heartbeat renews the rows of the holder that present their token, and only those
        assert!(store
            .heartbeat_frontier(WorkerId::new(), &[(a, *fa), (b, *fb)])
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .heartbeat_frontier(holder, &[(a, fa + 10_000), (b, *fb)])
                .await
                .unwrap(),
            vec![b]
        );
        assert_eq!(expiry(a).await, soon, "a stale token renews nothing");
        assert!(
            expiry(b).await > soon + Duration::seconds(30),
            "renewed to the full TTL"
        );

        // the reaper returns the row that was not renewed
        let later = store.now().await.unwrap() + Duration::seconds(30);
        let reaped = store.reap_frontier(later, 5).await.unwrap();
        assert_eq!((reaped.requeued, reaped.failed), (1, 0));
        assert_eq!(store.pending_count(run.id).await.unwrap(), 1);

        // the stalled holder keeps its token and can do nothing with it
        assert!(store
            .heartbeat_frontier(holder, &[(a, *fa)])
            .await
            .unwrap()
            .is_empty());
        assert!(matches!(
            store
                .complete_fenced(a, *fa, FrontierStatus::Succeeded, None)
                .await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(store.give_back(a, *fa).await, Err(StoreError::LeaseLost)));

        // and not after another worker leased the row either
        let again = store
            .lease_batch_fenced(run.id, WorkerId::new(), 1)
            .await
            .unwrap();
        assert_eq!((again[0].0.id, again[0].0.attempts), (a, 2));
        assert!(again[0].1 > *fa, "a new lease, a newer token");
        assert!(matches!(
            store.complete_fenced(a, *fa, FrontierStatus::Failed, None).await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(store.give_back(a, *fa).await, Err(StoreError::LeaseLost)));
        assert_eq!(
            store.open_count(run.id).await.unwrap(),
            2,
            "the new holder keeps the row"
        );
        store
            .complete_fenced(a, again[0].1, FrontierStatus::Succeeded, None)
            .await
            .unwrap();

        // the holder of the renewed row finishes it; finishing twice is a lost lease
        assert!(matches!(
            store.complete_fenced(b, *fb, FrontierStatus::Leased, None).await,
            Err(StoreError::IllegalTransition { .. })
        ));
        store
            .complete_fenced(b, *fb, FrontierStatus::Failed, Some("http_500".to_owned()))
            .await
            .unwrap();
        assert!(matches!(
            store.complete_fenced(b, *fb, FrontierStatus::Failed, None).await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(
            store
                .complete_fenced(i64::MAX, 1, FrontierStatus::Failed, None)
                .await,
            Err(StoreError::NotFound { .. })
        ));
        assert_eq!(store.open_count(run.id).await.unwrap(), 0);
    }
}

/// `state_counts` tallies the rows of one run by status, and splits out the rows the URL
/// counters hold as duplicates by their `dedupe:` reason: the same numbers as
/// `FrontierStateCounts::tally` over the rows.
async fn state_counts_tally_the_frontier_rows_of_one_run(rig: &Rig) {
    async fn run<S: RunRepo + FrontierRepo>(rig: &Rig, store: &S) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let other = new_run(store, tenant, &[], 1).await;
        assert_eq!(
            store.state_counts(run.id).await.unwrap(),
            FrontierStateCounts::default()
        );
        let url = |name: &str| canonical_url(&format!("https://example.test/{name}"));
        let blocked = |status, why: &str| Some((status, why.to_owned()));
        // the first six leave the lease below, `pending` is left in the queue
        for (name, denial) in [
            ("leased", None),
            ("ok", None),
            ("dup", None),
            ("bad", None),
            ("gone", None),
            ("stopped", None),
            ("pending", None),
            (
                "scope",
                blocked(FrontierStatus::PolicyBlocked, "excluded_path:/x"),
            ),
            (
                "shape",
                blocked(FrontierStatus::PolicyBlocked, "dedupe:fingerprint"),
            ),
            ("robots", blocked(FrontierStatus::RobotsBlocked, "robots")),
        ] {
            store.discover(run.id, &url(name), 0, None, denial).await.unwrap();
        }
        store
            .discover(other.id, &url("pending"), 0, None, None)
            .await
            .unwrap();
        let rows = FrontierRepo::list(store, run.id).await.unwrap();
        let id = |name: &str| {
            rows.iter()
                .find(|e| e.url.url.path() == format!("/{name}"))
                .unwrap()
                .id
        };
        let leased = store.lease_batch(run.id, WorkerId::new(), 6).await.unwrap();
        assert_eq!(leased.len(), 6);
        for (name, status, why) in [
            ("ok", FrontierStatus::Succeeded, None),
            ("dup", FrontierStatus::Succeeded, Some("dedupe:content_exact")),
            ("bad", FrontierStatus::Failed, Some("http_500")),
            ("gone", FrontierStatus::Unreachable, Some("dns")),
            ("stopped", FrontierStatus::Abandoned, Some("run_stopped")),
        ] {
            store
                .complete(id(name), status, why.map(str::to_owned))
                .await
                .unwrap();
        }

        let counts = store.state_counts(run.id).await.unwrap();
        assert_eq!(
            counts,
            FrontierStateCounts {
                pending: 1,
                leased: 1,
                succeeded: 2,
                failed: 1,
                unreachable: 1,
                abandoned: 1,
                policy_blocked: 2,
                robots_blocked: 1,
                succeeded_duplicate: 1,
                policy_blocked_duplicate: 1,
            }
        );
        assert_eq!(
            counts,
            FrontierStateCounts::tally(&FrontierRepo::list(store, run.id).await.unwrap())
        );
        // pending + leased + the page that is not a duplicate + failed + unreachable + abandoned
        assert_eq!(counts.admitted(), 1 + 1 + 1 + 1 + 1 + 1);
        assert_eq!(counts.blocked_by_policy(), 1);
        assert_eq!(counts.deduplicated(), 2);
        assert_eq!(
            store.state_counts(CrawlRunId::new()).await.unwrap(),
            FrontierStateCounts::default()
        );
    }
    rig.migrate().await;
    on_store!(rig, run);
}
