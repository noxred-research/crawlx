//! The URL plane keeps the lease of its batch alive while the batch is in flight: a worker that is alive and working renews the rows it holds
//! (`LeaseRepo::heartbeat_frontier`, under the fencing token of each lease) well inside the URL
//! lease TTL, so the stale-lease reaper only returns the rows of a holder that stopped
//! heartbeating, and a row whose lease is gone is never completed under the stale token.
//!
//! * a batch whose fetches take longer than the TTL completes every row exactly once;
//! * a batch whose holder dies mid-fetch is returned after the TTL, not before;
//! * a row the reaper took from a live holder is left to its next holder (the holder neither
//!   fetches it again nor completes it, and the run does not fail on an illegal transition).
//!
//! Every test runs on the in-memory store and on PostgreSQL (one throwaway schema of
//! `CRAWLX_TEST_DATABASE_URL`; the PostgreSQL variants skip without it). The URL TTL is 2 s.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod resume_rig;

use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::FrontierStatus;
use crawlx_core::{Clock, SystemClock};
use resume_rig::{
    by_state, enqueue, finish, fleet_reaper, frontier, page_paths, terminal, Doomed, Reaped, Rig, Shape,
    Site, BATCH, URL_TTL,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Twenty pages of 200 ms: the second batch of 16 takes 3.2 s, 1.6 times the URL TTL.
const SLOW: Shape = Shape {
    pages: 20,
    delay: Duration::from_millis(200),
    links_back: false,
};

/// Twenty pages that answer at once.
const FAST: Shape = Shape {
    pages: 20,
    delay: Duration::from_millis(5),
    links_back: false,
};

async fn slow_batch_completes_every_row_once(rig: Rig) {
    assert!(
        u32::try_from(BATCH).unwrap() * SLOW.delay > URL_TTL,
        "the batch must outlast the lease"
    );
    let site = Site::start(SLOW, usize::MAX).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |_| {}).await;

    // a fleet reaper sweeps all along: it may only return the rows of a holder that stopped
    // heartbeating
    let reaper = fleet_reaper(&stores);
    let started = Instant::now();
    finish(&rig, dir.path()).await;
    let reaped = reaper.stop().await;
    assert!(
        started.elapsed() > URL_TTL * 2,
        "the run must outlast the lease more than once"
    );

    let row = terminal(&stores, run).await;
    let rows = frontier(&stores, run).await;
    assert_eq!(row.status, RunStatus::Completed, "{:?}", row.terminal_reason);
    assert_eq!(row.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert_eq!(
        by_state(&rows),
        BTreeMap::from([("succeeded", SLOW.pages + 1)]),
        "every row finished: {rows:?}"
    );
    assert_eq!(
        reaped,
        Reaped {
            requeued: 0,
            failed: 0
        },
        "the reaper found nothing to return: the holder kept heartbeating"
    );
    for r in &rows {
        let path = r.url.url.path();
        assert_eq!(r.attempts, 1, "{path} was leased {} times", r.attempts);
        assert_eq!(
            site.hits(path),
            1,
            "{path} was requested {} times",
            site.hits(path)
        );
    }
    assert_eq!(page_paths(&stores, run).await, SLOW.paths());
    let urls = row.counters.urls;
    assert_eq!(
        (urls.succeeded, urls.attempted, urls.failed),
        (
            u64::try_from(SLOW.pages + 1).unwrap(),
            u64::try_from(SLOW.pages + 1).unwrap(),
            0
        )
    );
    assert!(urls.invariants_hold(), "{urls:?}");
    drop(stores);
    rig.teardown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_slower_than_the_lease_ttl_completes_every_row_once_in_memory() {
    slow_batch_completes_every_row_once(Rig::memory()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_slower_than_the_lease_ttl_completes_every_row_once_on_postgres() {
    let Some(rig) = Rig::pg().await else { return };
    slow_batch_completes_every_row_once(rig).await;
}

/// The holder is parked on its first fetch of the second batch for longer than twice the TTL
/// and kept its rows; when it dies the reaper returns them once the lease has run out.
async fn dead_holder_is_reclaimed_after_the_ttl(rig: Rig) {
    let site = Site::start(FAST, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |_| {}).await;

    let worker = Doomed::start(&rig, dir.path().to_path_buf(), CancellationToken::new());
    site.parked().await;
    let reaper = fleet_reaper(&stores);
    tokio::time::sleep(URL_TTL * 2 + URL_TTL / 4).await;
    let held = frontier(&stores, run).await;
    assert_eq!(
        by_state(&held),
        BTreeMap::from([
            ("leased", BATCH),
            ("pending", FAST.pages - BATCH),
            ("succeeded", 1)
        ]),
        "the holder is alive: its batch is still leased after more than twice the TTL"
    );
    assert_eq!(
        reaper.reaped(),
        Reaped {
            requeued: 0,
            failed: 0
        },
        "a live holder's lease is renewed, never reaped"
    );
    let batch: BTreeSet<i64> = held
        .iter()
        .filter(|r| r.status == FrontierStatus::Leased)
        .map(|r| r.id)
        .collect();

    // the holder dies: no heartbeat from now on, the lease runs out and the reaper returns it
    let died = Instant::now();
    worker.kill();
    site.open();
    let reclaimed = loop {
        let rows = frontier(&stores, run).await;
        if !rows.iter().any(|r| r.status == FrontierStatus::Leased) {
            break died.elapsed();
        }
        assert!(
            died.elapsed() < URL_TTL + Duration::from_secs(3),
            "the dead holder's batch was never returned: {:?}",
            by_state(&rows)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    eprintln!("batch of the dead holder returned {reclaimed:?} after its death (TTL {URL_TTL:?})");
    assert!(
        reclaimed >= Duration::from_millis(1000),
        "a lease renewed within the last third of the TTL cannot run out sooner than that: {reclaimed:?}"
    );
    let rows = frontier(&stores, run).await;
    assert_eq!(
        by_state(&rows),
        BTreeMap::from([("pending", FAST.pages), ("succeeded", 1)]),
        "{rows:?}"
    );

    // the next worker finishes the run
    rig.expire_session_leases(&stores, run).await;
    finish(&rig, dir.path()).await;
    let reaped = reaper.stop().await;
    assert_eq!(
        reaped,
        Reaped {
            requeued: u64::try_from(BATCH).unwrap(),
            failed: 0
        },
        "the dead holder's batch was returned once"
    );
    let row = terminal(&stores, run).await;
    let rows = frontier(&stores, run).await;
    assert_eq!(row.status, RunStatus::Completed, "{:?}", row.terminal_reason);
    assert_eq!(
        by_state(&rows),
        BTreeMap::from([("succeeded", FAST.pages + 1)]),
        "{rows:?}"
    );
    assert_eq!(page_paths(&stores, run).await, FAST.paths());
    for r in &rows {
        let expected = if batch.contains(&r.id) { 2 } else { 1 };
        assert_eq!(
            usize::from(r.attempts),
            expected,
            "{} was leased {} times",
            r.url.url.path(),
            r.attempts
        );
    }
    let requests: u32 = rows
        .iter()
        .filter(|r| batch.contains(&r.id))
        .map(|r| site.hits(r.url.url.path()))
        .sum();
    assert_eq!(
        requests,
        u32::try_from(BATCH).unwrap() + 1,
        "each row of the dead batch was fetched once, the page in flight when it died twice"
    );
    let urls = row.counters.urls;
    assert_eq!(urls.succeeded, u64::try_from(FAST.pages + 1).unwrap());
    assert!(urls.invariants_hold(), "{urls:?}");
    drop(stores);
    rig.teardown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_whose_holder_died_is_reclaimed_after_the_lease_ttl_in_memory() {
    dead_holder_is_reclaimed_after_the_ttl(Rig::memory()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_whose_holder_died_is_reclaimed_after_the_lease_ttl_on_postgres() {
    let Some(rig) = Rig::pg().await else { return };
    dead_holder_is_reclaimed_after_the_ttl(rig).await;
}

/// The reaper takes the rows of a live holder (an hour passes between two heartbeats: a paused
/// process, a partition): the holder finds out at its next heartbeat, leaves the rows it did not
/// start alone, does not complete the one it was fetching, and the run still finishes with every
/// row attempted and counted once.
async fn row_taken_from_a_live_holder_is_never_completed_under_the_stale_fence(rig: Rig) {
    let site = Site::start(FAST, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |_| {}).await;

    let worker = Doomed::start(&rig, dir.path().to_path_buf(), CancellationToken::new());
    site.parked().await;
    let held = frontier(&stores, run).await;
    let batch: BTreeSet<i64> = held
        .iter()
        .filter(|r| r.status == FrontierStatus::Leased)
        .map(|r| r.id)
        .collect();
    assert_eq!(batch.len(), BATCH);

    let taken = stores
        .leases
        .reap_frontier(SystemClock.now() + chrono::Duration::hours(1), 5)
        .await
        .unwrap();
    assert_eq!((taken.requeued, taken.failed), (u64::try_from(BATCH).unwrap(), 0));
    // a heartbeat or two: the plane finds none of its rows leased to it any more
    tokio::time::sleep(URL_TTL * 3 / 4).await;
    site.open();

    let row = terminal(&stores, run).await;
    worker.kill();
    let rows = frontier(&stores, run).await;
    assert_eq!(
        row.status,
        RunStatus::Completed,
        "a lost lease is not a failure of the run: {:?}",
        row.terminal_reason
    );
    assert_eq!(row.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert_eq!(
        by_state(&rows),
        BTreeMap::from([("succeeded", FAST.pages + 1)]),
        "{rows:?}"
    );
    for r in &rows {
        let expected = if batch.contains(&r.id) { 2 } else { 1 };
        assert_eq!(
            usize::from(r.attempts),
            expected,
            "{} was leased {} times",
            r.url.url.path(),
            r.attempts
        );
    }
    // the rows it did not start were not fetched under the lost lease: one request each, and
    // the page it was fetching when the lease was taken a second one
    let requests: u32 = rows
        .iter()
        .filter(|r| batch.contains(&r.id))
        .map(|r| site.hits(r.url.url.path()))
        .sum();
    assert_eq!(
        requests,
        u32::try_from(BATCH).unwrap() + 1,
        "one request per row of the taken batch, the page in flight twice"
    );
    assert_eq!(page_paths(&stores, run).await, FAST.paths());
    let urls = row.counters.urls;
    assert_eq!(
        (urls.succeeded, urls.attempted, urls.failed),
        (
            u64::try_from(FAST.pages + 1).unwrap(),
            u64::try_from(FAST.pages + 1).unwrap(),
            0
        ),
        "the stale holder counted nothing"
    );
    assert!(urls.invariants_hold(), "{urls:?}");
    drop(stores);
    rig.teardown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_taken_from_a_live_holder_is_never_completed_under_the_stale_fence_in_memory() {
    row_taken_from_a_live_holder_is_never_completed_under_the_stale_fence(Rig::memory()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_taken_from_a_live_holder_is_never_completed_under_the_stale_fence_on_postgres() {
    let Some(rig) = Rig::pg().await else { return };
    row_taken_from_a_live_holder_is_never_completed_under_the_stale_fence(rig).await;
}
