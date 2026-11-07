//! A static run whose worker dies in the middle of a URL batch finishes on the next worker with
//! every admitted frontier row attempted, the page set of an uninterrupted run and the URL
//! counters of an uninterrupted run (lease protocol; found by
//! the `wire-resume` differential family: a 41-page crawl restarted at the fourth document
//! finished `completed` with 25 pages).
//!
//! The worker runs on a runtime of its own; dropping the runtime kills it without any cleanup,
//! the in-process equivalent of `SIGKILL`, with the first request of its next batch parked at
//! the site, so its leased batch is neither finished nor handed back. The holder of the
//! coordinator session stopped heartbeating (its session lease is expired), while the URL batch
//! leases it took are still live: exactly the state a worker restarted within the batch TTL
//! finds. The next worker takes the run over, and the fleet's reaper returns the dead batch
//! once its lease has expired.
//!
//! `crawl_runs.counters` is a snapshot flushed after every batch: a worker that
//! dies after it finished rows and before the flush leaves them out of the stored counters, and
//! the worker that takes the run over re-derives the URL counters from `url_frontier`
//! (`RunCounters::recover_from_frontier`, called from `seed_if_empty`). What no row proves is the
//! sightings of URLs the run already knew (`deduplicated`): those the dead worker made after its
//! last flush are lost, and a test says so.
//!
//! Every test runs on the in-memory store and on PostgreSQL (one throwaway schema of
//! `CRAWLX_TEST_DATABASE_URL`; the PostgreSQL variants skip without it).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod resume_rig;

use crawlx_core::counters::{Counters, RunStatus, TerminalReason};
use crawlx_core::repo::{FrontierStatus, SessionStatus};
use crawlx_core::CrawlRunId;
use crawlx_worker::Stores;
use resume_rig::{
    by_state, enqueue, finish, fleet_reaper, frontier, page_paths, terminal, uninterrupted, Doomed, Rig,
    Shape, Site, BATCH,
};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// The stored URL counters of a finished run are what its frontier rows prove (`verify_trail`'s
/// rule): every outcome, `admitted`, `policy_blocked` and `robots_blocked` equal the rows, and
/// `deduplicated` is at least what the rows with a `dedupe:` reason prove.
async fn assert_counters_match_the_rows(stores: &Stores, run: CrawlRunId) {
    let rows = stores.frontier.state_counts(run).await.unwrap();
    let c = stores.runs.get(run).await.unwrap().counters.urls;
    assert_eq!(
        (c.succeeded, c.failed, c.unreachable, c.abandoned),
        (rows.succeeded, rows.failed, rows.unreachable, rows.abandoned),
        "{c:?} vs {rows:?}"
    );
    assert_eq!(
        (c.admitted, c.policy_blocked, c.robots_blocked),
        (rows.admitted(), rows.blocked_by_policy(), rows.robots_blocked),
        "{c:?} vs {rows:?}"
    );
    assert!(c.deduplicated >= rows.deduplicated(), "{c:?} vs {rows:?}");
    assert!(c.invariants_hold(), "{c:?}");
}

/// Kill the worker at the gate after `done_in_batch` pages of its third batch, restart within
/// the batch lease, and check the run against the uninterrupted one.
async fn killed_mid_batch(rig: Rig, shape: Shape, done_in_batch: usize) {
    let (baseline_pages, baseline_counters) = uninterrupted(&rig, shape).await;
    assert_eq!(baseline_pages, shape.paths());

    // `/p/1` ..= `/p/16` are the second batch, then `done_in_batch` pages of the third
    let site = Site::start(shape, BATCH + done_in_batch).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |_| {}).await;

    let worker = Doomed::start(&rig, dir.path().to_path_buf(), CancellationToken::new());
    site.parked().await;
    let before = frontier(&stores, run).await;
    worker.kill();
    site.open();
    let after_kill = frontier(&stores, run).await;
    eprintln!(
        "frontier before the kill: {:?}\nfrontier after the kill:  {:?}",
        by_state(&before),
        by_state(&after_kill)
    );
    let in_flight = BATCH - done_in_batch;
    assert_eq!(
        by_state(&after_kill),
        BTreeMap::from([
            ("leased", in_flight),
            ("pending", shape.pages - 2 * BATCH),
            ("succeeded", 1 + BATCH + done_in_batch),
        ]),
        "the kill must leave the batch leased"
    );
    // the window is open: the rows the dead worker finished after its last flush are not in
    // the stored counters
    let stored = stores.runs.get(run).await.unwrap().counters.urls;
    let rows = stores.frontier.state_counts(run).await.unwrap();
    assert_eq!(
        rows.succeeded - stored.succeeded,
        u64::try_from(done_in_batch).unwrap(),
        "stored {stored:?}, rows {rows:?}"
    );

    // the dead holder's session lease runs out first (30 s in production), its URL leases later
    // (60 s): the next worker takes the run over while the batch is still leased
    rig.expire_session_leases(&stores, run).await;
    let reaper = fleet_reaper(&stores);
    finish(&rig, dir.path()).await;
    let reaped = reaper.stop().await;

    let row = terminal(&stores, run).await;
    let rows = frontier(&stores, run).await;
    eprintln!("frontier at completion:   {:?}", by_state(&rows));
    assert_eq!(row.status, RunStatus::Completed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert_eq!(
        by_state(&rows),
        BTreeMap::from([("succeeded", shape.pages + 1)]),
        "every admitted row ends attempted: {rows:?}"
    );
    assert_eq!(
        (reaped.requeued, reaped.failed),
        (u64::try_from(in_flight).unwrap(), 0),
        "the reaper returned the dead worker's batch, once"
    );
    assert_eq!(
        page_paths(&stores, run).await,
        baseline_pages,
        "the page set of the uninterrupted run"
    );

    // exactly once: a row the dead worker finished is never fetched again; the batch it held is
    // leased a second time; of those only the page in flight when it died was requested twice
    // (a GET whose outcome is unknown is repeated)
    for r in &rows {
        let path = r.url.url.path();
        let (leases, requests) = if path == "/" {
            (1, 1)
        } else {
            let n: usize = path.trim_start_matches("/p/").parse().unwrap();
            match n {
                n if n <= BATCH + done_in_batch => (1, 1),
                n if n == BATCH + done_in_batch + 1 => (2, 2),
                n if n <= 2 * BATCH => (2, 1),
                _ => (1, 1),
            }
        };
        assert_eq!(
            usize::from(r.attempts),
            leases,
            "{path} leased {} times",
            r.attempts
        );
        assert_eq!(
            site.hits(path),
            requests,
            "{path} requested {} times",
            site.hits(path)
        );
    }

    assert_counters_match_the_rows(&stores, run).await;
    let urls = row.counters.urls;
    if shape.links_back && done_in_batch > 0 {
        // the only counters no row proves: a page links back to the index, a URL the run
        // already knew, and the sightings the dead worker made after its last flush are lost
        let lost = u64::try_from(done_in_batch).unwrap();
        assert_eq!(
            Counters {
                deduplicated: urls.deduplicated + lost,
                discovered: urls.discovered + lost,
                ..urls
            },
            baseline_counters,
            "{urls:?} vs {baseline_counters:?}"
        );
    } else {
        assert_eq!(urls, baseline_counters, "the counters of the uninterrupted run");
    }
    drop(stores);
    rig.teardown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_leased_by_a_killed_worker_is_attempted_after_recovery_in_memory() {
    killed_mid_batch(Rig::memory(), Shape::wire_resume(), 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_leased_by_a_killed_worker_is_attempted_after_recovery_on_postgres() {
    let Some(rig) = Rig::pg().await else { return };
    killed_mid_batch(rig, Shape::wire_resume(), 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_killed_after_finishing_part_of_its_batch_loses_nothing_in_memory() {
    killed_mid_batch(Rig::memory(), Shape::no_back_links(), 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_killed_after_finishing_part_of_its_batch_loses_nothing_on_postgres() {
    let Some(rig) = Rig::pg().await else { return };
    killed_mid_batch(rig, Shape::no_back_links(), 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_killed_after_finishing_part_of_its_batch_loses_only_the_sightings_no_row_proves_in_memory()
{
    killed_mid_batch(Rig::memory(), Shape::wire_resume(), 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_killed_after_finishing_part_of_its_batch_loses_only_the_sightings_no_row_proves_on_postgres(
) {
    let Some(rig) = Rig::pg().await else { return };
    killed_mid_batch(rig, Shape::wire_resume(), 3).await;
}

/// A worker drained by SIGTERM in the middle of its batch finishes the page in flight, releases
/// its session and hands the rest of the batch back: the next worker attempts those rows, none of
/// them is marked abandoned (an abandoned row belongs to a run that was cancelled, a limit or
/// the deadline), and no page the first worker fetched is fetched again.
async fn drained_mid_batch(rig: Rig) {
    let shape = Shape::wire_resume();
    let (baseline_pages, baseline_counters) = uninterrupted(&rig, shape).await;
    let site = Site::start(shape, BATCH + 2).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |_| {}).await;

    let sigterm = CancellationToken::new();
    let worker = Doomed::start(&rig, dir.path().to_path_buf(), sigterm.clone());
    site.parked().await;
    sigterm.cancel();
    site.open();
    // the worker leaves its loop by itself once the session is handed over
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let sessions = stores.runs.list_sessions(run).await.unwrap();
        if sessions.iter().all(|s| s.status == SessionStatus::Recovering) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the drained worker never released its session"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    worker.kill();
    let drained = frontier(&stores, run).await;
    eprintln!("frontier after the drain: {:?}", by_state(&drained));
    assert!(
        !drained.iter().any(|r| r.status == FrontierStatus::Leased),
        "a drained worker holds no lease: {:?}",
        by_state(&drained)
    );

    finish(&rig, dir.path()).await;
    let row = terminal(&stores, run).await;
    let rows = frontier(&stores, run).await;
    eprintln!("frontier at completion:   {:?}", by_state(&rows));
    assert_eq!(row.status, RunStatus::Completed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert_eq!(
        by_state(&rows),
        BTreeMap::from([("succeeded", shape.pages + 1)]),
        "{rows:?}"
    );
    assert_eq!(page_paths(&stores, run).await, baseline_pages);
    for path in shape.paths() {
        assert_eq!(site.hits(&path), 1, "{path} requested {} times", site.hits(&path));
    }
    assert_eq!(row.counters.urls, baseline_counters);
    assert_counters_match_the_rows(&stores, run).await;
    drop(stores);
    rig.teardown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drained_worker_hands_the_rest_of_its_batch_back_in_memory() {
    drained_mid_batch(Rig::memory()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drained_worker_hands_the_rest_of_its_batch_back_on_postgres() {
    let Some(rig) = Rig::pg().await else { return };
    drained_mid_batch(rig).await;
}

/// `limits.urls` bounds the run, not the worker: a run killed after 17 pages and recovered with
/// `limits.urls = 30` stops at 30 pages in total with `limit_reached`, not at 30 more.
async fn limit_survives_recovery(rig: Rig) {
    const LIMIT: usize = 30;
    let site = Site::start(Shape::wire_resume(), BATCH).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |c| {
        c.limits.urls = u32::try_from(LIMIT).unwrap();
    })
    .await;

    let worker = Doomed::start(&rig, dir.path().to_path_buf(), CancellationToken::new());
    site.parked().await;
    worker.kill();
    site.open();
    rig.expire_session_leases(&stores, run).await;
    let reaper = fleet_reaper(&stores);
    finish(&rig, dir.path()).await;
    reaper.stop().await;

    let row = terminal(&stores, run).await;
    let rows = frontier(&stores, run).await;
    eprintln!("frontier at completion:   {:?}", by_state(&rows));
    assert_eq!(row.status, RunStatus::Completed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(page_paths(&stores, run).await.len(), LIMIT);
    assert_eq!(row.counters.urls.succeeded, u64::try_from(LIMIT).unwrap());
    drop(stores);
    rig.teardown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recovered_run_keeps_its_url_limit_in_memory() {
    limit_survives_recovery(Rig::memory()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recovered_run_keeps_its_url_limit_on_postgres() {
    let Some(rig) = Rig::pg().await else { return };
    limit_survives_recovery(rig).await;
}
