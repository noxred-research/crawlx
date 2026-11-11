//! Scheduled retention passes mutate PostgreSQL rows at a controlled cadence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::{CrawlRunId, StoreError};
use crawlx_storage::retention::{run_sweep_loop, SweepLoopConfig, SweepReport};
use crawlx_storage::{Pg, PgConfig};
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn sweep_loop_deletes_expired_rows_on_each_tick_and_stops_on_cancel() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("t_{}", CrawlRunId::new().0.simple())),
            max_connections: 1,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    // One isolated table suffices: this test covers scheduling and real database I/O,
    // not the independent multi-table retention policy.
    sqlx::query("CREATE TABLE sweep_loop_items (id INTEGER PRIMARY KEY, expires_at BIGINT NOT NULL)")
        .execute(pg.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO sweep_loop_items VALUES (1, 0), (2, 10)")
        .execute(pg.pool())
        .await
        .unwrap();

    tokio::time::pause();
    let started = Instant::now();
    // Keep the runtime runnable while database sockets wait, preventing paused time
    // from auto-advancing to the loop's timeout during real PostgreSQL I/O.
    let keep_awake = CancellationToken::new();
    let awake = keep_awake.clone();
    let clock_guard = tokio::spawn(async move {
        while !awake.is_cancelled() {
            tokio::task::yield_now().await;
        }
    });
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let pool = pg.pool().clone();
    let (observed, mut passes) = tokio::sync::mpsc::channel(4);
    let handle = tokio::spawn(async move {
        run_sweep_loop(
            SweepLoopConfig::every(Duration::from_secs(10)),
            &stop,
            || {
                let pool = pool.clone();
                async move {
                    let now = i64::try_from(started.elapsed().as_secs()).unwrap();
                    let deleted = sqlx::query("DELETE FROM sweep_loop_items WHERE expires_at <= $1")
                        .bind(now)
                        .execute(&pool)
                        .await
                        .map_err(|error| StoreError::Backend(error.to_string()))?
                        .rows_affected();
                    Ok(SweepReport {
                        rows_deleted: deleted,
                        ..SweepReport::default()
                    })
                }
            },
            |pass, outcome| {
                observed
                    .try_send((pass, outcome.as_ref().unwrap().rows_deleted))
                    .unwrap();
            },
        )
        .await
    });
    // Register the immediate interval tick, then cross the timer wheel's millisecond
    // rounding boundary explicitly; the runnable guard deliberately disables auto-advance.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(1)).await;

    assert_eq!(passes.recv().await, Some((1, 1)));
    assert_eq!(started.elapsed(), Duration::from_millis(1));
    sqlx::query("INSERT INTO sweep_loop_items VALUES (3, 5)")
        .execute(pg.pool())
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert!(passes.try_recv().is_err());
    let retained: Vec<i32> = sqlx::query_scalar("SELECT id FROM sweep_loop_items ORDER BY id")
        .fetch_all(pg.pool())
        .await
        .unwrap();
    assert_eq!(retained, [2, 3]);

    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(passes.recv().await, Some((2, 2)));
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM sweep_loop_items")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(remaining, 0);
    cancel.cancel();
    let summary = handle.await.unwrap();
    assert_eq!((summary.passes, summary.failures), (2, 0));
    assert!(passes.recv().await.is_none());
    keep_awake.cancel();
    clock_guard.await.unwrap();
    tokio::time::resume();
    pg.drop_schema().await.unwrap();
}
