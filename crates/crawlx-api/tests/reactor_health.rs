//! Memory-router burst regression, not runtime evidence for the actor model.
//!
//! This measures only request-future polls during 200 concurrent requests. It does
//! not measure runtime workers, a paced 200 RPS workload, PostgreSQL or saturated
//! browser/CPU pools. The opt-in real proof lives in
//! `crawlx-bench/tests/runtime_proof.rs`; its worker metrics come from Tokio and
//! `tokio_metrics`, not this wrapper.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{env, simple_body};
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower::ServiceExt;

/// Concurrent requests in the burst.
const REQUESTS: usize = 200;
/// Upper bound on the p99 single-poll wall time.
const P99_BOUND: Duration = Duration::from_millis(5);

/// Records the wall time of every `poll` of the wrapped future.
struct PollTimed<F> {
    inner: F,
    polls: Arc<Mutex<Vec<Duration>>>,
}

impl<F: Future + Unpin> Future for PollTimed<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let started = Instant::now();
        let out = Pin::new(&mut self.inner).poll(cx);
        self.polls.lock().push(started.elapsed());
        out
    }
}

/// The `pct`-th percentile of `sorted` (nearest-rank).
fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    assert!(!sorted.is_empty());
    let rank = (sorted.len() * pct).div_ceil(100);
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hundred_concurrent_requests_keep_p99_poll_under_5ms() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let uri = format!("/v1/crawls/{id}");
    // one warm-up request so lazily initialised statics are not measured
    let (s, _, _) = e.send(Method::GET, &uri, Some(&e.key), &[], None).await;
    assert_eq!(s, StatusCode::OK);

    let polls = Arc::new(Mutex::new(Vec::with_capacity(REQUESTS * 4)));
    let mut tasks = Vec::with_capacity(REQUESTS);
    for _ in 0..REQUESTS {
        let app = e.app.clone();
        let req = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header("authorization", format!("Bearer {}", e.key))
            .body(Body::empty())
            .unwrap();
        let polls = Arc::clone(&polls);
        tasks.push(tokio::spawn(async move {
            let fut: Pin<Box<dyn Future<Output = _> + Send>> = Box::pin(async move {
                let resp = app.oneshot(req).await.unwrap();
                let status = resp.status();
                let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
                (status, body)
            });
            PollTimed { inner: fut, polls }.await
        }));
    }
    for t in tasks {
        let (status, body) = t.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(common::json(&body)["id"], id);
    }

    let mut all = polls.lock().clone();
    assert!(all.len() >= REQUESTS, "every request polled at least once");
    all.sort_unstable();
    let p50 = percentile(&all, 50);
    let p99 = percentile(&all, 99);
    let max = *all.last().unwrap();
    eprintln!(
        "polls={} p50={p50:?} p99={p99:?} max={max:?} (bound {P99_BOUND:?})",
        all.len()
    );
    assert!(
        p99 < P99_BOUND,
        "p99 single-poll time {p99:?} over {} polls exceeds {P99_BOUND:?} (max {max:?})",
        all.len()
    );
}
