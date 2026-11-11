#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Webhook delivery, signing, retry and egress behaviour over the in-memory API.
//!
//! Delivery metrics are process-global, so every test that ticks the sender takes `LOCK`
//! and asserts deltas against the `TickReport`.
mod common;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::Utc;
use common::{env_with, Env};
use crawlx_api::store::{DeliveryStatus, WebhookDelivery};
use crawlx_api::webhooks::{
    retry_delay, signature, TickReport, TransportError, WebhookRequest, WebhookSender, WebhookTransport,
    MAX_ATTEMPTS, RETRY_SCHEDULE_SECS,
};
use crawlx_api::{ApiConfig, ApiStore, Settings};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{EventRepo, RunRepo};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, CrawlRunId};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Arc;

const SECRET: &str = "whsec_test_secret";

static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `crawlx.webhook.deliveries{event}` by outcome: `(delivered, retry, exhausted)`.
fn delivery_counts(event: &str) -> (u64, u64, u64) {
    let c = Metrics::global().counter(names::WEBHOOK_DELIVERIES);
    let get = |outcome: &str| c.get(&[("event", event), ("outcome", outcome)]);
    (get("delivered"), get("retry"), get("exhausted"))
}

/// Assert the counter moved by exactly what `rep` reports for `event`.
fn assert_deliveries_match(before: (u64, u64, u64), event: &str, rep: &TickReport) {
    let after = delivery_counts(event);
    assert_eq!(
        (after.0 - before.0, after.1 - before.1, after.2 - before.2),
        (rep.delivered, rep.retried, rep.dead),
        "crawlx.webhook.deliveries deltas for {event} vs {rep:?}"
    );
}

fn pending(event: &str) -> Option<f64> {
    Metrics::global()
        .gauge(names::WEBHOOK_PENDING)
        .get(&[("event", event)])
}

fn oldest_pending_age(event: &str) -> Option<f64> {
    Metrics::global()
        .gauge(names::WEBHOOK_OLDEST_PENDING_AGE)
        .get(&[("event", event)])
}

/// Records requests and replies with scripted statuses (default 200).
#[derive(Default)]
struct Script {
    replies: Mutex<VecDeque<Result<u16, String>>>,
    seen: Mutex<Vec<WebhookRequest>>,
}

#[async_trait]
impl WebhookTransport for Script {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        self.seen.lock().push(req);
        match self.replies.lock().pop_front() {
            Some(Ok(s)) => Ok(s),
            Some(Err(m)) => Err(TransportError::Network(m)),
            None => Ok(200),
        }
    }
}

struct Rig {
    env: Env,
    script: Arc<Script>,
    clock: Arc<ManualClock>,
    sender: WebhookSender,
}

fn rig() -> Rig {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        webhook_secret: SECRET.to_owned(),
        ..ApiConfig::default()
    };
    let env = env_with(cfg, Settings::default(), clock.clone());
    let script = Arc::new(Script::default());
    let sender = WebhookSender::new(
        env.state.repos.api.clone(),
        env.state.repos.runs.clone(),
        env.state.repos.events.clone(),
        script.clone(),
        SECRET.to_owned(),
        clock.clone(),
    );
    Rig {
        env,
        script,
        clock,
        sender,
    }
}

async fn run_with_hook(r: &Rig, events: &[&str]) -> CrawlRunId {
    let body = json!({
        "seedUrl": "https://app.example.test/",
        "seed": 5,
        "output": {"webhook": {"url": "https://hooks.example.test/crawlx", "events": events}},
    });
    r.env.create_run(&body).await.parse().unwrap()
}

fn header<'a>(req: &'a WebhookRequest, name: &str) -> &'a str {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .unwrap()
}

#[tokio::test]
async fn signed_delivery_retries_on_500_then_succeeds() {
    let _serial = LOCK.lock().await;
    let r = rig();
    let run = run_with_hook(&r, &["completed"]).await;
    r.env
        .store
        .append(run, "page", json!({"ignored": true}))
        .await
        .unwrap();
    r.env
        .store
        .append(run, "completed", json!({"status": "completed"}))
        .await
        .unwrap();
    r.script.replies.lock().push_back(Ok(500));
    let before = delivery_counts("completed");
    let rep = r.sender.tick().await.unwrap();
    assert_eq!(
        (rep.enqueued, rep.retried, rep.delivered),
        (1, 1, 0),
        "only the subscribed event is queued"
    );
    assert_deliveries_match(before, "completed", &rep);
    assert_eq!(pending("completed"), Some(1.0));
    assert_eq!(
        oldest_pending_age("completed"),
        Some(0.0),
        "scheduled in the future"
    );
    {
        let seen = r.script.seen.lock();
        assert_eq!(seen.len(), 1);
        let req = &seen[0];
        assert_eq!(req.url.as_str(), "https://hooks.example.test/crawlx");
        assert_eq!(header(req, "Crawlx-Event"), "completed");
        let t: i64 = header(req, "Crawlx-Timestamp").parse().unwrap();
        assert_eq!(t, r.clock.now().timestamp());
        let sig = header(req, "Crawlx-Signature");
        // verify exactly as a receiver would: recompute HMAC-SHA256(secret, "{t}.{body}")
        let (tpart, vpart) = sig.split_once(',').unwrap();
        assert_eq!(tpart, format!("t={t}"));
        let expected = signature(SECRET, t, &req.body);
        assert_eq!(vpart, format!("v1={expected}"));
        assert_ne!(vpart, format!("v1={}", signature("wrong", t, &req.body)));
        uuid::Uuid::parse_str(header(req, "Crawlx-Delivery-Id")).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["type"], "completed");
        assert_eq!(body["seq"], 2);
        assert_eq!(body["runId"], run.to_string().as_str());
        assert_eq!(body["data"]["status"], "completed");
        assert_eq!(header(req, "Content-Type"), "application/json");
    }
    let d = r.env.api.deliveries();
    assert_eq!(d.len(), 1);
    assert_eq!(
        (d[0].status, d[0].attempts, d[0].last_status),
        (DeliveryStatus::Pending, 1, Some(500))
    );
    let wait = (d[0].next_attempt_at - r.clock.now()).num_milliseconds();
    assert!((8_000..=12_000).contains(&wait), "10 s ±20 %: {wait}");

    // not due yet
    r.clock.advance_ms(5_000);
    let before = delivery_counts("completed");
    let rep = r.sender.tick().await.unwrap();
    assert_eq!((rep.enqueued, rep.retried, rep.delivered), (0, 0, 0));
    assert_eq!(r.script.seen.lock().len(), 1);
    assert_deliveries_match(before, "completed", &rep);
    assert_eq!(pending("completed"), Some(1.0));

    // due: success, same delivery id
    r.clock.advance_ms(8_000);
    let before = delivery_counts("completed");
    let rep = r.sender.tick().await.unwrap();
    assert_eq!((rep.retried, rep.delivered), (0, 1));
    assert_deliveries_match(before, "completed", &rep);
    assert_eq!(pending("completed"), Some(0.0), "drained event types reset to 0");
    assert_eq!(oldest_pending_age("completed"), Some(0.0));
    {
        let seen = r.script.seen.lock();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            header(&seen[0], "Crawlx-Delivery-Id"),
            header(&seen[1], "Crawlx-Delivery-Id")
        );
        let t2: i64 = header(&seen[1], "Crawlx-Timestamp").parse().unwrap();
        assert_eq!(
            header(&seen[1], "Crawlx-Signature"),
            format!("t={t2},v1={}", signature(SECRET, t2, &seen[1].body))
        );
    }
    let d = r.env.api.deliveries();
    assert_eq!(
        (d[0].status, d[0].attempts, d[0].last_status),
        (DeliveryStatus::Delivered, 2, Some(200))
    );
    assert!(d[0].delivered_at.is_some());

    // delivered rows are never sent again and nothing is re-enqueued
    r.clock.advance_ms(3_600_000);
    let before = delivery_counts("completed");
    let rep = r.sender.tick().await.unwrap();
    assert_eq!((rep.enqueued, rep.delivered, rep.retried, rep.dead), (0, 0, 0, 0));
    assert_deliveries_match(before, "completed", &rep);
}

#[tokio::test]
async fn gone_stops_delivery_and_network_errors_retry_until_dead() {
    let _serial = LOCK.lock().await;
    let r = rig();
    let run = run_with_hook(&r, &[]).await; // default events: completed, failed
    r.env.store.append(run, "completed", json!({})).await.unwrap();
    r.script.replies.lock().push_back(Ok(410));
    let before = delivery_counts("completed");
    let rep = r.sender.tick().await.unwrap();
    assert_eq!(rep.dead, 1);
    assert_deliveries_match(before, "completed", &rep);
    let d = r.env.api.deliveries();
    assert_eq!(
        (d[0].status, d[0].attempts, d[0].last_status),
        (DeliveryStatus::Dead, 1, Some(410))
    );
    r.clock.advance_ms(48 * 3_600_000);
    assert_eq!(r.sender.tick().await.unwrap().retried, 0);
    assert_eq!(r.script.seen.lock().len(), 1);

    // eight failed attempts (network errors), then dead; the schedule is followed
    let run2 = run_with_hook(&r, &["failed"]).await;
    r.env
        .store
        .append(run2, "failed", json!({"status": "failed"}))
        .await
        .unwrap();
    for _ in 0..MAX_ATTEMPTS {
        r.script
            .replies
            .lock()
            .push_back(Err("connection reset".to_owned()));
    }
    let mut waits = Vec::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let before = delivery_counts("failed");
        let rep = r.sender.tick().await.unwrap();
        assert_eq!(rep.retried + rep.dead, 1, "attempt {attempt}");
        assert_deliveries_match(before, "failed", &rep);
        let d = r.env.api.webhook_list(run2).await.unwrap();
        if attempt < MAX_ATTEMPTS {
            waits.push((d[0].next_attempt_at - r.clock.now()).num_seconds());
            r.clock.advance_ms(30 * 3_600_000); // beyond the largest jittered delay (24 h + 20 %)
        }
    }
    let d = r.env.api.webhook_list(run2).await.unwrap();
    assert_eq!((d[0].status, d[0].attempts), (DeliveryStatus::Dead, MAX_ATTEMPTS));
    assert_eq!(d[0].last_error.as_deref(), Some("connection reset"));
    for (w, base) in waits.iter().zip(RETRY_SCHEDULE_SECS) {
        let (lo, hi) = (base as f64 * 0.8, base as f64 * 1.2);
        assert!(
            (lo - 1.0..=hi + 1.0).contains(&(*w as f64)),
            "{w}s not within ±20% of {base}s"
        );
    }
    assert_eq!(r.env.api.webhook_dead_count(run2).await.unwrap(), 1);
    // surfaced on the status resource
    let (s, _, v) = r.env.get(&format!("/v1/crawls/{run2}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["webhook"]["deadDeliveries"], 1);
    let (_, _, v) = r.env.get(&format!("/v1/crawls/{run}")).await;
    assert_eq!(v["webhook"]["deadDeliveries"], 1);
}

#[tokio::test]
async fn private_destinations_are_refused_before_the_transport() {
    let _serial = LOCK.lock().await;
    let r = rig();
    let run = run_with_hook(&r, &["completed"]).await;
    r.env.store.append(run, "completed", json!({})).await.unwrap();
    // a stale outbox row pointing at a private target (e.g. DNS rebinding after admission)
    let hook = WebhookDelivery {
        id: uuid::Uuid::now_v7(),
        run,
        event_seq: 1,
        event_type: "completed".to_owned(),
        url: "http://127.0.0.1:9/hook".to_owned(),
        status: DeliveryStatus::Pending,
        attempts: 0,
        next_attempt_at: r.clock.now(),
        delivered_at: None,
        last_status: None,
        last_error: None,
    };
    assert!(r.env.api.webhook_enqueue(&hook).await.unwrap());
    assert!(
        !r.env.api.webhook_enqueue(&hook).await.unwrap(),
        "duplicates are ignored"
    );
    let before = delivery_counts("completed");
    let rep = r.sender.tick().await.unwrap();
    // the legitimate row for seq 1 was enqueued as well
    assert_eq!(rep.dead, 1);
    assert_deliveries_match(before, "completed", &rep);
    let rows = r.env.api.webhook_list(run).await.unwrap();
    let private = rows.iter().find(|d| d.url.contains("127.0.0.1")).unwrap();
    assert_eq!(private.status, DeliveryStatus::Dead);
    assert!(
        private
            .last_error
            .as_deref()
            .unwrap()
            .starts_with("egress_denied"),
        "{private:?}"
    );
    assert!(r
        .script
        .seen
        .lock()
        .iter()
        .all(|q| q.url.host_str() != Some("127.0.0.1")));
}

#[tokio::test]
async fn sender_follows_the_outbox_across_runs_and_survives_a_purged_run() {
    let _serial = LOCK.lock().await;
    let r = rig();
    let a = run_with_hook(&r, &["paused"]).await;
    let b = run_with_hook(&r, &["paused"]).await;
    r.env.store.set_status(a, RunStatus::Running, None).await.unwrap();
    r.env.post_empty(&format!("/v1/crawls/{a}:pause")).await;
    r.env.store.append(b, "paused", json!({})).await.unwrap();
    let before = delivery_counts("paused");
    let rep = r.sender.tick().await.unwrap();
    assert_eq!((rep.enqueued, rep.delivered), (2, 2));
    assert_deliveries_match(before, "paused", &rep);
    // events appended later are picked up from the in-memory cursor
    r.env.store.append(b, "paused", json!({})).await.unwrap();
    let rep = r.sender.tick().await.unwrap();
    assert_eq!((rep.enqueued, rep.delivered), (1, 1));
    // a purged run no longer breaks the tick
    r.env.store.purge_run(a).await.unwrap();
    r.env.store.append(b, "paused", json!({})).await.unwrap();
    let rep = r.sender.tick().await.unwrap();
    assert_eq!(rep.delivered, 1);
}

#[tokio::test]
async fn pending_gauges_follow_the_backlog_and_its_age() {
    let _serial = LOCK.lock().await;
    let r = rig();
    let run = run_with_hook(&r, &["page"]).await;
    // one tick claims at most 50 deliveries, so 110 events leave a measurable backlog
    for i in 0..110 {
        r.env.store.append(run, "page", json!({"i": i})).await.unwrap();
    }
    let before = delivery_counts("page");
    let rep = r.sender.tick().await.unwrap();
    assert_eq!((rep.enqueued, rep.delivered), (110, 50));
    assert_deliveries_match(before, "page", &rep);
    assert_eq!(pending("page"), Some(60.0));
    assert_eq!(
        oldest_pending_age("page"),
        Some(0.0),
        "enqueued at this very instant"
    );

    r.clock.advance_ms(7_500);
    let rep = r.sender.tick().await.unwrap();
    assert_eq!((rep.enqueued, rep.delivered), (0, 50));
    assert_eq!(pending("page"), Some(10.0));
    assert_eq!(oldest_pending_age("page"), Some(7.5), "due since the first tick");

    r.clock.advance_ms(1_000);
    let rep = r.sender.tick().await.unwrap();
    assert_eq!(rep.delivered, 10);
    assert_eq!(pending("page"), Some(0.0));
    assert_eq!(oldest_pending_age("page"), Some(0.0));
}

#[tokio::test]
async fn retry_delays_are_deterministic_and_bounded() {
    let r = rig();
    let id = run_with_hook(&r, &["completed"]).await;
    let run = r.env.store.get(id).await.unwrap();
    let delivery = uuid::Uuid::now_v7();
    for (i, base) in RETRY_SCHEDULE_SECS.iter().enumerate() {
        let attempt = u16::try_from(i + 1).unwrap();
        let d = retry_delay(&run, delivery, attempt).unwrap();
        assert_eq!(
            d,
            retry_delay(&run, delivery, attempt).unwrap(),
            "seeded jitter is reproducible"
        );
        let secs = d.as_secs_f64();
        assert!(
            secs >= *base as f64 * 0.8 - 0.001 && secs <= *base as f64 * 1.2 + 0.001,
            "{secs} vs {base}"
        );
    }
    assert!(
        retry_delay(&run, delivery, 8).is_none(),
        "no delay after the last attempt"
    );
    assert!(retry_delay(&run, delivery, 0).is_none());
    assert_ne!(
        retry_delay(&run, delivery, 3).unwrap(),
        retry_delay(&run, uuid::Uuid::now_v7(), 3).unwrap(),
        "jitter varies per delivery"
    );
}
