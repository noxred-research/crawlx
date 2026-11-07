//! `MonitorScheduler`: claiming, exactly-once runs under the lease, rescheduling on the injected
//! clock, bounded concurrency and the `run_forever` loop. PostgreSQL variant skipped without
//! `CRAWLX_TEST_DATABASE_URL`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, TenantId};
use crawlx_scheduler::monitor::{MonitorRunner, MonitorScheduler, MonitorSchedulerConfig};
use crawlx_storage::{IntelRepo, MemoryIntel, MonitorRecord, MonitorStatus};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn utc(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn tenant() -> TenantId {
    TenantId(Uuid::from_u128(0x7e))
}

fn monitor(n: u128, cron: &str, next_run_at: Option<&str>, status: MonitorStatus) -> MonitorRecord {
    let at = utc("2025-06-01T00:00:00Z");
    MonitorRecord {
        id: Uuid::from_u128(n),
        tenant: tenant(),
        name: Some(format!("monitor {n}")),
        status,
        schedule: json!({"cron": cron, "timezone": "UTC"}),
        cron: cron.to_owned(),
        timezone: "UTC".to_owned(),
        goal: None,
        targets: json!([]),
        retention_days: 30,
        webhook: None,
        notification: json!({}),
        next_run_at: next_run_at.map(utc),
        last_run_at: None,
        last_check_id: None,
        claimed_until: None,
        created_at: at,
        updated_at: at,
    }
}

/// Records every run; behaviour is scripted per monitor.
#[derive(Default)]
struct Runner {
    runs: Mutex<Vec<(Uuid, String)>>,
    fail: Mutex<BTreeMap<Uuid, usize>>,
    checks: Mutex<BTreeMap<Uuid, Uuid>>,
    hold: Option<Arc<Notify>>,
    entered: Notify,
    active: AtomicUsize,
    peak: AtomicUsize,
    work: Option<Duration>,
    advance: Option<(ManualClock, i64)>,
}

impl Runner {
    fn runs(&self) -> Vec<(Uuid, String)> {
        self.runs.lock().clone()
    }
}

#[async_trait]
impl MonitorRunner for Runner {
    async fn run(&self, monitor: &MonitorRecord, trigger: &str) -> Result<Uuid, String> {
        self.runs.lock().push((monitor.id, trigger.to_owned()));
        let now_active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now_active, Ordering::SeqCst);
        self.entered.notify_waiters();
        if let Some(hold) = &self.hold {
            hold.notified().await;
        }
        if let Some(work) = self.work {
            tokio::time::sleep(work).await;
        }
        if let Some((clock, ms)) = &self.advance {
            clock.advance_ms(*ms);
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        {
            let mut fail = self.fail.lock();
            if let Some(left) = fail.get_mut(&monitor.id) {
                if *left > 0 {
                    *left -= 1;
                    return Err("store unavailable".to_owned());
                }
            }
        }
        let check = Uuid::from_u128(monitor.id.as_u128() + 0x1000);
        self.checks.lock().insert(monitor.id, check);
        Ok(check)
    }
}

struct Fixture {
    repo: Arc<MemoryIntel>,
    clock: ManualClock,
    runner: Arc<Runner>,
    sched: Arc<MonitorScheduler>,
}

fn fixture(runner: Runner, clock: ManualClock, cfg: MonitorSchedulerConfig) -> Fixture {
    let repo = Arc::new(MemoryIntel::new());
    let runner = Arc::new(runner);
    let sched = Arc::new(MonitorScheduler::new(
        repo.clone(),
        runner.clone(),
        Arc::new(clock.clone()),
        cfg,
    ));
    Fixture {
        repo,
        clock,
        runner,
        sched,
    }
}

fn cfg() -> MonitorSchedulerConfig {
    MonitorSchedulerConfig {
        lease: Duration::from_secs(600),
        ..MonitorSchedulerConfig::default()
    }
}

#[tokio::test]
async fn tick_claims_a_due_monitor_once_and_reschedules_on_the_injected_clock() {
    let clock = ManualClock::new(utc("2025-06-01T12:07:00Z"));
    let f = fixture(Runner::default(), clock.clone(), cfg());
    let m = monitor(
        1,
        "*/30 * * * *",
        Some("2025-06-01T12:00:00Z"),
        MonitorStatus::Active,
    );
    f.repo.monitor_insert(&m).await.unwrap();

    let report = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(report.claimed, 1);
    assert_eq!(report.ran, vec![(m.id, Uuid::from_u128(0x1001))]);
    assert!(report.failed.is_empty() && report.unschedulable.is_empty());
    assert_eq!(f.runner.runs(), vec![(m.id, "scheduled".to_owned())]);

    let stored = f.repo.monitor_get(tenant(), m.id).await.unwrap().unwrap();
    assert_eq!(stored.next_run_at, Some(utc("2025-06-01T12:30:00Z")));
    assert_eq!(stored.last_run_at, Some(utc("2025-06-01T12:07:00Z")));
    assert_eq!(stored.last_check_id, Some(Uuid::from_u128(0x1001)));
    assert_eq!(stored.claimed_until, None, "finish_run releases the claim");

    // nothing is due until 12:30: a second tick at the same instant runs nothing
    let again = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(again.claimed, 0);
    assert_eq!(f.runner.runs().len(), 1);

    f.clock.advance_ms(23 * 60_000); // 12:30:00 sharp
    let report = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(report.claimed, 1);
    let stored = f.repo.monitor_get(tenant(), m.id).await.unwrap().unwrap();
    assert_eq!(stored.next_run_at, Some(utc("2025-06-01T13:00:00Z")));
    assert_eq!(f.runner.runs().len(), 2);
}

#[tokio::test]
async fn only_due_active_monitors_are_claimed_oldest_first() {
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let f = fixture(Runner::default(), clock, cfg());
    for m in [
        monitor(
            1,
            "0 * * * *",
            Some("2025-06-01T11:30:00Z"),
            MonitorStatus::Active,
        ),
        monitor(
            2,
            "0 * * * *",
            Some("2025-06-01T11:00:00Z"),
            MonitorStatus::Active,
        ),
        monitor(
            3,
            "0 * * * *",
            Some("2025-06-01T13:00:00Z"),
            MonitorStatus::Active,
        ), // future
        monitor(
            4,
            "0 * * * *",
            Some("2025-06-01T10:00:00Z"),
            MonitorStatus::Paused,
        ), // paused
        monitor(5, "0 * * * *", None, MonitorStatus::Active), // no next run
    ] {
        f.repo.monitor_insert(&m).await.unwrap();
    }
    let report = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(report.claimed, 2);
    let ran: Vec<Uuid> = report.ran.iter().map(|(m, _)| *m).collect();
    assert_eq!(ran, vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
    let untouched = f
        .repo
        .monitor_get(tenant(), Uuid::from_u128(4))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(untouched.next_run_at, Some(utc("2025-06-01T10:00:00Z")));
    assert!(untouched.last_run_at.is_none());
}

#[tokio::test]
async fn concurrent_ticks_never_run_a_monitor_twice() {
    let hold = Arc::new(Notify::new());
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let f = fixture(
        Runner {
            hold: Some(hold.clone()),
            ..Runner::default()
        },
        clock,
        cfg(),
    );
    let m = monitor(
        1,
        "*/30 * * * *",
        Some("2025-06-01T11:59:00Z"),
        MonitorStatus::Active,
    );
    f.repo.monitor_insert(&m).await.unwrap();

    let entered = f.runner.entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();
    let first = {
        let sched = f.sched.clone();
        let now = f.clock.now();
        tokio::spawn(async move { sched.tick(now).await.unwrap() })
    };
    entered.await; // the first tick holds the claim and is inside the runner

    // second and third tickers (another task, another replica) see the lease and claim nothing
    let second = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(second.claimed, 0);
    let (a, b) = tokio::join!(f.sched.tick(f.clock.now()), f.sched.tick(f.clock.now()));
    assert_eq!(a.unwrap().claimed + b.unwrap().claimed, 0);
    assert_eq!(f.runner.runs().len(), 1);

    hold.notify_one();
    let report = first.await.unwrap();
    assert_eq!(report.ran.len(), 1);
    assert_eq!(f.runner.runs().len(), 1, "exactly one run for one due time");
    let stored = f.repo.monitor_get(tenant(), m.id).await.unwrap().unwrap();
    assert_eq!(stored.next_run_at, Some(utc("2025-06-01T12:30:00Z")));
}

#[tokio::test]
async fn a_failed_run_keeps_its_lease_and_is_reclaimed_after_it_expires() {
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let runner = Runner::default();
    runner.fail.lock().insert(Uuid::from_u128(1), 1);
    let f = fixture(runner, clock.clone(), cfg()); // lease 600 s
    let m = monitor(
        1,
        "*/30 * * * *",
        Some("2025-06-01T11:55:00Z"),
        MonitorStatus::Active,
    );
    f.repo.monitor_insert(&m).await.unwrap();

    let report = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(report.claimed, 1);
    assert_eq!(report.failed, vec![(m.id, "store unavailable".to_owned())]);
    assert!(report.ran.is_empty());
    let stored = f.repo.monitor_get(tenant(), m.id).await.unwrap().unwrap();
    assert_eq!(
        stored.next_run_at,
        Some(utc("2025-06-01T11:55:00Z")),
        "not rescheduled"
    );
    assert_eq!(stored.claimed_until, Some(utc("2025-06-01T12:10:00Z")));

    // within the lease nobody retries it
    f.clock.advance_ms(5 * 60_000);
    assert_eq!(f.sched.tick(f.clock.now()).await.unwrap().claimed, 0);
    // after the lease it is claimed again and this time succeeds
    f.clock.advance_ms(6 * 60_000);
    let report = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(report.claimed, 1);
    assert_eq!(report.ran.len(), 1);
    let stored = f.repo.monitor_get(tenant(), m.id).await.unwrap().unwrap();
    assert_eq!(stored.next_run_at, Some(utc("2025-06-01T12:30:00Z")));
}

#[tokio::test]
async fn a_slow_check_skips_the_occurrences_it_overran() {
    let clock = ManualClock::new(utc("2025-06-01T12:07:00Z"));
    let runner = Runner {
        advance: Some((clock.clone(), 73 * 60_000)), // the check "takes" until 13:20
        ..Runner::default()
    };
    let f = fixture(runner, clock, cfg());
    let m = monitor(
        1,
        "*/30 * * * *",
        Some("2025-06-01T12:00:00Z"),
        MonitorStatus::Active,
    );
    f.repo.monitor_insert(&m).await.unwrap();
    f.sched.tick(utc("2025-06-01T12:07:00Z")).await.unwrap();
    let stored = f.repo.monitor_get(tenant(), m.id).await.unwrap().unwrap();
    assert_eq!(stored.last_run_at, Some(utc("2025-06-01T12:07:00Z")));
    assert_eq!(
        stored.next_run_at,
        Some(utc("2025-06-01T13:30:00Z")),
        "next occurrence after the check finished, not a burst of catch-up runs"
    );
}

#[tokio::test]
async fn concurrency_is_bounded_by_the_config() {
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let runner = Runner {
        work: Some(Duration::from_millis(40)),
        ..Runner::default()
    };
    let f = fixture(
        runner,
        clock,
        MonitorSchedulerConfig {
            concurrency: 2,
            ..cfg()
        },
    );
    for n in 1..=6 {
        f.repo
            .monitor_insert(&monitor(
                n,
                "0 * * * *",
                Some("2025-06-01T11:00:00Z"),
                MonitorStatus::Active,
            ))
            .await
            .unwrap();
    }
    let report = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(report.claimed, 6);
    assert_eq!(report.ran.len(), 6);
    assert_eq!(
        f.runner.peak.load(Ordering::SeqCst),
        2,
        "two at a time, never more"
    );
}

#[tokio::test]
async fn claim_batch_limits_one_tick_and_the_rest_wait_for_the_next() {
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let f = fixture(
        Runner::default(),
        clock,
        MonitorSchedulerConfig {
            claim_batch: 2,
            ..cfg()
        },
    );
    for n in 1..=3 {
        f.repo
            .monitor_insert(&monitor(
                n,
                "0 * * * *",
                Some("2025-06-01T11:00:00Z"),
                MonitorStatus::Active,
            ))
            .await
            .unwrap();
    }
    assert_eq!(f.sched.tick(f.clock.now()).await.unwrap().claimed, 2);
    assert_eq!(f.sched.tick(f.clock.now()).await.unwrap().claimed, 1);
    assert_eq!(f.sched.tick(f.clock.now()).await.unwrap().claimed, 0);
    assert_eq!(f.runner.runs().len(), 3);
}

#[tokio::test]
async fn a_monitor_with_a_corrupt_schedule_stops_ticking() {
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let f = fixture(Runner::default(), clock, cfg());
    let mut m = monitor(
        1,
        "not a cron",
        Some("2025-06-01T11:00:00Z"),
        MonitorStatus::Active,
    );
    m.cron = "not a cron".to_owned();
    f.repo.monitor_insert(&m).await.unwrap();
    let report = f.sched.tick(f.clock.now()).await.unwrap();
    assert_eq!(report.unschedulable, vec![m.id]);
    let stored = f.repo.monitor_get(tenant(), m.id).await.unwrap().unwrap();
    assert_eq!(stored.next_run_at, None);
    assert_eq!(stored.claimed_until, None);
    assert_eq!(
        f.sched
            .tick(f.clock.now() + ChronoDuration::days(1))
            .await
            .unwrap()
            .claimed,
        0
    );
}

#[tokio::test]
async fn run_forever_ticks_until_cancelled() {
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let f = fixture(Runner::default(), clock, cfg());
    f.repo
        .monitor_insert(&monitor(
            1,
            "0 * * * *",
            Some("2025-06-01T11:00:00Z"),
            MonitorStatus::Active,
        ))
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let task = {
        let sched = f.sched.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { sched.run_forever(Duration::from_millis(10), cancel).await })
    };
    for _ in 0..200 {
        if !f.runner.runs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(f.runner.runs().len(), 1);
    // several more ticks pass; the monitor is not due again, so no further run
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(f.runner.runs().len(), 1);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn pg_two_schedulers_claim_each_due_monitor_once() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = format!("t_{}", Uuid::now_v7().simple());
    let pg = crawlx_storage::Pg::connect(
        &url,
        crawlx_storage::PgConfig {
            schema: Some(schema),
            max_connections: 8,
            ..crawlx_storage::PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    pg.ensure_tenant(tenant(), "monitor-tick").await.unwrap();
    let repo: Arc<dyn IntelRepo> = Arc::new(pg);
    for n in 1..=5 {
        repo.monitor_insert(&monitor(
            n,
            "*/30 * * * *",
            Some("2025-06-01T11:50:00Z"),
            MonitorStatus::Active,
        ))
        .await
        .unwrap();
    }
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let runner = Arc::new(Runner {
        work: Some(Duration::from_millis(30)),
        ..Runner::default()
    });
    let make = || {
        Arc::new(MonitorScheduler::new(
            repo.clone(),
            runner.clone(),
            Arc::new(clock.clone()),
            cfg(),
        ))
    };
    let (a, b) = (make(), make());
    let now = clock.now();
    let (ra, rb) = tokio::join!(a.tick(now), b.tick(now));
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(
        ra.claimed + rb.claimed,
        5,
        "every due monitor claimed by exactly one ticker"
    );
    assert_eq!(runner.runs().len(), 5);
    let mut ids: Vec<Uuid> = runner.runs().into_iter().map(|(id, _)| id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 5);
    for n in 1..=5 {
        let stored = repo
            .monitor_get(tenant(), Uuid::from_u128(n))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.next_run_at, Some(utc("2025-06-01T12:30:00Z")));
        assert_eq!(stored.claimed_until, None);
    }
}
