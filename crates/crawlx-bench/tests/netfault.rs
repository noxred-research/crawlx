//! `crawlx_bench::netfault` (chaos at scale without toxiproxy): the proxy's
//! fault semantics over a loopback echo server, and a worker whose PostgreSQL traffic is
//! reset five times mid-run — the journal invariants of the chaos suites must hold and the
//! worker must keep completing runs afterwards. The PostgreSQL half skips without
//! `CRAWLX_TEST_DATABASE_URL`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/authorization.rs"]
mod authorization;

use crawlx_bench::netfault::{rewrite_url, upstream_of, Proxy};
use crawlx_bench::trail::{verify_trail, TrailStore};
use crawlx_bench::worker_exec::authorize_fixture;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_policy::testkit::sample_record;
use crawlx_storage::{FsArtifactStore, LeaseRepo, Pg, PgConfig};
use crawlx_worker::{lease_loop, run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

async fn echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn round_trip(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    stream.write_all(payload).await?;
    let mut out = vec![0u8; payload.len()];
    stream.read_exact(&mut out).await?;
    Ok(out)
}

#[tokio::test]
async fn proxy_forwards_delays_resets_and_refuses() {
    let upstream = echo_server().await;
    let proxy = Proxy::start(upstream).await.unwrap();
    assert_eq!(proxy.upstream(), upstream);

    // plain forwarding
    let mut c = TcpStream::connect(proxy.addr()).await.unwrap();
    assert_eq!(round_trip(&mut c, b"hello").await.unwrap(), b"hello");

    // latency: one chunk each way, so a round trip costs at least twice the delay
    proxy.set_latency(Duration::from_millis(60));
    let t = Instant::now();
    assert_eq!(round_trip(&mut c, b"slow").await.unwrap(), b"slow");
    assert!(t.elapsed() >= Duration::from_millis(120), "{:?}", t.elapsed());
    proxy.set_latency(Duration::ZERO);

    // blackhole: nothing comes back within the window; bytes are not queued for later
    proxy.set_blackhole(true);
    c.write_all(b"void").await.unwrap();
    let mut buf = [0u8; 4];
    let got = tokio::time::timeout(Duration::from_millis(200), c.read(&mut buf)).await;
    assert!(got.is_err(), "blackholed bytes must not arrive: {got:?}");
    proxy.set_blackhole(false);
    assert_eq!(round_trip(&mut c, b"back").await.unwrap(), b"back");

    // reset: the live connection dies with an error or EOF, never with more data
    let mut c2 = TcpStream::connect(proxy.addr()).await.unwrap();
    assert_eq!(round_trip(&mut c2, b"two").await.unwrap(), b"two");
    assert_eq!(proxy.stats().live, 2);
    assert_eq!(proxy.reset_all(), 2);
    let mut buf = [0u8; 8];
    let dead = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
        .await
        .unwrap();
    assert!(matches!(dead, Ok(0) | Err(_)), "{dead:?}");
    let dead = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut buf))
        .await
        .unwrap();
    assert!(matches!(dead, Ok(0) | Err(_)), "{dead:?}");
    assert_eq!(proxy.stats().resets, 2);

    // refuse: a new connection is closed before any byte is forwarded
    proxy.set_refuse(true);
    let mut c3 = TcpStream::connect(proxy.addr()).await.unwrap();
    let refused = tokio::time::timeout(Duration::from_secs(2), round_trip(&mut c3, b"nope"))
        .await
        .unwrap();
    assert!(refused.is_err(), "{refused:?}");
    proxy.set_refuse(false);
    let mut c4 = TcpStream::connect(proxy.addr()).await.unwrap();
    assert_eq!(round_trip(&mut c4, b"again").await.unwrap(), b"again");
    let stats = proxy.stats();
    assert_eq!(stats.refused, 1);
    assert!(stats.accepted >= 4, "{stats:?}");
    assert!(stats.bytes_up == 21 && stats.bytes_down == 21, "{stats:?}");
    proxy.shutdown().await;
}

#[test]
fn rewrite_keeps_credentials_path_and_query() {
    let out = rewrite_url(
        "postgres://u:p@db.internal:5433/crawlx?options=-c%20search_path%3Dx",
        "127.0.0.1:4444".parse().unwrap(),
    )
    .unwrap();
    assert_eq!(
        out,
        "postgres://u:p@127.0.0.1:4444/crawlx?options=-c%20search_path%3Dx"
    );
}

/// A scripted site of `n` pages: every page links to the next two and home, and carries a
/// button that reveals a second link, so a run journals navigations and mutations.
fn site(n: usize) -> FakeScript {
    let page = |i: usize| {
        let url = if i == 0 {
            "https://example.test/".to_owned()
        } else {
            format!("https://example.test/p{i}")
        };
        let mut p = FakePage::new(&url).title(format!("Page {i}"));
        for j in 1..=2 {
            let to = (i + j) % n;
            let target = if to == 0 {
                "/".to_owned()
            } else {
                format!("/p{to}")
            };
            let key = format!("l{j}");
            p = p
                .node(FakeAxSpec::link(&key, format!("Go {to}"), &target))
                .on_click(&key, vec![FakeEffect::Navigate(target)]);
        }
        let home = "/".to_owned();
        p = p
            .node(FakeAxSpec::link("h", "Home", &home))
            .on_click("h", vec![FakeEffect::Navigate(home)]);
        let far = (i + 5) % n;
        let far_target = if far == 0 {
            "/".to_owned()
        } else {
            format!("/p{far}")
        };
        p.node(FakeAxSpec::button("more", "More"))
            .on_click(
                "more",
                vec![FakeEffect::Reveal(vec![FakeAxSpec::link(
                    "extra",
                    format!("Extra {far}"),
                    &far_target,
                )])],
            )
            .on_click("extra", vec![FakeEffect::Navigate(far_target)])
    };
    let mut script = FakeScript::new();
    for i in 0..n {
        script = script.page(page(i));
    }
    script
}

async fn count(pg: &Pg, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pg.pool()).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_survives_five_database_resets_with_the_journal_intact() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let upstream = upstream_of(&url).await.unwrap();
    let proxy = Arc::new(Proxy::start(upstream).await.unwrap());
    let proxied = rewrite_url(&url, proxy.addr()).unwrap();
    let schema = format!("t_netfault_{}", uuid::Uuid::now_v7().simple());
    let pg = Pg::connect(
        &proxied,
        PgConfig {
            schema: Some(schema),
            max_connections: 8,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "netfault").await.unwrap();
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), tenant);
    stores.checkpoint_keys =
        Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let backend = Arc::new(
        FakeBackend::builder()
            .script(site(12))
            .clock(Arc::new(SystemClock))
            .build(),
    );

    let now = SystemClock.now();
    let mut authorization = sample_record(stores.tenant, now, &["https://example.test"]);
    authorization.verified_at = Some(now);
    authorization::register_verified_record(&pg, &authorization).await;

    // five resets, 250 ms apart, each counted only when a live connection was killed
    let injector = {
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let mut injected = 0u32;
            let started = Instant::now();
            while injected < 5 && started.elapsed() < Duration::from_secs(180) {
                tokio::time::sleep(Duration::from_millis(250)).await;
                if proxy.reset_all() > 0 {
                    injected += 1;
                }
            }
            injected
        })
    };

    // runs until the resets are in and one more run has completed after the last of them
    let mut outcomes: Vec<Result<(CrawlRunId, RunStatus), String>> = Vec::new();
    let mut completed_after_faults = false;
    for i in 0..40u64 {
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.seed = Some(20_261_020 + i);
        crawl.limits.interactions = 24;
        crawl.safety.authorization_record_ref = Some(authorization.id);
        let local = authorize_fixture(
            LocalRun::new(crawl, cfg.clone())
                .with_backend(backend.clone())
                .with_stores(stores.clone())
                .with_authorization(authorization.clone()),
        );
        let result = run_local_with(local).await;
        let faults_done = injector.is_finished();
        match result {
            Ok(report) => {
                let status = report.status;
                outcomes.push(Ok((report.run_id, status)));
                if faults_done && status == RunStatus::Completed {
                    completed_after_faults = true;
                }
            }
            Err(e) => outcomes.push(Err(format!("{e}: {:?}", std::error::Error::source(&e)))),
        }
        if completed_after_faults {
            break;
        }
    }
    let injected = injector.await.unwrap();
    assert_eq!(injected, 5, "five resets were injected");
    assert!(proxy.stats().resets >= 5, "{:?}", proxy.stats());
    eprintln!("netfault: outcomes {outcomes:?}");
    assert!(
        completed_after_faults,
        "a run must complete after the last reset: {outcomes:?}"
    );

    // recovery: expire whatever the halted sessions still hold, let the lease loop reconcile
    sqlx::query(
        "UPDATE crawl_sessions SET lease_expires_at = now() - interval '1 hour' WHERE status IN ('running','recovering')",
    )
    .execute(pg.pool())
    .await
    .unwrap();
    let recover_cfg = WorkerConfig {
        idle_exit_after: Some(Duration::from_secs(2)),
        ..cfg.clone()
    };
    tokio::time::timeout(
        Duration::from_secs(120),
        lease_loop::run_with(
            recover_cfg,
            stores.clone(),
            Some(backend.clone()),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("recovery finishes")
    .unwrap();

    // journal invariants (chaos suites): nothing intended, nothing unknown, no re-execution
    assert_eq!(
        count(&pg, "SELECT count(*) FROM actions WHERE status = 'intended'").await,
        0
    );
    assert_eq!(
        count(&pg, "SELECT count(*) FROM actions WHERE status = 'unknown'").await,
        0
    );
    assert_eq!(
        count(&pg, "SELECT count(*) FROM actions WHERE attempt > 1").await,
        0,
        "no action was executed twice"
    );
    assert_eq!(
        count(
            &pg,
            "SELECT count(*) FROM crawl_sessions WHERE status NOT IN ('completed','failed','cancelled')"
        )
        .await,
        0,
        "every session is terminal after recovery"
    );
    let now = LeaseRepo::now(&pg).await.unwrap();
    assert!(LeaseRepo::reap(&pg, now)
        .await
        .unwrap()
        .sessions_recovering
        .is_empty());
    assert!(ActionJournal::mark_unknown(&pg, now).await.unwrap().is_empty());

    // every run of the schema (including the ones the resets failed) leaves a clean trail
    let run_ids: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT run_id FROM crawl_runs ORDER BY created_at")
        .fetch_all(pg.pool())
        .await
        .unwrap();
    // a run the reset hit before `crawl_runs` was written leaves no row at all
    let reported = outcomes.iter().filter(|o| o.is_ok()).count();
    assert!(run_ids.len() >= reported, "{run_ids:?} vs {outcomes:?}");
    let mut actions_total = 0u64;
    for id in run_ids {
        let report = verify_trail(
            CrawlRunId(id),
            TrailStore::Pg {
                pg: &pg,
                artifacts: Some(stores.artifacts.as_ref()),
            },
        )
        .await
        .unwrap();
        assert!(report.is_clean(), "run {id}: {report}");
        actions_total += report.checked["actions"];
    }
    assert!(actions_total > 0, "the runs journaled actions");
    pg.drop_schema().await.unwrap();
    let proxy = Arc::try_unwrap(proxy).ok().expect("proxy no longer shared");
    proxy.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Fault schedules: parsing, seeded generation, and the proxy driver (no database needed)
// ---------------------------------------------------------------------------------------------

use crawlx_bench::netfault::{Fault, FaultSchedule};

#[test]
fn schedule_parses_the_documented_spec_and_round_trips_through_its_canonical_form() {
    let spec = "latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,refuse@25s..27s";
    let s = FaultSchedule::parse(spec).unwrap();
    let events = s.events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].fault, Fault::Latency(Duration::from_millis(50)));
    assert_eq!(
        (events[0].start, events[0].end),
        (Duration::ZERO, Some(Duration::from_secs(10)))
    );
    assert_eq!(events[1].fault, Fault::Blackhole);
    assert_eq!(events[2].fault, Fault::Reset);
    assert_eq!((events[2].start, events[2].end), (Duration::from_secs(20), None));
    assert_eq!(events[3].fault, Fault::Refuse);
    assert_eq!(s.horizon(), Duration::from_secs(27));
    assert!(!s.latency_only());
    let canonical = s.to_string();
    assert_eq!(
        canonical,
        "latency=50ms@0ms..10000ms,blackhole@12000ms..15000ms,reset@20000ms,refuse@25000ms..27000ms"
    );
    assert_eq!(FaultSchedule::parse(&canonical).unwrap(), s);

    // compound spans, whitespace and out-of-order items
    let s = FaultSchedule::parse(" reset@1m30s , latency=1s@0s..1m ").unwrap();
    assert_eq!(s.events()[0].fault, Fault::Latency(Duration::from_secs(1)));
    assert_eq!(s.events()[1].start, Duration::from_secs(90));
    assert!(FaultSchedule::parse("").unwrap().is_empty());
    assert!(FaultSchedule::parse("latency=10ms@0s..1s")
        .unwrap()
        .latency_only());

    // windows of different kinds may overlap, windows of one kind may touch
    FaultSchedule::parse("latency=10ms@0s..5s,blackhole@1s..2s").unwrap();
    FaultSchedule::parse("refuse@1s..2s,refuse@2s..3s").unwrap();
}

#[test]
fn schedule_rejects_malformed_specs_with_the_offending_item() {
    let cases = [
        ("latency@0s..1s", "latency needs"),
        ("latency=0ms@0s..1s", "above zero"),
        ("latency=50@0s..1s", "needs a unit"),
        ("latency=50ms", "needs `@START"),
        ("blackhole@5s", "needs a window"),
        ("blackhole@5s..5s", "ends before"),
        ("refuse@6s..5s", "ends before"),
        ("reset@1s..2s", "instantaneous"),
        ("refuse=3@1s..2s", "takes no argument"),
        ("explode@1s", "unknown fault"),
        ("refuse@1s..3s,refuse@2s..4s", "overlap"),
        ("blackhole@x..2s", "expected a number"),
    ];
    for (spec, needle) in cases {
        let err = FaultSchedule::parse(spec).unwrap_err();
        assert!(err.contains(needle), "{spec}: {err}");
    }
}

#[test]
fn generated_schedules_are_a_pure_function_of_the_seed() {
    let horizon = Duration::from_secs(60);
    let a = FaultSchedule::generate(42, horizon, 6).unwrap();
    assert_eq!(a, FaultSchedule::generate(42, horizon, 6).unwrap());
    assert_ne!(a, FaultSchedule::generate(43, horizon, 6).unwrap());
    assert_eq!(a.events().len(), 6);
    // one fault per 10 s slot, inside the slot, so none overlap and all end inside the horizon
    let slot = Duration::from_secs(10);
    for (i, e) in a.events().iter().enumerate() {
        let i = u32::try_from(i).unwrap();
        assert!(e.start >= slot * i, "{e:?}");
        assert!(e.end.unwrap_or(e.start) < slot * (i + 1), "{e:?}");
    }
    assert!(a.horizon() <= horizon);
    // the canonical text reads back to the same schedule
    assert_eq!(FaultSchedule::parse(&a.to_string()).unwrap(), a);
    // every seed yields a valid schedule, and different seeds exercise every fault kind
    let mut kinds = std::collections::BTreeSet::new();
    for seed in 0..40 {
        let s = FaultSchedule::generate(seed, horizon, 6).unwrap();
        assert_eq!(FaultSchedule::parse(&s.to_string()).unwrap(), s);
        kinds.extend(s.events().iter().map(|e| e.fault.name()));
    }
    assert_eq!(kinds.len(), 4, "{kinds:?}");
    assert!(FaultSchedule::generate(1, Duration::ZERO, 3).is_err());
    assert!(FaultSchedule::generate(1, horizon, 0).is_err());
    assert!(FaultSchedule::generate(1, Duration::from_millis(2), 3).is_err());
}

/// One short exchange through the proxy: connect, send, read the echo.
async fn attempt(addr: std::net::SocketAddr) -> bool {
    let exchange = async {
        let mut c = TcpStream::connect(addr).await?;
        round_trip(&mut c, b"ping").await
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), exchange).await,
        Ok(Ok(_))
    )
}

#[tokio::test]
async fn a_refuse_window_fails_connections_only_inside_the_window() {
    let upstream = echo_server().await;
    let proxy = Arc::new(Proxy::start(upstream).await.unwrap());
    let schedule = FaultSchedule::parse("refuse@300ms..800ms").unwrap();
    let origin = Instant::now();
    let driver = tokio::spawn({
        let proxy = proxy.clone();
        async move { proxy.run_schedule(&schedule, CancellationToken::new()).await }
    });
    let mut outcomes: Vec<(Duration, bool)> = Vec::new();
    while origin.elapsed() < Duration::from_millis(1300) {
        let at = origin.elapsed();
        outcomes.push((at, attempt(proxy.addr()).await));
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let applied = driver.await.unwrap();

    let failed: Vec<Duration> = outcomes.iter().filter(|(_, ok)| !ok).map(|(at, _)| *at).collect();
    assert!(failed.len() >= 5, "the window refused connections: {outcomes:?}");
    for at in &failed {
        assert!(
            *at >= Duration::from_millis(250) && *at <= Duration::from_millis(850),
            "a failure outside the window: {at:?}"
        );
    }
    let before = outcomes
        .iter()
        .filter(|(at, _)| *at < Duration::from_millis(250))
        .count();
    let after = outcomes
        .iter()
        .filter(|(at, _)| *at > Duration::from_millis(900))
        .count();
    assert!(before >= 3 && after >= 3, "{outcomes:?}");
    assert!(
        outcomes
            .iter()
            .filter(|(at, _)| *at < Duration::from_millis(250) || *at > Duration::from_millis(900))
            .all(|(_, ok)| *ok),
        "{outcomes:?}"
    );
    assert_eq!(applied.len(), 1);
    assert!(
        applied[0].start_ms >= 300 && applied[0].end_ms.unwrap() >= 800,
        "{applied:?}"
    );
    assert!(proxy.stats().refused >= u64::try_from(failed.len()).unwrap());
    Arc::try_unwrap(proxy)
        .ok()
        .expect("proxy no longer shared")
        .shutdown()
        .await;
}

#[tokio::test]
async fn a_latency_window_slows_round_trips_only_inside_the_window() {
    let upstream = echo_server().await;
    let proxy = Arc::new(Proxy::start(upstream).await.unwrap());
    let schedule = FaultSchedule::parse("latency=80ms@300ms..900ms").unwrap();
    let origin = Instant::now();
    let driver = tokio::spawn({
        let proxy = proxy.clone();
        async move { proxy.run_schedule(&schedule, CancellationToken::new()).await }
    });
    let mut tasks = tokio::task::JoinSet::new();
    while origin.elapsed() < Duration::from_millis(1400) {
        let at = origin.elapsed();
        let addr = proxy.addr();
        tasks.spawn(async move {
            let started = Instant::now();
            let ok = attempt(addr).await;
            (at, started.elapsed(), ok)
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    let mut samples = Vec::new();
    while let Some(res) = tasks.join_next().await {
        samples.push(res.unwrap());
    }
    let applied = driver.await.unwrap();

    assert!(
        samples.iter().all(|(_, _, ok)| *ok),
        "latency never fails a round trip: {samples:?}"
    );
    let inside: Vec<_> = samples
        .iter()
        .filter(|(at, ..)| *at >= Duration::from_millis(450) && *at <= Duration::from_millis(750))
        .collect();
    assert!(inside.len() >= 4, "{samples:?}");
    // one chunk each way, so a round trip costs at least twice the 80 ms delay
    assert!(
        inside
            .iter()
            .all(|(_, took, _)| *took >= Duration::from_millis(120)),
        "{inside:?}"
    );
    let outside: Vec<_> = samples
        .iter()
        .filter(|(at, ..)| *at < Duration::from_millis(250) || *at > Duration::from_millis(1000))
        .collect();
    assert!(outside.len() >= 4, "{samples:?}");
    assert!(
        outside
            .iter()
            .all(|(_, took, _)| *took < Duration::from_millis(100)),
        "{outside:?}"
    );
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].fault, Fault::Latency(Duration::from_millis(80)));
    Arc::try_unwrap(proxy)
        .ok()
        .expect("proxy no longer shared")
        .shutdown()
        .await;
}

#[tokio::test]
async fn a_blackhole_window_strands_connections_until_it_ends_and_then_resets_them() {
    let upstream = echo_server().await;
    let proxy = Arc::new(Proxy::start(upstream).await.unwrap());
    let mut held = TcpStream::connect(proxy.addr()).await.unwrap();
    assert_eq!(round_trip(&mut held, b"warm").await.unwrap(), b"warm");
    let schedule = FaultSchedule::parse("blackhole@200ms..700ms").unwrap();
    let origin = Instant::now();
    let driver = tokio::spawn({
        let proxy = proxy.clone();
        async move { proxy.run_schedule(&schedule, CancellationToken::new()).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    held.write_all(b"void").await.unwrap();
    let mut buf = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_secs(3), held.read(&mut buf))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a stranded connection ends with a reset: {read:?}"
    );
    let waited = origin.elapsed();
    assert!(
        waited >= Duration::from_millis(650) && waited < Duration::from_millis(2500),
        "the connection waited out the window, not a client timeout: {waited:?}"
    );
    let applied = driver.await.unwrap();
    assert_eq!(applied.len(), 1);
    assert!(applied[0].resets >= 1, "{applied:?}");
    assert!(
        attempt(proxy.addr()).await,
        "the proxy forwards again after the window"
    );
    Arc::try_unwrap(proxy)
        .ok()
        .expect("proxy no longer shared")
        .shutdown()
        .await;
}

#[tokio::test]
async fn cancelling_the_driver_switches_the_active_faults_off() {
    let upstream = echo_server().await;
    let proxy = Arc::new(Proxy::start(upstream).await.unwrap());
    let schedule = FaultSchedule::parse("refuse@0ms..60s").unwrap();
    let cancel = CancellationToken::new();
    let driver = tokio::spawn({
        let proxy = proxy.clone();
        let cancel = cancel.clone();
        async move { proxy.run_schedule(&schedule, cancel).await }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!attempt(proxy.addr()).await, "the refuse window is open");
    cancel.cancel();
    let applied = driver.await.unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].end_ms, None, "a window cut short has no end");
    assert!(attempt(proxy.addr()).await, "cancelling restores forwarding");
    Arc::try_unwrap(proxy)
        .ok()
        .expect("proxy no longer shared")
        .shutdown()
        .await;
}

// ---------------------------------------------------------------------------------------------
// `load` through the proxy (`load --fault`): a local stub API, no database, no network
// ---------------------------------------------------------------------------------------------

/// A stub of the routes the load generator drives; every request succeeds at once.
async fn stub_api() -> std::net::SocketAddr {
    async fn handler(req: axum::extract::Request) -> axum::response::Response {
        let body = if req.method() == axum::http::Method::POST && req.uri().path() == "/v1/crawls" {
            r#"{"id":"run-1"}"#
        } else {
            r#"{"ok":true}"#
        };
        axum::response::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap()
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, axum::Router::new().fallback(handler)).await;
    });
    addr
}

fn load_config(base: std::net::SocketAddr, secs: u64) -> crawlx_bench::load::LoadConfig {
    crawlx_bench::load::LoadConfig {
        base_url: format!("http://{base}"),
        api_key: "test-key".to_owned(),
        rps: 50.0,
        duration: Duration::from_secs(secs),
        // reads only: the stub keeps no state
        mix: crawlx_bench::load::Mix::parse("get=50,pages=30,coverage=20,create=0,events=0").unwrap(),
        runs: 2,
        ..crawlx_bench::load::LoadConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_through_a_latency_only_schedule_keeps_zero_errors_and_the_p99_gate() {
    let api = stub_api().await;
    let schedule = FaultSchedule::parse("latency=15ms@0s..2s").unwrap();
    let report = crawlx_bench::load::run_faulted(&load_config(api, 2), &schedule, None)
        .await
        .unwrap();
    let fault = report.fault.as_ref().expect("a faulted run reports the fault");
    assert!(fault.latency_only);
    assert_eq!(fault.applied.len(), 1);
    assert!(
        fault.proxy.accepted >= 1 && fault.proxy.bytes_down > 0,
        "{:?}",
        fault.proxy
    );
    assert_eq!(fault.errors_in_disruption + fault.errors_outside_disruption, 0);
    assert!(
        report.routes.values().all(|r| r.error_rate() == 0.0),
        "{report:?}"
    );
    assert!(
        report.gate_failures(500.0, false).is_empty(),
        "{:?}",
        report.gate_failures(500.0, false)
    );
    // the added latency is visible in the in-fault split and the p99 gate still applies to it
    let slowest = fault.in_fault.values().map(|r| r.p50_ms).fold(0.0, f64::max);
    assert!(
        slowest >= 30.0,
        "30 ms of added latency per round trip: {slowest}"
    );
    assert!(
        !report.gate_failures(5.0, true).is_empty(),
        "a 5 ms gate fails under 15 ms latency"
    );
    assert!(report
        .markdown()
        .contains("## faults: `latency=15ms@0ms..2000ms`"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_through_a_blackhole_confines_failures_to_the_fault_window() {
    let api = stub_api().await;
    let schedule = FaultSchedule::parse("latency=10ms@0ms..500ms,blackhole@800ms..1400ms").unwrap();
    let report = crawlx_bench::load::run_faulted(&load_config(api, 3), &schedule, None)
        .await
        .unwrap();
    let fault = report.fault.as_ref().unwrap();
    assert_eq!(fault.seed, None);
    assert!(!fault.latency_only);
    assert!(!fault.disruption_windows_ms.is_empty());
    assert!(
        fault.applied.iter().any(|a| a.fault == Fault::Blackhole),
        "{:?}",
        fault.applied
    );
    // no request fails outside a window; with the flag the run passes, without it any failure fails
    assert_eq!(fault.errors_outside_disruption, 0, "{report:?}");
    assert!(
        report.gate_failures(2000.0, true).is_empty(),
        "{:?}",
        report.gate_failures(2000.0, true)
    );
    if report.error_rate() > 0.0 {
        assert!(!report.gate_failures(2000.0, false).is_empty());
    }
    let samples: u64 = fault
        .in_fault
        .values()
        .chain(fault.out_of_fault.values())
        .map(|r| r.requests)
        .sum();
    let all: u64 = report.routes.values().map(|r| r.requests).sum();
    assert_eq!(samples, all, "every sample is in exactly one side of the split");
}

#[tokio::test]
async fn faulted_load_refuses_a_tls_base_url() {
    let schedule = FaultSchedule::parse("refuse@0s..1s").unwrap();
    let cfg = crawlx_bench::load::LoadConfig {
        base_url: "https://127.0.0.1:1".to_owned(),
        ..crawlx_bench::load::LoadConfig::default()
    };
    let err = crawlx_bench::load::run_faulted(&cfg, &schedule, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("http:// base URL"), "{err}");
}
