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
