//! Opt-in runtime-diagnostics workload. Real PostgreSQL, Chromium, actor tasks, CPU pool,
//! HTTP API and remote-model transport; no request-future poll proxies.
#![cfg(feature = "runtime-diagnostics")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::routing::{get, post};
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::{ApiConfig, AppState, Repos, Scope};
use crawlx_bench::load::{LoadConfig, LoadReport, Mix};
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::repo::CrawlRun;
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock};
use crawlx_model::decision_http::{DecisionHttpConfig, DecisionHttpEngine};
use crawlx_model::{
    DecisionEngine, Instruction, ModelId, Provenance, ProvenanceTagged, StateView, TypedDecisionRequest,
    TypedQuestion,
};
use crawlx_storage::{FsArtifactStore, Pg, StoreConfig};
use crawlx_worker::actor::{SessionActor, ShutdownReason};
use crawlx_worker::pool::{BrowserPool, PoolConfig};
use crawlx_worker::runtime::diagnostics::{worker_mean_polls, RuntimeMonitor};
use crawlx_worker::{build_runtime, CpuPool, RunContext, RuntimeConfig, StateAnalyzer, Stores, WorkerConfig};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::prelude::*;

// Measure the same allocator as the production `crawlx` and `soak` executables.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[test]
#[ignore = "requires PostgreSQL, Chromium, tokio_unstable, Linux /proc; real 30-second pressure window"]
fn resource_reactor_200rps_with_saturated_browser_and_cpu_pools() {
    execute(Duration::from_secs(30), EvidenceMode::Resource);
}

#[test]
#[ignore = "requires PostgreSQL, Chromium, tokio_unstable, Linux /proc; real 10-minute measurement after warmup"]
fn resource_stalled_model_backpressure_rss_ten_minutes() {
    execute(Duration::from_secs(600), EvidenceMode::Resource);
}

#[test]
#[ignore = "requires PostgreSQL, Chromium, tokio_unstable and console client; no RSS acceptance"]
fn console_inspection_200rps_with_saturated_browser_and_cpu_pools() {
    execute(Duration::from_secs(30), EvidenceMode::ConsoleInspection);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceMode {
    Resource,
    ConsoleInspection,
}

fn execute(duration: Duration, mode: EvidenceMode) {
    // A global console subscriber and its retained pages cannot be removed between proofs.
    static EXECUTED: AtomicBool = AtomicBool::new(false);
    assert!(
        !EXECUTED.swap(true, Ordering::SeqCst),
        "run each runtime proof in a fresh process with --exact"
    );
    // Explicit execution without prerequisites fails, never silently passes as a skip.
    let db = std::env::var("CRAWLX_TEST_DATABASE_URL").expect("set CRAWLX_TEST_DATABASE_URL");
    let executable = crawlx_browser::launch::find_executable().expect("set CRAWLX_CHROMIUM_PATH");
    assert!(cfg!(target_os = "linux"), "RSS proof requires Linux /proc");
    // Subscriber owns a separate bounded aggregator runtime. Only static task names and
    // counters are exported. No page, request, credential or model payload is logged.
    static CONSOLE: std::sync::LazyLock<()> = std::sync::LazyLock::new(|| {
        let console = console_subscriber::ConsoleLayer::builder()
            .server_addr(([127, 0, 0, 1], 6669))
            .event_buffer_capacity(4096)
            .client_buffer_capacity(32)
            .retention(Duration::from_secs(5))
            .publish_interval(Duration::from_secs(1))
            .spawn();
        tracing_subscriber::registry().with(console).try_init().unwrap();
    });
    if mode == EvidenceMode::ConsoleInspection {
        std::sync::LazyLock::force(&CONSOLE);
        eprintln!("runtime proof evidence=console_inspection; RSS acceptance is a separate proof");
    } else {
        eprintln!("runtime proof evidence=resource; console inspection is a separate proof");
    }
    let runtime = build_runtime(&RuntimeConfig {
        worker_threads: NonZeroUsize::new(4),
        max_blocking_threads: NonZeroUsize::new(4).unwrap(),
        ..RuntimeConfig::default()
    })
    .unwrap();
    runtime.block_on(proof(&db, executable, duration, mode));
}

async fn rss_kib() -> u64 {
    let status = tokio::fs::read_to_string("/proc/self/status").await.unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .expect("VmRSS in /proc/self/status")
        .parse()
        .unwrap()
}

fn spawn_load(cfg: &LoadConfig, report: &std::path::Path) -> tokio::process::Child {
    // Keep request telemetry and its console task metadata outside measured worker RSS.
    tokio::process::Command::new(env!("CARGO_BIN_EXE_load"))
        .args(["--base", &cfg.base_url, "--key", &cfg.api_key])
        .args(["--rps", &cfg.rps.to_string()])
        .args(["--duration", &cfg.duration.as_secs().to_string()])
        .args([
            "--mix",
            &format!(
                "get={},pages={},coverage={},create={},events={}",
                cfg.mix.get, cfg.mix.pages, cfg.mix.coverage, cfg.mix.create, cfg.mix.events,
            ),
        ])
        .args(["--runs", &cfg.runs.to_string(), "--seed", &cfg.seed.to_string()])
        .args(["--seed-url", &cfg.seed_url])
        .args(["--max-in-flight", &cfg.max_in_flight.to_string()])
        // The proof applies its own p95/error gates after reading the complete report.
        .args(["--max-p99-ms", &f64::MAX.to_string()])
        .arg("--out")
        .arg(report)
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn proof(db: &str, executable: std::path::PathBuf, duration: Duration, mode: EvidenceMode) {
    let pg = Pg::connect(
        db,
        StoreConfig {
            schema: Some(format!("runtime_proof_{}", uuid::Uuid::now_v7().simple())),
            max_connections: 16,
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(SystemClock);
    let artifacts = Arc::new(
        FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    let repos = Repos::pg(&pg, artifacts.clone());
    let key = generate_key();
    let tenant = tenant_id_for("runtime-proof");
    repos
        .api
        .key_insert(
            &key_record(&key, tenant, Scope::all_set()).unwrap(),
            "runtime-proof",
        )
        .await
        .unwrap();
    let api_cfg = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let app = crawlx_api::router(AppState::new(
        repos,
        crawlx_api::admission_policy(&api_cfg, clock.clone()),
        api_cfg,
    ));
    let stop = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let shutdown = stop.clone();
    let api = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap();
    });

    let model_hits = Arc::new(AtomicU64::new(0));
    let effects = Arc::new(AtomicU64::new(0));
    let model_release = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hits = model_hits.clone();
    let release = model_release.clone();
    let effect_count = effects.clone();
    let fixture = axum::Router::new()
        .route("/", get(|| async { axum::response::Html(
            "<!doctype html><title>Runtime pressure</title><form method=post action=/effect><button>Delete account</button></form>"
        ) }))
        .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
        .route("/effect", post(move || { let effects = effect_count.clone(); async move {
            effects.fetch_add(1, Ordering::SeqCst); "unexpected effect"
        } }))
        .route("/model", post(move || {
            let hits = hits.clone(); let release = release.clone(); async move {
                hits.fetch_add(1, Ordering::SeqCst);
                release.cancelled().await;
                axum::Json(serde_json::json!({"answers":[{"kind":"noul","id":"blocking","p_yes":0.5}]}))
            }
        }));
    let shutdown = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, fixture)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap();
    });

    let stores = Stores::over_durable(
        crawlx_worker::DurableStore::Postgres(pg.clone()),
        artifacts.clone(),
        tenant,
    );
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{origin}/")).unwrap());
    crawl.safety.allow_private_networks = true;
    crawl.dynamic.observe_only = true;
    crawl.runs_per_role = 2;
    crawl.seed = Some(7);
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant,
        status: RunStatus::Running,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: clock.now(),
        started_at: Some(clock.now()),
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    let sessions = crawlx_scheduler::RunPlanner::sessions(run.id, &crawl);
    stores.runs.create_sessions(&sessions).await.unwrap();
    let cpu = CpuPool::with_permits(NonZeroUsize::new(2).unwrap());
    // This read-only fixture exercises actor infrastructure, not frontier gating.
    // Test-only G1 avoids requiring an installed deployment gate file; G3 remains off.
    let mut cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        checkpoint_keys: Some(Arc::new(
            crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap(),
        )),
        cpu_pool: cpu.clone(),
        contexts_per_browser: 1,
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus { g1: true, g3: false }),
        ..WorkerConfig::default()
    };
    cfg.launch.executable = executable;
    cfg.launch.allow_unpinned = true;
    cfg.launch.unsafe_no_sandbox_for_ci = std::env::var_os("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_some();
    let mut rc = RunContext::build(&run, &cfg, stores.clone(), None, None, stop.clone(), None, None)
        .await
        .unwrap();
    rc.pool = BrowserPool::new(
        cfg.launch.clone(),
        PoolConfig {
            max_browsers: 1,
            contexts_per_browser: 1,
        },
    );
    let session = &sessions[0];
    let scfg = rc.session_config(session);
    let pooled = rc
        .pool
        .acquire(scfg.context.clone(), scfg.exclusive_browser)
        .await
        .unwrap();
    let analyzer = Arc::new(StateAnalyzer::new(
        rc.run,
        session.id,
        rc.clusters.clone(),
        artifacts,
        rc.clock.clone(),
        crawl.capture.clone(),
        (&rc.controls, &rc.captcha_secrets),
    ));
    let handle = SessionActor::spawn(scfg.clone(), rc.services(), analyzer, 7, pooled)
        .await
        .unwrap();
    handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            rc.seed_url().unwrap(),
            0,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(rc.pool.available_contexts(), 0);
    assert_eq!(rc.pool.context_capacity(), 1);
    let pool = rc.pool.clone();
    let waiting_config = rc.session_config(&sessions[1]);
    let waiting_context = tokio::spawn(async move { pool.acquire(waiting_config.context, false).await });

    // All four clients await the real decision-http adapter: one HTTP call holds the only
    // guard permit; three calls queue behind it. No fake elapsed time or model engine.
    let mut model_cfg = DecisionHttpConfig::new(
        &format!("{origin}/model"),
        ModelId::new("local", "stalled", "", "proof"),
    );
    model_cfg.guard.max_concurrent = 1;
    model_cfg.guard.timeout = duration + Duration::from_secs(120);
    let engine = Arc::new(DecisionHttpEngine::new(model_cfg).unwrap());
    let mut models = JoinSet::new();
    let submitted = Arc::new(AtomicU64::new(0));
    for _ in 0..4 {
        let engine = engine.clone();
        let actor = handle.clone();
        let submitted = submitted.clone();
        models.spawn(async move {
            actor.storage_digest().await.unwrap();
            submitted.fetch_add(1, Ordering::SeqCst);
            engine
                .decide(TypedDecisionRequest {
                    goal: Instruction::from_static("Check whether this page blocks progress."),
                    state: ProvenanceTagged::new(Provenance::PageText, StateView::default()),
                    questions: vec![TypedQuestion::Noul {
                        id: "blocking".into(),
                        question: "Is this page blocking?".into(),
                    }],
                })
                .await
        });
    }
    let mut producers = JoinSet::new();
    let completed = Arc::new(AtomicU64::new(0));
    // Fixed producer count bounds both mailbox waiters and reply channels.
    for _ in 0..handle.mailbox_bound().saturating_add(4) {
        let actor = handle.clone();
        let stop = stop.clone();
        let completed = completed.clone();
        producers.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => break,
                    result = actor.storage_digest() => {
                        if stop.is_cancelled() {
                            break;
                        }
                        result.unwrap();
                        completed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }
    let mut cpu_jobs = JoinSet::new();
    for _ in 0..3 {
        let cpu = cpu.clone();
        let stop = stop.clone();
        cpu_jobs.spawn(async move {
            while !stop.is_cancelled() {
                cpu.run(|| {
                    let until = Instant::now() + Duration::from_millis(250);
                    let mut value = 7_u64;
                    while Instant::now() < until {
                        value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
                    }
                    std::hint::black_box(value)
                })
                .await
                .unwrap();
            }
        });
    }
    // Warm every route, connection, actor operation, CPU thread and allocator before RSS baseline.
    let load_cfg = LoadConfig {
        base_url,
        api_key: key,
        rps: 200.0,
        duration,
        mix: Mix {
            get: 40,
            pages: 30,
            coverage: 30,
            create: 0,
            events: 0,
        },
        runs: 3,
        max_in_flight: 64,
        ..LoadConfig::default()
    };
    let load_report_path = dir.path().join("load-report.json");
    assert!(spawn_load(
        &LoadConfig {
            duration: Duration::from_secs(5),
            ..load_cfg.clone()
        },
        &load_report_path,
    )
    .wait()
    .await
    .unwrap()
    .success());
    assert_eq!(model_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        submitted.load(Ordering::SeqCst),
        4,
        "all clients reached the real model adapter"
    );
    assert_eq!(models.len(), 4);
    assert!(
        models.try_join_next().is_none(),
        "model call completed before measurement"
    );
    assert!(!waiting_context.is_finished());
    assert_eq!(cpu.active(), 2);
    assert!(cpu.queue_depth() > 0);
    let baseline_slow = handle.task_metrics().total_slow_poll_count;
    let initial = if mode == EvidenceMode::Resource {
        rss_kib().await
    } else {
        0
    };
    let mut min_rss = initial;
    let mut max_rss = initial;
    let mut first_window = [0_u64; 30];
    let mut last_window = [0_u64; 30];
    let mut samples = 0_usize;
    let monitor = RuntimeMonitor::new(&tokio::runtime::Handle::current());
    let mut intervals = monitor.intervals();
    let metrics = tokio::runtime::Handle::current().metrics();
    let baseline_tasks = metrics.num_alive_tasks();
    let baseline_workers: [(Duration, u64); 4] = std::array::from_fn(|worker| {
        (
            metrics.worker_total_busy_duration(worker),
            metrics.worker_poll_count(worker),
        )
    });
    let mut runtime_polls = 0_u64;
    let mut worst_worker = Duration::ZERO;
    let mut max_occupancy = 0;
    let initial_completed = completed.load(Ordering::Relaxed);
    let mut previous_completed = initial_completed;
    let started = Instant::now();
    let mut load_process = spawn_load(&load_cfg, &load_report_path);
    while started.elapsed() < duration {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if mode == EvidenceMode::Resource {
            let rss = rss_kib().await;
            min_rss = min_rss.min(rss);
            max_rss = max_rss.max(rss);
            if samples < 30 {
                first_window[samples] = rss;
            }
            last_window[samples % 30] = rss;
        }
        samples = samples.saturating_add(1);
        let occupancy = handle.mailbox_bound().saturating_sub(handle.mailbox_capacity());
        max_occupancy = max_occupancy.max(occupancy);
        assert!(occupancy <= crawlx_worker::actor::MAILBOX);
        assert_eq!(model_hits.load(Ordering::SeqCst), 1);
        assert!(models.try_join_next().is_none(), "model pressure ended early");
        assert!(
            !waiting_context.is_finished(),
            "browser permit escaped saturation"
        );
        assert_eq!(rc.pool.browsers(), 1);
        assert_eq!(rc.pool.available_contexts(), 0);
        let now_completed = completed.load(Ordering::Relaxed);
        assert!(
            now_completed > previous_completed,
            "actor stopped responding during model stall"
        );
        previous_completed = now_completed;
        assert_eq!(cpu.active(), 2, "CPU pool stopped being busy");
        assert!(cpu.queue_depth() <= 3, "CPU waiters grew beyond fixed producers");
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        let snapshot = intervals.next().unwrap();
        runtime_polls = runtime_polls.saturating_add(snapshot.total_polls_count);
        assert!(
            metrics.num_alive_tasks() <= baseline_tasks.saturating_add(256),
            "live task count escaped bounded clients and producers"
        );
        for mean in worker_mean_polls(&tokio::runtime::Handle::current()) {
            worst_worker = worst_worker.max(mean);
        }
    }
    let measured = started.elapsed();
    assert!(measured >= duration, "wallclock window was shortened");
    assert!(load_process.wait().await.unwrap().success());
    let report: LoadReport =
        serde_json::from_slice(&tokio::fs::read(&load_report_path).await.unwrap()).unwrap();
    let slow_polls = handle
        .task_metrics()
        .total_slow_poll_count
        .saturating_sub(baseline_slow);
    let worker_totals: [(Duration, u64); 4] = std::array::from_fn(|worker| {
        (
            metrics
                .worker_total_busy_duration(worker)
                .saturating_sub(baseline_workers[worker].0),
            metrics
                .worker_poll_count(worker)
                .saturating_sub(baseline_workers[worker].1),
        )
    });
    // Stop and drain before asserting performance, so failure cannot strand browsers.
    stop.cancel();
    while producers.join_next().await.is_some() {}
    models.abort_all();
    while models.join_next().await.is_some() {}
    tokio::time::timeout(Duration::from_secs(5), engine.guard().run(|| async { Ok(()) }))
        .await
        .expect("cancelled model calls returned the guard permit")
        .unwrap();
    model_release.cancel();
    handle.shutdown(ShutdownReason::Completed).await.unwrap();
    let returned = tokio::time::timeout(Duration::from_secs(20), waiting_context)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (context, _, lease) = returned.into_parts();
    context.close().await.unwrap();
    lease.release(true).await.unwrap();
    while cpu_jobs.join_next().await.is_some() {}
    assert_eq!(cpu.active(), 0);
    assert_eq!(cpu.queue_depth(), 0);
    assert_eq!(rc.pool.available_contexts(), rc.pool.context_capacity());
    rc.pool.shutdown_persistent().await;
    rc.supervisor.shutdown().await;
    api.await.unwrap();
    server.await.unwrap();
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "shutdown emitted an unauthorized effect"
    );
    pg.drop_schema().await.unwrap();
    let first_window: u64 = first_window.iter().sum();
    let last_window: u64 = last_window.iter().sum();
    eprintln!("runtime proof evidence={mode:?} elapsed={measured:?} samples={samples} worker_worst_mean={worst_worker:?} actor_slow_polls={slow_polls} mailbox_peak={max_occupancy} completed={}\n{}",
        completed.load(Ordering::Relaxed).saturating_sub(initial_completed), report.markdown());
    if mode == EvidenceMode::Resource {
        eprintln!("resource RSS rss_kib_min={min_rss} rss_kib_max={max_rss} first30_sum={first_window} last30_sum={last_window}");
    }
    assert_eq!(report.dropped, 0);
    assert!(
        report.achieved_rps >= 195.0,
        "200 scheduled RPS must not degrade into a burst"
    );
    for stats in report.routes.values() {
        assert_eq!(stats.error_rate(), 0.0);
        assert!(stats.p95_ms < 150.0);
    }
    assert!(worst_worker < Duration::from_millis(1));
    assert!(runtime_polls > 0, "runtime monitor collected no polls");
    for (worker, (busy, polls)) in worker_totals.iter().enumerate() {
        assert!(*polls > 0, "worker {worker} performed no measured polls");
        // Busy time includes scheduler overhead, so this arithmetic ratio is stricter
        // than pure poll duration. It complements Tokio's per-worker mean estimates.
        assert!(
            busy.as_nanos() / u128::from(*polls) < 1_000_000,
            "worker {worker}: busy={busy:?}, polls={polls}"
        );
    }
    assert_eq!(slow_polls, 0, "actor poll exceeded 10ms outside await");
    assert!(completed.load(Ordering::Relaxed) > initial_completed);
    assert_eq!(
        max_occupancy,
        handle.mailbox_bound(),
        "mailbox never reached its configured bound"
    );
    if mode == EvidenceMode::Resource {
        // RSS is allocator/process noise, not exact byte equality. Fixed 8MiB spread and
        // 2MiB first/last-window mean drift are explicit proof tolerances, not sampled maxima only.
        assert!(
            max_rss.saturating_sub(min_rss) <= 8192,
            "RSS spread exceeded 8MiB"
        );
        if duration >= Duration::from_secs(600) {
            assert!(
                last_window <= first_window.saturating_add(30 * 2048),
                "RSS mean grew more than 2MiB"
            );
        }
    }
}

#[path = "../../crawlx-worker/tests/common/authorization.rs"]
mod url_filter_authorization;

mod url_filter {
    use super::*;
    use crawlx_bench::worker_exec::{authorize_fixture, crawl_request_for_url, worker_config_with};
    use crawlx_core::config::{CrawlMode, SafetyProfile, StrategyName, System1Mode};
    use crawlx_url::{CanonicalizeOptions, Canonicalizer, TrailingSlash};
    use crawlx_worker::fixture_evaluation::FixtureEvaluationHost;
    use crawlx_worker::{run_local_with, LocalRun};
    use tokio::sync::{mpsc, oneshot};

    const WINDOW: Duration = Duration::from_secs(10);
    const FLOOR: u128 = 100_000;

    #[derive(Debug)]
    struct Measurement {
        urls: u64,
        elapsed: Duration,
        browser_documents: [u64; 3],
        midpoint: Duration,
        checksum: u8,
    }

    impl Measurement {
        fn rate(&self) -> f64 {
            self.urls as f64 / self.elapsed.as_secs_f64()
        }

        fn meets_floor(&self) -> bool {
            u128::from(self.urls) * 1_000_000_000 >= FLOOR * self.elapsed.as_nanos()
        }
    }

    // Keep this corpus identical to crawlx-url/benches/canonicalize.rs::short_urls(1_000).
    // Corpus construction is outside both measured windows; classification stays inside.
    fn short_urls() -> Vec<String> {
        (0..1_000)
            .map(|i| match i % 4 {
                0 => format!(
                    "https://Example.com:443/shop/item/{i}?utm_source=x&id={i}&page={}#f",
                    i % 13
                ),
                1 => format!("/docs/guide-{}/../page-{i}/", i % 7),
                2 => format!("https://example.com/a/b/c/{i}?sort=price&ref=abc{i}&sessionid=deadbeef{i}"),
                _ => format!("https://sub.example.com/blog/{}/post-{i}.html?id={i}", i % 23),
            })
            .collect()
    }

    fn filter_batch(urls: &[String], base: &url::Url, opts: &CanonicalizeOptions) -> u8 {
        let mut checksum = 0;
        for raw in urls {
            let canonical = Canonicalizer::canonicalize(std::hint::black_box(raw), base, opts).unwrap();
            checksum ^= canonical.key.0[0];
            std::hint::black_box(canonical);
        }
        std::hint::black_box(checksum)
    }

    fn measure(
        urls: &[String],
        base: &url::Url,
        opts: &CanonicalizeOptions,
        documents: &AtomicU64,
    ) -> Measurement {
        let started = Instant::now();
        let mut browser_documents = [documents.load(Ordering::SeqCst); 3];
        let mut midpoint = None;
        let mut count = 0_u64;
        let mut checksum = 0;
        loop {
            checksum ^= filter_batch(urls, base, opts);
            count = count.checked_add(u64::try_from(urls.len()).unwrap()).unwrap();
            let elapsed = started.elapsed();
            if midpoint.is_none() && elapsed >= WINDOW / 2 {
                browser_documents[1] = documents.load(Ordering::SeqCst);
                midpoint = Some(started.elapsed());
            }
            if elapsed >= WINDOW {
                break;
            }
        }
        browser_documents[2] = documents.load(Ordering::SeqCst);
        let elapsed = started.elapsed();
        Measurement {
            urls: count,
            elapsed,
            browser_documents,
            midpoint: midpoint.unwrap(),
            checksum: std::hint::black_box(checksum),
        }
    }

    // Alphabetic page names and labels keep each next-link destination distinct without
    // relying on numeric text surviving state normalization. The chain has exactly 1,000 pages.
    fn page_word(mut index: u16) -> String {
        let mut word = [b'a'; 4];
        for byte in word.iter_mut().rev() {
            *byte += u8::try_from(index % 26).unwrap();
            index /= 26;
        }
        String::from_utf8(word.to_vec()).unwrap()
    }

    fn page_index(word: &str) -> Option<u16> {
        if word.len() != 4 || !word.bytes().all(|byte| byte.is_ascii_lowercase()) {
            return None;
        }
        word.bytes().try_fold(0_u16, |index, byte| {
            index.checked_mul(26)?.checked_add(u16::from(byte - b'a'))
        })
    }

    #[test]
    #[ignore = "optimized timing gate; requires PostgreSQL, Chromium and fresh --exact process"]
    fn managed_browser_keeps_single_filter_worker_above_100k_urls_per_second() {
        assert!(!cfg!(debug_assertions), "build this timing gate with --release");
        assert!(
            std::env::args().any(|arg| arg == "--exact"),
            "run this timing gate alone in a fresh process with --exact"
        );
        let db = std::env::var("CRAWLX_TEST_DATABASE_URL").expect("set CRAWLX_TEST_DATABASE_URL");
        let executable = std::env::var_os("CRAWLX_CHROMIUM_PATH")
            .map(std::path::PathBuf::from)
            .expect("set CRAWLX_CHROMIUM_PATH");
        assert!(executable.is_file(), "CRAWLX_CHROMIUM_PATH must name Chromium");
        let runtime = build_runtime(&RuntimeConfig {
            worker_threads: NonZeroUsize::new(4),
            max_blocking_threads: NonZeroUsize::new(4).unwrap(),
            ..RuntimeConfig::default()
        })
        .unwrap();
        runtime.block_on(browser_filter_proof(&db, executable));
    }

    async fn browser_filter_proof(db: &str, executable: std::path::PathBuf) {
        let documents = Arc::new(AtomicU64::new(0));
        let filter_documents = documents.clone();
        let (requests, mut receiver) = mpsc::channel::<oneshot::Sender<Measurement>>(1);
        // Both windows run on this same OS thread, not on a parallel iterator or Tokio pool.
        // Wall time includes scheduling pauses. This is not a CPU-affinity guarantee.
        let filter = std::thread::Builder::new()
            .name("mode-url-filter".into())
            .spawn(move || {
                let urls = short_urls();
                let base = url::Url::parse("https://example.com/shop/").unwrap();
                let opts = CanonicalizeOptions::default();
                filter_batch(&urls, &base, &opts);
                for _ in 0..2 {
                    let Some(reply) = receiver.blocking_recv() else {
                        break;
                    };
                    reply
                        .send(measure(&urls, &base, &opts, &filter_documents))
                        .unwrap();
                }
            })
            .unwrap();
        let (reply, result) = oneshot::channel();
        requests.send(reply).await.unwrap();
        let baseline = result.await.unwrap();
        assert_eq!(baseline.browser_documents, [0; 3]);

        let host = FixtureEvaluationHost::bind().unwrap();
        let listener = tokio::net::TcpListener::from_std(host.listener().unwrap()).unwrap();
        let server_stop = CancellationToken::new();
        let shutdown = server_stop.clone();
        let hits = documents.clone();
        let fixture = axum::Router::new()
            .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
            .route(
                "/url-throughput/{word}",
                get(move |axum::extract::Path(word): axum::extract::Path<String>,
                          headers: axum::http::HeaderMap| {
                    let hits = hits.clone();
                    async move {
                        let index = page_index(&word).filter(|index| *index < 1_000).unwrap();
                        // Pace the finite chain so its normalized depth-100 bound cannot
                        // exhaust before the ten-second concurrent window completes.
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        // Only document navigations count. Robots, favicon, HTTP URL-plane
                        // requests and background browser traffic cannot satisfy this witness.
                        if headers.get("sec-fetch-dest").is_some_and(|v| v == "document")
                            && headers.get("sec-fetch-mode").is_some_and(|v| v == "navigate")
                        {
                            hits.fetch_add(1, Ordering::SeqCst);
                        }
                        let next = if index < 999 {
                            let next = page_word(index.checked_add(1).unwrap());
                            format!("<a href=\"/url-throughput/{next}\">Continue {next}</a>")
                        } else {
                            String::new()
                        };
                        (
                            [(axum::http::header::CACHE_CONTROL, "no-store")],
                            axum::response::Html(format!(
                                "<!doctype html><title>Chapter {word}</title><main><h1>Chapter {word}</h1>{next}</main>"
                            )),
                        )
                    }
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, fixture)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await
                .unwrap();
        });
        let pg = Pg::connect(
            db,
            StoreConfig {
                schema: Some(format!("url_filter_proof_{}", uuid::Uuid::now_v7().simple())),
                max_connections: 8,
                ..StoreConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let artifacts = Arc::new(
            FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), Arc::new(SystemClock))
                .await
                .unwrap()
                .with_index(Arc::new(pg.clone())),
        );
        let stores = Stores::over_durable(
            crawlx_worker::DurableStore::Postgres(pg.clone()),
            artifacts,
            crawlx_core::TenantId::new(),
        );
        let mut cfg = worker_config_with(TrailingSlash::Keep, dir.path()).unwrap();
        cfg.launch.executable = executable;
        cfg.launch.unsafe_no_sandbox_for_ci = std::env::var_os("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_some();
        cfg.contexts_per_browser = 1;
        cfg.gates = crawlx_worker::Gates::none();
        cfg.checkpoint_keys = Some(Arc::new(
            crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap(),
        ));
        let mut crawl = crawl_request_for_url(
            host.origin().join("url-throughput/aaaa").unwrap(),
            7,
            SafetyProfile::ReadOnly,
        );
        crawl.mode = CrawlMode::Dynamic;
        crawl.dynamic.enabled = true;
        crawl.dynamic.observe_only = true;
        crawl.scope.max_discovery_depth = 100;
        // The seed is one chapter, not the parent directory. Default seed-descendant
        // scope would reject its sibling chapters after the first observation.
        crawl.scope.include_paths = vec!["^/url-throughput/[a-z]{4}$".into()];
        crawl.dynamic.system1_mode = System1Mode::Off;
        crawl.dynamic.strategies = vec![StrategyName::InteractionBfs];
        crawl.limits.interactions = 1_000;
        crawl.limits.states = 1_000;
        crawl.limits.urls = 1_000;
        crawl.limits.duration_seconds = 90;
        crawl.normalize().unwrap();
        let worker_stop = CancellationToken::new();
        let mut local = authorize_fixture(
            LocalRun::new(crawl, cfg)
                .with_stores(stores)
                .with_cancel(worker_stop.clone()),
        );
        let record = local.authorization.as_mut().unwrap();
        record.authorized_networks = vec!["127.0.0.1/32".parse().unwrap()];
        // PostgreSQL deliberately ignores lifecycle fields in the immutable record body.
        // Use the existing fixture protocol to mark authoritative custody verified too.
        super::url_filter_authorization::register_verified(&pg, record).await;
        let permit = host.permit("url-throughput", &local.crawl, record).unwrap();
        let mut browser = tokio::spawn(run_local_with(local.with_fixture_evaluation(permit)));
        let warmup = tokio::time::timeout(Duration::from_secs(45), async {
            while documents.load(Ordering::SeqCst) < 3 {
                tokio::select! {
                    outcome = &mut browser => return Some(outcome),
                    () = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
            }
            None
        })
        .await;
        if !matches!(&warmup, Ok(None)) {
            worker_stop.cancel();
            let timed_out = warmup.is_err();
            let outcome = match warmup {
                Ok(Some(outcome)) => Some(outcome),
                Err(_) => tokio::time::timeout(Duration::from_secs(30), &mut browser)
                    .await
                    .ok(),
                Ok(None) => unreachable!("successful warmup handled above"),
            };
            let diagnostic = format!("{outcome:#?}");
            eprintln!(
                "managed browser warmup failed timed_out={timed_out} documents={} worker={diagnostic}",
                documents.load(Ordering::SeqCst),
            );
            drop(requests);
            filter.join().unwrap();
            server_stop.cancel();
            host.scope().revoke();
            server.await.unwrap();
            pg.drop_schema().await.unwrap();
            panic!("managed browser warmup failed: timed_out={timed_out}; worker={diagnostic}");
        }
        let (reply, result) = oneshot::channel();
        requests.send(reply).await.unwrap();
        let concurrent = result.await.unwrap();
        let browser_still_running = !browser.is_finished();
        drop(requests);
        filter.join().unwrap();
        worker_stop.cancel();
        let report = tokio::time::timeout(Duration::from_secs(30), browser)
            .await
            .expect("managed browser did not stop")
            .unwrap()
            .unwrap();
        server_stop.cancel();
        host.scope().revoke();
        server.await.unwrap();
        pg.drop_schema().await.unwrap();

        eprintln!(
            "mode_url_filter evidence=shared_host_wall_time single_filter_thread=true affinity_guaranteed=false \
             corpus=canonicalize_classify_short_urls_1000 baseline={baseline:?} concurrent={concurrent:?} \
             baseline_urls_per_second={} concurrent_urls_per_second={} concurrent_to_baseline={} \
             browser_launches={} actions={} states={} floor_urls_per_second=100000",
            baseline.rate(),
            concurrent.rate(),
            concurrent.rate() / baseline.rate(),
            report.browser_launches,
            report.actions.len(),
            report.states.len(),
        );
        std::hint::black_box((baseline.checksum, concurrent.checksum));
        assert!(report.browser_launches > 0, "no managed Chromium launch");
        assert!(
            report.states.len() >= 3,
            "managed actor did not persist observed browser states"
        );
        assert!(browser_still_running, "browser workload ended during filtering");
        let [before, middle, after] = concurrent.browser_documents;
        assert!(
            middle.saturating_sub(before) >= 2,
            "no first-half browser navigation progress"
        );
        assert!(
            after.saturating_sub(middle) >= 2,
            "no second-half browser navigation progress"
        );
        assert!(
            concurrent.midpoint < concurrent.elapsed,
            "no second observation interval"
        );
        assert!(
            baseline.meets_floor(),
            "baseline canonicalize+classification below 100000 URLs/s"
        );
        assert!(
            concurrent.meets_floor(),
            "concurrent canonicalize+classification below 100000 URLs/s"
        );
    }
}
