//! The rig of the tests that stall or kill a worker in the middle of a URL batch
//! (`resume_frontier.rs`, `url_lease_heartbeat.rs`): a site that answers slowly or parks requests
//! at a gate, the in-memory store or one throwaway PostgreSQL schema, a worker on a runtime of
//! its own that dies when the runtime is dropped, and a fleet reaper that runs every 100 ms.
//!
//! The worker runs on a runtime of its own; dropping the runtime kills it without any cleanup,
//! the in-process equivalent of `SIGKILL`.
//!
//! PostgreSQL variants use `CRAWLX_TEST_DATABASE_URL` and skip without it.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::common::authorization as authorization_fixture;

use axum::extract::{Path as UrlPath, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::counters::{Counters, PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::repo::{CrawlRun, FrontierEntry, FrontierStatus};
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use crawlx_scheduler::{Reaper, ReaperConfig, RunPlanner};
use crawlx_storage::checkpoint_crypto::{CheckpointKeys, MemoryCheckpointKeys};
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, StoreConfig};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{EgressConfig, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Rows leased per batch, explicitly requested by this fixture's admission capacity.
pub const BATCH: usize = 16;
/// URL batch lease TTL of the stores under test (production: 60 s).
pub const URL_TTL: Duration = Duration::from_secs(2);
/// Period of the fleet's reaper (production: 15 s).
pub const REAP_EVERY: Duration = Duration::from_millis(100);

// ---- the site ------------------------------------------------------------------------------

/// What the site looks like: the index links `pages` pages, every page takes `delay` to answer,
/// and a page links back to the index when `links_back` (a link to a URL the run already knows:
/// a duplicate sighting, which leaves no frontier row).
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub pages: usize,
    pub delay: Duration,
    pub links_back: bool,
}

impl Shape {
    /// The 41 pages of the `wire-resume` differential family: the index, then 16 + 16 + 8 pages.
    pub const fn wire_resume() -> Self {
        Self {
            pages: 40,
            delay: Duration::from_millis(20),
            links_back: true,
        }
    }

    /// The same site without the links back to the index: no page sees a duplicate, so the URL
    /// counters are a function of the frontier rows alone.
    pub const fn no_back_links() -> Self {
        Self {
            links_back: false,
            ..Self::wire_resume()
        }
    }

    /// Every path of the site, sorted.
    pub fn paths(&self) -> Vec<String> {
        let mut v: Vec<String> = std::iter::once("/".to_owned())
            .chain((1..=self.pages).map(|n| format!("/p/{n}")))
            .collect();
        v.sort();
        v
    }
}

/// What the site answers and what it saw.
struct Shared {
    shape: Shape,
    /// Requests per path.
    hits: Mutex<BTreeMap<String, u32>>,
    /// `/p/*` requests received.
    started: AtomicUsize,
    /// `/p/*` requests answered before the gate parks the next one.
    allowed: AtomicUsize,
    /// Requests parked at the gate.
    parked: AtomicUsize,
    /// Parked requests are released and nothing parks any more.
    open: AtomicBool,
}

pub struct Site {
    pub base: String,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    /// A site that parks the `/p/*` request after the first `allowed`.
    pub async fn start(shape: Shape, allowed: usize) -> Self {
        let shared = Arc::new(Shared {
            shape,
            hits: Mutex::new(BTreeMap::new()),
            started: AtomicUsize::new(0),
            allowed: AtomicUsize::new(allowed),
            parked: AtomicUsize::new(0),
            open: AtomicBool::new(false),
        });
        let app = Router::new()
            .route("/", get(index))
            .route("/p/{n}", get(page))
            .with_state(Arc::clone(&shared));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { base, shared, task }
    }

    pub fn hits(&self, path: &str) -> u32 {
        self.shared.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }

    /// Wait until a request is parked at the gate.
    pub async fn parked(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.shared.parked.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "no request reached the gate");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Release the parked requests and park nothing from now on.
    pub fn open(&self) {
        self.shared.open.store(true, Ordering::SeqCst);
    }
}

fn html(body: String) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
}

async fn index(State(s): State<Arc<Shared>>) -> impl IntoResponse {
    *s.hits.lock().unwrap().entry("/".to_owned()).or_default() += 1;
    let links: String = (1..=s.shape.pages)
        .map(|n| format!(r#"<a href="/p/{n}">Page {n}</a> "#))
        .collect();
    html(format!(
        "<html><head><title>Index</title></head><body><main><h1>Index</h1><p>{} pages.</p>{links}</main></body></html>",
        s.shape.pages
    ))
}

async fn page(State(s): State<Arc<Shared>>, UrlPath(n): UrlPath<usize>) -> impl IntoResponse {
    *s.hits.lock().unwrap().entry(format!("/p/{n}")).or_default() += 1;
    let ordinal = s.started.fetch_add(1, Ordering::SeqCst);
    if ordinal >= s.allowed.load(Ordering::SeqCst) {
        s.parked.fetch_add(1, Ordering::SeqCst);
        while !s.open.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    tokio::time::sleep(s.shape.delay).await;
    let back = if s.shape.links_back {
        r#"<a href="/">Index</a>"#
    } else {
        ""
    };
    html(format!(
        r#"<html><head><title>Page {n}</title></head><body><main><h1>Page {n}</h1><p>Text that only page {n} has.</p>{back}</main></body></html>"#
    ))
}

// ---- where the run lives -------------------------------------------------------------------

/// The in-memory store, or one throwaway PostgreSQL schema.
#[derive(Clone)]
enum Backing {
    Memory(Arc<MemoryStore>),
    Pg {
        url: String,
        schema: String,
        admin: Pg,
        /// Explicit process-local custody shared across killed and restarted worker runtimes.
        checkpoint_keys: Arc<dyn CheckpointKeys>,
    },
}

/// A backing plus the tenant and the stored authorization record the runs refer to.
#[derive(Clone)]
pub struct Rig {
    backing: Backing,
    tenant: TenantId,
    record: AuthorizationRecord,
}

impl Rig {
    pub fn memory() -> Self {
        let tenant = TenantId::new();
        Self {
            backing: Backing::Memory(Arc::new(
                MemoryStore::new().with_ttls(Duration::from_secs(30), URL_TTL),
            )),
            tenant,
            record: loopback_record(tenant),
        }
    }

    /// `None` without `CRAWLX_TEST_DATABASE_URL`.
    pub async fn pg() -> Option<Self> {
        let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
            return None;
        };
        let schema = format!("t_resume_{}", uuid::Uuid::now_v7().simple());
        let admin = Pg::connect(&url, pg_config(&schema)).await.unwrap();
        admin.migrate().await.unwrap();
        let tenant = TenantId::new();
        admin.ensure_tenant(tenant, "resume-frontier").await.unwrap();
        let record = loopback_record(tenant);
        authorization_fixture::register_verified(&admin, &record).await;
        Some(Self {
            backing: Backing::Pg {
                url,
                schema,
                admin,
                checkpoint_keys: Arc::new(MemoryCheckpointKeys::new().unwrap()),
            },
            tenant,
            record,
        })
    }

    /// Stores over this backing. For PostgreSQL every call opens its own pool in the calling
    /// runtime, so a worker that runs (and is killed) on a runtime of its own leaves no
    /// connection behind that the survivors would reuse.
    /// Both backings expose the verified record so lease-time authorization survives restart.
    pub async fn stores(&self, dir: &Path) -> Stores {
        match &self.backing {
            Backing::Memory(store) => {
                let mut stores = Stores::over_memory(Arc::clone(store), dir).await.unwrap();
                stores.tenant = self.tenant;
                // Restarted workers must re-read the same verified record as PostgreSQL workers.
                stores.authorization = Some(Arc::new(crawlx_worker::StaticAuthorizationSource::new(
                    self.record.clone(),
                )));
                stores
            }
            Backing::Pg {
                url,
                schema,
                checkpoint_keys,
                ..
            } => {
                let pg = Pg::connect(url, pg_config(schema)).await.unwrap();
                let runs: Arc<dyn crawlx_core::repo::RunRepo> = Arc::new(pg.clone());
                let artifacts = FsArtifactStore::open(dir, runs, Arc::new(SystemClock))
                    .await
                    .unwrap()
                    .with_index(Arc::new(pg.clone()));
                let mut stores = Stores::over_durable(
                    crawlx_worker::DurableStore::Postgres(pg),
                    Arc::new(artifacts),
                    self.tenant,
                );
                stores.checkpoint_keys = Arc::clone(checkpoint_keys);
                stores
            }
        }
    }

    /// The holder of every session of `run` stopped heartbeating an hour ago; its URL batch
    /// leases are untouched.
    pub async fn expire_session_leases(&self, stores: &Stores, run: CrawlRunId) {
        match &self.backing {
            Backing::Memory(store) => {
                for s in stores.runs.list_sessions(run).await.unwrap() {
                    store.expire_session_lease(s.id, SystemClock.now() - chrono::Duration::hours(1));
                }
            }
            Backing::Pg { admin, .. } => {
                sqlx::query(
                    "UPDATE crawl_sessions SET lease_expires_at = now() - interval '1 hour' WHERE run_id = $1",
                )
                .bind(run.0)
                .execute(admin.pool())
                .await
                .unwrap();
            }
        }
    }

    pub async fn teardown(self) {
        if let Backing::Pg { admin, .. } = self.backing {
            admin.drop_schema().await.unwrap();
        }
    }
}

fn pg_config(schema: &str) -> StoreConfig {
    StoreConfig {
        schema: Some(schema.to_owned()),
        url_batch_ttl: URL_TTL,
        ..StoreConfig::default()
    }
}

/// A record that authorizes the loopback sites of the tests.
fn loopback_record(tenant: TenantId) -> AuthorizationRecord {
    let now = SystemClock.now();
    AuthorizationRecord {
        url_prefixes: vec!["http://127.0.0.1".to_owned()],
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        valid_from: now - chrono::Duration::days(1),
        valid_to: now + chrono::Duration::days(1),
        verified_at: Some(now),
        ..sample_record(tenant, now, &[])
    }
}

pub fn worker_cfg(dir: &Path, idle_exit_after: Option<Duration>) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        idle_exit_after,
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

/// What the API does: persist a queued static run and its sessions.
pub async fn enqueue(
    rig: &Rig,
    stores: &Stores,
    base: &str,
    tweak: impl FnOnce(&mut CreateCrawl),
) -> CrawlRunId {
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_029);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(rig.record.id);
    crawl.politeness.delay_ms = 0;
    crawl.politeness.max_concurrency = u16::try_from(BATCH).unwrap();
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    tweak(&mut crawl);
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: rig.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    run.id
}

// ---- the workers ---------------------------------------------------------------------------

/// A worker on a runtime of its own: dropping the runtime kills it without cleanup.
pub struct Doomed(Option<tokio::runtime::Runtime>);

impl Doomed {
    pub fn start(rig: &Rig, dir: PathBuf, cancel: CancellationToken) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let rig = rig.clone();
        runtime.spawn(async move {
            let stores = rig.stores(&dir).await;
            let _ = run_with(worker_cfg(&dir, None), stores, None, cancel).await;
        });
        Self(Some(runtime))
    }

    /// `SIGKILL`: every task of the worker is dropped where it stands.
    pub fn kill(mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// A worker that serves until it has been idle for a moment.
pub async fn finish(rig: &Rig, dir: &Path) {
    let stores = rig.stores(dir).await;
    run_with(
        worker_cfg(dir, Some(Duration::from_millis(800))),
        stores,
        None,
        CancellationToken::new(),
    )
    .await
    .unwrap();
}

/// What the fleet's reaper did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reaped {
    /// Expired URL leases returned to `pending`.
    pub requeued: u64,
    /// Expired URL leases failed for want of attempts.
    pub failed: u64,
}

/// What any worker of the fleet does every 15 s, here every 100 ms, with a tally of what it
/// found.
pub struct FleetReaper {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    requeued: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

pub fn fleet_reaper(stores: &Stores) -> FleetReaper {
    let cancel = CancellationToken::new();
    let requeued = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let reaper = Reaper::new(
        Arc::clone(&stores.leases),
        Arc::clone(&stores.journal),
        ReaperConfig {
            interval: REAP_EVERY,
            ..ReaperConfig::default()
        },
    );
    let task = {
        let (cancel, requeued, failed) = (cancel.clone(), Arc::clone(&requeued), Arc::clone(&failed));
        tokio::spawn(async move {
            while !cancel.is_cancelled() {
                if let Ok(swept) = reaper.run_once().await {
                    requeued.fetch_add(swept.urls_requeued, Ordering::SeqCst);
                    failed.fetch_add(swept.urls_failed, Ordering::SeqCst);
                }
                tokio::select! {
                    () = tokio::time::sleep(REAP_EVERY) => {}
                    () = cancel.cancelled() => {}
                }
            }
        })
    };
    FleetReaper {
        cancel,
        task,
        requeued,
        failed,
    }
}

impl FleetReaper {
    /// What it has returned so far.
    pub fn reaped(&self) -> Reaped {
        Reaped {
            requeued: self.requeued.load(Ordering::SeqCst),
            failed: self.failed.load(Ordering::SeqCst),
        }
    }

    /// Stop sweeping.
    pub async fn stop(self) -> Reaped {
        self.cancel.cancel();
        let _ = self.task.await;
        Reaped {
            requeued: self.requeued.load(Ordering::SeqCst),
            failed: self.failed.load(Ordering::SeqCst),
        }
    }
}

// ---- observations --------------------------------------------------------------------------

/// The frontier rows by status, as `status n` pairs.
pub fn by_state(rows: &[FrontierEntry]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for r in rows {
        *m.entry(r.status.as_str()).or_default() += 1;
    }
    m
}

pub async fn frontier(stores: &Stores, run: CrawlRunId) -> Vec<FrontierEntry> {
    stores.frontier.list(run).await.unwrap()
}

pub async fn page_paths(stores: &Stores, run: CrawlRunId) -> Vec<String> {
    let mut v: Vec<String> = stores
        .pages
        .list(run)
        .await
        .unwrap()
        .iter()
        .map(|p| p.url.url.path().to_owned())
        .collect();
    v.sort();
    v
}

/// Wait until `run` is terminal.
pub async fn terminal(stores: &Stores, run: CrawlRunId) -> CrawlRun {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let row = stores.runs.get(run).await.unwrap();
        if row.status.is_terminal() {
            return row;
        }
        assert!(
            Instant::now() < deadline,
            "the run never finished: {:?}",
            row.status
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// An uninterrupted crawl of a site of `shape` on `rig`: the page set and the URL counters to
/// match.
pub async fn uninterrupted(rig: &Rig, shape: Shape) -> (Vec<String>, Counters) {
    let site = Site::start(shape, usize::MAX).await;
    let dir = tempfile::tempdir().unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(rig, &stores, &site.base, |_| {}).await;
    finish(rig, dir.path()).await;
    let row = terminal(&stores, run).await;
    assert_eq!(row.terminal_reason, Some(TerminalReason::FrontierExhausted));
    let rows = frontier(&stores, run).await;
    assert_eq!(
        by_state(&rows),
        BTreeMap::from([("succeeded", shape.pages + 1)]),
        "{rows:?}"
    );
    (page_paths(&stores, run).await, row.counters.urls)
}

/// Every row of `rows` is `succeeded`.
pub fn all_succeeded(rows: &[FrontierEntry]) -> bool {
    rows.iter().all(|r| r.status == FrontierStatus::Succeeded)
}
