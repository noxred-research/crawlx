//! Shared helpers of the quality-gate modules: gym start, Chromium detection and launch,
//! worker-driven fixture runs, discovery and clicks through a raw browser context.
#![allow(dead_code)]

use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, BrowserContext, ContextConfig};
use crawlx_core::config::{CrawlMode, LaunchProfile, SafetyProfile};
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationBundle, ObservationSpec, QuiescencePolicy};
use crawlx_elements::{Candidate, CandidateDiscovery, DiscoveryConfig};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use crawlx_worker::{run_local_with, LocalRun, RunReport, Stores};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit};

/// Chromium instances running at once across this binary (see `tests/browser.rs`).
static BROWSER_SLOTS: Semaphore = Semaphore::const_new(2);

/// Acquire a browser slot; hold the permit for the life of the browser.
pub async fn browser_slot() -> SemaphorePermit<'static> {
    BROWSER_SLOTS.acquire().await.expect("semaphore is never closed")
}

/// Start a gym on an ephemeral loopback port.
pub async fn gym() -> GymHandle {
    GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap()
}

/// `true` when a Chromium executable is available; prints the skip message otherwise.
pub fn have_chromium() -> bool {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return false;
    }
    true
}

/// Launch Chromium (standard profile, unpinned allowed); `None` without an executable.
pub async fn launch() -> Option<ChromiumBackend> {
    let exe = find_executable()?;
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.launch_profile = LaunchProfile::Standard;
    cfg.allow_unpinned = true;
    match ChromiumBackend::launch(cfg.clone()).await {
        Ok(b) => Some(b),
        Err(first) => {
            eprintln!(
                "warning: launch failed ({first}); retrying once with --no-sandbox (CI containers only)"
            );
            cfg.unsafe_no_sandbox_for_ci = true;
            Some(ChromiumBackend::launch(cfg).await.expect("chromium must launch"))
        }
    }
}

/// Canonical form of an absolute URL.
pub fn canonical(url: &str) -> crawlx_core::url::CanonicalUrl {
    Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

/// Poll `cond` every 50 ms for up to `budget`.
pub async fn eventually(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A new context on `backend` navigated to the fixture entry page and settled.
pub async fn open_fixture(
    backend: &ChromiumBackend,
    gym: &GymHandle,
    manifest: &FixtureManifest,
) -> Box<dyn BrowserContext> {
    let mut ctx = backend
        .new_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    ctx.navigate(&canonical(&manifest.entry_url(&gym.base_url)))
        .await
        .unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    ctx
}

/// Settle and observe.
pub async fn observe(ctx: &mut dyn BrowserContext) -> ObservationBundle {
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    ctx.observe(ObservationSpec::default()).await.unwrap()
}

/// Settle, observe and run the discovery ladder.
pub async fn discover(ctx: &mut dyn BrowserContext) -> Vec<Candidate> {
    let bundle = observe(ctx).await;
    CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default())
}

/// DOM `id` attribute of a candidate, if any.
pub fn dom_id(c: &Candidate) -> Option<&str> {
    c.descriptor.attributes.get("id").map(String::as_str)
}

/// Native left click on the candidate whose DOM id is `id`.
pub async fn click(ctx: &mut dyn BrowserContext, cands: &[Candidate], id: &str) {
    let target = cands
        .iter()
        .find(|c| dom_id(c) == Some(id))
        .unwrap_or_else(|| panic!("{id} is discoverable"))
        .descriptor
        .locator
        .clone();
    ctx.perform(BrowserAction::Click {
        target,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    })
    .await
    .unwrap();
}

/// Everything a worker-driven fixture run leaves behind.
pub struct FixtureRun {
    /// The manifest the run crawled.
    pub manifest: FixtureManifest,
    /// The worker's report.
    pub report: RunReport,
    /// The (memory) stores the run wrote; `RunRows::collect` reads them.
    pub stores: Stores,
    /// Artifact directory; dropped with the run.
    pub _dir: tempfile::TempDir,
}

/// Run fixture `id` through `crawlx_worker::run_local_with` against `gym` in `mode` with
/// `interactions` budget under `TestEnvironment` (gym controls carry no semantics, so
/// `ReadOnly` would deny every unclassified button).
pub async fn run_fixture(
    gym: &GymHandle,
    id: &str,
    mode: CrawlMode,
    seed: u64,
    interactions: u32,
) -> FixtureRun {
    run_fixture_with(gym, id, mode, seed, interactions, |_| {}).await
}

/// [`run_fixture`] with a hook to tune the request before it runs.
pub async fn run_fixture_with(
    gym: &GymHandle,
    id: &str,
    mode: CrawlMode,
    seed: u64,
    interactions: u32,
    tune: impl FnOnce(&mut crawlx_core::config::CreateCrawl),
) -> FixtureRun {
    let manifest = FixtureManifest::embedded(id).unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, seed, SafetyProfile::TestEnvironment).unwrap();
    req.mode = mode;
    if mode == CrawlMode::Static {
        req.dynamic.enabled = false;
    }
    req.limits.interactions = interactions;
    tune(&mut req);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = Stores::open(&cfg).await.unwrap();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(req, cfg).with_stores(stores.clone()),
    ))
    .await
    .unwrap();
    assert!(report.status.is_terminal(), "{id}: {:?}", report.status);
    FixtureRun {
        manifest,
        report,
        stores,
        _dir: dir,
    }
}
