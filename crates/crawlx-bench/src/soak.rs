//! `soak`: repeated worker crawls of a gym fixture set for hours, with resource sampling and
//! the trail invariants checked after every cycle.
//!
//! `N` worker loops share one store (PostgreSQL through `Stores::over_pg`, or a fresh
//! `MemoryStore` per cycle) and crawl the fixture set round-robin through
//! `crawlx_worker::run_local_with`, over real Chromium against an in-process gym or over
//! `FakeBackend` scripted from the manifests (`--fake`). A sampler records every
//! `sample_interval` the RSS of this process and of its whole process tree (Chromium is a
//! child), the `sqlx` pool size, and the cycle counters. After every cycle `verify_trail`
//! runs and the journal is checked for stuck `intended` and unreconciled `unknown` rows and
//! for sessions still holding a lease — the "auditor" run per cycle instead of
//! on a timer. With `fault_every` set and PostgreSQL in use, the database traffic goes
//! through [`crate::netfault::Proxy`] and a seeded schedule injects one fault per period
//! (connection resets, added latency, a short blackhole).
//!
//! The report carries p50/p95/max of the tree RSS, the cycle and failure counts, the leak
//! slope (least-squares fit of this process's RSS over time, bytes per hour; the tree's slope
//! is reported alongside) and a verdict against [`SoakConfig::max_slope_bytes_per_hour`]
//! (planning default 32 MiB/h).
//!
//! Public admission authenticates the full default strategy workload before creating any
//! output, gym or schema. The admitted worker configuration is held for every cycle;
//! authored unit fixtures use a private execution seam, not deployment gate evidence.

use crate::ablation;
use crate::error::BenchError;
use crate::gym::manifest::FixtureManifest;
use crate::gym::{GymHandle, GymServer};
use crate::netfault::{self, Proxy};
use crate::stats::quantile;
use crate::trail::{verify_trail, TrailStore};
use crate::worker_exec::{crawl_request, worker_config};
use crawlx_browser::FakeBackend;
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ActionJournal, RunRepo, SessionStatus};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{Clock as _, SystemClock, TenantId, WorkerId};
use crawlx_policy::authorization::{AuthorizationRecord, Evidence};
use crawlx_policy::testkit::sample_record;
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, PgConfig};
use crawlx_worker::{run_local_with, LocalRun, Stores, WorkerConfig};
use rand::Rng as _;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Fixture set crawled by default: the D1 set (`g1-report` uses the same).
pub const DEFAULT_FIXTURES: [&str; 9] = ["d1", "g01", "g02", "g03", "g04", "g05", "g06", "g07", "g08"];

/// Leak-slope ceiling (planning default): 32 MiB of tree RSS per hour.
pub const DEFAULT_MAX_SLOPE_BYTES_PER_HOUR: f64 = 32.0 * 1024.0 * 1024.0;

/// Fewer samples than this leave the leak verdict `inconclusive`.
const MIN_SAMPLES_FOR_SLOPE: usize = 10;

/// Browser the cycles run on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoakBackend {
    /// Real Chromium (`CRAWLX_CHROMIUM_PATH`) against an in-process gym.
    Chromium,
    /// `FakeBackend` scripted from the fixture manifests; no network, no browser.
    Fake,
}

/// Harness settings.
#[derive(Clone, Debug)]
pub struct SoakConfig {
    /// Wall-clock budget; worker loops stop starting cycles when it is spent.
    pub duration: Duration,
    /// Parallel worker loops.
    pub workers: usize,
    /// Fixture ids crawled round-robin.
    pub fixtures: Vec<String>,
    /// Browser.
    pub backend: SoakBackend,
    /// PostgreSQL URL; `None` runs every cycle on a fresh in-memory store.
    pub database_url: Option<String>,
    /// Resource sampling period.
    pub sample_interval: Duration,
    /// Base seed; cycle `i` runs with `seed + i`.
    pub seed: u64,
    /// Interaction budget per cycle.
    pub interactions: u32,
    /// Wall-clock limit of one cycle (`limits.duration_seconds`).
    pub cycle_seconds: u32,
    /// Leak-slope ceiling in bytes of tree RSS per hour.
    pub max_slope_bytes_per_hour: f64,
    /// Shortest fitted window (after the warm-up fifth) the slope is judged on; shorter runs
    /// report the slope and an `inconclusive` verdict (default 8 min: a 10-minute check).
    pub min_slope_window: Duration,
    /// One network fault per period (PostgreSQL only); `None` disables the proxy.
    pub fault_every: Option<Duration>,
    /// Keep the PostgreSQL schema after the run (for inspection).
    pub keep_schema: bool,
}

impl Default for SoakConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(24 * 3600),
            workers: 4,
            fixtures: DEFAULT_FIXTURES.iter().map(|s| (*s).to_owned()).collect(),
            backend: SoakBackend::Chromium,
            database_url: None,
            sample_interval: Duration::from_secs(30),
            seed: 20_261_020,
            interactions: 40,
            cycle_seconds: 120,
            max_slope_bytes_per_hour: DEFAULT_MAX_SLOPE_BYTES_PER_HOUR,
            min_slope_window: Duration::from_secs(8 * 60),
            fault_every: None,
            keep_schema: false,
        }
    }
}

/// One resource sample.
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
#[non_exhaustive]
pub struct Sample {
    /// Seconds since the harness started.
    pub t_s: f64,
    /// PSS of this process (bytes; RSS where `smaps_rollup` is unreadable).
    pub rss_self: u64,
    /// PSS of this process and every descendant (bytes; RSS where `smaps_rollup` is unreadable).
    pub rss_tree: u64,
    /// PSS of the descendants whose command name contains `chrom` (bytes).
    pub rss_chromium: u64,
    /// Processes in the tree (including this one).
    pub processes: u32,
    /// `sqlx` pool connections open.
    pub pool_size: u32,
    /// `sqlx` pool connections idle.
    pub pool_idle: u32,
    /// Cycles finished so far.
    pub cycles: u64,
    /// Failed cycles so far.
    pub failures: u64,
}

/// Outcome of one cycle.
#[derive(Clone, PartialEq, Debug, serde::Serialize)]
#[non_exhaustive]
pub struct Cycle {
    /// Cycle index (global across workers).
    pub index: u64,
    /// Worker loop that ran it.
    pub worker: usize,
    /// Fixture id.
    pub fixture: String,
    /// Crawl seed.
    pub seed: u64,
    /// Seconds since the harness started when the cycle began.
    pub started_s: f64,
    /// Cycle duration (ms).
    pub duration_ms: u64,
    /// Run status; `None` when the run errored before producing a report.
    pub status: Option<RunStatus>,
    /// Actions journaled.
    pub actions: u64,
    /// Pages recorded.
    pub pages: u64,
    /// Trail violations (`verify_trail`).
    pub trail_violations: u64,
    /// Actions left `intended`.
    pub stuck_intended: u64,
    /// Actions left `unknown` (unreconciled).
    pub unreconciled_unknown: u64,
    /// Sessions still non-terminal after the run, `recovering` excluded.
    pub open_sessions: u64,
    /// Sessions left `recovering`: the worker's graceful hand-over when the run is cancelled
    /// (`run_local_with` keeps a cancelled session reconcilable), a finding otherwise.
    pub recovering_sessions: u64,
    /// Error text when the run or a check failed.
    pub error: Option<String>,
}

impl Cycle {
    /// A cycle counts as failed when the worker failed, the run errored, the trail is dirty
    /// or the journal is not settled. Sessions left `recovering` are expected only when
    /// the harness budget cancelled the run.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.error.is_some()
            || self.status == Some(RunStatus::Failed)
            || self.trail_violations > 0
            || self.stuck_intended > 0
            || self.unreconciled_unknown > 0
            || self.open_sessions > 0
            || (self.recovering_sessions > 0 && self.status != Some(RunStatus::Cancelled))
    }
}

/// A scheduled network fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultKind {
    /// Every live database connection reset.
    ResetAll,
    /// 250 ms added to every chunk for 10 s.
    Latency,
    /// Bytes swallowed for 5 s (a partition); the stuck connections are reset when it heals.
    Blackhole,
}

/// A fault that was injected.
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize)]
#[non_exhaustive]
pub struct Fault {
    /// Seconds since the harness started.
    pub t_s: f64,
    /// What was injected.
    pub kind: FaultKind,
    /// Connections reset (`ResetAll`, and `Blackhole` when the partition heals).
    pub reset: u64,
}

/// Verdict of the run.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict", content = "reasons")]
pub enum Verdict {
    /// No failed cycle and the leak slope is within the ceiling.
    Pass,
    /// At least one reason.
    Fail(Vec<String>),
    /// Too few samples for a slope (short run); cycle checks still hold.
    Inconclusive(Vec<String>),
}

/// Output of [`run`].
#[derive(Clone, PartialEq, Debug, serde::Serialize)]
#[non_exhaustive]
pub struct SoakReport {
    /// Requested budget (s).
    pub duration_s: f64,
    /// Wall clock actually spent (s).
    pub elapsed_s: f64,
    /// Worker loops.
    pub workers: usize,
    /// Browser.
    pub backend: SoakBackend,
    /// `postgres` or `memory`.
    pub store: &'static str,
    /// Fixture ids.
    pub fixtures: Vec<String>,
    /// Cycles finished.
    pub cycles: u64,
    /// Cycles that failed ([`Cycle::failed`]).
    pub failures: u64,
    /// Actions journaled over every cycle.
    pub actions: u64,
    /// Cycle duration p50 (ms).
    pub cycle_p50_ms: f64,
    /// Cycle duration p95 (ms).
    pub cycle_p95_ms: f64,
    /// Tree PSS p50 (bytes).
    pub rss_p50: u64,
    /// Tree PSS p95 (bytes).
    pub rss_p95: u64,
    /// Tree PSS max (bytes).
    pub rss_max: u64,
    /// Leak slope of this process: least-squares fit of its RSS over time (bytes per hour)
    /// after the warm-up fifth of the run; `None` below [`MIN_SAMPLES_FOR_SLOPE`] samples.
    /// This is the series judged against the ceiling.
    pub leak_slope_bytes_per_hour: Option<f64>,
    /// The same fit over the whole process tree (browsers included); reported, not judged.
    pub tree_slope_bytes_per_hour: Option<f64>,
    /// Seconds of samples the slope was fitted over.
    pub slope_window_s: f64,
    /// Ceiling the slope is judged against (only when the window is at least
    /// [`SoakConfig::min_slope_window`]).
    pub max_slope_bytes_per_hour: f64,
    /// Faults injected.
    pub faults: Vec<Fault>,
    /// Proxy counters at the end (with `fault_every`).
    pub proxy: Option<netfault::ProxyStats>,
    /// The verdict.
    pub verdict: Verdict,
    /// Resource samples.
    pub samples: Vec<Sample>,
    /// Failed cycles in full; successful cycles only count.
    pub failed_cycles: Vec<Cycle>,
    /// Per-fixture cycle counts.
    pub per_fixture: BTreeMap<String, u64>,
}

impl SoakReport {
    /// Markdown summary.
    #[must_use]
    pub fn markdown(&self) -> String {
        let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
        let slope_mib = |s: Option<f64>| {
            s.map_or_else(
                || "n/a".to_owned(),
                |b| format!("{:+.2} MiB/h", b / (1024.0 * 1024.0)),
            )
        };
        let mut s = format!(
            "# soak: {} workers, {:?} backend, {} store, {:.0} s of {:.0} s\n\n",
            self.workers, self.backend, self.store, self.elapsed_s, self.duration_s
        );
        s.push_str(&format!(
            "| metric | value |\n|---|---|\n| cycles | {} |\n| failures | {} |\n| actions | {} |\n| cycle p50 / p95 | {:.0} ms / {:.0} ms |\n| tree PSS p50 / p95 / max | {:.1} / {:.1} / {:.1} MiB |\n| leak slope (this process) | {} (ceiling {:.1} MiB/h) |\n| tree slope | {} |\n| faults | {} |\n| verdict | {} |\n",
            self.cycles,
            self.failures,
            self.actions,
            self.cycle_p50_ms,
            self.cycle_p95_ms,
            mib(self.rss_p50),
            mib(self.rss_p95),
            mib(self.rss_max),
            slope_mib(self.leak_slope_bytes_per_hour),
            self.max_slope_bytes_per_hour / (1024.0 * 1024.0),
            slope_mib(self.tree_slope_bytes_per_hour),
            self.faults.len(),
            match &self.verdict {
                Verdict::Pass => "pass".to_owned(),
                Verdict::Fail(r) => format!("**fail**: {}", r.join("; ")),
                Verdict::Inconclusive(r) => format!("inconclusive: {}", r.join("; ")),
            }
        ));
        s.push_str("\n| fixture | cycles |\n|---|---|\n");
        for (f, n) in &self.per_fixture {
            s.push_str(&format!("| `{f}` | {n} |\n"));
        }
        if !self.failed_cycles.is_empty() {
            s.push_str("\n| cycle | fixture | seed | status | error |\n|---|---|---|---|---|\n");
            for c in &self.failed_cycles {
                s.push_str(&format!(
                    "| {} | `{}` | {} | {:?} | {} |\n",
                    c.index,
                    c.fixture,
                    c.seed,
                    c.status,
                    c.error.as_deref().unwrap_or("trail/journal check")
                ));
            }
        }
        s
    }
}

/// Parse `24h`, `90m`, `30s`, `1h30m`, `2h15m10s`; a bare number is seconds.
///
/// # Errors
/// A `String` naming the malformed component.
pub fn parse_duration(spec: &str) -> Result<Duration, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("empty duration".to_owned());
    }
    if let Ok(secs) = spec.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    let mut total = Duration::ZERO;
    let mut num = String::new();
    for ch in spec.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
            continue;
        }
        let n: u64 = num
            .parse()
            .map_err(|_| format!("duration `{spec}`: missing number before `{ch}`"))?;
        num.clear();
        let unit = match ch {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            other => return Err(format!("duration `{spec}`: unknown unit `{other}`")),
        };
        total += Duration::from_secs(n * unit);
    }
    if !num.is_empty() {
        return Err(format!("duration `{spec}`: trailing number without unit"));
    }
    Ok(total)
}

// ---- procfs ------------------------------------------------------------------------------

struct ProcInfo {
    ppid: u32,
    comm: String,
}

/// `(pid → parent, command)` for every readable process in `/proc`; memory is read later for
/// the tree members only (`smaps_rollup` is costly and the host runs many other processes).
fn proc_table() -> BTreeMap<u32, ProcInfo> {
    let mut table = BTreeMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return table;
    };
    for entry in dir.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ppid ...`; comm may contain spaces and parentheses
        let Some(open) = stat.find('(') else { continue };
        let Some(close) = stat.rfind(')') else { continue };
        let comm = stat[open + 1..close].to_owned();
        let mut rest = stat[close + 1..].split_whitespace();
        let Some(ppid) = rest.nth(1).and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        table.insert(pid, ProcInfo { ppid, comm });
    }
    table
}

/// Proportional set size of `pid` when `smaps_rollup` is readable (shared pages of the
/// thirty-odd Chromium processes are counted once), else its resident set size; `0` when gone.
fn memory_of(pid: u32) -> u64 {
    let proc_dir = PathBuf::from("/proc").join(pid.to_string());
    std::fs::read_to_string(proc_dir.join("smaps_rollup"))
        .ok()
        .and_then(|rollup| kib_line(&rollup, "Pss:"))
        .or_else(|| {
            std::fs::read_to_string(proc_dir.join("status"))
                .ok()
                .and_then(|status| kib_line(&status, "VmRSS:"))
        })
        .unwrap_or(0)
}

/// Value in bytes of the `<key>  NNN kB` line of a procfs file.
fn kib_line(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        l.strip_prefix(key)
            .and_then(|v| v.split_whitespace().next())
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb * 1024)
    })
}

/// RSS of `root` and its descendants: `(self, tree, chromium, processes)`.
fn tree_rss(root: u32) -> (u64, u64, u64, u32) {
    let table = proc_table();
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (pid, info) in &table {
        children.entry(info.ppid).or_default().push(*pid);
    }
    let mut stack = vec![root];
    let mut tree = 0u64;
    let mut chromium = 0u64;
    let mut processes = 0u32;
    let mut own = 0u64;
    while let Some(pid) = stack.pop() {
        if let Some(info) = table.get(&pid) {
            let bytes = memory_of(pid);
            processes += 1;
            tree += bytes;
            if pid == root {
                own = bytes;
            } else if info.comm.contains("chrom") {
                chromium += bytes;
            }
        }
        if let Some(kids) = children.get(&pid) {
            stack.extend(kids.iter().copied());
        }
    }
    (own, tree, chromium, processes)
}

// ---- harness -----------------------------------------------------------------------------

struct Progress {
    cycles: AtomicU64,
    failures: AtomicU64,
}

struct PgStore {
    pg: Pg,
    stores: Stores,
    record: AuthorizationRecord,
}

enum Store {
    Memory,
    Pg(Box<PgStore>),
}

struct Rig {
    cfg: SoakConfig,
    worker_config: WorkerConfig,
    gym: Option<GymHandle>,
    base_url: String,
    store: Store,
    scratch: PathBuf,
    started: Instant,
    progress: Progress,
    cycles: parking_lot::Mutex<Vec<Cycle>>,
}

impl Rig {
    fn elapsed_s(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// One cycle: crawl, verify the trail, audit the journal, remove the scratch artifacts.
    async fn cycle(&self, worker: usize, index: u64, cancel: &CancellationToken) -> Cycle {
        let fixture = &self.cfg.fixtures[usize::try_from(index).unwrap_or(0) % self.cfg.fixtures.len()];
        let seed = self.cfg.seed.wrapping_add(index);
        let mut out = Cycle {
            index,
            worker,
            fixture: fixture.clone(),
            seed,
            started_s: self.elapsed_s(),
            duration_ms: 0,
            status: None,
            actions: 0,
            pages: 0,
            trail_violations: 0,
            stuck_intended: 0,
            unreconciled_unknown: 0,
            open_sessions: 0,
            recovering_sessions: 0,
            error: None,
        };
        let started = Instant::now();
        let artifacts = self.scratch.join(format!("w{worker}-c{index}"));
        let result = self.crawl(fixture, seed, index, worker, &artifacts, cancel).await;
        out.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok((report, stores)) => {
                out.status = Some(report.status);
                out.actions = u64::try_from(report.actions.len()).unwrap_or(u64::MAX);
                out.pages = u64::try_from(report.pages.len()).unwrap_or(u64::MAX);
                if report.status == RunStatus::Failed {
                    out.error = Some(format!("worker run failed: {:?}", report.terminal_reason));
                }
                let mut attempt = 0u32;
                loop {
                    let result = self.audit(&report, &stores, &mut out).await;
                    attempt += 1;
                    if let Some(delay) = audit_retry_delay(&result, attempt, out.failed()) {
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    if let Err(error) = result {
                        out.error = Some(format!("audit: {}", error.chain()));
                    }
                    break;
                }
            }
            Err(e) => out.error = Some(e.chain()),
        }
        if let Err(e) = tokio::fs::remove_dir_all(&artifacts).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %artifacts.display(), error = %e, "soak: scratch not removed");
            }
        }
        out
    }

    async fn crawl(
        &self,
        fixture: &str,
        seed: u64,
        index: u64,
        worker: usize,
        artifacts: &Path,
        cancel: &CancellationToken,
    ) -> Result<(crawlx_worker::RunReport, Stores), BenchError> {
        let manifest = FixtureManifest::embedded(fixture)?;
        let mut req = crawl_request(&manifest, &self.base_url, seed, SafetyProfile::TestEnvironment)?;
        req.limits.interactions = self.cfg.interactions;
        req.limits.duration_seconds = self.cfg.cycle_seconds;
        req.limits.urls = 200;
        let mut cfg = self.worker_config.clone();
        cfg.artifacts_dir = artifacts.to_path_buf();
        cfg.trailing_slash = crate::urlplane::trailing_slash(manifest.expected.trailing_slash);
        cfg.worker_id = WorkerId::new();
        let stores = match &self.store {
            Store::Memory => Stores::over_memory(Arc::new(MemoryStore::new()), artifacts).await?,
            Store::Pg(p) => p.stores.clone(),
        };
        let mut local = LocalRun::new(req, cfg)
            .with_stores(stores.clone())
            .with_cancel(cancel.child_token());
        match self.cfg.backend {
            SoakBackend::Chromium => {}
            SoakBackend::Fake => {
                local.crawl.safety.allow_private_networks = false;
                local.crawl.safety.authorization_record_ref = None;
                let script = ablation::script_from_manifest(&manifest, &self.base_url)?;
                // fake epoch ids are sequential per backend; parallel cycles on one schema
                // need disjoint `network_epochs` keys
                local = local.with_backend(Arc::new(
                    FakeBackend::builder()
                        .script(script)
                        .clock(Arc::new(SystemClock))
                        .epoch_base((index + 1) << 32)
                        .build(),
                ));
            }
        }
        if local.crawl.safety.authorization_record_ref.is_some() {
            let record = match &self.store {
                Store::Pg(p) => p.record.clone(),
                Store::Memory => loopback_record(&local.crawl.seed_url.origin().ascii_serialization())?,
            };
            local.crawl.safety.authorization_record_ref = Some(record.id);
            local = local.with_authorization(record);
        }
        tracing::info!(worker, fixture, seed, "soak: cycle start");
        let report = run_local_with(local).await?;
        Ok((report, stores))
    }

    /// `verify_trail` plus the auditor queries for one run.
    async fn audit(
        &self,
        report: &crawlx_worker::RunReport,
        stores: &Stores,
        out: &mut Cycle,
    ) -> Result<(), BenchError> {
        let trail = match &self.store {
            Store::Memory => {
                let Some(store) = stores.memory.as_ref() else {
                    return Err(BenchError::Trail("memory store missing".to_owned()));
                };
                verify_trail(
                    report.run_id,
                    TrailStore::Memory {
                        store,
                        artifacts: Some(stores.artifacts.as_ref()),
                    },
                )
                .await?
            }
            Store::Pg(p) => {
                verify_trail(
                    report.run_id,
                    TrailStore::Pg {
                        pg: &p.pg,
                        artifacts: Some(stores.artifacts.as_ref()),
                    },
                )
                .await?
            }
        };
        out.trail_violations = u64::try_from(trail.violations.len()).unwrap_or(u64::MAX);
        if !trail.unverifiable.is_empty() {
            return Err(BenchError::Trail(format!(
                "incomplete verification: {:?}",
                trail.unverifiable
            )));
        }
        if !trail.is_clean() {
            tracing::warn!(run = %report.run_id, "soak: trail violations: {trail}");
        }
        let journal: &dyn ActionJournal = stores.journal.as_ref();
        out.stuck_intended = u64::try_from(
            journal
                .list(report.run_id, Some(ActionStatus::Intended))
                .await?
                .len(),
        )
        .unwrap_or(u64::MAX);
        out.unreconciled_unknown = u64::try_from(
            journal
                .list(report.run_id, Some(ActionStatus::Unknown))
                .await?
                .len(),
        )
        .unwrap_or(u64::MAX);
        let runs: &dyn RunRepo = stores.runs.as_ref();
        let mut open = 0u64;
        let mut recovering = 0u64;
        for s in runs.list_sessions(report.run_id).await? {
            match s.status {
                SessionStatus::Completed | SessionStatus::Failed | SessionStatus::Cancelled => {}
                SessionStatus::Recovering => recovering += 1,
                _ => open += 1,
            }
        }
        out.open_sessions = open;
        out.recovering_sessions = recovering;
        Ok(())
    }

    fn sample(&self) -> Sample {
        let (rss_self, rss_tree, rss_chromium, processes) = tree_rss(std::process::id());
        let (pool_size, pool_idle) = match &self.store {
            Store::Pg(p) => (
                p.pg.pool().size(),
                u32::try_from(p.pg.pool().num_idle()).unwrap_or(u32::MAX),
            ),
            Store::Memory => (0, 0),
        };
        Sample {
            t_s: self.elapsed_s(),
            rss_self,
            rss_tree,
            rss_chromium,
            processes,
            pool_size,
            pool_idle,
            cycles: self.progress.cycles.load(Ordering::Relaxed),
            failures: self.progress.failures.load(Ordering::Relaxed),
        }
    }
}

/// Retry only a classified retryable read failure before any failure has been observed,
/// at most three times after the initial audit. A later read failure must not cause a
/// retry to overwrite an already observed invariant violation with a clean snapshot.
fn audit_retry_delay(
    result: &Result<(), BenchError>,
    attempt: u32,
    already_failed: bool,
) -> Option<Duration> {
    if !already_failed
        && (1..4).contains(&attempt)
        && matches!(result, Err(BenchError::Store(error)) if error.is_retryable())
    {
        Some(Duration::from_millis(100) * (1 << (attempt - 1)))
    } else {
        None
    }
}

/// Authorization record admitting the loopback gym (PostgreSQL holds a foreign key to it).
pub(crate) fn loopback_record(origin: &str) -> Result<AuthorizationRecord, BenchError> {
    let now = SystemClock.now();
    Ok(AuthorizationRecord {
        title: "soak harness: loopback gym".to_owned(),
        authorized_networks: vec!["127.0.0.0/8".parse()?],
        verified_at: Some(now),
        evidence: Evidence {
            kind: "soak_harness".to_owned(),
            artifact_id: None,
            digest: Digest::of("soak", b"loopback"),
        },
        ..sample_record(TenantId::new(), now, &[origin])
    })
}

/// Least-squares slope of `ys` over `xs` (per unit of `x`); `None` with fewer than two
/// distinct `x`.
fn slope(xs: &[f64], ys: &[f64]) -> Option<f64> {
    let n = f64::from(u32::try_from(xs.len()).ok()?);
    if xs.len() < 2 {
        return None;
    }
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let sxx: f64 = xs.iter().map(|x| (x - mx) * (x - mx)).sum();
    if sxx == 0.0 {
        return None;
    }
    let sxy: f64 = xs.iter().zip(ys).map(|(x, y)| (x - mx) * (y - my)).sum();
    Some(sxy / sxx)
}

/// Run the soak per `cfg`; `out_dir` receives `soak-report.json` and `soak-report.md`.
///
/// # Errors
/// [`BenchError`] when the requested strategies lack authenticated deployment gates, or
/// the gym, database, proxy or output directory cannot be set up. Cycle failures are reported.
pub async fn run(cfg: SoakConfig, out_dir: &Path) -> Result<SoakReport, BenchError> {
    if cfg.workers == 0 || cfg.fixtures.is_empty() {
        return Err(BenchError::Ablation(
            "soak: workers and fixtures must be non-empty".to_owned(),
        ));
    }
    for id in &cfg.fixtures {
        FixtureManifest::embedded(id)?;
    }
    // Resolve gates once, before allocating output, browsers or a database schema.
    // Every cycle clones this admitted configuration instead of reloading operator gates.
    let mut worker = worker_config(&FixtureManifest::embedded(&cfg.fixtures[0])?, out_dir)?;
    let gym_dynamic = crawlx_core::config::Dynamic {
        strategies: crate::worker_exec::GYM_STRATEGIES.to_vec(),
        ..crawlx_core::config::Dynamic::default()
    };
    crawlx_worker::build_strategies_gated(&gym_dynamic, &worker.gates)
        .map_err(crawlx_worker::WorkerError::from)?;
    worker
        .load_checkpoint_keys_from_lookup(&|name| std::env::var(name).ok())
        .await?;
    if cfg.database_url.is_some()
        && worker
            .checkpoint_keys
            .as_ref()
            .is_none_or(|keys| !keys.is_available())
    {
        return Err(BenchError::Gate(
            "durable soak checkpoints require CRAWLX_CHECKPOINT_KMS_KEY_ID".into(),
        ));
    }
    run_admitted(cfg, out_dir, worker).await
}

// Private seam for authored fixtures. Public callers must pass through authenticated
// admission above; fixture gate status is not measured G1 or release evidence.
async fn run_admitted(
    cfg: SoakConfig,
    out_dir: &Path,
    worker: WorkerConfig,
) -> Result<SoakReport, BenchError> {
    std::fs::create_dir_all(out_dir).map_err(|e| BenchError::io(out_dir, e))?;
    let scratch = out_dir.join(format!("soak-scratch-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|e| BenchError::io(&scratch, e))?;

    let (gym, base_url) = match cfg.backend {
        SoakBackend::Chromium => {
            let gym = GymServer::start(([127, 0, 0, 1], 0).into()).await?;
            let url = gym.base_url.clone();
            (Some(gym), url)
        }
        SoakBackend::Fake => (None, "https://gym.test".to_owned()),
    };

    // database, optionally through the fault proxy
    let mut proxy = None;
    let store = match &cfg.database_url {
        None => Store::Memory,
        Some(url) => {
            let url = match cfg.fault_every {
                Some(_) => {
                    let upstream = netfault::upstream_of(url).await?;
                    let p = Proxy::start(upstream).await?;
                    let rewritten = netfault::rewrite_url(url, p.addr())?;
                    proxy = Some(p);
                    rewritten
                }
                None => url.clone(),
            };
            let schema = format!("soak_{}", uuid::Uuid::now_v7().simple());
            let pg = Pg::connect(
                &url,
                PgConfig {
                    schema: Some(schema),
                    max_connections: u32::try_from(cfg.workers * 4 + 4).unwrap_or(32).min(32),
                    ..PgConfig::default()
                },
            )
            .await?;
            pg.migrate().await?;
            let origin = url::Url::parse(&base_url)?.origin().ascii_serialization();
            let record = loopback_record(&origin)?;
            pg.ensure_tenant(record.tenant, "soak").await?;
            let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
            let artifacts = FsArtifactStore::open(&scratch.join("artifacts"), runs, Arc::new(SystemClock))
                .await?
                .with_index(Arc::new(pg.clone()));
            let stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), record.tenant);
            Store::Pg(Box::new(PgStore { pg, stores, record }))
        }
    };

    let rig = Arc::new(Rig {
        cfg: cfg.clone(),
        worker_config: worker,
        gym,
        base_url,
        store,
        scratch: scratch.clone(),
        started: Instant::now(),
        progress: Progress {
            cycles: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        },
        cycles: parking_lot::Mutex::new(Vec::new()),
    });
    let deadline = rig.started + cfg.duration;
    let cancel = CancellationToken::new();
    let next_cycle = Arc::new(AtomicU64::new(0));

    // sampler
    let samples = Arc::new(parking_lot::Mutex::new(vec![rig.sample()]));
    let sampler = {
        let rig = rig.clone();
        let samples = samples.clone();
        let cancel = cancel.clone();
        let every = cfg.sample_interval;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(every) => {}
                }
                let s = rig.sample();
                tracing::info!(
                    t_s = s.t_s,
                    rss_tree_mib = s.rss_tree / (1024 * 1024),
                    rss_chromium_mib = s.rss_chromium / (1024 * 1024),
                    pool = s.pool_size,
                    cycles = s.cycles,
                    failures = s.failures,
                    "soak: sample"
                );
                samples.lock().push(s);
            }
        })
    };

    // seeded fault schedule
    let faults = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let fault_task = match (proxy.take(), cfg.fault_every) {
        (Some(proxy), Some(every)) => {
            let rig = rig.clone();
            let faults = faults.clone();
            let cancel = cancel.clone();
            let mut rng = CrawlSeed(cfg.seed).rng("soak-faults", &[]);
            Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        () = tokio::time::sleep(every) => {}
                    }
                    let kind = match rng.gen_range(0..3u8) {
                        0 => FaultKind::ResetAll,
                        1 => FaultKind::Latency,
                        _ => FaultKind::Blackhole,
                    };
                    let mut fault = Fault {
                        t_s: rig.elapsed_s(),
                        kind,
                        reset: 0,
                    };
                    tracing::warn!(kind = ?kind, t_s = fault.t_s, "soak: injecting fault");
                    match kind {
                        FaultKind::ResetAll => fault.reset = proxy.reset_all(),
                        FaultKind::Latency => {
                            proxy.set_latency(Duration::from_millis(250));
                            tokio::time::sleep(Duration::from_secs(10)).await;
                            proxy.set_latency(Duration::ZERO);
                        }
                        FaultKind::Blackhole => {
                            proxy.set_blackhole(true);
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            proxy.set_blackhole(false);
                            // the statements swallowed by the partition never get an answer;
                            // reset those connections as TCP keepalive eventually would
                            fault.reset = proxy.reset_all();
                        }
                    }
                    faults.lock().push(fault);
                }
                proxy
            }))
        }
        _ => None,
    };

    // worker loops
    let mut workers = JoinSet::new();
    for worker in 0..cfg.workers {
        let rig = rig.clone();
        let cancel = cancel.clone();
        let next_cycle = next_cycle.clone();
        workers.spawn(async move {
            while Instant::now() < deadline && !cancel.is_cancelled() {
                let index = next_cycle.fetch_add(1, Ordering::Relaxed);
                let cycle = rig.cycle(worker, index, &cancel).await;
                rig.progress.cycles.fetch_add(1, Ordering::Relaxed);
                if cycle.failed() {
                    rig.progress.failures.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(index, fixture = %cycle.fixture, error = ?cycle.error, "soak: cycle failed");
                } else {
                    tracing::info!(index, fixture = %cycle.fixture, ms = cycle.duration_ms, "soak: cycle ok");
                }
                rig.cycles.lock().push(cycle);
            }
        });
    }
    // the budget ends cycles in progress through the cancellation token
    let budget = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline.into()).await;
            cancel.cancel();
        })
    };
    while let Some(res) = workers.join_next().await {
        if let Err(e) = res {
            tracing::error!(error = %e, "soak: worker loop panicked");
            rig.progress.failures.fetch_add(1, Ordering::Relaxed);
        }
    }
    budget.abort();
    cancel.cancel();
    // no sample after the loops ended: the browsers are gone by then and a last point at
    // the baseline would dominate the slope
    let _ = sampler.await;
    // the proxy stays up until teardown: dropping the schema goes through it
    let proxy = match fault_task {
        Some(task) => task.await.ok(),
        None => None,
    };
    let proxy_stats = proxy.as_ref().map(Proxy::stats);

    let report = summarise(&rig, &samples.lock(), &faults.lock(), proxy_stats);
    let json = out_dir.join("soak-report.json");
    std::fs::write(&json, serde_json::to_vec_pretty(&report)?).map_err(|e| BenchError::io(&json, e))?;
    let md = out_dir.join("soak-report.md");
    std::fs::write(&md, report.markdown()).map_err(|e| BenchError::io(&md, e))?;

    // teardown
    let rig = match Arc::try_unwrap(rig) {
        Ok(rig) => rig,
        Err(_) => {
            return Err(BenchError::Ablation(
                "soak: rig still shared at teardown".to_owned(),
            ));
        }
    };
    if let Some(gym) = rig.gym {
        gym.shutdown().await;
    }
    if let Store::Pg(p) = rig.store {
        if cfg.keep_schema {
            tracing::info!("soak: keeping schema");
        } else {
            // faults are over; clear any lingering latency so the drop is quick
            if let Some(p) = &proxy {
                p.set_latency(Duration::ZERO);
                p.set_blackhole(false);
            }
            p.pg.drop_schema().await?;
        }
    }
    if let Some(p) = proxy {
        p.shutdown().await;
    }
    if let Err(e) = std::fs::remove_dir_all(&scratch) {
        tracing::warn!(path = %scratch.display(), error = %e, "soak: scratch not removed");
    }
    Ok(report)
}

fn summarise(
    rig: &Rig,
    samples: &[Sample],
    faults: &[Fault],
    proxy: Option<netfault::ProxyStats>,
) -> SoakReport {
    let cycles = rig.cycles.lock();
    let failures = cycles.iter().filter(|c| c.failed()).count();
    let mut durations: Vec<f64> = cycles.iter().map(|c| c.duration_ms as f64).collect();
    durations.sort_by(f64::total_cmp);
    let mut rss: Vec<f64> = samples.iter().map(|s| s.rss_tree as f64).collect();
    rss.sort_by(f64::total_cmp);
    // the slope skips the first fifth of the run (allocator and browser warm-up) and is only
    // judged against the ceiling once the fitted window is long enough to mean anything; the
    // judged series is this process (the leak candidate under crawlx's control), the tree
    // slope follows how many browsers happen to be open and is reported only
    let warmup_s = rig.elapsed_s() / 5.0;
    let fitted: Vec<&Sample> = samples.iter().filter(|s| s.t_s >= warmup_s).collect();
    let hours: Vec<f64> = fitted.iter().map(|s| s.t_s / 3600.0).collect();
    let own: Vec<f64> = fitted.iter().map(|s| s.rss_self as f64).collect();
    let tree: Vec<f64> = fitted.iter().map(|s| s.rss_tree as f64).collect();
    let enough = fitted.len() >= MIN_SAMPLES_FOR_SLOPE;
    let leak = enough.then(|| slope(&hours, &own)).flatten();
    let tree_leak = enough.then(|| slope(&hours, &tree)).flatten();
    let window = fitted
        .last()
        .zip(fitted.first())
        .map_or(0.0, |(last, first)| last.t_s - first.t_s);
    // the first post-warm-up sample lands up to one period after the warm-up boundary
    let judged = leak
        .filter(|_| window + rig.cfg.sample_interval.as_secs_f64() >= rig.cfg.min_slope_window.as_secs_f64());
    let mut reasons = Vec::new();
    if failures > 0 {
        reasons.push(format!("{failures} of {} cycles failed", cycles.len()));
    }
    let actions = cycles.iter().map(|c| c.actions).sum();
    if actions == 0 {
        reasons.push("no browser actions journaled; interaction workload was not exercised".to_owned());
    }
    if let Some(b) = judged {
        if b > rig.cfg.max_slope_bytes_per_hour {
            reasons.push(format!(
                "leak slope {:.1} MiB/h above {:.1} MiB/h",
                b / (1024.0 * 1024.0),
                rig.cfg.max_slope_bytes_per_hour / (1024.0 * 1024.0)
            ));
        }
    }
    let verdict = if !reasons.is_empty() {
        Verdict::Fail(reasons)
    } else if leak.is_none() {
        Verdict::Inconclusive(vec![format!(
            "{} samples after warm-up, {MIN_SAMPLES_FOR_SLOPE} needed for a leak slope",
            fitted.len()
        )])
    } else if judged.is_none() {
        Verdict::Inconclusive(vec![format!(
            "fitted window {window:.0} s shorter than the {:.0} s a leak verdict needs",
            rig.cfg.min_slope_window.as_secs_f64()
        )])
    } else {
        Verdict::Pass
    };
    let mut per_fixture = BTreeMap::new();
    for c in cycles.iter() {
        *per_fixture.entry(c.fixture.clone()).or_insert(0u64) += 1;
    }
    // bytes fit in f64 exactly up to 2^53; RSS is far below
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let as_bytes = |q: f64| quantile(&rss, q).unwrap_or(0.0) as u64;
    SoakReport {
        duration_s: rig.cfg.duration.as_secs_f64(),
        elapsed_s: rig.elapsed_s(),
        workers: rig.cfg.workers,
        backend: rig.cfg.backend,
        store: match rig.store {
            Store::Memory => "memory",
            Store::Pg(_) => "postgres",
        },
        fixtures: rig.cfg.fixtures.clone(),
        cycles: u64::try_from(cycles.len()).unwrap_or(u64::MAX),
        failures: u64::try_from(failures).unwrap_or(u64::MAX),
        actions,
        cycle_p50_ms: quantile(&durations, 0.5).unwrap_or(0.0),
        cycle_p95_ms: quantile(&durations, 0.95).unwrap_or(0.0),
        rss_p50: as_bytes(0.5),
        rss_p95: as_bytes(0.95),
        rss_max: as_bytes(1.0),
        leak_slope_bytes_per_hour: leak,
        tree_slope_bytes_per_hour: tree_leak,
        slope_window_s: window,
        max_slope_bytes_per_hour: rig.cfg.max_slope_bytes_per_hour,
        faults: faults.to_vec(),
        proxy,
        verdict,
        samples: samples.to_vec(),
        failed_cycles: cycles.iter().filter(|c| c.failed()).cloned().collect(),
        per_fixture,
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/support/soak_audit.rs"]
mod audit_pg_tests;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    // Match the production `crawlx` and `soak` executables in the memory regression.
    #[global_allocator]
    static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fake_memory_soak_cycles_are_trail_clean_and_the_report_is_written() {
        let out = tempfile::tempdir().unwrap();
        let mut worker = worker_config(&FixtureManifest::embedded("g01").unwrap(), out.path()).unwrap();
        // Authored FakeBackend fixtures exercise execution, not authenticated G1 evidence.
        worker.gates =
            crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus { g1: true, g3: false });
        let report = run_admitted(
            SoakConfig {
                duration: Duration::from_secs(8),
                workers: 2,
                fixtures: vec!["g01".to_owned(), "g02".to_owned()],
                backend: SoakBackend::Fake,
                database_url: None,
                sample_interval: Duration::from_millis(250),
                interactions: 12,
                cycle_seconds: 10,
                ..SoakConfig::default()
            },
            out.path(),
            worker,
        )
        .await
        .unwrap();
        eprintln!("{}", report.markdown());
        assert_eq!(report.failures, 0, "{:?}", report.failed_cycles);
        assert!(report.actions > 0);
        assert!(report.samples.len() >= 10, "{}", report.samples.len());
        assert!(report.rss_max >= report.rss_p50 && report.rss_p50 > 0);
        assert_eq!(report.per_fixture.len(), 2);
        assert!(
            matches!(report.verdict, Verdict::Pass | Verdict::Inconclusive(_)),
            "{:?}",
            report.verdict
        );
        assert!(report.leak_slope_bytes_per_hour.is_some());
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.path().join("soak-report.json")).unwrap()).unwrap();
        assert_eq!(json["cycles"].as_u64().unwrap(), report.cycles);
        assert_eq!(json["actions"].as_u64().unwrap(), report.actions);
        assert!(out.path().join("soak-report.md").is_file());
        assert!(!out
            .path()
            .join(format!("soak-scratch-{}", std::process::id()))
            .exists());
    }

    fn interrupted_read(retryable: bool) -> BenchError {
        crawlx_core::StoreError::Database {
            source: Box::new(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            retryable,
        }
        .into()
    }

    #[test]
    fn transient_audit_read_retries_stop_after_three_bounded_delays() {
        let result = Err(interrupted_read(true));
        for (attempt, delay_ms) in [(1, 100), (2, 200), (3, 400)] {
            assert_eq!(
                audit_retry_delay(&result, attempt, false),
                Some(Duration::from_millis(delay_ms)),
            );
        }
        for attempt in [0, 4, u32::MAX] {
            assert_eq!(audit_retry_delay(&result, attempt, false), None);
        }
    }

    #[test]
    fn invariant_and_permanent_audit_failures_are_never_retried() {
        let permanent = Err(interrupted_read(false));
        let violation = Err(BenchError::Trail("missing committed outcome".to_owned()));
        for attempt in 1..=4 {
            assert_eq!(audit_retry_delay(&permanent, attempt, false), None);
            assert_eq!(audit_retry_delay(&violation, attempt, false), None);
            assert_eq!(audit_retry_delay(&Ok(()), attempt, false), None);
        }
        let Err(BenchError::Store(error)) = permanent else {
            panic!("audit error must retain its storage type");
        };
        let source = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(source.kind(), std::io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn partial_audit_violation_cannot_be_erased_by_retrying_a_later_read_failure() {
        let mut cycle = Cycle {
            index: 0,
            worker: 0,
            fixture: "g01".to_owned(),
            seed: 1,
            started_s: 0.0,
            duration_ms: 0,
            status: Some(RunStatus::Completed),
            actions: 1,
            pages: 1,
            trail_violations: 0,
            stuck_intended: 0,
            unreconciled_unknown: 0,
            open_sessions: 0,
            recovering_sessions: 0,
            error: None,
        };
        let interrupted = Err(interrupted_read(true));
        for counter in [
            |cycle: &mut Cycle| cycle.trail_violations = 1,
            |cycle: &mut Cycle| cycle.stuck_intended = 1,
            |cycle: &mut Cycle| cycle.unreconciled_unknown = 1,
            |cycle: &mut Cycle| cycle.open_sessions = 1,
            |cycle: &mut Cycle| cycle.recovering_sessions = 1,
        ] {
            let mut observed = cycle.clone();
            counter(&mut observed);
            for attempt in 1..=3 {
                assert_eq!(audit_retry_delay(&interrupted, attempt, observed.failed()), None);
            }
        }
        cycle.status = Some(RunStatus::Failed);
        assert_eq!(audit_retry_delay(&interrupted, 1, cycle.failed()), None);
    }

    /// Fifteen browser cycles on an otherwise idle host: the fitted PSS growth per cycle must
    /// stay under half a MiB. The sample is too short to separate allocator growth from a
    /// leak when other test binaries load the host (a full-suite run measured 1.5 MiB/cycle
    /// for the same code that measures 0.15-0.37 MiB/cycle alone), so it runs only when
    /// `CRAWLX_SOAK_UNIT=1` selects it; the 30-minute `soak` gate is the
    /// release criterion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chromium_worker_cycles_retain_less_than_half_a_mib_per_cycle_after_warmup() {
        if std::env::var_os("CRAWLX_SOAK_UNIT").is_none() {
            eprintln!("SKIP: set CRAWLX_SOAK_UNIT=1 to run the memory-retention sample on an idle host");
            return;
        }
        if crawlx_browser::launch::find_executable().is_none() {
            eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
            return;
        }
        let scratch = tempfile::tempdir().unwrap();
        let gym = GymServer::start(([127, 0, 0, 1], 0).into()).await.unwrap();
        let rig = Rig {
            cfg: SoakConfig {
                workers: 1,
                fixtures: vec!["g01".to_owned()],
                interactions: 12,
                cycle_seconds: 15,
                ..SoakConfig::default()
            },
            worker_config: worker_config(&FixtureManifest::embedded("g01").unwrap(), scratch.path()).unwrap(),
            base_url: gym.base_url.clone(),
            gym: Some(gym),
            store: Store::Memory,
            scratch: scratch.path().to_path_buf(),
            started: Instant::now(),
            progress: Progress {
                cycles: AtomicU64::new(0),
                failures: AtomicU64::new(0),
            },
            cycles: parking_lot::Mutex::new(Vec::new()),
        };
        let cancel = CancellationToken::new();
        let mut retained = Vec::new();
        for index in 0..15 {
            let cycle = rig.cycle(0, index, &cancel).await;
            assert!(!cycle.failed(), "{cycle:?}");
            // Let the aborted context pump and the last backend's sampler finish dropping.
            tokio::time::sleep(Duration::from_millis(25)).await;
            if index >= 3 {
                retained.push(memory_of(std::process::id()));
            }
        }
        rig.gym.unwrap().shutdown().await;
        // The per-cycle PSS of a browser worker oscillates by several MiB (page caches,
        // allocator segments), so two endpoints measure noise; the least-squares slope over
        // the twelve post-warm-up samples is the estimator the soak report uses as well.
        let xs: Vec<f64> = (0..retained.len()).map(|i| i as f64).collect();
        let ys: Vec<f64> = retained.iter().map(|&b| b as f64).collect();
        let per_cycle = slope(&xs, &ys).unwrap();
        eprintln!("post-warmup worker PSS bytes: {retained:?}; fitted growth/cycle={per_cycle:.0}");
        assert!(retained[0] > 0, "worker PSS must be readable");
        assert!(
            per_cycle <= 512.0 * 1024.0,
            "worker PSS grew by {per_cycle:.0} bytes/cycle after warmup: {retained:?}"
        );
    }
}
