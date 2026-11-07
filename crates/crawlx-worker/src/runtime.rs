//! The Tokio runtime of the `crawlx` binary.
//!
//! Library crates never build a runtime; `crawlx-cli` calls [`build_runtime`] once from
//! `main` instead of `#[tokio::main]`, so the blocking pool is bounded (tokio's default is
//! 512 threads) and the threads are recognizable in a profiler.

use crawlx_extract::parse_budget::DEFAULT_PARSE_MEMORY_BYTES;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;
use tokio::task::JoinError;

/// Thread name of every runtime thread.
pub const THREAD_NAME: &str = "crawlx-rt";
/// Default upper bound of the `spawn_blocking` pool.
pub const DEFAULT_MAX_BLOCKING_THREADS: usize = 64;
/// Shared article serialization maxima, not an allocator-capacity, DOM or RSS bound.
const ARTICLE_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
static ARTICLE_OUTPUT_BUDGET: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(ARTICLE_OUTPUT_BYTES)));

/// Runtime metrics for explicit diagnostic builds. This instruments runtime workers,
/// not the client futures submitting requests.
#[cfg(feature = "runtime-diagnostics")]
pub mod diagnostics {
    /// Bounded runtime monitor; interval snapshots replace previous counters.
    pub use tokio_metrics::RuntimeMonitor;
    /// Bounded counters for a single instrumented actor task.
    pub use tokio_metrics::{TaskMetrics, TaskMonitor};

    /// Each runtime worker's actual scheduler poll-time estimate.
    ///
    /// Requires the opt-in `tokio_unstable` runtime hooks. Unlike a request wrapper,
    /// these estimates include every task scheduled on each worker.
    #[must_use]
    pub fn worker_mean_polls(handle: &tokio::runtime::Handle) -> impl Iterator<Item = std::time::Duration> {
        let metrics = handle.metrics();
        (0..metrics.num_workers()).map(move |worker| metrics.worker_mean_poll_time(worker))
    }
}
/// Environment variable that overrides [`RuntimeConfig::parse_memory_bytes`] (decimal bytes).
pub const PARSE_MEMORY_ENV: &str = "CRAWLX_PARSE_MEMORY_BYTES";

/// A runtime setting could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeConfigError {
    /// [`PARSE_MEMORY_ENV`] is not a positive integer.
    #[error("{PARSE_MEMORY_ENV} must be a positive number of bytes")]
    ParseMemory,
}

/// Runtime sizing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuntimeConfig {
    /// Async worker threads; `None` uses `std::thread::available_parallelism()`.
    pub worker_threads: Option<NonZeroUsize>,
    /// Upper bound of the blocking pool (planning default 64; tokio's own default is 512).
    pub max_blocking_threads: NonZeroUsize,
    /// Size of the process-wide HTML parse-memory budget in bytes. Every parse in
    /// `crawlx-extract` charges `input_len * PARSE_BYTES_PER_INPUT_BYTE` against it without
    /// waiting and fails with a typed resource error when it is exhausted.
    /// Defaults to [`DEFAULT_PARSE_MEMORY_BYTES`]; container memory limits are derived from it
    /// (`deploy/helm/crawlx/values.yaml`).
    pub parse_memory_bytes: NonZeroUsize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            max_blocking_threads: NonZeroUsize::new(DEFAULT_MAX_BLOCKING_THREADS)
                .unwrap_or(NonZeroUsize::MIN),
            parse_memory_bytes: NonZeroUsize::new(DEFAULT_PARSE_MEMORY_BYTES).unwrap_or(NonZeroUsize::MIN),
        }
    }
}

impl RuntimeConfig {
    /// Worker threads to use: the configured count or the host's available parallelism
    /// (1 when the host cannot report it).
    #[must_use]
    pub fn effective_worker_threads(&self) -> usize {
        self.worker_threads
            .or_else(|| std::thread::available_parallelism().ok())
            .map_or(1, NonZeroUsize::get)
    }

    /// The default configuration with the settings named in the environment applied.
    ///
    /// # Errors
    /// [`RuntimeConfigError::ParseMemory`] when [`PARSE_MEMORY_ENV`] is set but is not a
    /// positive integer.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, RuntimeConfigError> {
        let mut config = Self::default();
        if let Some(value) = get(PARSE_MEMORY_ENV) {
            config.parse_memory_bytes = value
                .trim()
                .parse::<NonZeroUsize>()
                .map_err(|_| RuntimeConfigError::ParseMemory)?;
        }
        Ok(config)
    }
}

/// Build the multi-threaded runtime: worker threads = available parallelism, bounded
/// blocking pool, thread name [`THREAD_NAME`], all drivers enabled. Also installs
/// [`RuntimeConfig::parse_memory_bytes`] as the limit of the process-wide parse-memory budget.
///
/// # Errors
/// Returns the `std::io::Error` of `tokio::runtime::Builder::build` when the runtime threads
/// cannot be spawned.
pub fn build_runtime(cfg: &RuntimeConfig) -> std::io::Result<tokio::runtime::Runtime> {
    crawlx_extract::parse_budget::global().set_limit(cfg.parse_memory_bytes.get());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.effective_worker_threads())
        .max_blocking_threads(cfg.max_blocking_threads.get())
        .thread_name(THREAD_NAME)
        .enable_all()
        .build()
}

/// The CPU pool: a semaphore sized like the blocking pool in front of
/// `spawn_blocking`, so CPU-bound steps (HTML extraction) queue here instead of piling up
/// unbounded tasks, and the queue is observable as `crawlx.cpu_pool.queue_depth`.
///
/// One pool per worker process; `Clone` shares it.
#[derive(Clone, Debug)]
pub struct CpuPool {
    permits: Arc<Semaphore>,
    waiting: Arc<AtomicUsize>,
    capacity: usize,
    article_output: Arc<Semaphore>,
}

impl Default for CpuPool {
    fn default() -> Self {
        Self::new(&RuntimeConfig::default())
    }
}

impl CpuPool {
    /// A pool with `cfg.max_blocking_threads` permits.
    #[must_use]
    pub fn new(cfg: &RuntimeConfig) -> Self {
        Self::with_permits(cfg.max_blocking_threads)
    }

    /// A pool with exactly `permits` concurrent closures.
    #[must_use]
    pub fn with_permits(permits: NonZeroUsize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits.get())),
            waiting: Arc::new(AtomicUsize::new(0)),
            capacity: permits.get(),
            article_output: Arc::clone(&ARTICLE_OUTPUT_BUDGET),
        }
    }

    /// Reserve a serializer's existing maximum without waiting while it owns a document.
    ///
    /// The permit must move with the blocking closure and approved bytes through sink I/O.
    /// Only migrated article buffers are covered; source bodies and parser allocations are not.
    ///
    /// # Errors
    /// Returns typed resource pressure before any output buffer allocation or CPU queueing.
    pub(crate) fn try_reserve_article_output(
        &self,
        maximum: usize,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, crawlx_core::StoreError> {
        let denied = || crawlx_core::StoreError::ResourceExhausted {
            resource: "article_output_reservation",
            requested: maximum,
            available: self.article_output.available_permits(),
            source: None,
        };
        let count = u32::try_from(maximum).map_err(|_| denied())?;
        Arc::clone(&self.article_output)
            .try_acquire_many_owned(count)
            .map_err(|_| denied())
    }

    #[cfg(test)]
    pub(crate) fn with_article_output_limit(permits: NonZeroUsize, limit: std::num::NonZeroU32) -> Self {
        let mut pool = Self::with_permits(permits);
        let maximum = usize::try_from(limit.get())
            .unwrap_or(0)
            .min(ARTICLE_OUTPUT_BYTES);
        pool.article_output = Arc::new(Semaphore::new(maximum));
        pool
    }

    #[cfg(test)]
    pub(crate) fn article_output_available(&self) -> usize {
        self.article_output.available_permits()
    }

    /// Closures waiting for a permit right now.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.waiting.load(Ordering::Relaxed)
    }

    /// Closures currently holding a CPU permit, including detached blocking work.
    #[must_use]
    pub fn active(&self) -> usize {
        self.capacity.saturating_sub(self.permits.available_permits())
    }

    /// Hard capacity of the existing CPU pool.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Run `f` on the blocking pool once a permit is free. The time spent waiting is counted
    /// in the queue-depth gauge; the permit is held until `f` returns.
    ///
    /// # Errors
    /// The [`JoinError`] of the blocking task when `f` panics or the runtime shuts down.
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, JoinError> {
        // Cancellation must return queue accounting, but must not return a running
        // blocking closure's permit before that closure actually exits.
        let waiting = Waiting::new(&self.waiting);
        let permit = Arc::clone(&self.permits).acquire_owned().await.ok();
        drop(waiting);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await
    }
}

struct Waiting<'a>(&'a AtomicUsize);

impl<'a> Waiting<'a> {
    fn new(waiting: &'a AtomicUsize) -> Self {
        let depth = waiting.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        Metrics::global()
            .gauge(names::CPU_POOL_QUEUE_DEPTH)
            .set(depth_value(depth), &[]);
        Self(waiting)
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let depth = self.0.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
        Metrics::global()
            .gauge(names::CPU_POOL_QUEUE_DEPTH)
            .set(depth_value(depth), &[]);
    }
}

fn depth_value(depth: usize) -> f64 {
    u32::try_from(depth).map_or(f64::MAX, f64::from)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn runtime_threads_carry_the_crawlx_name_and_the_default_pool_is_bounded() {
        let cfg = RuntimeConfig {
            worker_threads: NonZeroUsize::new(2),
            ..RuntimeConfig::default()
        };
        assert_eq!(cfg.max_blocking_threads.get(), 64);
        assert_eq!(cfg.effective_worker_threads(), 2);
        let rt = build_runtime(&cfg).unwrap();
        let name = rt.block_on(async {
            tokio::task::spawn_blocking(|| std::thread::current().name().map(str::to_owned))
                .await
                .unwrap()
        });
        assert_eq!(name.as_deref(), Some(THREAD_NAME));
        let worker = rt.block_on(async {
            tokio::spawn(async { std::thread::current().name().map(str::to_owned) })
                .await
                .unwrap()
        });
        assert_eq!(worker.as_deref(), Some(THREAD_NAME));
        assert!(RuntimeConfig::default().effective_worker_threads() >= 1);
    }

    #[test]
    fn parse_memory_budget_comes_from_the_environment_and_build_runtime_installs_it() {
        let env = |value: &'static str| move |key: &str| (key == PARSE_MEMORY_ENV).then(|| value.to_owned());
        let default = RuntimeConfig::from_env(&|_| None).unwrap();
        assert_eq!(default, RuntimeConfig::default());
        assert_eq!(default.parse_memory_bytes.get(), DEFAULT_PARSE_MEMORY_BYTES);
        let set = RuntimeConfig::from_env(&env(" 1048576 ")).unwrap();
        assert_eq!(set.parse_memory_bytes.get(), 1_048_576);
        for bad in ["0", "-1", "1G", ""] {
            assert_eq!(
                RuntimeConfig::from_env(&env(bad)),
                Err(RuntimeConfigError::ParseMemory),
                "{bad:?}"
            );
        }
        // only the default is installed here: the budget is process-wide and other tests parse
        drop(build_runtime(&default).unwrap());
        assert_eq!(
            crawlx_extract::parse_budget::global().limit(),
            DEFAULT_PARSE_MEMORY_BYTES
        );
    }

    async fn until(deadline: std::time::Instant, mut done: impl FnMut() -> bool) -> bool {
        while !done() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        true
    }

    /// Two closures hold the permits (parked on a barrier) and three more queue behind
    /// them; the barrier is released before any assertion so a failure never leaves the
    /// runtime waiting on parked blocking threads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cpu_pool_queue_depth_counts_waiters_and_drains() {
        let pool = CpuPool::with_permits(NonZeroUsize::new(2).unwrap());
        let release = Arc::new(std::sync::Barrier::new(3));
        let holding = Arc::new(AtomicUsize::new(0));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let release = Arc::clone(&release);
            let holding = Arc::clone(&holding);
            tasks.push(tokio::spawn(async move {
                pool.run(move || {
                    holding.fetch_add(1, Ordering::SeqCst);
                    release.wait();
                })
                .await
                .unwrap();
            }));
        }
        let both_hold = until(deadline, || holding.load(Ordering::SeqCst) == 2).await;
        for _ in 0..3 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move { pool.run(|| ()).await.unwrap() }));
        }
        let queued = until(deadline, || pool.queue_depth() == 3).await;
        let depth_seen = pool.queue_depth();
        tokio::task::spawn_blocking(move || release.wait()).await.unwrap();
        for t in tasks {
            t.await.unwrap();
        }
        assert!(both_hold, "the first two closures took the permits");
        assert!(queued, "three closures queued behind them");
        assert_eq!(depth_seen, 3);
        assert_eq!(pool.queue_depth(), 0);
        assert!(
            Metrics::global()
                .gauge(names::CPU_POOL_QUEUE_DEPTH)
                .get(&[])
                .is_some(),
            "the queue depth gauge is set"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_waiters_and_running_callers_preserves_cpu_bounds() {
        let pool =
            CpuPool::with_article_output_limit(NonZeroUsize::MIN, std::num::NonZeroU32::new(8).unwrap());
        let running_output = pool.try_reserve_article_output(4).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let running_pool = pool.clone();
        let running = tokio::spawn(async move {
            running_pool
                .run(move || {
                    let _output = running_output;
                    let _ = started_tx.send(());
                    release_rx.recv().unwrap();
                })
                .await
        });
        started_rx.await.unwrap();
        let waiting_pool = pool.clone();
        let waiting_output = pool.try_reserve_article_output(4).unwrap();
        let waiting = tokio::spawn(async move { waiting_pool.run(move || drop(waiting_output)).await });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let queued = until(deadline, || pool.queue_depth() == 1).await;
        let full = matches!(
            pool.try_reserve_article_output(1),
            Err(crawlx_core::StoreError::ResourceExhausted {
                resource: "article_output_reservation",
                requested: 1,
                available: 0,
                ..
            })
        );
        waiting.abort();
        let _ = waiting.await;
        running.abort();
        let _ = running.await;
        let held_after_cancel = pool.active();
        let waiting_after_cancel = pool.queue_depth();
        let output_after_cancel = pool.article_output_available();
        release_tx.send(()).unwrap();
        let drained = until(deadline, || pool.active() == 0).await;
        assert!(queued);
        assert!(
            full,
            "queued and running closures retain their output reservations"
        );
        assert_eq!(waiting_after_cancel, 0);
        assert_eq!(held_after_cancel, 1, "blocking closure still owns its permit");
        assert_eq!(
            output_after_cancel, 4,
            "only the cancelled queued closure released bytes"
        );
        assert!(drained);
        pool.run(|| 7).await.unwrap();
        assert_eq!(pool.active(), 0);
        assert_eq!(pool.article_output_available(), 8);
    }
}
