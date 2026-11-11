//! `--pprof-bind`: the debug listener of `crawlx serve` and `crawlx worker`.
//!
//! This is crawlx's counterpart of the compatibility `-pprof-server`. When `--pprof-bind ADDR` (env
//! `CRAWLX_PPROF_BIND`) is given, a small HTTP server answers two routes:
//!
//! * `GET /debug/pprof/profile?seconds=N` samples the CPU of the whole process at
//!   [`SAMPLE_FREQUENCY_HZ`] for `N` seconds and returns the profile in the pprof
//!   `profile.proto` encoding (`application/octet-stream`, `Content-Disposition: attachment;
//!   filename=profile.pb`), the same wire format `go tool pprof` reads. `seconds` defaults to
//!   [`DEFAULT_PROFILE_SECONDS`], is clamped to
//!   [`MIN_PROFILE_SECONDS`]`..=`[`MAX_PROFILE_SECONDS`] (`0` becomes `1`, `999` becomes `120`)
//!   and must be a non-negative integer: anything else answers `400`. Only one profile runs at
//!   a time (the sampler is process-global); a second request answers `409`. A profile still
//!   running when the process shuts down is abandoned with `503`.
//! * `GET /debug/pprof/heap` answers a JSON memory summary ([`HeapReport`]) read from the
//!   process's own `/proc` entry and the browser resident-set sampler. It is **not** a pprof
//!   heap profile: mimalloc, the allocator of the `crawlx` binary, exposes its statistics only
//!   through `unsafe` FFI, which this workspace forbids, so no per-allocation data exists.
//!   `GET /debug/pprof/heap?debug=1` renders the same numbers as `# Name = value` text lines
//!   (`debug=0` is the JSON default; any other value answers `400`). Both carry sizes and counts
//!   only, never labels, URLs, paths, headers or page content.
//! * `GET /debug/pprof/` lists these routes.
//!
//! The listener carries **no authentication** and exposes stack traces and memory sizes of a
//! process that holds tenant data, so it is refused on every non-loopback address unless
//! `CRAWLX_PPROF_ALLOW_NON_LOOPBACK=1` (or `--pprof-allow-non-loopback`) says the operator
//! fronts it with their own access control. A profile costs measurable CPU for its whole
//! duration (a `SIGPROF` handler runs 99 times per second), so leave the flag off in normal
//! operation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::builder::BoolishValueParser;
use clap::Args;
use pprof::protos::Message;
use pprof::ProfilerGuardBuilder;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Sampling frequency of `GET /debug/pprof/profile`, in samples per CPU-second.
pub const SAMPLE_FREQUENCY_HZ: i32 = 99;
/// Profile length when `seconds` is absent.
pub const DEFAULT_PROFILE_SECONDS: u64 = 10;
/// Shortest profile; `seconds=0` is raised to this.
pub const MIN_PROFILE_SECONDS: u64 = 1;
/// Longest profile; larger `seconds` values are lowered to this.
pub const MAX_PROFILE_SECONDS: u64 = 120;

/// Shared objects the sampler must not attribute time to: `pprof` documents that unwinding
/// through them from the signal handler can deadlock.
const BLOCKLIST: [&str; 4] = ["libc", "libgcc", "pthread", "vdso"];

/// The pprof flags of `crawlx serve` and `crawlx worker`.
#[derive(Args, Debug, Clone, Copy, Default)]
pub struct PprofArgs {
    /// Unauthenticated pprof listener (`GET /debug/pprof/profile?seconds=N` CPU profile in
    /// profile.proto form, `GET /debug/pprof/heap` memory summary); loopback addresses only.
    #[arg(long, env = "CRAWLX_PPROF_BIND", value_name = "ADDR")]
    pub pprof_bind: Option<SocketAddr>,
    /// Allow a non-loopback `--pprof-bind`. The listener has no authentication: only set this
    /// behind your own network access control.
    #[arg(
        long,
        env = "CRAWLX_PPROF_ALLOW_NON_LOOPBACK",
        value_parser = BoolishValueParser::new()
    )]
    pub pprof_allow_non_loopback: bool,
}

/// Failures of the pprof listener.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PprofError {
    /// The address is not loopback and non-loopback binds were not allowed.
    #[error(
        "pprof listener {bind} is not a loopback address; the unauthenticated pprof endpoints are \
         only served on loopback unless CRAWLX_PPROF_ALLOW_NON_LOOPBACK=1 (--pprof-allow-non-loopback) \
         is set"
    )]
    NonLoopback {
        /// The refused address.
        bind: SocketAddr,
    },
    /// The socket could not be bound.
    #[error("cannot bind pprof listener {bind}")]
    Bind {
        /// The address that could not be bound.
        bind: SocketAddr,
        /// The socket error.
        #[source]
        source: std::io::Error,
    },
    /// The server stopped with an I/O failure.
    #[error("pprof listener failed")]
    Serve(#[source] std::io::Error),
}

/// A `seconds` query value that is not a non-negative integer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("seconds must be a non-negative integer, got {0:?}")]
pub struct InvalidSeconds(pub String);

/// The profile duration asked for by the `seconds` query parameter: [`DEFAULT_PROFILE_SECONDS`]
/// when absent, otherwise the integer clamped to
/// [`MIN_PROFILE_SECONDS`]`..=`[`MAX_PROFILE_SECONDS`].
///
/// # Errors
/// [`InvalidSeconds`] when the value is not a non-negative integer (`abc`, `-1`, `1.5`, empty).
pub fn parse_seconds(raw: Option<&str>) -> Result<Duration, InvalidSeconds> {
    let seconds = match raw {
        None => DEFAULT_PROFILE_SECONDS,
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| InvalidSeconds(text.to_owned()))?
            .clamp(MIN_PROFILE_SECONDS, MAX_PROFILE_SECONDS),
    };
    Ok(Duration::from_secs(seconds))
}

/// Bind the pprof listener on `bind`.
///
/// # Errors
/// [`PprofError::NonLoopback`] when `bind` is not a loopback address and `allow_non_loopback`
/// is false (nothing is bound); [`PprofError::Bind`] when the socket cannot be bound.
pub async fn bind_pprof(bind: SocketAddr, allow_non_loopback: bool) -> Result<TcpListener, PprofError> {
    if !bind.ip().is_loopback() && !allow_non_loopback {
        return Err(PprofError::NonLoopback { bind });
    }
    TcpListener::bind(bind)
        .await
        .map_err(|source| PprofError::Bind { bind, source })
}

/// Serve the pprof routes on an already bound `listener` until `stop` is cancelled. Callers
/// decide where `listener` is bound ([`bind_pprof`] enforces the loopback rule). Cancelling
/// `stop` also abandons a profile in progress, so shutdown never waits for one.
///
/// # Errors
/// [`PprofError::Serve`] when the listener's address cannot be read or the server stops with
/// an I/O failure.
pub async fn serve_on(listener: TcpListener, stop: CancellationToken) -> Result<(), PprofError> {
    let addr = listener.local_addr().map_err(PprofError::Serve)?;
    tracing::warn!(bind = %addr, "unauthenticated pprof listener enabled");
    let app = router(stop.clone());
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { stop.cancelled().await })
        .await
        .map_err(PprofError::Serve)
}

/// A running pprof listener started from [`PprofArgs`].
#[derive(Debug)]
#[must_use = "dropping the handle leaves the listener running with no way to stop it"]
pub struct PprofListener {
    stop: CancellationToken,
    task: JoinHandle<Result<(), PprofError>>,
}

impl PprofListener {
    /// Bind and start the listener when `--pprof-bind` is set; `None` when it is not.
    ///
    /// # Errors
    /// The [`bind_pprof`] errors, so a bad address fails before the service starts.
    pub async fn start(args: &PprofArgs) -> Result<Option<Self>, PprofError> {
        let Some(bind) = args.pprof_bind else {
            return Ok(None);
        };
        let listener = bind_pprof(bind, args.pprof_allow_non_loopback).await?;
        let stop = CancellationToken::new();
        let task = tokio::spawn(serve_on(listener, stop.clone()));
        Ok(Some(Self { stop, task }))
    }

    /// Stop the listener and wait for it to drain; failures are logged, not returned, because
    /// the service this listener sidecars has its own result to report.
    pub async fn shutdown(self) {
        self.stop.cancel();
        match self.task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "pprof listener failed"),
            Err(e) => tracing::warn!(error = %e, "pprof listener task ended abnormally"),
        }
    }
}

#[derive(Clone)]
struct AppState {
    /// One permit: the CPU sampler is process-global, so profiles run one at a time.
    profile_slot: Arc<Semaphore>,
    stop: CancellationToken,
}

fn router(stop: CancellationToken) -> Router {
    let state = AppState {
        profile_slot: Arc::new(Semaphore::new(1)),
        stop,
    };
    Router::new()
        .route("/debug/pprof/", get(index))
        .route("/debug/pprof/profile", get(profile))
        .route("/debug/pprof/heap", get(heap))
        .with_state(state)
}

/// Query of `GET /debug/pprof/profile`.
#[derive(Debug, Deserialize)]
struct ProfileQuery {
    seconds: Option<String>,
}

fn text(status: StatusCode, message: impl Into<String>) -> Response {
    (status, message.into()).into_response()
}

async fn profile(State(state): State<AppState>, Query(query): Query<ProfileQuery>) -> Response {
    let duration = match parse_seconds(query.seconds.as_deref()) {
        Ok(duration) => duration,
        Err(e) => return text(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let Ok(permit) = Arc::clone(&state.profile_slot).try_acquire_owned() else {
        return text(
            StatusCode::CONFLICT,
            "a CPU profile is already running; retry when it finishes",
        );
    };
    // Starting the sampler resolves debug-info lazily (`pprof` captures a backtrace once), which
    // is CPU work: keep it off the async workers.
    let started = tokio::task::spawn_blocking(|| {
        ProfilerGuardBuilder::default()
            .frequency(SAMPLE_FREQUENCY_HZ)
            .blocklist(&BLOCKLIST)
            .build()
    })
    .await;
    let guard = match started {
        Ok(Ok(guard)) => guard,
        // the sampler is process-global: another profiler in this process holds it
        Ok(Err(pprof::Error::Running)) => {
            return text(
                StatusCode::CONFLICT,
                "the process CPU profiler is already running",
            )
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "cannot start the CPU profiler");
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot start the CPU profiler: {e}"),
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "CPU profiler start task ended abnormally");
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CPU profiler start task ended abnormally",
            );
        }
    };
    // Sleeping on the runtime instead of a blocking thread lets a client disconnect (the handler
    // future is dropped: guard and permit with it) or a shutdown end the profile at once.
    tokio::select! {
        () = tokio::time::sleep(duration) => {}
        () = state.stop.cancelled() => {
            return text(StatusCode::SERVICE_UNAVAILABLE, "shutting down; the CPU profile was abandoned");
        }
    }
    // Symbolizing every sampled frame is CPU-bound; the permit stays held until it is done.
    let encoded = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        encode_profile(&guard)
    })
    .await;
    match encoded {
        Ok(Ok(body)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_DISPOSITION, "attachment; filename=profile.pb"),
            ],
            body,
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "cannot build the CPU profile");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot build the CPU profile: {e}"),
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "CPU profile task ended abnormally");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CPU profile task ended abnormally",
            )
        }
    }
}

/// Failure of turning the collected samples into `profile.proto` bytes.
#[derive(Debug, thiserror::Error)]
enum EncodeError {
    #[error("resolving the sampled frames")]
    Report(#[from] pprof::Error),
    #[error("encoding profile.proto")]
    Encode(#[source] Box<dyn std::error::Error + Send + Sync>),
}

fn encode_profile(guard: &pprof::ProfilerGuard<'_>) -> Result<Vec<u8>, EncodeError> {
    let report = guard.report().build()?;
    let profile = report.pprof()?;
    profile
        .write_to_bytes()
        .map_err(|e| EncodeError::Encode(Box::new(e)))
}

/// Query of `GET /debug/pprof/heap`.
#[derive(Debug, Deserialize)]
struct HeapQuery {
    debug: Option<String>,
}

/// The route list `GET /debug/pprof/` answers, one `path<TAB>description` per line.
const INDEX: &str = "/debug/pprof/profile?seconds=N\tCPU profile, profile.proto\n\
                     /debug/pprof/heap\tprocess memory summary (JSON)\n\
                     /debug/pprof/heap?debug=1\tprocess memory summary (text)\n";

async fn index() -> Response {
    text(StatusCode::OK, INDEX)
}

async fn heap(Query(query): Query<HeapQuery>) -> Response {
    // `debug=1` is the reference plain-text rendering; absent or `0` is the JSON summary
    let as_text = match query.debug.as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        Some(other) => {
            return text(
                StatusCode::BAD_REQUEST,
                format!("debug must be 0 or 1, got {other:?}"),
            )
        }
    };
    match tokio::task::spawn_blocking(HeapReport::sample).await {
        Ok(report) if as_text => text(StatusCode::OK, report.to_text()),
        Ok(report) => Json(report).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "memory sample task ended abnormally");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "memory sample task ended abnormally",
            )
        }
    }
}

/// What `GET /debug/pprof/heap` returns: memory sizes read from the operating system for this
/// process, no allocator statistics. A field is `null` when its source cannot be read (no
/// `/proc`, a line the kernel does not report).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct HeapReport {
    /// Where the numbers come from.
    pub source: &'static str,
    /// Process id.
    pub pid: u32,
    /// Resident set size of this process (`VmRSS` of `/proc/self/status`), in bytes.
    pub rss_bytes: Option<u64>,
    /// Peak resident set size so far (`VmHWM`), in bytes.
    pub peak_rss_bytes: Option<u64>,
    /// Virtual memory size (`VmSize`), in bytes.
    pub virtual_bytes: Option<u64>,
    /// Private data and stack size, which includes the heap (`VmData`), in bytes.
    pub data_bytes: Option<u64>,
    /// Swapped-out size (`VmSwap`), in bytes.
    pub swap_bytes: Option<u64>,
    /// Kernel threads of the process (`Threads`).
    pub threads: Option<u64>,
    /// Resident set size of this process plus every descendant (a browser's renderers and GPU
    /// process), the quantity the browser sampler behind `crawlx.browser.rss_bytes` computes
    /// (`crawlx_browser::launch::tree_rss_bytes`), in bytes.
    pub rss_tree_bytes: Option<u64>,
    /// Last value the browser sampler wrote to the `crawlx.browser.rss_bytes` gauge in this
    /// process, in bytes; `null` when no browser was launched here.
    pub browser_rss_gauge_bytes: Option<f64>,
}

impl HeapReport {
    /// Read the numbers now (blocking file reads of `/proc`).
    #[must_use]
    pub fn sample() -> Self {
        let pid = std::process::id();
        let status = std::fs::read_to_string("/proc/self/status").ok();
        let bytes = |key: &str| {
            status
                .as_deref()
                .and_then(|text| status_value(text, key)?.checked_mul(1024))
        };
        Self {
            source: "procfs",
            pid,
            rss_bytes: status.as_deref().and_then(crawlx_browser::launch::rss_bytes_of),
            peak_rss_bytes: bytes("VmHWM"),
            virtual_bytes: bytes("VmSize"),
            data_bytes: bytes("VmData"),
            swap_bytes: bytes("VmSwap"),
            threads: status.as_deref().and_then(|text| status_value(text, "Threads")),
            rss_tree_bytes: crawlx_browser::launch::tree_rss_bytes(pid).ok(),
            browser_rss_gauge_bytes: crawlx_telemetry::Metrics::global()
                .gauge(crawlx_telemetry::metrics::names::BROWSER_RSS_BYTES)
                .get(&[]),
        }
    }

    /// The same numbers as `# Name = value` lines (`n/a` where unreadable), the plain-text
    /// shape of the reference heap summary (`?debug=1`). Only sizes and counts: no label, URL,
    /// path, header or page content ever appears here.
    #[must_use]
    pub fn to_text(&self) -> String {
        fn bytes(v: Option<u64>) -> String {
            v.map_or_else(|| "n/a".to_owned(), |n| n.to_string())
        }
        format!(
            "heap summary (source: {}; allocator statistics are not available in this build)\n\
             # Pid = {}\n# RssBytes = {}\n# PeakRssBytes = {}\n# VirtualBytes = {}\n# DataBytes = {}\n\
             # SwapBytes = {}\n# Threads = {}\n# RssTreeBytes = {}\n# BrowserRssGaugeBytes = {}\n",
            self.source,
            self.pid,
            bytes(self.rss_bytes),
            bytes(self.peak_rss_bytes),
            bytes(self.virtual_bytes),
            bytes(self.data_bytes),
            bytes(self.swap_bytes),
            bytes(self.threads),
            bytes(self.rss_tree_bytes),
            self.browser_rss_gauge_bytes
                .map_or_else(|| "n/a".to_owned(), |g| format!("{g:.0}")),
        )
    }
}

/// The number on the `<key>:` line of a `/proc/<pid>/status` text (kB for the `Vm*` keys).
fn status_value(status: &str, key: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn seconds_default_clamp_and_reject() {
        let secs = |raw: Option<&str>| parse_seconds(raw).map(|d| d.as_secs());
        assert_eq!(secs(None), Ok(10));
        assert_eq!(secs(Some("0")), Ok(1));
        assert_eq!(secs(Some("1")), Ok(1));
        assert_eq!(secs(Some("37")), Ok(37));
        assert_eq!(secs(Some("120")), Ok(120));
        assert_eq!(secs(Some("999")), Ok(120));
        for bad in ["abc", "-1", "1.5", "", " 5", "1e3", "99999999999999999999999"] {
            assert_eq!(secs(Some(bad)), Err(InvalidSeconds(bad.to_owned())), "{bad:?}");
        }
    }

    #[test]
    fn status_values_are_read_by_exact_key() {
        let status = "Name:\tcrawlx\nVmHWM:\t  2048 kB\nVmRSS:\t  1024 kB\nVmRSSx:\t 7 kB\nThreads:\t9\nVmSwap:\tlots kB\n";
        assert_eq!(status_value(status, "VmHWM"), Some(2048));
        assert_eq!(status_value(status, "VmRSS"), Some(1024));
        assert_eq!(status_value(status, "Threads"), Some(9));
        assert_eq!(status_value(status, "VmSwap"), None);
        assert_eq!(status_value(status, "VmData"), None);
        assert_eq!(status_value(status, "Vm"), None);
    }
}
