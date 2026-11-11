//! `load`: an open-loop HTTP load generator for `crawlx serve`.
//!
//! Requests are scheduled at a fixed rate from a seeded route mix, independently of when the
//! previous ones complete (open loop, as `oha`/`k6` do), so a slow server shows up as latency
//! rather than as a lower achieved rate. Routes: `POST /v1/crawls` (each created run is
//! cancelled at once so the tenant's active-run quota never saturates), `GET /v1/crawls/{id}`,
//! `GET /v1/crawls/{id}/pages`, `GET /v1/crawls/{id}/coverage`, and the SSE stream
//! `GET /v1/crawls/{id}/events` (latency until
//! the stream is open, i.e. the response headers; a queued run emits no event and the keepalive
//! comment comes every 15 s, so the body is not awaited and the stream is dropped). Reads go to
//! a pool of runs created before the clock starts. Per-route latency percentiles and error
//! rates are the output; the target is a p95 under 150 ms for the metadata routes.

use crate::error::BenchError;
use crate::netfault::{AppliedFault, FaultSchedule, Proxy, ProxyStats};
use crate::stats::quantile;
use crawlx_core::seed::CrawlSeed;
use rand::RngExt as _;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Routes the generator drives. Names are the `route` label of the report.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Route {
    /// `POST /v1/crawls`.
    Create,
    /// `POST /v1/crawls/{id}:cancel` (issued after every `Create`).
    Cancel,
    /// `GET /v1/crawls/{id}`.
    Get,
    /// `GET /v1/crawls/{id}/pages?limit=20`.
    Pages,
    /// `GET /v1/crawls/{id}/coverage`.
    Coverage,
    /// `GET /v1/crawls/{id}/events` until the stream is open (response headers).
    Events,
}

impl Route {
    /// Report label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Create => "POST /v1/crawls",
            Self::Cancel => "POST /v1/crawls/{id}:cancel",
            Self::Get => "GET /v1/crawls/{id}",
            Self::Pages => "GET /v1/crawls/{id}/pages",
            Self::Coverage => "GET /v1/crawls/{id}/coverage",
            Self::Events => "GET /v1/crawls/{id}/events",
        }
    }
}

/// Relative weights of the scheduled routes (`Cancel` follows every `Create`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Mix {
    /// `GET /v1/crawls/{id}`.
    pub get: u32,
    /// `GET /v1/crawls/{id}/pages`.
    pub pages: u32,
    /// `GET /v1/crawls/{id}/coverage`.
    pub coverage: u32,
    /// `POST /v1/crawls` (+ cancel).
    pub create: u32,
    /// SSE first-bytes.
    pub events: u32,
}

impl Default for Mix {
    /// Reads dominate (100 req/s baseline), writes 5 req/s, SSE a trickle.
    fn default() -> Self {
        Self {
            get: 40,
            pages: 30,
            coverage: 20,
            create: 5,
            events: 5,
        }
    }
}

impl Mix {
    /// Parse `get=40,pages=30,coverage=20,create=5,events=5` (missing keys keep the default).
    ///
    /// # Errors
    /// A `String` naming the malformed item.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut mix = Self::default();
        for item in spec.split(',').filter(|s| !s.is_empty()) {
            let (k, v) = item
                .split_once('=')
                .ok_or_else(|| format!("mix item `{item}` is not key=weight"))?;
            let w: u32 = v.parse().map_err(|e| format!("mix weight `{v}`: {e}"))?;
            match k {
                "get" => mix.get = w,
                "pages" => mix.pages = w,
                "coverage" => mix.coverage = w,
                "create" => mix.create = w,
                "events" => mix.events = w,
                other => return Err(format!("unknown mix key `{other}`")),
            }
        }
        if mix.total() == 0 {
            return Err("mix has no weight".to_owned());
        }
        Ok(mix)
    }

    fn total(self) -> u32 {
        self.get + self.pages + self.coverage + self.create + self.events
    }

    fn pick(self, roll: u32) -> Route {
        if roll < self.get {
            Route::Get
        } else if roll < self.get + self.pages {
            Route::Pages
        } else if roll < self.get + self.pages + self.coverage {
            Route::Coverage
        } else if roll < self.get + self.pages + self.coverage + self.create {
            Route::Create
        } else {
            Route::Events
        }
    }
}

/// Generator settings.
#[derive(Clone, Debug)]
pub struct LoadConfig {
    /// `http://host:port` of the API.
    pub base_url: String,
    /// Bearer key with `crawls:read` and `crawls:write`.
    pub api_key: String,
    /// Scheduled requests per second.
    pub rps: f64,
    /// Scheduling window.
    pub duration: Duration,
    /// Route mix.
    pub mix: Mix,
    /// Runs created before the clock starts; reads are spread over them.
    pub runs: usize,
    /// Seed of the route sequence.
    pub seed: u64,
    /// Longest wait for the first SSE bytes before the sample counts as an error.
    pub sse_timeout: Duration,
    /// Requests in flight at once; a tick that finds no slot is counted as `dropped`.
    pub max_in_flight: usize,
    /// Seed URL of the created runs.
    pub seed_url: String,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8080".to_owned(),
            api_key: String::new(),
            rps: 50.0,
            duration: Duration::from_secs(20),
            mix: Mix::default(),
            runs: 5,
            seed: 7,
            sse_timeout: Duration::from_secs(5),
            max_in_flight: 256,
            seed_url: "https://app.example.test/".to_owned(),
        }
    }
}

/// Latency and outcome summary of one route.
#[derive(Clone, PartialEq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct RouteStats {
    /// Samples.
    pub requests: u64,
    /// Transport failures (connect, timeout, body read).
    pub transport_errors: u64,
    /// Responses with a status outside `2xx`.
    pub http_errors: u64,
    /// Status code histogram.
    pub status: BTreeMap<u16, u64>,
    /// Mean latency (ms) over every sample, errors included.
    pub mean_ms: f64,
    /// p50 latency (ms).
    pub p50_ms: f64,
    /// p95 latency (ms).
    pub p95_ms: f64,
    /// p99 latency (ms).
    pub p99_ms: f64,
    /// Slowest sample (ms).
    pub max_ms: f64,
}

impl RouteStats {
    /// `(transport + http errors) / requests`, `0` without samples.
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        ratio(self.transport_errors + self.http_errors, self.requests)
    }
}

/// `num / den` as a rate; `0` for an empty denominator.
fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        return 0.0;
    }
    // counts stay far below 2^53
    #[allow(clippy::cast_precision_loss)]
    {
        num as f64 / den as f64
    }
}

/// What the fault proxy did during a [`run_faulted`] run and how the samples split around it.
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct FaultReport {
    /// The schedule in its canonical text form (`latency=50ms@0ms..10000ms,...`).
    pub schedule: String,
    /// Seed the schedule was generated from; `None` for an explicit schedule.
    pub seed: Option<u64>,
    /// The schedule only adds latency: no connection is broken.
    pub latency_only: bool,
    /// Proxy counters at the end of the run.
    pub proxy: ProxyStats,
    /// Faults the proxy applied, with the offsets they really switched on and off.
    pub applied: Vec<AppliedFault>,
    /// `[start, end + tail]` (ms from the first request) of every fault; a request that
    /// overlaps one is counted in `in_fault`.
    pub fault_windows_ms: Vec<(u64, u64)>,
    /// The same for the faults that break connections (blackhole, refuse, reset).
    pub disruption_windows_ms: Vec<(u64, u64)>,
    /// Per-route statistics of the requests that overlapped a fault window.
    pub in_fault: BTreeMap<String, RouteStats>,
    /// Per-route statistics of the requests that did not.
    pub out_of_fault: BTreeMap<String, RouteStats>,
    /// Failed requests that overlapped a disruptive window.
    pub errors_in_disruption: u64,
    /// Failed requests that did not.
    pub errors_outside_disruption: u64,
}

/// Output of [`run`].
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct LoadReport {
    /// Base URL driven.
    pub base_url: String,
    /// Scheduled rate.
    pub target_rps: f64,
    /// Completed samples per second of wall clock (all routes).
    pub achieved_rps: f64,
    /// Wall clock from the first scheduled request to the last completion (s).
    pub elapsed_s: f64,
    /// Route mix.
    pub mix: Mix,
    /// Ticks skipped because `max_in_flight` requests were outstanding.
    pub dropped: u64,
    /// Per-route statistics, keyed by [`Route::label`].
    pub routes: BTreeMap<String, RouteStats>,
    /// Fault-proxy results; present for [`run_faulted`] reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<FaultReport>,
}

impl LoadReport {
    /// Largest p99 over the routes (ms); `0` without samples.
    #[must_use]
    pub fn max_p99_ms(&self) -> f64 {
        self.routes.values().map(|r| r.p99_ms).fold(0.0, f64::max)
    }

    /// Errors over all routes divided by samples over all routes.
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        let requests: u64 = self.routes.values().map(|r| r.requests).sum();
        let errors: u64 = self
            .routes
            .values()
            .map(|r| r.transport_errors + r.http_errors)
            .sum();
        ratio(errors, requests)
    }

    /// Failures of the run's gate, one line each; empty when the run passes.
    ///
    /// Without a fault schedule, or with one that only adds latency, every route's p99 must stay
    /// at or under `max_p99_ms` and no request may fail. With faults that break connections the
    /// p99 gate applies to the requests outside every fault window, and errors are judged by
    /// `allow_errors_during_fault`: when it is set, failures are tolerated for requests that
    /// overlapped a disruptive window and none may occur outside them; when it is not set,
    /// any failure fails the run.
    #[must_use]
    pub fn gate_failures(&self, max_p99_ms: f64, allow_errors_during_fault: bool) -> Vec<String> {
        let mut failures = Vec::new();
        let p99 = |routes: &BTreeMap<String, RouteStats>, failures: &mut Vec<String>| {
            for (route, r) in routes {
                if r.p99_ms > max_p99_ms {
                    failures.push(format!(
                        "{route}: p99 {:.1} ms above {max_p99_ms:.1} ms",
                        r.p99_ms
                    ));
                }
            }
        };
        let any_error = |failures: &mut Vec<String>| {
            for (route, r) in &self.routes {
                if r.error_rate() > 0.0 {
                    failures.push(format!("{route}: error rate {:.4}", r.error_rate()));
                }
            }
        };
        match &self.fault {
            Some(f) if !f.latency_only && !f.disruption_windows_ms.is_empty() => {
                p99(&f.out_of_fault, &mut failures);
                if allow_errors_during_fault {
                    if f.errors_outside_disruption > 0 {
                        failures.push(format!(
                            "{} requests failed outside the fault windows",
                            f.errors_outside_disruption
                        ));
                    }
                } else {
                    any_error(&mut failures);
                }
            }
            _ => {
                p99(&self.routes, &mut failures);
                any_error(&mut failures);
            }
        }
        failures
    }

    /// Markdown table of the report.
    #[must_use]
    pub fn markdown(&self) -> String {
        let mut s = format!(
            "# load: {} at {:.0} rps for {:.1} s (achieved {:.1} rps, dropped {})\n\n| route | requests | errors | p50 ms | p95 ms | p99 ms | max ms |\n|---|---|---|---|---|---|---|\n",
            self.base_url, self.target_rps, self.elapsed_s, self.achieved_rps, self.dropped
        );
        for (route, r) in &self.routes {
            s.push_str(&format!(
                "| `{route}` | {} | {} ({:.2} %) | {:.1} | {:.1} | {:.1} | {:.1} |\n",
                r.requests,
                r.transport_errors + r.http_errors,
                r.error_rate() * 100.0,
                r.p50_ms,
                r.p95_ms,
                r.p99_ms,
                r.max_ms
            ));
        }
        if let Some(f) = &self.fault {
            s.push_str(&format!(
                "\n## faults: `{}`\n\nproxy: {} accepted, {} refused, {} reset, {} bytes up, {} bytes down; {} faults applied; errors in disruption windows {}, outside {}\n\n| route | in-fault requests | in-fault errors | out-of-fault requests | out-of-fault errors | out-of-fault p99 ms |\n|---|---|---|---|---|---|\n",
                f.schedule,
                f.proxy.accepted,
                f.proxy.refused,
                f.proxy.resets,
                f.proxy.bytes_up,
                f.proxy.bytes_down,
                f.applied.len(),
                f.errors_in_disruption,
                f.errors_outside_disruption
            ));
            for route in self.routes.keys() {
                let inside = f.in_fault.get(route);
                let outside = f.out_of_fault.get(route);
                let errors = |r: Option<&RouteStats>| r.map_or(0, |r| r.transport_errors + r.http_errors);
                s.push_str(&format!(
                    "| `{route}` | {} | {} | {} | {} | {:.1} |\n",
                    inside.map_or(0, |r| r.requests),
                    errors(inside),
                    outside.map_or(0, |r| r.requests),
                    errors(outside),
                    outside.map_or(0.0, |r| r.p99_ms)
                ));
            }
        }
        s
    }
}

#[derive(Clone, Copy)]
struct Sample {
    route: Route,
    /// Start of the request, from the start of the request clock.
    offset: Duration,
    latency: Duration,
    /// `None` for a transport failure (no usable response).
    status: Option<u16>,
}

impl Sample {
    /// Transport failure or a status outside `2xx`.
    fn is_error(&self) -> bool {
        self.status.is_none_or(|code| !(200..300).contains(&code))
    }
}

/// `POST /v1/crawls`; the created id and the sample.
#[allow(clippy::disallowed_types, reason = "reviewed API load HTTP driver adapter")]
async fn create_run(client: &reqwest::Client, cfg: &LoadConfig, origin: Instant) -> (Option<String>, Sample) {
    let started = Instant::now();
    let body = serde_json::json!({ "seedUrl": cfg.seed_url, "seed": cfg.seed });
    let res = client
        .post(format!("{}/v1/crawls", cfg.base_url))
        .bearer_auth(&cfg.api_key)
        .json(&body)
        .send()
        .await;
    let (id, status) = match res {
        Ok(res) => {
            let status = res.status().as_u16();
            let id = res
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_owned));
            (id, Some(status))
        }
        Err(_) => (None, None),
    };
    (
        id,
        Sample {
            route: Route::Create,
            offset: started.saturating_duration_since(origin),
            latency: started.elapsed(),
            status,
        },
    )
}

#[allow(clippy::disallowed_types, reason = "reviewed API load HTTP driver adapter")]
struct Shared {
    client: reqwest::Client,
    cfg: LoadConfig,
    runs: Vec<String>,
    /// Start of the request clock; sample offsets count from here.
    origin: Instant,
    samples: parking_lot::Mutex<Vec<Sample>>,
    sse_slots: Semaphore,
}

impl Shared {
    fn record(&self, route: Route, started: Instant, status: Option<u16>) {
        self.samples.lock().push(Sample {
            route,
            offset: started.saturating_duration_since(self.origin),
            latency: started.elapsed(),
            status,
        });
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.cfg.base_url)
    }

    async fn cancel(&self, id: &str) {
        let started = Instant::now();
        let res = self
            .client
            .post(self.url(&format!("/v1/crawls/{id}:cancel")))
            .bearer_auth(&self.cfg.api_key)
            .send()
            .await;
        match res {
            Ok(res) => {
                let status = res.status().as_u16();
                let _ = res.bytes().await;
                self.record(Route::Cancel, started, Some(status));
            }
            Err(_) => self.record(Route::Cancel, started, None),
        }
    }

    async fn get(&self, route: Route, path: String) {
        let started = Instant::now();
        let res = self
            .client
            .get(self.url(&path))
            .bearer_auth(&self.cfg.api_key)
            .send()
            .await;
        match res {
            Ok(res) => {
                let status = res.status().as_u16();
                let body_ok = res.bytes().await.is_ok();
                self.record(route, started, body_ok.then_some(status));
            }
            Err(_) => self.record(route, started, None),
        }
    }

    async fn events(&self, id: &str) {
        let started = Instant::now();
        let req = self
            .client
            .get(self.url(&format!("/v1/crawls/{id}/events")))
            .bearer_auth(&self.cfg.api_key)
            .header("accept", "text/event-stream")
            .send();
        match tokio::time::timeout(self.cfg.sse_timeout, req).await {
            Ok(Ok(res)) => {
                self.record(Route::Events, started, Some(res.status().as_u16()));
                // dropping the response closes the stream and frees the per-run slot
                drop(res);
            }
            _ => self.record(Route::Events, started, None),
        }
    }

    async fn drive(self: Arc<Self>, route: Route, run_index: usize) {
        let id = &self.runs[run_index];
        match route {
            Route::Create | Route::Cancel => {
                let (created, sample) = create_run(&self.client, &self.cfg, self.origin).await;
                self.samples.lock().push(sample);
                if let Some(created) = created {
                    self.cancel(&created).await;
                }
            }
            Route::Get => self.get(Route::Get, format!("/v1/crawls/{id}")).await,
            Route::Pages => {
                self.get(Route::Pages, format!("/v1/crawls/{id}/pages?limit=20"))
                    .await
            }
            Route::Coverage => {
                self.get(Route::Coverage, format!("/v1/crawls/{id}/coverage"))
                    .await
            }
            Route::Events => match self.sse_slots.try_acquire() {
                Ok(_permit) => self.events(id).await,
                // the per-run stream cap is reached: a metadata read instead of a refused stream
                Err(_) => self.get(Route::Get, format!("/v1/crawls/{id}")).await,
            },
        }
    }
}

/// Drive the API per `cfg` and summarise.
///
/// # Errors
/// [`BenchError::Ablation`] when the HTTP client cannot be built, the run pool cannot be
/// created, or `cfg.rps`/`cfg.runs` is zero.
pub async fn run(cfg: &LoadConfig) -> Result<LoadReport, BenchError> {
    run_inner(cfg, || {}).await.map(|(report, _)| report)
}

/// Time after the end of a fault during which a request that was in flight when the fault
/// ended can still fail because of it.
pub const FAULT_TAIL: Duration = Duration::from_secs(1);

/// Drive the API through an in-process fault proxy that applies `schedule` from the moment
/// the request clock starts (the run pool is created before, unfaulted), and summarise.
///
/// `cfg.base_url` must be an `http://` URL; the proxy listens on an ephemeral loopback port in
/// front of it. The report splits every route's samples by whether the request overlapped a
/// fault window (plus [`FAULT_TAIL`]) and carries the proxy counters; `seed` is recorded when
/// the schedule was generated from one. Judge the result with [`LoadReport::gate_failures`].
///
/// # Errors
/// [`BenchError::Ablation`] when the base URL is not a resolvable `http://` URL or as for
/// [`run`]; [`BenchError::Bind`] / [`BenchError::LocalAddr`] when the proxy cannot listen.
pub async fn run_faulted(
    cfg: &LoadConfig,
    schedule: &FaultSchedule,
    seed: Option<u64>,
) -> Result<LoadReport, BenchError> {
    let bad_base =
        |why: &str| BenchError::Ablation(format!("load: --fault needs an http:// base URL: {why}"));
    let url = url::Url::parse(&cfg.base_url).map_err(|e| bad_base(&e.to_string()))?;
    if url.scheme() != "http" {
        return Err(bad_base(&format!("`{}` is {}", cfg.base_url, url.scheme())));
    }
    let host = url.host_str().ok_or_else(|| bad_base("no host"))?;
    let port = url.port_or_known_default().ok_or_else(|| bad_base("no port"))?;
    let upstream: SocketAddr = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| bad_base(&format!("resolve {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| bad_base(&format!("{host}:{port} does not resolve")))?;
    let proxy = Proxy::start(upstream).await?;
    let mut through = cfg.clone();
    through.base_url = format!("http://{}", proxy.addr());

    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let cancel = CancellationToken::new();
    let driver = async {
        if go_rx.await.is_ok() {
            proxy.run_schedule(schedule, cancel.clone()).await
        } else {
            Vec::new()
        }
    };
    let load = async {
        let result = run_inner(&through, move || {
            let _ = go_tx.send(());
        })
        .await;
        cancel.cancel();
        result
    };
    let (result, applied) = tokio::join!(load, driver);
    let proxy_stats = proxy.stats();
    proxy.shutdown().await;
    let (mut report, samples) = result?;

    let fault_windows = schedule.windows(FAULT_TAIL, |_| true);
    let disruption = schedule.windows(FAULT_TAIL, crate::netfault::Fault::kills_connections);
    let (inside, outside): (Vec<Sample>, Vec<Sample>) =
        samples.iter().copied().partition(|s| overlaps(&fault_windows, s));
    let errors = |disrupted: bool| {
        let n = samples
            .iter()
            .filter(|s| s.is_error() && overlaps(&disruption, s) == disrupted)
            .count();
        u64::try_from(n).unwrap_or(u64::MAX)
    };
    let in_disruption = errors(true);
    let outside_disruption = errors(false);
    let millis = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let to_ms = |ws: &[(Duration, Duration)]| -> Vec<(u64, u64)> {
        ws.iter().map(|(a, b)| (millis(*a), millis(*b))).collect()
    };
    report.base_url.clone_from(&cfg.base_url);
    report.fault = Some(FaultReport {
        schedule: schedule.to_string(),
        seed,
        latency_only: schedule.latency_only(),
        proxy: proxy_stats,
        applied,
        fault_windows_ms: to_ms(&fault_windows),
        disruption_windows_ms: to_ms(&disruption),
        in_fault: route_stats(&inside),
        out_of_fault: route_stats(&outside),
        errors_in_disruption: in_disruption,
        errors_outside_disruption: outside_disruption,
    });
    Ok(report)
}

/// Did the request overlap any of the `windows` (offsets from the start of the run)?
fn overlaps(windows: &[(Duration, Duration)], s: &Sample) -> bool {
    let (from, to) = (s.offset, s.offset.saturating_add(s.latency));
    windows.iter().any(|(start, end)| from <= *end && to >= *start)
}

#[allow(clippy::disallowed_types, reason = "reviewed API load HTTP driver adapter")]
async fn run_inner(
    cfg: &LoadConfig,
    on_clock_start: impl FnOnce(),
) -> Result<(LoadReport, Vec<Sample>), BenchError> {
    if cfg.rps <= 0.0 || !cfg.rps.is_finite() || cfg.runs == 0 {
        return Err(BenchError::Ablation(
            "load: rps and runs must be positive".to_owned(),
        ));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(cfg.max_in_flight)
        .build()
        .map_err(|e| BenchError::Ablation(format!("load: http client: {e}")))?;
    let mut runs = Vec::with_capacity(cfg.runs);
    for _ in 0..cfg.runs {
        let (id, sample) = create_run(&client, cfg, Instant::now()).await;
        let id = id.ok_or_else(|| {
            BenchError::Ablation(format!(
                "load: could not create the run pool (status {:?})",
                sample.status
            ))
        })?;
        runs.push(id);
    }
    let in_flight = Arc::new(Semaphore::new(cfg.max_in_flight));
    let mut rng = CrawlSeed(cfg.seed).rng("load", &[]);
    let total = cfg.mix.total();
    let interval = Duration::from_secs_f64(1.0 / cfg.rps);
    // `duration * rps` is a small count of ticks
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ticks = (cfg.duration.as_secs_f64() * cfg.rps).floor() as u32;
    let mut tasks = JoinSet::new();
    let mut dropped = 0u64;
    let start = Instant::now();
    let shared = Arc::new(Shared {
        client,
        cfg: cfg.clone(),
        runs,
        origin: start,
        samples: parking_lot::Mutex::new(Vec::new()),
        // 5 SSE streams per run; keep one spare per run
        sse_slots: Semaphore::new(cfg.runs * 4),
    });
    on_clock_start();
    for i in 0..ticks {
        tokio::time::sleep_until((start + interval * i).into()).await;
        let route = cfg.mix.pick(rng.random_range(0..total));
        let run_index = rng.random_range(0..cfg.runs);
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            dropped += 1;
            continue;
        };
        let shared = shared.clone();
        tasks.spawn(async move {
            shared.drive(route, run_index).await;
            drop(permit);
        });
        while let Some(res) = tasks.try_join_next() {
            if let Err(e) = res {
                tracing::warn!(error = %e, "load: request task failed");
            }
        }
    }
    while let Some(res) = tasks.join_next().await {
        if let Err(e) = res {
            tracing::warn!(error = %e, "load: request task failed");
        }
    }
    let elapsed = start.elapsed();
    let samples = std::mem::take(&mut *shared.samples.lock());
    let report = summarise(cfg, &samples, elapsed, dropped);
    Ok((report, samples))
}

fn route_stats(samples: &[Sample]) -> BTreeMap<String, RouteStats> {
    let mut by_route: BTreeMap<Route, Vec<Sample>> = BTreeMap::new();
    for s in samples {
        by_route.entry(s.route).or_default().push(*s);
    }
    let mut routes = BTreeMap::new();
    for (route, xs) in by_route {
        let mut ms: Vec<f64> = xs.iter().map(|s| s.latency.as_secs_f64() * 1000.0).collect();
        ms.sort_by(f64::total_cmp);
        let mut stats = RouteStats {
            requests: u64::try_from(xs.len()).unwrap_or(u64::MAX),
            ..RouteStats::default()
        };
        for s in &xs {
            match s.status {
                None => stats.transport_errors += 1,
                Some(code) => {
                    *stats.status.entry(code).or_default() += 1;
                    if !(200..300).contains(&code) {
                        stats.http_errors += 1;
                    }
                }
            }
        }
        stats.mean_ms =
            ms.iter().sum::<f64>() / f64::from(u32::try_from(ms.len().max(1)).unwrap_or(u32::MAX));
        stats.p50_ms = quantile(&ms, 0.50).unwrap_or(0.0);
        stats.p95_ms = quantile(&ms, 0.95).unwrap_or(0.0);
        stats.p99_ms = quantile(&ms, 0.99).unwrap_or(0.0);
        stats.max_ms = ms.last().copied().unwrap_or(0.0);
        routes.insert(route.label().to_owned(), stats);
    }
    routes
}

fn summarise(cfg: &LoadConfig, samples: &[Sample], elapsed: Duration, dropped: u64) -> LoadReport {
    let completed = u64::try_from(samples.len()).unwrap_or(u64::MAX);
    LoadReport {
        base_url: cfg.base_url.clone(),
        target_rps: cfg.rps,
        achieved_rps: if elapsed.is_zero() {
            0.0
        } else {
            ratio(completed, 1) / elapsed.as_secs_f64()
        },
        elapsed_s: elapsed.as_secs_f64(),
        mix: cfg.mix,
        dropped,
        routes: route_stats(samples),
        fault: None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn route(requests: u64, errors: u64, p99_ms: f64) -> RouteStats {
        RouteStats {
            requests,
            transport_errors: errors,
            p99_ms,
            ..RouteStats::default()
        }
    }

    fn routes(r: RouteStats) -> BTreeMap<String, RouteStats> {
        BTreeMap::from([("GET /v1/crawls/{id}".to_owned(), r)])
    }

    fn fault(
        latency_only: bool,
        disruptive: bool,
        out_of_fault: RouteStats,
        errors_in: u64,
        errors_out: u64,
    ) -> FaultReport {
        FaultReport {
            schedule: "refuse@1ms..2ms".to_owned(),
            seed: None,
            latency_only,
            proxy: ProxyStats::default(),
            applied: Vec::new(),
            fault_windows_ms: vec![(1, 2)],
            disruption_windows_ms: if disruptive { vec![(1, 2)] } else { Vec::new() },
            in_fault: BTreeMap::new(),
            out_of_fault: routes(out_of_fault),
            errors_in_disruption: errors_in,
            errors_outside_disruption: errors_out,
        }
    }

    fn report(all: RouteStats, fault: Option<FaultReport>) -> LoadReport {
        LoadReport {
            base_url: "http://x".to_owned(),
            target_rps: 1.0,
            achieved_rps: 1.0,
            elapsed_s: 1.0,
            mix: Mix::default(),
            dropped: 0,
            routes: routes(all),
            fault,
        }
    }

    #[test]
    fn without_a_fault_any_error_or_slow_route_fails() {
        assert!(report(route(100, 0, 150.0), None)
            .gate_failures(150.0, false)
            .is_empty());
        let slow = report(route(100, 0, 150.1), None).gate_failures(150.0, false);
        assert_eq!(slow.len(), 1, "{slow:?}");
        assert!(slow[0].contains("p99"));
        let errors = report(route(100, 1, 10.0), None).gate_failures(150.0, false);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("error rate"));
        // the flag changes nothing without a fault
        assert_eq!(
            report(route(100, 1, 10.0), None).gate_failures(150.0, true).len(),
            1
        );
    }

    #[test]
    fn latency_only_schedules_keep_the_p99_gate_and_zero_errors_even_with_the_flag() {
        let clean = report(
            route(100, 0, 90.0),
            Some(fault(true, false, route(10, 0, 10.0), 0, 0)),
        );
        assert!(clean.gate_failures(150.0, true).is_empty());
        // the p99 gate covers the in-window requests too: all routes, not only out-of-fault ones
        let slow = report(
            route(100, 0, 400.0),
            Some(fault(true, false, route(10, 0, 10.0), 0, 0)),
        );
        assert_eq!(slow.gate_failures(150.0, true).len(), 1);
        // errors are never tolerated: nothing in the schedule breaks a connection
        let errors = report(
            route(100, 3, 90.0),
            Some(fault(true, false, route(10, 0, 10.0), 3, 0)),
        );
        assert_eq!(errors.gate_failures(150.0, true).len(), 1);
        assert_eq!(errors.gate_failures(150.0, false).len(), 1);
    }

    #[test]
    fn connection_kills_allow_errors_only_inside_their_windows_and_only_with_the_flag() {
        let inside = report(
            route(100, 4, 5000.0),
            Some(fault(false, true, route(60, 0, 20.0), 4, 0)),
        );
        // failures inside the window, slow in-window requests: tolerated with the flag
        assert!(
            inside.gate_failures(150.0, true).is_empty(),
            "{:?}",
            inside.gate_failures(150.0, true)
        );
        // without the flag any failure fails
        let strict = inside.gate_failures(150.0, false);
        assert_eq!(strict.len(), 1, "{strict:?}");
        assert!(strict[0].contains("error rate"));

        // a failure outside every window fails even with the flag
        let outside = report(
            route(100, 5, 80.0),
            Some(fault(false, true, route(60, 1, 20.0), 4, 1)),
        );
        let failures = outside.gate_failures(150.0, true);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("outside the fault windows"));

        // the p99 gate judges the out-of-fault requests
        let slow_outside = report(
            route(100, 0, 90.0),
            Some(fault(false, true, route(60, 0, 400.0), 0, 0)),
        );
        assert_eq!(slow_outside.gate_failures(150.0, true).len(), 1);
    }

    #[test]
    fn a_request_belongs_to_a_window_when_its_lifetime_touches_it() {
        let ms = Duration::from_millis;
        let sample = Sample {
            route: Route::Get,
            offset: ms(100),
            latency: ms(50),
            status: Some(200),
        };
        assert!(
            overlaps(&[(ms(0), ms(100))], &sample),
            "ends exactly when the request starts"
        );
        assert!(
            overlaps(&[(ms(150), ms(200))], &sample),
            "starts exactly when it finishes"
        );
        assert!(overlaps(&[(ms(120), ms(130))], &sample), "inside the request");
        assert!(!overlaps(&[(ms(0), ms(99))], &sample));
        assert!(!overlaps(&[(ms(151), ms(200))], &sample));
        assert!(!overlaps(&[], &sample));
        assert!(!sample.is_error());
        assert!(Sample {
            status: None,
            ..sample
        }
        .is_error());
        assert!(Sample {
            status: Some(503),
            ..sample
        }
        .is_error());
    }
}
