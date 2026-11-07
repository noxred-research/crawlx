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
use crate::stats::quantile;
use crawlx_core::seed::CrawlSeed;
use rand::Rng as _;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

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
        s
    }
}

#[derive(Clone, Copy)]
struct Sample {
    route: Route,
    latency: Duration,
    /// `None` for a transport failure (no usable response).
    status: Option<u16>,
}

/// `POST /v1/crawls`; the created id and the sample.
async fn create_run(client: &reqwest::Client, cfg: &LoadConfig) -> (Option<String>, Sample) {
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
            latency: started.elapsed(),
            status,
        },
    )
}

struct Shared {
    client: reqwest::Client,
    cfg: LoadConfig,
    runs: Vec<String>,
    samples: parking_lot::Mutex<Vec<Sample>>,
    sse_slots: Semaphore,
}

impl Shared {
    fn record(&self, route: Route, started: Instant, status: Option<u16>) {
        self.samples.lock().push(Sample {
            route,
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
                let (created, sample) = create_run(&self.client, &self.cfg).await;
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
        let (id, sample) = create_run(&client, cfg).await;
        let id = id.ok_or_else(|| {
            BenchError::Ablation(format!(
                "load: could not create the run pool (status {:?})",
                sample.status
            ))
        })?;
        runs.push(id);
    }
    let shared = Arc::new(Shared {
        client,
        cfg: cfg.clone(),
        runs,
        samples: parking_lot::Mutex::new(Vec::new()),
        // 5 SSE streams per run; keep one spare per run
        sse_slots: Semaphore::new(cfg.runs * 4),
    });

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
    for i in 0..ticks {
        tokio::time::sleep_until((start + interval * i).into()).await;
        let route = cfg.mix.pick(rng.gen_range(0..total));
        let run_index = rng.gen_range(0..cfg.runs);
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
    Ok(summarise(cfg, &samples, elapsed, dropped))
}

fn summarise(cfg: &LoadConfig, samples: &[Sample], elapsed: Duration, dropped: u64) -> LoadReport {
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
        routes,
    }
}
