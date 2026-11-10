//! `crawl-bench`: crawl coverage and throughput of the real URL plane, per target and crawl
//! profile, with baseline comparison (equivalent of a reference crawl-bench tool).
//!
//! # What it measures
//!
//! Every target sits behind a [`recorder::Recorder`] (a loopback reverse proxy). The crawl runs
//! through [`crawlx_worker::run_local_with`] against the proxy, so the numbers that describe
//! the *target* (requests received, `5xx` answers, page latency) are observed server-side, the
//! way the reference harness does it, while the numbers that describe the *crawl* (pages fetched,
//! endpoints discovered, recall) come from the run report. One crawl is a [`Sample`]; `repeat`
//! samples of one target and profile are combined into a [`Metrics`] row by the per-field
//! median (the reference harness's convention), except page latency, whose percentiles are taken over the
//! pooled requests of all repeats.
//!
//! | metric | meaning |
//! |---|---|
//! | `pages` | URLs the crawl fetched successfully (`counters.urls.succeeded`) |
//! | `endpoints` | distinct same-origin paths the crawl learned about: fetched pages, their links, and the endpoints mined from them ([`discovered_endpoints`]) |
//! | `recall` | known endpoints among the discovered ones, `found / known`; present only when the gym fixture ships a ground-truth list ([`known_endpoints`]) |
//! | `requests` | requests the target received, robots and sitemap fetches included |
//! | `errors` | requests the target answered with `5xx` |
//! | `seconds` | wall time of the crawl (`run_local_with` start to finish) |
//! | `rps` | `requests / seconds` |
//! | `p50_ms`, `p95_ms` | latency of every successful `GET`, from reaching the recorder to the last response byte |
//!
//! The aggregate row of a profile sums the counts over all targets, derives `recall` and `rps`
//! from the sums, and takes the latency percentiles over the pooled requests.
//!
//! # Targets
//!
//! * `gym:<fixture>`: a CrawlerGym fixture served by an in-process gym. The gym is reset to the
//!   run seed before every crawl, so repeats and profiles see identical content. `gym:s1`
//!   (static site, sitemap-only pages, robots rules), `gym:g32` (security-crawl-maze) and
//!   `gym:hybrid-mix` carry a known endpoint list; other fixtures report no recall.
//! * `http(s)://...`: an operator-run application (DVWA, Juice Shop, a staging site). The
//!   recorder forwards to its origin; the crawl starts at the URL's path. The recorder is a
//!   test tool: it does not apply the crawl egress policy to the upstream, so only name targets
//!   you are authorized to test.
//!
//! # Profiles
//!
//! All profiles crawl with `mode = static` (the URL plane); they differ in the request.
//!
//! | profile | request |
//! |---|---|
//! | `static` | the gym's reference slice: crawlx request defaults at the gym's pace (the 50 ms per-origin delay floor) |
//! | `crawlx-defaults` | the request defaults of `crawlx crawl` including the production politeness (250 ms per-origin delay) |
//! | `compat-flag-defaults` | the compatibility flag dialect's defaults mapped onto the request, see [`Profile::apply`] |
//!
//! # Baselines
//!
//! `--json FILE` writes the [`Report`]; a later run compares itself to it with
//! `--baseline FILE`. [`compare`] flags a metric that got worse by more than `--max-regress PCT`
//! percent (higher is better for `pages`, `endpoints`, `recall`, `rps`; lower is better for
//! `errors`, `seconds`, `p50_ms`, `p95_ms`; `requests` is informational). Only targets and
//! profiles present in both files are compared, and the aggregate rows only when both files
//! cover the same targets. Timing metrics are noisy: `--gate-metrics` narrows the gate, for
//! example to the deterministic coverage metrics `pages,endpoints,recall`.
//!
//! `bench/baselines/crawl-bench.json` is a recorded report of `gym:s1`, `gym:g32` and
//! `gym:hybrid-mix` under all three profiles (3 repeats, debug build); its coverage numbers are
//! guarded by `tests/crawl_bench.rs`, its timing numbers are the recording machine's. Record a
//! new one after an intended coverage change with the same command and `--json`.
//!
//! Seeds are fixed ([`DEFAULT_SEED`]) and every collection that reaches the output is sorted,
//! so the discovered endpoint set of a gym target is identical across runs; only the timing
//! columns vary.

pub mod recorder;

use crate::error::BenchError;
use crate::gym::fixtures::{crawl_maze, s1};
use crate::gym::manifest::{FixtureManifest, MazePlane};
use crate::gym::{GymHandle, GymServer};
use crate::urlplane::trailing_slash;
use crate::worker_exec::{authorize_fixture, crawl_request_for_url, worker_config_with};
use crawlx_core::config::{
    CrawlMode, CrawlStrategy, CreateCrawl, HostScope, Politeness, QueryPolicy, SafetyProfile, SitemapMode,
};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::PageRecord;
use crawlx_policy::robots::Match;
use crawlx_policy::RobotsTxt;
use crawlx_url::TrailingSlash;
use crawlx_worker::{run_local_with, LocalRun};
use recorder::{Hit, Recorder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use url::Url;

/// Version of the [`Report`] JSON document.
pub const SCHEMA: u32 = 1;

/// Seed of every crawl unless the caller picks another.
pub const DEFAULT_SEED: u64 = 20_261_027;

/// Target label of the aggregate row in tables and [`Regression`]s.
pub const AGGREGATE_LABEL: &str = "(all)";

// ---- profiles -------------------------------------------------------------------------------

/// A named crawl configuration.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum Profile {
    /// The gym's reference static slice (`mode = static`, crawlx request defaults, gym pace).
    Static,
    /// The compatibility flag dialect's defaults mapped onto the request.
    CompatFlagDefaults,
    /// The request defaults of `crawlx crawl`, production politeness included.
    CrawlxDefaults,
}

impl Profile {
    /// Every profile, in table order.
    pub const ALL: [Self; 3] = [Self::Static, Self::CompatFlagDefaults, Self::CrawlxDefaults];

    /// Name used on the command line and as the JSON key.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::CompatFlagDefaults => "compat-flag-defaults",
            Self::CrawlxDefaults => "crawlx-defaults",
        }
    }

    /// Parse a profile name.
    ///
    /// # Errors
    /// [`BenchError::CrawlBench`] listing the valid names.
    pub fn parse(name: &str) -> Result<Self, BenchError> {
        Self::ALL.into_iter().find(|p| p.name() == name).ok_or_else(|| {
            let valid: Vec<&str> = Self::ALL.iter().map(|p| p.name()).collect();
            BenchError::CrawlBench(format!("unknown profile `{name}` (one of {})", valid.join(", ")))
        })
    }

    /// Configure `req` (a [`crawl_request_for_url`] request) for this profile. Every profile
    /// forces `mode = static` and leaves the harness-owned parts (seed, safety profile,
    /// authorization, `limits.urls` and `limits.durationSeconds`) alone.
    ///
    /// `compat-flag-defaults` maps the compatibility flag dialect's defaults like this:
    ///
    /// | compat flag | crawlx request field |
    /// |---|---|
    /// | `-fs rdn` | `scope.hostScope = rdn` |
    /// | `-d 3` | `scope.maxDiscoveryDepth = 3` |
    /// | `-s depth-first` | `scope.strategy = depth_first` |
    /// | `-jc` off | `scope.jsEndpoints = false` |
    /// | `-kf` off | `scope.knownFiles = []`, `scope.sitemap = skip` |
    /// | no query folding | `scope.queryPolicy = keep_all` |
    /// | robots.txt not obeyed | `safety.respectRobotsTxt = false` |
    /// | `-mrs 4MiB`, `-timeout 10`, `-retry 1` | `fetch.maxResponseBytes`, `timeoutMs`, `retries` |
    /// | `-c 10`, `-rl 150`, `-rd 0` | `politeness.maxConcurrency = 10`, `globalRps = 150`, `delayMs = 50` (the crawlx floor), `maxInFlightPerOrigin = 8` (the crawlx ceiling) |
    pub fn apply(self, req: &mut CreateCrawl) {
        req.mode = CrawlMode::Static;
        req.dynamic.enabled = false;
        match self {
            Self::Static => {}
            Self::CrawlxDefaults => req.politeness = Politeness::default(),
            Self::CompatFlagDefaults => {
                req.scope.host_scope = HostScope::Rdn;
                req.scope.max_discovery_depth = 3;
                req.scope.strategy = CrawlStrategy::DepthFirst;
                req.scope.js_endpoints = false;
                req.scope.known_files = Vec::new();
                req.scope.sitemap = SitemapMode::Skip;
                req.scope.query_policy = QueryPolicy::KeepAll;
                req.safety.respect_robots_txt = false;
                req.fetch.max_response_bytes = 4 * 1024 * 1024;
                req.fetch.timeout_ms = 10_000;
                req.fetch.retries = 1;
                req.politeness = Politeness {
                    delay_ms: 50,
                    max_in_flight_per_origin: 8,
                    global_rps: Some(150),
                    max_concurrency: 10,
                    ..Politeness::default()
                };
            }
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ---- targets --------------------------------------------------------------------------------

/// What gets crawled.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Target {
    /// A CrawlerGym fixture by id (`gym:s1`).
    Gym(String),
    /// An operator-run application.
    Url(Url),
}

impl Target {
    /// Parse `gym:<fixture>` or an absolute `http(s)` URL.
    ///
    /// # Errors
    /// [`BenchError::UnknownFixture`] for a fixture outside the catalog,
    /// [`BenchError::CrawlBench`] for anything that is neither form.
    pub fn parse(spec: &str) -> Result<Self, BenchError> {
        if let Some(id) = spec.strip_prefix("gym:") {
            FixtureManifest::embedded(id)?;
            return Ok(Self::Gym(id.to_owned()));
        }
        let bad = |why: String| {
            BenchError::CrawlBench(format!(
                "target `{spec}`: {why} (expected gym:<fixture> or an http(s) URL)"
            ))
        };
        let url = Url::parse(spec).map_err(|e| bad(e.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(bad("not an http(s) URL with a host".to_owned()));
        }
        Ok(Self::Url(url))
    }

    /// The label of the target in tables and JSON: `gym:<fixture>` or the URL.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Gym(id) => format!("gym:{id}"),
            Self::Url(url) => url.as_str().to_owned(),
        }
    }
}

/// A target resolved against the running gym.
struct Prepared {
    name: String,
    upstream: Url,
    entry: String,
    trailing: TrailingSlash,
    known: Option<BTreeSet<String>>,
    fixture: Option<String>,
}

fn prepare(target: &Target, gym: Option<&GymHandle>) -> Result<Prepared, BenchError> {
    match target {
        Target::Gym(id) => {
            let gym =
                gym.ok_or_else(|| BenchError::CrawlBench(format!("gym:{id} needs the in-process gym")))?;
            let manifest = FixtureManifest::embedded(id)?;
            Ok(Prepared {
                name: target.name(),
                upstream: Url::parse(&gym.base_url)?,
                entry: manifest.url_path.clone(),
                trailing: trailing_slash(manifest.expected.trailing_slash),
                known: known_endpoints(&manifest),
                fixture: Some(id.clone()),
            })
        }
        Target::Url(url) => {
            let mut entry = url.path().to_owned();
            if let Some(q) = url.query() {
                entry.push('?');
                entry.push_str(q);
            }
            Ok(Prepared {
                name: target.name(),
                upstream: Url::parse(&url.origin().ascii_serialization())?,
                entry,
                trailing: TrailingSlash::default(),
                known: None,
                fixture: None,
            })
        }
    }
}

// ---- endpoint sets --------------------------------------------------------------------------

/// The endpoint key of a path: the path without query or fragment, a trailing slash removed
/// (the root stays `/`).
fn path_key(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// The endpoint key of `raw` (an absolute URL, or a reference resolved against `origin`), or
/// `None` when it points outside `origin`'s scheme, host and port.
#[must_use]
pub fn endpoint_key(raw: &str, origin: &Url) -> Option<String> {
    let url = origin.join(raw).ok()?;
    (url.origin() == origin.origin()).then(|| path_key(url.path()))
}

/// Every same-origin endpoint a crawl learned about: the fetched pages, the links found on them
/// and the endpoints mined from their content (`metadata.discovered_endpoints`).
#[must_use]
pub fn discovered_endpoints(pages: &[PageRecord], origin: &Url) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for page in pages {
        found.extend(endpoint_key(page.url.url.as_str(), origin));
        for link in &page.links {
            found.extend(endpoint_key(link, origin));
        }
        let mined = page
            .metadata
            .get("discovered_endpoints")
            .and_then(serde_json::Value::as_array);
        for endpoint in mined.into_iter().flatten() {
            if let Some(url) = endpoint.get("url").and_then(serde_json::Value::as_str) {
                found.extend(endpoint_key(url, origin));
            }
        }
    }
    found
}

/// The ground-truth endpoint list of a gym fixture, as endpoint keys, when it has one:
///
/// * `s1`: the pages of its generated link graph that its own `robots.txt` allows;
/// * a fixture with `expected.crawl_maze`: the targets the URL plane is expected to request
///   (`MazePlane::Static`), served under the fixture's test prefix;
/// * a fixture with `expected.url_addressable_pages`: those pages under the fixture path.
///
/// Any other fixture has no endpoint list and reports no recall.
#[must_use]
pub fn known_endpoints(manifest: &FixtureManifest) -> Option<BTreeSet<String>> {
    let keys: BTreeSet<String> = if manifest.id == s1::ID {
        let robots = RobotsTxt::parse(s1::robots_txt("gym.test").as_bytes());
        s1::page_paths()
            .into_iter()
            .filter(|p| !matches!(robots.evaluate("crawlx", p), Match::Disallowed(_)))
            .map(|p| path_key(&p))
            .collect()
    } else if !manifest.expected.crawl_maze.is_empty() {
        manifest
            .expected
            .crawl_maze
            .iter()
            .filter(|t| t.plane == MazePlane::Static)
            .map(|t| path_key(&format!("{}{}", crawl_maze::TEST_PREFIX, t.path)))
            .collect()
    } else if !manifest.expected.url_addressable_pages.is_empty() {
        manifest
            .expected
            .url_addressable_pages
            .iter()
            .map(|p| path_key(&format!("/{}{p}", manifest.id)))
            .collect()
    } else {
        return None;
    };
    (!keys.is_empty()).then_some(keys)
}

// ---- metrics --------------------------------------------------------------------------------

/// The measurements of one target under one profile.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
#[serde(default)]
#[non_exhaustive]
pub struct Metrics {
    /// URLs fetched successfully.
    pub pages: u64,
    /// Distinct same-origin endpoints discovered.
    pub endpoints: u64,
    /// Size of the target's known endpoint list; `None` without ground truth.
    pub known: Option<u64>,
    /// Known endpoints among the discovered ones; `None` without ground truth.
    pub found: Option<u64>,
    /// `found / known`; `None` without ground truth.
    pub recall: Option<f64>,
    /// Requests the target received.
    pub requests: u64,
    /// Requests the target answered with `5xx`.
    pub errors: u64,
    /// Wall time of the crawl in seconds.
    pub seconds: f64,
    /// `requests / seconds`.
    pub rps: f64,
    /// Median latency of the successful `GET`s in milliseconds.
    pub p50_ms: f64,
    /// 95th percentile latency of the successful `GET`s in milliseconds.
    pub p95_ms: f64,
}

/// `name=value` pairs of every metric, as the progress lines print them.
impl std::fmt::Display for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, metric) in Metric::ALL.into_iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{}={}", metric.name(), metric.cell(self))?;
        }
        Ok(())
    }
}

/// One crawl: its metrics plus the raw material the combination steps need.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct Sample {
    /// The metrics of this crawl.
    pub metrics: Metrics,
    /// Latency of every successful `GET` in milliseconds, ascending.
    pub latencies_ms: Vec<f64>,
    /// The discovered endpoint set.
    pub endpoints: BTreeSet<String>,
}

impl Sample {
    /// A sample from its parts; `latencies_ms` is sorted ascending.
    #[must_use]
    pub fn new(metrics: Metrics, mut latencies_ms: Vec<f64>, endpoints: BTreeSet<String>) -> Self {
        latencies_ms.sort_by(f64::total_cmp);
        Self {
            metrics,
            latencies_ms,
            endpoints,
        }
    }
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn ratio(found: u64, known: u64) -> Option<f64> {
    (known > 0).then(|| found as f64 / known as f64)
}

fn per_second(requests: u64, seconds: f64) -> f64 {
    if seconds > 0.0 {
        requests as f64 / seconds
    } else {
        0.0
    }
}

/// Nearest-rank percentile of an ascending slice; `0.0` for an empty one.
#[must_use]
pub fn percentile(sorted: &[f64], percent: u32) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    let percent = usize::try_from(percent.min(100)).unwrap_or(100);
    let rank = (n.saturating_mul(percent).saturating_add(99) / 100).clamp(1, n);
    sorted[rank - 1]
}

/// The metrics of one crawl, from what the run report and the recorder observed.
///
/// `pages` is the number of successful fetches, `discovered` the endpoint set of the crawl,
/// `known` the target's ground-truth list, `hits` the requests the target received and
/// `seconds` the wall time.
#[must_use]
pub fn summarize(
    pages: u64,
    discovered: BTreeSet<String>,
    known: Option<&BTreeSet<String>>,
    hits: &[Hit],
    seconds: f64,
) -> Sample {
    let requests = count(hits.len());
    let errors = count(hits.iter().filter(|h| h.is_error()).count());
    let mut latencies_ms: Vec<f64> = hits
        .iter()
        .filter(|h| h.is_page())
        .map(|h| h.latency.as_secs_f64() * 1000.0)
        .collect();
    latencies_ms.sort_by(f64::total_cmp);
    let known_n = known.map(|k| count(k.len()));
    let found_n = known.map(|k| count(k.intersection(&discovered).count()));
    let metrics = Metrics {
        pages,
        endpoints: count(discovered.len()),
        known: known_n,
        found: found_n,
        recall: known_n.zip(found_n).and_then(|(k, f)| ratio(f, k)),
        requests,
        errors,
        seconds,
        rps: per_second(requests, seconds),
        p50_ms: percentile(&latencies_ms, 50),
        p95_ms: percentile(&latencies_ms, 95),
    };
    Sample {
        metrics,
        latencies_ms,
        endpoints: discovered,
    }
}

/// The element at index `len / 2` of the sorted values (the reference median).
fn median<T: Copy + Ord>(mut values: Vec<T>) -> Option<T> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

fn median_f64(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values.get(values.len() / 2).copied().unwrap_or(0.0)
}

fn pooled(samples: &[Sample]) -> Vec<f64> {
    let mut all: Vec<f64> = samples
        .iter()
        .flat_map(|s| s.latencies_ms.iter().copied())
        .collect();
    all.sort_by(f64::total_cmp);
    all
}

/// Combine the repeats of one target and profile: per-field median, percentiles over the
/// pooled latencies. An empty slice gives all-zero metrics.
#[must_use]
pub fn combine(samples: &[Sample]) -> Metrics {
    let ints =
        |get: fn(&Metrics) -> u64| median(samples.iter().map(|s| get(&s.metrics)).collect()).unwrap_or(0);
    let requests = ints(|m| m.requests);
    let seconds = median_f64(samples.iter().map(|s| s.metrics.seconds).collect());
    let known = samples.first().and_then(|s| s.metrics.known);
    let found = known.and_then(|_| median(samples.iter().filter_map(|s| s.metrics.found).collect()));
    let latencies = pooled(samples);
    Metrics {
        pages: ints(|m| m.pages),
        endpoints: ints(|m| m.endpoints),
        known,
        found,
        recall: known.zip(found).and_then(|(k, f)| ratio(f, k)),
        requests,
        errors: ints(|m| m.errors),
        seconds,
        rps: per_second(requests, seconds),
        p50_ms: percentile(&latencies, 50),
        p95_ms: percentile(&latencies, 95),
    }
}

/// Aggregate of several rows of one profile: counts summed, `recall` and `rps` derived from the
/// sums, percentiles over the pooled latencies.
fn aggregate_rows(rows: &[Metrics], latencies: &[f64]) -> Metrics {
    let sum = |get: fn(&Metrics) -> u64| rows.iter().fold(0u64, |a, m| a.saturating_add(get(m)));
    let sum_opt = |get: fn(&Metrics) -> Option<u64>| rows.iter().filter_map(get).reduce(u64::saturating_add);
    let requests = sum(|m| m.requests);
    let seconds: f64 = rows.iter().map(|m| m.seconds).sum();
    let known = sum_opt(|m| m.known);
    let found = sum_opt(|m| m.found);
    Metrics {
        pages: sum(|m| m.pages),
        endpoints: sum(|m| m.endpoints),
        known,
        found,
        recall: known.zip(found).and_then(|(k, f)| ratio(f, k)),
        requests,
        errors: sum(|m| m.errors),
        seconds,
        rps: per_second(requests, seconds),
        p50_ms: percentile(latencies, 50),
        p95_ms: percentile(latencies, 95),
    }
}

// ---- report ---------------------------------------------------------------------------------

/// The repeats of one target under one profile.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct Row {
    /// Target label ([`Target::name`]).
    pub target: String,
    /// Profile.
    pub profile: Profile,
    /// One sample per repeat.
    pub samples: Vec<Sample>,
}

impl Row {
    /// A row from its samples.
    #[must_use]
    pub fn new(target: impl Into<String>, profile: Profile, samples: Vec<Sample>) -> Self {
        Self {
            target: target.into(),
            profile,
            samples,
        }
    }
}

/// The result of a `crawl-bench` run; also the baseline file format.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct Report {
    /// [`SCHEMA`].
    pub schema: u32,
    /// Crawls per target and profile.
    pub repeat: u32,
    /// Seed of every crawl.
    pub seed: u64,
    /// Median metrics by target, then profile name.
    pub results: BTreeMap<String, BTreeMap<String, Metrics>>,
    /// Aggregate over all targets by profile name.
    pub aggregate: BTreeMap<String, Metrics>,
    /// Discovered endpoints (first repeat) by target, then profile name, ascending.
    pub endpoints: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl Report {
    /// Combine `rows` into a report.
    #[must_use]
    pub fn assemble(repeat: u32, seed: u64, rows: &[Row]) -> Self {
        let mut results: BTreeMap<String, BTreeMap<String, Metrics>> = BTreeMap::new();
        let mut endpoints: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        let mut by_profile: BTreeMap<&'static str, (Vec<Metrics>, Vec<f64>)> = BTreeMap::new();
        for row in rows {
            let metrics = combine(&row.samples);
            let slot = by_profile.entry(row.profile.name()).or_default();
            slot.0.push(metrics.clone());
            slot.1.extend(pooled(&row.samples));
            results
                .entry(row.target.clone())
                .or_default()
                .insert(row.profile.name().to_owned(), metrics);
            endpoints.entry(row.target.clone()).or_default().insert(
                row.profile.name().to_owned(),
                row.samples
                    .first()
                    .map(|s| s.endpoints.iter().cloned().collect())
                    .unwrap_or_default(),
            );
        }
        let aggregate = by_profile
            .into_iter()
            .map(|(profile, (metrics, mut latencies))| {
                latencies.sort_by(f64::total_cmp);
                (profile.to_owned(), aggregate_rows(&metrics, &latencies))
            })
            .collect();
        Self {
            schema: SCHEMA,
            repeat,
            seed,
            results,
            aggregate,
            endpoints,
        }
    }

    /// The report as pretty JSON with a trailing newline.
    ///
    /// # Errors
    /// [`BenchError::Json`] when serialization fails.
    pub fn to_json(&self) -> Result<String, BenchError> {
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Parse a report (a baseline file).
    ///
    /// # Errors
    /// [`BenchError::Json`] on malformed JSON, [`BenchError::CrawlBench`] on a schema other
    /// than [`SCHEMA`].
    pub fn from_json(json: &str) -> Result<Self, BenchError> {
        let report: Self = serde_json::from_str(json)?;
        if report.schema != SCHEMA {
            return Err(BenchError::CrawlBench(format!(
                "report schema {} is not supported (expected {SCHEMA})",
                report.schema
            )));
        }
        Ok(report)
    }

    /// Whether both reports crawled the same set of targets, the precondition for comparing
    /// their aggregate rows.
    #[must_use]
    pub fn covers_same_targets(&self, other: &Self) -> bool {
        self.results.keys().eq(other.results.keys())
    }

    /// The report as an aligned text table, one row per target and profile followed by the
    /// aggregate rows. With a `baseline`, every cell that has a counterpart carries its change
    /// (`+12%`, `-3%`, `=`, `new`); the aggregate rows only when both reports cover the same
    /// targets ([`Self::covers_same_targets`]).
    #[must_use]
    pub fn table(&self, baseline: Option<&Self>) -> String {
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut header = vec!["target".to_owned(), "profile".to_owned()];
        header.extend(Metric::ALL.iter().map(|m| m.name().to_owned()));
        rows.push(header);
        let mut push = |target: &str, profile: &str, cur: &Metrics, base: Option<&Metrics>| {
            let mut cells = vec![target.to_owned(), profile.to_owned()];
            for metric in Metric::ALL {
                let mut cell = metric.cell(cur);
                if let (Some(b), Some(c)) = (base.and_then(|b| metric.value(b)), metric.value(cur)) {
                    cell.push_str(" (");
                    cell.push_str(&delta_label(b, c));
                    cell.push(')');
                }
                cells.push(cell);
            }
            rows.push(cells);
        };
        for (target, profiles) in &self.results {
            for (profile, cur) in profiles {
                let base = baseline
                    .and_then(|b| b.results.get(target))
                    .and_then(|p| p.get(profile));
                push(target, profile, cur, base);
            }
        }
        let comparable = baseline.filter(|b| self.covers_same_targets(b));
        for (profile, cur) in &self.aggregate {
            push(
                AGGREGATE_LABEL,
                profile,
                cur,
                comparable.and_then(|b| b.aggregate.get(profile)),
            );
        }
        render(&rows)
    }
}

/// Left-aligned columns separated by two spaces.
fn render(rows: &[Vec<String>]) -> String {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..columns)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (c, cell) in row.iter().enumerate() {
            if c > 0 {
                line.push_str("  ");
            }
            line.push_str(cell);
            let pad = widths[c].saturating_sub(cell.chars().count());
            line.push_str(&" ".repeat(pad));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The change from `base` to `current` as the reference report prints it.
#[must_use]
pub fn delta_label(base: f64, current: f64) -> String {
    if base == 0.0 {
        return if current == 0.0 {
            "=".to_owned()
        } else {
            "new".to_owned()
        };
    }
    let pct = (current - base) / base * 100.0;
    if (-0.5..0.5).contains(&pct) {
        "=".to_owned()
    } else {
        format!("{pct:+.0}%")
    }
}

// ---- baseline comparison --------------------------------------------------------------------

/// Which way a metric should move.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Direction {
    /// A larger value is an improvement.
    HigherIsBetter,
    /// A smaller value is an improvement.
    LowerIsBetter,
}

/// A column of the report.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum Metric {
    /// [`Metrics::pages`].
    Pages,
    /// [`Metrics::endpoints`].
    Endpoints,
    /// [`Metrics::recall`].
    Recall,
    /// [`Metrics::requests`].
    Requests,
    /// [`Metrics::errors`].
    Errors,
    /// [`Metrics::seconds`].
    Seconds,
    /// [`Metrics::rps`].
    Rps,
    /// [`Metrics::p50_ms`].
    P50Ms,
    /// [`Metrics::p95_ms`].
    P95Ms,
}

impl Metric {
    /// Every metric, in table order.
    pub const ALL: [Self; 9] = [
        Self::Pages,
        Self::Endpoints,
        Self::Recall,
        Self::Requests,
        Self::Errors,
        Self::Seconds,
        Self::Rps,
        Self::P50Ms,
        Self::P95Ms,
    ];

    /// Column and JSON name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pages => "pages",
            Self::Endpoints => "endpoints",
            Self::Recall => "recall",
            Self::Requests => "requests",
            Self::Errors => "errors",
            Self::Seconds => "seconds",
            Self::Rps => "rps",
            Self::P50Ms => "p50_ms",
            Self::P95Ms => "p95_ms",
        }
    }

    /// Parse a column name.
    ///
    /// # Errors
    /// [`BenchError::CrawlBench`] listing the valid names.
    pub fn parse(name: &str) -> Result<Self, BenchError> {
        Self::ALL.into_iter().find(|m| m.name() == name).ok_or_else(|| {
            let valid: Vec<&str> = Self::ALL.iter().map(|m| m.name()).collect();
            BenchError::CrawlBench(format!("unknown metric `{name}` (one of {})", valid.join(", ")))
        })
    }

    /// Which way the metric should move; `None` for `requests`, which is informational (a crawl
    /// that asks for less is not worse, nor better).
    #[must_use]
    pub const fn direction(self) -> Option<Direction> {
        match self {
            Self::Pages | Self::Endpoints | Self::Recall | Self::Rps => Some(Direction::HigherIsBetter),
            Self::Errors | Self::Seconds | Self::P50Ms | Self::P95Ms => Some(Direction::LowerIsBetter),
            Self::Requests => None,
        }
    }

    /// The metrics a baseline comparison gates on unless told otherwise: every metric with a
    /// [`Direction`].
    #[must_use]
    pub fn gated() -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|m| m.direction().is_some())
            .collect()
    }

    /// The value of this metric in `m`; `None` when it is absent (`recall` without ground truth).
    #[must_use]
    pub fn value(self, m: &Metrics) -> Option<f64> {
        Some(match self {
            Self::Pages => m.pages as f64,
            Self::Endpoints => m.endpoints as f64,
            Self::Recall => m.recall?,
            Self::Requests => m.requests as f64,
            Self::Errors => m.errors as f64,
            Self::Seconds => m.seconds,
            Self::Rps => m.rps,
            Self::P50Ms => m.p50_ms,
            Self::P95Ms => m.p95_ms,
        })
    }

    fn cell(self, m: &Metrics) -> String {
        match (self, self.value(m)) {
            (_, None) => "-".to_owned(),
            (Self::Recall, Some(v)) => format!("{:.1}%", v * 100.0),
            (Self::Seconds | Self::P50Ms | Self::P95Ms, Some(v)) => format!("{v:.2}"),
            (Self::Rps, Some(v)) => format!("{v:.1}"),
            (_, Some(v)) => format!("{v}"),
        }
    }
}

/// A metric that got worse than the baseline by more than the allowed percentage.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct Regression {
    /// Target label, or [`AGGREGATE_LABEL`].
    pub target: String,
    /// Profile name.
    pub profile: String,
    /// The metric.
    pub metric: Metric,
    /// Baseline value.
    pub baseline: f64,
    /// Current value.
    pub current: f64,
    /// How much worse the current value is, in percent of the baseline (`inf` when a
    /// lower-is-better metric left zero).
    pub worse_pct: f64,
}

impl std::fmt::Display for Regression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}: {} {} -> {} ({} worse)",
            self.target,
            self.profile,
            self.metric.name(),
            self.baseline,
            self.current,
            if self.worse_pct.is_finite() {
                format!("{:.1}%", self.worse_pct)
            } else {
                "from zero".to_owned()
            }
        )
    }
}

/// How much worse `current` is than `baseline`, in percent of the baseline; negative when it
/// improved.
fn worse_pct(direction: Direction, baseline: f64, current: f64) -> f64 {
    match direction {
        Direction::HigherIsBetter if baseline <= 0.0 => 0.0,
        Direction::HigherIsBetter => (baseline - current) / baseline * 100.0,
        Direction::LowerIsBetter if baseline <= 0.0 => {
            if current > 0.0 {
                f64::INFINITY
            } else {
                0.0
            }
        }
        Direction::LowerIsBetter => (current - baseline) / baseline * 100.0,
    }
}

/// Compare `current` with `baseline` on the `gate` metrics: every cell present in both reports
/// whose value got worse by more than `max_regress_pct` percent is returned, ordered by target,
/// profile, metric. Metrics without a [`Direction`] and cells absent from either report are
/// skipped. The aggregate rows are compared only when both reports cover the same targets (the
/// aggregate of a subset says nothing about the aggregate of the whole).
///
/// # Errors
/// [`BenchError::CrawlBench`] when `max_regress_pct` is negative or not finite, or `gate` names a
/// metric without a direction.
pub fn compare(
    current: &Report,
    baseline: &Report,
    max_regress_pct: f64,
    gate: &[Metric],
) -> Result<Vec<Regression>, BenchError> {
    if !max_regress_pct.is_finite() || max_regress_pct < 0.0 {
        return Err(BenchError::CrawlBench(format!(
            "--max-regress must be a non-negative number, got {max_regress_pct}"
        )));
    }
    if let Some(m) = gate.iter().find(|m| m.direction().is_none()) {
        return Err(BenchError::CrawlBench(format!(
            "metric `{}` has no better or worse direction and cannot be gated",
            m.name()
        )));
    }
    let mut gate = gate.to_vec();
    gate.sort_unstable();
    gate.dedup();

    let mut cells: Vec<(&str, &str, &Metrics, &Metrics)> = Vec::new();
    for (target, profiles) in &current.results {
        let Some(base_profiles) = baseline.results.get(target) else {
            continue;
        };
        for (profile, cur) in profiles {
            if let Some(base) = base_profiles.get(profile) {
                cells.push((target.as_str(), profile.as_str(), cur, base));
            }
        }
    }
    if current.covers_same_targets(baseline) {
        for (profile, cur) in &current.aggregate {
            if let Some(base) = baseline.aggregate.get(profile) {
                cells.push((AGGREGATE_LABEL, profile.as_str(), cur, base));
            }
        }
    }

    let mut out = Vec::new();
    for (target, profile, cur, base) in cells {
        for &metric in &gate {
            let (Some(direction), Some(b), Some(c)) =
                (metric.direction(), metric.value(base), metric.value(cur))
            else {
                continue;
            };
            let worse = worse_pct(direction, b, c);
            if worse > max_regress_pct {
                out.push(Regression {
                    target: target.to_owned(),
                    profile: profile.to_owned(),
                    metric,
                    baseline: b,
                    current: c,
                    worse_pct: worse,
                });
            }
        }
    }
    out.sort_by(|a, b| (&a.target, &a.profile, a.metric).cmp(&(&b.target, &b.profile, b.metric)));
    Ok(out)
}

// ---- running --------------------------------------------------------------------------------

/// What to crawl and how often.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct BenchConfig {
    /// Targets, crawled in this order.
    pub targets: Vec<Target>,
    /// Profiles, crawled in this order for every target.
    pub profiles: Vec<Profile>,
    /// Crawls per target and profile (at least 1).
    pub repeat: u32,
    /// Seed of every crawl and of the gym.
    pub seed: u64,
    /// Wall-clock budget of one crawl in seconds (`limits.durationSeconds`).
    pub duration_seconds: u32,
    /// URL budget of one crawl (`limits.urls`).
    pub max_pages: u32,
}

impl BenchConfig {
    /// `targets` under the `static` profile, three repeats, [`DEFAULT_SEED`], a 120 s budget
    /// and 10,000 URLs per crawl.
    #[must_use]
    pub fn new(targets: Vec<Target>) -> Self {
        Self {
            targets,
            profiles: vec![Profile::Static],
            repeat: 3,
            seed: DEFAULT_SEED,
            duration_seconds: 120,
            max_pages: 10_000,
        }
    }

    /// Check that the configuration describes at least one crawl and names nothing twice.
    ///
    /// # Errors
    /// [`BenchError::CrawlBench`] naming the first violation.
    pub fn validate(&self) -> Result<(), BenchError> {
        let bad = |why: &str| Err(BenchError::CrawlBench(why.to_owned()));
        if self.targets.is_empty() {
            return bad("at least one target is required");
        }
        if self.profiles.is_empty() {
            return bad("at least one profile is required");
        }
        if self.repeat < 1 {
            return bad("--repeat must be at least 1");
        }
        if self.duration_seconds < 1 {
            return bad("--duration-seconds must be at least 1");
        }
        if self.max_pages < 1 {
            return bad("--max-pages must be at least 1");
        }
        let names: BTreeSet<String> = self.targets.iter().map(Target::name).collect();
        if names.len() != self.targets.len() {
            return bad("a target is named twice");
        }
        let profiles: BTreeSet<Profile> = self.profiles.iter().copied().collect();
        if profiles.len() != self.profiles.len() {
            return bad("a profile is named twice");
        }
        Ok(())
    }
}

/// One finished crawl, reported as it completes.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Progress<'a> {
    /// Target label.
    pub target: &'a str,
    /// Profile.
    pub profile: Profile,
    /// 1-based repeat index.
    pub run: u32,
    /// Repeats per target and profile.
    pub of: u32,
    /// The metrics of this crawl.
    pub metrics: &'a Metrics,
}

static SCRATCH: AtomicU64 = AtomicU64::new(0);

/// Crawl every target under every profile `cfg.repeat` times and assemble the report.
///
/// `progress` is called after every crawl.
///
/// # Errors
/// [`BenchError::CrawlBench`] for an invalid configuration or a crawl that did not complete,
/// [`BenchError::Bind`]/[`BenchError::LocalAddr`] when a loopback listener cannot start,
/// [`BenchError::Worker`] when the worker run fails, and the errors of resolving a target
/// ([`BenchError::UnknownFixture`], [`BenchError::Url`]).
pub async fn run(cfg: &BenchConfig, mut progress: impl FnMut(&Progress<'_>)) -> Result<Report, BenchError> {
    cfg.validate()?;
    let gym = if cfg.targets.iter().any(|t| matches!(t, Target::Gym(_))) {
        Some(GymServer::start(SocketAddr::from(([127, 0, 0, 1], 0))).await?)
    } else {
        None
    };
    let rows = run_rows(cfg, gym.as_ref(), &mut progress).await;
    if let Some(gym) = gym {
        gym.shutdown().await;
    }
    Ok(Report::assemble(cfg.repeat, cfg.seed, &rows?))
}

async fn run_rows(
    cfg: &BenchConfig,
    gym: Option<&GymHandle>,
    progress: &mut dyn FnMut(&Progress<'_>),
) -> Result<Vec<Row>, BenchError> {
    let mut rows = Vec::new();
    for target in &cfg.targets {
        let prepared = prepare(target, gym)?;
        for &profile in &cfg.profiles {
            let mut samples = Vec::new();
            for run in 1..=cfg.repeat {
                let sample = crawl_once(cfg, &prepared, gym, profile).await?;
                progress(&Progress {
                    target: &prepared.name,
                    profile,
                    run,
                    of: cfg.repeat,
                    metrics: &sample.metrics,
                });
                samples.push(sample);
            }
            rows.push(Row::new(prepared.name.clone(), profile, samples));
        }
    }
    Ok(rows)
}

/// One crawl of `prepared` under `profile` behind a fresh recorder.
async fn crawl_once(
    cfg: &BenchConfig,
    prepared: &Prepared,
    gym: Option<&GymHandle>,
    profile: Profile,
) -> Result<Sample, BenchError> {
    if let (Some(gym), Some(fixture)) = (gym, &prepared.fixture) {
        gym.reset(cfg.seed);
        // One origin has one robots.txt: the crawl-maze fixture claims it, every other fixture
        // gets the default site's.
        gym.claim_origin(if fixture == crawl_maze::ID {
            crawl_maze::ID
        } else {
            s1::ID
        });
    }
    let recorder = Recorder::start(&prepared.upstream).await?;
    let outcome = crawl_behind(cfg, prepared, profile, &recorder).await;
    let hits = recorder.hits();
    recorder.shutdown().await;
    let (report, origin, seconds) = outcome?;

    if report.status != RunStatus::Completed {
        return Err(BenchError::CrawlBench(format!(
            "{}/{profile}: the crawl ended {:?} ({:?})",
            prepared.name, report.status, report.terminal_reason
        )));
    }
    let discovered = discovered_endpoints(&report.pages, &origin);
    Ok(summarize(
        report.counters.urls.succeeded,
        discovered,
        prepared.known.as_ref(),
        &hits,
        seconds,
    ))
}

async fn crawl_behind(
    cfg: &BenchConfig,
    prepared: &Prepared,
    profile: Profile,
    recorder: &Recorder,
) -> Result<(crawlx_worker::RunReport, Url, f64), BenchError> {
    let origin = Url::parse(&recorder.base_url())?;
    let seed_url = origin.join(&prepared.entry)?;
    let mut req = crawl_request_for_url(seed_url, cfg.seed, SafetyProfile::ReadOnly);
    profile.apply(&mut req);
    req.limits.urls = cfg.max_pages;
    req.limits.duration_seconds = cfg.duration_seconds;

    let scratch = std::env::temp_dir().join(format!(
        "crawlx-crawl-bench-{}-{}",
        std::process::id(),
        SCRATCH.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&scratch).map_err(|e| BenchError::io(&scratch, e))?;
    let worker = worker_config_with(prepared.trailing, &scratch);
    let result = match worker {
        Ok(worker) => {
            let started = Instant::now();
            let report = run_local_with(authorize_fixture(LocalRun::new(req, worker))).await;
            let seconds = started.elapsed().as_secs_f64();
            report.map(|r| (r, origin, seconds)).map_err(BenchError::from)
        }
        Err(e) => Err(e),
    };
    // Best effort: a leftover scratch directory is harmless.
    let _ = std::fs::remove_dir_all(&scratch);
    result
}
