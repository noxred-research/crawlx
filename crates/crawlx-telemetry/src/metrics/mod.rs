//! In-process metrics registry.
//!
//! Counters, gauges and fixed-bucket histograms keyed by the names in
//! [`catalog`]. The registry is closed: only catalogued names and each
//! metric's declared label keys are accepted, label values must be bounded
//! (≤ 64 chars, no control characters, no `://`), and a family holds at most
//! [`MAX_SERIES_PER_FAMILY`] label combinations. A rejected observation is
//! dropped and counted in `crawlx.telemetry.rejected{reason}` instead of
//! failing the caller. [`Metrics::render_prometheus`] produces the text
//! exposition format.
//!
//! No external metrics crate: state lives behind `parking_lot::Mutex`.

pub mod catalog;
mod render;

use catalog::REJECTED;
pub use catalog::{names, MetricDef, MetricKind, Unit, ALLOWED_LABELS, CATALOG};

use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// Upper bound on distinct label combinations per metric.
pub const MAX_SERIES_PER_FAMILY: usize = 1024;
/// Longest accepted label value.
pub const MAX_LABEL_VALUE_LEN: usize = 64;

type Labels = Vec<(&'static str, String)>;

#[derive(Clone, Debug)]
enum Series {
    Counter(u64),
    Gauge(f64),
    Histogram(HistState),
}

#[derive(Clone, Debug)]
struct HistState {
    /// Non-cumulative counts per bucket; the last slot is `+Inf`.
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

pub(crate) struct Family {
    def: &'static MetricDef,
    series: Mutex<BTreeMap<Labels, Series>>,
}

impl Family {
    fn new(def: &'static MetricDef) -> Self {
        Self {
            def,
            series: Mutex::new(BTreeMap::new()),
        }
    }

    /// Normalize caller labels against the family's declared label keys.
    fn normalize(&self, labels: &[(&str, &str)]) -> Result<Labels, &'static str> {
        let mut out: Labels = Vec::with_capacity(labels.len());
        for (k, v) in labels {
            let Some(key) = self.def.labels.iter().find(|d| **d == *k) else {
                return Err("label_not_allowed");
            };
            if v.len() > MAX_LABEL_VALUE_LEN || v.contains("://") || v.chars().any(char::is_control) {
                return Err("label_value_invalid");
            }
            if let Some(slot) = out.iter_mut().find(|(ek, _)| ek == key) {
                slot.1 = (*v).to_owned();
            } else {
                out.push((key, (*v).to_owned()));
            }
        }
        out.sort();
        Ok(out)
    }

    fn update(&self, labels: &[(&str, &str)], f: impl FnOnce(&mut Series)) -> Result<(), &'static str> {
        let key = self.normalize(labels)?;
        let mut map = self.series.lock();
        if !map.contains_key(&key) && map.len() >= MAX_SERIES_PER_FAMILY {
            return Err("cardinality");
        }
        let series = map.entry(key).or_insert_with(|| match self.def.kind {
            MetricKind::Counter => Series::Counter(0),
            MetricKind::Gauge => Series::Gauge(0.0),
            MetricKind::Histogram => Series::Histogram(HistState {
                counts: vec![0; self.def.buckets.len() + 1],
                sum: 0.0,
                count: 0,
            }),
        });
        f(series);
        Ok(())
    }

    fn read(&self, labels: &[(&str, &str)]) -> Option<Series> {
        let key = self.normalize(labels).ok()?;
        self.series.lock().get(&key).cloned()
    }
}

/// Shared handle plumbing: the target family plus the registry's rejection counter.
#[derive(Clone)]
struct Target {
    family: Result<Arc<Family>, &'static str>,
    rejected: Arc<Family>,
}

impl Target {
    fn reject(&self, reason: &'static str) {
        let _ = self.rejected.update(&[("reason", reason)], |s| {
            if let Series::Counter(c) = s {
                *c = c.saturating_add(1);
            }
        });
    }

    fn apply(&self, labels: &[(&str, &str)], f: impl FnOnce(&mut Series)) {
        match &self.family {
            Ok(fam) => {
                if let Err(reason) = fam.update(labels, f) {
                    self.reject(reason);
                }
            }
            Err(reason) => self.reject(reason),
        }
    }

    fn read(&self, labels: &[(&str, &str)]) -> Option<Series> {
        self.family.as_ref().ok().and_then(|f| f.read(labels))
    }
}

/// Monotonic counter handle.
#[derive(Clone)]
pub struct Counter(Target);

impl Counter {
    /// Add one with no labels.
    pub fn inc(&self) {
        self.inc_by(1, &[]);
    }

    /// Add `n` to the series identified by `labels`.
    pub fn inc_by(&self, n: u64, labels: &[(&str, &str)]) {
        self.0.apply(labels, |s| {
            if let Series::Counter(c) = s {
                *c = c.saturating_add(n);
            }
        });
    }

    /// Current value of a series (0 when it was never written).
    #[must_use]
    pub fn get(&self, labels: &[(&str, &str)]) -> u64 {
        match self.0.read(labels) {
            Some(Series::Counter(c)) => c,
            _ => 0,
        }
    }
}

/// Gauge handle.
#[derive(Clone)]
pub struct Gauge(Target);

impl Gauge {
    /// Set the series to `value`.
    pub fn set(&self, value: f64, labels: &[(&str, &str)]) {
        self.0.apply(labels, |s| {
            if let Series::Gauge(g) = s {
                *g = value;
            }
        });
    }

    /// Add `delta` (may be negative) to the series.
    pub fn add(&self, delta: f64, labels: &[(&str, &str)]) {
        self.0.apply(labels, |s| {
            if let Series::Gauge(g) = s {
                *g += delta;
            }
        });
    }

    /// Current value of a series, `None` when it was never written.
    #[must_use]
    pub fn get(&self, labels: &[(&str, &str)]) -> Option<f64> {
        match self.0.read(labels) {
            Some(Series::Gauge(g)) => Some(g),
            _ => None,
        }
    }
}

/// Fixed-bucket histogram handle.
#[derive(Clone)]
pub struct Histogram(Target);

/// Point-in-time view of one histogram series.
#[derive(Clone, PartialEq, Debug)]
pub struct HistogramSnapshot {
    /// Number of observations.
    pub count: u64,
    /// Sum of all observed values.
    pub sum: f64,
    /// Cumulative `(upper bound, count)` pairs; the final bound is `+Inf`.
    pub buckets: Vec<(f64, u64)>,
}

/// One series of a family as observed at snapshot time.
#[derive(Clone, PartialEq, Debug)]
pub enum SeriesValue {
    /// Counter value.
    Counter(u64),
    /// Gauge value.
    Gauge(f64),
    /// Histogram state.
    Histogram(HistogramSnapshot),
}

/// A labeled series captured by [`Metrics::snapshot_family`].
#[derive(Clone, PartialEq, Debug)]
pub struct SeriesSnapshot {
    /// Sorted `(key, value)` label pairs.
    pub labels: Vec<(&'static str, String)>,
    /// The series value.
    pub value: SeriesValue,
}

impl Histogram {
    /// Observe `value` in the unlabeled series.
    pub fn observe(&self, value: f64) {
        self.observe_with(value, &[]);
    }

    /// Observe `value` in the series identified by `labels`. Non-finite values are rejected.
    pub fn observe_with(&self, value: f64, labels: &[(&str, &str)]) {
        if !value.is_finite() {
            self.0.reject("non_finite");
            return;
        }
        let bounds: &'static [f64] = self.0.family.as_ref().map_or(&[], |f| f.def.buckets);
        self.0.apply(labels, |s| {
            if let Series::Histogram(h) = s {
                let idx = bounds.iter().position(|b| value <= *b).unwrap_or(bounds.len());
                if let Some(slot) = h.counts.get_mut(idx) {
                    *slot += 1;
                }
                h.sum += value;
                h.count += 1;
            }
        });
    }

    /// Observe a duration in seconds.
    pub fn observe_duration(&self, d: Duration, labels: &[(&str, &str)]) {
        self.observe_with(d.as_secs_f64(), labels);
    }

    /// Snapshot of a series, `None` when it was never written.
    #[must_use]
    pub fn snapshot(&self, labels: &[(&str, &str)]) -> Option<HistogramSnapshot> {
        let Ok(fam) = &self.0.family else { return None };
        match self.0.read(labels) {
            Some(Series::Histogram(h)) => Some(render::snapshot_of(fam.def.buckets, &h)),
            _ => None,
        }
    }
}

struct Inner {
    families: BTreeMap<&'static str, Arc<Family>>,
    rejected: Arc<Family>,
}

/// The registry. Cloning is cheap and shares state.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<Inner>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// A fresh registry holding every catalogued metric (no series yet).
    #[must_use]
    pub fn new() -> Self {
        let rejected = Arc::new(Family::new(&REJECTED));
        let mut families: BTreeMap<&'static str, Arc<Family>> = CATALOG
            .iter()
            .map(|d| (d.name, Arc::new(Family::new(d))))
            .collect();
        families.insert(REJECTED.name, Arc::clone(&rejected));
        Self {
            inner: Arc::new(Inner { families, rejected }),
        }
    }

    /// The process-wide registry.
    #[must_use]
    pub fn global() -> &'static Self {
        static GLOBAL: LazyLock<Metrics> = LazyLock::new(Metrics::new);
        &GLOBAL
    }

    fn target(&self, name: &str, kind: MetricKind) -> Target {
        let family = match self.inner.families.get(name) {
            None => Err("unknown_metric"),
            Some(f) if f.def.kind != kind => Err("wrong_kind"),
            Some(f) => Ok(Arc::clone(f)),
        };
        Target {
            family,
            rejected: Arc::clone(&self.inner.rejected),
        }
    }

    /// Counter handle for a catalogued name. An unknown name or a name of a
    /// different type yields a handle that counts rejections only.
    #[must_use]
    pub fn counter(&self, name: &str) -> Counter {
        Counter(self.target(name, MetricKind::Counter))
    }

    /// Gauge handle (see [`Metrics::counter`] for unknown names).
    #[must_use]
    pub fn gauge(&self, name: &str) -> Gauge {
        Gauge(self.target(name, MetricKind::Gauge))
    }

    /// Histogram handle (see [`Metrics::counter`] for unknown names).
    #[must_use]
    pub fn histogram(&self, name: &str) -> Histogram {
        Histogram(self.target(name, MetricKind::Histogram))
    }

    /// Every catalogued definition this registry holds, sorted by name.
    pub fn definitions(&self) -> impl Iterator<Item = &'static MetricDef> + '_ {
        self.inner.families.values().map(|f| f.def)
    }

    /// Point-in-time copy of every series of one family, sorted by label set.
    /// `None` for an unknown name; an empty `Vec` when nothing was written yet.
    #[must_use]
    pub fn snapshot_family(&self, name: &str) -> Option<Vec<SeriesSnapshot>> {
        let fam = self.inner.families.get(name)?;
        let series = fam.series.lock().clone();
        Some(
            series
                .into_iter()
                .map(|(labels, s)| SeriesSnapshot {
                    labels,
                    value: match s {
                        Series::Counter(c) => SeriesValue::Counter(c),
                        Series::Gauge(g) => SeriesValue::Gauge(g),
                        Series::Histogram(h) => {
                            SeriesValue::Histogram(render::snapshot_of(fam.def.buckets, &h))
                        }
                    },
                })
                .collect(),
        )
    }

    /// Render every series in the Prometheus text exposition format. Output is
    /// deterministic: families sorted by name, series by label set.
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        render::render(
            self.inner
                .families
                .values()
                .map(|f| (f.def, f.series.lock().clone())),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn counter_accumulates_per_label_set() {
        let m = Metrics::new();
        let c = m.counter(names::EGRESS_DENIALS);
        c.inc_by(2, &[("plane", "browser"), ("reason", "private_ip")]);
        c.inc_by(3, &[("reason", "private_ip"), ("plane", "browser")]);
        c.inc_by(1, &[("plane", "fetch"), ("reason", "private_ip")]);
        assert_eq!(c.get(&[("plane", "browser"), ("reason", "private_ip")]), 5);
        assert_eq!(c.get(&[("plane", "fetch"), ("reason", "private_ip")]), 1);
        assert_eq!(c.get(&[("plane", "fetch")]), 0);
    }

    #[test]
    fn gauge_set_and_add() {
        let m = Metrics::new();
        let g = m.gauge("crawlx.sessions.by_launch_profile");
        g.set(3.0, &[("profile", "standard")]);
        g.add(-1.0, &[("profile", "standard")]);
        assert_eq!(g.get(&[("profile", "standard")]), Some(2.0));
        assert_eq!(g.get(&[("profile", "stealth")]), None);
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let m = Metrics::new();
        let h = m.histogram(names::API_REQUEST_DURATION);
        for v in [0.0005, 0.004, 0.004, 0.3, 100.0] {
            h.observe_with(v, &[("route", "/v1/crawls")]);
        }
        let snap = h.snapshot(&[("route", "/v1/crawls")]).unwrap();
        assert_eq!(snap.count, 5);
        assert!((snap.sum - 100.3085).abs() < 1e-9);
        let at = |bound: f64| {
            snap.buckets
                .iter()
                .find(|(b, _)| *b == bound)
                .map(|(_, c)| *c)
                .unwrap()
        };
        assert_eq!(at(0.001), 1);
        assert_eq!(at(0.005), 3);
        assert_eq!(at(0.5), 4);
        assert_eq!(snap.buckets.last().unwrap().1, 5);
        assert!(snap.buckets.last().unwrap().0.is_infinite());
    }

    #[test]
    fn rejections_are_counted_not_applied() {
        let m = Metrics::new();
        let rejected = m.counter("crawlx.telemetry.rejected");
        m.counter("crawlx.no.such.metric").inc();
        m.counter(names::MODEL_LATENCY).inc(); // histogram used as counter
        m.counter(names::API_REQUESTS).inc_by(1, &[("url", "x")]);
        m.counter(names::API_REQUESTS)
            .inc_by(1, &[("route", "https://example.org/a")]);
        m.counter(names::API_REQUESTS)
            .inc_by(1, &[("route", &"x".repeat(65))]);
        m.histogram(names::API_REQUEST_DURATION).observe(f64::NAN);
        assert_eq!(rejected.get(&[("reason", "unknown_metric")]), 1);
        assert_eq!(rejected.get(&[("reason", "wrong_kind")]), 1);
        assert_eq!(rejected.get(&[("reason", "label_not_allowed")]), 1);
        assert_eq!(rejected.get(&[("reason", "label_value_invalid")]), 2);
        assert_eq!(rejected.get(&[("reason", "non_finite")]), 1);
        assert_eq!(m.counter(names::API_REQUESTS).get(&[]), 0);
    }

    #[test]
    fn cardinality_is_capped() {
        let m = Metrics::new();
        let c = m.counter(names::API_REQUESTS);
        for i in 0..(MAX_SERIES_PER_FAMILY + 10) {
            c.inc_by(1, &[("route", &format!("r{i}"))]);
        }
        let series = m
            .render_prometheus()
            .lines()
            .filter(|l| l.starts_with("crawlx_api_requests_total{"))
            .count();
        assert_eq!(series, MAX_SERIES_PER_FAMILY);
        assert_eq!(
            m.counter("crawlx.telemetry.rejected")
                .get(&[("reason", "cardinality")]),
            10
        );
    }

    #[test]
    fn global_is_shared() {
        let a = Metrics::global().counter(names::JOBS_ACCEPTED);
        let before = a.get(&[]);
        Metrics::global().counter(names::JOBS_ACCEPTED).inc();
        assert_eq!(a.get(&[]), before + 1);
    }

    #[test]
    fn concurrent_increments_do_not_lose_updates() {
        let m = Metrics::new();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let c = m.counter(names::LEASE_EXPIRED);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        c.inc();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(m.counter(names::LEASE_EXPIRED).get(&[]), 8000);
    }
}
