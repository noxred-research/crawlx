//! Prometheus text exposition rendering (format 0.0.4).

use super::{HistState, HistogramSnapshot, Labels, MetricDef, MetricKind, Series};
use std::collections::BTreeMap;
use std::fmt::Write as _;

pub(super) fn snapshot_of(bounds: &[f64], h: &HistState) -> HistogramSnapshot {
    let mut cumulative = 0_u64;
    let mut buckets = Vec::with_capacity(bounds.len() + 1);
    for (i, count) in h.counts.iter().enumerate() {
        cumulative += count;
        buckets.push((bounds.get(i).copied().unwrap_or(f64::INFINITY), cumulative));
    }
    HistogramSnapshot {
        count: h.count,
        sum: h.sum,
        buckets,
    }
}

fn fmt_f64(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_owned()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        v.to_string()
    }
}

fn escape_label_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn label_block(labels: &Labels, extra: Option<(&str, &str)>) -> String {
    if labels.is_empty() && extra.is_none() {
        return String::new();
    }
    let mut parts: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
        .collect();
    if let Some((k, v)) = extra {
        parts.push(format!("{k}=\"{v}\""));
    }
    format!("{{{}}}", parts.join(","))
}

/// Render families (already sorted by name) holding at least one series.
pub(super) fn render<'a>(
    families: impl Iterator<Item = (&'a MetricDef, BTreeMap<Labels, Series>)>,
) -> String {
    let mut out = String::new();
    for (def, series) in families {
        if series.is_empty() {
            continue;
        }
        let name = def.prometheus_name();
        let kind = match def.kind {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
            MetricKind::Histogram => "histogram",
        };
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "# HELP {name} {}", def.help);
        let _ = writeln!(out, "# TYPE {name} {kind}");
        for (labels, s) in &series {
            match s {
                Series::Counter(c) => {
                    let _ = writeln!(out, "{name}{} {c}", label_block(labels, None));
                }
                Series::Gauge(g) => {
                    let _ = writeln!(out, "{name}{} {}", label_block(labels, None), fmt_f64(*g));
                }
                Series::Histogram(h) => {
                    let snap = snapshot_of(def.buckets, h);
                    for (bound, count) in &snap.buckets {
                        let le = fmt_f64(*bound);
                        let _ = writeln!(
                            out,
                            "{name}_bucket{} {count}",
                            label_block(labels, Some(("le", &le)))
                        );
                    }
                    let _ = writeln!(
                        out,
                        "{name}_sum{} {}",
                        label_block(labels, None),
                        fmt_f64(snap.sum)
                    );
                    let _ = writeln!(out, "{name}_count{} {}", label_block(labels, None), snap.count);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use crate::metrics::{names, Metrics};

    #[test]
    fn empty_registry_renders_nothing() {
        assert_eq!(Metrics::new().render_prometheus(), "");
    }

    #[test]
    fn golden_exposition() {
        let m = Metrics::new();
        m.counter(names::API_REQUESTS)
            .inc_by(7, &[("route", "/v1/crawls"), ("outcome", "ok")]);
        m.counter(names::API_REQUESTS)
            .inc_by(1, &[("route", "/v1/crawls"), ("outcome", "error")]);
        m.counter(names::LEASE_EXPIRED).inc_by(2, &[]);
        m.counter(names::EGRESS_DENIALS)
            .inc_by(3, &[("plane", "browser"), ("reason", "private_ip")]);
        m.counter(names::ACTIONS_EXECUTED)
            .inc_by(5, &[("lane", "trusted")]);
        m.gauge(names::SESSIONS_BY_LAUNCH_PROFILE)
            .set(4.0, &[("profile", "standard")]);
        m.gauge(names::SESSIONS_BY_LAUNCH_PROFILE)
            .set(1.0, &[("profile", "stealth")]);
        m.gauge(names::IDENTITY_COLLISION_RATE).set(0.025, &[]);
        let h = m.histogram(names::SCHEDULER_OP_DURATION);
        h.observe_with(0.0004, &[("op", "lease_next")]);
        h.observe_with(0.003, &[("op", "lease_next")]);
        h.observe_with(2.0, &[("op", "lease_next")]);
        m.counter("crawlx.bogus").inc();

        let expected = "\
# HELP crawlx_actions_executed_total Actions executed per lane (trusted vs diagnostic) and kind
# TYPE crawlx_actions_executed_total counter
crawlx_actions_executed_total{lane=\"trusted\"} 5
# HELP crawlx_api_requests_total API requests
# TYPE crawlx_api_requests_total counter
crawlx_api_requests_total{outcome=\"error\",route=\"/v1/crawls\"} 1
crawlx_api_requests_total{outcome=\"ok\",route=\"/v1/crawls\"} 7
# HELP crawlx_egress_denials_total Egress guard denials
# TYPE crawlx_egress_denials_total counter
crawlx_egress_denials_total{plane=\"browser\",reason=\"private_ip\"} 3
# HELP crawlx_identity_collision_rate Element identity collision rate
# TYPE crawlx_identity_collision_rate gauge
crawlx_identity_collision_rate 0.025
# HELP crawlx_lease_expired_total Leases that expired
# TYPE crawlx_lease_expired_total counter
crawlx_lease_expired_total 2
# HELP crawlx_scheduler_op_duration_seconds Scheduler operation duration
# TYPE crawlx_scheduler_op_duration_seconds histogram
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.0005\"} 1
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.001\"} 1
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.0025\"} 1
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.005\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.01\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.025\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.05\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.1\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.25\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"0.5\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"1\"} 2
crawlx_scheduler_op_duration_seconds_bucket{op=\"lease_next\",le=\"+Inf\"} 3
crawlx_scheduler_op_duration_seconds_sum{op=\"lease_next\"} 2.0034
crawlx_scheduler_op_duration_seconds_count{op=\"lease_next\"} 3
# HELP crawlx_sessions_by_launch_profile Live sessions per launch profile
# TYPE crawlx_sessions_by_launch_profile gauge
crawlx_sessions_by_launch_profile{profile=\"standard\"} 4
crawlx_sessions_by_launch_profile{profile=\"stealth\"} 1
# HELP crawlx_telemetry_rejected_total Metric observations rejected by the registry
# TYPE crawlx_telemetry_rejected_total counter
crawlx_telemetry_rejected_total{reason=\"unknown_metric\"} 1
";
        assert_eq!(m.render_prometheus(), expected);
    }

    #[test]
    fn label_values_are_escaped() {
        let m = Metrics::new();
        m.counter(names::API_REQUESTS).inc_by(1, &[("route", "a\"b\\c")]);
        assert!(m
            .render_prometheus()
            .contains(r#"crawlx_api_requests_total{route="a\"b\\c"} 1"#));
    }
}
