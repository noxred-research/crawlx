//! The metric catalog: every metric name, type, help text and allowed label
//! set the runbooks and design docs reference (`docs/ops/runbooks.md`,
//! `docs/design/architecture.md`), plus the extra names the crawler
//! crates were assigned (`crawlx.proposals.stale`, `crawlx.actions.executed`,
//! `crawlx.unknown_outcome`, `crawlx.identity.collision_rate`,
//! `crawlx.sessions.by_launch_profile`) and the identity, safety, capture and
//! lane metrics reconciled with the catalog. Every entry has a producer; a `crawlx-bench`
//! test (`metrics_catalog.rs`) checks that each name is referenced from
//! non-test code of another crate.
//!
//! Names are OpenTelemetry style (dots); the Prometheus renderer maps `.` to
//! `_`, appends `_seconds` for [`Unit::Seconds`] and `_total` for counters.

/// Label keys any metric may use. No label may carry a URL, origin, element
/// name or `action_id`.
pub const ALLOWED_LABELS: &[&str] = &[
    "plane",
    "role",
    "lane",
    "strategy",
    "version",
    "verdict",
    "outcome",
    "reason",
    "kind",
    "model",
    "mode",
    "provider",
    "rung",
    "route",
    "op",
    "event",
    "profile",
    "partition",
];

/// Metric type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MetricKind {
    /// Monotonically increasing count; exported with a `_total` suffix.
    Counter,
    /// Value that can go up and down.
    Gauge,
    /// Observations bucketed into fixed upper bounds.
    Histogram,
}

/// Unit appended to the Prometheus name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unit {
    /// Dimensionless; no suffix.
    None,
    /// Durations in seconds; adds a `_seconds` suffix.
    Seconds,
}

/// Static description of one metric.
#[derive(Debug)]
pub struct MetricDef {
    /// Dotted metric name, e.g. `fetch.request.duration`.
    pub name: &'static str,
    /// Counter, gauge or histogram.
    pub kind: MetricKind,
    /// One-line `# HELP` text.
    pub help: &'static str,
    /// Label keys this metric accepts; each is in [`ALLOWED_LABELS`].
    pub labels: &'static [&'static str],
    /// Unit appended to the exported name.
    pub unit: Unit,
    /// Upper bounds (ascending, finite) for histograms; empty otherwise.
    pub buckets: &'static [f64],
}

impl MetricDef {
    /// Prometheus metric family name (without `_bucket`/`_sum`/`_count` suffixes).
    #[must_use]
    pub fn prometheus_name(&self) -> String {
        let mut n = self.name.replace('.', "_");
        if self.unit == Unit::Seconds {
            n.push_str("_seconds");
        }
        if self.kind == MetricKind::Counter {
            n.push_str("_total");
        }
        n
    }
}

/// Sub-millisecond to one second: DB, journal, scheduler, lease operations.
pub const FAST_BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];
/// 1 ms to 60 s: API, model, observation, action durations.
pub const DEFAULT_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];
/// 100 ms to 5 min: browser launch, settle, politeness waits, reconciliation.
pub const SLOW_BUCKETS: &[f64] = &[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0];
/// Counts of items (shortlist sizes): 1 to 500.
pub const SIZE_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0];

macro_rules! catalog {
    ($( $konst:ident = $kind:ident $name:literal $unit:ident [$($label:literal),*] $buckets:expr, $help:literal; )+) => {
        /// Constants for every catalogued metric name.
        pub mod names {
            $( #[doc = $help] pub const $konst: &str = $name; )+
        }
        /// `(constant identifier, metric name)` for every entry of [`names`],
        /// in declaration order; lets a test check that each catalogued
        /// metric has a producer.
        pub static NAMES_BY_IDENT: &[(&str, &str)] = &[
            $( (stringify!($konst), $name), )+
        ];
        /// All metric definitions, in declaration order.
        pub static CATALOG: &[MetricDef] = &[
            $( MetricDef {
                name: $name,
                kind: MetricKind::$kind,
                help: $help,
                labels: &[$($label),*],
                unit: Unit::$unit,
                buckets: $buckets,
            }, )+
        ];
    };
}

catalog! {
    // --- URL plane
    URLS_DISCOVERED = Counter "crawlx.urls.discovered" None ["plane"] &[], "URLs discovered";
    URLS_ADMITTED = Counter "crawlx.urls.admitted" None ["plane"] &[], "URLs admitted to the frontier";
    URLS_DEDUPLICATED = Counter "crawlx.urls.deduplicated" None ["plane"] &[], "URLs dropped as duplicates";
    URLS_POLICY_BLOCKED = Counter "crawlx.urls.policy_blocked" None ["plane", "reason"] &[], "URLs blocked by scope policy";
    URLS_ROBOTS_BLOCKED = Counter "crawlx.urls.robots_blocked" None ["plane"] &[], "URLs blocked by robots.txt";
    URLS_ATTEMPTED = Counter "crawlx.urls.attempted" None ["plane"] &[], "URL fetch attempts";
    URLS_SUCCEEDED = Counter "crawlx.urls.succeeded" None ["plane"] &[], "URL fetches that succeeded";
    URLS_FAILED = Counter "crawlx.urls.failed" None ["plane", "reason"] &[], "URL fetches that failed";
    URLS_ABANDONED = Counter "crawlx.urls.abandoned" None ["plane", "reason"] &[], "URLs abandoned after retries";
    URLS_UNREACHABLE = Counter "crawlx.urls.unreachable" None ["plane", "reason"] &[], "URLs found unreachable";
    // --- interactions
    INTERACTIONS_PROPOSED = Counter "crawlx.interactions.proposed" None ["role", "lane", "strategy", "kind"] &[], "Interaction proposals produced";
    INTERACTIONS_EXECUTED = Counter "crawlx.interactions.executed" None ["role", "lane", "strategy", "kind"] &[], "Interactions executed in the browser";
    INTERACTIONS_DROPPED_STALE = Counter "crawlx.interactions.dropped_stale" None ["role", "lane", "reason"] &[], "Proposals dropped because their epoch went stale";
    INTERACTIONS_DROPPED_UNACTIONABLE = Counter "crawlx.interactions.dropped_unactionable" None ["role", "lane", "reason"] &[], "Proposals dropped because the target was not actionable";
    INTERACTIONS_UNKNOWN_OUTCOME = Counter "crawlx.interactions.unknown_outcome" None ["role", "lane"] &[], "Actions whose outcome could not be persisted (SEV-1 on growth)";
    INTERACTIONS_UNKNOWN_UNRECONCILED = Gauge "crawlx.interactions.unknown_unreconciled" None [] &[], "Unknown-outcome actions awaiting reconciliation";
    // --- states
    STATES_OBSERVED = Counter "crawlx.states.observed" None ["role"] &[], "States observed";
    STATES_SPLITS = Counter "crawlx.states.splits" None [] &[], "State cluster splits applied to the store";
    STATES_FALSE_MERGE_SUSPECTS = Counter "crawlx.states.false_merge_suspects" None ["role"] &[], "Suspected false state merges";
    STATES_CLUSTERS = Gauge "crawlx.states.clusters" None ["role"] &[], "Current state clusters";
    COVERAGE_ACTION_CONTEXT = Gauge "crawlx.coverage.action_context" None ["role"] &[], "Action-context coverage per role";
    // --- durations
    ACTION_DURATION = Histogram "crawlx.action.duration" Seconds ["lane", "kind", "outcome"] DEFAULT_BUCKETS, "Action execution duration";
    SETTLE_DURATION = Histogram "crawlx.settle.duration" Seconds [] SLOW_BUCKETS, "Quiescence wait duration";
    OBSERVATION_DURATION = Histogram "crawlx.observation.duration" Seconds [] DEFAULT_BUCKETS, "Observation pipeline duration";
    FINGERPRINT_DURATION = Histogram "crawlx.fingerprint.duration" Seconds [] FAST_BUCKETS, "State fingerprint computation duration";
    CLUSTER_DECISION_DURATION = Histogram "crawlx.cluster.decision.duration" Seconds [] FAST_BUCKETS, "State cluster decision duration";
    ARBITER_DECISION_DURATION = Histogram "crawlx.arbiter.decision.duration" Seconds [] FAST_BUCKETS, "Arbiter decision duration";
    // --- strategy / safety / session
    SETTLE_TIMEOUTS = Counter "crawlx.settle.timeouts" None [] &[], "Quiescence waits that timed out";
    STRATEGY_PROPOSALS = Counter "crawlx.strategy.proposals" None ["strategy"] &[], "Proposals per strategy";
    STRATEGY_TIMEOUTS = Counter "crawlx.strategy.timeouts" None ["strategy"] &[], "Strategy calls that timed out";
    STRATEGY_ARM_ASSIGNMENTS = Counter "crawlx.strategy.arm.assignments" None ["strategy", "version"] &[], "Persisted session assignments per strategy implementation version";
    SAFETY_VERDICTS = Counter "crawlx.safety.verdicts" None ["verdict"] &[], "Safety kernel verdicts";
    SESSION_RECOVERIES = Counter "crawlx.session.recoveries" None ["rung"] &[], "Session recoveries by ladder rung";
    BROWSER_CRASHES = Counter "crawlx.browser.crashes" None ["reason"] &[], "Browser crashes";
    // --- models
    MODEL_REQUESTS = Counter "crawlx.model.requests" None ["provider", "model", "mode", "outcome"] &[], "Model requests";
    MODEL_ABSTENTIONS = Counter "crawlx.model.abstentions" None ["provider", "model", "mode"] &[], "Model abstentions";
    MODEL_LATENCY = Histogram "crawlx.model.latency" Seconds ["provider", "model"] DEFAULT_BUCKETS, "Model call latency";
    MODEL_BREAKER_STATE = Gauge "crawlx.model.breaker.state" None ["provider"] &[], "Breaker state: 0 closed, 1 half-open, 2 open";
    // --- journal / scheduler / fetch
    JOURNAL_T1_DURATION = Histogram "crawlx.journal.t1.duration" Seconds [] FAST_BUCKETS, "Intent journal T1 duration";
    JOURNAL_T2_DURATION = Histogram "crawlx.journal.t2.duration" Seconds [] FAST_BUCKETS, "Intent journal T2 duration";
    JOURNAL_HALTS = Counter "crawlx.journal.halts" None [] &[], "Sessions halted because the journal was unwritable (SEV-1)";
    SCHEDULER_LEASE_DURATION = Histogram "crawlx.scheduler.lease.duration" Seconds [] SLOW_BUCKETS, "Lease hold duration";
    SCHEDULER_OP_DURATION = Histogram "crawlx.scheduler.op.duration" Seconds ["op"] FAST_BUCKETS, "Scheduler operation duration";
    FETCH_ORIGIN_WAIT = Histogram "crawlx.fetch.origin_wait" Seconds [] SLOW_BUCKETS, "Time spent waiting for per-origin politeness";
    BROWSER_RSS_BYTES = Gauge "crawlx.browser.rss_bytes" None [] &[], "Browser resident set size";
    CPU_POOL_QUEUE_DEPTH = Gauge "crawlx.cpu_pool.queue_depth" None [] &[], "CPU pool queue depth";
    // --- API and operations
    API_REQUESTS = Counter "crawlx.api.requests" None ["route", "outcome"] &[], "API requests";
    API_REQUEST_DURATION = Histogram "crawlx.api.request.duration" Seconds ["route"] DEFAULT_BUCKETS, "API request duration";
    JOBS_ACCEPTED = Counter "crawlx.jobs.accepted" None [] &[], "Crawl jobs accepted";
    JOBS_DURABILITY_AUDIT_CHECKED = Counter "crawlx.jobs.durability_audit.checked" None [] &[], "Jobs checked by the durability audit";
    JOBS_DURABILITY_AUDIT_MISSING = Counter "crawlx.jobs.durability_audit.missing" None [] &[], "Accepted jobs missing at audit";
    WEBHOOK_DELIVERIES = Counter "crawlx.webhook.deliveries" None ["event", "outcome"] &[], "Webhook delivery attempts";
    WEBHOOK_PENDING = Gauge "crawlx.webhook.pending" None ["event"] &[], "Webhooks pending delivery";
    WEBHOOK_OLDEST_PENDING_AGE = Gauge "crawlx.webhook.oldest_pending_age" Seconds ["event"] &[], "Age of the oldest pending webhook";
    LEASE_EXPIRED = Counter "crawlx.lease.expired" None [] &[], "Leases that expired";
    LEASE_FENCED = Counter "crawlx.lease.fenced" None [] &[], "Operations refused because the lease was fenced";
    LEASE_RECONCILE_DURATION = Histogram "crawlx.lease.reconcile.duration" Seconds [] SLOW_BUCKETS, "Stale-lease reconciliation duration";
    LEASE_STALE_UNRECONCILED = Gauge "crawlx.lease.stale_unreconciled" None [] &[], "Expired leases not yet reconciled";
    SAFETY_INVARIANT_VIOLATIONS = Counter "crawlx.safety.invariant_violations" None ["reason"] &[], "Safety invariant violations (SEV-1)";
    EGRESS_DENIALS = Counter "crawlx.egress.denials" None ["plane", "reason"] &[], "Egress guard denials";
    RETENTION_OVERDUE_ARTIFACTS = Gauge "crawlx.retention.overdue_artifacts" None ["kind"] &[], "Artifacts past retention";
    RETENTION_SWEEP_FAILURES = Counter "crawlx.retention.sweep.failures" None [] &[], "Retention sweep failures";
    ZDR_VIOLATIONS = Counter "crawlx.zdr.violations" None [] &[], "Zero-data-retention violations";
    OBJECTSTORE_REQUESTS = Counter "crawlx.objectstore.requests" None ["op", "outcome"] &[], "Object store requests";
    OBJECTSTORE_DURATION = Histogram "crawlx.objectstore.duration" Seconds ["op"] DEFAULT_BUCKETS, "Object store request duration";
    OBJECTSTORE_SPOOL_BYTES = Gauge "crawlx.objectstore.spool_bytes" None [] &[], "Payload bytes reserved by queued and active memory-only uploads";
    DB_POOL_IN_USE = Gauge "crawlx.db.pool.in_use" None [] &[], "Database connections in use";
    DB_QUERY_DURATION = Histogram "crawlx.db.query.duration" Seconds ["op"] FAST_BUCKETS, "Database query duration";
    FETCH_RESPONSES = Counter "crawlx.fetch.responses" None ["outcome"] &[], "Fetch responses by outcome class";
    FETCH_THROTTLES = Counter "crawlx.fetch.throttles" None ["reason"] &[], "Fetches throttled (429/503)";
    FETCH_POLITENESS_VIOLATIONS = Counter "crawlx.fetch.politeness_violations" None [] &[], "Per-origin politeness violations";
    BROWSER_SESSIONS = Gauge "crawlx.browser.sessions" None [] &[], "Live browser sessions";
    BROWSER_LAUNCH_DURATION = Histogram "crawlx.browser.launch.duration" Seconds [] SLOW_BUCKETS, "Browser launch duration";
    CRAWLS_ACTIVE = Gauge "crawlx.crawls.active" None [] &[], "Crawls currently running";
    FRONTIER_DEPTH = Gauge "crawlx.frontier.depth" None ["plane"] &[], "Frontier depth";
    SESSIONS_BY_LAUNCH_PROFILE = Gauge "crawlx.sessions.by_launch_profile" None ["profile"] &[], "Live sessions per launch profile";
    // --- assigned to downstream crates by the build plan
    PROPOSALS_STALE = Counter "crawlx.proposals.stale" None ["strategy", "reason"] &[], "Proposals found stale or unactionable at execution time (reason = stale_epoch | not_actionable | identity_changed | confirm_denied)";
    ACTIONS_EXECUTED = Counter "crawlx.actions.executed" None ["lane", "kind"] &[], "Actions executed per lane (trusted vs diagnostic) and kind";
    UNKNOWN_OUTCOME = Counter "crawlx.unknown_outcome" None [] &[], "Unknown action outcomes";
    IDENTITY_COLLISION_RATE = Gauge "crawlx.identity.collision_rate" None [] &[], "Element identity collision rate";
    IDENTITY_SPLIT_RATE = Gauge "crawlx.identity.split_rate" None [] &[], "Element identity split rate";
    // --- identity, safety, capture and lane metrics reconciled with the catalog
    IDENTITY_COLLISION_SUSPECTED = Counter "crawlx.identity.collision_suspected" None ["role"] &[], "Descriptors with a materially different name resolved onto an existing identity by a fuzzy match";
    IDENTITY_SPLITS = Counter "crawlx.identity.splits" None ["role"] &[], "Identities minted in the ambiguity band and aliased to an existing one";
    TRUSTED_LANE_SYNTHETIC_ACTIONS = Counter "crawlx.trusted_lane.synthetic_actions" None ["kind"] &[], "Synthetic DOM-event actions recorded on the trusted lane; must stay 0";
    SAFETY_HARD_DENY_VIOLATIONS = Counter "crawlx.safety.hard_deny_violations" None ["reason"] &[], "Hard-deny classes that reached execution; must stay 0 (SEV-1)";
    KEYS_COLLISION_RATE = Gauge "crawlx.keys.collision_rate" None [] &[], "Share of ground-truth controls whose action-context key is shared with another control";
    KEYS_COARSENED = Counter "crawlx.keys.coarsened" None [] &[], "New action-context keys coarsened to route-level state after the per-element context limit";
    SESSION_ROUND_WAIT = Histogram "crawlx.session.round_wait" Seconds ["role"] SLOW_BUCKETS, "Time a role session waited for its round-robin turn";
    SESSION_CROSS_PRINCIPAL_ATTRIBUTION_RATE = Gauge "crawlx.session.cross_principal_attribution_rate" None ["role"] &[], "Share of cross-principal action contexts exercised on the trusted lane";
    ROLES_ABANDONED = Counter "crawlx.roles.abandoned" None ["reason"] &[], "Role sessions that ended without completing their turn";
    FORM_SUBMISSIONS = Counter "crawlx.form.submissions" None ["partition"] &[], "Form inputs executed per value partition";
    FORM_DENIED_NO_SINK = Counter "crawlx.form.denied_no_sink" None [] &[], "Form proposals denied because no verified sink exists";
    COVERAGE_DIAGNOSTIC_ONLY_KEYS = Gauge "crawlx.coverage.diagnostic_only_keys" None ["role"] &[], "Action-context keys exercised only in the diagnostic lane";
    EXPORT_TRUSTED_ROWS = Counter "crawlx.export.trusted_rows" None ["kind"] &[], "Rows served from the trusted corpus";
    TRAFFIC_LATE_RATIO = Gauge "crawlx.traffic.late_ratio" None [] &[], "Share of captured flows attributed late to an earlier epoch";
    TRAFFIC_UNATTRIBUTED = Counter "crawlx.traffic.unattributed" None ["reason"] &[], "Traffic events stored without an epoch";
    TRAFFIC_UNMATCHED_PROXY_FLOWS = Counter "crawlx.traffic.unmatched_proxy_flows" None [] &[], "Proxy flows no CDP request matched";
    REVALIDATE_LATENCY = Histogram "crawlx.revalidate.latency" Seconds ["outcome"] FAST_BUCKETS, "Pre-action target revalidation latency";
    MODEL_SHORTLIST_SIZE = Histogram "crawlx.model.shortlist_size" None ["mode"] SIZE_BUCKETS, "Candidates offered to the model per request";
}

/// The registry's own guard-rail counter: observations dropped for an unknown
/// name, wrong type, disallowed or unbounded label, non-finite value or
/// exhausted cardinality budget. Kept outside [`CATALOG`] because the registry
/// needs it to exist unconditionally.
pub static REJECTED: MetricDef = MetricDef {
    name: "crawlx.telemetry.rejected",
    kind: MetricKind::Counter,
    help: "Metric observations rejected by the registry",
    labels: &["reason"],
    unit: Unit::None,
    buckets: &[],
};

/// Every metric definition including [`REJECTED`].
pub fn all() -> impl Iterator<Item = &'static MetricDef> {
    CATALOG.iter().chain(std::iter::once(&REJECTED))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn names_and_prometheus_names_are_unique() {
        let mut names = HashSet::new();
        let mut prom = HashSet::new();
        for d in all() {
            assert!(names.insert(d.name), "duplicate {}", d.name);
            assert!(
                prom.insert(d.prometheus_name()),
                "duplicate prometheus name {}",
                d.name
            );
            assert!(d.name.starts_with("crawlx."), "{}", d.name);
        }
    }

    #[test]
    fn labels_come_from_the_allow_list() {
        for d in all() {
            for l in d.labels {
                assert!(ALLOWED_LABELS.contains(l), "{} uses label {l}", d.name);
            }
        }
    }

    #[test]
    fn histograms_have_ascending_finite_buckets() {
        for d in all() {
            match d.kind {
                MetricKind::Histogram => {
                    assert!(!d.buckets.is_empty(), "{}", d.name);
                    assert!(d.buckets.windows(2).all(|w| w[0] < w[1]), "{}", d.name);
                    assert!(d.buckets.iter().all(|b| b.is_finite()), "{}", d.name);
                }
                _ => assert!(d.buckets.is_empty(), "{}", d.name),
            }
        }
    }

    #[test]
    fn plan_names_are_present() {
        for n in [
            "crawlx.api.requests",
            "crawlx.lease.expired",
            "crawlx.egress.denials",
            "crawlx.sessions.by_launch_profile",
            "crawlx.proposals.stale",
            "crawlx.actions.executed",
            "crawlx.unknown_outcome",
            "crawlx.identity.collision_rate",
            "crawlx.model.breaker.state",
            "crawlx.journal.halts",
        ] {
            assert!(CATALOG.iter().any(|d| d.name == n), "{n}");
        }
    }

    /// The measurement metrics the quality gates and runbooks read: identity, key coverage,
    /// traffic capture, revalidation, round-robin roles, forms and the trusted corpus.
    /// `(name, kind, labels, exported Prometheus name)`.
    const MEASUREMENT_METRICS: &[(&str, MetricKind, &[&str], &str)] = &[
        (
            "crawlx.identity.collision_suspected",
            MetricKind::Counter,
            &["role"],
            "crawlx_identity_collision_suspected_total",
        ),
        (
            "crawlx.identity.splits",
            MetricKind::Counter,
            &["role"],
            "crawlx_identity_splits_total",
        ),
        (
            "crawlx.traffic.late_ratio",
            MetricKind::Gauge,
            &[],
            "crawlx_traffic_late_ratio",
        ),
        (
            "crawlx.traffic.unattributed",
            MetricKind::Counter,
            &["reason"],
            "crawlx_traffic_unattributed_total",
        ),
        (
            "crawlx.traffic.unmatched_proxy_flows",
            MetricKind::Counter,
            &[],
            "crawlx_traffic_unmatched_proxy_flows_total",
        ),
        (
            "crawlx.coverage.action_context",
            MetricKind::Gauge,
            &["role"],
            "crawlx_coverage_action_context",
        ),
        (
            "crawlx.keys.collision_rate",
            MetricKind::Gauge,
            &[],
            "crawlx_keys_collision_rate",
        ),
        (
            "crawlx.keys.coarsened",
            MetricKind::Counter,
            &[],
            "crawlx_keys_coarsened_total",
        ),
        (
            "crawlx.revalidate.latency",
            MetricKind::Histogram,
            &["outcome"],
            "crawlx_revalidate_latency_seconds",
        ),
        (
            "crawlx.session.round_wait",
            MetricKind::Histogram,
            &["role"],
            "crawlx_session_round_wait_seconds",
        ),
        (
            "crawlx.session.cross_principal_attribution_rate",
            MetricKind::Gauge,
            &["role"],
            "crawlx_session_cross_principal_attribution_rate",
        ),
        (
            "crawlx.roles.abandoned",
            MetricKind::Counter,
            &["reason"],
            "crawlx_roles_abandoned_total",
        ),
        (
            "crawlx.form.submissions",
            MetricKind::Counter,
            &["partition"],
            "crawlx_form_submissions_total",
        ),
        (
            "crawlx.form.denied_no_sink",
            MetricKind::Counter,
            &[],
            "crawlx_form_denied_no_sink_total",
        ),
        (
            "crawlx.coverage.diagnostic_only_keys",
            MetricKind::Gauge,
            &["role"],
            "crawlx_coverage_diagnostic_only_keys",
        ),
        (
            "crawlx.export.trusted_rows",
            MetricKind::Counter,
            &["kind"],
            "crawlx_export_trusted_rows_total",
        ),
    ];

    #[test]
    fn measurement_metrics_are_catalogued_with_bounded_labels() {
        for (name, kind, labels, prom) in MEASUREMENT_METRICS {
            let def = CATALOG
                .iter()
                .find(|d| d.name == *name)
                .unwrap_or_else(|| panic!("{name} is not catalogued"));
            assert_eq!(def.kind, *kind, "{name}");
            assert_eq!(def.labels, *labels, "{name}");
            assert_eq!(def.prometheus_name(), *prom, "{name}");
            // no unbounded dimension: never a role id, session id, URL or origin
            for l in def.labels {
                assert!(
                    ["role", "reason", "outcome", "partition", "kind"].contains(l),
                    "{name} uses label {l}"
                );
            }
        }
    }

    #[test]
    fn each_measurement_metric_moves_in_the_registry_and_is_exported() {
        use crate::metrics::Metrics;
        let m = Metrics::new();
        let label_value = |l: &str| match l {
            "role" => "alice",
            "reason" => "no_epoch",
            "outcome" => "ok",
            "partition" => "valid",
            _ => "trusted",
        };
        for (name, kind, labels, prom) in MEASUREMENT_METRICS {
            let pairs: Vec<(&str, &str)> = labels.iter().map(|l| (*l, label_value(l))).collect();
            match kind {
                MetricKind::Counter => {
                    let c = m.counter(name);
                    assert_eq!(c.get(&pairs), 0, "{name}");
                    c.inc_by(2, &pairs);
                    assert_eq!(c.get(&pairs), 2, "{name}");
                }
                MetricKind::Gauge => {
                    let g = m.gauge(name);
                    assert_eq!(g.get(&pairs), None, "{name}");
                    g.set(0.25, &pairs);
                    assert_eq!(g.get(&pairs), Some(0.25), "{name}");
                }
                MetricKind::Histogram => {
                    let h = m.histogram(name);
                    assert!(h.snapshot(&pairs).is_none(), "{name}");
                    h.observe_with(0.002, &pairs);
                    assert_eq!(h.snapshot(&pairs).unwrap().count, 1, "{name}");
                }
            }
            assert!(
                m.render_prometheus()
                    .lines()
                    .any(|l| !l.starts_with('#') && l.starts_with(prom)),
                "{name} is not exported as {prom}"
            );
        }
        let rejected = m.counter("crawlx.telemetry.rejected");
        assert_eq!(rejected.get(&[("reason", "label_not_allowed")]), 0);
        assert_eq!(rejected.get(&[("reason", "label_value_invalid")]), 0);
    }
}
