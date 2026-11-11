//! Finite authenticated operational reports derived only from retained repository facts.
//!
//! URL, host, MIME and unknown event identities are digests, not raw diagnostic strings.
//! Aggregations cover one bounded source page, not a silently truncated whole-run scan.
//! Missing facts use `notRecorded`; intentionally hidden source fields use `withheld`.
//!
//! Measured facts come only from the report-history repository. Primary history reports page
//! them with `after`/`next`; legacy reports attach one bounded companion fact page with its own
//! `factsAfter`/`factNext` cursor. The two cursor spaces never merge, and a field leaves
//! `notRecorded` only when a fact returned in that very page proves it.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::resources::metadata_expires_at;
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, Params};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{FrontierEntry, FrontierStatus, PageRecord, RunEvent, RunMetadata};
use crawlx_core::report_history::{
    page_duration_percentile, report_host_key, ReportDataV1, ReportEntryV1, ReportKindV1, ReportQueryV1,
    StageOutcomeV1,
};
use crawlx_core::{CrawlRunId, Timestamp};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_LIMIT: u32 = 64;
const MAX_QUERY_BYTES: usize = 2048;
const REDACTION: &str = "identities_hashed_payloads_and_diagnostic_text_withheld";
const FACTS_SCOPE: &str = "facts_page";
const FACT_KINDS: [ReportKindV1; 6] = [
    ReportKindV1::Dns,
    ReportKindV1::Stage,
    ReportKindV1::Wire,
    ReportKindV1::Alert,
    ReportKindV1::Loss,
    ReportKindV1::Pipeline,
];
const FACT_KIND_NAMES: &[&str] = &["dns", "stage", "wire", "alert", "loss", "pipeline"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Summary,
    Seeds,
    Hosts,
    Sources,
    MimeStatus,
    Frontier,
    ProcessorFailures,
    SkippedPages,
    Provenance,
    Threads,
    HostDnsHealth,
    CrawlLog,
    ErrorLog,
    UriLog,
    ProgressLog,
    AlertLog,
    Events,
    History,
    WireHistory,
    ProcessorHistory,
    PipelineHistory,
}

/// How a report relates to the measured fact history.
#[derive(Clone, Copy)]
enum Facts {
    /// No measured facts exist for this report.
    None,
    /// The report pages facts themselves; `None` lets the `kind` filter choose the class.
    Primary(Option<ReportKindV1>),
    /// Legacy rows plus a bounded companion fact page of this default class.
    Companion(ReportKindV1),
}

impl Kind {
    const ALL: [Self; 21] = [
        Self::Summary,
        Self::Seeds,
        Self::Hosts,
        Self::Sources,
        Self::MimeStatus,
        Self::Frontier,
        Self::ProcessorFailures,
        Self::SkippedPages,
        Self::Provenance,
        Self::Threads,
        Self::HostDnsHealth,
        Self::CrawlLog,
        Self::ErrorLog,
        Self::UriLog,
        Self::ProgressLog,
        Self::AlertLog,
        Self::Events,
        Self::History,
        Self::WireHistory,
        Self::ProcessorHistory,
        Self::PipelineHistory,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Seeds => "seeds",
            Self::Hosts => "hosts",
            Self::Sources => "sources",
            Self::MimeStatus => "mime_status",
            Self::Frontier => "frontier",
            Self::ProcessorFailures => "processor_failures",
            Self::SkippedPages => "skipped_pages",
            Self::Provenance => "provenance",
            Self::Threads => "threads",
            Self::HostDnsHealth => "host_dns_health",
            Self::CrawlLog => "crawl_log",
            Self::ErrorLog => "error_log",
            Self::UriLog => "uri_log",
            Self::ProgressLog => "progress_log",
            Self::AlertLog => "alert_log",
            Self::Events => "events",
            Self::History => "history",
            Self::WireHistory => "wire_history",
            Self::ProcessorHistory => "processor_history",
            Self::PipelineHistory => "pipeline_history",
        }
    }

    const fn facts(self) -> Facts {
        match self {
            Self::History => Facts::Primary(None),
            Self::WireHistory => Facts::Primary(Some(ReportKindV1::Wire)),
            Self::ProcessorHistory => Facts::Primary(Some(ReportKindV1::Stage)),
            Self::PipelineHistory => Facts::Primary(Some(ReportKindV1::Pipeline)),
            Self::HostDnsHealth => Facts::Primary(Some(ReportKindV1::Dns)),
            Self::AlertLog => Facts::Primary(Some(ReportKindV1::Alert)),
            Self::Frontier | Self::MimeStatus | Self::UriLog => Facts::Companion(ReportKindV1::Wire),
            Self::Hosts => Facts::Companion(ReportKindV1::Dns),
            Self::ProcessorFailures => Facts::Companion(ReportKindV1::Stage),
            Self::ErrorLog | Self::CrawlLog | Self::Events => Facts::Companion(ReportKindV1::Alert),
            Self::Summary
            | Self::Seeds
            | Self::Sources
            | Self::SkippedPages
            | Self::Provenance
            | Self::Threads
            | Self::ProgressLog => Facts::None,
        }
    }

    const fn source(self) -> &'static str {
        match self {
            Self::Summary | Self::Provenance | Self::ProgressLog => "run_metadata",
            Self::MimeStatus | Self::UriLog => "committed_page_generations",
            Self::CrawlLog | Self::Events => "event_metadata",
            Self::Threads => "unavailable",
            Self::HostDnsHealth
            | Self::AlertLog
            | Self::History
            | Self::WireHistory
            | Self::ProcessorHistory
            | Self::PipelineHistory => "report_history",
            _ => "frontier",
        }
    }

    const fn scope(self) -> &'static str {
        match self {
            Self::Summary | Self::Provenance | Self::ProgressLog => "run_snapshot",
            Self::HostDnsHealth
            | Self::AlertLog
            | Self::History
            | Self::WireHistory
            | Self::ProcessorHistory
            | Self::PipelineHistory => FACTS_SCOPE,
            _ => "source_page",
        }
    }

    const fn not_recorded(self) -> &'static [&'static str] {
        match self {
            Self::Summary | Self::ProgressLog => &[
                "historical_progress_samples",
                "archive_queue_occupancy",
                "archive_spool_bytes",
                "archive_finalization_latency",
            ],
            Self::Seeds => &["seed_outcomes_without_frontier_rows"],
            Self::Hosts => &["dns_health_history", "dns_percentiles"],
            Self::Sources => &["source_tags", "external_source_history"],
            Self::MimeStatus => &[
                "wire_size_bytes",
                "response_duration_ms",
                "uncommitted_legacy_pages",
            ],
            Self::ProcessorFailures => &["processor_identity", "failure_stage"],
            Self::SkippedPages => &["discoveries_without_persisted_rows"],
            Self::Provenance => &[
                "original_wire_protocol",
                "original_headers",
                "capture_completeness",
            ],
            Self::Threads => &["per_run_live_threads", "thread_stack_traces"],
            Self::HostDnsHealth => &["dns_health_history", "dns_recheck_schedule", "dns_percentiles"],
            Self::AlertLog => &["typed_alert_history", "alert_severity"],
            Self::CrawlLog | Self::Events => &[
                "log_level",
                "log_context",
                "dropped_event_count",
                "rotated_checkpoint_logs",
            ],
            Self::ErrorLog => &["failure_stage", "failure_timestamp"],
            Self::UriLog => &[
                "wire_size_bytes",
                "response_duration_ms",
                "failed_generations_without_committed_pages",
                "original_headers",
            ],
            Self::Frontier => &["wire_size_bytes", "response_duration_ms", "discovery_timestamp"],
            Self::History => &[
                "wire_size_bytes",
                "response_duration_ms",
                "processor_identity",
                "failure_stage",
                "typed_alert_history",
                "alert_severity",
                "dns_health_history",
                "dns_recheck_schedule",
                "dns_percentiles",
                "dropped_event_count",
                "pipeline_checkpoints",
            ],
            Self::WireHistory => &["wire_size_bytes", "response_duration_ms"],
            Self::ProcessorHistory => &["processor_identity", "failure_stage"],
            Self::PipelineHistory => &["pipeline_checkpoints"],
        }
    }

    const fn withheld(self) -> &'static [&'static str] {
        match self {
            Self::Seeds => &["original_seed_text", "raw_url", "hostnames", "denial_reason_text"],
            Self::Hosts => &["hostnames"],
            Self::Sources => &["source_urls"],
            Self::MimeStatus => &["unknown_mime_text"],
            Self::ProcessorFailures | Self::ErrorLog => &["exception_text", "raw_url", "hostnames"],
            Self::SkippedPages => &["unknown_skip_reason_text", "raw_url", "hostnames"],
            Self::CrawlLog | Self::Events => &["event_payload", "unknown_event_names"],
            Self::UriLog => &[
                "raw_url",
                "hostnames",
                "unknown_mime_text",
                "page_title",
                "page_metadata",
                "outgoing_links",
            ],
            Self::Frontier => &["raw_url", "hostnames", "denial_reason_text"],
            Self::HostDnsHealth
            | Self::AlertLog
            | Self::History
            | Self::WireHistory
            | Self::ProcessorHistory
            | Self::PipelineHistory => &["raw_url", "hostnames", "diagnostic_text"],
            Self::Summary | Self::Provenance | Self::ProgressLog | Self::Threads => &[],
        }
    }

    fn filters(self) -> &'static [&'static str] {
        match self {
            Self::History => &[
                "kind",
                "urlKey",
                "hostKey",
                "routeKey",
                "since",
                "until",
                "minDurationUs",
                "maxDurationUs",
                "minWireBytes",
                "maxWireBytes",
                "crossRun",
            ],
            Self::WireHistory => &[
                "urlKey",
                "hostKey",
                "routeKey",
                "since",
                "until",
                "minDurationUs",
                "maxDurationUs",
                "minWireBytes",
                "maxWireBytes",
            ],
            Self::ProcessorHistory | Self::HostDnsHealth => &[
                "urlKey",
                "hostKey",
                "routeKey",
                "since",
                "until",
                "minDurationUs",
                "maxDurationUs",
            ],
            Self::PipelineHistory | Self::AlertLog => &["urlKey", "hostKey", "routeKey", "since", "until"],
            Self::Frontier | Self::Hosts | Self::ProcessorFailures | Self::ErrorLog => &[
                "state",
                "minDepth",
                "maxDepth",
                "class",
                "urlKey",
                "hostKey",
                "factsAfter",
                "factKind",
            ],
            Self::MimeStatus | Self::UriLog => &[
                "status",
                "urlKey",
                "hostKey",
                "since",
                "until",
                "factsAfter",
                "factKind",
            ],
            Self::CrawlLog | Self::Events => &["event", "since", "until", "factsAfter", "factKind"],
            _ => match self.source() {
                "frontier" => &["state", "minDepth", "maxDepth", "class", "urlKey", "hostKey"],
                _ => &[],
            },
        }
    }

    fn facts_inventory(self) -> Option<FactsInventory> {
        match self.facts() {
            Facts::None => None,
            Facts::Primary(forced) => Some(FactsInventory {
                role: "primary",
                default_kind: forced.map(ReportKindV1::as_str),
                kinds: FACT_KIND_NAMES,
                cursor: "after",
                next: "next",
                cross_run: self == Self::History,
            }),
            Facts::Companion(default) => Some(FactsInventory {
                role: "companion",
                default_kind: Some(default.as_str()),
                kinds: FACT_KIND_NAMES,
                cursor: "factsAfter",
                next: "factNext",
                cross_run: false,
            }),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FactsInventory {
    role: &'static str,
    default_kind: Option<&'static str>,
    kinds: &'static [&'static str],
    cursor: &'static str,
    next: &'static str,
    cross_run: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InventoryEntry {
    name: &'static str,
    source: &'static str,
    aggregation_scope: &'static str,
    filters: &'static [&'static str],
    not_recorded: &'static [&'static str],
    withheld: &'static [&'static str],
    facts: Option<FactsInventory>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Class {
    OutOfScope,
    Limit,
    Robots,
    Redirect,
    Duplicate,
    Cancelled,
    Failed,
    Unreachable,
    Unknown,
}

impl Class {
    const fn name(self) -> &'static str {
        match self {
            Self::OutOfScope => "out_of_scope",
            Self::Limit => "limit",
            Self::Robots => "robots",
            Self::Redirect => "redirect",
            Self::Duplicate => "duplicate",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "rowType", rename_all = "snake_case", rename_all_fields = "camelCase")]
enum Row {
    Summary {
        status: crawlx_core::counters::RunStatus,
        terminal_reason: Option<crawlx_core::counters::TerminalReason>,
        counters: crawlx_core::counters::PlaneCounters,
        created_at: Timestamp,
        started_at: Option<Timestamp>,
        finished_at: Option<Timestamp>,
    },
    Provenance {
        config_digest: Digest,
        deterministic_seed: u64,
        policy_version: u32,
        software_version: &'static str,
    },
    Frontier {
        id: i64,
        url_key: Digest,
        host_key: Option<Digest>,
        depth: u16,
        state: FrontierStatus,
        attempts: u16,
        discovered_from: Option<i64>,
        class: Option<Class>,
    },
    Host {
        host_key: Option<Digest>,
        state: &'static str,
        count: u32,
    },
    Source {
        discovered_from: Option<i64>,
        state: &'static str,
        count: u32,
    },
    MimeStatus {
        mime_key: Option<Digest>,
        mime: Option<&'static str>,
        status: Option<u16>,
        count: u32,
    },
    Page {
        frontier_id: i64,
        url_key: Digest,
        host_key: Option<Digest>,
        status: Option<u16>,
        mime_key: Option<Digest>,
        mime: Option<&'static str>,
        content_digest: Digest,
        fetched_at: Timestamp,
        lane: crawlx_core::TrustLane,
    },
    Event {
        sequence: u64,
        event: &'static str,
        event_key: Digest,
        at: Timestamp,
    },
    /// One primary history fact with its repository sequence.
    Fact(ReportEntryV1),
    /// One companion fact line of a JSONL legacy report.
    CompanionFact(ReportEntryV1),
}

/// Measured-duration sample of one fact class on the returned fact page.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DurationStats {
    kind: &'static str,
    count: usize,
    p50_us: Option<u64>,
    p95_us: Option<u64>,
}

/// Checked sums over observed wire counters; unknown counters are never counted as zero.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireStats {
    received_count: usize,
    received_bytes: Option<u64>,
    sent_count: usize,
    sent_bytes: Option<u64>,
    overflow: bool,
}

/// Aggregates that describe only the facts returned in this page.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FactsPage {
    scope: &'static str,
    facts: usize,
    durations: Vec<DurationStats>,
    wire: WireStats,
}

#[derive(Default)]
struct Sum {
    count: usize,
    total: u64,
    overflow: bool,
}

impl Sum {
    fn add(&mut self, value: Option<u64>) {
        let Some(value) = value else {
            return;
        };
        self.count = self.count.saturating_add(1);
        match self.total.checked_add(value) {
            Some(total) => self.total = total,
            None => self.overflow = true,
        }
    }

    fn total(&self) -> Option<u64> {
        (self.count > 0 && !self.overflow).then_some(self.total)
    }
}

fn facts_page(entries: &[ReportEntryV1]) -> ApiResult<FactsPage> {
    let mut samples: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
    let (mut received, mut sent) = (Sum::default(), Sum::default());
    for entry in entries {
        let data = &entry.fact.data;
        if let Some(duration) = data.duration_us() {
            samples.entry(data.kind().as_str()).or_default().push(duration);
        }
        if let ReportDataV1::Wire {
            received_bytes,
            sent_bytes,
            ..
        } = data
        {
            received.add(*received_bytes);
            sent.add(*sent_bytes);
        }
    }
    let mut durations = Vec::with_capacity(samples.len());
    for (kind, mut sample) in samples {
        let p50_us = page_duration_percentile(&mut sample, 50).map_err(report_error)?;
        let p95_us = page_duration_percentile(&mut sample, 95).map_err(report_error)?;
        durations.push(DurationStats {
            kind,
            count: sample.len(),
            p50_us,
            p95_us,
        });
    }
    Ok(FactsPage {
        scope: FACTS_SCOPE,
        facts: entries.len(),
        durations,
        wire: WireStats {
            received_count: received.count,
            received_bytes: received.total(),
            sent_count: sent.count,
            sent_bytes: sent.total(),
            overflow: received.overflow || sent.overflow,
        },
    })
}

/// Whether one returned measured fact proves that a previously unrecorded field is now recorded.
fn proves(data: &ReportDataV1, field: &str) -> bool {
    matches!(
        (data, field),
        (
            ReportDataV1::Wire {
                received_bytes: Some(_),
                ..
            },
            "wire_size_bytes"
        ) | (
            ReportDataV1::Wire {
                duration_us: Some(_),
                ..
            },
            "response_duration_ms"
        ) | (ReportDataV1::Stage { .. }, "processor_identity")
            | (
                ReportDataV1::Stage {
                    outcome: StageOutcomeV1::Failed | StageOutcomeV1::Cancelled,
                    ..
                },
                "failure_stage",
            )
            | (
                ReportDataV1::Alert { .. },
                "typed_alert_history" | "alert_severity" | "log_level" | "log_context",
            )
            | (ReportDataV1::Dns { .. }, "dns_health_history" | "dns_percentiles")
            | (
                ReportDataV1::Dns {
                    recheck_at: Some(_),
                    ..
                },
                "dns_recheck_schedule"
            )
            | (ReportDataV1::Loss { .. }, "dropped_event_count")
            | (ReportDataV1::Pipeline { .. }, "pipeline_checkpoints")
    )
}

fn prune_not_recorded(fields: &mut Vec<&'static str>, entries: &[ReportEntryV1]) {
    fields.retain(|field| !entries.iter().any(|entry| proves(&entry.fact.data, field)));
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportPage {
    version: u16,
    report: &'static str,
    run: CrawlRunId,
    source: &'static str,
    aggregation_scope: &'static str,
    cross_run: bool,
    scanned: usize,
    next: Option<u64>,
    rows: Vec<Row>,
    facts: Vec<ReportEntryV1>,
    fact_next: Option<u64>,
    facts_page: Option<FactsPage>,
    not_recorded: Vec<&'static str>,
    withheld: &'static [&'static str],
    redaction: &'static str,
}

impl ReportPage {
    /// Empty page carrying the legacy `notRecorded` baseline; facts narrow it later.
    fn new(kind: Kind, run: &RunMetadata) -> Self {
        Self {
            version: 1,
            report: kind.name(),
            run: run.id,
            source: kind.source(),
            aggregation_scope: kind.scope(),
            cross_run: false,
            scanned: 0,
            next: None,
            rows: Vec::new(),
            facts: Vec::new(),
            fact_next: None,
            facts_page: None,
            not_recorded: kind.not_recorded().to_vec(),
            withheld: kind.withheld(),
            redaction: REDACTION,
        }
    }
}

struct Query {
    after: u64,
    limit: u32,
    jsonl: bool,
    state: Option<FrontierStatus>,
    status: Option<u16>,
    min_depth: Option<u16>,
    max_depth: Option<u16>,
    class: Option<Class>,
    url_key: Option<Digest>,
    host_key: Option<Digest>,
    route_key: Option<Digest>,
    event: Option<&'static str>,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
    kind: Option<ReportKindV1>,
    fact_kind: Option<ReportKindV1>,
    facts_after: u64,
    min_duration_us: Option<u64>,
    max_duration_us: Option<u64>,
    min_wire_bytes: Option<u64>,
    max_wire_bytes: Option<u64>,
    cross_run: bool,
}

fn invalid(message: &'static str) -> HttpError {
    HttpError::validation(vec![Detail::new("/query", "invalid_report_query", message)])
}

fn number<T: std::str::FromStr>(params: &Params, key: &str) -> ApiResult<Option<T>> {
    params
        .get(key)
        .map(str::parse)
        .transpose()
        .map_err(|_| invalid("report numeric filter is malformed or out of range"))
}

fn timestamp(params: &Params, key: &str) -> ApiResult<Option<Timestamp>> {
    params
        .get(key)
        .map(|text| chrono::DateTime::parse_from_rfc3339(text).map(|time| time.to_utc()))
        .transpose()
        .map_err(|_| invalid("report time filter must be an RFC 3339 timestamp"))
}

fn digest(params: &Params, key: &str) -> ApiResult<Option<Digest>> {
    params
        .get(key)
        .map(Digest::from_hex)
        .transpose()
        .map_err(|_| invalid("report identity filter must be a 32-byte hexadecimal digest"))
}

fn fact_kind(params: &Params, key: &str) -> ApiResult<Option<ReportKindV1>> {
    params
        .get(key)
        .map(|text| {
            FACT_KINDS
                .into_iter()
                .find(|kind| kind.as_str() == text)
                .ok_or_else(|| invalid("unknown report fact kind"))
        })
        .transpose()
}

fn check_param_bounds(kind: Kind, params: &Params) -> ApiResult<()> {
    if params.0.len() > 16
        || params.0.iter().fold(0_usize, |bytes, (key, value)| {
            bytes.saturating_add(key.len()).saturating_add(value.len())
        }) > MAX_QUERY_BYTES
    {
        return Err(invalid("report query exceeds its finite field or byte limit"));
    }
    for key in params.0.keys() {
        if !["after", "limit", "format"].contains(&key.as_str()) && !kind.filters().contains(&key.as_str()) {
            return Err(invalid("unsupported report filter; consult the report inventory"));
        }
    }
    Ok(())
}

/// A keyset cursor that must fit signed storage.
fn cursor(params: &Params, key: &str, message: &'static str) -> ApiResult<u64> {
    let value = number(params, key)?.unwrap_or(0);
    if i64::try_from(value).is_err() {
        return Err(invalid(message));
    }
    Ok(value)
}

fn jsonl_format(params: &Params) -> ApiResult<bool> {
    match params.get("format") {
        None | Some("json") => Ok(false),
        Some("jsonl") => Ok(true),
        _ => Err(invalid("report format must be json or jsonl")),
    }
}

fn cross_run(params: &Params) -> ApiResult<bool> {
    match params.get("crossRun") {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(invalid("crossRun must be true or false")),
    }
}

fn frontier_state(params: &Params) -> ApiResult<Option<FrontierStatus>> {
    params
        .get("state")
        .map(|state| match state {
            "pending" => Ok(FrontierStatus::Pending),
            "leased" => Ok(FrontierStatus::Leased),
            "succeeded" => Ok(FrontierStatus::Succeeded),
            "failed" => Ok(FrontierStatus::Failed),
            "abandoned" => Ok(FrontierStatus::Abandoned),
            "unreachable" => Ok(FrontierStatus::Unreachable),
            "policy_blocked" => Ok(FrontierStatus::PolicyBlocked),
            "robots_blocked" => Ok(FrontierStatus::RobotsBlocked),
            _ => Err(invalid("unknown frontier state")),
        })
        .transpose()
}

fn report_class(params: &Params) -> ApiResult<Option<Class>> {
    params
        .get("class")
        .map(|text| {
            [
                Class::OutOfScope,
                Class::Limit,
                Class::Robots,
                Class::Redirect,
                Class::Duplicate,
                Class::Cancelled,
                Class::Failed,
                Class::Unreachable,
                Class::Unknown,
            ]
            .into_iter()
            .find(|class| class.name() == text)
            .ok_or_else(|| invalid("unknown report classification"))
        })
        .transpose()
}

fn event_class(params: &Params) -> ApiResult<Option<&'static str>> {
    params
        .get("event")
        .map(|text| {
            let event = event_name(text);
            if event != "other" || text == "other" {
                Ok(event)
            } else {
                Err(invalid(
                    "unknown event class; use other for unrecognized event names",
                ))
            }
        })
        .transpose()
}

impl Query {
    fn parse(kind: Kind, params: &Params) -> ApiResult<Self> {
        check_param_bounds(kind, params)?;
        let after = cursor(
            params,
            "after",
            "report cursor exceeds the supported keyset range",
        )?;
        let facts_after = cursor(
            params,
            "factsAfter",
            "report fact cursor exceeds the supported keyset range",
        )?;
        let limit = number(params, "limit")?.unwrap_or(MAX_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(invalid("report limit must be between 1 and 64"));
        }
        let query = Self {
            after,
            limit,
            jsonl: jsonl_format(params)?,
            state: frontier_state(params)?,
            status: number(params, "status")?,
            min_depth: number(params, "minDepth")?,
            max_depth: number(params, "maxDepth")?,
            class: report_class(params)?,
            url_key: digest(params, "urlKey")?,
            host_key: digest(params, "hostKey")?,
            route_key: digest(params, "routeKey")?,
            event: event_class(params)?,
            since: timestamp(params, "since")?,
            until: timestamp(params, "until")?,
            kind: fact_kind(params, "kind")?,
            fact_kind: fact_kind(params, "factKind")?,
            facts_after,
            min_duration_us: number(params, "minDurationUs")?,
            max_duration_us: number(params, "maxDurationUs")?,
            min_wire_bytes: number(params, "minWireBytes")?,
            max_wire_bytes: number(params, "maxWireBytes")?,
            cross_run: cross_run(params)?,
        };
        // Primary history uses the core's inclusive bounds; legacy page/event sources keep `until` exclusive.
        query.check_ranges(matches!(kind.facts(), Facts::Primary(_)))?;
        Ok(query)
    }

    fn check_ranges(&self, inclusive_time: bool) -> ApiResult<()> {
        let reversed_time =
            self.since
                .zip(self.until)
                .is_some_and(|(min, max)| if inclusive_time { min > max } else { min >= max });
        if self.status.is_some_and(|status| !(100..=599).contains(&status))
            || self
                .min_depth
                .zip(self.max_depth)
                .is_some_and(|(min, max)| min > max)
            || reversed_time
        {
            return Err(invalid("report filter range is invalid"));
        }
        Ok(())
    }

    fn frontier(&self, row: &FrontierEntry) -> bool {
        self.state.is_none_or(|state| row.status == state)
            && self.min_depth.is_none_or(|depth| row.depth >= depth)
            && self.max_depth.is_none_or(|depth| row.depth <= depth)
            && self.class.is_none_or(|class| classify(row) == Some(class))
            && self.url_key.is_none_or(|key| row.url.key == key)
            && self.host_key.is_none_or(|key| host_key(&row.url) == Some(key))
    }

    fn time(&self, at: Timestamp) -> bool {
        self.since.is_none_or(|since| at >= since) && self.until.is_none_or(|until| at < until)
    }

    fn page(&self, row: &PageRecord) -> bool {
        self.status.is_none_or(|status| row.status == status)
            && self.url_key.is_none_or(|key| row.url.key == key)
            && self.host_key.is_none_or(|key| host_key(&row.url) == Some(key))
            && self.time(row.fetched_at)
    }

    /// Core filters for a primary history page; the report's fixed class overrides `kind`.
    fn history_query(&self, forced: Option<ReportKindV1>) -> ApiResult<ReportQueryV1> {
        let mut core = ReportQueryV1::default();
        core.after = self.after;
        core.limit = self.limit;
        core.kind = forced.or(self.kind);
        core.url_key = self.url_key;
        core.host_key = self.host_key;
        core.route_key = self.route_key;
        core.since = self.since;
        core.until = self.until;
        core.min_duration_us = self.min_duration_us;
        core.max_duration_us = self.max_duration_us;
        core.min_wire_bytes = self.min_wire_bytes;
        core.max_wire_bytes = self.max_wire_bytes;
        core.validate()
            .map_err(|_| invalid("report fact filter is outside the supported range"))?;
        Ok(core)
    }

    /// Core filters for a legacy report's companion page, independent of the source cursor.
    ///
    /// Source `until` is exclusive while core bounds are inclusive, so the bound moves back one
    /// nanosecond. Facts never predate the epoch, so earlier bounds clamp or select nothing.
    /// Returns `None` when no fact can match.
    fn companion_query(&self, class: ReportKindV1) -> ApiResult<Option<ReportQueryV1>> {
        let epoch: Timestamp = chrono::DateTime::UNIX_EPOCH;
        let mut core = ReportQueryV1::default();
        core.after = self.facts_after;
        core.limit = self.limit;
        core.kind = Some(class);
        core.url_key = self.url_key;
        core.host_key = self.host_key;
        core.since = self.since.map(|since| since.max(epoch));
        if let Some(until) = self.until {
            let inclusive = until
                .checked_sub_signed(chrono::Duration::nanoseconds(1))
                .ok_or_else(HttpError::internal)?;
            if inclusive < epoch {
                return Ok(None);
            }
            core.until = Some(inclusive);
        }
        core.validate()
            .map_err(|_| invalid("report fact filter is outside the supported range"))?;
        Ok(Some(core))
    }
}

fn host_key(url: &crawlx_core::url::CanonicalUrl) -> Option<Digest> {
    url.url.host_str().map(report_host_key)
}

fn classify(row: &FrontierEntry) -> Option<Class> {
    let reason = row.denial_reason.as_deref().unwrap_or_default();
    if matches!(
        reason,
        "dedupe:fingerprint" | "dedupe:content_exact" | "dedupe:content_similar"
    ) {
        return Some(Class::Duplicate);
    }
    if matches!(
        reason,
        "external"
            | "subdomain"
            | "host_scope"
            | "excluded_path"
            | "not_included"
            | "url_excluded"
            | "url_not_included"
            | "host_excluded"
            | "extension_filtered"
            | "external_homepage"
            | "authorization_scope"
    ) {
        return Some(Class::OutOfScope);
    }
    if matches!(
        reason,
        "depth_exceeded"
            | "host_page_limit"
            | "known_url_limit"
            | "body_limit"
            | "acquisition_allowance"
            | "acquisition_deadline"
            | "effect_budget_exhausted"
    ) {
        return Some(Class::Limit);
    }
    // No substring classification: arbitrary diagnostic text is not a typed denial code.
    if matches!(
        reason,
        "invalid_redirect" | "too_many_redirects" | "meta_refresh_target"
    ) {
        return Some(Class::Redirect);
    }
    match row.status {
        FrontierStatus::RobotsBlocked => Some(Class::Robots),
        FrontierStatus::Failed => Some(Class::Failed),
        FrontierStatus::Unreachable => Some(Class::Unreachable),
        FrontierStatus::Abandoned if reason == "cancelled" => Some(Class::Cancelled),
        FrontierStatus::Abandoned | FrontierStatus::PolicyBlocked => Some(Class::Unknown),
        _ => None,
    }
}

fn event_name(kind: &str) -> &'static str {
    match kind {
        "page" => "page",
        "page.failed" => "page.failed",
        "completed" => "completed",
        "started" => "started",
        "cancelled" => "cancelled",
        "request.rate_limited" => "request.rate_limited",
        _ => "other",
    }
}

fn mime_facts(value: Option<&str>) -> (Option<Digest>, Option<&'static str>) {
    let Some(value) = value else {
        return (None, None);
    };
    let essence = value.split(';').next().unwrap_or_default().trim();
    let known = [
        "text/html",
        "text/plain",
        "text/markdown",
        "text/css",
        "application/json",
        "application/xml",
        "text/xml",
        "application/pdf",
        "application/javascript",
        "text/javascript",
        "image/png",
        "image/jpeg",
        "image/svg+xml",
        "application/octet-stream",
    ]
    .into_iter()
    .find(|known| essence.eq_ignore_ascii_case(known));
    let key = Digest::of("crawlx/report-mime/v1", known.unwrap_or(essence).as_bytes());
    (Some(key), known)
}

fn frontier_rows(kind: Kind, rows: Vec<FrontierEntry>, query: &Query) -> Vec<Row> {
    let rows = rows
        .into_iter()
        .filter(|row| query.frontier(row))
        .filter(|row| match kind {
            Kind::Seeds => row.depth == 0,
            Kind::ProcessorFailures | Kind::ErrorLog => {
                matches!(row.status, FrontierStatus::Failed | FrontierStatus::Unreachable)
            }
            Kind::SkippedPages => {
                matches!(
                    row.status,
                    FrontierStatus::PolicyBlocked | FrontierStatus::RobotsBlocked | FrontierStatus::Abandoned
                ) || matches!(
                    classify(row),
                    Some(Class::Duplicate | Class::Redirect | Class::Limit)
                )
            }
            _ => true,
        });
    match kind {
        Kind::Hosts => {
            let mut counts = BTreeMap::new();
            for row in rows {
                let count = counts
                    .entry((host_key(&row.url), row.status.as_str()))
                    .or_insert(0_u32);
                *count = count.saturating_add(1);
            }
            counts
                .into_iter()
                .map(|((host_key, state), count)| Row::Host {
                    host_key,
                    state,
                    count,
                })
                .collect()
        }
        Kind::Sources => {
            let mut counts = BTreeMap::new();
            for row in rows {
                let count = counts
                    .entry((row.discovered_from, row.status.as_str()))
                    .or_insert(0_u32);
                *count = count.saturating_add(1);
            }
            counts
                .into_iter()
                .map(|((discovered_from, state), count)| Row::Source {
                    discovered_from,
                    state,
                    count,
                })
                .collect()
        }
        _ => rows
            .map(|row| Row::Frontier {
                id: row.id,
                url_key: row.url.key,
                host_key: host_key(&row.url),
                depth: row.depth,
                state: row.status,
                attempts: row.attempts,
                discovered_from: row.discovered_from,
                class: classify(&row),
            })
            .collect(),
    }
}

fn page_rows(kind: Kind, rows: Vec<PageRecord>, query: &Query) -> Vec<Row> {
    if kind == Kind::UriLog {
        return rows
            .into_iter()
            .filter(|row| query.page(row))
            .map(|row| {
                let (mime_key, mime) = mime_facts(row.content_type.as_deref());
                Row::Page {
                    frontier_id: row.frontier_id,
                    url_key: row.url.key,
                    host_key: host_key(&row.url),
                    status: (row.status != 0).then_some(row.status),
                    mime_key,
                    mime,
                    content_digest: row.content_digest,
                    fetched_at: row.fetched_at,
                    lane: row.lane,
                }
            })
            .collect();
    }
    let mut counts = BTreeMap::new();
    for row in rows.into_iter().filter(|row| query.page(row)) {
        let (mime_key, mime) = mime_facts(row.content_type.as_deref());
        let status = (row.status != 0).then_some(row.status);
        let count = counts.entry((mime_key, mime, status)).or_insert(0_u32);
        *count = count.saturating_add(1);
    }
    counts
        .into_iter()
        .map(|((mime_key, mime, status), count)| Row::MimeStatus {
            mime_key,
            mime,
            status,
            count,
        })
        .collect()
}

fn event_rows(rows: Vec<RunEvent>, query: &Query) -> Vec<Row> {
    rows.into_iter()
        .filter(|row| query.time(row.at) && query.event.is_none_or(|event| event_name(&row.kind) == event))
        .map(|row| Row::Event {
            sequence: row.seq,
            event: event_name(&row.kind),
            event_key: Digest::of("crawlx/report-event/v1", row.kind.as_bytes()),
            at: row.at,
        })
        .collect()
}

fn retained(run: &RunMetadata, now: Timestamp) -> ApiResult<()> {
    if run.retention.mode == RetentionMode::Zdr {
        return Err(HttpError::artifact_unavailable(
            "operational reports require retained source facts",
        ));
    }
    // Committed page custody can expire before the ordinary post-finish artifact horizon.
    // Never extend that earlier source deadline for a report, including an active run.
    if run.retention.days != 0 {
        let deadline = run
            .created_at
            .checked_add_signed(chrono::Duration::days(i64::from(run.retention.days)))
            .ok_or_else(HttpError::internal)?;
        if deadline <= now {
            return Err(HttpError::expired("report source retention expired"));
        }
    }
    if metadata_expires_at(run).is_some_and(|expiry| expiry <= now) {
        return Err(HttpError::expired("report source retention expired"));
    }
    Ok(())
}

fn report_error(error: crawlx_core::StoreError) -> HttpError {
    match error {
        crawlx_core::StoreError::RetentionDenied(_) => HttpError::expired("report source retention expired"),
        other => other.into(),
    }
}

/// List every operational report, its source, filters, not-recorded facts and withheld fields.
///
/// `notRecorded` per report is the legacy baseline; a returned page narrows it only by facts it
/// contains. `instrumentedFacts` describes the capability, not a guarantee that a run recorded any.
///
/// # Errors
/// Returns authentication, read-scope, tenant or repository errors. No source content is read.
pub async fn inventory(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let reports: Vec<_> = Kind::ALL
        .into_iter()
        .map(|kind| InventoryEntry {
            name: kind.name(),
            source: kind.source(),
            aggregation_scope: kind.scope(),
            filters: kind.filters(),
            not_recorded: kind.not_recorded(),
            withheld: kind.withheld(),
            facts: kind.facts_inventory(),
        })
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &serde_json::json!({
            "version": 1,
            "run": run.id,
            "reports": reports,
            "maxLimit": MAX_LIMIT,
            "maxFactsPerPage": MAX_LIMIT,
            "maxQueryBytes": MAX_QUERY_BYTES,
            "pagination": "after_last_scanned_source_identity_even_when_no_rows_match",
            "consistency": "live_keyset_not_a_frozen_snapshot",
            "formats": ["json", "jsonl"],
            "redaction": REDACTION,
            "instrumentedFacts": instrumented_facts(),
            "factCursors": {
                "primary": {"request": "after", "response": "next"},
                "companion": {"request": "factsAfter", "response": "factNext"},
                "semantics": "independent_filtered_keyset_with_matching_lookahead",
            },
            "notRecorded": ["legacy_runs_without_report_facts", "unmeasured_fact_fields_stay_null"],
            "availabilitySemantics": {
                "notRecorded": "not recorded by the selected repository projection",
                "withheld": "intentionally omitted or replaced with a digest when present",
            },
        }),
    ))
}

/// Names of the reports whose fact relationship satisfies `wanted`.
fn reports_with(wanted: fn(Facts) -> bool) -> Vec<&'static str> {
    Kind::ALL
        .into_iter()
        .filter(|kind| wanted(kind.facts()))
        .map(Kind::name)
        .collect()
}

/// Capability description of the instrumented fact history, not a guarantee of recorded facts.
fn instrumented_facts() -> serde_json::Value {
    serde_json::json!({
        "capability": "typed_facts_appear_only_when_a_producer_recorded_them",
        "kinds": FACT_KIND_NAMES,
        "primaryReports": reports_with(|facts| matches!(facts, Facts::Primary(_))),
        "companionReports": reports_with(|facts| matches!(facts, Facts::Companion(_))),
        "pageScope": FACTS_SCOPE,
        "timeBounds": "history_inclusive_since_until",
        "crossRun": {
            "report": Kind::History.name(),
            "parameter": "crossRun",
            "tenant": "authorized_run_tenant",
            "retention": "enforced_for_each_source_row",
        },
        "unavailable": [Kind::Threads.name()],
    })
}

/// Search one finite retained report page using only structured allowlisted filters.
///
/// `limit` bounds source rows scanned, not merely returned matches. `next` advances past scanned
/// nonmatches too. History reports page measured facts with the same `after`/`next` cursor, while
/// legacy reports add a bounded companion fact page with independent `factsAfter`/`factNext`.
/// JSONL ends with a cursor envelope distinguishing not-recorded and withheld facts.
///
/// # Errors
/// Returns tenant/read-scope, retention, unsupported-query or repository errors.
pub async fn search(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, report)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    retained(&run, state.clock.now())?;
    let kind = Kind::ALL
        .into_iter()
        .find(|kind| kind.name() == report)
        .ok_or_else(|| HttpError::not_found("report"))?;
    let query = Query::parse(kind, &params)?;
    let mut page = ReportPage::new(kind, &run);
    match kind.source() {
        "frontier" => {
            let after = i64::try_from(query.after).map_err(|_| invalid("invalid frontier cursor"))?;
            let rows = state
                .repos
                .frontier
                .page(run.id, after, query.limit)
                .await
                .map_err(report_error)?;
            page.scanned = rows.len();
            if rows.len() == usize::try_from(query.limit).unwrap_or(usize::MAX) {
                page.next = rows.last().and_then(|row| u64::try_from(row.id).ok());
            }
            page.rows = frontier_rows(kind, rows, &query);
        }
        "committed_page_generations" => {
            let after = i64::try_from(query.after).map_err(|_| invalid("invalid page cursor"))?;
            let rows = state
                .repos
                .pages
                .committed_page_keyset(run.id, after, query.limit)
                .await
                .map_err(report_error)?;
            page.scanned = rows.len();
            if rows.len() == usize::try_from(query.limit).unwrap_or(usize::MAX) {
                page.next = rows.last().and_then(|row| u64::try_from(row.frontier_id).ok());
            }
            page.rows = page_rows(kind, rows, &query);
        }
        "event_metadata" => {
            let rows = state
                .repos
                .events
                .list_metadata_after(run.id, query.after, query.limit)
                .await
                .map_err(report_error)?;
            page.scanned = rows.len();
            if rows.len() == usize::try_from(query.limit).unwrap_or(usize::MAX) {
                page.next = rows.last().map(|row| row.seq);
            }
            page.rows = event_rows(rows, &query);
        }
        "report_history" => history_page(&state, &principal, &run, kind, &query, &mut page).await?,
        "run_metadata" if query.after == 0 => {
            page.scanned = 1;
            page.rows.push(snapshot_row(kind, &run));
        }
        _ => {}
    }
    attach_companion(&state, &run, kind, &query, &mut page).await?;
    // Recheck the injected clock after repository I/O before exposing retained report facts.
    retained(&run, state.clock.now())?;
    render(&query, page)
}

/// Run-metadata row for the snapshot reports (`summary`, `provenance`, `progress_log`).
fn snapshot_row(kind: Kind, run: &RunMetadata) -> Row {
    if kind == Kind::Provenance {
        Row::Provenance {
            config_digest: run.config_digest,
            deterministic_seed: run.seed.0,
            policy_version: run.policy_version,
            software_version: env!("CARGO_PKG_VERSION"),
        }
    } else {
        Row::Summary {
            status: run.status,
            terminal_reason: run.terminal_reason,
            counters: run.counters,
            created_at: run.created_at,
            started_at: run.started_at,
            finished_at: run.finished_at,
        }
    }
}

/// Fill a primary history page from the filtered fact keyset.
///
/// Cross-run reads still bind to the authenticated tenant of the authorized run; the
/// repository enforces each source row's own retention, custody and authorization.
async fn history_page(
    state: &AppState,
    principal: &Principal,
    run: &RunMetadata,
    kind: Kind,
    query: &Query,
    page: &mut ReportPage,
) -> ApiResult<()> {
    let Facts::Primary(forced) = kind.facts() else {
        return Err(HttpError::internal());
    };
    let core = query.history_query(forced)?;
    let scope = (!query.cross_run).then_some(run.id);
    let mut facts = state
        .repos
        .report_history
        .query_facts(principal.tenant, scope, &core)
        .await
        .map_err(report_error)?;
    withhold_diagnostic_text(&mut facts.entries);
    page.cross_run = query.cross_run;
    page.scanned = facts.entries.len();
    page.next = facts.next;
    page.facts_page = Some(facts_page(&facts.entries)?);
    prune_not_recorded(&mut page.not_recorded, &facts.entries);
    page.rows = facts.entries.into_iter().map(Row::Fact).collect();
    Ok(())
}

/// Report APIs never serve diagnostic text: a failure snapshot keeps its stage, bounded code and
/// status, while the redacted free-text detail stays in the repository for operators.
fn withhold_diagnostic_text(entries: &mut [ReportEntryV1]) {
    for entry in entries {
        if let Some(error) = &mut entry.fact.error {
            error.detail = None;
        }
    }
}

/// Attach a legacy report's companion fact page; its cursor is independent of the source cursor.
async fn attach_companion(
    state: &AppState,
    run: &RunMetadata,
    kind: Kind,
    query: &Query,
    page: &mut ReportPage,
) -> ApiResult<()> {
    let Facts::Companion(default) = kind.facts() else {
        return Ok(());
    };
    if let Some(core) = query.companion_query(query.fact_kind.unwrap_or(default))? {
        let mut facts = state
            .repos
            .report_history
            .query_facts(run.tenant, Some(run.id), &core)
            .await
            .map_err(report_error)?;
        withhold_diagnostic_text(&mut facts.entries);
        page.fact_next = facts.next;
        page.facts = facts.entries;
    }
    page.facts_page = Some(facts_page(&page.facts)?);
    prune_not_recorded(&mut page.not_recorded, &page.facts);
    Ok(())
}

/// Serialize one page as JSON, or as JSONL rows and companion facts ending in the envelope.
fn render(query: &Query, mut page: ReportPage) -> ApiResult<Response> {
    if query.jsonl {
        let mut bytes = Vec::new();
        for row in &page.rows {
            serde_json::to_writer(&mut bytes, row).map_err(|_| HttpError::internal())?;
            bytes.push(b'\n');
        }
        for entry in std::mem::take(&mut page.facts) {
            serde_json::to_writer(&mut bytes, &Row::CompanionFact(entry))
                .map_err(|_| HttpError::internal())?;
            bytes.push(b'\n');
        }
        page.rows.clear();
        serde_json::to_writer(&mut bytes, &page).map_err(|_| HttpError::internal())?;
        bytes.push(b'\n');
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-ndjson")
            .header(header::CACHE_CONTROL, "private, no-store")
            .body(Body::from(bytes))
            .map_err(|_| HttpError::internal());
    }
    let value = serde_json::to_value(&page).map_err(|_| HttpError::internal())?;
    let mut response = json_response(StatusCode::OK, &value);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

#[cfg(test)]
#[path = "reports_tests.rs"]
mod tests;
