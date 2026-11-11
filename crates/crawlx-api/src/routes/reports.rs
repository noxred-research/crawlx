//! Finite authenticated operational reports derived only from retained repository facts.
//!
//! URL, host, MIME and unknown event identities are digests, not raw diagnostic strings.
//! Aggregations cover one bounded source page, not a silently truncated whole-run scan.
//! Missing facts use `notRecorded`; intentionally hidden source fields use `withheld`.

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
use crawlx_core::{CrawlRunId, Timestamp};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_LIMIT: u32 = 64;
const MAX_QUERY_BYTES: usize = 2048;
const REDACTION: &str = "identities_hashed_payloads_and_diagnostic_text_withheld";

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
}

impl Kind {
    const ALL: [Self; 17] = [
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
        }
    }

    const fn source(self) -> &'static str {
        match self {
            Self::Summary | Self::Provenance | Self::ProgressLog => "run_metadata",
            Self::MimeStatus | Self::UriLog => "committed_page_generations",
            Self::CrawlLog | Self::Events => "event_metadata",
            Self::Threads | Self::HostDnsHealth | Self::AlertLog => "unavailable",
            _ => "frontier",
        }
    }

    const fn scope(self) -> &'static str {
        match self {
            Self::Summary | Self::Provenance | Self::ProgressLog => "run_snapshot",
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
            Self::Summary
            | Self::Provenance
            | Self::ProgressLog
            | Self::Threads
            | Self::HostDnsHealth
            | Self::AlertLog => &[],
        }
    }

    fn filters(self) -> &'static [&'static str] {
        match self.source() {
            "frontier" => &["state", "minDepth", "maxDepth", "class", "urlKey", "hostKey"],
            "committed_page_generations" => &["status", "urlKey", "hostKey", "since", "until"],
            "event_metadata" => &["event", "since", "until"],
            _ => &[],
        }
    }
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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportPage {
    version: u16,
    report: &'static str,
    run: CrawlRunId,
    source: &'static str,
    aggregation_scope: &'static str,
    scanned: usize,
    next: Option<u64>,
    rows: Vec<Row>,
    not_recorded: &'static [&'static str],
    withheld: &'static [&'static str],
    redaction: &'static str,
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
    event: Option<&'static str>,
    since: Option<Timestamp>,
    until: Option<Timestamp>,
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

impl Query {
    fn parse(kind: Kind, params: &Params) -> ApiResult<Self> {
        if params.0.len() > 16
            || params.0.iter().fold(0_usize, |bytes, (key, value)| {
                bytes.saturating_add(key.len()).saturating_add(value.len())
            }) > MAX_QUERY_BYTES
        {
            return Err(invalid("report query exceeds its finite field or byte limit"));
        }
        for key in params.0.keys() {
            if !["after", "limit", "format"].contains(&key.as_str())
                && !kind.filters().contains(&key.as_str())
            {
                return Err(invalid("unsupported report filter; consult the report inventory"));
            }
        }
        let after = number(params, "after")?.unwrap_or(0);
        if i64::try_from(after).is_err() {
            return Err(invalid("report cursor exceeds the supported keyset range"));
        }
        let limit = number(params, "limit")?.unwrap_or(MAX_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(invalid("report limit must be between 1 and 64"));
        }
        let jsonl = match params.get("format") {
            None | Some("json") => false,
            Some("jsonl") => true,
            _ => return Err(invalid("report format must be json or jsonl")),
        };
        let state = params
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
            .transpose()?;
        let class = params
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
            .transpose()?;
        let event = params
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
            .transpose()?;
        let query = Self {
            after,
            limit,
            jsonl,
            state,
            status: number(params, "status")?,
            min_depth: number(params, "minDepth")?,
            max_depth: number(params, "maxDepth")?,
            class,
            url_key: digest(params, "urlKey")?,
            host_key: digest(params, "hostKey")?,
            event,
            since: timestamp(params, "since")?,
            until: timestamp(params, "until")?,
        };
        if query.status.is_some_and(|status| !(100..=599).contains(&status))
            || query
                .min_depth
                .zip(query.max_depth)
                .is_some_and(|(min, max)| min > max)
            || query.since.zip(query.until).is_some_and(|(min, max)| min >= max)
        {
            return Err(invalid("report filter range is invalid"));
        }
        Ok(query)
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
}

fn host_key(url: &crawlx_core::url::CanonicalUrl) -> Option<Digest> {
    url.url
        .host_str()
        .map(|host| Digest::of("crawlx/report-host/v1", host.as_bytes()))
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
        })
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &serde_json::json!({
            "version": 1,
            "run": run.id,
            "reports": reports,
            "maxLimit": MAX_LIMIT,
            "maxQueryBytes": MAX_QUERY_BYTES,
            "pagination": "after_last_scanned_source_identity_even_when_no_rows_match",
            "consistency": "live_keyset_not_a_frozen_snapshot",
            "formats": ["json", "jsonl"],
            "redaction": REDACTION,
            "notRecorded": ["cross_run_history", "wire_size_bytes", "response_duration_ms"],
            "availabilitySemantics": {
                "notRecorded": "not recorded by the selected repository projection",
                "withheld": "intentionally omitted or replaced with a digest when present",
            },
        }),
    ))
}

/// Search one finite retained report page using only structured allowlisted filters.
///
/// `limit` bounds source rows scanned, not merely returned matches. `next` advances past scanned
/// nonmatches too. JSONL ends with a cursor envelope distinguishing not-recorded and withheld facts.
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
    let mut page = ReportPage {
        version: 1,
        report: kind.name(),
        run: run.id,
        source: kind.source(),
        aggregation_scope: kind.scope(),
        scanned: 0,
        next: None,
        rows: Vec::new(),
        not_recorded: kind.not_recorded(),
        withheld: kind.withheld(),
        redaction: REDACTION,
    };
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
        "run_metadata" if query.after == 0 => {
            page.scanned = 1;
            page.rows.push(if kind == Kind::Provenance {
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
            });
        }
        _ => {}
    }
    // Recheck the injected clock after repository I/O before exposing retained report facts.
    retained(&run, state.clock.now())?;
    if query.jsonl {
        let mut bytes = Vec::new();
        for row in &page.rows {
            serde_json::to_writer(&mut bytes, row).map_err(|_| HttpError::internal())?;
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
