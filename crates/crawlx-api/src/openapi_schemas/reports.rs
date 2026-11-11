//! Finite schema mirrors for retained operational inventory, rows and structured search.

use super::Schemas;
use schemars::JsonSchema;
use serde_json::{json, Value};

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportKind {
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

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportSource {
    RunMetadata,
    Frontier,
    CommittedPageGenerations,
    EventMetadata,
    Unavailable,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportScope {
    RunSnapshot,
    SourcePage,
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
enum OperationalReportFilter {
    State,
    Status,
    MinDepth,
    MaxDepth,
    Class,
    UrlKey,
    HostKey,
    Event,
    Since,
    Until,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportNotRecorded {
    HistoricalProgressSamples,
    ArchiveQueueOccupancy,
    ArchiveSpoolBytes,
    ArchiveFinalizationLatency,
    SeedOutcomesWithoutFrontierRows,
    DnsHealthHistory,
    DnsPercentiles,
    SourceTags,
    ExternalSourceHistory,
    WireSizeBytes,
    ResponseDurationMs,
    UncommittedLegacyPages,
    ProcessorIdentity,
    FailureStage,
    DiscoveriesWithoutPersistedRows,
    OriginalWireProtocol,
    OriginalHeaders,
    CaptureCompleteness,
    PerRunLiveThreads,
    ThreadStackTraces,
    DnsRecheckSchedule,
    TypedAlertHistory,
    AlertSeverity,
    LogLevel,
    LogContext,
    DroppedEventCount,
    RotatedCheckpointLogs,
    FailureTimestamp,
    FailedGenerationsWithoutCommittedPages,
    DiscoveryTimestamp,
    CrossRunHistory,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportWithheld {
    OriginalSeedText,
    RawUrl,
    Hostnames,
    DenialReasonText,
    SourceUrls,
    UnknownMimeText,
    ExceptionText,
    UnknownSkipReasonText,
    EventPayload,
    UnknownEventNames,
    PageTitle,
    PageMetadata,
    OutgoingLinks,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportState {
    Pending,
    Leased,
    Succeeded,
    Failed,
    Abandoned,
    Unreachable,
    PolicyBlocked,
    RobotsBlocked,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportClass {
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

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportRunStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportTerminalReason {
    FrontierExhausted,
    LimitReached,
    DeadlineReached,
    PolicyStopped,
    Cancelled,
    FatalError,
    RecoveryExhausted,
    AuthorizationRevoked,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportLane {
    TrustedUi,
    Diagnostic,
}

#[derive(JsonSchema)]
enum OperationalReportEvent {
    #[serde(rename = "page")]
    Page,
    #[serde(rename = "page.failed")]
    PageFailed,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "started")]
    Started,
    #[serde(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "request.rate_limited")]
    RequestRateLimited,
    #[serde(rename = "other")]
    Other,
}

#[derive(JsonSchema)]
enum OperationalReportMime {
    #[serde(rename = "text/html")]
    Html,
    #[serde(rename = "text/plain")]
    Text,
    #[serde(rename = "text/markdown")]
    Markdown,
    #[serde(rename = "text/css")]
    Css,
    #[serde(rename = "application/json")]
    Json,
    #[serde(rename = "application/xml")]
    Xml,
    #[serde(rename = "text/xml")]
    TextXml,
    #[serde(rename = "application/pdf")]
    Pdf,
    #[serde(rename = "application/javascript")]
    ApplicationJavascript,
    #[serde(rename = "text/javascript")]
    TextJavascript,
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/svg+xml")]
    Svg,
    #[serde(rename = "application/octet-stream")]
    Binary,
}

#[derive(JsonSchema)]
struct OperationalReportDigest(#[schemars(regex(pattern = "^[0-9a-f]{64}$"))] String);
#[derive(JsonSchema)]
struct OperationalReportQueryDigest(#[schemars(regex(pattern = "^[0-9a-fA-F]{64}$"))] String);
#[derive(JsonSchema)]
struct OperationalReportTimestamp(#[schemars(extend("format" = "date-time"))] String);
#[derive(JsonSchema)]
struct OperationalReportRunId(#[schemars(extend("format" = "uuid"))] String);
#[derive(JsonSchema)]
struct OperationalReportCursor(#[schemars(range(min = 0), extend("maximum" = 9223372036854775807_u64))] u64);
#[derive(JsonSchema)]
struct OperationalReportRowId(#[schemars(range(min = 1), extend("maximum" = 9223372036854775807_i64))] i64);
#[derive(JsonSchema)]
struct OperationalReportStoredStatus(#[schemars(range(min = 1, max = 65535))] u16);

// Native repository counter names deliberately remain snake_case on this report wire.
#[derive(JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationalReportCounters {
    discovered: u64,
    admitted: u64,
    deduplicated: u64,
    policy_blocked: u64,
    robots_blocked: u64,
    attempted: u64,
    succeeded: u64,
    failed: u64,
    abandoned: u64,
    unreachable: u64,
    unknown_outcome: u64,
}

#[derive(JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationalReportPlanes {
    urls: OperationalReportCounters,
    interactions: OperationalReportCounters,
    states: OperationalReportCounters,
}

#[derive(JsonSchema)]
#[serde(
    tag = "rowType",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum OperationalReportRow {
    Summary {
        status: OperationalReportRunStatus,
        terminal_reason: Option<OperationalReportTerminalReason>,
        counters: Box<OperationalReportPlanes>,
        created_at: OperationalReportTimestamp,
        started_at: Option<OperationalReportTimestamp>,
        finished_at: Option<OperationalReportTimestamp>,
    },
    Provenance {
        config_digest: OperationalReportDigest,
        deterministic_seed: u64,
        policy_version: u32,
        software_version: String,
    },
    Frontier {
        id: OperationalReportRowId,
        url_key: OperationalReportDigest,
        host_key: Option<OperationalReportDigest>,
        depth: u16,
        state: OperationalReportState,
        attempts: u16,
        discovered_from: Option<OperationalReportRowId>,
        class: Option<OperationalReportClass>,
    },
    Host {
        host_key: Option<OperationalReportDigest>,
        state: OperationalReportState,
        #[schemars(range(min = 1, max = 64))]
        count: u32,
    },
    Source {
        discovered_from: Option<OperationalReportRowId>,
        state: OperationalReportState,
        #[schemars(range(min = 1, max = 64))]
        count: u32,
    },
    MimeStatus {
        mime_key: Option<OperationalReportDigest>,
        mime: Option<OperationalReportMime>,
        status: Option<OperationalReportStoredStatus>,
        #[schemars(range(min = 1, max = 64))]
        count: u32,
    },
    Page {
        frontier_id: OperationalReportRowId,
        url_key: OperationalReportDigest,
        host_key: Option<OperationalReportDigest>,
        status: Option<OperationalReportStoredStatus>,
        mime_key: Option<OperationalReportDigest>,
        mime: Option<OperationalReportMime>,
        content_digest: OperationalReportDigest,
        fetched_at: OperationalReportTimestamp,
        lane: OperationalReportLane,
    },
    Event {
        sequence: OperationalReportCursor,
        event: OperationalReportEvent,
        event_key: OperationalReportDigest,
        at: OperationalReportTimestamp,
    },
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportInventoryEntry {
    name: OperationalReportKind,
    source: OperationalReportSource,
    aggregation_scope: OperationalReportScope,
    #[schemars(length(max = 6))]
    filters: Vec<OperationalReportFilter>,
    /// Not recorded by this source projection; never inferred from other observations.
    #[schemars(length(max = 32))]
    not_recorded: Vec<OperationalReportNotRecorded>,
    /// Intentionally omitted or hashed when present; not a promise that they were recorded.
    #[schemars(length(max = 13))]
    withheld: Vec<OperationalReportWithheld>,
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportAvailabilitySemantics {
    #[schemars(extend("const" = "not recorded by the selected repository projection"))]
    not_recorded: String,
    #[schemars(extend("const" = "intentionally omitted or replaced with a digest when present"))]
    withheld: String,
}

#[derive(JsonSchema)]
#[serde(rename_all = "lowercase")]
enum OperationalReportFormat {
    Json,
    Jsonl,
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportInventory {
    #[schemars(extend("const" = 1))]
    version: u16,
    run: OperationalReportRunId,
    #[schemars(length(min = 17, max = 17))]
    reports: Vec<OperationalReportInventoryEntry>,
    #[schemars(extend("const" = 64))]
    max_limit: u32,
    #[schemars(extend("const" = 2048))]
    max_query_bytes: u32,
    #[schemars(extend("const" = "after_last_scanned_source_identity_even_when_no_rows_match"))]
    pagination: String,
    #[schemars(extend("const" = "live_keyset_not_a_frozen_snapshot"))]
    consistency: String,
    #[schemars(length(min = 2, max = 2), extend("uniqueItems" = true))]
    formats: Vec<OperationalReportFormat>,
    #[schemars(extend("const" = "identities_hashed_payloads_and_diagnostic_text_withheld"))]
    redaction: String,
    #[schemars(length(max = 32))]
    not_recorded: Vec<OperationalReportNotRecorded>,
    availability_semantics: OperationalReportAvailabilitySemantics,
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportPage {
    #[schemars(extend("const" = 1))]
    version: u16,
    report: OperationalReportKind,
    run: OperationalReportRunId,
    source: OperationalReportSource,
    aggregation_scope: OperationalReportScope,
    /// Source rows scanned, including rows that did not match the filters.
    #[schemars(range(min = 0, max = 64))]
    scanned: usize,
    /// Last scanned source identity on a full page; null on an exhausted page.
    next: Option<OperationalReportCursor>,
    #[schemars(length(max = 64))]
    rows: Vec<OperationalReportRow>,
    #[schemars(length(max = 32))]
    not_recorded: Vec<OperationalReportNotRecorded>,
    #[schemars(length(max = 13))]
    withheld: Vec<OperationalReportWithheld>,
    #[schemars(extend("const" = "identities_hashed_payloads_and_diagnostic_text_withheld"))]
    redaction: String,
}

#[derive(JsonSchema)]
#[serde(untagged)]
enum OperationalReportJsonlLine {
    Row(OperationalReportRow),
    Envelope(OperationalReportPage),
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportQuery {
    /// Last scanned source identity, not an offset or the last returned match.
    #[schemars(extend("default" = 0))]
    after: Option<OperationalReportCursor>,
    /// Source scan cap, inclusive 1..64; defaults to 64.
    #[schemars(range(min = 1, max = 64), extend("default" = 64))]
    limit: Option<u32>,
    /// JSON page or finite JSONL rows followed by one cursor envelope; defaults to json.
    #[schemars(extend("default" = "json"))]
    format: Option<OperationalReportFormat>,
    /// Frontier-derived reports only.
    state: Option<OperationalReportState>,
    /// Committed-page reports only. This filters stored status, not proof of original wire status.
    #[schemars(range(min = 100, max = 599))]
    status: Option<u16>,
    /// Frontier-derived reports only; must not exceed maxDepth when both are supplied.
    min_depth: Option<u16>,
    /// Frontier-derived reports only.
    max_depth: Option<u16>,
    /// Frontier-derived reports only; unknown source reasons remain unknown.
    class: Option<OperationalReportClass>,
    /// Frontier or committed-page reports only; full URL text is not accepted.
    url_key: Option<OperationalReportQueryDigest>,
    /// Frontier or committed-page reports only; full hostname text is not accepted.
    host_key: Option<OperationalReportQueryDigest>,
    /// Event-derived reports only; other selects unrecognized source event names.
    event: Option<OperationalReportEvent>,
    /// Event or committed-page reports only; inclusive, and strictly before until when both exist.
    since: Option<OperationalReportTimestamp>,
    /// Event or committed-page reports only; exclusive.
    until: Option<OperationalReportTimestamp>,
}

const KINDS: [(&str, &str, &str); 17] = [
    ("summary", "run_metadata", "summary"),
    ("seeds", "frontier", "frontier"),
    ("hosts", "frontier", "host"),
    ("sources", "frontier", "source"),
    ("mime_status", "committed_page_generations", "mime_status"),
    ("frontier", "frontier", "frontier"),
    ("processor_failures", "frontier", "frontier"),
    ("skipped_pages", "frontier", "frontier"),
    ("provenance", "run_metadata", "provenance"),
    ("threads", "unavailable", ""),
    ("host_dns_health", "unavailable", ""),
    ("crawl_log", "event_metadata", "event"),
    ("error_log", "frontier", "frontier"),
    ("uri_log", "committed_page_generations", "page"),
    ("progress_log", "run_metadata", "summary"),
    ("alert_log", "unavailable", ""),
    ("events", "event_metadata", "event"),
];

fn filters(source: &str) -> &'static [&'static str] {
    match source {
        "frontier" => &["state", "minDepth", "maxDepth", "class", "urlKey", "hostKey"],
        "committed_page_generations" => &["status", "urlKey", "hostKey", "since", "until"],
        "event_metadata" => &["event", "since", "until"],
        _ => &[],
    }
}

fn inventory_schema(schemas: &mut Schemas) -> Value {
    let base = schemas.res.subschema_for::<OperationalReportInventory>();
    let entries: Vec<_> = KINDS
        .iter()
        .map(|(kind, source, _)| {
            let scope = if *source == "run_metadata" {
                "run_snapshot"
            } else {
                "source_page"
            };
            let names = filters(source);
            let filter_items = if names.is_empty() {
                json!({"maxItems":0})
            } else {
                json!({"items":{"enum":names}})
            };
            json!({"if":{"properties":{"name":{"const":kind}}},
            "then":{"properties":{"source":{"const":source},"aggregationScope":{"const":scope},
                "filters":filter_items}}})
        })
        .collect();
    let contains: Vec<_> = KINDS
        .iter()
        .map(|(kind, _, _)| {
            json!({
                "contains":{"properties":{"name":{"const":kind}}},"minContains":1,"maxContains":1
            })
        })
        .collect();
    json!({"allOf":[base, {"properties":{"reports":{"items":{"allOf":entries},"allOf":contains}}}]})
}

fn page_schema(schemas: &mut Schemas) -> Value {
    let base = schemas.res.subschema_for::<OperationalReportPage>();
    let constraints: Vec<_> = KINDS
        .iter()
        .map(|(kind, source, row)| {
            let scope = if *source == "run_metadata" {
                "run_snapshot"
            } else {
                "source_page"
            };
            let rows = if row.is_empty() {
                json!({"maxItems":0})
            } else {
                json!({"items":{"properties":{"rowType":{"const":row}}},
                "maxItems":if *source == "run_metadata" { 1 } else { 64 }})
            };
            let scanned = if row.is_empty() {
                json!({"const":0})
            } else {
                json!({"maximum":if *source == "run_metadata" { 1 } else { 64 }})
            };
            let next = if *source == "run_metadata" || row.is_empty() {
                json!({"type":"null"})
            } else {
                json!({})
            };
            json!({"if":{"properties":{"report":{"const":kind}}},
            "then":{"properties":{"source":{"const":source},
                "aggregationScope":{"const":scope},"rows":rows,"scanned":scanned,"next":next}}})
        })
        .collect();
    json!({"allOf":[base, {"allOf":constraints}]})
}

fn query_schemas() -> Value {
    let mut generator = super::settings()
        .with(|settings| settings.inline_subschemas = true)
        .for_deserialize()
        .into_generator();
    let base = generator.root_schema_for::<OperationalReportQuery>().to_value();
    let mut by_kind = serde_json::Map::new();
    for (kind, source, _) in KINDS {
        let fields = filters(source);
        let mut schema = base.clone();
        if let Some(properties) = schema["properties"].as_object_mut() {
            properties.retain(|key, value| {
                super::strip_null(value);
                ["after", "limit", "format"].contains(&key.as_str()) || fields.contains(&key.as_str())
            });
        }
        schema["maxProperties"] = json!(16);
        by_kind.insert(kind.to_owned(), schema);
    }
    Value::Object(by_kind)
}

pub(super) fn apply(schemas: &mut Schemas, operation: &mut Value, id: &str) {
    if id == "listOperationalReports" {
        let schema = inventory_schema(schemas);
        operation["responses"]["200"] = json!({
            "description":"Finite report inventory; content-free discovery remains readable after source expiry. notRecorded and withheld have distinct meanings.",
            "content":{"application/json":{"schema":schema}}
        });
        return;
    }
    let report_kind = schemas.res.subschema_for::<OperationalReportKind>();
    let page = page_schema(schemas);
    let line = schemas.res.subschema_for::<OperationalReportJsonlLine>();
    if let Some(parameters) = operation["parameters"].as_array_mut() {
        parameters.push(json!({"name":"report","in":"path","required":true,
            "description":"Exactly one of the seventeen operational report kinds.","schema":report_kind}));
        parameters.extend(super::query_parameters::<OperationalReportQuery>());
    }
    operation["x-report-query-schemas"] = query_schemas();
    operation["x-report-max-decoded-query-bytes"] = json!(2048);
    operation["responses"]["200"] = json!({
        "description":"One bounded source scan. Follow next even when no rows match. JSONL contains at most 64 typed rows followed by one page envelope with rows empty. No snapshot, arbitrary text search, size filter or duration filter is implied.",
        "headers":{"Cache-Control":{"schema":{"type":"string","const":"private, no-store"}}},
        "content":{
            "application/json":{"schema":page},
            "application/x-ndjson":{"schema":{"type":"string"},
                "x-max-lines":65,"x-jsonl-line-schema":line,
                "x-envelope-schema":page}
        }
    });
    operation["responses"]["410"]["description"] = json!("Source retention expired or zero-data-retention source is unavailable; no retained report facts are returned.");
    operation["responses"]["422"]["description"] = json!("Unknown, unsupported, malformed, over-budget or contradictory structured query. The report-specific allowlist is authoritative; raw text, SQL and scripts are never accepted.");
}
