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
    History,
    WireHistory,
    ProcessorHistory,
    PipelineHistory,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportSource {
    RunMetadata,
    Frontier,
    CommittedPageGenerations,
    EventMetadata,
    Unavailable,
    ReportHistory,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportScope {
    RunSnapshot,
    SourcePage,
    FactsPage,
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
    Kind,
    FactKind,
    FactsAfter,
    CrossRun,
    MinDurationUs,
    MaxDurationUs,
    MinWireBytes,
    MaxWireBytes,
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
    PipelineCheckpoints,
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
    DiagnosticText,
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

/// Report-level `notRecorded` values of the inventory itself, distinct from per-report ones.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportInventoryNotRecorded {
    LegacyRunsWithoutReportFacts,
    UnmeasuredFactFieldsStayNull,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportFactKind {
    Dns,
    Stage,
    Wire,
    Alert,
    Loss,
    Pipeline,
}

/// Fact classes that carry a measured duration.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportDurationKind {
    Dns,
    Stage,
    Wire,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportDnsOutcome {
    Resolved,
    NotFound,
    Timeout,
    Refused,
    Failed,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportProcessorStage {
    Admission,
    Fetch,
    Parse,
    Extract,
    Index,
    Delivery,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportStageOutcome {
    Succeeded,
    Failed,
    Cancelled,
    Skipped,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportProcessorIdentity {
    NativeHttp,
    Browser,
    Parser,
    Extractor,
    ItemPipeline,
    Delivery,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportAlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportAlertCode {
    DnsFailure,
    ProcessorFailure,
    BudgetExhausted,
    Cancelled,
    DeliveryFailure,
    ObservationLoss,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportAlertContext {
    Acquisition,
    Processing,
    Delivery,
    Scheduling,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportPipelineStage {
    Fetch,
    Parse,
    Index,
    Completion,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportPipelineState {
    Pending,
    Succeeded,
    Failed,
    Skipped,
}

#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportFactRole {
    Primary,
    Companion,
}

/// Request parameter that pages a report's facts.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
enum OperationalReportFactRequestCursor {
    After,
    FactsAfter,
}

/// Response field that continues a report's facts.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
enum OperationalReportFactResponseCursor {
    Next,
    FactNext,
}

/// The existing ownership row that fenced a fact's producer; externally tagged by kind.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OperationalReportCustodySource {
    Session(OperationalReportRunId),
    Url(OperationalReportRowId),
    AuthenticatedProducer(OperationalReportRunId),
    ArchiveExport(OperationalReportRunId),
    Bootstrap(OperationalReportRunId),
}

/// Finite measured payload; its field names stay snake_case on this wire.
#[derive(JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OperationalReportFactData {
    Dns {
        outcome: OperationalReportDnsOutcome,
        duration_us: OperationalReportMeasure,
        recheck_at: Option<OperationalReportTimestamp>,
    },
    Stage {
        stage: OperationalReportProcessorStage,
        outcome: OperationalReportStageOutcome,
        duration_us: OperationalReportMeasure,
        processor: OperationalReportProcessorIdentity,
        #[schemars(range(min = 1))]
        processor_version: u32,
    },
    Wire {
        received_bytes: Option<OperationalReportMeasure>,
        sent_bytes: Option<OperationalReportMeasure>,
        duration_us: Option<OperationalReportMeasure>,
    },
    Alert {
        severity: OperationalReportAlertSeverity,
        code: OperationalReportAlertCode,
        context: OperationalReportAlertContext,
    },
    Loss {
        dropped: OperationalReportMeasure,
    },
    Pipeline {
        stage: OperationalReportPipelineStage,
        state: OperationalReportPipelineState,
    },
}

/// One fenced measured fact; URL and host are opaque digests, never raw text.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportFact {
    #[schemars(extend("const" = 1))]
    version: u16,
    id: OperationalReportDigest,
    tenant: OperationalReportRunId,
    run: OperationalReportRunId,
    source: OperationalReportCustodySource,
    fence: OperationalReportRowId,
    at: OperationalReportTimestamp,
    request_id: Option<OperationalReportRowId>,
    url_key: Option<OperationalReportDigest>,
    host_key: Option<OperationalReportDigest>,
    #[schemars(range(min = 1, max = 65535))]
    attempt: u16,
    data: OperationalReportFactData,
}

/// A fact with its repository sequence, as carried in a page's companion `facts`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportFactEntry {
    sequence: OperationalReportCursor,
    fact: OperationalReportFact,
}

/// Measured-duration sample of one fact class on the returned fact page.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportDuration {
    kind: OperationalReportDurationKind,
    #[schemars(range(min = 1, max = 64))]
    count: usize,
    p50_us: Option<OperationalReportMeasure>,
    p95_us: Option<OperationalReportMeasure>,
}

/// Checked sums over observed wire counters; unknown counters are never counted as zero.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportWireStats {
    #[schemars(range(min = 0, max = 64))]
    received_count: usize,
    /// Null when nothing was observed or the checked sum overflowed.
    received_bytes: Option<u64>,
    #[schemars(range(min = 0, max = 64))]
    sent_count: usize,
    sent_bytes: Option<u64>,
    overflow: bool,
}

/// Aggregates that describe only the facts returned in this page.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportFactsPage {
    #[schemars(extend("const" = "facts_page"))]
    scope: String,
    #[schemars(range(min = 0, max = 64))]
    facts: usize,
    #[schemars(length(max = 3))]
    durations: Vec<OperationalReportDuration>,
    wire: OperationalReportWireStats,
}

/// A nonnegative measurement that fits signed storage.
#[derive(JsonSchema)]
struct OperationalReportMeasure(#[schemars(range(min = 0), extend("maximum" = 9223372036854775807_u64))] u64);
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
    /// One primary history fact with its repository sequence.
    Fact {
        sequence: OperationalReportCursor,
        fact: Box<OperationalReportFact>,
    },
    /// One companion fact line of a JSONL legacy report.
    CompanionFact {
        sequence: OperationalReportCursor,
        fact: Box<OperationalReportFact>,
    },
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportFactsInventory {
    role: OperationalReportFactRole,
    /// Fact class a fixed-class report always serves, or the class a companion page defaults to.
    default_kind: Option<OperationalReportFactKind>,
    #[schemars(length(min = 6, max = 6), extend("uniqueItems" = true))]
    kinds: Vec<OperationalReportFactKind>,
    /// Request parameter that pages the facts.
    cursor: OperationalReportFactRequestCursor,
    /// Response field that continues the facts.
    next: OperationalReportFactResponseCursor,
    /// Whether the report accepts `crossRun`.
    cross_run: bool,
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportInventoryEntry {
    name: OperationalReportKind,
    source: OperationalReportSource,
    aggregation_scope: OperationalReportScope,
    #[schemars(length(max = 10), extend("uniqueItems" = true))]
    filters: Vec<OperationalReportFilter>,
    /// Not recorded by this source projection; a returned fact page narrows it only by what it proves.
    #[schemars(length(max = 11), extend("uniqueItems" = true))]
    not_recorded: Vec<OperationalReportNotRecorded>,
    /// Intentionally omitted or hashed when present; not a promise that they were recorded.
    #[schemars(length(max = 14), extend("uniqueItems" = true))]
    withheld: Vec<OperationalReportWithheld>,
    /// How the report relates to measured facts; null when it has none.
    facts: Option<OperationalReportFactsInventory>,
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
struct OperationalReportCrossRun {
    #[schemars(extend("const" = "history"))]
    report: String,
    #[schemars(extend("const" = "crossRun"))]
    parameter: String,
    #[schemars(extend("const" = "authorized_run_tenant"))]
    tenant: String,
    #[schemars(extend("const" = "enforced_for_each_source_row"))]
    retention: String,
}

/// Capability description of the fact history, not a guarantee that a run recorded any.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportInstrumentedFacts {
    #[schemars(extend("const" = "typed_facts_appear_only_when_a_producer_recorded_them"))]
    capability: String,
    #[schemars(length(min = 6, max = 6), extend("uniqueItems" = true))]
    kinds: Vec<OperationalReportFactKind>,
    /// Reports that page facts with `after`/`next`.
    #[schemars(extend("uniqueItems" = true))]
    primary_reports: Vec<OperationalReportKind>,
    /// Reports that keep their source rows and add a companion fact page.
    #[schemars(extend("uniqueItems" = true))]
    companion_reports: Vec<OperationalReportKind>,
    #[schemars(extend("const" = "facts_page"))]
    page_scope: String,
    #[schemars(extend("const" = "history_inclusive_since_until"))]
    time_bounds: String,
    cross_run: OperationalReportCrossRun,
    /// Reports for which no live facts are measured.
    #[schemars(extend("uniqueItems" = true))]
    unavailable: Vec<OperationalReportKind>,
}

#[derive(JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationalReportFactCursorPair {
    request: OperationalReportFactRequestCursor,
    response: OperationalReportFactResponseCursor,
}

#[derive(JsonSchema)]
#[serde(deny_unknown_fields)]
struct OperationalReportFactCursors {
    primary: OperationalReportFactCursorPair,
    companion: OperationalReportFactCursorPair,
    #[schemars(extend("const" = "independent_filtered_keyset_with_matching_lookahead"))]
    semantics: String,
}

#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationalReportInventory {
    #[schemars(extend("const" = 1))]
    version: u16,
    run: OperationalReportRunId,
    #[schemars(length(min = 21, max = 21))]
    reports: Vec<OperationalReportInventoryEntry>,
    #[schemars(extend("const" = 64))]
    max_limit: u32,
    #[schemars(extend("const" = 64))]
    max_facts_per_page: u32,
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
    instrumented_facts: OperationalReportInstrumentedFacts,
    fact_cursors: OperationalReportFactCursors,
    #[schemars(length(min = 2, max = 2), extend("uniqueItems" = true))]
    not_recorded: Vec<OperationalReportInventoryNotRecorded>,
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
    /// Whether a history page spans the caller tenant's retained runs.
    cross_run: bool,
    /// Source rows (or, for history reports, facts) scanned, including rows that did not match.
    #[schemars(range(min = 0, max = 64))]
    scanned: usize,
    /// Last scanned source identity on a full page; null on an exhausted page.
    next: Option<OperationalReportCursor>,
    #[schemars(length(max = 64))]
    rows: Vec<OperationalReportRow>,
    /// Companion facts of a legacy report; empty for history reports and in the JSONL envelope.
    #[schemars(length(max = 64))]
    facts: Vec<OperationalReportFactEntry>,
    /// Continues `facts` through `factsAfter`; independent of `next`.
    fact_next: Option<OperationalReportCursor>,
    /// Aggregates over the facts of this page only; null for reports without facts.
    facts_page: Option<OperationalReportFactsPage>,
    #[schemars(length(max = 11), extend("uniqueItems" = true))]
    not_recorded: Vec<OperationalReportNotRecorded>,
    #[schemars(length(max = 14), extend("uniqueItems" = true))]
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
    /// JSON page or finite JSONL rows (and companion facts) followed by one cursor envelope; defaults to json.
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
    /// Frontier, committed-page or fact-history reports; full URL text is not accepted.
    url_key: Option<OperationalReportQueryDigest>,
    /// Frontier, committed-page or fact-history reports; full hostname text is not accepted.
    host_key: Option<OperationalReportQueryDigest>,
    /// Event-derived reports only; other selects unrecognized source event names.
    event: Option<OperationalReportEvent>,
    /// Event, committed-page and fact-history reports; inclusive. Must be strictly before until for
    /// event and committed-page reports, and not after it for fact-history reports.
    since: Option<OperationalReportTimestamp>,
    /// Event and committed-page reports: exclusive. Fact-history reports: inclusive.
    until: Option<OperationalReportTimestamp>,
    /// `history` only: fact class to page; every other fact-history report has a fixed class.
    kind: Option<OperationalReportFactKind>,
    /// Companion reports only: class of the companion fact page; defaults to the report's own class.
    fact_kind: Option<OperationalReportFactKind>,
    /// Companion reports only: keyset cursor of the companion facts, independent of `after`.
    #[schemars(extend("default" = 0))]
    facts_after: Option<OperationalReportCursor>,
    /// Fact-history reports with measured durations (`history`, `wire_history`, `processor_history`,
    /// `host_dns_health`); must not exceed maxDurationUs.
    min_duration_us: Option<OperationalReportMeasure>,
    /// Same reports as minDurationUs.
    max_duration_us: Option<OperationalReportMeasure>,
    /// `history` and `wire_history` only: observed received bytes; must not exceed maxWireBytes.
    min_wire_bytes: Option<OperationalReportMeasure>,
    /// Same reports as minWireBytes.
    max_wire_bytes: Option<OperationalReportMeasure>,
    /// `history` only: page the caller tenant's retained timeline instead of this run.
    #[schemars(extend("default" = false))]
    cross_run: Option<bool>,
}

/// How a report relates to measured facts.
#[derive(Clone, Copy)]
enum Facts {
    None,
    /// Pages facts itself; the class is fixed unless `None` (the `kind` filter chooses).
    Primary(Option<&'static str>),
    /// Legacy rows plus a bounded companion fact page of this default class.
    Companion(&'static str),
}

struct Report {
    name: &'static str,
    source: &'static str,
    scope: &'static str,
    row: &'static str,
    facts: Facts,
    filters: &'static [&'static str],
}

const FRONTIER_FILTERS: &[&str] = &["state", "minDepth", "maxDepth", "class", "urlKey", "hostKey"];
const FRONTIER_FACT_FILTERS: &[&str] = &[
    "state",
    "minDepth",
    "maxDepth",
    "class",
    "urlKey",
    "hostKey",
    "factsAfter",
    "factKind",
];
const PAGE_FACT_FILTERS: &[&str] = &[
    "status",
    "urlKey",
    "hostKey",
    "since",
    "until",
    "factsAfter",
    "factKind",
];
const EVENT_FACT_FILTERS: &[&str] = &["event", "since", "until", "factsAfter", "factKind"];

const fn report(
    name: &'static str,
    source: &'static str,
    scope: &'static str,
    row: &'static str,
    facts: Facts,
    filters: &'static [&'static str],
) -> Report {
    Report {
        name,
        source,
        scope,
        row,
        facts,
        filters,
    }
}

/// Mirror of the runtime inventory: name, source, scope, row type, fact relationship, filters.
const REPORTS: [Report; 21] = [
    report(
        "summary",
        "run_metadata",
        "run_snapshot",
        "summary",
        Facts::None,
        &[],
    ),
    report(
        "seeds",
        "frontier",
        "source_page",
        "frontier",
        Facts::None,
        FRONTIER_FILTERS,
    ),
    report(
        "hosts",
        "frontier",
        "source_page",
        "host",
        Facts::Companion("dns"),
        FRONTIER_FACT_FILTERS,
    ),
    report(
        "sources",
        "frontier",
        "source_page",
        "source",
        Facts::None,
        FRONTIER_FILTERS,
    ),
    report(
        "mime_status",
        "committed_page_generations",
        "source_page",
        "mime_status",
        Facts::Companion("wire"),
        PAGE_FACT_FILTERS,
    ),
    report(
        "frontier",
        "frontier",
        "source_page",
        "frontier",
        Facts::Companion("wire"),
        FRONTIER_FACT_FILTERS,
    ),
    report(
        "processor_failures",
        "frontier",
        "source_page",
        "frontier",
        Facts::Companion("stage"),
        FRONTIER_FACT_FILTERS,
    ),
    report(
        "skipped_pages",
        "frontier",
        "source_page",
        "frontier",
        Facts::None,
        FRONTIER_FILTERS,
    ),
    report(
        "provenance",
        "run_metadata",
        "run_snapshot",
        "provenance",
        Facts::None,
        &[],
    ),
    report("threads", "unavailable", "source_page", "", Facts::None, &[]),
    report(
        "host_dns_health",
        "report_history",
        "facts_page",
        "fact",
        Facts::Primary(Some("dns")),
        &[
            "urlKey",
            "hostKey",
            "since",
            "until",
            "minDurationUs",
            "maxDurationUs",
        ],
    ),
    report(
        "crawl_log",
        "event_metadata",
        "source_page",
        "event",
        Facts::Companion("alert"),
        EVENT_FACT_FILTERS,
    ),
    report(
        "error_log",
        "frontier",
        "source_page",
        "frontier",
        Facts::Companion("alert"),
        FRONTIER_FACT_FILTERS,
    ),
    report(
        "uri_log",
        "committed_page_generations",
        "source_page",
        "page",
        Facts::Companion("wire"),
        PAGE_FACT_FILTERS,
    ),
    report(
        "progress_log",
        "run_metadata",
        "run_snapshot",
        "summary",
        Facts::None,
        &[],
    ),
    report(
        "alert_log",
        "report_history",
        "facts_page",
        "fact",
        Facts::Primary(Some("alert")),
        &["urlKey", "hostKey", "since", "until"],
    ),
    report(
        "events",
        "event_metadata",
        "source_page",
        "event",
        Facts::Companion("alert"),
        EVENT_FACT_FILTERS,
    ),
    report(
        "history",
        "report_history",
        "facts_page",
        "fact",
        Facts::Primary(None),
        &[
            "kind",
            "urlKey",
            "hostKey",
            "since",
            "until",
            "minDurationUs",
            "maxDurationUs",
            "minWireBytes",
            "maxWireBytes",
            "crossRun",
        ],
    ),
    report(
        "wire_history",
        "report_history",
        "facts_page",
        "fact",
        Facts::Primary(Some("wire")),
        &[
            "urlKey",
            "hostKey",
            "since",
            "until",
            "minDurationUs",
            "maxDurationUs",
            "minWireBytes",
            "maxWireBytes",
        ],
    ),
    report(
        "processor_history",
        "report_history",
        "facts_page",
        "fact",
        Facts::Primary(Some("stage")),
        &[
            "urlKey",
            "hostKey",
            "since",
            "until",
            "minDurationUs",
            "maxDurationUs",
        ],
    ),
    report(
        "pipeline_history",
        "report_history",
        "facts_page",
        "fact",
        Facts::Primary(Some("pipeline")),
        &["urlKey", "hostKey", "since", "until"],
    ),
];

/// `facts` of one inventory entry.
fn facts_constraint(report: &Report) -> Value {
    match report.facts {
        Facts::None => json!({"type":"null"}),
        Facts::Primary(kind) => json!({"type":"object","properties":{
            "role":{"const":"primary"},
            "defaultKind":kind.map_or_else(|| json!({"type":"null"}), |kind| json!({"const":kind})),
            "cursor":{"const":"after"},"next":{"const":"next"},
            "crossRun":{"const":report.name == "history"}}}),
        Facts::Companion(kind) => json!({"type":"object","properties":{
            "role":{"const":"companion"},"defaultKind":{"const":kind},
            "cursor":{"const":"factsAfter"},"next":{"const":"factNext"},
            "crossRun":{"const":false}}}),
    }
}

/// Exact unique list of the named reports.
fn exactly(names: &[&str]) -> Value {
    json!({"items":{"enum":names},"minItems":names.len(),"maxItems":names.len(),"uniqueItems":true})
}

fn inventory_schema(schemas: &mut Schemas) -> Value {
    let base = schemas.res.subschema_for::<OperationalReportInventory>();
    let entries: Vec<_> = REPORTS
        .iter()
        .map(|report| {
            let filters = if report.filters.is_empty() {
                json!({"maxItems":0})
            } else {
                json!({"items":{"enum":report.filters},"minItems":report.filters.len(),
                    "maxItems":report.filters.len(),"uniqueItems":true})
            };
            json!({"if":{"properties":{"name":{"const":report.name}}},
            "then":{"required":["facts"],"properties":{"source":{"const":report.source},
                "aggregationScope":{"const":report.scope},"filters":filters,
                "facts":facts_constraint(report)}}})
        })
        .collect();
    let contains: Vec<_> = REPORTS
        .iter()
        .map(|report| {
            json!({
                "contains":{"properties":{"name":{"const":report.name}}},"minContains":1,"maxContains":1
            })
        })
        .collect();
    let named = |wanted: fn(Facts) -> bool| -> Vec<&str> {
        REPORTS
            .iter()
            .filter(|report| wanted(report.facts))
            .map(|report| report.name)
            .collect()
    };
    let primary = named(|facts| matches!(facts, Facts::Primary(_)));
    let companion = named(|facts| matches!(facts, Facts::Companion(_)));
    json!({"allOf":[base, {
        "properties":{
            "reports":{"items":{"allOf":entries},"allOf":contains},
            "instrumentedFacts":{"properties":{
                "primaryReports":exactly(&primary),
                "companionReports":exactly(&companion),
                "unavailable":exactly(&["threads"])}}
        }
    }]})
}

/// Row constraints of one report: its row type and, for fixed-class history, the fact class.
fn row_items(report: &Report) -> Value {
    let mut item = json!({"properties":{"rowType":{"const":report.row}}});
    if let Facts::Primary(Some(kind)) = report.facts {
        item["properties"]["fact"] = json!({"properties":{"data":{"properties":{"kind":{"const":kind}}}}});
    }
    item
}

fn page_schema(schemas: &mut Schemas) -> Value {
    let base = schemas.res.subschema_for::<OperationalReportPage>();
    let constraints: Vec<_> = REPORTS
        .iter()
        .map(|report| {
            let snapshot = report.source == "run_metadata";
            let rows = if report.row.is_empty() {
                json!({"maxItems":0})
            } else {
                json!({"items":row_items(report),"maxItems":if snapshot { 1 } else { 64 }})
            };
            let scanned = if report.row.is_empty() {
                json!({"const":0})
            } else {
                json!({"maximum":if snapshot { 1 } else { 64 }})
            };
            let next = if snapshot || report.row.is_empty() {
                json!({"type":"null"})
            } else {
                json!({})
            };
            let (facts, fact_next, facts_page) = match report.facts {
                Facts::None => (
                    json!({"maxItems":0}),
                    json!({"type":"null"}),
                    json!({"type":"null"}),
                ),
                Facts::Primary(_) => (
                    json!({"maxItems":0}),
                    json!({"type":"null"}),
                    json!({"type":"object"}),
                ),
                Facts::Companion(_) => (json!({"maxItems":64}), json!({}), json!({"type":"object"})),
            };
            let cross_run = if report.name == "history" {
                json!({})
            } else {
                json!({"const":false})
            };
            json!({"if":{"properties":{"report":{"const":report.name}}},
            "then":{"required":["crossRun","facts","factNext","factsPage"],
                "properties":{"source":{"const":report.source},
                "aggregationScope":{"const":report.scope},"rows":rows,"scanned":scanned,"next":next,
                "crossRun":cross_run,"facts":facts,"factNext":fact_next,"factsPage":facts_page}}})
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
    for report in &REPORTS {
        let mut schema = base.clone();
        if let Some(properties) = schema["properties"].as_object_mut() {
            properties.retain(|key, value| {
                super::strip_null(value);
                ["after", "limit", "format"].contains(&key.as_str()) || report.filters.contains(&key.as_str())
            });
        }
        schema["maxProperties"] = json!(16);
        by_kind.insert(report.name.to_owned(), schema);
    }
    Value::Object(by_kind)
}

pub(super) fn apply(schemas: &mut Schemas, operation: &mut Value, id: &str) {
    if id == "listOperationalReports" {
        let schema = inventory_schema(schemas);
        operation["responses"]["200"] = json!({
            "description":"Finite report inventory; content-free discovery remains readable after source expiry. notRecorded and withheld have distinct meanings. instrumentedFacts and each report's facts describe capability, not a guarantee that a run recorded any fact.",
            "content":{"application/json":{"schema":schema}}
        });
        return;
    }
    let report_kind = schemas.res.subschema_for::<OperationalReportKind>();
    let page = page_schema(schemas);
    let line = schemas.res.subschema_for::<OperationalReportJsonlLine>();
    if let Some(parameters) = operation["parameters"].as_array_mut() {
        parameters.push(json!({"name":"report","in":"path","required":true,
            "description":"Exactly one of the twenty-one operational report kinds.","schema":report_kind}));
        parameters.extend(super::query_parameters::<OperationalReportQuery>());
    }
    operation["x-report-query-schemas"] = query_schemas();
    operation["x-report-max-decoded-query-bytes"] = json!(2048);
    operation["responses"]["200"] = json!({
        "description":"One bounded scan. Source reports scan source rows; history reports page measured facts with after/next; legacy reports add a companion fact page with its own factsAfter/factNext cursor. Follow next even when no rows match. factsPage aggregates describe only the facts of this page. JSONL contains at most 64 typed rows and 64 companion facts followed by one page envelope with rows and facts empty. No snapshot or arbitrary text search is implied.",
        "headers":{"Cache-Control":{"schema":{"type":"string","const":"private, no-store"}}},
        "content":{
            "application/json":{"schema":page},
            "application/x-ndjson":{"schema":{"type":"string"},
                "x-max-lines":129,"x-jsonl-line-schema":line,
                "x-envelope-schema":page}
        }
    });
    operation["responses"]["410"]["description"] = json!("Source retention expired or zero-data-retention source is unavailable; no retained report facts are returned.");
    operation["responses"]["422"]["description"] = json!("Unknown, unsupported, malformed, over-budget or contradictory structured query. The report-specific allowlist is authoritative; raw text, SQL and scripts are never accepted.");
}
