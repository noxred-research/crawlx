//! Monitor operations: create, list, read, update, delete, run now and the check history.

use super::common::{JobWebhookSpec, JsonObject};
use super::scrape::ScrapeOptions;
use super::Spec;
use schemars::JsonSchema;
use serde_json::Value;

// ---- requests ------------------------------------------------------------------------------

/// When a monitor runs: exactly one of `cron` and `text`.
#[derive(JsonSchema)]
pub(super) struct MonitorSchedule {
    /// A five-field cron expression (at least 5 minutes between runs).
    cron: Option<String>,
    /// A schedule in words (`every 6 hours`).
    text: Option<String>,
    /// IANA time zone of the schedule (default UTC).
    timezone: Option<String>,
}

/// Limits of a crawl target.
#[derive(JsonSchema)]
pub(super) struct CrawlOptions {
    /// Most pages per check (1 to 1000, default 100).
    #[schemars(range(min = 1, max = 1000))]
    limit: Option<u32>,
    /// Deepest path nesting below the start URL (0 to 100).
    #[serde(rename = "maxDepth")]
    #[schemars(range(min = 0, max = 100))]
    max_depth: Option<u32>,
    /// The same as `maxDepth`; the smaller of the two applies.
    #[serde(rename = "maxDiscoveryDepth")]
    #[schemars(range(min = 0, max = 100))]
    max_discovery_depth: Option<u32>,
    /// Regexes a page path must match (at most 100 of at most 512 characters).
    #[serde(rename = "includePaths")]
    include_paths: Option<Vec<String>>,
    /// Regexes that exclude a page path (at most 100 of at most 512 characters).
    #[serde(rename = "excludePaths")]
    exclude_paths: Option<Vec<String>>,
}

/// The recency window of a search target.
#[derive(JsonSchema)]
pub(super) enum SearchWindow {
    /// Five minutes.
    #[serde(rename = "5m")]
    Minutes5,
    /// Fifteen minutes.
    #[serde(rename = "15m")]
    Minutes15,
    /// One hour.
    #[serde(rename = "1h")]
    Hour1,
    /// Six hours.
    #[serde(rename = "6h")]
    Hours6,
    /// One day (default).
    #[serde(rename = "24h")]
    Hours24,
    /// One week.
    #[serde(rename = "7d")]
    Days7,
}

/// What a monitor watches.
#[derive(JsonSchema)]
#[serde(tag = "type")]
pub(super) enum MonitorTarget {
    /// A fixed list of URLs.
    #[serde(rename = "scrape")]
    Scrape {
        /// Stable id of the target (a UUID; generated when omitted).
        #[schemars(extend("format" = "uuid"))]
        id: Option<String>,
        /// 1 to 100 absolute `http(s)` URLs.
        urls: Option<Vec<String>>,
        /// A single URL, read as a one-element `urls`.
        url: Option<String>,
        /// Scrape options of every page; a `changeTracking` format selects how pages are compared.
        #[serde(rename = "scrapeOptions")]
        scrape_options: Option<ScrapeOptions>,
    },
    /// Every page found below a start URL.
    #[serde(rename = "crawl")]
    Crawl {
        /// Stable id of the target (a UUID; generated when omitted).
        #[schemars(extend("format" = "uuid"))]
        id: Option<String>,
        /// The start URL.
        url: String,
        /// Crawl limits.
        #[serde(rename = "crawlOptions")]
        crawl_options: Option<CrawlOptions>,
        /// Scrape options of every page.
        #[serde(rename = "scrapeOptions")]
        scrape_options: Option<ScrapeOptions>,
    },
    /// New web results for some queries.
    #[serde(rename = "search")]
    Search {
        /// Stable id of the target (a UUID; generated when omitted).
        #[schemars(extend("format" = "uuid"))]
        id: Option<String>,
        /// 1 to 12 queries of at most 256 characters.
        queries: Vec<String>,
        /// Recency window (default `24h`).
        #[serde(rename = "searchWindow")]
        search_window: Option<SearchWindow>,
        /// Most results evaluated per check (1 to 50, default 10).
        #[serde(rename = "maxResults")]
        #[schemars(range(min = 1, max = 50))]
        max_results: Option<u32>,
        /// Only these hosts (at most 50); not with `excludeDomains`.
        #[serde(rename = "includeDomains")]
        include_domains: Option<Vec<String>>,
        /// Never these hosts (at most 50).
        #[serde(rename = "excludeDomains")]
        exclude_domains: Option<Vec<String>>,
    },
}

/// E-mail notification settings.
#[derive(JsonSchema)]
pub(super) struct EmailNotification {
    /// Send e-mail.
    enabled: Option<bool>,
    /// Attach the diffs.
    #[serde(rename = "includeDiffs")]
    include_diffs: Option<bool>,
    /// Up to 25 e-mail addresses.
    recipients: Option<Vec<String>>,
}

/// Notification settings.
#[derive(JsonSchema)]
pub(super) struct MonitorNotification {
    /// E-mail settings.
    email: Option<EmailNotification>,
}

/// The scheduling state a monitor can be set to.
#[derive(JsonSchema)]
pub(super) enum MonitorState {
    /// Runs on its schedule.
    #[serde(rename = "active")]
    Active,
    /// Does not run; `nextRunAt` is cleared.
    #[serde(rename = "paused")]
    Paused,
}

/// `POST /monitor` body.
#[derive(JsonSchema)]
pub(super) struct MonitorCreateRequest {
    /// Display name (at most 256 characters).
    name: String,
    /// When the monitor runs.
    schedule: MonitorSchedule,
    /// What it watches (1 to 50 targets with unique ids).
    targets: Vec<MonitorTarget>,
    /// What counts as relevant; the LLM judges each changed page against it (at most 2000
    /// characters). Required when a target is a search target, unless `judgeEnabled` is `false`.
    goal: Option<String>,
    /// Judge pages against `goal` (default: whenever a goal exists); `true` needs a goal.
    #[serde(rename = "judgeEnabled")]
    judge_enabled: Option<bool>,
    /// Days a check is kept (1 to 365, default 30).
    #[serde(rename = "retentionDays")]
    #[schemars(range(min = 1, max = 365))]
    retention_days: Option<u32>,
    /// Webhook for the events `monitor.page` and `monitor.check.completed`.
    webhook: Option<JobWebhookSpec>,
    /// Notification settings.
    notification: Option<MonitorNotification>,
}

/// `PATCH /monitor/{monitorId}` body: any member to change; at least one is required. Absent
/// members stay as they are; `goal: null` and `webhook: null` clear them.
#[derive(JsonSchema)]
pub(super) struct MonitorUpdateRequest {
    /// New display name.
    name: Option<String>,
    /// New schedule.
    schedule: Option<MonitorSchedule>,
    /// New targets (replace the old ones).
    targets: Option<Vec<MonitorTarget>>,
    /// New goal; `null` clears it.
    goal: Option<String>,
    /// New judging flag.
    #[serde(rename = "judgeEnabled")]
    judge_enabled: Option<bool>,
    /// New retention in days.
    #[serde(rename = "retentionDays")]
    #[schemars(range(min = 1, max = 365))]
    retention_days: Option<u32>,
    /// New webhook; `null` clears it.
    webhook: Option<JobWebhookSpec>,
    /// New notification settings.
    notification: Option<MonitorNotification>,
    /// Pause or resume the monitor.
    status: Option<MonitorState>,
}

// ---- responses -----------------------------------------------------------------------------

/// The page counts of a check.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CheckSummary {
    /// Pages compared.
    total_pages: u64,
    /// Pages that did not change.
    same: u64,
    /// Pages that changed.
    changed: u64,
    /// New pages.
    new: u64,
    /// Pages that disappeared.
    removed: u64,
    /// Pages that could not be scraped.
    error: u64,
    /// Changed pages the judge found relevant to the goal.
    #[serde(skip_serializing_if = "Option::is_none")]
    relevant: Option<u64>,
    /// How goal judging went.
    #[serde(skip_serializing_if = "Option::is_none")]
    goal_judging: Option<Value>,
}

/// A monitor.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct Monitor {
    /// Id of the monitor.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// Display name.
    name: Option<String>,
    /// `active` or `paused`.
    status: String,
    /// The schedule as stored: `{cron, timezone}`.
    schedule: JsonObject,
    /// RFC 3339 time of the next run; `null` while paused.
    next_run_at: Option<String>,
    /// RFC 3339 time of the last run.
    last_run_at: Option<String>,
    /// The running check, if any.
    current_check_id: Option<String>,
    /// The targets as stored (the request's targets with their ids).
    targets: Vec<JsonObject>,
    /// The webhook as stored (`{url, headers, metadata, events}`); `null` without one.
    webhook: Option<JsonObject>,
    /// The notification settings as stored.
    notification: JsonObject,
    /// Days a check is kept.
    retention_days: u32,
    /// Credits the monitor is estimated to cost per 30 days.
    estimated_credits_per_month: Option<u64>,
    /// Summary of the newest finished check.
    last_check_summary: Option<CheckSummary>,
    /// The goal.
    goal: Option<String>,
    /// Whether pages are judged against the goal.
    judge_enabled: bool,
    /// RFC 3339 creation time.
    created_at: String,
    /// RFC 3339 time of the last change.
    updated_at: String,
}

/// One check (run) of a monitor.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct MonitorCheck {
    /// Id of the check.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// Id of the monitor.
    #[schemars(extend("format" = "uuid"))]
    monitor_id: String,
    /// `running`, `completed`, `partial`, `failed`, `skipped_overlap`.
    status: String,
    /// What started the check (`schedule` or `manual`).
    trigger: String,
    /// RFC 3339 time the check was scheduled for.
    scheduled_for: Option<String>,
    /// RFC 3339 start time.
    started_at: String,
    /// RFC 3339 end time; `null` while running.
    finished_at: Option<String>,
    /// Upper bound of the credits the check may spend.
    estimated_credits: Option<u64>,
    /// Credits reserved for the check.
    reserved_credits: Option<u64>,
    /// Credits the check spent; `null` while running.
    actual_credits: Option<u64>,
    /// `pending` while running, then `settled`.
    billing_status: String,
    /// Page counts.
    summary: CheckSummary,
    /// The outcome per target.
    target_results: Option<Value>,
    /// Whether the notifications were sent.
    notification_status: Option<Value>,
    /// Why the check failed.
    error: Option<String>,
    /// RFC 3339 creation time.
    created_at: String,
    /// RFC 3339 time of the last change.
    updated_at: String,
}

/// One page of a check.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct MonitorCheckPage {
    /// Stable id derived from the check, target and URL.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// The target the page belongs to.
    target_id: String,
    /// The URL.
    url: String,
    /// `same`, `new`, `changed`, `removed` or `error`.
    status: String,
    /// Always `null`: crawlx keeps no scrape ids for monitor pages.
    previous_scrape_id: Option<String>,
    /// Always `null`.
    current_scrape_id: Option<String>,
    /// HTTP status of the page.
    status_code: Option<u16>,
    /// Why the page could not be scraped.
    error: Option<String>,
    /// Page metadata.
    metadata: Option<Value>,
    /// The goal judge's verdict.
    judgment: Option<Value>,
    /// RFC 3339 time of the comparison.
    created_at: Option<String>,
    /// The diff of a changed page.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<Value>,
    /// The page content.
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<Value>,
}

/// A check with its pages.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct MonitorCheckDetail {
    /// Id of the check.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// Id of the monitor.
    #[schemars(extend("format" = "uuid"))]
    monitor_id: String,
    /// `running`, `completed`, `partial`, `failed`, `skipped_overlap`.
    status: String,
    /// What started the check.
    trigger: String,
    /// RFC 3339 time the check was scheduled for.
    scheduled_for: Option<String>,
    /// RFC 3339 start time.
    started_at: String,
    /// RFC 3339 end time.
    finished_at: Option<String>,
    /// Upper bound of the credits the check may spend.
    estimated_credits: Option<u64>,
    /// Credits reserved for the check.
    reserved_credits: Option<u64>,
    /// Credits the check spent.
    actual_credits: Option<u64>,
    /// `pending` or `settled`.
    billing_status: String,
    /// Page counts.
    summary: CheckSummary,
    /// The outcome per target.
    target_results: Option<Value>,
    /// Whether the notifications were sent.
    notification_status: Option<Value>,
    /// Why the check failed.
    error: Option<String>,
    /// RFC 3339 creation time.
    created_at: String,
    /// RFC 3339 time of the last change.
    updated_at: String,
    /// This page of the check's pages, by target and URL.
    pages: Vec<MonitorCheckPage>,
    /// URL of the next page of `pages`; `null` on the last page.
    next: Option<String>,
}

/// `{success: true, data: Monitor}`.
#[derive(JsonSchema)]
pub(super) struct MonitorResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The monitor.
    data: Monitor,
}

/// `GET /monitor`.
#[derive(JsonSchema)]
pub(super) struct MonitorListResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The monitors, newest first.
    data: Vec<Monitor>,
}

/// `DELETE /monitor/{monitorId}`.
#[derive(JsonSchema)]
pub(super) struct MonitorDeleted {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
}

/// `POST /monitor/{monitorId}/run`.
#[derive(JsonSchema)]
pub(super) struct MonitorRunResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the check.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// The check that was started.
    data: MonitorCheck,
}

/// `GET /monitor/{monitorId}/checks`.
#[derive(JsonSchema)]
pub(super) struct MonitorChecksResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The checks, newest first.
    data: Vec<MonitorCheck>,
}

/// `GET /monitor/{monitorId}/checks/{checkId}`.
#[derive(JsonSchema)]
pub(super) struct MonitorCheckDetailResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// URL of the next page of the check's pages; `null` on the last page.
    next: Option<String>,
    /// The check with its pages.
    data: MonitorCheckDetail,
}

// ---- query strings -------------------------------------------------------------------------

/// Query string of `GET /monitor`.
#[derive(JsonSchema)]
pub(super) struct MonitorListQuery {
    /// Monitors per response (1 to 100, default 25).
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    /// Monitors to skip.
    offset: Option<u32>,
    /// Only monitors in this state.
    status: Option<MonitorState>,
}

/// The status of a check.
#[derive(JsonSchema)]
pub(super) enum CheckStatus {
    /// Queued.
    #[serde(rename = "queued")]
    Queued,
    /// Running.
    #[serde(rename = "running")]
    Running,
    /// Completed.
    #[serde(rename = "completed")]
    Completed,
    /// Failed.
    #[serde(rename = "failed")]
    Failed,
    /// Some pages or targets failed.
    #[serde(rename = "partial")]
    Partial,
    /// Skipped because the previous check was still running.
    #[serde(rename = "skipped_overlap")]
    SkippedOverlap,
    /// Skipped for lack of credits (never produced).
    #[serde(rename = "skipped_no_credits")]
    SkippedNoCredits,
}

/// Query string of `GET /monitor/{monitorId}/checks`.
#[derive(JsonSchema)]
pub(super) struct MonitorChecksQuery {
    /// Checks per response (1 to 100, default 25).
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    /// Checks to skip.
    offset: Option<u32>,
    /// Only checks with this status.
    status: Option<CheckStatus>,
}

/// The status of a page of a check.
#[derive(JsonSchema)]
pub(super) enum PageStatus {
    /// Unchanged.
    #[serde(rename = "same")]
    Same,
    /// New.
    #[serde(rename = "new")]
    New,
    /// Changed.
    #[serde(rename = "changed")]
    Changed,
    /// Removed.
    #[serde(rename = "removed")]
    Removed,
    /// Could not be scraped.
    #[serde(rename = "error")]
    Error,
}

/// Query string of `GET /monitor/{monitorId}/checks/{checkId}`.
#[derive(JsonSchema)]
pub(super) struct MonitorCheckQuery {
    /// Pages per response (1 to 100, default 25).
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    /// Pages to skip.
    skip: Option<u32>,
    /// Only pages with this status.
    status: Option<PageStatus>,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "createMonitor" => Spec::new(&[422])
            .json::<MonitorCreateRequest>("The monitor's name, schedule, targets and options.")
            .reply::<MonitorResponse>("200", "The monitor was created."),
        "listMonitors" => Spec::new(&[422])
            .query::<MonitorListQuery>()
            .reply::<MonitorListResponse>("200", "The tenant's monitors."),
        "getMonitor" => Spec::new(&[400, 404])
            .path("monitorId", "Id of the monitor.", Some("uuid"))
            .reply::<MonitorResponse>("200", "The monitor."),
        "updateMonitor" => Spec::new(&[400, 404, 422])
            .path("monitorId", "Id of the monitor.", Some("uuid"))
            .json::<MonitorUpdateRequest>("The members to change (at least one).")
            .reply::<MonitorResponse>("200", "The monitor after the change."),
        "deleteMonitor" => Spec::new(&[400, 404])
            .path("monitorId", "Id of the monitor.", Some("uuid"))
            .reply::<MonitorDeleted>("200", "The monitor, its checks and baselines were deleted."),
        "runMonitor" => Spec::new(&[400, 404, 409, 503])
            .path("monitorId", "Id of the monitor.", Some("uuid"))
            .reply::<MonitorRunResponse>("200", "A check was started; it runs in the background."),
        "listMonitorChecks" => Spec::new(&[400, 404, 422])
            .path("monitorId", "Id of the monitor.", Some("uuid"))
            .query::<MonitorChecksQuery>()
            .reply::<MonitorChecksResponse>("200", "The monitor's checks, newest first."),
        "getMonitorCheck" => Spec::new(&[400, 404, 422])
            .path("monitorId", "Id of the monitor.", Some("uuid"))
            .path("checkId", "Id of the check.", Some("uuid"))
            .query::<MonitorCheckQuery>()
            .reply::<MonitorCheckDetailResponse>("200", "The check with one page of its pages."),
        _ => return None,
    };
    Some(s)
}
