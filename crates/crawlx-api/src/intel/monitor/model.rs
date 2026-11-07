//! Request side of the monitor API: validation of `MonitorCreateRequest` / `MonitorUpdateRequest`
//! into typed drafts, with every violation reported as a JSON-pointer [`Detail`].
//!
//! Stored shape (`MonitorRecord`): `schedule` is the request object with the zone filled in,
//! `targets` the request targets with a stable `id`, `webhook` the [`JobWebhook::to_value`] form
//! (full `monitor.*` event names), and `notification` the validated notification object plus the
//! an internal member `judgeEnabled` (the storage row has no column for it).

use crate::errors::{Detail, HttpError};
use crate::intel::webhook::JobWebhook;
use crawlx_scheduler::schedule::{Schedule, ScheduleError, ScheduleSpec};
use crawlx_storage::MonitorStatus;
use crawlx_url::PathFilter;
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// Targets per monitor.
pub const MAX_TARGETS: usize = 50;
/// Longest retention.
pub const MAX_RETENTION_DAYS: u32 = 365;
/// Retention when the request names none.
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
/// Longest monitor name.
pub const MAX_NAME_CHARS: usize = 256;
/// Longest goal.
pub const MAX_GOAL_CHARS: usize = 2_000;
/// URLs of one `scrape` target.
pub const MAX_SCRAPE_URLS: usize = 100;
/// Pages a `crawl` target checks when `crawlOptions.limit` is absent.
pub const DEFAULT_CRAWL_LIMIT: usize = 100;
/// Most pages a `crawl` target may check.
pub const MAX_CRAWL_LIMIT: usize = 1_000;
/// Queries of one `search` target.
pub const MAX_QUERIES: usize = 12;
/// Longest search query.
pub const MAX_QUERY_CHARS: usize = 256;
/// Results a `search` target evaluates when `maxResults` is absent.
pub const DEFAULT_MAX_RESULTS: usize = 10;
/// Most results a `search` target evaluates.
pub const MAX_MAX_RESULTS: usize = 50;
/// Domains in one include or exclude list.
pub const MAX_DOMAINS: usize = 50;
/// E-mail recipients of one monitor.
pub const MAX_RECIPIENTS: usize = 25;
/// Webhook event names of the monitor (`MonitorWebhook.events`).
pub const WEBHOOK_EVENTS: [&str; 2] = ["monitor.page", "monitor.check.completed"];
/// `searchWindow` values.
pub const SEARCH_WINDOWS: [&str; 6] = ["5m", "15m", "1h", "6h", "24h", "7d"];

/// How a `changeTracking` format asks pages to be compared.
#[derive(Clone, PartialEq, Debug)]
pub struct ChangeTracking {
    /// Unified markdown diff (`git-diff` mode, the default).
    pub git_diff: bool,
    /// Per-field diff of an LLM extraction (`json` mode).
    pub json: bool,
    /// JSON Schema of the extraction.
    pub schema: Option<Value>,
    /// Extraction prompt.
    pub prompt: Option<String>,
}

/// What one target watches.
#[derive(Clone, PartialEq, Debug)]
pub enum TargetKind {
    /// A fixed list of URLs.
    Scrape {
        /// The URLs.
        urls: Vec<String>,
    },
    /// Every page a map of the site finds.
    Crawl {
        /// Start URL.
        url: String,
        /// Most pages per check.
        limit: usize,
        /// Deepest path nesting below the start URL (`maxDepth` / `maxDiscoveryDepth`).
        max_depth: Option<usize>,
        /// Regexes a page path must match (any).
        include_paths: Vec<String>,
        /// Regexes that exclude a page path (any).
        exclude_paths: Vec<String>,
    },
    /// New web results for some queries.
    Search {
        /// The queries.
        queries: Vec<String>,
        /// Recency window (`5m` .. `7d`).
        window: String,
        /// Combined cap of results evaluated per check.
        max_results: usize,
        /// Only these hosts.
        include_domains: Vec<String>,
        /// Never these hosts.
        exclude_domains: Vec<String>,
    },
}

/// One validated monitor target.
#[derive(Clone, PartialEq, Debug)]
pub struct Target {
    /// Stable target id (generated when the request names none).
    pub id: Uuid,
    /// What it watches.
    pub kind: TargetKind,
    /// Options for scraping its pages: the request's `scrapeOptions` without `changeTracking`
    /// formats and with `markdown` among the formats.
    pub scrape_options: Value,
    /// The `changeTracking` format, when the request carries one.
    pub change_tracking: Option<ChangeTracking>,
    /// The stored form (request object, `id` filled in).
    pub value: Value,
}

/// A validated `MonitorCreateRequest`.
#[derive(Clone, Debug)]
pub struct NewMonitor {
    /// Display name.
    pub name: String,
    /// Schedule.
    pub schedule: Schedule,
    /// Targets.
    pub targets: Vec<Target>,
    /// Goal for judging.
    pub goal: Option<String>,
    /// `judgeEnabled` as the request sent it; absent means "judge whenever a goal exists".
    pub judge_explicit: Option<bool>,
    /// Retention in days.
    pub retention_days: u32,
    /// Webhook destination.
    pub webhook: Option<JobWebhook>,
    /// Validated notification settings.
    pub notification: Value,
}

/// A validated `MonitorUpdateRequest`; absent members stay as they are.
#[derive(Clone, Debug, Default)]
pub struct MonitorPatch {
    /// New name.
    pub name: Option<String>,
    /// New schedule.
    pub schedule: Option<Schedule>,
    /// New targets (replace the old ones).
    pub targets: Option<Vec<Target>>,
    /// New goal (`Some(None)` clears it).
    pub goal: Option<Option<String>>,
    /// New judging flag.
    pub judge_enabled: Option<bool>,
    /// New retention.
    pub retention_days: Option<u32>,
    /// New webhook (`Some(None)` clears it).
    pub webhook: Option<Option<JobWebhook>>,
    /// New notification settings.
    pub notification: Option<Value>,
    /// New scheduling state.
    pub status: Option<MonitorStatus>,
}

type Details = Vec<Detail>;

fn bad(details: &mut Details, path: &str, code: &str, message: impl Into<String>) {
    details.push(Detail::new(path, code, message));
}

fn as_object<'a>(v: &'a Value, path: &str, details: &mut Details) -> Option<&'a Map<String, Value>> {
    let o = v.as_object();
    if o.is_none() {
        bad(details, path, "invalid", "expected an object");
    }
    o
}

fn string_member(
    o: &Map<String, Value>,
    key: &str,
    ptr: &str,
    max: usize,
    details: &mut Details,
) -> Option<String> {
    let v = o.get(key).filter(|v| !v.is_null())?;
    let path = format!("{ptr}/{key}");
    match v.as_str() {
        Some(s) if s.chars().count() <= max => Some(s.to_owned()),
        Some(_) => {
            bad(
                details,
                &path,
                "out_of_range",
                format!("{key} is longer than {max} characters"),
            );
            None
        }
        None => {
            bad(details, &path, "invalid", format!("{key} must be a string"));
            None
        }
    }
}

/// An integer member within `lo..=hi`.
fn int_member(
    o: &Map<String, Value>,
    key: &str,
    ptr: &str,
    lo: u64,
    hi: u64,
    details: &mut Details,
) -> Option<u64> {
    let v = o.get(key).filter(|v| !v.is_null())?;
    let path = format!("{ptr}/{key}");
    match v.as_u64() {
        Some(n) if (lo..=hi).contains(&n) => Some(n),
        Some(_) => {
            bad(
                details,
                &path,
                "out_of_range",
                format!("{key} must be between {lo} and {hi}"),
            );
            None
        }
        None => {
            bad(details, &path, "invalid", format!("{key} must be an integer"));
            None
        }
    }
}

fn string_list(
    o: &Map<String, Value>,
    key: &str,
    ptr: &str,
    max_items: usize,
    max_chars: usize,
    details: &mut Details,
) -> Option<Vec<String>> {
    let v = o.get(key).filter(|v| !v.is_null())?;
    let path = format!("{ptr}/{key}");
    let Some(items) = v.as_array() else {
        bad(
            details,
            &path,
            "invalid",
            format!("{key} must be an array of strings"),
        );
        return None;
    };
    if items.len() > max_items {
        bad(
            details,
            &path,
            "out_of_range",
            format!("{key} takes at most {max_items} items"),
        );
        return None;
    }
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item.as_str() {
            Some(s) if !s.trim().is_empty() && s.chars().count() <= max_chars => out.push(s.to_owned()),
            Some(_) => bad(
                details,
                &format!("{path}/{i}"),
                "out_of_range",
                format!("each item must be 1 to {max_chars} characters"),
            ),
            None => bad(details, &format!("{path}/{i}"), "invalid", "expected a string"),
        }
    }
    Some(out)
}

fn http_url(text: &str) -> bool {
    url::Url::parse(text)
        .ok()
        .is_some_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
}

/// Split `scrapeOptions` into the options sent to the scrape service and the change-tracking
/// request. Validation failures are reported under `ptr`.
fn scrape_options(raw: Option<&Value>, ptr: &str, details: &mut Details) -> (Value, Option<ChangeTracking>) {
    let mut options = match raw.filter(|v| !v.is_null()) {
        None => Map::new(),
        Some(Value::Object(o)) => o.clone(),
        Some(_) => {
            bad(details, ptr, "invalid", "scrapeOptions must be an object");
            return (json!({ "formats": ["markdown"] }), None);
        }
    };
    let mut tracking: Option<ChangeTracking> = None;
    let mut formats: Vec<Value> = Vec::new();
    match options.get("formats") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                let is_tracking = item.get("type").and_then(Value::as_str) == Some("changeTracking")
                    || item.as_str() == Some("changeTracking");
                if !is_tracking {
                    formats.push(item.clone());
                    continue;
                }
                tracking = Some(change_tracking(item, &format!("{ptr}/formats/{i}"), details));
            }
        }
        Some(_) => bad(
            details,
            &format!("{ptr}/formats"),
            "invalid",
            "formats must be an array",
        ),
    }
    let has_markdown = formats
        .iter()
        .any(|f| f.as_str() == Some("markdown") || f.get("type").and_then(Value::as_str) == Some("markdown"));
    if !has_markdown {
        formats.insert(0, json!("markdown"));
    }
    options.insert("formats".to_owned(), Value::Array(formats));
    (Value::Object(options), tracking)
}

fn change_tracking(item: &Value, ptr: &str, details: &mut Details) -> ChangeTracking {
    let empty = Map::new();
    let o = item.as_object().unwrap_or(&empty);
    let mut git_diff = false;
    let mut json_mode = false;
    match o.get("modes") {
        None | Some(Value::Null) => {}
        Some(Value::Array(modes)) => {
            for (i, m) in modes.iter().enumerate() {
                match m.as_str() {
                    Some("git-diff") => git_diff = true,
                    Some("json") => json_mode = true,
                    _ => bad(
                        details,
                        &format!("{ptr}/modes/{i}"),
                        "invalid",
                        "modes take `git-diff` or `json`",
                    ),
                }
            }
        }
        Some(_) => bad(
            details,
            &format!("{ptr}/modes"),
            "invalid",
            "modes must be an array",
        ),
    }
    if !git_diff && !json_mode {
        git_diff = true;
    }
    let schema = o.get("schema").filter(|s| !s.is_null()).cloned();
    if schema.as_ref().is_some_and(|s| !s.is_object()) {
        bad(
            details,
            &format!("{ptr}/schema"),
            "invalid",
            "schema must be a JSON Schema object",
        );
    }
    let prompt = o
        .get("prompt")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
        .map(str::to_owned);
    if json_mode && schema.is_none() && prompt.is_none() {
        bad(
            details,
            ptr,
            "required",
            "the json mode needs a `schema` or a `prompt` describing the fields to track",
        );
    }
    ChangeTracking {
        git_diff,
        json: json_mode,
        schema,
        prompt,
    }
}

fn path_filters(include: &[String], exclude: &[String], ptr: &str, details: &mut Details) {
    if PathFilter::new(include, &[]).is_err() {
        bad(
            details,
            &format!("{ptr}/includePaths"),
            "invalid",
            "includePaths holds an invalid or oversized regex",
        );
    }
    if PathFilter::new(&[], exclude).is_err() {
        bad(
            details,
            &format!("{ptr}/excludePaths"),
            "invalid",
            "excludePaths holds an invalid or oversized regex",
        );
    }
}

impl Target {
    /// Validate one target object found at JSON pointer `ptr`.
    pub fn parse(v: &Value, ptr: &str, details: &mut Details) -> Option<Self> {
        let o = as_object(v, ptr, details)?;
        let id = match o.get("id").filter(|v| !v.is_null()) {
            None => Uuid::now_v7(),
            Some(Value::String(s)) => match Uuid::parse_str(s) {
                Ok(id) => id,
                Err(_) => {
                    bad(details, &format!("{ptr}/id"), "invalid", "id must be a UUID");
                    return None;
                }
            },
            Some(_) => {
                bad(details, &format!("{ptr}/id"), "invalid", "id must be a UUID");
                return None;
            }
        };
        let kind_name = o.get("type").and_then(Value::as_str);
        let before = details.len();
        let (kind, options_ptr) = match kind_name {
            Some("scrape") => (
                Self::parse_scrape(o, ptr, details),
                format!("{ptr}/scrapeOptions"),
            ),
            Some("crawl") => (Self::parse_crawl(o, ptr, details), format!("{ptr}/scrapeOptions")),
            Some("search") => (Self::parse_search(o, ptr, details), String::new()),
            _ => {
                bad(
                    details,
                    &format!("{ptr}/type"),
                    if kind_name.is_none() {
                        "required"
                    } else {
                        "invalid"
                    },
                    "type must be `scrape`, `crawl` or `search`",
                );
                return None;
            }
        };
        let (scrape_options, change_tracking) = if options_ptr.is_empty() {
            (json!({ "formats": ["markdown"] }), None)
        } else {
            scrape_options(o.get("scrapeOptions"), &options_ptr, details)
        };
        if details.len() > before {
            return None;
        }
        let kind = kind?;
        let mut stored = o.clone();
        stored.insert("id".to_owned(), json!(id));
        if let TargetKind::Scrape { urls } = &kind {
            stored.remove("url");
            stored.insert("urls".to_owned(), json!(urls));
        }
        Some(Self {
            id,
            kind,
            scrape_options,
            change_tracking,
            value: Value::Object(stored),
        })
    }

    fn parse_scrape(o: &Map<String, Value>, ptr: &str, details: &mut Details) -> Option<TargetKind> {
        // `url` (singular) is accepted as a one-element `urls`
        let single = o
            .get("url")
            .and_then(Value::as_str)
            .map(|u| vec![Value::String(u.to_owned())]);
        let urls_value = o
            .get("urls")
            .filter(|v| !v.is_null())
            .cloned()
            .or_else(|| single.map(Value::Array));
        let Some(Value::Array(items)) = urls_value else {
            bad(
                details,
                &format!("{ptr}/urls"),
                "required",
                "a scrape target needs a non-empty `urls` array",
            );
            return None;
        };
        if items.is_empty() || items.len() > MAX_SCRAPE_URLS {
            bad(
                details,
                &format!("{ptr}/urls"),
                "out_of_range",
                format!("urls takes 1 to {MAX_SCRAPE_URLS} items"),
            );
            return None;
        }
        let mut urls = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            match item.as_str() {
                Some(u) if http_url(u) => {
                    if !urls.iter().any(|seen| seen == u) {
                        urls.push(u.to_owned());
                    }
                }
                _ => bad(
                    details,
                    &format!("{ptr}/urls/{i}"),
                    "invalid",
                    "expected an absolute http(s) URL",
                ),
            }
        }
        Some(TargetKind::Scrape { urls })
    }

    fn parse_crawl(o: &Map<String, Value>, ptr: &str, details: &mut Details) -> Option<TargetKind> {
        let url = match o.get("url").and_then(Value::as_str) {
            Some(u) if http_url(u) => u.to_owned(),
            Some(_) => {
                bad(
                    details,
                    &format!("{ptr}/url"),
                    "invalid",
                    "expected an absolute http(s) URL",
                );
                return None;
            }
            None => {
                bad(
                    details,
                    &format!("{ptr}/url"),
                    "required",
                    "a crawl target needs a `url`",
                );
                return None;
            }
        };
        let mut limit = DEFAULT_CRAWL_LIMIT;
        let mut max_depth = None;
        let (mut include_paths, mut exclude_paths) = (Vec::new(), Vec::new());
        if let Some(opts) = o.get("crawlOptions").filter(|v| !v.is_null()) {
            let optr = format!("{ptr}/crawlOptions");
            if let Some(opts) = as_object(opts, &optr, details) {
                if let Some(n) = int_member(
                    opts,
                    "limit",
                    &optr,
                    1,
                    u64::try_from(MAX_CRAWL_LIMIT).unwrap_or(0),
                    details,
                ) {
                    limit = usize::try_from(n).unwrap_or(DEFAULT_CRAWL_LIMIT);
                }
                for key in ["maxDepth", "maxDiscoveryDepth"] {
                    if let Some(n) = int_member(opts, key, &optr, 0, 100, details) {
                        let n = usize::try_from(n).unwrap_or(0);
                        max_depth = Some(max_depth.map_or(n, |d: usize| d.min(n)));
                    }
                }
                include_paths =
                    string_list(opts, "includePaths", &optr, 100, 512, details).unwrap_or_default();
                exclude_paths =
                    string_list(opts, "excludePaths", &optr, 100, 512, details).unwrap_or_default();
                path_filters(&include_paths, &exclude_paths, &optr, details);
            }
        }
        Some(TargetKind::Crawl {
            url,
            limit,
            max_depth,
            include_paths,
            exclude_paths,
        })
    }

    fn parse_search(o: &Map<String, Value>, ptr: &str, details: &mut Details) -> Option<TargetKind> {
        let queries = string_list(o, "queries", ptr, MAX_QUERIES, MAX_QUERY_CHARS, details);
        let queries = match queries {
            Some(q) if !q.is_empty() => q,
            Some(_) | None => {
                if !details
                    .iter()
                    .any(|d| d.path.starts_with(&format!("{ptr}/queries")))
                {
                    bad(
                        details,
                        &format!("{ptr}/queries"),
                        "required",
                        "a search target needs 1 to 12 queries",
                    );
                }
                return None;
            }
        };
        let window = match o.get("searchWindow").filter(|v| !v.is_null()) {
            None => "24h".to_owned(),
            Some(Value::String(w)) if SEARCH_WINDOWS.contains(&w.as_str()) => w.clone(),
            Some(_) => {
                bad(
                    details,
                    &format!("{ptr}/searchWindow"),
                    "invalid",
                    format!("searchWindow takes one of {}", SEARCH_WINDOWS.join(", ")),
                );
                return None;
            }
        };
        let max_results = int_member(
            o,
            "maxResults",
            ptr,
            1,
            u64::try_from(MAX_MAX_RESULTS).unwrap_or(0),
            details,
        )
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(DEFAULT_MAX_RESULTS);
        let include_domains =
            string_list(o, "includeDomains", ptr, MAX_DOMAINS, 253, details).unwrap_or_default();
        let exclude_domains =
            string_list(o, "excludeDomains", ptr, MAX_DOMAINS, 253, details).unwrap_or_default();
        if !include_domains.is_empty() && !exclude_domains.is_empty() {
            bad(
                details,
                &format!("{ptr}/excludeDomains"),
                "invalid",
                "includeDomains and excludeDomains are mutually exclusive",
            );
        }
        Some(TargetKind::Search {
            queries,
            window,
            max_results,
            include_domains,
            exclude_domains,
        })
    }

    /// Rebuild a target from its stored form.
    ///
    /// # Errors
    /// A message naming the first violation when the stored value no longer validates.
    pub fn from_stored(v: &Value) -> Result<Self, String> {
        let mut details = Vec::new();
        Self::parse(v, "", &mut details).ok_or_else(|| {
            details.first().map_or_else(
                || "invalid target".to_owned(),
                |d| format!("{}: {}", d.path, d.message),
            )
        })
    }

    /// The target's type name (`scrape`, `crawl`, `search`).
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.kind {
            TargetKind::Scrape { .. } => "scrape",
            TargetKind::Crawl { .. } => "crawl",
            TargetKind::Search { .. } => "search",
        }
    }

    /// Upper bound of the pages one check of this target may scrape.
    #[must_use]
    pub fn max_pages(&self) -> usize {
        match &self.kind {
            TargetKind::Scrape { urls } => urls.len(),
            TargetKind::Crawl { limit, .. } => *limit,
            TargetKind::Search { max_results, .. } => *max_results,
        }
    }
}

fn parse_targets(v: &Value, details: &mut Details) -> Option<Vec<Target>> {
    let Some(items) = v.as_array() else {
        bad(details, "/targets", "invalid", "targets must be an array");
        return None;
    };
    if items.is_empty() || items.len() > MAX_TARGETS {
        bad(
            details,
            "/targets",
            "out_of_range",
            format!("targets takes 1 to {MAX_TARGETS} items"),
        );
        return None;
    }
    let before = details.len();
    let mut targets: Vec<Target> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        if let Some(t) = Target::parse(item, &format!("/targets/{i}"), details) {
            if targets.iter().any(|other| other.id == t.id) {
                bad(
                    details,
                    &format!("/targets/{i}/id"),
                    "invalid",
                    "target ids must be unique",
                );
            } else {
                targets.push(t);
            }
        }
    }
    (details.len() == before).then_some(targets)
}

fn parse_schedule(v: &Value, details: &mut Details) -> Option<Schedule> {
    let o = as_object(v, "/schedule", details)?;
    let mut spec = ScheduleSpec::default();
    for (key, slot) in [
        ("cron", &mut spec.cron),
        ("text", &mut spec.text),
        ("timezone", &mut spec.timezone),
    ] {
        match o.get(key).filter(|v| !v.is_null()) {
            None => {}
            Some(Value::String(s)) => *slot = Some(s.clone()),
            Some(_) => {
                bad(
                    details,
                    &format!("/schedule/{key}"),
                    "invalid",
                    format!("{key} must be a string"),
                );
                return None;
            }
        }
    }
    match Schedule::parse(&spec) {
        Ok(s) => Some(s),
        Err(e) => {
            let member = match &e {
                ScheduleError::TooFrequent { .. } if spec.cron.is_some() => "cron",
                ScheduleError::TooFrequent { .. } => "text",
                other => other.field(),
            };
            let path = if member.is_empty() {
                "/schedule".to_owned()
            } else {
                format!("/schedule/{member}")
            };
            bad(details, &path, e.code(), e.to_string());
            None
        }
    }
}

fn parse_webhook(v: Option<&Value>, details: &mut Details) -> Option<Option<JobWebhook>> {
    match JobWebhook::parse(v, "/webhook", &WEBHOOK_EVENTS) {
        Ok(hook) => Some(hook),
        Err(e) => {
            details.extend(e.details);
            None
        }
    }
}

fn parse_notification(v: &Value, details: &mut Details) -> Option<Value> {
    let o = as_object(v, "/notification", details)?;
    let mut out = Map::new();
    if let Some(email) = o.get("email").filter(|v| !v.is_null()) {
        let eptr = "/notification/email";
        let e = as_object(email, eptr, details)?;
        let mut norm = Map::new();
        for key in ["enabled", "includeDiffs"] {
            match e.get(key).filter(|v| !v.is_null()) {
                None => {}
                Some(Value::Bool(b)) => {
                    norm.insert(key.to_owned(), Value::Bool(*b));
                }
                Some(_) => bad(
                    details,
                    &format!("{eptr}/{key}"),
                    "invalid",
                    format!("{key} must be a boolean"),
                ),
            }
        }
        if let Some(recipients) = string_list(e, "recipients", eptr, MAX_RECIPIENTS, 320, details) {
            for (i, r) in recipients.iter().enumerate() {
                let ok = r.split_once('@').is_some_and(|(local, domain)| {
                    !local.is_empty() && domain.contains('.') && !r.chars().any(char::is_whitespace)
                });
                if !ok {
                    bad(
                        details,
                        &format!("{eptr}/recipients/{i}"),
                        "invalid",
                        "expected an e-mail address",
                    );
                }
            }
            norm.insert("recipients".to_owned(), json!(recipients));
        }
        out.insert("email".to_owned(), Value::Object(norm));
    }
    Some(Value::Object(out))
}

fn parse_goal(o: &Map<String, Value>, details: &mut Details) -> Option<Option<String>> {
    match o.get("goal") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(g)) => {
            if g.chars().count() > MAX_GOAL_CHARS {
                bad(
                    details,
                    "/goal",
                    "out_of_range",
                    format!("goal is longer than {MAX_GOAL_CHARS} characters"),
                );
                return None;
            }
            Some(Some(g.clone()).filter(|g| !g.trim().is_empty()))
        }
        Some(_) => {
            bad(details, "/goal", "invalid", "goal must be a string or null");
            None
        }
    }
}

fn parse_judge(o: &Map<String, Value>, details: &mut Details) -> Option<bool> {
    match o.get("judgeEnabled") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => {
            bad(
                details,
                "/judgeEnabled",
                "invalid",
                "judgeEnabled must be a boolean",
            );
            None
        }
    }
}

/// The goal / judging / search-target rules that span members.
fn check_goal(targets: &[Target], goal: Option<&str>, judge_explicit: Option<bool>, details: &mut Details) {
    let has_goal = goal.is_some_and(|g| !g.trim().is_empty());
    if judge_explicit == Some(true) && !has_goal {
        bad(
            details,
            "/judgeEnabled",
            "invalid",
            "judgeEnabled requires a non-empty goal",
        );
    }
    let searches = targets
        .iter()
        .any(|t| matches!(t.kind, TargetKind::Search { .. }));
    if searches && !has_goal && judge_explicit != Some(false) {
        bad(
            details,
            "/goal",
            "required",
            "a non-empty goal is required when a target is a search target, unless judgeEnabled is false",
        );
    }
}

fn required_text<'a>(o: &'a Map<String, Value>, key: &str, details: &mut Details) -> Option<&'a str> {
    match o.get(key).filter(|v| !v.is_null()) {
        Some(v) => v.as_str().or_else(|| {
            bad(
                details,
                &format!("/{key}"),
                "invalid",
                format!("{key} must be a string"),
            );
            None
        }),
        None => {
            bad(
                details,
                &format!("/{key}"),
                "required",
                format!("{key} is required"),
            );
            None
        }
    }
}

fn root_object(body: &Value) -> Result<&Map<String, Value>, HttpError> {
    body.as_object().ok_or_else(|| {
        HttpError::validation(vec![Detail::new("", "invalid", "the body must be a JSON object")])
    })
}

impl NewMonitor {
    /// Validate a `POST /monitor` body.
    ///
    /// # Errors
    /// `422 validation_failed` listing every violation with its JSON pointer.
    pub fn parse(body: &Value) -> Result<Self, HttpError> {
        let o = root_object(body)?;
        let mut details: Details = Vec::new();
        let name = required_text(o, "name", &mut details).map(str::to_owned);
        if let Some(n) = &name {
            if n.chars().count() > MAX_NAME_CHARS {
                bad(
                    &mut details,
                    "/name",
                    "out_of_range",
                    format!("name is longer than {MAX_NAME_CHARS} characters"),
                );
            }
        }
        let schedule = match o.get("schedule").filter(|v| !v.is_null()) {
            Some(v) => parse_schedule(v, &mut details),
            None => {
                bad(&mut details, "/schedule", "required", "schedule is required");
                None
            }
        };
        let targets = match o.get("targets").filter(|v| !v.is_null()) {
            Some(v) => parse_targets(v, &mut details),
            None => {
                bad(&mut details, "/targets", "required", "targets is required");
                None
            }
        };
        let retention_days = int_member(
            o,
            "retentionDays",
            "",
            1,
            u64::from(MAX_RETENTION_DAYS),
            &mut details,
        )
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS);
        let goal = parse_goal(o, &mut details).flatten();
        let judge_explicit = parse_judge(o, &mut details);
        if let Some(t) = &targets {
            check_goal(t, goal.as_deref(), judge_explicit, &mut details);
        }
        let webhook = parse_webhook(o.get("webhook"), &mut details).flatten();
        let notification = match o.get("notification").filter(|v| !v.is_null()) {
            Some(v) => parse_notification(v, &mut details),
            None => Some(json!({})),
        };
        match (name, schedule, targets, notification) {
            (Some(name), Some(schedule), Some(targets), Some(notification)) if details.is_empty() => {
                Ok(Self {
                    name,
                    schedule,
                    targets,
                    judge_explicit,
                    goal,
                    retention_days,
                    webhook,
                    notification,
                })
            }
            _ => Err(HttpError::validation(details)),
        }
    }
}

impl MonitorPatch {
    /// Validate a `PATCH /monitor/{id}` body. Cross-member rules (a search target needs a goal)
    /// are checked by the caller against the merged monitor.
    ///
    /// # Errors
    /// `422 validation_failed` listing every violation, including an empty patch.
    pub fn parse(body: &Value) -> Result<Self, HttpError> {
        let o = root_object(body)?;
        let mut details: Details = Vec::new();
        let mut patch = Self::default();
        if let Some(name) = string_member(o, "name", "", MAX_NAME_CHARS, &mut details) {
            patch.name = Some(name);
        }
        if let Some(v) = o.get("schedule").filter(|v| !v.is_null()) {
            patch.schedule = parse_schedule(v, &mut details);
        }
        if let Some(v) = o.get("targets").filter(|v| !v.is_null()) {
            patch.targets = parse_targets(v, &mut details);
        }
        if let Some(n) = int_member(
            o,
            "retentionDays",
            "",
            1,
            u64::from(MAX_RETENTION_DAYS),
            &mut details,
        ) {
            patch.retention_days = u32::try_from(n).ok();
        }
        patch.goal = parse_goal(o, &mut details);
        patch.judge_enabled = parse_judge(o, &mut details);
        if o.contains_key("webhook") {
            patch.webhook = parse_webhook(o.get("webhook"), &mut details);
        }
        if let Some(v) = o.get("notification").filter(|v| !v.is_null()) {
            patch.notification = parse_notification(v, &mut details);
        }
        match o.get("status") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => match MonitorStatus::parse(s) {
                Some(st) => patch.status = Some(st),
                None => bad(
                    &mut details,
                    "/status",
                    "invalid",
                    "status must be `active` or `paused`",
                ),
            },
            Some(_) => bad(
                &mut details,
                "/status",
                "invalid",
                "status must be `active` or `paused`",
            ),
        }
        let known = [
            "name",
            "schedule",
            "targets",
            "retentionDays",
            "goal",
            "judgeEnabled",
            "webhook",
            "notification",
            "status",
        ];
        if details.is_empty() && !known.iter().any(|k| o.contains_key(*k)) {
            bad(
                &mut details,
                "",
                "required",
                "include at least one field to update",
            );
        }
        if details.is_empty() {
            Ok(patch)
        } else {
            Err(HttpError::validation(details))
        }
    }

    /// The cross-member goal rules for the monitor the patch produces.
    ///
    /// # Errors
    /// `422 validation_failed` when the merged monitor has a search target and no goal while
    /// judging is on, or `judgeEnabled: true` without a goal.
    pub fn check_merged(
        targets: &[Target],
        goal: Option<&str>,
        judge_explicit: Option<bool>,
    ) -> Result<(), HttpError> {
        let mut details = Vec::new();
        check_goal(targets, goal, judge_explicit, &mut details);
        if details.is_empty() {
            Ok(())
        } else {
            Err(HttpError::validation(details))
        }
    }
}

/// Stored and rendered form of a monitor webhook: [`JobWebhook::to_value`] with an empty `events`
/// list (the default) spelled out as every monitor event.
#[must_use]
pub fn webhook_value(hook: &JobWebhook) -> Value {
    let mut v = hook.to_value();
    if hook.events.is_empty() {
        v["events"] = json!(WEBHOOK_EVENTS);
    }
    v
}
