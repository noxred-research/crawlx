//! Response side of the monitor API: `Monitor`, `MonitorCheck` and `MonitorCheckPage` objects
//! rendered from the stored rows.

use super::model::Target;
use crate::util::{ts, ts_opt};
use crawlx_scheduler::schedule::Schedule;
use crawlx_storage::{CheckPage, CheckRecord, CheckState, MonitorRecord};
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// Summary member that marks a scheduled run skipped because a check was still running.
pub const SKIPPED_OVERLAP: &str = "overlap";

/// Summary members shown to API clients (`MonitorSummary` plus crawlx's goal-judging additions).
const PUBLIC_SUMMARY: [&str; 8] = [
    "totalPages",
    "same",
    "changed",
    "new",
    "removed",
    "error",
    "relevant",
    "goalJudging",
];

fn count(summary: &Value, key: &str) -> u64 {
    summary.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// Whether the monitor's judge runs: judging is on and a goal exists.
#[must_use]
pub fn judging_requested(m: &MonitorRecord) -> bool {
    judge_enabled(m) && m.goal.as_deref().is_some_and(|g| !g.trim().is_empty())
}

/// The stored `judgeEnabled` flag (defaults to "a goal exists").
#[must_use]
pub fn judge_enabled(m: &MonitorRecord) -> bool {
    m.notification
        .get("judgeEnabled")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| m.goal.is_some())
}

/// The API status of a check: `running`, `completed`, `partial` (some pages or targets failed),
/// `failed`, or `skipped_overlap`. `queued` and `skipped_no_credits` never occur: checks start
/// immediately and crawlx has no credit limit.
#[must_use]
pub fn check_status(c: &CheckRecord) -> &'static str {
    match c.state {
        CheckState::Running => "running",
        CheckState::Failed => "failed",
        CheckState::Completed => {
            if c.summary.get("skipped").and_then(Value::as_str) == Some(SKIPPED_OVERLAP) {
                return "skipped_overlap";
            }
            let failed_target = c
                .summary
                .get("targetResults")
                .and_then(Value::as_array)
                .is_some_and(|ts| {
                    ts.iter()
                        .any(|t| t.get("status").and_then(Value::as_str) == Some("failed"))
                });
            if count(&c.summary, "error") > 0 || failed_target {
                "partial"
            } else {
                "completed"
            }
        }
    }
}

/// The public part of a check summary.
#[must_use]
pub fn public_summary(summary: &Value) -> Value {
    let mut out = Map::new();
    for key in PUBLIC_SUMMARY {
        if let Some(v) = summary.get(key) {
            out.insert(key.to_owned(), v.clone());
        }
    }
    if !out.contains_key("totalPages") {
        for key in ["totalPages", "same", "changed", "new", "removed", "error"] {
            out.insert(key.to_owned(), json!(0));
        }
    }
    Value::Object(out)
}

/// A `MonitorCheck` object.
#[must_use]
pub fn check_json(c: &CheckRecord) -> Value {
    let status = check_status(c);
    let skipped = status == "skipped_overlap";
    let running = c.state == CheckState::Running;
    let credits = c
        .summary
        .get("usage")
        .and_then(|u| u.get("credits"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let estimated = c.summary.get("estimatedCredits").and_then(Value::as_u64);
    json!({
        "id": c.id,
        "monitorId": c.monitor,
        "status": status,
        "trigger": c.trigger,
        "scheduledFor": c.summary.get("scheduledFor").cloned().unwrap_or(Value::Null),
        "startedAt": ts(c.started_at),
        "finishedAt": ts_opt(c.finished_at),
        "estimatedCredits": if skipped { Value::Null } else { json!(estimated) },
        "reservedCredits": if skipped { Value::Null } else { json!(estimated) },
        "actualCredits": if running { Value::Null } else { json!(credits) },
        "billingStatus": if running { "pending" } else { "settled" },
        "summary": public_summary(&c.summary),
        "targetResults": c.summary.get("targetResults").cloned().unwrap_or(Value::Null),
        "notificationStatus": c.summary.get("notificationStatus").cloned().unwrap_or(Value::Null),
        "error": if skipped { Value::Null } else { json!(c.error) },
        "createdAt": ts(c.started_at),
        "updatedAt": ts(c.finished_at.unwrap_or(c.started_at)),
    })
}

/// Id of a page row: derived from the check, target and URL so repeated reads agree.
#[must_use]
pub fn page_id(check: Uuid, target: &str, url: &str) -> Uuid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(check.as_bytes());
    hasher.update(target.as_bytes());
    hasher.update(&[0]);
    hasher.update(url.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

/// A `MonitorCheckPage` object.
#[must_use]
pub fn page_json(p: &CheckPage) -> Value {
    let mut out = json!({
        "id": page_id(p.check, &p.target_id, &p.url),
        "targetId": p.target_id,
        "url": p.url,
        "status": p.status,
        "previousScrapeId": Value::Null,
        "currentScrapeId": Value::Null,
        "statusCode": p.data.get("statusCode").cloned().unwrap_or(Value::Null),
        "error": p.data.get("error").cloned().unwrap_or(Value::Null),
        "metadata": p.data.get("metadata").cloned().unwrap_or(Value::Null),
        "judgment": p.data.get("judgment").cloned().unwrap_or(Value::Null),
        "createdAt": p.data.get("createdAt").cloned().unwrap_or(Value::Null),
    });
    for key in ["diff", "snapshot"] {
        if let Some(v) = p.data.get(key).filter(|v| !v.is_null()) {
            out[key] = v.clone();
        }
    }
    out
}

/// Upper bound of the credits one check may spend: every page it may scrape, one search charge
/// per 10 results and query, and one judge credit per page when judging is on.
#[must_use]
pub fn estimate_check_credits(targets: &[Target], judging: bool) -> u64 {
    let mut total: u64 = 0;
    for t in targets {
        let pages = u64::try_from(t.max_pages()).unwrap_or(u64::MAX);
        total = total.saturating_add(pages);
        if let super::model::TargetKind::Search { queries, .. } = &t.kind {
            let queries = u64::try_from(queries.len()).unwrap_or(u64::MAX);
            total = total.saturating_add(2_u64.saturating_mul(pages.div_ceil(10)).saturating_mul(queries));
        }
        if judging {
            total = total.saturating_add(pages);
        }
    }
    total
}

/// What the monitor object needs besides its own row.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct MonitorExtras {
    /// The running check, when one is.
    pub current_check: Option<Uuid>,
    /// Summary of the newest finished check.
    pub last_summary: Option<Value>,
}

/// A `Monitor` object.
#[must_use]
pub fn monitor_json(m: &MonitorRecord, extras: &MonitorExtras) -> Value {
    let targets: Vec<Target> = m
        .targets
        .as_array()
        .map(|items| items.iter().filter_map(|t| Target::from_stored(t).ok()).collect())
        .unwrap_or_default();
    let per_check = estimate_check_credits(&targets, judging_requested(m));
    let monthly = Schedule::from_stored(&m.cron, &m.timezone)
        .ok()
        .map(|s| per_check.saturating_mul(s.runs_per_30_days()));
    let email = m.notification.get("email").cloned();
    let notification = email.map_or_else(|| json!({}), |e| json!({ "email": e }));
    json!({
        "id": m.id,
        "name": m.name,
        "status": m.status.as_str(),
        "schedule": { "cron": m.cron, "timezone": m.timezone },
        "nextRunAt": ts_opt(m.next_run_at),
        "lastRunAt": ts_opt(m.last_run_at),
        "currentCheckId": extras.current_check,
        "targets": m.targets,
        "webhook": m.webhook,
        "notification": notification,
        "retentionDays": m.retention_days,
        "estimatedCreditsPerMonth": monthly,
        "lastCheckSummary": extras.last_summary.as_ref().map(public_summary),
        "goal": m.goal,
        "judgeEnabled": judge_enabled(m),
        "createdAt": ts(m.created_at),
        "updatedAt": ts(m.updated_at),
    })
}
