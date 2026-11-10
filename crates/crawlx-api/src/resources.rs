//! JSON resource builders: wire names are camelCase.

use crate::util::{ts, ts_opt};
use chrono::Duration as ChronoDuration;
use crawlx_core::config::{QueryPolicy, RetentionMode};
use crawlx_core::counters::{Counters, PlaneCounters};
use crawlx_core::repo::{CrawlRun, CrawlSession, LedgerRow, LedgerSummary, RunMetadata};
use serde::Serialize;
use serde_json::{json, Value};

/// `warnings[]` entry.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct Warning {
    /// Stable machine-readable warning code.
    pub code: String,
    /// JSON Pointer to the request or config field the warning is about.
    pub path: String,
    /// Human-readable explanation of what was changed or ignored.
    pub message: String,
}

impl Warning {
    /// A warning `code` about the field at `path`.
    #[must_use]
    pub fn new(code: &str, path: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            path: path.to_owned(),
            message: message.into(),
        }
    }
}

/// Warnings that follow from the stored configuration alone.
#[must_use]
pub fn config_warnings(run: &CrawlRun) -> Vec<Warning> {
    metadata_warnings(run.config.scope.query_policy)
}

/// Warnings that depend only on privacy-safe policy metadata.
pub(crate) fn metadata_warnings(query_policy: QueryPolicy) -> Vec<Warning> {
    let mut w = Vec::new();
    if query_policy == QueryPolicy::StripAll {
        w.push(Warning::new(
            "query_strip_merges_resources",
            "/scope/queryPolicy",
            "strip_all removes every query parameter and can merge distinct resources",
        ));
    }
    w
}

fn plane_json(c: &Counters) -> Value {
    json!({
        "discovered": c.discovered,
        "admitted": c.admitted,
        "deduplicated": c.deduplicated,
        "policyBlocked": c.policy_blocked,
        "robotsBlocked": c.robots_blocked,
        "attempted": c.attempted,
        "succeeded": c.succeeded,
        "failed": c.failed,
        "abandoned": c.abandoned,
        "unreachable": c.unreachable,
        "unknownOutcome": c.unknown_outcome,
    })
}

/// `counters` object.
#[must_use]
pub fn counters_json(c: &PlaneCounters) -> Value {
    json!({
        "urls": plane_json(&c.urls),
        "interactions": plane_json(&c.interactions),
        "states": plane_json(&c.states),
    })
}

/// `coverage` summary of the run resource.
#[must_use]
pub fn coverage_summary(rows: &[LedgerRow]) -> Value {
    let trusted = rows.iter().filter(|r| r.trusted_exercised > 0).count();
    json!({
        "unit": "ActionContextKey",
        "discovered": rows.len(),
        "exercisedTrusted": trusted,
        "groundTruthRecall": Value::Null,
    })
}

fn session_json(s: &CrawlSession) -> Value {
    json!({
        "id": s.id,
        "role": s.role.0,
        "runIndex": s.run_index,
        "scheduleSlot": s.schedule_slot,
        "status": s.status,
        "browserBuild": s.browser.as_ref().map(|b| format!("{} / {}", b.chromium_version, b.cdp_revision)),
    })
}

/// `expiresAt`: `finished_at + retention.days`, known once the run is terminal.
#[must_use]
pub fn expires_at(run: &CrawlRun) -> Option<crawlx_core::Timestamp> {
    let finished = run.finished_at?;
    let days = if run.config.retention.mode == RetentionMode::Zdr {
        0
    } else {
        i64::from(run.config.retention.days)
    };
    Some(finished + ChronoDuration::days(days))
}

/// Content retention deadline without access to transient operational configuration.
pub(crate) fn metadata_expires_at(run: &RunMetadata) -> Option<crawlx_core::Timestamp> {
    let days = if run.retention.mode == RetentionMode::Zdr {
        0
    } else {
        i64::from(run.retention.days)
    };
    Some(run.finished_at? + ChronoDuration::days(days))
}

/// The compat status `expiresAt`: [`metadata_expires_at`] once the run finished, until then the
/// deadline the run would have if it ended now (`created_at + retention.days`). The deadline moves
/// to `finished_at + retention.days` when the run ends.
pub(crate) fn status_expires_at(run: &RunMetadata) -> crawlx_core::Timestamp {
    metadata_expires_at(run).unwrap_or_else(|| {
        let days = if run.retention.mode == RetentionMode::Zdr {
            0
        } else {
            i64::from(run.retention.days)
        };
        run.created_at + ChronoDuration::days(days)
    })
}

/// The crawl resource returned by `POST /v1/crawls` and `GET /v1/crawls/{id}`.
#[must_use]
pub fn run_json(
    run: &CrawlRun,
    sessions: &[CrawlSession],
    ledger: &[LedgerRow],
    dead_deliveries: Option<u64>,
    warnings: &[Warning],
) -> Value {
    let mut coverage = LedgerSummary::default();
    for row in ledger {
        coverage.discovered = coverage.discovered.saturating_add(1);
        if row.trusted_exercised > 0 {
            coverage.exercised_trusted = coverage.exercised_trusted.saturating_add(1);
        }
    }
    run_metadata_json(
        &RunMetadata::from(run),
        sessions,
        coverage,
        dead_deliveries,
        warnings,
    )
}

/// The crawl resource from privacy-safe metadata, including after ZDR delivery expiry.
#[must_use]
pub fn run_metadata_json(
    run: &RunMetadata,
    sessions: &[CrawlSession],
    coverage: LedgerSummary,
    dead_deliveries: Option<u64>,
    warnings: &[Warning],
) -> Value {
    let id = run.id;
    let deadline = run
        .started_at
        .map(|s| s + ChronoDuration::seconds(i64::from(run.duration_seconds)));
    let mut v = json!({
        "id": id,
        "status": run.status,
        "terminalReason": run.terminal_reason,
        "mode": run.mode,
        "seed": run.seed.0,
        "safetyProfile": run.safety_profile,
        "createdAt": ts(run.created_at),
        "startedAt": ts_opt(run.started_at),
        "finishedAt": ts_opt(run.finished_at),
        "deadlineAt": ts_opt(deadline),
        "expiresAt": ts_opt(metadata_expires_at(run)),
        "counters": counters_json(&run.counters),
        "sessions": sessions.iter().map(session_json).collect::<Vec<_>>(),
        "coverage": {
            "unit": "ActionContextKey",
            "discovered": coverage.discovered,
            "exercisedTrusted": coverage.exercised_trusted,
            "groundTruthRecall": Value::Null,
        },
        "versions": {
            "policy": run.policy_version,
            "identity": "V1",
            "stateAlgo": crawlx_core::state::StateSignature::VERSION,
            "queryClassifier": 1,
            "crawlx": env!("CARGO_PKG_VERSION"),
        },
        "warnings": warnings,
        "links": {
            "pages": format!("/v1/crawls/{id}/pages"),
            "events": format!("/v1/crawls/{id}/events"),
            "coverage": format!("/v1/crawls/{id}/coverage"),
        },
    });
    if let (Some(n), Some(obj)) = (dead_deliveries, v.as_object_mut()) {
        obj.insert("webhook".to_owned(), json!({ "deadDeliveries": n }));
    }
    v
}
