//! JSON resource builders: wire names are camelCase.

use crate::util::{ts, ts_opt};
use chrono::Duration as ChronoDuration;
use crawlx_core::config::{QueryPolicy, RetentionMode, TargetIsolation};
use crawlx_core::counters::{Counters, PlaneCounters};
use crawlx_core::identity::CoverageStatus;
use crawlx_core::repo::{CrawlRun, CrawlSession, RunMetadata};
use crawlx_core::{CrawlRunId, StoreError, TrustLane};
use crawlx_storage::CoverageRow;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

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

/// Independently observed fixture evidence, never inferred from discovered crawler keys.
///
/// The manifest selects actionable, supported controls for the run's launch profile.
/// Exercise labels must come from the fixture's own server-side evidence for this run.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FixtureGroundTruth {
    fixture: String,
    keys: BTreeSet<String>,
    exercised: BTreeSet<String>,
}

#[derive(Deserialize)]
struct FixtureTruthManifest {
    id: String,
    #[serde(default)]
    controls: Vec<FixtureTruthControl>,
}

#[derive(Deserialize)]
struct FixtureTruthControl {
    id: String,
    #[serde(default)]
    expected: Option<String>,
    #[serde(default)]
    mechanism: Option<String>,
    #[serde(default)]
    stealth_only: bool,
}

impl FixtureGroundTruth {
    /// Read fixture-manifest JSON and attach independently recorded trusted exercise labels.
    ///
    /// Duplicate labels count once; labels outside the eligible manifest set never count.
    /// Empty ground truth has recall `1.0`, matching the benchmark's empty-set convention.
    ///
    /// # Errors
    /// Returns a JSON error if required manifest fields are missing or have invalid types.
    pub fn from_manifest(
        manifest: &str,
        stealth: bool,
        exercised: impl IntoIterator<Item = String>,
    ) -> Result<Self, serde_json::Error> {
        let manifest: FixtureTruthManifest = serde_json::from_str(manifest)?;
        let keys = manifest
            .controls
            .into_iter()
            .filter(|control| {
                control
                    .expected
                    .as_deref()
                    .is_none_or(|value| value == "actionable")
            })
            .filter(|control| control.mechanism.as_deref() != Some("unsupported"))
            .filter(|control| stealth || !control.stealth_only)
            .map(|control| control.id)
            .collect();
        Ok(Self {
            fixture: manifest.id,
            keys,
            exercised: exercised.into_iter().collect(),
        })
    }

    /// Recall over the fixture's eligible manifest keys, not the discovered-key denominator.
    #[must_use]
    pub fn recall(&self) -> f64 {
        if self.keys.is_empty() {
            1.0
        } else {
            self.keys.intersection(&self.exercised).count() as f64 / self.keys.len() as f64
        }
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "fixture": self.fixture,
            "keys": self.keys.len(),
            "recall": self.recall(),
        })
    }
}

/// Trusted fixture-harness input configured by the server, not through crawl request JSON.
///
/// Implementations must bind observations to the requested run and its tenant-owned fixture.
/// Return `None` for ordinary runs. The API checks run ownership before reading this source.
#[async_trait::async_trait]
pub trait FixtureGroundTruthSource: Send + Sync {
    /// Load the manifest and independent trusted exercise evidence for one run.
    ///
    /// # Errors
    /// Returns a storage error when fixture evidence cannot be read.
    async fn ground_truth(&self, run: CrawlRunId) -> Result<Option<FixtureGroundTruth>, StoreError>;
}

pub(crate) fn coverage_exercised(row: &CoverageRow, lane: TrustLane, status: CoverageStatus) -> bool {
    row.exercised(lane) > 0 && status != CoverageStatus::NotObservable
}

/// `coverage` summary from the same reachability-filtered rows as the coverage endpoint.
#[must_use]
pub fn coverage_summary(rows: &[CoverageRow], ground_truth: Option<&FixtureGroundTruth>) -> Value {
    // Successful trusted evidence takes precedence over isolation in CoverageStatus.
    // Shared therefore gives the same trusted count without reading operational config.
    let trusted = rows
        .iter()
        .filter(|row| {
            coverage_exercised(
                row,
                TrustLane::TrustedUi,
                CoverageStatus::classify(
                    &row.key,
                    TargetIsolation::Shared,
                    row.trusted_exercised,
                    row.exercised(TrustLane::Diagnostic),
                ),
            )
        })
        .count();
    json!({
        "unit": "ActionContextKey",
        "discovered": rows.len(),
        "exercisedTrusted": trusted,
        "groundTruthRecall": ground_truth.map(FixtureGroundTruth::recall),
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
    coverage: Value,
    dead_deliveries: Option<u64>,
    warnings: &[Warning],
) -> Value {
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
    coverage: Value,
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
        "coverage": coverage,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn empty_fixture_truth_has_the_benchmark_empty_set_recall() {
        let truth =
            FixtureGroundTruth::from_manifest(r#"{"id":"empty"}"#, false, ["stray".to_owned()]).unwrap();
        assert_eq!(
            truth.json(),
            json!({"fixture": "empty", "keys": 0, "recall": 1.0})
        );
    }

    #[test]
    fn malformed_fixture_input_is_not_treated_as_missing_truth() {
        assert!(
            FixtureGroundTruth::from_manifest(r#"{"controls":[]}"#, false, Vec::<String>::new(),).is_err()
        );
    }
}
