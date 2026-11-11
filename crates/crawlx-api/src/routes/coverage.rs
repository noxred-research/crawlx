//! `GET /v1/crawls/{id}/coverage`.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::resources::coverage_exercised;
use crate::routes::crawls::load_run;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, ts, Params};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::TargetIsolation;
use crawlx_core::identity::CoverageStatus;
use crawlx_core::repo::SessionStatus;
use crawlx_core::TrustLane;
use crawlx_storage::CoverageRow;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyCounts {
    discovered: u64,
    exercised: u64,
    denied: u64,
    unknown: u64,
    pending: u64,
    diagnostic_only: u64,
    not_observable: u64,
    coarsened: u64,
}

impl KeyCounts {
    fn observe(&mut self, row: &CoverageRow, lane: TrustLane, isolation: TargetIsolation) -> bool {
        self.discovered += 1;
        self.coarsened += u64::from(row.key.is_coarsened());
        let status = CoverageStatus::classify(
            &row.key,
            isolation,
            row.trusted_exercised,
            row.exercised(TrustLane::Diagnostic),
        );
        // All partitions count keys, not attempts. In particular repeated unknown attempts
        // must not subtract unrelated pending keys from the denominator.
        let exercised = coverage_exercised(row, lane, status);
        if exercised {
            self.exercised += 1;
        } else if status == CoverageStatus::NotObservable {
            self.not_observable += 1;
        } else if lane == TrustLane::TrustedUi && status == CoverageStatus::DiagnosticOnly {
            self.diagnostic_only += 1;
        } else if row.unknown > 0 && row.succeeded() == 0 {
            self.unknown += 1;
        } else if row.is_denied_only() {
            self.denied += 1;
        } else {
            self.pending += 1;
        }
        exercised
    }

    fn add(&mut self, other: &Self) {
        self.discovered += other.discovered;
        self.exercised += other.exercised;
        self.denied += other.denied;
        self.unknown += other.unknown;
        self.pending += other.pending;
        self.diagnostic_only += other.diagnostic_only;
        self.not_observable += other.not_observable;
        self.coarsened += other.coarsened;
    }
}

#[derive(Default)]
struct RoleAcc {
    keys: KeyCounts,
    by_kind: BTreeMap<&'static str, u64>,
    by_resource: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupBy {
    ActionKind,
    ResourceContext,
    RouteTemplate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoleView<'a> {
    role: &'a str,
    denominator: &'static str,
    #[serde(flatten)]
    keys: &'a KeyCounts,
    by_action_kind: &'a BTreeMap<&'static str, u64>,
    by_resource_context: &'a BTreeMap<&'static str, u64>,
    sessions_planned: usize,
    sessions_completed: usize,
}

/// `GET /v1/crawls/{id}/coverage`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant.
pub async fn coverage(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let lane = match params.get("lane") {
        None | Some("trusted_ui") => TrustLane::TrustedUi,
        Some("diagnostic") => TrustLane::Diagnostic,
        Some(_) => return Err(HttpError::malformed("lane must be trusted_ui or diagnostic")),
    };
    let group_by = match params.get("groupBy") {
        None => None,
        Some("actionKind") => Some(GroupBy::ActionKind),
        Some("resourceContext") => Some(GroupBy::ResourceContext),
        Some("routeTemplate") => Some(GroupBy::RouteTemplate),
        Some(_) => {
            return Err(HttpError::malformed(
                "groupBy must be actionKind, resourceContext or routeTemplate",
            ))
        }
    };
    let role_filter = params.get("role");
    // TrustedCorpus applies both lane and before-state reachability predicates in storage.
    let rows = state.repos.api.coverage(run.id).await?;
    let sessions = state.repos.runs.list_sessions(run.id).await?;
    let isolation = run.config.target_isolation;
    let mut roles: BTreeMap<&str, RoleAcc> = BTreeMap::new();
    let mut groups: BTreeMap<&str, KeyCounts> = BTreeMap::new();
    let mut total = KeyCounts::default();
    for row in &rows {
        let role = row.key.principal.0.as_str();
        if role_filter.is_some_and(|r| r != role) {
            continue;
        }
        let mut one = KeyCounts::default();
        let exercised = one.observe(row, lane, isolation);
        total.add(&one);
        let acc = roles.entry(role).or_default();
        acc.keys.add(&one);
        if exercised {
            *acc.by_kind.entry(row.key.action_kind.as_str()).or_default() += 1;
            *acc.by_resource
                .entry(row.key.resource_context.as_str())
                .or_default() += 1;
        }
        if let Some(g) = group_by {
            let key = match g {
                GroupBy::ActionKind => row.key.action_kind.as_str(),
                GroupBy::ResourceContext => row.key.resource_context.as_str(),
                GroupBy::RouteTemplate => row.key.route_template.0.as_str(),
            };
            groups.entry(key).or_default().add(&one);
        }
    }
    // Roles with sessions but no ledger rows still appear.
    for s in &sessions {
        if role_filter.is_none_or(|r| r == s.role.0) {
            roles.entry(s.role.0.as_str()).or_default();
        }
    }
    let role_items: Vec<_> = roles
        .iter()
        .map(|(role, acc)| RoleView {
            role,
            denominator: "discovered",
            keys: &acc.keys,
            by_action_kind: &acc.by_kind,
            by_resource_context: &acc.by_resource,
            sessions_planned: sessions.iter().filter(|s| s.role.0 == *role).count(),
            sessions_completed: sessions
                .iter()
                .filter(|s| s.role.0 == *role && s.status == SessionStatus::Completed)
                .count(),
        })
        .collect();
    // Fixture evidence describes the whole trusted run; do not relabel it as a role-filtered
    // or diagnostic-lane measurement when the fixture supplied no such denominator.
    let ground_truth = if lane == TrustLane::TrustedUi && role_filter.is_none() {
        state.load_fixture_ground_truth(run.id).await?
    } else {
        None
    };
    let mut body = json!({
        "unit": "ActionContextKey",
        "denominator": "discovered",
        "asOf": ts(state.clock.now()),
        "lane": lane,
        "targetIsolation": isolation,
        "crossPrincipalAttribution": run.config.cross_principal_attribution,
        "roles": role_items,
        "total": total,
        "groundTruth": ground_truth.as_ref().map(crate::resources::FixtureGroundTruth::json),
    });
    if let (Some(_), Some(obj)) = (group_by, body.as_object_mut()) {
        obj.insert("groups".to_owned(), json!(groups));
    }
    Ok(json_response(StatusCode::OK, &body))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn run_summary_and_endpoint_exclude_trusted_actions_from_unreachable_states() {
        let cluster = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        let rows: Vec<_> = (0..19)
            .map(|index| CoverageRow {
                key: crawlx_storage::testkit::proposal("member", cluster, index).key,
                trusted_exercised: u32::from(index < 17),
                trusted_unreachable: u32::from(index >= 17),
                diagnostic_exercised: 0,
                failures: 0,
                denied: 0,
                unknown: 0,
                first_seen: crawlx_core::Timestamp::default(),
                last_exercised: None,
            })
            .collect();
        let mut counts = KeyCounts::default();
        for row in &rows {
            counts.observe(row, TrustLane::TrustedUi, TargetIsolation::PerRoleReplica);
        }
        let summary = crate::resources::coverage_summary(&rows, None);
        assert_eq!(summary["discovered"], counts.discovered);
        assert_eq!(summary["exercisedTrusted"], counts.exercised);
        assert_eq!(counts.discovered, 19);
        assert_eq!(counts.exercised, 17);
        assert_eq!(counts.diagnostic_only, 2);
        assert_eq!(
            rows.iter()
                .filter(|row| row.trusted_exercised + row.trusted_unreachable > 0)
                .count(),
            19
        );
    }

    #[test]
    fn repeated_unknown_attempts_count_one_key_and_do_not_hide_pending_work() {
        let key = crawlx_storage::testkit::proposal("member", crawlx_core::StateClusterId::new(), 1).key;
        let mut row = CoverageRow {
            key,
            trusted_exercised: 0,
            trusted_unreachable: 0,
            diagnostic_exercised: 0,
            failures: 0,
            denied: 0,
            unknown: 7,
            first_seen: chrono::Utc::now(),
            last_exercised: None,
        };
        let mut counts = KeyCounts::default();
        counts.observe(&row, TrustLane::TrustedUi, TargetIsolation::Shared);
        row.key.input_class = crawlx_core::InputClass::new("email", "valid");
        row.unknown = 0;
        counts.observe(&row, TrustLane::TrustedUi, TargetIsolation::Shared);
        assert_eq!(counts.discovered, 2);
        assert_eq!(counts.unknown, 1);
        assert_eq!(counts.pending, 1);
    }
}
