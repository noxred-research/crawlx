//! `POST /v1/replays`. A replay is a `crawl_runs` row with
//! `run_kind = 'replay'`; the worker executes it. Admission publishes the run, sessions,
//! and resolved action/transition/state specification in one storage transaction, so a
//! lease never dispatches a replay as an ordinary crawl. Admission refuses a source run whose
//! sessions ran on another Chromium build than this deployment's pin
//! unless `allowBuildMismatch` is set; the override is recorded in the replay spec.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::idempotency::{idempotent, Reply};
use crate::routes::crawls::{create_replay_run, load_run, serde_detail};
use crate::state::{AppState, DeploymentBuild};
use crate::store::{Scope, TransitionFilter, TransitionRecord};
use crate::util::{idempotency_key, JsonBody};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::SafetyProfile;
use crawlx_core::repo::CrawlSession;
use crawlx_core::{AuthorizationRecordId, CrawlRunId, StateId, TransitionId};
use crawlx_policy::EgressPolicy;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PathSpec {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to_transition_id: Option<TransitionId>,
    #[serde(default)]
    transition_ids: Option<Vec<TransitionId>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Target {
    base_url: url::Url,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReplaySafety {
    #[serde(default)]
    profile: Option<SafetyProfile>,
    #[serde(default)]
    authorization_record_ref: Option<AuthorizationRecordId>,
}

#[derive(Deserialize, Clone, Copy, Default, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum ReplayMode {
    #[default]
    Verify,
    Reproduce,
}

const fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReplayRequest {
    source_run_id: CrawlRunId,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    path: PathSpec,
    #[serde(default)]
    target: Option<Target>,
    #[serde(default)]
    mode: ReplayMode,
    #[serde(default = "yes")]
    stop_on_divergence: bool,
    #[serde(default)]
    allow_build_mismatch: bool,
    #[serde(default)]
    safety: Option<ReplaySafety>,
}

/// Shortest recorded chain of transitions from a root state to `target` (inclusive).
fn chain_to(all: &[TransitionRecord], target: TransitionId) -> Option<Vec<TransitionId>> {
    let t = all.iter().find(|t| t.id == target)?;
    let afters: BTreeSet<StateId> = all.iter().filter_map(|x| x.after).collect();
    let mut adj: BTreeMap<StateId, Vec<usize>> = BTreeMap::new();
    for (i, x) in all.iter().enumerate() {
        adj.entry(x.before).or_default().push(i);
    }
    let roots: BTreeSet<StateId> = all
        .iter()
        .map(|x| x.before)
        .filter(|b| !afters.contains(b))
        .collect();
    // parent[state] = (previous state, transition index used to reach it)
    let mut parent: BTreeMap<StateId, Option<(StateId, usize)>> = roots.iter().map(|r| (*r, None)).collect();
    let mut queue: VecDeque<StateId> = roots.iter().copied().collect();
    while let Some(s) = queue.pop_front() {
        if s == t.before {
            break;
        }
        for &i in adj.get(&s).map_or(&[][..], Vec::as_slice) {
            if let Some(next) = all[i].after {
                if let std::collections::btree_map::Entry::Vacant(e) = parent.entry(next) {
                    e.insert(Some((s, i)));
                    queue.push_back(next);
                }
            }
        }
    }
    if !parent.contains_key(&t.before) {
        return None;
    }
    let mut chain = vec![target];
    let mut cur = t.before;
    while let Some(Some((prev, i))) = parent.get(&cur) {
        chain.push(all[*i].id);
        cur = *prev;
    }
    chain.reverse();
    Some(chain)
}

/// Builds recorded on the sessions of `role` that differ from the deployment's, as
/// `<version> / <cdp revision>` labels; a session without a recorded build contributes
/// `"unrecorded"` because there is nothing to verify it against.
fn mismatched_builds<'a>(
    sessions: impl IntoIterator<Item = &'a CrawlSession>,
    role: &str,
    build: &DeploymentBuild,
) -> BTreeSet<String> {
    sessions
        .into_iter()
        .filter(|s| s.role.0 == role)
        .filter_map(|s| match &s.browser {
            Some(b) if build.matches(b) => None,
            Some(b) => Some(format!("{} / {}", b.chromium_version, b.cdp_revision)),
            None => Some("unrecorded".to_owned()),
        })
        .collect()
}

/// `POST /v1/replays`.
///
/// # Errors
/// `403 scope_missing` without `replays:write`, `404 not_found` for an unknown source run, `422`
/// when the replay request is invalid (including `build_mismatch` when the source sessions ran
/// on another browser build and `allowBuildMismatch` is not set), and the idempotency errors of
/// [`crate::idempotency::idempotent`].
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::ReplaysWrite)?;
    let key = idempotency_key(&headers, false)?;
    idempotent(&state, &principal, key, "POST", "/v1/replays", &body, || async {
        let req: ReplayRequest = serde_json::from_value(body.clone())
            .map_err(|e| HttpError::validation(vec![serde_detail(&e)]))?;
        let source = load_run(&state, &principal, &req.source_run_id.to_string()).await?;
        let mut details: Vec<Detail> = Vec::new();

        let sessions = state.repos.runs.list_sessions(source.id).await?;
        let roles: BTreeSet<String> = sessions.iter().map(|s| s.role.0.clone()).collect();
        let role = match &req.role {
            Some(r) if roles.contains(r) => r.clone(),
            Some(r) => {
                details.push(Detail::new(
                    "/role",
                    "out_of_range",
                    format!("the source run has no role {r:?}"),
                ));
                r.clone()
            }
            None => sessions
                .first()
                .map_or_else(|| "anonymous".to_owned(), |s| s.role.0.clone()),
        };

        if req.path.from.as_deref().is_some_and(|f| f != "seed") {
            details.push(Detail::new("/path/from", "unknown_enum", "from must be \"seed\""));
        }
        let all = state
            .repos
            .api
            .transitions_list(
                source.id,
                &TransitionFilter {
                    role: Some(role.clone()),
                    ..TransitionFilter::default()
                },
            )
            .await?;
        let mut resolved: Vec<TransitionId> = Vec::new();
        match (&req.path.transition_ids, req.path.to_transition_id) {
            (Some(_), Some(_)) => details.push(Detail::new(
                "/path",
                "mode_conflict",
                "give either toTransitionId or transitionIds, not both",
            )),
            (Some(ids), None) => {
                let known: BTreeMap<TransitionId, &TransitionRecord> =
                    all.iter().map(|t| (t.id, t)).collect();
                if ids.is_empty() {
                    details.push(Detail::new(
                        "/path/transitionIds",
                        "required",
                        "transitionIds must not be empty",
                    ));
                }
                let mut prev_after: Option<StateId> = None;
                for (i, id) in ids.iter().enumerate() {
                    match known.get(id) {
                        None => details.push(Detail::new(
                            format!("/path/transitionIds/{i}"),
                            "out_of_range",
                            "unknown transition for this run and role",
                        )),
                        Some(t) => {
                            if prev_after.is_some_and(|a| a != t.before) {
                                details.push(Detail::new(
                                    format!("/path/transitionIds/{i}"),
                                    "out_of_range",
                                    "transition does not start where the previous one ended",
                                ));
                            }
                            prev_after = t.after;
                            resolved.push(*id);
                        }
                    }
                }
            }
            (None, Some(to)) => match chain_to(&all, to) {
                Some(chain) => resolved = chain,
                None => details.push(Detail::new(
                    "/path/toTransitionId",
                    "out_of_range",
                    "no recorded chain of transitions leads to this transition",
                )),
            },
            (None, None) => details.push(Detail::new(
                "/path",
                "required",
                "toTransitionId or transitionIds is required",
            )),
        }

        let profile = req
            .safety
            .as_ref()
            .and_then(|s| s.profile)
            .unwrap_or(source.config.safety.profile);
        if profile > source.config.safety.profile {
            details.push(Detail::new(
                "/safety/profile",
                "profile_conflict",
                "a replay may not exceed the source run's safety profile",
            ));
        }
        let base = req.target.as_ref().map(|t| t.base_url.clone());
        if let Some(b) = &base {
            if let Err(e) = EgressPolicy::new(source.config.safety.allow_private_networks).check_url(b) {
                details.push(Detail::new("/target/baseUrl", "url_denied", e.to_string()));
            }
        }
        let mismatched = mismatched_builds(&sessions, &role, &state.build);
        if !mismatched.is_empty() && !req.allow_build_mismatch {
            let recorded: Vec<&str> = mismatched.iter().map(String::as_str).collect();
            details.push(Detail::new(
                "/allowBuildMismatch",
                "build_mismatch",
                format!(
                    "the source sessions ran on browser build {} but this deployment runs {}; set allowBuildMismatch to replay anyway",
                    recorded.join(", "),
                    state.build.label()
                ),
            ));
        }
        if !details.is_empty() {
            return Err(HttpError::validation(details));
        }

        let mut cfg = state.repos.runs.get_for_execution(source.id).await?.config;
        if let Some(b) = &base {
            cfg.seed_url = b.clone();
        }
        cfg.roles = cfg
            .effective_roles()
            .into_iter()
            .filter(|r| r.name == role)
            .collect();
        cfg.runs_per_role = 1;
        cfg.seed = Some(source.seed.0);
        cfg.safety.profile = profile;
        if let Some(rec) = req.safety.as_ref().and_then(|s| s.authorization_record_ref) {
            cfg.safety.authorization_record_ref = Some(rec);
        }
        let transitions: BTreeMap<TransitionId, &TransitionRecord> =
            all.iter().map(|transition| (transition.id, transition)).collect();
        let (action_ids, after_state_ids): (Vec<_>, Vec<_>) = resolved
            .iter()
            .map(|id| {
                transitions
                    .get(id)
                    .map(|transition| (transition.action.id, transition.after))
                    .ok_or_else(HttpError::internal)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();
        let spec = json!({
            "sourceRunId": source.id,
            "role": role,
            "mode": match req.mode { ReplayMode::Verify => "verify", ReplayMode::Reproduce => "reproduce" },
            "transitionIds": resolved,
            "actionIds": action_ids,
            "afterStateIds": after_state_ids,
            "identityVersion": source.config.crawl.identity.version.decision_version(),
            // CrawlRun exposes no historical state version; this storage contract writes VERSION.
            "stateAlgoVersion": crawlx_core::state::StateSignature::VERSION,
            "target": { "baseUrl": base },
            "stopOnDivergence": req.stop_on_divergence,
            "allowBuildMismatch": req.allow_build_mismatch,
            "buildMismatchOverridden": !mismatched.is_empty(),
        });
        let created = create_replay_run(&state, &principal, cfg, &spec).await?;
        let id = created.run.id;
        Ok(Reply::new(
            StatusCode::ACCEPTED,
            json!({
                "id": id,
                "status": created.run.status,
                "links": { "run": format!("/v1/crawls/{id}"), "events": format!("/v1/crawls/{id}/events") },
            }),
        )
        .for_run(id)
        .at(format!("/v1/crawls/{id}")))
    })
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::store::ActionSummary;
    use crawlx_core::counters::ActionStatus;
    use crawlx_core::{ActionId, SessionId, TrustLane};

    fn tr(before: StateId, after: Option<StateId>) -> TransitionRecord {
        let action = ActionId::new();
        TransitionRecord {
            id: TransitionId::new(),
            session: SessionId::new(),
            role: "anonymous".to_owned(),
            before,
            after,
            network_epoch: None,
            lane: TrustLane::TrustedUi,
            settle: None,
            action: ActionSummary {
                id: action,
                seq: 1,
                kind: "click".to_owned(),
                status: ActionStatus::Succeeded,
                lane: Some(TrustLane::TrustedUi),
                fidelity: None,
                strategy: "t".to_owned(),
                strategy_version: 1,
                context_id: String::new(),
                risk_class: None,
                safety_verdict: None,
            },
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn shortest_chain_from_root() {
        let (a, b, c, d) = (StateId::new(), StateId::new(), StateId::new(), StateId::new());
        let ab = tr(a, Some(b));
        let bc = tr(b, Some(c));
        let ad = tr(a, Some(d));
        let dc = tr(d, Some(c));
        let cd2 = tr(c, Some(StateId::new()));
        let all = vec![ab.clone(), bc.clone(), ad.clone(), dc.clone(), cd2.clone()];
        let chain = chain_to(&all, cd2.id).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[2], cd2.id);
        assert!(chain[0] == ab.id || chain[0] == ad.id);
        assert_eq!(chain_to(&all, ab.id).unwrap(), vec![ab.id]);
        assert!(chain_to(&all, TransitionId::new()).is_none());
    }

    #[test]
    fn unreachable_target_has_no_chain() {
        let (a, b) = (StateId::new(), StateId::new());
        // a cycle without a root: neither state is a root, so nothing is reachable
        let ab = tr(a, Some(b));
        let ba = tr(b, Some(a));
        assert!(chain_to(&[ab.clone(), ba], ab.id).is_none());
    }
}

#[cfg(test)]
mod build_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_storage::testkit;

    fn session(role: &str, browser: Option<crawlx_core::observation::BrowserBuildInfo>) -> CrawlSession {
        let mut s = testkit::sessions(CrawlRunId::new(), 1, 1).remove(0);
        s.role = crawlx_core::PrincipalId(role.to_owned());
        s.browser = browser;
        s
    }

    #[test]
    fn only_the_replayed_role_is_checked_and_unrecorded_counts_as_a_mismatch() {
        let build = DeploymentBuild {
            chromium_version: "155.0.8059.84".to_owned(),
            cdp_revision: "1.3".to_owned(),
        };
        let same = testkit::browser_build("Chrome/155.0.8059.84", "1.3");
        let other = testkit::browser_build("154.0.8037.97", "1.3");
        let other_cdp = testkit::browser_build("155.0.8059.84", "1.2");
        let sessions = vec![
            session("member", Some(same.clone())),
            session("member", Some(other)),
            session("member", None),
            session("anonymous", Some(other_cdp)),
        ];
        assert_eq!(
            mismatched_builds(&sessions, "member", &build),
            ["154.0.8037.97 / 1.3", "unrecorded"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert_eq!(
            mismatched_builds(&sessions, "anonymous", &build),
            BTreeSet::from(["155.0.8059.84 / 1.2".to_owned()])
        );
        assert!(mismatched_builds(&[session("member", Some(same))], "member", &build).is_empty());
        let empty = DeploymentBuild {
            chromium_version: String::new(),
            cdp_revision: String::new(),
        };
        assert!(
            !empty.matches(&testkit::browser_build("", "")),
            "an unresolved pin matches nothing"
        );
    }
}
