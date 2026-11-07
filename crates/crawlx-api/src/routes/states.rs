//! `GET /v1/crawls/{id}/states`.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, next_link, paginate, ts, Params};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::repo::NewState;
use crawlx_core::{CrawlRunId, SessionId, StateClusterId};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn u64s_hex(v: &[u64]) -> String {
    v.iter().map(|x| format!("{x:016x}")).collect()
}

fn state_json(run: CrawlRunId, s: &NewState, role: &str) -> Value {
    let sig = &s.signature;
    let route_key = s.url.route_key();
    let manifest = s.artifacts.iter().find(|(k, _)| k == "manifest").map(|(_, a)| a);
    json!({
        "id": s.id,
        "sessionId": s.session,
        "role": role,
        "routeKey": format!("{}{}", route_key.origin, route_key.template),
        "routeKeyDigest": sig.route_key.to_hex(),
        "clusterId": s.cluster,
        "clusterSimilarity": s.cluster_similarity,
        "clusterIsNew": s.cluster_is_new,
        "signature": {
            "version": sig.version,
            "semanticAffordanceMinhash": u64s_hex(&sig.semantic_affordance_minhash),
            "domStructureSimhash": format!("{:016x}", sig.dom_structure_simhash),
            "visibleElementIdentityDigest": sig.visible_element_identity_digest.to_hex(),
            "frameTreeDigest": sig.frame_tree_digest.to_hex(),
            "networkOperationDigest": sig.network_operation_digest.to_hex(),
            "visualPhash": sig.visual_phash.map(|p| format!("{p:016x}")),
            "browserStorageDigest": sig.browser_storage_digest.map(|d| d.to_hex()),
        },
        "epoch": {
            "navigationSeq": s.epoch.navigation_seq,
            "documentSeq": s.epoch.document_seq,
            "mutationSeq": s.epoch.mutation_seq,
        },
        "masks": s.masks,
        "masksRef": Value::Null,
        "manifestRef": manifest.map(|a| format!("/v1/crawls/{run}/artifacts/{}", a.id)),
        "observedAt": ts(s.observed_at),
    })
}

/// `GET /v1/crawls/{id}/states`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for a bad `limit` or `cursor`.
pub async fn states(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let limit = params.limit(&state.settings)?;
    let cursor = params.cursor_key()?;
    let cluster: Option<StateClusterId> = params
        .get("clusterId")
        .map(|v| {
            v.parse()
                .map_err(|_| HttpError::malformed("clusterId must be a UUID"))
        })
        .transpose()?;
    let session: Option<SessionId> = params
        .get("sessionId")
        .map(|v| {
            v.parse()
                .map_err(|_| HttpError::malformed("sessionId must be a UUID"))
        })
        .transpose()?;
    let role = params.get("role");
    let route_key = params.get("routeKey");
    let roles: BTreeMap<SessionId, String> = state
        .repos
        .runs
        .list_sessions(run.id)
        .await?
        .into_iter()
        .map(|s| (s.id, s.role.0))
        .collect();
    let mut items: Vec<(String, Value)> = Vec::new();
    for s in state.repos.states.list_states(run.id).await? {
        let r = roles.get(&s.session).map_or("", String::as_str);
        let rk = s.url.route_key();
        let rk_string = format!("{}{}", rk.origin, rk.template);
        if cluster.is_some_and(|c| s.cluster != c)
            || session.is_some_and(|x| s.session != x)
            || role.is_some_and(|x| r != x)
            || route_key.is_some_and(|x| x != rk_string && x != s.signature.route_key.to_hex())
        {
            continue;
        }
        items.push((s.id.to_string(), state_json(run.id, &s, r)));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let total = items.len();
    let (page, next_key) = paginate(items, limit, cursor.as_deref());
    let path = format!("/v1/crawls/{}/states", run.id);
    let body =
        json!({ "data": page, "next": next_link(&path, &params, next_key.as_deref()), "total": total });
    Ok(json_response(StatusCode::OK, &body))
}
