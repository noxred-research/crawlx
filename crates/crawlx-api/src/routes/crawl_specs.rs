//! `/v1/crawl-specs`: dry-run validation, natural-language compilation, operator approval and
//! creation of a crawl from an approved spec.
//!
//! Compiling never touches the target. The compiled configuration goes through the same
//! admission code a real `POST /v1/crawls` uses ([`admit_crawl`]); creating from a spec needs a
//! single-use approval token bound to the spec digest and re-runs admission, so an
//! authorization that expired or was revoked, or a policy that changed, between preview and
//! start refuses the creation.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::govern::{self, ModelCall};
use crate::intel::proposals::{self, Kind};
use crate::intel::spec_compile::{self, CrawlIntentV1};
use crate::routes::crawls::{admit_crawl, client_form, create_run, parse_create, run_resource};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, ts, JsonBody};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::CreateCrawl;
use crawlx_core::hash::Digest;
use crawlx_core::ids::AuthorizationRecordId;
use crawlx_model::policy::{ModelInputEnvelopeV1, OperatorTask, Purpose, RetentionClass};
use crawlx_model::provenance::Instruction;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::Rng as _;
use serde_json::{json, Map, Value};

const INSTRUCTION: Instruction = Instruction::from_static(
    "Convert the operator's engagement description into a crawl intent. Use only the fields of the \
     schema. Put anything the schema cannot express into `unsupported` instead of dropping it. State \
     every prohibition the operator gives in `forbid`.",
);

fn object<'a>(body: &'a Value, allowed: &[&str]) -> ApiResult<&'a Map<String, Value>> {
    let map = body
        .as_object()
        .ok_or_else(|| HttpError::malformed("the body must be a JSON object"))?;
    let unknown: Vec<Detail> = map
        .keys()
        .filter(|k| !allowed.contains(&k.as_str()))
        .map(|k| Detail::new(format!("/{k}"), "unknown_field", format!("unknown field `{k}`")))
        .collect();
    if unknown.is_empty() {
        Ok(map)
    } else {
        Err(HttpError::validation(unknown))
    }
}

fn policy_digest(state: &AppState) -> String {
    let doc = json!({
        "admissionPolicyVersion": state.settings.policy_version,
        "ai": state.ai.governor.as_ref().map(|g| g.policy_digest().to_owned()),
    });
    Digest::of("crawlx.spec_policy.v1", proposals::canonical(&doc).as_bytes()).to_hex()
}

/// `POST /v1/crawl-specs/validate`: the body is a native create body; nothing is created.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`; the validation and admission errors of
/// `POST /v1/crawls`.
pub async fn validate(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let (crawl, details) = parse_create(&body)?;
    crate::scrape_service::validate_native_extraction(&crawl.extract)?;
    let admission = admit_crawl(&state, &principal, crawl, details, Vec::new()).await?;
    let config =
        serde_json::to_value(client_form(admission.crawl.clone())).map_err(|_| HttpError::internal())?;
    let reply = json!({
        "valid": true,
        "configDigest": admission.admitted.config_digest.to_string(),
        "authorizationDigest": admission.admitted.authorization.as_ref().map(|a| a.body_digest.to_string()),
        "policyDigest": policy_digest(&state),
        "config": config,
        "warnings": admission.warnings,
        "targetIo": false,
    });
    Ok(json_response(StatusCode::OK, &reply))
}

fn server_seed() -> u64 {
    let mut raw = [0u8; 8];
    UnwrapErr(SysRng).fill_bytes(&mut raw);
    u64::from_le_bytes(raw) >> 1
}

async fn intent_from_model(
    state: &AppState,
    principal: &Principal,
    prompt: &str,
) -> ApiResult<(CrawlIntentV1, Value)> {
    let task = OperatorTask::new(prompt).map_err(|e| govern::http_error(&e))?;
    let envelope =
        ModelInputEnvelopeV1::new(INSTRUCTION, spec_compile::PROMPT_VERSION, Some(task), Vec::new())
            .map_err(|e| govern::http_error(&e))?;
    let schema = spec_compile::intent_schema();
    let scope = govern::hourly_scope(state, "spec", principal);
    let call = ModelCall {
        scope: &scope,
        run: None,
        purpose: Purpose::CrawlSpec,
        retention: RetentionClass::Standard,
        schema: Some(&schema),
        schema_version: spec_compile::SCHEMA_VERSION,
    };
    let output = govern::call(state, principal, &call, &envelope)
        .await
        .map_err(|e| govern::http_error(&e))?;
    let intent = spec_compile::parse_intent(&output.value).map_err(|_| {
        HttpError::compat(
            StatusCode::BAD_GATEWAY,
            "ai_invalid_output",
            "the model reply is not a valid crawl intent",
        )
    })?;
    let record = serde_json::to_value(&output.record).map_err(|_| HttpError::internal())?;
    Ok((intent, record))
}

fn spec_error(error: &spec_compile::SpecError) -> HttpError {
    use spec_compile::SpecError;
    match error {
        SpecError::Invalid(message) => {
            HttpError::validation(vec![Detail::new("/intent", "invalid_intent", message.clone())])
        }
        SpecError::Conflict(message) => {
            HttpError::validation(vec![Detail::new("/intent", "conflicting_intent", *message)])
        }
    }
}

/// `POST /v1/crawl-specs/compile`.
///
/// # Errors
/// `403 scope_missing`, `422` for an invalid body, intent, conflict or a configuration that
/// fails native admission, `403`/`503` from the model-egress policy when `prompt` is used.
pub async fn compile(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let map = object(&body, &["prompt", "intent", "baseConfig", "authorizationId"])?;
    let base_value = map.get("baseConfig").ok_or_else(|| {
        HttpError::validation(vec![Detail::new(
            "/baseConfig",
            "required",
            "baseConfig is required",
        )])
    })?;
    let (mut base, details) = parse_create(base_value)?;
    if let Some(id) = map.get("authorizationId") {
        let id: AuthorizationRecordId = id.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
            HttpError::validation(vec![Detail::new(
                "/authorizationId",
                "invalid",
                "authorizationId must be a record id",
            )])
        })?;
        match base.safety.authorization_record_ref {
            Some(existing) if existing != id => {
                return Err(HttpError::validation(vec![Detail::new(
                    "/authorizationId",
                    "conflict",
                    "authorizationId differs from baseConfig.safety.authorizationRecordRef",
                )]));
            }
            _ => base.safety.authorization_record_ref = Some(id),
        }
    }
    let (intent, model_record, source) = match (map.get("prompt"), map.get("intent")) {
        (Some(Value::String(prompt)), None) => {
            let (intent, record) = intent_from_model(&state, &principal, prompt).await?;
            (intent, Some(record), "model")
        }
        (None, Some(intent)) => (
            spec_compile::parse_intent(intent).map_err(|e| spec_error(&e))?,
            None,
            "operator",
        ),
        _ => {
            return Err(HttpError::validation(vec![Detail::new(
                "/",
                "one_of_required",
                "give exactly one of `prompt` (a string) and `intent` (an object)",
            )]));
        }
    };
    let compiled = spec_compile::compile(&base, &intent).map_err(|e| spec_error(&e))?;
    let mut config = compiled.config;
    if config.seed.is_none() {
        // a fixed seed makes the digest of the previewed configuration the one that runs
        config.seed = Some(server_seed());
    }
    let before = serde_json::to_value(&base).map_err(|_| HttpError::internal())?;
    let after = serde_json::to_value(&config).map_err(|_| HttpError::internal())?;
    let admission = admit_crawl(&state, &principal, config, details, Vec::new()).await?;
    let stored_config =
        serde_json::to_value(client_form(admission.crawl.clone())).map_err(|_| HttpError::internal())?;
    let mut warnings: Vec<Value> = compiled
        .warnings
        .iter()
        .map(spec_compile::Note::to_value)
        .collect();
    warnings.extend(
        admission
            .warnings
            .iter()
            .filter_map(|w| serde_json::to_value(w).ok()),
    );
    let mut required = vec![
        "approvals:decide (an operator key other than the proposing key)",
        "crawls:write",
    ];
    if admission.admitted.authorization.is_some() {
        required.push("authorization record valid at creation");
    }
    let spec = json!({
        "config": stored_config,
        "configDigest": admission.admitted.config_digest.to_string(),
        "authorizationDigest": admission.admitted.authorization.as_ref().map(|a| a.body_digest.to_string()),
        "policyDigest": policy_digest(&state),
        "intent": {
            "source": source,
            "goals": intent.goals.iter().map(|g| format!("{g:?}")).collect::<Vec<_>>(),
            "forbid": intent.forbid.iter().map(|g| format!("{g:?}")).collect::<Vec<_>>(),
        },
        "diff": spec_compile::diff(&before, &after),
        "warnings": warnings,
        "unsupportedIntents": compiled.unsupported,
        "requiredCapabilities": required,
        "model": model_record,
    });
    let record = proposals::create(&state, &principal, Kind::Spec, spec.clone()).await?;
    let mut reply = proposals::view(&state, &record);
    if let (Some(out), Some(extra)) = (reply.as_object_mut(), spec.as_object()) {
        out.insert("specId".to_owned(), json!(record.id));
        out.insert(
            "expiresAt".to_owned(),
            json!(ts(chrono_from_ms(record.expires_at_ms))),
        );
        out.extend(extra.clone());
        out.insert("targetIo".to_owned(), json!(false));
    }
    Ok(json_response(StatusCode::CREATED, &reply))
}

fn chrono_from_ms(ms: i64) -> crawlx_core::Timestamp {
    crawlx_core::Timestamp::from_timestamp_millis(ms).unwrap_or_default()
}

/// `GET /v1/crawl-specs/{specId}`.
///
/// # Errors
/// `403 scope_missing`, `404` for an unknown spec or another tenant's.
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let record = proposals::load(&state, principal.tenant, Kind::Spec, &id).await?;
    let mut reply = proposals::view(&state, &record);
    if let (Some(out), Some(body)) = (reply.as_object_mut(), record.body.as_object()) {
        out.insert("specId".to_owned(), json!(record.id));
        out.extend(body.clone());
    }
    Ok(json_response(StatusCode::OK, &reply))
}

/// `POST /v1/crawl-specs/{specId}/approve`.
///
/// # Errors
/// `403 scope_missing` without `approvals:decide`, `403 self_approval_refused`, `404`, `409`
/// when not awaiting approval, `410` when expired.
pub async fn approve(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::ApprovalsDecide)?;
    let record = proposals::load(&state, principal.tenant, Kind::Spec, &id).await?;
    let (record, token) = proposals::approve(&state, &principal, Kind::Spec, record).await?;
    audit(&state, &principal, "crawl_spec.approved", &record).await;
    let expires = record.approval.as_ref().map_or(0, |a| a.expires_at_ms);
    let reply = json!({
        "specId": record.id,
        "digest": record.digest,
        "approvalToken": token,
        "expiresAt": ts(chrono_from_ms(expires)),
        "note": "the token is shown once, is bound to this digest and is spent by the first create",
    });
    Ok(json_response(StatusCode::OK, &reply))
}

async fn audit(state: &AppState, principal: &Principal, event: &str, record: &proposals::Record) {
    let subject = json!({"specId": record.id, "digest": record.digest});
    if let Err(error) = state
        .repos
        .api
        .audit_append(principal.tenant, None, &principal.actor(), event, subject)
        .await
    {
        tracing::warn!(%error, "spec audit row could not be written");
    }
}

/// `POST /v1/crawl-specs/{specId}/create`: body `{approvalToken}`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `403 approval_token_invalid`, `404`, `409` when
/// not approved or when the policy or authorization changed since the preview, `410` when
/// expired, and the admission errors of `POST /v1/crawls`.
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let map = object(&body, &["approvalToken"])?;
    let token = map.get("approvalToken").and_then(Value::as_str).ok_or_else(|| {
        HttpError::validation(vec![Detail::new(
            "/approvalToken",
            "required",
            "approvalToken is required",
        )])
    })?;
    let record = proposals::load(&state, principal.tenant, Kind::Spec, &id).await?;
    let stale = |what: &str| {
        HttpError::compat(
            StatusCode::CONFLICT,
            "spec_stale",
            format!("{what} changed since the spec was compiled; compile it again"),
        )
    };
    let config_value = record
        .body
        .get("config")
        .cloned()
        .ok_or_else(HttpError::internal)?;
    let (crawl, details) = parse_create(&config_value)?;
    let admission = admit_crawl(&state, &principal, crawl, details, Vec::new()).await?;
    let stored = |key: &str| record.body.get(key).and_then(Value::as_str).map(str::to_owned);
    if stored("policyDigest").as_deref() != Some(policy_digest(&state).as_str()) {
        return Err(stale("the admission or model policy"));
    }
    let digest_now = admission
        .admitted
        .authorization
        .as_ref()
        .map(|a| a.body_digest.to_string());
    if stored("authorizationDigest") != digest_now {
        return Err(stale("the authorization record"));
    }
    let record = proposals::consume(&state, &principal, Kind::Spec, record, token).await?;
    let crawl: CreateCrawl = admission.crawl;
    match create_run(&state, &principal, crawl, Vec::new(), Vec::new()).await {
        Ok(created) => {
            let mut done = record.clone();
            done.execution = Some(json!({"runId": created.run.id}));
            proposals::update(&state, principal.tenant, Kind::Spec, &done).await?;
            audit(&state, &principal, "crawl_spec.consumed", &done).await;
            let resource = run_resource(&state, &created.run, &created.warnings).await?;
            Ok(json_response(StatusCode::ACCEPTED, &resource))
        }
        Err(error) => {
            // nothing started: the approval stays spendable until it expires
            let mut restored = record;
            restored.status = proposals::Status::Approved;
            proposals::update(&state, principal.tenant, Kind::Spec, &restored).await?;
            Err(error)
        }
    }
}
