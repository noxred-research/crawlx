//! `POST /v1/crawls`, `GET/DELETE /v1/crawls/{id}`, `POST /v1/crawls/{id}:pause|:resume|:cancel`.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::idempotency::{idempotent, Reply};
use crate::resources::{config_warnings, run_json, Warning};
use crate::routes::authorizations::used_subject;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{idempotency_key, json_response, ts, JsonBody};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::CreateCrawl;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{CrawlRun, SessionStatus};
use crawlx_core::CrawlRunId;
use crawlx_policy::{AdmissionError, TenantLimits};
use crawlx_scheduler::RunPlanner;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::Rng as _;
use serde_json::{json, Value};
use std::future::Future;

/// A freshly persisted run.
pub(crate) struct Created {
    pub run: CrawlRun,
    pub warnings: Vec<Warning>,
}

/// Parse and unknown-field-check a native create body. Returns the request and the
/// violations found so far (the caller adds admission violations before failing).
pub(crate) fn parse_create(body: &Value) -> Result<(CreateCrawl, Vec<Detail>), HttpError> {
    let crawl: CreateCrawl = match serde_json::from_value(body.clone()) {
        Ok(c) => c,
        Err(e) => return Err(HttpError::validation(vec![serde_detail(&e)])),
    };
    let mut details = Vec::new();
    for path in [
        "/cachePrincipal",
        "/scrape/options/cachePrincipal",
        "/scrape/options/cacheHeaderIdentity",
        "/scrape/options/cacheExecutionContext",
    ] {
        if body.pointer(path).is_some() {
            details.push(Detail::new(
                path,
                "server_assigned",
                "cache authority and execution identities are assigned by the server",
            ));
        }
    }
    match serde_json::to_value(&crawl) {
        Ok(canon) => unknown_fields(body, &canon, "", &mut details),
        Err(e) => {
            tracing::error!(error = %e, "could not re-serialize a parsed create request");
            return Err(HttpError::internal());
        }
    }
    Ok((crawl, details))
}

pub(crate) fn serde_detail(e: &serde_json::Error) -> Detail {
    let msg = e.to_string();
    let field = msg.split('`').nth(1).map(str::to_owned);
    if msg.starts_with("missing field") {
        Detail::new(format!("/{}", field.unwrap_or_default()), "required", msg)
    } else if msg.starts_with("unknown field") {
        Detail::new(format!("/{}", field.unwrap_or_default()), "unknown_field", msg)
    } else if msg.starts_with("unknown variant") {
        Detail::new("/", "unknown_enum", msg)
    } else {
        Detail::new("/", "out_of_range", msg)
    }
}

/// Keys present in `input` that the typed request does not have (`unknown_field`).
fn unknown_fields(input: &Value, canon: &Value, path: &str, out: &mut Vec<Detail>) {
    match (input, canon) {
        (Value::Object(i), Value::Object(c)) => {
            for (k, v) in i {
                let p = format!("{path}/{}", k.replace('~', "~0").replace('/', "~1"));
                match c.get(k) {
                    Some(cv) => unknown_fields(v, cv, &p, out),
                    None => out.push(Detail::new(p, "unknown_field", format!("unknown field `{k}`"))),
                }
            }
        }
        (Value::Array(i), Value::Array(c)) => {
            for (n, (iv, cv)) in i.iter().zip(c.iter()).enumerate() {
                unknown_fields(iv, cv, &format!("{path}/{n}"), out);
            }
        }
        _ => {}
    }
}

fn admission_detail(e: &AdmissionError) -> Detail {
    Detail::new(e.path.clone(), e.code, e.message.clone())
}

/// Admit, persist and register a run (shared by native create and the compat facade).
pub(crate) async fn create_run(
    state: &AppState,
    principal: &Principal,
    crawl: CreateCrawl,
    details: Vec<Detail>,
    warnings: Vec<Warning>,
) -> ApiResult<Created> {
    create_run_as(state, principal, crawl, details, warnings, CrawlRunId::new()).await
}

/// As [`create_run`], creating the run under the already chosen `id` (the one an idempotency
/// claim announced, see [`crate::idempotency::idempotent_job`]).
pub(crate) async fn create_run_as(
    state: &AppState,
    principal: &Principal,
    crawl: CreateCrawl,
    details: Vec<Detail>,
    warnings: Vec<Warning>,
    id: CrawlRunId,
) -> ApiResult<Created> {
    create_admitted_run(state, principal, crawl, details, warnings, id, None).await
}

/// Admit a replay using the crawl policy, then publish its sessions and specification atomically.
pub(crate) async fn create_replay_run(
    state: &AppState,
    principal: &Principal,
    crawl: CreateCrawl,
    spec: &Value,
) -> ApiResult<Created> {
    create_admitted_run(
        state,
        principal,
        crawl,
        Vec::new(),
        Vec::new(),
        CrawlRunId::new(),
        Some(spec),
    )
    .await
}

fn create_admitted_run<'a>(
    state: &'a AppState,
    principal: &'a Principal,
    crawl: CreateCrawl,
    details: Vec<Detail>,
    warnings: Vec<Warning>,
    id: CrawlRunId,
    replay_spec: Option<&'a Value>,
) -> impl Future<Output = ApiResult<Created>> + Send + 'a {
    // Admission retains configuration and storage state; do not copy it into every route future.
    Box::pin(create_admitted_run_inner(
        state,
        principal,
        crawl,
        details,
        warnings,
        id,
        replay_spec,
    ))
}

/// A crawl request that passed every native admission check, with what admission produced.
pub(crate) struct Admission {
    pub crawl: CreateCrawl,
    pub admitted: crawlx_policy::Admitted,
    pub warnings: Vec<Warning>,
}

/// `crawl` without the fields only the server assigns, so the result is a valid request body
/// again (`parse_create` refuses those fields).
pub(crate) fn client_form(mut crawl: CreateCrawl) -> CreateCrawl {
    crawl.cache_principal = None;
    if let Some(scrape) = &mut crawl.scrape {
        scrape.options.cache_principal = None;
        scrape.options.cache_header_identity = None;
        scrape.options.cache_execution_context = None;
    }
    crawl
}

/// Run the whole native admission (references, quota, validation policy, authorization record,
/// URL and scope policy, worker capability, retention) without persisting anything. Creation
/// and the dry-run endpoints share this one path, so a previewed configuration is admitted by
/// exactly the code that would admit it at start.
pub(crate) async fn admit_crawl(
    state: &AppState,
    principal: &Principal,
    mut crawl: CreateCrawl,
    mut details: Vec<Detail>,
    mut warnings: Vec<Warning>,
) -> ApiResult<Admission> {
    crate::routes::login_flows::validate_references(state, principal, &crawl).await?;
    crawl.cache_principal = Some(principal.key_id);
    if let Some(scrape) = &mut crawl.scrape {
        // API callers cannot select another cache principal through native request JSON.
        scrape.options.cache_principal = Some(principal.key_id);
        scrape.options.cache_header_identity = None;
        scrape.options.cache_execution_context = None;
    }
    let api = &state.repos.api;
    let active = api.active_run_count(principal.tenant).await?;
    if active >= state.settings.max_active_runs {
        return Err(HttpError::quota_exceeded(state.settings.max_active_runs));
    }
    if let Some(policy) = &crawl.acquisition {
        if let Err(error) = crawlx_extract::validation::compile_policy(&policy.validation) {
            details.push(Detail::new(
                "/acquisition/validation",
                "invalid_validation_policy",
                error.to_string(),
            ));
        }
    }
    if crawl.seed.is_none() {
        // Server-drawn seed: any value in 0..2^63, from the OS entropy source.
        let mut raw = [0u8; 8];
        UnwrapErr(SysRng).fill_bytes(&mut raw);
        crawl.seed = Some(u64::from_le_bytes(raw) >> 1);
    }
    let record = match crawl.safety.authorization_record_ref {
        Some(id) => api.authorization_get(principal.tenant, id).await?,
        None => None,
    };
    let limits = TenantLimits {
        tenant_id: Some(principal.tenant),
        ..state.settings.tenant_limits.clone()
    };
    let admitted = match state.policy.admit(&mut crawl, &limits, record.as_ref()) {
        Ok(a) => Some(a),
        Err(errs) => {
            details.extend(errs.iter().map(admission_detail));
            None
        }
    };
    for (path, content) in [
        ("/extract/content", crawl.extract.content.as_ref()),
        (
            "/scrape/options/contentPolicy",
            crawl
                .scrape
                .as_ref()
                .and_then(|job| job.options.content_policy.as_ref()),
        ),
    ]
    .into_iter()
    .filter_map(|(path, policy)| policy.map(|policy| (path, policy)))
    {
        if let Err(error) = crawlx_extract::validate_content_policy(content) {
            details.push(Detail::new(path, "invalid_content_policy", error.to_string()));
        }
    }
    if !details.is_empty() {
        return Err(HttpError::validation(details));
    }
    let Some(admitted) = admitted else {
        return Err(HttpError::internal());
    };
    let data = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(&crawl)?;
    if crawl.acquisition.is_some() || !data.destinations.is_empty() || data.language_bundle.is_some() {
        let backend_ids = crawl
            .acquisition
            .as_ref()
            .map_or(&[][..], |policy| policy.backend_ids.as_slice());
        let worker = state
            .repos
            .worker_registry
            .eligible_data_worker(backend_ids, &data, super::capabilities::WORKER_MAX_AGE)
            .await?;
        if worker.is_none() {
            return Err(HttpError::backend_unavailable(
                "acquisition_capability_unavailable",
                "no fresh worker reports every required acquisition, delivery and language bundle capability",
            ));
        }
    }
    if crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr && !state.zdr.is_enabled() {
        return Err(HttpError::validation(vec![Detail::new(
            "/retention/mode",
            "zdr_unavailable",
            "zero-data-retention requires a configured shared volatile delivery backend",
        )]));
    }
    for c in &admitted.clamps {
        warnings.push(Warning::new(
            "limit_clamped",
            c.path,
            format!("clamped from {} to plan maximum {}", c.requested, c.applied),
        ));
    }
    Ok(Admission {
        crawl,
        admitted,
        warnings,
    })
}

async fn create_admitted_run_inner(
    state: &AppState,
    principal: &Principal,
    crawl: CreateCrawl,
    details: Vec<Detail>,
    warnings: Vec<Warning>,
    id: CrawlRunId,
    replay_spec: Option<&Value>,
) -> ApiResult<Created> {
    let Admission {
        crawl,
        admitted,
        mut warnings,
    } = admit_crawl(state, principal, crawl, details, warnings).await?;
    let api = &state.repos.api;
    let run = CrawlRun {
        id,
        tenant: principal.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config: crawl,
        config_digest: admitted.config_digest,
        policy_version: state.settings.policy_version,
        counters: crawlx_core::counters::PlaneCounters::default(),
        created_at: state.clock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    warnings.extend(config_warnings(&run));
    let sessions = RunPlanner::sessions(id, &run.config);
    if let Some(spec) = replay_spec {
        state.repos.runs.create_replay(&run, &sessions, spec).await?;
    } else {
        state.repos.runs.create(&run, None).await?;
        state.repos.runs.create_sessions(&sessions).await?;
    }
    // the append-only accept log the durability audit compares `crawl_runs` against.
    api.audit_append(
        principal.tenant,
        Some(id),
        &principal.actor(),
        "crawl.accepted",
        json!({ "configDigest": run.config_digest.to_string() }),
    )
    .await?;
    if let Some(binding) = &admitted.authorization {
        // the run is bound to the exact record body it was admitted under
        api.authorization_bind_run(id, binding.body_digest).await?;
        api.audit_append(
            principal.tenant,
            Some(id),
            &principal.actor(),
            "authorization.used",
            used_subject(binding.record_id, binding.version, binding.body_digest, id),
        )
        .await?;
    }
    api.run_created(principal.tenant, id).await?;
    if run.config.output.webhook.is_some() {
        api.webhook_watch(id).await?;
    }
    Metrics::global().counter(names::JOBS_ACCEPTED).inc();
    Ok(Created { run, warnings })
}

/// Load a run owned by the caller's tenant (`404` for absent or foreign runs).
pub(crate) async fn load_run(state: &AppState, principal: &Principal, id: &str) -> ApiResult<CrawlRun> {
    let id: CrawlRunId = id.parse().map_err(|_| HttpError::not_found("crawl"))?;
    let run = state.repos.runs.get(id).await.map_err(|e| match e {
        crawlx_core::StoreError::NotFound { .. } => HttpError::not_found("crawl"),
        other => other.into(),
    })?;
    if run.tenant == principal.tenant {
        Ok(run)
    } else {
        Err(HttpError::not_found("crawl"))
    }
}

/// Load only privacy-safe run metadata; ZDR content expiry never makes status inaccessible.
pub(crate) async fn load_run_metadata(
    state: &AppState,
    principal: &Principal,
    id: &str,
) -> ApiResult<crawlx_core::repo::RunMetadata> {
    let id: CrawlRunId = id.parse().map_err(|_| HttpError::not_found("crawl"))?;
    let run = state.repos.runs.get_metadata(id).await.map_err(|e| match e {
        crawlx_core::StoreError::NotFound { .. } => HttpError::not_found("crawl"),
        other => other.into(),
    })?;
    if run.tenant != principal.tenant {
        return Err(HttpError::not_found("crawl"));
    }
    Ok(run)
}

async fn metadata_resource(state: &AppState, run: &crawlx_core::repo::RunMetadata) -> ApiResult<Value> {
    let sessions = state.repos.runs.list_sessions(run.id).await?;
    let rows = state.repos.api.coverage(run.id).await?;
    let ground_truth = state.load_fixture_ground_truth(run.id).await?;
    let coverage = crate::resources::coverage_summary(&rows, ground_truth.as_ref());
    let dead = if run.webhook_configured {
        Some(state.repos.api.webhook_dead_count(run.id).await?)
    } else {
        None
    };
    let warnings = crate::resources::metadata_warnings(run.query_policy);
    Ok(crate::resources::run_metadata_json(
        run, &sessions, coverage, dead, &warnings,
    ))
}

/// The full crawl resource for `run`.
pub(crate) async fn run_resource(state: &AppState, run: &CrawlRun, warnings: &[Warning]) -> ApiResult<Value> {
    let sessions = state.repos.runs.list_sessions(run.id).await?;
    let rows = state.repos.api.coverage(run.id).await?;
    let ground_truth = state.load_fixture_ground_truth(run.id).await?;
    let coverage = crate::resources::coverage_summary(&rows, ground_truth.as_ref());
    let dead = if run.config.output.webhook.is_some() {
        Some(state.repos.api.webhook_dead_count(run.id).await?)
    } else {
        None
    };
    let mut all = config_warnings(run);
    for w in warnings {
        if !all.contains(w) {
            all.push(w.clone());
        }
    }
    Ok(run_json(run, &sessions, coverage, dead, &all))
}

/// `POST /v1/crawls`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write` (also `crawls:read` for recorded-artifact login
/// plans), `400 malformed_request` for a non-JSON body, `422` when validation or admission
/// fails, `404` for absent/foreign source artifacts, `410` for expired sources, `429
/// quota_exceeded` above the active-run quota, and the errors of [`crate::idempotency::idempotent`].
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let key = idempotency_key(&headers, false)?;
    idempotent(&state, &principal, key, "POST", "/v1/crawls", &body, || async {
        let (crawl, details) = parse_create(&body)?;
        crate::scrape_service::validate_native_extraction(&crawl.extract)?;
        let created = create_run(&state, &principal, crawl, details, Vec::new()).await?;
        let resource = run_resource(&state, &created.run, &created.warnings).await?;
        let id = created.run.id;
        Ok(Reply::new(StatusCode::ACCEPTED, resource)
            .for_run(id)
            .at(format!("/v1/crawls/{id}")))
    })
    .await
}

/// `GET /v1/crawls/{id}`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant.
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    if id.contains(':') {
        return Err(HttpError::not_found("crawl"));
    }
    let run = load_run_metadata(&state, &principal, &id).await?;
    let body = metadata_resource(&state, &run).await?;
    Ok(json_response(StatusCode::OK, &body))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
    Pause,
    Resume,
    Cancel,
}

/// `POST /v1/crawls/{id}:pause|:resume|:cancel`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for an unknown verb, `409 invalid_state` when the verb
/// is not valid in the run's status.
pub async fn verb(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id_action): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let Some((id, action)) = id_action.rsplit_once(':') else {
        return Err(HttpError::method_not_allowed());
    };
    let verb = match action {
        "pause" => Verb::Pause,
        "resume" => Verb::Resume,
        "cancel" => Verb::Cancel,
        _ => return Err(HttpError::not_found("action")),
    };
    let run = load_run(&state, &principal, id).await?;
    let (status, run) = apply_verb(&state, run, verb).await?;
    let body = run_resource(&state, &run, &[]).await?;
    Ok(json_response(status, &body))
}

pub(crate) async fn apply_verb(
    state: &AppState,
    run: CrawlRun,
    verb: Verb,
) -> ApiResult<(StatusCode, CrawlRun)> {
    let runs = &state.repos.runs;
    let now = ts(state.clock.now());
    match (verb, run.status) {
        (Verb::Pause, RunStatus::Paused) | (Verb::Cancel, RunStatus::Cancelled) => Ok((StatusCode::OK, run)),
        (Verb::Pause, RunStatus::Running) => {
            runs.set_status(run.id, RunStatus::Paused, None).await?;
            state
                .repos
                .events
                .append(run.id, "paused", json!({ "at": now }))
                .await?;
            Ok((StatusCode::ACCEPTED, runs.get(run.id).await?))
        }
        (Verb::Resume, RunStatus::Paused) => {
            runs.set_status(run.id, RunStatus::Running, None).await?;
            state
                .repos
                .events
                .append(run.id, "resumed", json!({ "at": now }))
                .await?;
            Ok((StatusCode::ACCEPTED, runs.get(run.id).await?))
        }
        (Verb::Cancel, RunStatus::Queued | RunStatus::Running | RunStatus::Paused) => {
            runs.set_status(run.id, RunStatus::Cancelled, Some(TerminalReason::Cancelled))
                .await?;
            for s in runs.list_sessions(run.id).await? {
                if s.status == SessionStatus::Pending {
                    if let Err(e) = runs.set_session_status(s.id, SessionStatus::Cancelled).await {
                        tracing::debug!(error = %e, session = %s.id, "session already moved on");
                    }
                }
            }
            let after = runs.get(run.id).await?;
            let rows = state.repos.api.coverage(run.id).await?;
            let ground_truth = state.load_fixture_ground_truth(run.id).await?;
            let coverage = crate::resources::coverage_summary(&rows, ground_truth.as_ref());
            state
                .repos
                .events
                .append(
                    run.id,
                    "status",
                    json!({ "status": "cancelled", "terminalReason": "cancelled" }),
                )
                .await?;
            state
                .repos
                .events
                .append(
                    run.id,
                    "completed",
                    json!({
                        "status": "cancelled",
                        "terminalReason": "cancelled",
                        "counters": crate::resources::counters_json(&after.counters),
                        "coverage": coverage,
                    }),
                )
                .await?;
            Ok((StatusCode::ACCEPTED, after))
        }
        (Verb::Pause, s) => Err(HttpError::invalid_state(format!(
            "only a running crawl can be paused (status is {})",
            s.as_str()
        ))),
        (Verb::Resume, s) => Err(HttpError::invalid_state(format!(
            "only a paused crawl can be resumed (status is {})",
            s.as_str()
        ))),
        (Verb::Cancel, s) => Err(HttpError::invalid_state(format!(
            "a {} crawl cannot be cancelled",
            s.as_str()
        ))),
    }
}

/// `DELETE /v1/crawls/{id}`: erase a terminal run and everything it owns.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `409 invalid_state` while the run is not terminal.
pub async fn erase(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    if id.contains(':') {
        return Err(HttpError::not_found("crawl"));
    }
    let run = load_run_metadata(&state, &principal, &id).await?;
    if !run.status.is_terminal() {
        return Err(HttpError::invalid_state(format!(
            "only terminal crawls can be erased (status is {})",
            run.status.as_str()
        )));
    }
    state
        .repos
        .api
        .audit_append(
            principal.tenant,
            Some(run.id),
            &principal.actor(),
            "run.erase_requested",
            json!({ "run_id": run.id }),
        )
        .await?;
    // records the AI endpoints keep for the run (extractions, triage, findings, summaries)
    for kind in crawlx_storage::intel::RUN_SETTING_KINDS {
        state
            .repos
            .intel
            .setting_delete(run.tenant, &crawlx_storage::intel::run_setting_key(kind, run.id))
            .await?;
    }
    let rows = state.repos.eraser.erase(run.id).await?;
    let buffered = if state.zdr.is_enabled() {
        state.zdr.purge_run(run.tenant, run.id).await?
    } else {
        0
    };
    tracing::info!(run = %run.id, rows, buffered, "run erased");
    Ok(json_response(
        StatusCode::ACCEPTED,
        &json!({ "id": run.id, "status": "erased", "rowsDeleted": rows }),
    ))
}
