//! Evidence-backed AI endpoints over a run's retained data:
//! `POST|GET /v1/crawls/{id}/{extractions,triage,summaries}`, operator-reviewed findings
//! (`PUT|GET /v1/crawls/{id}/findings`) and `GET /v1/capabilities/ai`.
//!
//! Everything here is passive: sources are retained artifacts, traffic and counters; nothing
//! enqueues a request or touches the target. Rules and accumulators produce the facts; a model
//! may add generated, unverified prose that deterministic validators then check. Derived
//! records of zero-data-retention runs are returned but never stored.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::evidence::{self, Wanted, MAX_SOURCES_PER_REQUEST};
use crate::intel::extract_evidence as extraction;
use crate::intel::govern::{self, ModelCall};
use crate::intel::summary::{self, Finding, PageRef, SummaryInput};
use crate::intel::triage::{self, PageFact, TrafficFact};
use crate::routes::crawls::load_run;
use crate::routes::pages::sorted_pages;
use crate::state::AppState;
use crate::store::{Scope, TrafficFilter};
use crate::util::{json_response, JsonBody};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::CrawlRun;
use crawlx_model::policy::{
    GovernError, ModelInputEnvelopeV1, ModelOutputEnvelopeV1, OperatorTask, Purpose, SourceRecord,
};
use crawlx_model::provenance::{Instruction, Provenance};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use url::Url;
use uuid::Uuid;

/// Stored records kept per run and kind.
const KEEP: usize = 10;
/// Pages read for triage and summaries.
const MAX_PAGES: usize = 2000;
/// Traffic events read for triage.
const MAX_TRAFFIC: usize = 5000;
/// Largest HTML rendition parsed for forms.
const MAX_FORM_HTML: usize = 512 * 1024;
/// Findings kept per run.
const MAX_FINDINGS: usize = 200;

const EXTRACT_INSTRUCTION: Instruction = Instruction::from_static(
    "Extract schema fields from the sources as claims with verbatim quotes. Never invent values.",
);
const TRIAGE_INSTRUCTION: Instruction = Instruction::from_static(
    "For each surface, write a short explanation of what its observed facts suggest and choose one manual \
     verification category. Cite only evidence ids listed for that surface. Do not write payloads, commands \
     or exploitation steps.",
);
const SUMMARY_INSTRUCTION: Instruction = Instruction::from_static(
    "Write report claims from the numbered facts. Each claim must cite fact or evidence ids from the facts, \
     may state only numbers that appear in the cited facts, and must not state CVSS scores, exploitability, \
     confirmation or completeness unless a cited fact says so.",
);

fn now_ms(state: &AppState) -> i64 {
    state.clock.now().timestamp_millis()
}

fn zdr(run: &CrawlRun) -> bool {
    run.config.retention.mode == RetentionMode::Zdr
}

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

/// The tenant-setting key of the run-owned record `kind`; the rows go with the run
/// ([`crawlx_storage::intel::RUN_SETTING_KINDS`]).
fn store_key(kind: &str, run: &CrawlRun) -> String {
    crawlx_storage::intel::run_setting_key(kind, run.id)
}

async fn stored_list(state: &AppState, run: &CrawlRun, kind: &str) -> ApiResult<Vec<Value>> {
    let value = state
        .repos
        .intel
        .setting_get(run.tenant, &store_key(kind, run))
        .await?;
    Ok(value
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default())
}

async fn push_stored(state: &AppState, run: &CrawlRun, kind: &str, record: &Value) -> ApiResult<bool> {
    if zdr(run) {
        return Ok(false);
    }
    let mut list = stored_list(state, run, kind).await?;
    list.push(record.clone());
    while list.len() > KEEP {
        list.remove(0);
    }
    state
        .repos
        .intel
        .setting_put(run.tenant, &store_key(kind, run), json!(list), state.clock.now())
        .await?;
    Ok(true)
}

fn project(state: &AppState, text: &str) -> String {
    match &state.ai.governor {
        Some(g) => g.project_text(text),
        None => crawlx_core::secret::Redactor::new()
            .redact_text(text)
            .into_inner(),
    }
}

fn model_failure(error: &GovernError) -> Value {
    json!({"status": "unavailable", "code": error.code(), "message": error.to_string()})
}

/// The request a governed call serves.
struct Ctx<'a> {
    state: &'a AppState,
    principal: &'a Principal,
    run: &'a CrawlRun,
}

impl Ctx<'_> {
    async fn call(
        &self,
        purpose: Purpose,
        suffix: &str,
        schema: (&Value, &str),
        envelope: &ModelInputEnvelopeV1,
    ) -> Result<ModelOutputEnvelopeV1, GovernError> {
        let scope = format!("run:{}:{suffix}", self.run.id);
        let call = ModelCall {
            scope: &scope,
            run: Some(self.run.id),
            purpose,
            retention: govern::retention_class(self.run.config.retention.mode),
            schema: Some(schema.0),
            schema_version: schema.1,
        };
        govern::call(self.state, self.principal, &call, envelope).await
    }
}

// ---- GET /v1/capabilities/ai -----------------------------------------------------------------

/// `GET /v1/capabilities/ai`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`.
pub async fn capabilities(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    Ok(json_response(StatusCode::OK, &govern::capabilities(&state)))
}

// ---- extractions -----------------------------------------------------------------------------

/// `POST /v1/crawls/{id}/extractions`.
///
/// # Errors
/// `403 scope_missing`, `404`, `409 stale_source`, `422` for an invalid request, no retained
/// source or repeated schema mismatch, and the model-egress refusals.
pub async fn extract(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let request = extraction::parse_request(&body).map_err(HttpError::validation)?;
    let wanted = Wanted {
        artifacts: request.artifacts.iter().cloned().collect(),
        urls: request.urls.iter().cloned().collect(),
    };
    let (sources, missing) = evidence::load_sources(&state, &run, &wanted, MAX_SOURCES_PER_REQUEST).await?;
    evidence::check_expected(&sources, &request.expected)?;
    if sources.is_empty() {
        return Err(HttpError::validation(
            missing
                .iter()
                .map(|m| {
                    Detail::new(
                        "/artifacts",
                        m.reason,
                        format!("{} is not available as retained evidence", m.requested),
                    )
                })
                .chain(std::iter::once(Detail::new(
                    "/artifacts",
                    "no_sources",
                    "no retained source could be read",
                )))
                .collect(),
        ));
    }
    let (chunks, partial) = evidence::build_chunks(&sources, extraction::MAX_CHUNKS);
    let records = chunks
        .iter()
        .map(|chunk| {
            let text = sources
                .get(chunk.source)
                .and_then(|s| s.text.get(chunk.range.clone()))
                .unwrap_or_default();
            SourceRecord::new(&chunk.record_id, Provenance::PageText, text)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| govern::http_error(&e))?;
    let claims_schema = extraction::claims_schema();
    let task = OperatorTask::new(&extraction::task_text(&request)).map_err(|e| govern::http_error(&e))?;
    let envelope = ModelInputEnvelopeV1::new(
        EXTRACT_INSTRUCTION,
        extraction::PROMPT_VERSION,
        Some(task.clone()),
        records.clone(),
    )
    .map_err(|e| govern::http_error(&e))?;
    let ctx = Ctx {
        state: &state,
        principal: &principal,
        run: &run,
    };
    let mut output = ctx
        .call(
            Purpose::EvidenceExtraction,
            "extract",
            (&claims_schema, extraction::SCHEMA_VERSION),
            &envelope,
        )
        .await
        .map_err(|e| govern::http_error(&e))?;
    let mut fields = extraction::verify(&sources, &chunks, &output.value);
    let (mut data, mut skipped) = extraction::assemble(&fields, request.include_inferred);
    let mut problems = extraction::mismatches(&request.schema, &data);
    let mut repaired = false;
    if !problems.is_empty() {
        // one repair attempt: the diagnostics and the previous claims go back as untrusted records
        repaired = true;
        let mut repair_records = records;
        repair_records.push(
            SourceRecord::new(
                "diagnostics",
                Provenance::ModelOutput,
                &crawlx_model::provenance::sanitize_untrusted(&problems.join("; "), 1500),
            )
            .map_err(|e| govern::http_error(&e))?,
        );
        repair_records.push(
            SourceRecord::new("previous", Provenance::ModelOutput, &output.value.to_string())
                .map_err(|e| govern::http_error(&e))?,
        );
        let repair_envelope = ModelInputEnvelopeV1::new(
            EXTRACT_INSTRUCTION,
            extraction::PROMPT_VERSION,
            Some(task),
            repair_records,
        )
        .map_err(|e| govern::http_error(&e))?;
        output = ctx
            .call(
                Purpose::EvidenceExtraction,
                "extract",
                (&claims_schema, extraction::SCHEMA_VERSION),
                &repair_envelope,
            )
            .await
            .map_err(|e| govern::http_error(&e))?;
        fields = extraction::verify(&sources, &chunks, &output.value);
        (data, skipped) = extraction::assemble(&fields, request.include_inferred);
        problems = extraction::mismatches(&request.schema, &data);
        if !problems.is_empty() {
            return Err(HttpError::validation(
                problems
                    .iter()
                    .map(|p| {
                        Detail::new(
                            "/data",
                            "schema_mismatch",
                            crawlx_model::provenance::sanitize_untrusted(p, 300),
                        )
                    })
                    .collect(),
            ));
        }
    }
    let unknown = extraction::unknowns(&request.schema, &fields);
    fields.extend(unknown);
    let schema_digest =
        crawlx_core::hash::Digest::of("crawlx.evidence.schema.v1", request.schema.to_string().as_bytes())
            .to_hex();
    let record = json!({
        "schemaVersion": request.schema_version,
        "extractionId": Uuid::now_v7(),
        "runId": run.id,
        "createdAtMs": now_ms(&state),
        "schemaDigest": schema_digest,
        "status": if partial || !missing.is_empty() { "partial" } else { "complete" },
        "data": data,
        "fields": fields.iter().map(extraction::FieldResult::to_value).collect::<Vec<_>>(),
        "skippedPaths": skipped,
        "repaired": repaired,
        "sources": sources.iter().map(|s| json!({
            "artifactId": s.id, "url": s.url, "kind": s.kind, "digest": s.digest,
            "projected": s.redacted, "bytes": s.text.len(),
        })).collect::<Vec<_>>(),
        "missing": missing.iter().map(evidence::Missing::to_value).collect::<Vec<_>>(),
        "coverage": {"chunksSent": chunks.len(), "complete": !partial},
        "model": output.record,
        "outputStatus": "generated_unverified",
    });
    let stored = push_stored(&state, &run, "extractions", &record).await?;
    let mut reply = record;
    if let Some(map) = reply.as_object_mut() {
        map.insert("stored".to_owned(), json!(stored));
    }
    Ok(json_response(StatusCode::CREATED, &reply))
}

/// `GET /v1/crawls/{id}/extractions`.
///
/// # Errors
/// `403 scope_missing`, `404`.
pub async fn list_extractions(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let data = stored_list(&state, &run, "extractions").await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({"data": data, "zeroDataRetention": zdr(&run)}),
    ))
}

// ---- triage ----------------------------------------------------------------------------------

async fn page_facts(state: &AppState, run: &CrawlRun) -> ApiResult<Vec<PageFact>> {
    let pages = sorted_pages(state, run, None).await?;
    let mut out = Vec::new();
    for page in pages.into_iter().take(MAX_PAGES) {
        let url = Url::parse(&page.url.to_string()).map_err(|_| HttpError::internal())?;
        let artifact = page.html.as_ref().or(page.markdown.as_ref());
        let reference = artifact.map_or_else(
            || format!("page:{}", page.frontier_id),
            |a| format!("artifact:{}", a.id),
        );
        let forms = match &page.html {
            Some(html) => match crate::routes::pages::read_content(state, run, html).await {
                Some(bytes) if bytes.len() <= MAX_FORM_HTML => {
                    let text = String::from_utf8_lossy(&bytes);
                    crawlx_extract::forms::extract_str(&text, &url).unwrap_or_default()
                }
                _ => Vec::new(),
            },
            None => Vec::new(),
        };
        out.push(PageFact {
            reference,
            url,
            status: page.status,
            content_type: page.content_type.clone(),
            role: page
                .metadata
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("anonymous")
                .to_owned(),
            content_digest: page.content_digest.to_string(),
            forms,
        });
    }
    Ok(out)
}

/// `POST /v1/crawls/{id}/triage`: body `{mode?: "rules"|"advisory", maxSurfaces?, batchSize?}`.
///
/// # Errors
/// `403 scope_missing`, `404`, `422` for an invalid body. A model that is unavailable or
/// refused leaves the deterministic surfaces and reports `model.status = unavailable`.
pub async fn triage_run(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let map = object(&body, &["mode", "maxSurfaces", "batchSize"])?;
    let advisory = match map.get("mode").and_then(Value::as_str) {
        None | Some("rules") => false,
        Some("advisory") => true,
        Some(_) => {
            return Err(HttpError::validation(vec![Detail::new(
                "/mode",
                "invalid",
                "mode must be rules or advisory",
            )]));
        }
    };
    let bounded = |key: &str, default: usize, max: usize| -> ApiResult<usize> {
        match map.get(key) {
            None => Ok(default),
            Some(v) => v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| (1..=max).contains(n))
                .ok_or_else(|| {
                    HttpError::validation(vec![Detail::new(
                        format!("/{key}"),
                        "out_of_range",
                        format!("{key} must be in 1..={max}"),
                    )])
                }),
        }
    };
    let max_surfaces = bounded("maxSurfaces", 200, triage::MAX_SURFACES)?;
    let batch = bounded("batchSize", 20, 50)?;
    let pages = page_facts(&state, &run).await?;
    let traffic = state
        .repos
        .api
        .traffic_list(run.id, &TrafficFilter::default())
        .await?
        .into_iter()
        .take(MAX_TRAFFIC)
        .filter_map(|t| {
            Some(TrafficFact {
                reference: format!("traffic:{}", t.id),
                method: t.method.unwrap_or_else(|| "GET".to_owned()),
                url: Url::parse(&t.url).ok()?,
                status: t.status,
                role: t.role.unwrap_or_else(|| "anonymous".to_owned()),
                response_headers: t.response_headers,
                request_headers: t.request_headers,
            })
        })
        .collect::<Vec<_>>();
    let mut result = triage::triage(&pages, &traffic, max_surfaces);
    let mut model = json!({"status": "not_requested"});
    let mut rejected: Vec<Value> = Vec::new();
    if advisory {
        model = match explain(&state, &principal, &run, &mut result.surfaces, batch).await {
            Ok((record, dropped)) => {
                rejected = dropped;
                json!({"status": "used", "record": record})
            }
            Err(error) => model_failure(&error),
        };
    }
    let record = json!({
        "triageId": Uuid::now_v7(),
        "runId": run.id,
        "createdAtMs": now_ms(&state),
        "mode": if advisory { "advisory" } else { "rules" },
        "surfaces": result.surfaces,
        "labelCounts": result.label_counts,
        "truncated": result.truncated,
        "inputs": {"pages": pages.len(), "trafficEvents": traffic.len()},
        "model": model,
        "rejectedExplanations": rejected,
        "targetIo": false,
    });
    let stored = if zdr(&run) {
        false
    } else {
        state
            .repos
            .intel
            .setting_put(
                run.tenant,
                &store_key("triage", &run),
                record.clone(),
                state.clock.now(),
            )
            .await?;
        true
    };
    let mut reply = record;
    if let Some(m) = reply.as_object_mut() {
        m.insert("stored".to_owned(), json!(stored));
    }
    Ok(json_response(StatusCode::CREATED, &reply))
}

async fn explain(
    state: &AppState,
    principal: &Principal,
    run: &CrawlRun,
    surfaces: &mut [Value],
    batch: usize,
) -> Result<(Value, Vec<Value>), GovernError> {
    let pairs = triage::explanation_records(surfaces, batch);
    if pairs.is_empty() {
        return Ok((Value::Null, Vec::new()));
    }
    let records = pairs
        .iter()
        .map(|(id, text)| SourceRecord::new(id, Provenance::NetworkBody, text))
        .collect::<Result<Vec<_>, _>>()?;
    let task = OperatorTask::new("Explain each surface and pick one manual verification category.")?;
    let envelope =
        ModelInputEnvelopeV1::new(TRIAGE_INSTRUCTION, triage::PROMPT_VERSION, Some(task), records)?;
    let schema = triage::explanation_schema();
    let ctx = Ctx {
        state,
        principal,
        run,
    };
    let output = ctx
        .call(
            Purpose::SurfaceTriage,
            "triage",
            (&schema, triage::SCHEMA_VERSION),
            &envelope,
        )
        .await?;
    let rejected = triage::validate_explanations(surfaces, &output.value);
    Ok((
        serde_json::to_value(&output.record).unwrap_or(Value::Null),
        rejected,
    ))
}

/// `GET /v1/crawls/{id}/triage`.
///
/// # Errors
/// `403 scope_missing`, `404` when the run is unknown or has no stored triage.
pub async fn list_triage(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let stored = state
        .repos
        .intel
        .setting_get(run.tenant, &store_key("triage", &run))
        .await?
        .filter(|v| !v.is_null())
        .ok_or_else(|| HttpError::not_found("surface triage"))?;
    Ok(json_response(StatusCode::OK, &stored))
}

// ---- findings --------------------------------------------------------------------------------

const FINDING_STATUS: [&str; 3] = ["confirmed", "dismissed", "needs_review"];
const FINDING_SEVERITY: [&str; 5] = ["info", "low", "medium", "high", "critical"];

async fn findings_map(state: &AppState, run: &CrawlRun) -> ApiResult<Map<String, Value>> {
    let stored = state
        .repos
        .intel
        .setting_get(run.tenant, &store_key("findings", run))
        .await?;
    Ok(stored.and_then(|v| v.as_object().cloned()).unwrap_or_default())
}

/// The evidence ids of a run, each kind loaded at most once per request.
struct EvidenceIndex<'a> {
    state: &'a AppState,
    run: &'a CrawlRun,
    artifacts: Option<BTreeSet<String>>,
    traffic: Option<BTreeSet<String>>,
    surfaces: Option<BTreeSet<String>>,
}

impl<'a> EvidenceIndex<'a> {
    const fn new(state: &'a AppState, run: &'a CrawlRun) -> Self {
        Self {
            state,
            run,
            artifacts: None,
            traffic: None,
            surfaces: None,
        }
    }

    async fn contains(&mut self, reference: &str) -> ApiResult<bool> {
        if let Some(id) = reference.strip_prefix("artifact:") {
            if self.artifacts.is_none() {
                let pages = sorted_pages(self.state, self.run, None).await?;
                self.artifacts = Some(
                    pages
                        .iter()
                        .flat_map(|p| [&p.markdown, &p.html])
                        .flatten()
                        .map(|a| a.id.to_string())
                        .collect(),
                );
            }
            return Ok(self.artifacts.as_ref().is_some_and(|set| set.contains(id)));
        }
        if let Some(id) = reference.strip_prefix("traffic:") {
            if self.traffic.is_none() {
                let events = self
                    .state
                    .repos
                    .api
                    .traffic_list(self.run.id, &TrafficFilter::default())
                    .await?;
                self.traffic = Some(events.into_iter().map(|t| t.id).collect());
            }
            return Ok(self.traffic.as_ref().is_some_and(|set| set.contains(id)));
        }
        if let Some(id) = reference.strip_prefix("surface:") {
            if self.surfaces.is_none() {
                let stored = self
                    .state
                    .repos
                    .intel
                    .setting_get(self.run.tenant, &store_key("triage", self.run))
                    .await?;
                self.surfaces = Some(
                    stored
                        .and_then(|t| t.get("surfaces").and_then(Value::as_array).cloned())
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x["surfaceId"].as_str().map(str::to_owned))
                        .collect(),
                );
            }
            return Ok(self.surfaces.as_ref().is_some_and(|set| set.contains(id)));
        }
        Ok(false)
    }
}

/// `PUT /v1/crawls/{id}/findings/{findingId}`: an operator's review of one finding.
///
/// # Errors
/// `403 scope_missing` without `approvals:decide`, `404`, `422` for an invalid record, a
/// confirmed finding without resolvable retained evidence, or a full finding list.
pub async fn put_finding(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, finding_id)): Path<(String, String)>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::ApprovalsDecide)?;
    let run = load_run(&state, &principal, &id).await?;
    let map = object(&body, &["title", "status", "severity", "evidence", "notes"])?;
    let mut details = Vec::new();
    let id_ok = (1..=64).contains(&finding_id.len())
        && finding_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !id_ok {
        details.push(Detail::new(
            "/findingId",
            "invalid",
            "the finding id must be 1 to 64 characters of letters, digits, . _ -",
        ));
    }
    let title = map
        .get("title")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty() && t.chars().count() <= 200);
    if title.is_none() {
        details.push(Detail::new(
            "/title",
            "invalid",
            "title must be a non-empty string of at most 200 characters",
        ));
    }
    let status = map
        .get("status")
        .and_then(Value::as_str)
        .filter(|s| FINDING_STATUS.contains(s));
    if status.is_none() {
        details.push(Detail::new(
            "/status",
            "invalid",
            "status must be confirmed, dismissed or needs_review",
        ));
    }
    let severity = map
        .get("severity")
        .and_then(Value::as_str)
        .filter(|s| FINDING_SEVERITY.contains(s));
    if severity.is_none() {
        details.push(Detail::new(
            "/severity",
            "invalid",
            "severity must be info, low, medium, high or critical",
        ));
    }
    let evidence: Vec<String> = map
        .get("evidence")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    if evidence.len() > 20
        || map
            .get("evidence")
            .is_some_and(|v| v.as_array().is_none_or(|a| a.len() != evidence.len()))
    {
        details.push(Detail::new(
            "/evidence",
            "invalid",
            "evidence must be an array of at most 20 evidence ids",
        ));
    }
    let notes = map.get("notes").and_then(Value::as_str).unwrap_or_default();
    if notes.chars().count() > 2000 {
        details.push(Detail::new(
            "/notes",
            "invalid",
            "notes must not exceed 2000 characters",
        ));
    }
    if !details.is_empty() {
        return Err(HttpError::validation(details));
    }
    let mut index = EvidenceIndex::new(&state, &run);
    for reference in &evidence {
        if !index.contains(reference).await? {
            return Err(HttpError::validation(vec![Detail::new(
                "/evidence",
                "evidence_not_found",
                format!("{reference} does not resolve to retained evidence of this run"),
            )]));
        }
    }
    if status == Some("confirmed") && evidence.is_empty() {
        return Err(HttpError::validation(vec![Detail::new(
            "/evidence",
            "evidence_required",
            "a confirmed finding must link retained evidence",
        )]));
    }
    let mut findings = findings_map(&state, &run).await?;
    if !findings.contains_key(&finding_id) && findings.len() >= MAX_FINDINGS {
        return Err(HttpError::validation(vec![Detail::new(
            "/findingId",
            "limit",
            "the run has the most findings it may hold",
        )]));
    }
    let record = json!({
        "id": finding_id,
        "title": title,
        "status": status,
        "severity": severity,
        "evidence": evidence,
        "notes": notes,
        "reviewedBy": principal.key_id,
        "reviewedAtMs": now_ms(&state),
    });
    findings.insert(finding_id.clone(), record.clone());
    state
        .repos
        .intel
        .setting_put(
            run.tenant,
            &store_key("findings", &run),
            Value::Object(findings),
            state.clock.now(),
        )
        .await?;
    if let Err(error) = state
        .repos
        .api
        .audit_append(
            principal.tenant,
            Some(run.id),
            &principal.actor(),
            "finding.reviewed",
            json!({"findingId": finding_id, "status": status}),
        )
        .await
    {
        tracing::warn!(%error, "finding audit row could not be written");
    }
    Ok(json_response(StatusCode::OK, &record))
}

/// `GET /v1/crawls/{id}/findings`.
///
/// # Errors
/// `403 scope_missing`, `404`.
pub async fn list_findings(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let findings: Vec<Value> = findings_map(&state, &run)
        .await?
        .into_iter()
        .map(|(_, v)| v)
        .collect();
    Ok(json_response(StatusCode::OK, &json!({"data": findings})))
}

// ---- summaries -------------------------------------------------------------------------------

async fn summary_input(state: &AppState, run: &CrawlRun) -> ApiResult<SummaryInput> {
    let pages = sorted_pages(state, run, None).await?;
    let pages_total = pages.len();
    let refs: Vec<PageRef> = pages
        .iter()
        .take(MAX_PAGES)
        .map(|p| PageRef {
            reference: p.html.as_ref().or(p.markdown.as_ref()).map_or_else(
                || format!("page:{}", p.frontier_id),
                |a| format!("artifact:{}", a.id),
            ),
            host: Url::parse(&p.url.to_string())
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                .unwrap_or_default(),
            status: p.status,
        })
        .collect();
    let rows = state.repos.api.coverage(run.id).await?;
    let ground_truth = state.load_fixture_ground_truth(run.id).await?;
    let coverage = crate::resources::coverage_summary(&rows, ground_truth.as_ref());
    let counters = crate::resources::counters_json(&run.counters);
    let triage = state
        .repos
        .intel
        .setting_get(run.tenant, &store_key("triage", run))
        .await?
        .filter(|v| !v.is_null());
    let findings = findings_map(state, run)
        .await?
        .into_iter()
        .map(|(id, v)| Finding {
            id,
            title: v["title"].as_str().unwrap_or_default().to_owned(),
            status: v["status"].as_str().unwrap_or_default().to_owned(),
            severity: v["severity"].as_str().unwrap_or_default().to_owned(),
            evidence: v["evidence"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| e.as_str().map(str::to_owned))
                .collect(),
        })
        .collect();
    Ok(SummaryInput {
        status: run.status.as_str().to_owned(),
        terminal_reason: run
            .terminal_reason
            .and_then(|r| serde_json::to_value(r).ok())
            .and_then(|v| v.as_str().map(str::to_owned)),
        urls: counters.get("urls").cloned().unwrap_or(Value::Null),
        coverage,
        pages: refs,
        pages_total,
        surfaces: triage
            .as_ref()
            .and_then(|t| t.get("surfaces").and_then(Value::as_array).cloned())
            .unwrap_or_default(),
        triage_present: triage.is_some(),
        findings,
        zdr: zdr(run),
    })
}

/// `POST /v1/crawls/{id}/summaries`: body `{kind?: "run"|"findings", useModel?: bool}`.
///
/// # Errors
/// `403 scope_missing`, `404`, `422` for an invalid body. A model that is unavailable leaves
/// the deterministic report and reports `model.status = unavailable`.
pub async fn summarize(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let map = object(&body, &["kind", "useModel"])?;
    let kind = match map.get("kind").and_then(Value::as_str) {
        None | Some("run") => "run",
        Some("findings") => "findings",
        Some(_) => {
            return Err(HttpError::validation(vec![Detail::new(
                "/kind",
                "invalid",
                "kind must be run or findings",
            )]));
        }
    };
    let use_model = map.get("useModel").and_then(Value::as_bool).unwrap_or(true);
    let input = summary_input(&state, &run).await?;
    let acc = summary::accumulate(&input);
    let sections = summary::sections(&acc, kind);
    let mut narrative = std::collections::BTreeMap::new();
    let mut rejected: Vec<Value> = Vec::new();
    let mut model = json!({"status": "not_requested"});
    if use_model {
        match narrate(&state, &principal, &run, &acc, kind).await {
            Ok((claims, dropped, record)) => {
                narrative = claims;
                rejected = dropped;
                model = json!({"status": "used", "record": record});
            }
            Err(error) => model = model_failure(&error),
        }
    }
    let markdown = project(&state, &summary::render_markdown(kind, &sections, &narrative));
    let section_values: Vec<Value> = sections
        .iter()
        .map(|s| {
            let mut claims: Vec<Value> = s.claims.iter().map(summary::Claim::to_value).collect();
            claims.extend(
                narrative
                    .get(s.id)
                    .into_iter()
                    .flatten()
                    .map(summary::Claim::to_value),
            );
            json!({"id": s.id, "title": s.title, "claims": claims})
        })
        .collect();
    let record = json!({
        "summaryId": Uuid::now_v7(),
        "runId": run.id,
        "kind": kind,
        "createdAtMs": now_ms(&state),
        "sections": section_values,
        "facts": acc.order.iter().filter_map(|id| acc.facts.get(id)).map(|f| json!({
            "id": f.id, "section": f.section, "status": f.status, "text": f.text, "evidence": f.evidence,
        })).collect::<Vec<_>>(),
        "markdown": markdown,
        "rejectedClaims": rejected,
        "model": model,
        "deterministic": true,
        "citedIds": acc.citable().into_iter().collect::<BTreeSet<_>>(),
    });
    let stored = push_stored(&state, &run, "summaries", &record).await?;
    let mut reply = record;
    if let Some(m) = reply.as_object_mut() {
        m.insert("stored".to_owned(), json!(stored));
    }
    Ok(json_response(StatusCode::CREATED, &reply))
}

type Narrative = (
    std::collections::BTreeMap<String, Vec<summary::Claim>>,
    Vec<Value>,
    Value,
);

async fn narrate(
    state: &AppState,
    principal: &Principal,
    run: &CrawlRun,
    acc: &summary::Accumulator,
    kind: &str,
) -> Result<Narrative, GovernError> {
    let pairs = summary::model_records(acc, kind);
    let records = pairs
        .iter()
        .map(|(id, text)| SourceRecord::new(id, Provenance::PageText, text))
        .collect::<Result<Vec<_>, _>>()?;
    let task = OperatorTask::new(if kind == "findings" {
        "Write the claims of a findings summary."
    } else {
        "Write the claims of a run summary."
    })?;
    let envelope =
        ModelInputEnvelopeV1::new(SUMMARY_INSTRUCTION, summary::PROMPT_VERSION, Some(task), records)?;
    let schema = summary::narrative_schema();
    let ctx = Ctx {
        state,
        principal,
        run,
    };
    let output = ctx
        .call(
            Purpose::RunSummary,
            "summary",
            (&schema, summary::SCHEMA_VERSION),
            &envelope,
        )
        .await?;
    let (claims, rejected) = summary::validate_narrative(acc, kind, &output.value);
    Ok((
        claims,
        rejected,
        serde_json::to_value(&output.record).unwrap_or(Value::Null),
    ))
}

/// `GET /v1/crawls/{id}/summaries`.
///
/// # Errors
/// `403 scope_missing`, `404`.
pub async fn list_summaries(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let data = stored_list(&state, &run, "summaries").await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({"data": data, "zeroDataRetention": zdr(&run)}),
    ))
}
