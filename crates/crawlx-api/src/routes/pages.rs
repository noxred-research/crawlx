//! `GET /v1/crawls/{id}/pages` (Firecrawl-compatible documents, `?field=`, `?format=jsonl`),
//! `GET .../export` (katana-style text/JSONL output) and `GET .../errors`.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::{load_run, load_run_metadata};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, next_link, paginate, ts, Params};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::{OutputFormat, RetentionMode};
use crawlx_core::counters::ActionStatus;
use crawlx_core::repo::{CrawlRun, FrontierStatus, PageRecord};
use crawlx_core::ArtifactRef;
use crawlx_storage::PRESIGN_MAX_TTL;
use crawlx_worker::output::{write_line, ExportFormat, Exporter, Field, OutputFilters, Template};
use futures::stream;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::convert::Infallible;

/// Which content fields a request asks for.
#[derive(Clone, Debug, Default)]
pub(crate) struct Include {
    pub markdown: bool,
    pub html: bool,
    pub raw_html: bool,
    pub links: bool,
    pub screenshot: bool,
}

impl Include {
    fn from_formats(formats: &[OutputFormat]) -> Self {
        let mut i = Self::default();
        for f in formats {
            match f {
                OutputFormat::Markdown => i.markdown = true,
                OutputFormat::Html => i.html = true,
                OutputFormat::RawHtml => i.raw_html = true,
                OutputFormat::Links => i.links = true,
                OutputFormat::Screenshot => i.screenshot = true,
                OutputFormat::Metadata => {}
            }
        }
        i
    }

    fn from_param(v: &str) -> Result<Self, HttpError> {
        let mut i = Self::default();
        for part in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match part {
                "markdown" => i.markdown = true,
                "html" => i.html = true,
                "rawHtml" => i.raw_html = true,
                "links" => i.links = true,
                "screenshot" => i.screenshot = true,
                "metadata" => {}
                other => return Err(HttpError::malformed(format!("unknown include value {other:?}"))),
            }
        }
        Ok(i)
    }

    pub(crate) fn resolve(run: &CrawlRun, params: &Params) -> Result<Self, HttpError> {
        match params.get("include") {
            Some(v) => Self::from_param(v),
            None => Ok(Self::from_formats(&run.config.output.formats)),
        }
    }
}

fn page_role(p: &PageRecord) -> &str {
    p.metadata
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("anonymous")
}

pub(crate) fn page_key(p: &PageRecord) -> String {
    format!("{:020}\u{1}{}", p.frontier_id.max(0), p.url)
}

/// Bytes of a page artifact: the delivery buffer for zero-data-retention runs,
/// the artifact store otherwise.
pub(crate) async fn read_content(state: &AppState, run: &CrawlRun, r: &ArtifactRef) -> Option<Vec<u8>> {
    if run.config.retention.mode == RetentionMode::Zdr {
        return match state.zdr.read_for_run(run.tenant, run.id, r).await {
            Ok(blob) => blob.map(|b| b.bytes),
            Err(e) => {
                tracing::warn!(error = %e, "zdr content unavailable");
                None
            }
        };
    }
    match state.repos.artifacts.read(r).await {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::debug!(error = %e, artifact = %r.id, "page artifact unavailable");
            None
        }
    }
}

/// Link for content above `inline_max_bytes`: a presigned object-store URL (60 s) when the
/// store offers one, otherwise the API's artifact endpoint.
async fn content_link(state: &AppState, run: &CrawlRun, r: &ArtifactRef) -> String {
    let api_link = format!("/v1/crawls/{}/artifacts/{}", run.id, r.id);
    if run.config.retention.mode == RetentionMode::Zdr {
        return api_link;
    }
    match state.repos.artifacts.presign(r, PRESIGN_MAX_TTL).await {
        Ok(Some(url)) => url.into(),
        Ok(None) => api_link,
        Err(e) => {
            tracing::debug!(error = %e, artifact = %r.id, "presign failed; serving through the api");
            api_link
        }
    }
}

pub(crate) async fn content(
    state: &AppState,
    run: &CrawlRun,
    artifact: Option<&ArtifactRef>,
) -> (Value, Option<String>) {
    let Some(r) = artifact else {
        return (Value::Null, None);
    };
    match read_content(state, run, r).await {
        Some(bytes) if bytes.len() <= state.settings.inline_max_bytes => {
            (Value::String(String::from_utf8_lossy(&bytes).into_owned()), None)
        }
        Some(_) => (Value::Null, Some(content_link(state, run, r).await)),
        None => (Value::Null, None),
    }
}

/// One Firecrawl-shaped document.
pub(crate) async fn page_doc(state: &AppState, run: &CrawlRun, p: &PageRecord, inc: &Include) -> Value {
    let (markdown, markdown_ref) = if inc.markdown {
        content(state, run, p.markdown.as_ref()).await
    } else {
        (Value::Null, None)
    };
    let (html, html_ref) = if inc.html {
        content(state, run, p.html.as_ref()).await
    } else {
        (Value::Null, None)
    };
    let meta = &p.metadata;
    let get = |k: &str| meta.get(k).cloned().unwrap_or(Value::Null);
    let url = p.url.to_string();
    json!({
        "markdown": markdown,
        "html": html,
        "rawHtml": Value::Null,
        "links": if inc.links { json!(p.links) } else { json!([]) },
        "screenshot": Value::Null,
        "metadata": {
            "title": p.title,
            "description": get("description"),
            "language": get("language"),
            "sourceURL": url,
            "url": url,
            "statusCode": p.status,
            "contentType": p.content_type,
            "error": Value::Null,
            "crawlx": {
                "pageId": p.frontier_id.to_string(),
                "role": page_role(p),
                "plane": meta.get("plane").and_then(Value::as_str).unwrap_or("http"),
                "depth": get("depth"),
                "contentDigest": format!("blake3:{}", p.content_digest),
                "fetchedAt": ts(p.fetched_at),
                "stateId": get("stateId"),
                "markdownRef": markdown_ref,
                "htmlRef": html_ref,
            },
        },
    })
}

/// Katana-style output options read from the query: `field`, `template`,
/// `match`, `filter`, `extensionMatch`, `extensionFilter`, `exclude`; `include=html` attaches
/// the stored HTML as the JSONL `response.body`.
fn exporter_from_params(params: &Params, format: ExportFormat) -> Result<Exporter, HttpError> {
    let list = |k: &str| -> Vec<String> {
        params
            .get(k)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let one = |k: &str| -> Vec<String> { params.get(k).map(str::to_owned).into_iter().collect() };
    let fields = params
        .get("field")
        .map(|f| Field::parse_list(f).map_err(|e| HttpError::malformed(format!("field: {e}"))))
        .transpose()?
        .unwrap_or_default();
    let template = params
        .get("template")
        .map(|t| Template::parse(t).map_err(|e| HttpError::malformed(format!("template: {e}"))))
        .transpose()?;
    let filters = OutputFilters::new(
        &one("match"),
        &one("filter"),
        &list("extensionMatch"),
        &list("extensionFilter"),
    )
    .map_err(|e| HttpError::malformed(format!("match/filter: {e}")))?;
    let include_body = params
        .get("include")
        .is_some_and(|v| v.split(',').any(|s| s.trim() == "html"));
    Ok(Exporter {
        format,
        fields,
        template,
        filters,
        exclude_fields: list("exclude"),
        include_body,
        ..Exporter::default()
    })
}

/// `format=jsonl|text` (default `text` for `/export`; `None` on `/pages` means the document list).
fn format_param(params: &Params) -> Result<Option<ExportFormat>, HttpError> {
    match params.get("format") {
        None => Ok(None),
        Some("jsonl") => Ok(Some(ExportFormat::Jsonl)),
        Some("text") => Ok(Some(ExportFormat::Text)),
        Some(other) => Err(HttpError::malformed(format!("unknown format {other:?}"))),
    }
}

/// All pages of `run` matching `?role=`, sorted by page key. A zero-data-retention run lists
/// only the pages whose content is still in the delivery buffer: once a page
/// was acknowledged by the webhook receiver or its buffer TTL ended it is gone.
pub(crate) async fn sorted_pages(
    state: &AppState,
    run: &CrawlRun,
    role: Option<&str>,
) -> ApiResult<Vec<PageRecord>> {
    let buffered: Option<BTreeSet<i64>> = if run.config.retention.mode == RetentionMode::Zdr {
        Some(
            state
                .zdr
                .list(run.tenant, run.id)
                .await?
                .into_iter()
                .map(|p| p.page)
                .collect(),
        )
    } else {
        None
    };
    let mut records: Vec<PageRecord> = state
        .repos
        .pages
        .list(run.id)
        .await?
        .into_iter()
        .filter(|p| role.is_none_or(|r| page_role(p) == r))
        .filter(|p| buffered.as_ref().is_none_or(|b| b.contains(&p.frontier_id)))
        .collect();
    records.sort_by_cached_key(page_key);
    Ok(records)
}

/// Whether a ZDR run has no page output left, independently of expired operational config.
pub(crate) async fn zdr_output_expired(
    state: &AppState,
    run: &crawlx_core::repo::RunMetadata,
) -> ApiResult<bool> {
    if run.retention.mode != RetentionMode::Zdr {
        return Ok(false);
    }
    Ok(!state.zdr.list(run.tenant, run.id).await?.iter().any(|page| {
        page.page >= 0
            && page.blobs.keys().any(|kind| {
                kind == "page_record"
                    || (!kind.starts_with('_') && !matches!(kind.as_str(), "frontier_record" | "run_config"))
            })
    }))
}

/// The stored HTML of `p` as text, when it exists and the exporter wants bodies.
async fn html_body(state: &AppState, run: &CrawlRun, exporter: &Exporter, p: &PageRecord) -> Option<String> {
    if !exporter.include_body {
        return None;
    }
    let r = p.html.as_ref()?;
    read_content(state, run, r)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn text_response(bytes: Vec<u8>, content_type: &'static str) -> Response {
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp
}

/// Stream one JSONL [`Record`] per page (`text/x-ndjson`), bodies loaded lazily.
fn jsonl_stream(state: AppState, run: CrawlRun, exporter: Exporter, pages: Vec<PageRecord>) -> Response {
    let stream = stream::unfold(
        (state, run, exporter, pages.into_iter()),
        |(state, run, exporter, mut pages)| async move {
            loop {
                let p = pages.next()?;
                let body = html_body(&state, &run, &exporter, &p).await;
                let Some(record) = exporter.record(&p, body) else {
                    continue;
                };
                let mut line = Vec::new();
                if let Err(e) = write_line(&record, &mut line) {
                    tracing::warn!(error = %e, "jsonl record skipped");
                    continue;
                }
                return Some((
                    Ok::<Bytes, Infallible>(Bytes::from(line)),
                    (state, run, exporter, pages),
                ));
            }
        },
    );
    let mut resp = Response::new(Body::from_stream(stream));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/x-ndjson"));
    resp
}

/// `GET /v1/crawls/{id}/pages`.
///
/// With `?field=<name>` (or `?template=`, or `?format=text`) the envelope's `data` is the list
/// of that field's or template's values over the paginated pages; with
/// `?format=jsonl` the whole run streams as JSONL records. A zero-data-retention run is served
/// from the delivery buffer: only pages not yet acknowledged by the webhook
/// receiver and within the buffer TTL appear.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for a bad `limit`, `cursor`, `field`, `template`,
/// `format` or regex, `410` for pages whose content was purged.
pub async fn pages(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let metadata = load_run_metadata(&state, &principal, &id).await?;
    if zdr_output_expired(&state, &metadata).await? {
        let format = format_param(&params)?;
        let _ = params.limit(&state.settings)?;
        let _ = params.cursor_key()?;
        if let Some(include) = params.get("include") {
            let _ = Include::from_param(include)?;
        }
        if format == Some(ExportFormat::Jsonl) {
            let _ = exporter_from_params(&params, ExportFormat::Jsonl)?;
            return Ok(text_response(Vec::new(), "text/x-ndjson"));
        }
        if format == Some(ExportFormat::Text)
            || params.get("field").is_some()
            || params.get("template").is_some()
        {
            let _ = exporter_from_params(&params, ExportFormat::Text)?;
        }
        return Ok(json_response(
            StatusCode::OK,
            &json!({"data": [], "next": null, "total": 0}),
        ));
    }
    let run = load_run(&state, &principal, &id).await?;
    let format = format_param(&params)?;
    if format == Some(ExportFormat::Jsonl) {
        let exporter = exporter_from_params(&params, ExportFormat::Jsonl)?;
        let records = sorted_pages(&state, &run, params.get("role")).await?;
        return Ok(jsonl_stream(state, run, exporter, records));
    }
    let limit = params.limit(&state.settings)?;
    let cursor = params.cursor_key()?;
    let text_mode = format == Some(ExportFormat::Text)
        || params.get("field").is_some()
        || params.get("template").is_some();
    let field_exporter = if text_mode {
        Some(exporter_from_params(&params, ExportFormat::Text)?)
    } else {
        None
    };
    let include = if field_exporter.is_some() {
        Include::default()
    } else {
        Include::resolve(&run, &params)?
    };
    let records = sorted_pages(&state, &run, params.get("role")).await?;
    let total = records.len();
    let keyed: Vec<(String, PageRecord)> = records.into_iter().map(|p| (page_key(&p), p)).collect();
    let (page, next_key) = paginate(keyed, limit, cursor.as_deref());
    let data: Vec<Value> = match &field_exporter {
        Some(exporter) => page
            .iter()
            .flat_map(|p| exporter.text_lines(p).0)
            .map(Value::String)
            .collect(),
        None => {
            let mut data = Vec::with_capacity(page.len());
            for p in &page {
                data.push(page_doc(&state, &run, p, &include).await);
            }
            data
        }
    };
    let path = format!("/v1/crawls/{}/pages", run.id);
    let body =
        json!({ "data": data, "next": next_link(&path, &params, next_key.as_deref()), "total": total });
    Ok(json_response(StatusCode::OK, &body))
}

/// `GET /v1/crawls/{id}/export?format=jsonl|text&field=&template=` — the whole run through
/// [`Exporter`], unpaginated: `text/plain` lines (template > field > `url`) or `text/x-ndjson`
/// records. Same query options as `/pages`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for a bad `field`, `template`, `format` or regex.
/// Zero-data-retention runs export only the pages still in the delivery buffer.
pub async fn export(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let metadata = load_run_metadata(&state, &principal, &id).await?;
    if zdr_output_expired(&state, &metadata).await? {
        let format = format_param(&params)?.unwrap_or(ExportFormat::Text);
        let _ = exporter_from_params(&params, format)?;
        return Ok(text_response(
            Vec::new(),
            if format == ExportFormat::Jsonl {
                "text/x-ndjson"
            } else {
                "text/plain; charset=utf-8"
            },
        ));
    }
    let run = load_run(&state, &principal, &id).await?;
    let format = format_param(&params)?.unwrap_or(ExportFormat::Text);
    let exporter = exporter_from_params(&params, format)?;
    let records = sorted_pages(&state, &run, params.get("role")).await?;
    if format == ExportFormat::Jsonl {
        return Ok(jsonl_stream(state, run, exporter, records));
    }
    let mut out = Vec::new();
    exporter.export_pages(&records, |_| None, &mut out).map_err(|e| {
        tracing::error!(error = %e, run = %run.id, "export failed");
        HttpError::internal()
    })?;
    Ok(text_response(out, "text/plain; charset=utf-8"))
}

/// Error items for a run (also used by the compat facade).
pub(crate) async fn error_items(state: &AppState, run: &CrawlRun) -> ApiResult<Vec<(String, Value)>> {
    let mut items: Vec<(String, Value)> = Vec::new();
    for f in state.repos.frontier.list(run.id).await? {
        let (code, retryable) = match f.status {
            FrontierStatus::Failed => ("failed", false),
            FrontierStatus::Abandoned => ("abandoned", false),
            FrontierStatus::Unreachable => ("unreachable", true),
            FrontierStatus::PolicyBlocked => ("policy_blocked", false),
            FrontierStatus::RobotsBlocked => ("robots_blocked", false),
            _ => continue,
        };
        items.push((
            format!("u:{:020}", f.id.max(0)),
            json!({
                "id": format!("url:{}", f.id),
                "plane": "url",
                "subject": f.url.to_string(),
                "code": f.denial_reason.clone().unwrap_or_else(|| code.to_owned()),
                "status": code,
                "httpStatus": Value::Null,
                "retryable": retryable,
                "attempts": f.attempts,
                "actionId": Value::Null,
                "occurredAt": Value::Null,
                "ref": f.id.to_string(),
            }),
        ));
    }
    for status in [ActionStatus::Failed, ActionStatus::Unknown] {
        for a in state.repos.journal.list(run.id, Some(status)).await? {
            items.push((
                format!("i:{}", a.id),
                json!({
                    "id": format!("action:{}", a.id),
                    "plane": "interaction",
                    "subject": a.key.action_kind.as_str(),
                    "code": a.status.as_str(),
                    "status": a.status.as_str(),
                    "httpStatus": Value::Null,
                    "retryable": a.status == ActionStatus::Unknown,
                    "attempts": a.attempt,
                    "actionId": a.id,
                    "occurredAt": a.finished_at.map(ts),
                    "ref": a.id.to_string(),
                }),
            ));
        }
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(items)
}

/// `GET /v1/crawls/{id}/errors`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for a bad `limit` or `cursor`.
pub async fn errors(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let limit = params.limit(&state.settings)?;
    let cursor = params.cursor_key()?;
    let plane = params.get("plane");
    let all = error_items(&state, &run).await?;
    let filtered: Vec<(String, Value)> = all
        .into_iter()
        .filter(|(_, v)| plane.is_none_or(|p| v.get("plane").and_then(Value::as_str) == Some(p)))
        .collect();
    let total = filtered.len();
    let (page, next_key) = paginate(filtered, limit, cursor.as_deref());
    let path = format!("/v1/crawls/{}/errors", run.id);
    let body =
        json!({ "data": page, "next": next_link(&path, &params, next_key.as_deref()), "total": total });
    Ok(json_response(StatusCode::OK, &body))
}

/// Which includes a run's default formats imply (compat facade).
pub(crate) fn default_include(run: &CrawlRun) -> Include {
    Include::from_formats(&run.config.output.formats)
}
