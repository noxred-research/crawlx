//! `GET /v1/crawls/{id}/events`: SSE over `crawl_events`.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::Scope;
use crate::streams::StreamPermit;
use crate::util::{ts, Params};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::RunEvent;
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use crawlx_storage::{BufferedPage, DeliveryBuffer};
use serde_json::json;
use std::collections::{BTreeSet, VecDeque};
use std::convert::Infallible;

/// Terminal event kinds: the stream closes after one of them.
const TERMINAL: [&str; 2] = ["completed", "failed"];

struct Cursor {
    /// Keeps the tenant/run SSE slot reserved until the stream is dropped.
    _permit: StreamPermit,
    state: AppState,
    run: CrawlRunId,
    tenant: TenantId,
    zdr: bool,
    after: u64,
    types: Option<BTreeSet<String>>,
    pending: VecDeque<RunEvent>,
    finished: bool,
}

/// The SSE `data` envelope.
#[must_use]
pub fn envelope(run: CrawlRunId, e: &RunEvent) -> serde_json::Value {
    json!({
        "id": format!("evt_{}", e.seq),
        "runId": run,
        "seq": e.seq,
        "type": e.kind,
        "createdAt": ts(e.at),
        "data": e.payload,
    })
}

/// Hydrate delivery-only page content without placing it in the durable event journal.
pub(crate) async fn delivery_envelope(
    tenant: TenantId,
    run: CrawlRunId,
    zdr: bool,
    event: &RunEvent,
    buffer: Option<&DeliveryBuffer>,
) -> Result<(serde_json::Value, Option<BufferedPage>), StoreError> {
    let mut payload = envelope(run, event);
    let page = if zdr && event.kind == "page" {
        match (
            buffer,
            event.payload.get("pageId").and_then(serde_json::Value::as_i64),
        ) {
            (Some(buffer), Some(page)) => buffer.get(tenant, run, page).await?,
            _ => None,
        }
    } else {
        None
    };
    if let Some(page) = &page {
        payload["data"]["content"] = serde_json::Value::Object(
            page.blobs
                .iter()
                .filter(|(kind, _)| {
                    !kind.starts_with('_')
                        && !matches!(kind.as_str(), "page_record" | "frontier_record" | "run_config")
                })
                .map(|(kind, blob)| {
                    (
                        kind.clone(),
                        serde_json::Value::String(String::from_utf8_lossy(&blob.bytes).into_owned()),
                    )
                })
                .collect(),
        );
    }
    Ok((payload, page))
}

async fn next_event(mut c: Cursor) -> Option<(Result<Event, Infallible>, Cursor)> {
    loop {
        if let Some(mut ev) = c.pending.pop_front() {
            let mut hydrated = true;
            if c.zdr {
                // Hydrate at delivery, not batch acquisition: one expired sideband must not
                // discard live neighbors or leave full payloads queued past their lifetime.
                match c.state.repos.events.list_after(c.run, c.after, 1).await {
                    Ok(mut batch) => match batch.pop() {
                        Some(live) if live.seq == ev.seq => ev = live,
                        _ => return None,
                    },
                    Err(StoreError::RetentionDenied(_)) => hydrated = false,
                    Err(error) => {
                        tracing::warn!(%error, run = %c.run, "event stream ends: hydration failed");
                        return None;
                    }
                }
            }
            c.after = ev.seq;
            let terminal = TERMINAL.contains(&ev.kind.as_str());
            if terminal {
                c.finished = true;
            }
            if c.types.as_ref().is_some_and(|t| !t.contains(&ev.kind)) {
                continue;
            }
            let data = if c.zdr && hydrated && ev.kind == "page" {
                match delivery_envelope(c.tenant, c.run, c.zdr, &ev, Some(c.state.zdr.as_ref())).await {
                    Ok((payload, _)) => payload.to_string(),
                    Err(error) => {
                        tracing::warn!(%error, "event stream ends: delivery content unavailable");
                        return None;
                    }
                }
            } else {
                envelope(c.run, &ev).to_string()
            };
            let event = Event::default().id(ev.seq.to_string()).event(ev.kind).data(data);
            return Some((Ok(event), c));
        }
        if c.finished {
            return None;
        }
        let terminal_run = match c.state.repos.runs.get_metadata(c.run).await {
            Ok(r) => r.status.is_terminal(),
            Err(e) => {
                tracing::debug!(error = %e, run = %c.run, "event stream ends: run unavailable");
                return None;
            }
        };
        let batch = if c.zdr {
            c.state
                .repos
                .events
                .list_metadata_after(c.run, c.after, c.state.settings.sse_batch)
                .await
        } else {
            c.state
                .repos
                .events
                .list_after(c.run, c.after, c.state.settings.sse_batch)
                .await
        };
        match batch {
            Ok(batch) if !batch.is_empty() => c.pending = batch.into(),
            Ok(_) if terminal_run => return None,
            Ok(_) => {
                tokio::select! {
                    () = c.state.shutdown.cancelled() => return None,
                    () = tokio::time::sleep(c.state.settings.sse_poll_interval) => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, run = %c.run, "event stream ends: list failed");
                return None;
            }
        }
    }
}

/// `GET /v1/crawls/{id}/events`, resumable with `Last-Event-ID` or `?after=`.
///
/// # Errors
/// `403` without `crawls:read`, `404` for an unknown run, `400` for a malformed resume
/// position and `429 too_many_streams` above 50 open streams per tenant or 5 per run.
pub async fn events(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let from_header = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let after = match (from_header, params.get("after")) {
        (Some(h), _) => h
            .parse::<u64>()
            .map_err(|_| HttpError::malformed("Last-Event-ID must be an event sequence number"))?,
        (None, Some(a)) => a
            .parse::<u64>()
            .map_err(|_| HttpError::malformed("after must be an event sequence number"))?,
        (None, None) => 0,
    };
    let types = params.get("types").map(|t| {
        t.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    });
    let permit = state.streams.acquire(principal.tenant, run.id)?;
    let keepalive = state.settings.sse_keepalive;
    let cursor = Cursor {
        _permit: permit,
        state,
        run: run.id,
        tenant: principal.tenant,
        zdr: run.retention.mode == RetentionMode::Zdr,
        after,
        types,
        pending: VecDeque::new(),
        finished: false,
    };
    let stream = futures::stream::unfold(cursor, next_event);
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(keepalive).text("ping"))
        .into_response())
}
