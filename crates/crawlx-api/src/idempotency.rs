//! `Idempotency-Key` handling: scope `(tenant, key)`, request hash =
//! BLAKE3(method + path + canonical JSON body), 24 h retention.
//!
//! First use claims the key, runs the handler, stores the response. A repeat with the same
//! hash returns the stored response with `Idempotent-Replayed: true`; a different hash is
//! `422 idempotency_key_reuse`; a concurrent repeat is `409 idempotency_in_progress`.
//! Failed handlers (any error) release the key so the client can retry. A handler that creates
//! one run ([`idempotent_job`]) announces the run's id on the claim, so those two refusals can
//! name the job of the original request.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::state::AppState;
use crate::store::{IdemBegin, StoredResponse};
use crate::util::{json_response, request_hash};
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use crawlx_core::CrawlRunId;
use serde_json::Value;
use std::future::Future;

/// A handler's successful result.
pub struct Reply {
    /// Status the client receives and a replay repeats.
    pub status: StatusCode,
    /// JSON body the client receives and a replay repeats.
    pub body: Value,
    /// Run the response is about (links the key to the run for purge and `Location`).
    pub run_id: Option<CrawlRunId>,
    /// Value of the `Location` header, if the response carries one.
    pub location: Option<String>,
}

impl Reply {
    /// A reply with `status` and JSON `body`, no run link and no `Location`.
    #[must_use]
    pub fn new(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            body,
            run_id: None,
            location: None,
        }
    }

    /// Link the reply to `run` so the key is purged with the run.
    #[must_use]
    pub fn for_run(mut self, run: CrawlRunId) -> Self {
        self.run_id = Some(run);
        self
    }

    /// Set the `Location` header.
    #[must_use]
    pub fn at(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }
}

fn reply_response(status: StatusCode, body: &Value, location: Option<&str>) -> Response {
    let mut resp = json_response(status, body);
    if let Some(loc) = location {
        if let Ok(v) = HeaderValue::from_str(loc) {
            resp.headers_mut().insert(header::LOCATION, v);
        }
    }
    resp
}

fn replay_response(s: &StoredResponse) -> Response {
    let status = StatusCode::from_u16(s.status).unwrap_or(StatusCode::OK);
    let mut resp = json_response(status, &s.body);
    if let (StatusCode::ACCEPTED, Some(run)) = (status, s.run_id) {
        if let Ok(v) = HeaderValue::from_str(&format!("/v1/crawls/{run}")) {
            resp.headers_mut().insert(header::LOCATION, v);
        }
    }
    resp.headers_mut().insert(
        HeaderName::from_static("idempotent-replayed"),
        HeaderValue::from_static("true"),
    );
    resp
}

/// Run `f` under idempotency key `key` (no key: just run it).
///
/// # Errors
/// `422 idempotency_key_reuse` for a key used with a different body, `409
/// idempotency_in_progress` for a still-running key, storage failures, plus whatever `f` returns.
pub async fn idempotent<F, Fut>(
    state: &AppState,
    principal: &Principal,
    key: Option<String>,
    method: &str,
    path: &str,
    body: &Value,
    f: F,
) -> ApiResult<Response>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ApiResult<Reply>>,
{
    claimed(state, principal, key, method, path, body, None, f).await
}

/// As [`idempotent`] for a handler that creates one run. The id of that run is chosen up front,
/// stored on the claim and handed to `f`, which must create the run under it: a repeat that
/// arrives while `f` is still running is refused with the errors of [`idempotent`] carrying that
/// id ([`HttpError::job_id`]), so the client can tell which job the original request is about.
///
/// # Errors
/// As [`idempotent`].
pub async fn idempotent_job<F, Fut>(
    state: &AppState,
    principal: &Principal,
    key: Option<String>,
    method: &str,
    path: &str,
    body: &Value,
    f: F,
) -> ApiResult<Response>
where
    F: FnOnce(CrawlRunId) -> Fut,
    Fut: Future<Output = ApiResult<Reply>>,
{
    let job = CrawlRunId::new();
    claimed(state, principal, key, method, path, body, Some(job), || f(job)).await
}

/// The run `key`'s claim is about, for the error of a refused repeat (`job` set: the handler
/// announced one). Failing to read it leaves the error without an id.
async fn name_job(
    state: &AppState,
    principal: &Principal,
    key: &str,
    announced: bool,
    e: HttpError,
) -> HttpError {
    if !announced {
        return e;
    }
    match state.repos.api.idem_run(principal.tenant, key).await {
        Ok(Some(run)) => e.with_job_id(run),
        Ok(None) => e,
        Err(err) => {
            tracing::warn!(error = %err, "could not read the run of an idempotency claim");
            e
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn claimed<F, Fut>(
    state: &AppState,
    principal: &Principal,
    key: Option<String>,
    method: &str,
    path: &str,
    body: &Value,
    job: Option<CrawlRunId>,
    f: F,
) -> ApiResult<Response>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ApiResult<Reply>>,
{
    let Some(key) = key else {
        return f()
            .await
            .map(|r| reply_response(r.status, &r.body, r.location.as_deref()));
    };
    let api = &state.repos.api;
    let hash = request_hash(method, path, body);
    match api
        .idem_begin(principal.tenant, &key, hash, state.clock.now())
        .await?
    {
        IdemBegin::Started => {}
        IdemBegin::Replay(stored) => return Ok(replay_response(&stored)),
        IdemBegin::InProgress => {
            let e = HttpError::idempotency_in_progress();
            return Err(name_job(state, principal, &key, job.is_some(), e).await);
        }
        IdemBegin::Mismatch => {
            let e = HttpError::idempotency_key_reuse();
            return Err(name_job(state, principal, &key, job.is_some(), e).await);
        }
    }
    if let Some(run) = job {
        if let Err(link) = api.idem_link_run(principal.tenant, &key, run).await {
            if let Err(e) = api.idem_release(principal.tenant, &key).await {
                tracing::error!(error = %e, "could not release idempotency key");
            }
            return Err(link.into());
        }
    }
    match f().await {
        Ok(reply) => {
            let stored = StoredResponse {
                status: reply.status.as_u16(),
                body: reply.body,
                run_id: reply.run_id,
            };
            if let Err(e) = api.idem_complete(principal.tenant, &key, &stored).await {
                tracing::error!(error = %e, "could not store idempotent response");
                if let Err(e) = api.idem_release(principal.tenant, &key).await {
                    tracing::error!(error = %e, "could not release idempotency key");
                }
            }
            Ok(reply_response(
                reply.status,
                &stored.body,
                reply.location.as_deref(),
            ))
        }
        Err(e) => {
            if let Err(e) = api.idem_release(principal.tenant, &key).await {
                tracing::error!(error = %e, "could not release idempotency key");
            }
            Err(e)
        }
    }
}
