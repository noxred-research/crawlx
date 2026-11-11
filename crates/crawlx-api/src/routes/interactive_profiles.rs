//! Authenticated local profile creation, using the worker's shared actor registry.
//!
//! The capability is unavailable in a separately deployed API process. Every mutation
//! requires bearer authentication, an exact operator-configured loopback Origin and
//! Host, and a non-simple CSRF header. The UI accepts credential references only; login
//! secrets, browser control ports and raw browser frames never enter API responses.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Extension;
use base64::Engine as _;
use crawlx_core::CrawlRunId;
use crawlx_worker::interactive_profiles::{
    InteractiveError, InteractiveProfiles, InteractiveScope, InteractiveStart, ProfileInput,
};
use sha2::{Digest as _, Sha256};

pub(crate) fn interactive_error(error: InteractiveError) -> HttpError {
    match error {
        InteractiveError::Invalid => HttpError::malformed("invalid interactive control request"),
        InteractiveError::Busy => HttpError::invalid_state("another interactive operation is in flight"),
        InteractiveError::Refused => HttpError::invalid_state("interactive operation refused by live policy"),
        _ => HttpError::not_found("interactive session"),
    }
}

pub(crate) fn registry(state: &AppState) -> Result<&InteractiveProfiles, HttpError> {
    if !state.config.bind.ip().is_loopback() {
        return Err(HttpError::invalid_state(
            "interactive profiles require a loopback API listener",
        ));
    }
    state
        .interactive_profiles
        .as_deref()
        .ok_or_else(|| {
            HttpError::invalid_state(
                "local interactive worker capability is not configured: it exists only when the API and the worker run in one process and share the registry; `crawlx serve` with a separate `crawlx worker` does not provide it",
            )
        })
}

fn validate_origin(expected: &url::Url, headers: &HeaderMap) -> Result<(), HttpError> {
    let origin = expected.origin().ascii_serialization();
    let host = origin.split_once("://").map(|(_, host)| host).unwrap_or_default();
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) != Some(origin.as_str())
        || headers.get_all(header::HOST).iter().count() != 1
        || headers.get(header::HOST).and_then(|h| h.to_str().ok()) != Some(host)
        || headers.get_all("x-crawlx-interactive").iter().count() != 1
        || headers.get("x-crawlx-interactive").and_then(|h| h.to_str().ok()) != Some("1")
        || headers
            .get("sec-fetch-site")
            .is_some_and(|value| value != "same-origin")
    {
        return Err(HttpError::scope_missing("interactive:same-origin"));
    }
    Ok(())
}

pub(crate) fn check_origin(state: &AppState, headers: &HeaderMap) -> Result<(), HttpError> {
    validate_origin(registry(state)?.origin(), headers)
}

pub(crate) fn request_scope(
    principal: &Principal,
    run: CrawlRunId,
    session: &str,
    params: &Params,
) -> Result<InteractiveScope, HttpError> {
    let session = session
        .parse()
        .map_err(|_| HttpError::not_found("interactive session"))?;
    let generation = params
        .get("generation")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| HttpError::malformed("positive generation is required"))?;
    let fence = params
        .get("leaseFence")
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| HttpError::malformed("positive leaseFence is required"))?;
    Ok(InteractiveScope::new(
        principal.tenant,
        run,
        session,
        generation,
        fence,
        principal.actor(),
    ))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

/// Start an explicitly consented local profile workflow on a registered fresh actor.
///
/// # Errors
/// Requires crawls:write, exact same-origin headers, a tenant-owned run, current
/// generation/fence, explicit privacy/retention consent and live worker authorization.
pub async fn start(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, session)): Path<(String, String)>,
    headers: HeaderMap,
    params: Params,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    check_origin(&state, &headers)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let scope = request_scope(&principal, run.id, &session, &params)?;
    let request: InteractiveStart =
        serde_json::from_value(body).map_err(|_| HttpError::malformed("invalid interactive start body"))?;
    let status = registry(&state)?
        .start(&scope, request)
        .await
        .map_err(interactive_error)?;
    Ok(no_store(json_response(
        StatusCode::OK,
        &serde_json::to_value(status)
            .map_err(|_| HttpError::invalid_state("interactive status encoding failed"))?,
    )))
}

/// Inspect structural workflow status after a fresh worker lease/authorization check.
///
/// # Errors
/// Returns refusal for missing scope, foreign ownership, stale generation/fence,
/// expiry or unavailable local worker; never returns profile or browser contents.
pub async fn status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, session)): Path<(String, String)>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    check_origin(&state, &headers)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let scope = request_scope(&principal, run.id, &session, &params)?;
    let status = registry(&state)?
        .status(&scope)
        .await
        .map_err(interactive_error)?;
    Ok(no_store(json_response(
        StatusCode::OK,
        &serde_json::to_value(status)
            .map_err(|_| HttpError::invalid_state("interactive status encoding failed"))?,
    )))
}

/// Submit one allowlisted, reference-only input through normal actor safety admission.
///
/// # Errors
/// Returns refusal for stale ownership or missing consent, malformed input,
/// secret-registration failure, unsafe actions or exhausted budgets.
pub async fn input(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, session)): Path<(String, String)>,
    headers: HeaderMap,
    params: Params,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    check_origin(&state, &headers)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let scope = request_scope(&principal, run.id, &session, &params)?;
    let input: ProfileInput =
        serde_json::from_value(body).map_err(|_| HttpError::malformed("invalid typed profile input"))?;
    let status = registry(&state)?
        .input(&scope, input)
        .await
        .map_err(interactive_error)?;
    Ok(no_store(json_response(
        StatusCode::OK,
        &serde_json::to_value(status)
            .map_err(|_| HttpError::invalid_state("interactive status encoding failed"))?,
    )))
}

/// Commit bounded structured state through encrypted custody, then confirm actor cleanup.
///
/// # Errors
/// Returns refusal for stale authority/generation, incomplete export, custody failure
/// or unconfirmed resource death. A failed finish never reports a saved profile.
pub async fn finish(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, session)): Path<(String, String)>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    check_origin(&state, &headers)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let scope = request_scope(&principal, run.id, &session, &params)?;
    let status = registry(&state)?
        .finish(&scope)
        .await
        .map_err(interactive_error)?;
    Ok(no_store(json_response(
        StatusCode::OK,
        &serde_json::to_value(status)
            .map_err(|_| HttpError::invalid_state("interactive status encoding failed"))?,
    )))
}

/// Revoke input/capture immediately; actor cancellation performs owned cleanup.
///
/// # Errors
/// Returns refusal for missing scope, foreign ownership or stale generation/fence.
pub async fn cancel(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, session)): Path<(String, String)>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    check_origin(&state, &headers)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let scope = request_scope(&principal, run.id, &session, &params)?;
    let status = registry(&state)?.cancel(&scope).map_err(interactive_error)?;
    Ok(no_store(json_response(
        StatusCode::OK,
        &serde_json::to_value(status)
            .map_err(|_| HttpError::invalid_state("interactive status encoding failed"))?,
    )))
}

const UI_SCRIPT: &str = r#"'use strict';
let token = '';
const field = id => document.getElementById(id);
const output = field('result');
async function control(operation, body) {
  token = field('token').value || token;
  field('token').value = '';
  const run = encodeURIComponent(field('run').value);
  const session = encodeURIComponent(field('session').value);
  const query = new URLSearchParams({generation:field('generation').value, leaseFence:field('fence').value});
  const endpoint = `/v1/crawls/${run}/interactive-profiles/${session}/${operation}?${query}`;
  try {
    const response = await fetch(endpoint, {method:'POST', credentials:'omit', cache:'no-store', redirect:'error',
      headers:{Authorization:`Bearer ${token}`, 'Content-Type':'application/json', 'X-CrawlX-Interactive':'1'},
      body:body === undefined ? undefined : JSON.stringify(body)});
    const result = await response.json();
    output.textContent = response.ok ? JSON.stringify(result, null, 2) : (result.error?.code || 'refused');
  } catch (_) { output.textContent = 'unavailable'; }
}
field('start').addEventListener('click', () => control('start', {
  profileName:field('profile').value, expectedGeneration:Number(field('expected').value),
  ttlSeconds:Number(field('ttl').value), retainedProfileConsent:field('retain').checked,
  privacyConsent:field('privacy').checked, captureConsent:field('capture').checked}));
field('status').addEventListener('click', () => control('status'));
field('finish').addEventListener('click', () => control('finish'));
field('cancel').addEventListener('click', () => { control('cancel'); token = ''; });
field('activate').addEventListener('click', () => control('input', {kind:'activate',selector:field('selector').value}));
field('type').addEventListener('click', () => control('input', {
  kind:'type_secret',selector:field('selector').value,credential:field('credential').value}));
"#;

const UI_BODY: &str = r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CrawlX local profile</title><main><h1>Local profile creation</h1>
<p>Use only an operator-approved fresh local session. Browser pixels remain suppressed when privacy cannot be proven. No login secret value is accepted here.</p>
<fieldset><legend>Authenticated session</legend>
<label>API bearer key <input id="token" type="password" autocomplete="off"></label>
<label>Run <input id="run" autocomplete="off" required></label>
<label>Session <input id="session" autocomplete="off" required></label>
<label>Browser generation <input id="generation" type="number" min="1" value="1"></label>
<label>Lease fence <input id="fence" type="number" min="1"></label></fieldset>
<fieldset><legend>Encrypted structured profile</legend>
<label>Profile name <input id="profile" maxlength="128" required></label>
<label>Expected saved generation <input id="expected" type="number" min="0" value="0"></label>
<label>Lifetime seconds <input id="ttl" type="number" min="1" max="300" value="300"></label>
<label><input id="retain" type="checkbox">I approve encrypted profile retention.</label>
<label><input id="privacy" type="checkbox">I approve the privacy policy and secret-screen suppression.</label>
<label><input id="capture" type="checkbox">I opt in to ephemeral private capture status.</label>
<button id="start" type="button">Start</button><button id="status" type="button">Status</button>
<button id="finish" type="button">Finish and save</button><button id="cancel" type="button">Cancel and close</button></fieldset>
<fieldset><legend>Typed operator input</legend>
<label>CSS selector <input id="selector" maxlength="2048" autocomplete="off"></label>
<button id="activate" type="button">Request activation</button>
<label>Approved credential reference <input id="credential" maxlength="512" autocomplete="off"></label>
<button id="type" type="button">Request secret fill</button></fieldset>
<h2>Status</h2><pre id="result" role="status" aria-live="polite"></pre></main>"#;

/// Minimal safe local UI; it stores bearer credentials in memory only and accepts
/// credential references instead of login secret values.
///
/// # Errors
/// Requires a configured shared local worker registry and exact loopback Host.
/// The static shell contains no run/session data; every control call authenticates.
pub async fn ui(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let expected = registry(&state)?.origin().origin().ascii_serialization();
    let expected_host = expected
        .split_once("://")
        .map(|(_, host)| host)
        .unwrap_or_default();
    if headers.get(header::HOST).and_then(|value| value.to_str().ok()) != Some(expected_host) {
        return Err(HttpError::scope_missing("interactive:local-host"));
    }
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(UI_SCRIPT.as_bytes()));
    let policy = format!(
        "default-src 'none'; script-src 'sha256-{hash}'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
    let mut response =
        no_store(Html(format!("{UI_BODY}<script>{UI_SCRIPT}</script></html>")).into_response());
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy)
            .map_err(|_| HttpError::invalid_state("interactive UI policy unavailable"))?,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, HeaderValue::from_static("http://127.0.0.1:8080"));
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
        headers.insert("x-crawlx-interactive", HeaderValue::from_static("1"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        headers
    }

    #[test]
    fn exact_origin_host_and_non_simple_csrf_header_are_required() {
        let expected = url::Url::parse("http://127.0.0.1:8080/").unwrap();
        assert!(validate_origin(&expected, &headers()).is_ok());
        for name in ["origin", "host", "x-crawlx-interactive"] {
            let mut request = headers();
            request.remove(name);
            assert!(validate_origin(&expected, &request).is_err());
        }
        for (name, value) in [
            ("origin", "http://127.0.0.1:8081"),
            ("origin", "null"),
            ("host", "untrusted.test:8080"),
            ("sec-fetch-site", "cross-site"),
            ("x-crawlx-interactive", "0"),
        ] {
            let mut request = headers();
            request.insert(name, HeaderValue::from_str(value).unwrap());
            assert!(validate_origin(&expected, &request).is_err());
        }
        let mut duplicate = headers();
        duplicate.append(header::ORIGIN, HeaderValue::from_static("http://127.0.0.1:8080"));
        assert!(validate_origin(&expected, &duplicate).is_err());
    }

    #[test]
    fn ui_never_uses_secret_values_raw_control_ports_or_persistent_credentials() {
        assert!(UI_SCRIPT.contains("credentials:'omit'"));
        assert!(UI_SCRIPT.contains("redirect:'error'"));
        assert!(UI_SCRIPT.contains("textContent"));
        for forbidden in [
            "localStorage",
            "sessionStorage",
            "innerHTML",
            "eval(",
            "devtools",
            "ws://",
        ] {
            assert!(!UI_SCRIPT.contains(forbidden));
        }
        assert!(UI_BODY.contains("Approved credential reference"));
        assert!(UI_BODY.contains("aria-live=\"polite\""));
    }
}
