//! `POST /v1/crawls/{id}/sessions/{session}/screencast`: volatile status SSE.
//!
//! The live registry authorizes the exact tenant/run/session/generation/fence and
//! API-key owner before handing out a bounded receiver. This endpoint does not
//! use the durable event journal, event IDs, artifacts, or replay. Ordinary page
//! pixels have no full-frame privacy proof, so only suppression statuses flow;
//! consent is not a claim that pixels are safe. No screenshot is requested.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::routes::interactive_profiles::{check_origin, interactive_error, registry, request_scope};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Consents {
    capture_consent: bool,
    privacy_consent: bool,
}

fn consents(body: Value) -> ApiResult<Consents> {
    let consent: Consents = serde_json::from_value(body).map_err(|_| {
        HttpError::malformed("captureConsent and privacyConsent must be explicit JSON booleans")
    })?;
    if !consent.capture_consent || !consent.privacy_consent {
        return Err(HttpError::malformed(
            "captureConsent and privacyConsent must both be true",
        ));
    }
    Ok(consent)
}

fn reject_replay(headers: &HeaderMap, params: &Params) -> ApiResult<()> {
    if headers.contains_key("last-event-id") || params.get("after").is_some() {
        return Err(HttpError::malformed("screencast streams do not support replay"));
    }
    Ok(())
}

/// Subscribe to a live, owner-bound session's ephemeral suppression statuses.
///
/// Requires `crawls:write`, exact configured Origin, `x-crawlx-interactive: 1`,
/// allowed fetch-site metadata, `generation`/`leaseFence` query values, and explicit
/// JSON `{ "captureConsent": true, "privacyConsent": true }`. Each connection
/// starts empty. Slow consumers, actor cancellation, disconnect, and TTL end it.
///
/// # Errors
/// Returns authentication/scope, Origin/CSRF, run visibility, malformed consent,
/// lease/session ownership, expiry, concurrent-subscription, or stream quota errors.
/// A disabled local interactive registry returns service unavailable.
pub(crate) async fn subscribe(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, session)): Path<(String, String)>,
    headers: HeaderMap,
    params: Params,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    check_origin(&state, &headers)?;
    reject_replay(&headers, &params)?;
    let consent = consents(body)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let scope = request_scope(&principal, run.id, &session, &params)?;
    let permit = state.streams.acquire(principal.tenant, run.id)?;
    let receiver = registry(&state)?
        .subscribe(&scope, consent.capture_consent, consent.privacy_consent)
        .await
        .map_err(interactive_error)?;
    let stream = futures::stream::unfold((receiver, permit), |(mut receiver, permit)| async move {
        let event = receiver.recv().await?;
        Some((
            Event::default().event("suppressed").json_data(event),
            (receiver, permit),
        ))
    });
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(state.settings.sse_keepalive)
                .text("ping"),
        )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn explicit_capture_and_privacy_consent_are_both_required() {
        assert!(consents(json!({"captureConsent": true, "privacyConsent": true})).is_ok());
        for body in [
            Value::Null,
            json!({}),
            json!({"captureConsent": true}),
            json!({"privacyConsent": true}),
            json!({"captureConsent": false, "privacyConsent": true}),
            json!({"captureConsent": true, "privacyConsent": false}),
            json!({"captureConsent": "true", "privacyConsent": true}),
            json!({"captureConsent": true, "privacyConsent": true, "safe": true}),
        ] {
            assert!(consents(body).is_err());
        }
    }

    #[test]
    fn ephemeral_stream_refuses_every_resume_position() {
        let params = Params(BTreeMap::new());
        let mut headers = HeaderMap::new();
        assert!(reject_replay(&headers, &params).is_ok());
        headers.insert("last-event-id", HeaderValue::from_static(""));
        assert!(reject_replay(&headers, &params).is_err());
        headers.clear();
        let params = Params(BTreeMap::from([("after".to_owned(), "0".to_owned())]));
        assert!(reject_replay(&headers, &params).is_err());
    }
}
