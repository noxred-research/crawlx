//! `POST /search/{jobId}/feedback` and `POST /feedback`: validated, stored per tenant and job
//! (`tenant_settings` key `feedback/<endpoint>/<jobId>`), idempotent per job. crawlx has no
//! billing, so `creditsRefunded` is always 0.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::request::{is_http_url, Body};
use crate::state::AppState;
use serde_json::{json, Value};
use uuid::Uuid;

const ENDPOINTS: [&str; 4] = ["search", "scrape", "parse", "map"];
const RATINGS: [&str; 3] = ["good", "partial", "bad"];

fn label_ok(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        && s.len() <= 80
}

/// Validate the feedback body of `endpoint` (`search` for the per-job route).
fn validate(body: &Value, endpoint: &str) -> ApiResult<()> {
    let mut b = Body::new(body)?;
    let rating = b.string("rating", 16);
    match &rating {
        Some(r) if RATINGS.contains(&r.as_str()) => {}
        Some(_) => b.fail("rating", "invalid", "expected good, partial or bad"),
        None => {
            if b.raw("rating").is_none() {
                b.fail("rating", "required", "rating is required");
            }
        }
    }
    let list_len = |b: &mut Body<'_>, key: &str, max: usize| -> usize {
        match b.array(key) {
            Some(items) if items.len() > max => {
                b.fail(key, "out_of_range", format!("at most {max} items"));
                0
            }
            Some(items) => items.len(),
            None => 0,
        }
    };
    let sources = b.array("valuableSources").map_or(0, <[Value]>::len);
    if let Some(items) = b.array("valuableSources") {
        for (i, item) in items.iter().enumerate() {
            if !item.get("url").and_then(Value::as_str).is_some_and(is_http_url) {
                b.fail(
                    &format!("valuableSources/{i}/url"),
                    "invalid",
                    "expected an absolute URL",
                );
            }
        }
        if items.len() > 50 {
            b.fail("valuableSources", "out_of_range", "at most 50 items");
        }
    }
    let results = list_len(&mut b, "valuableResults", 50);
    if let Some(items) = b.array("valuableResults") {
        for (i, item) in items.iter().enumerate() {
            let source_ok = item
                .get("source")
                .and_then(Value::as_str)
                .is_some_and(|s| matches!(s, "web" | "images" | "news"));
            let position_ok = item
                .get("position")
                .and_then(Value::as_u64)
                .is_some_and(|p| (1..=100).contains(&p));
            if !source_ok || !position_ok {
                b.fail(
                    &format!("valuableResults/{i}"),
                    "invalid",
                    "expected {source: web|images|news, position: 1..100}",
                );
            }
        }
    }
    let missing = list_len(&mut b, "missingContent", 50);
    if let Some(items) = b.array("missingContent") {
        for (i, item) in items.iter().enumerate() {
            let ok = item
                .get("topic")
                .and_then(Value::as_str)
                .is_some_and(|t| !t.is_empty() && t.chars().count() <= 200);
            if !ok {
                b.fail(
                    &format!("missingContent/{i}/topic"),
                    "invalid",
                    "expected a topic of 1 to 200 characters",
                );
            }
        }
    }
    let suggestions = b
        .string("querySuggestions", 2000)
        .is_some_and(|s| !s.trim().is_empty());
    let note = b.string("note", 4000).is_some_and(|s| !s.trim().is_empty());
    let mut issues = 0;
    for key in ["issues", "tags"] {
        if let Some(items) = b.strings(key, 20, 80) {
            for (i, item) in items.iter().enumerate() {
                if !label_ok(item) {
                    b.fail(
                        &format!("{key}/{i}"),
                        "invalid",
                        "expected lowercase letters, digits, `_` or `-`",
                    );
                }
            }
            if key == "issues" {
                issues = items.len();
            }
        }
    }
    let url = b.string("url", 2048);
    if url.as_deref().is_some_and(|u| !is_http_url(u)) {
        b.fail("url", "invalid", "expected an absolute URL");
    }
    let pages = b.array("pageNumbers").map_or(0, <[Value]>::len);
    if let Some(m) = b.object("metadata") {
        if m.to_string().len() > 8 * 1024 {
            b.fail("metadata", "out_of_range", "metadata must be 8 KiB or smaller");
        }
    }
    if let Some(r) = rating.as_deref() {
        let enough = match r {
            "good" => sources + results > 0,
            "partial" => sources + results + missing > 0,
            _ => missing > 0 || suggestions,
        };
        let generic = issues > 0 || note || url.is_some() || pages > 0;
        if !enough && !(endpoint != "search" && generic) {
            let need = match r {
                "good" => "valuableSources or valuableResults",
                "partial" => "valuableSources, valuableResults or missingContent",
                _ => "missingContent or querySuggestions",
            };
            b.fail("rating", "required", format!("a {r} rating needs {need}"));
        }
    }
    b.finish()
}

/// Store feedback for `job` of `endpoint` and answer the `FeedbackResponse` object.
///
/// # Errors
/// `404 not_found` when the tenant has no ledger row for `job`, `422` for an invalid body.
pub async fn submit(
    state: &AppState,
    principal: &Principal,
    endpoint: &str,
    job: Uuid,
    body: &Value,
) -> ApiResult<Value> {
    validate(body, endpoint)?;
    let tenant = principal.tenant;
    if state.repos.intel.usage_by_ref(tenant, job).await?.is_none() {
        return Err(HttpError::not_found("job"));
    }
    let key = format!("feedback/{endpoint}/{job}");
    if let Some(existing) = state.repos.intel.setting_get(tenant, &key).await? {
        let id = existing.get("feedbackId").cloned().unwrap_or(Value::Null);
        return Ok(json!({
            "success": true,
            "feedbackId": id,
            "creditsRefunded": 0,
            "alreadySubmitted": true,
        }));
    }
    let feedback_id = Uuid::now_v7();
    let now = state.clock.now();
    state
        .repos
        .intel
        .setting_put(
            tenant,
            &key,
            json!({
                "feedbackId": feedback_id,
                "endpoint": endpoint,
                "jobId": job,
                "createdAt": crate::util::ts(now),
                "feedback": body,
            }),
            now,
        )
        .await?;
    Ok(json!({
        "success": true,
        "feedbackId": feedback_id,
        "creditsRefunded": 0,
    }))
}

/// `POST /feedback` body: `endpoint` and `jobId` plus the shared feedback fields.
///
/// # Errors
/// `422` when `endpoint` or `jobId` is missing or malformed.
pub fn endpoint_and_job(body: &Value) -> ApiResult<(String, Uuid)> {
    let mut b = Body::new(body)?;
    let endpoint = b.required_string("endpoint", 16);
    let job = b.required_string("jobId", 64);
    if let Some(e) = &endpoint {
        if !ENDPOINTS.contains(&e.as_str()) {
            b.fail("endpoint", "invalid", "expected search, scrape, parse or map");
        }
    }
    let parsed = job.as_deref().map(Uuid::parse_str);
    if let Some(Err(_)) = parsed {
        b.fail("jobId", "invalid", "expected a UUID");
    }
    b.finish()?;
    match (endpoint, parsed) {
        (Some(e), Some(Ok(j))) => Ok((e, j)),
        _ => Err(HttpError::validation(vec![Detail::new(
            "/",
            "required",
            "endpoint and jobId are required",
        )])),
    }
}
