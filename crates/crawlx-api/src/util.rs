//! Small shared helpers: timestamps, canonical JSON, cursors, query and body extractors,
//! the request-id/error-envelope middleware.

use crate::config::Settings;
use crate::errors::{ErrorParts, HttpError};
use crate::state::AppState;
use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use crawlx_core::hash::Digest;
use crawlx_core::Timestamp;
use serde_json::Value;
use std::collections::BTreeMap;
use tracing::Instrument as _;
use uuid::Uuid;

/// RFC 3339 UTC with milliseconds.
#[must_use]
pub fn ts(t: Timestamp) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Optional timestamp as JSON.
#[must_use]
pub fn ts_opt(t: Option<Timestamp>) -> Value {
    t.map_or(Value::Null, |t| Value::String(ts(t)))
}

/// Canonical JSON: object keys sorted, no insignificant whitespace.
#[must_use]
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<&String, &Value> = m.iter().collect();
            out.push('{');
            for (i, (k, val)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, val) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(val, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// BLAKE3 of `method`, `path` and the canonical body.
#[must_use]
pub fn request_hash(method: &str, path: &str, body: &Value) -> Digest {
    let mut h = blake3::Hasher::new_derive_key("crawlx/api/idempotency/v1");
    h.update(method.as_bytes());
    h.update(&[0]);
    h.update(path.as_bytes());
    h.update(&[0]);
    h.update(canonical_json(body).as_bytes());
    Digest(*h.finalize().as_bytes())
}

// ---- cursors -------------------------------------------------------------

/// Opaque cursor for sort key `key`: base64url(key ‖ 4-byte checksum).
#[must_use]
pub fn encode_cursor(key: &str) -> String {
    let mut bytes = key.as_bytes().to_vec();
    bytes.extend_from_slice(&checksum(key));
    URL_SAFE_NO_PAD.encode(bytes)
}

fn checksum(key: &str) -> [u8; 4] {
    let h = blake3::hash(key.as_bytes());
    let mut c = [0u8; 4];
    c.copy_from_slice(&h.as_bytes()[..4]);
    c
}

/// Decode a cursor.
///
/// # Errors
/// `400 malformed_request` for tampered cursors.
pub fn decode_cursor(cursor: &str) -> Result<String, HttpError> {
    let bad = || HttpError::malformed("invalid cursor");
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| bad())?;
    if bytes.len() < 4 {
        return Err(bad());
    }
    let (key, sum) = bytes.split_at(bytes.len() - 4);
    let key = std::str::from_utf8(key).map_err(|_| bad())?;
    if checksum(key) != sum {
        return Err(bad());
    }
    Ok(key.to_owned())
}

/// Query parameters as a sorted map.
pub struct Params(pub BTreeMap<String, String>);

impl Params {
    /// The value of query parameter `k`, if present.
    #[must_use]
    pub fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }

    /// `?limit=` clamped to `1..=max` (default `default_page_limit`).
    ///
    /// # Errors
    /// `400` when `limit` is not a positive integer.
    pub fn limit(&self, s: &Settings) -> Result<usize, HttpError> {
        match self.get("limit") {
            None => Ok(s.default_page_limit),
            Some(v) => match v.parse::<usize>() {
                Ok(n) if n >= 1 => Ok(n.min(s.max_page_limit)),
                _ => Err(HttpError::malformed("limit must be a positive integer")),
            },
        }
    }

    /// Decoded `?cursor=` sort key.
    ///
    /// # Errors
    /// `400` for tampered cursors.
    pub fn cursor_key(&self) -> Result<Option<String>, HttpError> {
        self.get("cursor").map(decode_cursor).transpose()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Params {
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let mut m = BTreeMap::new();
        if let Some(q) = parts.uri.query() {
            for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
                m.entry(k.into_owned()).or_insert_with(|| v.into_owned());
            }
        }
        Ok(Self(m))
    }
}

/// One page of `items` (already sorted by key, ascending) after `cursor_key`.
/// Returns the page and the key of its last item when more remain.
#[must_use]
pub fn paginate<T>(
    items: Vec<(String, T)>,
    limit: usize,
    cursor_key: Option<&str>,
) -> (Vec<T>, Option<String>) {
    let mut rest: Vec<(String, T)> = match cursor_key {
        Some(c) => items.into_iter().filter(|(k, _)| k.as_str() > c).collect(),
        None => items,
    };
    let more = rest.len() > limit;
    rest.truncate(limit);
    let last = rest.last().map(|(k, _)| k.clone());
    (
        rest.into_iter().map(|(_, v)| v).collect(),
        if more { last } else { None },
    )
}

/// `next` link carrying the original query minus `cursor`.
#[must_use]
pub fn next_link(path: &str, params: &Params, next_key: Option<&str>) -> Value {
    let Some(k) = next_key else {
        return Value::Null;
    };
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in &params.0 {
        if name != "cursor" {
            ser.append_pair(name, value);
        }
    }
    ser.append_pair("cursor", &encode_cursor(k));
    Value::String(format!("{path}?{}", ser.finish()))
}

// ---- body ----------------------------------------------------------------

/// Parsed JSON request body, capped at `Settings::max_body_bytes`. An empty body is `null`.
pub struct JsonBody(pub Value);

impl FromRequest<AppState> for JsonBody {
    type Rejection = HttpError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let limit = state.settings.max_body_bytes;
        let bytes = axum::body::to_bytes(req.into_body(), limit)
            .await
            .map_err(|_| HttpError::payload_too_large(limit))?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self(Value::Null));
        }
        serde_json::from_slice(&bytes)
            .map(Self)
            .map_err(|e| HttpError::malformed(format!("body is not valid JSON: {e}")))
    }
}

/// `Idempotency-Key` (or the Firecrawl alias) when present and valid.
///
/// # Errors
/// `422 validation_failed` for keys outside 1..=255 printable ASCII characters.
pub fn idempotency_key(headers: &axum::http::HeaderMap, alias: bool) -> Result<Option<String>, HttpError> {
    let raw = headers.get("idempotency-key").or_else(|| {
        if alias {
            headers.get("x-idempotency-key")
        } else {
            None
        }
    });
    let Some(raw) = raw else {
        return Ok(None);
    };
    let ok = raw
        .to_str()
        .ok()
        .filter(|s| (1..=255).contains(&s.len()) && s.bytes().all(|b| (0x20..0x7f).contains(&b)));
    match ok {
        Some(s) => Ok(Some(s.to_owned())),
        None => Err(HttpError::validation(vec![crate::errors::Detail::new(
            "/headers/Idempotency-Key",
            "out_of_range",
            "Idempotency-Key must be 1 to 255 printable ASCII characters",
        )])),
    }
}

/// JSON response with the given status.
#[must_use]
pub fn json_response(status: StatusCode, body: &Value) -> Response {
    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp
}

// ---- request id / error envelope ------------------------------------------

/// Per-request id (also the envelope's `requestId`).
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Outermost middleware: request id + span, final error envelope, `X-Request-Id`.
pub async fn envelope_layer(mut req: Request, next: Next) -> Response {
    let rid = Uuid::now_v7().to_string();
    let compat = req.uri().path().starts_with("/compat/");
    let traceparent = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    req.extensions_mut().insert(RequestId(rid.clone()));
    let span = tracing::info_span!(
        "http_request",
        request_id = %rid,
        method = %req.method(),
        path = %req.uri().path(),
        traceparent = %traceparent,
    );
    let mut resp = next.run(req).instrument(span).await;
    let parts = resp.extensions().get::<ErrorParts>().cloned();
    let parts = match parts {
        Some(p) => Some(p.0),
        None if resp.status() == StatusCode::METHOD_NOT_ALLOWED => {
            Some(std::sync::Arc::new(HttpError::method_not_allowed()))
        }
        None => None,
    };
    if let Some(e) = parts {
        let body = if compat {
            e.compat_envelope(&rid)
        } else {
            e.envelope(&rid)
        };
        let headers = resp.headers().clone();
        let mut out = json_response(e.status, &body);
        for name in [header::RETRY_AFTER, header::WWW_AUTHENTICATE, header::ALLOW] {
            if let Some(v) = headers.get(&name) {
                out.headers_mut().insert(name, v.clone());
            }
        }
        for (name, v) in &headers {
            if name.as_str().starts_with("ratelimit-") {
                out.headers_mut().insert(name.clone(), v.clone());
            }
        }
        resp = out;
    }
    if let Ok(v) = HeaderValue::from_str(&rid) {
        resp.headers_mut()
            .insert(HeaderName::from_static("x-request-id"), v);
    }
    resp
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let a = json!({"b": 1, "a": {"d": [1, {"z": 1, "y": 2}], "c": null}});
        let b = json!({"a": {"c": null, "d": [1, {"y": 2, "z": 1}]}, "b": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(
            canonical_json(&a),
            r#"{"a":{"c":null,"d":[1,{"y":2,"z":1}]},"b":1}"#
        );
        assert_eq!(request_hash("POST", "/x", &a), request_hash("POST", "/x", &b));
        assert_ne!(request_hash("POST", "/x", &a), request_hash("POST", "/y", &a));
    }

    #[test]
    fn cursor_roundtrip_and_tamper() {
        let c = encode_cursor("00000000000000000042https://a.test/");
        assert_eq!(decode_cursor(&c).unwrap(), "00000000000000000042https://a.test/");
        let mut t = c.clone();
        t.push('A');
        assert!(decode_cursor(&t).is_err());
        assert!(decode_cursor("***").is_err());
        assert!(decode_cursor("").is_err());
    }

    #[test]
    fn pagination_walks_all_items() {
        let items: Vec<(String, u32)> = (0..7).map(|i| (format!("{i:03}"), i)).collect();
        let (p1, n1) = paginate(items.clone(), 3, None);
        assert_eq!(p1, vec![0, 1, 2]);
        let (p2, n2) = paginate(items.clone(), 3, n1.as_deref());
        assert_eq!(p2, vec![3, 4, 5]);
        let (p3, n3) = paginate(items, 3, n2.as_deref());
        assert_eq!(p3, vec![6]);
        assert!(n3.is_none());
    }
}
