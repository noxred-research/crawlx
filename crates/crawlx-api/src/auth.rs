//! API-key authentication, scopes and per-tenant token buckets.

use crate::errors::HttpError;
use crate::state::AppState;
use crate::store::{KeyRecord, Scope};
use axum::body::{Body, HttpBody};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use crawlx_core::{TenantId, Timestamp};
use parking_lot::Mutex;
use rand::RngCore;
use std::collections::{BTreeSet, HashMap};
use std::pin::Pin;
use std::task::{Context, Poll};
use uuid::Uuid;

/// Every key starts with this literal.
pub const KEY_PREFIX: &str = "cx_live_";
/// Firecrawl-style keys start with this literal (`compat.firecrawlKeys`).
pub const FIRECRAWL_KEY_PREFIX: &str = "fc-";
/// Length of the base32 secret part.
pub const SECRET_LEN: usize = 26;
/// Characters of the secret part stored as `api_keys.prefix`.
pub const LOOKUP_LEN: usize = 8;
/// Key cache TTL (revocation takes effect within 30 s).
const KEY_CACHE_TTL_MS: i64 = 30_000;
/// `last_used_at` refresh interval.
const TOUCH_INTERVAL_MS: i64 = 60_000;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A fresh random key: `cx_live_` + 26 base32 characters (130 bits).
#[must_use]
pub fn generate_key() -> String {
    let mut bytes = [0u8; 17];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut bits = 0u32;
    let mut have = 0u32;
    let mut out = String::with_capacity(KEY_PREFIX.len() + SECRET_LEN);
    out.push_str(KEY_PREFIX);
    let mut n = 0;
    for b in bytes {
        bits = (bits << 8) | u32::from(b);
        have += 8;
        while have >= 5 && n < SECRET_LEN {
            have -= 5;
            let idx = ((bits >> have) & 0x1f) as usize;
            out.push(char::from(ALPHABET[idx]));
            n += 1;
        }
        bits &= (1 << have) - 1;
    }
    out
}

/// A fresh random Firecrawl-style key: `fc-` + 32 lowercase hexadecimal characters. It
/// authenticates only when `compat.firecrawlKeys` is on, and only on `/compat/` routes.
#[must_use]
pub fn generate_firecrawl_key() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{FIRECRAWL_KEY_PREFIX}{}", hex::encode(bytes))
}

/// The lookup prefix of a well-formed key, or `None` for anything else.
#[must_use]
pub fn parse_key(token: &str) -> Option<&str> {
    let secret = token.strip_prefix(KEY_PREFIX)?;
    if secret.len() != SECRET_LEN || !secret.bytes().all(|b| ALPHABET.contains(&b)) {
        return None;
    }
    secret.get(..LOOKUP_LEN)
}

/// The lookup prefix of a well-formed `fc-` key (`fc-` + the first [`LOOKUP_LEN`] characters of
/// its secret), or `None` for anything else. The secret is 16 to 64 ASCII alphanumerics
/// (Firecrawl's own keys are 32 hexadecimal characters). The prefix is longer than a
/// `cx_live_` lookup prefix, so the two key families can never collide in `api_keys.prefix`.
#[must_use]
pub fn parse_firecrawl_key(token: &str) -> Option<&str> {
    let secret = token.strip_prefix(FIRECRAWL_KEY_PREFIX)?;
    if !(16..=64).contains(&secret.len()) || !secret.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    token.get(..FIRECRAWL_KEY_PREFIX.len() + LOOKUP_LEN)
}

/// The lookup prefix of `token`: a `cx_live_` key always, an `fc-` key only when
/// `firecrawl_keys` is `true` (`compat.firecrawlKeys`).
#[must_use]
pub fn lookup_prefix(token: &str, firecrawl_keys: bool) -> Option<&str> {
    parse_key(token).or_else(|| firecrawl_keys.then(|| parse_firecrawl_key(token)).flatten())
}

/// BLAKE3-256 of the full key.
#[must_use]
pub fn hash_key(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

/// Build the stored record for the `cx_live_` key `token`; `None` when the key is malformed.
#[must_use]
pub fn key_record(token: &str, tenant: TenantId, scopes: BTreeSet<Scope>) -> Option<KeyRecord> {
    key_record_for(token, tenant, scopes, false)
}

/// As [`key_record`], additionally accepting an `fc-` key when `firecrawl_keys` is `true`
/// (`compat.firecrawlKeys`). The record's `prefix` is [`lookup_prefix`] of the key.
#[must_use]
pub fn key_record_for(
    token: &str,
    tenant: TenantId,
    scopes: BTreeSet<Scope>,
    firecrawl_keys: bool,
) -> Option<KeyRecord> {
    let prefix = lookup_prefix(token, firecrawl_keys)?.to_owned();
    Some(KeyRecord {
        key_id: Uuid::now_v7(),
        tenant,
        prefix,
        hash: hash_key(token),
        scopes,
        expires_at: None,
        revoked: false,
    })
}

/// Tenant id for a bootstrap `tenant` string: a UUID is used as is, a name maps to a
/// deterministic id.
#[must_use]
pub fn tenant_id_for(name: &str) -> TenantId {
    if let Ok(u) = Uuid::parse_str(name) {
        return TenantId(u);
    }
    let h = blake3::Hasher::new_derive_key("crawlx/api/tenant-name/v1")
        .update(name.as_bytes())
        .finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&h.as_bytes()[..16]);
    TenantId(uuid::Builder::from_custom_bytes(b).into_uuid())
}

/// An authenticated caller.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Tenant that owns the key; every query is scoped to it.
    pub tenant: TenantId,
    /// Identifier of the API key row (audit actor, `last_used_at` refresh).
    pub key_id: Uuid,
    /// Scopes the key carries.
    pub scopes: BTreeSet<Scope>,
}

impl Principal {
    /// Fail with `403 scope_missing` unless the key carries `scope`.
    ///
    /// # Errors
    /// [`HttpError::scope_missing`].
    pub fn require(&self, scope: Scope) -> Result<(), HttpError> {
        if self.scopes.contains(&scope) {
            Ok(())
        } else {
            Err(HttpError::scope_missing(scope.as_str()))
        }
    }

    /// Audit actor string.
    #[must_use]
    pub fn actor(&self) -> String {
        format!("api_key:{}", self.key_id)
    }
}

struct CachedKey {
    record: KeyRecord,
    fetched_ms: i64,
    touched_ms: i64,
}

/// 30 s cache of key lookups.
#[derive(Default)]
pub(crate) struct KeyCache {
    map: Mutex<HashMap<String, CachedKey>>,
}

impl KeyCache {
    fn get(&self, prefix: &str, now_ms: i64) -> Option<KeyRecord> {
        let g = self.map.lock();
        g.get(prefix)
            .filter(|c| now_ms - c.fetched_ms < KEY_CACHE_TTL_MS)
            .map(|c| c.record.clone())
    }

    fn put(&self, record: &KeyRecord, now_ms: i64) {
        self.map.lock().insert(
            record.prefix.clone(),
            CachedKey {
                record: record.clone(),
                fetched_ms: now_ms,
                touched_ms: now_ms,
            },
        );
    }

    fn should_touch(&self, prefix: &str, now_ms: i64) -> bool {
        let mut g = self.map.lock();
        match g.get_mut(prefix) {
            Some(c) if now_ms - c.touched_ms >= TOUCH_INTERVAL_MS => {
                c.touched_ms = now_ms;
                true
            }
            _ => false,
        }
    }

    /// Drop every cached entry (tests, key revocation hooks).
    pub(crate) fn clear(&self) {
        self.map.lock().clear();
    }
}

/// Result of one bucket check.
#[derive(Clone, Copy, Debug)]
pub struct RateDecision {
    /// Whether a token was available and taken.
    pub allowed: bool,
    /// Bucket capacity: requests per minute (`RateLimit-Limit`).
    pub limit: u32,
    /// Whole tokens left after this check (`RateLimit-Remaining`).
    pub remaining: u32,
    /// Seconds until the bucket is full again.
    pub reset_secs: u64,
    /// Seconds until one token is available (`429` only).
    pub retry_after_secs: u64,
}

struct Bucket {
    tokens: f64,
    last_ms: i64,
}

/// Per-tenant token buckets: capacity and refill are `per_minute` per 60 s.
pub struct RateLimiter {
    per_minute: u32,
    buckets: Mutex<HashMap<TenantId, Bucket>>,
}

impl RateLimiter {
    /// A limiter allowing `per_minute` requests per tenant per minute (also the burst size);
    /// `0` disables limiting.
    #[must_use]
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `tenant` at `now_ms`; `None` when limiting is disabled.
    pub fn check(&self, tenant: TenantId, now_ms: i64) -> Option<RateDecision> {
        if self.per_minute == 0 {
            return None;
        }
        let cap = f64::from(self.per_minute);
        let per_ms = cap / 60_000.0;
        let mut g = self.buckets.lock();
        let b = g.entry(tenant).or_insert(Bucket {
            tokens: cap,
            last_ms: now_ms,
        });
        let elapsed = (now_ms - b.last_ms).max(0) as f64;
        b.tokens = (b.tokens + elapsed * per_ms).min(cap);
        b.last_ms = now_ms;
        let allowed = b.tokens >= 1.0;
        if allowed {
            b.tokens -= 1.0;
        }
        let secs = |tokens: f64| ceil_secs(tokens / per_ms);
        Some(RateDecision {
            allowed,
            limit: self.per_minute,
            remaining: whole_tokens(b.tokens, self.per_minute),
            reset_secs: secs(cap - b.tokens),
            retry_after_secs: if allowed { 0 } else { secs(1.0 - b.tokens).max(1) },
        })
    }
}

/// Whole seconds in `ms` milliseconds, rounded up; `0` for non-positive or non-finite input.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "ms is finite and positive and at most one bucket refill period (60 000 ms), so the rounded-up seconds fit u64"
)]
fn ceil_secs(ms: f64) -> u64 {
    if ms.is_finite() && ms > 0.0 {
        (ms / 1000.0).ceil() as u64
    } else {
        0
    }
}

/// Whole tokens in a bucket holding `tokens` of at most `cap`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to [0, cap] and cap is a u32"
)]
fn whole_tokens(tokens: f64, cap: u32) -> u32 {
    tokens.floor().clamp(0.0, f64::from(cap)) as u32
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Does `headers` carry a WebSocket handshake (`Upgrade: websocket`)?
#[must_use]
pub(crate) fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|protocol| protocol.trim().eq_ignore_ascii_case("websocket"))
}

/// The API key a WebSocket handshake carries as its subprotocol: the first offered
/// `Sec-WebSocket-Protocol` token that is shaped like a key. Browsers and the Firecrawl SDK
/// (`new WebSocket(url, apiKey)`) cannot set an `Authorization` header on a WebSocket, so the
/// facade accepts the key there; the handshake echoes the token back as the chosen subprotocol.
#[must_use]
pub(crate) fn websocket_key(headers: &HeaderMap, firecrawl_keys: bool) -> Option<&str> {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .find(|token| lookup_prefix(token, firecrawl_keys).is_some())
}

/// Validate a bearer token against the key store.
///
/// # Errors
/// `401 unauthenticated` for malformed, unknown, revoked, expired or wrong keys.
pub async fn authenticate(state: &AppState, token: &str) -> Result<Principal, HttpError> {
    let prefix =
        lookup_prefix(token, state.config.compat.firecrawl_keys).ok_or_else(HttpError::unauthenticated)?;
    let now = state.clock.now();
    let now_ms = now.timestamp_millis();
    let record = match state.keys.get(prefix, now_ms) {
        Some(r) => r,
        None => {
            let r = state
                .repos
                .api
                .key_by_prefix(prefix)
                .await?
                .ok_or_else(HttpError::unauthenticated)?;
            state.keys.put(&r, now_ms);
            r
        }
    };
    // Constant-time comparison of the BLAKE3 digests.
    let presented = blake3::hash(token.as_bytes());
    if presented != blake3::Hash::from_bytes(record.hash) {
        return Err(HttpError::unauthenticated());
    }
    if record.revoked || expired(record.expires_at, now) {
        return Err(HttpError::unauthenticated());
    }
    if state.keys.should_touch(prefix, now_ms) {
        if let Err(e) =
            crawlx_storage::tenant::scope(record.tenant, state.repos.api.key_touch(record.key_id, now)).await
        {
            tracing::debug!(error = %e, "api key last_used_at update failed");
        }
    }
    Ok(Principal {
        tenant: record.tenant,
        key_id: record.key_id,
        scopes: record.scopes,
    })
}

fn expired(at: Option<Timestamp>, now: Timestamp) -> bool {
    at.is_some_and(|e| e <= now)
}

fn apply_rate_headers(resp: &mut Response, d: &RateDecision) {
    let h = resp.headers_mut();
    for (name, value) in [
        ("ratelimit-limit", d.limit.to_string()),
        ("ratelimit-remaining", d.remaining.to_string()),
        ("ratelimit-reset", d.reset_secs.to_string()),
    ] {
        if let Ok(v) = HeaderValue::from_str(&value) {
            h.insert(HeaderName::from_static(name), v);
        }
    }
}

/// Response streams are polled after middleware returns. Re-enter the tenant
/// scope on each poll so SSE, exports and delayed artifact reads cannot fall back
/// to maintenance authority.
struct TenantBody {
    tenant: TenantId,
    inner: Body,
}

impl HttpBody for TenantBody {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let tenant = self.tenant;
        crawlx_storage::tenant::scope_sync(tenant, || Pin::new(&mut self.inner).poll_frame(cx))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Middleware: authenticate, rate limit, attach [`Principal`], add `RateLimit-*` headers.
pub async fn auth_layer(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let handshake = req.method() == Method::GET
        && req.uri().path().starts_with("/compat/")
        && is_websocket_upgrade(req.headers());
    let token = match bearer(req.headers()) {
        Some(token) => Some(token),
        None if handshake => websocket_key(req.headers(), state.config.compat.firecrawl_keys),
        None => None,
    };
    let Some(token) = token else {
        return HttpError::unauthenticated().into_response();
    };
    // an `fc-` key is a facade credential: it never opens a native `/v1` route
    if token.starts_with(FIRECRAWL_KEY_PREFIX) && !req.uri().path().starts_with("/compat/") {
        return HttpError::unauthenticated().into_response();
    }
    let principal = match authenticate(&state, token).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let decision = state
        .limiter
        .check(principal.tenant, state.clock.now().timestamp_millis());
    if let Some(d) = &decision {
        if !d.allowed {
            let mut resp = HttpError::rate_limited(d.retry_after_secs).into_response();
            apply_rate_headers(&mut resp, d);
            return resp;
        }
    }
    let tenant = principal.tenant;
    req.extensions_mut().insert(principal);
    let mut resp = crawlx_storage::tenant::scope(tenant, next.run(req)).await;
    let (parts, body) = resp.into_parts();
    resp = Response::from_parts(parts, Body::new(TenantBody { tenant, inner: body }));
    if let Some(d) = &decision {
        apply_rate_headers(&mut resp, d);
    }
    resp
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn generated_keys_parse_and_differ() {
        let a = generate_key();
        let b = generate_key();
        assert_ne!(a, b);
        assert_eq!(a.len(), KEY_PREFIX.len() + SECRET_LEN);
        assert_eq!(parse_key(&a).map(str::len), Some(LOOKUP_LEN));
        assert!(parse_key("cx_live_short").is_none());
        assert!(parse_key("nope_abcdefghijklmnopqrstuvwxyz").is_none());
        assert!(parse_key("cx_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ").is_none());
    }

    #[test]
    fn tenant_names_are_deterministic() {
        assert_eq!(tenant_id_for("acme"), tenant_id_for("acme"));
        assert_ne!(tenant_id_for("acme"), tenant_id_for("other"));
        let u = Uuid::now_v7();
        assert_eq!(tenant_id_for(&u.to_string()).0, u);
    }

    #[test]
    fn bucket_empties_and_refills() {
        let rl = RateLimiter::new(60);
        let t = TenantId::new();
        for i in 0..60 {
            assert!(rl.check(t, 0).unwrap().allowed, "request {i}");
        }
        let d = rl.check(t, 0).unwrap();
        assert!(!d.allowed);
        assert_eq!(d.retry_after_secs, 1);
        assert!(rl.check(t, 1_000).unwrap().allowed);
        assert!(RateLimiter::new(0).check(t, 0).is_none());
    }

    #[test]
    fn keycache_expires() {
        let c = KeyCache::default();
        let rec = key_record(&generate_key(), TenantId::new(), Scope::all_set()).unwrap();
        c.put(&rec, 0);
        assert!(c.get(&rec.prefix, 29_999).is_some());
        assert!(c.get(&rec.prefix, 30_000).is_none());
        c.clear();
    }

    #[test]
    fn firecrawl_keys_parse_only_when_enabled() {
        let fc = generate_firecrawl_key();
        assert!(fc.starts_with("fc-") && fc.len() == 3 + 32);
        assert_eq!(parse_firecrawl_key(&fc), Some(&fc[..3 + LOOKUP_LEN]));
        assert_eq!(lookup_prefix(&fc, true), Some(&fc[..3 + LOOKUP_LEN]));
        assert_eq!(lookup_prefix(&fc, false), None, "off by default");
        assert!(key_record(&fc, TenantId::new(), Scope::all_set()).is_none());
        let rec = key_record_for(&fc, TenantId::new(), Scope::all_set(), true).unwrap();
        assert_eq!(rec.prefix, &fc[..3 + LOOKUP_LEN]);
        assert_eq!(rec.hash, hash_key(&fc));
        assert!(key_record_for(&fc, TenantId::new(), Scope::all_set(), false).is_none());
        // cx_live_ keys keep working with the switch on, and the prefixes cannot collide
        let cx = generate_key();
        assert_eq!(lookup_prefix(&cx, true).map(str::len), Some(LOOKUP_LEN));
        assert_ne!(fc[..3 + LOOKUP_LEN].len(), LOOKUP_LEN);
        for bad in [
            "fc-",
            "fc-short",
            "fc-!!!!!!!!!!!!!!!!!!!!",
            "fc_0123456789abcdef0123",
            "FC-0123456789abcdef0123",
        ] {
            assert_eq!(lookup_prefix(bad, true), None, "{bad}");
        }
        assert_eq!(parse_firecrawl_key(&format!("fc-{}", "a".repeat(65))), None);
    }

    #[test]
    fn websocket_handshakes_are_recognised_and_carry_the_key_as_subprotocol() {
        let mut h = HeaderMap::new();
        assert!(!is_websocket_upgrade(&h));
        h.insert(header::UPGRADE, HeaderValue::from_static("h2c"));
        assert!(!is_websocket_upgrade(&h));
        h.insert(header::UPGRADE, HeaderValue::from_static("WebSocket"));
        assert!(is_websocket_upgrade(&h));
        h.insert(header::UPGRADE, HeaderValue::from_static("h2c, websocket"));
        assert!(is_websocket_upgrade(&h));

        let cx = generate_key();
        let fc = generate_firecrawl_key();
        let mut h = HeaderMap::new();
        assert_eq!(websocket_key(&h, true), None);
        h.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&format!("graphql, {cx}")).unwrap(),
        );
        assert_eq!(
            websocket_key(&h, false),
            Some(cx.as_str()),
            "the first key-shaped token"
        );
        h.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&fc).unwrap(),
        );
        assert_eq!(websocket_key(&h, true), Some(fc.as_str()));
        assert_eq!(websocket_key(&h, false), None, "`fc-` keys are off by default");
        h.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("graphql"),
        );
        assert_eq!(websocket_key(&h, true), None);
    }
}
