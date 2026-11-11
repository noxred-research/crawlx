//! Conditional requests and the HTTP-cache validator policy.
//!
//! [`Validators`] are the `If-None-Match` / `If-Modified-Since` pair of an earlier response.
//! [`CachedValidators`] binds them to the cache scope they were learned under so a stored
//! validator is never offered to another tenant or principal, never kept for a response that
//! forbade storage, and never kept for zero-data-retention content. [`interpret`] then judges
//! the answer honestly: a `304` whose `ETag` disagrees with the one that was sent is not a
//! confirmation of the stored copy.

use http::{header, HeaderMap, HeaderValue};

/// Cache validators remembered from an earlier response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validators {
    /// Verbatim `ETag` header value, quotes and `W/` prefix included.
    pub etag: Option<String>,
    /// Verbatim `Last-Modified` header value (HTTP-date).
    pub last_modified: Option<String>,
}

impl Validators {
    /// Capture the validators a response offers.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let get = |name| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        Self {
            etag: get(header::ETAG),
            last_modified: get(header::LAST_MODIFIED),
        }
    }

    /// True when neither validator is present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }

    /// Add the request headers. Values that are not valid header values are skipped.
    pub fn apply(&self, headers: &mut HeaderMap) {
        if let Some(v) = self.etag.as_deref().and_then(|v| HeaderValue::from_str(v).ok()) {
            headers.insert(header::IF_NONE_MATCH, v);
        }
        if let Some(v) = self
            .last_modified
            .as_deref()
            .and_then(|v| HeaderValue::from_str(v).ok())
        {
            headers.insert(header::IF_MODIFIED_SINCE, v);
        }
    }
}

/// Validators bound to the cache scope they were learned under.
///
/// The scope is an opaque key chosen by the caller (tenant, principal and session
/// generation, joined unambiguously). Equality is the only operation: an entry learned for
/// one scope offers nothing to a different one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedValidators {
    validators: Validators,
    scope: String,
}

impl CachedValidators {
    /// Keep the validators of a response under `scope`.
    ///
    /// Returns `None` when nothing may be revalidated later: the response offered no
    /// validator, carried `Cache-Control: no-store`, varies on `*`, or the content is
    /// zero-data-retention content (`zdr`; validators identify retained bytes).
    #[must_use]
    pub fn capture(headers: &HeaderMap, scope: &str, zdr: bool) -> Option<Self> {
        if zdr || forbids_storage(headers) {
            return None;
        }
        let validators = Validators::from_headers(headers);
        (!validators.is_empty()).then(|| Self {
            validators,
            scope: scope.to_owned(),
        })
    }

    /// The validators to send for a request made under `scope`; `None` for any other scope.
    #[must_use]
    pub fn offer(&self, scope: &str) -> Option<&Validators> {
        (self.scope == scope).then_some(&self.validators)
    }
}

fn forbids_storage(headers: &HeaderMap) -> bool {
    let directive = headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| d.trim().eq_ignore_ascii_case("no-store"));
    let vary_any = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| d.trim() == "*");
    directive || vary_any
}

/// What a conditional answer means for the stored copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Revalidation {
    /// `304` that confirms the stored copy: it may be reused.
    Reusable,
    /// The server sent a new representation; the stored copy is stale.
    Replaced,
    /// A `304` that does not confirm what was sent (different `ETag`) or one to a request
    /// that was not conditional: the stored copy must not be reused.
    Unconfirmed,
}

/// Weak comparison of two entity tags (RFC 9110 section 8.8.3.2).
fn weak_eq(a: &str, b: &str) -> bool {
    let strip = |t: &str| t.trim().strip_prefix("W/").unwrap_or_else(|| t.trim()).to_owned();
    strip(a) == strip(b)
}

/// Interpret `status` and `headers` of the answer to a request that sent `sent`.
#[must_use]
pub fn interpret(sent: &Validators, status: u16, headers: &HeaderMap) -> Revalidation {
    if status != 304 {
        return Revalidation::Replaced;
    }
    if sent.is_empty() {
        return Revalidation::Unconfirmed;
    }
    let answered = headers.get(header::ETAG).and_then(|v| v.to_str().ok());
    match (sent.etag.as_deref(), answered) {
        (Some(sent), Some(answered)) if !weak_eq(sent, answered) => Revalidation::Unconfirmed,
        _ => Revalidation::Reusable,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn roundtrip_headers() {
        let mut resp = HeaderMap::new();
        resp.insert(header::ETAG, HeaderValue::from_static("\"abc\""));
        resp.insert(
            header::LAST_MODIFIED,
            HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        let v = Validators::from_headers(&resp);
        assert!(!v.is_empty());
        let mut req = HeaderMap::new();
        v.apply(&mut req);
        assert_eq!(req.get(header::IF_NONE_MATCH).unwrap(), "\"abc\"");
        assert_eq!(
            req.get(header::IF_MODIFIED_SINCE).unwrap(),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn empty_adds_nothing() {
        let mut req = HeaderMap::new();
        Validators::default().apply(&mut req);
        assert!(req.is_empty());
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| (header::HeaderName::from_static(k), HeaderValue::from_static(v)))
            .collect()
    }

    #[test]
    fn validators_are_scoped_and_withheld_for_no_store_vary_star_and_zdr() {
        let page = headers(&[("etag", "\"v1\""), ("cache-control", "max-age=60")]);
        let kept = CachedValidators::capture(&page, "tenant-a/anon/0", false).unwrap();
        assert_eq!(
            kept.offer("tenant-a/anon/0").unwrap().etag.as_deref(),
            Some("\"v1\"")
        );
        assert!(kept.offer("tenant-b/anon/0").is_none());
        assert!(kept.offer("tenant-a/user-1/0").is_none());
        assert!(
            CachedValidators::capture(&page, "s", true).is_none(),
            "ZDR content keeps no validator"
        );
        for blocked in [
            headers(&[("etag", "\"v1\""), ("cache-control", "private, No-Store")]),
            headers(&[("etag", "\"v1\""), ("vary", "Accept-Encoding, *")]),
            headers(&[("cache-control", "max-age=60")]),
        ] {
            assert!(CachedValidators::capture(&blocked, "s", false).is_none());
        }
    }

    #[test]
    fn a_304_confirms_the_stored_copy_only_when_it_agrees_with_what_was_sent() {
        let sent = Validators {
            etag: Some("W/\"v1\"".to_owned()),
            last_modified: None,
        };
        assert_eq!(
            interpret(&sent, 304, &headers(&[("etag", "\"v1\"")])),
            Revalidation::Reusable
        );
        assert_eq!(interpret(&sent, 304, &HeaderMap::new()), Revalidation::Reusable);
        assert_eq!(
            interpret(&sent, 304, &headers(&[("etag", "\"v2\"")])),
            Revalidation::Unconfirmed
        );
        assert_eq!(
            interpret(&sent, 200, &headers(&[("etag", "\"v1\"")])),
            Revalidation::Replaced
        );
        assert_eq!(
            interpret(&Validators::default(), 304, &HeaderMap::new()),
            Revalidation::Unconfirmed
        );
    }
}
