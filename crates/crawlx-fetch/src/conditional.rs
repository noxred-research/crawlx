//! Conditional requests: `If-None-Match` / `If-Modified-Since` from a
//! caller-supplied validator pair.

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
}
