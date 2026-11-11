//! `HEAD` preflight before a `GET`.
//!
//! A preflight is an ordinary fetch hop: it passes the same egress check, pin, governor and
//! deployment admission as the `GET` it precedes, spends the parent request allowance, and
//! follows redirects with a full re-check per hop. The `GET` then starts from the original
//! URL and is checked again, so a redirect target is validated twice and a `HEAD` answer can
//! never stand in for the `GET`'s own. Nothing here is a parser-owned request: callers opt in
//! per fetch through [`crate::FetchOptions::preflight`].

use crate::charset::essence;
use crate::codec::{BodyLimits, ContentEncoding};
use http::{header, HeaderMap};

/// Why a preflight refused the `GET`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PreflightRefusal {
    /// The `HEAD` answered with an error status.
    #[error("HEAD answered {0}")]
    Status(u16),
    /// The declared length exceeds the limit.
    #[error("declared length {declared} exceeds {limit}")]
    TooLarge {
        /// `Content-Length` the sender declared.
        declared: u64,
        /// The limit it was checked against.
        limit: u64,
    },
    /// The media type is not in the allow-list.
    #[error("content type {0} is not accepted")]
    ContentType(String),
}

/// Preflight policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HeadPreflight {
    /// Refuse a declared length above this. Default: the cap the `GET` will apply (wire cap
    /// for an encoded body, decoded cap otherwise).
    pub max_content_length: Option<u64>,
    /// Accepted media types (lower-case `type/subtype`). Empty accepts any.
    pub content_types: Vec<String>,
}

impl HeadPreflight {
    /// Preflight with the default limits and any content type.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Refuse declared lengths above `limit`.
    #[must_use]
    pub const fn with_max_content_length(mut self, limit: u64) -> Self {
        self.max_content_length = Some(limit);
        self
    }

    /// Accept only these media types.
    #[must_use]
    pub fn with_content_types<S: Into<String>>(mut self, types: impl IntoIterator<Item = S>) -> Self {
        self.content_types = types.into_iter().map(|t| t.into().to_ascii_lowercase()).collect();
        self
    }

    /// Judge a `HEAD` answer. `405` and `501` mean the server does not implement `HEAD`:
    /// that is not a verdict on the resource, so the `GET` proceeds.
    ///
    /// # Errors
    /// The refusal, when the `GET` must not be sent.
    pub fn evaluate(
        &self,
        status: u16,
        headers: &HeaderMap,
        limits: &BodyLimits,
    ) -> Result<(), PreflightRefusal> {
        if matches!(status, 405 | 501) {
            return Ok(());
        }
        if status >= 400 {
            return Err(PreflightRefusal::Status(status));
        }
        let declared = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if let Some(declared) = declared {
            let encoded = matches!(ContentEncoding::from_headers(headers), Ok(ContentEncoding::Supported(c)) if !c.is_empty());
            let default =
                u64::try_from(if encoded { limits.wire() } else { limits.decoded() }).unwrap_or(u64::MAX);
            let limit = self.max_content_length.unwrap_or(default);
            if declared > limit {
                return Err(PreflightRefusal::TooLarge { declared, limit });
            }
        }
        if !self.content_types.is_empty() {
            let kind = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(essence)
                .unwrap_or_default();
            if !self.content_types.contains(&kind) {
                return Err(PreflightRefusal::ContentType(kind.chars().take(64).collect()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| (header::HeaderName::from_static(k), HeaderValue::from_static(v)))
            .collect()
    }

    #[test]
    fn status_length_and_type_verdicts() {
        let limits = BodyLimits::new(1000);
        let policy = HeadPreflight::new().with_content_types(["Text/HTML"]);
        assert!(policy
            .evaluate(
                200,
                &headers(&[("content-type", "text/html; charset=utf-8")]),
                &limits
            )
            .is_ok());
        assert_eq!(
            policy.evaluate(404, &HeaderMap::new(), &limits),
            Err(PreflightRefusal::Status(404))
        );
        assert_eq!(
            policy.evaluate(200, &headers(&[("content-type", "image/png")]), &limits),
            Err(PreflightRefusal::ContentType("image/png".to_owned()))
        );
        assert_eq!(
            policy.evaluate(200, &headers(&[("content-type", "text/html")]), &limits),
            Ok(())
        );
        let open = HeadPreflight::new();
        assert_eq!(
            open.evaluate(200, &headers(&[("content-length", "1001")]), &limits),
            Err(PreflightRefusal::TooLarge {
                declared: 1001,
                limit: 1000
            })
        );
        assert!(open
            .evaluate(200, &headers(&[("content-length", "1000")]), &limits)
            .is_ok());
        assert!(open
            .with_max_content_length(5)
            .evaluate(200, &headers(&[("content-length", "6")]), &limits)
            .is_err());
    }

    #[test]
    fn encoded_lengths_are_compared_with_the_wire_cap() {
        let limits = BodyLimits::new(1000).with_wire_cap(100);
        let encoded = headers(&[("content-length", "101"), ("content-encoding", "gzip")]);
        assert_eq!(
            HeadPreflight::new().evaluate(200, &encoded, &limits),
            Err(PreflightRefusal::TooLarge {
                declared: 101,
                limit: 100
            })
        );
        assert!(HeadPreflight::new()
            .evaluate(200, &headers(&[("content-length", "101")]), &limits)
            .is_ok());
    }

    #[test]
    fn heads_that_are_not_implemented_do_not_veto_the_get() {
        let limits = BodyLimits::default();
        assert!(HeadPreflight::new()
            .evaluate(405, &HeaderMap::new(), &limits)
            .is_ok());
        assert!(HeadPreflight::new()
            .evaluate(501, &HeaderMap::new(), &limits)
            .is_ok());
        assert!(HeadPreflight::new()
            .evaluate(500, &HeaderMap::new(), &limits)
            .is_err());
    }
}
