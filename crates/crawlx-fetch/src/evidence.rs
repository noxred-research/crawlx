//! Typed facts the fetch plane observed about one response, carried in a reserved header.
//!
//! [`FetchEvidence`] travels in the `x-crawlx-stream-evidence` header of
//! [`crate::FetchResponse::headers`]. The fetch plane strips the whole `x-crawlx-stream-`
//! namespace from wire headers before adding its own, so a server cannot forge the evidence;
//! a response that was not produced by a live fetch (a replayed cache entry) simply has none,
//! and [`crate::FetchResponse::evidence`] returns `None` instead of inventing facts.

use crate::certificate::CertificateEvidence;
use crate::charset::CharsetEvidence;
use crate::codec::BodyLimitKind;
use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

/// Reserved response header carrying the JSON-serialized [`FetchEvidence`].
pub const EVIDENCE_HEADER: &str = "x-crawlx-stream-evidence";

/// Body-reading facts: what crossed the wire, what was decoded, and what stopped it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BodyEvidence {
    /// Content codings the sender listed, in the order it applied them.
    pub content_encoding: Vec<String>,
    /// This plane removed those codings (`false` for identity bodies and for codings it
    /// cannot decode, whose bytes are passed through).
    pub decoded: bool,
    /// Bytes read from the transport (compressed size when encoded).
    pub wire_bytes: u64,
    /// blake3 (hex) of the wire bytes read; present for encoded bodies, so the original
    /// representation stays identifiable after decoding.
    pub wire_digest: Option<String>,
    /// Bytes of the returned body.
    pub decoded_bytes: u64,
    /// `Content-Length` the sender declared for the wire body.
    pub declared_length: Option<u64>,
    /// The body is partial: a cap cut it.
    pub truncated: bool,
    /// The cap that cut the body.
    pub limit: Option<BodyLimitKind>,
}

/// Everything observed about a response beyond status, headers and body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FetchEvidence {
    /// Layout version; `1`.
    pub schema_version: u8,
    /// Peer certificate of the request's own connection.
    pub certificate: CertificateEvidence,
    /// Body sizes and limits.
    pub body: BodyEvidence,
    /// Selected text encoding; `None` for non-text responses.
    pub charset: Option<CharsetEvidence>,
    /// The `Content-Type` the sender wrote, recorded only when a declaration overrode it.
    pub wire_content_type: Option<String>,
}

impl FetchEvidence {
    /// Current layout version.
    pub const SCHEMA_VERSION: u8 = 1;

    /// Assemble evidence.
    #[must_use]
    pub const fn new(
        certificate: CertificateEvidence,
        body: BodyEvidence,
        charset: Option<CharsetEvidence>,
        wire_content_type: Option<String>,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            certificate,
            body,
            charset,
            wire_content_type,
        }
    }

    /// Header value for [`EVIDENCE_HEADER`]. `None` when the serialization is not a valid
    /// header value (non-ASCII content), in which case no evidence is attached.
    #[must_use]
    pub fn to_header_value(&self) -> Option<HeaderValue> {
        let json = serde_json::to_string(self).ok()?;
        HeaderValue::from_str(&json).ok()
    }

    /// Evidence carried by `headers`, if a live fetch attached it.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let value = headers.get(EVIDENCE_HEADER)?.to_str().ok()?;
        let evidence: Self = serde_json::from_str(value).ok()?;
        (evidence.schema_version == Self::SCHEMA_VERSION).then_some(evidence)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::certificate::CertificateUnavailable;

    fn sample() -> FetchEvidence {
        FetchEvidence::new(
            CertificateEvidence::unavailable(CertificateUnavailable::NotTls),
            BodyEvidence {
                content_encoding: vec!["gzip".to_owned()],
                decoded: true,
                wire_bytes: 10,
                wire_digest: Some("00".repeat(32)),
                decoded_bytes: 100,
                declared_length: Some(10),
                truncated: false,
                limit: None,
            },
            None,
            Some("text/plain".to_owned()),
        )
    }

    #[test]
    fn header_roundtrip_and_unknown_versions_are_ignored() {
        let evidence = sample();
        let mut headers = HeaderMap::new();
        headers.insert(EVIDENCE_HEADER, evidence.to_header_value().unwrap());
        assert_eq!(FetchEvidence::from_headers(&headers), Some(evidence));
        let mut future = sample();
        future.schema_version = 2;
        headers.insert(EVIDENCE_HEADER, future.to_header_value().unwrap());
        assert!(FetchEvidence::from_headers(&headers).is_none());
        headers.insert(EVIDENCE_HEADER, HeaderValue::from_static("{not json"));
        assert!(FetchEvidence::from_headers(&headers).is_none());
        assert!(FetchEvidence::from_headers(&HeaderMap::new()).is_none());
    }
}
