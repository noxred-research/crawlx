//! Versioned request identity and retention-safe queue envelopes.
//!
//! These values are proposals, not authority to execute HTTP writes. Unsafe methods
//! still require the independent safety kernel and admitted-effect journal.

use crate::{hash::Digest, url::CanonicalUrl, CrawlRunId, TenantId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Safe version-pinned declarative upstream queue imports.
pub mod import;

/// Hard upper bound on an append transaction.
pub const MAX_REQUEST_BATCH: usize = 1000;
/// Hard upper bound on serialized queue metadata in one transaction.
pub const MAX_REQUEST_BATCH_BYTES: usize = 1024 * 1024;

/// Separately pinned source identity dialects; not source-language execution modes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityDialectV1 {
    /// Native, authority-scoped identity.
    #[default]
    NativeV1,
    /// JavaScript actor framework 3.18.2 exported request keys.
    #[serde(rename = "js_actor_3_18")]
    JsActor318,
    /// Python actor framework 1.11.0 exported session-aware keys.
    #[serde(rename = "py_actor_1_11")]
    PyActor111,
    /// Python spider framework 2.19.0 exported fingerprints.
    #[serde(rename = "python_spider_2_19")]
    PythonSpider219,
    /// Go collector framework 2.2.0 exported visited-request keys.
    #[serde(rename = "go_collector_2_2")]
    GoCollector22,
}

/// Replayable content reference. Contents never belong in queue JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RequestBodyV1 {
    /// Approved artifact or volatile-store identifier.
    pub handle: String,
    /// Tenant-keyed digest, not an unkeyed hash of secret content.
    pub digest: Digest,
    /// Correlation-key version.
    pub key_version: u32,
    /// Exact byte length charged to the effect budget.
    pub length: u64,
    /// Declared media type.
    pub media_type: String,
}

/// Immutable request proposal. Admission assigns run and principal separately.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RequestEnvelopeV1 {
    /// Exactly one.
    pub version: u16,
    /// Canonicalized using the run's current URL policy.
    pub url: CanonicalUrl,
    /// Uppercase HTTP token; no transport authority implied.
    pub method: String,
    /// Credential-free approved control identifier, never header contents.
    pub header_control: Option<String>,
    /// Optional replayable content reference.
    pub body: Option<RequestBodyV1>,
    /// Reviewed route identifier.
    pub route: String,
    /// Public, schema-validated metadata; secret-bearing values are forbidden.
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Parent row in the same run.
    pub parent: Option<i64>,
    /// Link distance from a seed.
    pub depth: u16,
    /// Higher values dispatch first.
    pub priority: i32,
    /// Source identity dialect, separately pinned.
    pub dialect: IdentityDialectV1,
    /// Optional tenant-keyed opaque source identity, never raw uniqueKey content.
    pub source_key: Option<Digest>,
    /// Explicit nonce replacing unbounded always_enqueue/dont_filter behavior.
    pub revisit_generation: u32,
    /// Strict session-generation identity, when required.
    pub session_generation: Option<u64>,
    /// Earliest allowed dispatch time; current authorization still applies.
    pub not_before: Option<Timestamp>,
}

impl RequestEnvelopeV1 {
    /// Native anonymous GET with legacy URL-key semantics.
    #[must_use]
    pub fn get(url: CanonicalUrl, depth: u16, parent: Option<i64>) -> Self {
        Self {
            version: 1,
            url,
            method: "GET".into(),
            header_control: None,
            body: None,
            route: "default".into(),
            metadata: BTreeMap::new(),
            parent,
            depth,
            priority: 0,
            dialect: IdentityDialectV1::NativeV1,
            source_key: None,
            revisit_generation: 0,
            session_generation: None,
            not_before: None,
        }
    }

    /// Validate structural limits before any queue mutation.
    ///
    /// # Errors
    /// Rejects malformed tokens, unbounded metadata and unsupported identity combinations.
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.version != 1
            || self.method.is_empty()
            || self.method.len() > 16
            || !self.method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
            || !safe_id(&self.route)
            || self.header_control.as_deref().is_some_and(|s| !safe_id(s))
            || i16::try_from(self.priority).is_err()
        {
            return Err(RequestError::InvalidEnvelope);
        }
        if let Some(body) = &self.body {
            if !safe_id(&body.handle)
                || body.key_version == 0
                || body.media_type.len() > 128
                || body.media_type.bytes().any(|b| b.is_ascii_control())
            {
                return Err(RequestError::InvalidEnvelope);
            }
        }
        if self.metadata.len() > 64
            || self
                .metadata
                .iter()
                .any(|(key, value)| !safe_id(key) || sensitive_key(key) || !bounded_value(value, 0))
            || serde_json::to_vec(&self.metadata)
                .map_err(|_| RequestError::InvalidEnvelope)?
                .len()
                > 16 * 1024
        {
            return Err(RequestError::InvalidMetadata);
        }
        if self
            .metadata
            .get("autothrottle_dont_adjust_delay")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(RequestError::InvalidMetadata);
        }
        Ok(())
    }

    /// Compute scoped identity. Legacy native anonymous GET keeps its existing canonical key.
    /// Header variations must be represented by tenant-keyed digests, sorted by header name.
    ///
    /// # Errors
    /// Returns validation errors; correlation-key version must be positive.
    pub fn identity(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        principal: &str,
        varying_headers: &BTreeMap<String, Digest>,
        key_version: u32,
    ) -> Result<RequestIdentityV1, RequestError> {
        self.validate()?;
        if !safe_id(principal) || key_version == 0 || varying_headers.len() > 64 {
            return Err(RequestError::InvalidEnvelope);
        }
        let legacy = self.dialect == IdentityDialectV1::NativeV1
            && principal == "anonymous"
            && self.method == "GET"
            && self.body.is_none()
            && varying_headers.is_empty()
            && self.session_generation.is_none()
            && self.source_key.is_none();
        let key = if legacy {
            self.url.key
        } else if self.dialect != IdentityDialectV1::NativeV1 {
            let exported = self.source_key.ok_or(RequestError::ConflictingIdentity)?;
            Digest::of_value(
                "crawlx/imported-request-identity/v1",
                &(
                    &tenant,
                    &run,
                    principal,
                    self.dialect,
                    exported,
                    self.session_generation,
                    key_version,
                ),
            )
            .map_err(|_| RequestError::InvalidEnvelope)?
        } else {
            let descriptor = (
                &tenant,
                &run,
                principal,
                self.dialect,
                self.url.key,
                &self.method,
                self.body.as_ref().map(|body| (body.digest, body.key_version)),
                varying_headers,
                self.session_generation,
                self.source_key,
                key_version,
            );
            Digest::of_value("crawlx/request-identity/v1", &descriptor)
                .map_err(|_| RequestError::InvalidEnvelope)?
        };
        Ok(RequestIdentityV1 {
            version: 1,
            key,
            key_version,
            revisit_generation: self.revisit_generation,
        })
    }
}

/// Privacy-safe queue key, with revisit generation kept as a typed predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RequestIdentityV1 {
    /// Identity schema version.
    pub version: u16,
    /// Scoped digest; legacy anonymous GET preserves the canonical URL key.
    pub key: Digest,
    /// Tenant correlation-key version.
    pub key_version: u32,
    /// New generation rather than reopening completed rows.
    pub revisit_generation: u32,
}
impl RequestIdentityV1 {
    /// Rehydrate a validated stored identity.
    #[must_use]
    pub const fn stored(key: Digest, key_version: u32, revisit_generation: u32) -> Self {
        Self {
            version: 1,
            key,
            key_version,
            revisit_generation,
        }
    }
}

pub(crate) fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}
fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "password",
        "secret",
        "token",
        "cookie",
        "authorization",
        "credential",
    ]
    .iter()
    .any(|part| key.contains(part))
}
fn bounded_value(value: &serde_json::Value, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match value {
        serde_json::Value::Array(values) => {
            values.len() <= 256 && values.iter().all(|v| bounded_value(v, depth + 1))
        }
        serde_json::Value::Object(values) => {
            values.len() <= 64
                && values
                    .iter()
                    .all(|(k, v)| safe_id(k) && !sensitive_key(k) && bounded_value(v, depth + 1))
        }
        serde_json::Value::String(value) => value.len() <= 4096,
        _ => true,
    }
}

/// Request validation failed without exposing input contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// Version, method, reference or identifier is invalid.
    #[error("invalid request envelope")]
    InvalidEnvelope,
    /// Metadata violates bounds or contains a reserved sensitive field.
    #[error("invalid request metadata")]
    InvalidMetadata,
    /// Source dialect forbids the supplied key/revisit combination.
    #[error("conflicting request identity options")]
    ConflictingIdentity,
}

#[cfg(test)]
mod tests;
