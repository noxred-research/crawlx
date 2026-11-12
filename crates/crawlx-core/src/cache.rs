//! Principal-scoped response caching, offline development replay and selector retention.

use crate::hash::Digest;
use crate::selectors::{AdaptiveSelectorSpecV1, SelectorScopeV1};
use crate::{CoreError, CrawlRunId, StoreError, TenantId, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Explicit native cache behavior. Bypass permits writes; disabled permits neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheModeV1 {
    /// Read matching fresh entries and write successful acquisitions.
    #[default]
    ReadWrite,
    /// Never read; permit successful acquisition writes.
    Bypass,
    /// Neither read nor write reusable entries.
    Disabled,
    /// Read only. A miss never dispatches a network request.
    ReadOnly,
    /// Never read; write successful acquisitions.
    WriteOnly,
}

/// Optional validator exchange under the parent acquisition allowance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheFreshnessV1 {
    /// Use age and retained-body checks without network I/O.
    #[default]
    Retained,
    /// HEAD must repeat a matching ETag or Last-Modified value.
    Head,
    /// Conditional GET must return 304 for the matching retained body.
    ConditionalGet,
}

/// Native cache controls. Absence preserves facade cache semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct CachePolicyV1 {
    /// Supported layout, exactly one.
    pub schema_version: u8,
    /// Explicit read/write behavior.
    pub mode: CacheModeV1,
    /// Maximum retained response age in milliseconds.
    pub max_age_ms: u64,
    /// Offline artifact replay, distinct from action replay; never fetches or writes.
    pub development_replay: bool,
    /// Optional live validation. Read-only and replay never dispatch these exchanges.
    pub freshness: CacheFreshnessV1,
}
impl Default for CachePolicyV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: CacheModeV1::ReadWrite,
            max_age_ms: 172_800_000,
            development_replay: false,
            freshness: CacheFreshnessV1::Retained,
        }
    }
}
impl CachePolicyV1 {
    /// Validate schema and finite retention-age bounds at admission.
    /// # Errors
    /// Returns invalid cache policy for unsupported versions or ages beyond one year.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != 1 || self.max_age_ms > 31_536_000_000 {
            return Err(CoreError::Invalid {
                field: "cache",
                reason: "unsupported schema or cache age exceeds one year".into(),
            });
        }
        Ok(())
    }
    /// Whether this policy permits a stored response read.
    #[must_use]
    pub fn reads(&self) -> bool {
        self.schema_version == 1
            && (self.development_replay
                || matches!(self.mode, CacheModeV1::ReadWrite | CacheModeV1::ReadOnly))
    }
    /// Whether this policy permits a reusable response write.
    #[must_use]
    pub fn writes(&self) -> bool {
        self.schema_version == 1
            && !self.development_replay
            && matches!(
                self.mode,
                CacheModeV1::ReadWrite | CacheModeV1::Bypass | CacheModeV1::WriteOnly
            )
    }
    /// Whether a miss must stop before network I/O.
    #[must_use]
    pub fn cache_only(&self) -> bool {
        self.development_replay || self.mode == CacheModeV1::ReadOnly
    }
}

/// Versioned identity of bytes reusable by a single authenticated principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CacheKeyV1 {
    /// Trusted API-key principal, or an isolated local run identifier.
    pub principal: String,
    /// Full acquisition and validation policy digest.
    pub acquisition_profile: Digest,
    /// Actual registered implementation revision, not a user-supplied version.
    pub backend_capability: String,
    /// Validation rule-set revision.
    pub validator_version: u8,
    /// Wire response versus rendered DOM.
    pub representation: String,
    /// Request options, including headers and session/profile identity.
    pub request_identity: Digest,
}
impl CacheKeyV1 {
    /// Construct a key from trusted execution facts.
    #[must_use]
    pub fn new(
        principal: String,
        acquisition_profile: Digest,
        backend_capability: String,
        validator_version: u8,
        representation: String,
        request_identity: Digest,
    ) -> Self {
        Self {
            principal,
            acquisition_profile,
            backend_capability,
            validator_version,
            representation,
            request_identity,
        }
    }
    /// Domain-separated digest; serialization consists only of infallible primitive fields.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        Digest::of("crawlx/response-cache/v1", &encoded)
    }
}

/// Tenant-keyed correlation over resolved credential controls. Raw values never leave this helper.
///
/// # Errors
/// Returns serialization errors without including credential bytes.
pub fn credential_digest(
    root: &[u8; 32],
    tenant: crate::TenantId,
    controls: &crate::request_controls::RequestControls,
) -> Result<Digest, CoreError> {
    use zeroize::Zeroize;
    let mut tenant_key = Digest::keyed(root, "crawlx/tenant-request-key/v1", tenant.0.as_bytes()).0;
    let headers: Vec<_> = controls
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str(), value.expose().as_str()))
        .collect();
    let mut cookies: Vec<_> = controls
        .cookies()
        .iter()
        .map(|c| {
            (
                c.domain.as_str(),
                c.path.as_str(),
                c.name.as_str(),
                c.value.expose().as_str(),
            )
        })
        .collect();
    cookies.sort_unstable();
    // Realm credentials and the TLS client identity decide what a server answers, so they are
    // part of the identity; without them the encoding (and the digest) is the original one.
    let mut realms: Vec<_> = controls
        .realm_credentials()
        .iter()
        .map(|c| {
            (
                c.origin().origin().ascii_serialization(),
                c.realm(),
                c.scheme().token(),
                c.encoded_secret(),
            )
        })
        .collect();
    realms.sort_unstable();
    let identity = controls
        .client_identity()
        .map(|i| (i.certificate_pem(), i.private_key_pem(), i.hosts()));
    let serialized = if realms.is_empty() && identity.is_none() {
        serde_json::to_vec(&(1u8, headers, cookies))
    } else {
        serde_json::to_vec(&(2u8, headers, cookies, realms, identity))
    };
    let mut encoded = serialized
        .map_err(|_| CoreError::Serialization("credential identity serialization failed".into()))?;
    let digest = Digest::keyed(&tenant_key, "crawlx/credential-request-identity/v1", &encoded);
    encoded.zeroize();
    tenant_key.zeroize();
    Ok(digest)
}

/// Layout of an exported response cache this build imports.
pub const CACHE_EXPORT_VERSION: u16 = 1;
/// Largest exported cache file, in bytes.
pub const MAX_CACHE_EXPORT_BYTES: usize = 16 * 1024 * 1024;
/// Most entries one export may carry.
pub const MAX_CACHE_EXPORT_ENTRIES: usize = 1_000;
/// Largest body of one imported entry, in bytes.
pub const MAX_CACHE_ENTRY_BODY_BYTES: usize = 1024 * 1024;

/// One response header of an exported cache entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CacheHeaderV1 {
    /// Header name, any case.
    pub name: String,
    /// Header value.
    pub value: String,
}

/// One stored response of an exported cache. Every field is declared: an exported entry with any
/// other field fails the whole export, so no field is silently dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct CacheEntryExportV1 {
    /// Absolute HTTP(S) URL of the response, without credentials.
    pub url: String,
    /// Status code; only successful (2xx) responses are importable.
    pub status_code: u16,
    /// Media type; only textual types are importable.
    #[serde(default)]
    pub content_type: Option<String>,
    /// When the response was fetched.
    pub fetched_at: Timestamp,
    /// Response headers; only the safe set of [`SAFE_CACHE_HEADERS`] may appear.
    #[serde(default)]
    pub headers: Vec<CacheHeaderV1>,
    /// Response body as UTF-8 text.
    pub body: String,
    /// Tenant the entry was cached for, when the exporter recorded one.
    #[serde(default)]
    pub tenant: Option<TenantId>,
    /// The exporter marked the entry as private to its principal (an authenticated or
    /// per-user response).
    #[serde(default)]
    pub private: bool,
}

/// An exported response cache: one tenant's stored responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct CacheExportV1 {
    /// [`CACHE_EXPORT_VERSION`].
    pub version: u16,
    /// Tenant the whole export belongs to.
    pub tenant: TenantId,
    /// The stored responses.
    pub entries: Vec<CacheEntryExportV1>,
}

/// The response headers an import keeps. Everything else (cookies, credentials, proxy and
/// tracking headers, unknown headers) refuses the entry.
pub const SAFE_CACHE_HEADERS: [&str; 4] = ["etag", "last-modified", "content-language", "cache-control"];

/// Why an exported entry was not imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheRefusalV1 {
    /// The export or the entry belongs to another tenant.
    ForeignTenant,
    /// The exporter marked the entry private, or its `cache-control` says `private` or `no-store`.
    Private,
    /// A header outside [`SAFE_CACHE_HEADERS`] (cookies, credentials, proxy or unknown headers).
    UnsafeHeader,
    /// A safe header appears more than once.
    DuplicateHeader,
    /// The URL is not absolute HTTP(S), or carries credentials.
    BadUrl,
    /// A status other than 2xx.
    NotSuccessful,
    /// The media type is missing or not textual.
    UnsupportedContentType,
    /// The body is over [`MAX_CACHE_ENTRY_BODY_BYTES`].
    BodyTooLarge,
    /// The fetch time is later than the import time.
    FutureDate,
    /// An earlier entry of the same export has this URL.
    DuplicateUrl,
}

impl CacheRefusalV1 {
    /// Stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForeignTenant => "foreign_tenant",
            Self::Private => "private",
            Self::UnsafeHeader => "unsafe_header",
            Self::DuplicateHeader => "duplicate_header",
            Self::BadUrl => "bad_url",
            Self::NotSuccessful => "not_successful",
            Self::UnsupportedContentType => "unsupported_content_type",
            Self::BodyTooLarge => "body_too_large",
            Self::FutureDate => "future_date",
            Self::DuplicateUrl => "duplicate_url",
        }
    }

    /// One line for an operator; never contains entry data.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ForeignTenant => "the entry or export belongs to a different tenant than the import",
            Self::Private => "a private, authenticated or no-store response is never shared through a cache import",
            Self::UnsafeHeader => "only etag, last-modified, content-language and cache-control are imported; any other header refuses the entry",
            Self::DuplicateHeader => "a safe header appears more than once, so its value is ambiguous",
            Self::BadUrl => "the URL must be absolute HTTP(S) without credentials",
            Self::NotSuccessful => "only 2xx responses are reusable",
            Self::UnsupportedContentType => "only textual bodies (text/*, JSON, XML) are imported",
            Self::BodyTooLarge => "the body exceeds the per-entry import bound",
            Self::FutureDate => "the entry claims to have been fetched after the import time",
            Self::DuplicateUrl => "an earlier entry already carries this URL",
        }
    }
}

/// One entry that passed every check; the response validators and language are the only headers kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SafeCacheEntryV1 {
    /// The response URL.
    pub url: url::Url,
    /// A 2xx status.
    pub status_code: u16,
    /// A textual media type.
    pub content_type: String,
    /// When the response was fetched.
    pub fetched_at: Timestamp,
    /// `etag`, when exported.
    pub etag: Option<String>,
    /// `last-modified`, when exported.
    pub last_modified: Option<String>,
    /// `content-language`, when exported.
    pub content_language: Option<String>,
    /// The body text.
    pub body: String,
}

/// An entry that was refused, by its position in the export.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CacheRefusalRowV1 {
    /// Position of the entry in the export.
    pub index: usize,
    /// Why.
    pub cause: CacheRefusalV1,
}

/// The outcome of screening one export for one tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheImportV1 {
    /// Entries that may be stored, in export order.
    pub accepted: Vec<SafeCacheEntryV1>,
    /// Entries that may not, in export order.
    pub refused: Vec<CacheRefusalRowV1>,
}

impl CacheExportV1 {
    /// Parse an exported cache. The schema is strict: an unknown field, a repeated field or an
    /// unsupported version fails the whole export, and nothing of the input is echoed in the error.
    ///
    /// # Errors
    /// [`CoreError::Invalid`] for oversized, malformed or unsupported input.
    pub fn parse(bytes: &[u8]) -> Result<Self, CoreError> {
        let invalid = |reason: &str| CoreError::Invalid {
            field: "cache export",
            reason: reason.into(),
        };
        if bytes.len() > MAX_CACHE_EXPORT_BYTES {
            return Err(invalid("export exceeds the size bound"));
        }
        let export: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("not a version 1 cache export"))?;
        if export.version != CACHE_EXPORT_VERSION {
            return Err(invalid("unsupported cache export version"));
        }
        if export.entries.len() > MAX_CACHE_EXPORT_ENTRIES {
            return Err(invalid("export exceeds the entry bound"));
        }
        Ok(export)
    }

    /// Screen every entry for import into `tenant`'s cache at time `now`. Pure: no I/O, no clock.
    ///
    /// An export of another tenant yields no accepted entry. An entry is refused (never
    /// repaired) when it is private, names another tenant, carries any header outside
    /// [`SAFE_CACHE_HEADERS`], is not a successful textual HTTP(S) response without URL
    /// credentials, is too large, claims a future fetch time, or repeats a URL.
    #[must_use]
    pub fn screen(&self, tenant: TenantId, now: Timestamp) -> CacheImportV1 {
        let mut accepted = Vec::new();
        let mut refused = Vec::new();
        let mut seen = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let verdict = if self.tenant != tenant {
                Err(CacheRefusalV1::ForeignTenant)
            } else {
                screen_entry(entry, tenant, now, &mut seen)
            };
            match verdict {
                Ok(safe) => accepted.push(safe),
                Err(cause) => refused.push(CacheRefusalRowV1 { index, cause }),
            }
        }
        CacheImportV1 { accepted, refused }
    }
}

fn textual(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence.starts_with("text/")
        || matches!(
            essence.as_str(),
            "application/json" | "application/xml" | "application/xhtml+xml"
        )
        || essence.ends_with("+json")
        || essence.ends_with("+xml")
}

fn screen_entry(
    entry: &CacheEntryExportV1,
    tenant: TenantId,
    now: Timestamp,
    seen: &mut BTreeSet<String>,
) -> Result<SafeCacheEntryV1, CacheRefusalV1> {
    if entry.tenant.is_some_and(|owner| owner != tenant) {
        return Err(CacheRefusalV1::ForeignTenant);
    }
    if entry.private {
        return Err(CacheRefusalV1::Private);
    }
    let mut etag = None;
    let mut last_modified = None;
    let mut content_language = None;
    let mut cache_control = None;
    for header in &entry.headers {
        let slot = match header.name.to_ascii_lowercase().as_str() {
            "etag" => &mut etag,
            "last-modified" => &mut last_modified,
            "content-language" => &mut content_language,
            "cache-control" => &mut cache_control,
            _ => return Err(CacheRefusalV1::UnsafeHeader),
        };
        if slot.replace(header.value.clone()).is_some() {
            return Err(CacheRefusalV1::DuplicateHeader);
        }
    }
    if cache_control.is_some_and(|value: String| {
        let value = value.to_ascii_lowercase();
        value.split(',').any(|d| {
            matches!(
                d.trim().split('=').next().unwrap_or("").trim(),
                "private" | "no-store"
            )
        })
    }) {
        return Err(CacheRefusalV1::Private);
    }
    let url = url::Url::parse(&entry.url)
        .ok()
        .filter(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.has_host()
                && u.username().is_empty()
                && u.password().is_none()
        })
        .ok_or(CacheRefusalV1::BadUrl)?;
    if !(200..300).contains(&entry.status_code) {
        return Err(CacheRefusalV1::NotSuccessful);
    }
    let content_type = entry
        .content_type
        .clone()
        .filter(|ct| textual(ct))
        .ok_or(CacheRefusalV1::UnsupportedContentType)?;
    if entry.body.len() > MAX_CACHE_ENTRY_BODY_BYTES {
        return Err(CacheRefusalV1::BodyTooLarge);
    }
    if entry.fetched_at > now {
        return Err(CacheRefusalV1::FutureDate);
    }
    if !seen.insert(url.as_str().to_owned()) {
        return Err(CacheRefusalV1::DuplicateUrl);
    }
    Ok(SafeCacheEntryV1 {
        url,
        status_code: entry.status_code,
        content_type,
        fetched_at: entry.fetched_at,
        etag,
        last_modified,
        content_language,
        body: entry.body.clone(),
    })
}

/// A sanitized selector descriptor tied to a retained source run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdaptiveSelectorRecordV1 {
    /// Source run, used for authorization, retention and purge.
    pub run: CrawlRunId,
    /// Pure descriptor and caller-owned authority namespace.
    pub spec: AdaptiveSelectorSpecV1,
    /// Fixed expiry, never later than source run retention.
    pub expires_at: Timestamp,
}
impl AdaptiveSelectorRecordV1 {
    /// Construct a descriptor record; the repository enforces ownership and retention.
    #[must_use]
    pub fn new(run: CrawlRunId, spec: AdaptiveSelectorSpecV1, expires_at: Timestamp) -> Self {
        Self {
            run,
            spec,
            expires_at,
        }
    }
}

/// Scoped descriptor persistence. ZDR implementations use only shared volatile delivery.
#[async_trait]
pub trait AdaptiveSelectorRepo: Send + Sync {
    /// Save a bounded descriptor under its authenticated scope.
    /// # Errors
    /// Returns invalid descriptor, ownership, retention or storage errors.
    async fn put(&self, record: &AdaptiveSelectorRecordV1) -> Result<(), StoreError>;
    /// Read one exact scope and identifier, excluding expired or purged source runs.
    /// # Errors
    /// Returns ownership or storage errors; absence is not a relocation success.
    async fn get(
        &self,
        scope: &SelectorScopeV1,
        selector_id: &str,
        now: Timestamp,
    ) -> Result<Option<AdaptiveSelectorRecordV1>, StoreError>;
    /// Delete all descriptors of a purged run.
    /// # Errors
    /// Returns storage failures.
    async fn delete_run(&self, run: CrawlRunId) -> Result<(), StoreError>;
    /// Delete expired descriptors.
    /// # Errors
    /// Returns storage failures.
    async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn modes_have_explicit_read_write_and_offline_semantics() {
        for (mode, reads, writes, offline) in [
            (CacheModeV1::ReadWrite, true, true, false),
            (CacheModeV1::Bypass, false, true, false),
            (CacheModeV1::Disabled, false, false, false),
            (CacheModeV1::ReadOnly, true, false, true),
            (CacheModeV1::WriteOnly, false, true, false),
        ] {
            let p = CachePolicyV1 {
                mode,
                ..CachePolicyV1::default()
            };
            assert_eq!((p.reads(), p.writes(), p.cache_only()), (reads, writes, offline));
        }
        let p = CachePolicyV1 {
            development_replay: true,
            ..CachePolicyV1::default()
        };
        assert!(p.reads() && p.cache_only() && !p.writes());
    }
    #[test]
    fn principal_backend_validator_and_representation_never_share_keys() {
        let key = CacheKeyV1::new(
            "alice".into(),
            Digest::of("test", b"profile"),
            "http-1".into(),
            1,
            "wire_response".into(),
            Digest::of("test", b"request"),
        );
        let mut changed = key.clone();
        changed.principal = "bob".into();
        assert_ne!(key.digest(), changed.digest());
        changed = key.clone();
        changed.backend_capability = "http-2".into();
        assert_ne!(key.digest(), changed.digest());
        changed = key.clone();
        changed.validator_version = 2;
        assert_ne!(key.digest(), changed.digest());
        changed = key.clone();
        changed.representation = "rendered_dom".into();
        assert_ne!(key.digest(), changed.digest());
    }
    #[tokio::test]
    async fn resolved_credentials_are_tenant_keyed_and_order_stable() {
        let tenant = crate::TenantId(uuid::Uuid::from_u128(1));
        let other = crate::TenantId(uuid::Uuid::from_u128(2));
        let mut fetch = crate::config::Fetch::default();
        fetch.extra_headers.insert("x-token", "credential-canary-value");
        fetch.extra_headers.insert("authorization", "Bearer example");
        let controls = crate::request_controls::RequestControls::resolve(&fetch, "example.test", None)
            .await
            .unwrap();
        let digest = credential_digest(&[7; 32], tenant, &controls).unwrap();
        assert_ne!(digest, credential_digest(&[7; 32], other, &controls).unwrap());
        assert_ne!(digest, credential_digest(&[8; 32], tenant, &controls).unwrap());
        let mut reordered = crate::config::Fetch::default();
        reordered.extra_headers.insert("authorization", "Bearer example");
        reordered
            .extra_headers
            .insert("x-token", "credential-canary-value");
        let controls = crate::request_controls::RequestControls::resolve(&reordered, "example.test", None)
            .await
            .unwrap();
        assert_eq!(digest, credential_digest(&[7; 32], tenant, &controls).unwrap());
        let mut changed = reordered;
        changed.extra_headers.insert("x-token", "changed-credential");
        let controls = crate::request_controls::RequestControls::resolve(&changed, "example.test", None)
            .await
            .unwrap();
        assert_ne!(digest, credential_digest(&[7; 32], tenant, &controls).unwrap());
    }

    fn export(entries: serde_json::Value) -> CacheExportV1 {
        CacheExportV1::parse(
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "tenant": "00000000-0000-7000-8000-000000000001",
                "entries": entries,
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap()
    }
    fn tenant() -> TenantId {
        TenantId(uuid::Uuid::parse_str("00000000-0000-7000-8000-000000000001").unwrap())
    }
    fn now() -> Timestamp {
        "2026-02-01T00:00:00Z".parse().unwrap()
    }
    fn entry(extra: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "url": "https://example.test/a", "statusCode": 200, "contentType": "text/html; charset=utf-8",
            "fetchedAt": "2026-01-01T00:00:00Z", "body": "<p>a</p>"
        });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        base
    }

    #[test]
    fn a_plain_entry_is_imported_with_only_the_declared_fields() {
        let screened = export(serde_json::json!([entry(serde_json::json!({
            "headers": [
                {"name": "ETag", "value": "\"v1\""},
                {"name": "Last-Modified", "value": "Wed, 01 Jan 2026 00:00:00 GMT"},
                {"name": "Content-Language", "value": "en"},
                {"name": "Cache-Control", "value": "max-age=60, public"}
            ],
            "tenant": "00000000-0000-7000-8000-000000000001"
        }))]))
        .screen(tenant(), now());
        assert!(screened.refused.is_empty(), "{:?}", screened.refused);
        let safe = &screened.accepted[0];
        assert_eq!(safe.url.as_str(), "https://example.test/a");
        assert_eq!(safe.etag.as_deref(), Some("\"v1\""));
        assert_eq!(safe.content_language.as_deref(), Some("en"));
        assert_eq!(safe.body, "<p>a</p>");
        // nothing of the export beyond the declared fields exists on the imported value
        let wire = serde_json::to_value(safe).unwrap();
        let keys: std::collections::BTreeSet<&str> =
            wire.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "body",
                "contentLanguage",
                "contentType",
                "etag",
                "fetchedAt",
                "lastModified",
                "statusCode",
                "url"
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn private_foreign_and_credential_bearing_entries_are_refused_and_the_rest_imported() {
        let other = "00000000-0000-7000-8000-000000000002";
        let screened = export(serde_json::json!([
            entry(serde_json::json!({})),
            entry(serde_json::json!({"url": "https://example.test/private", "private": true})),
            entry(serde_json::json!({"url": "https://example.test/other", "tenant": other})),
            entry(serde_json::json!({"url": "https://example.test/cookie",
                "headers": [{"name": "Set-Cookie", "value": "sid=1"}]})),
            entry(serde_json::json!({"url": "https://example.test/auth",
                "headers": [{"name": "authorization", "value": "Bearer x"}]})),
            entry(serde_json::json!({"url": "https://example.test/unknown",
                "headers": [{"name": "X-Anything", "value": "1"}]})),
            entry(serde_json::json!({"url": "https://example.test/nostore",
                "headers": [{"name": "Cache-Control", "value": "no-store"}]})),
            entry(serde_json::json!({"url": "https://example.test/priv2",
                "headers": [{"name": "cache-control", "value": "max-age=5, Private=\"x\""}]})),
            entry(serde_json::json!({"url": "https://example.test/twice",
                "headers": [{"name": "etag", "value": "a"}, {"name": "ETAG", "value": "b"}]})),
            entry(serde_json::json!({"url": "https://user:pw@example.test/cred"})),
            entry(serde_json::json!({"url": "ftp://example.test/f"})),
            entry(serde_json::json!({"url": "not a url"})),
            entry(serde_json::json!({"url": "https://example.test/404", "statusCode": 404})),
            entry(serde_json::json!({"url": "https://example.test/img", "contentType": "image/png"})),
            entry(serde_json::json!({"url": "https://example.test/noct", "contentType": null})),
            entry(
                serde_json::json!({"url": "https://example.test/future", "fetchedAt": "2026-03-01T00:00:00Z"})
            ),
            entry(serde_json::json!({"url": "https://example.test/big",
                "body": "x".repeat(MAX_CACHE_ENTRY_BODY_BYTES + 1)})),
            entry(serde_json::json!({})),
            entry(
                serde_json::json!({"url": "https://example.test/json", "contentType": "application/ld+json"})
            ),
        ]))
        .screen(tenant(), now());
        let causes: Vec<(usize, &str)> = screened
            .refused
            .iter()
            .map(|r| (r.index, r.cause.as_str()))
            .collect();
        assert_eq!(
            causes,
            [
                (1, "private"),
                (2, "foreign_tenant"),
                (3, "unsafe_header"),
                (4, "unsafe_header"),
                (5, "unsafe_header"),
                (6, "private"),
                (7, "private"),
                (8, "duplicate_header"),
                (9, "bad_url"),
                (10, "bad_url"),
                (11, "bad_url"),
                (12, "not_successful"),
                (13, "unsupported_content_type"),
                (14, "unsupported_content_type"),
                (15, "future_date"),
                (16, "body_too_large"),
                (17, "duplicate_url"),
            ]
        );
        let urls: Vec<&str> = screened.accepted.iter().map(|e| e.url.as_str()).collect();
        assert_eq!(urls, ["https://example.test/a", "https://example.test/json"]);
        assert!(screened.refused.iter().all(|r| !r.cause.reason().is_empty()));
    }

    #[test]
    fn an_export_of_another_tenant_imports_nothing() {
        let mine = export(serde_json::json!([entry(serde_json::json!({}))]));
        let other = TenantId(uuid::Uuid::parse_str("00000000-0000-7000-8000-000000000009").unwrap());
        let screened = mine.screen(other, now());
        assert!(screened.accepted.is_empty());
        assert_eq!(screened.refused.len(), 1);
        assert_eq!(screened.refused[0].cause, CacheRefusalV1::ForeignTenant);
    }

    #[test]
    fn the_export_schema_is_strict_and_never_echoes_the_input() {
        let bad = |value: serde_json::Value| CacheExportV1::parse(&serde_json::to_vec(&value).unwrap());
        let ok_entry = entry(serde_json::json!({}));
        let t = "00000000-0000-7000-8000-000000000001";
        // an undeclared entry field is not dropped: the export is refused
        let mut with_cookie = ok_entry.clone();
        with_cookie["cookies"] = serde_json::json!("sid=secret-canary");
        let error = bad(serde_json::json!({"version":1,"tenant":t,"entries":[with_cookie]})).unwrap_err();
        assert!(!error.to_string().contains("secret-canary"), "{error}");
        assert!(bad(serde_json::json!({"version":1,"tenant":t,"entries":[],"extra":1})).is_err());
        assert!(bad(serde_json::json!({"version":2,"tenant":t,"entries":[]})).is_err());
        assert!(bad(serde_json::json!({"version":1,"entries":[]})).is_err());
        assert!(bad(serde_json::json!({"version":1,"tenant":"not-a-tenant","entries":[]})).is_err());
        // a repeated member cannot hide a second tenant or private flag
        let repeated = format!(
            "{{\"version\":1,\"tenant\":\"{t}\",\"tenant\":\"00000000-0000-7000-8000-000000000002\",\"entries\":[]}}"
        );
        assert!(CacheExportV1::parse(repeated.as_bytes()).is_err());
        let repeated_entry = format!(
            "{{\"version\":1,\"tenant\":\"{t}\",\"entries\":[{{\"url\":\"https://a.test/\",\"statusCode\":200,\"contentType\":\"text/html\",\"fetchedAt\":\"2026-01-01T00:00:00Z\",\"body\":\"\",\"private\":true,\"private\":false}}]}}"
        );
        assert!(CacheExportV1::parse(repeated_entry.as_bytes()).is_err());
        // bounds
        assert!(CacheExportV1::parse(&vec![b' '; MAX_CACHE_EXPORT_BYTES + 1]).is_err());
        let many: Vec<serde_json::Value> = (0..=MAX_CACHE_EXPORT_ENTRIES).map(|_| ok_entry.clone()).collect();
        assert!(bad(serde_json::json!({"version":1,"tenant":t,"entries":many})).is_err());
    }
}
