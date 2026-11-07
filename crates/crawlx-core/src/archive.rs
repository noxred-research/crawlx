//! Shared retained-resource archival contracts for offline export and opt-in live finalization.
//! Capture facts describe retained representations, never inferred wire bytes.

use crate::{CrawlRunId, TenantId, Timestamp};
use serde::{Deserialize, Serialize};

/// Retained-resource archive container.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveFormat {
    /// Record-at-a-time gzip WARC with adjacent CDXJ and manifest files.
    Warc,
    /// WACZ 1.1.1 ZIP64 package.
    #[default]
    Wacz,
}

/// Required completeness of an export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveCapture {
    /// Export available approved resources and disclose omissions.
    #[default]
    Available,
    /// Refuse if any required original resource is unavailable.
    RequireComplete,
}

/// Bounded archive configuration for retained-resource export and live finalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveConfigV1 {
    /// Contract version; only 1 is supported.
    pub version: u16,
    /// Output format.
    pub format: ArchiveFormat,
    /// Completeness requirement.
    pub capture: ArchiveCapture,
    /// Maximum total encoded export bytes.
    pub max_bytes: u64,
    /// Maximum retained UTF-8 representation size. Does not authorize raw binary capture.
    pub max_record_bytes: u64,
    /// Maximum number of retained records.
    pub max_records: u32,
}

impl Default for ArchiveConfigV1 {
    fn default() -> Self {
        Self {
            version: 1,
            format: ArchiveFormat::Wacz,
            capture: ArchiveCapture::Available,
            max_bytes: 1_073_741_824,
            max_record_bytes: 16_777_216,
            max_records: 10_000,
        }
    }
}

impl ArchiveConfigV1 {
    /// Validate bounded retained-resource codec settings; this does not authorize binary capture.
    ///
    /// # Errors
    /// Returns a static reason for an unsupported version or unsafe bound.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 {
            return Err("unsupported archive configuration version");
        }
        if self.max_record_bytes == 0 || self.max_record_bytes > 16_777_216 {
            return Err("archive record bound must be between 1 and 16777216 bytes");
        }
        if self.max_bytes < self.max_record_bytes || self.max_bytes > 1_073_741_824 {
            return Err("archive total bound must contain one record and not exceed 1 GiB");
        }
        if self.max_records == 0 || self.max_records > 10_000 {
            return Err("archive record count must be between 1 and 10000");
        }
        Ok(())
    }
}

/// Meaning of stored bytes, independent of their MIME type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveRepresentation {
    /// Captured original protocol wire message; requires explicit source evidence.
    WireHttp,
    /// Rebuilt HTTP message, not original wire framing.
    NormalizedHttp,
    /// Retained HTML snapshot; may be rendered or sanitized.
    RenderedDom,
    /// Retained screenshot under a separate binary capability.
    Screenshot,
    /// Retained extracted text or Markdown.
    ExtractedText,
    /// Non-HTTP resource.
    ProtocolResource,
}

/// Truthful capture provenance attached to an archived resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveCaptureFactsV1 {
    /// Capture source, such as retained_page_html; never an inferred backend.
    pub capture_source: String,
    /// Actual source protocol, when persisted.
    pub source_protocol: Option<String>,
    /// Meaning of the stored bytes.
    pub representation: ArchiveRepresentation,
    /// Complete, prefix, or unknown as established by capture owner.
    pub body_state: String,
    /// Redaction policy applied before any archive staging.
    pub redaction_revision: String,
    /// Ordered transformations of the stored bytes.
    pub transformations: Vec<String>,
    /// Persisted source event ordinal or page frontier identifier.
    pub source_event: String,
    /// Real capture date from the retained source.
    pub captured_at: Timestamp,
}

impl ArchiveCaptureFactsV1 {
    /// Describe a retained page rendition without inferring its original acquisition backend.
    #[must_use]
    pub fn retained(
        source_event: impl Into<String>,
        captured_at: Timestamp,
        representation: ArchiveRepresentation,
        capture_source: impl Into<String>,
    ) -> Self {
        Self {
            capture_source: capture_source.into(),
            source_protocol: None,
            representation,
            body_state: "unknown".into(),
            redaction_revision: "archive-text-v1".into(),
            transformations: vec![
                "retained_rendition_not_original_wire".into(),
                "secret_and_session_redaction".into(),
            ],
            source_event: source_event.into(),
            captured_at,
        }
    }
}
/// Resource excluded or unavailable in this export.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveOmissionV1 {
    /// Stable source ordinal, without raw URL or credential material.
    pub source_event: String,
    /// Machine-readable omission reason.
    pub reason: String,
}

impl ArchiveOmissionV1 {
    /// Describe an omitted source resource.
    #[must_use]
    pub fn new(source_event: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            source_event: source_event.into(),
            reason: reason.into(),
        }
    }
}

/// Final offline export description. This is content-bearing retention metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveManifestV1 {
    /// Contract version.
    pub schema_version: u16,
    /// Tenant whose retained artifacts were read.
    pub tenant: TenantId,
    /// Source run.
    pub run: CrawlRunId,
    /// Persisted source time used for reproducible packaging metadata.
    pub created: Timestamp,
    /// False when original response/capture completeness is unavailable.
    pub complete: bool,
    /// Number of committed resource records, excluding warcinfo/metadata.
    pub records: u64,
    /// Explicit absent representations and privacy exclusions.
    pub omissions: Vec<ArchiveOmissionV1>,
}

impl ArchiveManifestV1 {
    /// Start an honest available-resource manifest for a retained run.
    #[must_use]
    pub fn available(tenant: TenantId, run: CrawlRunId, created: Timestamp) -> Self {
        Self {
            schema_version: 1,
            tenant,
            run,
            created,
            complete: false,
            records: 0,
            omissions: vec![
                ArchiveOmissionV1::new(
                    "run",
                    "original_wire_headers_bodies_and_subresource_completeness_unavailable",
                ),
                ArchiveOmissionV1::new("run", "binary_capture_not_authorized"),
                ArchiveOmissionV1::new("run", "credentials_cookies_and_storage_excluded"),
            ],
        }
    }
}
