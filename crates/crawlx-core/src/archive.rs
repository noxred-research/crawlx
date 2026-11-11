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

/// Explicit payload reuse scope. Chronological capture records are never removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveDedupe {
    /// Keep independent payloads; the default preserves existing behavior.
    #[default]
    None,
    /// Reuse committed compatible native bodies or run-bound retained DOM/text renditions in this export.
    Collection,
    /// Also reuse compatible complete native bodies from published tenant-opted-in sources, with local package closure.
    Tenant,
}

impl ArchiveDedupe {
    fn is_none(&self) -> bool {
        *self == Self::None
    }
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
    /// Opt-in reuse of approved native bodies and same-run retained DOM/text renditions.
    #[serde(skip_serializing_if = "ArchiveDedupe::is_none")]
    pub dedupe: ArchiveDedupe,
    /// Maximum total encoded export bytes.
    pub max_bytes: u64,
    /// Optional hard encoded size cap per WARC file; supported only for WACZ.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollover_bytes: Option<u64>,
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
            dedupe: ArchiveDedupe::None,
            max_bytes: 1_073_741_824,
            rollover_bytes: None,
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
        if let Some(bytes) = self.rollover_bytes {
            if bytes == 0 || bytes > self.max_bytes {
                return Err("archive rollover bound must be positive and not exceed total bytes");
            }
            if self.format != ArchiveFormat::Wacz {
                return Err("archive rollover requires WACZ format");
            }
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Byte classification and source deadline inherited by the package and adjacent index.
    #[serde(default)]
    pub custody: crate::archive_catalog::ArchiveCustodyV1,
    /// Standalone source records embedded to close cross-export revisit dependencies.
    #[serde(default, skip_serializing_if = "zero")]
    pub materialized_dependencies: u64,
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
            custody: crate::archive_catalog::ArchiveCustodyV1::default(),
            materialized_dependencies: 0,
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

fn zero(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn rollover_is_opt_in_and_does_not_change_default_serialized_spec() {
        let mut config = ArchiveConfigV1::default();
        let previous = serde_json::json!({
            "version": 1, "format": "wacz", "capture": "available",
            "maxBytes": 1_073_741_824_u64, "maxRecordBytes": 16_777_216,
            "maxRecords": 10_000
        });
        assert_eq!(serde_json::to_value(&config).unwrap(), previous);
        assert_eq!(
            serde_json::from_value::<ArchiveConfigV1>(previous).unwrap(),
            config
        );
        config.rollover_bytes = Some(1);
        assert!(config.validate().is_ok());
        assert_eq!(serde_json::to_value(&config).unwrap()["rolloverBytes"], 1);
        config.format = ArchiveFormat::Warc;
        assert_eq!(config.validate(), Err("archive rollover requires WACZ format"));
        config.format = ArchiveFormat::Wacz;
        config.rollover_bytes = Some(0);
        assert!(config.validate().is_err());
        config.rollover_bytes = Some(config.max_bytes + 1);
        assert!(config.validate().is_err());
    }
}
