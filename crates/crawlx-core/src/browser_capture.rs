//! Bounded browser evidence and its retention-policy boundary.

use crate::{ArtifactRef, StoreError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Browser-produced representation, never a claim of original wire fidelity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CaptureKind {
    /// Browser-generated multipart page snapshot.
    Mhtml,
    /// Encoded page image.
    Screenshot,
    /// Browser-generated printed document.
    Pdf,
    /// Explicitly authorized attachment.
    Download,
    /// Rendered document text.
    Text,
}

/// Proven completeness of a browser-produced representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CaptureCompleteness {
    /// Complete within the stated representation, not necessarily all remote assets.
    Complete,
    /// Requested representation exceeded a stated bound.
    Clipped,
    /// Completeness cannot be established from available browser evidence.
    Unknown,
}

/// Metadata passed to the policy sink before persistence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CaptureDescriptor {
    /// Representation being retained.
    pub kind: CaptureKind,
    /// Actual encoded media type.
    pub content_type: String,
    /// Validated attachment basename, never a host path.
    pub filename: Option<String>,
    /// Source document or attachment URL; policy must approve/redact before storage.
    pub source_url: String,
    /// Whether the requested representation was clipped or known source resources are missing.
    pub truncated: bool,
}

/// Retained browser evidence. Raw bytes and host paths are not exposed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CaptureArtifact {
    /// Truthful representation metadata.
    pub descriptor: CaptureDescriptor,
    /// Policy-owned retained artifact.
    pub artifact: ArtifactRef,
    /// Encoded bytes accepted by the sink.
    pub bytes: u64,
    /// Actual image width in pixels, when applicable.
    pub width: Option<u32>,
    /// Actual image height in pixels, when applicable.
    pub height: Option<u32>,
    /// Completeness of the chosen representation.
    pub completeness: CaptureCompleteness,
}

/// Explicit bounded capture request. No request implies capture permission.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum CaptureSpec {
    /// Capture the browser's multipart snapshot with a hard encoded byte limit.
    Mhtml {
        /// Maximum accepted encoded bytes.
        max_bytes: u64,
    },
    /// Capture the selected screenshot representation.
    Screenshot {
        /// Screenshot selection and encoding.
        shot: crate::page_op::ShotSpec,
        /// Maximum accepted encoded bytes.
        max_bytes: u64,
        /// Maximum accepted pixel count.
        max_pixels: u64,
    },
    /// Print a bounded PDF.
    Pdf {
        /// Paper and scale selection.
        spec: crate::page_op::PdfSpec,
        /// Maximum accepted encoded bytes.
        max_bytes: u64,
    },
    /// Capture bounded rendered text, explicitly labelled if clipped.
    Text {
        /// Maximum accepted UTF-8 bytes.
        max_bytes: u64,
    },
}

/// Fail-closed policy authority for browser evidence.
///
/// Implementations reject ZDR/durable mismatches before capture, then validate/redact bytes
/// before handing approved payloads to the typed artifact sink. Binary approval is explicit.
#[async_trait]
pub trait BrowserCaptureSink: Send + Sync + std::fmt::Debug {
    /// Authorize a representation before enabling capture or transient spooling.
    ///
    /// # Errors
    /// Returns retention or policy authority failures without content.
    async fn authorize(&self, kind: CaptureKind) -> Result<bool, StoreError>;

    /// Approve bounded source DOM before a screenshot or opaque generated representation.
    ///
    /// # Errors
    /// Returns source privacy failures. The default refuses sources it cannot validate.
    async fn authorize_source(&self, source: &[u8]) -> Result<bool, StoreError> {
        let _ = source;
        Ok(false)
    }

    /// Validate and retain bounded bytes. `None` records a policy refusal, not an empty body.
    ///
    /// # Errors
    /// Returns secret-validation, retention or storage failures without content.
    async fn store(
        &self,
        descriptor: &CaptureDescriptor,
        bytes: &crate::secret::Redacted<Vec<u8>>,
    ) -> Result<Option<ArtifactRef>, StoreError>;
}

/// URL-filtered XHR/Fetch response projection bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct XhrProjectionSpec {
    /// URL patterns using `*` as the only wildcard. Empty matches nothing.
    pub url_patterns: Vec<String>,
    /// Maximum retained response records.
    pub max_records: u32,
    /// Maximum serialized metadata bytes, excluding policy-owned body artifacts.
    pub max_bytes: u64,
}

/// Bounded console and network projection settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DiagnosticsSpec {
    /// Maximum network events.
    pub max_records: u32,
    /// Maximum serialized metadata bytes across network and console records.
    pub max_bytes: u64,
}

/// Opt-in evidence capture configuration. Absence preserves existing capture behavior.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct BrowserEvidenceConfig {
    /// Filtered XHR/Fetch response projection, with body artifact provenance.
    pub xhr: Option<XhrProjectionSpec>,
    /// Bounded console/network diagnostics with explicit unavailable states.
    pub diagnostics: Option<DiagnosticsSpec>,
    /// Retain browser-produced MHTML at observation boundaries.
    pub mhtml: bool,
    /// Retain browser-produced PDF at observation boundaries.
    pub pdf: bool,
    /// Retain initial/final rendered text and screenshots around session behavior.
    pub phase_resources: bool,
    /// Explicit attachment requests; no arbitrary host destination is accepted.
    pub downloads: Vec<crate::browser_download::DownloadSpec>,
}

impl CaptureDescriptor {
    /// Describe a complete representation before policy validation.
    #[must_use]
    pub fn new(kind: CaptureKind, content_type: impl Into<String>, source_url: impl Into<String>) -> Self {
        Self {
            kind,
            content_type: content_type.into(),
            filename: None,
            source_url: source_url.into(),
            truncated: false,
        }
    }
}

impl CaptureArtifact {
    /// Describe accepted artifact bytes without inventing image geometry.
    #[must_use]
    pub fn new(
        descriptor: CaptureDescriptor,
        artifact: ArtifactRef,
        bytes: u64,
        completeness: CaptureCompleteness,
    ) -> Self {
        Self {
            descriptor,
            artifact,
            bytes,
            width: None,
            height: None,
            completeness,
        }
    }
}

impl BrowserEvidenceConfig {
    /// Whether any browser evidence was explicitly requested.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.xhr.is_some() || self.diagnostics.is_some() || self.durable()
    }

    /// Whether evidence needs durable content permission.
    #[must_use]
    pub fn durable(&self) -> bool {
        self.mhtml || self.pdf || self.phase_resources || !self.downloads.is_empty()
    }

    /// Check hard bounds before browser effects or queue allocation.
    ///
    /// # Errors
    /// Returns a fixed reason for invalid projection or download limits.
    pub fn validate(&self) -> Result<(), &'static str> {
        fn bounds(records: u32, bytes: u64) -> Result<(), &'static str> {
            if !(1..=5_000).contains(&records) || !(1..=8_388_608).contains(&bytes) {
                return Err("browser projection requires 1..=5000 records and 1..=8388608 bytes");
            }
            Ok(())
        }
        if let Some(xhr) = &self.xhr {
            bounds(xhr.max_records, xhr.max_bytes)?;
            if xhr.url_patterns.is_empty()
                || xhr.url_patterns.len() > 128
                || xhr
                    .url_patterns
                    .iter()
                    .any(|pattern| pattern.is_empty() || pattern.len() > 8192)
            {
                return Err("xhr capture requires 1..=128 URL patterns of 1..=8192 bytes");
            }
        }
        if let Some(diagnostics) = &self.diagnostics {
            bounds(diagnostics.max_records, diagnostics.max_bytes)?;
        }
        if self.downloads.len() > 32 {
            return Err("browser capture permits at most 32 explicit downloads");
        }
        for download in &self.downloads {
            download.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn projection_bounds_are_explicit_and_default_capture_is_disabled() {
        let mut config = BrowserEvidenceConfig::default();
        assert!(!config.enabled());
        config.xhr = Some(XhrProjectionSpec {
            url_patterns: vec!["https://site.test/api/*".into()],
            max_records: 2,
            max_bytes: 4096,
        });
        assert!(config.enabled());
        assert!(!config.durable());
        assert!(config.validate().is_ok());
        config.xhr.as_mut().unwrap().max_bytes = 0;
        assert!(config.validate().is_err());
        config.xhr.as_mut().unwrap().max_bytes = 8_388_609;
        assert!(config.validate().is_err());
        config.xhr.as_mut().unwrap().max_bytes = 4096;
        config.xhr.as_mut().unwrap().url_patterns.clear();
        assert!(config.validate().is_err());
    }
}
