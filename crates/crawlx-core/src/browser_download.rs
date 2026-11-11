//! Explicit, bounded browser download requests. No caller-controlled filesystem destination exists.

use serde::{Deserialize, Serialize};
use url::Url;

/// An opt-in download into bounded memory before approved artifact delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DownloadSpec {
    /// HTTP(S) resource to download, checked by the context's navigation guard first.
    pub url: Url,
    /// Maximum accepted bytes, from 1 through 16 MiB, enforced while reading the stream.
    pub max_bytes: u64,
    /// Deadline for admission, transfer and artifact delivery, from 1 through 120,000 milliseconds.
    pub timeout_ms: u32,
}

impl DownloadSpec {
    /// Build an explicitly bounded download request. Execution validates all limits.
    #[must_use]
    pub const fn new(url: Url, max_bytes: u64, timeout_ms: u32) -> Self {
        Self {
            url,
            max_bytes,
            timeout_ms,
        }
    }

    /// Validate download admission bounds without sending any browser command.
    ///
    /// # Errors
    /// Rejects non-HTTP(S) URLs, user information, fragments and limits outside supported bounds.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.url.scheme(), "http" | "https")
            || !self.url.username().is_empty()
            || self.url.password().is_some()
            || self.url.fragment().is_some()
        {
            return Err("download URL must be HTTP(S) without user information or fragment");
        }
        if !(1..=16 * 1024 * 1024).contains(&self.max_bytes) {
            return Err("download byte limit must be within 1..=16777216");
        }
        if !(1..=120_000).contains(&self.timeout_ms) {
            return Err("download timeout must be within 1..=120000 milliseconds");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn bounds_and_url_admission_are_explicit() {
        let mut spec = DownloadSpec::new(Url::parse("https://example.test/public").unwrap(), 1024, 1000);
        assert!(spec.validate().is_ok());
        assert_eq!(
            serde_json::from_str::<DownloadSpec>(&serde_json::to_string(&spec).unwrap()).unwrap(),
            spec
        );
        for url in [
            "file:///tmp/private",
            "https://user@example.test/",
            "https://example.test/#fragment",
        ] {
            spec.url = Url::parse(url).unwrap();
            assert!(spec.validate().is_err());
        }
        spec.url = Url::parse("https://example.test/public").unwrap();
        for bytes in [0, 16 * 1024 * 1024 + 1] {
            spec.max_bytes = bytes;
            assert!(spec.validate().is_err());
        }
        spec.max_bytes = 1024;
        for milliseconds in [0, 120_001] {
            spec.timeout_ms = milliseconds;
            assert!(spec.validate().is_err());
        }
    }
}
