//! Explicit, bounded source discovery and worker-only auxiliary acquisition policy.
//!
//! URLs and publisher hints are content, not safe telemetry. Parsing never grants network
//! authority. Each discovered resource still passes the run's scope and checked egress.

use crate::{time::Timestamp, CoreError};
use serde::{Deserialize, Serialize};
use url::Url;

/// Default lifetime known-URL ceiling, independent of page acquisition limits.
#[must_use]
pub const fn default_max_known_urls() -> u32 {
    100_000
}

/// Sources enabled by an admitted crawl, in deterministic stage order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DiscoverySourceV1 {
    /// Normal document links.
    Html,
    /// Declared RSS, RDF, Atom or JSON feeds.
    Feeds,
    /// Robots-declared or configured sitemaps.
    Sitemap,
    /// Navigation/category links, never a scope exemption.
    Categories,
    /// Explicitly configured conventional feed paths.
    Conventional,
    /// Explicit Google News connector.
    GoogleNews,
    /// Explicit Google Trends connector.
    GoogleTrends,
    /// Explicit Internet Archive CDX connector.
    Archive,
}
/// Whether to explore or measure actual extracted article sufficiency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DiscoveryModeV1 {
    /// Discover sources and use bounded focused traversal after sitemap enumeration.
    #[default]
    Explore,
    /// Record article extraction counts and reasons; never infer success from HTTP alone.
    Probe,
}
/// Explicit provider protocol; no default endpoint is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DiscoveryProviderV1 {
    /// RSS article records, including publisher-source hints.
    GoogleNews,
    /// Google Trends daily-trends JSON response or trends RSS.
    GoogleTrends,
    /// CDX JSON table with original, timestamp and optional statuscode columns.
    InternetArchive,
}
/// Operator-selected connector. The endpoint is still subject to run authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DiscoveryConnectorV1 {
    /// Declared response protocol.
    pub provider: DiscoveryProviderV1,
    /// Exact request URL, including caller-selected query and provider options.
    pub endpoint: Url,
    /// For CDX only: explicitly authorized replay prefix, e.g. https://archive.test/web/.
    pub archive_base: Option<Url>,
}
/// Treatment of sitemap entries whose last-modified hint is absent or unparseable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SitemapUnknownLastmodV1 {
    /// Preserve entries with no usable last-modified hint.
    #[default]
    Include,
    /// Reject entries with no usable last-modified hint.
    Exclude,
}

/// Inclusive UTC bounds on sitemap URL-entry last-modified hints, not publication dates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "SitemapLastmodPolicyWire")]
#[non_exhaustive]
pub struct SitemapLastmodPolicyV1 {
    /// Inclusive lower instant; omission leaves the lower side unbounded.
    pub lower: Option<Timestamp>,
    /// Inclusive upper instant; omission leaves the upper side unbounded.
    pub upper: Option<Timestamp>,
    /// Explicit treatment of missing or unparseable hints; defaults to include.
    pub missing_or_unparseable: SitemapUnknownLastmodV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SitemapLastmodPolicyWire {
    lower: Option<Timestamp>,
    upper: Option<Timestamp>,
    #[serde(default)]
    missing_or_unparseable: SitemapUnknownLastmodV1,
}

impl TryFrom<SitemapLastmodPolicyWire> for SitemapLastmodPolicyV1 {
    type Error = CoreError;

    fn try_from(value: SitemapLastmodPolicyWire) -> Result<Self, Self::Error> {
        Self::new(value.lower, value.upper, value.missing_or_unparseable)
    }
}

impl SitemapLastmodPolicyV1 {
    /// Construct an inclusive last-modified range without consulting a clock.
    ///
    /// # Errors
    /// Rejects a range with neither bound, or a lower bound after its upper bound.
    pub fn new(
        lower: Option<Timestamp>,
        upper: Option<Timestamp>,
        missing_or_unparseable: SitemapUnknownLastmodV1,
    ) -> Result<Self, CoreError> {
        let policy = Self {
            lower,
            upper,
            missing_or_unparseable,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Reject empty or reversed ranges, including manually edited native policies.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` for absent bounds or reversed instants.
    pub fn validate(&self) -> Result<(), CoreError> {
        if (self.lower.is_none() && self.upper.is_none())
            || self
                .lower
                .zip(self.upper)
                .is_some_and(|(lower, upper)| lower > upper)
        {
            return Err(CoreError::Invalid {
                field: "scope.discovery.sitemapLastmod",
                reason: "at least one bound is required and lower must not exceed upper".into(),
            });
        }
        Ok(())
    }

    /// Test a parsed URL-entry hint. Index-file hints must never call this filter.
    #[must_use]
    pub fn includes(&self, lastmod: Option<&Timestamp>) -> bool {
        let Some(lastmod) = lastmod else {
            return self.missing_or_unparseable == SitemapUnknownLastmodV1::Include;
        };
        self.lower.as_ref().is_none_or(|lower| lastmod >= lower)
            && self.upper.as_ref().is_none_or(|upper| lastmod <= upper)
    }
}

/// Opt-in discovery; omission keeps existing crawl behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceDiscoveryPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Explore or actual extraction sufficiency probe.
    pub mode: DiscoveryModeV1,
    /// Maximum source documents admitted per parent document.
    pub max_source_documents: usize,
    /// Largest decoded source body accepted by pure parsers.
    pub max_feed_bytes: usize,
    /// Maximum article records from one source body.
    pub max_entries: usize,
    /// Maximum XML/JSON structural nesting.
    pub max_nesting: usize,
    /// Maximum source traversal depth, also bounded by normal scope depth.
    pub max_source_depth: u16,
    /// Conventional feed/source paths; empty means no guessed source paths.
    /// Explicit feed discovery may still admit a bounded origin-homepage fallback.
    pub conventional_paths: Vec<String>,
    /// Maximum navigation/category links admitted per document.
    pub max_category_links: usize,
    /// Maximum focused article links admitted per document.
    pub max_focused_links: usize,
    /// Minimum in-scope sitemap candidates before focused HTML fallback is unnecessary.
    pub min_sitemap_articles: usize,
    /// Optional URL-entry last-modified filter; index-file timestamps never prune traversal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sitemap_lastmod: Option<SitemapLastmodPolicyV1>,
    /// Minimum selected article characters for a sufficient probe.
    pub sufficient_main_chars: usize,
    /// Maximum read-more hops per primary page; zero disables acquisition.
    pub read_more_hops: u8,
    /// Maximum image header probes per primary page; zero disables acquisition.
    pub media_probes: usize,
    /// Maximum decoded bytes read from one media response.
    pub media_header_bytes: usize,
    /// Maximum accepted width times height, checked before image decoding.
    pub max_media_pixels: u64,
    /// Explicit external connectors; never auto-populated after feed failure.
    pub connectors: Vec<DiscoveryConnectorV1>,
}
impl Default for SourceDiscoveryPolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            mode: DiscoveryModeV1::Explore,
            max_source_documents: 16,
            max_feed_bytes: 2 * 1024 * 1024,
            max_entries: 1000,
            max_nesting: 32,
            max_source_depth: 5,
            conventional_paths: Vec::new(),
            max_category_links: 32,
            max_focused_links: 64,
            min_sitemap_articles: 1,
            sitemap_lastmod: None,
            sufficient_main_chars: 300,
            read_more_hops: 0,
            media_probes: 0,
            media_header_bytes: 64 * 1024,
            max_media_pixels: 40_000_000,
            connectors: Vec::new(),
        }
    }
}
impl SourceDiscoveryPolicyV1 {
    /// Reject unbounded or ambiguous source policy before admission.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` for unsupported versions, excessive limits or unsafe URLs.
    pub fn validate(&self) -> Result<(), CoreError> {
        if let Some(lastmod) = &self.sitemap_lastmod {
            lastmod.validate()?;
        }
        let valid = self.version == 1
            && (1..=64).contains(&self.max_source_documents)
            && (1..=8_388_608).contains(&self.max_feed_bytes)
            && (1..=10_000).contains(&self.max_entries)
            && (1..=64).contains(&self.max_nesting)
            && (1..=16).contains(&self.max_source_depth)
            && self.conventional_paths.len() <= 16
            && self.max_category_links <= 256
            && self.max_focused_links <= 1000
            && (1..=1000).contains(&self.min_sitemap_articles)
            && (1..=1_000_000).contains(&self.sufficient_main_chars)
            && self.read_more_hops <= 4
            && self.media_probes <= 16
            && (24..=65_536).contains(&self.media_header_bytes)
            && (1..=100_000_000).contains(&self.max_media_pixels)
            && self.connectors.len() <= 8
            && self.conventional_paths.iter().all(|path| {
                path.starts_with('/')
                    && !path.starts_with("//")
                    && path.len() <= 2048
                    && !path.contains(['#', '\\'])
            })
            && self.connectors.iter().all(|connector| {
                safe_endpoint(&connector.endpoint)
                    && (connector.provider != DiscoveryProviderV1::InternetArchive
                        || connector.archive_base.is_some())
                    && connector.archive_base.as_ref().is_none_or(safe_endpoint)
            });
        if valid {
            Ok(())
        } else {
            Err(CoreError::Invalid {
                field: "scope.discovery",
                reason: "invalid source, connector, traversal or auxiliary acquisition bounds".into(),
            })
        }
    }
}
fn safe_endpoint(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.as_str().len() <= 4096
}
/// Typed connector absence or protocol failure; never an empty-success substitute.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryErrorV1 {
    /// Required protected worker resource is absent.
    #[error("discovery capability unavailable: {0}")]
    CapabilityUnavailable(&'static str),
    /// Replay never dispatches live external provider protocols.
    #[error("discovery provider forbidden in cache-only replay: {0:?}")]
    ProviderForbiddenInReplay(DiscoveryProviderV1),
    /// Requested connector was not explicitly configured.
    #[error("discovery provider unavailable: {0:?}")]
    ProviderUnavailable(DiscoveryProviderV1),
    /// Bounded source protocol parsing failed.
    #[error("discovery protocol rejected: {0}")]
    Protocol(String),
    /// A fixed resource limit was reached before accepting the document.
    #[error("discovery resource limit exceeded: {0}")]
    Limit(&'static str),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn sitemap_lastmod_bounds_are_inclusive_and_normalize_utc_offsets() {
        let policy: SitemapLastmodPolicyV1 = serde_json::from_value(serde_json::json!({
            "lower":"2026-01-02T02:00:00+02:00",
            "upper":"2026-01-02T19:00:00-05:00"
        }))
        .unwrap();
        for (hint, included) in [
            ("2026-01-01T23:59:59Z", false),
            ("2026-01-02T00:00:00Z", true),
            ("2026-01-02T12:00:00Z", true),
            ("2026-01-03T00:00:00Z", true),
            ("2026-01-03T00:00:01Z", false),
        ] {
            let timestamp: Timestamp = hint.parse().unwrap();
            assert_eq!(policy.includes(Some(&timestamp)), included, "{hint}");
        }
        assert!(policy.includes(None));
        let mut exclude = policy.clone();
        exclude.missing_or_unparseable = SitemapUnknownLastmodV1::Exclude;
        assert!(!exclude.includes(None));
        let mut equal = policy.clone();
        equal.upper = equal.lower;
        assert!(equal.validate().is_ok());
        assert!(equal.includes(equal.lower.as_ref()));
        let mut lower_only = policy.clone();
        lower_only.upper = None;
        assert!(lower_only.includes(Some(&"2030-01-01T00:00:00Z".parse().unwrap())));
        let mut upper_only = policy;
        upper_only.lower = None;
        assert!(upper_only.includes(Some(&"2020-01-01T00:00:00Z".parse().unwrap())));
    }

    #[test]
    fn sitemap_lastmod_rejects_empty_reversed_and_ambiguous_bounds() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"lower":null,"upper":null,"missingOrUnparseable":"exclude"}),
            serde_json::json!({"lower":"2026-01-03T00:00:00Z","upper":"2026-01-02T00:00:00Z"}),
            serde_json::json!({"lower":"2026-01-02"}),
            serde_json::json!({"lower":"2026-01-02T00:00:00"}),
            serde_json::json!({"lower":"2026-01-02T00:00:00Z","relativeDays":7}),
        ] {
            assert!(serde_json::from_value::<SitemapLastmodPolicyV1>(value).is_err());
        }
        let mut source = SourceDiscoveryPolicyV1 {
            sitemap_lastmod: Some(
                SitemapLastmodPolicyV1::new(
                    Some("2026-01-02T00:00:00Z".parse().unwrap()),
                    None,
                    SitemapUnknownLastmodV1::Include,
                )
                .unwrap(),
            ),
            ..SourceDiscoveryPolicyV1::default()
        };
        source.sitemap_lastmod.as_mut().unwrap().lower = None;
        assert!(source.validate().is_err());
    }

    #[test]
    fn rejects_unbounded_or_authority_changing_conventional_paths() {
        let mut policy = SourceDiscoveryPolicyV1::default();
        policy.conventional_paths.push("//private.test/feed".into());
        assert!(policy.validate().is_err());
        policy.conventional_paths.clear();
        policy.max_nesting = usize::MAX;
        assert!(policy.validate().is_err());
    }
}
