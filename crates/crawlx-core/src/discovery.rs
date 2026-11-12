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
    /// Explicit news-search connector.
    NewsSearch,
    /// Explicit trends-search connector.
    TrendsSearch,
    /// Explicit web-archive CDX index connector.
    Archive,
    /// Caller-supplied inline URL list ([`UrlListSourceV1`]); no network or file is read.
    UrlList,
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
    NewsSearch,
    /// Trends-search daily-trends JSON response or trends RSS.
    TrendsSearch,
    /// CDX JSON table with original, timestamp and optional statuscode columns.
    WebArchiveIndex,
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
    /// Optional inline URL list; requires [`DiscoverySourceV1::UrlList`] in `scope.sources`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_list: Option<UrlListSourceV1>,
    /// Optional target language whose URL evidence only orders discovered URLs
    /// ([`url_language_evidence`]); never proof of content language, never a filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_language_hint: Option<String>,
    /// Explicit bounded article repeat suppression, applied only after current admission.
    pub article_memo: crate::dataset::memo::ArticleMemoPolicyV1,
    /// Representation/role-scoped category proposals with worker-clock expiry.
    pub category_cache: crate::dataset::memo::CategoryCachePolicyV1,
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
            url_list: None,
            url_language_hint: None,
            article_memo: crate::dataset::memo::ArticleMemoPolicyV1::default(),
            category_cache: crate::dataset::memo::CategoryCachePolicyV1::default(),
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
        if let Some(list) = &self.url_list {
            list.validate()?;
        }
        if let Some(hint) = &self.url_language_hint {
            validate_language_hint(hint)?;
        }
        let valid = self.version == 1
            && (1..=crate::dataset::memo::MAX_MEMO_ENTRIES).contains(&self.article_memo.max_entries)
            && (1..=604_800).contains(&self.category_cache.ttl_seconds)
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
                    && (connector.provider != DiscoveryProviderV1::WebArchiveIndex
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

impl SourceDiscoveryPolicyV1 {
    /// Check that `sources` and the policy agree about list discovery: the list source is
    /// enabled exactly when an inline list is present, and the list fits the lifetime
    /// known-URL ceiling `max_known_urls`.
    ///
    /// # Errors
    /// Returns `CoreError::Conflict` when only one of source and list is present, or
    /// `CoreError::Invalid` when the list is invalid or larger than `max_known_urls`.
    pub fn validate_sources(
        &self,
        sources: &[DiscoverySourceV1],
        max_known_urls: u32,
    ) -> Result<(), CoreError> {
        let listed = sources.contains(&DiscoverySourceV1::UrlList);
        match (&self.url_list, listed) {
            (Some(list), true) => list.resolve(max_known_urls).map(|_| ()),
            (None, false) => Ok(()),
            _ => Err(CoreError::Conflict {
                a: "scope.sources",
                b: "scope.discovery.urlList",
                reason: "the url_list source and an inline URL list must be configured together".to_owned(),
            }),
        }
    }

    /// Ranking adjustment of `url` from the optional language hint: positive when the URL
    /// carries evidence for the hinted language, negative for evidence of another language,
    /// zero without a hint or without evidence. It orders candidates only; it never admits,
    /// denies, or labels the content language of a URL.
    #[must_use]
    pub fn language_rank(&self, url: &Url) -> i8 {
        self.url_language_hint
            .as_deref()
            .map_or(0, |hint| url_language_evidence(url, hint).rank_delta())
    }
}

/// Most URLs in one inline list.
pub const MAX_LISTED_URLS: usize = 10_000;
/// Longest accepted URL in an inline list, in bytes.
pub const MAX_LISTED_URL_BYTES: usize = 4096;
/// Largest total of URL bytes in one inline list.
pub const MAX_LISTED_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// Caller-supplied, inline URL list: the list-discovery source.
///
/// The type holds URL text only. Reading a file or standard input is the caller's job and
/// happens before this value exists, so the core type carries no filesystem path and
/// resolving it performs no I/O. Resolution bounds the count and bytes, rejects anything that
/// is not a credential-free HTTP(S) URL, strips fragments and drops exact duplicates while
/// keeping first-seen order. Every resolved URL is still only a candidate: the worker applies
/// scope, robots, authorization and checked egress to each one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlListSourceV1 {
    /// URL text, one entry per URL. Entries carry no surrounding whitespace or control
    /// characters; blank entries are rejected, not skipped.
    pub urls: Vec<String>,
}

/// Deduplicated list: candidate URLs in first-seen order and the known-URL set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedUrlListV1 {
    /// Unique URLs in first-seen order.
    pub urls: Vec<Url>,
    /// The same URLs as a sorted set of normalized strings, to seed the lifetime known-URL
    /// check so rediscovering a listed URL is not queued twice.
    pub known: std::collections::BTreeSet<String>,
    /// Entries dropped as exact duplicates of an earlier entry.
    pub duplicates: usize,
}

impl ResolvedUrlListV1 {
    /// One discovery intent per unique URL, in list order. An intent is a candidate, never
    /// permission to fetch.
    #[must_use]
    pub fn intents(&self) -> Vec<crate::extraction::DiscoveryIntentV1> {
        self.urls
            .iter()
            .map(|url| {
                crate::extraction::DiscoveryIntentV1::new(
                    url.clone(),
                    crate::extraction::DiscoveryPurposeV1::ListedUrl,
                )
            })
            .collect()
    }
}

impl UrlListSourceV1 {
    /// Build a list from entries, validating it.
    ///
    /// # Errors
    /// Same as [`UrlListSourceV1::validate`].
    pub fn new(urls: Vec<String>) -> Result<Self, CoreError> {
        let list = Self { urls };
        list.validate()?;
        Ok(list)
    }

    /// Check count, byte and per-entry bounds.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` for an empty or oversized list, an oversized, blank,
    /// whitespace-padded or non-HTTP(S) entry, an entry with credentials, or an unparseable URL.
    pub fn validate(&self) -> Result<(), CoreError> {
        self.resolve(u32::MAX).map(|_| ())
    }

    /// Parse, normalize and deduplicate the list without any I/O.
    ///
    /// `max_known_urls` is the crawl's lifetime known-URL ceiling; a list with more unique
    /// URLs is refused rather than truncated.
    ///
    /// # Errors
    /// Same as [`UrlListSourceV1::validate`], plus when the unique URL count exceeds
    /// `max_known_urls`.
    pub fn resolve(&self, max_known_urls: u32) -> Result<ResolvedUrlListV1, CoreError> {
        let invalid = |reason: &str| CoreError::Invalid {
            field: "scope.discovery.urlList",
            reason: reason.to_owned(),
        };
        if self.urls.is_empty() {
            return Err(invalid("a URL list needs at least one entry"));
        }
        if self.urls.len() > MAX_LISTED_URLS {
            return Err(invalid("at most 10000 URLs"));
        }
        let total = self
            .urls
            .iter()
            .fold(0usize, |sum, url| sum.saturating_add(url.len()));
        if total > MAX_LISTED_TOTAL_BYTES {
            return Err(invalid("at most 4 MiB of URL text"));
        }
        let ceiling = usize::try_from(max_known_urls).unwrap_or(usize::MAX);
        let mut urls = Vec::new();
        let mut known = std::collections::BTreeSet::new();
        let mut duplicates = 0usize;
        for entry in &self.urls {
            if entry.is_empty() || entry.len() > MAX_LISTED_URL_BYTES {
                return Err(invalid("each URL is between one and 4096 bytes"));
            }
            if entry.trim() != entry || entry.chars().any(char::is_control) {
                return Err(invalid(
                    "URLs carry no surrounding whitespace or control characters",
                ));
            }
            let mut url = Url::parse(entry).map_err(|_| invalid("an entry is not an absolute URL"))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(invalid("entries are credential-free HTTP(S) URLs"));
            }
            url.set_fragment(None);
            if known.insert(url.as_str().to_owned()) {
                if known.len() > ceiling {
                    return Err(invalid("unique URLs exceed the known-URL ceiling"));
                }
                urls.push(url);
            } else {
                duplicates = duplicates.saturating_add(1);
            }
        }
        Ok(ResolvedUrlListV1 {
            urls,
            known,
            duplicates,
        })
    }
}

/// Most substrings in one filter.
pub const MAX_URL_SUBSTRINGS: usize = 64;
/// Longest substring, in bytes. Escaping at most doubles it, inside the 512-byte pattern bound.
pub const MAX_URL_SUBSTRING_BYTES: usize = 256;

/// Plain-substring URL include filter, the discovery form of the source `--url-filter`
/// option.
///
/// A URL passes when its normalized text contains at least one substring (case-sensitive;
/// normalized URLs have a lowercase scheme and host). The filter translates to
/// `scope.urlInclude` through [`UrlSubstringFilterV1::include_patterns`], so it composes with
/// the rest of scope exactly like any other include pattern:
///
/// * host scope, `excludeHosts`, `urlExclude`, `excludePaths`, robots, authorization and
///   checked egress run unchanged; an explicit deny always wins and a substring match never
///   re-admits a URL they refuse;
/// * the substring filter only narrows: with it present, a candidate must match one substring
///   in addition to passing every other scope rule;
/// * the crawl seed is exempt from include patterns, as for every `urlInclude`: it is fetched
///   once to start discovery.
///
/// A target-language hint is separate: see [`url_language_evidence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSubstringFilterV1 {
    substrings: Vec<String>,
}

impl UrlSubstringFilterV1 {
    /// Validate `substrings`: between one and 64 distinct, non-blank entries without control
    /// characters, each at most 256 bytes. Exact duplicates are dropped, order is kept.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` when a bound or character rule fails.
    pub fn new(substrings: Vec<String>) -> Result<Self, CoreError> {
        let invalid = |reason: &str| CoreError::Invalid {
            field: "scope.urlInclude",
            reason: reason.to_owned(),
        };
        if substrings.is_empty() || substrings.len() > MAX_URL_SUBSTRINGS {
            return Err(invalid("between one and 64 substrings"));
        }
        let mut unique: Vec<String> = Vec::with_capacity(substrings.len());
        for substring in substrings {
            if substring.trim().is_empty()
                || substring.len() > MAX_URL_SUBSTRING_BYTES
                || substring.chars().any(char::is_control)
            {
                return Err(invalid(
                    "substrings are non-blank, at most 256 bytes, without control characters",
                ));
            }
            if !unique.contains(&substring) {
                unique.push(substring);
            }
        }
        Ok(Self { substrings: unique })
    }

    /// The substrings, in input order.
    #[must_use]
    pub fn substrings(&self) -> &[String] {
        &self.substrings
    }

    /// Does `url` (normalized URL text) contain any substring?
    #[must_use]
    pub fn matches(&self, url: &str) -> bool {
        self.substrings
            .iter()
            .any(|substring| url.contains(substring.as_str()))
    }

    /// Regex patterns for `scope.urlInclude`: each substring with every regex metacharacter
    /// escaped, so the pattern matches the literal text anywhere in the URL.
    #[must_use]
    pub fn include_patterns(&self) -> Vec<String> {
        self.substrings
            .iter()
            .map(|substring| regex::escape(substring))
            .collect()
    }
}

/// ISO 639-1 language codes, sorted for binary search.
const ISO_639_1: [&str; 184] = [
    "aa", "ab", "ae", "af", "ak", "am", "an", "ar", "as", "av", "ay", "az", "ba", "be", "bg", "bh", "bi",
    "bm", "bn", "bo", "br", "bs", "ca", "ce", "ch", "co", "cr", "cs", "cu", "cv", "cy", "da", "de", "dv",
    "dz", "ee", "el", "en", "eo", "es", "et", "eu", "fa", "ff", "fi", "fj", "fo", "fr", "fy", "ga", "gd",
    "gl", "gn", "gu", "gv", "ha", "he", "hi", "ho", "hr", "ht", "hu", "hy", "hz", "ia", "id", "ie", "ig",
    "ii", "ik", "io", "is", "it", "iu", "ja", "jv", "ka", "kg", "ki", "kj", "kk", "kl", "km", "kn", "ko",
    "kr", "ks", "ku", "kv", "kw", "ky", "la", "lb", "lg", "li", "ln", "lo", "lt", "lu", "lv", "mg", "mh",
    "mi", "mk", "ml", "mn", "mr", "ms", "mt", "my", "na", "nb", "nd", "ne", "ng", "nl", "nn", "no", "nr",
    "nv", "ny", "oc", "oj", "om", "or", "os", "pa", "pi", "pl", "ps", "pt", "qu", "rm", "rn", "ro", "ru",
    "rw", "sa", "sc", "sd", "se", "sg", "si", "sk", "sl", "sm", "sn", "so", "sq", "sr", "ss", "st", "su",
    "sv", "sw", "ta", "te", "tg", "th", "ti", "tk", "tl", "tn", "to", "tr", "ts", "tt", "tw", "ty", "ug",
    "uk", "ur", "uz", "ve", "vi", "vo", "wa", "wo", "xh", "yi", "yo", "za", "zh", "zu",
];

/// Primary language subtag of an ISO 639-1 tag (`de`, `de-AT`, `pt_BR`, `es-419`), or `None`
/// for anything else.
fn primary_language(tag: &str) -> Option<&'static str> {
    let (primary, region) = match tag.split_once(['-', '_']) {
        Some((primary, region)) => (primary, Some(region)),
        None => (tag, None),
    };
    if let Some(region) = region {
        let alpha = region.len() == 2 && region.bytes().all(|b| b.is_ascii_alphabetic());
        let numeric = region.len() == 3 && region.bytes().all(|b| b.is_ascii_digit());
        if !(alpha || numeric) {
            return None;
        }
    }
    let bytes = primary.as_bytes();
    if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let lower = [bytes[0].to_ascii_lowercase(), bytes[1].to_ascii_lowercase()];
    let lower = std::str::from_utf8(&lower).ok()?;
    ISO_639_1.binary_search(&lower).ok().map(|index| ISO_639_1[index])
}

fn validate_language_hint(hint: &str) -> Result<(), CoreError> {
    if primary_language(hint).is_some() {
        Ok(())
    } else {
        Err(CoreError::Invalid {
            field: "scope.discovery.urlLanguageHint",
            reason: "an ISO 639-1 code, optionally with a region (`de`, `pt-BR`)".to_owned(),
        })
    }
}

/// What the URL itself says about a target language. It is a guess from URL shape, not a
/// property of the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UrlLanguageEvidenceV1 {
    /// Every language marker in the URL names the target language.
    Matches,
    /// Every language marker in the URL names another language.
    Conflicts,
    /// No marker, or markers for both the target and another language.
    Absent,
}

impl UrlLanguageEvidenceV1 {
    /// Ranking adjustment: `1` for a match, `-1` for a conflict, `0` otherwise. A consumer may
    /// add it to a priority; it is not a decision input.
    #[must_use]
    pub const fn rank_delta(self) -> i8 {
        match self {
            Self::Matches => 1,
            Self::Conflicts => -1,
            Self::Absent => 0,
        }
    }
}

/// Language evidence in the shape of `url`.
///
/// Markers are the first host label when the host has at least three labels
/// (`de.example.test`), the first path segment (`/de/`, `/pt-BR/`), and the query values of
/// `lang`, `language`, `hl`, `locale` and `lng`. Only ISO 639-1 codes, alone or with a region,
/// count. The result is never proof of the language of the content behind the URL: a `/de/`
/// page may be English, and an unmarked page may be German. Callers use it to order discovery
/// candidates and must not use it to admit, deny or label content; language decisions stay
/// with the extraction language policy.
#[must_use]
pub fn url_language_evidence(url: &Url, language: &str) -> UrlLanguageEvidenceV1 {
    let Some(target) = primary_language(language) else {
        return UrlLanguageEvidenceV1::Absent;
    };
    let mut equal = false;
    let mut differs = false;
    let mut observe = |candidate: &str| {
        if let Some(code) = primary_language(candidate) {
            if code == target {
                equal = true;
            } else {
                differs = true;
            }
        }
    };
    if let Some(host) = url.host_str() {
        if host.matches('.').count() >= 2 {
            if let Some(label) = host.split('.').next() {
                observe(label);
            }
        }
    }
    if let Some(segment) = url.path_segments().and_then(|mut segments| segments.next()) {
        observe(segment);
    }
    for (key, value) in url.query_pairs() {
        if matches!(
            key.to_ascii_lowercase().as_str(),
            "lang" | "language" | "hl" | "locale" | "lng"
        ) {
            observe(&value);
        }
    }
    match (equal, differs) {
        (true, false) => UrlLanguageEvidenceV1::Matches,
        (false, true) => UrlLanguageEvidenceV1::Conflicts,
        _ => UrlLanguageEvidenceV1::Absent,
    }
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

/// Most recorded seed fixtures one crawl carries.
pub const MAX_SEED_FIXTURES: usize = 8;
/// Largest recorded seed fixture, in bytes.
pub const MAX_SEED_FIXTURE_BYTES: usize = 1024 * 1024;
/// Largest candidate count `scope.seeding.maxUrls` may ask for.
pub const MAX_SEED_URLS: u32 = 100_000;

/// What kind of recorded document a seed fixture is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SeedSourceKindV1 {
    /// A capture-index listing: one record per line (`urlkey timestamp original ...`), JSON
    /// lines, or a JSON table with an `original`/`url` column.
    ArchiveIndex,
    /// A certificate-transparency log search result (a JSON array of entries naming hosts).
    CertificateTransparency,
    /// A sitemap or sitemap index.
    Sitemap,
    /// A `robots.txt`: its sitemap lines and its literal allow/disallow paths.
    Robots,
    /// An RSS, Atom or JSON feed.
    Feed,
    /// An HTML home page: its links.
    Homepage,
}

impl SeedSourceKindV1 {
    /// Stable `snake_case` name, identical to the serde form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArchiveIndex => "archive_index",
            Self::CertificateTransparency => "certificate_transparency",
            Self::Sitemap => "sitemap",
            Self::Robots => "robots",
            Self::Feed => "feed",
            Self::Homepage => "homepage",
        }
    }
}

/// One recorded document. It holds the bytes themselves, never a path or an address: the caller
/// reads a file before it builds the crawl, and nothing here touches a network or a disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SeedFixtureV1 {
    /// What the document is.
    pub kind: SeedSourceKindV1,
    /// The recorded document text, at most [`MAX_SEED_FIXTURE_BYTES`].
    pub content: String,
}

impl SeedFixtureV1 {
    /// A fixture of `kind` holding `content`.
    #[must_use]
    pub fn new(kind: SeedSourceKindV1, content: impl Into<String>) -> Self {
        Self {
            kind,
            content: content.into(),
        }
    }
}

/// Whether a candidate must answer a live request before it is queued.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SeedLiveCheckV1 {
    /// Queue every in-scope, robots-allowed candidate without a request.
    #[default]
    Off,
    /// Send one `HEAD` request per candidate first and queue it only on a status of 200 to 399.
    /// The request is made only after scope and robots admit the candidate, goes through the
    /// run's checked fetcher and origin governor, and follows no redirect.
    Head,
}

/// `scope.seeding`: candidate URLs read from recorded sources, queued next to the seed.
///
/// Candidates are parsed from [`SeedFixtureV1`] documents in order, deduplicated by their
/// normalized text (first sighting wins), capped at `maxUrls`, and queued at depth 1. A
/// candidate is only a proposal: it must pass scope, robots, authorization and the budget like
/// any discovered link, so a source can never widen the crawl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SeedSourcesV1 {
    /// Exactly one.
    #[serde(default = "SeedSourcesV1::default_version")]
    pub version: u16,
    /// Recorded documents, parsed in order.
    pub fixtures: Vec<SeedFixtureV1>,
    /// Candidates kept after deduplication, `1..=100000` (default 1000).
    #[serde(default = "SeedSourcesV1::default_max_urls")]
    pub max_urls: u32,
    /// Live check applied to each candidate (default off).
    #[serde(default)]
    pub live_check: SeedLiveCheckV1,
}

impl SeedSourcesV1 {
    const fn default_version() -> u16 {
        1
    }
    const fn default_max_urls() -> u32 {
        1000
    }

    /// Sources over `fixtures` with the documented defaults.
    #[must_use]
    pub fn new(fixtures: Vec<SeedFixtureV1>) -> Self {
        Self {
            version: 1,
            fixtures,
            max_urls: Self::default_max_urls(),
            live_check: SeedLiveCheckV1::Off,
        }
    }

    /// Check count and byte bounds.
    ///
    /// # Errors
    /// An unsupported version, no fixture, too many or too large fixtures, or `maxUrls` out of
    /// range.
    pub fn validate(&self) -> Result<(), CoreError> {
        let invalid = |reason: &str| CoreError::Invalid {
            field: "scope.seeding",
            reason: reason.to_owned(),
        };
        if self.version != 1 {
            return Err(invalid("unsupported version"));
        }
        if self.fixtures.is_empty() || self.fixtures.len() > MAX_SEED_FIXTURES {
            return Err(invalid("between 1 and 8 fixtures"));
        }
        if self
            .fixtures
            .iter()
            .any(|fixture| fixture.content.len() > MAX_SEED_FIXTURE_BYTES)
        {
            return Err(invalid("a fixture is at most 1 MiB"));
        }
        if !(1..=MAX_SEED_URLS).contains(&self.max_urls) {
            return Err(invalid("maxUrls is between 1 and 100000"));
        }
        Ok(())
    }
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

    fn list(entries: &[&str]) -> UrlListSourceV1 {
        UrlListSourceV1 {
            urls: entries.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn url_list_is_deduplicated_in_first_seen_order_with_a_sorted_known_set() {
        let resolved = list(&[
            "https://b.example.test/two",
            "https://a.example.test/one#section",
            "https://B.EXAMPLE.test/two",
            "https://a.example.test/one",
            "https://c.example.test:443/three",
        ])
        .resolve(100)
        .unwrap();
        let order: Vec<_> = resolved.urls.iter().map(Url::as_str).collect();
        assert_eq!(
            order,
            [
                "https://b.example.test/two",
                "https://a.example.test/one",
                "https://c.example.test/three"
            ]
        );
        assert_eq!(resolved.duplicates, 2);
        let known: Vec<_> = resolved.known.iter().map(String::as_str).collect();
        assert_eq!(
            known,
            [
                "https://a.example.test/one",
                "https://b.example.test/two",
                "https://c.example.test/three"
            ]
        );
        let intents = resolved.intents();
        assert_eq!(intents.len(), 3);
        assert!(intents
            .iter()
            .all(|i| i.purpose == crate::extraction::DiscoveryPurposeV1::ListedUrl));
        assert_eq!(intents[0].url.as_str(), "https://b.example.test/two");
    }

    #[test]
    fn url_list_refuses_unbounded_blank_foreign_and_credentialed_entries() {
        for entries in [
            vec![],
            vec![""],
            vec![" https://a.example.test/"],
            vec!["https://a.example.test/\n"],
            vec!["ftp://a.example.test/file"],
            vec!["file:///etc/passwd"],
            vec!["/var/lib/urls.txt"],
            vec!["urls.txt"],
            vec!["https://user:secret@a.example.test/"],
            vec!["https://user@a.example.test/"],
            vec!["not a url"],
        ] {
            assert!(list(&entries).validate().is_err(), "{entries:?}");
        }
        let long = format!("https://a.example.test/{}", "x".repeat(MAX_LISTED_URL_BYTES));
        assert!(list(&[long.as_str()]).validate().is_err());
        let many: Vec<String> = (0..=MAX_LISTED_URLS)
            .map(|n| format!("https://a.example.test/{n}"))
            .collect();
        assert!(UrlListSourceV1::new(many).is_err());
        let at_limit: Vec<String> = (0..MAX_LISTED_URLS)
            .map(|n| format!("https://a.example.test/{n}"))
            .collect();
        assert_eq!(
            UrlListSourceV1::new(at_limit)
                .unwrap()
                .resolve(100_000)
                .unwrap()
                .urls
                .len(),
            MAX_LISTED_URLS
        );
        // The known-URL ceiling counts unique URLs and refuses instead of truncating.
        let three = list(&[
            "https://a.example.test/1",
            "https://a.example.test/2",
            "https://a.example.test/1",
        ]);
        assert!(three.resolve(2).is_ok());
        assert!(three.resolve(1).is_err());
        // Byte ceiling: a thousand maximum-size entries exceed the 4 MiB total before parsing.
        let big: Vec<String> = (0..1100)
            .map(|n| {
                format!(
                    "https://a.example.test/{n}/{}",
                    "y".repeat(MAX_LISTED_URL_BYTES - 40)
                )
            })
            .collect();
        assert!(UrlListSourceV1::new(big).is_err());
    }

    #[test]
    fn list_source_and_inline_list_must_be_configured_together() {
        let mut policy = SourceDiscoveryPolicyV1::default();
        assert!(policy.validate_sources(&[DiscoverySourceV1::Html], 10).is_ok());
        assert!(policy
            .validate_sources(&[DiscoverySourceV1::UrlList], 10)
            .is_err());
        policy.url_list = Some(list(&["https://a.example.test/"]));
        assert!(policy.validate().is_ok());
        assert!(policy.validate_sources(&[DiscoverySourceV1::Html], 10).is_err());
        assert!(policy.validate_sources(&[DiscoverySourceV1::UrlList], 10).is_ok());
        policy.url_list = Some(list(&["ftp://a.example.test/"]));
        assert!(policy.validate().is_err());
    }

    #[test]
    fn omitted_list_and_hint_keep_policy_serialization_unchanged() {
        let encoded = serde_json::to_value(SourceDiscoveryPolicyV1::default()).unwrap();
        let object = encoded.as_object().unwrap();
        assert!(!object.contains_key("urlList") && !object.contains_key("urlLanguageHint"));
        let with = SourceDiscoveryPolicyV1 {
            url_list: Some(list(&["https://a.example.test/"])),
            url_language_hint: Some("de".into()),
            ..SourceDiscoveryPolicyV1::default()
        };
        let round: SourceDiscoveryPolicyV1 =
            serde_json::from_value(serde_json::to_value(&with).unwrap()).unwrap();
        assert_eq!(round, with);
        assert_eq!(
            serde_json::to_value(DiscoverySourceV1::UrlList).unwrap(),
            "url_list"
        );
    }

    #[test]
    fn substring_filter_patterns_are_literal_and_agree_with_substring_matching() {
        let filter = UrlSubstringFilterV1::new(vec![
            "/blog/".into(),
            "?id=1".into(),
            "a.b".into(),
            "/blog/".into(),
        ])
        .unwrap();
        assert_eq!(filter.substrings().len(), 3);
        let patterns = filter.include_patterns();
        assert!(patterns.iter().all(|p| p.len() <= 2 * MAX_URL_SUBSTRING_BYTES));
        let compiled: Vec<regex::Regex> = patterns.iter().map(|p| regex::Regex::new(p).unwrap()).collect();
        for url in [
            "https://example.test/blog/post",
            "https://example.test/blogger/post",
            "https://example.test/page?id=1&x=2",
            "https://example.test/page?id=12",
            "https://example.test/page?idx1",
            "https://example.test/a.b",
            "https://example.test/aXb",
            "https://example.test/",
        ] {
            let by_regex = compiled.iter().any(|r| r.is_match(url));
            assert_eq!(by_regex, filter.matches(url), "{url}");
        }
        assert!(!filter.matches("https://example.test/aXb"));
    }

    #[test]
    fn substring_filter_rejects_empty_oversized_and_control_entries() {
        assert!(UrlSubstringFilterV1::new(vec![]).is_err());
        assert!(UrlSubstringFilterV1::new(vec!["  ".into()]).is_err());
        assert!(UrlSubstringFilterV1::new(vec!["a\u{0}b".into()]).is_err());
        assert!(UrlSubstringFilterV1::new(vec!["x".repeat(MAX_URL_SUBSTRING_BYTES + 1)]).is_err());
        assert!(UrlSubstringFilterV1::new(vec!["x".repeat(MAX_URL_SUBSTRING_BYTES)]).is_ok());
        assert!(
            UrlSubstringFilterV1::new((0..=MAX_URL_SUBSTRINGS).map(|n| n.to_string()).collect()).is_err()
        );
    }

    #[test]
    fn language_evidence_orders_but_never_proves() {
        let ev = |url: &str, lang: &str| url_language_evidence(&Url::parse(url).unwrap(), lang);
        assert_eq!(
            ev("https://example.test/de/news", "de"),
            UrlLanguageEvidenceV1::Matches
        );
        assert_eq!(
            ev("https://example.test/de-AT/news", "de"),
            UrlLanguageEvidenceV1::Matches
        );
        assert_eq!(
            ev("https://example.test/pt_BR/news", "pt-BR"),
            UrlLanguageEvidenceV1::Matches
        );
        assert_eq!(
            ev("https://de.example.test/news", "de"),
            UrlLanguageEvidenceV1::Matches
        );
        assert_eq!(
            ev("https://example.test/news?lang=DE", "de"),
            UrlLanguageEvidenceV1::Matches
        );
        assert_eq!(
            ev("https://example.test/fr/news", "de"),
            UrlLanguageEvidenceV1::Conflicts
        );
        assert_eq!(
            ev("https://example.test/news", "de"),
            UrlLanguageEvidenceV1::Absent
        );
        // Two-label hosts and non-language segments carry no evidence.
        assert_eq!(ev("https://de.test/news", "fr"), UrlLanguageEvidenceV1::Absent);
        assert_eq!(
            ev("https://example.test/xx/news", "de"),
            UrlLanguageEvidenceV1::Absent
        );
        assert_eq!(
            ev("https://example.test/german/news", "de"),
            UrlLanguageEvidenceV1::Absent
        );
        // Markers for both the target and another language cancel out.
        assert_eq!(
            ev("https://fr.example.test/de/news", "de"),
            UrlLanguageEvidenceV1::Absent
        );
        // A bad hint yields no evidence rather than a guess.
        assert_eq!(
            ev("https://example.test/de/news", "german"),
            UrlLanguageEvidenceV1::Absent
        );
        assert_eq!(UrlLanguageEvidenceV1::Matches.rank_delta(), 1);
        assert_eq!(UrlLanguageEvidenceV1::Conflicts.rank_delta(), -1);

        let mut policy = SourceDiscoveryPolicyV1::default();
        let page = Url::parse("https://example.test/de/news").unwrap();
        assert_eq!(policy.language_rank(&page), 0);
        policy.url_language_hint = Some("de".into());
        assert_eq!(policy.language_rank(&page), 1);
        assert_eq!(
            policy.language_rank(&Url::parse("https://example.test/fr/news").unwrap()),
            -1
        );
        policy.url_language_hint = Some("german".into());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn language_code_table_is_sorted_and_unique() {
        assert!(ISO_639_1.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(ISO_639_1
            .iter()
            .all(|code| code.len() == 2 && code.bytes().all(|b| b.is_ascii_lowercase())));
    }
}
