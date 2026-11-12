//! Typed configuration and portable state of adaptive crawling.
//!
//! Two independent policies live here as plain data; neither performs I/O or reads a clock:
//!
//! * [`AdaptiveRendering`] decides how often a page that looks static is nevertheless verified in
//!   the browser plane (the "probe"), under a recorded predictor version.
//! * [`AdaptiveStopConfigV1`] bounds a query-driven crawl: it stops when more pages stop adding
//!   information about the query. [`AdaptiveStopExportV1`] is its versioned, portable state.
//!
//! The logic that evaluates them lives in `crawlx-strategies`; the worker records every decision.

use crate::{hash::Digest, CoreError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The only predictor implementation this build can record and replay.
pub const PREDICTOR_VERSION: u32 = 1;

/// Largest run-wide probe allowance a crawl may configure.
pub const MAX_PROBES: u32 = 100_000;

/// `dynamic.adaptive`: the static/browser render predictor.
///
/// Every fetched page is classified by the heuristic render predictor. A page it calls static is
/// additionally *probed* (handed to the browser plane once) with a seeded probability, so a wrong
/// prediction can be noticed. The draw is a pure function of the run seed, the predictor version
/// and the URL, recorded with the page, so replaying a run reproduces it. Each probe is charged
/// to the request's effect budget before the page is fetched; a probe the budget cannot pay is
/// denied and recorded, never run for free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdaptiveRendering {
    /// Predictor implementation to record and replay; only [`PREDICTOR_VERSION`] exists.
    #[serde(default = "AdaptiveRendering::default_version")]
    pub predictor_version: u32,
    /// Probability, in thousandths, that a URL is selected for a probe (default 100).
    #[serde(default = "AdaptiveRendering::default_probe_per_mille")]
    pub probe_per_mille: u16,
    /// Most probes one worker pays for in a run (default 16).
    #[serde(default = "AdaptiveRendering::default_max_probes")]
    pub max_probes: u32,
    /// Effects one probe adds to its request's effect charge, `1..=8` (default 1).
    #[serde(default = "AdaptiveRendering::default_probe_effects")]
    pub probe_effects: u32,
}

impl AdaptiveRendering {
    const fn default_version() -> u32 {
        PREDICTOR_VERSION
    }
    const fn default_probe_per_mille() -> u16 {
        100
    }
    const fn default_max_probes() -> u32 {
        16
    }
    const fn default_probe_effects() -> u32 {
        1
    }

    /// A configuration probing with probability `probe_per_mille` thousandths, at most
    /// `max_probes` times a run, one effect each.
    #[must_use]
    pub const fn new(probe_per_mille: u16, max_probes: u32) -> Self {
        Self {
            predictor_version: PREDICTOR_VERSION,
            probe_per_mille,
            max_probes,
            probe_effects: Self::default_probe_effects(),
        }
    }

    /// Check the bounds. Mode and orchestration requirements are checked with the crawl.
    ///
    /// # Errors
    /// An unsupported predictor version, a probability over 1000 or an out-of-range allowance.
    pub fn validate(&self) -> Result<(), CoreError> {
        let invalid = |reason: &str| CoreError::Invalid {
            field: "dynamic.adaptive",
            reason: reason.to_owned(),
        };
        if self.predictor_version != PREDICTOR_VERSION {
            return Err(invalid("unsupported predictorVersion"));
        }
        if self.probe_per_mille > 1000 {
            return Err(invalid("probePerMille is at most 1000"));
        }
        if self.max_probes > MAX_PROBES {
            return Err(invalid("maxProbes is at most 100000"));
        }
        if !(1..=8).contains(&self.probe_effects) {
            return Err(invalid("probeEffects is between 1 and 8"));
        }
        Ok(())
    }
}

impl Default for AdaptiveRendering {
    fn default() -> Self {
        Self {
            predictor_version: PREDICTOR_VERSION,
            probe_per_mille: Self::default_probe_per_mille(),
            max_probes: Self::default_max_probes(),
            probe_effects: Self::default_probe_effects(),
        }
    }
}

/// Highest confidence the adaptive stop policy ever reports, in thousandths. Confidence is a
/// coverage estimate over the pages fetched so far; it is capped below certainty because a
/// finished crawl never proves that nothing relevant was left unfetched.
pub const CONFIDENCE_CEILING_PERMILLE: u16 = 950;

/// Most query terms kept after normalization.
pub const MAX_QUERY_TERMS: usize = 32;

/// Words too common to describe a query; dropped by [`query_terms`].
const STOP_WORDS: [&str; 40] = [
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can", "do", "for", "from", "has", "have", "how",
    "i", "in", "is", "it", "its", "of", "on", "or", "that", "the", "this", "to", "was", "what", "when",
    "where", "which", "who", "why", "will", "with", "you", "your", "about",
];

/// Whether `token` is a lowercase term the adaptive policy counts.
fn usable_term(token: &str) -> bool {
    let chars = token.chars().count();
    (2..=40).contains(&chars) && !STOP_WORDS.contains(&token)
}

/// Lowercase alphanumeric terms of `text`, in document order, without stop words. Stable across
/// platforms: it uses only Unicode alphanumeric classification and lowercase mapping.
pub fn terms(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .filter(|token| usable_term(token))
}

/// Sorted, distinct terms of a query, at most [`MAX_QUERY_TERMS`] of them.
#[must_use]
pub fn query_terms(query: &str) -> Vec<String> {
    let mut found: Vec<String> = terms(query).collect();
    found.sort();
    found.dedup();
    found.truncate(MAX_QUERY_TERMS);
    found
}

/// Digest of a query's normalized terms. Two queries that normalize to the same terms share it,
/// so exported state binds to the question it answered, not to its spelling.
#[must_use]
pub fn query_digest(query: &str) -> Digest {
    Digest::of(
        "crawlx/adaptive-query/v1",
        query_terms(query).join("\n").as_bytes(),
    )
}

/// `adaptive`: a query-driven stop policy for a crawl.
///
/// The crawl stops at the first of: `maxPages` evaluated pages; the average information gain of
/// the last `window` pages falling below `minGainPermille` (saturation); the confidence estimate
/// reaching `targetConfidencePermille`. The stop is a statement about gain on the fetched pages,
/// never about exhaustive coverage of the site.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdaptiveStopConfigV1 {
    /// Exactly one.
    #[serde(default = "AdaptiveStopConfigV1::default_version")]
    pub version: u16,
    /// The question. At least one term must survive normalization.
    pub query: String,
    /// Pages evaluated before the crawl stops, `1..=100000` (default 100).
    #[serde(default = "AdaptiveStopConfigV1::default_max_pages")]
    pub max_pages: u32,
    /// Pages evaluated before saturation may stop the crawl (default 3).
    #[serde(default = "AdaptiveStopConfigV1::default_min_pages")]
    pub min_pages: u32,
    /// Pages whose gain is averaged for saturation, `1..=1000` (default 3).
    #[serde(default = "AdaptiveStopConfigV1::default_window")]
    pub window: u32,
    /// Average gain, in thousandths, below which the crawl is saturated (default 50).
    #[serde(default = "AdaptiveStopConfigV1::default_min_gain")]
    pub min_gain_permille: u16,
    /// Confidence, in thousandths, that stops the crawl; `0` is off, at most
    /// [`CONFIDENCE_CEILING_PERMILLE`] (default 0).
    #[serde(default)]
    pub target_confidence_permille: u16,
    /// Distinct terms remembered from relevant pages, `16..=65536` (default 4096).
    #[serde(default = "AdaptiveStopConfigV1::default_max_vocabulary")]
    pub max_vocabulary: u32,
    /// State exported by an earlier run of the same query; the crawl continues from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<AdaptiveStopExportV1>,
}

impl AdaptiveStopConfigV1 {
    const fn default_version() -> u16 {
        1
    }
    const fn default_max_pages() -> u32 {
        100
    }
    const fn default_min_pages() -> u32 {
        3
    }
    const fn default_window() -> u32 {
        3
    }
    const fn default_min_gain() -> u16 {
        50
    }
    const fn default_max_vocabulary() -> u32 {
        4096
    }

    /// A policy for `query` with the documented defaults.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            version: 1,
            query: query.into(),
            max_pages: Self::default_max_pages(),
            min_pages: Self::default_min_pages(),
            window: Self::default_window(),
            min_gain_permille: Self::default_min_gain(),
            target_confidence_permille: 0,
            max_vocabulary: Self::default_max_vocabulary(),
            import: None,
        }
    }

    /// Check every bound.
    ///
    /// # Errors
    /// A bound outside its range, a query without usable terms, or imported state that is not
    /// this crawl's (version, query digest, shape).
    pub fn validate(&self) -> Result<(), CoreError> {
        let invalid = |reason: &str| CoreError::Invalid {
            field: "adaptive",
            reason: reason.to_owned(),
        };
        if self.version != 1 {
            return Err(invalid("unsupported version"));
        }
        if self.query.len() > 512 {
            return Err(invalid("query is at most 512 bytes"));
        }
        if query_terms(&self.query).is_empty() {
            return Err(invalid("query needs at least one term"));
        }
        if !(1..=100_000).contains(&self.max_pages) {
            return Err(invalid("maxPages is between 1 and 100000"));
        }
        if self.min_pages > self.max_pages {
            return Err(invalid("minPages is at most maxPages"));
        }
        if !(1..=1000).contains(&self.window) {
            return Err(invalid("window is between 1 and 1000"));
        }
        if self.min_gain_permille > 1000 {
            return Err(invalid("minGainPermille is at most 1000"));
        }
        if self.target_confidence_permille > CONFIDENCE_CEILING_PERMILLE {
            return Err(invalid("targetConfidencePermille is at most 950"));
        }
        if !(16..=65_536).contains(&self.max_vocabulary) {
            return Err(invalid("maxVocabulary is between 16 and 65536"));
        }
        if let Some(state) = &self.import {
            state
                .check(&self.query, self.window, self.max_vocabulary)
                .map_err(|reason| CoreError::Invalid {
                    field: "adaptive.import",
                    reason: reason.to_owned(),
                })?;
        }
        Ok(())
    }
}

/// Why an adaptive crawl stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AdaptiveStopReason {
    /// `maxPages` pages were evaluated.
    PageLimit,
    /// The average gain of the last `window` pages fell below `minGainPermille`.
    Saturated,
    /// The confidence estimate reached `targetConfidencePermille`.
    ConfidenceTarget,
}

impl AdaptiveStopReason {
    /// Stable `snake_case` name, identical to the serde form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PageLimit => "page_limit",
            Self::Saturated => "saturated",
            Self::ConfidenceTarget => "confidence_target",
        }
    }
}

/// Current export format of [`AdaptiveStopExportV1`].
pub const ADAPTIVE_EXPORT_VERSION: u16 = 1;

/// Portable, versioned state of an adaptive stop policy.
///
/// It holds terms and counts only, never page text or URLs. It binds to its query by digest, so
/// importing it into a different question is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdaptiveStopExportV1 {
    /// Exactly [`ADAPTIVE_EXPORT_VERSION`].
    pub version: u16,
    /// Digest of the normalized query terms ([`query_digest`]).
    pub query_digest: Digest,
    /// Pages evaluated.
    pub pages: u32,
    /// Evaluated pages that matched at least one query term.
    pub relevant_pages: u32,
    /// Gain, in thousandths, of the most recent pages, oldest first, at most the policy window.
    pub recent_gains: Vec<u16>,
    /// Relevant pages that contain each query term.
    pub term_pages: BTreeMap<String, u32>,
    /// Distinct terms of relevant pages, sorted.
    pub vocabulary: Vec<String>,
    /// The reason the crawl stopped, once it has.
    pub stopped: Option<AdaptiveStopReason>,
}

impl AdaptiveStopExportV1 {
    /// Check that this state belongs to `query` and fits the policy bounds.
    ///
    /// # Errors
    /// A static description of the first mismatch.
    pub fn check(&self, query: &str, window: u32, max_vocabulary: u32) -> Result<(), &'static str> {
        if self.version != ADAPTIVE_EXPORT_VERSION {
            return Err("unsupported export version");
        }
        if self.query_digest != query_digest(query) {
            return Err("export belongs to a different query");
        }
        let terms = query_terms(query);
        if self.relevant_pages > self.pages
            || self.recent_gains.len() > usize::try_from(window).unwrap_or(usize::MAX)
            || self.recent_gains.len() > usize::try_from(self.pages).unwrap_or(usize::MAX)
            || self.recent_gains.iter().any(|gain| *gain > 1000)
        {
            return Err("export counters are inconsistent");
        }
        if self.term_pages.len() > terms.len()
            || self
                .term_pages
                .iter()
                .any(|(term, count)| terms.binary_search(term).is_err() || *count > self.relevant_pages)
        {
            return Err("export names terms outside the query");
        }
        if self.vocabulary.len() > usize::try_from(max_vocabulary).unwrap_or(usize::MAX)
            || !self.vocabulary.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err("export vocabulary is not a bounded sorted set");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn query_normalization_is_order_case_and_noise_independent() {
        assert_eq!(query_terms("The Quick, quick fox!"), vec!["fox", "quick"]);
        assert_eq!(query_digest("fox QUICK"), query_digest("the quick, FOX?"));
        assert_ne!(query_digest("fox"), query_digest("fox hound"));
        assert!(query_terms("the of a").is_empty());
    }

    #[test]
    fn rendering_bounds_are_checked() {
        assert!(AdaptiveRendering::default().validate().is_ok());
        let bad = |tune: fn(&mut AdaptiveRendering)| {
            let mut config = AdaptiveRendering::default();
            tune(&mut config);
            config.validate().is_err()
        };
        assert!(bad(|c| c.probe_per_mille = 1001));
        assert!(bad(|c| c.predictor_version = 2));
        assert!(bad(|c| c.probe_effects = 0));
        assert!(bad(|c| c.probe_effects = 9));
        assert!(bad(|c| c.max_probes = crate::adaptive::MAX_PROBES + 1));
        let wire: AdaptiveRendering = serde_json::from_str("{}").unwrap();
        assert_eq!(wire, AdaptiveRendering::default());
        assert!(serde_json::from_str::<AdaptiveRendering>(r#"{"ratio":1}"#).is_err());
    }

    #[test]
    fn stop_config_bounds_are_checked() {
        assert!(AdaptiveStopConfigV1::new("rust async").validate().is_ok());
        assert!(AdaptiveStopConfigV1::new("the of").validate().is_err());
        let mut config = AdaptiveStopConfigV1::new("rust");
        config.target_confidence_permille = 1000;
        assert!(config.validate().is_err(), "certainty cannot be a target");
        let mut config = AdaptiveStopConfigV1::new("rust");
        config.min_pages = config.max_pages + 1;
        assert!(config.validate().is_err());
    }
}
