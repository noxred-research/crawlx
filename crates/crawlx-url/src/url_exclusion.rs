//! Pre-acquisition URL exclusion.
//!
//! A compiled [`UrlExclusionFilter`] decides from the canonical URL string alone, so an excluded
//! URL is dropped before any request, robots lookup or DNS resolution exists. The verdict is a
//! typed [`UrlExclusion`] with its own reason code, independent of the content-quality reasons
//! (for example an excluded author) that only exist after a page was acquired.
//! [`PreFetchGate`] puts the filter in front of the ordinary [`ScopeFilter`] verdict.
//!
//! Substrings are matched case-insensitively. Patterns use the `regex` engine (no backtracking)
//! under the same size, DFA and nesting limits as the path filters.

use regex::{Regex, RegexBuilder};
use url::Url;

use crawlx_core::extraction::UrlExclusionPolicyV1;

use crate::error::UrlError;
use crate::scope::{ScopeDecision, ScopeFilter};

/// Stable machine-readable reason code of every URL exclusion.
pub const URL_EXCLUDED_CODE: &str = "url_excluded";

const REGEX_SIZE_LIMIT: usize = 64 * 1024;
const REGEX_DFA_LIMIT: usize = 1024 * 1024;
const REGEX_NEST_LIMIT: u32 = 20;

/// Why a URL was excluded before acquisition.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum UrlExclusion {
    /// The canonical URL contains this configured substring (source text, original case).
    Substring(String),
    /// The canonical URL matches this configured pattern (source text).
    Pattern(String),
}
impl UrlExclusion {
    /// Stable reason code, the same for every variant and distinct from content-quality reasons.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        URL_EXCLUDED_CODE
    }
    /// The configured rule that matched.
    #[must_use]
    pub fn rule(&self) -> &str {
        match self {
            Self::Substring(rule) | Self::Pattern(rule) => rule,
        }
    }
}

/// Compiled URL exclusion rules. The default filter excludes nothing.
#[derive(Clone, Debug, Default)]
pub struct UrlExclusionFilter {
    /// `(original text, lowercase needle)`, in policy order.
    substrings: Vec<(String, String)>,
    patterns: Vec<(String, Regex)>,
}
impl UrlExclusionFilter {
    /// Compile a policy.
    ///
    /// # Errors
    /// Returns [`UrlError::Pattern`] when the policy is out of bounds or a pattern does not
    /// compile within the regex limits.
    pub fn from_policy(policy: &UrlExclusionPolicyV1) -> Result<Self, UrlError> {
        policy.validate().map_err(|e| UrlError::Pattern {
            pattern: "<url exclusion policy>".into(),
            reason: e.to_string(),
        })?;
        let patterns = policy
            .patterns
            .iter()
            .map(|p| {
                RegexBuilder::new(p)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .dfa_size_limit(REGEX_DFA_LIMIT)
                    .nest_limit(REGEX_NEST_LIMIT)
                    .build()
                    .map(|r| (p.clone(), r))
                    .map_err(|e| UrlError::Pattern {
                        pattern: p.clone(),
                        reason: e.to_string(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            substrings: policy
                .substrings
                .iter()
                .map(|s| (s.clone(), s.to_lowercase()))
                .collect(),
            patterns,
        })
    }

    /// True when no rule is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.substrings.is_empty() && self.patterns.is_empty()
    }

    /// First matching rule (substrings before patterns, each in policy order), or `None`.
    /// Pure: no I/O, no clock.
    #[must_use]
    pub fn check(&self, url: &Url) -> Option<UrlExclusion> {
        if self.is_empty() {
            return None;
        }
        let text = url.as_str();
        if !self.substrings.is_empty() {
            let lower = text.to_lowercase();
            if let Some((rule, _)) = self.substrings.iter().find(|(_, needle)| lower.contains(needle)) {
                return Some(UrlExclusion::Substring(rule.clone()));
            }
        }
        self.patterns
            .iter()
            .find(|(_, re)| re.is_match(text))
            .map(|(rule, _)| UrlExclusion::Pattern(rule.clone()))
    }
}

/// Admission verdict made before any request exists.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PreFetchDecision {
    /// The URL matched a configured URL exclusion rule: no request is made. The reason is
    /// separate from every scope reason and from post-acquisition content-quality reasons.
    UrlExcluded(UrlExclusion),
    /// The URL passed URL exclusion; this is the ordinary scope verdict.
    Scope(ScopeDecision),
}

/// URL exclusion in front of the crawl scope: the single pre-fetch decision of a crawl.
#[derive(Clone, Debug)]
pub struct PreFetchGate {
    scope: ScopeFilter,
    exclusion: UrlExclusionFilter,
}
impl PreFetchGate {
    /// Combine a scope filter with compiled URL exclusion rules.
    #[must_use]
    pub fn new(scope: ScopeFilter, exclusion: UrlExclusionFilter) -> Self {
        Self { scope, exclusion }
    }

    /// The wrapped scope filter.
    #[must_use]
    pub fn scope(&self) -> &ScopeFilter {
        &self.scope
    }

    /// URL exclusion first (a distinct typed reason), then [`ScopeFilter::decide`]. Pure, so an
    /// excluded URL costs zero target requests.
    #[must_use]
    pub fn decide(&self, url: &Url) -> PreFetchDecision {
        match self.exclusion.check(url) {
            Some(excluded) => PreFetchDecision::UrlExcluded(excluded),
            None => PreFetchDecision::Scope(self.scope.decide(url)),
        }
    }

    /// Entry-URL variant of [`Self::decide`]: URL exclusion, then
    /// [`ScopeFilter::decide_entry_path`].
    #[must_use]
    pub fn decide_entry(&self, url: &Url) -> PreFetchDecision {
        match self.exclusion.check(url) {
            Some(excluded) => PreFetchDecision::UrlExcluded(excluded),
            None => PreFetchDecision::Scope(self.scope.decide_entry_path(url)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn filter(substrings: &[&str], patterns: &[&str]) -> UrlExclusionFilter {
        let mut policy = UrlExclusionPolicyV1::default();
        policy.substrings = substrings.iter().map(|s| (*s).to_owned()).collect();
        policy.patterns = patterns.iter().map(|s| (*s).to_owned()).collect();
        UrlExclusionFilter::from_policy(&policy).unwrap()
    }

    #[test]
    fn substring_is_case_insensitive_and_reports_the_rule() {
        let f = filter(&["/Tag/", "sponsored"], &[]);
        let hit = f
            .check(&Url::parse("https://example.test/TAG/news").unwrap())
            .unwrap();
        assert_eq!(hit, UrlExclusion::Substring("/Tag/".into()));
        assert_eq!(hit.rule(), "/Tag/");
        assert_eq!(hit.code(), "url_excluded");
        assert!(f
            .check(&Url::parse("https://example.test/news/story").unwrap())
            .is_none());
    }

    #[test]
    fn patterns_match_the_whole_canonical_url_including_query_and_host() {
        let f = filter(&[], &[r"\?utm_", r"^https://ads\."]);
        assert_eq!(
            f.check(&Url::parse("https://example.test/a?utm_source=x").unwrap()),
            Some(UrlExclusion::Pattern(r"\?utm_".into()))
        );
        assert!(f
            .check(&Url::parse("https://ads.example.test/a").unwrap())
            .is_some());
        assert!(f
            .check(&Url::parse("http://ads.example.test/a").unwrap())
            .is_none());
    }

    #[test]
    fn empty_filter_excludes_nothing_and_bad_policy_fails_closed() {
        assert!(UrlExclusionFilter::default()
            .check(&Url::parse("https://example.test/").unwrap())
            .is_none());
        let mut policy = UrlExclusionPolicyV1::default();
        policy.patterns = vec!["(".into()];
        assert!(matches!(
            UrlExclusionFilter::from_policy(&policy),
            Err(UrlError::Pattern { .. })
        ));
        policy.patterns = Vec::new();
        policy.substrings = vec![String::new()];
        assert!(UrlExclusionFilter::from_policy(&policy).is_err());
    }
}
