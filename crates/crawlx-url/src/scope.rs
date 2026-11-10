//! Crawl scope decisions (the pipeline step "scope").
//!
//! Include/exclude path patterns come from API callers and are untrusted:
//! each is capped at 2000 bytes, at most 1000 per list, and compiled with
//! `regex` size, DFA-size and nesting limits (the `regex` engine has no
//! backtracking, so these limits bound both memory and time).

use regex::{Regex, RegexBuilder};
use url::Url;

use crawlx_core::config::Scope;

use crate::error::UrlError;

/// Maximum pattern length in bytes (compatibility API limit: 2000).
pub const MAX_PATTERN_LEN: usize = crawlx_core::config::MAX_PATH_PATTERN_LEN;
/// Maximum number of patterns per list (compatibility API limit: 1000).
pub const MAX_PATTERNS: usize = crawlx_core::config::MAX_PATH_PATTERNS;
/// Lists longer than this compile every pattern under [`LARGE_LIST_REGEX_SIZE_LIMIT`].
const LARGE_LIST: usize = 100;
const LARGE_LIST_REGEX_SIZE_LIMIT: usize = 64 * 1024;
const REGEX_SIZE_LIMIT: usize = 256 * 1024;
const REGEX_DFA_LIMIT: usize = 1024 * 1024;
const REGEX_NEST_LIMIT: u32 = 20;

/// Relation of a host to the seed host.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostRelation {
    /// The host equals the seed host.
    Same,
    /// The host is a strict subdomain of the seed host.
    Subdomain,
    /// Any other host.
    External,
}

/// Compare `host` with `seed_host` (both lowercased, trailing dot removed).
#[must_use]
pub fn host_relation(seed_host: &str, host: &str) -> HostRelation {
    let seed = seed_host.trim_end_matches('.').to_ascii_lowercase();
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h == seed {
        HostRelation::Same
    } else if h.len() > seed.len() + 1 && h.ends_with(&seed) && h.as_bytes()[h.len() - seed.len() - 1] == b'.'
    {
        HostRelation::Subdomain
    } else {
        HostRelation::External
    }
}

/// Decision for one URL against the crawl scope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScopeDecision {
    /// The URL is on the seed host (or an allowed subdomain) and passes the path rules.
    InScope,
    /// Different registrable host (fetched as a leaf only when external links are allowed).
    External,
    /// Subdomain of the seed host while `allowSubdomains` is off.
    Subdomain,
    /// Matched this exclude pattern.
    Excluded(String),
    /// Include patterns exist (or the seed-path rule applies) and the path matched none.
    NotIncluded,
}

fn compile(list: &[String], kind: &str) -> Result<Vec<(String, Regex)>, UrlError> {
    if list.len() > MAX_PATTERNS {
        return Err(UrlError::Pattern {
            pattern: format!("<{kind} list>"),
            reason: format!("{} patterns (max {MAX_PATTERNS})", list.len()),
        });
    }
    // a long list shares the memory a short one would have: the per-pattern program limit shrinks
    let size_limit = if list.len() > LARGE_LIST {
        LARGE_LIST_REGEX_SIZE_LIMIT
    } else {
        REGEX_SIZE_LIMIT
    };
    list.iter()
        .map(|p| {
            if p.len() > MAX_PATTERN_LEN {
                return Err(UrlError::Pattern {
                    pattern: p.chars().take(32).collect::<String>() + "…",
                    reason: format!("{} bytes (max {MAX_PATTERN_LEN})", p.len()),
                });
            }
            RegexBuilder::new(p)
                .size_limit(size_limit)
                .dfa_size_limit(REGEX_DFA_LIMIT)
                .nest_limit(REGEX_NEST_LIMIT)
                .build()
                .map(|r| (p.clone(), r))
                .map_err(|e| UrlError::Pattern {
                    pattern: p.clone(),
                    reason: e.to_string(),
                })
        })
        .collect()
}

/// Compiled include/exclude path patterns (matched against the URL path).
#[derive(Clone, Debug, Default)]
pub struct PathFilter {
    include: Vec<(String, Regex)>,
    exclude: Vec<(String, Regex)>,
}

impl PathFilter {
    /// Compile bounded patterns.
    ///
    /// # Errors
    /// Returns [`UrlError::Pattern`] when a pattern is too long, the list is
    /// too long, or a pattern does not compile within the regex size limits.
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self, UrlError> {
        Ok(Self {
            include: compile(include, "include")?,
            exclude: compile(exclude, "exclude")?,
        })
    }

    /// True when `include` is empty or any include pattern matches.
    #[must_use]
    pub fn matches_include(&self, path: &str) -> bool {
        self.include.is_empty() || self.include.iter().any(|(_, r)| r.is_match(path))
    }

    /// True when any exclude pattern matches.
    #[must_use]
    pub fn matches_exclude(&self, path: &str) -> bool {
        self.first_exclude(path).is_some()
    }

    /// The first exclude pattern (source text) matching `path`.
    #[must_use]
    pub fn first_exclude(&self, path: &str) -> Option<&str> {
        self.exclude
            .iter()
            .find(|(_, r)| r.is_match(path))
            .map(|(p, _)| p.as_str())
    }

    /// Are there include patterns?
    #[must_use]
    pub fn has_include(&self) -> bool {
        !self.include.is_empty()
    }
}

/// Scope decision engine for one crawl.
#[derive(Clone, Debug)]
pub struct ScopeFilter {
    seed_host: String,
    /// Seed path without trailing slash (`""` for the root).
    seed_base: String,
    paths: PathFilter,
    allow_subdomains: bool,
    allow_external_links: bool,
    crawl_entire_domain: bool,
}

impl ScopeFilter {
    /// Build from the seed URL and the crawl `Scope`.
    ///
    /// # Errors
    /// Returns [`UrlError::NoHost`] when the seed has no host and
    /// [`UrlError::Pattern`] when an include/exclude pattern is rejected.
    pub fn new(seed: &Url, scope: &Scope) -> Result<Self, UrlError> {
        let seed_host = seed
            .host_str()
            .ok_or(UrlError::NoHost)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        Ok(Self {
            seed_host,
            seed_base: seed.path().trim_end_matches('/').to_owned(),
            paths: PathFilter::new(&scope.include_paths, &scope.exclude_paths)?,
            allow_subdomains: scope.allow_subdomains,
            allow_external_links: scope.allow_external_links,
            crawl_entire_domain: scope.crawl_entire_domain,
        })
    }

    /// May external pages be fetched (as leaves; never expanded)?
    #[must_use]
    pub const fn allow_external_links(&self) -> bool {
        self.allow_external_links
    }

    /// Decide for `url`. Order: host relation, then [`Self::decide_path`].
    #[must_use]
    pub fn decide(&self, url: &Url) -> ScopeDecision {
        let host = url.host_str().unwrap_or("");
        match host_relation(&self.seed_host, host) {
            HostRelation::External => return ScopeDecision::External,
            HostRelation::Subdomain if !self.allow_subdomains => return ScopeDecision::Subdomain,
            HostRelation::Same | HostRelation::Subdomain => {}
        }
        self.decide_path(url)
    }

    /// Path rules only (the host is assumed in scope): exclude patterns,
    /// include patterns, then (without include patterns and with
    /// `crawlEntireDomain: false`) descendants-of-seed-path.
    #[must_use]
    pub fn decide_path(&self, url: &Url) -> ScopeDecision {
        let path = url.path();
        if let Some(p) = self.paths.first_exclude(path) {
            return ScopeDecision::Excluded(p.to_owned());
        }
        if self.paths.has_include() {
            return if self.paths.matches_include(path) {
                ScopeDecision::InScope
            } else {
                ScopeDecision::NotIncluded
            };
        }
        if !self.crawl_entire_domain && !self.seed_base.is_empty() {
            let under = path == self.seed_base
                || path
                    .strip_prefix(self.seed_base.as_str())
                    .is_some_and(|rest| rest.starts_with('/'));
            if !under {
                return ScopeDecision::NotIncluded;
            }
        }
        ScopeDecision::InScope
    }

    /// Path rules for the crawl's entry URL (the seed): the exclude patterns only. The include
    /// patterns and the seed-path rule do not apply to it, because the entry URL is always
    /// fetched to start discovery (its links then pass [`Self::decide_path`] like any other).
    #[must_use]
    pub fn decide_entry_path(&self, url: &Url) -> ScopeDecision {
        match self.paths.first_exclude(url.path()) {
            Some(p) => ScopeDecision::Excluded(p.to_owned()),
            None => ScopeDecision::InScope,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn scope(f: impl FnOnce(&mut Scope)) -> Scope {
        let mut s = Scope {
            crawl_entire_domain: true,
            ..Scope::default()
        };
        f(&mut s);
        s
    }

    #[test]
    fn host_relations() {
        assert_eq!(host_relation("example.com", "EXAMPLE.com."), HostRelation::Same);
        assert_eq!(
            host_relation("example.com", "blog.example.com"),
            HostRelation::Subdomain
        );
        assert_eq!(
            host_relation("example.com", "notexample.com"),
            HostRelation::External
        );
        assert_eq!(
            host_relation("example.com", "example.org"),
            HostRelation::External
        );
    }

    #[test]
    fn decisions() {
        let seed = u("https://example.com/");
        let s = scope(|s| {
            s.include_paths = vec!["^/docs/".into()];
            s.exclude_paths = vec!["private".into()];
        });
        let f = ScopeFilter::new(&seed, &s).unwrap();
        assert_eq!(f.decide(&u("https://example.com/docs/a")), ScopeDecision::InScope);
        assert_eq!(
            f.decide(&u("https://example.com/blog")),
            ScopeDecision::NotIncluded
        );
        assert_eq!(
            f.decide(&u("https://example.com/docs/private/x")),
            ScopeDecision::Excluded("private".into())
        );
        assert_eq!(
            f.decide(&u("https://a.example.com/docs/a")),
            ScopeDecision::Subdomain
        );
        assert_eq!(f.decide(&u("https://other.org/docs/a")), ScopeDecision::External);

        let s = scope(|s| s.allow_subdomains = true);
        let f = ScopeFilter::new(&seed, &s).unwrap();
        assert_eq!(f.decide(&u("https://a.example.com/x")), ScopeDecision::InScope);
    }

    #[test]
    fn entry_path_ignores_include_patterns_but_not_exclude_patterns() {
        let seed = u("https://example.com/");
        let s = scope(|s| {
            s.include_paths = vec!["^/docs/".into()];
            s.exclude_paths = vec!["^/private".into()];
        });
        let f = ScopeFilter::new(&seed, &s).unwrap();
        assert_eq!(f.decide_path(&seed), ScopeDecision::NotIncluded);
        assert_eq!(f.decide_entry_path(&seed), ScopeDecision::InScope);
        assert_eq!(
            f.decide_entry_path(&u("https://example.com/private")),
            ScopeDecision::Excluded("^/private".into())
        );
    }

    #[test]
    fn seed_path_descendants_when_not_entire_domain() {
        let seed = u("https://example.com/docs/");
        let f = ScopeFilter::new(&seed, &Scope::default()).unwrap();
        assert_eq!(
            f.decide(&u("https://example.com/docs/a/b")),
            ScopeDecision::InScope
        );
        assert_eq!(f.decide(&u("https://example.com/docs")), ScopeDecision::InScope);
        assert_eq!(
            f.decide(&u("https://example.com/docsx")),
            ScopeDecision::NotIncluded
        );
        assert_eq!(f.decide(&u("https://example.com/")), ScopeDecision::NotIncluded);
        let root = ScopeFilter::new(&u("https://example.com/"), &Scope::default()).unwrap();
        assert_eq!(
            root.decide(&u("https://example.com/anything")),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn bounded_patterns() {
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert!(matches!(
            PathFilter::new(&[long], &[]),
            Err(UrlError::Pattern { .. })
        ));
        assert!(matches!(
            PathFilter::new(&["(".into()], &[]),
            Err(UrlError::Pattern { .. })
        ));
        // nested quantifier blow-up is rejected by the size limit
        assert!(matches!(
            PathFilter::new(&["((a{100}){100}){100}".into()], &[]),
            Err(UrlError::Pattern { .. })
        ));
        // classic catastrophic pattern compiles but matches in linear time
        let f = PathFilter::new(&["(a+)+$".into()], &[]).unwrap();
        assert!(!f.matches_include(&format!("{}b", "a".repeat(5000))));
        let many: Vec<String> = (0..=MAX_PATTERNS).map(|i| format!("p{i}")).collect();
        assert!(PathFilter::new(&[], &many).is_err());
    }

    #[test]
    fn empty_include_matches_everything() {
        let f = PathFilter::new(&[], &["^/x".into()]).unwrap();
        assert!(f.matches_include("/anything"));
        assert!(f.matches_exclude("/x/y"));
        assert!(!f.matches_exclude("/y"));
    }
}
