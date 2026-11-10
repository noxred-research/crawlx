//! Crawl scope policy.
//!
//! Wraps `crawlx_url::scope::ScopeFilter`, which owns the path-pattern logic
//! (there is exactly one copy of it), and adds the surface discovery
//! scope model: [`HostScopeRule`] (`fqdn | rdn | dn | none`), [`UrlPatterns`]
//! (regexes over the full URL), [`ExcludeHosts`] (`private-ips`, `cdn`, CIDR, IP,
//! regex), the `hostScopePattern` host regex, the extension filter, the depth limit, and a
//! verdict type carrying the denial reason that the `policy_blocked` counter and
//! `urls.policy_reason` need.
//!
//! [`ScopePolicy::decide`] checks, in order: the authorization record's target (when bound with
//! [`ScopePolicy::with_record_scope`]) → exclude hosts → host scope (or the
//! `hostScopePattern` regex) → URL exclude → URL include → path rules → extension filter →
//! depth.

use std::net::IpAddr;
use std::sync::LazyLock;

use crate::authorization::RecordScope;
use crate::cdn::is_cdn_host;
use crate::egress::classify_ip;
use crate::error::PolicyError;
use crawlx_core::config::{CreateCrawl, HostScope};
use crawlx_core::url::CanonicalUrl;
use crawlx_url::extensions::ExtensionFilter;
use crawlx_url::scope::{host_relation, HostRelation, PathFilter, ScopeDecision, ScopeFilter};
use crawlx_url::UrlError;
use ipnet::IpNet;
use publicsuffix::{List, Psl};
use url::Url;

/// The public suffix list (MPL-2.0), vendored so `rdn` scoping needs
/// no network; refresh `data/public_suffix_list.dat` with dependency updates.
static PSL: LazyLock<Result<List, publicsuffix::Error>> =
    LazyLock::new(|| List::from_bytes(include_bytes!("../data/public_suffix_list.dat")));

/// Registrable domain (eTLD+1) of `host`, lowercase; `None` for IP literals,
/// hosts that are only a public suffix, or an unloadable list.
#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let list = PSL.as_ref().ok()?;
    let domain = list.domain(host.as_bytes())?;
    // a bare suffix (`co.uk`) has no registrable label
    if domain.suffix().as_bytes().len() == domain.as_bytes().len() {
        return None;
    }
    std::str::from_utf8(domain.as_bytes()).ok().map(str::to_owned)
}

/// Domain keyword of `host`: its registrable domain without the public
/// suffix (`example` for `a.b.example.co.uk`).
#[must_use]
pub fn domain_keyword(host: &str) -> Option<String> {
    let rdn = registrable_domain(host)?;
    let list = PSL.as_ref().ok()?;
    let suffix = list.suffix(rdn.as_bytes())?;
    let suffix_len = suffix.as_bytes().len();
    let keyword = rdn.get(..rdn.len().checked_sub(suffix_len + 1)?)?;
    (!keyword.is_empty()).then(|| keyword.to_owned())
}

/// Why a URL was kept out of the crawl.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum DenialReason {
    /// Link depth exceeds `scope.maxDiscoveryDepth`.
    DepthExceeded {
        /// Link depth of the URL.
        depth: u16,
        /// Configured `scope.maxDiscoveryDepth`.
        max: u16,
    },
    /// Different host under `hostScope: fqdn` and `allowExternalLinks` is off.
    External,
    /// Subdomain of the seed host under `hostScope: fqdn` and `allowSubdomains` is off.
    Subdomain,
    /// Outside the `rdn`/`dn` host scope.
    HostScope,
    /// Matched this `excludePaths` pattern.
    Excluded(String),
    /// Outside the include patterns or (without `crawlEntireDomain`) the seed path.
    NotIncluded,
    /// Matched this `urlExclude` pattern.
    UrlExcluded(String),
    /// `urlInclude` patterns exist and none matched.
    UrlNotIncluded,
    /// Matched this `excludeHosts` entry.
    HostExcluded(String),
    /// Refused by the extension filter.
    ExtensionFiltered,
    /// The host already admitted `scope.maxPagesPerHost` pages.
    HostPageLimit,
    /// The root page (`/` or no path) of another site, skipped under `allowExternalLinks` of a
    /// compatibility API scrape job (which reports it as `EXTERNAL_LINK`).
    ExternalHomepage,
    /// Outside the target of the run's authorization record: a hard bound that no
    /// `scope` setting widens.
    AuthorizationScope,
}

impl DenialReason {
    /// Stable code for counters and the frontier row.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DepthExceeded { .. } => "depth_exceeded",
            Self::External => "external",
            Self::Subdomain => "subdomain",
            Self::HostScope => "host_scope",
            Self::Excluded(_) => "excluded_path",
            Self::NotIncluded => "not_included",
            Self::UrlExcluded(_) => "url_excluded",
            Self::UrlNotIncluded => "url_not_included",
            Self::HostExcluded(_) => "host_excluded",
            Self::ExtensionFiltered => "extension_filtered",
            Self::ExternalHomepage => "external_homepage",
            Self::HostPageLimit => "host_page_limit",
            Self::AuthorizationScope => "authorization_scope",
        }
    }

    /// Is this the include filter (`includePaths`, `urlInclude`) refusing the URL?
    #[must_use]
    pub const fn is_include(&self) -> bool {
        matches!(self, Self::NotIncluded | Self::UrlNotIncluded)
    }

    /// Is this an out-of-scope *host* (the URL may still be recorded as a leaf)?
    const fn is_host_scope(&self) -> bool {
        matches!(self, Self::External | Self::Subdomain | Self::HostScope)
    }
}

/// Scope verdict for one URL.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScopeVerdict {
    /// Admit. `leaf_only`: an out-of-scope page recorded (and, under
    /// `allowExternalLinks`, fetched) without following its links.
    Admitted {
        /// The page may be recorded/fetched but its links must not be followed.
        leaf_only: bool,
    },
    /// The URL is kept out of the crawl for this reason.
    Denied(DenialReason),
}

impl ScopeVerdict {
    /// Whether the verdict admits the URL (leaf-only or not).
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

/// `scope.hostScope` compiled against the seed host.
#[derive(Clone, Debug)]
pub struct HostScopeRule {
    mode: HostScope,
    seed_host: String,
    allow_subdomains: bool,
    /// Registrable domain of the seed (`rdn`), or the seed host when it has none.
    rdn: String,
    /// Domain keyword of the seed (`dn`), or the seed host when it has none.
    dn: String,
}

impl HostScopeRule {
    /// Compile `mode` for `seed_host`.
    ///
    /// # Errors
    /// [`PolicyError::PublicSuffixList`] when `rdn`/`dn` is requested and the
    /// bundled public suffix list failed to load.
    pub fn new(mode: HostScope, seed_host: &str, allow_subdomains: bool) -> Result<Self, PolicyError> {
        let seed_host = seed_host.trim_end_matches('.').to_ascii_lowercase();
        if matches!(mode, HostScope::Rdn | HostScope::Dn) {
            if let Err(e) = PSL.as_ref() {
                return Err(PolicyError::PublicSuffixList(e.to_string()));
            }
        }
        let rdn = registrable_domain(&seed_host).unwrap_or_else(|| seed_host.clone());
        let dn = domain_keyword(&seed_host).unwrap_or_else(|| seed_host.clone());
        Ok(Self {
            mode,
            seed_host,
            allow_subdomains,
            rdn,
            dn,
        })
    }

    /// The mode.
    #[must_use]
    pub const fn mode(&self) -> HostScope {
        self.mode
    }

    /// Registrable domain the `rdn` mode admits.
    #[must_use]
    pub fn registrable_domain(&self) -> &str {
        &self.rdn
    }

    /// Keyword the `dn` mode looks for.
    #[must_use]
    pub fn keyword(&self) -> &str {
        &self.dn
    }

    /// Is `host` inside the host scope?
    ///
    /// # Errors
    /// The [`DenialReason`] (`external`, `subdomain` or `host_scope`).
    pub fn check(&self, host: &str) -> Result<(), DenialReason> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        match self.mode {
            HostScope::None => Ok(()),
            HostScope::Fqdn => match host_relation(&self.seed_host, &h) {
                HostRelation::Same => Ok(()),
                HostRelation::Subdomain if self.allow_subdomains => Ok(()),
                HostRelation::Subdomain => Err(DenialReason::Subdomain),
                HostRelation::External => Err(DenialReason::External),
            },
            HostScope::Rdn => {
                if h == self.seed_host
                    || matches!(
                        host_relation(&self.rdn, &h),
                        HostRelation::Same | HostRelation::Subdomain
                    )
                {
                    Ok(())
                } else {
                    Err(DenialReason::HostScope)
                }
            }
            HostScope::Dn => {
                if h == self.seed_host || (h.parse::<IpAddr>().is_err() && h.contains(self.dn.as_str())) {
                    Ok(())
                } else {
                    Err(DenialReason::HostScope)
                }
            }
        }
    }
}

/// `scope.urlInclude`/`urlExclude`: bounded regexes over the full URL.
#[derive(Clone, Debug, Default)]
pub struct UrlPatterns {
    patterns: PathFilter,
    count: usize,
}

impl UrlPatterns {
    /// Compile bounded patterns (same limits as the path patterns).
    ///
    /// # Errors
    /// [`UrlError::Pattern`] for an over-long list or pattern, or a pattern
    /// that does not compile within the regex size limits.
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self, UrlError> {
        Ok(Self {
            patterns: PathFilter::new(include, exclude)?,
            count: include.len() + exclude.len(),
        })
    }

    /// Any patterns at all?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check `url` (serialized): exclude first, then include.
    ///
    /// # Errors
    /// [`DenialReason::UrlExcluded`] naming the pattern, or
    /// [`DenialReason::UrlNotIncluded`].
    pub fn check(&self, url: &str) -> Result<(), DenialReason> {
        self.check_exclude(url)?;
        if self.patterns.matches_include(url) {
            Ok(())
        } else {
            Err(DenialReason::UrlNotIncluded)
        }
    }

    /// Check `url` (serialized) against the exclude patterns only.
    ///
    /// # Errors
    /// [`DenialReason::UrlExcluded`] naming the pattern.
    pub fn check_exclude(&self, url: &str) -> Result<(), DenialReason> {
        match self.patterns.first_exclude(url) {
            Some(p) => Err(DenialReason::UrlExcluded(p.to_owned())),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
enum HostExclusion {
    PrivateIps,
    Cdn,
    Net(IpNet),
    Ip(IpAddr),
    Regex(PathFilter),
}

/// `scope.excludeHosts`: `private-ips`, `cdn`, CIDRs, IP literals and host regexes.
#[derive(Clone, Debug, Default)]
pub struct ExcludeHosts {
    entries: Vec<(String, HostExclusion)>,
}

impl ExcludeHosts {
    /// Parse the entries. The keyword `cdn` (case-insensitive) is the bundled CDN host list
    /// ([`crate::cdn::is_cdn_host`]) and `private-ips` the private ranges; anything else
    /// that is not a CIDR or an IP literal is compiled as a bounded regex over the host name.
    ///
    /// # Errors
    /// [`PolicyError::Scope`] for a regex that fails the pattern limits.
    pub fn new(entries: &[String]) -> Result<Self, PolicyError> {
        let mut out = Vec::with_capacity(entries.len());
        for raw in entries {
            let e = raw.trim();
            if e.is_empty() {
                continue;
            }
            let rule = if e.eq_ignore_ascii_case("private-ips") {
                HostExclusion::PrivateIps
            } else if e.eq_ignore_ascii_case("cdn") {
                HostExclusion::Cdn
            } else if let Ok(net) = e.parse::<IpNet>() {
                HostExclusion::Net(net)
            } else if let Ok(ip) = e.trim_matches(['[', ']']).parse::<IpAddr>() {
                HostExclusion::Ip(ip)
            } else {
                HostExclusion::Regex(PathFilter::new(std::slice::from_ref(raw), &[])?)
            };
            out.push((e.to_owned(), rule));
        }
        Ok(Self { entries: out })
    }

    /// No entries?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Does any entry refuse `host`? Address rules apply to the literal IP
    /// (if `host` is one) or to `resolved`, which the caller supplies from
    /// its own DNS lookup.
    #[must_use]
    pub fn matches(&self, host: &str, resolved: Option<IpAddr>) -> Option<&str> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let literal = h.trim_matches(['[', ']']).parse::<IpAddr>().ok();
        let ip = literal.or(resolved);
        self.entries
            .iter()
            .find(|(_, rule)| match rule {
                HostExclusion::PrivateIps => ip.is_some_and(|ip| classify_ip(ip).is_some()),
                HostExclusion::Cdn => is_cdn_host(&h),
                HostExclusion::Net(net) => ip.is_some_and(|ip| net.contains(&ip)),
                HostExclusion::Ip(x) => ip == Some(*x),
                HostExclusion::Regex(r) => r.matches_include(&h),
            })
            .map(|(src, _)| src.as_str())
    }
}

/// Is `url` the root page of its site (empty path or `/`, any query)?
fn is_homepage(url: &Url) -> bool {
    matches!(url.path(), "" | "/")
}

/// Scope policy for one crawl.
#[derive(Clone, Debug)]
pub struct ScopePolicy {
    filter: ScopeFilter,
    hosts: HostScopeRule,
    exclude_hosts: ExcludeHosts,
    /// `scope.hostScopePattern`: hosts matching it are in scope on top of the host scope.
    host_pattern: Option<PathFilter>,
    urls: UrlPatterns,
    extensions: ExtensionFilter,
    max_depth: u16,
    leaf_out_of_scope: bool,
    fetch_leaves: bool,
    /// A compatibility API scrape job under `allowExternalLinks` never follows a link to the root page
    /// of another site (`DenialReason::ExternalHomepage`).
    skip_external_homepages: bool,
    max_pages_per_host: Option<u32>,
    /// The target of the run's authorization record; checked before every other rule.
    record_scope: Option<RecordScope>,
}

impl ScopePolicy {
    /// Build from the (normalized) request.
    ///
    /// # Errors
    /// [`PolicyError::Scope`] for an invalid pattern or a seed without host;
    /// [`PolicyError::PublicSuffixList`] when `rdn`/`dn` cannot load the list.
    pub fn new(crawl: &CreateCrawl) -> Result<Self, PolicyError> {
        let s = &crawl.scope;
        let seed_host = crawl.seed_url.host_str().ok_or(UrlError::NoHost)?;
        let host_pattern = s
            .host_scope_pattern
            .as_deref()
            .filter(|p| !p.trim().is_empty())
            .map(|p| PathFilter::new(&[p.to_owned()], &[]))
            .transpose()?;
        Ok(Self {
            filter: ScopeFilter::new(&crawl.seed_url, s)?,
            hosts: HostScopeRule::new(s.host_scope, seed_host, s.allow_subdomains)?,
            host_pattern,
            exclude_hosts: ExcludeHosts::new(&if crawl.safety.allow_private_networks {
                // The authorization record governs private ranges; `private-ips` would
                // otherwise deny the very hosts the record authorizes.
                s.exclude_hosts
                    .iter()
                    .filter(|e| !e.trim().eq_ignore_ascii_case("private-ips"))
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                s.exclude_hosts.clone()
            })?,
            urls: UrlPatterns::new(&s.url_include, &s.url_exclude)?,
            extensions: ExtensionFilter::new(
                &s.extension_match,
                &s.extension_filter,
                s.no_default_extension_filter,
            ),
            max_depth: s.max_discovery_depth,
            leaf_out_of_scope: s.allow_external_links || crawl.output.include_out_of_scope,
            fetch_leaves: s.allow_external_links,
            skip_external_homepages: s.allow_external_links && crawl.scrape.is_some(),
            max_pages_per_host: s.max_pages_per_host,
            record_scope: None,
        })
    }

    /// Bound the policy to the target of an authorization record: a URL outside it is denied
    /// with [`DenialReason::AuthorizationScope`] whatever the rest of the scope says, so
    /// `allowSubdomains`, `allowExternalLinks` and the host scope can only narrow it.
    #[must_use]
    pub fn with_record_scope(mut self, scope: RecordScope) -> Self {
        self.record_scope = Some(scope);
        self
    }

    /// `scope.maxPagesPerHost`, for the per-host budget.
    #[must_use]
    pub const fn max_pages_per_host(&self) -> Option<u32> {
        self.max_pages_per_host
    }

    /// May `leaf_only` pages be fetched (`scope.allowExternalLinks`)? With
    /// only `output.includeOutOfScope` they are recorded, never fetched.
    #[must_use]
    pub const fn fetch_leaves(&self) -> bool {
        self.fetch_leaves
    }

    /// The compiled host-scope rule.
    #[must_use]
    pub const fn host_scope(&self) -> &HostScopeRule {
        &self.hosts
    }

    /// The compiled extension filter.
    #[must_use]
    pub const fn extensions(&self) -> &ExtensionFilter {
        &self.extensions
    }

    /// Decide for a canonical URL discovered `depth` links from the seed.
    /// Address-based host exclusions see literal IP hosts only; use
    /// [`Self::decide_resolved`] once the host's address is known.
    #[must_use]
    pub fn decide(&self, url: &CanonicalUrl, depth: u16) -> ScopeVerdict {
        self.decide_url(&url.url, depth)
    }

    /// As [`Self::decide`] for an already-parsed URL.
    #[must_use]
    pub fn decide_url(&self, url: &Url, depth: u16) -> ScopeVerdict {
        self.decide_resolved(url, depth, None)
    }

    /// As [`Self::decide_url`], with the host's resolved address (if any)
    /// for `excludeHosts` entries that match addresses.
    #[must_use]
    pub fn decide_resolved(&self, url: &Url, depth: u16, resolved: Option<IpAddr>) -> ScopeVerdict {
        self.decide_with(url, depth, resolved, false)
    }

    /// Decide for the crawl's entry URL (the seed, depth 0): every rule of [`Self::decide`]
    /// except the include filters (`includePaths`, `urlInclude`) and the seed-path rule. The
    /// entry URL is always fetched to start discovery; its links then meet the include filters
    /// like every other URL.
    #[must_use]
    pub fn decide_entry(&self, url: &CanonicalUrl) -> ScopeVerdict {
        self.decide_with(&url.url, 0, None, true)
    }

    /// The include denial of the crawl's entry URL `url` when the include filters are the only
    /// rule that refuses it ([`Self::decide`] denies it with [`DenialReason::is_include`] and
    /// [`Self::decide_entry`] admits it); `None` when it is admitted or refused for any other
    /// reason (`excludePaths`, `urlExclude`, host, extension filter).
    #[must_use]
    pub fn entry_include_denial(&self, url: &CanonicalUrl) -> Option<DenialReason> {
        match self.decide(url, 0) {
            ScopeVerdict::Denied(reason) if reason.is_include() && self.decide_entry(url).is_admitted() => {
                Some(reason)
            }
            _ => None,
        }
    }

    fn decide_with(&self, url: &Url, depth: u16, resolved: Option<IpAddr>, is_entry: bool) -> ScopeVerdict {
        if self
            .record_scope
            .as_ref()
            .is_some_and(|scope| scope.check_request(url).is_err())
        {
            return ScopeVerdict::Denied(DenialReason::AuthorizationScope);
        }
        let host = url.host_str().unwrap_or("");
        if let Some(entry) = self.exclude_hosts.matches(host, resolved) {
            return ScopeVerdict::Denied(DenialReason::HostExcluded(entry.to_owned()));
        }
        if let Err(reason) = self.hosts.check(host) {
            debug_assert!(reason.is_host_scope());
            // `scope.hostScopePattern` admits hosts on top of the host scope
            if !self.host_pattern_admits(host) {
                return if self.leaf_out_of_scope {
                    if self.skip_external_homepages && is_homepage(url) {
                        ScopeVerdict::Denied(DenialReason::ExternalHomepage)
                    } else {
                        ScopeVerdict::Admitted { leaf_only: true }
                    }
                } else {
                    ScopeVerdict::Denied(reason)
                };
            }
        }
        let urls = if is_entry {
            self.urls.check_exclude(url.as_str())
        } else {
            self.urls.check(url.as_str())
        };
        if let Err(reason) = urls {
            return ScopeVerdict::Denied(reason);
        }
        let path = if is_entry {
            self.filter.decide_entry_path(url)
        } else {
            self.filter.decide_path(url)
        };
        match path {
            ScopeDecision::InScope => {}
            ScopeDecision::Excluded(p) => return ScopeVerdict::Denied(DenialReason::Excluded(p)),
            ScopeDecision::NotIncluded => return ScopeVerdict::Denied(DenialReason::NotIncluded),
            // host relations are decided above; `decide_path` never returns them
            ScopeDecision::External | ScopeDecision::Subdomain => {
                return ScopeVerdict::Denied(DenialReason::HostScope)
            }
        }
        if !self.extensions.allows(url) {
            return ScopeVerdict::Denied(DenialReason::ExtensionFiltered);
        }
        if depth > self.max_depth {
            return ScopeVerdict::Denied(DenialReason::DepthExceeded {
                depth,
                max: self.max_depth,
            });
        }
        ScopeVerdict::Admitted { leaf_only: false }
    }

    fn host_pattern_admits(&self, host: &str) -> bool {
        self.host_pattern
            .as_ref()
            .is_some_and(|p| p.matches_include(&host.trim_end_matches('.').to_ascii_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;
    use crawlx_core::url::RouteTemplate;
    use url::Url;

    fn crawl(seed: &str, f: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
        let mut c = CreateCrawl::new(Url::parse(seed).unwrap());
        // the request default `excludeHosts: ["private-ips"]` is exercised explicitly below
        c.scope.exclude_hosts.clear();
        f(&mut c);
        c
    }

    fn cu(s: &str) -> CanonicalUrl {
        let url = Url::parse(s).unwrap();
        CanonicalUrl {
            origin: url.origin().ascii_serialization(),
            key: Digest::of("test", s.as_bytes()),
            route_template: RouteTemplate(url.path().to_owned()),
            params: Vec::new(),
            url,
        }
    }

    fn denied(v: &ScopeVerdict) -> &'static str {
        match v {
            ScopeVerdict::Denied(r) => r.as_str(),
            ScopeVerdict::Admitted { .. } => "admitted",
        }
    }

    #[test]
    fn same_host_admitted_external_and_subdomain_denied_by_default() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true
        }))
        .unwrap();
        assert_eq!(
            p.decide(&cu("https://example.com/a"), 1),
            ScopeVerdict::Admitted { leaf_only: false }
        );
        assert_eq!(
            p.decide(&cu("https://blog.example.com/a"), 1),
            ScopeVerdict::Denied(DenialReason::Subdomain)
        );
        assert_eq!(
            p.decide(&cu("https://other.org/a"), 1),
            ScopeVerdict::Denied(DenialReason::External)
        );
    }

    #[test]
    fn subdomains_allowed_when_enabled() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.allow_subdomains = true;
        }))
        .unwrap();
        assert!(p.decide(&cu("https://blog.example.com/a"), 1).is_admitted());
        assert!(!p.decide(&cu("https://notexample.com/a"), 1).is_admitted());
    }

    #[test]
    fn external_links_admitted_as_leaves() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.allow_external_links = true;
        }))
        .unwrap();
        assert_eq!(
            p.decide(&cu("https://other.org/x"), 1),
            ScopeVerdict::Admitted { leaf_only: true }
        );
    }

    #[test]
    fn include_out_of_scope_records_leaves_for_every_host_scope() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.output.include_out_of_scope = true;
        }))
        .unwrap();
        assert_eq!(
            p.decide(&cu("https://other.org/x"), 1),
            ScopeVerdict::Admitted { leaf_only: true }
        );
        assert_eq!(
            p.decide(&cu("https://blog.example.com/x"), 1),
            ScopeVerdict::Admitted { leaf_only: true }
        );
        assert!(
            !p.fetch_leaves(),
            "includeOutOfScope records leaves without fetching"
        );
        let fetching = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.allow_external_links = true;
        }))
        .unwrap();
        assert!(fetching.fetch_leaves());
        let rdn = ScopePolicy::new(&crawl("https://a.example.co.uk/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.host_scope = HostScope::Rdn;
            c.output.include_out_of_scope = true;
        }))
        .unwrap();
        assert_eq!(
            rdn.decide(&cu("https://other.org/x"), 1),
            ScopeVerdict::Admitted { leaf_only: true }
        );
    }

    #[test]
    fn depth_limit_is_inclusive_and_checked_last() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.max_discovery_depth = 2;
        }))
        .unwrap();
        assert!(p.decide(&cu("https://example.com/a"), 2).is_admitted());
        assert_eq!(
            p.decide(&cu("https://example.com/a"), 3),
            ScopeVerdict::Denied(DenialReason::DepthExceeded { depth: 3, max: 2 })
        );
        // an out-of-scope host beyond the depth limit reports the host (check order)
        assert_eq!(
            p.decide(&cu("https://other.org/"), 9),
            ScopeVerdict::Denied(DenialReason::External)
        );
    }

    #[test]
    fn seed_path_restricts_unless_crawl_entire_domain() {
        let narrow = ScopePolicy::new(&crawl("https://example.com/docs/", |_| {})).unwrap();
        assert!(narrow.decide(&cu("https://example.com/docs/a"), 1).is_admitted());
        assert_eq!(
            narrow.decide(&cu("https://example.com/blog"), 1),
            ScopeVerdict::Denied(DenialReason::NotIncluded)
        );
        let wide = ScopePolicy::new(&crawl("https://example.com/docs/", |c| {
            c.scope.crawl_entire_domain = true
        }))
        .unwrap();
        assert!(wide.decide(&cu("https://example.com/blog"), 1).is_admitted());
    }

    #[test]
    fn include_and_exclude_patterns() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.include_paths = vec!["^/docs/".into()];
            c.scope.exclude_paths = vec!["private".into()];
        }))
        .unwrap();
        assert!(p.decide(&cu("https://example.com/docs/a"), 1).is_admitted());
        assert_eq!(
            p.decide(&cu("https://example.com/blog"), 1),
            ScopeVerdict::Denied(DenialReason::NotIncluded)
        );
        let v = p.decide(&cu("https://example.com/docs/private/x"), 1);
        assert_eq!(v, ScopeVerdict::Denied(DenialReason::Excluded("private".into())));
        assert_eq!(denied(&v), "excluded_path");
    }

    #[test]
    fn entry_url_is_exempt_from_the_include_filters_only() {
        // the seed `/` matches neither include list: it is still fetched to start discovery
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.include_paths = vec!["^/docs/".into()];
            c.scope.url_include = vec!["^https://example\\.com/docs/".into()];
            c.scope.exclude_paths = vec!["^/private".into()];
            c.scope.url_exclude = vec!["secret".into()];
        }))
        .unwrap();
        let seed = cu("https://example.com/");
        assert_eq!(
            p.decide(&seed, 0),
            ScopeVerdict::Denied(DenialReason::UrlNotIncluded)
        );
        assert_eq!(p.decide_entry(&seed), ScopeVerdict::Admitted { leaf_only: false });
        assert_eq!(p.entry_include_denial(&seed), Some(DenialReason::UrlNotIncluded));
        // everything else keeps its include verdict
        let blog = cu("https://example.com/blog");
        assert_eq!(
            p.decide(&blog, 1),
            ScopeVerdict::Denied(DenialReason::UrlNotIncluded)
        );
        // the exclude lists still refuse the entry URL, whatever the include lists say
        for excluded in ["https://example.com/private", "https://example.com/x/secret"] {
            let url = cu(excluded);
            assert!(!p.decide_entry(&url).is_admitted(), "{excluded}");
            assert_eq!(p.entry_include_denial(&url), None, "{excluded}");
        }
        // an admitted entry URL has no include denial
        let inside = cu("https://example.com/docs/a");
        assert_eq!(p.entry_include_denial(&inside), None);

        let paths_only = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.include_paths = vec!["^/docs/".into()];
        }))
        .unwrap();
        assert_eq!(
            paths_only.entry_include_denial(&seed),
            Some(DenialReason::NotIncluded)
        );
        assert_eq!(
            paths_only.entry_include_denial(&seed).map(|r| r.as_str()),
            Some("not_included")
        );
    }

    #[test]
    fn entry_url_keeps_its_other_denials() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.include_paths = vec!["^/docs/".into()];
        }))
        .unwrap();
        // the extension filter and the host rules are not include filters
        let image = cu("https://example.com/logo.png");
        assert_eq!(
            p.decide_entry(&image),
            ScopeVerdict::Denied(DenialReason::ExtensionFiltered)
        );
        assert_eq!(p.entry_include_denial(&image), None);
        let external = cu("https://other.org/");
        assert_eq!(p.entry_include_denial(&external), None);
        assert!(!DenialReason::Excluded("x".into()).is_include());
        assert!(DenialReason::NotIncluded.is_include() && DenialReason::UrlNotIncluded.is_include());
    }

    #[test]
    fn bad_pattern_is_a_policy_error() {
        let r = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.include_paths = vec!["(".into()]
        }));
        assert!(matches!(r, Err(PolicyError::Scope(_))));
        let r = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.url_exclude = vec!["(".into()]
        }));
        assert!(matches!(r, Err(PolicyError::Scope(_))));
        let r = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.exclude_hosts = vec!["(".into()]
        }));
        assert!(matches!(r, Err(PolicyError::Scope(_))));
    }

    #[test]
    fn public_suffix_helpers() {
        assert!(PSL.as_ref().is_ok_and(|l| !l.is_empty()));
        assert_eq!(
            registrable_domain("a.b.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("WWW.Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("example.github.io").as_deref(),
            Some("example.github.io")
        );
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("10.0.0.1"), None);
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(domain_keyword("a.b.example.co.uk").as_deref(), Some("example"));
        assert_eq!(domain_keyword("example.com").as_deref(), Some("example"));
        assert_eq!(domain_keyword("::1"), None);
    }

    #[test]
    fn host_scope_table() {
        // seed, mode, host, expected code
        let table: &[(&str, HostScope, &str, &str)] = &[
            (
                "a.b.example.co.uk",
                HostScope::Fqdn,
                "a.b.example.co.uk",
                "admitted",
            ),
            (
                "a.b.example.co.uk",
                HostScope::Fqdn,
                "A.B.EXAMPLE.CO.UK.",
                "admitted",
            ),
            (
                "a.b.example.co.uk",
                HostScope::Fqdn,
                "x.a.b.example.co.uk",
                "subdomain",
            ),
            (
                "a.b.example.co.uk",
                HostScope::Fqdn,
                "b.example.co.uk",
                "external",
            ),
            ("a.b.example.co.uk", HostScope::Fqdn, "example.co.uk", "external"),
            (
                "a.b.example.co.uk",
                HostScope::Rdn,
                "a.b.example.co.uk",
                "admitted",
            ),
            ("a.b.example.co.uk", HostScope::Rdn, "b.example.co.uk", "admitted"),
            ("a.b.example.co.uk", HostScope::Rdn, "example.co.uk", "admitted"),
            (
                "a.b.example.co.uk",
                HostScope::Rdn,
                "cdn.example.co.uk",
                "admitted",
            ),
            (
                "a.b.example.co.uk",
                HostScope::Rdn,
                "evilexample.co.uk",
                "host_scope",
            ),
            ("a.b.example.co.uk", HostScope::Rdn, "example.com", "host_scope"),
            ("a.b.example.co.uk", HostScope::Rdn, "co.uk", "host_scope"),
            ("a.b.example.co.uk", HostScope::Dn, "example.com", "admitted"),
            ("a.b.example.co.uk", HostScope::Dn, "myexample.net", "admitted"),
            ("a.b.example.co.uk", HostScope::Dn, "other.org", "host_scope"),
            ("a.b.example.co.uk", HostScope::None, "anything.test", "admitted"),
            ("192.0.2.10", HostScope::Rdn, "192.0.2.10", "admitted"),
            ("192.0.2.10", HostScope::Rdn, "192.0.2.11", "host_scope"),
            ("192.0.2.10", HostScope::Dn, "192.0.2.11", "host_scope"),
            ("192.0.2.10", HostScope::Fqdn, "192.0.2.10", "admitted"),
        ];
        for (seed, mode, host, want) in table {
            let p = ScopePolicy::new(&crawl(&format!("https://{seed}/"), |c| {
                c.scope.crawl_entire_domain = true;
                c.scope.host_scope = *mode;
            }))
            .unwrap();
            let v = p.decide(&cu(&format!("https://{host}/x")), 1);
            assert_eq!(denied(&v), *want, "{seed} {mode:?} {host}");
        }
        let rule = HostScopeRule::new(HostScope::Rdn, "a.b.example.co.uk", false).unwrap();
        assert_eq!(rule.registrable_domain(), "example.co.uk");
        assert_eq!(rule.keyword(), "example");
        assert_eq!(rule.mode(), HostScope::Rdn);
    }

    #[test]
    fn url_regex_include_and_exclude() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.allow_subdomains = true;
            c.scope.url_include = vec!["^https://[a-z]+\\.example\\.com/api/".into()];
            c.scope.url_exclude = vec!["logout".into(), "\\?debug=".into()];
        }))
        .unwrap();
        assert!(p.decide(&cu("https://app.example.com/api/v1"), 1).is_admitted());
        let v = p.decide(&cu("https://app.example.com/api/logout"), 1);
        assert_eq!(
            v,
            ScopeVerdict::Denied(DenialReason::UrlExcluded("logout".into()))
        );
        assert_eq!(denied(&v), "url_excluded");
        assert_eq!(
            denied(&p.decide(&cu("https://app.example.com/api/x?debug=1"), 1)),
            "url_excluded"
        );
        let v = p.decide(&cu("https://example.com/api/v1"), 1);
        assert_eq!(v, ScopeVerdict::Denied(DenialReason::UrlNotIncluded));
        assert_eq!(denied(&v), "url_not_included");
        // exclude wins over include
        assert_eq!(
            denied(&p.decide(&cu("https://app.example.com/api/logout"), 1)),
            "url_excluded"
        );
        // out-of-scope hosts are decided before URL patterns
        assert_eq!(denied(&p.decide(&cu("https://other.org/api/"), 1)), "external");
    }

    #[test]
    fn exclude_hosts_private_ips_cidr_ip_and_regex() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.host_scope = HostScope::None;
            c.scope.exclude_hosts = vec![
                "private-ips".into(),
                "8.8.8.0/24".into(),
                "1.1.1.1".into(),
                "^cdn\\.".into(),
                "2606:4700::/32".into(),
            ];
        }))
        .unwrap();
        let cases = [
            ("https://10.0.0.5/x", "private-ips"),
            ("https://127.0.0.1/x", "private-ips"),
            ("https://[::1]/x", "private-ips"),
            ("https://8.8.8.9/x", "8.8.8.0/24"),
            ("https://1.1.1.1/x", "1.1.1.1"),
            ("https://cdn.example.com/x", "^cdn\\."),
            ("https://[2606:4700::1]/x", "2606:4700::/32"),
        ];
        for (u, entry) in cases {
            let v = p.decide(&cu(u), 1);
            assert_eq!(
                v,
                ScopeVerdict::Denied(DenialReason::HostExcluded(entry.into())),
                "{u}"
            );
            assert_eq!(denied(&v), "host_excluded");
        }
        assert!(p.decide(&cu("https://8.8.9.1/x"), 1).is_admitted());
        assert!(p.decide(&cu("https://www.example.com/x"), 1).is_admitted());
        // a name resolving to a private address is excluded only when the resolver says so
        let u = Url::parse("https://intranet.example.com/x").unwrap();
        assert!(p.decide_url(&u, 1).is_admitted());
        assert_eq!(
            p.decide_resolved(&u, 1, Some("10.1.2.3".parse().unwrap())),
            ScopeVerdict::Denied(DenialReason::HostExcluded("private-ips".into()))
        );
        assert!(p
            .decide_resolved(&u, 1, Some("93.184.216.34".parse().unwrap()))
            .is_admitted());
        // exclusions beat the host scope and leaf recording
        let strict = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.exclude_hosts = vec!["private-ips".into()];
            c.output.include_out_of_scope = true;
        }))
        .unwrap();
        assert_eq!(
            denied(&strict.decide(&cu("https://192.168.1.1/"), 1)),
            "host_excluded"
        );
        assert_eq!(denied(&strict.decide(&cu("https://other.org/"), 1)), "admitted");
        let direct = ExcludeHosts::new(&["[::1]".into()]).unwrap();
        assert_eq!(direct.matches("[::1]", None), Some("[::1]"));
        // the request default has no exclusions: private ranges are the egress policy's job
        let default =
            ScopePolicy::new(&CreateCrawl::new(Url::parse("https://example.com/").unwrap())).unwrap();
        assert_eq!(denied(&default.decide(&cu("https://10.0.0.1/"), 1)), "external");
        // `private-ips` is dropped when private networks are explicitly authorized
        let authorized = ScopePolicy::new(&crawl("https://10.0.0.1/", |c| {
            c.scope.exclude_hosts = vec!["private-ips".into()];
            c.safety.allow_private_networks = true;
        }))
        .unwrap();
        assert_eq!(
            denied(&authorized.decide(&cu("https://10.0.0.1/app/"), 1)),
            "admitted"
        );
    }

    #[test]
    fn record_scope_is_a_hard_bound_that_scope_settings_cannot_widen() {
        let mut record = crate::authorization::tests::record();
        record.origins = vec!["https://a.example.test".to_owned()];
        record.excluded_paths = vec!["/billing/*".to_owned()];
        let c = crawl("https://a.example.test/", |c| {
            c.scope.allow_subdomains = true;
            c.scope.allow_external_links = true;
            c.scope.crawl_entire_domain = true;
        });
        let unbound = ScopePolicy::new(&c).unwrap();
        assert!(unbound.decide(&cu("https://other.test/x"), 1).is_admitted());
        let bound = ScopePolicy::new(&c).unwrap().with_record_scope(record.scope());
        for out in [
            "https://other.test/x",
            "https://b.example.test/",
            "https://a.example.test/billing/x",
            "http://a.example.test/",
        ] {
            assert_eq!(denied(&bound.decide(&cu(out), 1)), "authorization_scope", "{out}");
        }
        assert!(bound.decide(&cu("https://a.example.test/docs"), 1).is_admitted());
        assert!(bound.decide_entry(&cu("https://a.example.test/")).is_admitted());
    }

    #[test]
    fn extension_filter_and_denial_codes() {
        let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
        }))
        .unwrap();
        let v = p.decide(&cu("https://example.com/logo.png"), 1);
        assert_eq!(v, ScopeVerdict::Denied(DenialReason::ExtensionFiltered));
        assert_eq!(denied(&v), "extension_filtered");
        assert!(p.decide(&cu("https://example.com/page.html"), 1).is_admitted());
        let matched = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.extension_match = vec!["png".into()];
        }))
        .unwrap();
        assert!(matched
            .decide(&cu("https://example.com/logo.png"), 1)
            .is_admitted());
        assert_eq!(
            denied(&matched.decide(&cu("https://example.com/page.html"), 1)),
            "extension_filtered"
        );
        let off = ScopePolicy::new(&crawl("https://example.com/", |c| {
            c.scope.crawl_entire_domain = true;
            c.scope.no_default_extension_filter = true;
            c.scope.max_pages_per_host = Some(5);
        }))
        .unwrap();
        assert!(off.decide(&cu("https://example.com/logo.png"), 1).is_admitted());
        assert_eq!(off.max_pages_per_host(), Some(5));
        assert_eq!(DenialReason::HostPageLimit.as_str(), "host_page_limit");
        assert_eq!(DenialReason::HostScope.as_str(), "host_scope");
    }
}
