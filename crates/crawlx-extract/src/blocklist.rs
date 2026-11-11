//! Ad, analytics, tracker, pixel and cookie-popup blocklist (compatibility API `blockAds`).
//!
//! The list lives in `data/blocklist.txt` (authored for crawlx, embedded with `include_str!`
//! and parsed once). Every entry becomes Chrome DevTools Protocol `Network.setBlockedURLs`
//! wildcard patterns, where `*` matches any run of characters:
//!
//! | entry | patterns |
//! |---|---|
//! | `doubleclick.net` | `*://doubleclick.net/*`, `*://*.doubleclick.net/*` |
//! | `s.pinimg.com/ct/` | `*://s.pinimg.com/ct/*`, `*://*.s.pinimg.com/ct/*` |
//! | `/pagead/` | `*://*/pagead/*` |
//!
//! [`patterns`] is what the browser plane installs; [`is_blocked`] applies the very same
//! patterns to a URL for the fetch plane. Both are first-party-agnostic: a site that is itself
//! on the list (a tracker vendor's own marketing site) would be blocked while it is the scraped
//! page, so callers that know the page URL use [`patterns_for`] / [`is_blocked_for`], which
//! drop every host rule related to the page's host.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use crawlx_core::hash::Digest;
use crawlx_core::page_op::{BlockClass, BlockEntry, BlockInstall, ResourceBlockSpec};
use crawlx_core::scrape::{BlockListReportV1, ResourceBlocking};
use url::Url;

/// The embedded list.
const LIST: &str = include_str!("../data/blocklist.txt");

/// One list entry: the host it is about (host rules only) and its patterns.
struct Entry {
    host: Option<String>,
    patterns: Vec<String>,
}

/// Parsed list and the flat pattern list, built once.
struct Parsed {
    entries: Vec<Entry>,
    flat: Vec<String>,
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !host.starts_with('.')
        && !host.ends_with('.')
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'*' && b != b'?' && b != b'#')
}

/// Parse the list format of `data/blocklist.txt`; malformed lines are skipped.
fn parse(src: &str) -> Parsed {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut entries = Vec::new();
    let mut flat = Vec::new();
    for line in src
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (host, patterns) = if line.starts_with('/') {
            if !valid_path(line) {
                continue;
            }
            (None, vec![format!("*://*{line}*")])
        } else if let Some((host, path)) = line.split_once('/') {
            if !valid_host(host) || !valid_path(path) {
                continue;
            }
            (
                Some(host.to_owned()),
                vec![format!("*://{host}/{path}*"), format!("*://*.{host}/{path}*")],
            )
        } else {
            if !valid_host(line) {
                continue;
            }
            (
                Some(line.to_owned()),
                vec![format!("*://{line}/*"), format!("*://*.{line}/*")],
            )
        };
        if !seen.insert(line.to_owned()) {
            continue;
        }
        flat.extend(patterns.iter().cloned());
        entries.push(Entry { host, patterns });
    }
    Parsed { entries, flat }
}

static PARSED: LazyLock<Parsed> = LazyLock::new(|| parse(LIST));

/// `*` matches any run of characters (including none); everything else matches literally.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|b| *b == b'*')
}

/// Every pattern of the list, in file order, for `Network.setBlockedURLs`.
#[must_use]
pub fn patterns() -> &'static [String] {
    &PARSED.flat
}

/// True when `url` matches a pattern of [`patterns`].
#[must_use]
pub fn is_blocked(url: &Url) -> bool {
    let s = url.as_str();
    PARSED.flat.iter().any(|p| glob_match(p, s))
}

/// True when one host equals the other or is a subdomain of it.
fn related(page_host: &str, rule: &str) -> bool {
    let sub = |child: &str, parent: &str| {
        child == parent || child.strip_suffix(parent).is_some_and(|rest| rest.ends_with('.'))
    };
    sub(page_host, rule) || sub(rule, page_host)
}

/// A host rule is exempt when it is related to the page's host; path rules never are.
fn exempt(entry: &Entry, page_host: Option<&str>) -> bool {
    match (&entry.host, page_host) {
        (Some(rule), Some(host)) => related(host, rule),
        _ => false,
    }
}

/// The patterns of [`patterns`] without the host rules related to `page`'s host (the host itself,
/// its subdomains and its parent domains), so that scraping a listed site does not block the
/// site's own requests. Path rules stay.
#[must_use]
pub fn patterns_for(page: &Url) -> Vec<String> {
    let host = page.host_str();
    PARSED
        .entries
        .iter()
        .filter(|e| !exempt(e, host))
        .flat_map(|e| e.patterns.iter().cloned())
        .collect()
}

/// [`is_blocked`] for a request made by `page`: false for requests to hosts related to the page.
#[must_use]
pub fn is_blocked_for(page: &Url, url: &Url) -> bool {
    let (s, host) = (url.as_str(), page.host_str());
    PARSED
        .entries
        .iter()
        .filter(|e| !exempt(e, host))
        .any(|e| e.patterns.iter().any(|p| glob_match(p, s)))
}

/// Layout generation of the list format and of the type tables below; bump it when either
/// changes shape.
const LIST_LAYOUT: u32 = 1;

static VERSION: LazyLock<String> = LazyLock::new(|| {
    let digest = Digest::of("crawlx/blocklist/v1", LIST.as_bytes()).to_hex();
    format!(
        "crawlx-blocklist/{LIST_LAYOUT}+{}",
        digest.get(..12).unwrap_or(&digest)
    )
});

/// Version of the built-in list and type tables: the layout generation plus a digest of the
/// embedded list, so it changes whenever a rule does.
#[must_use]
pub fn list_version() -> &'static str {
    &VERSION
}

/// URL extensions that mark a font.
const FONT_EXTENSIONS: [&str; 5] = ["woff2", "woff", "ttf", "otf", "eot"];
/// URL extensions that mark audio or video.
const MEDIA_EXTENSIONS: [&str; 14] = [
    "mp4", "webm", "ogv", "mov", "m4v", "mp3", "ogg", "oga", "wav", "flac", "aac", "m4a", "m3u8", "mpd",
];
/// URL extensions that mark an image.
const IMAGE_EXTENSIONS: [&str; 9] = ["png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp"];

/// The extensions of a caller-selectable resource type; `None` for the other classes.
fn extensions(class: BlockClass) -> Option<&'static [&'static str]> {
    match class {
        BlockClass::Font => Some(&FONT_EXTENSIONS),
        BlockClass::Media => Some(&MEDIA_EXTENSIONS),
        BlockClass::Image => Some(&IMAGE_EXTENSIONS),
        _ => None,
    }
}

/// Is `host` acceptable as a caller-named blocked host (see
/// [`ResourceBlocking::is_valid_domain`])?
#[must_use]
pub fn valid_domain(host: &str) -> bool {
    ResourceBlocking::is_valid_domain(host)
}

/// What a render asks the block list to cover.
#[derive(Clone, Copy, Debug)]
pub struct BlockRequest<'a> {
    /// Block the built-in advertising, measurement and consent hosts.
    pub ads: bool,
    /// Resource types to block by URL extension (`Font`, `Media`, `Image`; other classes are
    /// ignored).
    pub resource_types: &'a [BlockClass],
    /// Hosts to block with their subdomains; entries that are not [`valid_domain`] are ignored
    /// (callers validate first).
    pub domains: &'a [String],
}

/// The list a render installs and the facts its completeness report needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockPlan {
    /// The list to install; empty when the request blocks nothing.
    pub spec: ResourceBlockSpec,
    ads: bool,
    classes: Vec<BlockClass>,
    custom_domains: u32,
    exempt_rules: u32,
}

impl BlockPlan {
    /// Does the plan block anything?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spec.entries.is_empty()
    }

    /// The metadata of the render once the plan was installed (`install`) or could not be
    /// (`None`: the plan did not reach any session, which is a gap, never a silent success).
    #[must_use]
    pub fn report(&self, install: Option<BlockInstall>) -> BlockListReportV1 {
        let install = install.unwrap_or_default();
        let mut gaps: Vec<String> = self
            .classes
            .iter()
            .filter(|class| class.by_extension())
            .map(|class| format!("type_by_url_extension:{}", class.as_str()))
            .collect();
        if self.exempt_rules > 0 {
            gaps.push(format!("first_party_rules_exempt:{}", self.exempt_rules));
        }
        if install.sessions_failed > 0 || install.sessions_applied == 0 {
            gaps.push("session_apply_failed".to_owned());
        }
        BlockListReportV1 {
            list_version: self.spec.list_version.clone(),
            ads: self.ads,
            resource_types: self
                .classes
                .iter()
                .copied()
                .filter(|class| class.by_extension())
                .collect(),
            custom_domains: self.custom_domains,
            patterns_installed: install.patterns,
            sessions_applied: install.sessions_applied,
            sessions_failed: install.sessions_failed,
            complete: gaps.is_empty(),
            gaps,
        }
    }
}

/// The block list for a render of `page`: the built-in hosts without those related to the
/// page's own host, the caller's hosts (sorted, de-duplicated), then the extension patterns of
/// each requested resource type (fonts, media, images in that order).
#[must_use]
pub fn plan(page: &Url, request: &BlockRequest<'_>) -> BlockPlan {
    let mut entries = Vec::new();
    let mut exempt_rules = 0_u32;
    if request.ads {
        let host = page.host_str();
        for entry in &PARSED.entries {
            if exempt(entry, host) {
                exempt_rules = exempt_rules.saturating_add(1);
                continue;
            }
            entries.extend(entry.patterns.iter().map(|pattern| BlockEntry {
                pattern: pattern.clone(),
                class: BlockClass::Ads,
            }));
        }
    }
    let domains: BTreeSet<&str> = request
        .domains
        .iter()
        .map(String::as_str)
        .filter(|d| valid_domain(d))
        .collect();
    for domain in &domains {
        for pattern in [
            format!("*://{domain}/*"),
            format!("*://{domain}:*/*"),
            format!("*://*.{domain}/*"),
            format!("*://*.{domain}:*/*"),
        ] {
            entries.push(BlockEntry {
                pattern,
                class: BlockClass::Domain,
            });
        }
    }
    let mut classes = Vec::new();
    for class in [BlockClass::Font, BlockClass::Media, BlockClass::Image] {
        let Some(list) = extensions(class) else {
            continue;
        };
        if !request.resource_types.contains(&class) {
            continue;
        }
        classes.push(class);
        for extension in list {
            for pattern in [format!("*.{extension}"), format!("*.{extension}?*")] {
                entries.push(BlockEntry { pattern, class });
            }
        }
    }
    BlockPlan {
        spec: ResourceBlockSpec {
            list_version: list_version().to_owned(),
            entries,
        },
        ads: request.ads,
        classes,
        custom_domains: u32::try_from(domains.len()).unwrap_or(u32::MAX),
        exempt_rules,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn list_has_at_least_150_distinct_vendor_entries_and_every_line_parses() {
        let lines: Vec<&str> = LIST
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let distinct: BTreeSet<&str> = lines.iter().copied().collect();
        assert_eq!(lines.len(), distinct.len(), "no duplicate entries");
        assert!(lines.len() >= 150, "{} entries", lines.len());
        assert_eq!(
            PARSED.entries.len(),
            lines.len(),
            "a line was rejected by the parser"
        );
        let hosts = lines.iter().filter(|l| !l.contains('/')).count();
        let paths = lines.iter().filter(|l| l.starts_with('/')).count();
        let host_paths = lines.len() - hosts - paths;
        assert_eq!(patterns().len(), 2 * hosts + paths + 2 * host_paths);
    }

    #[test]
    fn patterns_have_the_cdp_wildcard_shape() {
        let all = patterns();
        assert!(all.contains(&"*://doubleclick.net/*".to_owned()));
        assert!(all.contains(&"*://*.doubleclick.net/*".to_owned()));
        assert!(all.contains(&"*://*.s.pinimg.com/ct/*".to_owned()));
        assert!(all.contains(&"*://*/pagead/*".to_owned()));
        assert!(all.iter().all(|p| p.starts_with("*://")));
        assert!(all
            .iter()
            .all(|p| !p.contains(char::is_whitespace) && !p.contains("**")));
    }

    #[test]
    fn hosts_and_their_subdomains_are_blocked() {
        assert!(is_blocked(&u("https://doubleclick.net/")));
        assert!(is_blocked(&u(
            "https://ad.doubleclick.net/ddm/trackclk/N1;sz=300x250"
        )));
        assert!(is_blocked(&u("http://www.google-analytics.com/analytics.js"))); // detection-data
        assert!(is_blocked(&u("https://stats.g.doubleclick.net/j/collect?t=dc")));
        assert!(is_blocked(&u(
            "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"
        )));
    }

    #[test]
    fn lookalike_hosts_and_ordinary_pages_are_not_blocked() {
        assert!(!is_blocked(&u("https://notdoubleclick.net/")));
        assert!(!is_blocked(&u("https://doubleclick.net.example.org/")));
        assert!(!is_blocked(&u("https://example.com/")));
        assert!(!is_blocked(&u("https://example.com/blog/analytics-guide")));
        assert!(!is_blocked(&u("https://www.facebook.com/acme")));
        assert!(!is_blocked(&u("data:image/gif;base64,R0lGODlh")));
    }

    #[test]
    fn host_path_and_path_only_rules_apply() {
        assert!(is_blocked(&u("https://s.pinimg.com/ct/core.js")));
        assert!(!is_blocked(&u("https://s.pinimg.com/images/pin.png")));
        assert!(is_blocked(&u("https://www.google.com/ads/measurement/l?ebp=1"))); // detection-data
        assert!(!is_blocked(&u("https://www.google.com/search?q=ads"))); // detection-data
        assert!(is_blocked(&u("https://example.com/pagead/js/adsbygoogle.js"))); // detection-data
        assert!(is_blocked(&u("https://static.example.com/js/gtm.js?id=GTM-XXXX")));
        assert!(!is_blocked(&u("https://example.com/pageant/gallery")));
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_match("*", ""));
        assert!(glob_match("a*c", "abc"));
        assert!(glob_match("a*c", "ac"));
        assert!(glob_match("*://*.x.com/*", "https://a.b.x.com/p"));
        assert!(!glob_match("*://*.x.com/*", "https://x.com/p"));
        assert!(!glob_match("a*c", "abd"));
        assert!(glob_match("a**b", "a123b"));
        assert!(!glob_match("abc", "abcd"));
    }

    #[test]
    fn first_party_exemption_drops_related_host_rules_only() {
        let page = u("https://www.hotjar.com/pricing");
        assert!(is_blocked(&u("https://static.hotjar.com/c/hotjar-1.js")));
        assert!(!is_blocked_for(
            &page,
            &u("https://static.hotjar.com/c/hotjar-1.js")
        ));
        assert!(is_blocked_for(
            &page,
            &u("https://www.google-analytics.com/collect") // detection-data
        ));
        assert!(
            is_blocked_for(&page, &u("https://www.hotjar.com/pagead/x.js")),
            "path rules stay"
        );
        let kept = patterns_for(&page);
        assert!(kept.len() < patterns().len());
        assert!(!kept.contains(&"*://*.hotjar.com/*".to_owned()));
        assert!(kept.contains(&"*://*.doubleclick.net/*".to_owned()));
        let unrelated = u("https://example.com/");
        assert_eq!(patterns_for(&unrelated).len(), patterns().len());
    }

    #[test]
    fn related_hosts() {
        assert!(related("www.hotjar.com", "hotjar.com"));
        assert!(related("hotjar.com", "static.hotjar.com"));
        assert!(related("hotjar.com", "hotjar.com"));
        assert!(!related("nothotjar.com", "hotjar.com"));
        assert!(!related("example.com", "hotjar.com"));
    }

    fn request<'a>(ads: bool, classes: &'a [BlockClass], domains: &'a [String]) -> BlockRequest<'a> {
        BlockRequest {
            ads,
            resource_types: classes,
            domains,
        }
    }

    fn patterns_of(plan: &BlockPlan, class: BlockClass) -> Vec<&str> {
        plan.spec
            .entries
            .iter()
            .filter(|e| e.class == class)
            .map(|e| e.pattern.as_str())
            .collect()
    }

    #[test]
    fn the_version_names_the_layout_and_follows_the_list_content() {
        let version = list_version();
        let (layout, digest) = version.split_once('+').unwrap();
        assert_eq!(layout, "crawlx-blocklist/1");
        assert_eq!(digest.len(), 12);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        let again = Digest::of("crawlx/blocklist/v1", LIST.as_bytes()).to_hex();
        assert!(again.starts_with(digest));
        let changed = Digest::of("crawlx/blocklist/v1", format!("{LIST}\nexample.org\n").as_bytes()).to_hex();
        assert!(!changed.starts_with(digest), "one added rule changes the version");
    }

    #[test]
    fn ads_only_plan_is_exactly_the_first_party_aware_pattern_list() {
        let page = u("https://www.hotjar.com/");
        let plan = plan(&page, &request(true, &[], &[]));
        let planned: Vec<String> = plan.spec.entries.iter().map(|e| e.pattern.clone()).collect();
        assert_eq!(planned, patterns_for(&page));
        assert!(plan.spec.entries.iter().all(|e| e.class == BlockClass::Ads));
        assert_eq!(plan.spec.list_version, list_version());
        let report = plan.report(Some(BlockInstall {
            patterns: 3,
            sessions_applied: 2,
            sessions_failed: 0,
        }));
        assert!(plan.exempt_rules > 0, "the page's own host rules are left out");
        assert!(!report.complete, "{report:?}");
        assert_eq!(
            report.gaps,
            [format!("first_party_rules_exempt:{}", plan.exempt_rules)]
        );
        let unrelated = super::plan(&u("https://example.com/"), &request(true, &[], &[]));
        let clean = unrelated.report(Some(BlockInstall {
            patterns: u32::try_from(unrelated.spec.entries.len()).unwrap(),
            sessions_applied: 1,
            sessions_failed: 0,
        }));
        assert!(clean.complete && clean.gaps.is_empty(), "{clean:?}");
        assert!(clean.ads);
        assert_eq!(clean.list_version, list_version());
    }

    #[test]
    fn resource_types_match_by_extension_with_and_without_a_query_and_say_so() {
        let page = u("https://example.com/");
        let classes = [
            BlockClass::Image,
            BlockClass::Font,
            BlockClass::Media,
            BlockClass::Font,
        ];
        let plan = plan(&page, &request(false, &classes, &[]));
        // fonts, media, images in a fixed order whatever the request order was
        let order: Vec<BlockClass> =
            plan.spec
                .entries
                .iter()
                .map(|e| e.class)
                .fold(Vec::new(), |mut seen, c| {
                    if seen.last() != Some(&c) {
                        seen.push(c);
                    }
                    seen
                });
        assert_eq!(order, [BlockClass::Font, BlockClass::Media, BlockClass::Image]);
        let fonts = patterns_of(&plan, BlockClass::Font);
        assert_eq!(fonts.len(), 2 * FONT_EXTENSIONS.len());
        let matches = |url: &str| plan.spec.entries.iter().any(|e| glob_match(&e.pattern, url));
        assert!(matches("https://cdn.example/a/font.woff2"));
        assert!(matches("https://cdn.example/a/font.woff2?v=3&x=1"));
        assert!(matches("https://cdn.example/clip.mp4"));
        assert!(matches("https://cdn.example/clip.m3u8?token=1"));
        assert!(matches("https://cdn.example/p.avif"));
        assert!(!matches("https://cdn.example/app.js"));
        assert!(!matches("https://cdn.example/font.woff2.map"));
        assert!(
            !matches("https://cdn.example/api/font"),
            "a type without an extension is not matched"
        );
        let report = plan.report(Some(BlockInstall {
            patterns: 1,
            sessions_applied: 1,
            sessions_failed: 0,
        }));
        assert!(!report.complete);
        assert_eq!(
            report.gaps,
            [
                "type_by_url_extension:font",
                "type_by_url_extension:media",
                "type_by_url_extension:image"
            ]
        );
        assert_eq!(
            report.resource_types,
            [BlockClass::Font, BlockClass::Media, BlockClass::Image]
        );
    }

    #[test]
    fn custom_hosts_are_sorted_deduplicated_and_cover_subdomains_and_ports() {
        let page = u("https://example.com/");
        let domains: Vec<String> = [
            "b.test",
            "a.test",
            "b.test",
            "Bad.Test",
            "x.test:8080",
            "a..test",
            "",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let plan = plan(&page, &request(false, &[], &domains));
        let hosts = patterns_of(&plan, BlockClass::Domain);
        assert_eq!(
            hosts,
            [
                "*://a.test/*",
                "*://a.test:*/*",
                "*://*.a.test/*",
                "*://*.a.test:*/*",
                "*://b.test/*",
                "*://b.test:*/*",
                "*://*.b.test/*",
                "*://*.b.test:*/*"
            ]
        );
        assert_eq!(plan.report(None).custom_domains, 2);
        let matches = |url: &str| plan.spec.entries.iter().any(|e| glob_match(&e.pattern, url));
        assert!(matches("https://a.test/x"));
        assert!(matches("http://a.test:8080/x"));
        assert!(matches("https://cdn.b.test:8443/x"));
        assert!(!matches("https://nota.test/x"));
        assert!(!matches("https://a.test.evil.example/x"));
    }

    #[test]
    fn an_install_that_reached_no_session_or_lost_one_is_a_reported_gap() {
        let page = u("https://example.com/");
        let plan = plan(&page, &request(true, &[], &[]));
        let none = plan.report(None);
        assert!(!none.complete);
        assert_eq!(none.gaps, ["session_apply_failed"]);
        let lost = plan.report(Some(BlockInstall {
            patterns: 9,
            sessions_applied: 1,
            sessions_failed: 1,
        }));
        assert!(!lost.complete);
        assert_eq!(lost.gaps, ["session_apply_failed"]);
        assert_eq!(
            (
                lost.sessions_applied,
                lost.sessions_failed,
                lost.patterns_installed
            ),
            (1, 1, 9)
        );
    }

    #[test]
    fn a_request_that_blocks_nothing_makes_an_empty_plan() {
        let plan = plan(&u("https://example.com/"), &request(false, &[], &[]));
        assert!(plan.is_empty());
        // only the caller-selectable classes become patterns
        let ignored = super::plan(
            &u("https://example.com/"),
            &request(false, &[BlockClass::Ads, BlockClass::Domain], &[]),
        );
        assert!(ignored.is_empty());
    }
}
