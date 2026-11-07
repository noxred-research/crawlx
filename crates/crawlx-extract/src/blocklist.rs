//! Ad, analytics, tracker, pixel and cookie-popup blocklist (Firecrawl `blockAds`).
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
        assert!(is_blocked(&u("http://www.google-analytics.com/analytics.js")));
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
        assert!(is_blocked(&u("https://www.google.com/ads/measurement/l?ebp=1")));
        assert!(!is_blocked(&u("https://www.google.com/search?q=ads")));
        assert!(is_blocked(&u("https://example.com/pagead/js/adsbygoogle.js")));
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
            &u("https://www.google-analytics.com/collect")
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
}
