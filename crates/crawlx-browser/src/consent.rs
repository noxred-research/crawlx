//! The cookie-consent banner blocklist behind `dynamic.blockConsentBanners` (the compatibility
//! cookie-consent bypass).
//!
//! `data/consent_block.txt` lists the URL patterns of well-known consent-management providers
//! and cookie-banner scripts (OneTrust, Cookiebot, TrustArc, Quantcast Choice, Usercentrics,
//! Didomi, Osano, Iubenda, CookieYes, Termly, ...). [`patterns`] parses it once; the worker
//! hands the result to
//! [`BrowserContext::page_op`](crawlx_core::BrowserContext::page_op) as
//! [`PageOp::BlockUrls`](crawlx_core::page_op::PageOp::BlockUrls), so the browser cancels those
//! requests (`Network.setBlockedURLs`) before they leave the machine and the banner never
//! renders over the page.
//!
//! # File format
//!
//! One pattern per line. Blank lines and lines starting with `#` are ignored; surrounding
//! whitespace is trimmed. A pattern is matched against the whole request URL and may contain
//! `*` wildcards, the syntax `PageOp::BlockUrls` documents. Entries are written
//! `*://<host>/<path>`.

use std::sync::LazyLock;

/// The bundled blocklist source.
const SOURCE: &str = include_str!("../data/consent_block.txt");

static PARSED: LazyLock<Vec<String>> = LazyLock::new(|| parse(SOURCE));

/// The URL patterns of the bundled consent-banner blocklist, in file order.
#[must_use]
pub fn patterns() -> &'static [String] {
    &PARSED
}

/// Parse a blocklist: one pattern per line, `#` comments and blank lines skipped.
#[must_use]
pub fn parse(source: &str) -> Vec<String> {
    source
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn parse_skips_comments_and_blank_lines_and_trims() {
        let parsed = parse("# header\n\n  *://a.test/*  \n#*://b.test/*\n*://c.test/x*\n");
        assert_eq!(parsed, ["*://a.test/*", "*://c.test/x*"]);
    }

    #[test]
    fn bundled_list_covers_the_named_providers_in_the_documented_shape() {
        let all = patterns();
        for host in [
            "cdn.cookielaw.org",
            "consent.cookiebot.com",
            "consent.trustarc.com",
            "cmp.quantcast.com",
            "app.usercentrics.eu",
            "sdk.privacy-center.org",
            "cmp.osano.com",
            "cdn.iubenda.com",
            "cdn-cookieyes.com",
            "app.termly.io",
        ] {
            assert!(
                all.iter().any(|p| p.contains(host)),
                "no pattern for {host}: {all:?}"
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for p in all {
            assert!(p.starts_with("*://"), "{p}: entries start with `*://`");
            assert!(p.ends_with('*'), "{p}: entries end with a wildcard path");
            assert!(!p.contains(char::is_whitespace), "{p}: no whitespace");
            assert!(seen.insert(p), "{p}: duplicate entry");
        }
        // patterns() hands out the same parsed list on every call
        assert!(std::ptr::eq(patterns(), patterns()));
    }
}
