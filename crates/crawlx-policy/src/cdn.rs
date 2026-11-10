//! CDN host list behind `scope.excludeHosts: ["cdn"]` (compatibility flag `-exclude cdn`).
//!
//! `data/cdn_hosts.txt` is an own-authored suffix list of delivery-network, public asset and
//! shared edge hostnames, embedded at build time. A host is a CDN host when it equals a
//! suffix or is a subdomain of one, matched on label boundaries (`d1.edge.example` and
//! `edge.example` match, `notedge.example` does not). Names are matched, never
//! resolved: no I/O.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// Suffixes of `data/cdn_hosts.txt` (blank lines and `#` comments skipped).
static SUFFIXES: LazyLock<BTreeSet<&'static str>> = LazyLock::new(|| {
    include_str!("../data/cdn_hosts.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
});

/// Is `host` a CDN or edge hostname of the bundled list? Case-insensitive; one trailing dot
/// is ignored. IP literals never match.
#[must_use]
pub fn is_cdn_host(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host: Cow<'_, str> = if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(host.to_ascii_lowercase())
    } else {
        Cow::Borrowed(host)
    };
    let mut rest: &str = &host;
    loop {
        if SUFFIXES.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, tail)) => rest = tail,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn suffix_and_subdomains_match_on_label_boundaries() {
        for host in [
            "cloudfront.net",                // detection-data
            "d111111abcdef8.cloudfront.net", // detection-data
            "cdn.jsdelivr.net",
            "a.b.c.akamaiedge.net",
            "mysite.b-cdn.net",
            "fonts.gstatic.com",
            "ajax.googleapis.com",  // detection-data
            "cdnjs.cloudflare.com", // detection-data
        ] {
            assert!(is_cdn_host(host), "{host}");
        }
        for host in [
            "notcloudfront.net",        // detection-data
            "cloudfront.net.evil.test", // detection-data
            "example.com",
            "www.cloudflare.com", // detection-data
            "www.googleapis.com", // detection-data
            "net",
            "",
            "10.0.0.1",
            "[::1]",
        ] {
            assert!(!is_cdn_host(host), "{host}");
        }
    }

    #[test]
    fn case_and_trailing_dot_are_ignored() {
        assert!(is_cdn_host("CDN.JsDelivr.NET."));
        assert!(is_cdn_host("Unpkg.com"));
    }

    #[test]
    fn data_file_is_well_formed() {
        let mut seen = BTreeSet::new();
        for line in include_str!("../data/cdn_hosts.txt").lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            assert!(line.contains('.'), "{line}: needs at least two labels");
            assert!(
                line.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'),
                "{line}: lowercase ascii, digits, dot, hyphen only"
            );
            assert!(!line.starts_with('.') && !line.ends_with('.'), "{line}");
            assert!(seen.insert(line), "{line}: duplicate");
        }
        assert!(seen.len() >= 50, "{} suffixes", seen.len());
        assert_eq!(seen, *SUFFIXES);
    }
}
