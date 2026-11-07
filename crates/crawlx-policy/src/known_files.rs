//! Known-files seeding (`scope.knownFiles`, katana `-kf`).
//!
//! `robots_paths` seeds every `Allow:` path of `robots.txt`; `Disallow:`
//! paths are seeded only when robots are *not* respected under an
//! authorization record (the only configuration where fetching them is
//! permitted at all). `sitemap` seeds every `Sitemap:` URL. Wildcard rules
//! (`*`, `$`) are patterns, not paths, and are never seeded.

use crawlx_core::config::KnownFile;
use url::Url;

use crate::robots::RobotsTxt;

/// Seed URLs mined from `robots` for the origin of `base`, in file order,
/// deduplicated.
#[must_use]
pub fn seeds(
    robots: &RobotsTxt,
    base: &Url,
    known_files: &[KnownFile],
    respect_robots: bool,
    authorized: bool,
) -> Vec<Url> {
    let mut out: Vec<Url> = Vec::new();
    let mut push = |u: Url| {
        if !out.contains(&u) {
            out.push(u);
        }
    };
    if known_files.contains(&KnownFile::RobotsPaths) {
        let seed_disallow = !respect_robots && authorized;
        for rule in robots.rules() {
            if !(rule.allow || seed_disallow) {
                continue;
            }
            let p = rule.pattern.as_str();
            if !p.starts_with('/') || p.contains('*') || p.contains('$') {
                continue;
            }
            if let Ok(u) = base.join(p) {
                if u.origin() == base.origin() {
                    push(u);
                }
            }
        }
    }
    if known_files.contains(&KnownFile::Sitemap) {
        for s in robots.sitemaps() {
            if let Ok(u) = base.join(s) {
                if matches!(u.scheme(), "http" | "https") {
                    push(u);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const ROBOTS: &str = "User-agent: *\nAllow: /public\nDisallow: /private\nDisallow: /tmp/*.json\nAllow: /docs$\nDisallow: /admin\nSitemap: https://e.test/s.xml\nSitemap: /relative.xml\nUser-agent: other\nAllow: /other-allowed\nSitemap: https://e.test/s.xml\n";

    fn paths(urls: &[Url]) -> Vec<String> {
        urls.iter().map(|u| u.path().to_owned()).collect()
    }

    #[test]
    fn allow_paths_and_sitemaps_seeded_disallow_only_without_respect_and_authorized() {
        let r = RobotsTxt::parse(ROBOTS.as_bytes());
        let base = Url::parse("https://e.test/start").unwrap();
        let both = [KnownFile::RobotsPaths, KnownFile::Sitemap];
        let respected = seeds(&r, &base, &both, true, true);
        assert_eq!(
            paths(&respected),
            ["/public", "/other-allowed", "/s.xml", "/relative.xml"]
        );
        // respected robots never seed a Disallow path, authorized or not
        assert_eq!(paths(&seeds(&r, &base, &both, true, false)), paths(&respected));
        // without respect but without authorization: still no Disallow paths
        assert_eq!(paths(&seeds(&r, &base, &both, false, false)), paths(&respected));
        let open = seeds(&r, &base, &both, false, true);
        assert_eq!(
            paths(&open),
            [
                "/public",
                "/private",
                "/admin",
                "/other-allowed",
                "/s.xml",
                "/relative.xml"
            ]
        );
        assert_eq!(open[0].as_str(), "https://e.test/public");
        // kinds select what is seeded
        assert_eq!(
            paths(&seeds(&r, &base, &[KnownFile::Sitemap], true, false)),
            ["/s.xml", "/relative.xml"]
        );
        assert_eq!(
            paths(&seeds(&r, &base, &[KnownFile::RobotsPaths], true, false)),
            ["/public", "/other-allowed"]
        );
        assert!(seeds(&r, &base, &[], false, true).is_empty());
        assert!(seeds(&RobotsTxt::allow_all(), &base, &both, false, true).is_empty());
    }
}
