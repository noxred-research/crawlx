//! `changeTracking.visibility`: is the page still reachable from the site's own link graph?
//!
//! Firecrawl: `visible` means discoverable through links or the sitemap, `hidden` means the URL
//! works but nothing points at it any more. crawlx decides from what it can observe:
//!
//! 1. a page of a crawl that was found by following a link or reading the sitemap (frontier
//!    depth above zero) is `visible`;
//! 2. the origin's root page is `visible` (it is the entry point of the link graph);
//! 3. otherwise the URL must be listed by one of the origin's sitemaps (`Sitemap:` lines of
//!    `robots.txt`, else `/sitemap.xml`) or linked from the origin's front page, both read
//!    through the run's own fetcher (egress policy and request controls apply);
//! 4. else it is `hidden`.
//!
//! The sitemap set and the front-page links of an origin are read once per run. A fetch that
//! fails contributes nothing, so an unreachable front page can only make a page `hidden`, never
//! fail the scrape. A page that answers `404`/`410` is `hidden` ([`super::change::track`]).

use crate::scrape::{Acquired, FetchObserver, ScrapeEngine};
use crawlx_core::repo::FrontierEntry;
use crawlx_extract::LinkExtractor;
use crawlx_fetch::FetchOptions;
use crawlx_policy::robots::RobotsTxt;
use crawlx_url::sitemap::SitemapTraversal;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::BTreeSet;
use url::Url;

/// Most sitemap documents read per origin.
const MAX_SITEMAP_DOCUMENTS: usize = 8;
/// Largest body read for `robots.txt`, a sitemap or the front page.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The URLs one origin's own pages and sitemaps point at.
#[derive(Debug, Default)]
pub(crate) struct OriginReach {
    /// Canonical URLs the origin's sitemaps list.
    sitemap: BTreeSet<String>,
    /// Canonical URLs the front page links to.
    front: BTreeSet<String>,
    /// The front page could not be parsed because the process-wide parse-memory budget was
    /// exhausted: the reach is unknown, not empty, so it is neither cached nor used to hide pages.
    parse_refused: bool,
}

impl OriginReach {
    /// Does the origin point at `key`?
    pub(crate) fn reaches(&self, key: &str) -> bool {
        self.parse_refused || self.sitemap.contains(key) || self.front.contains(key)
    }

    /// An origin that points at `urls` through its sitemap (tests).
    #[cfg(test)]
    pub(crate) fn with_sitemap(urls: &[&str]) -> Self {
        Self {
            sitemap: urls.iter().map(|u| (*u).to_owned()).collect(),
            front: BTreeSet::new(),
            parse_refused: false,
        }
    }
}

/// The comparison key of `url`: its canonical form.
fn key(url: &Url) -> Option<String> {
    Canonicalizer::canonicalize_url(url, &CanonicalizeOptions::default())
        .ok()
        .map(|c| c.url.to_string())
}

impl ScrapeEngine {
    /// Is the page of `entry` reachable from the link graph (see the module documentation)?
    pub(super) async fn is_visible(
        &self,
        entry: &FrontierEntry,
        acq: &mut Acquired,
        observe: &FetchObserver<'_>,
    ) -> bool {
        if entry.depth > 0 {
            return true;
        }
        let url = &entry.url.url;
        if url.path() == "/" && url.query().is_none() {
            return true;
        }
        let Some(wanted) = key(url) else {
            return true;
        };
        self.origin_reach(url, acq, observe).await.reaches(&wanted)
    }

    /// The (cached) reach of the origin of `url`.
    async fn origin_reach(
        &self,
        url: &Url,
        acq: &mut Acquired,
        observe: &FetchObserver<'_>,
    ) -> std::sync::Arc<OriginReach> {
        let origin = url.origin().ascii_serialization();
        if let Some(found) = self.reach.lock().get(&origin) {
            return std::sync::Arc::clone(found);
        }
        let reach = std::sync::Arc::new(self.read_origin(url, acq, observe).await);
        if !reach.parse_refused {
            self.reach.lock().insert(origin, std::sync::Arc::clone(&reach));
        }
        reach
    }

    /// One fetch through the run's fetcher; a failure or a non-2xx answer is `None`.
    async fn fetch_text(
        &self,
        url: &Url,
        acq: &mut Acquired,
        observe: &FetchObserver<'_>,
    ) -> Option<bytes::Bytes> {
        let options = FetchOptions {
            max_body_bytes: Some(MAX_BODY_BYTES),
            ..FetchOptions::default()
        };
        match self.fetch_auxiliary(url, &options, acq, observe).await {
            Ok(r) if r.status.is_success() => Some(r.body),
            Ok(r) => {
                tracing::debug!(status = r.status.as_u16(), "visibility source not usable");
                None
            }
            Err(e) => {
                tracing::debug!(code = e.code(), "visibility source not fetched");
                None
            }
        }
    }

    async fn read_origin(&self, url: &Url, acq: &mut Acquired, observe: &FetchObserver<'_>) -> OriginReach {
        let mut reach = OriginReach::default();
        if let Ok(home) = url.join("/") {
            if let Some(body) = self.fetch_text(&home, acq, observe).await {
                let html = String::from_utf8_lossy(&body);
                match LinkExtractor::links(&html, &home) {
                    Ok(links) => reach.front = links.iter().filter_map(|l| key(&l.url)).collect(),
                    Err(crawlx_extract::ExtractError::ParseMemory(_)) => reach.parse_refused = true,
                    // over the size, node or depth limits: this front page has no usable links
                    Err(_) => {}
                }
            }
        }
        let mut roots: Vec<String> = Vec::new();
        if let Ok(robots_url) = url.join("/robots.txt") {
            if let Some(body) = self.fetch_text(&robots_url, acq, observe).await {
                roots = RobotsTxt::parse(&body).sitemaps().to_vec();
            }
        }
        if roots.is_empty() {
            if let Ok(default) = url.join("/sitemap.xml") {
                roots.push(default.to_string());
            }
        }
        let mut traversal = SitemapTraversal::new();
        let mut queue: Vec<(String, usize, bool)> = roots.into_iter().map(|r| (r, 0, true)).collect();
        let mut fetched = 0usize;
        while let Some((loc, depth, root)) = queue.pop() {
            if fetched >= MAX_SITEMAP_DOCUMENTS || !traversal.has_room() {
                break;
            }
            let Ok(sitemap_url) = url.join(&loc) else { continue };
            fetched += 1;
            let Some(body) = self.fetch_text(&sitemap_url, acq, observe).await else {
                continue;
            };
            let pending = if root {
                traversal.ingest_root(&loc, &body)
            } else {
                traversal.ingest(&body, depth)
            };
            match pending {
                Ok(nested) => queue.extend(nested.into_iter().map(|p| (p.loc, p.depth, false))),
                Err(e) => tracing::debug!(sitemap = %loc, error = %e, "sitemap not usable"),
            }
        }
        reach.sitemap = traversal
            .into_urls()
            .into_iter()
            .filter_map(|u| Url::parse(&u.loc).ok())
            .filter_map(|u| key(&u))
            .collect();
        reach
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn keys_ignore_fragments_and_tracking_parameters() {
        let a = key(&Url::parse("https://e.test/a?utm_source=x#top").unwrap());
        let b = key(&Url::parse("https://e.test/a").unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn reach_matches_the_canonical_key() {
        let reach = OriginReach::with_sitemap(&["https://e.test/a"]);
        assert!(reach.reaches("https://e.test/a"));
        assert!(!reach.reaches("https://e.test/b"));
    }
}
