//! Compatibility API `allowExternalLinks`: an external page is fetched as a leaf, an
//! external homepage is skipped with `DenialReason::ExternalHomepage`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::CreateCrawl;
use crawlx_core::scrape::{JobKind, ScrapeJob, ScrapeOptions};
use crawlx_policy::{DenialReason, ScopePolicy, ScopeVerdict};
use url::Url;

fn crawl(scrape: bool, allow_external: bool) -> CreateCrawl {
    let mut c = CreateCrawl::new(Url::parse("https://example.com/docs/").unwrap());
    c.scope.exclude_hosts.clear();
    c.scope.allow_external_links = allow_external;
    if scrape {
        c.scrape = Some(ScrapeJob::new(JobKind::Crawl, ScrapeOptions::default()));
    }
    c
}

fn decide(p: &ScopePolicy, url: &str) -> ScopeVerdict {
    p.decide_url(&Url::parse(url).unwrap(), 1)
}

#[test]
fn external_pages_are_leaves_and_external_homepages_are_skipped() {
    let p = ScopePolicy::new(&crawl(true, true)).unwrap();
    assert_eq!(
        decide(&p, "https://other.org/article"),
        ScopeVerdict::Admitted { leaf_only: true }
    );
    for homepage in [
        "https://other.org/",
        "https://other.org",
        "https://other.org/?ref=x",
        "https://blog.example.com/",
    ] {
        assert_eq!(
            decide(&p, homepage),
            ScopeVerdict::Denied(DenialReason::ExternalHomepage),
            "{homepage}"
        );
    }
    assert_eq!(DenialReason::ExternalHomepage.as_str(), "external_homepage");
    // in-scope pages are untouched, including the seed host's own homepage
    assert_eq!(
        decide(&p, "https://example.com/docs/intro"),
        ScopeVerdict::Admitted { leaf_only: false }
    );
    assert!(p.fetch_leaves());
}

#[test]
fn native_crawls_and_crawls_without_external_links_keep_their_behaviour() {
    // a native crawl (no scrape job) fetches external homepages as leaves
    let native = ScopePolicy::new(&crawl(false, true)).unwrap();
    assert_eq!(
        decide(&native, "https://other.org/"),
        ScopeVerdict::Admitted { leaf_only: true }
    );
    // without allowExternalLinks an external page is simply out of scope
    let closed = ScopePolicy::new(&crawl(true, false)).unwrap();
    assert_eq!(
        decide(&closed, "https://other.org/"),
        ScopeVerdict::Denied(DenialReason::External)
    );
    assert_eq!(
        decide(&closed, "https://other.org/article"),
        ScopeVerdict::Denied(DenialReason::External)
    );
}
