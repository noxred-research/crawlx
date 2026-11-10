#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Imported URL substring filters composed with explicit scope, evaluated by the real scope
//! policy.
//!
//! Composition documented by these cases:
//! * the imported substring filter becomes `scope.urlInclude` and only narrows;
//! * every explicit deny (`urlExclude`, host scope, `excludeHosts`) still wins over a
//!   substring match;
//! * the crawl seed is exempt from include patterns;
//! * the target-language hint only orders candidates and adds no scope rule.

use crawlx_core::CreateCrawl;
use crawlx_extract::extraction_import::{convert, inspect};
use crawlx_policy::scope::{DenialReason, ScopePolicy, ScopeVerdict};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use url::Url;

fn manifest(seed: &str, options: &str) -> Vec<u8> {
    format!(
        r#"{{"version":1,"source":"text-precision","sourceVersion":"2.3.1","dialect":"cli","options":{{"URL":"{seed}",{options}}}}}"#
    )
    .into_bytes()
}

fn crawl(seed: &str, options: &str) -> CreateCrawl {
    convert(&manifest(seed, options)).unwrap()
}

fn verdict(policy: &ScopePolicy, url: &str) -> ScopeVerdict {
    policy.decide_url(&Url::parse(url).unwrap(), 1)
}

fn denied(policy: &ScopePolicy, url: &str) -> Option<DenialReason> {
    match verdict(policy, url) {
        ScopeVerdict::Denied(reason) => Some(reason),
        _ => None,
    }
}

#[test]
fn substring_filter_narrows_and_matches_anywhere_in_the_url_text() {
    let crawl = crawl(
        "https://news.example.test/",
        r#""url-filter":["/blog/","?id=1","a.b"]"#,
    );
    assert_eq!(crawl.scope.url_include, ["/blog/", r"\?id=1", r"a\.b"]);
    let policy = ScopePolicy::new(&crawl).unwrap();
    for admitted in [
        "https://news.example.test/blog/post",
        "https://news.example.test/page?id=1",
        "https://news.example.test/page?id=12",
        "https://news.example.test/files/a.b",
    ] {
        assert!(verdict(&policy, admitted).is_admitted(), "{admitted}");
    }
    for narrowed in [
        "https://news.example.test/about",
        "https://news.example.test/blogger/post",
        "https://news.example.test/files/aXb",
    ] {
        assert_eq!(
            denied(&policy, narrowed),
            Some(DenialReason::UrlNotIncluded),
            "{narrowed}"
        );
    }
}

#[test]
fn explicit_scope_denies_win_over_a_matching_substring() {
    let mut crawl = crawl("https://news.example.test/", r#""url-filter":["/blog/"]"#);
    // Explicit native scope supplied next to the import.
    crawl.scope.url_exclude = vec!["/blog/private/".to_owned()];
    crawl.normalize().unwrap();
    let policy = ScopePolicy::new(&crawl).unwrap();

    assert!(verdict(&policy, "https://news.example.test/blog/public").is_admitted());
    assert!(matches!(
        denied(&policy, "https://news.example.test/blog/private/draft"),
        Some(DenialReason::UrlExcluded(_))
    ));
    // Host scope: the substring matches, but another site is not in scope.
    assert_eq!(
        denied(&policy, "https://other.example.test/blog/post"),
        Some(DenialReason::External)
    );
    // Include patterns never re-admit a URL outside the host scope, whatever its text.
    assert_eq!(
        denied(&policy, "https://news.example.test.evil.test/blog/post"),
        Some(DenialReason::External)
    );
}

#[test]
fn seed_is_exempt_from_the_substring_filter_but_its_links_are_not() {
    let crawl = crawl("https://news.example.test/", r#""url-filter":["/blog/"]"#);
    let policy = ScopePolicy::new(&crawl).unwrap();
    let seed = Canonicalizer::canonicalize_url(&crawl.seed_url, &CanonicalizeOptions::default()).unwrap();
    assert!(policy.decide_entry(&seed).is_admitted());
    assert_eq!(
        denied(&policy, "https://news.example.test/"),
        Some(DenialReason::UrlNotIncluded)
    );
    assert!(verdict(&policy, "https://news.example.test/blog/a").is_admitted());
}

#[test]
fn language_hint_adds_no_scope_rule_and_only_ranks() {
    let bytes = manifest(
        "https://news.example.test/",
        r#""feed":true,"target-language":"de""#,
    );
    let (report, crawl) = inspect(&bytes).unwrap();
    assert!(report.convertible);
    let crawl = crawl.unwrap();
    assert!(crawl.scope.url_include.is_empty() && crawl.scope.url_exclude.is_empty());
    let policy = ScopePolicy::new(&crawl).unwrap();
    // A URL marked for another language is still in scope; only its rank drops.
    let french = Url::parse("https://news.example.test/fr/story").unwrap();
    let german = Url::parse("https://news.example.test/de/story").unwrap();
    assert!(policy.decide_url(&french, 1).is_admitted());
    assert!(policy.decide_url(&german, 1).is_admitted());
    let discovery = crawl.scope.discovery.as_ref().unwrap();
    assert_eq!(discovery.language_rank(&german), 1);
    assert_eq!(discovery.language_rank(&french), -1);
    // Content language stays with the quality gate: the extraction policy keeps its strict target.
    assert_eq!(
        crawl.extract.content.as_ref().unwrap().target_language.as_deref(),
        Some("de")
    );
}

#[test]
fn invalid_filters_fail_before_any_request_exists() {
    for options in [
        r#""url-filter":[]"#,
        r##""url-filter":"""##,
        r#""url-filter":[" "]"#,
        r#""url-filter":{"nested":"x"}"#,
    ] {
        let bytes = manifest("https://news.example.test/", options);
        let (report, crawl) = inspect(&bytes).unwrap();
        assert!(!report.convertible && crawl.is_none(), "{options}");
    }
}
