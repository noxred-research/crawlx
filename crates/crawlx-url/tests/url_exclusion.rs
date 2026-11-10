//! Pre-acquisition URL exclusion in front of the scope admission surface.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::Scope;
use crawlx_core::extraction::{QualityReasonV1, UrlExclusionPolicyV1};
use crawlx_url::{
    PreFetchDecision, PreFetchGate, ScopeDecision, ScopeFilter, UrlExclusion, UrlExclusionFilter,
};
use url::Url;

fn u(s: &str) -> Url {
    Url::parse(s).unwrap()
}

fn gate() -> PreFetchGate {
    let mut policy = UrlExclusionPolicyV1::default();
    policy.substrings = vec!["/Sponsored/".into()];
    policy.patterns = vec![r"[?&]session=".into()];
    let scope = Scope {
        crawl_entire_domain: true,
        exclude_paths: vec!["^/private/".into()],
        ..Scope::default()
    };
    PreFetchGate::new(
        ScopeFilter::new(&u("https://example.test/"), &scope).unwrap(),
        UrlExclusionFilter::from_policy(&policy).unwrap(),
    )
}

#[test]
fn excluded_url_gets_zero_target_requests() {
    let gate = gate();
    let candidates = [
        u("https://example.test/sponsored/deal"),
        u("https://example.test/news/a?session=1"),
        u("https://example.test/news/b"),
        u("https://example.test/private/c"),
        u("https://other.test/news"),
    ];
    let mut requests = Vec::new();
    for url in &candidates {
        // the only place a request could be issued: after admission
        if matches!(gate.decide(url), PreFetchDecision::Scope(ScopeDecision::InScope)) {
            requests.push(url.as_str().to_owned());
        }
    }
    assert_eq!(requests, ["https://example.test/news/b"]);
}

#[test]
fn url_exclusion_reason_is_distinct_from_scope_and_quality_reasons() {
    let gate = gate();
    assert_eq!(
        gate.decide(&u("https://example.test/sponsored/deal")),
        PreFetchDecision::UrlExcluded(UrlExclusion::Substring("/Sponsored/".into()))
    );
    assert_eq!(
        gate.decide(&u("https://example.test/n?x=1&session=9")),
        PreFetchDecision::UrlExcluded(UrlExclusion::Pattern(r"[?&]session=".into()))
    );
    // a path-scope exclusion keeps its own verdict
    assert_eq!(
        gate.decide(&u("https://example.test/private/c")),
        PreFetchDecision::Scope(ScopeDecision::Excluded("^/private/".into()))
    );
    // the URL-exclusion code is not any content-quality reason code
    let code = UrlExclusion::Substring("x".into()).code();
    let quality = serde_json::to_value(QualityReasonV1::AuthorExcluded).unwrap();
    assert_eq!(code, "url_excluded");
    assert_eq!(quality, "author_excluded");
    assert_ne!(quality, code);
}

#[test]
fn entry_url_is_subject_to_url_exclusion_in_addition_to_path_excludes() {
    let gate = gate();
    assert_eq!(
        gate.decide_entry(&u("https://example.test/sponsored/")),
        PreFetchDecision::UrlExcluded(UrlExclusion::Substring("/Sponsored/".into()))
    );
    assert_eq!(
        gate.decide_entry(&u("https://example.test/")),
        PreFetchDecision::Scope(ScopeDecision::InScope)
    );
}

#[test]
fn gate_without_rules_decides_like_the_scope_filter() {
    let scope = ScopeFilter::new(&u("https://example.test/"), &Scope::default()).unwrap();
    let gate = PreFetchGate::new(scope.clone(), UrlExclusionFilter::default());
    let url = u("https://example.test/sponsored/deal");
    assert_eq!(gate.decide(&url), PreFetchDecision::Scope(scope.decide(&url)));
    assert_eq!(gate.scope().decide(&url), scope.decide(&url));
}
