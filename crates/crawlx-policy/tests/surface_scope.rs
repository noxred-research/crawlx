//! Surface discovery parity: `scope.excludeHosts: ["cdn"]` and `scope.hostScopePattern`
//! (compatibility flags `-exclude cdn`, `-fs <regex>`) through `ScopePolicy`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::{CreateCrawl, HostScope};
use crawlx_policy::{DenialReason, ExcludeHosts, PolicyError, ScopePolicy, ScopeVerdict};
use url::Url;

fn crawl(seed: &str, f: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
    let mut c = CreateCrawl::new(Url::parse(seed).unwrap());
    c.scope.exclude_hosts.clear();
    c.scope.crawl_entire_domain = true;
    f(&mut c);
    c
}

fn decide(p: &ScopePolicy, url: &str) -> ScopeVerdict {
    p.decide_url(&Url::parse(url).unwrap(), 1)
}

fn code(v: &ScopeVerdict) -> &'static str {
    match v {
        ScopeVerdict::Denied(r) => r.as_str(),
        ScopeVerdict::Admitted { leaf_only: false } => "admitted",
        ScopeVerdict::Admitted { leaf_only: true } => "leaf_only",
    }
}

// ---- excludeHosts: cdn ------------------------------------------------------------------

#[test]
fn cdn_keyword_excludes_cdn_hosts_and_keeps_the_rest() {
    let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope = HostScope::None;
        c.scope.exclude_hosts = vec!["cdn".into()];
    }))
    .unwrap();
    for url in [
        "https://d111111abcdef8.cloudfront.net/app.js", // detection-data
        "https://cdn.jsdelivr.net/npm/x@1/x.js",
        "https://unpkg.com/x",
        "https://fonts.googleapis.com/css", // detection-data
        "https://example.akamaized.net/a",
        "https://assets.b-cdn.net/logo",
    ] {
        assert_eq!(
            decide(&p, url),
            ScopeVerdict::Denied(DenialReason::HostExcluded("cdn".into())),
            "{url}"
        );
    }
    for url in [
        "https://example.com/",
        "https://www.example.org/page",
        "https://notcloudfront.net/",           // detection-data
        "https://cloudfront.net.evil.test/",    // detection-data
        "https://www.googleapis.com/discovery", // detection-data
        "https://10.1.2.3/",
    ] {
        assert_eq!(code(&decide(&p, url)), "admitted", "{url}");
    }
}

#[test]
fn without_the_keyword_cdn_hosts_are_not_excluded() {
    let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope = HostScope::None;
    }))
    .unwrap();
    assert_eq!(
        code(&decide(&p, "https://cdn.jsdelivr.net/npm/x@1/x.js")),
        "admitted"
    );
}

#[test]
fn cdn_keyword_is_case_insensitive_trimmed_and_combines_with_other_entries() {
    let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope = HostScope::None;
        c.scope.exclude_hosts = vec![" CDN ".into(), "private-ips".into(), "^ads\\.".into()];
    }))
    .unwrap();
    assert_eq!(
        decide(&p, "https://x.cloudfront.net/a"), // detection-data
        ScopeVerdict::Denied(DenialReason::HostExcluded("CDN".into()))
    );
    assert_eq!(
        decide(&p, "https://10.0.0.1/a"),
        ScopeVerdict::Denied(DenialReason::HostExcluded("private-ips".into()))
    );
    assert_eq!(
        decide(&p, "https://ads.example.org/a"),
        ScopeVerdict::Denied(DenialReason::HostExcluded("^ads\\.".into()))
    );
    assert_eq!(code(&decide(&p, "https://shop.example.org/a")), "admitted");
}

#[test]
fn cdn_exclusion_beats_leaf_recording_and_external_links() {
    let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.allow_external_links = true;
        c.output.include_out_of_scope = true;
        c.scope.exclude_hosts = vec!["cdn".into()];
    }))
    .unwrap();
    assert_eq!(code(&decide(&p, "https://other.org/x")), "leaf_only");
    assert_eq!(code(&decide(&p, "https://d1.cloudfront.net/x")), "host_excluded");
    // detection-data
}

#[test]
fn exclude_hosts_matches_cdn_by_name_only() {
    let hosts = ExcludeHosts::new(&["cdn".into()]).unwrap();
    assert_eq!(hosts.matches("Fonts.GStatic.com.", None), Some("cdn"));
    assert_eq!(hosts.matches("example.com", None), None);
    // an address that merely resolves into a CDN range is not a name match
    assert_eq!(
        hosts.matches("origin.example.com", Some("104.16.0.1".parse().unwrap())),
        None
    );
    assert_eq!(hosts.matches("104.16.0.1", None), None);
}

#[test]
fn request_validation_accepts_the_cdn_keyword() {
    let mut c = CreateCrawl::new(Url::parse("https://example.com/").unwrap());
    c.scope.exclude_hosts = vec!["cdn".into(), "private-ips".into()];
    c.normalize().unwrap();
    assert_eq!(c.scope.exclude_hosts, ["cdn", "private-ips"]);
    assert!(ScopePolicy::new(&c).is_ok());
}

// ---- hostScopePattern -------------------------------------------------------------------

fn with_pattern(pattern: &str) -> ScopePolicy {
    ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope_pattern = Some(pattern.to_owned());
    }))
    .unwrap()
}

#[test]
fn host_scope_pattern_admits_extra_hosts_and_rejects_the_rest() {
    let p = with_pattern("^(cdn|static)\\.partner\\.test$");
    // the seed host stays in scope: the pattern adds to `hostScope`, it does not replace it
    assert_eq!(code(&decide(&p, "https://example.com/a")), "admitted");
    assert_eq!(code(&decide(&p, "https://cdn.partner.test/a")), "admitted");
    assert_eq!(code(&decide(&p, "https://static.partner.test/a")), "admitted");
    assert_eq!(
        decide(&p, "https://evil.partner.test/a"),
        ScopeVerdict::Denied(DenialReason::External)
    );
    assert_eq!(
        decide(&p, "https://blog.example.com/a"),
        ScopeVerdict::Denied(DenialReason::Subdomain)
    );
    // without the pattern the extra host is external
    let plain = ScopePolicy::new(&crawl("https://example.com/", |_| {})).unwrap();
    assert_eq!(
        decide(&plain, "https://cdn.partner.test/a"),
        ScopeVerdict::Denied(DenialReason::External)
    );
}

#[test]
fn host_scope_pattern_is_an_unanchored_regex_over_the_host_name_only() {
    let p = with_pattern("partner");
    assert_eq!(code(&decide(&p, "https://x.partner.test/a")), "admitted");
    assert_eq!(code(&decide(&p, "https://mypartner.org/a")), "admitted");
    // the path and the query are not part of the host
    assert_eq!(
        code(&decide(&p, "https://other.org/partner?partner=1")),
        "external"
    );
    // host case and a trailing dot are normalised before matching
    assert_eq!(code(&decide(&p, "https://X.PARTNER.test./a")), "admitted");
}

#[test]
fn host_scope_pattern_works_next_to_every_host_scope_mode() {
    for (mode, refused) in [
        (HostScope::Fqdn, "external"),
        (HostScope::Rdn, "host_scope"),
        (HostScope::Dn, "host_scope"),
    ] {
        let p = ScopePolicy::new(&crawl("https://www.example.co.uk/", |c| {
            c.scope.host_scope = mode;
            c.scope.host_scope_pattern = Some("^assets\\.partner\\.test$".into());
        }))
        .unwrap();
        assert_eq!(
            code(&decide(&p, "https://www.example.co.uk/a")),
            "admitted",
            "{mode:?}"
        );
        assert_eq!(
            code(&decide(&p, "https://assets.partner.test/a")),
            "admitted",
            "{mode:?}"
        );
        assert_eq!(
            code(&decide(&p, "https://api.partner.test/a")),
            refused,
            "{mode:?}"
        );
    }
}

#[test]
fn matching_hosts_are_in_scope_not_leaves_while_the_rest_still_become_leaves() {
    let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.output.include_out_of_scope = true;
        c.scope.host_scope_pattern = Some("^cdn\\.partner\\.test$".into());
    }))
    .unwrap();
    assert_eq!(
        decide(&p, "https://cdn.partner.test/a"),
        ScopeVerdict::Admitted { leaf_only: false }
    );
    assert_eq!(
        decide(&p, "https://other.org/a"),
        ScopeVerdict::Admitted { leaf_only: true }
    );
    assert!(!p.fetch_leaves());
}

#[test]
fn host_scope_pattern_does_not_override_exclusions_or_url_rules() {
    let p = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope_pattern = Some("partner\\.test$".into());
        c.scope.exclude_hosts = vec!["^cdn\\.".into()];
        c.scope.url_exclude = vec!["logout".into()];
        c.scope.max_discovery_depth = 2;
    }))
    .unwrap();
    assert_eq!(code(&decide(&p, "https://www.partner.test/a")), "admitted");
    assert_eq!(code(&decide(&p, "https://cdn.partner.test/a")), "host_excluded");
    assert_eq!(
        code(&decide(&p, "https://www.partner.test/logout")),
        "url_excluded"
    );
    assert_eq!(
        p.decide_url(&Url::parse("https://www.partner.test/a").unwrap(), 3),
        ScopeVerdict::Denied(DenialReason::DepthExceeded { depth: 3, max: 2 })
    );
}

#[test]
fn an_invalid_host_scope_pattern_is_a_scope_error() {
    let r = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope_pattern = Some("(".into());
    }));
    assert!(matches!(r, Err(PolicyError::Scope(_))), "{r:?}");
    // a pattern over the size bound is refused too, like every other pattern
    let r = ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope_pattern = Some("a".repeat(crawlx_core::config::MAX_PATH_PATTERN_LEN + 1));
    }));
    assert!(matches!(r, Err(PolicyError::Scope(_))), "{r:?}");
    // catastrophic-backtracking shapes are linear time with the `regex` engine and compile
    assert!(ScopePolicy::new(&crawl("https://example.com/", |c| {
        c.scope.host_scope_pattern = Some("^(a+)+$".into());
    }))
    .is_ok());
}

#[test]
fn a_blank_host_scope_pattern_admits_nothing_extra() {
    let p = with_pattern("   ");
    assert_eq!(code(&decide(&p, "https://other.org/a")), "external");
}
