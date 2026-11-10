//! Link extractor options: allow/deny regex and domains, tags/attributes, canonical form,
//! CSS/XPath restriction, unique and nofollow handling. Deny always wins.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::link_options::{LinkFilter, LinkOptions, LinkOptionsError, NofollowPolicy};
use url::Url;

const PAGE: &str = "https://shop.example.test/index.html";

const HTML: &str = r##"<!doctype html><html><head><base href="https://shop.example.test/catalog/"><title>t</title></head><body>
<a href="item?id=2&amp;b=1&amp;a=3#frag">Tom &amp; Jerry</a>
<a href="/news/a">First</a>
<a href="/news/a#again" rel="nofollow noopener">Second</a>
<a href="/news/a" rel="NoFollow">Third</a>
<a href="https://blog.example.test/post/1">blog</a>
<a href="https://ads.example.test/click?x=1">ad</a>
<a href="https://other.test/page">other</a>
<a href="mailto:x@y.test">mail</a>
<a href="javascript:void(0)">js</a>
<a href="#top">top</a>
<div id="nav"><a href="/news/b?z=1&amp;a=2">nav</a><area href="/map"><iframe src="/frame"></iframe></div>
<div class="footer"><a href="/legal">legal</a></div>
<script>document.write('<a href="/script">no</a>')</script>
</body></html>"##;

fn run(options: &LinkOptions) -> Vec<String> {
    LinkFilter::new(options)
        .unwrap()
        .links(HTML, &Url::parse(PAGE).unwrap())
        .unwrap()
        .into_iter()
        .map(|link| link.url.to_string())
        .collect()
}

fn options(edit: impl FnOnce(&mut LinkOptions)) -> LinkOptions {
    let mut options = LinkOptions::default();
    edit(&mut options);
    options
}

const ITEM: &str = "https://shop.example.test/catalog/item?id=2&b=1&a=3";
const NEWS_A: &str = "https://shop.example.test/news/a";
const BLOG: &str = "https://blog.example.test/post/1";
const ADS: &str = "https://ads.example.test/click?x=1";
const OTHER: &str = "https://other.test/page";
const NEWS_B: &str = "https://shop.example.test/news/b?z=1&a=2";
const MAP: &str = "https://shop.example.test/map";
const LEGAL: &str = "https://shop.example.test/legal";

#[test]
fn defaults_resolve_against_base_decode_entities_and_skip_non_navigation() {
    assert_eq!(
        run(&LinkOptions::default()),
        [ITEM, NEWS_A, BLOG, ADS, OTHER, NEWS_B, MAP, LEGAL]
    );
    let links = LinkFilter::new(&LinkOptions::default())
        .unwrap()
        .links(HTML, &Url::parse(PAGE).unwrap())
        .unwrap();
    // Entity-decoded text, first non-empty text wins, rel tokens union, nofollow needs every occurrence.
    assert_eq!(links[0].text, "Tom & Jerry");
    assert_eq!(links[1].text, "First");
    assert_eq!(links[1].rel, ["nofollow", "noopener"]);
    assert!(!links[1].nofollow);
    assert!(links[1].internal && !links[2].internal);
}

#[test]
fn allow_and_deny_regexes_run_on_the_absolute_url_and_deny_wins() {
    assert_eq!(
        run(&options(|o| o.allow = vec!["/news/".into()])),
        [NEWS_A, NEWS_B]
    );
    assert_eq!(
        run(&options(
            |o| o.allow = vec!["/news/".into(), "^https://blog\\.".into()]
        )),
        [NEWS_A, BLOG, NEWS_B]
    );
    // Everything on the example domain is allowed, but ads and the news section are denied.
    assert_eq!(
        run(&options(|o| {
            o.allow = vec!["example\\.test".into()];
            o.deny = vec!["^https://ads\\.".into(), "/news/".into()];
        })),
        [ITEM, BLOG, MAP, LEGAL]
    );
    // Deny only: no allow list means everything else passes.
    assert_eq!(
        run(&options(|o| o.deny = vec!["\\?".into()])),
        [NEWS_A, BLOG, OTHER, MAP, LEGAL]
    );
    // A rule matching both lists is rejected.
    assert!(run(&options(|o| {
        o.allow = vec!["news".into()];
        o.deny = vec!["news".into()];
    }))
    .is_empty());
}

#[test]
fn domain_rules_match_hosts_and_subdomains_and_deny_wins() {
    assert_eq!(
        run(&options(|o| o.allow_domains = vec!["example.test".into()])),
        [ITEM, NEWS_A, BLOG, ADS, NEWS_B, MAP, LEGAL]
    );
    assert_eq!(
        run(&options(
            |o| o.allow_domains = vec!["blog.example.test".into(), ".other.test".into()]
        )),
        [BLOG, OTHER]
    );
    // Suffix without a label boundary is not a subdomain.
    assert!(run(&options(|o| o.allow_domains = vec!["ample.test".into()])).is_empty());
    assert_eq!(
        run(&options(
            |o| o.deny_domains = vec!["ads.example.test".into(), "OTHER.test".into()]
        )),
        [ITEM, NEWS_A, BLOG, NEWS_B, MAP, LEGAL]
    );
    // Allowed by domain, denied by domain: denied.
    assert!(run(&options(|o| {
        o.allow_domains = vec!["shop.example.test".into()];
        o.deny_domains = vec!["example.test".into()];
    }))
    .is_empty());
    // Allowed by regex, denied by domain: denied.
    assert_eq!(
        run(&options(|o| {
            o.allow = vec!["example\\.test".into()];
            o.deny_domains = vec!["shop.example.test".into()];
        })),
        [BLOG, ADS]
    );
    // Allowed by domain, denied by regex: denied.
    assert_eq!(
        run(&options(|o| {
            o.allow_domains = vec!["example.test".into()];
            o.deny = vec!["^https://shop\\.".into()];
        })),
        [BLOG, ADS]
    );
}

#[test]
fn tags_and_attributes_are_configurable() {
    let frame = "https://shop.example.test/frame";
    assert_eq!(
        run(&options(|o| {
            o.tags = vec!["IFrame".into()];
            o.attrs = vec!["src".into()];
        })),
        [frame]
    );
    assert_eq!(
        run(&options(|o| {
            o.tags = vec!["a".into(), "iframe".into()];
            o.attrs = vec!["href".into(), "src".into()];
            o.allow = vec!["/(news/b|frame)".into()];
        })),
        [NEWS_B, frame]
    );
    // `area` is not scanned when only `a` is requested.
    assert!(!run(&options(|o| o.tags = vec!["a".into()])).contains(&MAP.to_owned()));
}

#[test]
fn restriction_selectors_limit_the_scanned_regions() {
    assert_eq!(
        run(&options(|o| o.restrict_css = vec!["#nav".into()])),
        [NEWS_B, MAP]
    );
    assert_eq!(
        run(&options(
            |o| o.restrict_xpath = vec!["//div[@class='footer']".into()]
        )),
        [LEGAL]
    );
    // Union in document order; an element selected directly counts as its own region.
    assert_eq!(
        run(&options(|o| {
            o.restrict_css = vec![".footer".into(), "#nav".into()];
            o.restrict_xpath = vec!["//a[@href='/news/a']".into()];
        })),
        [NEWS_A, NEWS_B, MAP, LEGAL]
    );
    // Restriction composes with deny.
    assert_eq!(
        run(&options(|o| {
            o.restrict_css = vec!["#nav".into()];
            o.deny = vec!["/map".into()];
        })),
        [NEWS_B]
    );
    // A selector that matches nothing yields nothing rather than the whole page.
    assert!(run(&options(|o| o.restrict_css = vec!["#absent".into()])).is_empty());
}

#[test]
fn canonical_form_sorts_query_pairs_and_collapses_variants() {
    let html = r##"<a href="/p?b=2&a=1#x">1</a><a href="/p?a=1&b=2">2</a><a href="/p?&a=1&&b=2&">3</a><a href="/q?">4</a>"##;
    let page = Url::parse(PAGE).unwrap();
    let plain = LinkFilter::new(&LinkOptions::default())
        .unwrap()
        .links(html, &page)
        .unwrap();
    assert_eq!(plain.len(), 4);
    let canonical = LinkFilter::new(&options(|o| o.canonicalize = true))
        .unwrap()
        .links(html, &page)
        .unwrap();
    let urls: Vec<_> = canonical.iter().map(|link| link.url.as_str()).collect();
    assert_eq!(
        urls,
        [
            "https://shop.example.test/p?a=1&b=2",
            "https://shop.example.test/q"
        ]
    );
    assert_eq!(canonical[0].text, "1");
    // Deny/allow see the canonical form.
    let filtered = LinkFilter::new(&options(|o| {
        o.canonicalize = true;
        o.allow = vec!["\\?a=1&b=2$".into()];
    }))
    .unwrap()
    .links(html, &page)
    .unwrap();
    assert_eq!(filtered.len(), 1);
}

#[test]
fn unique_and_nofollow_options() {
    let links = |options: &LinkOptions| {
        LinkFilter::new(options)
            .unwrap()
            .links(HTML, &Url::parse(PAGE).unwrap())
            .unwrap()
            .into_iter()
            .filter(|link| link.url.as_str() == NEWS_A)
            .map(|link| (link.text, link.rel, link.nofollow))
            .collect::<Vec<_>>()
    };
    let each = links(&options(|o| o.unique = false));
    assert_eq!(
        each,
        vec![
            ("First".to_owned(), vec![], false),
            (
                "Second".to_owned(),
                vec!["nofollow".to_owned(), "noopener".to_owned()],
                true
            ),
            ("Third".to_owned(), vec!["nofollow".to_owned()], true),
        ]
    );
    // Skip drops nofollow occurrences before merging.
    let skipped = links(&options(|o| o.nofollow = NofollowPolicy::Skip));
    assert_eq!(skipped, vec![("First".to_owned(), vec![], false)]);
    // A URL linked only with nofollow disappears entirely under Skip and is flagged under Keep.
    let only = r#"<a href="/x" rel="nofollow">x</a><a href="/x#y" rel="ugc nofollow">again</a>"#;
    let page = Url::parse(PAGE).unwrap();
    let kept = LinkFilter::new(&LinkOptions::default())
        .unwrap()
        .links(only, &page)
        .unwrap();
    assert_eq!(kept.len(), 1);
    assert!(kept[0].nofollow);
    assert_eq!(kept[0].rel, ["nofollow", "ugc"]);
    let dropped = LinkFilter::new(&options(|o| o.nofollow = NofollowPolicy::Skip))
        .unwrap()
        .links(only, &page)
        .unwrap();
    assert!(dropped.is_empty());
}

#[test]
fn unsafe_or_invalid_options_are_refused_at_compile_time() {
    let refuse = |edit: fn(&mut LinkOptions)| LinkFilter::new(&options(edit)).unwrap_err();
    // Backreferences and look-around cannot run on the linear-time engine.
    assert!(matches!(
        refuse(|o| o.allow = vec!["(a)\\1".into()]),
        LinkOptionsError::Rule {
            list: "allow",
            index: 0,
            ..
        }
    ));
    assert!(matches!(
        refuse(|o| o.deny = vec!["ok".into(), "(?=x)y".into()]),
        LinkOptionsError::Rule {
            list: "deny",
            index: 1,
            ..
        }
    ));
    assert!(matches!(
        refuse(|o| o.allow = vec![String::new()]),
        LinkOptionsError::Rule { .. }
    ));
    assert!(matches!(
        refuse(|o| o.allow = vec!["a".repeat(513)]),
        LinkOptionsError::Rule { .. }
    ));
    assert!(matches!(
        refuse(|o| o.deny = vec!["(((((a{1000}){1000}){1000}){1000}){1000})".into()]),
        LinkOptionsError::Rule { .. }
    ));
    assert!(matches!(
        refuse(|o| o.allow_domains = vec!["not a domain".into()]),
        LinkOptionsError::Rule {
            list: "allow_domains",
            ..
        }
    ));
    assert!(matches!(
        refuse(|o| o.deny_domains = vec!["127.0.0.1".into()]),
        LinkOptionsError::Rule {
            list: "deny_domains",
            ..
        }
    ));
    assert!(matches!(
        refuse(|o| o.tags = Vec::new()),
        LinkOptionsError::Invalid(_)
    ));
    assert!(matches!(
        refuse(|o| o.attrs = vec!["hr ef".into()]),
        LinkOptionsError::Invalid(_)
    ));
    assert!(matches!(
        refuse(|o| o.allow = vec!["x".into(); 65]),
        LinkOptionsError::Invalid(_)
    ));
    assert!(matches!(
        refuse(|o| o.restrict_css = vec!["div[".into()]),
        LinkOptionsError::Selector(_)
    ));
    assert!(matches!(
        refuse(|o| o.restrict_xpath = vec!["//a[".into()]),
        LinkOptionsError::Selector(_)
    ));
}

#[test]
fn catastrophic_looking_patterns_stay_linear() {
    // `(a+)+$` blows up a backtracking engine on this input; the linear engine answers at once.
    let html = format!("<a href=\"/{}!\">x</a>", "a".repeat(4000));
    let page = Url::parse(PAGE).unwrap();
    let filter = LinkFilter::new(&options(|o| o.deny = vec!["(a+)+$".into()])).unwrap();
    assert_eq!(filter.links(&html, &page).unwrap().len(), 1);
}
