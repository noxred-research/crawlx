//! Surface discovery parity: the `priority` strategy (`-s priority`), exact-content dedupe
//! switch (`-duf`) and parent paths (`-pc`) of the frontier.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::CrawlStrategy;
use crawlx_core::hash::Digest;
use crawlx_core::priority::{priority_depth, surface_score};
use crawlx_core::url::CanonicalUrl;
use crawlx_url::{
    parent_paths, CanonicalizeOptions, Canonicalizer, DedupeReason, Frontier, LinkSource, PushOutcome,
};
use url::Url;

fn canon(s: &str) -> CanonicalUrl {
    let base = Url::parse("https://a.example/").unwrap();
    Canonicalizer::canonicalize(s, &base, &CanonicalizeOptions::default()).unwrap()
}

fn drain(f: &mut Frontier) -> Vec<String> {
    std::iter::from_fn(|| f.pop())
        .map(|e| {
            let u = &e.url.url;
            format!(
                "{}{}",
                u.path(),
                u.query().map(|q| format!("?{q}")).unwrap_or_default()
            )
        })
        .collect()
}

/// (url, depth, source): a deliberately mixed discovery order.
const MIXED: [(&str, u32, LinkSource); 9] = [
    ("https://a.example/", 0, LinkSource::Seed),
    ("https://a.example/blog/a", 1, LinkSource::Body),
    ("https://a.example/blog/b", 1, LinkSource::Body),
    ("https://a.example/admin?x=1", 2, LinkSource::Body),
    ("https://a.example/news/2024/deep/page", 3, LinkSource::Body),
    ("https://a.example/api/v1/users?id=7", 3, LinkSource::Body),
    ("https://a.example/contact", 1, LinkSource::Navigation),
    ("https://a.example/login", 1, LinkSource::Body),
    ("https://a.example/about", 1, LinkSource::Sitemap),
];

fn build(strategy: CrawlStrategy) -> Frontier {
    let mut f = Frontier::new().with_strategy(strategy);
    for (url, depth, source) in MIXED {
        assert_eq!(
            f.push(canon(url), depth, source, None),
            PushOutcome::Admitted,
            "{url}"
        );
    }
    f
}

// ---- priority ---------------------------------------------------------------------------

#[test]
fn surface_url_one_level_deeper_leases_before_a_plain_url() {
    let mut f = Frontier::new().with_strategy(CrawlStrategy::Priority);
    assert_eq!(f.strategy(), CrawlStrategy::Priority);
    f.push(canon("https://a.example/blog/post"), 1, LinkSource::Body, None);
    f.push(canon("https://a.example/admin?x=1"), 2, LinkSource::Body, None);
    // depth 1 plain = 1 - 0, depth 2 `/admin?x=1` = 2 - 3: the surface URL goes first
    assert_eq!(drain(&mut f), ["/admin?x=1", "/blog/post"]);

    // breadth-first keeps the shallower URL first for the very same input
    let mut b = Frontier::new();
    b.push(canon("https://a.example/blog/post"), 1, LinkSource::Body, None);
    b.push(canon("https://a.example/admin?x=1"), 2, LinkSource::Body, None);
    assert_eq!(drain(&mut b), ["/blog/post", "/admin?x=1"]);
}

#[test]
fn priority_orders_a_mixed_set_by_depth_minus_surface_score() {
    // key = depth + 4 - surface score (word 2, query 1); ties: source rank, discovery order
    //   /admin?x=1 2+4-3=3 and /login 1+4-2=3 (discovery order)
    //   /          0+4-0=4 (seed) before /api/v1/users?id=7 3+4-3=4 (body)
    //   /about 1+4 (sitemap), /contact 1+4 (navigation), /blog/a, /blog/b 1+4 (body): 5
    //   /news/2024/deep/page 3+4-0=7
    let got = drain(&mut build(CrawlStrategy::Priority));
    assert_eq!(
        got,
        [
            "/admin?x=1",
            "/login",
            "/",
            "/api/v1/users?id=7",
            "/about",
            "/contact",
            "/blog/a",
            "/blog/b",
            "/news/2024/deep/page",
        ]
    );
    assert_eq!(
        surface_score(&Url::parse("https://a.example/admin?x=1").unwrap(), true),
        3
    );
    assert_eq!(
        priority_depth(&Url::parse("https://a.example/admin?x=1").unwrap(), 2, true),
        3
    );
}

#[test]
fn priority_order_is_deterministic() {
    let first = drain(&mut build(CrawlStrategy::Priority));
    for _ in 0..5 {
        assert_eq!(drain(&mut build(CrawlStrategy::Priority)), first);
    }
    // and it is a different order than breadth-first, so the strategy is really applied
    assert_ne!(first, drain(&mut build(CrawlStrategy::BreadthFirst)));
}

#[test]
fn priority_pops_per_origin_in_the_same_order() {
    let mut f = Frontier::new().with_strategy(CrawlStrategy::Priority);
    f.push(canon("https://a.example/blog/post"), 1, LinkSource::Body, None);
    f.push(canon("https://a.example/admin?x=1"), 2, LinkSource::Body, None);
    f.push(canon("https://b.example/x"), 0, LinkSource::Body, None);
    let a = f.next_for_origin("https://a.example").unwrap();
    assert_eq!(a.url.url.path(), "/admin");
    let ready = f.pop_where(|o| o == "https://a.example").unwrap();
    assert_eq!(ready.url.url.path(), "/blog/post");
}

// ---- content dedupe (-duf) --------------------------------------------------------------

#[test]
fn identical_bodies_are_dropped_by_default() {
    let mut f = Frontier::new();
    let (a, b) = (canon("https://a.example/a"), canon("https://a.example/b"));
    let body = Digest::of("test/body", b"same");
    f.push(a.clone(), 0, LinkSource::Seed, None);
    f.push(b.clone(), 1, LinkSource::Body, None);
    assert!(f.note_content(&a.key, body));
    assert!(!f.note_content(&b.key, body));
    assert_eq!(f.dedupe_count(DedupeReason::ContentExact), 1);
    assert_eq!(f.counters().admitted, 1);
}

#[test]
fn with_content_dedupe_false_keeps_identical_bodies() {
    let mut f = Frontier::new().with_content_dedupe(false);
    let (a, b, c) = (
        canon("https://a.example/a"),
        canon("https://a.example/b"),
        canon("https://a.example/c"),
    );
    let body = Digest::of("test/body", b"same");
    for (u, d) in [(&a, 0), (&b, 1), (&c, 1)] {
        f.push(u.clone(), d, LinkSource::Body, None);
    }
    assert!(f.note_content(&a.key, body));
    assert!(f.note_content(&b.key, body));
    assert!(f.note_content(&c.key, body));
    // nothing was re-attributed: all three pages stay admitted
    assert_eq!(f.dedupe_count(DedupeReason::ContentExact), 0);
    assert_eq!(f.counters().admitted, 3);
    assert_eq!(f.counters().deduplicated, 0);
    // a body for a key that was never admitted is kept as well
    assert!(f.note_content(&canon("https://a.example/never").key, body));
}

#[test]
fn content_dedupe_can_be_switched_back_on() {
    let mut f = Frontier::new()
        .with_content_dedupe(false)
        .with_content_dedupe(true);
    let (a, b) = (canon("https://a.example/a"), canon("https://a.example/b"));
    let body = Digest::of("test/body", b"same");
    f.push(a.clone(), 0, LinkSource::Seed, None);
    f.push(b.clone(), 1, LinkSource::Body, None);
    assert!(f.note_content(&a.key, body));
    assert!(!f.note_content(&b.key, body));
}

#[test]
fn disabling_content_dedupe_leaves_url_dedupe_alone() {
    let mut f = Frontier::new().with_content_dedupe(false);
    assert_eq!(
        f.push(canon("https://a.example/x"), 0, LinkSource::Seed, None),
        PushOutcome::Admitted
    );
    assert_eq!(
        f.push(canon("https://a.example/x#frag"), 1, LinkSource::Body, None),
        PushOutcome::Duplicate
    );
    assert_eq!(f.dedupe_count(DedupeReason::Canonical), 1);
}

// ---- parent paths (-pc) -----------------------------------------------------------------

#[test]
fn parent_paths_feed_the_frontier_without_duplicates() {
    let mut f = Frontier::new();
    let mut offered = Vec::new();
    for page in [
        "https://a.example/docs/guide/intro.html",
        "https://a.example/docs/guide/usage.html?v=2#top",
    ] {
        let url = Url::parse(page).unwrap();
        for parent in parent_paths(&url) {
            offered.push(parent.to_string());
            f.push(canon(parent.as_str()), 1, LinkSource::Body, None);
        }
    }
    assert_eq!(
        offered,
        [
            "https://a.example/docs/guide/",
            "https://a.example/docs/",
            "https://a.example/",
            "https://a.example/docs/guide/",
            "https://a.example/docs/",
            "https://a.example/",
        ]
    );
    // the second page's parents are the same directories: the frontier admitted each once
    assert_eq!(f.len(), 3);
    assert_eq!(f.counters().deduplicated, 3);
    assert_eq!(drain(&mut f), ["/docs/guide/", "/docs/", "/"]);
}
