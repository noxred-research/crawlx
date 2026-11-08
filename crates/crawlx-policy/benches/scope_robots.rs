//! Criterion benches for the policy plane: `robots_match_longest`,
//! `egress_deny_lookup` and `scope_decide_regex`.
//!
//! `crawlx-url/benches/canonicalize.rs` (`url_filter/scope_decide`) already measures the
//! path-pattern `ScopeFilter`; `scope_decide_regex` here measures the layered
//! `ScopePolicy::decide_url` path on top of it (exclude-hosts regex, `rdn` host scope,
//! full-URL include/exclude regexes, path rules, extension filter, depth).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::config::{CreateCrawl, HostScope};
use crawlx_policy::robots::{Match, RobotsTxt};
use crawlx_policy::{EgressPolicy, ScopePolicy, ScopeVerdict};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::fmt::Write as _;
use std::hint::black_box;
use url::Url;

const RULES: usize = 200;
const PATHS: usize = 1_000;
const HOSTS: usize = 1_000;
const URLS: usize = 1_000;

/// A `robots.txt` with one `*` group of `n` rules: mixed `Allow`/`Disallow`, nested
/// prefixes so several patterns match one path and the longest has to win, `*` and `$`
/// wildcards, and a `crawlx`-specific group that the `*` lookup must skip.
fn robots_body(n: usize) -> String {
    let mut s = String::from("User-agent: other-bot\nDisallow: /\n\nUser-agent: *\n");
    for i in 0..n {
        let section = i % 20;
        let line = match i % 5 {
            0 => format!("Disallow: /section-{section}/\n"),
            1 => format!("Allow: /section-{section}/public/\n"),
            2 => format!("Disallow: /section-{section}/public/private-{}/\n", i % 7),
            3 => format!("Disallow: /section-{section}/*/download$\n"),
            _ => format!("Allow: /section-{section}/*.html$\n"),
        };
        s.push_str(&line);
    }
    s.push_str("Sitemap: https://example.com/sitemap.xml\n");
    s
}

fn paths(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let section = i % 23;
            match i % 4 {
                0 => format!("/section-{section}/public/private-{}/page-{i}", i % 7),
                1 => format!("/section-{section}/public/item-{i}.html"),
                2 => format!("/section-{section}/asset-{i}/download"),
                _ => format!("/section-{section}/page-{i}?ref=bench&id={i}"),
            }
        })
        .collect()
}

fn robots_match_longest(c: &mut Criterion) {
    let body = robots_body(RULES);
    let robots = RobotsTxt::parse(body.as_bytes());
    assert_eq!(robots.rules().count(), RULES + 1, "every generated rule parsed");
    let paths = paths(PATHS);
    let mut g = c.benchmark_group("robots_match_longest");
    g.throughput(Throughput::Elements(paths.len() as u64));
    g.bench_with_input(
        BenchmarkId::new("rules_200/paths", paths.len()),
        &paths,
        |b, paths| {
            b.iter(|| {
                let mut disallowed = 0u32;
                for p in paths {
                    if matches!(
                        robots.evaluate("crawlx/1.0 (+https://example.com/bot)", black_box(p)),
                        Match::Disallowed(_)
                    ) {
                        disallowed += 1;
                    }
                }
                disallowed
            });
        },
    );
    g.finish();
}

/// Hosts and literals in the mix the fetch plane sees: public names, internal
/// suffixes, metadata hosts, private/loopback/link-local/CGNAT v4, public v4,
/// IPv4-mapped and NAT64 v6, unique-local v6, legacy decimal/hex v4 forms.
fn hosts(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| match i % 12 {
            0 => format!("www{}.example.com", i % 50),
            1 => format!("api-{}.internal", i % 9),
            2 => "metadata.google.internal".to_owned(),
            3 => format!("10.{}.{}.{}", i % 256, (i / 3) % 256, (i / 7) % 256),
            4 => format!("192.168.{}.{}", i % 256, (i / 5) % 256),
            5 => format!("203.0.113.{}", i % 256),
            6 => format!("8.8.{}.{}", i % 256, (i / 11) % 256),
            7 => format!("::ffff:169.254.169.{}", i % 256),
            8 => format!("64:ff9b::10.0.{}.{}", i % 256, (i / 13) % 256),
            9 => format!("fd12:3456::{:x}", i % 65_536),
            10 => format!("{}", 2_130_706_433 + (i % 200)), // 127.0.0.1 as a decimal literal
            _ => format!("0x{:x}", 0x0A00_0000 + (i % 1000)),
        })
        .collect()
}

fn egress_deny_lookup(c: &mut Criterion) {
    let strict = EgressPolicy::new(false);
    let hosts = hosts(HOSTS);
    let mut g = c.benchmark_group("egress_deny_lookup");
    g.throughput(Throughput::Elements(hosts.len() as u64));
    g.bench_with_input(BenchmarkId::new("check_host", hosts.len()), &hosts, |b, hosts| {
        b.iter(|| {
            let mut denied = 0u32;
            for h in hosts {
                if strict.check_host(black_box(h)).is_err() {
                    denied += 1;
                }
            }
            denied
        });
    });
    g.finish();
}

fn scope_urls(n: usize) -> Vec<Url> {
    (0..n)
        .map(|i| {
            let mut s = String::new();
            match i % 6 {
                0 => write!(s, "https://shop.example.co.uk/products/{}/item-{i}", i % 40).unwrap(),
                1 => write!(s, "https://shop.example.co.uk/docs/guide-{}/page-{i}/", i % 7).unwrap(),
                2 => write!(s, "https://cdn{}.example.co.uk/assets/img-{i}.png", i % 4).unwrap(),
                3 => write!(s, "https://shop.example.co.uk/admin/users/{i}?tab=roles").unwrap(),
                4 => write!(s, "https://other-{}.example.net/products/{i}", i % 5).unwrap(),
                _ => write!(
                    s,
                    "https://shop.example.co.uk/products/{i}?sort=price&page={}",
                    i % 13
                )
                .unwrap(),
            }
            Url::parse(&s).unwrap()
        })
        .collect()
}

fn scope_decide_regex(c: &mut Criterion) {
    let mut crawl = CreateCrawl::new(Url::parse("https://shop.example.co.uk/").unwrap());
    let s = &mut crawl.scope;
    s.host_scope = HostScope::Rdn;
    s.include_paths = vec!["/products/.*".to_owned(), "/docs/.*".to_owned()];
    s.exclude_paths = vec!["/admin/.*".to_owned()];
    s.url_include = vec![
        "^https://[a-z0-9.-]+\\.example\\.co\\.uk/".to_owned(),
        "^https://shop\\.example\\.co\\.uk/docs/".to_owned(),
    ];
    s.url_exclude = vec![".*[?&]tab=roles.*".to_owned(), ".*/assets/.*\\.png$".to_owned()];
    s.exclude_hosts = vec!["private-ips".to_owned(), "^cdn3\\.".to_owned()];
    s.max_discovery_depth = 8;
    let policy = ScopePolicy::new(&crawl).unwrap();
    let urls = scope_urls(URLS);
    let mut g = c.benchmark_group("scope_decide_regex");
    g.throughput(Throughput::Elements(urls.len() as u64));
    g.bench_with_input(
        BenchmarkId::new("policy_decide_url", urls.len()),
        &urls,
        |b, urls| {
            b.iter(|| {
                let mut admitted = 0u32;
                for (i, u) in urls.iter().enumerate() {
                    let depth = u16::try_from(i % 10).unwrap();
                    if matches!(
                        policy.decide_url(black_box(u), depth),
                        ScopeVerdict::Admitted { leaf_only: false }
                    ) {
                        admitted += 1;
                    }
                }
                admitted
            });
        },
    );
    g.finish();
}

criterion_group!(
    benches,
    robots_match_longest,
    egress_deny_lookup,
    scope_decide_regex
);
criterion_main!(benches);
