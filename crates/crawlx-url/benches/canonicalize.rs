//! Criterion benches for the URL plane.
//!
//! Gate: `url_canonicalize` ≥ 100k short URLs/s/core. The throughput is
//! reported in elements/s by Criterion; `ci/bench-gate.sh` compares the median against the
//! committed baseline with a 10% regression threshold.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::config::Scope;
use crawlx_core::url::RouteTemplate;
use crawlx_url::{CanonicalizeOptions, Canonicalizer, ParamClassifier, ParamObservation, ScopeFilter};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::BTreeMap;
use std::hint::black_box;
use url::Url;

fn short_urls(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| match i % 4 {
            0 => format!(
                "https://Example.com:443/shop/item/{i}?utm_source=x&id={i}&page={}#f",
                i % 13
            ),
            1 => format!("/docs/guide-{}/../page-{i}/", i % 7),
            2 => format!("https://example.com/a/b/c/{i}?sort=price&ref=abc{i}&sessionid=deadbeef{i}"),
            _ => format!("https://sub.example.com/blog/{}/post-{i}.html?id={i}", i % 23),
        })
        .collect()
}

fn canonicalize(c: &mut Criterion) {
    let base = Url::parse("https://example.com/shop/").unwrap();
    let urls = short_urls(1_000);
    for (name, opts) in [
        ("classify", CanonicalizeOptions::default()),
        (
            "keep_all",
            CanonicalizeOptions {
                query_policy: crawlx_core::config::QueryPolicy::KeepAll,
                ..CanonicalizeOptions::default()
            },
        ),
    ] {
        let mut g = c.benchmark_group("url_canonicalize");
        g.throughput(Throughput::Elements(urls.len() as u64));
        g.bench_with_input(BenchmarkId::from_parameter(name), &urls, |b, urls| {
            b.iter(|| {
                let mut acc = 0u8;
                for u in urls {
                    let canon = Canonicalizer::canonicalize(black_box(u), &base, &opts).unwrap();
                    acc ^= canon.key.0[0];
                }
                acc
            });
        });
        g.finish();
    }
}

fn filter(c: &mut Criterion) {
    let seed = Url::parse("https://example.com/docs/").unwrap();
    let scope = Scope {
        include_paths: vec!["/docs/.*".to_owned(), "/blog/[0-9]+/.*".to_owned()],
        exclude_paths: vec!["/docs/private/.*".to_owned(), ".*\\.pdf$".to_owned()],
        ..Scope::default()
    };
    let filter = ScopeFilter::new(&seed, &scope).unwrap();
    let urls: Vec<Url> = short_urls(1_000).iter().map(|u| seed.join(u).unwrap()).collect();
    let mut g = c.benchmark_group("url_filter");
    g.throughput(Throughput::Elements(urls.len() as u64));
    g.bench_function("scope_decide", |b| {
        b.iter(|| {
            let mut in_scope = 0u32;
            for u in &urls {
                if matches!(filter.decide(black_box(u)), crawlx_url::ScopeDecision::InScope) {
                    in_scope += 1;
                }
            }
            in_scope
        });
    });
    g.finish();
}

fn classify(c: &mut Criterion) {
    let classifier = ParamClassifier::new(&BTreeMap::new());
    let route = RouteTemplate("/invoice".to_owned());
    let params: Vec<(String, String)> = (0..1_000)
        .map(|i| match i % 5 {
            0 => ("id".to_owned(), i.to_string()),
            1 => ("utm_source".to_owned(), "email".to_owned()),
            2 => ("page".to_owned(), (i % 40).to_string()),
            3 => ("sort".to_owned(), "price".to_owned()),
            _ => (format!("custom{}", i % 17), format!("v{i}")),
        })
        .collect();
    let mut g = c.benchmark_group("query_classify");
    g.throughput(Throughput::Elements(params.len() as u64));
    g.bench_function("builtin_table", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for (name, value) in &params {
                let class = classifier.classify(&ParamObservation {
                    route: &route,
                    name: black_box(name),
                    value,
                });
                acc += class as usize;
            }
            acc
        });
    });
    g.finish();
}

criterion_group!(benches, canonicalize, filter, classify);
criterion_main!(benches);
