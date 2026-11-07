//! Criterion benches for sitemaps and the frontier: `sitemap_parse_10mb`
//! (a generated 10 MiB `<urlset>` through `SitemapParser::parse`, which stops collecting
//! at the crate's `MAX_URLS` cap but still streams the whole document) and
//! `frontier_push_pop` (100k canonical URLs pushed into the in-memory `Frontier` and
//! popped in breadth-first order).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_core::url::CanonicalUrl;
use crawlx_url::sitemap::{SitemapKind, SitemapParser, MAX_URLS};
use crawlx_url::{CanonicalizeOptions, Canonicalizer, Frontier, LinkSource};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use std::fmt::Write as _;
use url::Url;

const SITEMAP_BYTES: usize = 10 * 1024 * 1024;
const FRONTIER_URLS: usize = 100_000;

/// A `<urlset>` grown to at least `target` bytes with `lastmod`, `changefreq` and
/// `priority` on every entry (the shape a CMS emits).
fn urlset(target: usize) -> Vec<u8> {
    let mut s = String::with_capacity(target + 512);
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    let mut i = 0usize;
    while s.len() < target {
        write!(
            s,
            "  <url>\n    <loc>https://www.example.com/catalog/{}/product-{i}?variant={}</loc>\n    \
             <lastmod>2026-{:02}-{:02}T{:02}:00:00+00:00</lastmod>\n    <changefreq>{}</changefreq>\n    \
             <priority>0.{}</priority>\n  </url>\n",
            i % 97,
            i % 5,
            1 + i % 12,
            1 + i % 28,
            i % 24,
            ["daily", "weekly", "monthly"][i % 3],
            1 + i % 9
        )
        .unwrap();
        i += 1;
    }
    s.push_str("</urlset>\n");
    s.into_bytes()
}

fn sitemap_parse_10mb(c: &mut Criterion) {
    let body = urlset(SITEMAP_BYTES);
    let doc = SitemapParser::parse(&body).unwrap();
    assert_eq!(doc.kind, SitemapKind::UrlSet);
    assert!(doc.urls.len() <= MAX_URLS);
    assert!(doc.truncated, "a 10 MiB urlset exceeds the entry cap");
    let mut g = c.benchmark_group("sitemap_parse_10mb");
    g.throughput(Throughput::Bytes(body.len() as u64));
    g.sample_size(20);
    g.bench_with_input(BenchmarkId::new("urlset", body.len()), &body, |b, body| {
        b.iter(|| SitemapParser::parse(black_box(body)).unwrap().urls.len());
    });
    g.finish();
}

fn canonical_urls(n: usize) -> Vec<CanonicalUrl> {
    let base = Url::parse("https://www.example.com/").unwrap();
    let opts = CanonicalizeOptions::default();
    (0..n)
        .map(|i| {
            let raw = match i % 3 {
                0 => format!("https://www.example.com/catalog/{}/product-{i}", i % 97),
                1 => format!("https://blog.example.com/{}/post-{i}.html?id={i}", i % 23),
                _ => format!("https://www.example.com/docs/{}/page-{i}/", i % 7),
            };
            Canonicalizer::canonicalize(&raw, &base, &opts).unwrap()
        })
        .collect()
}

fn frontier_push_pop(c: &mut Criterion) {
    let urls = canonical_urls(FRONTIER_URLS);
    let mut g = c.benchmark_group("frontier_push_pop");
    g.throughput(Throughput::Elements(urls.len() as u64));
    g.sample_size(20);
    g.bench_with_input(BenchmarkId::new("breadth_first", urls.len()), &urls, |b, urls| {
        b.iter_batched(
            || urls.clone(),
            |urls| {
                let mut f = Frontier::new();
                for (i, u) in urls.into_iter().enumerate() {
                    let depth = u32::try_from(i % 6).unwrap();
                    let source = if i % 5 == 0 {
                        LinkSource::Sitemap
                    } else {
                        LinkSource::Body
                    };
                    f.push(black_box(u), depth, source, None);
                }
                let mut popped = 0usize;
                while f.pop().is_some() {
                    popped += 1;
                }
                popped
            },
            BatchSize::LargeInput,
        );
    });
    g.finish();
}

criterion_group!(benches, sitemap_parse_10mb, frontier_push_pop);
criterion_main!(benches);
