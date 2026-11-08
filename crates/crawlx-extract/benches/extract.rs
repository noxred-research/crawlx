//! Criterion benches for the extraction plane: `html_to_markdown_100kb`,
//! `link_extract` and `metadata_extract` over one generated ~100 KiB article page, plus
//! `endpoints_discover_1mib` over a generated 1 MiB page with inline
//! scripts, links and forms. Throughput is reported in bytes of input.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use crawlx_extract::dom::{convert_node, Node, Selected};
use crawlx_extract::endpoints::{discover, DiscoveryInput};
use crawlx_extract::{links, markdown, metadata};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scraper::Html;
use std::fmt::Write as _;
use std::hint::black_box;
use url::Url;

const PAGE_URL: &str = "https://docs.example.com/guide/intro";
const ARTICLE_BYTES: usize = 100 * 1024;
const ENDPOINT_BYTES: usize = 1024 * 1024;

fn head(title: &str) -> String {
    format!(
        concat!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<title>{t}</title>",
            "<meta name=\"description\" content=\"Generated article about {t}\">",
            "<meta property=\"og:title\" content=\"{t}\"><meta property=\"og:type\" content=\"article\">",
            "<meta name=\"twitter:card\" content=\"summary\"><meta name=\"author\" content=\"crawlx\">",
            "<link rel=\"canonical\" href=\"https://docs.example.com/guide/intro\">",
            "<link rel=\"alternate\" hreflang=\"de\" href=\"/de/guide/intro\">",
            "<link rel=\"stylesheet\" href=\"/static/site.css\">",
            "<script type=\"application/ld+json\">{{\"@type\":\"Article\",\"headline\":\"{t}\"}}</script>",
            "</head><body>"
        ),
        t = title
    )
}

/// An article of headings, paragraphs with inline links, lists, a table and images,
/// grown until it is at least `target` bytes.
fn article(target: usize) -> String {
    let mut s = head("Intro guide");
    s.push_str("<nav><a href=\"/\">Home</a> <a href=\"/guide/\">Guide</a> <a href=\"/blog/\">Blog</a></nav>");
    s.push_str("<main><article><h1>Intro guide</h1>");
    let mut i = 0usize;
    while s.len() < target {
        write!(s, "<h2 id=\"s{i}\">Section {i}</h2>").unwrap();
        for p in 0..3 {
            write!(
                s,
                "<p>Paragraph {p} of section {i} explains <strong>feature {i}</strong> and links to \
                 <a href=\"/guide/section-{i}/part-{p}\">part {p}</a>, <a href=\"https://api.example.com/v1/items/{i}\">the API</a> \
                 and <a href=\"mailto:team@example.com\">the team</a>. It is <em>long enough</em> to carry a few \
                 sentences of ordinary prose so that the Markdown renderer wraps real text, not just markup.</p>"
            )
            .unwrap();
        }
        write!(s, "<ul><li>Point one for {i}</li><li>Point two with <code>code_{i}</code></li><li><a href=\"/ref/{i}\">Reference {i}</a></li></ul>").unwrap();
        if i.is_multiple_of(4) {
            write!(
                s,
                "<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>\
                 <tr><td>alpha {i}</td><td>{}</td></tr><tr><td>beta {i}</td><td>{}</td></tr></tbody></table>",
                i * 3,
                i * 7
            )
            .unwrap();
        }
        if i.is_multiple_of(3) {
            write!(s, "<figure><img src=\"/img/{i}.png\" alt=\"Figure {i}\"><figcaption>Figure {i}</figcaption></figure>").unwrap();
        }
        write!(
            s,
            "<blockquote>Quote {i}: determinism beats cleverness.</blockquote>"
        )
        .unwrap();
        i += 1;
    }
    s.push_str("</article></main><footer><a href=\"/privacy\">Privacy</a> <a href=\"/terms\">Terms</a></footer></body></html>");
    s
}

/// A page mixing endpoint sources: inline scripts with fetch/XHR URLs, forms with
/// inputs, htmx attributes, link/iframe/img/srcset constructs and plain-text URLs.
fn endpoint_page(target: usize) -> String {
    let mut s = head("Endpoints");
    s.push_str("<base href=\"https://app.example.com/ui/\">");
    let mut i = 0usize;
    while s.len() < target {
        write!(
            s,
            "<script>const base{i} = '/api/v{}/items/{i}'; fetch('/api/items?page={i}').then(r => r.json()); \
             const xhr{i} = new XMLHttpRequest(); xhr{i}.open('POST', \"/api/items/{i}/actions\"); \
             axios.get(`/api/users/{i}/profile`); window.location = '../reports/{i}.pdf'; \
             var u{i} = 'https://cdn.example.com/bundle-{i}.js';</script>",
            i % 3 + 1
        )
        .unwrap();
        write!(
            s,
            "<form id=\"f{i}\" action=\"/submit/{i}\" method=\"{}\"><input type=\"text\" name=\"q{i}\" value=\"x\">\
             <input type=\"email\" name=\"email\"><select name=\"kind\"><option value=\"a\">a</option><option value=\"b\">b</option></select>\
             <textarea name=\"notes\"></textarea><button type=\"submit\">Go</button></form>",
            if i.is_multiple_of(2) { "post" } else { "get" }
        )
        .unwrap();
        write!(
            s,
            "<a href=\"/items/{i}\">item {i}</a> <a href=\"detail?id={i}\">detail</a> \
             <button hx-get=\"/fragments/{i}\" hx-target=\"#t{i}\">load</button> <div hx-post=\"/htmx/{i}\"></div>\
             <iframe src=\"/embed/{i}\"></iframe> <img src=\"/img/{i}.png\" srcset=\"/img/{i}@2x.png 2x, /img/{i}@3x.png 3x\">\
             <link rel=\"preload\" href=\"/static/chunk-{i}.css\"><object data=\"/objects/{i}.swf\"></object>\
             <p>See https://partner.example.org/docs/{i} and /plain/path/{i}.</p>"
        )
        .unwrap();
        i += 1;
    }
    s.push_str("</body></html>");
    s
}

fn markdown_of(html: &str, base: &Url) -> String {
    let doc = Html::parse_document(html);
    let sel = Selected::default();
    let content: Vec<Node> = match convert_node(*doc.root_element(), &sel) {
        Some(Node::Elem(e)) => e.children,
        _ => Vec::new(),
    };
    markdown::to_markdown(&content, base, false)
}

fn article_benches(c: &mut Criterion) {
    let base = Url::parse(PAGE_URL).unwrap();
    let html = article(ARTICLE_BYTES);
    let doc = Html::parse_document(&html);
    let effective = metadata::effective_base(&doc, &base);
    assert!(!markdown_of(&html, &base).is_empty());
    assert!(links::extract_links(&doc, &base, &effective).len() > 100);

    let mut g = c.benchmark_group("html_to_markdown_100kb");
    g.throughput(Throughput::Bytes(html.len() as u64));
    g.bench_with_input(
        BenchmarkId::new("parse_convert_render", html.len()),
        &html,
        |b, html| {
            b.iter(|| markdown_of(black_box(html), &base).len());
        },
    );
    g.finish();

    let mut g = c.benchmark_group("link_extract");
    g.throughput(Throughput::Bytes(html.len() as u64));
    g.bench_function(BenchmarkId::new("parsed_doc", html.len()), |b| {
        b.iter(|| links::extract_links(black_box(&doc), &base, &effective).len());
    });
    g.finish();

    let mut g = c.benchmark_group("metadata_extract");
    g.throughput(Throughput::Bytes(html.len() as u64));
    g.bench_function(BenchmarkId::new("parsed_doc", html.len()), |b| {
        b.iter(|| metadata::extract(black_box(&doc), &effective).title.is_some());
    });
    g.finish();
}

fn endpoints_discover_1mib(c: &mut Criterion) {
    let url = Url::parse("https://app.example.com/ui/index.html").unwrap();
    let html = endpoint_page(ENDPOINT_BYTES);
    let headers = vec![
        ("content-type".to_owned(), "text/html; charset=utf-8".to_owned()),
        ("link".to_owned(), "</api/next>; rel=\"next\"".to_owned()),
    ];
    let input = DiscoveryInput {
        url: &url,
        status: 200,
        headers: &headers,
        content_type: Some("text/html; charset=utf-8"),
        body: html.as_bytes(),
        depth: 1,
    };
    assert!(
        discover(&input)
            .expect("benchmark endpoint discovery must succeed")
            .len()
            > 1_000,
        "the generated page yields many endpoints"
    );
    let mut g = c.benchmark_group("endpoints_discover_1mib");
    g.throughput(Throughput::Bytes(html.len() as u64));
    g.sample_size(20);
    g.bench_function(BenchmarkId::new("discover", html.len()), |b| {
        b.iter(|| {
            discover(black_box(&input))
                .expect("benchmark endpoint discovery must succeed")
                .len()
        });
    });
    g.finish();
}

criterion_group!(benches, article_benches, endpoints_discover_1mib);
criterion_main!(benches);
