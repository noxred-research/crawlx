//! `X-Robots-Tag` on the static plane: the header's directives are recorded in the page metadata
//! (`x_robots_tag`) and merged with the robots meta element (`robots_effective`). Record only:
//! no page is skipped because of them. Owned loopback fixture only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::{header, HeaderName, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::Arc;

struct Site {
    base: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn page(head: &str, body: &str, x_robots_tag: &[&[u8]]) -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "text/html")],
        format!(
            "<html><head><title>Page</title>{head}</head><body><main><h1>Page</h1><p>{}</p>{body}</main></body></html>",
            "A page with enough text to be extracted as content. ".repeat(8)
        ),
    )
        .into_response();
    for value in x_robots_tag {
        response.headers_mut().append(
            HeaderName::from_static("x-robots-tag"),
            HeaderValue::from_bytes(value).unwrap(),
        );
    }
    response
}

/// `/` links the leaves; every leaf answers with its own `X-Robots-Tag` lines. `/a/child` is
/// linked only from the `noindex, nofollow` page `/a`: it must still be crawled.
async fn site() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                page(
                    "",
                    r#"<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a> <a href="/d">d</a>
                       <a href="/e">e</a> <a href="/f">f</a>"#,
                    &[],
                )
            }),
        )
        .route(
            "/a",
            get(|| async { page("", r#"<a href="/a/child">child</a>"#, &[b"NoIndex, NoFollow"]) }),
        )
        .route("/a/child", get(|| async { page("", "", &[]) }))
        .route(
            "/b",
            get(|| async { page("", "", &[b"googlebot: noindex", b"crawlx: noarchive, nosnippet"]) }),
        )
        .route("/c", get(|| async { page("", "", &[]) }))
        .route(
            "/d",
            get(|| async {
                page(
                    r#"<meta name="robots" content="noimageindex">"#,
                    "",
                    &[b"none, unavailable_after: 25 Jun 2030 15:00:00 PST"],
                )
            }),
        )
        .route(
            "/e",
            get(|| async { page("", "", &[b"noindex, \xff\xfe, nofollow", b"\xff"]) }),
        )
        .route("/f", get(|| async { page("", "", &[b"other: noindex"]) }));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, task }
}

async fn crawl(site: &Site, tweak: impl FnOnce(&mut CreateCrawl)) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_122);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    tweak(&mut crawl);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    run_local_with(LocalRun::new(crawl, config).with_stores(stores))
        .await
        .unwrap()
}

fn metadata<'a>(report: &'a RunReport, path: &str) -> &'a serde_json::Value {
    &report
        .pages
        .iter()
        .find(|page| page.url.url.path() == path)
        .unwrap_or_else(|| panic!("no page for {path}"))
        .metadata
}

fn flags(value: &serde_json::Value) -> [bool; 5] {
    ["noindex", "nofollow", "noarchive", "nosnippet", "noimageindex"].map(|key| {
        value[key]
            .as_bool()
            .unwrap_or_else(|| panic!("{key} missing in {value}"))
    })
}

#[tokio::test]
async fn the_header_is_recorded_merged_with_meta_robots_and_changes_nothing_crawled() {
    let site = site().await;
    let report = crawl(&site, |_| {}).await;

    // no header: nothing recorded
    let c = metadata(&report, "/c");
    assert!(
        c.get("x_robots_tag").is_none() && c.get("robots_effective").is_none(),
        "{c}"
    );

    // `noindex, nofollow`, case-insensitive; the page's own links are still crawled
    let a = metadata(&report, "/a");
    assert_eq!(flags(&a["x_robots_tag"]), [true, true, false, false, false]);
    assert_eq!(flags(&a["robots_effective"]), [true, true, false, false, false]);
    metadata(&report, "/a/child");

    // two lines: the `googlebot` one is not ours, the `crawlx` one is
    let b = metadata(&report, "/b");
    assert_eq!(flags(&b["x_robots_tag"]), [false, false, true, true, false]);

    // `none` and an ignored `unavailable_after`; the meta element's `noimageindex` merges in
    let d = metadata(&report, "/d");
    assert_eq!(flags(&d["x_robots_tag"]), [true, true, false, false, false]);
    assert_eq!(flags(&d["robots"]), [false, false, false, false, true]);
    assert_eq!(flags(&d["robots_effective"]), [true, true, false, false, true]);

    // bytes that are not UTF-8 do not hide the directives around them
    let e = metadata(&report, "/e");
    assert_eq!(flags(&e["x_robots_tag"]), [true, true, false, false, false]);

    // a scope for another crawler is ignored
    let f = metadata(&report, "/f");
    assert_eq!(flags(&f["x_robots_tag"]), [false; 5]);
}

#[tokio::test]
async fn a_scoped_value_follows_the_configured_robots_user_agent() {
    let site = site().await;
    let report = crawl(&site, |crawl| {
        crawl.fetch.robots_user_agent = Some("Other/2.0".to_owned());
    })
    .await;
    // `other: noindex` now applies; `crawlx: noarchive, nosnippet` does not
    assert_eq!(
        flags(&metadata(&report, "/f")["x_robots_tag"]),
        [true, false, false, false, false]
    );
    assert_eq!(flags(&metadata(&report, "/b")["x_robots_tag"]), [false; 5]);
}
