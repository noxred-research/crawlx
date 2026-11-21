//! The default extension filter selects crawl pages, never sitemap documents: a `.xml.gz` index
//! child or `Sitemap:` URL is fetched and decoded, while the pages it lists still meet the filter.
//! Owned loopback fixture only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::CrawlMode;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_worker::{EgressConfig, WorkerConfig};
use std::sync::{Arc, Mutex};

struct Site {
    base: String,
    hits: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Site {
    fn count(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.as_str() == path)
            .count()
    }
}

async fn record(
    State(hits): State<Arc<Mutex<Vec<String>>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.lock().unwrap().push(request.uri().path().to_owned());
    next.run(request).await
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn page(title: &str) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html")],
        format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>{}</p></main></body></html>",
            "A listed page with enough text to be extracted as content. ".repeat(8)
        ),
    )
}

/// `/` has no links, so only a sitemap can reach `/p/*`. `declared_root` puts a gzip sitemap in
/// `robots.txt`; otherwise the default `/sitemap.xml` is an index with a `.xml.gz` and an `.xml` child.
async fn site(declared_root: bool) -> Site {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let urlset = |paths: &[&str]| {
        let entries: String = paths
            .iter()
            .map(|path| format!("<url><loc>{base}{path}</loc></url>"))
            .collect();
        format!("<urlset>{entries}</urlset>").into_bytes()
    };
    // `/files/report.pdf` is a page candidate: the filter still drops it
    let gz_body = gzip(&urlset(&["/p/one", "/p/two", "/files/report.pdf"]));
    let plain_body = urlset(&["/p/three"]);
    let index = format!(
        "<sitemapindex><sitemap><loc>{base}/maps/pages.xml.gz</loc></sitemap>\
         <sitemap><loc>{base}/maps/more.xml</loc></sitemap></sitemapindex>"
    );
    let robots = if declared_root {
        format!("User-agent: *\nSitemap: {base}/maps/pages.xml.gz\nSitemap: {base}/maps/more.xml\n")
    } else {
        "User-agent: *\nDisallow: /nothing/\n".to_owned()
    };
    let app = Router::new()
        .route("/", get(|| async { page("Home") }))
        .route("/robots.txt", get(move || async move { robots }))
        .route(
            "/sitemap.xml",
            get(move || async move { ([(header::CONTENT_TYPE, "application/xml")], index) }),
        )
        .route(
            "/maps/pages.xml.gz",
            get(move || async move { ([(header::CONTENT_TYPE, "application/gzip")], gz_body) }),
        )
        .route(
            "/maps/more.xml",
            get(move || async move { ([(header::CONTENT_TYPE, "application/xml")], plain_body) }),
        )
        .route("/p/{name}", get(|| async { page("Listed") }))
        .route("/files/report.pdf", get(|| async { "must not be fetched" }))
        .with_state(Arc::clone(&hits))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, hits, task }
}

async fn default_filter_crawl(site: &Site) {
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_121);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    assert!(!crawl.scope.no_default_extension_filter && crawl.scope.extension_match.is_empty());
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    common::authorization::run_authorized_local(crawl, config)
        .await
        .unwrap();
}

fn assert_gzip_sitemap_read(site: &Site) {
    assert_eq!(
        site.count("/maps/pages.xml.gz"),
        1,
        "the .xml.gz sitemap is requested"
    );
    assert_eq!(site.count("/maps/more.xml"), 1);
    for listed in ["/p/one", "/p/two", "/p/three"] {
        assert_eq!(site.count(listed), 1, "{listed} is listed by a sitemap");
    }
    assert_eq!(
        site.count("/files/report.pdf"),
        0,
        "a listed page still meets the extension filter"
    );
}

#[tokio::test]
async fn gzip_index_child_is_fetched_under_the_default_extension_filter() {
    let site = site(false).await;
    default_filter_crawl(&site).await;
    assert_eq!(site.count("/sitemap.xml"), 1);
    assert_gzip_sitemap_read(&site);
}

#[tokio::test]
async fn gzip_robots_sitemap_is_fetched_under_the_default_extension_filter() {
    let site = site(true).await;
    default_filter_crawl(&site).await;
    assert_eq!(site.count("/sitemap.xml"), 0, "robots.txt names the roots");
    assert_gzip_sitemap_read(&site);
}
