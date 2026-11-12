//! `location{country, languages}` on the HTTP plane of the scrape engine: the
//! request carries the `Accept-Language` the location asks for, and a header the caller set
//! explicitly through `headers` wins. The fixture records the actual outgoing header separately
//! from its echoed response, which must redact configured literal header values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::scrape::{JobKind, Location, ScrapeJob, ScrapeOptions};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};
use url::Url;

async fn echo(
    axum::extract::State(received): axum::extract::State<Arc<Mutex<Vec<String>>>>,
    headers: HeaderMap,
) -> axum::response::Html<String> {
    let lang = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none-sent");
    received.lock().unwrap().push(lang.to_owned());
    axum::response::Html(format!(
        "<html><head><title>Echo</title></head><body><main><p>accept-language: {lang}</p></main></body></html>"
    ))
}

async fn site() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/echo", get(echo))
        .with_state(Arc::clone(&received));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://127.0.0.1:{port}/echo"), received)
}

/// Run one scrape of `url` and return the stored markdown.
async fn scrape(url: &str, options: ScrapeOptions, headers: &[(&str, &str)]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(Url::parse(url).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(7);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.max_discovery_depth = 0;
    for (name, value) in headers {
        crawl.fetch.set_header(name, value).unwrap();
    }
    crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone()))
        .await
        .unwrap();
    let page = report.pages.first().expect("one stored page");
    let bytes = stores
        .artifacts
        .get(page.markdown.as_ref().expect("markdown artifact"))
        .await
        .unwrap();
    String::from_utf8(bytes).unwrap()
}

fn with_location(country: Option<&str>, languages: &[&str]) -> ScrapeOptions {
    ScrapeOptions {
        location: Some(Location {
            country: country.map(str::to_owned),
            languages: languages.iter().map(|l| (*l).to_owned()).collect(),
            geolocation: None,
        }),
        ..ScrapeOptions::default()
    }
}

#[tokio::test]
async fn location_languages_become_a_weighted_accept_language_header() {
    let (url, received) = site().await;
    let md = scrape(&url, with_location(Some("JP"), &["en-US", "fr", "de"]), &[]).await;
    assert_eq!(*received.lock().unwrap(), ["en-US,fr;q=0.9,de;q=0.8"]);
    assert!(md.contains("accept-language: en-US,fr;q=0.9,de;q=0.8"), "{md}");
}

#[tokio::test]
async fn a_country_alone_sends_its_main_language() {
    let (url, received) = site().await;
    let md = scrape(&url, with_location(Some("DE"), &[]), &[]).await;
    assert_eq!(*received.lock().unwrap(), ["de-DE"]);
    assert!(md.contains("accept-language: de-DE"), "{md}");
}

#[tokio::test]
async fn without_location_no_accept_language_is_sent() {
    let (url, received) = site().await;
    let md = scrape(&url, ScrapeOptions::default(), &[]).await;
    assert_eq!(*received.lock().unwrap(), ["none-sent"]);
    assert!(md.contains("accept-language: none-sent"), "{md}");
}

#[tokio::test]
async fn an_explicit_accept_language_header_wins_over_location() {
    let (url, received) = site().await;
    let md = scrape(
        &url,
        with_location(Some("DE"), &[]),
        &[("Accept-Language", "sv-SE")],
    )
    .await;
    assert_eq!(*received.lock().unwrap(), ["sv-SE"]);
    assert!(md.contains("accept-language: [REDACTED]"), "{md}");
    assert!(!md.contains("sv-SE"), "{md}");
    assert!(!md.contains("de-DE"), "{md}");
}
