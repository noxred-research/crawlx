//! Katana `-traffic-export` on the static plane: every page fetch and redirect hop reaches the
//! collector, robots.txt does not, and the exporter is flushed when the run ends, whether it
//! completes or is cancelled.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod katana_p4_common;

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_worker::katana::traffic_export::TrafficExportConfig;
use katana_p4_common::{crawl_with, page, Collector, Site};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

fn export_to(collector: &Collector) -> impl FnOnce(&mut crawlx_worker::WorkerConfig) {
    let mut cfg = TrafficExportConfig::new(collector.url.clone());
    cfg.flush_interval = Duration::from_secs(3600); // only the end-of-run flush delivers
    cfg.retry_delays = Vec::new();
    move |worker| worker.traffic_export = Some(cfg)
}

#[tokio::test]
async fn pages_and_redirect_hops_are_exported_and_robots_is_not() {
    let site = Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async { page("Home", r#"<a href="/old">old</a><a href="/gone">gone</a>"#) }),
            )
            .route(
                "/old",
                get(|| async {
                    ([(header::LOCATION, "/new")], StatusCode::MOVED_PERMANENTLY).into_response()
                }),
            )
            .route("/new", get(|| async { page("New", "") }))
            .route("/gone", get(|| async { StatusCode::NOT_FOUND }))
            .route(
                "/robots.txt",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/plain")],
                        "User-agent: *\nAllow: /\n",
                    )
                }),
            )
    })
    .await;
    let collector = Collector::start().await;
    crawl_with(&site.base, |_| {}, export_to(&collector), |run| run).await;

    assert!(
        site.requests().iter().any(|(_, p)| p == "/robots.txt"),
        "robots.txt was fetched"
    );
    let mut got = collector.exchanges();
    got.sort();
    // `/old` answers 301 -> `/new` (the hop and the page it led to are two exchanges), and
    // the plane then fetches the redirect target as a page of its own (a third request)
    assert_eq!(
        got,
        [
            (200, "/".to_owned()),
            (200, "/new".to_owned()),
            (200, "/new".to_owned()),
            (301, "/old".to_owned()),
            (404, "/gone".to_owned()),
        ],
        "robots.txt is not an exchange"
    );
    assert_eq!(site.gets().iter().filter(|p| *p == "/new").count(), 2);
    let events = collector.events();
    assert!(events.iter().all(|e| e["plane"] == "url"));
    let home = events
        .iter()
        .find(|e| e["request"]["full_url"].as_str().unwrap().ends_with('/'))
        .unwrap();
    assert!(home["request"]["headers"]["user-agent"]
        .as_str()
        .unwrap()
        .starts_with("crawlx/"));
    assert!(home["response"]["body_preview"]
        .as_str()
        .unwrap()
        .contains("<h1>Home</h1>"));
    assert_eq!(home["response"]["content_type"], "text/html; charset=utf-8");
}

#[tokio::test]
async fn nothing_is_exported_without_a_configured_collector() {
    let site = Site::start(|_| Router::new().route("/", get(|| async { page("Home", "") }))).await;
    let collector = Collector::start().await;
    crawl_with(&site.base, |_| {}, |_| {}, |run| run).await;
    assert!(collector.events().is_empty());
}

#[tokio::test]
async fn a_cancelled_run_still_flushes_what_it_recorded() {
    let next_page_started = Arc::new(Notify::new());
    let signal = Arc::clone(&next_page_started);
    let site = Site::start(move |_| {
        let signal = Arc::clone(&signal);
        Router::new()
            .route(
                "/",
                get(|| async { page("Home", r#"<a href="/a">a</a><a href="/b">b</a>"#) }),
            )
            .route(
                "/a",
                get(move || {
                    let signal = Arc::clone(&signal);
                    async move {
                        // Home is committed and its exchange is queued before this request.
                        signal.notify_one();
                        std::future::pending::<axum::response::Response>().await
                    }
                }),
            )
            .route("/b", get(|| async { page("B", "") }))
    })
    .await;
    let collector = Collector::start().await;
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    tokio::spawn(async move {
        next_page_started.notified().await;
        stop.cancel();
    });
    let run = crawl_with(
        &site.base,
        |_| {},
        export_to(&collector),
        |run| run.with_cancel(cancel),
    )
    .await;
    assert_eq!(run.report.status, crawlx_core::counters::RunStatus::Cancelled);
    assert_eq!(
        run.report.terminal_reason,
        Some(crawlx_core::counters::TerminalReason::Cancelled)
    );
    assert!(
        run.report.resume.is_some(),
        "the run was cancelled with URLs left"
    );
    let exported = collector.exchanges();
    assert!(
        exported.contains(&(200, "/".to_owned())),
        "the page fetched before the cancel was flushed: {exported:?}"
    );
    assert_eq!(
        exported.len(),
        site.gets().len(),
        "exactly the fetched pages are exported"
    );
}

#[tokio::test]
async fn configured_header_values_are_redacted_in_metadata_raw_text_and_exchanges() {
    const SECRET: &str = "tok-very-secret-123";
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    let site = Site::start(move |_| {
        let sink = Arc::clone(&sink);
        Router::new().route(
            "/",
            get(move |headers: axum::http::HeaderMap| {
                let sink = Arc::clone(&sink);
                async move {
                    if let Some(v) = headers.get("x-qa-token") {
                        sink.lock().unwrap().push(v.to_str().unwrap().to_owned());
                    }
                    (
                        [
                            (header::CONTENT_TYPE, "text/html"),
                            (header::HeaderName::from_static("x-echo"), SECRET),
                        ],
                        "<html><body><main><p>hi</p></main></body></html>",
                    )
                }
            }),
        )
    })
    .await;
    let collector = Collector::start().await;
    let run = crawl_with(
        &site.base,
        |c| {
            c.fetch.extra_headers.insert("x-qa-token", SECRET);
            c.output.capture_raw = true;
        },
        export_to(&collector),
        |run| run,
    )
    .await;
    assert_eq!(*seen.lock().unwrap(), [SECRET], "the header was sent");

    let home = katana_p4_common::page_at(&run.report, "/");
    assert_eq!(home.metadata["request"]["headers"]["x-qa-token"], "[redacted]");
    assert_eq!(home.metadata["response_headers"]["x-echo"], "[redacted]");
    let request_raw = home.metadata["request"]["raw"].as_str().unwrap();
    assert!(
        request_raw.contains("x-qa-token: [redacted]\r\n"),
        "{request_raw:?}"
    );
    let raw = run.report.page_contents[0].raw.as_deref().unwrap();
    assert!(raw.contains("x-echo: [redacted]\r\n"), "{raw:?}");
    for text in [request_raw, raw, &home.metadata.to_string()] {
        assert!(!text.contains(SECRET));
    }

    let events = collector.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["request"]["headers"]["x-qa-token"], "[redacted]");
    assert_eq!(events[0]["response"]["headers"]["x-echo"], "[redacted]");
    assert!(!serde_json::to_string(&events).unwrap().contains(SECRET));
}
