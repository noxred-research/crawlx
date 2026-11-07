//! In-process fixture site for the static plane.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;

pub struct Site {
    pub base: String,
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn html(body: String) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
}

/// Pages: `/` (links to a, b, a?utm_source=x, /private/secret, an external URL, c), `/a`, `/b`
/// (links to c and a 404), `/c`; robots.txt blocks `/private/`; the sitemap lists `/c` and `/a`.
///
/// Expected URL counters: discovered 13, admitted 5, deduplicated 6, policy_blocked 1,
/// robots_blocked 1; attempted 5, succeeded 4, failed 1.
pub async fn start() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let sitemap = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{base}/c</loc></url><url><loc>{base}/a</loc></url></urlset>"#
    );
    let robots = format!("User-agent: *\nDisallow: /private/\nSitemap: {base}/sitemap.xml\n");
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                html(
                    r#"<html><head><title>Home</title></head><body><main><h1>Home</h1><p>Welcome to the fixture site.</p>
                    <a href="/a">A</a> <a href="/b">B</a> <a href="/a?utm_source=newsletter">A again</a>
                    <a href="/private/secret">Secret</a> <a href="https://external.example/out">Out</a> <a href="/c">C</a></main></body></html>"#
                        .to_owned(),
                )
            }),
        )
        .route(
            "/a",
            get(|| async {
                html(r#"<html><head><title>A</title></head><body><main><h1>A</h1><p>Page A text.</p><a href="/">Home</a> <a href="/b">B</a></main></body></html>"#.to_owned())
            }),
        )
        .route(
            "/b",
            get(|| async {
                html(r#"<html><head><title>B</title></head><body><main><h1>B</h1><p>Page B text.</p><a href="/c">C</a> <a href="/missing">Missing</a></main></body></html>"#.to_owned())
            }),
        )
        .route(
            "/c",
            get(|| async { html(r#"<html><head><title>C</title></head><body><main><h1>C</h1><p>Leaf page.</p></main></body></html>"#.to_owned()) }),
        )
        .route("/private/secret", get(|| async { html("<p>never fetched</p>".to_owned()) }))
        .route(
            "/robots.txt",
            get(move || {
                let robots = robots.clone();
                async move { ([(header::CONTENT_TYPE, "text/plain")], robots) }
            }),
        )
        .route(
            "/sitemap.xml",
            get(move || {
                let sitemap = sitemap.clone();
                async move { ([(header::CONTENT_TYPE, "application/xml")], sitemap) }
            }),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") });
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        base,
        port: addr.port(),
        task,
    }
}
