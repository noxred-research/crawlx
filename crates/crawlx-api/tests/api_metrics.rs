#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Request metrics middleware, `GET /metrics` and the loopback-only metrics listener.
//!
//! Metrics are process-global, so every test here takes `LOCK` and asserts deltas.
mod common;

use axum::http::{Method, StatusCode};
use common::{env, simple_body};
use crawlx_api::metrics::{bind_metrics, serve_metrics, serve_metrics_on, PROMETHEUS_CONTENT_TYPE};
use crawlx_api::{ApiError, Scope};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn requests(route: &str, outcome: &str) -> u64 {
    Metrics::global()
        .counter(names::API_REQUESTS)
        .get(&[("route", route), ("outcome", outcome)])
}

fn duration_count(route: &str) -> u64 {
    Metrics::global()
        .histogram(names::API_REQUEST_DURATION)
        .snapshot(&[("route", route)])
        .map_or(0, |s| s.count)
}

#[tokio::test]
async fn requests_are_counted_by_templated_route_and_outcome() {
    let _serial = LOCK.lock().await;
    let e = env();
    let jobs = Metrics::global().counter(names::JOBS_ACCEPTED);

    let (ok0, dur0, jobs0) = (
        requests("/v1/crawls", "ok"),
        duration_count("/v1/crawls"),
        jobs.get(&[]),
    );
    let (s, _, v) = e
        .post_with("/v1/crawls", &[("idempotency-key", "metrics-1")], &simple_body())
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    assert_eq!(requests("/v1/crawls", "ok") - ok0, 1);
    assert_eq!(duration_count("/v1/crawls") - dur0, 1);
    assert_eq!(jobs.get(&[]) - jobs0, 1);
    // every accepted job leaves an append-only `crawl.accepted` audit row
    let accepted: Vec<_> = e
        .api
        .audit_entries()
        .into_iter()
        .filter(|a| a.event == "crawl.accepted")
        .collect();
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert_eq!(
        accepted[0].run.map(|r| r.to_string()).as_deref(),
        Some(id.as_str())
    );
    assert!(
        accepted[0].subject["configDigest"].is_string(),
        "{:?}",
        accepted[0].subject
    );

    // an idempotent replay is a request but not a newly accepted job
    let (s, h, _) = e
        .post_with("/v1/crawls", &[("idempotency-key", "metrics-1")], &simple_body())
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(h["idempotent-replayed"], "true");
    assert_eq!(requests("/v1/crawls", "ok") - ok0, 2);
    assert_eq!(jobs.get(&[]) - jobs0, 1);

    // id routes carry the template, never the id
    let (id_ok0, id_err0) = (
        requests("/v1/crawls/{id}", "ok"),
        requests("/v1/crawls/{id}", "client_error"),
    );
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(requests("/v1/crawls/{id}", "ok") - id_ok0, 1);
    assert_eq!(requests(&format!("/v1/crawls/{id}"), "ok"), 0);

    let (s, _, _) = e.get("/v1/crawls/00000000-0000-7000-8000-000000000000").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(requests("/v1/crawls/{id}", "client_error") - id_err0, 1);

    // a 401 from the auth layer is still attributed to the matched route
    let (s, _, _) = e
        .send(Method::GET, &format!("/v1/crawls/{id}"), None, &[], None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(requests("/v1/crawls/{id}", "client_error") - id_err0, 2);

    // the fallback has no matched path
    let unmatched0 = requests("unmatched", "client_error");
    let (s, _, _) = e.get("/nope").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(requests("unmatched", "client_error") - unmatched0, 1);
    assert_eq!(requests("/nope", "client_error"), 0);

    // the unauthenticated document is counted too
    let doc0 = requests("/v1/openapi.json", "ok");
    let (s, _, _) = e.send(Method::GET, "/v1/openapi.json", None, &[], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(requests("/v1/openapi.json", "ok") - doc0, 1);
}

#[tokio::test]
async fn metrics_endpoint_requires_the_metrics_read_scope() {
    let _serial = LOCK.lock().await;
    let e = env();
    // make sure at least one request series exists before rendering
    let (s, _, _) = e.get("/v1/crawls/00000000-0000-7000-8000-000000000000").await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let limited = e.key_for("acme", &[Scope::CrawlsRead, Scope::CrawlsWrite]).await;
    let (s, _, v) = e.get_as(&limited, "/metrics").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"]["code"], "scope_missing");

    let (s, _, _) = e.send(Method::GET, "/metrics", None, &[], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let scraper = e.key_for("acme", &[Scope::MetricsRead]).await;
    let (s, h, body) = e.send(Method::GET, "/metrics", Some(&scraper), &[], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], PROMETHEUS_CONTENT_TYPE);
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("# TYPE crawlx_api_requests_total counter"),
        "{text}"
    );
    assert!(text.contains("crawlx_api_requests_total{"), "{text}");
    assert!(
        text.contains("# TYPE crawlx_api_request_duration_seconds histogram"),
        "{text}"
    );

    let (metrics_ok0, metrics_err0) = (requests("/metrics", "ok"), requests("/metrics", "client_error"));
    let (s, _, _) = e.send(Method::GET, "/metrics", Some(&scraper), &[], None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = e.get_as(&limited, "/metrics").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(requests("/metrics", "ok") - metrics_ok0, 1);
    assert_eq!(requests("/metrics", "client_error") - metrics_err0, 1);

    assert_eq!(Scope::parse("metrics:read"), Some(Scope::MetricsRead));
    assert_eq!(Scope::ALL.len(), 8);
    assert_eq!(
        Scope::parse("authorizations:read"),
        Some(Scope::AuthorizationsRead)
    );
    assert!(Scope::all_set().contains(&Scope::MetricsRead));
}

#[tokio::test]
async fn loopback_listener_refuses_public_addresses_and_drains_on_cancel() {
    let _serial = LOCK.lock().await;
    let shutdown = CancellationToken::new();
    let err = serve_metrics("0.0.0.0:0".parse().unwrap(), shutdown.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ApiError::Config(m) if m.contains("loopback")),
        "{err}"
    );
    let err = bind_metrics("[::]:0".parse().unwrap()).await.unwrap_err();
    assert!(matches!(err, ApiError::Config(_)), "{err}");

    // Ensure the family has at least one series regardless of test order: the renderer
    // omits families that have never been observed in this process.
    let e = env();
    let (_s, _h, _b) = e.get("/v1/openapi.json").await;

    let listener = bind_metrics("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_metrics_on(listener, shutdown.clone()));

    let body = reqwest::get(format!("http://{addr}/metrics")).await.unwrap();
    assert_eq!(body.status(), 200);
    assert_eq!(body.headers()["content-type"], PROMETHEUS_CONTENT_TYPE);
    let text = body.text().await.unwrap();
    assert!(
        text.contains("# TYPE crawlx_api_requests_total counter"),
        "{text}"
    );
    // nothing but /metrics is served, and nothing is authenticated
    let other = reqwest::get(format!("http://{addr}/v1/crawls")).await.unwrap();
    assert_eq!(other.status(), 404);

    shutdown.cancel();
    let joined = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("metrics listener drains after cancel")
        .unwrap();
    assert!(joined.is_ok(), "{joined:?}");
}
