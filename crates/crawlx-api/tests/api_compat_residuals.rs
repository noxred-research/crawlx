#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Residual shapes of the compat facade, each proven through the public router: the crawl status
//! `warning`, the in-flight `expiresAt` and stored-page-only `next`, the map `id` and URL spelling, the `html`
//! document skeleton, `changeTracking` ignoring iframe `src`, the response headers of the compat
//! routes (CORS, `ETag`, `X-Response-Time`), the echo of the caller's `x-request-id` on a `409`,
//! `compat.mode` and the dual signing of native webhooks.
mod common;
#[path = "common/crawl_rig.rs"]
mod crawl_rig;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use async_trait::async_trait;
use axum::http::{header, HeaderMap, Method, StatusCode};
use chrono::Utc;
use common::env_with;
use crawlx_api::intel::webhook::{compat_signature, SIGNATURE_HEADER};
use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookSender, WebhookTransport};
use crawlx_api::{ApiConfig, CompatConfig, CompatMode, Settings};
use crawlx_core::config::QueryPolicy;
use crawlx_core::repo::{EventRepo, RunRepo};
use crawlx_core::time::ManualClock;
use crawlx_core::CrawlRunId;
use parking_lot::Mutex;
use scrape_rig::RigConfig;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const V2: &str = "/compat/v2";

/// A worker that starts only after the test is over: runs created meanwhile stay queued.
fn parked(compat: CompatConfig) -> RigConfig {
    RigConfig {
        worker_start_delay: Some(Duration::from_secs(120)),
        compat,
        ..RigConfig::default()
    }
}

/// Poll the compat status of crawl `id` until it is no longer `scraping`.
async fn wait_crawl(rig: &scrape_rig::Rig, id: &str) -> Value {
    for _ in 0..600 {
        let (_, _, v) = rig.env.get(&format!("{V2}/crawl/{id}?limit=1000")).await;
        if v["status"] != "scraping" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("crawl {id} did not finish in 30 s");
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

// ---- status `warning` --------------------------------------------------------------------------

#[tokio::test]
async fn crawl_status_warns_about_robots_blocked_pages_and_names_the_errors_route() {
    let rig = crawl_rig::Rig::start(crawl_rig::RigConfig::default()).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({"url": rig.url("/"), "sitemap": "skip", "robotsUserAgent": "FireBot"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let status = rig.wait_crawl(&id).await;
    assert_eq!(status["status"], "completed", "{status}");
    let warning = status["warning"]
        .as_str()
        .unwrap_or_else(|| panic!("no warning: {status}"));
    assert!(warning.contains("robots.txt disallows"), "{warning}");
    assert!(warning.contains(&format!("{V2}/crawl/{id}/errors")), "{warning}");
    let (_, _, errors) = rig.env.get(&format!("{V2}/crawl/{id}/errors")).await;
    assert_eq!(
        errors["robotsBlocked"],
        json!([rig.url("/b")]),
        "the list the warning points at"
    );

    // the same crawl as the default agent hits nothing blocked and has several pages: no warning
    let (_, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({"url": rig.url("/"), "sitemap": "skip"}),
        )
        .await;
    let other = rig.wait_crawl(v["id"].as_str().unwrap()).await;
    assert!(other.get("warning").is_none(), "{other}");
    rig.stop().await;
}

#[tokio::test]
async fn a_stopped_crawl_that_found_one_page_says_how_to_broaden_it() {
    let rig = crawl_rig::Rig::start(crawl_rig::RigConfig::default()).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({"url": rig.url("/a"), "sitemap": "skip", "limit": 1}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let status = rig.wait_crawl(v["id"].as_str().unwrap()).await;
    assert_eq!(status["status"], "completed", "{status}");
    assert_eq!(status["completed"], 1, "{status}");
    let host = url::Url::parse(&rig.url("/a"))
        .unwrap()
        .host_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        status["warning"],
        format!(
            "Only 1 result(s) found. For broader coverage, try crawling with crawlEntireDomain=true or start from a higher-level path like {host}"
        )
    );
    rig.stop().await;
}

// ---- in-flight `expiresAt` and stored-page pagination ------------------------------------------

#[tokio::test]
async fn a_running_crawl_has_an_expiry_but_no_next_without_stored_pages() {
    let rig = scrape_rig::Rig::start(parked(CompatConfig::default())).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({"url": rig.url("/a"), "sitemap": "skip", "limit": 1}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();

    let (s, _, status) = rig.env.get(&format!("{V2}/crawl/{id}")).await;
    assert_eq!(s, StatusCode::OK, "{status}");
    assert_eq!(status["status"], "scraping", "{status}");
    let created = chrono::DateTime::parse_from_rfc3339(status["createdAt"].as_str().unwrap()).unwrap();
    let expires = chrono::DateTime::parse_from_rfc3339(
        status["expiresAt"].as_str().unwrap_or_else(|| panic!("{status}")),
    )
    .unwrap();
    assert!(expires > created, "{status}");
    assert_eq!(status["next"], Value::Null, "{status}");
    assert_eq!(status["data"], json!([]));

    // An offset past the available data must not turn pagination into a polling link.
    let (_, _, status) = rig.env.get(&format!("{V2}/crawl/{id}?limit=5&skip=3")).await;
    assert_eq!(status["data"], json!([]));
    assert_eq!(status["next"], Value::Null, "{status}");
}

#[tokio::test]
async fn a_finished_crawl_expires_after_retention_and_has_no_next() {
    let rig = scrape_rig::Rig::start(RigConfig::default()).await;
    let (_, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({"url": rig.url("/a"), "sitemap": "skip", "limit": 1}),
        )
        .await;
    let status = wait_crawl(&rig, v["id"].as_str().unwrap()).await;
    assert_eq!(status["status"], "completed", "{status}");
    assert_eq!(status["next"], Value::Null, "{status}");
    let completed = chrono::DateTime::parse_from_rfc3339(status["completedAt"].as_str().unwrap()).unwrap();
    let expires = chrono::DateTime::parse_from_rfc3339(status["expiresAt"].as_str().unwrap()).unwrap();
    assert!(expires > completed, "{status}");
    rig.stop().await;
}

// ---- response headers --------------------------------------------------------------------------

#[tokio::test]
async fn compat_answers_carry_cors_etag_and_response_time() {
    let rig = scrape_rig::Rig::start(parked(CompatConfig::default())).await;
    let uri = format!("{V2}/team/credit-usage");
    let (s, h, _) = rig
        .env
        .send(Method::GET, &uri, Some(&rig.env.key), &[], None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(header_str(&h, "access-control-allow-origin"), "*");
    let took = header_str(&h, "x-response-time");
    let (ms, unit) = took.split_at(took.len().saturating_sub(2));
    assert_eq!(unit, "ms", "{took}");
    assert!(
        ms.parse::<f64>().is_ok() && ms.split_once('.').is_some_and(|(_, f)| f.len() == 3),
        "{took}"
    );
    let etag = header_str(&h, "etag").to_owned();
    assert!(etag.starts_with("W/\""), "{etag}");
    assert!(h.contains_key("x-request-id"));

    // the same body has the same tag; a matching `If-None-Match` is a 304 without a body
    let (s, h2, _) = rig
        .env
        .send(Method::GET, &uri, Some(&rig.env.key), &[], None)
        .await;
    assert_eq!((s, header_str(&h2, "etag")), (StatusCode::OK, etag.as_str()));
    let (s, h3, body) = rig
        .env
        .send(
            Method::GET,
            &uri,
            Some(&rig.env.key),
            &[("if-none-match", &etag)],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(header_str(&h3, "etag"), etag);
    assert_eq!(header_str(&h3, "access-control-allow-origin"), "*");
    let (s, _, body) = rig
        .env
        .send(
            Method::GET,
            &uri,
            Some(&rig.env.key),
            &[("if-none-match", "W/\"other\"")],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!body.is_empty());

    // errors carry them too: an unknown crawl and a missing key
    let (s, h, _) = rig
        .env
        .send(
            Method::GET,
            &format!("{V2}/crawl/{}", CrawlRunId::new()),
            Some(&rig.env.key),
            &[],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(header_str(&h, "access-control-allow-origin"), "*");
    assert!(header_str(&h, "x-response-time").ends_with("ms"));
    let (s, h, _) = rig.env.send(Method::GET, &uri, None, &[], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(header_str(&h, "access-control-allow-origin"), "*");

    // the native routes are not part of the compat surface
    let (s, h, _) = rig
        .env
        .send(Method::GET, "/v1/openapi.json", None, &[], None)
        .await;
    assert_eq!(s, StatusCode::OK);
    for name in ["access-control-allow-origin", "etag", "x-response-time"] {
        assert!(!h.contains_key(name), "{name} on a native route");
    }
}

#[tokio::test]
async fn a_cross_origin_preflight_of_a_compat_route_is_answered_without_a_key() {
    let rig = scrape_rig::Rig::start(parked(CompatConfig::default())).await;
    let (s, h, body) = rig
        .env
        .send(
            Method::OPTIONS,
            &format!("{V2}/scrape"),
            None,
            &[
                ("origin", "https://app.example.test"),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "authorization, content-type"),
            ],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
    assert_eq!(header_str(&h, "access-control-allow-origin"), "*");
    assert!(header_str(&h, "access-control-allow-methods").contains("POST"));
    let allowed = header_str(&h, "access-control-allow-headers");
    assert!(
        allowed.contains("authorization") && allowed.contains("content-type"),
        "{allowed}"
    );
    assert!(h.contains_key(header::ACCESS_CONTROL_MAX_AGE));
}

// ---- 409 echoes the caller's request id --------------------------------------------------------

#[tokio::test]
async fn a_409_echoes_the_callers_request_id() {
    let rig = scrape_rig::Rig::start(parked(CompatConfig::default())).await;
    let uri = format!("{V2}/crawl");
    let first = json!({"url": rig.url("/a"), "sitemap": "skip", "limit": 1});
    let other = json!({"url": rig.url("/b"), "sitemap": "skip", "limit": 1});
    let (s, h, v) = rig
        .env
        .post_with(&uri, &[("x-request-id", "client-req-7")], &first)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_ne!(
        header_str(&h, "x-request-id"),
        "client-req-7",
        "a 200 keeps crawlx's own id"
    );

    let (s, h, v) = rig
        .env
        .post_with(&uri, &[("x-request-id", "client-req-7")], &other)
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "duplicate_request", "{v}");
    assert_eq!(header_str(&h, "x-request-id"), "client-req-7");
    assert_eq!(v["requestId"], "client-req-7", "{v}");

    // other failures keep crawlx's own id
    let (s, h, v) = rig
        .env
        .post_with(&uri, &[("x-request-id", "client-req-8")], &json!({}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_ne!(header_str(&h, "x-request-id"), "client-req-8");

    // an `Idempotency-Key` reuse is not the 409 of a request id: crawlx's own id stays
    let (s, _, _) = rig
        .env
        .post_with(&uri, &[("idempotency-key", "k-1")], &first)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, h, v) = rig
        .env
        .post_with(&uri, &[("idempotency-key", "k-1")], &other)
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["requestId"], header_str(&h, "x-request-id"));
    assert_ne!(header_str(&h, "x-request-id"), "k-1");
}

// ---- map `id` and spelling ---------------------------------------------------------------------

fn directory_site() -> axum::Router {
    let page = |links: &'static str| {
        move || async move {
            (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                format!("<html><head><title>Dir</title></head><body><main><h1>Dir</h1>{links}</main></body></html>"),
            )
        }
    };
    axum::Router::new()
        .route(
            "/dir/",
            axum::routing::get(page(
                r#"<a href="/dir/sub/">Sub</a> <a href="/dir/file">File</a>"#,
            )),
        )
        .route("/dir/sub/", axum::routing::get(page("")))
        .route("/dir/file", axum::routing::get(page("")))
}

#[tokio::test]
async fn map_answers_the_id_of_its_run_and_spells_urls_without_a_trailing_slash() {
    let rig = scrape_rig::Rig::start(RigConfig {
        site_routes: Some(directory_site()),
        ..RigConfig::default()
    })
    .await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/map"),
            &json!({"url": rig.url("/dir/"), "sitemap": "skip"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap_or_else(|| panic!("no id: {v}"));
    assert!(id.parse::<CrawlRunId>().is_ok(), "{id}");
    let run = RunRepo::get(rig.env.store.as_ref(), id.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(run.tenant, rig.env.tenant, "the id names the map's own run");

    let urls: Vec<&str> = v["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["url"].as_str().unwrap())
        .collect();
    assert!(urls.contains(&rig.url("/dir").as_str()), "{urls:?}");
    assert!(urls.contains(&rig.url("/dir/sub").as_str()), "{urls:?}");
    assert!(urls.contains(&rig.url("/dir/file").as_str()), "{urls:?}");
    assert!(
        urls.iter().all(|u| !u.ends_with('/')),
        "no trailing slash: {urls:?}"
    );
    rig.stop().await;
}

// ---- `html` skeleton ---------------------------------------------------------------------------

#[tokio::test]
async fn the_html_format_is_a_document_with_doctype_and_language() {
    let rig = scrape_rig::Rig::start(RigConfig::default()).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/scrape"),
            &json!({"url": rig.url("/"), "formats": ["html", "markdown"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let data = &v["data"];
    let html = data["html"].as_str().unwrap();
    assert!(
        html.starts_with("<!DOCTYPE html><html lang=\"en\">\n<body>\n<main>"),
        "{html}"
    );
    assert!(html.contains("<h1>Fixture Home</h1>"), "{html}");
    assert!(html.ends_with("</body>\n</html>"), "{html}");
    assert_eq!(data["metadata"]["language"], "en");
    assert!(!data["markdown"].as_str().unwrap().contains("DOCTYPE"));
    rig.stop().await;
}

// ---- changeTracking and iframe src -------------------------------------------------------------

#[tokio::test]
async fn change_tracking_ignores_the_src_of_an_iframe() {
    let token = Arc::new(AtomicUsize::new(1));
    let text = Arc::new(Mutex::new("Widgets overview".to_owned()));
    let (t, x) = (token.clone(), text.clone());
    let routes = axum::Router::new().route(
        "/framed",
        axum::routing::get(move || {
            let n = t.load(Ordering::SeqCst);
            let text = x.lock().clone();
            async move {
                (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    format!(
                        "<html><head><title>Framed</title></head><body><main><h1>Widgets</h1><p>{text}</p>\
                         <pre><code>&lt;iframe src=\"https://widget.example.test/embed?tok={n}\" width=\"10\"&gt;&lt;/iframe&gt;</code></pre></main></body></html>"
                    ),
                )
            }
        }),
    );
    let rig = scrape_rig::Rig::start(RigConfig {
        site_routes: Some(routes),
        ..RigConfig::default()
    })
    .await;
    let body = json!({
        "url": rig.url("/framed"),
        "formats": ["markdown", {"type": "changeTracking", "modes": ["git-diff"], "tag": "iframes"}],
    });
    let scrape = |body: Value| {
        let env = &rig.env;
        async move {
            let (s, _, v) = env.post(&format!("{V2}/scrape"), &body).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            v["data"].clone()
        }
    };
    let first = scrape(body.clone()).await;
    assert!(
        first["markdown"].as_str().unwrap().contains("<iframe src="),
        "{first}"
    );
    assert_eq!(first["changeTracking"]["changeStatus"], "new");

    token.store(2, Ordering::SeqCst);
    let second = scrape(body.clone()).await;
    assert!(
        second["markdown"].as_str().unwrap().contains("tok=2"),
        "the page did change: {second}"
    );
    assert_eq!(second["changeTracking"]["changeStatus"], "same", "{second}");

    *text.lock() = "Widgets, now with a price list".to_owned();
    token.store(3, Ordering::SeqCst);
    let third = scrape(body).await;
    let ct = &third["changeTracking"];
    assert_eq!(ct["changeStatus"], "changed", "{third}");
    assert!(
        ct["diff"]["text"].as_str().unwrap().contains("price list"),
        "{ct}"
    );
    rig.stop().await;
}

// ---- compat.mode -------------------------------------------------------------------------------

async fn query_policy_of(rig: &scrape_rig::Rig, extra: Value) -> QueryPolicy {
    let mut body = json!({"url": rig.url("/a"), "sitemap": "skip", "limit": 1});
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let (s, _, v) = rig.env.post(&format!("{V2}/crawl"), &body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id: CrawlRunId = v["id"].as_str().unwrap().parse().unwrap();
    RunRepo::get(rig.env.store.as_ref(), id)
        .await
        .unwrap()
        .config
        .scope
        .query_policy
}

#[tokio::test]
async fn strict_mode_keeps_every_query_string_and_native_defaults_classifies() {
    let strict = scrape_rig::Rig::start(parked(CompatConfig::default())).await;
    assert_eq!(query_policy_of(&strict, json!({})).await, QueryPolicy::KeepAll);
    assert_eq!(
        query_policy_of(&strict, json!({"ignoreQueryParameters": true})).await,
        QueryPolicy::StripAll
    );

    let native = scrape_rig::Rig::start(parked(CompatConfig {
        mode: CompatMode::NativeDefaults,
        ..CompatConfig::default()
    }))
    .await;
    assert_eq!(query_policy_of(&native, json!({})).await, QueryPolicy::Classify);
    // an explicit choice always wins
    assert_eq!(
        query_policy_of(&native, json!({"ignoreQueryParameters": true})).await,
        QueryPolicy::StripAll
    );
    assert_eq!(
        query_policy_of(&native, json!({"ignoreQueryParameters": false})).await,
        QueryPolicy::KeepAll
    );
}

#[test]
fn the_mode_is_read_from_the_environment_unless_set() {
    let env = |v: &'static str| move |k: &str| (k == "CRAWLX_COMPAT_MODE").then(|| v.to_owned());
    let read = |v| CompatConfig::default().from_lookup(env(v));
    assert_eq!(read("native_defaults").unwrap().mode, CompatMode::NativeDefaults);
    assert_eq!(
        read(" Native-Defaults ").unwrap().mode,
        CompatMode::NativeDefaults
    );
    assert_eq!(read("strict").unwrap().mode, CompatMode::Strict);
    assert!(read("lenient").is_err());
    assert_eq!(
        CompatConfig::default().from_lookup(|_| None).unwrap().mode,
        CompatMode::Strict
    );
    let set = CompatConfig {
        mode: CompatMode::NativeDefaults,
        ..CompatConfig::default()
    };
    assert_eq!(
        set.from_lookup(env("strict")).unwrap().mode,
        CompatMode::NativeDefaults
    );
    assert!(
        CompatMode::Strict.dual_signs_native_webhooks()
            && !CompatMode::NativeDefaults.dual_signs_native_webhooks()
    );
    let json = serde_json::to_value(CompatConfig {
        mode: CompatMode::NativeDefaults,
        ..CompatConfig::default()
    })
    .unwrap();
    assert_eq!(json["mode"], "native_defaults");
}

// ---- dual signing of native webhooks -----------------------------------------------------------

const SECRET: &str = "whsec_dual";

#[derive(Default)]
struct Script {
    seen: Mutex<Vec<WebhookRequest>>,
}

#[async_trait]
impl WebhookTransport for Script {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        self.seen.lock().push(req);
        Ok(200)
    }
}

async fn native_delivery(dual: bool) -> WebhookRequest {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        webhook_secret: SECRET.to_owned(),
        ..ApiConfig::default()
    };
    let env = env_with(cfg, Settings::default(), clock.clone());
    let script = Arc::new(Script::default());
    let sender = WebhookSender::new(
        env.state.repos.api.clone(),
        env.state.repos.runs.clone(),
        env.state.repos.events.clone(),
        script.clone(),
        SECRET.to_owned(),
        clock,
    )
    .with_dual_signing(dual);
    let run = env
        .create_run(&json!({
            "seedUrl": "https://app.example.test/",
            "seed": 5,
            "output": {"webhook": {"url": "https://hooks.example.test/crawlx", "events": ["completed"]}},
        }))
        .await;
    let run: CrawlRunId = run.parse().unwrap();
    env.store
        .append(run, "completed", json!({"status": "completed"}))
        .await
        .unwrap();
    let report = sender.tick().await.unwrap();
    assert_eq!(report.delivered, 1, "{report:?}");
    let seen = script.seen.lock();
    assert_eq!(seen.len(), 1);
    seen[0].clone()
}

fn signatures(req: &WebhookRequest) -> (Vec<&str>, Vec<&str>) {
    let named = |n: &str| {
        req.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
    };
    (named("Crawlx-Signature"), named(SIGNATURE_HEADER))
}

#[tokio::test]
async fn native_deliveries_are_signed_twice_in_strict_mode_only() {
    let dual = native_delivery(true).await;
    let (native, compat) = signatures(&dual);
    assert_eq!(native.len(), 1);
    assert!(native[0].starts_with("t="), "{native:?}");
    assert_eq!(compat, vec![compat_signature(SECRET, &dual.body).as_str()]);
    assert!(compat[0].starts_with("sha256="));

    let single = native_delivery(false).await;
    let (native, compat) = signatures(&single);
    assert_eq!(native.len(), 1);
    assert!(compat.is_empty(), "{compat:?}");
}
