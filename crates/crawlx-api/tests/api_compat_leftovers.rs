#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The four items the Firecrawl facade corrections left open:
//!
//! 1. `metadata.concurrencyLimited` / `concurrencyQueueDurationMs`: the wait of a run in the
//!    admission queue;
//! 2. the `409` of `POST /v2/crawl` for a request id replayed while the original is in flight
//!    (`request_in_flight`, `duplicate_request`, with the `id` of the original job);
//! 3. `branding` from computed styles on the browser leg, the markup and stylesheet heuristics
//!    on the HTTP leg (the real Chromium test skips without `CRAWLX_CHROMIUM_PATH`);
//! 4. `deduplicateSimilarURLs`: URL normalization, never the native URL-shape filter
//!    (`scope.filterSimilar` stays `false`); an explicit `false` warns.

mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use async_trait::async_trait;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::CrawlRunId;
use crawlx_extract::branding::ComputedStyles;
use crawlx_model::llm::{Completion, LlmError, LlmExtractor, TokenUsage};
use crawlx_worker::scrape::render::{ActionOutputs, PageRenderer, RenderError, RenderRequest, Rendered};
use scrape_rig::{Rig, RigConfig};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

const V2: &str = "/compat/firecrawl/v2";
const CRAWL: &str = "/compat/firecrawl/v2/crawl";
const SCRAPE: &str = "/compat/firecrawl/v2/scrape";

async fn scrape_ok(rig: &Rig, body: &Value) -> Value {
    let (s, _, v) = rig.env.post(SCRAPE, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true, "{v}");
    v["data"].clone()
}

async fn start_crawl(rig: &Rig, body: &Value) -> String {
    let (s, _, v) = rig.env.post(CRAWL, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["id"].as_str().unwrap().to_owned()
}

/// Poll the crawl until it is no longer `scraping` (30 s at most).
async fn wait_crawl(rig: &Rig, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (s, _, v) = rig.env.get(&format!("{CRAWL}/{id}?limit=1000")).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        if v["status"] != "scraping" {
            return v;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "crawl did not finish: {v}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn sources(v: &Value) -> BTreeSet<String> {
    v["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["metadata"]["sourceURL"].as_str().map(str::to_owned))
        .collect()
}

// ---- 1. metadata.concurrencyLimited -------------------------------------------------------

#[tokio::test]
async fn a_run_that_waited_for_a_worker_reports_its_queue_wait() {
    // the worker comes up 1.5 s after the request: the run waits in the admission queue
    let rig = Rig::start(RigConfig {
        worker_start_delay: Some(Duration::from_millis(1500)),
        ..RigConfig::default()
    })
    .await;
    let queued = scrape_ok(&rig, &json!({"url": rig.url("/a"), "maxAge": 0})).await;
    let m = &queued["metadata"];
    assert_eq!(m["concurrencyLimited"], true, "{m}");
    let waited = m["concurrencyQueueDurationMs"].as_u64().unwrap();
    assert!(
        (1_000..30_000).contains(&waited),
        "the wait is at least the worker's start delay (less its poll): {waited} ms"
    );

    // the stored document of the run reports the same wait
    let id = m["scrapeId"].as_str().unwrap();
    let (s, _, again) = rig.env.get(&format!("{V2}/scrape/{id}")).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again["data"]["metadata"]["concurrencyLimited"], true);
    assert_eq!(
        again["data"]["metadata"]["concurrencyQueueDurationMs"], m["concurrencyQueueDurationMs"],
        "the wait is derived from the run's created and started times"
    );

    // the worker is up now: the next run starts at once and did not queue
    let fresh = scrape_ok(&rig, &json!({"url": rig.url("/b"), "maxAge": 0})).await;
    assert_eq!(fresh["metadata"]["concurrencyLimited"], false, "{fresh}");
    assert!(fresh["metadata"].get("concurrencyQueueDurationMs").is_none());

    // a stored scrape served from the cache created no run, so it never waited
    let cached = scrape_ok(&rig, &json!({"url": rig.url("/a"), "maxAge": 3_600_000})).await;
    assert_eq!(cached["metadata"]["cacheState"], "hit");
    assert_eq!(cached["metadata"]["concurrencyLimited"], false, "{cached}");
    assert!(cached["metadata"].get("concurrencyQueueDurationMs").is_none());
    rig.stop().await;
}

#[tokio::test]
async fn the_pages_of_a_crawl_that_queued_carry_the_wait_too() {
    let rig = Rig::start(RigConfig {
        worker_start_delay: Some(Duration::from_millis(1500)),
        ..RigConfig::default()
    })
    .await;
    let id = start_crawl(
        &rig,
        &json!({"url": rig.url("/a"), "limit": 1, "sitemap": "skip"}),
    )
    .await;
    let done = wait_crawl(&rig, &id).await;
    let page = &done["data"][0]["metadata"];
    assert_eq!(page["concurrencyLimited"], true, "{done}");
    assert!(page["concurrencyQueueDurationMs"].as_u64().unwrap() >= 1_000);
    rig.stop().await;
}

// ---- 2. 409 request_in_flight with the original job id ------------------------------------

/// The crawl planner of the `prompt` option: holds the first request in flight until released.
struct GatedPlanner {
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl LlmExtractor for GatedPlanner {
    async fn complete(
        &self,
        _system: &str,
        _user: &str,
        _schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(Completion {
            value: json!({"limit": 1}),
            usage: TokenUsage {
                prompt_tokens: 3,
                completion_tokens: 2,
            },
        })
    }
}

fn assert_conflict(v: &Value, code: &str, job: &str) {
    assert_eq!(v["success"], false, "{v}");
    assert_eq!(v["code"], code, "{v}");
    assert_eq!(v["id"], job, "the id of the original job: {v}");
    assert!(v["error"].as_str().is_some_and(|e| !e.is_empty()), "{v}");
}

#[tokio::test]
async fn a_crawl_request_replayed_in_flight_is_a_409_naming_the_original_job() {
    let planner = Arc::new(GatedPlanner {
        entered: Notify::new(),
        release: Notify::new(),
    });
    let rig = Rig::start(RigConfig {
        llm: Some(planner.clone()),
        ..RigConfig::default()
    })
    .await;
    let body = json!({"url": rig.url("/a"), "prompt": "the home page", "sitemap": "skip"});
    let other = json!({"url": rig.url("/a"), "prompt": "the home page", "sitemap": "skip", "limit": 7});
    let post = |header: &'static str, key: &'static str, body: &Value| {
        let body = body.clone();
        let env = &rig.env;
        async move { env.post_with(CRAWL, &[(header, key)], &body).await }
    };

    let (first, (in_flight, different)) = tokio::join!(post("x-request-id", "crawl-req-1", &body), async {
        tokio::time::timeout(Duration::from_secs(10), planner.entered.notified())
            .await
            .expect("the first request reached the planner");
        // the original is still being planned: the same request id is in flight
        let in_flight = post("x-request-id", "crawl-req-1", &body).await;
        // the same id with other parameters
        let different = post("x-request-id", "crawl-req-1", &other).await;
        planner.release.notify_one();
        (in_flight, different)
    });
    assert_eq!(first.0, StatusCode::OK, "{}", first.2);
    let job = first.2["id"].as_str().unwrap().to_owned();
    assert_eq!(in_flight.0, StatusCode::CONFLICT, "{}", in_flight.2);
    assert_conflict(&in_flight.2, "request_in_flight", &job);
    assert_eq!(different.0, StatusCode::CONFLICT, "{}", different.2);
    assert_conflict(&different.2, "duplicate_request", &job);

    // the existing replay semantics are unchanged: a finished request replays its response
    let (s, h, replay) = post("x-request-id", "crawl-req-1", &body).await;
    assert_eq!(s, StatusCode::OK, "{replay}");
    assert_eq!(replay, first.2, "the original response is replayed");
    assert_eq!(h.get("idempotent-replayed").unwrap(), "true");
    // ... and the same id with other parameters is a 409 duplicate_request naming that job
    let (s, _, dup) = post("x-request-id", "crawl-req-1", &other).await;
    assert_eq!(s, StatusCode::CONFLICT, "{dup}");
    assert_conflict(&dup, "duplicate_request", &job);
    // a malformed request id is a 400 on the header
    let (s, _, bad) = post("x-request-id", "no spaces allowed", &body).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    assert_eq!(bad["details"][0]["path"], "/headers/x-request-id");
    rig.stop().await;
}

#[tokio::test]
async fn an_idempotency_key_keeps_its_422_for_other_parameters_and_names_the_job_in_flight() {
    let planner = Arc::new(GatedPlanner {
        entered: Notify::new(),
        release: Notify::new(),
    });
    let rig = Rig::start(RigConfig {
        llm: Some(planner.clone()),
        ..RigConfig::default()
    })
    .await;
    let body = json!({"url": rig.url("/a"), "prompt": "the home page", "sitemap": "skip"});
    let other = json!({"url": rig.url("/a"), "prompt": "the home page", "sitemap": "skip", "limit": 7});
    let post = |body: &Value| {
        let body = body.clone();
        let env = &rig.env;
        async move {
            env.post_with(CRAWL, &[("idempotency-key", "native-style-key")], &body)
                .await
        }
    };
    let (first, (in_flight, different)) = tokio::join!(post(&body), async {
        tokio::time::timeout(Duration::from_secs(10), planner.entered.notified())
            .await
            .expect("the first request reached the planner");
        let in_flight = post(&body).await;
        let different = post(&other).await;
        planner.release.notify_one();
        (in_flight, different)
    });
    assert_eq!(first.0, StatusCode::OK, "{}", first.2);
    let job = first.2["id"].as_str().unwrap();
    assert_eq!(in_flight.0, StatusCode::CONFLICT, "{}", in_flight.2);
    assert_conflict(&in_flight.2, "request_in_flight", job);
    assert_eq!(different.0, StatusCode::UNPROCESSABLE_ENTITY, "{}", different.2);
    assert_eq!(different.2["code"], "idempotency_key_reuse", "{}", different.2);
    rig.stop().await;
}

// ---- 3. branding from computed styles -----------------------------------------------------

/// A page whose palette only a browser can read: the rules arrive through the CSSOM
/// (`adoptedStyleSheets`), so they are in no `<style>` block and no stylesheet.
const BRAND_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Palette Co</title>
<link rel="icon" href="/brand/favicon.png" sizes="32x32">
<link rel="apple-touch-icon" href="/brand/touch.png" sizes="180x180">
<meta property="og:image" content="/brand/og.png">
</head><body>
<header><a href="/"><img class="logo" alt="Palette Co logo" src="/brand/logo.svg" width="40" height="40"></a></header>
<main>
<h1>Palette Co</h1>
<p>Colours by script.</p>
<p><a href="/docs">Docs</a> <a href="/pricing">Pricing</a></p>
<p><button class="b1">Buy</button> <button class="b1">Subscribe</button> <button class="b2">Learn more</button></p>
<p><input type="text" value="you@example.test"></p>
<pre><code>fn main() {}</code></pre>
</main>
<script>
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(`
    body { margin: 0; background-color: rgb(16, 24, 32); color: rgb(242, 242, 242);
           font-family: "DejaVu Sans", sans-serif; font-size: 17px; line-height: 1.5; }
    h1 { font-family: "DejaVu Serif", serif; font-size: 44px; font-weight: 700; color: rgb(255, 255, 255); }
    a { color: rgb(74, 163, 255); }
    .b1 { background-color: rgb(255, 107, 53); color: rgb(255, 255, 255); border: 2px solid rgb(255, 107, 53);
          border-radius: 14px; padding: 8px 16px; font-size: 16px; }
    .b2 { background-color: transparent; color: rgb(255, 107, 53); border: 2px solid rgb(255, 107, 53);
          border-radius: 14px; padding: 8px 16px; }
    input { background-color: rgb(30, 40, 50); color: rgb(240, 240, 240); border: 1px solid rgb(90, 100, 110);
            border-radius: 6px; }
    code { font-family: "DejaVu Sans Mono", monospace; }
  `);
  document.adoptedStyleSheets = [sheet];
</script>
</body></html>"#;

fn brand_site() -> Router {
    Router::new().route(
        "/brand",
        get(|| async { ([(header::CONTENT_TYPE, "text/html")], BRAND_PAGE).into_response() }),
    )
}

/// What a browser reports for [`BRAND_PAGE`].
fn brand_report() -> ComputedStyles {
    let el = |tag: &str, v: Value| {
        let mut e = json!({"tag": tag});
        e.as_object_mut().unwrap().extend(v.as_object().unwrap().clone());
        e
    };
    let button = el(
        "button",
        json!({"color": "rgb(255, 255, 255)", "backgroundColor": "rgb(255, 107, 53)",
               "borderColor": "rgb(255, 107, 53)", "borderWidth": "2px", "borderRadius": "14px"}),
    );
    ComputedStyles::from_value(json!({
        "root": {"tag": "html", "backgroundColor": "rgba(0, 0, 0, 0)"},
        "body": el("body", json!({"color": "rgb(242, 242, 242)", "backgroundColor": "rgb(16, 24, 32)",
            "fontFamily": "\"DejaVu Sans\", sans-serif", "fontSize": "17px", "fontWeight": "400",
            "lineHeight": "25.5px"})),
        "headings": [el("h1", json!({"color": "rgb(255, 255, 255)", "fontFamily": "\"DejaVu Serif\", serif",
            "fontSize": "44px", "fontWeight": "700"}))],
        "links": [el("a", json!({"color": "rgb(74, 163, 255)"})), el("a", json!({"color": "rgb(74, 163, 255)"}))],
        "buttons": [button.clone(), button, el("button", json!({"color": "rgb(255, 107, 53)",
            "backgroundColor": "rgba(0, 0, 0, 0)", "borderColor": "rgb(255, 107, 53)",
            "borderWidth": "2px", "borderRadius": "14px"}))],
        "inputs": [el("input", json!({"color": "rgb(240, 240, 240)", "backgroundColor": "rgb(30, 40, 50)",
            "borderColor": "rgb(90, 100, 110)", "borderWidth": "1px", "borderRadius": "6px"}))],
        "code": el("code", json!({"fontFamily": "\"DejaVu Sans Mono\", monospace"})),
    }))
    .unwrap()
}

/// A renderer that answers the HTML the HTTP leg would fetch, plus [`brand_report`] when the
/// request asks for `branding`.
struct BrandRenderer;

#[async_trait]
impl PageRenderer for BrandRenderer {
    async fn render(&self, req: &RenderRequest<'_>) -> Result<Rendered, RenderError> {
        Ok(Rendered {
            final_url: req.request.url.url.clone(),
            status: 200,
            headers: vec![("content-type".to_owned(), "text/html".to_owned())],
            content_type: Some("text/html".to_owned()),
            html: BRAND_PAGE.to_owned(),
            screenshot: None,
            actions: ActionOutputs::default(),
            computed_styles: req.options.wants("branding").then(brand_report),
            evidence: None,
        })
    }
}

/// The palette [`BRAND_PAGE`] paints, as the branding profile must report it.
fn assert_brand_palette(b: &Value, site: &dyn Fn(&str) -> String) {
    assert_eq!(b["colorScheme"], "dark", "{b}");
    assert_eq!(b["colors"]["background"], "#101820", "{b}");
    assert_eq!(b["colors"]["textPrimary"], "#F2F2F2", "{b}");
    assert_eq!(b["colors"]["link"], "#4AA3FF", "{b}");
    assert_eq!(b["colors"]["primary"], "#FF6B35", "{b}");
    assert_eq!(b["fonts"][0]["family"], "DejaVu Sans", "{b}");
    assert_eq!(b["typography"]["fontFamilies"]["primary"], "DejaVu Sans", "{b}");
    assert_eq!(b["typography"]["fontFamilies"]["heading"], "DejaVu Serif", "{b}");
    assert_eq!(b["typography"]["fontFamilies"]["code"], "DejaVu Sans Mono", "{b}");
    assert_eq!(b["typography"]["fontSizes"]["body"], "17px", "{b}");
    assert_eq!(b["typography"]["fontSizes"]["h1"], "44px", "{b}");
    assert_eq!(b["typography"]["lineHeights"]["body"], json!(1.5), "{b}");
    assert_eq!(b["spacing"]["borderRadius"], "14px", "{b}");
    assert_eq!(
        b["components"]["buttonPrimary"],
        json!({"background": "#FF6B35", "textColor": "#FFFFFF", "borderColor": "#FF6B35", "borderRadius": "14px"}),
        "{b}"
    );
    assert_eq!(
        b["components"]["buttonSecondary"],
        json!({"background": "transparent", "textColor": "#FF6B35", "borderColor": "#FF6B35", "borderRadius": "14px"}),
        "{b}"
    );
    assert_eq!(b["components"]["input"]["borderRadius"], "6px", "{b}");
    assert_eq!(b["components"]["input"]["background"], "#1E2832", "{b}");
    assert_eq!(b["logo"], site("/brand/logo.svg"), "{b}");
    assert_eq!(b["images"]["favicon"], site("/brand/favicon.png"), "{b}");
    assert_eq!(b["images"]["ogImage"], site("/brand/og.png"), "{b}");
}

#[tokio::test]
async fn a_rendered_page_brings_its_computed_styles_and_an_http_fetch_keeps_the_heuristics() {
    let rig = Rig::start(RigConfig {
        site_routes: Some(brand_site()),
        renderer: Some(Arc::new(BrandRenderer)),
        ..RigConfig::default()
    })
    .await;
    let url = rig.url("/brand");
    let site = |p: &str| rig.url(p);

    // browser leg: `waitFor` renders in the (scripted) browser, which reports computed styles
    let rendered = scrape_ok(
        &rig,
        &json!({"url": url, "formats": ["branding"], "waitFor": 10, "maxAge": 0}),
    )
    .await;
    assert_brand_palette(&rendered["branding"], &site);

    // HTTP leg: the same page fetched over HTTP has no `<style>` to read, so the profile holds
    // the markup findings only (no colours, a default colour scheme, the icons and the logo)
    let fetched = scrape_ok(&rig, &json!({"url": url, "formats": ["branding"], "maxAge": 0})).await;
    let b = &fetched["branding"];
    assert_eq!(b["colorScheme"], "light", "{b}");
    assert!(b["colors"].get("background").is_none(), "{b}");
    assert!(
        b.get("components").is_none() && b.get("typography").is_none(),
        "{b}"
    );
    assert_eq!(b["logo"], rig.url("/brand/logo.svg"), "{b}");
    assert_eq!(b["images"]["ogImage"], rig.url("/brand/og.png"), "{b}");
    rig.stop().await;
}

#[tokio::test]
async fn real_chromium_reads_the_computed_palette_of_a_page() {
    let Some(rig) = Rig::start_chromium(RigConfig {
        site_routes: Some(brand_site()),
        ..RigConfig::default()
    })
    .await
    else {
        eprintln!("skipped: set CRAWLX_CHROMIUM_PATH");
        return;
    };
    let site = |p: &str| rig.url(p);
    let data = scrape_ok(
        &rig,
        &json!({"url": rig.url("/brand"), "formats": ["branding"], "waitFor": 200, "maxAge": 0}),
    )
    .await;
    assert_brand_palette(&data["branding"], &site);

    // the same page over HTTP: the CSSOM rules do not exist there
    let fetched = scrape_ok(
        &rig,
        &json!({"url": rig.url("/brand"), "formats": ["branding"], "maxAge": 0}),
    )
    .await;
    assert!(
        fetched["branding"]["colors"].get("background").is_none(),
        "{}",
        fetched["branding"]
    );
    rig.stop().await;
}

// ---- 4. deduplicateSimilarURLs -------------------------------------------------------------

fn items_site() -> Router {
    let hub: String = (0..20)
        .map(|n| format!(r#"<p><a href="/items/{n}">Item {n}</a></p>"#))
        .collect();
    Router::new()
        .route(
            "/items",
            get(move || {
                let hub = hub.clone();
                async move {
                    (
                        [(header::CONTENT_TYPE, "text/html")],
                        format!("<html><body><main><h1>Items</h1>{hub}</main></body></html>"),
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/items/{n}",
            get(|axum::extract::Path(n): axum::extract::Path<u32>| async move {
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    format!("<html><body><main><h1>Item {n}</h1></main></body></html>"),
                )
                    .into_response()
            }),
        )
}

#[tokio::test]
async fn deduplicate_similar_urls_never_enables_the_shape_filter() {
    let rig = Rig::start(RigConfig {
        site_routes: Some(items_site()),
        ..RigConfig::default()
    })
    .await;
    let seed = rig.url("/items");
    let crawl = |extra: Value| {
        let mut body = json!({"url": seed, "sitemap": "skip", "limit": 50});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let run = |id: &str| {
        let repos = rig.env.state.repos.runs.clone();
        let id: CrawlRunId = id.parse().unwrap();
        async move { repos.get(id).await.unwrap() }
    };

    // Firecrawl's default (real pinned run, 2026-10-28): every sibling page of one URL shape is
    // fetched, so no setting drops the near-duplicate item URLs
    let default_id = start_crawl(&rig, &crawl(json!({}))).await;
    let default_pages = sources(&wait_crawl(&rig, &default_id).await);
    assert_eq!(default_pages.len(), 21, "hub + 20 items: {default_pages:?}");
    assert!(!run(&default_id).await.config.scope.filter_similar);
    let on_id = start_crawl(&rig, &crawl(json!({"deduplicateSimilarURLs": true}))).await;
    let on_pages = sources(&wait_crawl(&rig, &on_id).await);
    assert_eq!(default_pages, on_pages, "the default is the explicit true");
    assert!(!run(&on_id).await.config.scope.filter_similar);

    // an explicit `false` cannot un-normalize: same crawl, reported as not honoured
    let (s, _, v) = rig
        .env
        .post(CRAWL, &crawl(json!({"deduplicateSimilarURLs": false})))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| { w["code"] == "unsupported_option" && w["path"] == "/deduplicateSimilarURLs" }),
        "{v}"
    );
    let off_id = v["id"].as_str().unwrap();
    let off_pages = sources(&wait_crawl(&rig, off_id).await);
    assert_eq!(off_pages, default_pages);
    assert!(!run(off_id).await.config.scope.filter_similar);

    // the native default is unchanged: no similar-URL filter
    let native = rig.env.create_run(&common::simple_body()).await;
    assert!(
        !run(&native).await.config.scope.filter_similar,
        "POST /v1/crawls keeps its own default"
    );
    rig.stop().await;
}
