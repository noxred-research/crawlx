#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! compat v2 scrape endpoints of the compat facade: `POST /scrape`,
//! `GET /scrape/{jobId}`, the batch scrape family and the self-host health probes, run end to
//! end through a REAL worker lease loop over the same store as the API (see `scrape_rig`).
mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use axum::http::{HeaderMap, Method, StatusCode};
use common::{json, Env};
use crawlx_core::config::{CrawlMode, DestructiveActions, ExternalCommunication, SafetyProfile};
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ArtifactStore, CrawlRun, PageRecord, PageRepo, RunRepo, Sensitivity};
use crawlx_core::scrape::{
    ActionResults, BlobRef, CacheState, FormatSpec, JobKind, ParserSpec, PdfMode, PdfPageMarkdown,
    ScrapeDocument, ScrapeJob, ScrapeOptions,
};
use crawlx_core::{Clock, CreateCrawl, SystemClock, TrustLane};
use crawlx_model::llm::{LlmCall, LlmError, MockLlm};
use crawlx_storage::testkit;
use scrape_rig::{Rig, RigConfig};
use serde_json::{json as j, Value};
use std::sync::Arc;
use std::time::Duration;

const V2: &str = "/compat/v2";

async fn scrape(rig: &Rig, body: Value) -> (StatusCode, HeaderMap, Value) {
    rig.env.post(&format!("{V2}/scrape"), &body).await
}

/// `POST /scrape` expecting `200 {success:true}`; returns `data`.
async fn scrape_ok(rig: &Rig, body: Value) -> Value {
    let (s, _, v) = scrape(rig, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true, "{v}");
    v["data"].clone()
}

/// Poll a batch until its status is `want`.
async fn wait_batch(rig: &Rig, id: &str, want: &str) -> Value {
    for _ in 0..400 {
        let (s, _, v) = rig.env.get(&format!("{V2}/batch/scrape/{id}")).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        if v["status"] == want {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("batch {id} never reached {want}");
}

fn assert_compat_error(v: &Value, code: &str) {
    assert_eq!(v["success"], false, "{v}");
    assert_eq!(v["code"], code, "{v}");
    assert!(v["error"].is_string(), "{v}");
}

fn llm_mock() -> Arc<MockLlm> {
    Arc::new(MockLlm::from_fn(|call: &LlmCall| {
        let u = &call.user;
        if u.contains("Summarize the page") {
            Ok(j!({ "summary": "A fixture home page." }))
        } else if u.contains("Answer the question") {
            Ok(j!({ "answer": "forty-two" }))
        } else if u.contains("most relevant to the query") {
            Ok(j!({ "highlights": ["The answer is forty-two."] }))
        } else if u.contains("Extract") {
            Ok(j!({ "headline": "Fixture Home" }))
        } else {
            Err(LlmError::InvalidOutput("unscripted".to_owned()))
        }
    }))
}

// ---- POST /scrape: documents ------------------------------------------------------------

#[tokio::test]
async fn scrape_returns_the_compat_document_with_metadata_and_credits() {
    let rig = Rig::start(RigConfig::default()).await;
    let url = rig.url("/");
    let data = scrape_ok(&rig, j!({ "url": url })).await;
    let md = data["markdown"].as_str().unwrap();
    assert!(md.contains("Fixture Home") && md.contains("forty-two"), "{md}");
    assert!(
        !md.contains("Footer text"),
        "onlyMainContent drops the footer: {md}"
    );
    assert!(!md.contains("base64"), "removeBase64Images: {md}");
    let m = &data["metadata"];
    assert_eq!(m["title"], "Fixture Home");
    assert_eq!(m["description"], "The fixture home page");
    assert_eq!(m["language"], "en");
    assert_eq!(m["sourceURL"], url);
    assert_eq!(m["url"], url);
    assert_eq!(m["statusCode"], 200);
    assert!(m["contentType"].as_str().unwrap().starts_with("text/html"));
    assert_eq!(m["cacheState"], "miss");
    assert_eq!(m["creditsUsed"], 1);
    assert_eq!(m["proxyUsed"], "basic");
    assert!(uuid::Uuid::parse_str(m["scrapeId"].as_str().unwrap()).is_ok());
    assert!(m.get("error").is_none() || m["error"].is_null());
    assert!(
        data.get("html").is_none() && data.get("links").is_none(),
        "only markdown was asked for"
    );
    rig.stop().await;
}

#[tokio::test]
async fn requested_native_outputs_reach_scrape_status_and_keep_selection_distinct_from_capture() {
    const SOURCE: &str = "<html><body><nav><a href='/outside'>Navigation only</a></nav><main id='selected'><h1>Output fixture</h1><p>Local article words explain the selected content and its <a href='/terms'>useful terms</a>.</p><table><thead><tr><th>Item</th><th>Count</th></tr></thead><tbody><tr><td>Books</td><td>7</td></tr></tbody></table></main><footer>Outside selected content</footer><script>discard_this_script()</script></body></html>";
    let rig = Rig::start(RigConfig {
        site_routes: Some(axum::Router::new().route(
            "/native-outputs",
            axum::routing::get(|| async { axum::response::Html(SOURCE) }),
        )),
        ..RigConfig::default()
    })
    .await;
    let url = rig.url("/native-outputs");
    let plain = scrape_ok(&rig, j!({"url": url, "maxAge": 0})).await;
    assert!(plain.get("outputs").is_none(), "{plain}");
    let selected = j!({
        "targetElements": ["#selected"],
        "discoveryScope": "selected",
        "rawHtml": true,
        "cleanedHtml": true,
        "fit": {"strategy": "pruning", "thresholdPermille": 0},
        "citations": "selected",
        "tables": true,
        "linkMedia": {"maxPreviews": 0},
    });
    let data = scrape_ok(
        &rig,
        j!({"url": url, "maxAge": 0, "formats": ["markdown", "links"], "outputs": selected}),
    )
    .await;
    let outputs = &data["outputs"];
    assert_eq!(outputs["discoveryScope"], "selected");
    assert_eq!(outputs["rawHtml"], SOURCE);
    assert!(outputs["cleanedHtml"]
        .as_str()
        .unwrap()
        .contains("Outside selected content"));
    assert!(!outputs["cleanedHtml"]
        .as_str()
        .unwrap()
        .contains("discard_this_script"));
    assert!(outputs["fitMarkdown"]
        .as_str()
        .unwrap()
        .contains("Output fixture"));
    assert!(outputs["fitHtml"].as_str().unwrap().contains("<h1>"));
    assert_eq!(outputs["fit"]["strategy"], "pruning_v1");
    assert!(outputs["markdownWithCitations"]
        .as_str()
        .unwrap()
        .contains("useful terms"));
    assert_eq!(outputs["citations"][0]["url"], rig.url("/terms"));
    assert_eq!(outputs["citations"][0]["linkIndex"], 0);
    assert_eq!(data["links"], j!([rig.url("/terms")]));
    assert_eq!(outputs["tables"]["tables"][0]["rows"], j!([["Books", "7"]]));
    assert_eq!(outputs["linkMedia"]["links"][0]["url"], rig.url("/terms"));
    assert!(outputs["linkMedia"]["previews"].as_array().unwrap().is_empty());
    let id = data["metadata"]["scrapeId"].as_str().unwrap();
    let (status, _, stored) = rig.env.get(&format!("{V2}/scrape/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert_eq!(stored["data"]["outputs"], *outputs);
    let run = rig.env.state.repos.runs.get(id.parse().unwrap()).await.unwrap();
    assert_eq!(run.config.extract.outputs.as_ref(), Some(&selected));
    rig.stop().await;
}

/// Real deployment proxy tiers, selected only by the facade request and worker egress config.
mod proxy_facade {
    use super::*;
    use axum::extract::Request;
    use axum::http::header;
    use axum::response::IntoResponse;
    use axum::Router;
    use base64::Engine as _;
    use crawlx_core::repo::EventRepo;
    use crawlx_core::scrape::ProxyMode;
    use crawlx_fetch::ProxyRoutes;
    use parking_lot::Mutex;
    use url::Url;

    struct Provider {
        url: Url,
        hits: Arc<Mutex<Vec<(String, HeaderMap)>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Provider {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Provider {
        async fn start(tier: &'static str) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
            url.set_username(&format!("facade-{tier}-user")).unwrap();
            url.set_password(Some(&format!("facade-{tier}-secret"))).unwrap();
            let hits = Arc::new(Mutex::new(Vec::new()));
            let received = Arc::clone(&hits);
            let app = Router::new().fallback(move |req: Request| {
                let received = Arc::clone(&received);
                async move {
                    let path = req.uri().path().to_owned();
                    received.lock().push((path.clone(), req.headers().clone()));
                    if path == "/robots.txt" {
                        return (StatusCode::OK, "User-agent: *\nAllow: /\n").into_response();
                    }
                    let status = if tier == "basic" {
                        path.rsplit('/').next().unwrap().parse().unwrap()
                    } else {
                        200
                    };
                    (
                        StatusCode::from_u16(status).unwrap(),
                        [(header::CONTENT_TYPE, "text/html")],
                        format!("<html><body><main><h1>{tier}-route</h1></main></body></html>"),
                    )
                        .into_response()
                }
            });
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self { url, hits, task }
        }

        fn authorization(&self) -> String {
            let credentials = format!("{}:{}", self.url.username(), self.url.password().unwrap());
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(credentials)
            )
        }
    }

    #[tokio::test]
    async fn auto_escalates_blocked_responses_through_real_worker_without_leaking_proxy_secrets() {
        let basic = Provider::start("basic").await;
        let enhanced = Provider::start("enhanced").await;
        let mut routes = ProxyRoutes::default();
        routes.basic = Some(basic.url.clone());
        routes.enhanced = Some(enhanced.url.clone());
        let rig = Rig::start(RigConfig {
            proxy_routes: routes,
            ..RigConfig::default()
        })
        .await;

        // A successful basic response is the control: auto must not mean always-enhanced.
        for status in [200, 401, 403, 429] {
            let path = format!("/status/{status}");
            let url = rig.url(&path);
            let (code, headers, response) = scrape(
                &rig,
                j!({
                    "url": url, "proxy": "auto", "formats": ["markdown", "rawHtml"],
                    "blockAds": false, "maxAge": 0, "storeInCache": false,
                    "headers": { "Authorization": "Bearer facade-origin-secret" }
                }),
            )
            .await;
            assert_eq!(code, StatusCode::OK, "{response}");
            assert_eq!(response["success"], true);
            let data = &response["data"];
            let tier = if status == 200 { "basic" } else { "enhanced" };
            assert_eq!(data["metadata"]["proxyUsed"], tier);
            assert_eq!(data["metadata"]["statusCode"], 200);
            assert_eq!(data["metadata"]["sourceURL"], url);
            assert_eq!(data["metadata"]["url"], url);
            assert_eq!(data["metadata"]["cacheState"], "miss");
            let marker = format!("{tier}-route");
            assert!(data["markdown"].as_str().unwrap().contains(&marker));
            assert!(data["rawHtml"].as_str().unwrap().contains(&marker));
            assert_eq!(rig.site.hits(&path), 0, "worker must not bypass either proxy");
            for (provider, count) in [(&basic, 1), (&enhanced, usize::from(status != 200))] {
                let hits = provider.hits.lock();
                let pages: Vec<_> = hits.iter().filter(|(p, _)| p == &path).collect();
                assert_eq!(pages.len(), count, "one attempt per selected tier");
                for (_, received) in pages {
                    assert_eq!(received[header::AUTHORIZATION], "Bearer facade-origin-secret");
                    assert_eq!(
                        received[header::PROXY_AUTHORIZATION].to_str().unwrap(),
                        provider.authorization()
                    );
                }
            }

            let id = data["metadata"]["scrapeId"].as_str().unwrap();
            let run_id = id.parse().unwrap();
            let stored = RunRepo::get(rig.env.store.as_ref(), run_id).await.unwrap();
            assert_eq!(
                stored.config.scrape.as_ref().unwrap().options.proxy,
                ProxyMode::Auto
            );
            assert!(
                stored.config.fetch.proxy.is_none(),
                "deployment routes stay out of run config"
            );
            let pages = PageRepo::list(rig.env.store.as_ref(), run_id).await.unwrap();
            assert_eq!(pages.len(), 1);
            let doc = ScrapeDocument::from_page_metadata(&pages[0].metadata).unwrap();
            assert_eq!(
                doc.proxy_used,
                if status == 200 {
                    ProxyMode::Basic
                } else {
                    ProxyMode::Enhanced
                }
            );
            let markdown =
                ArtifactStore::get(rig.env.artifacts.as_ref(), pages[0].markdown.as_ref().unwrap())
                    .await
                    .unwrap();
            assert_eq!(
                std::str::from_utf8(&markdown).unwrap(),
                data["markdown"].as_str().unwrap()
            );
            let events = EventRepo::list_after(rig.env.store.as_ref(), run_id, 0, 10_000)
                .await
                .unwrap();
            let (code, _, polled) = rig.env.get(&format!("{V2}/scrape/{id}")).await;
            assert_eq!(code, StatusCode::OK, "{polled}");
            assert_eq!(polled["data"]["metadata"]["proxyUsed"], tier);
            let (code, _, resource) = rig.env.get(&format!("/v1/crawls/{id}")).await;
            assert_eq!(code, StatusCode::OK, "{resource}");
            let output = format!("{headers:?}{response}{polled}{resource}{pages:?}{events:?}");
            assert!(
                !output.contains("facade-origin-secret"),
                "output leaked origin credentials"
            );
            for provider in [&basic, &enhanced] {
                let authorization = provider.authorization();
                for secret in [
                    provider.url.as_str(),
                    provider.url.username(),
                    provider.url.password().unwrap(),
                    authorization.strip_prefix("Basic ").unwrap(),
                ] {
                    assert!(
                        !output.contains(secret),
                        "output leaked deployment proxy credentials"
                    );
                }
            }
        }
        rig.stop().await;
    }
}

#[tokio::test]
async fn every_content_format_is_produced() {
    let rig = Rig::start(RigConfig::default()).await;
    let base = rig.url("");
    let data = scrape_ok(
        &rig,
        j!({
            "url": rig.url("/"),
            "formats": [
                "markdown", "html", "rawHtml", "links", "images", "branding",
                { "type": "attributes", "selectors": [{ "selector": "a[data-kind]", "attribute": "data-kind" }] }
            ],
            "onlyMainContent": false,
        }),
    )
    .await;
    assert!(data["markdown"].as_str().unwrap().contains("Footer text"));
    assert!(data["html"].as_str().unwrap().contains("<h1>Fixture Home</h1>"));
    let raw = data["rawHtml"].as_str().unwrap();
    assert!(
        raw.starts_with("<!doctype html>") && raw.contains("<nav>"),
        "verbatim body: {raw}"
    );
    let links: Vec<&str> = data["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert!(links.contains(&format!("{base}/a").as_str()), "{links:?}");
    assert!(links.contains(&"https://other.example/out"), "{links:?}");
    let images: Vec<&str> = data["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert!(
        images.contains(&format!("{base}/logo.png").as_str()),
        "{images:?}"
    );
    assert!(
        images.contains(&format!("{base}/og.png").as_str()),
        "og:image: {images:?}"
    );
    assert_eq!(
        data["attributes"],
        j!([{ "selector": "a[data-kind]", "attribute": "data-kind", "values": ["primary", "external"] }])
    );
    assert!(data["branding"].is_object(), "{}", data["branding"]);
    assert_eq!(data["metadata"]["ogTitle"], "OG Home");
    assert_eq!(data["metadata"]["keywords"], "alpha, beta");
    rig.stop().await;
}

#[tokio::test]
async fn raw_base64_is_the_body_and_nothing_else() {
    let rig = Rig::start(RigConfig::default()).await;
    let data = scrape_ok(&rig, j!({ "url": rig.url("/raw.txt"), "formats": ["rawBase64"] })).await;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data["rawBase64"].as_str().unwrap())
        .unwrap();
    assert_eq!(bytes, b"plain text body");
    assert_eq!(data["metadata"]["contentType"], "text/plain");
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": rig.url("/"), "formats": ["rawBase64", "markdown"] }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["details"][0]["path"], "/formats");
    rig.stop().await;
}

#[tokio::test]
async fn content_selection_options_apply() {
    let rig = Rig::start(RigConfig::default()).await;
    let md = scrape_ok(
        &rig,
        j!({ "url": rig.url("/"), "onlyMainContent": false, "formats": ["markdown"] }),
    )
    .await["markdown"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(md.contains("Footer text") && md.contains("Nav"), "{md}");
    let md = scrape_ok(
        &rig,
        j!({ "url": rig.url("/"), "maxAge": 0, "includeTags": ["main"], "excludeTags": ["a"], "onlyMainContent": false }),
    )
    .await["markdown"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        md.contains("forty-two") && !md.contains("Footer text") && !md.contains("Page A"),
        "{md}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn request_headers_reach_the_site_and_never_the_stored_config() {
    let rig = Rig::start(RigConfig::default()).await;
    let data = scrape_ok(
        &rig,
        j!({ "url": rig.url("/echo-headers"), "headers": { "X-Token": "s3cret", "User-Agent": "Probe/9", "Cookie": "sid=77" } }),
    )
    .await;
    // Prove delivery independently: the echoed document must redact the same credentials.
    {
        let requests = rig.site.headers.lock();
        let received = requests.get("/echo-headers").unwrap();
        assert_eq!(received.get("x-token").map(String::as_str), Some("s3cret"));
        assert_eq!(received.get("cookie").map(String::as_str), Some("sid=77"));
        assert_eq!(received.get("user-agent").map(String::as_str), Some("Probe/9"));
    }
    let md = data["markdown"].as_str().unwrap();
    assert!(md.contains("x-token=[REDACTED]"), "{md}");
    assert!(md.contains("user-agent: Probe/9"), "{md}");
    assert!(md.contains("cookie=[REDACTED]"), "{md}");
    let response = data.to_string();
    assert!(
        !response.contains("s3cret") && !response.contains("sid=77"),
        "{response}"
    );
    let run_id = data["metadata"]["scrapeId"].as_str().unwrap();
    let stored = RunRepo::get(rig.env.store.as_ref(), run_id.parse().unwrap())
        .await
        .unwrap();
    let job = stored.config.scrape.as_ref().unwrap();
    assert!(
        job.options.headers.is_empty(),
        "header values stay out of the stored scrape options"
    );
    assert_eq!(
        stored.config.fetch.extra_headers.get("x-token"),
        Some("[redacted]"),
        "literal header values never enter stored config"
    );
    assert_eq!(stored.config.fetch.cookies[0].value, "[redacted]");
    let journal = rig.env.store.dump_run(stored.id);
    assert!(
        !journal.contains("s3cret") && !journal.contains("sid=77"),
        "{journal}"
    );
    assert!(!job.options.store_in_cache, "headers force storeInCache=false");
    let pages = PageRepo::list(rig.env.store.as_ref(), stored.id).await.unwrap();
    assert_eq!(pages.len(), 1);
    let markdown = ArtifactStore::get(rig.env.artifacts.as_ref(), pages[0].markdown.as_ref().unwrap())
        .await
        .unwrap();
    assert_eq!(std::str::from_utf8(&markdown).unwrap(), md);
    let metadata = pages[0].metadata.to_string();
    assert!(
        !metadata.contains("s3cret") && !metadata.contains("sid=77"),
        "{metadata}"
    );
    let (_, _, resource) = rig.env.get(&format!("/v1/crawls/{run_id}")).await;
    let text = resource.to_string();
    assert!(!text.contains("s3cret") && !text.contains("sid=77"), "{text}");
    rig.stop().await;
}

#[tokio::test]
async fn error_pages_are_documents_with_their_status() {
    let rig = Rig::start(RigConfig::default()).await;
    let data = scrape_ok(&rig, j!({ "url": rig.url("/status/404") })).await;
    assert_eq!(data["metadata"]["statusCode"], 404);
    assert!(data["metadata"]["error"].is_string(), "{}", data["metadata"]);
    assert_eq!(data["metadata"]["creditsUsed"], 1);
    let data = scrape_ok(&rig, j!({ "url": rig.url("/status/500") })).await;
    assert_eq!(data["metadata"]["statusCode"], 500);
    rig.stop().await;
}

#[tokio::test]
async fn redirects_report_the_final_url_and_keep_the_source() {
    let rig = Rig::start(RigConfig::default()).await;
    let data = scrape_ok(&rig, j!({ "url": rig.url("/redirect") })).await;
    assert_eq!(data["metadata"]["sourceURL"], rig.url("/redirect"));
    assert_eq!(data["metadata"]["url"], rig.url("/a"));
    assert!(data["markdown"].as_str().unwrap().contains("Text of A."));
    rig.stop().await;
}

// ---- POST /scrape: errors -----------------------------------------------------------------

#[tokio::test]
async fn invalid_requests_are_compat_400s_with_every_violation() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = scrape(
        &rig,
        j!({ "formats": ["nope"], "timeout": 5, "location": { "country": "de" } }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_compat_error(&v, "BAD_REQUEST");
    assert_eq!(v["error"], "Bad Request");
    let paths: Vec<&str> = v["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["path"].as_str().unwrap())
        .collect();
    for want in ["/url", "/formats/0/type", "/timeout", "/location/country"] {
        assert!(paths.contains(&want), "{want} in {paths:?}");
    }
    assert!(v["details"][0]["code"].is_string() && v["details"][0]["message"].is_string());
    let (s, _, v) = scrape(&rig, j!({ "url": "ftp://x.example/" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _, v) = rig.env.post(&format!("{V2}/scrape"), &j!([1, 2])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _, v) = rig.env.post(&format!("{V2}/scrape"), &Value::Null).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": rig.url("/"), "headers": { "Cookie": "nameless" } }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["details"][0]["path"], "/headers/Cookie");
    assert_eq!(rig.site.hits("/"), 0, "nothing was fetched");
    rig.stop().await;
}

#[tokio::test]
async fn targets_the_egress_policy_denies_are_403_unsupported_site() {
    let rig = Rig::start(RigConfig::default()).await;
    for url in [
        "http://127.0.0.1/",
        "http://10.0.0.5/admin",
        "http://169.254.169.254/latest/meta-data",
    ] {
        let (s, _, v) = scrape(&rig, j!({ "url": url })).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{url}: {v}");
        assert_compat_error(&v, "UNSUPPORTED_SITE");
    }
    rig.stop().await;
}

#[tokio::test]
async fn an_unreachable_site_is_a_500_with_the_failure_reason() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": format!("http://gone.example.test:{}/", rig.site.port), "timeout": 20000 }),
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    let code = v["code"].as_str().unwrap();
    assert!(
        [
            "SCRAPE_SITE_ERROR",
            "SCRAPE_DNS_RESOLUTION_ERROR",
            "SCRAPE_ALL_ENGINES_FAILED"
        ]
        .contains(&code),
        "{v}"
    );
    assert!(
        v["error"].as_str().unwrap().contains("reason:"),
        "the worker's reason is reported: {v}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn a_slow_site_times_out_with_408_and_the_run_does_not_stay_active() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = scrape(&rig, j!({ "url": rig.url("/slow"), "timeout": 1000 })).await;
    assert_eq!(s, StatusCode::REQUEST_TIMEOUT, "{v}");
    assert_compat_error(&v, "SCRAPE_TIMEOUT");
    assert_eq!(
        rig.env
            .state
            .repos
            .api
            .active_run_count(rig.env.tenant)
            .await
            .unwrap(),
        0
    );
    rig.stop().await;
}

#[tokio::test]
async fn quota_scope_and_body_limits_answer_429_403_413() {
    let settings = crawlx_api::Settings {
        max_active_runs: 0,
        ..crawlx_api::Settings::default()
    };
    let rig = Rig::start(RigConfig {
        settings: Some(settings),
        ..RigConfig::default()
    })
    .await;
    let (s, _, v) = scrape(&rig, j!({ "url": rig.url("/") })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_compat_error(&v, "quota_exceeded");
    rig.stop().await;

    let rig = Rig::start(RigConfig {
        settings: Some(crawlx_api::Settings {
            max_body_bytes: 64,
            ..crawlx_api::Settings::default()
        }),
        ..RigConfig::default()
    })
    .await;
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": rig.url("/"), "formats": ["markdown", "html", "links", "rawHtml"] }),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    let read_only = rig.env.key_for("acme", &[crawlx_api::Scope::CrawlsRead]).await;
    let (s, _, v) = rig
        .env
        .send(
            Method::POST,
            &format!("{V2}/scrape"),
            Some(&read_only),
            &[],
            Some(&j!({ "url": rig.url("/") })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(json(&v)["code"], "scope_missing");
    rig.stop().await;
}

#[tokio::test]
async fn unknown_and_unsupported_options_warn_without_failing() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": rig.url("/"), "proxy": "basic", "bogus": 1, "origin": "api", "integration": "sdk", "onlyCleanContent": true }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let warnings = v["warnings"].as_array().unwrap();
    let codes: Vec<(&str, &str)> = warnings
        .iter()
        .map(|w| (w["code"].as_str().unwrap(), w["path"].as_str().unwrap()))
        .collect();
    assert!(!codes.iter().any(|(_, path)| *path == "/proxy"), "{codes:?}");
    assert!(codes.contains(&("unsupported_option", "/bogus")), "{codes:?}");
    assert!(
        !codes.iter().any(|(_, p)| *p == "/onlyCleanContent"),
        "onlyCleanContent is an option now (without an LLM the document warns): {codes:?}"
    );
    assert!(
        v["data"]["warning"]
            .as_str()
            .is_some_and(|w| w.contains("only_clean_content_skipped")),
        "{v}"
    );
    assert!(
        !codes.iter().any(|(_, p)| *p == "/origin" || *p == "/integration"),
        "{codes:?}"
    );
    rig.stop().await;
}

// ---- cache semantics ----------------------------------------------------------------------

#[tokio::test]
async fn max_age_serves_a_stored_scrape_without_fetching() {
    let rig = Rig::start(RigConfig::default()).await;
    let url = rig.url("/versioned");
    let first = scrape_ok(&rig, j!({ "url": url })).await;
    assert_eq!(first["metadata"]["cacheState"], "miss");
    assert!(first["markdown"].as_str().unwrap().contains("Price version 1"));
    assert_eq!(rig.site.hits("/versioned"), 1);
    rig.site.set_version(2);
    let hit = scrape_ok(&rig, j!({ "url": url })).await;
    assert_eq!(hit["metadata"]["cacheState"], "hit");
    assert!(hit["metadata"]["cachedAt"].is_string(), "{}", hit["metadata"]);
    assert!(
        hit["markdown"].as_str().unwrap().contains("Price version 1"),
        "stale content is served"
    );
    assert_eq!(rig.site.hits("/versioned"), 1, "no fetch for a hit");
    assert_eq!(hit["metadata"]["creditsUsed"], 1, "a hit costs the normal price");
    let fresh = scrape_ok(&rig, j!({ "url": url, "maxAge": 0 })).await;
    assert_eq!(fresh["metadata"]["cacheState"], "miss");
    assert!(fresh["markdown"].as_str().unwrap().contains("Price version 2"));
    assert_eq!(rig.site.hits("/versioned"), 2);
    // different shaping options never share a stored scrape
    let other = scrape_ok(&rig, j!({ "url": url, "formats": ["markdown", "links"] })).await;
    assert_eq!(other["metadata"]["cacheState"], "miss");
    rig.stop().await;
}

#[tokio::test]
async fn store_in_cache_false_and_headers_are_never_served_later() {
    let rig = Rig::start(RigConfig::default()).await;
    let url = rig.url("/versioned");
    scrape_ok(&rig, j!({ "url": url, "storeInCache": false })).await;
    let again = scrape_ok(&rig, j!({ "url": url })).await;
    assert_eq!(
        again["metadata"]["cacheState"], "miss",
        "storeInCache:false stored nothing reusable"
    );
    assert_eq!(rig.site.hits("/versioned"), 2);
    rig.stop().await;
}

#[tokio::test]
async fn min_age_and_lockdown_only_read_stored_scrapes() {
    let rig = Rig::start(RigConfig::default()).await;
    let url = rig.url("/versioned");
    let (s, _, v) = scrape(&rig, j!({ "url": url, "minAge": 1 })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    assert_compat_error(&v, "SCRAPE_NO_CACHED_DATA");
    let (s, _, v) = scrape(&rig, j!({ "url": url, "lockdown": true })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    assert_compat_error(&v, "SCRAPE_LOCKDOWN_CACHE_MISS");
    assert_eq!(rig.site.hits("/versioned"), 0, "neither fetched");
    scrape_ok(&rig, j!({ "url": url })).await;
    let aged = scrape_ok(&rig, j!({ "url": url, "minAge": 1 })).await;
    assert_eq!(aged["metadata"]["cacheState"], "hit");
    let (s, _, v) = scrape(&rig, j!({ "url": url, "minAge": 3_600_000 })).await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "a scrape younger than minAge does not count: {v}"
    );
    let locked = scrape_ok(&rig, j!({ "url": url, "lockdown": true })).await;
    assert_eq!(locked["metadata"]["cacheState"], "hit");
    assert_eq!(
        locked["metadata"]["creditsUsed"], 5,
        "lockdown hit costs 5 credits"
    );
    assert_eq!(rig.site.hits("/versioned"), 1);
    rig.stop().await;
}

// ---- x-request-id -------------------------------------------------------------------------

#[tokio::test]
async fn x_request_id_replays_conflicts_and_detects_in_flight_requests() {
    let rig = Rig::start(RigConfig::default()).await;
    let url = rig.url("/versioned");
    let body = j!({ "url": url, "maxAge": 0 });
    let post = |id: &str, body: &Value| {
        let id = id.to_owned();
        let body = body.clone();
        let env = &rig.env;
        async move {
            env.post_with(&format!("{V2}/scrape"), &[("x-request-id", id.as_str())], &body)
                .await
        }
    };
    let (s1, h1, v1) = post("req-1", &body).await;
    assert_eq!(s1, StatusCode::OK, "{v1}");
    assert_eq!(rig.site.hits("/versioned"), 1);
    let (s2, h2, v2) = post("req-1", &body).await;
    assert_eq!(s2, StatusCode::OK, "{v2}");
    assert_eq!(v2, v1, "the original response is replayed");
    assert_eq!(h2.get("idempotent-replayed").unwrap(), "true");
    assert!(h1.get("idempotent-replayed").is_none());
    assert_eq!(rig.site.hits("/versioned"), 1, "a replay does not scrape again");
    let (s3, _, v3) = post("req-1", &j!({ "url": url, "maxAge": 0, "formats": ["html"] })).await;
    assert_eq!(s3, StatusCode::CONFLICT, "{v3}");
    assert_compat_error(&v3, "duplicate_request");
    let (s4, _, v4) = post("bad id!", &body).await;
    assert_eq!(s4, StatusCode::BAD_REQUEST, "{v4}");
    assert_eq!(v4["details"][0]["path"], "/headers/x-request-id");

    let slow = j!({ "url": rig.url("/slow"), "timeout": 4000 });
    let (first, second) = tokio::join!(post("req-slow", &slow), async {
        tokio::time::sleep(Duration::from_millis(600)).await;
        post("req-slow", &slow).await
    });
    assert_eq!(second.0, StatusCode::CONFLICT, "{}", second.2);
    assert_compat_error(&second.2, "request_in_flight");
    assert_eq!(first.0, StatusCode::REQUEST_TIMEOUT, "{}", first.2);
    rig.stop().await;
}

// ---- GET /scrape/{jobId} ------------------------------------------------------------------

#[tokio::test]
async fn a_scrape_can_be_fetched_again_by_its_job_id() {
    let rig = Rig::start(RigConfig::default()).await;
    let data = scrape_ok(&rig, j!({ "url": rig.url("/a") })).await;
    let id = data["metadata"]["scrapeId"].as_str().unwrap().to_owned();
    let (s, _, v) = rig.env.get(&format!("{V2}/scrape/{id}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    assert_eq!(v["data"]["markdown"], data["markdown"]);
    assert_eq!(v["data"]["metadata"]["scrapeId"], id);
    let other_key = rig
        .env
        .key_for("someone-else", &[crawlx_api::Scope::CrawlsRead])
        .await;
    let (s, _, v) = rig.env.get_as(&other_key, &format!("{V2}/scrape/{id}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "tenant scoped: {v}");
    assert_compat_error(&v, "not_found");
    for bad in [
        uuid::Uuid::now_v7().to_string(),
        "nonsense".to_owned(),
        format!("{id}.999999"),
    ] {
        let (s, _, v) = rig.env.get(&format!("{V2}/scrape/{bad}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{bad}: {v}");
    }
    rig.stop().await;
}

// ---- usage ledger -------------------------------------------------------------------------

#[tokio::test]
async fn every_scrape_is_booked_in_the_usage_ledger() {
    let rig = Rig::start(RigConfig::default()).await;
    let data = scrape_ok(&rig, j!({ "url": rig.url("/a") })).await;
    let id: uuid::Uuid = data["metadata"]["scrapeId"].as_str().unwrap().parse().unwrap();
    let row = rig
        .env
        .state
        .repos
        .intel
        .usage_by_ref(rig.env.tenant, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.endpoint.as_str(), row.credits, row.status.as_str()),
        ("scrape", 1, "completed")
    );
    let (s, _, _) = scrape(
        &rig,
        j!({ "url": format!("http://gone.example.test:{}/", rig.site.port), "timeout": 20000 }),
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    let rows = rig
        .env
        .state
        .repos
        .intel
        .usage_recent(rig.env.tenant, Some("scrape"), 10, 0)
        .await
        .unwrap();
    assert!(
        rows.iter().any(|r| r.status == "failed" && r.credits == 0),
        "{rows:?}"
    );
    rig.stop().await;
}

// ---- zero data retention ------------------------------------------------------------------

#[tokio::test]
async fn zero_data_retention_returns_the_content_and_costs_one_more_credit() {
    let rig = Rig::start(RigConfig::default()).await;
    let data = scrape_ok(&rig, j!({ "url": rig.url("/a"), "zeroDataRetention": true })).await;
    assert!(data["markdown"].as_str().unwrap().contains("Text of A."));
    assert_eq!(data["metadata"]["creditsUsed"], 2);
    let id = data["metadata"]["scrapeId"].as_str().unwrap();
    let run = RunRepo::get(rig.env.store.as_ref(), id.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(run.config.retention.mode, crawlx_core::config::RetentionMode::Zdr);
    rig.stop().await;
}

// ---- LLM formats --------------------------------------------------------------------------

#[tokio::test]
async fn llm_formats_need_a_configured_llm_before_any_run_is_created() {
    let rig = Rig::start(RigConfig::default()).await;
    for formats in [
        j!(["summary"]),
        j!([{ "type": "json", "prompt": "x" }]),
        j!([{ "type": "question", "question": "q" }]),
    ] {
        let (s, h, v) = scrape(&rig, j!({ "url": rig.url("/"), "formats": formats })).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
        assert_compat_error(&v, "llm_not_configured");
        assert!(h.get("retry-after").is_some());
    }
    assert_eq!(rig.site.hits("/"), 0);
    rig.stop().await;
}

#[tokio::test]
async fn llm_formats_run_in_the_worker_and_are_priced() {
    let llm = llm_mock();
    let rig = Rig::start(RigConfig {
        llm: Some(llm.clone()),
        ..RigConfig::default()
    })
    .await;
    let data = scrape_ok(
        &rig,
        j!({
            "url": rig.url("/"),
            "formats": [
                "markdown", "summary",
                { "type": "json", "schema": { "type": "object", "properties": { "headline": { "type": "string" } } } },
                { "type": "question", "question": "What is the answer?" },
                { "type": "highlights", "query": "answer" }
            ],
        }),
    )
    .await;
    assert_eq!(data["summary"], "A fixture home page.");
    assert_eq!(data["json"], j!({ "headline": "Fixture Home" }));
    assert_eq!(data["answer"], "forty-two");
    assert_eq!(
        data["highlights"], "The answer is forty-two.",
        "the compat API documents highlights as one string"
    );
    assert_eq!(
        data["metadata"]["creditsUsed"], 13,
        "1 + json 4 + question 4 + highlights 4; summary is free"
    );
    let calls = llm.calls();
    assert!(calls.len() >= 4, "{}", calls.len());
    assert!(
        calls.iter().all(|c| c.user.contains("Fixture Home")),
        "the page text reaches the model"
    );
    let id: uuid::Uuid = data["metadata"]["scrapeId"].as_str().unwrap().parse().unwrap();
    let row = rig
        .env
        .state
        .repos
        .intel
        .usage_by_ref(rig.env.tenant, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.credits, 13);
    assert!(row.prompt_tokens > 0, "LLM tokens are booked: {row:?}");
    rig.stop().await;
}

#[tokio::test]
async fn a_failing_llm_is_a_500_not_a_missing_field() {
    let llm = Arc::new(MockLlm::scripted(vec![Err(LlmError::Timeout { after_ms: 5 })]));
    let rig = Rig::start(RigConfig {
        llm: Some(llm),
        ..RigConfig::default()
    })
    .await;
    let (s, _, v) = scrape(&rig, j!({ "url": rig.url("/"), "formats": ["summary"] })).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert!(v["error"].as_str().unwrap().contains("llm_failed"), "{v}");
    rig.stop().await;
}

// ---- change tracking ----------------------------------------------------------------------

#[tokio::test]
async fn change_tracking_always_fetches_and_reports_new_same_changed_with_a_diff() {
    let rig = Rig::start(RigConfig::default()).await;
    let body = j!({
        "url": rig.url("/versioned"),
        "formats": ["markdown", { "type": "changeTracking", "modes": ["git-diff"], "tag": "t1" }],
    });
    let first = scrape_ok(&rig, body.clone()).await;
    assert_eq!(first["changeTracking"]["changeStatus"], "new");
    assert_eq!(first["changeTracking"]["previousScrapeAt"], Value::Null);
    let second = scrape_ok(&rig, body.clone()).await;
    assert_eq!(second["changeTracking"]["changeStatus"], "same");
    assert!(second["changeTracking"]["previousScrapeAt"].is_string());
    rig.site.set_version(2);
    let third = scrape_ok(&rig, body.clone()).await;
    let ct = &third["changeTracking"];
    assert_eq!(ct["changeStatus"], "changed");
    // nothing on the fixture site links to `/versioned` and it has no sitemap
    assert_eq!(ct["visibility"], "hidden");
    let diff = ct["diff"]["text"].as_str().unwrap();
    assert!(
        diff.contains("-Price version 1") && diff.contains("+Price version 2"),
        "{diff}"
    );
    let other_tag = scrape_ok(
        &rig,
        j!({ "url": rig.url("/versioned"), "formats": ["markdown", { "type": "changeTracking", "tag": "t2" }] }),
    )
    .await;
    assert_eq!(
        other_tag["changeTracking"]["changeStatus"], "new",
        "tags keep separate histories"
    );
    rig.stop().await;
}

// ---- screenshots and actions (scripted renderer) ------------------------------------------

mod failing {
    use async_trait::async_trait;
    use crawlx_worker::scrape::render::{PageRenderer, RenderError, RenderRequest, Rendered};

    /// A renderer whose every render fails with the error `make` builds.
    pub struct Failing(pub fn() -> RenderError);

    #[async_trait]
    impl PageRenderer for Failing {
        async fn render(&self, _: &RenderRequest<'_>) -> Result<Rendered, RenderError> {
            Err((self.0)())
        }
    }
}

mod scripted {
    use async_trait::async_trait;
    use crawlx_core::scrape::{ActionScrape, JavascriptReturn};
    use crawlx_worker::scrape::render::{
        ActionOutputs, PageRenderer, RenderError, RenderRequest, Rendered, Shot,
    };
    use serde_json::json;

    /// Browser text as the render seam carries it: reserved against the shared budget first.
    fn admitted(text: &str) -> crawlx_core::parser_memory::AdmittedText {
        let permit = crawlx_core::parser_memory::global()
            .try_reserve(text.len())
            .unwrap();
        crawlx_core::parser_memory::AdmittedText::new(text.to_owned(), permit)
    }

    fn admitted_bytes(bytes: Vec<u8>) -> crawlx_core::parser_memory::AdmittedBytes {
        let permit = crawlx_core::parser_memory::global()
            .try_reserve(bytes.len())
            .unwrap();
        crawlx_core::parser_memory::AdmittedBytes::new(bytes, permit)
    }

    pub const PNG: &[u8] = b"\x89PNG\r\n\x1a\nscripted-screenshot";

    /// Renders every page as a fixed document with a screenshot and one result per action kind,
    /// and remembers the options of every render request.
    #[derive(Default)]
    pub struct Scripted {
        pub seen: parking_lot::Mutex<Vec<crawlx_core::scrape::ScrapeOptions>>,
    }

    #[async_trait]
    impl PageRenderer for Scripted {
        async fn render(&self, req: &RenderRequest<'_>) -> Result<Rendered, RenderError> {
            self.seen.lock().push(req.options.clone());
            Ok(Rendered {
                final_url: req.request.url.url.clone(),
                status: 200,
                headers: vec![("content-type".to_owned(), "text/html".to_owned())],
                content_type: Some("text/html".to_owned()),
                evidence: None,
                html: admitted(
                    "<html><head><title>Rendered</title></head><body><main><h1>Rendered page</h1></main></body></html>",
                ),
                screenshot: Some(Shot {
                    bytes: admitted_bytes(PNG.to_vec()),
                    content_type: "image/png",
                }),
                actions: ActionOutputs {
                    screenshots: vec![Shot {
                        bytes: admitted_bytes(PNG.to_vec()),
                        content_type: "image/png",
                    }],
                    scrapes: vec![ActionScrape {
                        url: req.request.url.url.to_string(),
                        html: admitted("<p>step</p>"),
                    }],
                    javascript_returns: vec![JavascriptReturn {
                        kind: "number".to_owned(),
                        value: json!(2),
                    }],
                    pdfs: vec![Shot {
                        bytes: admitted_bytes(super::scrape_rig::pdf(&["Scripted PDF"])),
                        content_type: "application/pdf",
                    }],
                    ..ActionOutputs::default()
                },
                computed_styles: None,
            })
        }
    }
}

#[tokio::test]
async fn screenshots_and_action_results_are_linked_to_stored_artifacts() {
    let rig = Rig::start(RigConfig {
        renderer: Some(Arc::new(scripted::Scripted::default())),
        ..RigConfig::default()
    })
    .await;
    let data = scrape_ok(
        &rig,
        j!({
            "url": rig.url("/"),
            "formats": ["markdown", { "type": "screenshot", "fullPage": true }],
            "actions": [
                { "type": "screenshot" }, { "type": "scrape" },
                { "type": "executeJavascript", "script": "1+1" }, { "type": "pdf" }
            ],
        }),
    )
    .await;
    assert!(data["markdown"].as_str().unwrap().contains("Rendered page"));
    let shot = data["screenshot"].as_str().unwrap();
    assert!(
        shot.contains("/v1/crawls/") && shot.contains("/artifacts/"),
        "{shot}"
    );
    let path = shot.split_once("/v1/").map(|(_, p)| format!("/v1/{p}")).unwrap();
    let (s, _, bytes) = rig
        .env
        .send(Method::GET, &path, Some(&rig.env.key), &[], None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(bytes.as_ref(), scripted::PNG);
    let a = &data["actions"];
    assert_eq!(a["screenshots"].as_array().unwrap().len(), 1);
    assert_eq!(a["scrapes"], j!([{ "url": rig.url("/"), "html": "<p>step</p>" }]));
    assert_eq!(a["javascriptReturns"], j!([{ "type": "number", "value": 2 }]));
    let pdf_path = a["pdfs"][0]
        .as_str()
        .unwrap()
        .split_once("/v1/")
        .map(|(_, p)| format!("/v1/{p}"))
        .unwrap();
    let (s, _, pdf) = rig
        .env
        .send(Method::GET, &pdf_path, Some(&rig.env.key), &[], None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(pdf.starts_with(b"%PDF"));
    rig.stop().await;
}

#[tokio::test]
async fn real_chromium_screenshots_and_actions() {
    let Some(rig) = Rig::start_chromium(RigConfig::default()).await else {
        eprintln!("skipped: set CRAWLX_CHROMIUM_PATH");
        return;
    };
    let data = scrape_ok(
        &rig,
        j!({
            "url": rig.url("/"),
            "formats": ["markdown", { "type": "screenshot" }],
            "actions": [
                { "type": "wait", "selector": "body", "state": "visible" },
                { "type": "wait", "selector": "#sp09-missing", "state": "hidden" },
                { "type": "wait", "selector": "#sp09-missing", "state": "detached" },
                { "type": "executeJavascript", "script": "document.title" },
                { "type": "scrape" }
            ],
            "waitFor": 100,
        }),
    )
    .await;
    let shot = data["screenshot"].as_str().unwrap();
    let path = shot.split_once("/v1/").map(|(_, p)| format!("/v1/{p}")).unwrap();
    let (s, _, bytes) = rig
        .env
        .send(Method::GET, &path, Some(&rig.env.key), &[], None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(bytes.starts_with(b"\x89PNG"), "a real PNG");
    assert_eq!(data["actions"]["javascriptReturns"][0]["value"], "Fixture Home");
    assert!(data["actions"]["scrapes"][0]["html"]
        .as_str()
        .unwrap()
        .contains("Fixture Home"));
    rig.stop().await;
}

// ---- batch scrape -------------------------------------------------------------------------

async fn batch(rig: &Rig, body: Value) -> (StatusCode, HeaderMap, Value) {
    rig.env.post(&format!("{V2}/batch/scrape"), &body).await
}

#[tokio::test]
async fn batch_scrape_runs_to_completion_with_paging_and_credits() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = batch(
        &rig,
        j!({ "urls": [rig.url("/a"), "not a url", rig.url("/b"), rig.url("/c"), rig.url("/a")], "formats": ["markdown", "links"] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    assert_eq!(v["invalidURLs"], j!(["not a url"]));
    let id = v["id"].as_str().unwrap().to_owned();
    assert!(
        v["url"]
            .as_str()
            .unwrap()
            .ends_with(&format!("{V2}/batch/scrape/{id}")),
        "{v}"
    );
    let done = wait_batch(&rig, &id, "completed").await;
    assert_eq!(
        (
            done["total"].clone(),
            done["completed"].clone(),
            done["creditsUsed"].clone()
        ),
        (j!(3), j!(3), j!(3))
    );
    assert!(done["expiresAt"].is_string() && done["next"].is_null());
    let docs = done["data"].as_array().unwrap();
    assert_eq!(docs.len(), 3);
    let titles: Vec<&str> = docs
        .iter()
        .map(|d| d["metadata"]["title"].as_str().unwrap())
        .collect();
    for t in ["Page A", "Page B", "Page C"] {
        assert!(titles.contains(&t), "{titles:?}");
    }
    assert!(docs
        .iter()
        .all(|d| d["links"].is_array() && d["metadata"]["scrapeId"].as_str().unwrap().starts_with(&id)));

    // paging with skip/limit
    let (_, _, p1) = rig.env.get(&format!("{V2}/batch/scrape/{id}?limit=2")).await;
    assert_eq!(p1["data"].as_array().unwrap().len(), 2);
    let next = p1["next"].as_str().unwrap();
    assert!(next.contains("skip=2") && next.contains("limit=2"), "{next}");
    let path = format!("{V2}{}", next.split_once(V2).unwrap().1);
    let (_, _, p2) = rig.env.get(&path).await;
    assert_eq!(p2["data"].as_array().unwrap().len(), 1);
    assert!(p2["next"].is_null());
    assert_ne!(
        p1["data"][0]["metadata"]["scrapeId"],
        p2["data"][0]["metadata"]["scrapeId"]
    );

    // one page by its `{run}.{frontier}` job id
    let page_id = docs[0]["metadata"]["scrapeId"].as_str().unwrap();
    let (s, _, one) = rig.env.get(&format!("{V2}/scrape/{page_id}")).await;
    assert_eq!(s, StatusCode::OK, "{one}");
    assert_eq!(one["data"]["markdown"], docs[0]["markdown"]);

    // batch and scrape ids live in separate namespaces
    let (s, _, _) = rig.env.get(&format!("{V2}/scrape/{id}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "a batch run id is not a scrape job id");

    // the finished batch is booked once, however often it is read
    rig.env.get(&format!("{V2}/batch/scrape/{id}")).await;
    let run_id: uuid::Uuid = id.parse().unwrap();
    let row = rig
        .env
        .state
        .repos
        .intel
        .usage_by_ref(rig.env.tenant, run_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((row.endpoint.as_str(), row.credits), ("batch_scrape", 3));
    let rows = rig
        .env
        .state
        .repos
        .intel
        .usage_recent(rig.env.tenant, Some("batch_scrape"), 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    rig.stop().await;
}

#[tokio::test]
async fn batch_validation_and_ignore_invalid_urls() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = batch(
        &rig,
        j!({ "urls": [rig.url("/a"), "nope"], "ignoreInvalidURLs": false }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["details"][0]["path"], "/urls/1");
    let (s, _, v) = batch(&rig, j!({ "urls": ["nope", "http://10.1.2.3/"] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "no valid URL: {v}");
    let (s, _, v) = batch(&rig, j!({ "urls": [] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _, v) = batch(&rig, j!({ "formats": ["nope"] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let paths: Vec<&str> = v["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"/urls") && paths.contains(&"/formats/0/type"),
        "{paths:?}"
    );
    let (s, _, v) = batch(&rig, j!({ "urls": [rig.url("/a")], "ignoreInvalidURLs": false })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v.get("invalidURLs").is_none(),
        "undefined when ignoreInvalidURLs is false: {v}"
    );
    let (s, _, v) = batch(
        &rig,
        j!({ "urls": [rig.url("/a")], "webhook": { "url": "http://127.0.0.1/hook" } }),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "a private webhook target is refused: {v}"
    );
    let (s, _, v) = rig
        .env
        .get(&format!("{V2}/batch/scrape/{}", uuid::Uuid::now_v7()))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    rig.stop().await;
}

#[tokio::test]
async fn batch_errors_list_failed_pages_and_scrapes_do_not_consult_robots() {
    // Authorize the failing origin without resolving it, so it reaches DNS failure rather than
    // being filtered out as an authorization-scope denial before scraping.
    let rig = Rig::start(RigConfig {
        additional_authorization_hosts: vec!["gone.example.test".to_owned()],
        ..RigConfig::default()
    })
    .await;
    let gone = format!("http://gone.example.test:{}/x", rig.site.port);
    let (s, _, v) = batch(&rig, j!({ "urls": [rig.url("/a"), gone, rig.url("/private/x")] })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    wait_batch(&rig, &id, "completed").await;
    let (s, _, e) = rig.env.get(&format!("{V2}/batch/scrape/{id}/errors")).await;
    assert_eq!(s, StatusCode::OK, "{e}");
    let errors = e["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{e}");
    assert_eq!(errors[0]["url"], gone);
    assert!(errors[0]["id"].as_str().unwrap().starts_with(&id));
    assert!(errors[0]["timestamp"].is_string());
    assert_eq!(errors[0]["code"], "dns_failed", "{e}");
    assert!(
        errors[0]["error"]
            .as_str()
            .unwrap()
            .contains("reason: dns_failed"),
        "{e}"
    );
    // The compat API scrapes the URLs it is given: robots.txt is a crawl concern, so nothing is blocked
    assert_eq!(e["robotsBlocked"], j!([]));
    assert_eq!(rig.site.hits("/robots.txt"), 0);
    assert_eq!(rig.site.hits("/private/x"), 1);
    let (s, _, status) = rig.env.get(&format!("{V2}/batch/scrape/{id}")).await;
    assert_eq!(s, StatusCode::OK, "{status}");
    assert_eq!(
        (status["total"].clone(), status["completed"].clone()),
        (j!(3), j!(2))
    );
    let sources: std::collections::BTreeSet<_> = status["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|document| document["metadata"]["sourceURL"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        sources,
        std::collections::BTreeSet::from([rig.url("/a"), rig.url("/private/x")]),
        "{status}"
    );
    let (s, _, e) = rig
        .env
        .get(&format!("{V2}/batch/scrape/{}/errors", uuid::Uuid::now_v7()))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{e}");
    rig.stop().await;
}

#[tokio::test]
async fn batch_can_be_cancelled_and_stays_cancelled() {
    let rig = Rig::start(RigConfig::default()).await;
    let (_, _, v) = batch(
        &rig,
        j!({ "urls": [rig.url("/slow?i=1"), rig.url("/slow?i=2"), rig.url("/slow?i=3")], "maxConcurrency": 1, "timeout": 30000 }),
    )
    .await;
    let id = v["id"].as_str().unwrap().to_owned();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (s, _, c) = rig.env.delete(&format!("{V2}/batch/scrape/{id}")).await;
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["status"], "cancelled");
    let st = wait_batch(&rig, &id, "cancelled").await;
    assert_eq!(st["total"], 3);
    assert!(st["completedAt"].is_string());
    let (s, _, e) = rig.env.delete(&format!("{V2}/batch/scrape/{id}")).await;
    assert_eq!(s, StatusCode::OK, "cancel is idempotent by state: {e}");
    rig.stop().await;
}

#[tokio::test]
async fn batch_webhook_headers_metadata_and_events_are_stored_on_the_run() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = batch(
        &rig,
        j!({
            "urls": [rig.url("/a"), rig.url("/b")],
            "maxConcurrency": 2,
            "webhook": {
                "url": "https://hooks.example.test/fc",
                "headers": { "X-Auth": "tok" },
                "metadata": { "job": "nightly" },
                "events": ["batch_scrape.page", "completed"]
            },
            "headers": { "X-Site-Token": "t0k" },
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let run = RunRepo::get(rig.env.store.as_ref(), v["id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap();
    let job = run.config.scrape.as_ref().unwrap();
    assert_eq!(job.kind, JobKind::Batch);
    assert_eq!(job.kind.event_prefix(), "batch_scrape");
    assert_eq!(job.webhook_headers.get("X-Auth").map(String::as_str), Some("tok"));
    assert_eq!(job.webhook_metadata, j!({ "job": "nightly" }));
    assert_eq!(job.urls.len(), 1);
    let hook = run.config.output.webhook.as_ref().unwrap();
    assert_eq!(hook.url.as_str(), "https://hooks.example.test/fc");
    assert_eq!(hook.events, vec!["page".to_owned(), "completed".to_owned()]);
    assert_eq!(run.config.politeness.max_concurrency, 2);
    assert_eq!(run.config.mode, CrawlMode::Static);
    assert_eq!(run.config.limits.urls, 2);
    let (_, _, resource) = rig.env.get(&format!("/v1/crawls/{}", run.id)).await;
    let text = resource.to_string();
    assert!(
        !text.contains("t0k"),
        "request header values never leave the API: {text}"
    );
    // string form: default events
    let (s, _, v) = batch(
        &rig,
        j!({ "urls": [rig.url("/c")], "webhook": "https://hooks.example.test/two" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let run = RunRepo::get(rig.env.store.as_ref(), v["id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        run.config.output.webhook.unwrap().events,
        ["started", "page", "completed", "failed"]
            .map(str::to_owned)
            .to_vec()
    );
    rig.stop().await;
}

// ---- health probes ------------------------------------------------------------------------

#[tokio::test]
async fn health_probes_need_no_authentication() {
    let env = common::env();
    for path in ["/v0/health/readiness", "/v0/health/liveness"] {
        let (s, _, b) = env.send(Method::GET, path, None, &[], None).await;
        assert_eq!(s, StatusCode::OK, "{path}");
        assert_eq!(json(&b)["status"], "ok", "{path}");
    }
}

// ---- read side over hand-built pages (no worker) --------------------------------------------

/// A finished batch run with one stored page whose document, blobs and options the caller shapes.
struct Planted {
    run: CrawlRun,
    page: PageRecord,
}

async fn plant(
    env: &Env,
    kind: JobKind,
    options: ScrapeOptions,
    zdr: bool,
    markdown: Option<&[u8]>,
    build: impl FnOnce(&mut ScrapeDocument, &mut PageRecord),
) -> Planted {
    let mut crawl = CreateCrawl::new("https://stored.example.test/p".parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.scrape = Some(ScrapeJob::new(kind, options));
    if zdr {
        crawl.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    }
    crawl.normalize().unwrap();
    let mut run = testkit::crawl_run(env.tenant, crawl);
    run.status = RunStatus::Queued;
    RunRepo::create(env.store.as_ref(), &run, None).await.unwrap();
    RunRepo::set_status(env.store.as_ref(), run.id, RunStatus::Running, None)
        .await
        .unwrap();
    RunRepo::set_status(
        env.store.as_ref(),
        run.id,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    let run = RunRepo::get(env.store.as_ref(), run.id).await.unwrap();
    let mut doc = ScrapeDocument::new(
        "https://stored.example.test/p".into(),
        "https://stored.example.test/p".into(),
        200,
        Digest::of("t", b"x"),
    );
    doc.content_type = Some("text/html".into());
    let md_ref = match markdown {
        Some(b) => Some(
            env.artifacts
                .put(run.id, Sensitivity::Content, "text/markdown", b)
                .await
                .unwrap(),
        ),
        None => None,
    };
    let mut page = PageRecord {
        run: run.id,
        frontier_id: 1,
        url: testkit::canonical_url("https://stored.example.test/p"),
        status: 200,
        content_type: Some("text/html".into()),
        content_digest: Digest::of("c", b"x"),
        title: Some("Stored".into()),
        markdown: md_ref,
        html: None,
        metadata: j!({}),
        links: vec!["https://stored.example.test/q".into()],
        fetched_at: SystemClock.now(),
        lane: TrustLane::Diagnostic,
    };
    build(&mut doc, &mut page);
    page.metadata = j!({ "scrape": doc });
    PageRepo::put(env.store.as_ref(), &page).await.unwrap();
    Planted { run, page }
}

#[tokio::test]
async fn stored_blobs_are_inlined_linked_or_base64_encoded() {
    let env = common::env();
    let opts = ScrapeOptions {
        formats: vec![
            FormatSpec::Markdown,
            FormatSpec::RawHtml,
            FormatSpec::Screenshot {
                full_page: false,
                quality: None,
                viewport: None,
            },
            FormatSpec::Links,
        ],
        ..ScrapeOptions::default()
    };
    let p = plant(&env, JobKind::Scrape, opts, false, Some(b"# Stored"), |_, _| {}).await;
    // blobs of the same run, attached once the run id is known
    let raw = env
        .artifacts
        .put(p.run.id, Sensitivity::Content, "text/html", b"<p>raw</p>")
        .await
        .unwrap();
    let shot = env
        .artifacts
        .put(p.run.id, Sensitivity::Content, "image/png", b"PNGDATA")
        .await
        .unwrap();
    let mut doc = ScrapeDocument::from_page_metadata(&p.page.metadata).unwrap();
    doc.proxy_used = crawlx_core::scrape::ProxyMode::Enhanced;
    doc.raw_html = Some(BlobRef {
        artifact: raw,
        content_type: "text/html".into(),
        size: 10,
    });
    doc.screenshot = Some(BlobRef {
        artifact: shot.clone(),
        content_type: "image/png".into(),
        size: 7,
    });
    let mut page = p.page.clone();
    page.metadata = j!({ "scrape": doc });
    PageRepo::put(env.store.as_ref(), &page).await.unwrap();
    let data =
        crawlx_api::scrape_service::compat_document(&env.state, &p.run, &page, "https://api.test").await;
    assert_eq!(data["markdown"], "# Stored");
    assert_eq!(data["rawHtml"], "<p>raw</p>");
    assert_eq!(data["links"], j!(["https://stored.example.test/q"]));
    assert_eq!(
        data["screenshot"],
        format!("https://api.test/v1/crawls/{}/artifacts/{}", p.run.id, shot.id)
    );
    assert_eq!(data["metadata"]["scrapeId"], p.run.id.to_string());
    assert_eq!(data["metadata"]["title"], "Stored");
    assert_eq!(data["metadata"]["proxyUsed"], "enhanced");

    // rawBase64 must be the only format: the bare bytes, base64 encoded, not a data URI
    let only = ScrapeOptions {
        formats: vec![FormatSpec::RawBase64],
        ..ScrapeOptions::default()
    };
    let p = plant(&env, JobKind::Scrape, only, false, None, |_, _| {}).await;
    let body = env
        .artifacts
        .put(
            p.run.id,
            Sensitivity::Content,
            "application/octet-stream",
            b"\x00\x01\x02",
        )
        .await
        .unwrap();
    let mut doc = ScrapeDocument::from_page_metadata(&p.page.metadata).unwrap();
    doc.raw_base64 = Some(BlobRef {
        artifact: body,
        content_type: "application/octet-stream".into(),
        size: 3,
    });
    let mut page = p.page.clone();
    page.metadata = j!({ "scrape": doc });
    let data = crawlx_api::scrape_service::compat_document(&env.state, &p.run, &page, "").await;
    assert_eq!(data["rawBase64"], "AAEC");
    assert!(data.get("markdown").is_none(), "{data}");
}

#[tokio::test]
async fn content_above_the_inline_limit_is_linked_not_inlined() {
    let (env, _) = common::env_with_zdr(
        crawlx_api::ApiConfig {
            rate_limit_per_minute: 0,
            ..crawlx_api::ApiConfig::default()
        },
        crawlx_api::Settings {
            inline_max_bytes: 8,
            ..crawlx_api::Settings::default()
        },
        Arc::new(SystemClock),
    );
    let p = plant(
        &env,
        JobKind::Batch,
        ScrapeOptions::default(),
        false,
        Some(b"this markdown is longer than eight bytes"),
        |_, _| {},
    )
    .await;
    let data = crawlx_api::scrape_service::compat_document(&env.state, &p.run, &p.page, "").await;
    assert_eq!(data["markdown"], Value::Null);
    let link = data["metadata"]["crawlx"]["markdownRef"].as_str().unwrap();
    assert!(link.contains("/artifacts/"), "{link}");
    assert_eq!(
        data["metadata"]["scrapeId"],
        format!("{}.{}", p.run.id, p.page.frontier_id),
        "pages of batch runs are {{run}}.{{frontier}}"
    );
}

#[tokio::test]
async fn pdf_pages_cost_one_credit_each_and_report_page_counts() {
    let env = common::env();
    let p = plant(
        &env,
        JobKind::Batch,
        ScrapeOptions::default(),
        false,
        Some(b"pdf text"),
        |doc, page| {
            doc.num_pages = Some(5);
            doc.total_pages = Some(9);
            doc.content_type = Some("application/pdf".into());
            page.content_type = Some("application/pdf".into());
        },
    )
    .await;
    let (s, _, v) = env.get(&format!("{V2}/batch/scrape/{}", p.run.id)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["creditsUsed"], 5);
    let m = &v["data"][0]["metadata"];
    assert_eq!(
        (
            m["numPages"].clone(),
            m["totalPages"].clone(),
            m["contentType"].clone()
        ),
        (j!(5), j!(9), j!("application/pdf"))
    );
    assert_eq!(m["creditsUsed"], 5);
    assert_eq!(credits(&p), 5);
}

fn credits(p: &Planted) -> u64 {
    crawlx_api::scrape_service::credits_for(&p.run, &p.page)
}

#[tokio::test]
async fn every_optional_field_of_a_stored_document_is_rendered() {
    let env = common::env();
    let opts = ScrapeOptions {
        formats: vec![
            FormatSpec::Markdown,
            FormatSpec::Json {
                schema: None,
                prompt: Some("p".into()),
            },
        ],
        ..ScrapeOptions::default()
    };
    let p = plant(&env, JobKind::Scrape, opts, false, Some(b"x"), |doc, _| {
        doc.images = Some(vec!["https://stored.example.test/i.png".into()]);
        doc.summary = Some("sum".into());
        doc.json = Some(j!({ "k": 1 }));
        doc.answer = Some("ans".into());
        doc.highlights = Some(vec!["h1".into(), "h2".into()]);
        doc.query = Some("q-out".into());
        doc.branding = Some(j!({ "colorScheme": "dark" }));
        doc.warning = Some("careful".into());
        doc.outputs = Some(j!({"discoveryScope": "whole_page", "rawHtml": "not requested"}));
        doc.error = Some("Not Found".into());
        doc.status_code = 404;
        doc.cache_state = CacheState::Hit;
        doc.cached_at = Some("2026-10-01T00:00:00Z".into());
        doc.meta.insert("ogTitle".into(), j!("OG"));
        doc.actions = Some(ActionResults::default());
    })
    .await;
    let data = crawlx_api::scrape_service::compat_document(&env.state, &p.run, &p.page, "").await;
    assert_eq!(data["images"], j!(["https://stored.example.test/i.png"]));
    assert_eq!(data["summary"], "sum");
    assert_eq!(data["json"], j!({ "k": 1 }));
    assert_eq!(data["answer"], "ans");
    assert_eq!(data["highlights"], "h1\n\nh2");
    assert!(
        data.get("query").is_none(),
        "the query answer shares `answer`: {data}"
    );
    assert_eq!(data["branding"]["colorScheme"], "dark");
    assert_eq!(data["warning"], "careful");
    assert!(
        data.get("outputs").is_none(),
        "unselected stored outputs must stay absent"
    );
    assert_eq!(
        data["actions"],
        j!({ "screenshots": [], "scrapes": [], "javascriptReturns": [], "pdfs": [] })
    );
    let m = &data["metadata"];
    assert_eq!(m["statusCode"], 404);
    assert_eq!(m["error"], "Not Found");
    assert_eq!(m["cacheState"], "hit");
    assert_eq!(m["cachedAt"], "2026-10-01T00:00:00Z");
    assert_eq!(m["ogTitle"], "OG");
    assert_eq!(m["creditsUsed"], 1, "an error page costs its base credit only");
}

#[tokio::test]
async fn pages_of_runs_without_a_scrape_job_keep_the_native_document() {
    let env = common::env();
    let mut crawl = CreateCrawl::new("https://plain.example.test/".parse().unwrap());
    crawl.mode = CrawlMode::Static;
    let mut run = testkit::crawl_run(env.tenant, crawl);
    run.status = RunStatus::Queued;
    RunRepo::create(env.store.as_ref(), &run, None).await.unwrap();
    let page = PageRecord {
        run: run.id,
        frontier_id: 1,
        url: testkit::canonical_url("https://plain.example.test/"),
        status: 200,
        content_type: Some("text/html".into()),
        content_digest: Digest::of("c", b"y"),
        title: Some("Plain".into()),
        markdown: None,
        html: None,
        metadata: j!({}),
        links: vec![],
        fetched_at: SystemClock.now(),
        lane: TrustLane::Diagnostic,
    };
    let data = crawlx_api::scrape_service::compat_document(&env.state, &run, &page, "").await;
    assert_eq!(data["metadata"]["title"], "Plain");
    assert!(data["metadata"]["crawlx"].is_object(), "native shape: {data}");
    assert_eq!(crawlx_api::scrape_service::credits_for(&run, &page), 1);
}

#[tokio::test]
async fn unfinished_scrapes_report_scraping_and_other_runs_are_not_batches() {
    let env = common::env();
    let mut crawl = CreateCrawl::new("https://queued.example.test/".parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, ScrapeOptions::default()));
    crawl.normalize().unwrap();
    let run = testkit::crawl_run(env.tenant, crawl);
    RunRepo::create(env.store.as_ref(), &run, None).await.unwrap();
    let (s, _, v) = env.get(&format!("{V2}/scrape/{}", run.id)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "scraping");
    let (s, _, v) = env.get(&format!("{V2}/batch/scrape/{}", run.id)).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "a scrape run is not a batch: {v}");
    let (s, _, v) = env.get(&format!("{V2}/scrape/{}.1", run.id)).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "no such frontier row: {v}");
}

#[tokio::test]
async fn browser_options_reach_the_renderer_and_plain_scrapes_never_do() {
    let renderer = Arc::new(scripted::Scripted::default());
    let rig = Rig::start(RigConfig {
        renderer: Some(renderer.clone()),
        ..RigConfig::default()
    })
    .await;
    scrape_ok(&rig, j!({ "url": rig.url("/a") })).await;
    assert!(
        renderer.seen.lock().is_empty(),
        "an HTTP-plane scrape needs no browser"
    );
    scrape_ok(
        &rig,
        j!({
            "url": rig.url("/b"),
            "waitFor": 250,
            "mobile": true,
            "blockAds": false,
            "location": { "country": "DE", "languages": ["de-DE", "en"] },
            "actions": [
                { "type": "wait", "milliseconds": 10 },
                { "type": "click", "selector": "#x", "all": true },
                { "type": "wait", "selector": "#ready", "state": "visible" }
            ],
            "timeout": 20000,
        }),
    )
    .await;
    let seen = renderer.seen.lock().clone();
    assert_eq!(seen.len(), 1);
    let o = &seen[0];
    assert_eq!(
        (o.wait_for_ms, o.mobile, o.block_ads, o.timeout_ms),
        (250, true, false, 20_000)
    );
    let loc = o.location.as_ref().unwrap();
    assert_eq!(loc.country.as_deref(), Some("DE"));
    assert_eq!(loc.languages, vec!["de-DE".to_owned(), "en".to_owned()]);
    assert_eq!(o.actions.len(), 3);
    assert!(matches!(
        &o.actions[2],
        crawlx_core::scrape::ScrapeAction::Wait {
            state: crawlx_core::page_op::SelectorState::Visible,
            selector: Some(selector),
            ..
        } if selector == "#ready"
    ));
    assert!(!o.store_in_cache, "actions force storeInCache=false");
    assert!(
        o.skip_tls_verification,
        "the compat API defaults skipTlsVerification to true"
    );
    rig.stop().await;
}

#[tokio::test]
async fn the_scrape_routes_are_authenticated_and_listed_in_the_openapi_document() {
    let env = common::env();
    for (method, path) in [
        (Method::POST, format!("{V2}/scrape")),
        (Method::GET, format!("{V2}/scrape/{}", uuid::Uuid::now_v7())),
        (Method::POST, format!("{V2}/batch/scrape")),
        (Method::GET, format!("{V2}/batch/scrape/{}", uuid::Uuid::now_v7())),
        (
            Method::DELETE,
            format!("{V2}/batch/scrape/{}", uuid::Uuid::now_v7()),
        ),
        (
            Method::GET,
            format!("{V2}/batch/scrape/{}/errors", uuid::Uuid::now_v7()),
        ),
    ] {
        let (s, _, b) = env.send(method.clone(), &path, None, &[], None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(json(&b)["code"], "unauthenticated");
    }
    let (_, _, doc) = env.get("/v1/openapi.json").await;
    let paths = &doc["paths"];
    for (method, path) in [
        ("post", "/compat/v2/scrape"),
        ("get", "/compat/v2/scrape/{jobId}"),
        ("post", "/compat/v2/batch/scrape"),
        ("get", "/compat/v2/batch/scrape/{id}"),
        ("delete", "/compat/v2/batch/scrape/{id}"),
        ("get", "/compat/v2/batch/scrape/{id}/errors"),
    ] {
        assert!(paths[path][method].is_object(), "{method} {path}");
    }
    assert_eq!(
        paths["/compat/v2/scrape"]["post"]["security"][0]["bearerAuth"][0],
        "crawls:write"
    );
}

/// A render failure, the response it must produce, the accepted the compat API codes and the worker's
/// reason the message names.
type Case = (
    fn() -> crawlx_worker::scrape::render::RenderError,
    StatusCode,
    &'static [&'static str],
    &'static str,
);

#[tokio::test]
async fn render_failures_and_unsupported_content_map_to_their_compat_codes() {
    let cases: [Case; 4] = [
        (
            || crawlx_worker::scrape::render::RenderError::Action {
                index: 0,
                kind: "click",
                reason: "selector_not_found".to_owned(),
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &["SCRAPE_ACTION_ERROR"],
            "action_failed",
        ),
        (
            || crawlx_worker::scrape::render::RenderError::Browser("crashed".to_owned()),
            StatusCode::INTERNAL_SERVER_ERROR,
            &["SCRAPE_ALL_ENGINES_FAILED"],
            "render_failed",
        ),
        (
            || crawlx_worker::scrape::render::RenderError::EgressDenied("private range".to_owned()),
            StatusCode::FORBIDDEN,
            &["UNSUPPORTED_SITE"],
            "egress_denied",
        ),
        (
            || {
                crawlx_worker::scrape::render::RenderError::Navigation(
                    "net::ERR_CONNECTION_REFUSED".to_owned(),
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &["SCRAPE_SITE_ERROR", "SCRAPE_DNS_RESOLUTION_ERROR"],
            "unreachable",
        ),
    ];
    for (make, status, codes, reason) in cases {
        let rig = Rig::start(RigConfig {
            renderer: Some(Arc::new(failing::Failing(make))),
            ..RigConfig::default()
        })
        .await;
        let (s, _, v) = scrape(&rig, j!({ "url": rig.url("/"), "waitFor": 10 })).await;
        assert_eq!(s, status, "{reason}: {v}");
        assert!(codes.contains(&v["code"].as_str().unwrap()), "{reason}: {v}");
        assert!(
            v["error"].as_str().unwrap().contains(reason),
            "the worker's reason is reported: {v}"
        );
        rig.stop().await;
    }
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = scrape(&rig, j!({ "url": rig.url("/binary") })).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_compat_error(&v, "SCRAPE_UNSUPPORTED_FILE_ERROR");
    rig.stop().await;
}

// ---- the safety profile of caller-authored actions ----------------------------------------

#[tokio::test]
async fn click_write_and_press_raise_the_run_to_test_environment_and_warn() {
    let rig = Rig::start(RigConfig {
        renderer: Some(Arc::new(scripted::Scripted::default())),
        ..RigConfig::default()
    })
    .await;
    let run_of = |data: &Value| -> crawlx_core::repo::CrawlRun {
        let id = data["metadata"]["scrapeId"].as_str().unwrap().parse().unwrap();
        futures::executor::block_on(RunRepo::get(rig.env.store.as_ref(), id)).unwrap()
    };
    for action in [
        j!({ "type": "click", "selector": "#go" }),
        j!({ "type": "write", "text": "hi" }),
        j!({ "type": "press", "key": "Enter" }),
    ] {
        let (s, _, v) = scrape(&rig, j!({ "url": rig.url("/"), "actions": [action] })).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let w = v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["code"] == "actions_profile_raised");
        assert_eq!(w.unwrap()["path"], "/actions", "{v}");
        let run = run_of(&v["data"]);
        assert_eq!(run.config.safety.profile, SafetyProfile::TestEnvironment);
        assert_eq!(run.config.safety.destructive_actions, DestructiveActions::Deny);
        assert_eq!(
            run.config.safety.external_communication,
            ExternalCommunication::Deny
        );
        assert!(
            run.config.safety.authorization_record_ref.is_none(),
            "no authorization record needed"
        );
    }
    // actions that never need the raise leave the default profile and add no warning
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": rig.url("/"), "actions": [
            { "type": "wait", "milliseconds": 10 }, { "type": "scroll" }, { "type": "screenshot" },
            { "type": "scrape" }, { "type": "executeJavascript", "script": "1" }, { "type": "pdf" }
        ] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v.get("warnings").is_none(), "{v}");
    assert_eq!(run_of(&v["data"]).config.safety.profile, SafetyProfile::ReadOnly);
    // and so does a plain scrape
    let data = scrape_ok(&rig, j!({ "url": rig.url("/a") })).await;
    assert_eq!(run_of(&data).config.safety.profile, SafetyProfile::ReadOnly);
    rig.stop().await;
}

#[tokio::test]
async fn real_chromium_clicks_a_plain_button_and_still_refuses_a_delete_control() {
    let Some(rig) = Rig::start_chromium(RigConfig::default()).await else {
        eprintln!("skipped: set CRAWLX_CHROMIUM_PATH");
        return;
    };
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": rig.url("/interactive"), "actions": [
            { "type": "click", "selector": "#go" },
            { "type": "click", "selector": "#q" },
            { "type": "write", "text": "abc" },
            { "type": "wait", "milliseconds": 50 },
            { "type": "scrape" }
        ] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let md = v["data"]["markdown"].as_str().unwrap();
    assert!(
        md.contains("clicked") && md.contains("typed:abc"),
        "the actions ran: {md}"
    );
    assert!(v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w["code"] == "actions_profile_raised"));
    let data = scrape_ok(
        &rig,
        j!({ "url": rig.url("/interactive"), "actions": [
            { "type": "click", "selector": "#q" }, { "type": "press", "key": "Enter" }
        ] }),
    )
    .await;
    assert!(
        data["markdown"].as_str().unwrap().contains("entered"),
        "{}",
        data["markdown"]
    );

    let (s, _, v) = scrape(
        &rig,
        j!({ "url": rig.url("/interactive"), "actions": [{ "type": "click", "selector": "#danger" }] }),
    )
    .await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_compat_error(&v, "SCRAPE_ACTION_ERROR");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains("action_failed") && msg.contains("denied"),
        "the denial is reported: {msg}"
    );
    assert_eq!(
        rig.site.hits("/delete"),
        0,
        "the destructive request was never sent"
    );
    rig.stop().await;
}

// ---- PDF parsers ---------------------------------------------------------------------------

#[tokio::test]
async fn pdf_parsers_follow_the_openapi_options_end_to_end() {
    let rig = Rig::start(RigConfig::default()).await;
    let url = rig.url("/doc.pdf");
    // default parsers: every page is parsed, 1 credit per page
    let data = scrape_ok(&rig, j!({ "url": url })).await;
    let md = data["markdown"].as_str().unwrap();
    assert!(
        md.contains("Alpha page one") && md.contains("Gamma page three"),
        "{md}"
    );
    let m = &data["metadata"];
    assert_eq!((m["numPages"].clone(), m["totalPages"].clone()), (j!(3), j!(3)));
    assert_eq!(m["creditsUsed"], 3);
    assert_eq!(m["contentType"], "application/pdf");
    assert!(data.get("pages").is_none() && data.get("blocks").is_none());
    // maxPages caps the parse, totalPages keeps the true count; pageMarkers + pages
    let data = scrape_ok(
        &rig,
        j!({ "url": url, "parsers": [{ "type": "pdf", "maxPages": 2, "pages": true, "pageMarkers": true }] }),
    )
    .await;
    let md = data["markdown"].as_str().unwrap();
    assert!(
        md.contains("<!-- page 2 -->") && md.contains("Beta page two") && !md.contains("Gamma"),
        "{md}"
    );
    assert_eq!(
        (
            data["metadata"]["numPages"].clone(),
            data["metadata"]["totalPages"].clone()
        ),
        (j!(2), j!(3))
    );
    assert_eq!(data["metadata"]["creditsUsed"], 2);
    let pages = data["pages"].as_array().unwrap();
    assert_eq!(pages.len(), 2, "{pages:?}");
    assert_eq!(pages[0]["pageNumber"], 1);
    assert!(pages[0]["markdown"].as_str().unwrap().contains("Alpha page one"));
    assert!(pages[1]["markdown"].as_str().unwrap().contains("Beta page two"));
    // blocks: the compat API's per-page typed layout blocks
    let data = scrape_ok(
        &rig,
        j!({ "url": url, "parsers": [{ "type": "pdf", "blocks": true }] }),
    )
    .await;
    let blocks = data["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0]["pageNumber"], 1);
    assert!(
        blocks[0]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["content"].as_str().is_some_and(|c| c.contains("Alpha"))),
        "{}",
        blocks[0]
    );
    // an empty list: the PDF is not parsed, one flat credit, no page count
    let data = scrape_ok(&rig, j!({ "url": url, "parsers": [] })).await;
    assert_eq!(data["metadata"]["creditsUsed"], 1);
    assert!(data["metadata"].get("numPages").is_none(), "{}", data["metadata"]);
    // ocr mode extracts the text layer and warns
    let (s, _, v) = scrape(
        &rig,
        j!({ "url": url, "parsers": [{ "type": "pdf", "mode": "ocr" }], "maxAge": 0 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["data"]["markdown"].as_str().unwrap().contains("Alpha page one"));
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "ocr_unavailable" && w["path"] == "/parsers/0/mode"),
        "{v}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn stored_pdf_pages_and_blocks_are_rendered_verbatim() {
    let env = common::env();
    let opts = ScrapeOptions {
        parsers: vec![ParserSpec::Pdf {
            mode: PdfMode::Auto,
            max_pages: None,
            pages: true,
            blocks: true,
            page_markers: false,
        }],
        ..ScrapeOptions::default()
    };
    let blocks = j!([{ "pageNumber": 1, "width": 612.0, "height": 792.0, "status": "ok",
        "items": [{ "id": "p1.b0", "type": "text", "content": "Hello", "bbox": [0.1, 0.1, 0.9, 0.2], "readingOrder": 0 }] }]);
    let p = plant(&env, JobKind::Batch, opts, false, Some(b"Hello"), |doc, _| {
        doc.num_pages = Some(1);
        doc.pages = Some(vec![PdfPageMarkdown {
            page_number: 1,
            markdown: "Hello".into(),
        }]);
        doc.blocks = Some(blocks.clone());
    })
    .await;
    let data = crawlx_api::scrape_service::compat_document(&env.state, &p.run, &p.page, "").await;
    assert_eq!(data["pages"], j!([{ "pageNumber": 1, "markdown": "Hello" }]));
    assert_eq!(data["blocks"], blocks);
}

// ---- map of a deep seed ---------------------------------------------------------------------

#[tokio::test]
async fn map_of_a_deep_seed_lists_links_elsewhere_on_the_host() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/map"),
            &j!({ "url": rig.url("/docs/a"), "sitemap": "skip" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let links: Vec<&str> = v["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["url"].as_str().unwrap())
        .collect();
    for want in ["/docs/b", "/other/c", "/"] {
        assert!(
            links.contains(&rig.url(want).as_str()),
            "{want} missing in {links:?}"
        );
    }
    assert_eq!(rig.site.hits("/other/c"), 0, "listed, never fetched");
    rig.stop().await;
}

#[tokio::test]
async fn decode_and_markup_only_requests_return_their_selected_diagnostics() {
    let rig = Rig::start(RigConfig {
        site_routes: Some(axum::Router::new().route(
            "/diagnostic-outputs",
            axum::routing::get(|| async {
                axum::response::Html("<html><body><!--retained note--><main><h1>Diagnostic fixture</h1><p>Local fixture words stay in the cleaned text.</p></main></body></html>")
            }),
        )),
        ..RigConfig::default()
    })
    .await;
    let data = scrape_ok(
        &rig,
        j!({
            "url": rig.url("/diagnostic-outputs"),
            "decode": {"declaredCharset": "utf-8"},
            "markup": {"comments": true},
        }),
    )
    .await;
    let outputs = &data["outputs"];
    assert_eq!(outputs["discoveryScope"], "whole_page");
    assert_eq!(outputs["decode"]["encoding"], "UTF-8");
    assert_eq!(outputs["markup"]["comments"], j!(["retained note"]));
    for absent in [
        "rawHtml",
        "cleanedHtml",
        "fitHtml",
        "fitMarkdown",
        "tables",
        "linkMedia",
    ] {
        assert!(
            outputs.get(absent).is_none(),
            "{absent} was not requested: {outputs}"
        );
    }
    assert!(!data["markdown"].as_str().unwrap().contains("retained note"));
    rig.stop().await;
}

#[tokio::test]
async fn native_output_markup_and_citations_do_not_bypass_requested_pii_redaction() {
    let rig = Rig::start(RigConfig {
        site_routes: Some(axum::Router::new().route(
            "/private-outputs",
            axum::routing::get(|| async {
                axum::response::Html("<html><body><main><h1>Private fixture</h1><p>Contact output-person@example.test for local article details.</p><a href='/terms'>Useful terms</a></main></body></html>")
            }),
        )),
        ..RigConfig::default()
    })
    .await;
    let data = scrape_ok(
        &rig,
        j!({
            "url": rig.url("/private-outputs"), "redactPII": true,
            "outputs": {
                "rawHtml": true, "cleanedHtml": true, "citations": "selected",
                "fit": {"strategy": "pruning", "thresholdPermille": 0}
            },
        }),
    )
    .await;
    assert!(data["outputs"].is_object(), "{data}");
    assert!(
        !data["outputs"].to_string().contains("output-person@example.test"),
        "{data}"
    );
    assert!(
        !data["markdown"]
            .as_str()
            .unwrap()
            .contains("output-person@example.test"),
        "{data}"
    );
    rig.stop().await;
}
