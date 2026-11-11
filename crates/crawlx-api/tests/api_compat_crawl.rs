#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The compat crawl facade end to end: crawls executed by a REAL worker lease
//! loop over the fixture site, `GET /crawl/active`, `POST /crawl/params-preview`, `POST /map`,
//! compat-shaped webhooks, `fc-` keys and the compat API's error codes.
//!
//! The rig (`common/crawl_rig.rs`) serves one site for several host names: the seed host, a
//! subdomain and an external host of another registrable domain.
mod common;
#[path = "common/crawl_rig.rs"]
mod crawl_rig;

use axum::http::{Method, StatusCode};
use common::{env, env_with};
use crawl_rig::{header_of, Receiver, Rig, RigConfig, WEBHOOK_SECRET};
use crawlx_api::auth::{generate_compat_key, generate_key, key_record_for, tenant_id_for};
use crawlx_api::intel::webhook::compat_signature;
use crawlx_api::webhooks::WebhookSender;
use crawlx_api::{ApiConfig, ApiKeyBootstrap, CompatConfig, Scope, Settings};
use crawlx_core::config::SitemapMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{EventRepo, RunRepo};
use crawlx_core::scrape::JobKind;
use crawlx_core::{CrawlRunId, SystemClock};
use crawlx_model::llm::{LlmError, MockLlm};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

const CRAWL: &str = "/compat/v2/crawl";
const MAP: &str = "/compat/v2/map";

/// Start a crawl and return its id.
async fn start_crawl(rig: &Rig, body: &Value) -> String {
    let (s, _, v) = rig.env.post(CRAWL, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    v["id"].as_str().unwrap().to_owned()
}

/// `metadata.sourceURL` of every document of a status body.
fn sources(v: &Value) -> BTreeSet<String> {
    v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["metadata"]["sourceURL"].as_str().unwrap().to_owned())
        .collect()
}

/// The `url` of every link of a map body, in order.
fn links(v: &Value) -> Vec<String> {
    v["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["url"].as_str().unwrap().to_owned())
        .collect()
}

async fn run_of(rig: &Rig, id: &str) -> crawlx_core::repo::CrawlRun {
    rig.env
        .store
        .get(id.parse::<CrawlRunId>().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn compat_v2_create_omitted_strategy_persists_breadth_first() {
    for mode in [
        crawlx_api::CompatMode::Strict,
        crawlx_api::CompatMode::NativeDefaults,
    ] {
        let e = env_with(
            ApiConfig {
                rate_limit_per_minute: 0,
                compat: CompatConfig {
                    mode,
                    ..CompatConfig::default()
                },
                ..ApiConfig::default()
            },
            Settings::default(),
            Arc::new(SystemClock),
        );
        let (status, _, response) = e.post(CRAWL, &json!({"url": "https://docs.example.test/"})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let id: CrawlRunId = response["id"].as_str().unwrap().parse().unwrap();
        let run = e.store.get(id).await.unwrap();
        assert_eq!(
            run.config.scope.strategy,
            crawlx_core::config::CrawlStrategy::BreadthFirst,
            "{mode:?}"
        );
        assert_eq!(
            serde_json::to_value(&run.config).unwrap()["scope"]["strategy"],
            "breadth_first"
        );
        assert_eq!(run.config.scrape.as_ref().unwrap().kind, JobKind::Crawl);
    }
}

#[tokio::test]
async fn fixture_authorization_is_verified_stable_and_revocable() {
    let rig = Rig::start(RigConfig::default()).await;
    let record =
        crawlx_api::ApiStore::authorization_get(rig.env.api.as_ref(), rig.env.tenant, rig.authorization)
            .await
            .unwrap()
            .unwrap();
    assert!(record.verified_at.is_some());
    assert!(matches!(
        record.ownership,
        Some(crawlx_policy::authorization::OwnershipProof::OperatorSignature { .. })
    ));

    let first = start_crawl(
        &rig,
        &json!({"url": rig.url("/a"), "sitemap": "skip", "limit": 1}),
    )
    .await;
    let status = rig.wait_crawl(&first).await;
    assert_eq!(status["status"], "completed", "{status}");
    assert!(rig.seen.hits("/a") > 0, "the real worker fetched the fixture");
    assert!(
        run_of(&rig, &first)
            .await
            .config
            .safety
            .authorization_record_ref
            .is_none(),
        "fixture authorization must not alter the API-admitted configuration"
    );

    let (status, _, body) = rig
        .env
        .post(
            &format!("/v1/authorizations/{}/revoke", rig.authorization),
            &json!({"reason": "fixture ownership withdrawn"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second = start_crawl(
        &rig,
        &json!({"url": rig.url("/b"), "sitemap": "skip", "limit": 1}),
    )
    .await;
    let status = rig.wait_crawl(&second).await;
    assert_eq!(status["status"], "failed", "{status}");
    assert_eq!(
        run_of(&rig, &second).await.terminal_reason,
        Some(TerminalReason::AuthorizationRevoked)
    );
    assert_eq!(rig.seen.hits("/b"), 0, "revocation stops work before fetching");
    rig.stop().await;
}

#[tokio::test]
async fn crawl_with_scrape_options_returns_compat_documents() {
    let llm = Arc::new(MockLlm::from_fn(|_| Ok(json!({"headline": "Fixture Home"}))));
    let rig = Rig::start(RigConfig {
        llm: Some(llm),
        ..RigConfig::default()
    })
    .await;
    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/"),
            "limit": 1,
            "scrapeOptions": {
                "formats": [
                    "markdown", "rawHtml", "links", "images",
                    {"type": "json", "prompt": "Extract the headline"}
                ],
            },
        }),
    )
    .await;
    let v = rig.wait_crawl(&id).await;
    assert_eq!(v["status"], "completed", "{v}");
    assert_eq!(
        (v["total"].as_u64(), v["completed"].as_u64()),
        (Some(1), Some(1)),
        "{v}"
    );
    assert_eq!(v["creditsUsed"], 5, "1 for the page + 4 for the json format: {v}");
    assert!(v["createdAt"].is_string() && v["completedAt"].is_string(), "{v}");
    assert!(v["duration"].as_f64().unwrap() >= 0.0, "{v}");
    assert_eq!(v["next"], Value::Null);
    let d = &v["data"][0];
    assert!(d["markdown"].as_str().unwrap().contains("Welcome"), "{d}");
    assert!(
        d["rawHtml"].as_str().unwrap().contains("<h1>Fixture Home</h1>"),
        "{d}"
    );
    let page_links: Vec<&str> = d["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert!(page_links.contains(&rig.url("/a").as_str()), "{page_links:?}");
    let images: Vec<&str> = d["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert!(images.contains(&rig.url("/logo.png").as_str()), "{images:?}");
    assert!(
        images.contains(&rig.url("/og.png").as_str()),
        "og:image is an image: {images:?}"
    );
    assert_eq!(d["json"], json!({"headline": "Fixture Home"}), "{d}");
    let m = &d["metadata"];
    assert_eq!(m["title"], "Fixture Home");
    assert_eq!(m["description"], "The fixture home page");
    assert_eq!(m["statusCode"], 200);
    assert_eq!(m["sourceURL"], rig.url("/"));
    assert_eq!(m["creditsUsed"], 5);

    let run = run_of(&rig, &id).await;
    let job = run.config.scrape.as_ref().unwrap();
    assert_eq!(job.kind, JobKind::Crawl);
    assert!(job.options.wants("rawHtml") && job.options.wants("json") && job.options.wants("images"));

    // a finished crawl is booked in the usage ledger once, however often it is read
    for _ in 0..2 {
        rig.env.get(&format!("{CRAWL}/{id}")).await;
    }
    let usage = rig
        .env
        .state
        .repos
        .intel
        .usage_recent(rig.env.tenant, Some("crawl"), 10, 0)
        .await
        .unwrap();
    assert_eq!(usage.len(), 1, "{usage:?}");
    assert_eq!(usage[0].credits, 5);
    rig.stop().await;
}

#[tokio::test]
async fn regex_on_full_url_matches_the_whole_url() {
    let rig = Rig::start(RigConfig::default()).await;
    // control: a pathname regex never sees the query string, so `/page?id=1` is crawled
    let control = start_crawl(
        &rig,
        &json!({"url": rig.url("/"), "sitemap": "skip", "excludePaths": ["id=1$"]}),
    )
    .await;
    let v = rig.wait_crawl(&control).await;
    assert!(sources(&v).contains(&rig.url("/page?id=1")), "{:?}", sources(&v));

    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/"), "sitemap": "skip",
            "regexOnFullURL": true, "excludePaths": ["\\?id=1$"],
        }),
    )
    .await;
    let v = rig.wait_crawl(&id).await;
    let got = sources(&v);
    assert!(!got.contains(&rig.url("/page?id=1")), "{got:?}");
    assert!(
        got.contains(&rig.url("/a")) && got.contains(&rig.url("/docs/guide")),
        "{got:?}"
    );
    let run = run_of(&rig, &id).await;
    assert_eq!(run.config.scope.url_exclude, vec!["\\?id=1$"]);
    assert!(run.config.scope.exclude_paths.is_empty());

    // include patterns over the full URL select by host and path together
    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/"), "sitemap": "skip",
            "regexOnFullURL": true, "includePaths": ["^http://site\\.example\\.test:\\d+/(docs/.*)?$"],
        }),
    )
    .await;
    let v = rig.wait_crawl(&id).await;
    let got = sources(&v);
    assert!(
        got.contains(&rig.url("/docs/guide")) && !got.contains(&rig.url("/a")),
        "{got:?}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn allow_external_links_follows_one_hop_and_skips_external_homepages() {
    let rig = Rig::start(RigConfig::default()).await;
    let closed = start_crawl(&rig, &json!({"url": rig.url("/"), "sitemap": "skip"})).await;
    let v = rig.wait_crawl(&closed).await;
    assert!(
        !sources(&v).contains(&rig.ext_url("/article")),
        "external links are off by default"
    );
    assert_eq!(rig.seen.hits("/article"), 0);

    let id = start_crawl(
        &rig,
        &json!({"url": rig.url("/"), "sitemap": "skip", "allowExternalLinks": true}),
    )
    .await;
    let v = rig.wait_crawl(&id).await;
    assert_eq!(v["status"], "completed", "{v}");
    let got = sources(&v);
    assert!(
        got.contains(&rig.ext_url("/article")),
        "the external page is scraped once: {got:?}"
    );
    assert!(got.contains(&rig.url("/a")), "{got:?}");
    assert!(
        !got.contains(&rig.ext_url("/")),
        "external homepages are skipped: {got:?}"
    );
    assert_eq!(
        rig.seen.hits("/deep-ext"),
        0,
        "the links of an external page are not followed"
    );
    assert_eq!(rig.seen.hits("/article"), 1);

    let (s, _, e) = rig.env.get(&format!("{CRAWL}/{id}/errors")).await;
    assert_eq!(s, StatusCode::OK, "{e}");
    let skipped: Vec<&Value> = e["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["code"] == "EXTERNAL_LINK")
        .collect();
    assert_eq!(skipped.len(), 1, "{e}");
    assert_eq!(skipped[0]["url"], rig.ext_url("/"));
    assert!(
        skipped[0]["id"].is_string()
            && skipped[0]["timestamp"].is_string()
            && skipped[0]["error"].is_string()
    );
    assert!(
        !e["policyBlocked"].to_string().contains("external_homepage"),
        "a skipped homepage is reported once, as an error: {e}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn max_concurrency_and_robots_user_agent_reach_the_config_and_the_crawl() {
    let rig = Rig::start(RigConfig::default()).await;
    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/"), "sitemap": "skip",
            "maxConcurrency": 4, "robotsUserAgent": "FireBot",
        }),
    )
    .await;
    let run = run_of(&rig, &id).await;
    assert_eq!(run.config.politeness.max_concurrency, 4);
    assert_eq!(run.config.politeness.max_in_flight_per_origin, 4);
    assert_eq!(run.config.fetch.robots_user_agent.as_deref(), Some("FireBot"));
    assert!(run.config.safety.respect_robots_txt);
    let v = rig.wait_crawl(&id).await;
    assert_eq!(v["status"], "completed", "{v}");
    // the fixture's robots.txt disallows `/b` for the `firebot` group only
    assert!(!sources(&v).contains(&rig.url("/b")), "{:?}", sources(&v));
    assert_eq!(rig.seen.hits("/b"), 0);
    let (_, _, e) = rig.env.get(&format!("{CRAWL}/{id}/errors")).await;
    assert_eq!(e["robotsBlocked"], json!([rig.url("/b")]), "{e}");

    // the same crawl as the default agent is allowed to fetch it
    let other = start_crawl(&rig, &json!({"url": rig.url("/"), "sitemap": "skip"})).await;
    let v = rig.wait_crawl(&other).await;
    assert!(sources(&v).contains(&rig.url("/b")), "{:?}", sources(&v));
    // without `compat.robotsAuthorization` the override is refused and no run is created
    let (s, _, r) = rig
        .env
        .post(CRAWL, &json!({"url": rig.url("/"), "ignoreRobotsTxt": true}))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "ROBOTS_OVERRIDE_NOT_AUTHORIZED", "{r}");
    assert_eq!(r["success"], false, "{r}");
    rig.stop().await;
}

#[tokio::test]
async fn v1_aliases_are_accepted() {
    let llm = Arc::new(MockLlm::from_fn(|_| Ok(json!({"title": "x"}))));
    let rig = Rig::start(RigConfig {
        llm: Some(llm),
        ..RigConfig::default()
    })
    .await;
    let (s, _, v) = rig
        .env
        .post(
            CRAWL,
            &json!({
                "url": rig.url("/"),
                "maxDepth": 1,
                "ignoreSitemap": true,
                "allowBackwardLinks": true,
                "deduplicateSimilarURLs": true,
                "crawlerOptions": {"limit": 2, "maxDepth": 7},
                "scrapeOptions": {"extract": {"prompt": "the title", "schema": {"type": "object"}}},
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let deprecated: Vec<&str> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["code"] == "deprecated_option")
        .map(|w| w["path"].as_str().unwrap())
        .collect();
    for p in [
        "/maxDepth",
        "/ignoreSitemap",
        "/allowBackwardLinks",
        "/crawlerOptions",
    ] {
        assert!(deprecated.contains(&p), "{p} in {deprecated:?}");
    }
    let run = run_of(&rig, v["id"].as_str().unwrap()).await;
    let c = &run.config;
    assert_eq!(
        c.scope.max_discovery_depth, 1,
        "maxDepth is maxDiscoveryDepth; the top level wins"
    );
    assert_eq!(c.scope.sitemap, SitemapMode::Skip);
    assert!(c.scope.crawl_entire_domain);
    assert!(
        !c.scope.filter_similar,
        "deduplicateSimilarURLs is URL normalization, not the shape filter"
    );
    assert_eq!(c.limits.urls, 2, "the crawlerOptions wrapper is read");
    let job = c.scrape.as_ref().unwrap();
    assert!(
        job.options.wants("json"),
        "scrapeOptions.extract is the json format"
    );
    let done = rig.wait_crawl(v["id"].as_str().unwrap()).await;
    assert_eq!(done["data"].as_array().unwrap().len(), 2, "{done}");
    assert!(done["data"][0]["json"].is_object(), "{done}");
    rig.stop().await;
}

#[tokio::test]
async fn crawl_active_lists_only_the_running_crawls_of_the_tenant() {
    // no worker: crawls stay where the test puts them
    let e = env();
    let make = |body: Value| {
        let e = &e;
        async move {
            let (s, _, v) = e.post(CRAWL, &body).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            v["id"].as_str().unwrap().to_owned()
        }
    };
    let queued = make(json!({"url": "https://docs.example.test/", "limit": 7, "scrapeOptions": {"formats": ["markdown", "links"], "waitFor": 100, "headers": {"X-Secret": "hunter2"}}, "webhook": {"url": "https://hooks.example.test/x", "headers": {"X-Hook": "tok"}, "metadata": {"m": "n"}}})).await;
    let running = make(json!({"url": "https://docs.example.test/running"})).await;
    let paused = make(json!({"url": "https://docs.example.test/paused"})).await;
    let done = make(json!({"url": "https://docs.example.test/done"})).await;
    let cancelled = make(json!({"url": "https://docs.example.test/cancelled"})).await;
    let rid = |s: &str| s.parse::<CrawlRunId>().unwrap();
    e.store
        .set_status(rid(&running), RunStatus::Running, None)
        .await
        .unwrap();
    e.store
        .set_status(rid(&paused), RunStatus::Running, None)
        .await
        .unwrap();
    e.store
        .set_status(rid(&paused), RunStatus::Paused, None)
        .await
        .unwrap();
    e.store
        .set_status(rid(&done), RunStatus::Running, None)
        .await
        .unwrap();
    e.store
        .set_status(
            rid(&done),
            RunStatus::Completed,
            Some(TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    let (s, _, _) = e.delete(&format!("{CRAWL}/{cancelled}")).await;
    assert_eq!(s, StatusCode::OK);
    // a native run is no crawl, and another tenant's crawl is not ours
    e.create_run(&common::simple_body()).await;
    let other = e.key_for("other", &[Scope::CrawlsRead, Scope::CrawlsWrite]).await;
    let (s, _, o) = e
        .send(
            Method::POST,
            CRAWL,
            Some(&other),
            &[],
            Some(&json!({"url": "https://other.example.test/"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let other_id = common::json(&o)["id"].as_str().unwrap().to_owned();

    let (s, _, v) = e.get(&format!("{CRAWL}/active")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    let listed: BTreeSet<String> = v["crawls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(listed, BTreeSet::from([queued.clone(), running, paused]), "{v}");
    let item = v["crawls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == queued)
        .unwrap();
    assert_eq!(item["teamId"], e.tenant.to_string());
    assert_eq!(item["url"], "https://docs.example.test/");
    assert_eq!(item["status"], "scraping");
    let o = &item["options"];
    assert_eq!(o["limit"], 7);
    assert_eq!(
        o["scrapeOptions"]["formats"],
        json!([{"type": "markdown"}, {"type": "links"}])
    );
    assert_eq!(o["scrapeOptions"]["waitFor"], 100);
    let shown = item.to_string();
    for secret in ["hunter2", "tok", "hooks.example.test"] {
        assert!(!shown.contains(secret), "{secret} leaked: {shown}");
    }

    let (_, _, ov) = e.get_as(&other, &format!("{CRAWL}/active")).await;
    let theirs: Vec<&str> = ov["crawls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(theirs, [other_id.as_str()]);

    // reading needs `crawls:read`
    let write_only = e.key_for("acme", &[Scope::CrawlsWrite]).await;
    let (s, _, _) = e.get_as(&write_only, &format!("{CRAWL}/active")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn params_preview_plans_options_with_the_llm_and_is_503_without_one() {
    let plan = json!({"limit": 5, "includePaths": ["^/blog"], "maxDiscoveryDepth": 2, "bogus": true});
    let llm = Arc::new(MockLlm::from_fn(move |_| Ok(plan.clone())));
    let rig = Rig::start(RigConfig {
        llm: Some(llm.clone()),
        ..RigConfig::default()
    })
    .await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{CRAWL}/params-preview"),
            &json!({"url": "https://docs.example.test/", "prompt": "only the blog, five pages"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    assert_eq!(
        v["data"],
        json!({"url": "https://docs.example.test/", "limit": 5, "includePaths": ["^/blog"], "maxDiscoveryDepth": 2})
    );
    let call = llm.calls().pop().unwrap();
    assert!(call.user.contains("only the blog, five pages"), "{}", call.user);

    for bad in [
        json!({"prompt": "x"}),
        json!({"url": "https://a.example.test/"}),
        json!({"url": "nope://x", "prompt": "x"}),
    ] {
        let (s, _, v) = rig.env.post(&format!("{CRAWL}/params-preview"), &bad).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
        assert_eq!(v["code"], "BAD_REQUEST");
    }

    // a crawl `prompt` is planned by the same LLM; explicit options win over the plan
    let (s, _, c) = rig
        .env
        .post(
            CRAWL,
            &json!({"url": rig.url("/"), "prompt": "only the blog", "limit": 2, "sitemap": "skip"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{c}");
    let codes: Vec<&str> = c["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(!codes.contains(&"prompt_ignored"), "{c}");
    let run = run_of(&rig, c["id"].as_str().unwrap()).await;
    assert_eq!(run.config.limits.urls, 2, "explicit limit beats the planned one");
    assert_eq!(run.config.scope.include_paths, vec!["^/blog"]);
    assert_eq!(run.config.scope.max_discovery_depth, 2);
    rig.stop().await;

    // without an LLM: 503 for the preview, and a crawl only warns
    let e = env();
    let (s, _, v) = e
        .post(
            &format!("{CRAWL}/params-preview"),
            &json!({"url": "https://docs.example.test/", "prompt": "x"}),
        )
        .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["code"], "llm_not_configured");
    assert_eq!(v["success"], false);
    let (_, _, c) = e
        .post(
            CRAWL,
            &json!({"url": "https://docs.example.test/", "prompt": "x", "limit": 3}),
        )
        .await;
    let w: Vec<(&str, &str)> = c["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| (w["code"].as_str().unwrap(), w["path"].as_str().unwrap()))
        .collect();
    assert!(w.contains(&("prompt_ignored", "/prompt")), "{c}");

    // a failing LLM is a failure of the request, never a silent fallback
    let failing = Arc::new(MockLlm::from_fn(|_| Err(LlmError::Timeout { after_ms: 5 })));
    let rig = Rig::start(RigConfig {
        llm: Some(failing),
        ..RigConfig::default()
    })
    .await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{CRAWL}/params-preview"),
            &json!({"url": "https://docs.example.test/", "prompt": "x"}),
        )
        .await;
    assert_eq!(s, StatusCode::GATEWAY_TIMEOUT, "{v}");
    rig.stop().await;
}

#[tokio::test]
async fn map_lists_sitemap_urls_and_page_links() {
    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = rig.env.post(MAP, &json!({"url": rig.url("/")})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    let got = links(&v);
    let all = got.len();
    assert_eq!(got[0], rig.url("/"), "the start page comes first: {got:?}");
    let set: BTreeSet<&str> = got.iter().map(String::as_str).collect();
    assert_eq!(set.len(), got.len(), "one entry per URL: {got:?}");
    for path in [
        "/a",
        "/b",
        "/docs/guide",
        "/docs/old/x",
        "/c",
        "/blog-post",
        "/page",
    ] {
        assert!(set.contains(rig.url(path).as_str()), "{path} in {got:?}");
    }
    assert!(
        set.contains(rig.sub_url("/sub-post").as_str()),
        "subdomains are included by default: {got:?}"
    );
    for path in ["/article", "/", "/elsewhere"] {
        assert!(
            !set.contains(rig.ext_url(path).as_str()),
            "external {path} in {got:?}"
        );
    }
    assert!(
        !got.iter().any(|u| u.contains('?')),
        "query strings are dropped by default: {got:?}"
    );
    assert_eq!(v["links"][0]["title"], "Fixture Home");
    assert_eq!(v["links"][0]["description"], "The fixture home page");
    assert!(
        v["links"][1].get("title").is_none(),
        "only the fetched page has a title"
    );
    assert_eq!(rig.seen.hits("/a"), 0, "a map does not fetch the pages it lists");

    // one credit per call
    let usage = rig
        .env
        .state
        .repos
        .intel
        .usage_recent(rig.env.tenant, Some("map"), 10, 0)
        .await
        .unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].credits, 1);

    // ignoreQueryParameters: false keeps the query strings apart
    let (_, _, v) = rig
        .env
        .post(MAP, &json!({"url": rig.url("/"), "ignoreQueryParameters": false}))
        .await;
    let got = links(&v);
    assert!(
        got.contains(&rig.url("/page?id=1")) && got.contains(&rig.url("/page?id=2")),
        "{got:?}"
    );
    assert!(!got.contains(&rig.url("/page")), "{got:?}");

    // includeSubdomains: false
    let (_, _, v) = rig
        .env
        .post(MAP, &json!({"url": rig.url("/"), "includeSubdomains": false}))
        .await;
    let got = links(&v);
    assert!(!got.iter().any(|u| u.contains(crawl_rig::SUB_HOST)), "{got:?}");
    assert!(got.contains(&rig.url("/blog-post")));

    // limit and search: relevance order, the limit applies after it
    let (_, _, v) = rig
        .env
        .post(MAP, &json!({"url": rig.url("/"), "search": "guide"}))
        .await;
    assert_eq!(links(&v)[0], rig.url("/docs/guide"), "{v}");
    assert_eq!(
        links(&v).len(),
        all,
        "search orders the links, it never drops one"
    );
    let (_, _, v) = rig
        .env
        .post(MAP, &json!({"url": rig.url("/"), "search": "guide", "limit": 2}))
        .await;
    assert_eq!(links(&v).len(), 2);
    assert_eq!(links(&v)[0], rig.url("/docs/guide"));
    let (_, _, v) = rig.env.post(MAP, &json!({"url": rig.url("/"), "limit": 3})).await;
    assert_eq!(links(&v).len(), 3);

    // sitemap: only lists what the sitemap names; skip lists what the pages link to
    let (_, _, v) = rig
        .env
        .post(MAP, &json!({"url": rig.url("/"), "sitemap": "only"}))
        .await;
    let got = links(&v);
    assert!(
        got.contains(&rig.url("/c")) && got.contains(&rig.url("/blog-post")),
        "{got:?}"
    );
    assert!(
        !got.contains(&rig.url("/b")) && !got.contains(&rig.url("/docs/old/x")),
        "{got:?}"
    );
    let (_, _, v) = rig
        .env
        .post(MAP, &json!({"url": rig.url("/"), "sitemap": "skip"}))
        .await;
    let got = links(&v);
    assert!(
        got.contains(&rig.url("/b")) && got.contains(&rig.url("/docs/old/x")),
        "{got:?}"
    );
    assert!(
        !got.contains(&rig.url("/c")) && !got.contains(&rig.url("/blog-post")),
        "{got:?}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn map_validates_its_request_and_reports_unapplied_options() {
    let e = env();
    for (body, path) in [
        (json!({}), "/url"),
        (json!({"url": "nope://x"}), "/url"),
        (
            json!({"url": "https://a.example.test/", "limit": 100_001}),
            "/limit",
        ),
        (
            json!({"url": "https://a.example.test/", "sitemap": "weird"}),
            "/sitemap",
        ),
        (
            json!({"url": "https://a.example.test/", "includeSubdomains": "yes"}),
            "/includeSubdomains",
        ),
    ] {
        let (s, _, v) = e.post(MAP, &body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {v}");
        assert_eq!(v["code"], "BAD_REQUEST");
        assert!(
            v["details"].as_array().unwrap().iter().any(|d| d["path"] == path),
            "{v}"
        );
    }
    let (s, _, v) = e.post(MAP, &json!({"url": "http://localhost/"})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "UNSUPPORTED_SITE");
    let write_less = e.key_for("acme", &[Scope::CrawlsRead]).await;
    let (s, _, _) = e
        .send(
            Method::POST,
            MAP,
            Some(&write_less),
            &[],
            Some(&json!({"url": "https://a.example.test/"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webhooks_deliver_signed_compat_payloads() {
    let rig = Rig::start(RigConfig::default()).await;
    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/"), "sitemap": "skip", "limit": 3,
            "webhook": {
                "url": "https://hooks.example.test/fc",
                "headers": {"X-Auth-Token": "tok-123", "X-Firecrawl-Signature": "forged", "Content-Type": "text/plain"}, // wire-compat
                "metadata": {"job": "nightly", "n": 7},
            },
        }),
    )
    .await;
    let v = rig.wait_crawl(&id).await;
    assert_eq!(v["status"], "completed", "{v}");
    rig.drain_webhooks().await;
    let types = rig.receiver.types();
    assert_eq!(
        types.first().map(String::as_str),
        Some("crawl.started"),
        "{types:?}"
    );
    assert_eq!(
        types.last().map(String::as_str),
        Some("crawl.completed"),
        "{types:?}"
    );
    assert_eq!(
        types.iter().filter(|t| *t == "crawl.page").count(),
        3,
        "{types:?}"
    );
    let bodies = rig.receiver.bodies();
    let mut ids = BTreeSet::new();
    for (req, body) in rig.receiver.seen.lock().iter().zip(&bodies) {
        assert_eq!(body["success"], true, "{body}");
        assert_eq!(body["id"], id.as_str());
        assert_eq!(body["metadata"], json!({"job": "nightly", "n": 7}), "{body}");
        assert!(
            ids.insert(body["webhookId"].as_str().unwrap().to_owned()),
            "webhookId is unique per delivery"
        );
        // `sha256=<hex HMAC-SHA256(raw body, secret)>`
        let sig = header_of(req, "X-Firecrawl-Signature").unwrap(); // wire-compat
        assert_eq!(sig, compat_signature(WEBHOOK_SECRET, &req.body));
        assert!(sig.starts_with("sha256="));
        // the caller's headers are sent, but never override the signed envelope
        assert_eq!(header_of(req, "X-Auth-Token"), Some("tok-123"));
        assert_eq!(header_of(req, "Content-Type"), Some("application/json"));
        assert_eq!(
            req.headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("x-firecrawl-signature")) // wire-compat
                .count(),
            1
        );
    }
    let first_page = bodies.iter().find(|b| b["type"] == "crawl.page").unwrap();
    let doc = &first_page["data"][0];
    assert!(doc["markdown"].is_string(), "{first_page}");
    assert_eq!(doc["metadata"]["statusCode"], 200);
    assert!(doc["metadata"]["sourceURL"]
        .as_str()
        .unwrap()
        .starts_with("http://site.example.test:"));
    assert_eq!(bodies[0]["data"], json!([]));
    assert_eq!(bodies.last().unwrap()["data"], json!([]));

    // the credentials never come back from the API
    let (_, _, native) = rig.env.get(&format!("/v1/crawls/{id}")).await;
    let (_, _, facade) = rig.env.get(&format!("{CRAWL}/{id}")).await;
    for shown in [native.to_string(), facade.to_string()] {
        assert!(!shown.contains("tok-123") && !shown.contains("forged"), "{shown}");
    }

    // `events` selects the compat API names, with or without the prefix
    rig.receiver.seen.lock().clear();
    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/"), "sitemap": "skip", "limit": 2,
            "webhook": {"url": "https://hooks.example.test/fc", "events": ["crawl.page", "completed"]},
        }),
    )
    .await;
    rig.wait_crawl(&id).await;
    rig.drain_webhooks().await;
    let types = rig.receiver.types();
    assert_eq!(
        types.iter().filter(|t| *t == "crawl.page").count(),
        2,
        "{types:?}"
    );
    assert_eq!(types.last().map(String::as_str), Some("crawl.completed"));
    assert!(!types.contains(&"crawl.started".to_owned()), "{types:?}");

    rig.receiver.seen.lock().clear();
    let id = start_crawl(
        &rig,
        &json!({"url": rig.url("/"), "sitemap": "skip", "limit": 2, "webhook": {"url": "https://hooks.example.test/fc", "events": ["started"]}}),
    )
    .await;
    rig.wait_crawl(&id).await;
    rig.drain_webhooks().await;
    assert_eq!(rig.receiver.types(), ["crawl.started"]);

    // an unknown event name is a 400, not a silently empty subscription
    let (s, _, v) = rig
        .env
        .post(
            CRAWL,
            &json!({"url": rig.url("/"), "webhook": {"url": "https://hooks.example.test/fc", "events": ["nope"]}}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    rig.stop().await;
}

#[tokio::test]
async fn failed_pages_and_failed_crawls_are_delivered_as_failures() {
    let e = env();
    let (s, _, v) = e
        .post(
            CRAWL,
            &json!({"url": "https://docs.example.test/", "webhook": {"url": "https://hooks.example.test/fc", "metadata": {"k": 1}}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id: CrawlRunId = v["id"].as_str().unwrap().parse().unwrap();
    e.store.set_status(id, RunStatus::Running, None).await.unwrap();
    e.store
        .append(id, "page.failed", json!({"url": "https://docs.example.test/x", "reason": "unreachable", "message": "connection refused"}))
        .await
        .unwrap();
    e.store
        .append(
            id,
            "completed",
            json!({"status": "failed", "terminalReason": "fatal_error"}),
        )
        .await
        .unwrap();
    e.store
        .set_status(id, RunStatus::Failed, Some(TerminalReason::FatalError))
        .await
        .unwrap();
    let receiver = Receiver::new();
    let sender = WebhookSender::new(
        e.state.repos.api.clone(),
        e.state.repos.runs.clone(),
        e.state.repos.events.clone(),
        receiver.clone(),
        WEBHOOK_SECRET.to_owned(),
        Arc::new(SystemClock),
    )
    .with_documents(e.state.clone());
    for _ in 0..5 {
        sender.tick().await.unwrap();
    }
    assert_eq!(receiver.types(), ["crawl.started", "crawl.page", "crawl.failed"]);
    let bodies = receiver.bodies();
    assert_eq!(bodies[0]["success"], true);
    assert_eq!(bodies[1]["success"], false);
    assert_eq!(bodies[1]["data"], json!([]));
    assert!(
        bodies[1]["error"]
            .as_str()
            .unwrap()
            .contains("connection refused"),
        "{}",
        bodies[1]
    );
    assert_eq!(bodies[2]["success"], false);
    assert!(
        bodies[2]["error"].as_str().unwrap().contains("fatal_error"),
        "{}",
        bodies[2]
    );
    for b in &bodies {
        assert_eq!(b["metadata"], json!({"k": 1}));
        assert_eq!(b["id"], id.to_string());
    }

    // a cancelled crawl ends `completed`, like the native stream
    let (_, _, v) = e
        .post(CRAWL, &json!({"url": "https://docs.example.test/c", "webhook": {"url": "https://hooks.example.test/fc"}}))
        .await;
    let cancel_id = v["id"].as_str().unwrap().to_owned();
    e.delete(&format!("{CRAWL}/{cancel_id}")).await;
    receiver.seen.lock().clear();
    for _ in 0..5 {
        sender.tick().await.unwrap();
    }
    let got: Vec<(String, String)> = receiver
        .bodies()
        .iter()
        .filter(|b| b["id"] == cancel_id.as_str())
        .map(|b| (b["type"].as_str().unwrap().to_owned(), b["success"].to_string()))
        .collect();
    assert_eq!(
        got,
        [
            ("crawl.started".to_owned(), "true".to_owned()),
            ("crawl.completed".to_owned(), "true".to_owned())
        ]
    );
}

#[tokio::test]
async fn fc_keys_authenticate_the_compat_routes_only_when_enabled() {
    let make_env = |prefixed_keys: bool| {
        env_with(
            ApiConfig {
                rate_limit_per_minute: 0,
                compat: CompatConfig {
                    prefixed_keys,
                    ..CompatConfig::default()
                },
                ..ApiConfig::default()
            },
            Settings::default(),
            Arc::new(SystemClock),
        )
    };
    for enabled in [false, true] {
        let e = make_env(enabled);
        let fc = generate_compat_key();
        let rec = key_record_for(&fc, tenant_id_for("acme"), Scope::all_set(), true).unwrap();
        crawlx_api::ApiStore::key_insert(e.api.as_ref(), &rec, "acme")
            .await
            .unwrap();
        let active = format!("{CRAWL}/active");
        let (s, _, b) = e.send(Method::GET, &active, Some(&fc), &[], None).await;
        if enabled {
            assert_eq!(s, StatusCode::OK, "{}", common::json(&b));
            // and it works for real work: start a crawl with it
            let (s, _, b) = e
                .send(
                    Method::POST,
                    CRAWL,
                    Some(&fc),
                    &[],
                    Some(&json!({"url": "https://docs.example.test/"})),
                )
                .await;
            assert_eq!(s, StatusCode::OK, "{}", common::json(&b));
        } else {
            assert_eq!(s, StatusCode::UNAUTHORIZED, "fc- keys are off by default");
        }
        // an fc- key is never a native credential
        let (s, _, _) = e
            .send(
                Method::GET,
                "/v1/crawls/00000000-0000-0000-0000-000000000000",
                Some(&fc),
                &[],
                None,
            )
            .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        // cx_live_ keys work either way, on both route families
        let (s, _, _) = e.send(Method::GET, &active, Some(&e.key), &[], None).await;
        assert_eq!(s, StatusCode::OK);
        // a malformed fc- key is 401 even when enabled
        let (s, _, _) = e.send(Method::GET, &active, Some("fc-short"), &[], None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let plain = generate_key();
        assert!(key_record_for(&plain, tenant_id_for("acme"), Scope::all_set(), enabled).is_some());
    }
}

#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "test client speaks HTTP to an owned local fixture server"
)]
async fn bootstrap_accepts_fc_keys_only_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let fc = generate_compat_key();
    let off = ApiConfig {
        bind: ([127, 0, 0, 1], 0).into(),
        artifacts_dir: dir.path().to_path_buf(),
        api_keys: vec![ApiKeyBootstrap::new("acme", &fc)],
        ..ApiConfig::default()
    };
    let err = crawlx_api::run_until(off, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(err, crawlx_api::ApiError::Config(_)), "{err}");

    let on = ApiConfig {
        bind: ([127, 0, 0, 1], 0).into(),
        artifacts_dir: dir.path().to_path_buf(),
        api_keys: vec![ApiKeyBootstrap::new("acme", &fc)],
        compat: CompatConfig {
            prefixed_keys: true,
            ..CompatConfig::default()
        },
        ..ApiConfig::default()
    };
    let shutdown = tokio_util::sync::CancellationToken::new();
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(crawlx_api::run_until_bound(on, shutdown.clone(), Some(bound_tx)));
    // the server reports the port it bound (port 0 above), so no pre-bound port can be
    // taken by a concurrent test between release and re-bind
    let port = tokio::time::timeout(Duration::from_secs(10), bound_rx)
        .await
        .expect("server bound within 10 s")
        .expect("server reports its address")
        .port();
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}{CRAWL}/active");
    let status = client.get(&url).bearer_auth(&fc).send().await.unwrap().status();
    assert_eq!(status, reqwest::StatusCode::OK);
    let native = client
        .get(format!(
            "http://127.0.0.1:{port}/v1/crawls/00000000-0000-0000-0000-000000000000"
        ))
        .bearer_auth(&fc)
        .send()
        .await
        .unwrap();
    assert_eq!(native.status(), reqwest::StatusCode::UNAUTHORIZED);
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
}

#[tokio::test]
async fn compat_error_codes() {
    let e = env();
    // invalid URL: 400 BAD_REQUEST; a missing url stays a validation failure
    for url in [
        json!("not a url"),
        json!("ftp://x.example.test/"),
        json!(""),
        json!(7),
    ] {
        let (s, _, v) = e.post(CRAWL, &json!({"url": url})).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{url}: {v}");
        assert_eq!(v["success"], false);
        assert_eq!(v["code"], "BAD_REQUEST");
        assert_eq!(v["error"], "Bad Request");
        assert_eq!(v["details"][0]["path"], "/url");
    }
    // a missing url is the compat API's 400, with every violation listed
    let (s, _, v) = e.post(CRAWL, &json!({"limit": 3})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "BAD_REQUEST", "{v}");
    assert_eq!(v["details"][0]["path"], "/url", "{v}");
    let (s, _, v) = e
        .post(
            CRAWL,
            &json!({"url": "https://a.example.test/", "includePaths": ["("], "limit": 0}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let paths: Vec<&str> = v["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"/limit"), "{v}");
    let (s, _, v) = e
        .post(
            CRAWL,
            &json!({"url": "https://a.example.test/", "includePaths": ["("]}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["details"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["path"] == "/includePaths" && d["code"] == "invalid_pattern"),
        "{v}"
    );

    // admission-denied targets: 403 UNSUPPORTED_SITE
    for url in [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://192.168.1.10/",
        "http://169.254.169.254/latest/meta-data",
    ] {
        let (s, _, v) = e.post(CRAWL, &json!({"url": url})).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{url}: {v}");
        assert_eq!(v["code"], "UNSUPPORTED_SITE");
        assert_eq!(v["success"], false);
    }

    // 413: a body over the configured limit
    let huge = json!({"url": "https://a.example.test/", "includePaths": vec!["x".repeat(1000); 400]});
    let (s, _, v) = e.post(CRAWL, &huge).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    assert_eq!(v["success"], false);

    // 429: the concurrency allowance
    let limited = env_with(
        ApiConfig {
            rate_limit_per_minute: 0,
            ..ApiConfig::default()
        },
        Settings {
            max_active_runs: 1,
            ..Settings::default()
        },
        Arc::new(SystemClock),
    );
    let (s, _, _) = limited
        .post(CRAWL, &json!({"url": "https://a.example.test/"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, h, v) = limited
        .post(CRAWL, &json!({"url": "https://a.example.test/2"}))
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .starts_with("Concurrency limit reached"),
        "{v}"
    );
    assert!(h.contains_key("retry-after"));
    let (s, _, v) = limited
        .post(MAP, &json!({"url": "https://a.example.test/"}))
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .starts_with("Concurrency limit reached"),
        "{v}"
    );

    // batch runs are not crawls: the crawl routes do not know their ids
    let (s, _, b) = e
        .post(
            "/compat/v2/batch/scrape",
            &json!({"urls": ["https://a.example.test/", "https://a.example.test/2"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let batch = b["id"].as_str().unwrap();
    for (method, tail) in [(Method::GET, ""), (Method::GET, "/errors"), (Method::DELETE, "")] {
        let (s, _, _) = e
            .send(method, &format!("{CRAWL}/{batch}{tail}"), Some(&e.key), &[], None)
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{tail}");
    }
    let (s, _, _) = e.get(&format!("{CRAWL}/{}", CrawlRunId::new())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

const BATCH: &str = "/compat/v2/batch/scrape";

/// Start a batch scrape and return its id.
async fn start_batch(rig: &Rig, body: &Value) -> String {
    let (s, _, v) = rig.env.post(BATCH, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    v["id"].as_str().unwrap().to_owned()
}

/// Poll a batch scrape until it is no longer `scraping`.
async fn wait_batch(rig: &Rig, id: &str) -> Value {
    for _ in 0..600 {
        let (_, _, v) = rig.env.get(&format!("{BATCH}/{id}?limit=1000")).await;
        if v["status"] != "scraping" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("batch {id} did not finish in 30 s");
}

/// Check every delivery the receiver holds: signed with the webhook secret over the raw body and
/// carrying the run id, the job metadata and a unique `webhookId`.
fn check_deliveries(rig: &Rig, id: &str, metadata: &Value) {
    let bodies = rig.receiver.bodies();
    let mut ids = BTreeSet::new();
    for (req, body) in rig.receiver.seen.lock().iter().zip(&bodies) {
        assert_eq!(body["id"], id);
        assert_eq!(&body["metadata"], metadata, "{body}");
        assert!(
            ids.insert(body["webhookId"].as_str().unwrap().to_owned()),
            "webhookId is unique"
        );
        let sig = header_of(req, "X-Firecrawl-Signature").unwrap(); // wire-compat
        assert_eq!(sig, compat_signature(WEBHOOK_SECRET, &req.body));
        assert!(sig.starts_with("sha256="));
    }
}

#[tokio::test]
async fn batch_scrape_webhooks_deliver_batch_scrape_events() {
    let rig = Rig::start(RigConfig::default()).await;
    let urls = json!([rig.url("/a"), rig.url("/b"), rig.url("/c")]);
    let id = start_batch(
        &rig,
        &json!({
            "urls": urls,
            "webhook": {
                "url": "https://hooks.example.test/batch",
                "headers": {"X-Batch-Token": "batch-tok", "X-Firecrawl-Signature": "forged"}, // wire-compat
                "metadata": {"batch": "nightly", "n": 3},
            },
        }),
    )
    .await;
    let v = wait_batch(&rig, &id).await;
    assert_eq!(v["status"], "completed", "{v}");
    rig.drain_webhooks().await;
    let types = rig.receiver.types();
    assert_eq!(
        types.first().map(String::as_str),
        Some("batch_scrape.started"),
        "{types:?}"
    );
    assert_eq!(
        types.last().map(String::as_str),
        Some("batch_scrape.completed"),
        "{types:?}"
    );
    assert_eq!(
        types.iter().filter(|t| *t == "batch_scrape.page").count(),
        3,
        "{types:?}"
    );
    assert!(
        types.iter().all(|t| t.starts_with("batch_scrape.")),
        "no crawl.* names: {types:?}"
    );
    check_deliveries(&rig, &id, &json!({"batch": "nightly", "n": 3}));
    let bodies = rig.receiver.bodies();
    for (req, body) in rig.receiver.seen.lock().iter().zip(&bodies) {
        assert_eq!(body["success"], true, "{body}");
        assert_eq!(header_of(req, "X-Batch-Token"), Some("batch-tok"));
        assert_eq!(header_of(req, "Content-Type"), Some("application/json"));
        assert_eq!(
            req.headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("x-firecrawl-signature")) // wire-compat
                .count(),
            1,
            "the caller cannot replace the signature"
        );
        assert!(header_of(req, "Crawlx-Event")
            .unwrap()
            .starts_with("batch_scrape."));
    }
    let pages: Vec<&Value> = bodies
        .iter()
        .filter(|b| b["type"] == "batch_scrape.page")
        .collect();
    let sources: BTreeSet<&str> = pages
        .iter()
        .map(|b| b["data"][0]["metadata"]["sourceURL"].as_str().unwrap())
        .collect();
    assert_eq!(
        sources,
        BTreeSet::from([
            rig.url("/a").as_str(),
            rig.url("/b").as_str(),
            rig.url("/c").as_str()
        ])
    );
    assert!(pages
        .iter()
        .all(|b| b["data"][0]["markdown"].is_string() && b["data"].as_array().unwrap().len() == 1));
    assert_eq!(bodies[0]["data"], json!([]));
    assert_eq!(bodies.last().unwrap()["data"], json!([]));

    // the headers and the metadata never come back from the API
    let (_, _, native) = rig.env.get(&format!("/v1/crawls/{id}")).await;
    let (_, _, status) = rig.env.get(&format!("{BATCH}/{id}")).await;
    for shown in [native.to_string(), status.to_string()] {
        assert!(
            !shown.contains("batch-tok") && !shown.contains("forged"),
            "{shown}"
        );
    }

    // `events` with and without the prefix, and the string form of `webhook`
    for (events, want) in [
        (
            json!(["batch_scrape.page", "completed"]),
            vec!["batch_scrape.page", "batch_scrape.page", "batch_scrape.completed"],
        ),
        (json!(["started"]), vec!["batch_scrape.started"]),
        (
            json!(["batch_scrape.started", "batch_scrape.completed"]),
            vec!["batch_scrape.started", "batch_scrape.completed"],
        ),
    ] {
        rig.receiver.seen.lock().clear();
        let id = start_batch(
            &rig,
            &json!({
                "urls": [rig.url("/a"), rig.url("/b")],
                "webhook": {"url": "https://hooks.example.test/batch", "events": events},
            }),
        )
        .await;
        wait_batch(&rig, &id).await;
        rig.drain_webhooks().await;
        assert_eq!(rig.receiver.types(), want, "events {events}");
        check_deliveries(&rig, &id, &json!({}));
    }
    rig.receiver.seen.lock().clear();
    let id = start_batch(
        &rig,
        &json!({"urls": [rig.url("/a"), rig.url("/b")], "webhook": "https://hooks.example.test/string-form"}),
    )
    .await;
    wait_batch(&rig, &id).await;
    rig.drain_webhooks().await;
    assert_eq!(
        rig.receiver.types(),
        [
            "batch_scrape.started",
            "batch_scrape.page",
            "batch_scrape.page",
            "batch_scrape.completed"
        ]
    );
    assert_eq!(
        rig.receiver.seen.lock()[0].url.as_str(),
        "https://hooks.example.test/string-form"
    );
    check_deliveries(&rig, &id, &json!({}));

    // an unknown event is a 400
    let (s, _, v) = rig
        .env
        .post(
            BATCH,
            &json!({"urls": [rig.url("/a")], "webhook": {"url": "https://hooks.example.test/x", "events": ["crawl.nope"]}}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    rig.stop().await;
}

#[tokio::test]
async fn a_failed_crawl_delivers_crawl_failed_with_an_error() {
    let rig = Rig::start(RigConfig {
        fail_page_writes: Some("/boom".to_owned()),
        ..RigConfig::default()
    })
    .await;
    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/boom"), "sitemap": "skip",
            "webhook": {"url": "https://hooks.example.test/fc", "metadata": {"job": "doomed"}, "headers": {"X-T": "t"}},
        }),
    )
    .await;
    let v = rig.wait_crawl(&id).await;
    assert_eq!(
        v["status"], "failed",
        "a storage failure of the url plane fails the run: {v}"
    );
    assert_eq!(v["terminalReason"], "fatal_error");
    rig.drain_webhooks().await;
    let types = rig.receiver.types();
    assert_eq!(
        types.first().map(String::as_str),
        Some("crawl.started"),
        "{types:?}"
    );
    assert_eq!(
        types.last().map(String::as_str),
        Some("crawl.failed"),
        "{types:?}"
    );
    assert!(!types.contains(&"crawl.completed".to_owned()), "{types:?}");
    check_deliveries(&rig, &id, &json!({"job": "doomed"}));
    let failed = rig.receiver.bodies().pop().unwrap();
    assert_eq!(failed["success"], false, "{failed}");
    assert_eq!(failed["data"], json!([]));
    let error = failed["error"].as_str().unwrap();
    assert!(
        error.contains("crawl failed") && error.contains("fatal_error"),
        "{error}"
    );
    let req = rig.receiver.seen.lock().last().cloned().unwrap();
    assert_eq!(header_of(&req, "X-T"), Some("t"));

    // the `failed` filter selects exactly this event
    rig.receiver.seen.lock().clear();
    let id = start_crawl(
        &rig,
        &json!({
            "url": rig.url("/boom"), "sitemap": "skip",
            "webhook": {"url": "https://hooks.example.test/fc", "events": ["crawl.failed"]},
        }),
    )
    .await;
    rig.wait_crawl(&id).await;
    rig.drain_webhooks().await;
    assert_eq!(rig.receiver.types(), ["crawl.failed"]);

    // a healthy crawl of the same site is unaffected
    rig.receiver.seen.lock().clear();
    let id = start_crawl(
        &rig,
        &json!({"url": rig.url("/a"), "sitemap": "skip", "limit": 1, "webhook": {"url": "https://hooks.example.test/fc"}}),
    )
    .await;
    rig.wait_crawl(&id).await;
    rig.drain_webhooks().await;
    assert_eq!(
        rig.receiver.types(),
        ["crawl.started", "crawl.page", "crawl.completed"]
    );
    rig.stop().await;
}

#[tokio::test]
async fn a_failed_batch_scrape_delivers_batch_scrape_failed_with_an_error() {
    let rig = Rig::start(RigConfig {
        fail_page_writes: Some("/boom".to_owned()),
        ..RigConfig::default()
    })
    .await;
    let id = start_batch(
        &rig,
        &json!({
            "urls": [rig.url("/boom"), rig.url("/a")],
            "webhook": {"url": "https://hooks.example.test/batch", "metadata": {"b": 1}},
        }),
    )
    .await;
    let v = wait_batch(&rig, &id).await;
    assert_eq!(v["status"], "failed", "{v}");
    rig.drain_webhooks().await;
    let types = rig.receiver.types();
    assert_eq!(
        types.first().map(String::as_str),
        Some("batch_scrape.started"),
        "{types:?}"
    );
    assert_eq!(
        types.last().map(String::as_str),
        Some("batch_scrape.failed"),
        "{types:?}"
    );
    check_deliveries(&rig, &id, &json!({"b": 1}));
    let failed = rig.receiver.bodies().pop().unwrap();
    assert_eq!(failed["success"], false, "{failed}");
    let error = failed["error"].as_str().unwrap();
    assert!(
        error.contains("batch_scrape failed") && error.contains("fatal_error"),
        "{error}"
    );

    rig.receiver.seen.lock().clear();
    let id = start_batch(
        &rig,
        &json!({
            "urls": [rig.url("/boom")],
            "webhook": {"url": "https://hooks.example.test/batch", "events": ["batch_scrape.failed"]},
        }),
    )
    .await;
    wait_batch(&rig, &id).await;
    rig.drain_webhooks().await;
    assert_eq!(rig.receiver.types(), ["batch_scrape.failed"]);
    rig.stop().await;
}
