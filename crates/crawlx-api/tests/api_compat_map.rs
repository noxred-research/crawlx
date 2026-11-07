#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Firecrawl v2 `POST /map`, the request fields that read the store and the request headers:
//! `ignoreCache` (the live results are extended with the URLs earlier
//! crawls and scrapes of the same tenant stored for the site, unless it is true) and
//! `location{country, languages}` (the `Accept-Language` the fixture site receives), end to end
//! through a REAL worker lease loop over the same store as the API (see `scrape_rig`).
mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use axum::http::{Method, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use crawlx_api::Scope;
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{FrontierRepo, PageRecord, PageRepo, RunRepo};
use crawlx_core::scrape::{ScrapeDocument, ScrapeOptions};
use crawlx_core::{CrawlRunId, TenantId, TrustLane};
use crawlx_storage::testkit;
use scrape_rig::{Rig, RigConfig};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;

const MAP: &str = "/compat/firecrawl/v2/map";
const CRAWL: &str = "/compat/firecrawl/v2/crawl";
const SCRAPE: &str = "/compat/firecrawl/v2/scrape";

/// The `url` of every link of a map body, in order.
fn links(v: &Value) -> Vec<String> {
    v["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["url"].as_str().unwrap().to_owned())
        .collect()
}

/// `(code, path)` of every warning of a body.
fn warnings(v: &Value) -> Vec<(String, String)> {
    v["warnings"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|w| {
                    (
                        w["code"].as_str().unwrap().to_owned(),
                        w["path"].as_str().unwrap().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The `map_cached_sources` warning of a body, if any.
fn cached_warning(v: &Value) -> Option<&Value> {
    v["warnings"]
        .as_array()?
        .iter()
        .find(|w| w["code"] == "map_cached_sources")
}

/// `POST /map` as the acme key expecting `200 {success: true}`.
async fn map(rig: &Rig, body: Value) -> Value {
    let (s, _, v) = rig.env.post(MAP, &body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true, "{v}");
    v
}

/// `POST /scrape` as `key` (the acme key when `None`) expecting `200 {success: true}`.
async fn scrape_as(rig: &Rig, key: Option<&str>, body: Value) {
    let key = key.unwrap_or(&rig.env.key);
    let (s, _, b) = rig
        .env
        .send(Method::POST, SCRAPE, Some(key), &[], Some(&body))
        .await;
    let v = common::json(&b);
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true, "{v}");
}

/// Poll the facade status of crawl `id` until it is no longer `scraping`.
async fn wait_crawl(rig: &Rig, id: &str) -> Value {
    let uri = format!("{CRAWL}/{id}?limit=1000");
    for _ in 0..600 {
        let (_, _, v) = rig.env.get(&uri).await;
        if v["status"] != "scraping" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("crawl {id} did not finish in 30 s");
}

/// A finished run of `tenant` holding the given pages, written straight into the store: a run in
/// the given retention mode, created `age` ago with `days` of retention. Every page is `(url,
/// status, cacheable)`.
async fn stored_run(
    rig: &Rig,
    tenant: TenantId,
    mode: RetentionMode,
    days: u16,
    age: ChronoDuration,
    pages: &[(String, u16, bool)],
) -> CrawlRunId {
    let store = rig.env.store.as_ref();
    let mut cfg = testkit::create_crawl("https://site.example.test/", &[], 1);
    cfg.retention.mode = mode;
    cfg.retention.days = days;
    let mut run = testkit::crawl_run(tenant, cfg);
    // finished, so the worker's lease loop leaves it alone
    run.status = RunStatus::Completed;
    run.terminal_reason = Some(TerminalReason::FrontierExhausted);
    run.created_at = Utc::now() - age;
    run.finished_at = Some(run.created_at);
    RunRepo::create(store, &run, None).await.unwrap();
    for (url, status, cacheable) in pages {
        let url = testkit::canonical_url(url);
        let (_, frontier) = FrontierRepo::discover(store, run.id, &url, 0, None, None)
            .await
            .unwrap();
        let mut metadata = json!({});
        if !cacheable {
            let mut doc = ScrapeDocument::new(
                url.url.to_string(),
                url.url.to_string(),
                *status,
                ScrapeOptions::default().cache_digest(),
            );
            doc.not_cacheable = true;
            metadata[ScrapeDocument::METADATA_KEY] = serde_json::to_value(&doc).unwrap();
        }
        PageRepo::put(
            store,
            &PageRecord {
                run: run.id,
                frontier_id: frontier.unwrap(),
                url: url.clone(),
                status: *status,
                content_type: Some("text/html".to_owned()),
                content_digest: Digest::of("t", url.url.as_str().as_bytes()),
                title: Some("Stored by hand".to_owned()),
                markdown: None,
                html: None,
                metadata,
                links: Vec::new(),
                fetched_at: run.created_at,
                lane: TrustLane::Diagnostic,
            },
        )
        .await
        .unwrap();
    }
    run.id
}

#[tokio::test]
async fn a_map_lists_the_urls_of_prior_crawls_unless_ignore_cache_is_true() {
    let rig = Rig::start(RigConfig::default()).await;
    // a crawl of the fixture site: `/a` and `/b` are reachable only from the home page
    let (s, _, v) = rig
        .env
        .post(
            CRAWL,
            &json!({
                "url": rig.url("/"), "sitemap": "skip", "limit": 20,
                "scrapeOptions": {"formats": ["markdown", "links"]},
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let done = wait_crawl(&rig, v["id"].as_str().unwrap()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert!(
        rig.site.hits("/b") > 0 && rig.site.hits("/a") > 0,
        "the crawl fetched both pages"
    );

    // another entry of the same site: `/docs/a` links `/docs/b`, `/other/c` and the home page
    let seed = rig.url("/docs/a");
    let live = map(&rig, json!({"url": seed, "sitemap": "skip", "ignoreCache": true})).await;
    let live_links = links(&live);
    for path in ["/docs/a", "/docs/b", "/other/c", "/"] {
        assert!(live_links.contains(&rig.url(path)), "{path} in {live_links:?}");
    }
    assert!(
        !live_links.contains(&rig.url("/b")),
        "the live map does not reach `/b`: {live_links:?}"
    );
    assert!(
        cached_warning(&live).is_none(),
        "ignoreCache reads nothing from the store: {live}"
    );

    let cached = map(&rig, json!({"url": seed, "sitemap": "skip"})).await;
    let cached_links = links(&cached);
    assert_eq!(
        cached_links[..live_links.len()],
        live_links[..],
        "the live results keep their entries and their order"
    );
    let extra: Vec<&String> = cached_links[live_links.len()..].iter().collect();
    for path in ["/a", "/b"] {
        assert!(extra.contains(&&rig.url(path)), "{path} in {extra:?}");
    }
    let set: BTreeSet<&String> = cached_links.iter().collect();
    assert_eq!(
        set.len(),
        cached_links.len(),
        "one entry per URL: {cached_links:?}"
    );
    assert!(
        !cached_links.iter().any(|u| u.contains("other.example")),
        "links outside the host scope are never listed: {cached_links:?}"
    );
    let warning = cached_warning(&cached).expect("map_cached_sources");
    assert_eq!(warning["path"], "/ignoreCache");
    assert!(
        warning["message"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{} URLs", extra.len())),
        "{warning}"
    );
    // titles come with the stored pages
    let b = cached["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["url"] == rig.url("/b"))
        .unwrap();
    assert_eq!(b["title"], "Page B", "{b}");

    // ignoreCache false is the default
    let explicit = map(
        &rig,
        json!({"url": seed, "sitemap": "skip", "ignoreCache": false}),
    )
    .await;
    assert_eq!(links(&explicit), cached_links);

    // `limit` cuts the merged list, `search` orders it first
    let one_more = map(
        &rig,
        json!({"url": seed, "sitemap": "skip", "limit": live_links.len() + 1}),
    )
    .await;
    assert_eq!(links(&one_more).len(), live_links.len() + 1);
    assert_eq!(links(&one_more)[..live_links.len()], live_links[..]);
    let ranked = map(
        &rig,
        json!({"url": seed, "sitemap": "skip", "search": "b", "limit": 2}),
    )
    .await;
    assert_eq!(
        links(&ranked),
        [rig.url("/b"), rig.url("/docs/b")],
        "both URLs have the token `b`; the stored page's title `Page B` ranks it first"
    );
    let all = map(&rig, json!({"url": seed, "sitemap": "skip", "search": "b"})).await;
    assert_eq!(
        links(&all).len(),
        cached_links.len(),
        "search orders the links, it never drops one"
    );

    // `sitemap: only` lists the sitemap: no stored URL joins it
    let only = map(&rig, json!({"url": seed, "sitemap": "only"})).await;
    assert!(cached_warning(&only).is_none(), "{only}");
    assert!(!links(&only).contains(&rig.url("/b")), "{only}");

    // the default is to read the store: a map without options sees the crawl as well
    let plain = map(&rig, json!({"url": seed})).await;
    assert!(links(&plain).contains(&rig.url("/b")), "{plain}");
    rig.stop().await;
}

#[tokio::test]
async fn stored_urls_never_cross_tenants_or_come_from_zdr_expired_error_or_foreign_pages() {
    let rig = Rig::start(RigConfig::default()).await;
    let globex = rig
        .env
        .key_for("globex", &[Scope::CrawlsRead, Scope::CrawlsWrite])
        .await;
    let seed = rig.url("/docs/a");

    // acme: a scrape of the home page (its links are stored with it) and a ZDR scrape
    scrape_as(
        &rig,
        None,
        json!({"url": rig.url("/"), "formats": ["markdown", "links"]}),
    )
    .await;
    scrape_as(
        &rig,
        None,
        json!({"url": rig.url("/versioned"), "zeroDataRetention": true}),
    )
    .await;
    // globex: a scrape of `/c`
    scrape_as(&rig, Some(&globex), json!({"url": rig.url("/c")})).await;
    // acme, by hand: a good page, a ZDR run's cacheable page, an expired run, an error page, a
    // page flagged not cacheable and a page of another site
    let acme = rig.env.tenant;
    let now = ChronoDuration::zero();
    stored_run(
        &rig,
        acme,
        RetentionMode::Standard,
        7,
        now,
        &[
            (rig.url("/stored-ok"), 200, true),
            (rig.url("/error-page"), 500, true),
            (rig.url("/uncacheable"), 200, false),
            ("https://other.example/page".to_owned(), 200, true),
        ],
    )
    .await;
    stored_run(
        &rig,
        acme,
        RetentionMode::Zdr,
        0,
        now,
        &[(rig.url("/zdr-run-page"), 200, true)],
    )
    .await;
    stored_run(
        &rig,
        acme,
        RetentionMode::Standard,
        1,
        ChronoDuration::days(3),
        &[(rig.url("/expired-page"), 200, true)],
    )
    .await;

    let acme_links = links(&map(&rig, json!({"url": seed, "sitemap": "skip"})).await);
    for path in ["/", "/a", "/b", "/nav-only", "/stored-ok"] {
        assert!(
            acme_links.contains(&rig.url(path)),
            "{path} (a stored page or a link of one) in {acme_links:?}"
        );
    }
    for path in [
        "/c",
        "/versioned",
        "/zdr-run-page",
        "/expired-page",
        "/error-page",
        "/uncacheable",
    ] {
        assert!(
            !acme_links.contains(&rig.url(path)),
            "{path} must not be listed: {acme_links:?}"
        );
    }
    assert!(
        !acme_links.iter().any(|u| u.contains("other.example")),
        "{acme_links:?}"
    );

    // globex sees its own page and none of acme's
    let (s, _, b) = rig
        .env
        .send(
            Method::POST,
            MAP,
            Some(&globex),
            &[],
            Some(&json!({"url": seed, "sitemap": "skip"})),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let globex_links = links(&common::json(&b));
    assert!(globex_links.contains(&rig.url("/c")), "{globex_links:?}");
    for path in ["/a", "/b", "/nav-only", "/stored-ok"] {
        assert!(
            !globex_links.contains(&rig.url(path)),
            "{path} belongs to acme: {globex_links:?}"
        );
    }

    // with ignoreCache the store is not read at all
    let fresh = links(&map(&rig, json!({"url": seed, "sitemap": "skip", "ignoreCache": true})).await);
    for path in ["/a", "/b", "/stored-ok", "/nav-only"] {
        assert!(!fresh.contains(&rig.url(path)), "{path} in {fresh:?}");
    }
    rig.stop().await;
}

#[tokio::test]
async fn include_subdomains_picks_the_registrable_domain_or_the_host_of_the_stored_urls() {
    let rig = Rig::start(RigConfig::default()).await;
    let acme = rig.env.tenant;
    let sub = format!("http://blog.site.example.test:{}/sub-page", rig.site.port);
    let sibling = format!("http://www.example.test:{}/sibling-page", rig.site.port);
    let foreign = "http://www.example.org/foreign-page".to_owned();
    stored_run(
        &rig,
        acme,
        RetentionMode::Standard,
        7,
        ChronoDuration::zero(),
        &[
            (rig.url("/own-page"), 200, true),
            (sub.clone(), 200, true),
            (sibling.clone(), 200, true),
            (foreign.clone(), 200, true),
        ],
    )
    .await;
    let seed = rig.url("/docs/a");
    let with = links(&map(&rig, json!({"url": seed, "sitemap": "skip"})).await);
    assert!(with.contains(&rig.url("/own-page")), "{with:?}");
    assert!(with.contains(&sub), "a subdomain of the host: {with:?}");
    assert!(
        with.contains(&sibling),
        "a sibling host is in the registrable domain `example.test`: {with:?}"
    );
    assert!(!with.contains(&foreign), "another domain: {with:?}");
    let without = links(
        &map(
            &rig,
            json!({"url": seed, "sitemap": "skip", "includeSubdomains": false}),
        )
        .await,
    );
    assert!(without.contains(&rig.url("/own-page")), "{without:?}");
    assert!(!without.contains(&sub), "{without:?}");
    assert!(
        !without.contains(&sibling),
        "under includeSubdomains: false only the seed's host counts: {without:?}"
    );
    assert!(!without.contains(&foreign), "{without:?}");
    rig.stop().await;
}

#[tokio::test]
async fn location_reaches_the_site_as_accept_language_and_only_the_missing_proxy_is_reported() {
    let rig = Rig::start(RigConfig::default()).await;
    let language_of = |rig: &Rig| {
        rig.site
            .headers
            .lock()
            .get("/")
            .and_then(|h| h.get("accept-language"))
            .cloned()
    };
    for (location, expected) in [
        (json!({"country": "DE", "languages": ["de-DE"]}), Some("de-DE")),
        (json!({"country": "DE"}), Some("de-DE")),
        (
            json!({"country": "FR", "languages": ["fr-FR", "en", "de"]}),
            Some("fr-FR,en;q=0.9,de;q=0.8"),
        ),
        (json!({"languages": ["pt-BR", "en"]}), Some("pt-BR,en;q=0.9")),
    ] {
        rig.site.headers.lock().clear();
        let v = map(
            &rig,
            json!({"url": rig.url("/"), "sitemap": "skip", "location": location}),
        )
        .await;
        assert_eq!(language_of(&rig).as_deref(), expected, "{location}: {v}");
        let w = warnings(&v);
        assert!(
            !w.contains(&("unsupported_option".to_owned(), "/location/country".to_owned())),
            "the country is applied now: {v}"
        );
        assert_eq!(
            w.contains(&("location_no_proxy".to_owned(), "/location/country".to_owned())),
            location.get("country").is_some(),
            "{location}: {v}"
        );
    }

    // the explanation names the missing proxy
    let v = map(
        &rig,
        json!({"url": rig.url("/"), "sitemap": "skip", "location": {"country": "DE"}}),
    )
    .await;
    let note = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "location_no_proxy")
        .unwrap();
    assert!(
        note["message"]
            .as_str()
            .unwrap()
            .contains("no geo-located proxies"),
        "{note}"
    );

    // no location: the map sends no language of its own
    rig.site.headers.lock().clear();
    let v = map(&rig, json!({"url": rig.url("/"), "sitemap": "skip"})).await;
    assert_eq!(language_of(&rig), None, "{v}");
    assert!(
        warnings(&v)
            .iter()
            .all(|(code, path)| !path.starts_with("/location") && code != "location_no_proxy"),
        "{v}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn map_rejects_a_non_boolean_ignore_cache() {
    let e = common::env();
    let (s, _, v) = e
        .post(
            MAP,
            &json!({"url": "https://a.example.test/", "ignoreCache": "yes"}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "BAD_REQUEST");
    assert!(
        v["details"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["path"] == "/ignoreCache"),
        "{v}"
    );
}
