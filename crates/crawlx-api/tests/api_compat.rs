#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The compat API compatibility facade: request translation, status mapping and warnings.
mod common;

use axum::http::{Method, StatusCode};
use chrono::Utc;
use common::env;
use crawlx_core::config::QueryPolicy;
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{FrontierRepo, FrontierStatus, PageRecord, PageRepo, RunRepo, Sensitivity};
use crawlx_core::{CrawlRunId, TrustLane};
use crawlx_storage::testkit;
use serde_json::{json, Value};

#[tokio::test]
async fn compat_create_maps_compat_options() {
    let e = env();
    let body = json!({
        "url": "https://docs.example.test/",
        "limit": 25,
        "includePaths": ["^/docs/"],
        "excludePaths": ["^/docs/old"],
        "maxDiscoveryDepth": 3,
        "sitemap": "skip",
        "ignoreQueryParameters": true,
        "crawlEntireDomain": true,
        "allowExternalLinks": false,
        "allowSubdomains": true,
        "delay": 2,
        "maxConcurrency": 8,
        "prompt": "only docs",
        "zeroDataRetention": false,
        "webhook": {"url": "https://hooks.example.test/fc", "events": ["started", "page", "completed"], "metadata": {"a": 1}},
        "scrapeOptions": {
            "formats": ["markdown", "html", "rawHtml"],
            "onlyMainContent": false,
            "includeTags": ["article"],
            "excludeTags": ["nav"],
            "waitFor": 750,
            "actions": [],
            "proxy": "enhanced"
        },
        "mystery": true,
    });
    let (s, h, v) = e.post("/compat/v2/crawl", &body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    let id = v["id"].as_str().unwrap();
    assert!(v["url"]
        .as_str()
        .unwrap()
        .ends_with(&format!("/compat/v2/crawl/{id}")));
    assert!(h.contains_key("x-request-id"));
    let warnings: Vec<(&str, &str)> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| (w["code"].as_str().unwrap(), w["path"].as_str().unwrap()))
        .collect();
    for expected in [
        ("query_strip_merges_resources", "/ignoreQueryParameters"),
        ("prompt_ignored", "/prompt"),
        ("concurrency_forced", "/maxConcurrency"),
        ("unsupported_option", "/mystery"),
    ] {
        assert!(
            warnings.contains(&expected),
            "{expected:?} missing in {warnings:?}"
        );
    }

    let run = e.store.get(id.parse().unwrap()).await.unwrap();
    let c = &run.config;
    assert_eq!(
        c.scrape.as_ref().unwrap().options.proxy,
        crawlx_core::scrape::ProxyMode::Enhanced,
    );
    assert_eq!(
        c.scope.query_policy,
        QueryPolicy::StripAll,
        "ignoreQueryParameters: true -> strip_all"
    );
    assert_eq!(c.limits.urls, 25);
    assert_eq!(c.scope.include_paths, vec!["^/docs/"]);
    assert_eq!(c.scope.exclude_paths, vec!["^/docs/old"]);
    assert_eq!(c.scope.max_discovery_depth, 3);
    assert_eq!(c.scope.sitemap, crawlx_core::config::SitemapMode::Skip);
    assert!(c.scope.crawl_entire_domain && c.scope.allow_subdomains && !c.scope.allow_external_links);
    assert_eq!(c.politeness.delay_ms, 2000);
    assert_eq!(c.mode, crawlx_core::config::CrawlMode::Static);
    assert!(!c.output.only_main_content);
    assert_eq!(c.output.include_tags, vec!["article"]);
    assert_eq!(c.output.exclude_tags, vec!["nav"]);
    assert_eq!(c.output.wait_for_ms, 750);
    let formats: Vec<_> = c.output.formats.iter().map(|f| format!("{f:?}")).collect();
    assert_eq!(formats, vec!["Metadata", "Markdown", "Html", "RawHtml"]);
    assert_eq!(
        c.politeness.max_concurrency, 1,
        "delay forces one request at a time"
    );
    assert_eq!(c.politeness.max_in_flight_per_origin, 1);
    let job = c.scrape.as_ref().unwrap();
    assert!(job.options.wants("rawHtml"), "the formats are the scrape job's");
    assert_eq!(
        job.webhook_metadata,
        json!({"a": 1}),
        "webhook.metadata is kept for the payloads"
    );
    let hook = c.output.webhook.as_ref().unwrap();
    assert_eq!(hook.url.as_str(), "https://hooks.example.test/fc");
    assert_eq!(hook.events, vec!["started", "page", "completed"]);
    assert_eq!(run.status, RunStatus::Queued);

    // the unset default keeps every query string distinct
    let (_, _, v) = e
        .post("/compat/v2/crawl", &json!({"url": "https://docs.example.test/"}))
        .await;
    let run = e
        .store
        .get(v["id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap();
    assert_eq!(run.config.scope.query_policy, QueryPolicy::KeepAll);
}

#[tokio::test]
async fn compat_errors_use_the_compat_shape_and_report_every_violation() {
    let e = env();
    let (s, _, v) = e
        .post("/compat/v2/crawl", &json!({"limit": 0, "sitemap": "weird"}))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["success"], false);
    assert!(v["error"].is_string());
    assert_eq!(v["code"], "BAD_REQUEST");
    assert!(v["details"].as_array().unwrap().len() >= 3);
    assert!(v["requestId"].is_string());

    let (s, _, v) = e
        .post("/compat/v2/crawl", &json!({"url": "http://localhost/"}))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "UNSUPPORTED_SITE", "{v}");

    let (s, _, v) = e.get(&format!("/compat/v2/crawl/{}", CrawlRunId::new())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["success"], false);
    let (s, _, _) = e
        .send(
            Method::POST,
            "/compat/v2/crawl",
            None,
            &[],
            Some(&json!({"url": "https://a.example.test/"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn compat_status_cancel_errors_and_idempotency_alias() {
    let e = env();
    let h = [("x-idempotency-key", "fc-1")];
    let body = json!({"url": "https://docs.example.test/", "limit": 10});
    let (s, _, v1) = e.post_with("/compat/v2/crawl", &h, &body).await;
    assert_eq!(s, StatusCode::OK, "{v1}");
    let (s, h2, v2) = e.post_with("/compat/v2/crawl", &h, &body).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h2["idempotent-replayed"], "true");
    assert_eq!(v1["id"], v2["id"]);
    let id = v1["id"].as_str().unwrap().to_owned();
    let run_id: CrawlRunId = id.parse().unwrap();
    let uri = format!("/compat/v2/crawl/{id}");

    // queued -> scraping
    let (s, _, v) = e.get(&uri).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    assert_eq!(v["status"], "scraping");
    assert_eq!(
        v["creditsUsed"], 0,
        "credits are real: a crawl without pages costs nothing"
    );
    assert_eq!(v["total"], 0);
    assert_eq!(v["completed"], 0);
    assert_eq!(v["data"], json!([]));
    assert_eq!(v["next"], Value::Null);
    assert_eq!(v["terminalReason"], Value::Null);
    assert!(v["counters"]["urls"].is_object());

    // pages show up as the compat API documents, with `next` pagination
    e.store
        .set_status(run_id, RunStatus::Running, None)
        .await
        .unwrap();
    for n in 1..=3i64 {
        let md = e
            .artifacts
            .put_kind(
                run_id,
                Sensitivity::Content,
                "markdown",
                "text/markdown",
                format!("# {n}").as_bytes(),
            )
            .await
            .unwrap();
        e.store
            .put(&PageRecord {
                run: run_id,
                frontier_id: n,
                url: testkit::canonical_url(&format!("https://docs.example.test/{n}")),
                status: 200,
                content_type: Some("text/html".to_owned()),
                content_digest: Digest::of("t", &[u8::try_from(n).unwrap()]),
                title: Some(format!("T{n}")),
                markdown: Some(md),
                html: None,
                metadata: json!({}),
                links: vec![],
                fetched_at: Utc::now(),
                lane: TrustLane::Diagnostic,
            })
            .await
            .unwrap();
    }
    let mut counters = PlaneCounters::default();
    counters.urls.admitted = 3;
    counters.urls.succeeded = 3;
    e.store.update_counters(run_id, counters).await.unwrap();
    let (_, _, v) = e.get(&format!("{uri}?limit=2")).await;
    assert_eq!(v["total"], 3);
    assert_eq!(v["creditsUsed"], 3, "one credit per stored page");
    assert_eq!(v["completed"], 3);
    assert_eq!(v["data"].as_array().unwrap().len(), 2);
    assert_eq!(v["data"][0]["markdown"], "# 1");
    assert_eq!(
        v["data"][0]["metadata"]["sourceURL"],
        "https://docs.example.test/1"
    );
    let next = v["next"].as_str().unwrap();
    assert!(
        next.contains("/compat/v2/crawl/") && next.contains("cursor="),
        "{next}"
    );
    let (_, _, v) = e.get(next).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 1);
    assert_eq!(v["next"], Value::Null);

    // Offset pagination has the same boundary while the crawl remains running.
    let (_, _, v) = e.get(&format!("{uri}?limit=2&skip=0")).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 2);
    let next = v["next"].as_str().unwrap();
    assert!(next.contains("limit=2") && next.ends_with("skip=2"), "{next}");
    let (_, _, v) = e.get(next).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 1);
    assert_eq!(v["next"], Value::Null);
    for query in ["limit=3", "limit=3&skip=0", "limit=2&skip=3", "limit=2&skip=4"] {
        let (s, _, v) = e.get(&format!("{uri}?{query}")).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["status"], "scraping");
        assert_eq!(v["next"], Value::Null, "{query}: {v}");
    }

    // errors: failed, robots-blocked and policy-blocked rows
    e.store
        .discover(
            run_id,
            &testkit::canonical_url("https://docs.example.test/robots"),
            1,
            None,
            Some((FrontierStatus::RobotsBlocked, "robots".to_owned())),
        )
        .await
        .unwrap();
    e.store
        .discover(
            run_id,
            &testkit::canonical_url("https://docs.example.test/out"),
            1,
            None,
            Some((FrontierStatus::PolicyBlocked, "out_of_scope".to_owned())),
        )
        .await
        .unwrap();
    e.store
        .discover(
            run_id,
            &testkit::canonical_url("https://docs.example.test/bad"),
            1,
            None,
            None,
        )
        .await
        .unwrap();
    let leased = e
        .store
        .lease_batch(run_id, crawlx_core::WorkerId::new(), 10)
        .await
        .unwrap();
    assert_eq!(leased.len(), 1);
    e.store
        .complete(leased[0].id, FrontierStatus::Failed, Some("http_500".to_owned()))
        .await
        .unwrap();
    let (s, _, v) = e.get(&format!("{uri}/errors")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["robotsBlocked"], json!(["https://docs.example.test/robots"]));
    assert_eq!(v["policyBlocked"][0]["reason"], "out_of_scope");
    assert_eq!(v["errors"][0]["url"], "https://docs.example.test/bad");
    assert_eq!(v["errors"][0]["code"], "SCRAPE_SITE_ERROR");
    assert!(
        v["errors"][0]["error"]
            .as_str()
            .unwrap()
            .ends_with("(reason: http_500)"),
        "{v}"
    );
    assert!(v["errors"][0]["timestamp"].is_string());

    // DELETE cancels
    let (s, _, v) = e.delete(&uri).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "cancelled");
    let (_, _, v) = e.get(&uri).await;
    assert_eq!(v["status"], "cancelled");
    assert_eq!(v["terminalReason"], "cancelled");
    assert!(v["expiresAt"].is_string());
    let (s, _, _) = e.delete(&uri).await;
    assert_eq!(s, StatusCode::OK, "repeat delete is idempotent");

    // completed and failed map one to one
    for (st, reason, want) in [
        (
            RunStatus::Completed,
            TerminalReason::FrontierExhausted,
            "completed",
        ),
        (RunStatus::Failed, TerminalReason::FatalError, "failed"),
    ] {
        let (_, _, c) = e
            .post("/compat/v2/crawl", &json!({"url": "https://docs.example.test/"}))
            .await;
        let rid: CrawlRunId = c["id"].as_str().unwrap().parse().unwrap();
        e.store.set_status(rid, st, Some(reason)).await.unwrap();
        let (_, _, v) = e.get(&format!("/compat/v2/crawl/{rid}")).await;
        assert_eq!(v["status"], want);
        assert_eq!(v["terminalReason"], reason.as_str());
    }
}

#[tokio::test]
async fn compat_zdr_runs_return_no_data() {
    let e = env();
    let (_, _, c) = e
        .post(
            "/compat/v2/crawl",
            &json!({"url": "https://docs.example.test/", "zeroDataRetention": true}),
        )
        .await;
    let id = c["id"].as_str().unwrap();
    let (s, _, v) = e.get(&format!("/compat/v2/crawl/{id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["data"], json!([]));
}
