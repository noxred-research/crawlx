#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Auth, scopes, rate limits, idempotency, envelope shape and run lifecycle verbs.
mod common;

use axum::http::{Method, StatusCode};
use common::{env, env_with, simple_body};
use crawlx_api::{ApiConfig, Scope, Settings};
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{EventRepo, RunRepo};
use crawlx_core::{CrawlRunId, SystemClock};
use serde_json::{json, Value};
use std::sync::Arc;

#[tokio::test]
async fn missing_and_invalid_keys_are_unauthenticated() {
    let e = env();
    let (s, h, _) = e.send(Method::GET, "/v1/crawls/x", None, &[], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(h["www-authenticate"], "Bearer");
    let (s, h, b) = e
        .send(Method::POST, "/v1/crawls", None, &[], Some(&simple_body()))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let v = common::json(&b);
    assert_eq!(v["error"]["code"], "unauthenticated");
    assert_eq!(v["error"]["retryable"], false);
    assert_eq!(v["error"]["details"], json!([]));
    assert_eq!(v["error"]["requestId"], h["x-request-id"].to_str().unwrap());

    for bad in [
        "cx_live_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "cx_live_short",
        "Bearer-less",
        "cx_test_abcdefghijklmnopqrstuvwxyz",
    ] {
        let (s, _, _) = e.send(Method::GET, "/v1/crawls/x", Some(bad), &[], None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{bad}");
    }
    // right prefix, wrong secret tail
    let mut tampered = e.key.clone();
    tampered.pop();
    tampered.push(if e.key.ends_with('a') { 'b' } else { 'a' });
    let (s, _, _) = e
        .send(Method::GET, "/v1/crawls/x", Some(&tampered), &[], None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_scope_is_forbidden_and_other_tenants_get_404() {
    let e = env();
    let reader = e.key_for("acme", &[Scope::CrawlsRead]).await;
    let (s, _, b) = e
        .send(
            Method::POST,
            "/v1/crawls",
            Some(&reader),
            &[],
            Some(&simple_body()),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(common::json(&b)["error"]["code"], "scope_missing");

    let id = e.create_run(&simple_body()).await;
    let (s, _, v) = e.get_as(&reader, &format!("/v1/crawls/{id}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = e
        .send(
            Method::POST,
            &format!("/v1/crawls/{id}:cancel"),
            Some(&reader),
            &[],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{}", common::json(&v));

    let other = e.key_for("globex", &Scope::ALL).await;
    let (s, _, v) = e.get_as(&other, &format!("/v1/crawls/{id}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["code"], "not_found");
    let (s, _, _) = e
        .get_as(&e.key, &format!("/v1/crawls/{}", CrawlRunId::new()))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = e.get_as(&e.key, "/v1/crawls/not-a-uuid").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn token_bucket_limits_per_tenant_and_reports_headers() {
    let cfg = ApiConfig {
        rate_limit_per_minute: 2,
        ..ApiConfig::default()
    };
    let e = env_with(cfg, Settings::default(), Arc::new(SystemClock));
    let (s, h, _) = e.get(&format!("/v1/crawls/{}", CrawlRunId::new())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(h["ratelimit-limit"], "2");
    assert_eq!(h["ratelimit-remaining"], "1");
    e.get("/v1/crawls/x").await;
    let (s, h, v) = e.get("/v1/crawls/x").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v["error"]["code"], "rate_limited");
    assert_eq!(v["error"]["retryable"], true);
    assert!(h.contains_key("retry-after"));
    // another tenant has its own bucket
    let other = e.key_for("globex", &Scope::ALL).await;
    let (s, _, _) = e.get_as(&other, "/v1/crawls/x").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn native_sitemap_lastmod_schema_and_api_preserve_typed_policy() {
    use crawlx_core::discovery::SitemapUnknownLastmodV1;
    use crawlx_storage::WorkerRegistry as _;
    let e = env();
    let worker = crawlx_core::WorkerId::new();
    e.store
        .register_worker(worker, "lastmod-api-fixture", "1")
        .await
        .unwrap();
    e.store
        .publish_acquisition_capabilities(
            worker,
            &[crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
                "fixture", "1",
            )],
        )
        .await
        .unwrap();
    let document = crawlx_api::openapi::document();
    let schema = &document["paths"]["/v1/crawls"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]["properties"]["scope"]["properties"]["discovery"];
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(schema)
        .unwrap();
    for (range, expected) in [
        (
            json!({"lower":"2026-01-02T02:00:00+02:00"}),
            SitemapUnknownLastmodV1::Include,
        ),
        (
            json!({"upper":"2026-01-03T00:00:00Z","missingOrUnparseable":"exclude"}),
            SitemapUnknownLastmodV1::Exclude,
        ),
    ] {
        let discovery = json!({"sitemapLastmod":range});
        assert!(validator.is_valid(&discovery));
        let (status, _, body) = e
            .post(
                "/v1/crawls",
                &json!({
                    "seedUrl":"https://app.example.test/", "mode":"static", "seed":7,
                    "scope":{"sources":["sitemap"],"discovery":discovery}
                }),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let run = e
            .store
            .get(body["id"].as_str().unwrap().parse().unwrap())
            .await
            .unwrap();
        let policy = run
            .config
            .scope
            .discovery
            .as_ref()
            .unwrap()
            .sitemap_lastmod
            .as_ref()
            .unwrap();
        assert_eq!(policy.missing_or_unparseable, expected);
        let inside = "2026-01-02T00:00:00Z".parse().unwrap();
        assert!(policy.includes(Some(&inside)));
        assert_eq!(
            policy.includes(None),
            expected == SitemapUnknownLastmodV1::Include
        );
    }
    for range in [
        json!({}),
        json!({"lower":null,"upper":null}),
        json!({"lower":"2026-01-02"}),
        json!({"lower":"2026-01-02T00:00:00"}),
        json!({"upper":"2026-01-03T00:00:00Z","relativeDays":7}),
        json!({"lower":"2026-01-03T00:00:00Z","upper":"2026-01-02T00:00:00Z"}),
    ] {
        let (status, _, _) = e
            .post(
                "/v1/crawls",
                &json!({
                    "seedUrl":"https://app.example.test/", "scope":{"discovery":{"sitemapLastmod":range}}
                }),
            )
            .await;
        assert!(status.is_client_error(), "{range}: {status}");
    }
}

#[tokio::test]
async fn create_returns_202_location_and_queued_zero_counters() {
    let e = env();
    let body = json!({"seedUrl": "https://app.example.test/", "seed": 7,
        "roles": [{"name": "anonymous"}, {"name": "member"}], "runsPerRole": 2});
    let (s, h, v) = e.post("/v1/crawls", &body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let id = v["id"].as_str().unwrap();
    assert_eq!(h["location"], format!("/v1/crawls/{id}").as_str());
    assert!(h.contains_key("x-request-id"));
    assert_eq!(v["status"], "queued");
    assert_eq!(v["seed"], 7);
    assert_eq!(v["terminalReason"], Value::Null);
    assert_eq!(v["links"]["events"], format!("/v1/crawls/{id}/events").as_str());

    let (s, _, g) = e.get(&format!("/v1/crawls/{id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(g["status"], "queued");
    for plane in ["urls", "interactions", "states"] {
        for (k, val) in g["counters"][plane].as_object().unwrap() {
            assert_eq!(val, 0, "{plane}.{k}");
        }
    }
    assert_eq!(g["sessions"].as_array().unwrap().len(), 4);
    assert_eq!(g["coverage"]["discovered"], 0);
    assert_eq!(g["safetyProfile"], "read_only");
    assert_eq!(g["versions"]["policy"], 1);

    let run = e.store.get(id.parse().unwrap()).await.unwrap();
    assert_eq!(run.status, RunStatus::Queued);
    assert_eq!(run.tenant, e.tenant);
    assert_eq!(run.config.seed, Some(7));
    // an omitted seed is drawn by the server and returned
    let (_, _, v) = e
        .post("/v1/crawls", &json!({"seedUrl": "https://app.example.test/"}))
        .await;
    assert!(v["seed"].as_u64().is_some());
}

#[tokio::test]
async fn native_create_omitted_strategy_persists_breadth_first() {
    let e = env();
    for body in [
        json!({"seedUrl": "https://app.example.test/"}),
        json!({"seedUrl": "https://app.example.test/", "scope": {}}),
    ] {
        let id = e.create_run(&body).await;
        let run = e.store.get(id.parse().unwrap()).await.unwrap();
        assert_eq!(
            run.config.scope.strategy,
            crawlx_core::config::CrawlStrategy::BreadthFirst
        );
        assert_eq!(
            serde_json::to_value(&run.config).unwrap()["scope"]["strategy"],
            "breadth_first"
        );
    }
}

#[tokio::test]
async fn clamps_are_reported_as_warnings() {
    let mut settings = Settings::default();
    settings.tenant_limits.max_urls = 50;
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let e = env_with(cfg, settings, Arc::new(SystemClock));
    let (s, _, v) = e
        .post(
            "/v1/crawls",
            &json!({"seedUrl": "https://app.example.test/", "limits": {"urls": 5000}}),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let w = v["warnings"].as_array().unwrap();
    assert!(
        w.iter()
            .any(|x| x["code"] == "limit_clamped" && x["path"] == "/limits/urls"),
        "{w:?}"
    );
}

#[tokio::test]
async fn validation_lists_every_violation() {
    let e = env();
    let body = json!({
        "seedUrl": "https://app.example.test/",
        "safety": {"profile": "read_only", "externalCommunication": "test_sinks", "destructiveActions": "approval"},
        "dynamic": {"launchProfile": "stealth"},
        "mode": "static",
        "bogus": 1,
        "scope": {"nope": true},
    });
    let (s, _, v) = e.post("/v1/crawls", &body).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["code"], "validation_failed");
    let details = v["error"]["details"].as_array().unwrap();
    let codes: Vec<(&str, &str)> = details
        .iter()
        .map(|d| (d["path"].as_str().unwrap(), d["code"].as_str().unwrap()))
        .collect();
    assert!(details.len() >= 5, "{codes:?}");
    assert!(codes.contains(&("/bogus", "unknown_field")), "{codes:?}");
    assert!(codes.contains(&("/scope/nope", "unknown_field")), "{codes:?}");
    assert!(
        codes.contains(&("/safety/externalCommunication", "profile_conflict")),
        "{codes:?}"
    );
    assert!(
        codes.contains(&("/safety/destructiveActions", "profile_conflict")),
        "{codes:?}"
    );
    assert!(
        codes.contains(&("/dynamic/launchProfile", "profile_conflict")),
        "{codes:?}"
    );
    // nothing was persisted
    assert_eq!(
        crawlx_api::ApiStore::active_run_count(e.api.as_ref(), e.tenant)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn malformed_scrape_content_policy_is_rejected_before_native_or_facade_queueing() {
    let e = env();
    for policy in [
        json!({"dateTimezone": "Not/A_Timezone"}),
        json!({"selectors": {"include": [{"kind": "css", "expression": "["}]}}),
        json!({"selectors": {"readMore": [{"kind": "xpath", "expression": "//missing:article"}]}}),
    ] {
        let (status, _, body) = e
            .post(
                "/v1/crawls",
                &json!({
                    "seedUrl": "https://app.example.test/article", "mode": "static",
                    "extract": {"content": {}},
                    "scrape": {"kind": "scrape", "options": {"contentPolicy": policy.clone()}}
                }),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["error"]["details"]
                .as_array()
                .unwrap()
                .iter()
                .any(|detail| detail["path"] == "/scrape/options/contentPolicy"
                    && detail["code"] == "invalid_content_policy"),
            "{body}"
        );

        for (path, request) in [
            (
                "/compat/v2/scrape",
                json!({
                    "url": "https://app.example.test/article", "contentPolicy": policy.clone(),
                    "cache": {"mode": "read_only"}
                }),
            ),
            (
                "/compat/v2/batch/scrape",
                json!({
                    "urls": ["https://app.example.test/article"], "contentPolicy": policy.clone()
                }),
            ),
            (
                "/compat/v2/crawl",
                json!({
                    "url": "https://app.example.test/article", "scrapeOptions": {"contentPolicy": policy.clone()}
                }),
            ),
        ] {
            let (status, _, body) = e.post(path, &request).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert!(
                body.to_string().contains("invalid_content_policy"),
                "{path}: {body}"
            );
        }
        assert_eq!(
            crawlx_api::ApiStore::active_run_count(e.api.as_ref(), e.tenant)
                .await
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
async fn bad_bodies_and_urls_have_specific_codes() {
    let e = env();
    let (s, _, b) = e.send(Method::POST, "/v1/crawls", Some(&e.key), &[], None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{}", common::json(&b));

    let (s, _, v) = e.post("/v1/crawls", &json!({})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error"]["details"][0]["code"], "required");
    assert_eq!(v["error"]["details"][0]["path"], "/seedUrl");

    let (s, _, v) = e
        .post("/v1/crawls", &json!({"seedUrl": "http://127.0.0.1/"}))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error"]["code"], "url_denied", "{v}");

    let (s, _, v) = e
        .post("/v1/crawls", &json!({"seedUrl": "https://app.example.test/", "safety": {"profile": "authorized_security_test"}}))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error"]["code"], "authorization_required", "{v}");

    let (s, _, b) = e
        .send(
            Method::POST,
            "/v1/crawls",
            Some(&e.key),
            &[("content-type", "application/json")],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{}", common::json(&b));
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/v1/crawls")
        .header("authorization", format!("Bearer {}", e.key))
        .body(axum::body::Body::from("{not json"))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(e.app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let huge = json!({"seedUrl": "https://app.example.test/", "pad": "x".repeat(300 * 1024)});
    let (s, _, v) = e.post("/v1/crawls", &huge).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(v["error"]["code"], "payload_too_large");

    let (s, h, v) = e.send(Method::PUT, "/v1/crawls", Some(&e.key), &[], None).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(common::json(&v)["error"]["code"], "method_not_allowed");
    assert!(h.contains_key("x-request-id"));
    let (s, _, v) = e.get("/v1/nothing-here").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["code"], "not_found");
}

#[tokio::test]
async fn active_run_quota_is_enforced() {
    let settings = Settings {
        max_active_runs: 2,
        ..Settings::default()
    };
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let e = env_with(cfg, settings, Arc::new(SystemClock));
    let first = e.create_run(&simple_body()).await;
    e.create_run(&simple_body()).await;
    let (s, _, v) = e.post("/v1/crawls", &simple_body()).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v["error"]["code"], "quota_exceeded");
    // finishing a run frees a slot
    e.post_empty(&format!("/v1/crawls/{first}:cancel")).await;
    let (s, _, _) = e.post("/v1/crawls", &simple_body()).await;
    assert_eq!(s, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn idempotency_replays_and_detects_mismatch() {
    let e = env();
    let h = [("Idempotency-Key", "key-1")];
    let (s1, _, v1) = e.post_with("/v1/crawls", &h, &simple_body()).await;
    assert_eq!(s1, StatusCode::ACCEPTED, "{v1}");
    // key order does not matter: canonical JSON
    let reordered = json!({"seed": 7, "seedUrl": "https://app.example.test/"});
    let (s2, h2, v2) = e.post_with("/v1/crawls", &h, &reordered).await;
    assert_eq!(s2, StatusCode::ACCEPTED);
    assert_eq!(h2["idempotent-replayed"], "true");
    assert_eq!(
        h2["location"],
        format!("/v1/crawls/{}", v1["id"].as_str().unwrap()).as_str()
    );
    assert_eq!(v1["id"], v2["id"]);
    assert_eq!(
        crawlx_api::ApiStore::active_run_count(e.api.as_ref(), e.tenant)
            .await
            .unwrap(),
        1
    );

    let (s3, _, v3) = e
        .post_with(
            "/v1/crawls",
            &h,
            &json!({"seedUrl": "https://other.example.test/"}),
        )
        .await;
    assert_eq!(s3, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v3["error"]["code"], "idempotency_key_reuse");

    // keys are scoped by tenant
    let other = e.key_for("globex", &Scope::ALL).await;
    let (s, _, b) = e
        .send(
            Method::POST,
            "/v1/crawls",
            Some(&other),
            &[("Idempotency-Key", "key-1")],
            Some(&simple_body()),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{}", common::json(&b));

    // an in-flight key answers 409 idempotency_in_progress
    let hash = crawlx_api::util::request_hash("POST", "/v1/crawls", &simple_body());
    crawlx_api::ApiStore::idem_begin(e.api.as_ref(), e.tenant, "busy", hash, chrono::Utc::now())
        .await
        .unwrap();
    let (s, _, v) = e
        .post_with("/v1/crawls", &[("Idempotency-Key", "busy")], &simple_body())
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["error"]["code"], "idempotency_in_progress");
    assert_eq!(v["error"]["retryable"], true);

    // a failed request releases its key
    let bad = json!({"seedUrl": "ftp://nope/"});
    let (s, _, _) = e
        .post_with("/v1/crawls", &[("Idempotency-Key", "retry")], &bad)
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _, _) = e
        .post_with("/v1/crawls", &[("Idempotency-Key", "retry")], &simple_body())
        .await;
    assert_eq!(s, StatusCode::ACCEPTED);

    // invalid key
    let (s, _, v) = e
        .post_with("/v1/crawls", &[("Idempotency-Key", "")], &simple_body())
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
}

#[tokio::test]
async fn pause_resume_cancel_follow_the_state_machine() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run_id: CrawlRunId = id.parse().unwrap();
    let uri = |verb: &str| format!("/v1/crawls/{id}:{verb}");

    // queued: cannot pause or resume
    let (s, _, v) = e.post_empty(&uri("pause")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["error"]["code"], "invalid_state");
    let (s, _, _) = e.post_empty(&uri("resume")).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // the worker picks the run up
    e.store
        .set_status(run_id, RunStatus::Running, None)
        .await
        .unwrap();
    let (s, _, v) = e.post_empty(&uri("resume")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _, v) = e.post_empty(&uri("pause")).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(v["status"], "paused");
    let (s, _, v) = e.post_empty(&uri("pause")).await;
    assert_eq!(s, StatusCode::OK, "pause is idempotent by state");
    assert_eq!(v["status"], "paused");
    let (s, _, v) = e.post_empty(&uri("resume")).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(v["status"], "running");

    let (s, _, v) = e.post_empty(&uri("cancel")).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(v["status"], "cancelled");
    assert_eq!(v["terminalReason"], "cancelled");
    assert!(v["finishedAt"].is_string());
    let (s, _, v) = e.post_empty(&uri("cancel")).await;
    assert_eq!(s, StatusCode::OK, "repeat cancel returns 200");
    assert_eq!(v["status"], "cancelled");
    let (s, _, _) = e.post_empty(&uri("pause")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = e.post_empty(&uri("resume")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, v) = e.post_empty(&uri("explode")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    let run = e.store.get(run_id).await.unwrap();
    assert_eq!(run.terminal_reason, Some(TerminalReason::Cancelled));

    // a terminal event closes the stream; transitions were announced
    let events = e.store.list_after(run_id, 0, 100).await.unwrap();
    let kinds: Vec<&str> = events.iter().map(|ev| ev.kind.as_str()).collect();
    assert_eq!(kinds, vec!["paused", "resumed", "status", "completed"]);

    // cancelling a queued run goes straight to cancelled and cancels pending sessions
    let queued = e.create_run(&simple_body()).await;
    let (s, _, v) = e.post_empty(&format!("/v1/crawls/{queued}:cancel")).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(v["status"], "cancelled");
    assert_eq!(v["sessions"][0]["status"], "cancelled");

    // a completed run cannot be cancelled
    let done = e.create_run(&simple_body()).await;
    e.store
        .set_status(
            done.parse().unwrap(),
            RunStatus::Completed,
            Some(TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    let (s, _, v) = e.post_empty(&format!("/v1/crawls/{done}:cancel")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
}

#[tokio::test]
async fn erasure_removes_every_row_of_a_terminal_run() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run_id: CrawlRunId = id.parse().unwrap();
    e.store.append(run_id, "page", json!({})).await.unwrap();
    let (s, _, v) = e.delete(&format!("/v1/crawls/{id}")).await;
    assert_eq!(s, StatusCode::CONFLICT, "only terminal runs can be erased: {v}");
    e.post_empty(&format!("/v1/crawls/{id}:cancel")).await;
    let (s, _, v) = e.delete(&format!("/v1/crawls/{id}")).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "erased");
    assert!(v["rowsDeleted"].as_u64().unwrap() >= 3);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(e.store.get(run_id).await.is_err());
    assert!(e.store.list_sessions(run_id).await.unwrap().is_empty());
    assert!(e.store.list_after(run_id, 0, 10).await.unwrap().is_empty());
    let audit = e.api.audit_entries();
    assert!(audit
        .iter()
        .any(|a| a.event == "run.erase_requested" && a.run == Some(run_id)));
}

#[tokio::test]
async fn erasure_failure_keeps_owner_metadata_and_retry_erases_volatile_bytes() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run: CrawlRunId = id.parse().unwrap();
    let root = tempfile::tempdir().unwrap();
    let buffer = Arc::new(
        crawlx_storage::DeliveryBuffer::open_fs(
            root.path(),
            Arc::new(SystemClock),
            crawlx_storage::BufferLimits::default(),
        )
        .await
        .unwrap(),
    );
    e.store.set_dataset_delivery(buffer.clone());
    buffer
        .insert(
            e.tenant,
            run,
            -700,
            "_owned_erasure",
            "text/plain",
            b"owned transient erasure state",
        )
        .await
        .unwrap();
    e.post_empty(&format!("/v1/crawls/{id}:cancel")).await;

    // An actual volatile-backend outage must leave a retryable run and never acknowledge erasure.
    let delivery = root.path().join("zdr");
    let unavailable = root.path().join("unavailable-zdr");
    std::fs::rename(&delivery, &unavailable).unwrap();
    std::fs::write(&delivery, b"owned fixture blocks directory access").unwrap();
    let (status, _, body) = e.delete(&format!("/v1/crawls/{id}")).await;
    assert_ne!(status, StatusCode::ACCEPTED, "{body}");
    let (status, _, body) = e.get(&format!("/v1/crawls/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "cancelled");

    std::fs::remove_file(&delivery).unwrap();
    std::fs::rename(&unavailable, &delivery).unwrap();
    let (status, _, body) = e.delete(&format!("/v1/crawls/{id}")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "erased");
    assert!(buffer.is_empty().await.unwrap());
    assert_eq!(e.get(&format!("/v1/crawls/{id}")).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn completed_head_content_refuses_public_authorization_revocation() {
    use crawlx_api::ApiStore;
    use crawlx_core::acquisition::{AcquisitionResultV1, BackendCapabilitiesV1};
    use crawlx_core::hash::Digest;
    use crawlx_core::orchestration::{RequestBatchV1, RequestCommitRepo, RequestCommitV1};
    use crawlx_core::repo::{FrontierRepo, FrontierStatus};
    use crawlx_core::request::RequestEnvelopeV1;
    use crawlx_core::{Clock, StoreError, WorkerId};
    use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};

    let e = env();
    let now = SystemClock.now();
    let record = crawlx_policy::testkit::sample_record(e.tenant, now, &["https://app.example.test"]);
    e.api
        .authorization_create(e.tenant, uuid::Uuid::nil(), &record, &json!({}), now)
        .await
        .unwrap();
    let mut config = create_crawl("https://app.example.test/", &[], 1);
    config.safety.authorization_record_ref = Some(record.id);
    config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    config.retention.days = 0;
    let run = crawl_run(e.tenant, config);
    e.store.create(&run, None).await.unwrap();
    e.api
        .authorization_bind_run(run.id, record.body_digest().unwrap())
        .await
        .unwrap();
    let request = RequestEnvelopeV1::new(canonical_url("https://app.example.test/"), "HEAD".into(), 0, None);
    e.store
        .append_batch(RequestBatchV1::new(
            e.tenant,
            run.id,
            "anonymous".into(),
            Digest::of("test/completed-head", b"one"),
            vec![request],
        ))
        .await
        .unwrap();
    let (entry, fence) = e
        .store
        .lease_batch_fenced(run.id, WorkerId::new(), 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let queued = e.store.get_request(run.id, entry.id).await.unwrap();
    let mut acquisition = AcquisitionResultV1::new(
        run.id,
        e.tenant,
        queued.envelope.url.url.clone(),
        queued.identity.key,
        BackendCapabilitiesV1::native_http("crawlx-fetch", "test"),
    );
    acquisition.target_status = Some(200);
    acquisition.transport_succeeded = true;
    let mut commit = RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
    commit.head_response = Some(json!({
        "requestId":entry.id,"method":"HEAD","status":200,"bodyBytes":0,
        "response_headers":{"x-owned":"head-authorization-canary"},"acquisition":acquisition
    }));
    e.store.commit_fenced(commit.clone()).await.unwrap();
    e.store
        .set_status(
            run.id,
            RunStatus::Completed,
            Some(TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    assert_eq!(
        e.store.list_after(run.id, 0, 10).await.unwrap()[0].payload["response_headers"]["x-owned"],
        "head-authorization-canary"
    );
    let metadata = e.store.list_metadata_after(run.id, 0, 10).await.unwrap();
    let (status, _, body) = e
        .post(
            &format!("/v1/authorizations/{}/revoke", record.id),
            &json!({"reason":"completed engagement"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(e.store.get(run.id).await.unwrap().status, RunStatus::Completed);
    assert!(matches!(
        e.store.list_after(run.id, 0, 10).await,
        Err(StoreError::AccessDenied(_))
    ));
    assert!(matches!(
        e.store.commit_fenced(commit).await,
        Err(StoreError::AccessDenied(_))
    ));
    assert_eq!(
        e.store.list_metadata_after(run.id, 0, 10).await.unwrap(),
        metadata
    );
}

#[tokio::test]
async fn openapi_lists_every_route_without_authentication() {
    let e = env();
    let (s, _, b) = e.send(Method::GET, "/v1/openapi.json", None, &[], None).await;
    assert_eq!(s, StatusCode::OK);
    let doc = common::json(&b);
    assert!(doc["openapi"].as_str().unwrap().starts_with("3."));
    let paths = doc["paths"].as_object().unwrap();
    let expected: &[(&str, &str)] = &[
        ("post", "/v1/crawls"),
        ("get", "/v1/crawls/{id}"),
        ("delete", "/v1/crawls/{id}"),
        ("post", "/v1/crawls/{id}:pause"),
        ("post", "/v1/crawls/{id}:resume"),
        ("post", "/v1/crawls/{id}:cancel"),
        ("get", "/v1/crawls/{id}/pages"),
        ("get", "/v1/crawls/{id}/export"),
        ("get", "/v1/crawls/{id}/events"),
        ("get", "/v1/crawls/{id}/errors"),
        ("get", "/v1/crawls/{id}/states"),
        ("get", "/v1/crawls/{id}/transitions"),
        ("get", "/v1/crawls/{id}/coverage"),
        ("get", "/v1/crawls/{id}/traffic"),
        ("get", "/v1/crawls/{id}/artifacts/{artifactId}"),
        ("get", "/v1/crawls/{id}/approvals"),
        ("post", "/v1/crawls/{id}/approvals/{approvalId}:approve"),
        ("post", "/v1/crawls/{id}/approvals/{approvalId}:deny"),
        ("post", "/v1/replays"),
        ("post", "/v1/authorizations"),
        ("post", "/v1/authorizations/evidence"),
        ("get", "/v1/authorizations/{id}"),
        ("post", "/v1/authorizations/{id}/revoke"),
        ("post", "/v1/authorizations/{id}/verify"),
        ("get", "/v1/openapi.json"),
        ("get", "/metrics"),
        ("post", "/compat/v2/crawl"),
        ("get", "/compat/v2/crawl/{id}"),
        ("delete", "/compat/v2/crawl/{id}"),
        ("get", "/compat/v2/crawl/{id}/errors"),
    ];
    for (method, path) in expected.iter().copied() {
        assert!(
            paths.get(path).and_then(|p| p.get(method)).is_some(),
            "missing {method} {path}"
        );
    }
    let listed = crawlx_api::openapi::operations();
    for (m, p) in listed {
        assert!(paths[p].get(m).is_some());
    }
    assert!(paths["/v1/crawls"]["post"]["security"][0]["bearerAuth"][0] == "crawls:write");
}

#[tokio::test]
async fn bootstrap_keys_and_run_wiring_accept_requests() {
    // `run` itself binds a socket; check the building blocks it uses.
    let e = env();
    let key = crawlx_api::auth::generate_key();
    let cfg = ApiConfig {
        api_keys: vec![crawlx_api::ApiKeyBootstrap::new("acme", &key)],
        ..ApiConfig::default()
    };
    assert!(format!("{cfg:?}").contains("<redacted>"));
    assert!(!format!("{cfg:?}").contains(&key));
    let rec = crawlx_api::auth::key_record(&key, crawlx_api::auth::tenant_id_for("acme"), Scope::all_set())
        .unwrap();
    crawlx_api::ApiStore::key_insert(e.api.as_ref(), &rec, "acme")
        .await
        .unwrap();
    let (s, _, _) = e.get_as(&key, "/v1/crawls/x").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// A device matrix as a worker's startup probe publishes it: every preset measured as asked.
fn measured_matrix(coherent: bool) -> crawlx_core::page_op::DeviceMatrixV1 {
    use crawlx_core::page_op::{
        DeviceBuildV1, DeviceMatrixEntryV1, DeviceMatrixV1, DeviceMeasurement, DevicePreset,
    };
    let version = "155.0.8059.84";
    let entries = DevicePreset::ALL
        .into_iter()
        .map(|preset| {
            let requested = preset.emulation(version, "en-US");
            let viewport = requested.viewport.unwrap();
            let measured = DeviceMeasurement {
                viewport,
                screen: viewport,
                device_pixel_ratio_milli: requested.device_scale_milli.unwrap(),
                user_agent: requested
                    .user_agent
                    .clone()
                    .unwrap_or_else(|| format!("fixture HeadlessChrome/{version} Safari/537.36")),
                language: "en-US".to_owned(),
                time_zone: "UTC".to_owned(),
                max_touch_points: if requested.mobile && coherent { 5 } else { 0 },
                pointer_coarse: requested.mobile,
                geolocation: None,
                geolocation_error: None,
            };
            DeviceMatrixEntryV1::check(preset, requested, measured, version)
        })
        .collect();
    DeviceMatrixV1::new(
        DeviceBuildV1 {
            chromium_version: version.to_owned(),
            pinned: true,
        },
        entries,
    )
}

fn browser_capability(
    matrix: Option<crawlx_core::page_op::DeviceMatrixV1>,
) -> crawlx_core::acquisition::BackendCapabilitiesV1 {
    use crawlx_core::observation::BrowserBuildInfo;
    let mut capability = crawlx_core::acquisition::BackendCapabilitiesV1::native_browser(BrowserBuildInfo {
        chromium_version: "155.0.8059.84".to_owned(),
        cdp_revision: "1.3".to_owned(),
        user_agent: "fixture".to_owned(),
        pinned: true,
        launch_profile: crawlx_core::LaunchProfile::Standard,
        console_capture: false,
        attached: false,
    });
    capability.device_matrix = matrix;
    capability
}

#[tokio::test]
async fn published_device_matrices_are_counted_as_measured_and_coherent_workers() {
    use crawlx_storage::WorkerRegistry as _;
    let e = env();
    let (_, _, before) = e.get("/v1/capabilities/acquisition").await;
    assert_eq!(before["devices"]["measuredWorkers"], json!(0));
    assert_eq!(before["devices"]["coherentWorkers"], json!(0));
    for matrix in [Some(measured_matrix(true)), Some(measured_matrix(false)), None] {
        let worker = crawlx_core::WorkerId::new();
        e.store
            .register_worker(worker, "device-matrix-fixture", "1")
            .await
            .unwrap();
        e.store
            .publish_acquisition_capabilities(worker, &[browser_capability(matrix)])
            .await
            .unwrap();
    }
    let (status, _, after) = e.get("/v1/capabilities/acquisition").await;
    assert_eq!(status, StatusCode::OK, "{after}");
    let devices = &after["devices"];
    assert_eq!(devices["measuredWorkers"], json!(2), "{devices}");
    assert_eq!(devices["coherentWorkers"], json!(1), "{devices}");
    assert_eq!(devices["stealthClaim"], json!(false));
    let published: Vec<_> = after["workers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|worker| worker["backends"][0].get("deviceMatrix"))
        .collect();
    assert_eq!(published.len(), 2);
    assert_eq!(published[0]["entries"].as_array().unwrap().len(), 3);
}
