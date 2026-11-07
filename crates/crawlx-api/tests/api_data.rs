#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Data endpoints (pages, states, transitions, traffic, artifacts, approvals) and SSE.
mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use common::{env, env_with, simple_body, Env};
use crawlx_api::memory::approval_summary;
use crawlx_api::store::{ApprovalDecision, ApprovalRecord};
use crawlx_api::{ApiConfig, Scope, Settings};
use crawlx_core::action::BrowserAction;
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::ActionReceipt;
use crawlx_core::repo::{
    ActionJournal, EventRepo, FrontierRepo, FrontierStatus, OutcomeRecord, PageRecord, PageRepo, RunRepo,
    Sensitivity, SessionStatus, StateRepo,
};
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin};
use crawlx_core::{
    ActionId, ApprovalId, CrawlRunId, NetworkEpochId, SessionId, StateClusterId, SystemClock, TrustLane,
};
use crawlx_storage::testkit;
use futures::StreamExt;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

fn rid(s: &str) -> CrawlRunId {
    s.parse().unwrap()
}

async fn sse_body(e: &Env, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let (s, h, b) = e.send(Method::GET, uri, Some(&e.key), headers, None).await;
    if s == StatusCode::OK {
        assert!(h["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
    }
    (s, String::from_utf8(b.to_vec()).unwrap())
}

// ---- pages -----------------------------------------------------------------

async fn add_page(e: &Env, run: CrawlRunId, n: i64, role: &str, big: bool) {
    let text = if big {
        "x".repeat(2 * 1024 * 1024)
    } else {
        format!("# Page {n}\n\nbody")
    };
    let md = e
        .artifacts
        .put_kind(
            run,
            Sensitivity::Content,
            "markdown",
            "text/markdown",
            text.as_bytes(),
        )
        .await
        .unwrap();
    let html = e
        .artifacts
        .put_kind(
            run,
            Sensitivity::Content,
            "html",
            "text/html",
            format!("<h1>{n}</h1>").as_bytes(),
        )
        .await
        .unwrap();
    e.store
        .put(&PageRecord {
            run,
            frontier_id: n,
            url: testkit::canonical_url(&format!("https://app.example.test/p/{n}")),
            status: 200,
            content_type: Some("text/html".to_owned()),
            content_digest: Digest::of("t", n.to_string().as_bytes()),
            title: Some(format!("Page {n}")),
            markdown: Some(md),
            html: Some(html),
            metadata: json!({"description": "d", "language": "en", "role": role, "depth": 1}),
            links: vec![format!("https://app.example.test/p/{}", n + 1)],
            fetched_at: Utc::now(),
            lane: TrustLane::Diagnostic,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn pages_are_firecrawl_shaped_and_paginated() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run = rid(&id);
    for n in 1..=5 {
        add_page(&e, run, n, if n % 2 == 0 { "member" } else { "anonymous" }, false).await;
    }
    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/pages?limit=2")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["total"], 5);
    let data = v["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    let d0 = &data[0];
    assert_eq!(d0["markdown"], "# Page 1\n\nbody");
    assert_eq!(d0["html"], Value::Null, "html is not in the default formats");
    assert_eq!(d0["links"][0], "https://app.example.test/p/2");
    assert_eq!(d0["metadata"]["title"], "Page 1");
    assert_eq!(d0["metadata"]["sourceURL"], "https://app.example.test/p/1");
    assert_eq!(d0["metadata"]["statusCode"], 200);
    assert_eq!(d0["metadata"]["description"], "d");
    assert_eq!(d0["metadata"]["crawlx"]["role"], "anonymous");
    assert!(d0["metadata"]["crawlx"]["contentDigest"]
        .as_str()
        .unwrap()
        .starts_with("blake3:"));

    let mut seen = vec![d0["metadata"]["sourceURL"].as_str().unwrap().to_owned()];
    seen.push(data[1]["metadata"]["sourceURL"].as_str().unwrap().to_owned());
    let mut next = v["next"].as_str().map(str::to_owned);
    let mut pages = 1;
    while let Some(n) = next {
        assert!(n.contains("limit=2") && n.contains("cursor="), "{n}");
        let (s, _, v) = e.get(&n).await;
        assert_eq!(s, StatusCode::OK);
        for d in v["data"].as_array().unwrap() {
            seen.push(d["metadata"]["sourceURL"].as_str().unwrap().to_owned());
        }
        next = v["next"].as_str().map(str::to_owned);
        pages += 1;
    }
    assert_eq!(pages, 3);
    assert_eq!(seen.len(), 5);
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 5, "no duplicates: {seen:?}");

    let (_, _, v) = e.get(&format!("/v1/crawls/{id}/pages?role=member")).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 2);
    let (_, _, v) = e
        .get(&format!("/v1/crawls/{id}/pages?include=html,metadata"))
        .await;
    assert_eq!(v["data"][0]["html"], "<h1>1</h1>");
    assert_eq!(v["data"][0]["markdown"], Value::Null);
    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/pages?cursor=AAAA")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["code"], "malformed_request");
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/pages?limit=0")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/pages?include=bogus")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn large_content_is_returned_as_an_artifact_link() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    add_page(&e, rid(&id), 1, "anonymous", true).await;
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}/pages")).await;
    let doc = &v["data"][0];
    assert_eq!(doc["markdown"], Value::Null);
    let link = doc["metadata"]["crawlx"]["markdownRef"].as_str().unwrap();
    assert!(link.starts_with(&format!("/v1/crawls/{id}/artifacts/")));
    let (s, h, b) = e.send(Method::GET, link, Some(&e.key), &[], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b.len(), 2 * 1024 * 1024);
    assert_eq!(h["content-type"], "text/markdown");
}

#[tokio::test]
async fn pages_field_lists_values_over_the_paginated_pages() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run = rid(&id);
    for n in 1..=5 {
        add_page(&e, run, n, "anonymous", false).await;
    }
    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/pages?field=path&limit=2")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"], json!(["/p/1", "/p/2"]));
    assert_eq!(v["total"], 5);
    let next = v["next"].as_str().unwrap().to_owned();
    assert!(next.contains("field=path") && next.contains("cursor="), "{next}");
    let (_, _, v) = e.get(&next).await;
    assert_eq!(v["data"], json!(["/p/3", "/p/4"]));
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}/pages?field=qurl")).await;
    assert_eq!(v["data"], json!([]), "no page has a query");
    assert_eq!(v["total"], 5);
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}/pages?field=udir&limit=1")).await;
    assert_eq!(v["data"], json!(["https://app.example.test/p/"]));
    let (_, _, v) = e
        .get(&format!(
            "/v1/crawls/{id}/pages?format=text&template={{{{fqdn}}}}%20{{{{path}}}}&filter=/p/[2-5]"
        ))
        .await;
    assert_eq!(v["data"], json!(["app.example.test /p/1"]));
    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/pages?field=no%20such")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["code"], "malformed_request");
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/pages?format=xml")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/pages?template={{{{url")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/pages?field=url&match=(")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pages_format_jsonl_streams_one_record_per_page() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run = rid(&id);
    for n in 1..=3 {
        add_page(&e, run, n, "anonymous", false).await;
    }
    let uri = format!("/v1/crawls/{id}/pages?format=jsonl");
    let (s, h, b) = e.send(Method::GET, &uri, Some(&e.key), &[], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "text/x-ndjson");
    let text = String::from_utf8(b.to_vec()).unwrap();
    let records: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(records.len(), 3, "{text}");
    assert_eq!(records[0]["request"]["method"], "GET");
    assert_eq!(records[0]["request"]["endpoint"], "https://app.example.test/p/1");
    assert_eq!(records[0]["response"]["status_code"], 200);
    assert!(records[0]["timestamp"].is_string());
    assert!(records[0]["response"].get("body").is_none());

    let uri = format!("/v1/crawls/{id}/pages?format=jsonl&include=html&exclude=timestamp&filter=/p/3");
    let (_, _, b) = e.send(Method::GET, &uri, Some(&e.key), &[], None).await;
    let text = String::from_utf8(b.to_vec()).unwrap();
    let records: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(records.len(), 2, "{text}");
    assert_eq!(records[1]["response"]["body"], "<h1>2</h1>");
    assert!(records[1].get("timestamp").is_none());
}

#[tokio::test]
async fn export_route_renders_text_and_jsonl() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run = rid(&id);
    for n in 1..=3 {
        add_page(&e, run, n, if n == 2 { "member" } else { "anonymous" }, false).await;
    }
    let (s, h, b) = e
        .send(
            Method::GET,
            &format!("/v1/crawls/{id}/export"),
            Some(&e.key),
            &[],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "text/plain; charset=utf-8");
    assert_eq!(
        String::from_utf8(b.to_vec()).unwrap(),
        "https://app.example.test/p/1\nhttps://app.example.test/p/2\nhttps://app.example.test/p/3\n"
    );
    let uri = format!("/v1/crawls/{id}/export?format=text&field=fqdn&role=member");
    let (_, _, b) = e.send(Method::GET, &uri, Some(&e.key), &[], None).await;
    assert_eq!(String::from_utf8(b.to_vec()).unwrap(), "app.example.test\n");
    let uri = format!("/v1/crawls/{id}/export?format=jsonl&exclude=request");
    let (s, h, b) = e.send(Method::GET, &uri, Some(&e.key), &[], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "text/x-ndjson");
    let text = String::from_utf8(b.to_vec()).unwrap();
    assert_eq!(text.lines().count(), 3, "{text}");
    let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert!(first.get("request").is_none());
    assert_eq!(first["response"]["status_code"], 200);
    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/export?format=csv")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let key = e.key_for("acme", &[Scope::CrawlsWrite]).await;
    let (s, _, _) = e.get_as(&key, &format!("/v1/crawls/{id}/export")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// ---- SSE ---------------------------------------------------------------------

#[tokio::test]
async fn sse_streams_appended_events_and_resumes_from_last_event_id() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run = rid(&id);
    e.store.set_status(run, RunStatus::Running, None).await.unwrap();
    e.store
        .append(run, "page", json!({"url": "https://app.example.test/"}))
        .await
        .unwrap();
    e.store.append(run, "state", json!({"n": 2})).await.unwrap();
    e.store.append(run, "page", json!({"n": 3})).await.unwrap();
    e.store
        .append(run, "completed", json!({"status": "completed"}))
        .await
        .unwrap();

    let (s, body) = sse_body(&e, &format!("/v1/crawls/{id}/events"), &[]).await;
    assert_eq!(s, StatusCode::OK);
    let frames: Vec<&str> = body.split("\n\n").filter(|f| !f.is_empty()).collect();
    assert_eq!(frames.len(), 4, "{body}");
    assert!(
        frames[0].starts_with("id: 1\nevent: page\ndata: "),
        "{}",
        frames[0]
    );
    let data: Value =
        serde_json::from_str(frames[0].lines().last().unwrap().trim_start_matches("data: ")).unwrap();
    assert_eq!(data["seq"], 1);
    assert_eq!(data["type"], "page");
    assert_eq!(data["runId"], id.as_str());
    assert_eq!(data["data"]["url"], "https://app.example.test/");
    assert!(frames[3].contains("event: completed"));

    // resume
    let (_, body) = sse_body(&e, &format!("/v1/crawls/{id}/events"), &[("Last-Event-ID", "2")]).await;
    let frames: Vec<&str> = body.split("\n\n").filter(|f| !f.is_empty()).collect();
    assert_eq!(frames.len(), 2, "{body}");
    assert!(frames[0].starts_with("id: 3\n"));
    let (_, body) = sse_body(&e, &format!("/v1/crawls/{id}/events?after=3"), &[]).await;
    assert!(body.starts_with("id: 4\nevent: completed"), "{body}");
    // type filter keeps the terminal close
    let (_, body) = sse_body(&e, &format!("/v1/crawls/{id}/events?types=state"), &[]).await;
    let frames: Vec<&str> = body.split("\n\n").filter(|f| !f.is_empty()).collect();
    assert_eq!(frames.len(), 1, "{body}");
    assert!(frames[0].contains("event: state"));
    let (s, _, v) = e
        .send(
            Method::GET,
            &format!("/v1/crawls/{id}/events"),
            Some(&e.key),
            &[("Last-Event-ID", "abc")],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{}", common::json(&v));

    // a terminal run without a terminal event closes after replaying what exists
    let id2 = e.create_run(&simple_body()).await;
    e.post_empty(&format!("/v1/crawls/{id2}:cancel")).await;
    let (_, body) = sse_body(&e, &format!("/v1/crawls/{id2}/events"), &[]).await;
    assert!(body.contains("event: completed"), "{body}");
}

#[tokio::test]
async fn sse_keepalive_and_live_events() {
    let settings = Settings {
        sse_keepalive: Duration::from_millis(100),
        sse_poll_interval: Duration::from_millis(20),
        ..Settings::default()
    };
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let e = env_with(cfg, settings, Arc::new(SystemClock));
    let id = e.create_run(&simple_body()).await;
    let run = rid(&id);
    e.store.set_status(run, RunStatus::Running, None).await.unwrap();
    let req = Request::builder()
        .uri(format!("/v1/crawls/{id}/events"))
        .header("authorization", format!("Bearer {}", e.key))
        .body(Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(e.app.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.into_body().into_data_stream();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut appended = false;
    while tokio::time::Instant::now() < deadline {
        let chunk = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap();
        let Some(chunk) = chunk else { break };
        text.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
        if text.contains(": ping") && !appended {
            e.store.append(run, "page", json!({"live": true})).await.unwrap();
            e.store.append(run, "completed", json!({})).await.unwrap();
            appended = true;
        }
    }
    assert!(text.contains(": ping"), "{text}");
    assert!(text.contains("event: page"), "{text}");
    assert!(text.contains("event: completed"), "{text}");
}

async fn open_events(e: &Env, id: &str) -> axum::response::Response {
    let req = Request::builder()
        .uri(format!("/v1/crawls/{id}/events"))
        .header("authorization", format!("Bearer {}", e.key))
        .body(Body::empty())
        .unwrap();
    tower::ServiceExt::oneshot(e.app.clone(), req).await.unwrap()
}

#[tokio::test]
async fn sse_streams_are_capped_per_run_and_per_tenant() {
    let settings = Settings {
        sse_max_per_run: 2,
        sse_max_per_tenant: 3,
        ..Settings::default()
    };
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let e = env_with(cfg, settings, Arc::new(SystemClock));
    let a = e.create_run(&simple_body()).await;
    let b = e.create_run(&simple_body()).await;
    for id in [&a, &b] {
        e.store
            .set_status(rid(id), RunStatus::Running, None)
            .await
            .unwrap();
    }

    let a1 = open_events(&e, &a).await;
    let a2 = open_events(&e, &a).await;
    assert_eq!((a1.status(), a2.status()), (StatusCode::OK, StatusCode::OK));

    // the third stream on the same run hits the per-run cap
    let denied = open_events(&e, &a).await;
    assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(denied.headers().contains_key("retry-after"));
    let body = axum::body::to_bytes(denied.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(common::json(&body)["error"]["code"], "too_many_streams");

    // another run still has room until the tenant cap (3) is reached
    let b1 = open_events(&e, &b).await;
    assert_eq!(b1.status(), StatusCode::OK);
    let b2 = open_events(&e, &b).await;
    assert_eq!(b2.status(), StatusCode::TOO_MANY_REQUESTS);

    // dropping a connection frees its slot
    drop(a1);
    let again = open_events(&e, &a).await;
    assert_eq!(again.status(), StatusCode::OK);
    drop((a2, b1, again));
}

// ---- journal-backed endpoints --------------------------------------------------

struct Journal {
    run: CrawlRunId,
    session: SessionId,
    trusted: ActionId,
    diagnostic: ActionId,
    failed: ActionId,
    before: crawlx_core::StateId,
}

async fn finish(
    e: &Env,
    a: ActionId,
    status: ActionStatus,
    lane: TrustLane,
    fidelity: Fidelity,
    with_traffic: Option<&str>,
) {
    let epoch = NetworkEpochId::new();
    let now = Utc::now();
    let traffic: Vec<TrafficEvent> = with_traffic
        .into_iter()
        .map(|url| TrafficEvent {
            seq: 1,
            epoch_id: Some(epoch),
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "GET".to_owned(),
            url: url.to_owned(),
            status: Some(200),
            request_headers: vec![("accept".to_owned(), "*/*".to_owned())],
            response_headers: vec![("content-type".to_owned(), "text/html".to_owned())],
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: None,
            started_at: now,
            finished_at: Some(now),
        })
        .collect();
    e.store
        .finish(
            a,
            OutcomeRecord {
                status,
                receipt: Some(ActionReceipt {
                    network_epoch: epoch,
                    fidelity,
                    lane,
                    started_at: now,
                    finished_at: now,
                }),
                settle: None,
                after_state: None,
                traffic,
                error: None,
                finished_at: now,
            },
        )
        .await
        .unwrap();
}

/// The build this deployment admits replays against, as a session would record it.
fn deployment_build(e: &Env) -> crawlx_core::observation::BrowserBuildInfo {
    testkit::browser_build(&e.state.build.chromium_version, &e.state.build.cdp_revision)
}

async fn seed_journal(e: &Env, id: &str) -> Journal {
    let run = rid(id);
    e.store.set_status(run, RunStatus::Running, None).await.unwrap();
    let session = e.store.list_sessions(run).await.unwrap()[0].id;
    e.store
        .set_session_status(session, SessionStatus::Running)
        .await
        .unwrap();
    e.store
        .set_session_browser(session, &deployment_build(e))
        .await
        .unwrap();
    let epoch = ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: 0,
    };
    let cluster = StateClusterId::new();
    let st = testkit::new_state(session, cluster, true, 1, epoch);
    let before = st.id;
    e.store.put_state(&st).await.unwrap();

    let mut ids = Vec::new();
    for n in 0..3u32 {
        let mut p = testkit::proposal("anonymous", cluster, n);
        if n != 1 {
            p.action = BrowserAction::Keys { sequence: Vec::new() };
            p.key.action_kind = ActionKind::Keys;
        }
        let a = e
            .store
            .propose(run, session, &p, &testkit::allow_verdict())
            .await
            .unwrap();
        e.store.intend(a, session, epoch).await.unwrap();
        ids.push(a);
    }
    finish(
        e,
        ids[0],
        ActionStatus::Succeeded,
        TrustLane::TrustedUi,
        Fidelity::NativeKeyboard,
        Some("https://app.example.test/api/trusted"),
    )
    .await;
    finish(
        e,
        ids[1],
        ActionStatus::Succeeded,
        TrustLane::Diagnostic,
        Fidelity::ScriptedNavigation,
        Some("https://app.example.test/api/diag"),
    )
    .await;
    finish(
        e,
        ids[2],
        ActionStatus::Failed,
        TrustLane::TrustedUi,
        Fidelity::NativeKeyboard,
        None,
    )
    .await;
    Journal {
        run,
        session,
        trusted: ids[0],
        diagnostic: ids[1],
        failed: ids[2],
        before,
    }
}

#[tokio::test]
async fn coverage_replica_partitions_equal_the_strategy_ledger_and_grouped_views() {
    use crawlx_core::config::TargetIsolation;
    use crawlx_core::repo::{LedgerRepo, LedgerRow};
    use crawlx_core::safety::SafetyDecision;
    use crawlx_core::ResourceContext;
    use crawlx_strategies::InMemoryLedger;

    for isolation in [TargetIsolation::Shared, TargetIsolation::PerRoleReplica] {
        let e = env();
        let mut body = simple_body();
        body["targetIsolation"] = json!(isolation);
        body["roles"] = json!([
            {"name": "anonymous", "replicaBaseUrl": "https://app.example.test/"},
            {"name": "observer", "replicaBaseUrl": "https://app.example.test/"}
        ]);
        let id = e.create_run(&body).await;
        let journal = seed_journal(&e, &id).await;
        for (n, resource) in [
            ResourceContext::Own,
            ResourceContext::None,
            ResourceContext::OtherUserSameRole,
            ResourceContext::HigherRole,
            ResourceContext::Shared,
            ResourceContext::Own,
            ResourceContext::Own,
        ]
        .into_iter()
        .enumerate()
        {
            let mut proposal = testkit::proposal(
                "anonymous",
                StateClusterId::new(),
                100 + u32::try_from(n).unwrap(),
            );
            proposal.key.resource_context = resource;
            if n == 1 {
                proposal.key.state_cluster = proposal.key.coarsened_cluster();
            }
            LedgerRepo::upsert(
                e.store.as_ref(),
                journal.run,
                &LedgerRow {
                    key: proposal.key.clone(),
                    trusted_exercised: 0,
                    diagnostic_exercised: u32::from(n == 2),
                    failures: 0,
                    first_seen: Utc::now(),
                    last_exercised: None,
                },
            )
            .await
            .unwrap();
            if n == 5 {
                let mut verdict = testkit::allow_verdict();
                verdict.decision = SafetyDecision::Deny;
                // Two rejected attempts remain one denied key.
                for _ in 0..2 {
                    e.store
                        .propose(journal.run, journal.session, &proposal, &verdict)
                        .await
                        .unwrap();
                }
            }
        }
        let rows = LedgerRepo::list(e.store.as_ref(), journal.run).await.unwrap();
        let scorer = InMemoryLedger::from_rows(rows)
            .with_isolation(isolation)
            .coverage(None);
        let (status, _, view) = e.get(&format!("/v1/crawls/{id}/coverage")).await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["denominator"], "discovered");
        assert_eq!(view["targetIsolation"], json!(isolation));
        let total = &view["total"];
        assert_eq!(total["discovered"], scorer.keys_total);
        assert_eq!(total["exercised"], scorer.keys_exercised_trusted);
        assert_eq!(total["diagnosticOnly"], scorer.keys_diagnostic_only);
        assert_eq!(total["notObservable"], scorer.keys_not_observable);
        assert_eq!(total["coarsened"], scorer.keys_coarsened);
        assert_eq!(total["denied"], 1);
        assert_eq!(
            total["pending"].as_u64().unwrap()
                + total["denied"].as_u64().unwrap()
                + total["unknown"].as_u64().unwrap(),
            u64::from(scorer.keys_uncovered())
        );
        let role = &view["roles"][0];
        for field in [
            "discovered",
            "exercised",
            "diagnosticOnly",
            "notObservable",
            "coarsened",
            "pending",
            "denied",
        ] {
            assert_eq!(role[field], total[field], "{field}: {view}");
        }
        assert_eq!(view["roles"][1]["role"], "observer");
        assert_eq!(view["roles"][1]["notObservable"], 0);
        let (_, _, filtered) = e.get(&format!("/v1/crawls/{id}/coverage?role=observer")).await;
        assert_eq!(filtered["total"]["discovered"], 0);
        for group in ["actionKind", "resourceContext", "routeTemplate"] {
            let (_, _, grouped) = e
                .get(&format!(
                    "/v1/crawls/{id}/coverage?role=anonymous&groupBy={group}"
                ))
                .await;
            for field in [
                "discovered",
                "exercised",
                "diagnosticOnly",
                "notObservable",
                "coarsened",
                "pending",
                "denied",
            ] {
                let sum: u64 = grouped["groups"]
                    .as_object()
                    .unwrap()
                    .values()
                    .map(|counts| counts[field].as_u64().unwrap())
                    .sum();
                assert_eq!(json!(sum), total[field], "{group}/{field}: {grouped}");
            }
        }
        if isolation == TargetIsolation::PerRoleReplica {
            assert_eq!(total["notObservable"], 3);
            assert_eq!(total["pending"], 4);
            let (_, _, diagnostic) = e
                .get(&format!(
                    "/v1/crawls/{id}/coverage?lane=diagnostic&groupBy=resourceContext"
                ))
                .await;
            assert_eq!(diagnostic["groups"]["other_user_same_role"]["notObservable"], 1);
            assert_eq!(diagnostic["groups"]["other_user_same_role"]["exercised"], 0);
        }
    }
}

#[tokio::test]
async fn coverage_and_traffic_default_to_the_trusted_lane() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let j = seed_journal(&e, &id).await;

    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/coverage")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["lane"], "trusted_ui");
    assert_eq!(v["unit"], "ActionContextKey");
    assert_eq!(v["groundTruth"], Value::Null);
    let role = &v["roles"][0];
    assert_eq!(role["role"], "anonymous");
    assert_eq!(role["discovered"], 3);
    assert_eq!(
        role["exercised"], 1,
        "the diagnostic action does not count: {role}"
    );
    assert_eq!(role["byActionKind"]["keys"], 1);
    assert_eq!(
        role["diagnosticOnly"], 1,
        "the navigate key was exercised only diagnostically"
    );
    assert_eq!(role["sessionsPlanned"], 1);
    assert_eq!(v["total"]["exercised"], 1);
    let (_, _, d) = e.get(&format!("/v1/crawls/{id}/coverage?lane=diagnostic")).await;
    assert_eq!(d["lane"], "diagnostic");
    assert_eq!(d["roles"][0]["exercised"], 1);
    assert_eq!(d["roles"][0]["byActionKind"]["navigate"], 1);
    let (_, _, g) = e
        .get(&format!("/v1/crawls/{id}/coverage?groupBy=actionKind"))
        .await;
    assert_eq!(g["groups"]["keys"]["exercised"], 1);
    let (_, _, none) = e.get(&format!("/v1/crawls/{id}/coverage?role=nobody")).await;
    assert_eq!(none["roles"], json!([]));
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/coverage?lane=weird")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // the run resource carries the summary
    let (_, _, run) = e.get(&format!("/v1/crawls/{id}")).await;
    assert_eq!(run["coverage"]["discovered"], 3);
    assert_eq!(run["coverage"]["exercisedTrusted"], 1);

    // traffic
    let (s, _, t) = e.get(&format!("/v1/crawls/{id}/traffic")).await;
    assert_eq!(s, StatusCode::OK, "{t}");
    let data = t["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["url"], "https://app.example.test/api/trusted");
    assert_eq!(data[0]["lane"], "trusted_ui");
    assert_eq!(data[0]["role"], "anonymous");
    assert_eq!(data[0]["actionId"], j.trusted.to_string().as_str());
    assert_eq!(data[0]["requestHeaders"]["accept"], "*/*");
    let (_, _, t) = e.get(&format!("/v1/crawls/{id}/traffic?lane=all")).await;
    assert_eq!(t["data"].as_array().unwrap().len(), 2);
    let (_, _, t) = e.get(&format!("/v1/crawls/{id}/traffic?lane=diagnostic")).await;
    assert_eq!(t["data"][0]["url"], "https://app.example.test/api/diag");
    let (_, _, t) = e
        .get(&format!("/v1/crawls/{id}/traffic?lane=all&role=nobody"))
        .await;
    assert_eq!(t["data"], json!([]));
    let (_, _, t) = e
        .get(&format!("/v1/crawls/{id}/traffic?lane=all&origin=websocket"))
        .await;
    assert_eq!(t["data"], json!([]));
    let (_, _, t) = e
        .get(&format!("/v1/crawls/{id}/traffic?lane=all&origin=page&limit=1"))
        .await;
    assert!(t["next"].is_string());
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/traffic?lane=zzz")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/traffic?origin=zzz")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn states_transitions_and_errors_reflect_the_journal() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let j = seed_journal(&e, &id).await;

    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/states")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["total"], 1);
    let st = &v["data"][0];
    assert_eq!(st["id"], j.before.to_string().as_str());
    assert_eq!(st["role"], "anonymous");
    assert_eq!(st["sessionId"], j.session.to_string().as_str());
    assert_eq!(st["epoch"]["navigationSeq"], 1);
    assert_eq!(st["routeKey"], "https://example.test/page");
    assert_eq!(st["signature"]["domStructureSimhash"].as_str().unwrap().len(), 16);
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}/states?role=nobody")).await;
    assert_eq!(v["data"], json!([]));
    let (_, _, v) = e
        .get(&format!("/v1/crawls/{id}/states?sessionId={}", j.session))
        .await;
    assert_eq!(v["total"], 1);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/states?clusterId=nope")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/transitions")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["total"], 3);
    let t = &v["data"][0];
    assert_eq!(t["before"], j.before.to_string().as_str());
    assert_eq!(t["role"], "anonymous");
    assert!(t["action"]["kind"].as_str().is_some());
    let (_, _, v) = e
        .get(&format!(
            "/v1/crawls/{id}/transitions?lane=trusted_ui&status=succeeded"
        ))
        .await;
    assert_eq!(v["total"], 1);
    assert_eq!(v["data"][0]["id"], j.trusted.0.to_string().as_str());
    assert_eq!(v["data"][0]["action"]["status"], "succeeded");
    let (_, _, v) = e
        .get(&format!("/v1/crawls/{id}/transitions?lane=diagnostic"))
        .await;
    assert_eq!(v["data"][0]["id"], j.diagnostic.0.to_string().as_str());
    let (_, _, v) = e
        .get(&format!("/v1/crawls/{id}/transitions?fromState={}", j.before))
        .await;
    assert_eq!(v["total"], 3);
    let (_, _, v) = e
        .get(&format!("/v1/crawls/{id}/transitions?toState={}", j.before))
        .await;
    assert_eq!(v["total"], 0);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/transitions?status=nope")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // errors: the failed action and every non-succeeded frontier row
    e.store
        .discover(
            j.run,
            &testkit::canonical_url("https://app.example.test/private"),
            1,
            None,
            Some((FrontierStatus::PolicyBlocked, "out_of_scope".to_owned())),
        )
        .await
        .unwrap();
    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/errors")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let items = v["data"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{items:?}");
    assert!(items
        .iter()
        .any(|i| i["plane"] == "url" && i["code"] == "out_of_scope" && i["retryable"] == false));
    assert!(items
        .iter()
        .any(|i| i["plane"] == "interaction" && i["actionId"] == j.failed.to_string().as_str()));
    let (_, _, v) = e.get(&format!("/v1/crawls/{id}/errors?plane=interaction")).await;
    assert_eq!(v["total"], 1);
}

// ---- artifacts -----------------------------------------------------------------

#[tokio::test]
async fn artifact_sensitivity_rules() {
    let e = env();
    let id = e.create_run(&simple_body()).await;
    let run = rid(&id);
    let put = |class: Sensitivity, kind: &'static str, bytes: &'static [u8]| {
        let a = e.artifacts.clone();
        async move { a.put_kind(run, class, kind, "text/plain", bytes).await.unwrap() }
    };
    let metadata = put(Sensitivity::Metadata, "manifest", b"meta").await;
    let content = put(Sensitivity::Content, "html", b"hello content").await;
    let sensitive = put(Sensitivity::Sensitive, "dom_snapshot", b"secret dom").await;
    let cred = put(Sensitivity::CredentialBearing, "storage_state", b"cookies").await;
    let reader = e.key_for("acme", &[Scope::CrawlsRead]).await;
    let sens_reader = e
        .key_for("acme", &[Scope::CrawlsRead, Scope::ArtifactsReadSensitive])
        .await;
    let uri = |a: &crawlx_core::ArtifactRef| format!("/v1/crawls/{id}/artifacts/{}", a.id);

    // metadata + content: plain read scope
    for (a, body) in [(&metadata, "meta"), (&content, "hello content")] {
        let (s, h, b) = e.send(Method::GET, &uri(a), Some(&reader), &[], None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&b).unwrap(), body);
        assert!(h["digest"].to_str().unwrap().starts_with("blake3="));
        assert!(h.contains_key("x-crawlx-sensitivity"));
    }
    let (_, h, _) = e
        .send(Method::GET, &uri(&content), Some(&reader), &[], None)
        .await;
    assert_eq!(h["x-crawlx-sensitivity"], "content");
    assert!(e
        .api
        .audit_entries()
        .iter()
        .all(|a| a.event != "artifact.read_sensitive"));

    // sensitive: scope + audit
    let (s, _, b) = e
        .send(Method::GET, &uri(&sensitive), Some(&reader), &[], None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(common::json(&b)["error"]["code"], "scope_missing");
    let reads = || {
        e.api
            .audit_entries()
            .into_iter()
            .filter(|a| a.event != "crawl.accepted")
            .collect::<Vec<_>>()
    };
    assert!(reads().is_empty(), "denied reads write no audit");
    let (s, h, b) = e
        .send(Method::GET, &uri(&sensitive), Some(&sens_reader), &[], None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(&b[..], b"secret dom");
    assert_eq!(h["x-crawlx-sensitivity"], "sensitive");
    let audit = reads();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].event, "artifact.read_sensitive");
    assert_eq!(audit[0].run, Some(run));
    assert_eq!(audit[0].subject["artifact_id"], sensitive.id.to_string().as_str());

    // credential-bearing: never served
    for key in [&e.key, &sens_reader] {
        let (s, _, b) = e.send(Method::GET, &uri(&cred), Some(key), &[], None).await;
        assert_eq!(s, StatusCode::GONE);
        assert_eq!(common::json(&b)["error"]["code"], "artifact_unavailable");
    }

    // metadata view hides the object key
    let (s, _, v) = e.get(&format!("{}?view=metadata", uri(&content))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["sensitivity"], "content");
    assert_eq!(v["sizeBytes"], 13);
    assert!(v.get("objectKey").is_none() && v.get("bucket").is_none());

    // other tenants and unknown ids look absent
    let other = e.key_for("globex", &Scope::ALL).await;
    let (s, _, _) = e.send(Method::GET, &uri(&content), Some(&other), &[], None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = e
        .get(&format!("/v1/crawls/{id}/artifacts/{}", uuid::Uuid::now_v7()))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = e.get(&format!("/v1/crawls/{id}/artifacts/not-a-uuid")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // an artifact of another run is not reachable through this run
    let id2 = e.create_run(&simple_body()).await;
    let (s, _, _) = e.get(&format!("/v1/crawls/{id2}/artifacts/{}", content.id)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// ---- approvals -----------------------------------------------------------------

fn approval(run: CrawlRunId, expires_in_secs: i64) -> ApprovalRecord {
    let now = Utc::now();
    ApprovalRecord {
        id: ApprovalId::new(),
        run,
        action: ActionId::new(),
        risk_class: "destructive".to_owned(),
        summary: approval_summary("member", "/orders/:id", "click"),
        decision: ApprovalDecision::Pending,
        requested_at: now,
        expires_at: now + chrono::Duration::seconds(expires_in_secs),
        decided_by: None,
        decided_at: None,
        reason: None,
        consumed_at: None,
    }
}

#[tokio::test]
async fn approvals_can_be_decided_once() {
    let e = env();
    let id = e.create_run(&json!({"seedUrl": "https://app.example.test/", "safety": {"profile": "test_environment", "destructiveActions": "approval"}})).await;
    let run = rid(&id);
    let a1 = approval(run, 3600);
    let a2 = approval(run, 3600);
    let expired = approval(run, -5);
    for a in [&a1, &a2, &expired] {
        e.api.add_approval(a.clone());
    }

    let (s, _, v) = e.get(&format!("/v1/crawls/{id}/approvals")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["total"], 3);
    let item = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == a1.id.to_string().as_str())
        .unwrap()
        .clone();
    assert_eq!(item["decision"], "pending");
    assert_eq!(item["riskClass"], "destructive");
    assert_eq!(item["profile"], "test_environment");
    assert_eq!(item["summary"]["elementRole"], "member");
    assert_eq!(item["summary"]["routeTemplate"], "/orders/:id");
    assert_eq!(item["summary"]["actionKind"], "click");
    let (_, _, v) = e
        .get(&format!("/v1/crawls/{id}/approvals?decision=pending"))
        .await;
    assert_eq!(v["total"], 2);
    let (_, _, v) = e
        .get(&format!("/v1/crawls/{id}/approvals?decision=expired"))
        .await;
    assert_eq!(v["total"], 1);

    // approve
    let uri = |a: &ApprovalRecord, verb: &str| format!("/v1/crawls/{id}/approvals/{}:{verb}", a.id);
    let (s, _, v) = e
        .post(&uri(&a1, "approve"), &json!({"reason": "looks fine"}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], "approved");
    assert_eq!(v["reason"], "looks fine");
    assert!(v["decidedBy"].is_string());
    assert_eq!(v["consumed"], false);
    // repeating the same decision is a 200; the opposite is 409
    let (s, _, v) = e.post_empty(&uri(&a1, "approve")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], "approved");
    let (s, _, v) = e.post_empty(&uri(&a1, "deny")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["error"]["code"], "approval_not_pending");

    // consumed approvals cannot change
    let (s, _, _) = e.post_empty(&uri(&a2, "approve")).await;
    assert_eq!(s, StatusCode::OK);
    e.api.consume_approval(a2.id, Utc::now());
    let (s, _, v) = e.post_empty(&uri(&a2, "deny")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (_, _, l) = e
        .get(&format!("/v1/crawls/{id}/approvals?decision=approved"))
        .await;
    let consumed: Vec<bool> = l["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["consumed"].as_bool().unwrap())
        .collect();
    assert!(
        consumed.contains(&true) && consumed.contains(&false),
        "{consumed:?}"
    );

    // expired approvals cannot be decided
    let (s, _, v) = e.post_empty(&uri(&expired, "approve")).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"]["code"], "approval_not_pending");

    // deny works on a pending approval
    let a3 = approval(run, 3600);
    e.api.add_approval(a3.clone());
    let (s, _, v) = e.post(&uri(&a3, "deny"), &json!({"reason": "no"})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], "denied");

    // unknown approval / verb / invalid reason / scope
    let (s, _, _) = e
        .post_empty(&format!(
            "/v1/crawls/{id}/approvals/{}:approve",
            ApprovalId::new()
        ))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = e.post_empty(&uri(&a3, "shred")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = e.post(&uri(&a3, "approve"), &json!({"reason": 5})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let writer = e.key_for("acme", &[Scope::CrawlsRead, Scope::CrawlsWrite]).await;
    let (s, _, b) = e
        .send(Method::POST, &uri(&a3, "approve"), Some(&writer), &[], None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{}", common::json(&b));

    // audit and events
    let audit = e.api.audit_entries();
    assert!(audit.iter().any(|a| a.event == "approval.approved"));
    assert!(audit.iter().any(|a| a.event == "approval.denied"));
    let events = e.store.list_after(run, 0, 100).await.unwrap();
    assert!(events.iter().filter(|ev| ev.kind == "approval_resolved").count() >= 3);

    // Idempotency-Key replays the stored decision
    let a4 = approval(run, 3600);
    e.api.add_approval(a4.clone());
    let h = [("Idempotency-Key", "approve-4")];
    let (s1, _, v1) = e.post_with(&uri(&a4, "approve"), &h, &json!({})).await;
    let (s2, h2, v2) = e.post_with(&uri(&a4, "approve"), &h, &json!({})).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    assert_eq!(h2["idempotent-replayed"], "true");
    assert_eq!(v1, v2);
}

// ---- replays ---------------------------------------------------------------------

#[tokio::test]
async fn replays_create_a_replay_run_from_recorded_transitions() {
    let e = env();
    let id = e
        .create_run(
            &json!({"seedUrl": "https://app.example.test/", "seed": 99, "roles": [{"name": "anonymous"}]}),
        )
        .await;
    let j = seed_journal(&e, &id).await;
    let (_, _, t) = e
        .get(&format!(
            "/v1/crawls/{id}/transitions?lane=trusted_ui&status=succeeded"
        ))
        .await;
    let tid = t["data"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(tid, j.trusted.0.to_string());

    let body = json!({
        "sourceRunId": id, "role": "anonymous",
        "path": {"from": "seed", "toTransitionId": tid},
        "target": {"baseUrl": "https://staging.example.test/"},
        "mode": "reproduce", "stopOnDivergence": false,
    });
    let (s, h, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "queued");
    let new_id = v["id"].as_str().unwrap();
    assert_eq!(h["location"], format!("/v1/crawls/{new_id}").as_str());
    assert_ne!(new_id, id);
    let spec = e.store.replay_spec(rid(new_id)).await.unwrap().unwrap();
    assert_eq!(spec["sourceRunId"], json!(rid(&id)));
    assert_eq!(spec["transitionIds"], json!([tid]));
    assert_eq!(spec["actionIds"], json!([t["data"][0]["action"]["id"]]));
    assert_eq!(spec["afterStateIds"], json!([t["data"][0]["after"]]));
    assert_eq!(spec["identityVersion"], 1);
    assert_eq!(
        spec["stateAlgoVersion"],
        crawlx_core::state::StateSignature::VERSION
    );
    assert_eq!(spec["mode"], "reproduce");
    assert_eq!(spec["stopOnDivergence"], false);
    assert_eq!(spec["target"]["baseUrl"], "https://staging.example.test/");
    assert_eq!(spec["allowBuildMismatch"], false);
    assert_eq!(spec["buildMismatchOverridden"], false);
    let run = RunRepo::get(e.store.as_ref(), rid(new_id)).await.unwrap();
    assert_eq!(run.status, RunStatus::Queued);
    assert_eq!(run.seed.0, 99, "replays keep the source seed");
    assert_eq!(run.config.seed_url.as_str(), "https://staging.example.test/");
    assert_eq!(e.store.list_sessions(rid(new_id)).await.unwrap().len(), 1);
    // status/events use the ordinary endpoints
    let (s, _, g) = e.get(&format!("/v1/crawls/{new_id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(g["status"], "queued");

    // explicit transitionIds
    let explicit = json!({"sourceRunId": id, "path": {"transitionIds": [tid]}});
    let (s, _, v) = e.post("/v1/replays", &explicit).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");

    // idempotency applies
    let h = [("Idempotency-Key", "replay-1")];
    let (_, _, r1) = e.post_with("/v1/replays", &h, &explicit).await;
    let (_, h2, r2) = e.post_with("/v1/replays", &h, &explicit).await;
    assert_eq!(r1["id"], r2["id"]);
    assert_eq!(h2["idempotent-replayed"], "true");

    // validation: every violation reported
    let bad = json!({
        "sourceRunId": id, "role": "ghost",
        "path": {"transitionIds": [uuid::Uuid::now_v7()], "toTransitionId": tid},
        "target": {"baseUrl": "http://127.0.0.1/"},
        "safety": {"profile": "test_environment"},
    });
    let (s, _, v) = e.post("/v1/replays", &bad).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let paths: Vec<&str> = v["error"]["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["path"].as_str().unwrap())
        .collect();
    for p in ["/role", "/path", "/target/baseUrl", "/safety/profile"] {
        assert!(paths.contains(&p), "{p} missing in {paths:?}");
    }
    let (s, _, v) = e
        .post("/v1/replays", &json!({"sourceRunId": id, "path": {}}))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error"]["details"][0]["path"], "/path");
    let (s, _, v) = e
        .post(
            "/v1/replays",
            &json!({"sourceRunId": id, "nope": 1, "path": {"toTransitionId": tid}}),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error"]["details"][0]["code"], "unknown_field");
    let (s, _, _) = e
        .post(
            "/v1/replays",
            &json!({"sourceRunId": CrawlRunId::new(), "path": {"toTransitionId": tid}}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let reader = e.key_for("acme", &[Scope::CrawlsRead, Scope::CrawlsWrite]).await;
    let (s, _, _) = e
        .send(Method::POST, "/v1/replays", Some(&reader), &[], Some(&explicit))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// A source run whose journal was recorded on `build` (or on no build at all), plus a replay
/// request body targeting its trusted transition.
async fn replay_source(
    e: &Env,
    build: Option<&crawlx_core::observation::BrowserBuildInfo>,
) -> (String, Value) {
    let id = e
        .create_run(&json!({"seedUrl": "https://app.example.test/", "roles": [{"name": "anonymous"}]}))
        .await;
    let j = seed_journal(e, &id).await;
    // seed_journal records the deployment build; the memory store overwrites it in place, and
    // "no build" is modelled by a fresh second session of the same role that never launched.
    match build {
        Some(b) => e.store.set_session_browser(j.session, b).await.unwrap(),
        None => {
            let mut extra = testkit::sessions(j.run, 1, 1);
            extra[0].role = crawlx_core::PrincipalId("anonymous".to_owned());
            extra[0].run_index = 2;
            extra[0].schedule_slot = 1;
            e.store.create_sessions(&extra).await.unwrap();
        }
    }
    let (_, _, t) = e
        .get(&format!(
            "/v1/crawls/{id}/transitions?lane=trusted_ui&status=succeeded"
        ))
        .await;
    let tid = t["data"][0]["id"].as_str().unwrap().to_owned();
    let body = json!({"sourceRunId": id, "role": "anonymous", "path": {"toTransitionId": tid}});
    (id, body)
}

#[tokio::test]
async fn a_replay_under_an_authorization_record_is_bound_and_audited_like_a_crawl() {
    let e = env();
    let now = chrono::Utc::now();
    let record = crawlx_policy::AuthorizationRecord {
        verified_at: Some(now),
        ..crawlx_policy::testkit::sample_record(e.tenant, now, &["https://app.example.test"])
    };
    let digest = record.body_digest().unwrap();
    e.api.add_authorization(record.clone());
    let id = e
        .create_run(&json!({
            "seedUrl": "https://app.example.test/", "seed": 99, "roles": [{"name": "anonymous"}],
            "safety": {"profile": "authorized_security_test", "authorizationRecordRef": record.id},
        }))
        .await;
    seed_journal(&e, &id).await;
    let (_, _, t) = e
        .get(&format!(
            "/v1/crawls/{id}/transitions?lane=trusted_ui&status=succeeded"
        ))
        .await;
    let tid = t["data"][0]["id"].as_str().unwrap().to_owned();

    let body = json!({"sourceRunId": id, "role": "anonymous", "path": {"toTransitionId": tid}});
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let replay = rid(v["id"].as_str().unwrap());
    assert_eq!(
        crawlx_api::ApiStore::authorization_run_digest(e.api.as_ref(), replay)
            .await
            .unwrap(),
        Some(digest),
        "the replay is bound to the record body like the crawl it replays"
    );
    let used: Vec<_> = e
        .api
        .audit_entries()
        .into_iter()
        .filter(|a| a.event == "authorization.used")
        .collect();
    assert_eq!(used.len(), 2, "the source crawl and its replay");
    assert_eq!(used[1].run, Some(replay));
    assert_eq!(used[1].subject["record_id"], record.id.to_string());
    assert_eq!(used[1].subject["bodyDigest"], digest.to_string());

    // a revoked record refuses the replay at admission, like any new run
    let (s, _, v) = e
        .post(&format!("/v1/authorizations/{}/revoke", record.id), &json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["code"], "authorization_required");
}

#[tokio::test]
async fn replays_refuse_a_source_recorded_on_another_build() {
    let e = env();
    let here = &e.state.build;
    assert!(
        !here.chromium_version.is_empty(),
        "the test environment resolves the workspace pin"
    );
    let other = testkit::browser_build("1.0.0.1", &here.cdp_revision);
    let (_, body) = replay_source(&e, Some(&other)).await;
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["code"], "validation_failed");
    let details = v["error"]["details"].as_array().unwrap();
    assert_eq!(details.len(), 1, "{v}");
    assert_eq!(details[0]["path"], "/allowBuildMismatch");
    assert_eq!(details[0]["code"], "build_mismatch");
    let msg = details[0]["message"].as_str().unwrap();
    assert!(msg.contains("1.0.0.1"), "{msg}");
    assert!(msg.contains(&here.label()), "{msg}");

    // same version, other CDP revision is a mismatch too
    let other_cdp = testkit::browser_build(&here.chromium_version, "0.0");
    let (_, body) = replay_source(&e, Some(&other_cdp)).await;
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["details"][0]["code"], "build_mismatch");

    // a session that never recorded a build has nothing to verify: refused as well
    let (_, body) = replay_source(&e, None).await;
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["details"][0]["code"], "build_mismatch");
    assert!(
        v["error"]["details"][0]["message"]
            .as_str()
            .unwrap()
            .contains("unrecorded"),
        "{v}"
    );
    // the refusal is reported alongside the other violations, not instead of them
    let mut combined = body.clone();
    combined["safety"] = json!({"profile": "test_environment"});
    let (s, _, v) = e.post("/v1/replays", &combined).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let codes: Vec<&str> = v["error"]["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.contains(&"profile_conflict") && codes.contains(&"build_mismatch"),
        "{codes:?}"
    );
}

#[tokio::test]
async fn replays_accept_the_deployment_build() {
    let e = env();
    let same = deployment_build(&e);
    let (source, body) = replay_source(&e, Some(&same)).await;
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let spec = e
        .store
        .replay_spec(rid(v["id"].as_str().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(spec["sourceRunId"], json!(rid(&source)));
    assert_eq!(spec["allowBuildMismatch"], false);
    assert_eq!(spec["buildMismatchOverridden"], false);

    // a `Product/` prefixed version string of the same build still matches
    let prefixed = testkit::browser_build(
        &format!("Chrome/{}", e.state.build.chromium_version),
        &e.state.build.cdp_revision,
    );
    let (_, body) = replay_source(&e, Some(&prefixed)).await;
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
}

#[tokio::test]
async fn replays_allow_build_mismatch_when_overridden() {
    let e = env();
    let other = testkit::browser_build("1.0.0.1", &e.state.build.cdp_revision);
    let (source, mut body) = replay_source(&e, Some(&other)).await;
    body["allowBuildMismatch"] = json!(true);
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let spec = e
        .store
        .replay_spec(rid(v["id"].as_str().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(spec["sourceRunId"], json!(rid(&source)));
    assert_eq!(spec["allowBuildMismatch"], true);
    assert_eq!(spec["buildMismatchOverridden"], true, "{spec}");

    // the override is recorded as such only when there was something to override
    let same = deployment_build(&e);
    let (_, mut body) = replay_source(&e, Some(&same)).await;
    body["allowBuildMismatch"] = json!(true);
    let (s, _, v) = e.post("/v1/replays", &body).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let spec = e
        .store
        .replay_spec(rid(v["id"].as_str().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(spec["allowBuildMismatch"], true);
    assert_eq!(spec["buildMismatchOverridden"], false);
}
