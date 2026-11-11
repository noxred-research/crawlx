#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end API flows over PostgreSQL (skipped without `CRAWLX_TEST_DATABASE_URL`).

use axum::body::Body;
#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::{ApiConfig, AppState, Repos, Scope};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{EventRepo, RunRepo, Sensitivity};
use crawlx_core::{CrawlRunId, SystemClock};
use crawlx_storage::{FsArtifactStore, Pg, StoreConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

struct Rig {
    app: Router,
    pg: Pg,
    key: String,
    artifacts: Arc<FsArtifactStore>,
    _dir: tempfile::TempDir,
}

async fn rig() -> Option<Rig> {
    rig_with_delivery(Arc::new(SystemClock), None).await
}

async fn rig_with_delivery(
    clock: Arc<dyn crawlx_core::Clock>,
    delivery: Option<Arc<crawlx_storage::DeliveryBuffer>>,
) -> Option<Rig> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("apie2e_{}", CrawlRunId::new().0.simple())),
            max_connections: 8,
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let pg = match &delivery {
        Some(delivery) => pg.with_delivery_buffer(delivery.clone()),
        None => pg,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    if let Some(delivery) = &delivery {
        artifacts = artifacts.with_zdr_buffer(delivery.clone());
    }
    let artifacts = Arc::new(artifacts);
    let repos = Repos::over_store(&pg, artifacts.clone());
    let key = generate_key();
    let rec = key_record(&key, tenant_id_for("acme"), Scope::all_set()).unwrap();
    repos.api.key_insert(&rec, "acme").await.unwrap();
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let mut builder =
        AppState::builder(repos, crawlx_api::admission_policy(&cfg, clock.clone()), cfg).clock(clock);
    if let Some(delivery) = delivery {
        builder = builder.zdr_buffer(delivery);
    }
    let state = builder.build();
    Some(Rig {
        app: crawlx_api::router(state),
        pg,
        key,
        artifacts,
        _dir: dir,
    })
}

impl Rig {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> (StatusCode, axum::http::HeaderMap, Value, Vec<u8>) {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.key));
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (p, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 64 << 20).await.unwrap().to_vec();
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (p.status, p.headers, v, bytes)
    }
}

#[tokio::test]
async fn native_and_all_pinned_head_identities_and_receipts_survive_postgres_restart() {
    use crawlx_core::repo::FrontierRepo;
    use crawlx_core::request::import::SOURCE_PINS;

    let Some(mut r) = rig().await else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        request_identity_key: Some(crawlx_core::SecretOr::secret([9; 32])),
        ..ApiConfig::default()
    };
    let clock = Arc::new(SystemClock);
    r.app = crawlx_api::router(
        AppState::builder(
            Repos::over_store(&r.pg, r.artifacts.clone()),
            crawlx_api::admission_policy(&config, clock.clone()),
            config.clone(),
        )
        .clock(clock)
        .build(),
    );
    let mut cases = Vec::new();
    for pin in std::iter::once(None).chain(SOURCE_PINS.into_iter().map(Some)) {
        let create = json!({"seedUrl":"https://app.example.test/","seed":11,
            "roles":[{"name":"anonymous"}]});
        let (status, _, created, _) = r.call(Method::POST, "/v1/crawls", &[], Some(&create)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{created}");
        let id = created["id"].as_str().unwrap();
        let run_id: CrawlRunId = id.parse().unwrap();
        let mut rows = json!([
            {"url":"https://app.example.test/same","method":"GET"},
            {"url":"https://app.example.test/same","method":"HEAD"},
            {"url":"https://app.example.test/same","method":"HEAD"}
        ]);
        let (endpoint, body) = match pin {
            Some((dialect, release, commit)) => {
                for row in rows.as_array_mut().unwrap() {
                    row["sourceKey"] = json!("same-opaque-key");
                }
                (
                    format!("/v1/crawls/{id}/requests/import"),
                    json!({
                        "producerEpoch":1,"export":{"version":1,
                            "source":{"dialect":dialect,"release":release,"commit":commit},
                            "requests":rows}
                    }),
                )
            }
            None => (
                format!("/v1/crawls/{id}/requests"),
                json!({
                    "producerEpoch":1,"requests":rows
                }),
            ),
        };
        let (status, _, receipt, _) = r
            .call(
                Method::POST,
                &endpoint,
                &[("Idempotency-Key", "head-restart")],
                Some(&body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        let inserted = receipt["data"]["inserted"].as_array().unwrap();
        assert_eq!(inserted.len(), 2);
        assert_eq!(receipt["data"]["duplicates"], 1);
        let get =
            r.pg.get_request(run_id, inserted[0].as_i64().unwrap())
                .await
                .unwrap();
        let head =
            r.pg.get_request(run_id, inserted[1].as_i64().unwrap())
                .await
                .unwrap();
        assert_eq!(get.envelope.method, "GET");
        assert_eq!(head.envelope.method, "HEAD");
        assert_ne!(get.identity, head.identity);
        cases.push((run_id, endpoint, body, receipt, get.identity, head.identity));
    }
    // Close all old API connections. Reopen both the repository and artifact index.
    r.app = Router::new();
    r.pg.pool().close().await;
    r.pg = Pg::connect_existing(
        &std::env::var("CRAWLX_TEST_DATABASE_URL").unwrap(),
        r.pg.config().clone(),
    )
    .await
    .unwrap();
    let clock = Arc::new(SystemClock);
    r.artifacts = Arc::new(
        FsArtifactStore::open(r._dir.path(), Arc::new(r.pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(r.pg.clone())),
    );
    r.app = crawlx_api::router(
        AppState::builder(
            Repos::over_store(&r.pg, r.artifacts.clone()),
            crawlx_api::admission_policy(&config, clock.clone()),
            config,
        )
        .clock(clock)
        .build(),
    );
    for (run_id, endpoint, body, first, get_identity, head_identity) in cases {
        let (status, _, retry, _) = r
            .call(
                Method::POST,
                &endpoint,
                &[("Idempotency-Key", "head-restart")],
                Some(&body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{retry}");
        assert_eq!(first["data"], retry["data"]);
        let inserted = first["data"]["inserted"].as_array().unwrap();
        let get =
            r.pg.get_request(run_id, inserted[0].as_i64().unwrap())
                .await
                .unwrap();
        let head =
            r.pg.get_request(run_id, inserted[1].as_i64().unwrap())
                .await
                .unwrap();
        assert_eq!(get.identity, get_identity);
        assert_eq!(head.identity, head_identity);
        assert_eq!(head.envelope.method, "HEAD");
        let (status, _, next, _) = r
            .call(
                Method::POST,
                &endpoint,
                &[("Idempotency-Key", "head-restart-next")],
                Some(&body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{next}");
        assert!(next["data"]["inserted"].as_array().unwrap().is_empty());
        assert_eq!(next["data"]["duplicates"], 3);
        let (status, _, page, _) = r
            .call(Method::GET, &format!("/v1/crawls/{run_id}/requests"), &[], None)
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let listed: Vec<_> = page["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].clone())
            .collect();
        assert_eq!(&listed, inserted);
        let mut post = body.clone();
        if post.get("export").is_some() {
            post["export"]["requests"][1]["method"] = json!("POST");
        } else {
            post["requests"][1]["method"] = json!("POST");
        }
        let (status, _, refused, _) = r
            .call(
                Method::POST,
                &endpoint,
                &[("Idempotency-Key", "head-restart-post")],
                Some(&post),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    }
    r.pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn full_lifecycle_over_postgres() {
    let Some(r) = rig().await else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    // auth against the api_keys table
    let bad = Request::builder()
        .uri("/v1/crawls/x")
        .header("authorization", "Bearer cx_live_aaaaaaaaaaaaaaaaaaaaaaaaaa")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        r.app.clone().oneshot(bad).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    // create + idempotent replay
    let body = json!({"seedUrl": "https://app.example.test/", "seed": 11, "roles": [{"name": "anonymous"}, {"name": "member"}],
        "output": {"webhook": {"url": "https://hooks.example.test/x", "events": ["completed"]}}});
    let h = [("Idempotency-Key", "pg-1")];
    let (s, hdr, v, _) = r.call(Method::POST, "/v1/crawls", &h, Some(&body)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    assert_eq!(hdr["location"], format!("/v1/crawls/{id}").as_str());
    assert_eq!(v["status"], "queued");
    let (s, hdr, v2, _) = r.call(Method::POST, "/v1/crawls", &h, Some(&body)).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(hdr["idempotent-replayed"], "true");
    assert_eq!(v2["id"], id.as_str());
    let (s, _, v3, _) = r
        .call(
            Method::POST,
            "/v1/crawls",
            &h,
            Some(&json!({"seedUrl": "https://x.example.test/"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v3["error"]["code"], "idempotency_key_reuse");

    let (s, _, g, _) = r.call(Method::GET, &format!("/v1/crawls/{id}"), &[], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(g["seed"], 11);
    assert_eq!(g["sessions"].as_array().unwrap().len(), 2);
    assert_eq!(g["webhook"]["deadDeliveries"], 0);

    // pause / resume need a running run (the worker's job)
    let run_id: CrawlRunId = id.parse().unwrap();
    r.pg.set_status(run_id, RunStatus::Running, None).await.unwrap();
    let (s, _, v, _) = r
        .call(Method::POST, &format!("/v1/crawls/{id}:pause"), &[], None)
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "paused");
    let (s, _, v, _) = r
        .call(Method::POST, &format!("/v1/crawls/{id}:resume"), &[], None)
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "running");

    // events: SSE replays crawl_events and closes on the terminal event
    r.pg.append(run_id, "page", json!({"n": 1})).await.unwrap();
    let (s, _, v, _) = r
        .call(Method::POST, &format!("/v1/crawls/{id}:cancel"), &[], None)
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["terminalReason"], "cancelled");
    let (s, _, _, raw) = r
        .call(Method::GET, &format!("/v1/crawls/{id}/events"), &[], None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let text = String::from_utf8(raw).unwrap();
    assert!(
        text.contains("event: paused")
            && text.contains("event: resumed")
            && text.contains("event: completed"),
        "{text}"
    );
    assert!(event_frames(text.as_bytes())
        .iter()
        .any(|event| event["type"] == "page" && event["data"] == json!({"n": 1})));
    let (_, _, _, raw) = r
        .call(
            Method::GET,
            &format!("/v1/crawls/{id}/events"),
            &[("Last-Event-ID", "3")],
            None,
        )
        .await;
    assert!(String::from_utf8(raw).unwrap().starts_with("id: 4\n"));

    // artifacts: sensitive read is audited in the hash chain
    let a = r
        .artifacts
        .put_kind(
            run_id,
            Sensitivity::Sensitive,
            "dom_snapshot",
            "text/plain",
            b"dom",
        )
        .await
        .unwrap();
    let (s, _, _, raw) = r
        .call(
            Method::GET,
            &format!("/v1/crawls/{id}/artifacts/{}", a.id),
            &[],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(raw, b"dom");
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event = 'artifact.read_sensitive'")
            .fetch_one(r.pg.pool())
            .await
            .unwrap();
    assert_eq!(audits, 1);

    // coverage / states / transitions / traffic / approvals / errors answer on an empty run
    for ep in [
        "coverage",
        "states",
        "transitions",
        "traffic",
        "approvals",
        "errors",
        "pages",
    ] {
        let (s, _, v, _) = r
            .call(Method::GET, &format!("/v1/crawls/{id}/{ep}"), &[], None)
            .await;
        assert_eq!(s, StatusCode::OK, "{ep}: {v}");
    }

    // compat facade over the same tables
    let (s, _, c, _) = r
        .call(
            Method::POST,
            "/compat/v2/crawl",
            &[],
            Some(&json!({"url": "https://docs.example.test/", "ignoreQueryParameters": true})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{c}");
    let cid = c["id"].as_str().unwrap();
    let (_, _, st, _) = r
        .call(Method::GET, &format!("/compat/v2/crawl/{cid}"), &[], None)
        .await;
    assert_eq!(st["status"], "scraping");
    let stored = r.pg.get(cid.parse().unwrap()).await.unwrap();
    assert_eq!(
        stored.config.scope.query_policy,
        crawlx_core::config::QueryPolicy::StripAll
    );

    // a replay run is tagged run_kind = replay
    let tid = uuid::Uuid::now_v7();
    let (s, _, v, _) = r
        .call(
            Method::POST,
            "/v1/replays",
            &[],
            Some(&json!({"sourceRunId": id, "path": {"transitionIds": [tid]}})),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "unknown transition: {v}");

    // erase: terminal runs only; rows are gone afterwards
    let (s, _, _, _) = r
        .call(Method::DELETE, &format!("/v1/crawls/{cid}"), &[], None)
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, v, _) = r
        .call(Method::DELETE, &format!("/v1/crawls/{id}"), &[], None)
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let (s, _, _, _) = r.call(Method::GET, &format!("/v1/crawls/{id}"), &[], None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM crawl_events WHERE run_id = $1")
        .bind(run_id.0)
        .fetch_one(r.pg.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
    let run_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM crawl_runs WHERE run_id = $1")
        .bind(run_id.0)
        .fetch_one(r.pg.pool())
        .await
        .unwrap();
    assert_eq!(run_rows, 0);
    r.pg.clone().drop_schema().await.unwrap();
}

#[tokio::test]
async fn shared_zdr_delivery_expiry_preserves_status_and_numeric_billing_without_runtime_config() {
    use crawlx_core::repo::{ArtifactStore, FrontierRepo, PageRepo};
    use crawlx_core::time::ManualClock;
    use crawlx_core::{Clock, StoreError, TrustLane};
    use crawlx_storage::{testkit, BufferLimits, DeliveryBuffer};

    let clock = Arc::new(ManualClock::new("2026-11-04T00:00:00Z".parse().unwrap()));
    let delivery_root = tempfile::tempdir().unwrap();
    let writer = Arc::new(
        DeliveryBuffer::open_fs(delivery_root.path(), clock.clone(), BufferLimits::default())
            .await
            .unwrap(),
    );
    let reader = Arc::new(
        DeliveryBuffer::open_fs(delivery_root.path(), clock.clone(), BufferLimits::default())
            .await
            .unwrap(),
    );
    let Some(r) = rig_with_delivery(clock.clone(), Some(reader.clone())).await else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let (status, _, created, _) = r
        .call(
            Method::POST,
            "/v1/crawls",
            &[],
            Some(&json!({"seedUrl": "https://app.example.test/private", "seed": 11,
            "retention": {"mode": "zdr", "days": 0}})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    let run: CrawlRunId = created["id"].as_str().unwrap().parse().unwrap();
    let worker = r.pg.clone().with_delivery_buffer(writer.clone());
    let tenant = worker.get(run).await.unwrap().tenant;
    let artifacts = FsArtifactStore::open(r._dir.path(), Arc::new(worker.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(worker.clone()))
        .with_zdr_buffer(writer.clone());
    let mut artifact = None;
    let mut first_page = None;
    for page in [1, 2] {
        let url = testkit::canonical_url(&format!("https://app.example.test/private/{page}"));
        let (_, frontier) = worker.discover(run, &url, 0, None, None).await.unwrap();
        let frontier = frontier.unwrap();
        first_page.get_or_insert(frontier);
        let markdown = artifacts
            .put_page(
                run,
                frontier,
                Sensitivity::Content,
                "text/markdown",
                b"ZDR_BODY_CANARY",
            )
            .await
            .unwrap();
        artifact = Some(markdown.id);
        let record = crawlx_core::repo::PageRecord {
            run,
            frontier_id: frontier,
            url,
            status: 200,
            content_type: Some("text/html".to_owned()),
            content_digest: markdown.digest,
            title: Some("ZDR_TITLE_CANARY".to_owned()),
            markdown: Some(markdown),
            html: None,
            metadata: json!({"description": "ZDR_DESCRIPTION_CANARY"}),
            links: Vec::new(),
            fetched_at: clock.now(),
            lane: TrustLane::Diagnostic,
        };
        worker.put(&record).await.unwrap();
        worker
            .append(run, "page", json!({"pageId": frontier}))
            .await
            .unwrap();
    }
    let mut counters = crawlx_core::counters::PlaneCounters::default();
    counters.urls.admitted = 2;
    counters.urls.succeeded = 2;
    worker.update_counters(run, counters).await.unwrap();
    worker
        .set_status(
            run,
            RunStatus::Completed,
            Some(crawlx_core::counters::TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    worker
        .append(run, "completed", json!({"status": "completed"}))
        .await
        .unwrap();
    let (status, _, pages, _) = r
        .call(Method::GET, &format!("/v1/crawls/{run}/pages"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK, "{pages}");
    assert_eq!(pages["total"], 2);
    assert_eq!(pages["data"][0]["markdown"], "ZDR_BODY_CANARY");
    assert!(writer.ack(tenant, run, first_page.unwrap()).await.unwrap());
    let (status, _, pages, _) = r
        .call(Method::GET, &format!("/v1/crawls/{run}/pages"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK, "{pages}");
    assert_eq!(pages["total"], 1);
    assert_eq!(worker.billing(run).await.unwrap().unwrap().credits, 2);

    clock.advance_ms(60 * 60 * 1000);
    assert!(matches!(
        worker.get(run).await,
        Err(StoreError::RetentionDenied(_))
    ));
    let (status, _, summary, _) = r.call(Method::GET, &format!("/v1/crawls/{run}"), &[], None).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["status"], "completed");
    let (status, _, pages, _) = r
        .call(Method::GET, &format!("/v1/crawls/{run}/pages"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK, "{pages}");
    assert_eq!(pages["total"], 0);
    let (status, _, _, bytes) = r
        .call(Method::GET, &format!("/v1/crawls/{run}/export"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(bytes.is_empty());
    let (status, _, _, _) = r
        .call(
            Method::GET,
            &format!("/v1/crawls/{run}/artifacts/{}", artifact.unwrap()),
            &[],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
    let (status, _, _, events) = r
        .call(Method::GET, &format!("/v1/crawls/{run}/events"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!String::from_utf8(events).unwrap().contains("ZDR_BODY_CANARY"));
    let (status, _, compat, _) = r
        .call(Method::GET, &format!("/compat/v2/crawl/{run}"), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK, "{compat}");
    assert_eq!(compat["creditsUsed"], 2);
    assert_eq!(compat["data"], json!([]));
    assert_eq!(worker.billing(run).await.unwrap().unwrap().pages, 2);
    let _ = reader.sweep(clock.now()).await.unwrap();
    assert!(reader.is_empty().await.unwrap());
    r.pg.clone().drop_schema().await.unwrap();
}

fn event_frames(raw: &[u8]) -> Vec<Value> {
    std::str::from_utf8(raw)
        .unwrap()
        .split("\n\n")
        .filter_map(|frame| frame.lines().find_map(|line| line.strip_prefix("data: ")))
        .map(|data| serde_json::from_str(data).unwrap())
        .collect()
}

#[tokio::test]
async fn shared_zdr_sse_preserves_live_events_and_replays_only_metadata_after_expiry() {
    use crawlx_core::counters::TerminalReason;
    use crawlx_core::time::ManualClock;
    use crawlx_core::StoreError;
    use crawlx_storage::{BufferLimits, DeliveryBuffer};

    let clock = Arc::new(ManualClock::new("2026-11-04T00:00:00Z".parse().unwrap()));
    let root = tempfile::tempdir().unwrap();
    let writer = Arc::new(
        DeliveryBuffer::open_fs(root.path(), clock.clone(), BufferLimits::default())
            .await
            .unwrap(),
    );
    let reader = Arc::new(
        DeliveryBuffer::open_fs(root.path(), clock.clone(), BufferLimits::default())
            .await
            .unwrap(),
    );
    let Some(r) = rig_with_delivery(clock.clone(), Some(reader)).await else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let worker = r.pg.clone().with_delivery_buffer(writer);
    let (status, _, created, _) = r
        .call(
            Method::POST,
            "/v1/crawls",
            &[],
            Some(&json!({"seedUrl": "https://app.example.test/", "seed": 11,
                "retention": {"mode": "zdr", "days": 0}})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    let run: CrawlRunId = created["id"].as_str().unwrap().parse().unwrap();
    let originals = [
        (
            "page",
            json!({"pageId": 77, "url": "https://app.example.test/SSE_URL_CANARY",
            "status": 200, "title": "SSE_TITLE_CANARY"}),
        ),
        (
            "page.failed",
            json!({"pageId": 78, "url": "https://app.example.test/SSE_FAILED_CANARY",
            "status": 503, "error": "SSE_ERROR_CANARY"}),
        ),
        (
            "progress",
            json!({"counters": {"urls": {"succeeded": 1, "failed": 1}}}),
        ),
        (
            "completed",
            json!({"status": "failed", "terminalReason": "fatal_error",
            "counters": {"urls": {"succeeded": 1, "failed": 1}}}),
        ),
    ];
    let mut sequences = Vec::new();
    for (kind, payload) in &originals {
        sequences.push(worker.append(run, kind, payload.clone()).await.unwrap());
    }
    worker
        .set_status(run, RunStatus::Failed, Some(TerminalReason::FatalError))
        .await
        .unwrap();
    let metadata = worker.list_metadata_after(run, 0, 100).await.unwrap();
    let durable: Vec<(String, Value)> =
        sqlx::query_as("SELECT type, payload FROM crawl_events WHERE run_id = $1 ORDER BY seq")
            .bind(run.0)
            .fetch_all(worker.pool())
            .await
            .unwrap();
    let durable_text = serde_json::to_string(&durable).unwrap();
    for canary in [
        "SSE_URL_CANARY",
        "SSE_TITLE_CANARY",
        "SSE_FAILED_CANARY",
        "SSE_ERROR_CANARY",
    ] {
        assert!(!durable_text.contains(canary), "{durable_text}");
    }
    assert!(!durable_text.contains("page.failed"), "{durable_text}");
    for (_, payload) in &durable {
        assert!(payload.get("digest").is_some(), "{payload}");
        assert!(payload.get("url").is_none(), "{payload}");
        assert!(payload.get("status").is_none(), "{payload}");
        assert!(payload.get("counters").is_none(), "{payload}");
    }
    let path = format!("/v1/crawls/{run}/events");
    let (status, _, _, raw) = r.call(Method::GET, &path, &[], None).await;
    assert_eq!(status, StatusCode::OK);
    let live = event_frames(&raw);
    assert_eq!(live.len(), metadata.len());
    for ((kind, payload), seq) in originals.iter().zip(&sequences) {
        let frame = live.iter().find(|frame| frame["seq"] == *seq).unwrap();
        assert_eq!(frame["type"], *kind);
        assert_eq!(&frame["data"], payload);
    }
    let (_, _, _, raw) = r
        .call(Method::GET, &format!("{path}?types=page.failed"), &[], None)
        .await;
    let filtered = event_frames(&raw);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["type"], "page.failed");
    assert_eq!(filtered[0]["data"], originals[1].1);

    clock.advance_ms(60 * 60 * 1000);
    assert!(matches!(
        worker.list_after(run, 0, 100).await,
        Err(StoreError::RetentionDenied(_))
    ));
    let (status, _, _, raw) = r.call(Method::GET, &path, &[], None).await;
    assert_eq!(status, StatusCode::OK);
    let expired = event_frames(&raw);
    assert_eq!(expired.len(), metadata.len());
    for (frame, event) in expired.iter().zip(&metadata) {
        assert_eq!(frame["seq"], event.seq);
        assert_eq!(frame["type"], event.kind);
        assert_eq!(frame["data"], event.payload);
    }
    assert_eq!(expired.last().unwrap()["type"], "completed");
    assert!(expired.last().unwrap()["data"].get("status").is_none());
    let (_, _, _, raw) = r
        .call(Method::GET, &format!("{path}?types=page.failed"), &[], None)
        .await;
    assert!(event_frames(&raw).is_empty());
    r.pg.clone().drop_schema().await.unwrap();
}

#[tokio::test]
async fn shared_zdr_sse_hydrates_live_neighbors_of_expired_events() {
    use crawlx_core::counters::TerminalReason;
    use crawlx_core::time::ManualClock;
    use crawlx_storage::{BufferLimits, DeliveryBuffer};

    let clock = Arc::new(ManualClock::new("2026-11-04T00:00:00Z".parse().unwrap()));
    let root = tempfile::tempdir().unwrap();
    let writer = Arc::new(
        DeliveryBuffer::open_fs(root.path(), clock.clone(), BufferLimits::default())
            .await
            .unwrap(),
    );
    let reader = Arc::new(
        DeliveryBuffer::open_fs(root.path(), clock.clone(), BufferLimits::default())
            .await
            .unwrap(),
    );
    let Some(r) = rig_with_delivery(clock.clone(), Some(reader)).await else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let worker = r.pg.clone().with_delivery_buffer(writer.clone());
    let (status, _, created, _) = r
        .call(
            Method::POST,
            "/v1/crawls",
            &[],
            Some(&json!({"seedUrl": "https://app.example.test/", "seed": 11,
                "retention": {"mode": "zdr", "days": 0}})),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    let run: CrawlRunId = created["id"].as_str().unwrap().parse().unwrap();
    let old = worker
        .append(run, "paused", json!({"reason": "EXPIRED_SSE_CANARY"}))
        .await
        .unwrap();
    let expired_page = worker.append(run, "page", json!({"pageId": 91})).await.unwrap();
    clock.advance_ms(60 * 60 * 1000);
    assert!(matches!(
        worker.list_after(run, old.saturating_sub(1), 1).await,
        Err(crawlx_core::StoreError::RetentionDenied(_))
    ));
    let tenant = worker.get_metadata(run).await.unwrap().tenant;
    writer
        .insert(
            tenant,
            run,
            91,
            "markdown",
            "text/markdown",
            b"RESURRECTED_PAGE_CANARY",
        )
        .await
        .unwrap();
    let fresh = json!({"url": "https://app.example.test/LIVE_SSE_CANARY", "status": 503});
    let seq = worker.append(run, "page.failed", fresh.clone()).await.unwrap();
    worker
        .set_status(run, RunStatus::Failed, Some(TerminalReason::FatalError))
        .await
        .unwrap();
    worker
        .append(run, "failed", json!({"status": "failed"}))
        .await
        .unwrap();
    let (_, _, _, raw) = r
        .call(Method::GET, &format!("/v1/crawls/{run}/events"), &[], None)
        .await;
    let frames = event_frames(&raw);
    let expired = frames.iter().find(|frame| frame["seq"] == old).unwrap();
    assert!(expired["data"].get("digest").is_some());
    assert!(expired["data"].get("reason").is_none());
    let page = frames.iter().find(|frame| frame["seq"] == expired_page).unwrap();
    assert!(page["data"].get("digest").is_some());
    assert!(page["data"].get("content").is_none());
    let live = frames.iter().find(|frame| frame["seq"] == seq).unwrap();
    assert_eq!(live["type"], "page.failed");
    assert_eq!(live["data"], fresh);
    assert_eq!(frames.last().unwrap()["type"], "failed");
    assert!(!std::str::from_utf8(&raw).unwrap().contains("EXPIRED_SSE_CANARY"));
    assert!(!std::str::from_utf8(&raw)
        .unwrap()
        .contains("RESURRECTED_PAGE_CANARY"));
    // A corrupt live original is not an expiry: do not fall back to metadata and
    // then emit a terminal event that could make the failed stream look complete.
    writer
        .insert(
            tenant,
            run,
            i64::MIN + 1,
            &format!("_event:{seq}"),
            "application/json",
            b"not valid JSON",
        )
        .await
        .unwrap();
    let (_, _, _, raw) = r
        .call(
            Method::GET,
            &format!("/v1/crawls/{run}/events?after={expired_page}"),
            &[],
            None,
        )
        .await;
    assert!(event_frames(&raw).is_empty(), "{raw:?}");
    r.pg.clone().drop_schema().await.unwrap();
}

#[tokio::test]
async fn authenticated_zdr_auditor_event_does_not_block_webhooks_for_other_runs() {
    use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookSender, WebhookTransport};
    use crawlx_core::epoch::ObservationEpoch;
    use crawlx_core::hash::Digest;
    use crawlx_core::repo::ActionJournal;
    use crawlx_core::time::ManualClock;
    use crawlx_core::{StateClusterId, WorkerId};
    use crawlx_storage::testkit::{allow_verdict, proposal};
    use crawlx_storage::{BufferLimits, DeliveryBuffer, LeaseRepo};

    #[derive(Default)]
    struct Receiver(std::sync::Mutex<Vec<WebhookRequest>>);

    #[async_trait::async_trait]
    impl WebhookTransport for Receiver {
        async fn post(&self, request: WebhookRequest) -> Result<u16, TransportError> {
            self.0.lock().unwrap().push(request);
            Ok(200)
        }
    }

    let clock = Arc::new(ManualClock::new("2026-11-04T00:00:00Z".parse().unwrap()));
    let root = tempfile::tempdir().unwrap();
    let delivery = Arc::new(
        DeliveryBuffer::open_fs(root.path(), clock.clone(), BufferLimits::default())
            .await
            .unwrap(),
    );
    let Some(r) = rig_with_delivery(clock.clone(), Some(delivery.clone())).await else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let mut runs = Vec::new();
    for mode in ["zdr", "standard"] {
        let (status, _, created, _) = r
            .call(
                Method::POST,
                "/v1/crawls",
                &[],
                Some(&json!({"seedUrl": "https://app.example.test/", "seed": 11,
                    "retention": {"mode": mode, "days": if mode == "zdr" { 0 } else { 7 }},
                    "output": {"webhook": {"url": "https://hooks.example.test/events", "events": ["paused"]}}})),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{created}");
        runs.push(created["id"].as_str().unwrap().parse::<CrawlRunId>().unwrap());
    }
    let run = runs[0];
    r.pg.set_status(run, RunStatus::Running, None).await.unwrap();
    let lease =
        r.pg.claim_session(run, WorkerId::new(), true)
            .await
            .unwrap()
            .unwrap();
    let action =
        r.pg.propose(
            run,
            lease.session.id,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    r.pg.intend(action, lease.session.id, ObservationEpoch::default())
        .await
        .unwrap();
    sqlx::query("UPDATE safety_decisions SET verdict = 'deny' WHERE action_id = $1")
        .bind(action.0)
        .execute(r.pg.pool())
        .await
        .unwrap();
    let tenant = r.pg.get_metadata(run).await.unwrap().tenant;
    let mut tx = r.pg.pool().begin().await.unwrap();
    let previous: Vec<u8> = sqlx::query_scalar("SELECT safety_auditor_chain_head()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let subject = json!({"action": action, "reason": "denied_action_intended"});
    let entry = json!({"tenant": tenant, "run": run, "actor": "safety_auditor",
        "event": "safety.invariant_violation", "subject": subject});
    let mut bytes = previous.clone();
    bytes.extend_from_slice(entry.to_string().as_bytes());
    let hash = Digest::of("crawlx/audit-chain/v1", &bytes);
    let paused: bool = sqlx::query_scalar("SELECT safety_auditor_pause($1,$2,$3,$4)")
        .bind(action.0)
        .bind("denied_action_intended")
        .bind(previous)
        .bind(hash.0.as_slice())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(paused);
    tx.commit().await.unwrap();
    let auditor_event = r.pg.list_after(run, 0, 100).await.unwrap().pop().unwrap();
    assert_eq!(auditor_event.kind, "paused");
    assert!(auditor_event.payload.get("digest").is_some());
    assert!(auditor_event.payload.get("reason").is_none());
    let custody: i64 =
        sqlx::query_scalar("SELECT metadata_only_audit_id FROM crawl_events WHERE run_id = $1 AND seq = $2")
            .bind(run.0)
            .bind(i64::try_from(auditor_event.seq).unwrap())
            .fetch_one(r.pg.pool())
            .await
            .unwrap();
    assert!(sqlx::query(
        "UPDATE crawl_events SET payload = '{\"digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}' WHERE metadata_only_audit_id = $1",
    )
    .bind(custody)
    .execute(r.pg.pool())
    .await
    .is_err());
    assert!(
        sqlx::query("UPDATE crawl_events SET type = 'completed' WHERE metadata_only_audit_id = $1")
            .bind(custody)
            .execute(r.pg.pool())
            .await
            .is_err()
    );
    r.pg.append(runs[1], "paused", json!({"by": "operator"}))
        .await
        .unwrap();
    let repos = Repos::over_store(&r.pg, r.artifacts.clone());
    let receiver = Arc::new(Receiver::default());
    let sender = WebhookSender::new(
        repos.api,
        repos.runs,
        repos.events,
        receiver.clone(),
        "whsec_test".to_owned(),
        clock,
    )
    .with_zdr_buffer(delivery);
    let report = sender.tick().await.unwrap();
    assert_eq!((report.enqueued, report.delivered), (2, 2));
    let received: Vec<Value> = receiver
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap())
        .collect();
    assert!(received.iter().any(|event| event["runId"] == run.to_string()
        && event["type"] == "paused"
        && event["data"] == auditor_event.payload));
    assert!(received
        .iter()
        .any(|event| event["runId"] == runs[1].to_string() && event["data"] == json!({"by": "operator"})));
    let ordinary =
        r.pg.append(run, "paused", json!({"by": "operator"}))
            .await
            .unwrap();
    assert!(sqlx::query(
        "UPDATE crawl_events SET metadata_only_audit_id = $1 WHERE run_id = $2 AND seq = $3",
    )
    .bind(custody)
    .bind(run.0)
    .bind(i64::try_from(ordinary).unwrap())
    .execute(r.pg.pool())
    .await
    .is_err());
    let marker: Option<i64> =
        sqlx::query_scalar("SELECT metadata_only_audit_id FROM crawl_events WHERE run_id = $1 AND seq = $2")
            .bind(run.0)
            .bind(i64::try_from(ordinary).unwrap())
            .fetch_one(r.pg.pool())
            .await
            .unwrap();
    assert!(marker.is_none());
    crawlx_storage::retention::RetentionSweeper::new(r.pg.clone())
        .purge_run(run)
        .await
        .unwrap();
    for table in ["crawl_events", "webhook_deliveries"] {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE run_id = $1"
        )))
        .bind(run.0)
        .fetch_one(r.pg.pool())
        .await
        .unwrap();
        assert_eq!(count, 0, "run erasure must remove {table}");
    }
    let retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_events WHERE audit_id = $1)")
        .bind(custody)
        .fetch_one(r.pg.pool())
        .await
        .unwrap();
    assert!(retained, "run erasure preserves the canonical audit chain");
    r.pg.clone().drop_schema().await.unwrap();
}
