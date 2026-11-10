#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Presigned `content` URLs and zero-data-retention delivery. `/pages` and the
//! compat facade serve a ZDR run from the in-memory delivery buffer; a webhook `2xx` or the
//! 1 h TTL removes a page. `/artifacts/{id}` redirects `content` to a presigned URL.
mod common;

use async_trait::async_trait;
use axum::http::{Method, StatusCode};
use chrono::Utc;
use common::{env_with_zdr, json, Env};
use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookSender, WebhookTransport};
use crawlx_api::{ApiConfig, Settings};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ArtifactStore, EventRepo, PageRecord, PageRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::TrustLane;
use crawlx_core::{Clock, CrawlRunId};
use crawlx_storage::testkit;
use crawlx_storage::DeliveryBuffer;
use parking_lot::Mutex;
use serde_json::{json as j, Value};
use std::sync::Arc;

const SECRET: &str = "whsec_zdr";

/// Records requests and answers `200`.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<WebhookRequest>>,
}

#[async_trait]
impl WebhookTransport for Recorder {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        self.seen.lock().push(req);
        Ok(200)
    }
}

struct Rig {
    env: Env,
    zdr: Arc<DeliveryBuffer>,
    clock: Arc<ManualClock>,
}

fn rig() -> Rig {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        webhook_secret: SECRET.to_owned(),
        ..ApiConfig::default()
    };
    let settings = Settings {
        inline_max_bytes: 64,
        ..Settings::default()
    };
    let (env, zdr) = env_with_zdr(cfg, settings, clock.clone());
    Rig { env, zdr, clock }
}

async fn zdr_run(r: &Rig, webhook_events: Option<&[&str]>) -> (String, CrawlRunId) {
    let mut body = j!({
        "seedUrl": "https://app.example.test/",
        "seed": 3,
        "retention": {"mode": "zdr"},
    });
    if let Some(events) = webhook_events {
        body["output"] = j!({"webhook": {"url": "https://hooks.example.test/zdr", "events": events}});
    }
    let id = r.env.create_run(&body).await;
    let run: CrawlRunId = id.parse().unwrap();
    (id, run)
}

/// What the worker does for a page of a ZDR run: `put_page` (lands in the buffer), the page
/// row (metadata only) and the `page` event.
async fn write_page(r: &Rig, run: CrawlRunId, page: i64, markdown: &str) -> PageRecord {
    let md = r
        .env
        .artifacts
        .put_page(
            run,
            page,
            Sensitivity::Content,
            "text/markdown",
            markdown.as_bytes(),
        )
        .await
        .unwrap();
    let html = r
        .env
        .artifacts
        .put_page(
            run,
            page,
            Sensitivity::Content,
            "text/html",
            format!("<h1>{page}</h1>").as_bytes(),
        )
        .await
        .unwrap();
    let record = PageRecord {
        run,
        frontier_id: page,
        url: testkit::canonical_url(&format!("https://app.example.test/p/{page}")),
        status: 200,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("t", markdown.as_bytes()),
        title: Some(format!("Page {page}")),
        markdown: Some(md),
        html: Some(html),
        metadata: j!({"role": "anonymous", "depth": 1}),
        links: vec![],
        fetched_at: r.clock.now(),
        lane: TrustLane::Diagnostic,
    };
    r.env.store.put(&record).await.unwrap();
    r.env
        .store
        .append(
            run,
            "page",
            j!({"pageId": page, "url": record.url.to_string(), "status": 200}),
        )
        .await
        .unwrap();
    record
}

fn urls(v: &Value) -> Vec<String> {
    v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["metadata"]["sourceURL"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn sse_hydrates_live_page_content_without_exposing_internal_sidebands_or_acknowledging() {
    let r = rig();
    let (id, run) = zdr_run(&r, None).await;
    let record = write_page(&r, run, 1, "# streamed").await;
    r.zdr
        .insert(
            r.env.tenant,
            run,
            1,
            "page_record",
            "application/json",
            &serde_json::to_vec(&record).unwrap(),
        )
        .await
        .unwrap();
    r.zdr
        .insert(
            r.env.tenant,
            run,
            1,
            "_context",
            "application/json",
            b"PRIVATE_CONTEXT_CANARY",
        )
        .await
        .unwrap();
    r.env
        .store
        .append(run, "completed", j!({"status": "completed"}))
        .await
        .unwrap();
    let (status, _, bytes) = r
        .env
        .send(
            Method::GET,
            &format!("/v1/crawls/{id}/events"),
            Some(&r.env.key),
            &[],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let stream = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(stream.contains("# streamed"), "{stream}");
    assert!(!stream.contains("PRIVATE_CONTEXT_CANARY"), "{stream}");
    assert!(!stream.contains("page_record"), "{stream}");
    assert!(
        r.zdr.get(r.env.tenant, run, 1).await.unwrap().is_some(),
        "SSE does not acknowledge"
    );

    r.clock.advance_ms(60 * 60 * 1000);
    let (status, _, bytes) = r
        .env
        .send(
            Method::GET,
            &format!("/v1/crawls/{id}/events"),
            Some(&r.env.key),
            &[],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!String::from_utf8(bytes.to_vec()).unwrap().contains("# streamed"));
}

#[tokio::test]
async fn zdr_pages_are_served_from_the_delivery_buffer_and_nothing_is_durable() {
    let r = rig();
    let (id, run) = zdr_run(&r, None).await;
    write_page(&r, run, 1, "# one").await;
    write_page(&r, run, 2, "# two").await;
    assert!(
        r.env.artifacts.blobs().is_empty(),
        "no object written for a zdr run"
    );
    assert_eq!(r.zdr.len().await.unwrap(), 2);

    let (s, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["total"], 2);
    assert_eq!(v["data"][0]["markdown"], "# one");
    assert_eq!(v["data"][0]["metadata"]["crawlx"]["pageId"], "1");
    assert_eq!(
        urls(&v),
        ["https://app.example.test/p/1", "https://app.example.test/p/2"]
    );
    let (_, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages?include=html")).await;
    assert_eq!(v["data"][1]["html"], "<h1>2</h1>");

    // the compat facade lists the same pages
    let (s, _, v) = r.env.get(&format!("/compat/v2/crawl/{id}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"].as_array().unwrap().len(), 2);
    assert_eq!(v["data"][0]["markdown"], "# one");

    // export and jsonl read the buffer too
    let (s, _, b) = r
        .env
        .send(
            Method::GET,
            &format!("/v1/crawls/{id}/export?format=jsonl&include=html"),
            Some(&r.env.key),
            &[],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let text = String::from_utf8(b.to_vec()).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("<h1>1</h1>"), "{text}");

    // acknowledging page 1 removes it from every listing
    assert!(r.zdr.ack(r.env.tenant, run, 1).await.unwrap());
    let (_, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages")).await;
    assert_eq!(v["total"], 1);
    assert_eq!(urls(&v), ["https://app.example.test/p/2"]);

    // the TTL hides page 2 at 1 h, and the sweeper drops it
    r.clock.advance_ms(60 * 60 * 1000);
    let (s, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["total"], 0);
    assert_eq!(v["data"], j!([]));
    assert_eq!(r.zdr.len().await.unwrap(), 1, "hidden but not yet swept");
    assert_eq!(r.zdr.sweep(r.clock.now()).await.unwrap(), 1);
    assert!(r.zdr.is_empty().await.unwrap());
}

#[tokio::test]
async fn zdr_content_above_the_inline_cap_links_to_the_buffered_artifact() {
    let r = rig();
    let (id, run) = zdr_run(&r, None).await;
    let big = "x".repeat(200);
    let record = write_page(&r, run, 1, &big).await;
    let (s, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"][0]["markdown"], Value::Null);
    let link = v["data"][0]["metadata"]["crawlx"]["markdownRef"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        link,
        format!(
            "/v1/crawls/{id}/artifacts/{}",
            record.markdown.as_ref().unwrap().id
        )
    );
    let (s, h, b) = r.env.send(Method::GET, &link, Some(&r.env.key), &[], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b.as_ref(), big.as_bytes());
    assert_eq!(h["content-type"], "text/markdown");
    assert_eq!(h["x-crawlx-sensitivity"], "content");
    // once acknowledged the artifact is gone (410), like any other zdr artifact
    assert!(r.zdr.ack(r.env.tenant, run, 1).await.unwrap());
    let (s, _, b) = r.env.send(Method::GET, &link, Some(&r.env.key), &[], None).await;
    assert_eq!(s, StatusCode::GONE);
    assert_eq!(json(&b)["error"]["code"], "artifact_unavailable");
    // another run cannot reach it through its own id
    let (other, _) = zdr_run(&r, None).await;
    write_page(&r, run, 2, "# again").await;
    let aid = r.zdr.get(r.env.tenant, run, 2).await.unwrap().unwrap().blobs["markdown"]
        .artifact
        .id;
    let (s, _, _) = r
        .env
        .send(
            Method::GET,
            &format!("/v1/crawls/{other}/artifacts/{aid}"),
            Some(&r.env.key),
            &[],
            None,
        )
        .await;
    assert_eq!(s, StatusCode::GONE);
}

#[tokio::test]
async fn webhook_delivery_carries_buffered_content_and_a_2xx_acknowledges_the_page() {
    let r = rig();
    let (id, run) = zdr_run(&r, Some(&["page"])).await;
    write_page(&r, run, 1, "# delivered").await;
    write_page(&r, run, 2, "# pending").await;
    let recorder = Arc::new(Recorder::default());
    let sender = WebhookSender::new(
        r.env.state.repos.api.clone(),
        r.env.state.repos.runs.clone(),
        r.env.state.repos.events.clone(),
        recorder.clone(),
        SECRET.to_owned(),
        r.clock.clone(),
    )
    .with_zdr_buffer(r.zdr.clone());

    let rep = sender.tick().await.unwrap();
    assert_eq!((rep.enqueued, rep.delivered), (2, 2), "{rep:?}");
    let bodies: Vec<Value> = recorder
        .seen
        .lock()
        .iter()
        .map(|q| serde_json::from_slice(&q.body).unwrap())
        .collect();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["type"], "page");
    assert_eq!(bodies[0]["data"]["pageId"], 1);
    assert_eq!(bodies[0]["data"]["content"]["markdown"], "# delivered");
    assert_eq!(bodies[0]["data"]["content"]["html"], "<h1>1</h1>");
    assert_eq!(bodies[1]["data"]["content"]["markdown"], "# pending");
    // both pages were acknowledged out of the buffer
    assert!(r.zdr.is_empty().await.unwrap(), "{:?}", r.zdr);
    let (s, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["total"], 0);
    // an event the buffer knows nothing about goes out as-is
    r.env
        .store
        .append(
            run,
            "page",
            j!({"pageId": 99, "url": "https://app.example.test/p/99"}),
        )
        .await
        .unwrap();
    let rep = sender.tick().await.unwrap();
    assert_eq!(rep.delivered, 1);
    let last: Value = serde_json::from_slice(&recorder.seen.lock().last().unwrap().body).unwrap();
    assert_eq!(last["data"].get("content"), None);
}

#[tokio::test]
async fn standard_runs_keep_durable_content_and_never_touch_the_buffer() {
    let r = rig();
    let id = r.env.create_run(&common::simple_body()).await;
    let run: CrawlRunId = id.parse().unwrap();
    write_page(&r, run, 1, "# durable").await;
    assert!(r.zdr.is_empty().await.unwrap());
    assert!(!r.env.artifacts.blobs().is_empty());
    let (s, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"][0]["markdown"], "# durable");
    // the in-memory backend cannot presign, so large content still links to the api
    let big = "y".repeat(200);
    write_page(&r, run, 2, &big).await;
    let (_, _, v) = r.env.get(&format!("/v1/crawls/{id}/pages")).await;
    let link = v["data"][1]["metadata"]["crawlx"]["markdownRef"]
        .as_str()
        .unwrap();
    assert!(link.starts_with(&format!("/v1/crawls/{id}/artifacts/")), "{link}");
}

/// The in-memory store with a presigning backend bolted on: every `content` artifact gets a
/// fake object-store URL carrying the requested TTL.
struct Presigning(Arc<crawlx_storage::MemoryArtifactStore>);

#[async_trait]
impl crawlx_api::store::ArtifactSource for Presigning {
    async fn row(
        &self,
        id: crawlx_core::ArtifactId,
    ) -> Result<Option<crawlx_storage::ArtifactRow>, crawlx_core::StoreError> {
        self.0.row(id).await
    }
    async fn read(&self, artifact: &crawlx_core::ArtifactRef) -> Result<Vec<u8>, crawlx_core::StoreError> {
        self.0.get(artifact).await
    }
    async fn put_evidence(
        &self,
        run: CrawlRunId,
        bytes: &[u8],
    ) -> Result<crawlx_core::ArtifactRef, crawlx_core::StoreError> {
        self.0
            .put_kind(
                run,
                Sensitivity::Sensitive,
                "evidence",
                "text/plain; charset=utf-8",
                bytes,
            )
            .await
    }
    async fn put_login_flow(
        &self,
        run: CrawlRunId,
        bytes: &crawlx_core::secret::Redacted<Vec<u8>>,
        deadline: crawlx_core::Timestamp,
    ) -> Result<crawlx_core::ArtifactRef, crawlx_core::StoreError> {
        crawlx_api::ArtifactSource::put_login_flow(self.0.as_ref(), run, bytes, deadline).await
    }
    async fn purge_run(&self, run: CrawlRunId) -> Result<u64, crawlx_core::StoreError> {
        crawlx_storage::ArtifactReaper::purge_run(self.0.as_ref(), run).await
    }
    async fn presign(
        &self,
        artifact: &crawlx_core::ArtifactRef,
        ttl: std::time::Duration,
    ) -> Result<Option<url::Url>, crawlx_core::StoreError> {
        let row = self
            .0
            .row(artifact.id)
            .await?
            .ok_or(crawlx_core::StoreError::NotFound {
                entity: "artifact",
                id: artifact.id.to_string(),
            })?;
        if row.sensitivity != Sensitivity::Content {
            return Err(crawlx_core::StoreError::AccessDenied("not content".to_owned()));
        }
        Ok(Some(
            url::Url::parse(&format!(
                "https://bucket.example.test/{}?X-Amz-Expires={}",
                row.object_key,
                ttl.as_secs()
            ))
            .unwrap(),
        ))
    }
}

#[tokio::test]
async fn content_artifacts_redirect_to_a_presigned_url_when_the_store_offers_one() {
    use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
    use crawlx_api::{AppState, Repos, Scope};
    use crawlx_policy::AdmissionPolicy;
    use crawlx_storage::{MemoryArtifactStore, MemoryStore};
    use tower::ServiceExt as _;

    let clock: Arc<dyn Clock> = Arc::new(crawlx_core::SystemClock);
    let store = Arc::new(MemoryStore::new());
    let inner = Arc::new(MemoryArtifactStore::in_memory(store.clone(), clock.clone()));
    let (repos, api) = Repos::memory_with_api(store.clone(), Arc::new(Presigning(inner.clone())));
    let cfg = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let settings = Settings {
        inline_max_bytes: 8,
        ..Settings::default()
    };
    let state = AppState::builder(repos, AdmissionPolicy::new(clock.clone()), cfg)
        .settings(settings)
        .clock(clock.clone())
        .build();
    let app = crawlx_api::router(state);
    let key = generate_key();
    let rec = key_record(&key, tenant_id_for("acme"), Scope::all_set()).unwrap();
    crawlx_api::ApiStore::key_insert(api.as_ref(), &rec, "acme")
        .await
        .unwrap();
    let call = |uri: String| {
        let app = app.clone();
        let key = key.clone();
        async move {
            let req = axum::http::Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("authorization", format!("Bearer {key}"))
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let (parts, body) = resp.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
            (parts.status, parts.headers, bytes)
        }
    };
    let create = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/v1/crawls")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(common::simple_body().to_string()))
        .unwrap();
    let resp = app.clone().oneshot(create).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let created = json(&axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap());
    let id = created["id"].as_str().unwrap().to_owned();
    let run: CrawlRunId = id.parse().unwrap();

    let content = inner
        .put(run, Sensitivity::Content, "text/markdown", b"# twelve bytes")
        .await
        .unwrap();
    let sensitive = inner
        .put(run, Sensitivity::Sensitive, "image/webp", b"shot")
        .await
        .unwrap();
    store
        .put(&PageRecord {
            run,
            frontier_id: 1,
            url: testkit::canonical_url("https://app.example.test/p/1"),
            status: 200,
            content_type: Some("text/html".to_owned()),
            content_digest: Digest::of("t", b"1"),
            title: None,
            markdown: Some(content.clone()),
            html: None,
            metadata: j!({}),
            links: vec![],
            fetched_at: clock.now(),
            lane: TrustLane::Diagnostic,
        })
        .await
        .unwrap();
    let expected = format!(
        "https://bucket.example.test/content/{}/{run}/{}?X-Amz-Expires=60",
        tenant_id_for("acme"),
        content.digest.to_hex()
    );

    // the artifact endpoint answers 307 to the presigned URL for content ...
    let (s, h, _) = call(format!("/v1/crawls/{id}/artifacts/{}", content.id)).await;
    assert_eq!(s, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(h["location"], expected.as_str());
    assert_eq!(h["cache-control"], "private, no-store");
    // ... but `?view=metadata` and sensitive artifacts are never redirected
    let (s, _, b) = call(format!("/v1/crawls/{id}/artifacts/{}?view=metadata", content.id)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json(&b)["sensitivity"], "content");
    let (s, h, b) = call(format!("/v1/crawls/{id}/artifacts/{}", sensitive.id)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["x-crawlx-sensitivity"], "sensitive");
    assert_eq!(b.as_ref(), b"shot");
    // `/pages` links content above the inline cap through the presigned URL
    let (s, _, b) = call(format!("/v1/crawls/{id}/pages")).await;
    assert_eq!(s, StatusCode::OK);
    let v = json(&b);
    assert_eq!(v["data"][0]["markdown"], Value::Null);
    assert_eq!(
        v["data"][0]["metadata"]["crawlx"]["markdownRef"],
        expected.as_str()
    );
}

#[tokio::test]
async fn virtual_rows_use_separate_zdr_rendition_and_expire_from_actual_api_consumer() {
    use crawlx_core::scrape::{ActionResults, BlobRef, ScrapeDocument};
    use crawlx_core::secret::{ArtifactSink, Redactor};
    let r = rig();
    let id = r
        .env
        .create_run(&j!({
            "seedUrl":"https://app.example.test/","seed":3,"retention":{"mode":"zdr"},
            "scrape":{"kind":"crawl","options":{"formats":[{"type":"markdown"}],"actions":[{
                "type":"collectVirtualRows","spec":{
                    "container":"#virtual","rows":".row","maxSteps":1,"settleMs":50,
                    "maxRowsPerWindow":10,"maxRows":100,"maxBytes":65536
                }
            }]}}
        }))
        .await;
    let run: CrawlRunId = id.parse().unwrap();
    let mut record = write_page(&r, run, 1, "Final canonical text only.").await;
    let report: crawlx_core::dom_ops::VirtualRowsReport = serde_json::from_value(j!({
        "windows":[{
            "epoch":{"navigation_seq":1,"document_seq":1,"mutation_seq":10},
            "rows":["historic-only ZDR row","C++","C#","東京"],
            "bottom":false,"capped":false,"scrollStep":99,"transportBytes":1024
        }],
        "steps":0,"stop":"step_cap","restoration":"restored","maxBytes":65536
    }))
    .unwrap();
    let encoded = serde_json::to_vec(&report).unwrap();
    let approved = Redactor::new().verify_canonical_owned(encoded.clone()).unwrap();
    let mime = "application/vnd.crawlx.virtual-rows+json";
    let artifact = ArtifactSink::over(r.env.artifacts.as_ref())
        .put_dataset(run, 1, "virtual_rows_0", mime, &approved)
        .await
        .unwrap();
    let mut document = ScrapeDocument::new(
        record.url.to_string(),
        record.url.to_string(),
        200,
        Digest::of("test", b"options"),
    );
    document.actions = Some(ActionResults {
        virtual_rows: vec![BlobRef {
            artifact,
            content_type: mime.into(),
            size: u64::try_from(encoded.len()).unwrap(),
        }],
        ..ActionResults::default()
    });
    record.metadata["scrape"] = serde_json::to_value(document).unwrap();
    r.env.store.put(&record).await.unwrap();
    assert!(
        r.env.artifacts.blobs().is_empty(),
        "ZDR rows must never enter durable object storage"
    );
    let persisted = PageRepo::list(r.env.store.as_ref(), run).await.unwrap();
    let structural = serde_json::to_string(&persisted).unwrap();
    assert!(!structural.contains("historic-only ZDR row"));
    assert!(!structural.contains("C++"));
    let (status, _, body) = r.env.get(&format!("/compat/v2/crawl/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entry = &body["data"][0]["actions"]["virtualRows"][0];
    assert_eq!(
        entry["rendition"],
        Value::Null,
        "inline limit must not truncate JSON"
    );
    let link = entry["url"].as_str().expect("authorized volatile artifact link");
    let (status, headers, body) = r.env.send(Method::GET, link, Some(&r.env.key), &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-crawlx-sensitivity"], "content");
    assert_eq!(body.as_ref(), encoded.as_slice());
    assert!(r.zdr.ack(r.env.tenant, run, 1).await.unwrap());
    let (status, _, _) = r.env.send(Method::GET, link, Some(&r.env.key), &[], None).await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "ack must remove the virtual rendition with its page"
    );
}
