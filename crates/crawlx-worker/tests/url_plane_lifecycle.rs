//! End-to-end URL-plane lifecycle: ordered boundaries, header abort before any body byte,
//! single terminal outcome, replay validation, cancellation and recipe route matching.
//!
//! Every test serves its own local fixture site; nothing leaves the host.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use crawlx_core::{
    config::{CrawlMode, RetentionMode, SitemapMode},
    extension_recipes::{DiscoveryRuleV1, ExtensionRecipeV1, RecipeSourceV1},
    extensions::{
        validate_extension_receipts, ExtensionConfigV1, ExtensionEventLimitsV1, ExtensionPipelineV1,
        ExtensionReceiptV1, ExtensionSpecV1, ExtensionStageV1, HandlerV1, HeaderPolicyV1,
    },
    repo::FrontierStatus,
    CreateCrawl,
};
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Hits {
    paths: Mutex<Vec<String>>,
    streamed_chunks: AtomicUsize,
}

struct Site {
    base: String,
    hits: Arc<Hits>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn count(&self, path: &str) -> usize {
        self.hits
            .paths
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.as_str() == path)
            .count()
    }
}

async fn record(
    State(hits): State<Arc<Hits>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.paths.lock().unwrap().push(request.uri().path().into());
    next.run(request).await
}

fn page(links: &str) -> axum::response::Response {
    (
        [(header::CONTENT_TYPE, "text/html")],
        format!(
            "<html><head><title>Lifecycle fixture</title></head><body><main><h1>Lifecycle fixture</h1><p>{}</p>{links}</main></body></html>",
            "Public records provide independent facts and careful reporting about local events. ".repeat(24),
        ),
    )
        .into_response()
}

/// A body that keeps producing chunks for as long as the client keeps reading it.
fn endless(hits: Arc<Hits>) -> axum::response::Response {
    let stream = futures::stream::unfold(hits, |hits| async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        hits.streamed_chunks.fetch_add(1, Ordering::SeqCst);
        Some((
            Ok::<_, std::convert::Infallible>(bytes::Bytes::from_static(b"<p>chunk</p>")),
            hits,
        ))
    });
    (
        [(header::CONTENT_TYPE, "text/html")],
        axum::body::Body::from_stream(stream),
    )
        .into_response()
}

async fn site() -> Site {
    let hits = Arc::new(Hits::default());
    let stream_hits = Arc::clone(&hits);
    let app = Router::new()
        .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
        .route(
            "/",
            get(|| async { page(r#"<a href="/a">a</a><a href="/b">b</a><a href="/blocked">blocked</a>"#) }),
        )
        .route("/plain", get(|| async { page("") }))
        .route("/a", get(|| async { page("") }))
        .route("/b", get(|| async { page("") }))
        .route("/blocked", get(|| async { page("") }))
        .route(
            "/stream",
            get(move || {
                let hits = Arc::clone(&stream_hits);
                async move { endless(hits) }
            }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                page("")
            }),
        )
        .with_state(Arc::clone(&hits))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Site { base, hits, task }
}

fn crawl(site: &Site, seed: &str) -> CreateCrawl {
    let mut crawl = CreateCrawl::new(format!("{}{seed}", site.base).parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_112);
    crawl.retention.mode = RetentionMode::Standard;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files.clear();
    crawl
}

fn annotate(stage: ExtensionStageV1, code: &str, order: i32) -> ExtensionSpecV1 {
    ExtensionSpecV1::new(
        ExtensionConfigV1::Annotate {
            stage,
            code: code.into(),
        },
        order,
    )
}

struct Outcome {
    stores: Stores,
    report: RunReport,
}

async fn run(crawl: CreateCrawl, cancel: Option<CancellationToken>) -> Outcome {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_owned(),
        egress: EgressConfig {
            resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let mut local = LocalRun::new(crawl, config).with_stores(stores.clone());
    if let Some(cancel) = cancel {
        local = local.with_cancel(cancel);
    }
    let report = common::authorization::run_authorized_local_with(local)
        .await
        .unwrap();
    Outcome { stores, report }
}

/// The persisted attempt receipts of the request fetched from `path`.
async fn receipts_of(outcome: &Outcome, path: &str) -> Vec<Vec<ExtensionReceiptV1>> {
    let rows = outcome.stores.frontier.list(outcome.report.run_id).await.unwrap();
    let row = rows.iter().find(|row| row.url.url.path() == path).unwrap();
    outcome
        .stores
        .events
        .list_after(outcome.report.run_id, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "extension_attempt" && event.payload["requestId"] == row.id)
        .map(|event| serde_json::from_value(event.payload["receipts"].clone()).unwrap())
        .collect()
}

fn kinds(trail: &[ExtensionReceiptV1]) -> Vec<String> {
    trail
        .iter()
        .map(|receipt| {
            serde_json::to_value(&receipt.event).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn position(kinds: &[String], kind: &str) -> usize {
    kinds
        .iter()
        .position(|candidate| candidate == kind)
        .unwrap_or_else(|| panic!("{kind} missing in {kinds:?}"))
}

#[tokio::test]
async fn a_fetched_page_executes_boundaries_in_order_with_one_terminal_and_replays() {
    let site = site().await;
    let mut crawl = crawl(&site, "/plain");
    // The parse-stage extension needs the explicit article envelope.
    crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
    crawl.extensions.extensions = vec![
        annotate(ExtensionStageV1::HeadersReceived, "headers", 0),
        annotate(ExtensionStageV1::Response, "response", 0),
        annotate(ExtensionStageV1::Html, "html", 0),
        annotate(ExtensionStageV1::Parse, "parse", 0),
    ];
    let pipeline = crawl.extensions.clone();
    let outcome = run(crawl, None).await;
    let trails = receipts_of(&outcome, "/plain").await;
    assert_eq!(trails.len(), 1, "one attempt, one persisted trail");
    let trail = &trails[0];
    let order = kinds(trail);
    assert_eq!(order.first().map(String::as_str), Some("configure"));
    assert!(position(&order, "request_proposed") < position(&order, "before_acquisition"));
    assert!(position(&order, "before_acquisition") < position(&order, "headers_received"));
    assert!(position(&order, "headers_received") < position(&order, "response"));
    assert!(position(&order, "response") < position(&order, "html"));
    assert!(position(&order, "html") < position(&order, "parse"));
    assert!(position(&order, "parse") < position(&order, "terminal"));
    assert_eq!(&order[order.len() - 3..], ["terminal", "checkpoint", "close"]);
    assert_eq!(order.iter().filter(|kind| kind.as_str() == "terminal").count(), 1);
    let terminal = trail
        .iter()
        .find(|r| serde_json::to_value(&r.event).unwrap()["kind"] == "terminal")
        .unwrap();
    assert_eq!(
        serde_json::to_value(&terminal.event).unwrap()["facts"]["kind"],
        "completed"
    );
    // Replay: the committed trail re-executes to identical receipts; any edit is refused.
    validate_extension_receipts(trail).unwrap();
    crawlx_worker::extensions::RequestLifecycle::validate_replay(
        &pipeline,
        ExtensionEventLimitsV1::default(),
        trail,
    )
    .unwrap();
    let mut tampered = trail.clone();
    tampered.remove(2);
    assert!(validate_extension_receipts(&tampered).is_err());
    let rows = outcome.stores.frontier.list(outcome.report.run_id).await.unwrap();
    assert_eq!(
        rows.iter()
            .find(|row| row.url.url.path() == "/plain")
            .unwrap()
            .status,
        FrontierStatus::Succeeded
    );
}

#[tokio::test]
async fn a_header_policy_abort_stops_before_the_body_and_records_one_skipped_terminal() {
    let site = site().await;
    let mut crawl = crawl(&site, "/stream");
    let mut policy = HeaderPolicyV1::default();
    policy.content_types = ["application/json".to_owned()].into();
    crawl.extensions.extensions = vec![ExtensionSpecV1::new(
        ExtensionConfigV1::HeaderPolicy { policy },
        0,
    )];
    let outcome = run(crawl, None).await;
    let rows = outcome.stores.frontier.list(outcome.report.run_id).await.unwrap();
    let row = rows.iter().find(|row| row.url.url.path() == "/stream").unwrap();
    assert_eq!(row.status, FrontierStatus::Failed);
    assert_eq!(row.denial_reason.as_deref(), Some("extension_header_skipped"));
    assert!(
        outcome.report.pages.is_empty(),
        "no page is fabricated from an aborted response"
    );
    // The endless server stops being read at the header stage: a polled body would keep growing.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        site.hits.streamed_chunks.load(Ordering::SeqCst) <= 2,
        "body bytes were polled after abort"
    );
    let trails = receipts_of(&outcome, "/stream").await;
    assert_eq!(trails.len(), 1);
    let order = kinds(&trails[0]);
    assert!(order.contains(&"headers_received".to_owned()));
    assert!(
        !order.contains(&"response".to_owned()),
        "no response boundary after a header abort"
    );
    assert_eq!(order.iter().filter(|kind| kind.as_str() == "terminal").count(), 1);
    let terminal = trails[0]
        .iter()
        .find(|r| serde_json::to_value(&r.event).unwrap()["kind"] == "terminal")
        .unwrap();
    assert_eq!(
        serde_json::to_value(&terminal.event).unwrap()["facts"]["kind"],
        "skipped"
    );
    validate_extension_receipts(&trails[0]).unwrap();
}

#[tokio::test]
async fn a_failing_compiled_stage_fails_the_row_and_can_never_become_success() {
    let site = site().await;
    let mut crawl = crawl(&site, "/plain");
    crawl.extensions.extensions = vec![ExtensionSpecV1::new(
        ExtensionConfigV1::FailStage {
            stage: ExtensionStageV1::Response,
        },
        0,
    )];
    let outcome = run(crawl, None).await;
    let rows = outcome.stores.frontier.list(outcome.report.run_id).await.unwrap();
    let row = rows.iter().find(|row| row.url.url.path() == "/plain").unwrap();
    assert_eq!(row.status, FrontierStatus::Failed);
    assert!(outcome.report.pages.is_empty());
    let trails = receipts_of(&outcome, "/plain").await;
    assert_eq!(trails.len(), 1);
    let order = kinds(&trails[0]);
    assert!(position(&order, "response") < position(&order, "error"));
    assert!(position(&order, "error") < position(&order, "terminal"));
    assert_eq!(order.iter().filter(|kind| kind.as_str() == "terminal").count(), 1);
    validate_extension_receipts(&trails[0]).unwrap();
}

#[tokio::test]
async fn cancelling_mid_acquisition_abandons_the_row_and_commits_one_cancelled_terminal() {
    let site = site().await;
    let mut crawl = crawl(&site, "/slow");
    crawl.extensions.extensions = vec![annotate(ExtensionStageV1::Response, "response", 0)];
    let cancel = CancellationToken::new();
    let stopper = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        stopper.cancel();
    });
    let started = std::time::Instant::now();
    let outcome = run(crawl, Some(cancel)).await;
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "cancellation interrupted the 30 s response"
    );
    assert!(outcome.report.pages.is_empty());
    for trail in receipts_of(&outcome, "/slow").await {
        let order = kinds(&trail);
        assert!(
            !order.contains(&"response".to_owned()),
            "no response boundary ever ran"
        );
        assert_eq!(order.iter().filter(|kind| kind.as_str() == "terminal").count(), 1);
        let terminal = trail
            .iter()
            .find(|r| serde_json::to_value(&r.event).unwrap()["kind"] == "terminal")
            .unwrap();
        let facts = serde_json::to_value(&terminal.event).unwrap()["facts"].clone();
        assert_eq!(
            (facts["kind"].as_str(), facts["reason"].as_str()),
            (Some("skipped"), Some("cancelled"))
        );
        validate_extension_receipts(&trail).unwrap();
    }
}

#[tokio::test]
async fn recipe_rules_choose_exact_routes_and_a_hard_deny_beats_every_allow() {
    let site = site().await;
    let mut crawl = crawl(&site, "/");
    // Document-item routes need the explicit article envelope.
    crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
    let mut recipe = ExtensionRecipeV1::new("lifecycle-recipe".into(), 1);
    recipe.pipeline = ExtensionPipelineV1::default();
    recipe
        .pipeline
        .routes
        .insert("article".into(), HandlerV1::DocumentItem);
    recipe
        .pipeline
        .routes
        .insert("catchall".into(), HandlerV1::DocumentItem);
    let mut article = DiscoveryRuleV1::new(RecipeSourceV1::Html, "article".into());
    article.allow.push("/a$".into());
    let mut catchall = DiscoveryRuleV1::new(RecipeSourceV1::Html, "catchall".into());
    catchall.allow.push("/blocked$".into());
    catchall.deny.push("/blocked$".into());
    recipe.rules = vec![article, catchall];
    crawl.extension_recipe = Some(recipe);
    let outcome = run(crawl, None).await;
    assert_eq!(site.count("/a"), 1, "the selected link is fetched once");
    assert_eq!(site.count("/b"), 0, "a link no rule selects is not enqueued");
    assert_eq!(
        site.count("/blocked"),
        0,
        "a hard deny wins over a matching allow"
    );
    let rows = outcome.stores.frontier.list(outcome.report.run_id).await.unwrap();
    let row = rows.iter().find(|row| row.url.url.path() == "/a").unwrap();
    let queued = outcome
        .stores
        .frontier
        .get_request(outcome.report.run_id, row.id)
        .await
        .unwrap();
    assert_eq!(
        queued.envelope.route, "article",
        "the rule's exact route survives admission"
    );
    assert!(rows.iter().all(|row| row.url.url.path() != "/b"));
}
