//! The opt-in `modelV1` content strategy through real runs: request options -> scrape engine ->
//! bounded model strategy -> `modelContent` / markdown sink. The provider is a real loopback HTTP
//! fixture (wiremock) behind `ChatCompletionsClient`; there is no estimated mock usage and no
//! network beyond 127.0.0.1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, RetentionMode, SitemapMode};
use crawlx_core::scrape::{
    ContentStrategySpecV1, ContentStrategyTargetV1, JobKind, ScrapeDocument, ScrapeJob, ScrapeOptions,
};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_model::llm::{ChatCompletionsClient, LlmConfig, LlmExtractor, MockLlm};
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PAGE: &str = r#"<!doctype html><html lang="en"><head><title>Acme</title></head>
<body><main><h1>Acme pricing</h1><p>Native paragraph.</p>
<table><tr><th>Plan</th><th>Price</th></tr><tr><td>Basic</td><td>10</td></tr></table></main></body></html>"#;

const MAX_TOKENS: u32 = 256;
const MAX_BYTES: usize = 64 * 1024;

struct Site {
    base: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn site() -> Site {
    let app = Router::new().route(
        "/page",
        get(|| async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, task }
}

fn model_v1(target: ContentStrategyTargetV1) -> ContentStrategySpecV1 {
    ContentStrategySpecV1::ModelV1 {
        target,
        max_output_tokens: MAX_TOKENS,
        max_response_bytes: MAX_BYTES,
        external_processing_consent: true,
    }
}

fn model_content() -> Value {
    json!({
        "version": 1,
        "markdown": "Generated selection of the page.",
        "tables": [{"headers": ["Plan", "Price"], "rows": [["Basic", "10"]], "ambiguous": false}]
    })
}

fn tables_only() -> Value {
    json!({
        "version": 1,
        "markdown": "",
        "tables": [{"headers": ["Plan", "Price"], "rows": [["Basic", "10"]], "ambiguous": false}]
    })
}

fn envelope(value: &Value) -> Value {
    json!({
        "choices": [{"finish_reason": "stop", "message": {"content": value.to_string()}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18}
    })
}

/// A loopback provider that must receive exactly `calls` requests, each bounded to
/// `MAX_TOKENS` completion tokens and never streamed.
async fn provider(response: ResponseTemplate, calls: u64) -> (MockServer, Arc<dyn LlmExtractor>) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({"max_tokens": MAX_TOKENS, "stream": false}),
        ))
        .respond_with(response)
        .expect(calls)
        .mount(&server)
        .await;
    let client = ChatCompletionsClient::new(LlmConfig::new(&server.uri(), "fixture-model")).unwrap();
    (server, Arc::new(client))
}

struct Done {
    report: RunReport,
    stores: Stores,
    _dir: tempfile::TempDir,
}

impl Done {
    fn doc(&self) -> ScrapeDocument {
        let page = self
            .report
            .pages
            .iter()
            .find(|p| p.url.url.path() == "/page")
            .expect("the page was stored");
        ScrapeDocument::from_page_metadata(&page.metadata).expect("a scrape document")
    }

    async fn markdown(&self) -> String {
        let page = self.report.pages.first().expect("the page was stored");
        let artifact = page.markdown.as_ref().expect("markdown artifact");
        String::from_utf8(self.stores.artifacts.get(artifact).await.unwrap()).unwrap()
    }

    fn failed_with(&self, reason: &str) -> bool {
        self.report.pages.is_empty() && self.report.failures.iter().any(|f| f.reason == reason)
    }
}

async fn run(
    site: &Site,
    strategy: Option<ContentStrategySpecV1>,
    zdr: bool,
    llm: Option<Arc<dyn LlmExtractor>>,
    cancel: Option<tokio_util::sync::CancellationToken>,
) -> Done {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let options = ScrapeOptions {
        content_strategy: strategy,
        ..ScrapeOptions::default()
    };
    let mut crawl = CreateCrawl::new(Url::parse(&format!("{}/page", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_028);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.max_discovery_depth = 0;
    if zdr {
        crawl.retention.mode = RetentionMode::Zdr;
    }
    crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        llm,
        ..WorkerConfig::default()
    };
    let mut local = LocalRun::new(crawl, config).with_stores(stores.clone());
    if let Some(cancel) = cancel {
        local.cancel = cancel;
    }
    let report = run_local_with(local).await.unwrap();
    Done {
        report,
        stores,
        _dir: dir,
    }
}

#[tokio::test]
async fn model_strategy_reaches_the_bounded_loopback_provider_and_the_sinks() {
    let site = site().await;
    let (_server, llm) = provider(
        ResponseTemplate::new(200).set_body_json(envelope(&model_content())),
        1,
    )
    .await;
    let done = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::TablesAndContent)),
        false,
        Some(llm),
        None,
    )
    .await;
    let doc = done.doc();
    assert_eq!(doc.model_content, Some(model_content()));
    assert_eq!(done.markdown().await, "Generated selection of the page.");
    assert_eq!(
        doc.llm_tokens, 18,
        "prompt + completion tokens of the real provider usage"
    );
    assert!(
        doc.outputs.is_none(),
        "generated content never becomes native outputs"
    );
}

#[tokio::test]
async fn tables_target_keeps_native_markdown_and_sidecars_only_the_tables() {
    let site = site().await;
    let (_server, llm) = provider(
        ResponseTemplate::new(200).set_body_json(envelope(&tables_only())),
        1,
    )
    .await;
    let done = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::Tables)),
        false,
        Some(llm),
        None,
    )
    .await;
    assert_eq!(done.doc().model_content, Some(tables_only()));
    let markdown = done.markdown().await;
    assert!(
        markdown.contains("Acme pricing"),
        "native markdown untouched: {markdown}"
    );
    assert!(!markdown.contains("Generated"), "{markdown}");
}

#[tokio::test]
async fn native_strategy_never_calls_a_provider_and_matches_no_provider_output() {
    let site = site().await;
    let baseline = run(&site, None, false, None, None).await;
    let baseline_markdown = baseline.markdown().await;
    for strategy in [None, Some(ContentStrategySpecV1::NativeV1)] {
        let (server, llm) = provider(
            ResponseTemplate::new(200).set_body_json(envelope(&model_content())),
            0,
        )
        .await;
        let done = run(&site, strategy, false, Some(llm), None).await;
        let doc = done.doc();
        assert!(doc.model_content.is_none());
        assert_eq!(doc.llm_tokens, 0);
        assert_eq!(
            done.markdown().await,
            baseline_markdown,
            "bit-for-bit native markdown"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn zero_data_retention_rejects_before_any_model_or_target_io() {
    let site = site().await;
    let (server, llm) = provider(
        ResponseTemplate::new(200).set_body_json(envelope(&model_content())),
        0,
    )
    .await;
    let done = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::Content)),
        true,
        Some(llm),
        None,
    )
    .await;
    assert!(done.failed_with("llm_failed"), "{:?}", done.report.failures);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_provider_error_fails_the_page_without_retry_or_native_fallback() {
    let site = site().await;
    let (_server, llm) = provider(ResponseTemplate::new(503), 1).await;
    let done = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::Content)),
        false,
        Some(llm),
        None,
    )
    .await;
    assert!(done.failed_with("llm_failed"), "{:?}", done.report.failures);
}

#[tokio::test]
async fn an_invalid_model_response_fails_the_page_instead_of_degrading() {
    let site = site().await;
    let invalid = json!({"version": 2, "markdown": "x", "tables": []});
    let (_server, llm) = provider(ResponseTemplate::new(200).set_body_json(envelope(&invalid)), 1).await;
    let done = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::Content)),
        false,
        Some(llm),
        None,
    )
    .await;
    assert!(done.failed_with("llm_failed"), "{:?}", done.report.failures);
}

#[tokio::test]
async fn an_unconfigured_or_unbounded_provider_is_an_explicit_failure() {
    let site = site().await;
    let none = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::Content)),
        false,
        None,
        None,
    )
    .await;
    assert!(
        none.failed_with("llm_not_configured"),
        "{:?}",
        none.report.failures
    );

    // A provider without the bounded primitive is refused; it is never downgraded to `complete`.
    let unbounded = Arc::new(MockLlm::from_fn(|_| panic!("must not be called")));
    let done = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::Content)),
        false,
        Some(Arc::clone(&unbounded) as Arc<dyn LlmExtractor>),
        None,
    )
    .await;
    assert!(done.failed_with("llm_failed"), "{:?}", done.report.failures);
    assert!(unbounded.calls().is_empty());
}

#[tokio::test]
async fn cancellation_stops_the_in_flight_model_call_and_abandons_the_page() {
    let site = site().await;
    let (server, llm) = provider(
        ResponseTemplate::new(200)
            .set_body_json(envelope(&model_content()))
            .set_delay(Duration::from_secs(30)),
        1,
    )
    .await;
    let cancel = tokio_util::sync::CancellationToken::new();
    let trigger = cancel.clone();
    let watcher = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(20), async {
            while server.received_requests().await.unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            trigger.cancel();
        })
        .await
        .unwrap();
        server
    });
    let started = tokio::time::Instant::now();
    let done = run(
        &site,
        Some(model_v1(ContentStrategyTargetV1::Content)),
        false,
        Some(llm),
        Some(cancel),
    )
    .await;
    let _server = watcher.await.unwrap();
    assert!(done.report.pages.is_empty(), "no document survives cancellation");
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "cancellation did not wait for the delayed provider"
    );
}
