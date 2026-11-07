//! The self-host provider overrides of the scrape formats ("LLM providers"), through
//! real runs: `BRANDING_LLM_*` refines the markup-derived `branding` profile (success, and the
//! fallback with a warning), and `EXTRACTION_PROVIDER_*` answers the `json` format from a second
//! endpoint while `summary` keeps the default model. In-memory stores, a fixture HTTP site on
//! 127.0.0.1 and scripted LLMs: no network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, RetentionMode, SitemapMode};
use crawlx_core::scrape::{FormatSpec, JobKind, ScrapeDocument, ScrapeJob, ScrapeOptions};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_model::llm::{ExtractionPolicy, ExtractionRouter, LlmError, LlmExtractor, MockLlm};
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use url::Url;

const PAGE: &str = r#"<!doctype html><html lang="en"><head><title>Acme</title>
<link rel="stylesheet" href="/site.css"></head>
<body><main><h1>Acme pricing</h1><p>price: 10</p></main></body></html>"#;

const SITE_CSS: &str =
    ":root{--primary:#ff5500;--bg:#fafafa} body{font-family:'Inter',sans-serif;color:#111111;background:#fafafa}";

struct Site {
    base: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start() -> Site {
    let app = Router::new()
        .route(
            "/page",
            get(|| async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE).into_response() }),
        )
        .route(
            "/site.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], SITE_CSS).into_response() }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Site { base, task }
}

fn mock(f: impl Fn(&str) -> Result<Value, LlmError> + Send + Sync + 'static) -> Arc<MockLlm> {
    Arc::new(MockLlm::from_fn(move |call| f(&call.user)))
}

/// A run of one scrape of `/page` with `formats`; `cfg` customises the worker.
async fn scrape(
    site: &Site,
    formats: Vec<FormatSpec>,
    zdr: bool,
    cfg: impl FnOnce(&mut WorkerConfig),
) -> ScrapeDocument {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let options = ScrapeOptions {
        formats,
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
    let mut config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    cfg(&mut config);
    let report = run_local_with(LocalRun::new(crawl, config).with_stores(stores))
        .await
        .unwrap();
    let page = report
        .pages
        .iter()
        .find(|p| p.url.url.path() == "/page")
        .expect("the page was stored");
    ScrapeDocument::from_page_metadata(&page.metadata).expect("a scrape document")
}

// ---- BRANDING_LLM_* ----------------------------------------------------------------------------

fn refinement() -> Value {
    json!({
        "colorScheme": "dark",
        "colors": {"primary": "#0a84ff", "accent": "#FFAA00"},
        "fonts": [{"family": "Inter", "role": "body"}],
        "personality": {"tone": "bold", "targetAudience": "developers"},
    })
}

#[tokio::test]
async fn the_branding_llm_refines_the_markup_profile() {
    let site = start().await;
    let heuristic = scrape(&site, vec![FormatSpec::Branding], false, |_| {}).await;
    let heuristic = heuristic.branding.unwrap();
    assert_eq!(
        heuristic["colors"]["primary"], "#FF5500",
        "the markup profile: {heuristic}"
    );
    assert!(heuristic.get("fonts").is_some());

    let llm = mock(|_| Ok(refinement()));
    let doc = scrape(&site, vec![FormatSpec::Branding], false, |c| {
        c.branding_llm = Some(llm.clone() as Arc<dyn LlmExtractor>);
    })
    .await;
    let branding = doc.branding.unwrap();
    assert_eq!(
        branding["colors"]["primary"], "#0A84FF",
        "the refinement wins: {branding}"
    );
    assert_eq!(branding["colors"]["accent"], "#FFAA00");
    assert_eq!(
        branding["colors"]["background"], heuristic["colors"]["background"],
        "fields the model did not name keep the markup value"
    );
    assert_eq!(branding["colorScheme"], "dark");
    assert_eq!(branding["fonts"], json!([{"family": "Inter", "role": "body"}]));
    assert_eq!(branding["personality"]["tone"], "bold");
    assert_eq!(branding["personality"]["targetAudience"], "developers");
    assert_eq!(branding["logo"], heuristic["logo"]);
    assert!(doc.warning.is_none(), "{:?}", doc.warning);
    assert!(doc.llm_tokens > 0, "the refinement call is metered");

    let calls = llm.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].user.contains("--primary:#ff5500"),
        "the stylesheet excerpt reaches the model: {}",
        calls[0].user
    );
    assert!(calls[0].user.contains("\"colors\""), "so does the markup profile");
    assert!(
        calls[0].schema.is_some(),
        "a structured-output schema is requested"
    );
}

#[tokio::test]
async fn a_failing_branding_llm_keeps_the_markup_profile_and_warns() {
    let site = start().await;
    let heuristic = scrape(&site, vec![FormatSpec::Branding], false, |_| {})
        .await
        .branding
        .unwrap();
    for failing in [
        Err(LlmError::Status { status: 503 }),
        Err(LlmError::Timeout { after_ms: 5_000 }),
        Ok(json!({"colors": {"primary": "not-a-colour"}})),
        Ok(json!(["not", "an", "object"])),
    ] {
        let llm = mock(move |_| failing.clone());
        let doc = scrape(&site, vec![FormatSpec::Branding], false, |c| {
            c.branding_llm = Some(llm.clone() as Arc<dyn LlmExtractor>);
        })
        .await;
        assert_eq!(doc.branding.unwrap(), heuristic, "the markup profile survives");
        let warning = doc.warning.expect("a warning");
        assert!(warning.contains("branding_llm_skipped"), "{warning}");
        assert_eq!(llm.calls().len(), 1, "one attempt, no retry");
    }
}

#[tokio::test]
async fn without_a_branding_llm_nothing_is_sent_and_nothing_warns() {
    let site = start().await;
    let llm = mock(|_| Ok(refinement()));
    // the default LLM is configured, but branding has its own setting
    let doc = scrape(&site, vec![FormatSpec::Branding], false, |c| {
        c.llm = Some(llm.clone() as Arc<dyn LlmExtractor>);
    })
    .await;
    assert_eq!(doc.branding.unwrap()["colors"]["primary"], "#FF5500");
    assert!(doc.warning.is_none() && doc.llm_tokens == 0);
    assert!(llm.calls().is_empty());
}

#[tokio::test]
async fn zero_data_retention_runs_never_send_page_data_to_the_branding_llm() {
    let site = start().await;
    let llm = mock(|_| Ok(refinement()));
    let doc = scrape(&site, vec![FormatSpec::Branding], true, |c| {
        c.branding_llm = Some(llm.clone() as Arc<dyn LlmExtractor>);
    })
    .await;
    assert_eq!(doc.branding.unwrap()["colors"]["primary"], "#FF5500");
    assert!(llm.calls().is_empty(), "nothing left the process");
    assert!(doc.warning.unwrap().contains("zero data retention"));
}

// ---- EXTRACTION_PROVIDER_* ---------------------------------------------------------------------

fn by_task(label: &'static str) -> Arc<MockLlm> {
    mock(move |user| {
        if user.contains("Summarize the page") {
            Ok(json!({"summary": format!("summary by {label}")}))
        } else {
            Ok(json!({"answered_by": label}))
        }
    })
}

fn router(default: &Arc<MockLlm>, provider: &Arc<MockLlm>, rollout: u8) -> Arc<ExtractionRouter> {
    Arc::new(ExtractionRouter::new(
        default.clone(),
        provider.clone(),
        ExtractionPolicy::new(rollout, 0, [], 400_000).unwrap(),
    ))
}

fn json_and_summary() -> Vec<FormatSpec> {
    vec![
        FormatSpec::Json {
            schema: None,
            prompt: Some("extract the price".to_owned()),
        },
        FormatSpec::Summary,
    ]
}

#[tokio::test]
async fn the_json_format_calls_the_provider_while_summary_keeps_the_default_model() {
    let site = start().await;
    let (default, provider) = (by_task("default"), by_task("provider"));
    let doc = scrape(&site, json_and_summary(), false, |c| {
        c.llm = Some(default.clone() as Arc<dyn LlmExtractor>);
        c.extraction_llm = Some(router(&default, &provider, 100));
    })
    .await;
    assert_eq!(doc.json.unwrap(), json!({"answered_by": "provider"}));
    assert_eq!(doc.summary.unwrap(), "summary by default");
    assert_eq!(provider.calls().len(), 1);
    assert!(provider.calls()[0].user.contains("extract the price"));
    assert_eq!(default.calls().len(), 1, "the default model got only the summary");
    assert!(default.calls()[0].user.contains("Summarize the page"));
}

#[tokio::test]
async fn a_tenant_outside_the_rollout_is_answered_by_the_default_model() {
    let site = start().await;
    let (default, provider) = (by_task("default"), by_task("provider"));
    let doc = scrape(&site, json_and_summary(), false, |c| {
        c.llm = Some(default.clone() as Arc<dyn LlmExtractor>);
        c.extraction_llm = Some(router(&default, &provider, 0));
    })
    .await;
    assert_eq!(doc.json.unwrap(), json!({"answered_by": "default"}));
    assert!(provider.calls().is_empty());
}

#[tokio::test]
async fn a_failing_provider_falls_back_to_the_default_model() {
    let site = start().await;
    let default = by_task("default");
    let provider = mock(|_| Err(LlmError::Status { status: 503 }));
    let doc = scrape(&site, json_and_summary(), false, |c| {
        c.llm = Some(default.clone() as Arc<dyn LlmExtractor>);
        c.extraction_llm = Some(router(&default, &provider, 100));
    })
    .await;
    assert_eq!(doc.json.unwrap(), json!({"answered_by": "default"}));
    assert_eq!(provider.calls().len(), 1, "tried once");
}

#[tokio::test]
async fn zero_data_retention_runs_stay_on_the_default_model() {
    let site = start().await;
    let (default, provider) = (by_task("default"), by_task("provider"));
    let doc = scrape(&site, json_and_summary(), true, |c| {
        c.llm = Some(default.clone() as Arc<dyn LlmExtractor>);
        c.extraction_llm = Some(router(&default, &provider, 100));
    })
    .await;
    assert_eq!(doc.json.unwrap(), json!({"answered_by": "default"}));
    assert!(provider.calls().is_empty(), "no page text left for the provider");
}
