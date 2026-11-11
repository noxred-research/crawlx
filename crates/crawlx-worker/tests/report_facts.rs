//! Measured parse facts on a committed URL-plane request, over the in-memory store: the commit
//! carries a `Parse` pipeline checkpoint and its measured stage, and the real delivery
//! acknowledgement then moves the index and completion checkpoints from pending to succeeded.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::{http::header, routing::get, Router};
use crawlx_core::{
    config::{CrawlMode, SitemapMode},
    counters::RunStatus,
    report_history::{
        PipelineStageV1, PipelineStateV1, ProcessorIdentityV1, ProcessorStageV1, ReportDataV1, ReportFactV1,
        ReportKindV1, ReportQueryV1, StageOutcomeV1,
    },
    CreateCrawl,
};
use crawlx_worker::delivery::{DeliveryRegistry, LocalDestination};
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

const ARTICLE: &str = concat!(
    "<html><head><title>Measured parse article</title></head><body><article id=\"main\">",
    "<h1>Measured parse article</h1><p>Owned research teams preserve exact source text ",
    "while reserving bounded output capacity before serialization begins. This article ",
    "describes a local fixture with no external acquisition dependencies.</p>",
    "<p>Dataset acceptance must retain the document when delivery completes. The stage ",
    "durations recorded for this request are measured, never inferred from the response.</p>",
    "</article></body></html>",
);

fn pipeline(facts: &[ReportFactV1], request: i64, stage: PipelineStageV1) -> Vec<PipelineStateV1> {
    facts
        .iter()
        .filter(|fact| fact.request_id == Some(request))
        .filter_map(|fact| match fact.data {
            ReportDataV1::Pipeline { stage: actual, state } if actual == stage => Some(state),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn committed_request_carries_measured_parse_facts_and_delivery_ack_completes_the_pipeline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/article",
        get(|| async { ([(header::CONTENT_TYPE, "text/html")], ARTICLE) }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let sink = tempfile::tempdir().unwrap();
    let mut registry = DeliveryRegistry::new();
    registry
        .register(
            "fixture".into(),
            Arc::new(LocalDestination::open(sink.path()).await.unwrap()),
        )
        .unwrap();
    let mut crawl = CreateCrawl::new(format!("{base}/article").parse().unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_114);
    crawl.safety.allow_private_networks = true;
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.limits.urls = 1;
    crawl.scope.max_discovery_depth = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
    crawl.acquisition = Some(crawlx_core::acquisition::AcquisitionPolicyV1::default());
    crawl.datasets = serde_json::from_value(serde_json::json!({
        "version": 1,
        "articleDataset": "articles",
        "stores": [{"name": "articles", "schemaVersion": "document_v1", "maxItems": 10, "maxBytes": 16_777_216}],
        "feeds": [{"id": "articles_jsonl", "source": "articles", "serializer": "jsonl",
                   "serializerVersion": 1, "destination": "fixture",
                   "maxBatchItems": 10, "maxBatchBytes": 1_048_576}]
    }))
    .unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut authorization = common::authorization::verified_record(&crawl, stores.tenant);
    authorization.robots_override_acknowledged = true;
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_owned(),
        egress: EgressConfig {
            resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
            ..EgressConfig::default()
        },
        delivery: Arc::new(registry),
        ..WorkerConfig::default()
    };
    let report = crawlx_worker::run_local_with(
        LocalRun::new(crawl, config)
            .with_stores(stores.clone())
            .with_authorization(authorization),
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );

    let rows = stores.frontier.list(report.run_id).await.unwrap();
    let request = rows
        .iter()
        .find(|row| row.url.url.path() == "/article")
        .expect("article request")
        .id;
    let page = stores
        .report_history
        .query_facts(stores.tenant, Some(report.run_id), &ReportQueryV1::default())
        .await
        .unwrap();
    assert!(page.next.is_none(), "history fits one page");
    let facts: Vec<ReportFactV1> = page.entries.iter().map(|entry| entry.fact.clone()).collect();
    assert!(facts.iter().all(|fact| fact.run == report.run_id));

    // The attempt's measured wire and stage facts join the requested host by the same digest the
    // `hosts` report shows and the `hostKey` filter accepts.
    let host = crawlx_core::report_history::report_host_key("127.0.0.1");
    let hosted: Vec<_> = facts
        .iter()
        .filter(|fact| fact.request_id == Some(request))
        .filter(|fact| matches!(fact.data.kind(), ReportKindV1::Wire | ReportKindV1::Stage))
        .collect();
    assert!(
        hosted.iter().any(|fact| fact.data.kind() == ReportKindV1::Wire),
        "the fetched page records a wire fact"
    );
    assert!(
        hosted.iter().all(|fact| fact.host_key == Some(host)),
        "{hosted:?}"
    );

    // Fetch and parse are checkpointed by the producer exactly once and succeeded.
    assert_eq!(
        pipeline(&facts, request, PipelineStageV1::Fetch),
        vec![PipelineStateV1::Succeeded]
    );
    assert_eq!(
        pipeline(&facts, request, PipelineStageV1::Parse),
        vec![PipelineStateV1::Succeeded]
    );
    // Only the commit's own report facts can introduce a parse checkpoint: the storage
    // checkpoints cover fetch, index and completion, and never infer parsing.
    let parse = page
        .entries
        .iter()
        .find(|entry| {
            matches!(
                entry.fact.data,
                ReportDataV1::Pipeline {
                    stage: PipelineStageV1::Parse,
                    ..
                }
            )
        })
        .unwrap();
    assert_eq!(parse.fact.request_id, Some(request));
    assert_eq!(parse.fact.data.kind(), ReportKindV1::Pipeline);
    assert!(parse.fact.attempt >= 1);

    // The measured parse stage: stage, outcome, processor and a real duration.
    let stages: Vec<_> = facts
        .iter()
        .filter(|fact| fact.request_id == Some(request))
        .filter_map(|fact| match &fact.data {
            ReportDataV1::Stage {
                stage: ProcessorStageV1::Parse,
                outcome,
                duration_us,
                processor,
                ..
            } => Some((*outcome, *duration_us, *processor)),
            _ => None,
        })
        .collect();
    assert_eq!(stages.len(), 1, "{stages:?}");
    let (outcome, duration_us, processor) = stages[0];
    assert_eq!(outcome, StageOutcomeV1::Succeeded);
    assert_eq!(processor, ProcessorIdentityV1::Parser);
    assert!(
        duration_us < 60_000_000,
        "a local parse is measured in microseconds, got {duration_us}"
    );

    // The commit queued delivery, so index and completion started pending; the run's real
    // delivery acknowledgement then marked both succeeded, after the parse checkpoint.
    for stage in [PipelineStageV1::Index, PipelineStageV1::Completion] {
        assert_eq!(
            pipeline(&facts, request, stage),
            vec![PipelineStateV1::Pending, PipelineStateV1::Succeeded],
            "{stage:?}"
        );
    }
    let sequence_of = |stage: PipelineStageV1, state: PipelineStateV1| {
        page.entries
            .iter()
            .find(|entry| {
                entry.fact.request_id == Some(request)
                    && entry.fact.data == ReportDataV1::Pipeline { stage, state }
            })
            .map(|entry| entry.sequence)
            .unwrap()
    };
    let parsed = sequence_of(PipelineStageV1::Parse, PipelineStateV1::Succeeded);
    let acked = sequence_of(PipelineStageV1::Index, PipelineStateV1::Succeeded);
    assert!(parsed < acked, "acknowledgement follows the parse checkpoint");
    // The delivered batch is on the approved local destination.
    assert_eq!(std::fs::read_dir(sink.path()).unwrap().count(), 1);
}
