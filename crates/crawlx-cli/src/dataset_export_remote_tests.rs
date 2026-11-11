//! Native API router consumers and closed artifact-capability boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::dataset_export::{DatasetExportArgs, DatasetExportFormat};
use crawlx_api::{ApiConfig, ApiStore, AppState, Repos, Scope};
use crawlx_core::{
    dataset::{AcceptedBatchV1, AcceptedItemV1, DatasetRepo},
    orchestration::{RequestCommitRepo, RequestCommitV1},
    repo::{ArtifactStore, FrontierRepo, FrontierStatus, RunRepo},
    time::ManualClock,
    Clock, TenantId, WorkerId,
};
use crawlx_storage::{
    testkit::{canonical_url, crawl_run, create_crawl},
    WorkerRegistry,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

struct Fixture {
    args: DatasetExportArgs,
    store: Arc<crawlx_storage::MemoryStore>,
    clock: Arc<ManualClock>,
    foreign_key: String,
    no_scope_key: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(schema: &str) -> Fixture {
    let clock = Arc::new(ManualClock::new("2030-01-01T00:00:00Z".parse().unwrap()));
    let store = Arc::new(crawlx_storage::MemoryStore::with_clock(clock.clone()));
    // Dataset commits validate live content through the run's artifact index.
    let artifacts = Arc::new(
        crawlx_storage::MemoryArtifactStore::in_memory(store.clone(), clock.clone())
            .with_index(store.clone()),
    );
    let (repos, api) = Repos::memory_with_api(store.clone(), artifacts.clone());
    let tenant = TenantId::new();
    let key = crawlx_api::auth::generate_key();
    let record =
        crawlx_api::auth::key_record(&key, tenant, [Scope::CrawlsRead].into_iter().collect()).unwrap();
    api.key_insert(&record, "export_fixture").await.unwrap();
    let foreign_key = crawlx_api::auth::generate_key();
    let record = crawlx_api::auth::key_record(
        &foreign_key,
        TenantId::new(),
        [Scope::CrawlsRead].into_iter().collect(),
    )
    .unwrap();
    api.key_insert(&record, "foreign_fixture").await.unwrap();
    let no_scope_key = crawlx_api::auth::generate_key();
    let record = crawlx_api::auth::key_record(
        &no_scope_key,
        tenant,
        [Scope::AuthorizationsRead].into_iter().collect(),
    )
    .unwrap();
    api.key_insert(&record, "scope_fixture").await.unwrap();
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.datasets = serde_json::from_value(json!({"version":1,"stores":[{
        "name":"items","schemaVersion":schema,"maxItems":10,"maxBytes":1048576
    }]}))
    .unwrap();
    let mut run = crawl_run(tenant, config);
    run.created_at = clock.now();
    store.create(&run, None).await.unwrap();
    let worker = WorkerId::new();
    store
        .register_worker(worker, "export_fixture", "1")
        .await
        .unwrap();
    for (index, title) in [(1, "first"), (2, "second")] {
        let (_, request) = store
            .discover(
                run.id,
                &canonical_url(&format!("https://fixture.test/{index}")),
                0,
                None,
                None,
            )
            .await
            .unwrap();
        let request = request.unwrap();
        let lease = store
            .lease_batch_fenced(run.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(request, lease.0.id);
        let bytes = serde_json::to_vec(&json!({"title":title,"rank":index})).unwrap();
        let deadline = clock.now() + chrono::Duration::seconds(600);
        let artifact = artifacts
            .put_dataset_until(
                run.id,
                request,
                "export_fixture",
                "application/json",
                &bytes,
                deadline,
            )
            .await
            .unwrap();
        let content = artifacts
            .dataset_content(run.id, request, &artifact, u64::try_from(bytes.len()).unwrap())
            .await
            .unwrap();
        let mut item = AcceptedItemV1::new(
            format!("item_{index}"),
            "fixture_v1".into(),
            schema.into(),
            "fixture_v1".into(),
            content,
            u64::try_from(bytes.len()).unwrap(),
        );
        item.expires_at = Some(deadline);
        let mut commit =
            RequestCommitV1::terminal(run.id, request, lease.1, 1, FrontierStatus::Succeeded, None);
        commit
            .accepted
            .push(AcceptedBatchV1::new("items".into(), vec![item]));
        store.commit_fenced(commit).await.unwrap();
    }
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let state = AppState::builder(
        repos,
        crawlx_api::admission_policy(&config, clock.clone()),
        config,
    )
    .clock(clock.clone())
    .build();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let router = crawlx_api::router(state).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let observed = observed.clone();
            async move {
                observed.lock().unwrap().push(request.uri().to_string());
                next.run(request).await
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Fixture {
        args: DatasetExportArgs {
            format: DatasetExportFormat::Json,
            csv_fields: Vec::new(),
            max_row_bytes: 1_048_576,
            run: Some(run.id),
            dataset: Some("items".into()),
            page_size: 1,
            api: crate::authz::ApiTarget {
                api_url,
                api_key: Some(key),
            },
        },
        store,
        clock,
        foreign_key,
        no_scope_key,
        requests,
        task,
    }
}

#[tokio::test]
async fn native_router_exports_committed_items_across_exact_durable_keyset_boundaries() {
    for schema in ["document_item_v1", "json_object_v1"] {
        let fixture = fixture(schema).await;
        let mut output = Vec::new();
        assert_eq!(
            crate::dataset_export::run(fixture.args_for(DatasetExportFormat::Json), &mut output)
                .await
                .unwrap(),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            output,
            b"[{\"rank\":1,\"title\":\"first\"},{\"rank\":2,\"title\":\"second\"}]\n"
        );
        let run = fixture.args.run.unwrap();
        let expected: Vec<_> = [0, 1, 2]
            .into_iter()
            .map(|cursor| format!("/v1/crawls/{run}/datasets/items/items?limit=1&cursor={cursor}"))
            .collect();
        assert_eq!(
            fixture
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|path| path.contains("/datasets/items/items?"))
                .cloned()
                .collect::<Vec<_>>(),
            expected
        );
        let boundary = fixture.store.items(run, "items", 1, 1).await.unwrap();
        assert_eq!(boundary.len(), 1);
        assert_eq!(boundary[0].ordinal, 2);
        for format in [
            DatasetExportFormat::Jsonl,
            DatasetExportFormat::Csv,
            DatasetExportFormat::Xml,
        ] {
            output.clear();
            let args = fixture.args_for(format);
            export(&args, &mut output).await.unwrap();
            let mut expected = Vec::new();
            crate::dataset_export::export_reader(
                &args,
                tokio::io::BufReader::new(
                    &b"{\"title\":\"first\",\"rank\":1}\n{\"title\":\"second\",\"rank\":2}\n"[..],
                ),
                &mut expected,
            )
            .await
            .unwrap();
            assert_eq!(output, expected);
        }
        assert_eq!(fixture.store.items(run, "items", 1, 1).await.unwrap(), boundary);
    }
}

impl Fixture {
    fn args_for(&self, format: DatasetExportFormat) -> DatasetExportArgs {
        DatasetExportArgs {
            format,
            csv_fields: self.args.csv_fields.clone(),
            max_row_bytes: self.args.max_row_bytes,
            run: self.args.run,
            dataset: self.args.dataset.clone(),
            page_size: self.args.page_size,
            api: self.args.api.clone(),
        }
    }
}

#[tokio::test]
async fn native_auth_tenant_scope_and_expired_content_fail_without_fake_collection_output() {
    let fixture = fixture("document_item_v1").await;
    for key in [
        None,
        Some("invalid_bearer".into()),
        Some(fixture.foreign_key.clone()),
        Some(fixture.no_scope_key.clone()),
    ] {
        let mut args = fixture.args_for(DatasetExportFormat::Json);
        args.api.api_key = key;
        let mut out = Vec::new();
        assert!(export(&args, &mut out).await.is_err());
        assert!(out.is_empty());
    }
    let mut too_small = fixture.args_for(DatasetExportFormat::Xml);
    too_small.max_row_bytes = 1;
    let mut out = Vec::new();
    assert!(export(&too_small, &mut out).await.is_err());
    assert!(out.is_empty());
    fixture.clock.advance_ms(600_001);
    assert!(export(&fixture.args, &mut out).await.is_err());
    assert!(out.is_empty());
}

#[tokio::test]
async fn native_article_dataset_is_not_relabelled_as_generic_items() {
    let fixture = fixture("document_v1").await;
    let mut out = Vec::new();
    assert!(export(&fixture.args, &mut out).await.is_err());
    assert!(out.is_empty());
    assert!(!fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|path| path.contains("/artifacts/")));
}

#[tokio::test]
async fn artifact_capability_binds_origin_run_id_artifact_id_and_query_free_path() {
    let fixture = fixture("document_item_v1").await;
    let run = fixture.args.run.unwrap();
    let item = fixture
        .store
        .items(run, "items", 0, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let correct = format!("/v1/crawls/{run}/artifacts/{}", item.item.content.artifact().id);
    let mut entry = Entry {
        item,
        content_url: correct.clone(),
    };
    let base = endpoint(&fixture.args, run).unwrap();
    assert!(artifact_url(&base, run, &entry).is_ok());
    for path in [
        format!("https://foreign.test{correct}"),
        format!("{correct}?view=metadata"),
        format!("{correct}#fragment"),
        correct.replace(&run.to_string(), &CrawlRunId::new().to_string()),
        format!("/v1/crawls/{run}/artifacts/{}", crawlx_core::ArtifactId::new()),
        "/v1/authorizations".into(),
    ] {
        entry.content_url = path;
        assert!(artifact_url(&base, run, &entry).is_err());
    }
}

#[tokio::test]
async fn redirects_and_response_byte_caps_are_closed() {
    use axum::{routing::get, Json};
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = seen.clone();
    let app = axum::Router::new()
        .route(
            "/redirect",
            get(|| async { axum::response::Redirect::temporary("/target") }),
        )
        .route(
            "/target",
            get(move || {
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Json(json!({"value":true}))
                }
            }),
        )
        .route(
            "/large",
            get(|| async { Json(json!({"value":"x".repeat(1024)})) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    assert!(bytes(&http, base.join("/redirect").unwrap(), "fixture", 1024)
        .await
        .is_err());
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(bytes(&http, base.join("/large").unwrap(), "fixture", 32)
        .await
        .is_err());
    task.abort();
}
