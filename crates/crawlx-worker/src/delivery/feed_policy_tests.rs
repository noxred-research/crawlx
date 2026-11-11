//! Native feed policy consumers over real artifacts and request/outbox transactions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::dataset::{AcceptedBatchV1, DatasetConfigV1, DeliveryOutboxRepo};
use crawlx_core::orchestration::{RequestBatchV1, RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, TenantId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{MemoryStore, WorkerRegistry};

struct Fixture {
    stores: Stores,
    repo: Arc<MemoryStore>,
    clock: Arc<ManualClock>,
    run: CrawlRun,
    worker: WorkerId,
    _directory: tempfile::TempDir,
}

async fn fixture(feeds: Value, schema: &str, zdr: bool) -> Fixture {
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(repo.clone(), directory.path()).await.unwrap();
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.mode = if zdr {
        RetentionMode::Zdr
    } else {
        RetentionMode::Standard
    };
    config.retention.days = if zdr { 0 } else { 1 };
    config.datasets = serde_json::from_value(json!({"version":1,
        "stores":[{"name":"items","schemaVersion":schema,"maxItems":100,"maxBytes":16777216}],"feeds":feeds}))
    .unwrap();
    config.datasets.validate().unwrap();
    let mut run = crawl_run(TenantId::new(), config);
    run.created_at = clock.now();
    repo.create(&run, None).await.unwrap();
    let worker = WorkerId::new();
    repo.register_worker(worker, "feed-fixture", "1").await.unwrap();
    repo.publish_acquisition_capabilities(
        worker,
        &[crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
            "fixture", "1",
        )],
    )
    .await
    .unwrap();
    let mut facts = crawlx_core::data_capabilities::WorkerDataCapabilitiesV1::default();
    facts.destinations.insert("first".into(), true);
    facts.destinations.insert("second".into(), true);
    facts
        .compressed_destinations
        .extend(["first".into(), "second".into()]);
    repo.publish_data_capabilities(worker, &facts).await.unwrap();
    Fixture {
        stores,
        repo,
        clock,
        run,
        worker,
        _directory: directory,
    }
}

fn feed(id: &str, format: &str) -> Value {
    json!({"id":id,"source":"items","serializer":format,"serializerVersion":1,"destination":id,
        "maxBatchItems":2,"maxBatchBytes":4096,"batching":"terminal","emptyPolicy":"emit"})
}

async fn accept(f: &Fixture, values: &[Value], imported: bool) {
    let requests = values
        .iter()
        .enumerate()
        .map(|(index, _)| {
            RequestEnvelopeV1::get(canonical_url(&format!("https://fixture.test/{index}")), 0, None)
        })
        .collect();
    f.repo
        .append_batch(RequestBatchV1::new(
            f.run.tenant,
            f.run.id,
            "anonymous".into(),
            crawlx_core::hash::Digest::of("feed-fixture", b"requests"),
            requests,
        ))
        .await
        .unwrap();
    let leased = f
        .repo
        .lease_batch_fenced(f.run.id, f.worker, u32::try_from(values.len()).unwrap())
        .await
        .unwrap();
    assert_eq!(leased.len(), values.len());
    let cpu = CpuPool::default();
    for ((entry, fence), value) in leased.into_iter().zip(values) {
        let bytes = Redactor::new()
            .verify_canonical_owned(serde_json::to_vec(value).unwrap())
            .unwrap();
        let artifact = ArtifactSink::over(f.stores.artifacts.as_ref())
            .put_dataset(f.run.id, entry.id, "item", "application/json", &bytes)
            .await
            .unwrap();
        let size = u64::try_from(bytes.as_ref().len()).unwrap();
        let content = f
            .stores
            .artifacts
            .dataset_content(f.run.id, entry.id, &artifact, size)
            .await
            .unwrap();
        let mut item = AcceptedItemV1::new(
            format!("item.{}", entry.id),
            "fixture_v1".into(),
            if imported {
                "json_object_v1"
            } else {
                "document_item_v1"
            }
            .into(),
            "fixture_v1".into(),
            content,
            size,
        );
        item.expires_at = item
            .content
            .expires_at()
            .or_else(|| article_deadline(&f.run, None));
        let outbox = if imported {
            Vec::new()
        } else {
            let batches = prepare_generic(
                f.stores.artifacts.as_ref(),
                &cpu,
                &f.run,
                entry.id,
                "items",
                &artifact,
                bytes,
            )
            .await
            .unwrap();
            take_fragments(&f.run, &mut item, batches)
        };
        assert!(outbox.is_empty());
        let mut commit =
            RequestCommitV1::terminal(f.run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
        commit
            .accepted
            .push(AcceptedBatchV1::new("items".into(), vec![item]));
        f.repo.commit_fenced(commit).await.unwrap();
    }
}

#[test]
fn accumulator_respects_item_bytes_and_contiguous_ranges() {
    let mut policy: FeedDeclarationV1 = serde_json::from_value(feed("first", "jsonl")).unwrap();
    policy.max_batch_bytes = 16;
    let now = chrono::Utc::now();
    let mut output = Accumulator::new(16, now);
    assert!(output.push(&policy, false, 1, b"{\"n\":1}\n", now).unwrap());
    assert!(output.push(&policy, false, 2, b"{\"n\":2}\n", now).unwrap());
    assert!(!output.push(&policy, false, 3, b"{\"n\":3}\n", now).unwrap());
    let mut gap = Accumulator::new(16, now);
    assert!(gap.push(&policy, false, 1, b"{}\n", now).unwrap());
    assert!(!gap.push(&policy, false, 3, b"{}\n", now).unwrap());
    let mut byte_bound = Accumulator::new(16, now);
    policy.max_batch_items = 10;
    assert!(byte_bound.push(&policy, false, 1, b"{\"n\":1}\n", now).unwrap());
    assert!(!byte_bound
        .push(&policy, false, 2, b"{\"n\":12345}\n", now)
        .unwrap());
}

#[test]
fn jsonl_accumulator_frames_records_with_or_without_fragment_newlines() {
    let policy: FeedDeclarationV1 = serde_json::from_value(feed("first", "jsonl")).unwrap();
    let now = chrono::Utc::now();
    let mut output = Accumulator::new(4096, now);
    assert!(output.push(&policy, false, 1, b"{\"n\":1}", now).unwrap());
    assert!(output.push(&policy, false, 2, b"{\"n\":2}\n", now).unwrap());
    write_bytes(&mut output.output, &output.suffix).unwrap();
    assert_eq!(output.output.bytes, b"{\"n\":1}\n{\"n\":2}\n");
    assert!(Redactor::new()
        .verify_canonical_jsonl_owned(output.output.bytes)
        .is_ok());
}

#[test]
fn parameters_preserve_declared_csv_order_and_json_indent() {
    let mut policy: FeedDeclarationV1 = serde_json::from_value(feed("first", "csv")).unwrap();
    policy.parameters.csv_columns = vec!["b".into(), "a".into()];
    let mut output = LimitedOutput::new(1024);
    write_generic(&mut output, &json!({"a":"one","b":"two","omitted":"no"}), &policy).unwrap();
    assert_eq!(output.bytes, b"\"b\",\"a\"\n\"two\",\"one\"\n");
    policy.serializer = "json".into();
    policy.parameters.csv_columns.clear();
    policy.parameters.json_indent = 2;
    let mut output = LimitedOutput::new(1024);
    write_generic(&mut output, &json!({"a":1}), &policy).unwrap();
    assert_eq!(output.bytes, b"{\n  \"a\": 1\n}\n");
}

#[tokio::test]
async fn terminal_filters_multiple_destinations_and_bounded_batches_keep_exact_ranges() {
    let mut first = feed("first", "json");
    first["itemFilter"] = json!({"all":[{"kind":"equals","field":"keep","value":true}]});
    let mut second = first.clone();
    second["id"] = json!("second");
    second["destination"] = json!("second");
    let f = fixture(json!([first, second]), "document_item_v1", false).await;
    let values: Vec<_> = (1..=5).map(|n| json!({"n":n,"keep":n!=3})).collect();
    accept(&f, &values, false).await;
    assert!(f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap().is_empty());
    let cpu = CpuPool::default();
    f.repo.stage_feed_batches(f.run.id, &[]).await.unwrap();
    for policy in &f.run.config.datasets.feeds {
        terminal_batches(&f.stores, &cpu, &f.run, policy).await.unwrap();
    }
    let mut staged = Vec::new();
    for id in ["first", "second"] {
        for (first, last) in [(1, 2), (4, 5)] {
            staged.push(
                f.repo
                    .staged_feed_batch(f.run.id, id, &format!("terminal.{id}.{first}.{last}"))
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
    }
    // A restart before the terminal transaction must not expose or regenerate different batches.
    assert!(f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap().is_empty());
    f.stores
        .finish_run(
            f.run.id,
            TerminalReason::FrontierExhausted,
            &CpuPool::default(),
            f.worker,
        )
        .await
        .unwrap();
    assert_eq!(f.repo.get(f.run.id).await.unwrap().status, RunStatus::Completed);
    let claims = f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap();
    assert_eq!(claims.len(), 4);
    for batch in staged {
        assert!(claims.iter().any(|claim| claim.batch == batch));
    }
    for id in ["first", "second"] {
        let rows: Vec<_> = claims.iter().filter(|row| row.batch.feed == id).collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].batch.range,
            DeliveryRangeV1::Committed { first: 1, last: 2 }
        );
        assert_eq!(
            rows[1].batch.range,
            DeliveryRangeV1::Committed { first: 4, last: 5 }
        );
        for row in rows {
            let bytes = f
                .stores
                .artifacts
                .get(row.batch.content.artifact())
                .await
                .unwrap();
            assert_eq!(serde_json::from_slice::<Vec<Value>>(&bytes).unwrap().len(), 2);
        }
    }
}

#[tokio::test]
async fn terminal_imported_objects_use_same_bounded_serializer_without_fragments() {
    let f = fixture(json!([feed("first", "jsonl")]), "json_object_v1", false).await;
    accept(&f, &[json!({"n":1}), json!({"n":2}), json!({"n":3})], true).await;
    f.stores
        .finish_run(
            f.run.id,
            TerminalReason::FrontierExhausted,
            &CpuPool::default(),
            f.worker,
        )
        .await
        .unwrap();
    let claims = f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap();
    assert_eq!(claims.len(), 2);
    let bytes = f
        .stores
        .artifacts
        .get(claims[0].batch.content.artifact())
        .await
        .unwrap();
    assert_eq!(
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        2
    );
}

#[tokio::test]
async fn terminal_empty_emit_has_no_invented_item_range_and_skip_has_no_receipt() {
    for zdr in [false, true] {
        let mut skip = feed("second", "json");
        skip["emptyPolicy"] = json!("skip");
        let f = fixture(json!([feed("first", "json"), skip]), "document_item_v1", zdr).await;
        f.stores
            .finish_run(
                f.run.id,
                TerminalReason::FrontierExhausted,
                &CpuPool::default(),
                f.worker,
            )
            .await
            .unwrap();
        let claims = f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].batch.range, DeliveryRangeV1::Empty);
        assert_eq!(claims[0].batch.feed, "first");
        assert_eq!(
            f.stores
                .artifacts
                .get(claims[0].batch.content.artifact())
                .await
                .unwrap(),
            b"[]\n"
        );
    }
}

#[tokio::test]
async fn invalid_empty_transaction_rolls_back_status_and_every_manifest() {
    let f = fixture(json!([feed("first", "json")]), "document_item_v1", false).await;
    let approved = Redactor::new().verify_canonical(b"[]\n").unwrap();
    let artifact = ArtifactSink::over(f.stores.artifacts.as_ref())
        .put_dataset(f.run.id, -100, "empty", "application/json", &approved)
        .await
        .unwrap();
    let content = f
        .stores
        .artifacts
        .dataset_content(f.run.id, -100, &artifact, 3)
        .await
        .unwrap();
    let mut valid = DeliveryBatchV1::for_request(
        "first".into(),
        "terminal.empty.first".into(),
        content,
        3,
        article_deadline(&f.run, None).unwrap(),
    );
    valid.range = DeliveryRangeV1::Empty;
    let mut invalid = valid.clone();
    invalid.feed = "undeclared".into();
    assert!(f
        .repo
        .finalize_run_feeds(
            f.run.id,
            RunStatus::Completed,
            TerminalReason::FrontierExhausted,
            &[valid, invalid]
        )
        .await
        .is_err());
    assert!(!f.repo.get(f.run.id).await.unwrap().status.is_terminal());
    assert!(f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap().is_empty());
}

#[tokio::test]
async fn terminal_batch_reclaims_same_identity_after_local_put_without_receipt() {
    let f = fixture(json!([feed("first", "jsonl")]), "document_item_v1", false).await;
    accept(&f, &[json!({"n":1}), json!({"n":2})], false).await;
    f.stores
        .finish_run(
            f.run.id,
            TerminalReason::FrontierExhausted,
            &CpuPool::default(),
            f.worker,
        )
        .await
        .unwrap();
    let first = f
        .repo
        .claim(f.run.id, f.worker, 1, 60)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let sink = LocalDestination::open(root.path()).await.unwrap();
    let config = crate::WorkerConfig::default();
    let authority = DeliveryAuthority {
        policy: Arc::new(config.egress.policy_for_run(&f.run.config, None).unwrap()),
        resolver: config.egress.resolver_for(&f.run.config).unwrap(),
        governor: Arc::new(crawlx_fetch::OriginGovernor::new(
            crawlx_fetch::GovernorConfig::from_politeness(&f.run.config.politeness, f.run.seed),
        )),
        cancel: CancellationToken::new(),
    };
    let bytes = Bytes::from(
        f.stores
            .artifacts
            .get(first.batch.content.artifact())
            .await
            .unwrap(),
    );
    sink.send(&authority, &f.run, &first.batch, bytes.clone())
        .await
        .unwrap();
    f.clock.advance_ms(61_000);
    let retry = f
        .repo
        .claim(f.run.id, f.worker, 1, 60)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first.id, retry.id);
    assert_eq!(first.batch.idempotency_key, retry.batch.idempotency_key);
    assert_eq!(first.batch, retry.batch);
    sink.send(&authority, &f.run, &retry.batch, bytes).await.unwrap();
    f.repo.acknowledge(f.run.id, retry.id, retry.fence).await.unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn raw_object_feeds_require_terminal_policy_and_keep_per_request_default() {
    let mut config: DatasetConfigV1 = serde_json::from_value(json!({"stores":[{"name":"items","schemaVersion":"json_object_v1","maxItems":10,"maxBytes":4096}],"feeds":[feed("first","json")]})).unwrap();
    config.validate().unwrap();
    config.feeds[0].batching = FeedBatchingV1::PerRequest;
    assert!(config.validate().is_err());
    config.stores[0].schema_version = "document_item_v1".into();
    config.validate().unwrap();
}

#[tokio::test]
async fn compressed_byte_expansion_splits_only_at_stable_record_boundaries() {
    let mut policy = feed("first", "jsonl");
    policy["compression"] = json!("gzip");
    policy["maxBatchBytes"] = json!(50);
    let f = fixture(json!([policy]), "document_item_v1", false).await;
    accept(
        &f,
        &[json!({"v":"a1B2c3D4e5F6g7H8"}), json!({"v":"j9K0l1M2n3P4q5R6"})],
        false,
    )
    .await;
    f.stores
        .finish_run(
            f.run.id,
            TerminalReason::FrontierExhausted,
            &CpuPool::default(),
            f.worker,
        )
        .await
        .unwrap();
    let claims = f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap();
    assert_eq!(claims.len(), 2);
    assert_eq!(
        claims[0].batch.range,
        DeliveryRangeV1::Committed { first: 1, last: 1 }
    );
    assert_eq!(
        claims[1].batch.range,
        DeliveryRangeV1::Committed { first: 2, last: 2 }
    );
    assert!(claims.iter().all(|claim| claim.batch.size_bytes <= 50));
}

#[tokio::test]
async fn every_filtered_item_still_commits_but_feed_publishes_only_one_empty_manifest() {
    let mut policy = feed("first", "json");
    policy["itemFilter"] = json!({"all":[{"kind":"equals","field":"keep","value":true}]});
    let f = fixture(json!([policy]), "document_item_v1", false).await;
    accept(&f, &[json!({"keep":false}), json!({"keep":false})], false).await;
    f.stores
        .finish_run(
            f.run.id,
            TerminalReason::FrontierExhausted,
            &CpuPool::default(),
            f.worker,
        )
        .await
        .unwrap();
    let claims = f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].batch.range, DeliveryRangeV1::Empty);
    assert_eq!(
        f.stores
            .datasets
            .items(f.run.id, "items", 0, 10)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn terminal_article_fragments_preserve_real_serializers_and_native_collection_framing() {
    let formats = [
        "json",
        "jsonl",
        "csv",
        "xml",
        "tei",
        "text",
        "markdown",
        "html",
        "search_json",
    ];
    let policies: Vec<_> = formats
        .iter()
        .map(|format| {
            let mut policy = feed(&format!("f_{format}"), format);
            policy["destination"] = json!("first");
            policy["maxBatchBytes"] = json!(1048576);
            if *format == "tei" {
                policy["emptyPolicy"] = json!("skip");
            }
            policy
        })
        .collect();
    let f = fixture(json!(policies), "document_v1", false).await;
    f.repo
        .append_batch(RequestBatchV1::new(
            f.run.tenant,
            f.run.id,
            "anonymous".into(),
            crawlx_core::hash::Digest::of("article-feed-fixture", b"requests"),
            vec![
                RequestEnvelopeV1::get(canonical_url("https://fixture.test/one"), 0, None),
                RequestEnvelopeV1::get(canonical_url("https://fixture.test/two"), 0, None),
            ],
        ))
        .await
        .unwrap();
    let cpu = CpuPool::default();
    for (entry, fence) in f.repo.lease_batch_fenced(f.run.id, f.worker, 2).await.unwrap() {
        let (_, accepted, outbox) = crate::delivery::prepare_article_acceptance(
            f.stores.artifacts.as_ref(),
            &cpu,
            &f.run,
            entry.id,
            Box::new(crate::delivery::tests::document(200).await),
            true,
        )
        .await
        .unwrap();
        assert!(outbox.is_empty());
        assert_eq!(accepted[0].items[0].feed_fragments.len(), formats.len());
        let mut commit =
            RequestCommitV1::terminal(f.run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
        commit.accepted = accepted;
        f.repo.commit_fenced(commit).await.unwrap();
    }
    f.stores
        .finish_run(f.run.id, TerminalReason::FrontierExhausted, &cpu, f.worker)
        .await
        .unwrap();
    let claims = f.repo.claim(f.run.id, f.worker, 16, 60).await.unwrap();
    assert_eq!(claims.len(), 10);
    for claim in claims {
        let bytes = f
            .stores
            .artifacts
            .get(claim.batch.content.artifact())
            .await
            .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        match claim.batch.feed.as_str() {
            "f_json" => assert_eq!(serde_json::from_slice::<Vec<Value>>(&bytes).unwrap().len(), 2),
            "f_jsonl" => assert_eq!(text.lines().count(), 2),
            "f_csv" => assert_eq!(text.matches("source,title,source_url,text,comments").count(), 1),
            "f_xml" => {
                assert_eq!(text.matches("<entry source=").count(), 2);
                assert!(text.ends_with("</articles>\n"));
            }
            "f_tei" => {
                assert_eq!(text.matches("<teiCorpus").count(), 1);
                assert!(text.ends_with("</teiCorpus>\n"));
            }
            "f_html" => assert_eq!(text.matches("<section data-source=").count(), 2),
            "f_text" | "f_markdown" => assert_eq!(text.matches('\u{1e}').count(), 2),
            "f_search_json" => {
                assert!(serde_json::from_slice::<Value>(&bytes).unwrap().is_object());
            }
            _ => panic!("unexpected feed"),
        }
    }
}

async fn recover_fixture(f: &Fixture, output: &std::path::Path) {
    let mut registry = DeliveryRegistry::new();
    registry
        .register(
            "first".into(),
            Arc::new(LocalDestination::open(output).await.unwrap()),
        )
        .unwrap();
    let config = crate::WorkerConfig {
        worker_id: f.worker,
        delivery: Arc::new(registry),
        ..crate::WorkerConfig::default()
    };
    let clock: Arc<dyn Clock> = f.clock.clone();
    let mut governors = BTreeMap::new();
    let mut after = None;
    crate::delivery::recover_once(
        &f.stores,
        &config,
        &clock,
        &CancellationToken::new(),
        &mut governors,
        &mut after,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn crash_after_source_seal_without_outbox_recovers_original_failure_reason_once() {
    let f = fixture(json!([feed("first", "jsonl")]), "document_item_v1", false).await;
    accept(&f, &[json!({"n":1}), json!({"n":2})], false).await;
    assert_eq!(
        f.repo
            .begin_feed_finalization(f.run.id, Some(TerminalReason::FatalError))
            .await
            .unwrap(),
        Some(TerminalReason::FatalError)
    );
    assert!(f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap().is_empty());
    assert!(f.repo.ready_runs(None, 10).await.unwrap().contains(&f.run.id));
    let output = tempfile::tempdir().unwrap();
    recover_fixture(&f, output.path()).await;
    let run = f.repo.get(f.run.id).await.unwrap();
    assert_eq!(run.status, RunStatus::Failed);
    assert_eq!(run.terminal_reason, Some(TerminalReason::FatalError));
    recover_fixture(&f, output.path()).await;
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 1);
    assert_eq!(
        f.repo.begin_feed_finalization(f.run.id, None).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn api_cancellation_before_worker_finalization_recovers_empty_feed_once() {
    let f = fixture(json!([feed("first", "json")]), "document_item_v1", false).await;
    f.repo
        .set_status(f.run.id, RunStatus::Cancelled, Some(TerminalReason::Cancelled))
        .await
        .unwrap();
    assert!(f.repo.ready_runs(None, 10).await.unwrap().contains(&f.run.id));
    let output = tempfile::tempdir().unwrap();
    recover_fixture(&f, output.path()).await;
    let run = f.repo.get(f.run.id).await.unwrap();
    assert_eq!(run.status, RunStatus::Cancelled);
    assert_eq!(run.terminal_reason, Some(TerminalReason::Cancelled));
    recover_fixture(&f, output.path()).await;
    let files: Vec<_> = std::fs::read_dir(output.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(std::fs::read(&files[0]).unwrap(), b"[]\n");
    assert_eq!(
        f.repo.begin_feed_finalization(f.run.id, None).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn expired_terminal_sources_retire_once_without_reselecting_or_publishing() {
    let f = fixture(json!([feed("first", "json")]), "document_item_v1", true).await;
    accept(&f, &[json!({"n":1})], false).await;
    f.repo
        .begin_feed_finalization(f.run.id, Some(TerminalReason::FatalError))
        .await
        .unwrap();
    f.clock.advance_ms(7_200_000);
    assert!(
        matches!(f.repo.maintain(f.run.id).await,Err(StoreError::RetentionDenied(message)) if message=="feed content_expired")
    );
    assert!(!f.repo.ready_runs(None, 10).await.unwrap().contains(&f.run.id));
    assert_eq!(
        f.repo.begin_feed_finalization(f.run.id, None).await.unwrap(),
        None
    );
    assert_eq!(f.repo.get(f.run.id).await.unwrap().status, RunStatus::Failed);
    assert!(f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap().is_empty());
}

#[test]
fn empty_tei_corpus_is_refused_without_inventing_a_document() {
    let mut config: DatasetConfigV1 = serde_json::from_value(json!({"stores":[{"name":"items","schemaVersion":"document_v1","maxItems":10,"maxBytes":4096}],"feeds":[feed("first","tei")]})).unwrap();
    assert!(config.validate().is_err());
    config.feeds[0].empty_policy = EmptyFeedPolicyV1::Skip;
    config.validate().unwrap();
    assert!(empty_bytes(&config.feeds[0], true).is_err());
}

#[tokio::test]
async fn destinations_keep_disjoint_volatile_deadline_namespaces() {
    let f = fixture(
        json!([feed("first", "json"), feed("second", "json")]),
        "document_item_v1",
        true,
    )
    .await;
    let first = &f.run.config.datasets.feeds[0];
    let second = &f.run.config.datasets.feeds[1];
    assert_ne!(
        terminal_page(&f.run, first, 1).unwrap(),
        terminal_page(&f.run, second, 1).unwrap()
    );
    assert_ne!(
        terminal_page(&f.run, first, 0).unwrap(),
        terminal_page(&f.run, first, 1).unwrap()
    );
}

#[tokio::test]
async fn sealed_terminal_feeds_are_written_under_the_finalizer_claim() {
    let f = fixture(json!([feed("first", "json")]), "document_item_v1", false).await;
    accept(&f, &[json!({"n":1}), json!({"n":2}), json!({"n":3})], false).await;
    // Same run and artifact directory, but every Content write now needs a producer lease.
    let sealed = Stores::over_memory_with_local_custody(f.repo.clone(), f._directory.path())
        .await
        .unwrap();
    let probe = Redactor::new().verify_canonical_owned(b"[]\n".to_vec()).unwrap();
    let refused = ArtifactSink::over(sealed.artifacts.as_ref())
        .put_dataset(f.run.id, 0, "probe", "application/json", &probe)
        .await;
    assert!(matches!(refused, Err(StoreError::Unavailable(_))), "{refused:?}");
    sealed
        .finish_run(
            f.run.id,
            TerminalReason::FrontierExhausted,
            &CpuPool::default(),
            f.worker,
        )
        .await
        .unwrap();
    assert_eq!(f.repo.get(f.run.id).await.unwrap().status, RunStatus::Completed);
    let claims = f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap();
    assert_eq!(claims.len(), 2);
    for claim in &claims {
        sealed
            .artifacts
            .get(claim.batch.content.artifact())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn finalizer_claim_is_exclusive_fenced_and_ends_with_finalization() {
    let mut policy = feed("first", "json");
    policy["emptyPolicy"] = json!("skip");
    let f = fixture(json!([policy]), "document_item_v1", false).await;
    let ttl = std::time::Duration::from_secs(60);
    let other = WorkerId::new();
    assert!(matches!(
        f.repo.claim_feed_finalizer(f.run.id, f.worker, ttl).await,
        Err(StoreError::LeaseLost)
    ));
    f.repo
        .begin_feed_finalization(f.run.id, Some(TerminalReason::FrontierExhausted))
        .await
        .unwrap();
    let first = f
        .repo
        .claim_feed_finalizer(f.run.id, f.worker, ttl)
        .await
        .unwrap();
    assert!(matches!(
        f.repo.claim_feed_finalizer(f.run.id, other, ttl).await,
        Err(StoreError::Conflict(_))
    ));
    f.repo.release_feed_finalizer(&first).await.unwrap();
    let second = f.repo.claim_feed_finalizer(f.run.id, other, ttl).await.unwrap();
    assert!(second.fence > first.fence);
    assert!(matches!(
        f.repo.renew_feed_finalizer(&first, ttl).await,
        Err(StoreError::LeaseLost)
    ));
    f.repo.renew_feed_finalizer(&second, ttl).await.unwrap();
    f.clock.advance_ms(61_000);
    assert!(matches!(
        f.repo.renew_feed_finalizer(&second, ttl).await,
        Err(StoreError::LeaseLost)
    ));
    let third = f
        .repo
        .claim_feed_finalizer(f.run.id, f.worker, ttl)
        .await
        .unwrap();
    assert!(third.fence > second.fence);
    f.repo
        .finalize_run_feeds(
            f.run.id,
            RunStatus::Completed,
            TerminalReason::FrontierExhausted,
            &[],
        )
        .await
        .unwrap();
    assert!(matches!(
        f.repo.renew_feed_finalizer(&third, ttl).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        f.repo.claim_feed_finalizer(f.run.id, f.worker, ttl).await,
        Err(StoreError::LeaseLost)
    ));
}

#[tokio::test]
async fn finish_run_waits_out_another_workers_live_finalizer_claim() {
    let f = fixture(json!([feed("first", "json")]), "document_item_v1", false).await;
    accept(&f, &[json!({"n":1}), json!({"n":2}), json!({"n":3})], false).await;
    f.repo
        .begin_feed_finalization(f.run.id, Some(TerminalReason::FrontierExhausted))
        .await
        .unwrap();
    let held = f
        .repo
        .claim_feed_finalizer(f.run.id, WorkerId::new(), std::time::Duration::from_secs(60))
        .await
        .unwrap();
    let repo = f.repo.clone();
    let release = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        repo.release_feed_finalizer(&held).await.unwrap();
    });
    f.stores
        .finish_run(
            f.run.id,
            TerminalReason::FrontierExhausted,
            &CpuPool::default(),
            f.worker,
        )
        .await
        .unwrap();
    release.await.unwrap();
    assert_eq!(f.repo.get(f.run.id).await.unwrap().status, RunStatus::Completed);
    assert_eq!(f.repo.claim(f.run.id, f.worker, 10, 60).await.unwrap().len(), 2);
}
