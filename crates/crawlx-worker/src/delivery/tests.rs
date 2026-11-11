//! Real native parsing, retained article feeds and approved local sink regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crawlx_core::{
    config::RetentionMode,
    dataset::{DatasetRepo, DeliveryOutboxRepo},
    orchestration::{RequestBatchV1, RequestCommitRepo, RequestCommitV1},
    repo::{FrontierRepo, FrontierStatus, RunRepo},
    request::RequestEnvelopeV1,
    time::ManualClock,
    Clock, TenantId,
};
use crawlx_storage::artifacts::{ArtifactBlobs, BlobEntry, FsArtifactStore, FsBlobs, ObjectArtifactStore};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{BufferLimits, DeliveryBuffer, MemoryStore, WorkerRegistry};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn run(mode: RetentionMode, now: crawlx_core::Timestamp, formats: &[&str]) -> CrawlRun {
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.mode = mode;
    config.retention.days = if mode == RetentionMode::Zdr { 0 } else { 1 };
    let feeds: Vec<_> = formats
        .iter()
        .map(|format| {
            json!({"id":format!("feed_{format}"),"source":"articles","serializer":format,
        "serializerVersion":1,"destination":"fixture","maxBatchItems":10,"maxBatchBytes":1048576})
        })
        .collect();
    config.datasets=serde_json::from_value(json!({"version":1,"articleDataset":"articles",
        "stores":[{"name":"articles","schemaVersion":"document_v1","maxItems":100,"maxBytes":16777216}],"feeds":feeds})).unwrap();
    let mut run = crawl_run(TenantId::new(), config);
    run.created_at = now;
    run
}
pub(super) async fn document(status: u16) -> crawlx_extract::Document {
    let mut fetch = crawlx_core::config::Fetch::default();
    fetch.extra_headers.insert("x-custom", "hdrCanary742");
    fetch
        .cookies
        .push(crawlx_core::request_controls::FetchCookie::new(
            "session",
            "cookieCanary853",
        ));
    let controls = crawlx_core::request_controls::RequestControls::resolve(&fetch, "fixture.test", None)
        .await
        .unwrap();
    let captcha = crawlx_core::captcha::CaptchaSecrets::default();
    captcha
        .register(crawlx_core::secret::SecretOr::secret("captchaCanary953".into()))
        .unwrap();
    let options = crawlx_extract::ExtractOptions {
        content: Some(crawlx_core::extraction::ExtractionPolicyV1::default()),
        acquisition_validation: Some(crate::acquisition::context(
            &crawlx_core::acquisition::AcquisitionPolicyV1::default(),
            Some(status),
            false,
        )),
        ..crawlx_extract::ExtractOptions::default()
    };
    crate::acquisition::extract_document_with_secrets(
        b"<html><body><article><h1>hdrCanary<span>742</span> cookieCanary<i>853</i> captchaCanary<b>953</b></h1><p>A complete native privacy fixture paragraph with enough text for article selection. This paragraph remains actual canonical content after secret projection.</p></article></body></html>",
        &url::Url::parse("https://fixture.test/article").unwrap(),&options,&controls,&captcha).unwrap()
}
async fn register(repo: &MemoryStore) -> WorkerId {
    let id = WorkerId::new();
    repo.register_worker(id, "fixture", "1").await.unwrap();
    repo.publish_acquisition_capabilities(
        id,
        &[crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
            "fixture", "1",
        )],
    )
    .await
    .unwrap();
    let mut facts = crawlx_core::data_capabilities::WorkerDataCapabilitiesV1::default();
    facts.destinations.insert("fixture".into(), true);
    repo.publish_data_capabilities(id, &facts).await.unwrap();
    id
}

struct HeldArticlePut {
    entered: tokio::sync::Notify,
    release: CancellationToken,
    puts: AtomicUsize,
}

struct ReleaseArticlePut(CancellationToken);

impl Drop for ReleaseArticlePut {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct HeldArticleBlobs {
    actual: Arc<FsBlobs>,
    held: Arc<HeldArticlePut>,
}

#[async_trait]
impl ArtifactBlobs for HeldArticleBlobs {
    fn bucket(&self) -> &str {
        self.actual.bucket()
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        if self.held.puts.fetch_add(1, Ordering::SeqCst) == 0 {
            // ObjectArtifactStore reaches this only after canonical approval.
            // Keep the real filesystem write pending, not an approved-byte echo.
            self.held.entered.notify_one();
            self.held.release.cancelled().await;
        }
        self.actual.put(key, bytes).await
    }

    async fn reader(&self, key: &str) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        self.actual.reader(key).await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.actual.get(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        self.actual.exists(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.actual.delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<BlobEntry>, StoreError> {
        self.actual.list(prefix).await
    }
}

#[derive(Clone, Copy)]
enum ArticleConsumer {
    Dataset,
    Cache,
    Feed,
}

impl ArticleConsumer {
    async fn write(
        self,
        artifacts: &ObjectArtifactStore<HeldArticleBlobs>,
        cpu: &crate::runtime::CpuPool,
        run: &CrawlRun,
        page: i64,
        document: Box<crawlx_extract::Document>,
    ) -> Result<usize, StoreError> {
        let source = format!("{}:document:{page}", run.id);
        let digest = document.article.as_ref().unwrap().main_digest;
        assert!(document.validation.as_ref().unwrap().content_accepted);
        assert_eq!(
            document.article.as_ref().unwrap().privacy_projection_version,
            Some(1)
        );
        let mut canonical = Vec::new();
        write_article(&mut canonical, &document, ArticleFormat::Json).unwrap();
        let mut feed = Vec::new();
        let mut stream = ArticleStream::begin(&mut feed, ArticleFormat::Jsonl).unwrap();
        stream.push(&source, &document).unwrap();
        stream.finish().unwrap();
        let references = match self {
            Self::Dataset => {
                let (returned, accepted, batches) =
                    prepare_article_acceptance(artifacts, cpu, run, page, document, true).await?;
                assert_eq!(returned.article.as_ref().unwrap().main_digest, digest);
                assert_eq!(accepted.len(), 1);
                assert_eq!(accepted[0].items.len(), 1);
                assert_eq!(accepted[0].items[0].source_document, Some(digest));
                assert_eq!(batches.len(), 1);
                let reference = accepted[0].items[0].content.artifact();
                assert_eq!(artifacts.get(reference).await?, canonical);
                assert_eq!(artifacts.get(batches[0].content.artifact()).await?, feed);
                vec![reference.clone(), batches[0].content.artifact().clone()]
            }
            Self::Cache => {
                let (returned, reference) =
                    store_article_cache(artifacts, cpu, run, page, document, true).await?;
                let reference = reference.unwrap();
                let (restored, deadline, restored_source) = load_article_cache(
                    artifacts,
                    cpu,
                    run,
                    &reference,
                    run.created_at,
                    Some(&crawlx_core::extraction::ExtractionPolicyV1::default()),
                )
                .await?;
                assert_eq!(restored_source, source);
                assert_eq!(deadline, article_deadline(run, None).unwrap());
                assert_eq!(restored.article.as_ref().unwrap().main_digest, digest);
                assert_eq!(restored.text, returned.text);
                assert_eq!(restored.comments, returned.comments);
                assert_eq!(restored.markdown, returned.markdown);
                assert_eq!(restored.html, returned.html);
                let mut restored_canonical = Vec::new();
                write_article(&mut restored_canonical, &restored, ArticleFormat::Json).unwrap();
                assert_eq!(restored_canonical, canonical);
                vec![reference.artifact]
            }
            Self::Feed => {
                let (returned, batches) = prepare_article_feeds_inner(
                    artifacts, cpu, run, page, "articles", document, true, None, &source,
                )
                .await?;
                assert_eq!(returned.article.as_ref().unwrap().main_digest, digest);
                assert_eq!(batches.len(), 1);
                let reference = batches[0].content.artifact();
                assert_eq!(artifacts.get(reference).await?, feed);
                vec![reference.clone()]
            }
        };
        for reference in &references {
            let row = artifacts.row(reference.id).await?.unwrap();
            assert_eq!(row.run, run.id);
            assert_eq!(row.tenant, run.tenant);
            assert_eq!(row.expires_at, article_deadline(run, None));
            let bytes = artifacts.get(reference).await?;
            assert_eq!(row.digest, reference.digest);
            let text = std::str::from_utf8(&bytes).unwrap();
            for secret in ["hdrCanary742", "cookieCanary853", "captchaCanary953"] {
                assert!(!text.contains(secret));
            }
        }
        Ok(references.len())
    }
}

async fn article_reservation_survives_real_put(holder: ArticleConsumer) {
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    ));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let actual = Arc::new(FsBlobs::open(dir.path()).await.unwrap());
    let held = Arc::new(HeldArticlePut {
        entered: tokio::sync::Notify::new(),
        release: CancellationToken::new(),
        puts: AtomicUsize::new(0),
    });
    let artifacts = ObjectArtifactStore::new(
        HeldArticleBlobs {
            actual: actual.clone(),
            held: held.clone(),
        },
        repo.clone(),
        clock.clone(),
    )
    .with_index(repo.clone());
    let mut run = run(RetentionMode::Standard, clock.now(), &["jsonl"]);
    // A feed charges its declared maximum, not the dataset's maximum. Give
    // only the held feed the full limit; all competing feeds remain 1 MiB.
    if matches!(holder, ArticleConsumer::Feed) {
        run.config.datasets.feeds[0].max_batch_bytes = MAX_VALUE_BYTES;
    }
    repo.create(&run, None).await.unwrap();
    let worker = register(&repo).await;
    repo.append_batch(RequestBatchV1::new(
        run.tenant,
        run.id,
        "anonymous".into(),
        crawlx_core::hash::Digest::of("fixture", b"article-reservation"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://fixture.test/article"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let lease = repo
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let maximum = usize::try_from(MAX_VALUE_BYTES).unwrap();
    let cpu = crate::runtime::CpuPool::with_article_output_limit(
        NonZeroUsize::new(2).unwrap(),
        NonZeroU32::new(u32::try_from(MAX_VALUE_BYTES).unwrap()).unwrap(),
    );
    let dataset_cpu = cpu.clone();
    let cache_cpu = cpu.clone();
    let feed_cpu = cpu.clone();
    // The release guard and pinned future both drop on timeout or panic.
    // No detached task can retain the filesystem fixture or held put.
    let release = ReleaseArticlePut(held.release.clone());
    let original = Box::new(document(200).await);
    let mut first = Box::pin(holder.write(&artifacts, &cpu, &run, lease.0.id, original));
    tokio::select! {
        () = held.entered.notified() => {}
        result = &mut first => panic!("article write did not reach held filesystem put: {result:?}"),
    }
    assert_eq!(cpu.article_output_available(), 0);
    assert_eq!(held.puts.load(Ordering::SeqCst), 1);
    assert!(actual.list("").await.unwrap().is_empty());

    let mut contenders = run.clone();
    contenders.config.datasets.feeds[0].max_batch_bytes = 1_048_576;
    let dataset = Box::new(document(200).await);
    let cache = Box::new(document(200).await);
    let feed = Box::new(document(200).await);
    let (dataset, cache, feed) = tokio::join!(
        ArticleConsumer::Dataset.write(&artifacts, &dataset_cpu, &contenders, lease.0.id, dataset),
        ArticleConsumer::Cache.write(&artifacts, &cache_cpu, &contenders, lease.0.id, cache),
        ArticleConsumer::Feed.write(&artifacts, &feed_cpu, &contenders, lease.0.id, feed),
    );
    for (result, requested) in [(dataset, maximum), (cache, maximum), (feed, 1_048_576)] {
        match result {
            Err(StoreError::ResourceExhausted {
                resource,
                requested: actual_requested,
                available,
                source,
            }) => {
                assert_eq!(resource, "article_output_reservation");
                assert_eq!(actual_requested, requested);
                assert_eq!(available, 0);
                assert!(source.is_none());
            }
            other => panic!("expected article reservation refusal, got {other:?}"),
        }
    }
    assert_eq!(held.puts.load(Ordering::SeqCst), 1);
    assert!(actual.list("").await.unwrap().is_empty());
    assert!(repo.items(run.id, "articles", 0, 10).await.unwrap().is_empty());
    assert_eq!(cpu.article_output_available(), 0);

    drop(release);
    let first_count = first.await.unwrap();
    assert_eq!(cpu.article_output_available(), maximum);
    let mut artifact_count = first_count;
    for consumer in [
        ArticleConsumer::Dataset,
        ArticleConsumer::Cache,
        ArticleConsumer::Feed,
    ] {
        // Repeat the exact valid source and request identity rejected above.
        artifact_count += consumer
            .write(
                &artifacts,
                &cpu,
                &contenders,
                lease.0.id,
                Box::new(document(200).await),
            )
            .await
            .unwrap();
        assert_eq!(cpu.article_output_available(), maximum);
    }
    let indexes = actual.list("_index/").await.unwrap();
    assert_eq!(indexes.len(), artifact_count);
}

#[tokio::test]
async fn dataset_reservation_spans_real_put_rejects_cache_and_feed_then_releases_before_default_feed() {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        article_reservation_survives_real_put(ArticleConsumer::Dataset),
    )
    .await
    .expect("dataset reservation regression timed out");
}

#[tokio::test]
async fn cache_reservation_spans_real_put_and_rejected_dataset_cache_and_feed_recover() {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        article_reservation_survives_real_put(ArticleConsumer::Cache),
    )
    .await
    .expect("cache reservation regression timed out");
}

#[tokio::test]
async fn feed_reservation_spans_real_put_and_rejected_dataset_cache_and_feed_recover() {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        article_reservation_survives_real_put(ArticleConsumer::Feed),
    )
    .await
    .expect("feed reservation regression timed out");
}

#[tokio::test]
async fn actual_parser_projection_flows_through_atomic_dataset_outbox_and_all_article_serializers() {
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    repo.set_dataset_delivery(buffer.clone());
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone())
        .with_zdr_buffer(buffer);
    let run = run(
        RetentionMode::Zdr,
        clock.now(),
        &[
            "json",
            "jsonl",
            "csv",
            "xml",
            "tei",
            "text",
            "markdown",
            "html",
            "search_json",
        ],
    );
    repo.create(&run, None).await.unwrap();
    let worker = register(&repo).await;
    repo.append_batch(RequestBatchV1::new(
        run.tenant,
        run.id,
        "anonymous".into(),
        crawlx_core::hash::Digest::of("fixture", b"article"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://fixture.test/article"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let lease = repo
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let document = document(200).await;
    assert!(document.validation.as_ref().unwrap().content_accepted);
    let source_document = document.article.as_ref().unwrap().main_digest;
    let cpu = crate::runtime::CpuPool::default();
    let (_, accepted, outbox) =
        prepare_article_acceptance(&artifacts, &cpu, &run, lease.0.id, Box::new(document), true)
            .await
            .unwrap();
    assert_eq!(accepted.len(), 1);
    assert_eq!(outbox.len(), 9);
    assert_eq!(accepted[0].items[0].source_document, Some(source_document));
    let reference = accepted[0].items[0].content.artifact().clone();
    for batch in &outbox {
        let bytes = artifacts.get(batch.content.artifact()).await.unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for secret in ["hdrCanary742", "cookieCanary853", "captchaCanary953"] {
            assert!(!text.contains(secret));
        }
        match batch.feed.as_str() {
            "feed_json" => assert!(serde_json::from_slice::<Value>(&bytes).unwrap().is_array()),
            "feed_jsonl" => assert!(serde_json::from_slice::<Value>(&bytes)
                .unwrap()
                .get("document")
                .is_some()),
            "feed_csv" => assert!(text.starts_with("source,title,source_url,text,comments\r\n")),
            "feed_xml" => assert!(text.contains("<articles")),
            "feed_tei" => assert!(text.contains("<teiCorpus") && text.contains("</teiCorpus>")),
            "feed_search_json" => assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["version"], 1),
            _ => assert!(!text.is_empty()),
        }
    }
    let mut commit =
        RequestCommitV1::terminal(run.id, lease.0.id, lease.1, 1, FrontierStatus::Succeeded, None);
    commit.accepted = accepted;
    commit.outbox = outbox;
    repo.commit_fenced(commit).await.unwrap();
    assert_eq!(repo.items(run.id, "articles", 0, 10).await.unwrap().len(), 1);
    let claims = repo.claim(run.id, worker, 10, 60).await.unwrap();
    assert_eq!(claims.len(), 9);
    for claim in claims {
        repo.acknowledge(run.id, claim.id, claim.fence).await.unwrap();
    }
    assert!(artifacts.get(&reference).await.is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn report_only_error_pages_and_partial_articles_never_become_dataset_items() {
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let run = run(RetentionMode::Standard, clock.now(), &["jsonl"]);
    repo.create(&run, None).await.unwrap();
    let error = document(403).await;
    let acquisition_accepted = error.validation.as_ref().unwrap().content_accepted;
    let cpu = crate::runtime::CpuPool::default();
    let result = prepare_article_acceptance(&artifacts, &cpu, &run, 1, Box::new(error), acquisition_accepted)
        .await
        .unwrap();
    assert!(result.1.is_empty() && result.2.is_empty());
    let mut partial = document(200).await;
    partial.article.as_mut().unwrap().quality.status = crawlx_core::extraction::QualityStatusV1::Partial;
    let result = prepare_article_acceptance(&artifacts, &cpu, &run, 1, Box::new(partial), true)
        .await
        .unwrap();
    assert!(result.1.is_empty() && result.2.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn secret_registered_while_article_waits_for_cpu_refuses_dataset_and_feed_publication() {
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let run = run(RetentionMode::Standard, clock.now(), &["jsonl"]);
    repo.create(&run, None).await.unwrap();
    let mut document = Box::new(document(200).await);
    let secret = "lateArticleDeliveryCanary619";
    document.article.as_mut().unwrap().metadata.title.value = Some(secret.into());
    let cpu = crate::runtime::CpuPool::with_permits(std::num::NonZeroUsize::new(1).unwrap());
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let occupied = cpu.clone();
    let blocker = tokio::spawn(async move {
        occupied
            .run(move || {
                started.send(()).unwrap();
                blocked.recv().unwrap();
            })
            .await
            .unwrap();
    });
    ready.await.unwrap();
    let mut acceptance = Box::pin(prepare_article_acceptance(
        &artifacts, &cpu, &run, 1, document, true,
    ));
    let first_poll =
        std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(acceptance.as_mut(), cx)))
            .await;
    let registered = crawlx_core::secret::register_secret(secret);
    release.send(()).unwrap();
    blocker.await.unwrap();
    assert!(registered);
    assert!(first_poll.is_pending());
    assert!(matches!(acceptance.await, Err(StoreError::RetentionDenied(_))));
    assert!(repo.items(run.id, "articles", 0, 10).await.unwrap().is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn excluded_author_stays_rejected_after_secret_projection_and_never_enters_feeds_or_cache() {
    use crawlx_core::extraction::{ExtractionPolicyV1, QualityReasonV1, QualityStatusV1};
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let controls = crawlx_core::request_controls::RequestControls::resolve(
        &crawlx_core::config::Fetch::default(),
        "fixture.test",
        None,
    )
    .await
    .unwrap();
    let captcha = crawlx_core::captcha::CaptchaSecrets::default();
    captcha
        .register(crawlx_core::secret::SecretOr::secret("Excluded Writer".into()))
        .unwrap();
    let mut policy = ExtractionPolicyV1::default();
    policy.excluded_authors = vec!["excluded writer".into()];
    let options = crawlx_extract::ExtractOptions {
        content: Some(policy),
        acquisition_validation: Some(crate::acquisition::context(
            &crawlx_core::acquisition::AcquisitionPolicyV1::default(),
            Some(200),
            false,
        )),
        ..crawlx_extract::ExtractOptions::default()
    };
    let doc = crate::acquisition::extract_document_with_secrets(
        b"<html><head><meta name='author' content='Excluded Writer'></head><body><article><p>Independent reporting preserves acquisition evidence while the configured author policy blocks publication into article datasets.</p></article></body></html>",
        &url::Url::parse("https://fixture.test/article").unwrap(), &options, &controls, &captcha).unwrap();
    assert!(doc.validation.as_ref().unwrap().content_accepted);
    assert_eq!(
        doc.article.as_ref().unwrap().quality.status,
        QualityStatusV1::Rejected
    );
    assert_eq!(
        doc.article.as_ref().unwrap().quality.reasons,
        vec![QualityReasonV1::AuthorExcluded]
    );
    assert!(doc.text.contains("Independent reporting"));
    // Document also carries legacy raw metadata. Ingestion uses this canonical
    // serializer, never serde serialization of the unrestricted Document.
    let mut approved = Vec::new();
    write_article(&mut approved, &doc, ArticleFormat::Json).unwrap();
    assert!(!String::from_utf8(approved).unwrap().contains("Excluded Writer"));
    let cpu = crate::runtime::CpuPool::default();
    let mut doc = Box::new(doc);
    for mode in [RetentionMode::Standard, RetentionMode::Zdr] {
        let run = run(mode, clock.now(), &["jsonl"]);
        repo.create(&run, None).await.unwrap();
        let (returned, items, deliveries) = prepare_article_acceptance(&artifacts, &cpu, &run, 1, doc, true)
            .await
            .unwrap();
        doc = returned;
        assert!(items.is_empty() && deliveries.is_empty());
        let (returned, reference) = store_article_cache(&artifacts, &cpu, &run, 1, doc, true)
            .await
            .unwrap();
        doc = returned;
        assert!(reference.is_none());
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn retained_article_cache_preserves_real_text_formats_identity_and_original_physical_deadline() {
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone());
    let source = run(RetentionMode::Standard, clock.now(), &["markdown", "html", "tei"]);
    repo.create(&source, None).await.unwrap();
    let cpu = crate::runtime::CpuPool::default();
    let original = Box::new(document(200).await);
    let (original, reference) = store_article_cache(&artifacts, &cpu, &source, 10, original, true)
        .await
        .unwrap();
    let reference = reference.unwrap();
    clock.advance_ms(3_600_000);
    let (saved, deadline, source_id) = load_article_cache(
        &artifacts,
        &cpu,
        &source,
        &reference,
        clock.now(),
        Some(&crawlx_core::extraction::ExtractionPolicyV1::default()),
    )
    .await
    .unwrap();
    assert_eq!(saved.text, original.text);
    assert_eq!(saved.comments, original.comments);
    assert_eq!(saved.markdown, original.markdown);
    assert_eq!(saved.html, original.html);
    assert_eq!(source_id, format!("{}:document:10", source.id));
    let mut target = run(
        RetentionMode::Standard,
        clock.now(),
        &["jsonl", "markdown", "html", "tei"],
    );
    target.config.retention.days = 7;
    repo.create(&target, None).await.unwrap();
    let (_, accepted, outbox) = prepare_article_acceptance_retained(
        &artifacts,
        &cpu,
        &target,
        20,
        Box::new(saved),
        true,
        Some(deadline),
        &source_id,
    )
    .await
    .unwrap();
    assert_eq!(accepted[0].items[0].expires_at, Some(deadline));
    for batch in outbox {
        assert_eq!(batch.expires_at, deadline);
        assert_eq!(
            artifacts
                .row(batch.content.artifact().id)
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            Some(deadline)
        );
        let bytes = artifacts.get(batch.content.artifact()).await.unwrap();
        if batch.feed == "feed_jsonl" {
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap()["source"],
                source_id
            );
        }
    }
    clock.advance_ms(86_400_000);
    assert!(load_article_cache(
        &artifacts,
        &cpu,
        &source,
        &reference,
        clock.now(),
        Some(&crawlx_core::extraction::ExtractionPolicyV1::default()),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn approved_local_sink_retries_same_batch_without_overwrite_or_duplicate_file() {
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let artifacts_dir = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(artifacts_dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let run = run(RetentionMode::Standard, clock.now(), &["jsonl"]);
    repo.create(&run, None).await.unwrap();
    let cpu = crate::runtime::CpuPool::default();
    let (_, _, outbox) =
        prepare_article_acceptance(&artifacts, &cpu, &run, 1, Box::new(document(200).await), true)
            .await
            .unwrap();
    let batch = &outbox[0];
    let bytes = Bytes::from(artifacts.get(batch.content.artifact()).await.unwrap());
    let cfg = crate::WorkerConfig::default();
    let authority = DeliveryAuthority {
        policy: Arc::new(cfg.egress.policy_for_run(&run.config, None).unwrap()),
        resolver: cfg.egress.resolver_for(&run.config).unwrap(),
        governor: Arc::new(crawlx_fetch::OriginGovernor::new(
            crawlx_fetch::GovernorConfig::from_politeness(&run.config.politeness, run.seed),
        )),
        cancel: CancellationToken::new(),
    };
    let sink = LocalDestination::open(root.path()).await.unwrap();
    assert!(!sink.duplicate_possible());
    sink.send(&authority, &run, batch, bytes.clone()).await.unwrap();
    sink.send(&authority, &run, batch, bytes).await.unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert!(sink
        .send(&authority, &run, batch, Bytes::from_static(b"different bytes"))
        .await
        .is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    let mut zdr = run.clone();
    zdr.config.retention.mode = RetentionMode::Zdr;
    assert!(sink
        .send(&authority, &zdr, batch, Bytes::from_static(b"private"))
        .await
        .is_err());
}

#[test]
fn search_receipts_require_exact_operation_identity_and_allow_idempotent_missing_delete() {
    assert!(search_acknowledged(
        &json!({"errors":false,"items":[{"index":{"_id":"logical:1","status":201}}]}),
        "logical:1",
        false
    ));
    assert!(!search_acknowledged(
        &json!({"errors":false,"items":[{"index":{"_id":"other","status":201}}]}),
        "logical:1",
        false
    ));
    assert!(!search_acknowledged(
        &json!({"errors":true,"items":[{"index":{"_id":"logical:1","status":400,"error":{}}}]}),
        "logical:1",
        false
    ));
    assert!(search_acknowledged(
        &json!({"errors":false,"items":[{"delete":{"_id":"logical:1","status":404,"result":"not_found"}}]}),
        "logical:1",
        true
    ));
    assert!(!search_acknowledged(
        &json!({"errors":false,"items":[{"delete":{"_id":"logical:1","status":404,"result":"not_found"}}]}),
        "logical:1",
        false
    ));
    assert!(!search_acknowledged(
        &json!({"errors":false,"items":[]}),
        "logical:1",
        false
    ));
}

#[test]
fn generic_projection_cannot_advertise_article_only_serializers() {
    for serializer in ["tei", "markdown", "html", "search_json"] {
        let config: crawlx_core::dataset::DatasetConfigV1 = serde_json::from_value(json!({"version":1,
            "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":1048576}],
            "feeds":[{"id":"fixture","source":"items","serializer":serializer,"serializerVersion":1,
                "destination":"fixture","maxBatchItems":1,"maxBatchBytes":1048576}]}))
        .unwrap();
        assert!(
            config.validate().is_err(),
            "wrong input schema must fail before request admission"
        );
    }
}

struct CrashBeforeReceipt {
    repo: Arc<MemoryStore>,
    fail: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl DeliveryOutboxRepo for CrashBeforeReceipt {
    async fn ready_runs(
        &self,
        after: Option<crawlx_core::CrawlRunId>,
        limit: u16,
    ) -> Result<Vec<crawlx_core::CrawlRunId>, StoreError> {
        self.repo.ready_runs(after, limit).await
    }
    async fn maintain(&self, run: crawlx_core::CrawlRunId) -> Result<(), StoreError> {
        self.repo.maintain(run).await
    }
    async fn expire(&self, run: crawlx_core::CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        self.repo.expire(run, id, fence).await
    }
    async fn claim(
        &self,
        run: crawlx_core::CrawlRunId,
        worker: WorkerId,
        limit: u16,
        lease: u16,
    ) -> Result<Vec<DurableDeliveryOutboxV1>, StoreError> {
        self.repo.claim(run, worker, limit, lease).await
    }
    async fn acknowledge(&self, run: crawlx_core::CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        if self.fail.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::Backend(
                "fixture crash after send before receipt".into(),
            ));
        }
        self.repo.acknowledge(run, id, fence).await
    }
    async fn retry(
        &self,
        run: crawlx_core::CrawlRunId,
        id: i64,
        fence: i64,
        at: crawlx_core::Timestamp,
    ) -> Result<(), StoreError> {
        self.repo.retry(run, id, fence, at).await
    }
}

#[tokio::test]
async fn real_registry_drain_retries_after_local_send_receipt_crash_without_losing_accepted_item() {
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let artifacts_dir = tempfile::tempdir().unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let mut stores = Stores::over_memory(repo.clone(), artifacts_dir.path())
        .await
        .unwrap();
    stores.delivery = Arc::new(CrashBeforeReceipt {
        repo: repo.clone(),
        fail: std::sync::atomic::AtomicBool::new(true),
    });
    let run = run(RetentionMode::Standard, clock.now(), &["jsonl"]);
    stores.runs.create(&run, None).await.unwrap();
    let worker = register(&repo).await;
    stores
        .frontier
        .append_batch(RequestBatchV1::new(
            run.tenant,
            run.id,
            "anonymous".into(),
            crawlx_core::hash::Digest::of("fixture", b"local-drain"),
            vec![RequestEnvelopeV1::get(
                canonical_url("https://fixture.test/article"),
                0,
                None,
            )],
        ))
        .await
        .unwrap();
    let lease = stores
        .frontier
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let cpu = crate::runtime::CpuPool::default();
    let (_, accepted, outbox) = prepare_article_acceptance(
        stores.artifacts.as_ref(),
        &cpu,
        &run,
        lease.0.id,
        Box::new(document(200).await),
        true,
    )
    .await
    .unwrap();
    let expected = stores.artifacts.get(outbox[0].content.artifact()).await.unwrap();
    let mut commit =
        RequestCommitV1::terminal(run.id, lease.0.id, lease.1, 1, FrontierStatus::Succeeded, None);
    commit.accepted = accepted;
    commit.outbox = outbox;
    stores.request_commits.commit_fenced(commit).await.unwrap();
    let mut registry = DeliveryRegistry::new();
    registry
        .register(
            "fixture".into(),
            Arc::new(LocalDestination::open(output_dir.path()).await.unwrap()),
        )
        .unwrap();
    let cfg = crate::WorkerConfig::default();
    let authority = DeliveryAuthority {
        policy: Arc::new(cfg.egress.policy_for_run(&run.config, None).unwrap()),
        resolver: cfg.egress.resolver_for(&run.config).unwrap(),
        governor: Arc::new(crawlx_fetch::OriginGovernor::new(
            crawlx_fetch::GovernorConfig::from_politeness(&run.config.politeness, run.seed),
        )),
        cancel: CancellationToken::new(),
    };
    assert!(registry
        .drain_once(&stores, &run, worker, clock.as_ref(), &authority)
        .await
        .is_err());
    assert_eq!(
        stores
            .datasets
            .items(run.id, "articles", 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(std::fs::read_dir(output_dir.path()).unwrap().count(), 1);
    clock.advance_ms(61_000);
    assert_eq!(
        registry
            .drain_once(&stores, &run, worker, clock.as_ref(), &authority)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        registry
            .drain_once(&stores, &run, worker, clock.as_ref(), &authority)
            .await
            .unwrap(),
        0
    );
    let files: Vec<_> = std::fs::read_dir(output_dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(std::fs::read(&files[0]).unwrap(), expected);
    assert_eq!(
        stores
            .datasets
            .items(run.id, "articles", 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}
