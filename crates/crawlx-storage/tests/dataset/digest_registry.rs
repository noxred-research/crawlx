//! Same claim contract for memory and PostgreSQL, including rejected ingestion and rollback.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crawlx_core::digest_registry::{ContentDedupeClaimV1, DigestDispositionV1, DigestRegistryRepo};
use crawlx_core::extraction::{
    ArticleMetadataV1, ContentDigestsV1, DedupeReportV1, DocumentEnvelopeV1, QualityOutcomeV1,
    QualityStatusV1,
};
use crawlx_core::repo::{PageRecord, PageRepo};
use crawlx_core::TrustLane;

fn document() -> DocumentEnvelopeV1 {
    let mut article = DocumentEnvelopeV1::new(
        Digest::of("registry-test", b"policy"),
        Digest::of("registry-test", b"envelope-main"),
        "article".into(),
        0,
        Vec::new(),
        ArticleMetadataV1::default(),
        QualityOutcomeV1::new(QualityStatusV1::Accepted, Vec::new(), 100, 1, 1),
    );
    article.privacy_projection_version = Some(1);
    let mut report = DedupeReportV1::new(
        ContentDigestsV1::new(
            Digest::of("registry-test", b"raw"),
            Digest::of("registry-test", b"page"),
            Digest::of("registry-test", b"dedupe-main"),
            None,
            1,
        ),
        true,
        1,
        0,
        "https://example.test".into(),
    );
    report.content_sha256 = Some("12".repeat(32));
    article.dedupe = Some(report);
    article
}
fn claim(run: &CrawlRun, role: &[u8]) -> ContentDedupeClaimV1 {
    ContentDedupeClaimV1::from_document(
        run.tenant,
        run.id,
        Digest::of("registry-test/role", role),
        &document(),
    )
    .unwrap()
}
fn retained_deadline(run: &CrawlRun) -> crawlx_core::Timestamp {
    chrono::DateTime::from_timestamp_micros((run.created_at + Duration::hours(1)).timestamp_micros()).unwrap()
}
fn page_commit(
    run: &CrawlRun,
    entry: &(crawlx_core::repo::FrontierEntry, i64),
    content: &DatasetContentV1,
    name: &str,
) -> RequestCommitV1 {
    let mut result =
        RequestCommitV1::terminal(run.id, entry.0.id, entry.1, 1, FrontierStatus::Succeeded, None);
    let size = u64::try_from(CANARY.len()).unwrap();
    // Bound accepted content as well as delivery to its approved source deadline.
    // PostgreSQL stores microseconds, so retained deadlines use that precision at issuance.
    let delivery_deadline = content.expires_at().unwrap_or_else(|| retained_deadline(run));
    let mut item = AcceptedItemV1::new(
        name.into(),
        "fixture_v1".into(),
        "document_item_v1".into(),
        "fixture_v1".into(),
        content.clone(),
        size,
    );
    item.expires_at = Some(delivery_deadline);
    result
        .accepted
        .push(AcceptedBatchV1::new("items".into(), vec![item]));
    for feed in ["first", "second"] {
        result.outbox.push(DeliveryBatchV1::for_request(
            feed.into(),
            format!("request.{}.{}", entry.0.id, feed),
            content.clone(),
            size,
            delivery_deadline,
        ));
    }
    result.content_dedupe = Some(claim(run, b"anonymous"));
    result.page = Some(PageRecord {
        run: run.id,
        frontier_id: entry.0.id,
        url: entry.0.url.clone(),
        status: 200,
        content_type: Some("text/html".into()),
        content_digest: Digest::of("registry-test", name.as_bytes()),
        title: None,
        markdown: None,
        html: None,
        links: Vec::new(),
        fetched_at: run.created_at,
        lane: TrustLane::Diagnostic,
        metadata: serde_json::json!({
            "extraction":{"quality":document().quality,"content":{"preArbitration":true}},
            "extensions":{"content":{"preArbitration":true},"outcome":"accepted"},
            "scrape":{"meta":{"article":document(),"articleDocumentRef":{"preArbitration":true},
                "articleCacheSourceRun":run.id,"extensionItem":{"accepted":true}}}
        }),
    });
    result
}

async fn contract<R>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: crawlx_core::Timestamp,
    zdr: bool,
) -> (CrawlRun, DatasetContentV1)
where
    R: RunRepo
        + FrontierRepo
        + RequestCommitRepo
        + DigestRegistryRepo
        + DatasetRepo
        + DeliveryOutboxRepo
        + WorkerRegistry
        + PageRepo,
{
    let mut run = run(tenant, now);
    if !zdr {
        run.config.retention.mode = RetentionMode::Standard;
        run.config.retention.days = 7;
    }
    run.config_digest = run.config.digest().unwrap();
    repo.create(&run, None).await.unwrap();
    let worker_a = worker(repo).await;
    let worker_b = worker(repo).await;
    let requests = (0..8)
        .map(|index| {
            RequestEnvelopeV1::get(
                canonical_url(&format!("https://example.test/digest/{index}")),
                0,
                None,
            )
        })
        .collect();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("registry-test/batch", b"initial"),
        requests,
    ))
    .await
    .unwrap();
    let a = repo
        .lease_batch_fenced(run.id, worker_a, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let b = repo
        .lease_batch_fenced(run.id, worker_b, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_ne!(a.0.id, b.0.id);
    let approved = crawlx_core::secret::Redactor::new()
        .verify_canonical(CANARY)
        .unwrap();
    let artifact = ArtifactSink::over(artifacts)
        .put_dataset_until(
            run.id,
            a.0.id,
            "fixture",
            "application/json",
            &approved,
            retained_deadline(&run),
        )
        .await
        .unwrap();
    let content = artifacts
        .dataset_content(run.id, a.0.id, &artifact, u64::try_from(CANARY.len()).unwrap())
        .await
        .unwrap();
    let (one, two) = tokio::join!(
        repo.commit_fenced(page_commit(&run, &a, &content, "a")),
        repo.commit_fenced(page_commit(&run, &b, &content, "b")),
    );
    one.unwrap();
    two.unwrap();
    let first = repo.digest_outcome(run.id, a.0.id).await.unwrap().unwrap();
    let second = repo.digest_outcome(run.id, b.0.id).await.unwrap().unwrap();
    assert_ne!(first.is_duplicate(), second.is_duplicate());
    let canonical = if first.is_duplicate() { &second } else { &first };
    let duplicate = if first.is_duplicate() { &first } else { &second };
    assert_eq!(canonical.disposition, DigestDispositionV1::Canonical);
    assert_eq!(duplicate.first_frontier_id, canonical.first_frontier_id);
    assert_eq!(duplicate.committed_at, canonical.committed_at);
    assert_eq!(repo.items(run.id, "items", 0, 100).await.unwrap().len(), 1);
    assert_eq!(
        repo.claim(run.id, worker_a, 10, 60).await.unwrap().len(),
        2,
        "only canonical's two delivery intents publish"
    );
    let loser = if first.is_duplicate() { a.0.id } else { b.0.id };
    if !zdr {
        let stored = repo.get_committed(run.id, loser).await.unwrap().unwrap();
        assert_eq!(stored.metadata["extraction"]["quality"]["status"], "rejected");
        assert_eq!(
            stored.metadata["extraction"]["quality"]["reasons"],
            serde_json::json!(["duplicate_main"])
        );
        assert_eq!(
            stored.metadata["extraction"]["parseQuality"]["status"],
            "accepted"
        );
        assert!(stored.metadata["extraction"].get("content").is_none());
        assert!(stored.metadata["extensions"].get("content").is_none());
        assert_eq!(stored.metadata["extensions"]["outcome"], "rejected");
        assert_eq!(
            stored.metadata["scrape"]["meta"]["article"]["quality"]["status"],
            "rejected"
        );
        assert_eq!(
            stored.metadata["scrape"]["meta"]["articleParseQuality"]["status"],
            "accepted"
        );
        assert!(stored.metadata["scrape"]["meta"]
            .get("articleDocumentRef")
            .is_none());
        assert!(stored.metadata["scrape"]["meta"].get("extensionItem").is_none());
    }

    let remaining = repo.lease_batch_fenced(run.id, worker_a, 6).await.unwrap();
    assert_eq!(remaining.len(), 6);
    // A new scope plus failed CAS reaches registry arbitration but rolls back every effect.
    let mut failed = page_commit(&run, &remaining[0], &content, "rollback");
    failed.content_dedupe = Some(claim(&run, b"rollback-scope"));
    failed.state_deltas.push(delta(&content, "state", 99));
    failed.state_deltas[0].expires_at = Some(content.expires_at().unwrap_or_else(|| retained_deadline(&run)));
    assert!(repo.commit_fenced(failed).await.is_err());
    assert!(repo
        .digest_outcome(run.id, remaining[0].0.id)
        .await
        .unwrap()
        .is_none());
    let mut after = page_commit(&run, &remaining[1], &content, "after-rollback");
    after.content_dedupe = Some(claim(&run, b"rollback-scope"));
    repo.commit_fenced(after).await.unwrap();
    let outcome = repo
        .digest_outcome(run.id, remaining[1].0.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!outcome.is_duplicate());
    assert_eq!(outcome.first_frontier_id, remaining[1].0.id);

    let mut later = page_commit(&run, &remaining[2], &content, "later-worker");
    // Different content hash still duplicates the earlier main stage.
    later.content_dedupe.as_mut().unwrap().content = Digest::of("registry-test", b"new-title");
    repo.commit_fenced(later).await.unwrap();
    assert!(repo
        .digest_outcome(run.id, remaining[2].0.id)
        .await
        .unwrap()
        .unwrap()
        .is_duplicate());
    let mut other_role = page_commit(&run, &remaining[3], &content, "other-role");
    other_role.content_dedupe = Some(claim(&run, b"other-role"));
    repo.commit_fenced(other_role).await.unwrap();
    assert!(!repo
        .digest_outcome(run.id, remaining[3].0.id)
        .await
        .unwrap()
        .unwrap()
        .is_duplicate());
    let mut optout = page_commit(&run, &remaining[4], &content, "optout");
    optout.content_dedupe = None;
    repo.commit_fenced(optout).await.unwrap();
    assert!(repo
        .digest_outcome(run.id, remaining[4].0.id)
        .await
        .unwrap()
        .is_none());
    let mut forged = page_commit(&run, &remaining[5], &content, "wrong-tenant");
    forged.content_dedupe.as_mut().unwrap().tenant = TenantId::new();
    assert!(repo.commit_fenced(forged).await.is_err());
    assert!(crawlx_storage::tenant::scope(
        TenantId::new(),
        repo.digest_outcome(run.id, canonical.first_frontier_id)
    )
    .await
    .is_err());
    assert_eq!(repo.items(run.id, "items", 0, 100).await.unwrap().len(), 4);
    let isolated = crawl_run(tenant, run.config.clone());
    repo.create(&isolated, None).await.unwrap();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        isolated.id,
        "anonymous".into(),
        Digest::of("registry-test/batch", b"isolated-run"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://example.test/digest/0"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let isolated_entry = repo
        .lease_batch_fenced(isolated.id, worker_b, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let mut isolated_commit = page_commit(&isolated, &isolated_entry, &content, "isolated-run");
    isolated_commit.accepted.clear();
    isolated_commit.outbox.clear();
    repo.commit_fenced(isolated_commit).await.unwrap();
    assert!(!repo
        .digest_outcome(isolated.id, isolated_entry.0.id)
        .await
        .unwrap()
        .unwrap()
        .is_duplicate());
    (run, content)
}

#[tokio::test]
async fn memory_digest_claim_race_rollback_scope_isolation_and_optout() {
    for zdr in [false, true] {
        let clock = Arc::new(ManualClock::new(Utc::now()));
        let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
        let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
        repo.set_dataset_delivery(buffer.clone());
        let dir = tempfile::tempdir().unwrap();
        let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(repo.clone())
            .with_zdr_buffer(buffer);
        let (run, _) = contract(repo.as_ref(), &artifacts, TenantId::new(), clock.now(), zdr).await;
        repo.purge_run(run.id).await.unwrap();
        assert!(repo.digest_outcome(run.id, 1).await.is_err());
    }
}

#[tokio::test]
async fn postgres_digest_claim_race_rollback_and_restart() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let config = PgConfig {
        schema: Some(format!("digest_registry_{}", CrawlRunId::new().0.simple())),
        ..PgConfig::default()
    };
    let pg = Pg::connect(&url, config.clone()).await.unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "digest-registry-fixture").await.unwrap();
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let (run, content) = contract(&pg, &artifacts, tenant, clock.now(), false).await;
    drop(artifacts);
    drop(pg);
    let reopened = Pg::connect(&url, config).await.unwrap();
    let worker_b = worker(&reopened).await;
    reopened
        .append_batch(RequestBatchV1::new(
            tenant,
            run.id,
            "anonymous".into(),
            Digest::of("registry-test/batch", b"restart"),
            vec![RequestEnvelopeV1::get(
                canonical_url("https://example.test/digest/restart"),
                0,
                None,
            )],
        ))
        .await
        .unwrap();
    let next = reopened
        .lease_batch_fenced(run.id, worker_b, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    // Row left leased by the forged attempt remains invisible to the restarted worker.
    reopened
        .commit_fenced(page_commit(&run, &next, &content, "restart"))
        .await
        .unwrap();
    assert!(reopened
        .digest_outcome(run.id, next.0.id)
        .await
        .unwrap()
        .unwrap()
        .is_duplicate());
    assert_eq!(reopened.items(run.id, "items", 0, 100).await.unwrap().len(), 4);
    reopened.drop_schema().await.unwrap();
}

#[test]
fn claim_binds_actual_report_stages_and_rejects_bad_versions_hashes_and_bounds() {
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let representation = Digest::of("registry-test", b"role-session-representation");
    let article = document();
    let valid = ContentDedupeClaimV1::from_document(tenant, run, representation, &article).unwrap();
    assert_eq!(valid.content, Digest::from_hex(&"12".repeat(32)).unwrap());
    assert_eq!(valid.main, article.dedupe.as_ref().unwrap().digests.main);
    assert_ne!(valid.main, article.main_digest);
    assert_eq!(valid.stages().len(), 2);
    let mut different_policy = article.clone();
    different_policy.policy_digest = Digest::of("registry-test", b"other-policy");
    assert_ne!(
        valid.scope,
        ContentDedupeClaimV1::from_document(tenant, run, representation, &different_policy)
            .unwrap()
            .scope
    );
    assert_ne!(
        valid.scope,
        ContentDedupeClaimV1::from_document(
            tenant,
            run,
            Digest::of("registry-test", b"other-session"),
            &article
        )
        .unwrap()
        .scope
    );
    assert_ne!(
        valid.scope,
        ContentDedupeClaimV1::from_document(tenant, CrawlRunId::new(), representation, &article)
            .unwrap()
            .scope
    );
    assert_ne!(
        valid.scope,
        ContentDedupeClaimV1::from_document(TenantId::new(), run, representation, &article)
            .unwrap()
            .scope
    );
    let invalid = |article: &DocumentEnvelopeV1| {
        assert!(ContentDedupeClaimV1::from_document(tenant, run, representation, article).is_err());
    };
    let mut changed = article.clone();
    changed.version = 2;
    invalid(&changed);
    changed = article.clone();
    changed.quality.status = QualityStatusV1::Rejected;
    invalid(&changed);
    changed = article.clone();
    changed.privacy_projection_version = None;
    invalid(&changed);
    changed = article.clone();
    changed.dedupe = None;
    invalid(&changed);
    changed = article.clone();
    changed.dedupe.as_mut().unwrap().version = 2;
    invalid(&changed);
    changed = article.clone();
    changed.dedupe.as_mut().unwrap().digests.normalization = "unsupported".into();
    invalid(&changed);
    changed = article.clone();
    changed.dedupe.as_mut().unwrap().content_sha256 = Some("FF".repeat(32));
    invalid(&changed);
    changed = article.clone();
    changed.dedupe.as_mut().unwrap().content_sha256 = Some("12".repeat(33));
    invalid(&changed);
    changed = article.clone();
    changed.dedupe.as_mut().unwrap().content_sha256 = None;
    invalid(&changed);
    changed = article.clone();
    changed.dedupe.as_mut().unwrap().blocks_removed = 2;
    invalid(&changed);
}
