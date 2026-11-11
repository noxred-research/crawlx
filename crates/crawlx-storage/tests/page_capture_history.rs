//! Immutable retained generations share the request result transaction on memory and PostgreSQL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, Utc};
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{OrchestrationConfigV1, RequestBatchV1, RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{CrawlRun, FrontierRepo, FrontierStatus, PageRecord, PageRepo, RunRepo, Sensitivity};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::secret::{ArtifactSink, Redactor};
use crawlx_core::time::ManualClock;
use crawlx_core::traffic::TrustLane;
use crawlx_core::{Clock, StoreError, TenantId, WorkerId};
use crawlx_storage::artifacts::ArtifactIndex;
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, PgConfig};
use std::sync::Arc;

fn fixture(tenant: TenantId, clock: &dyn Clock) -> CrawlRun {
    let mut config = create_crawl("https://history.example.test/article", &[], 1);
    config.retention.days = 1;
    let mut policy = OrchestrationConfigV1::default();
    policy.recrawl = Some(
        serde_json::from_value(serde_json::json!({
            "version":1,"minIntervalMs":1000,"maxIntervalMs":1000,"maxVisits":2,
            "endAt":clock.now()+Duration::minutes(1)
        }))
        .unwrap(),
    );
    config.orchestration = Some(policy);
    let mut run = crawl_run(tenant, config);
    run.created_at = clock.now();
    run
}

fn descriptor(run: &CrawlRun, id: i64, body: &[u8]) -> PageRecord {
    PageRecord {
        run: run.id,
        frontier_id: id,
        url: canonical_url("https://history.example.test/article"),
        status: 200,
        content_type: Some("text/markdown".into()),
        content_digest: Digest::of("test/page", body),
        title: None,
        markdown: None,
        html: None,
        metadata: serde_json::json!({}),
        links: Vec::new(),
        fetched_at: run.created_at,
        lane: TrustLane::Diagnostic,
    }
}

async fn exercise<R>(repo: Arc<R>, clock: Arc<ManualClock>, pg: Option<&Pg>, tenant: TenantId)
where
    R: RunRepo + FrontierRepo + RequestCommitRepo + PageRepo + ArtifactIndex + 'static,
{
    let run = fixture(tenant, clock.as_ref());
    repo.create(&run, None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(root.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone());
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("test/batch", b"history"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://history.example.test/article"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let mut expected = Vec::new();
    let mut first_id = 0;
    for (generation, bytes) in [
        b"first retained generation".as_slice(),
        b"second retained generation".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let (entry, fence) = repo
            .lease_batch_fenced(run.id, WorkerId::new(), 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        if generation == 0 {
            first_id = entry.id;
        }
        assert_eq!(
            repo.get_request(run.id, entry.id)
                .await
                .unwrap()
                .envelope
                .revisit_generation,
            u32::try_from(generation).unwrap()
        );
        let source = ArtifactSink::over(&artifacts)
            .put_page(
                run.id,
                entry.id,
                Sensitivity::Content,
                "text/markdown",
                &Redactor::new().redact_artifact(bytes).unwrap(),
            )
            .await
            .unwrap();
        let mut page = descriptor(&run, entry.id, bytes);
        page.markdown = Some(source.clone());
        let mut commit =
            RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
        commit.page = Some(page.clone());
        // A staging write must not become evidence, even with a leased frontier identity.
        let mut staging = page.clone();
        staging.title = Some("uncommitted staging".into());
        repo.put(&staging).await.unwrap();
        assert!(repo.get_committed(run.id, entry.id).await.unwrap().is_none());
        let mut stale = commit.clone();
        stale.fence += 1;
        assert!(matches!(
            repo.commit_fenced(stale).await,
            Err(StoreError::LeaseLost)
        ));
        let mut aborted = commit.clone();
        aborted.expected_state_version += 1;
        assert!(matches!(
            repo.commit_fenced(aborted).await,
            Err(StoreError::Conflict(_))
        ));
        let mut wrong = commit.clone();
        wrong.page.as_mut().unwrap().frontier_id += 1000;
        assert!(matches!(
            repo.commit_fenced(wrong).await,
            Err(StoreError::Conflict(_))
        ));
        let mut failed = commit.clone();
        failed.status = FrontierStatus::Failed;
        assert!(matches!(
            repo.commit_fenced(failed).await,
            Err(StoreError::Conflict(_))
        ));
        assert!(repo.get_committed(run.id, entry.id).await.unwrap().is_none());
        if let Some(pg) = pg.filter(|_| generation == 0) {
            // Abort after descriptor insertion and latest-page upsert, at the terminal update.
            sqlx::query("CREATE FUNCTION reject_capture_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned result abort'; END $$")
                .execute(pg.pool()).await.unwrap();
            sqlx::query("CREATE TRIGGER reject_capture_result BEFORE UPDATE OF status ON url_frontier FOR EACH ROW WHEN (NEW.status='succeeded') EXECUTE FUNCTION reject_capture_result()")
                .execute(pg.pool()).await.unwrap();
            assert!(repo.commit_fenced(commit.clone()).await.is_err());
            assert!(repo.get_committed(run.id, entry.id).await.unwrap().is_none());
            assert_eq!(
                PageRepo::list(repo.as_ref(), run.id).await.unwrap()[0]
                    .title
                    .as_deref(),
                Some("uncommitted staging")
            );
            assert_eq!(repo.metadata_page(run.id, 0, 64).await.unwrap().len(), 1);
            sqlx::query("DROP TRIGGER reject_capture_result ON url_frontier")
                .execute(pg.pool())
                .await
                .unwrap();
            sqlx::query("DROP FUNCTION reject_capture_result()")
                .execute(pg.pool())
                .await
                .unwrap();
        }
        repo.commit_fenced(commit.clone()).await.unwrap();
        // Lost acknowledgement cannot duplicate or replace a logical result.
        assert!(matches!(
            repo.commit_fenced(commit).await,
            Err(StoreError::LeaseLost)
        ));
        expected.push((entry.id, source));
        if generation == 0 {
            let next = repo
                .metadata_page(run.id, entry.id, 1)
                .await
                .unwrap()
                .pop()
                .unwrap();
            if let Some(pg) = pg {
                sqlx::query("UPDATE url_frontier SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND frontier_id=$2")
                    .bind(run.id.0).bind(next.id).execute(pg.pool()).await.unwrap();
            } else {
                clock.advance_ms(1000);
            }
        }
    }
    let latest = PageRepo::list(repo.as_ref(), run.id).await.unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].markdown.as_ref(), Some(&expected[1].1));
    // Mutable projection replacement cannot change either immutable source reference.
    let mut staged = descriptor(&run, first_id, b"uncommitted replacement");
    staged.title = Some("must not replace archive evidence".into());
    repo.put(&staged).await.unwrap();
    let first = repo.committed_page_keyset(run.id, 0, 1).await.unwrap();
    let second = repo
        .committed_page_keyset(run.id, first[0].frontier_id, 1)
        .await
        .unwrap();
    assert!(repo
        .committed_page_keyset(run.id, second[0].frontier_id, 1)
        .await
        .unwrap()
        .is_empty());
    for (page, (id, source)) in first.iter().chain(second.iter()).zip(&expected) {
        assert_eq!(page.frontier_id, *id);
        assert_eq!(page.markdown.as_ref(), Some(source));
        assert!(page.title.is_none());
    }
    assert_eq!(
        artifacts
            .read_content_limited(&expected[0].1, 1024)
            .await
            .unwrap(),
        b"first retained generation"
    );
    assert_eq!(
        artifacts
            .read_content_limited(&expected[1].1, 1024)
            .await
            .unwrap(),
        b"second retained generation"
    );
    assert!(
        crawlx_storage::tenant::scope(TenantId::new(), repo.committed_page_keyset(run.id, 0, 64))
            .await
            .is_err()
    );
    if let Some(pg) = pg {
        sqlx::query("UPDATE crawl_runs SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1")
            .bind(run.id.0)
            .execute(pg.pool())
            .await
            .unwrap();
    } else {
        clock.advance_ms(86_400_000);
    }
    assert!(matches!(
        repo.committed_page_keyset(run.id, 0, 64).await,
        Err(StoreError::RetentionDenied(_))
    ));
}

#[tokio::test]
async fn memory_generations_survive_projection_replacement_and_reject_uncommitted_results() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    exercise(repo, clock, None, TenantId::new()).await;
}

#[tokio::test]
async fn postgres_generations_survive_projection_replacement_and_reject_uncommitted_results() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("page_history_{}", uuid::Uuid::now_v7().simple())),
            max_connections: 1,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "page-history").await.unwrap();
    let clock = Arc::new(ManualClock::new(Utc::now()));
    exercise(Arc::new(pg.clone()), clock, Some(&pg), tenant).await;
    let captures: i64 = sqlx::query_scalar("SELECT count(*) FROM page_captures")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(captures, 2);
    assert!(sqlx::query("UPDATE page_captures SET payload='{}'::jsonb")
        .execute(pg.pool())
        .await
        .is_err());
    crawlx_storage::retention::RetentionSweeper::new(pg.clone())
        .sweep(Utc::now())
        .await
        .unwrap();
    let captures: i64 = sqlx::query_scalar("SELECT count(*) FROM page_captures")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(captures, 0);
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let zdr_pg = pg
        .clone()
        .with_delivery_buffer(Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(
            clock.clone(),
        )));
    zdr_contract(&zdr_pg, tenant, clock.as_ref()).await;
    let captures: i64 = sqlx::query_scalar("SELECT count(*) FROM page_captures")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(captures, 0);
    pg.drop_schema().await.unwrap();
}

async fn zdr_contract<R: RunRepo + FrontierRepo + RequestCommitRepo + PageRepo>(
    repo: &R,
    tenant: TenantId,
    clock: &dyn Clock,
) {
    let mut run = fixture(tenant, clock);
    run.config.retention.mode = RetentionMode::Zdr;
    run.config.retention.days = 0;
    run.config.orchestration = None;
    repo.create(&run, None).await.unwrap();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("test/batch", b"zdr-history"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://history.example.test/article"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let (entry, fence) = repo
        .lease_batch_fenced(run.id, WorkerId::new(), 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let mut commit = RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
    commit.page = Some(descriptor(&run, entry.id, b"volatile only"));
    repo.commit_fenced(commit).await.unwrap();
    assert_eq!(PageRepo::list(repo, run.id).await.unwrap().len(), 1);
    assert!(matches!(
        repo.committed_page_keyset(run.id, 0, 64).await,
        Err(StoreError::RetentionDenied(_))
    ));
}

#[tokio::test]
async fn zdr_history_refuses_even_when_latest_delivery_projection_exists() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let repo = MemoryStore::with_clock(clock.clone());
    repo.set_dataset_delivery(Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(
        clock.clone(),
    )));
    zdr_contract(&repo, TenantId::new(), clock.as_ref()).await;
}

async fn assert_observations_are_not_url_work<R: FrontierRepo>(
    repo: &R,
    run: crawlx_core::CrawlRunId,
    worker: WorkerId,
    id: i64,
) {
    assert!(repo.lease_batch(run, worker, 64).await.unwrap().is_empty());
    assert!(repo.lease_batch_fenced(run, worker, 64).await.unwrap().is_empty());
    assert!(repo.lease_one_fenced(run, worker, id).await.unwrap().is_none());
    assert_eq!(repo.pending_count(run).await.unwrap(), 0);
    assert_eq!(repo.open_count(run).await.unwrap(), 0);
    assert_eq!(
        repo.state_counts(run).await.unwrap(),
        crawlx_core::repo::FrontierStateCounts::default()
    );
    assert!(matches!(
        repo.activity(run).await.unwrap(),
        crawlx_core::orchestration::FrontierActivityV1::Terminal
            | crawlx_core::orchestration::FrontierActivityV1::WaitingProducer
    ));
    assert!(FrontierRepo::list(repo, run)
        .await
        .unwrap()
        .iter()
        .any(|row| row.id == id));
}

async fn observed_contract<R>(repo: &R, tenant: TenantId, now: crawlx_core::Timestamp)
where
    R: RunRepo
        + FrontierRepo
        + RequestCommitRepo
        + PageRepo
        + crawlx_storage::LeaseRepo
        + crawlx_storage::WorkerRegistry,
{
    use crawlx_core::custody::CustodyLease;
    use crawlx_core::orchestration::{ObservedAppendV1, ObservedRequestV1};
    use crawlx_core::ObservationEpoch;

    let mut config = create_crawl("https://history.example.test/article", &["role0"], 2);
    config.mode = crawlx_core::CrawlMode::Hybrid;
    config.dynamic.max_page_revisits = 1;
    config.retention.days = 1;
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    repo.create(&run, None).await.unwrap();
    repo.create_sessions(&crawlx_storage::testkit::sessions(run.id, 1, 2))
        .await
        .unwrap();
    let worker = WorkerId::new();
    repo.register_worker(worker, "observed-fixture", "1")
        .await
        .unwrap();
    let url_worker = WorkerId::new();
    repo.register_worker(url_worker, "observed-url-fixture", "1")
        .await
        .unwrap();
    let first = repo.claim_session(run.id, worker, true).await.unwrap().unwrap();
    let second = repo.claim_session(run.id, worker, true).await.unwrap().unwrap();
    let authority = |lease: &crawlx_storage::SessionLease| {
        CustodyLease::new(tenant, run.id, lease.session.id, worker, lease.fencing_token)
    };
    let first_authority = authority(&first);
    let second_authority = authority(&second);
    let envelope = RequestEnvelopeV1::get(canonical_url("https://history.example.test/article"), 0, None);
    let epoch = |mutation_seq| ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq,
    };
    let proposal = |lease: CustodyLease, mutation_seq| {
        ObservedRequestV1::new(lease, epoch(mutation_seq), envelope.clone(), now)
    };
    let mut stale = first_authority.clone();
    stale.fence += 1;
    assert!(matches!(
        repo.append_observed_fenced(proposal(stale.clone(), 0)).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(repo.metadata_page(run.id, 0, 64).await.unwrap().is_empty());
    let mut arbitrary = envelope.clone();
    arbitrary.revisit_generation = 1;
    assert!(matches!(
        repo.append_batch(RequestBatchV1::new(
            tenant,
            run.id,
            "role0".into(),
            Digest::of("test/observed", b"generic"),
            vec![arbitrary]
        ))
        .await,
        Err(StoreError::AccessDenied(_))
    ));
    let mut forged = envelope.clone();
    forged
        .metadata
        .insert("observed_epoch".into(), serde_json::json!("forged"));
    assert!(matches!(
        repo.append_batch(RequestBatchV1::new(
            tenant,
            run.id,
            "role0".into(),
            Digest::of("test/observed", b"forged-source"),
            vec![forged]
        ))
        .await,
        Err(StoreError::AccessDenied(_))
    ));

    let mut ids = Vec::new();
    for generation in 0..=1 {
        let admitted = repo
            .append_observed_fenced(proposal(first_authority.clone(), generation))
            .await
            .unwrap();
        let id = match admitted {
            ObservedAppendV1::Appended {
                request_id,
                revisit_generation,
            } => {
                assert_eq!(revisit_generation, u32::try_from(generation).unwrap());
                request_id
            }
            other => panic!("unexpected admission: {other:?}"),
        };
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        assert_eq!(repo.get_request(run.id, id).await.unwrap().entry.attempts, 0);
        assert_eq!(
            repo.append_observed_fenced(proposal(first_authority.clone(), generation))
                .await
                .unwrap(),
            ObservedAppendV1::Duplicate {
                request_id: id,
                revisit_generation: u32::try_from(generation).unwrap()
            }
        );
        assert!(matches!(
            repo.lease_observed_fenced(&stale, epoch(generation), id).await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(
            repo.lease_observed_fenced(&first_authority, epoch(generation + 10), id)
                .await,
            Err(StoreError::LeaseLost)
        ));
        let (_, returned_fence) = repo
            .lease_observed_fenced(&first_authority, epoch(generation), id)
            .await
            .unwrap()
            .unwrap();
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        repo.give_back(id, returned_fence).await.unwrap();
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        let (_, expired_fence) = repo
            .lease_observed_fenced(&first_authority, epoch(generation), id)
            .await
            .unwrap()
            .unwrap();
        let reaped = repo.reap_frontier(now + Duration::days(1), 10).await.unwrap();
        assert_eq!(reaped, crawlx_storage::leases::FrontierReap::default());
        assert_eq!(
            repo.get_request(run.id, id).await.unwrap().entry.status,
            FrontierStatus::Pending
        );
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        assert!(matches!(
            repo.give_back(id, expired_fence).await,
            Err(StoreError::LeaseLost)
        ));
        let (_, fence) = repo
            .lease_observed_fenced(&first_authority, epoch(generation), id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(fence, returned_fence);
        assert_ne!(fence, expired_fence);
        let queued = repo.get_request(run.id, id).await.unwrap();
        let mut commit = RequestCommitV1::terminal(
            run.id,
            id,
            fence,
            queued.state_version,
            FrontierStatus::Succeeded,
            None,
        );
        let mut rendition = descriptor(&run, id, &generation.to_le_bytes());
        rendition.metadata["xhr_requests"] = serde_json::json!([{"method":"GET","url":"https://history.example.test/api","resource_type":"fetch","status":200,"endpoint_class":"rest"}]);
        commit.page = Some(rendition);
        assert!(matches!(
            repo.commit_fenced(commit.clone()).await,
            Err(StoreError::LeaseLost)
        ));
        let mut refused = commit.clone();
        let mut children = RequestBatchV1::new(
            tenant,
            run.id,
            "role0".into(),
            Digest::of("test/observed-child", &id.to_be_bytes()),
            vec![RequestEnvelopeV1::get(
                canonical_url("https://history.example.test/child"),
                1,
                Some(id),
            )],
        );
        children.parent_fence = Some((id, fence));
        refused.children = Some(children);
        assert!(matches!(
            repo.commit_observed_fenced(refused, stale.clone(), epoch(generation))
                .await,
            Err(StoreError::LeaseLost)
        ));
        assert_eq!(
            repo.metadata_page(run.id, 0, 64).await.unwrap().len(),
            usize::try_from(generation + 1).unwrap()
        );
        assert!(repo.get_committed(run.id, id).await.unwrap().is_none());
        assert_eq!(
            repo.get_request(run.id, id).await.unwrap().entry.status,
            FrontierStatus::Leased
        );
        assert!(matches!(
            repo.commit_observed_fenced(commit.clone(), first_authority.clone(), epoch(generation + 10))
                .await,
            Err(StoreError::LeaseLost)
        ));
        assert_eq!(
            repo.commit_observed_fenced(commit, first_authority.clone(), epoch(generation))
                .await
                .unwrap(),
            crawlx_core::orchestration::ObservedCommitV1::Committed
        );
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        ids.push(id);
    }
    let pages = PageRepo::list(repo, run.id).await.unwrap();
    assert!(pages
        .iter()
        .all(|page| page.metadata["late_xhr_attribution"] == "late_xhr_not_epoch_attributed"));
    assert_eq!(pages[0].metadata["xhr_requests"][0]["status"], 200);
    assert!(repo
        .get_committed(run.id, ids[0])
        .await
        .unwrap()
        .unwrap()
        .metadata
        .get("late_xhr_attribution")
        .is_none());
    assert_eq!(pages.iter().map(|page| page.frontier_id).collect::<Vec<_>>(), ids);
    assert_ne!(pages[0].content_digest, pages[1].content_digest);
    let canonical = repo.recent_for_url(tenant, &envelope.url, 8).await.unwrap();
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].frontier_id, ids[0]);
    assert_eq!(
        repo.append_observed_fenced(proposal(second_authority.clone(), 2))
            .await
            .unwrap(),
        ObservedAppendV1::CapReached
    );
    assert_eq!(
        serde_json::to_value(ObservedAppendV1::CapReached).unwrap(),
        "revisit_cap_reached"
    );
    assert_eq!(repo.metadata_page(run.id, 0, 64).await.unwrap().len(), 2);

    let race = RequestEnvelopeV1::get(canonical_url("https://history.example.test/race"), 0, None);
    assert!(matches!(
        repo.append_observed_fenced(ObservedRequestV1::new(
            first_authority.clone(),
            epoch(20),
            race.clone(),
            now
        ))
        .await
        .unwrap(),
        ObservedAppendV1::Appended {
            revisit_generation: 0,
            ..
        }
    ));
    let (left, right) = tokio::join!(
        repo.append_observed_fenced(ObservedRequestV1::new(
            first_authority.clone(),
            epoch(21),
            race.clone(),
            now
        )),
        repo.append_observed_fenced(ObservedRequestV1::new(second_authority, epoch(21), race, now)),
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                ObservedAppendV1::Appended {
                    revisit_generation: 1,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ObservedAppendV1::CapReached))
            .count(),
        1
    );
    assert_eq!(repo.metadata_page(run.id, 0, 64).await.unwrap().len(), 4);
    assert_eq!(PageRepo::list(repo, run.id).await.unwrap().len(), 2);
    assert_eq!(
        repo.append_observed_fenced(proposal(first_authority, 0))
            .await
            .unwrap(),
        ObservedAppendV1::Duplicate {
            request_id: ids[0],
            revisit_generation: 0
        }
    );
    let (_, ordinary) = repo
        .discover(
            run.id,
            &canonical_url("https://history.example.test/ordinary"),
            0,
            None,
            None,
        )
        .await
        .unwrap();
    let ordinary = ordinary.unwrap();
    let claimed = repo.lease_batch_fenced(run.id, url_worker, 64).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].0.id, ordinary);
    repo.complete_fenced(ordinary, claimed[0].1, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    let counts = repo.state_counts(run.id).await.unwrap();
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.leased, 0);
    assert_eq!(counts.succeeded, 1);
    assert_eq!(FrontierRepo::list(repo, run.id).await.unwrap().len(), 5);
    let mut dynamic_config = create_crawl("https://history.example.test/legacy-dynamic", &[], 1);
    dynamic_config.mode = crawlx_core::CrawlMode::Dynamic;
    let mut dynamic_run = crawl_run(tenant, dynamic_config);
    dynamic_run.created_at = now;
    repo.create(&dynamic_run, None).await.unwrap();
    let (_, ordinary) = repo
        .discover(
            dynamic_run.id,
            &canonical_url("https://history.example.test/legacy-dynamic"),
            0,
            None,
            None,
        )
        .await
        .unwrap();
    assert_observations_are_not_url_work(repo, dynamic_run.id, url_worker, ordinary.unwrap()).await;
}

#[tokio::test]
async fn memory_observed_epochs_are_fenced_bounded_and_keep_first_canonical() {
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let repo = MemoryStore::with_clock(Arc::new(ManualClock::new(now)));
    observed_contract(&repo, TenantId::new(), now).await;
}

#[tokio::test]
async fn postgres_observed_epochs_are_fenced_bounded_and_keep_first_canonical() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("observed_history_{}", uuid::Uuid::now_v7().simple())),
            max_connections: 4,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "observed-history").await.unwrap();
    observed_contract(&pg, tenant, Utc::now()).await;
    let legacy = sqlx::query(
        "UPDATE url_frontier SET via='link' WHERE via='interaction' AND request_envelope IS NOT NULL",
    )
    .execute(pg.pool())
    .await
    .unwrap();
    assert_eq!(legacy.rows_affected(), 4);
    sqlx::raw_sql(include_str!("../migrations/0064_observed_frontier_source.sql"))
        .execute(pg.pool())
        .await
        .unwrap();
    let restored: i64 = sqlx::query_scalar("SELECT count(*) FROM url_frontier WHERE via='interaction'")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(restored, 4);
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let buffer = Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(clock.clone()));
    let volatile = pg.clone().with_delivery_buffer(buffer.clone());
    let (run, ids) = observed_zdr_contract(&volatile, tenant, clock.now()).await;
    let captures: i64 = sqlx::query_scalar("SELECT count(*) FROM page_captures WHERE run_id=$1")
        .bind(run.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(captures, 0);
    let retained_envelopes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM url_frontier WHERE run_id=$1 AND request_envelope IS NOT NULL",
    )
    .bind(run.0)
    .fetch_one(pg.pool())
    .await
    .unwrap();
    assert_eq!(retained_envelopes, 0);
    buffer.ack(tenant, run, ids[0]).await.unwrap();
    assert_eq!(PageRepo::list(&volatile, run).await.unwrap().len(), 1);
    assert!(volatile
        .recent_for_url(tenant, &canonical_url("https://history.example.test/article"), 8)
        .await
        .unwrap()
        .iter()
        .all(|page| page.run != run));
    pg.drop_schema().await.unwrap();
}

async fn observed_zdr_contract<R>(
    repo: &R,
    tenant: TenantId,
    now: crawlx_core::Timestamp,
) -> (crawlx_core::CrawlRunId, Vec<i64>)
where
    R: RunRepo
        + FrontierRepo
        + RequestCommitRepo
        + PageRepo
        + crawlx_storage::LeaseRepo
        + crawlx_storage::WorkerRegistry,
{
    use crawlx_core::orchestration::{ObservedAppendV1, ObservedRequestV1};
    let mut config = create_crawl("https://history.example.test/article", &["role0"], 1);
    config.mode = crawlx_core::CrawlMode::Hybrid;
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    repo.create(&run, None).await.unwrap();
    repo.create_sessions(&crawlx_storage::testkit::sessions(run.id, 1, 1))
        .await
        .unwrap();
    let worker = WorkerId::new();
    repo.register_worker(worker, "observed-volatile-fixture", "1")
        .await
        .unwrap();
    let url_worker = WorkerId::new();
    repo.register_worker(url_worker, "observed-url-volatile-fixture", "1")
        .await
        .unwrap();
    let session = repo.claim_session(run.id, worker, false).await.unwrap().unwrap();
    let lease = crawlx_core::custody::CustodyLease::new(
        tenant,
        run.id,
        session.session.id,
        worker,
        session.fencing_token,
    );
    let mut ids = Vec::new();
    for mutation_seq in 0..2_u64 {
        let epoch = crawlx_core::ObservationEpoch {
            navigation_seq: 1,
            document_seq: 1,
            mutation_seq,
        };
        let proposal = ObservedRequestV1::new(
            lease.clone(),
            epoch,
            RequestEnvelopeV1::get(canonical_url("https://history.example.test/article"), 0, None),
            now,
        );
        let id = match repo.append_observed_fenced(proposal).await.unwrap() {
            ObservedAppendV1::Appended { request_id, .. } => request_id,
            other => panic!("unexpected admission: {other:?}"),
        };
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        let (_, fence) = repo
            .lease_observed_fenced(&lease, epoch, id)
            .await
            .unwrap()
            .unwrap();
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        let mut commit = RequestCommitV1::terminal(run.id, id, fence, 1, FrontierStatus::Succeeded, None);
        let mut page = descriptor(&run, id, &mutation_seq.to_le_bytes());
        page.title = Some(format!("volatile rendition {mutation_seq}"));
        page.metadata["xhr_requests"] = serde_json::json!([{"method":"GET","url":"https://history.example.test/api","resource_type":"xhr","endpoint_class":"rest"}]);
        commit.page = Some(page);
        assert_eq!(
            repo.commit_observed_fenced(commit, lease.clone(), epoch)
                .await
                .unwrap(),
            crawlx_core::orchestration::ObservedCommitV1::Committed
        );
        assert_observations_are_not_url_work(repo, run.id, url_worker, id).await;
        ids.push(id);
    }
    assert_eq!(
        PageRepo::list(repo, run.id)
            .await
            .unwrap()
            .iter()
            .map(|page| page.frontier_id)
            .collect::<Vec<_>>(),
        ids
    );
    assert!(PageRepo::list(repo, run.id)
        .await
        .unwrap()
        .iter()
        .all(|page| page.metadata["late_xhr_attribution"] == "late_xhr_not_epoch_attributed"));
    assert!(repo
        .recent_for_url(tenant, &canonical_url("https://history.example.test/article"), 8)
        .await
        .unwrap()
        .iter()
        .all(|page| page.run != run.id));
    assert!(matches!(
        repo.committed_page_keyset(run.id, 0, 64).await,
        Err(StoreError::RetentionDenied(_))
    ));
    (run.id, ids)
}

#[tokio::test]
async fn memory_observed_zdr_renditions_expire_with_existing_custody() {
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let buffer = Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(clock.clone()));
    let repo = MemoryStore::with_clock(clock);
    repo.set_dataset_delivery(buffer.clone());
    let tenant = TenantId::new();
    let (run, ids) = observed_zdr_contract(&repo, tenant, now).await;
    buffer.ack(tenant, run, ids[0]).await.unwrap();
    assert_eq!(PageRepo::list(&repo, run).await.unwrap().len(), 1);
    assert!(repo
        .recent_for_url(tenant, &canonical_url("https://history.example.test/article"), 8)
        .await
        .unwrap()
        .is_empty());
}

async fn observed_receipt_fixture<R>(
    repo: &R,
    tenant: TenantId,
    created_at: crawlx_core::Timestamp,
) -> (CrawlRun, crawlx_core::custody::CustodyLease)
where
    R: RunRepo + crawlx_storage::LeaseRepo + crawlx_storage::WorkerRegistry,
{
    let mut config = create_crawl("https://history.example.test/receipt", &["role0"], 1);
    config.mode = crawlx_core::CrawlMode::Dynamic;
    config.limits.duration_seconds = 1;
    config.retention.days = 1;
    config.acquisition = Some(crawlx_core::acquisition::AcquisitionPolicyV1::default());
    let mut run = crawl_run(tenant, config);
    run.created_at = created_at;
    repo.create(&run, None).await.unwrap();
    repo.create_sessions(&crawlx_storage::testkit::sessions(run.id, 1, 1))
        .await
        .unwrap();
    let worker = WorkerId::new();
    repo.register_worker(worker, "observed-receipt", "1")
        .await
        .unwrap();
    repo.publish_acquisition_capabilities(
        worker,
        &[crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
            "fixture", "1",
        )],
    )
    .await
    .unwrap();
    let session = repo.claim_session(run.id, worker, true).await.unwrap().unwrap();
    let lease = crawlx_core::custody::CustodyLease::new(
        tenant,
        run.id,
        session.session.id,
        worker,
        session.fencing_token,
    );
    (run, lease)
}

async fn late_observed_receipt_contract<R>(repo: &R, tenant: TenantId, now: crawlx_core::Timestamp)
where
    R: RunRepo
        + FrontierRepo
        + RequestCommitRepo
        + crawlx_storage::LeaseRepo
        + crawlx_storage::WorkerRegistry,
{
    use crawlx_core::orchestration::{ObservedAppendV1, ObservedRequestV1};
    let (run, lease) = observed_receipt_fixture(repo, tenant, now - Duration::seconds(3)).await;
    let captured_at = run.created_at + Duration::milliseconds(500);
    let epoch = crawlx_core::ObservationEpoch::default();
    let envelope = RequestEnvelopeV1::get(canonical_url("https://history.example.test/receipt"), 0, None);
    assert!(matches!(
        repo.append_batch(RequestBatchV1::new(
            tenant,
            run.id,
            "role0".into(),
            Digest::of("observed/late", b"dispatch"),
            vec![envelope.clone()]
        ))
        .await,
        Err(StoreError::AccessDenied(_))
    ));
    assert!(matches!(
        repo.append_observed_fenced(ObservedRequestV1::new(
            lease.clone(),
            epoch,
            envelope.clone(),
            now
        ))
        .await,
        Err(StoreError::AccessDenied(_))
    ));
    let stopped = tokio_util::sync::CancellationToken::new();
    stopped.cancel();
    let stopped_lease = lease.clone().with_cancellation(stopped);
    assert!(matches!(
        repo.append_observed_fenced(ObservedRequestV1::new(
            stopped_lease.clone(),
            epoch,
            envelope.clone(),
            captured_at
        ))
        .await,
        Err(StoreError::LeaseLost)
    ));
    let id = match repo
        .append_observed_fenced(ObservedRequestV1::new(
            lease.clone(),
            epoch,
            envelope,
            captured_at,
        ))
        .await
        .unwrap()
    {
        ObservedAppendV1::Appended { request_id, .. } => request_id,
        other => panic!("unexpected observed receipt: {other:?}"),
    };
    assert!(repo
        .lease_one_fenced(run.id, lease.worker, id)
        .await
        .unwrap()
        .is_none());
    let mut stale = lease.clone();
    stale.fence += 1;
    assert!(matches!(
        repo.lease_observed_fenced(&stale, epoch, id).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        repo.lease_observed_fenced(&stopped_lease, epoch, id).await,
        Err(StoreError::LeaseLost)
    ));
    let (_, fence) = repo
        .lease_observed_fenced(&lease, epoch, id)
        .await
        .unwrap()
        .unwrap();
    let queued = repo.get_request(run.id, id).await.unwrap();
    let restored = ObservedRequestV1::from_staged(lease.clone(), epoch, queued.envelope).unwrap();
    assert_eq!(restored.acquired_at, captured_at);
    let original_marker = restored.batch_id("role0").unwrap();
    let mut changed = restored;
    changed.acquired_at += Duration::milliseconds(1);
    assert_ne!(changed.batch_id("role0").unwrap(), original_marker);
    let commit = RequestCommitV1::terminal(
        run.id,
        id,
        fence,
        queued.state_version,
        FrontierStatus::Succeeded,
        None,
    );
    assert!(matches!(
        repo.commit_observed_fenced(commit.clone(), stopped_lease, epoch)
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(
        repo.commit_observed_fenced(commit, lease, epoch).await.unwrap(),
        crawlx_core::orchestration::ObservedCommitV1::Committed
    );
    assert_eq!(
        repo.get_request(run.id, id).await.unwrap().entry.status,
        FrontierStatus::Succeeded
    );
}

#[tokio::test]
async fn memory_late_observed_receipts_require_early_capture_and_live_uncancelled_session() {
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let repo = MemoryStore::with_clock(Arc::new(ManualClock::new(now)));
    late_observed_receipt_contract(&repo, TenantId::new(), now).await;
}

#[tokio::test]
async fn memory_observed_capture_uses_completed_login_credit_not_reserved_allowance() {
    use crawlx_core::orchestration::{ObservedAppendV1, ObservedRequestV1};
    use crawlx_core::repo::EventRepo;
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let repo = MemoryStore::with_clock(clock.clone());
    let (run, lease) = observed_receipt_fixture(&repo, TenantId::new(), now).await;
    let crawlx_core::custody::CustodySource::Session(session) = lease.source else {
        panic!("session lease")
    };
    EventRepo::append(
        &repo,
        run.id,
        "session.budget",
        serde_json::json!({
            "session_id":session,"login_credit_ms":0,"login_allowance_ms":10_000
        }),
    )
    .await
    .unwrap();
    clock.advance_ms(2_000);
    let epoch = crawlx_core::ObservationEpoch::default();
    let envelope = RequestEnvelopeV1::get(canonical_url("https://history.example.test/receipt"), 0, None);
    assert!(matches!(
        repo.append_observed_fenced(ObservedRequestV1::new(
            lease.clone(),
            epoch,
            envelope.clone(),
            clock.now()
        ))
        .await,
        Err(StoreError::AccessDenied(_))
    ));
    EventRepo::append(
        &repo,
        run.id,
        "session.budget",
        serde_json::json!({
            "session_id":session,"login_credit_ms":2_000,"login_allowance_ms":0
        }),
    )
    .await
    .unwrap();
    let captured_at = clock.now();
    clock.advance_ms(1_500);
    assert!(matches!(
        repo.append_observed_fenced(ObservedRequestV1::new(lease, epoch, envelope, captured_at))
            .await
            .unwrap(),
        ObservedAppendV1::Appended { .. }
    ));
}

#[tokio::test]
async fn postgres_observed_receipts_survive_drain_and_late_publication_without_new_dispatch() {
    use crawlx_core::orchestration::{ObservedAppendV1, ObservedRequestV1};
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("observed_receipts_{}", uuid::Uuid::now_v7().simple())),
            max_connections: 1,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "observed-receipt").await.unwrap();
    late_observed_receipt_contract(&pg, tenant, pg.db_now().await.unwrap()).await;
    let (run, lease) = observed_receipt_fixture(&pg, tenant, pg.db_now().await.unwrap()).await;
    let epoch = crawlx_core::ObservationEpoch::default();
    let captured_at = pg.db_now().await.unwrap();
    let envelope = RequestEnvelopeV1::get(canonical_url("https://history.example.test/receipt"), 0, None);
    let id = match pg
        .append_observed_fenced(ObservedRequestV1::new(
            lease.clone(),
            epoch,
            envelope.clone(),
            captured_at,
        ))
        .await
        .unwrap()
    {
        ObservedAppendV1::Appended { request_id, .. } => request_id,
        other => panic!("unexpected observed receipt: {other:?}"),
    };
    pg.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "role0".into(),
        Digest::of("observed/drain", b"dispatch"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://history.example.test/new-target"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    sqlx::query("UPDATE workers SET draining=true WHERE worker_id=$1")
        .bind(lease.worker.0)
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(pg
        .lease_batch_fenced(run.id, lease.worker, 10)
        .await
        .unwrap()
        .is_empty());
    assert!(pg
        .lease_one_fenced(run.id, lease.worker, id)
        .await
        .unwrap()
        .is_none());
    let mut changed = pg.get_request(run.id, id).await.unwrap().envelope;
    changed.metadata.insert(
        "observed_acquired_at".into(),
        serde_json::to_value(captured_at - Duration::milliseconds(1)).unwrap(),
    );
    sqlx::query("UPDATE url_frontier SET request_envelope=$3 WHERE run_id=$1 AND frontier_id=$2")
        .bind(run.id.0)
        .bind(id)
        .bind(serde_json::to_value(&changed).unwrap())
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        pg.lease_observed_fenced(&lease, epoch, id).await,
        Err(StoreError::LeaseLost)
    ));
    changed.metadata.insert(
        "observed_acquired_at".into(),
        serde_json::to_value(captured_at).unwrap(),
    );
    sqlx::query("UPDATE url_frontier SET request_envelope=$3 WHERE run_id=$1 AND frontier_id=$2")
        .bind(run.id.0)
        .bind(id)
        .bind(serde_json::to_value(changed).unwrap())
        .execute(pg.pool())
        .await
        .unwrap();
    let (_, fence) = pg
        .lease_observed_fenced(&lease, epoch, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pg.commit_observed_fenced(
            RequestCommitV1::terminal(run.id, id, fence, 1, FrontierStatus::Succeeded, None),
            lease,
            epoch,
        )
        .await
        .unwrap(),
        crawlx_core::orchestration::ObservedCommitV1::Committed
    );
    pg.drop_schema().await.unwrap();
}
