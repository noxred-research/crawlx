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
