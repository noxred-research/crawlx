//! Measured history parity over the actual fenced storage backends.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::custody::CustodyLease;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{RequestBatchV1, RequestCommitRepo};
use crawlx_core::repo::{FrontierRepo, RunRepo};
use crawlx_core::report_history::{
    DnsOutcomeV1, ReportDataV1, ReportFactV1, ReportHistoryRepo, ReportKindV1, ReportQueryV1,
};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::{CrawlRunId, StoreError, TenantId, WorkerId};
use crawlx_storage::{testkit, MemoryStore, Pg, PgConfig};

async fn fixture<R: RunRepo + FrontierRepo + RequestCommitRepo>(
    repo: &R,
    tenant: TenantId,
) -> (crawlx_core::repo::CrawlRun, CustodyLease) {
    let mut config = testkit::create_crawl("https://history.example.test/secret?token=private", &[], 1);
    config.retention.days = 1;
    let run = testkit::crawl_run(tenant, config);
    repo.create(&run, None).await.unwrap();
    let batch = RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("test/report-batch", run.id.0.as_bytes()),
        vec![RequestEnvelopeV1::get(
            testkit::canonical_url("https://history.example.test/secret?token=private"),
            0,
            None,
        )],
    );
    repo.append_batch(batch).await.unwrap();
    let worker = WorkerId::new();
    let rows = repo.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    let (entry, fence) = &rows[0];
    (
        run.clone(),
        CustodyLease::for_url(tenant, run.id, entry.id, worker, *fence),
    )
}

async fn contract<R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo>(
    repo: &R,
    tenant: TenantId,
) {
    let (run, lease) = fixture(repo, tenant).await;
    let mut unknown = ReportFactV1::new(
        &lease,
        Digest::of("test/report-fact", b"unknown"),
        run.created_at,
        ReportDataV1::Wire {
            received_bytes: None,
            sent_bytes: None,
            duration_us: None,
        },
    );
    unknown.request_id = match lease.source {
        crawlx_core::custody::CustodySource::Url(id) => Some(id),
        _ => None,
    };
    let first = repo.append_fact(&lease, &unknown).await.unwrap();
    assert_eq!(repo.append_fact(&lease, &unknown).await.unwrap(), first);
    let mut changed = unknown.clone();
    changed.data = ReportDataV1::Wire {
        received_bytes: Some(0),
        sent_bytes: None,
        duration_us: Some(0),
    };
    assert!(matches!(
        repo.append_fact(&lease, &changed).await,
        Err(StoreError::Conflict(_))
    ));
    for value in [9_u64, 1, 5] {
        let mut fact = ReportFactV1::new(
            &lease,
            Digest::of("test/report-fact", &value.to_le_bytes()),
            run.created_at,
            ReportDataV1::Wire {
                received_bytes: Some(value * 10),
                sent_bytes: None,
                duration_us: Some(value),
            },
        );
        fact.request_id = unknown.request_id;
        repo.append_fact(&lease, &fact).await.unwrap();
    }
    let dns = ReportFactV1::new(
        &lease,
        Digest::of("test/report-fact", b"dns"),
        run.created_at,
        ReportDataV1::Dns {
            outcome: DnsOutcomeV1::Resolved,
            duration_us: 13,
            recheck_at: Some(run.created_at + chrono::Duration::minutes(5)),
        },
    );
    repo.append_fact(&lease, &dns).await.unwrap();
    let mut query = ReportQueryV1::default();
    query.kind = Some(ReportKindV1::Wire);
    query.min_duration_us = Some(1);
    query.limit = 2;
    let page = repo.query_facts(tenant, Some(run.id), &query).await.unwrap();
    assert_eq!(page.entries.len(), 2);
    assert!(page.next.is_some());
    assert!(page
        .entries
        .iter()
        .all(|entry| entry.fact.data.duration_us().is_some()));
    query.after = page.next.unwrap();
    let tail = repo.query_facts(tenant, Some(run.id), &query).await.unwrap();
    assert_eq!(tail.entries.len(), 1);
    assert_eq!(tail.next, None);
    query.after = 0;
    query.min_wire_bytes = Some(60);
    assert_eq!(
        repo.query_facts(tenant, Some(run.id), &query)
            .await
            .unwrap()
            .entries
            .len(),
        1
    );
    let foreign = TenantId::new();
    assert!(repo.query_facts(foreign, Some(run.id), &query).await.is_err());
    assert!(repo
        .query_facts(foreign, None, &query)
        .await
        .unwrap()
        .entries
        .is_empty());
    let (second, second_lease) = fixture(repo, tenant).await;
    let fact = ReportFactV1::new(
        &second_lease,
        Digest::of("test/report-fact", b"second"),
        second.created_at,
        ReportDataV1::Loss { dropped: 3 },
    );
    repo.append_fact(&second_lease, &fact).await.unwrap();
    let timeline = repo
        .query_facts(tenant, None, &ReportQueryV1::default())
        .await
        .unwrap();
    assert!(timeline.entries.iter().any(|entry| entry.fact.run == run.id));
    assert!(timeline.entries.iter().any(|entry| entry.fact.run == second.id));
    let serialized = serde_json::to_string(&timeline).unwrap();
    for secret in ["history.example.test", "secret?token", "private"] {
        assert!(!serialized.contains(secret));
    }
    let mut wrong = lease.clone();
    wrong.fence += 1;
    let mut stale = unknown.clone();
    stale.id = Digest::of("test/report-fact", b"stale");
    stale.fence = wrong.fence;
    assert!(matches!(
        repo.append_fact(&wrong, &stale).await,
        Err(StoreError::LeaseLost)
    ));
    let mut invalid = unknown;
    invalid.id = Digest::of("test/report-fact", b"invalid");
    invalid.at = crawlx_core::Timestamp::from_timestamp(-1, 0).unwrap();
    assert!(repo.append_fact(&lease, &invalid).await.is_err());
}

#[tokio::test]
async fn memory_measured_history_contract() {
    contract(&MemoryStore::new(), TenantId::new()).await;
}

#[tokio::test]
async fn postgres_measured_history_contract() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("report_{}", CrawlRunId::new().0.simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "report-history-tests").await.unwrap();
    contract(&pg, tenant).await;
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn postgres_pipeline_completion_requires_every_fenced_delivery_ack() {
    use crawlx_core::dataset::DeliveryOutboxRepo;
    use crawlx_core::report_history::{PipelineStageV1, PipelineStateV1};
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("report_ack_{}", CrawlRunId::new().0.simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "report-ack-tests").await.unwrap();
    let (run, lease) = fixture(&pg, tenant).await;
    let crawlx_core::custody::CustodySource::Url(request) = lease.source else {
        panic!("url fixture");
    };
    for (ordinal, stage, state) in [
        (0_u8, PipelineStageV1::Fetch, PipelineStateV1::Succeeded),
        (1, PipelineStageV1::Parse, PipelineStateV1::Succeeded),
        (2, PipelineStageV1::Index, PipelineStateV1::Pending),
        (3, PipelineStageV1::Completion, PipelineStateV1::Pending),
    ] {
        let mut fact = ReportFactV1::new(
            &lease,
            Digest::of("test/report-pipeline", &[ordinal]),
            run.created_at,
            ReportDataV1::Pipeline { stage, state },
        );
        fact.request_id = Some(request);
        pg.append_fact(&lease, &fact).await.unwrap();
    }
    pg.complete_fenced(
        request,
        lease.fence,
        crawlx_core::repo::FrontierStatus::Succeeded,
        None,
    )
    .await
    .unwrap();
    let mut ids = Vec::new();
    for name in ["first", "second"] {
        let id:i64=sqlx::query_scalar("INSERT INTO dataset_delivery_outbox(tenant_id,run_id,source_request_id,feed,idempotency_key,payload,state,fence,lease_owner,lease_expires_at,expires_at) VALUES($1,$2,$3,'fixture',$4,'{}','leased',1,$5,CURRENT_TIMESTAMP+INTERVAL '10 minutes',CURRENT_TIMESTAMP+INTERVAL '1 day') RETURNING delivery_id")
            .bind(tenant.0).bind(run.id.0).bind(request).bind(name).bind(WorkerId::new().0).fetch_one(pg.pool()).await.unwrap();
        ids.push(id);
    }
    DeliveryOutboxRepo::acknowledge(&pg, run.id, ids[0], 1)
        .await
        .unwrap();
    let page = pg
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap();
    assert!(!page.entries.iter().any(|entry| matches!(
        entry.fact.data,
        ReportDataV1::Pipeline {
            stage: PipelineStageV1::Completion,
            state: PipelineStateV1::Succeeded
        }
    )));
    assert!(matches!(
        DeliveryOutboxRepo::acknowledge(&pg, run.id, ids[1], 2).await,
        Err(StoreError::LeaseLost)
    ));
    let count_before = page.entries.len();
    // A fact conflict after the delivery UPDATE must roll back the outbox ACK too.
    let collision_id = Digest::of(
        "crawlx/report-delivery-ack/v1",
        &serde_json::to_vec(&(
            tenant,
            run.id,
            request,
            lease.fence,
            1_u16,
            PipelineStageV1::Index,
        ))
        .unwrap(),
    );
    let mut collision = ReportFactV1::new(
        &lease,
        collision_id,
        run.created_at,
        ReportDataV1::Loss { dropped: 1 },
    );
    collision.request_id = Some(request);
    let receipt = Digest::of("crawlx/report-fact/v1", &serde_json::to_vec(&collision).unwrap());
    sqlx::query("INSERT INTO report_history(tenant_id,run_id,fact_id,receipt,kind,observed_at,fact) VALUES($1,$2,$3,$4,'loss',$5,$6)")
        .bind(tenant.0).bind(run.id.0).bind(collision_id.0.as_slice()).bind(receipt.0.as_slice()).bind(run.created_at).bind(serde_json::to_value(collision).unwrap()).execute(pg.pool()).await.unwrap();
    assert!(matches!(
        DeliveryOutboxRepo::acknowledge(&pg, run.id, ids[1], 1).await,
        Err(StoreError::Conflict(_))
    ));
    let state: String = sqlx::query_scalar("SELECT state FROM dataset_delivery_outbox WHERE delivery_id=$1")
        .bind(ids[1])
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(state, "leased");
    sqlx::query("DELETE FROM report_history WHERE tenant_id=$1 AND run_id=$2 AND fact_id=$3")
        .bind(tenant.0)
        .bind(run.id.0)
        .bind(collision_id.0.as_slice())
        .execute(pg.pool())
        .await
        .unwrap();
    DeliveryOutboxRepo::acknowledge(&pg, run.id, ids[1], 1)
        .await
        .unwrap();
    let page = pg
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap();
    assert_eq!(page.entries.len(), count_before + 2);
    assert!(page.entries.iter().any(|entry| matches!(
        entry.fact.data,
        ReportDataV1::Pipeline {
            stage: PipelineStageV1::Completion,
            state: PipelineStateV1::Succeeded
        }
    )));
    DeliveryOutboxRepo::acknowledge(&pg, run.id, ids[1], 1)
        .await
        .unwrap();
    assert_eq!(
        pg.query_facts(tenant, Some(run.id), &ReportQueryV1::default())
            .await
            .unwrap()
            .entries
            .len(),
        page.entries.len()
    );
    pg.drop_schema().await.unwrap();
}
