//! Fenced approval transactions on PostgreSQL; skips without CRAWLX_TEST_DATABASE_URL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Duration;
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::safety::{SafetyDecision, SafetyVerdict};
use crawlx_core::{ApprovalId, CrawlRunId, StateClusterId, TenantId, Timestamp, WorkerId};
use crawlx_storage::approvals::{
    ApprovalBindingV1, ApprovalRepository, ApprovalRequestV1, DurableApprovalV1,
};
use crawlx_storage::testkit::{crawl_run, create_crawl, proposal, sessions, verdict};
use crawlx_storage::{ApiKeyRow, ApprovalDecision, LeaseRepo, Pg, PgApiRepo, PgConfig, SessionLease};

struct Fixture {
    pg: Pg,
    api: PgApiRepo,
    tenant: TenantId,
    lease: SessionLease,
    request: ApprovalRequestV1,
    reviewer: uuid::Uuid,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
        let pg = Pg::connect(
            &url,
            PgConfig {
                schema: Some(format!("approval_{}", uuid::Uuid::now_v7().simple())),
                max_connections: 8,
                ..PgConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        let tenant = TenantId(uuid::Uuid::from_u128(1));
        pg.ensure_tenant(tenant, "approval-test").await.unwrap();
        let now: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(pg.pool())
            .await
            .unwrap();
        let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        run.created_at = now;
        pg.create(&run, None).await.unwrap();
        pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
        let lease = pg
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        let api = PgApiRepo::new(pg.clone());
        let reviewer = uuid::Uuid::from_u128(2);
        api.key_insert(
            &ApiKeyRow {
                key_id: reviewer,
                tenant,
                prefix: "approval-fixture".into(),
                hash: [1; 32],
                scopes: vec!["approvals:decide".into()],
                expires_at: None,
                revoked: false,
            },
            "approval-test",
        )
        .await
        .unwrap();
        let p = proposal("role0", StateClusterId(uuid::Uuid::nil()), 1);
        let mut v = verdict(SafetyDecision::ApprovalRequired);
        v.approval = Some(ApprovalId(uuid::Uuid::from_u128(3)));
        let action = pg.propose(run.id, lease.session.id, &p, &v).await.unwrap();
        let request = ApprovalRequestV1::new(
            v.approval.unwrap(),
            ApprovalBindingV1::new(
                tenant,
                &lease,
                action,
                p.key.id(),
                v.risk_class,
                crawlx_core::hash::Digest::of("approval-test", b"params"),
                p.epoch,
            ),
            "redacted durable test".into(),
            now,
            now + Duration::minutes(5),
        );
        pg.persist_approval(tenant, &lease, &request).await.unwrap();
        Some(Self {
            pg,
            api,
            tenant,
            lease,
            request,
            reviewer,
        })
    }

    async fn decide(&self, decision: ApprovalDecision) -> DurableApprovalV1 {
        // An intentionally false application clock must not govern durable expiry.
        self.api
            .approval_decide(
                self.lease.session.run,
                self.request.id,
                decision,
                self.reviewer,
                None,
                self.request.expires_at + Duration::days(2),
            )
            .await
            .unwrap();
        DurableApprovalV1::new(
            self.request.clone(),
            self.api
                .approval_get(self.lease.session.run, self.request.id)
                .await
                .unwrap()
                .unwrap(),
        )
    }

    fn allowed(&self) -> SafetyVerdict {
        let mut v = verdict(SafetyDecision::Allow);
        v.risk_class = self.request.binding.risk;
        v.approval = Some(self.request.id);
        v
    }
}

#[tokio::test]
async fn durable_reviewer_decision_consumes_once_and_links_original_action_at_t1() {
    let Some(f) = Fixture::new().await else { return };
    let snapshot = f.decide(ApprovalDecision::Approved).await;
    assert_eq!(snapshot.record.decision, ApprovalDecision::Approved);
    let binding = &f.request.binding;
    let found =
        f.pg.find_approval(
            f.tenant,
            &f.lease,
            binding.action_key,
            binding.risk,
            binding.params_digest,
            binding.epoch,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.request, f.request);
    let mut wrong_params = binding.params_digest;
    wrong_params.0[0] ^= 1;
    assert!(f
        .pg
        .find_approval(
            f.tenant,
            &f.lease,
            binding.action_key,
            binding.risk,
            wrong_params,
            binding.epoch
        )
        .await
        .unwrap()
        .is_none());
    assert!(f
        .pg
        .intend(
            f.request.binding.action,
            f.lease.session.id,
            f.request.binding.epoch
        )
        .await
        .is_err());
    for dimension in 0..7 {
        let mut wrong = snapshot.clone();
        match dimension {
            0 => wrong.request.binding.tenant = TenantId(uuid::Uuid::from_u128(101)),
            1 => wrong.request.binding.run = CrawlRunId(uuid::Uuid::from_u128(102)),
            2 => wrong.request.binding.action = crawlx_core::ActionId(uuid::Uuid::from_u128(103)),
            3 => wrong.request.binding.params_digest.0[0] ^= 1,
            4 => wrong.request.binding.epoch.mutation_seq += 1,
            5 => wrong.request.binding.action_key.0[0] ^= 1,
            6 => wrong.request.binding.risk = crawlx_core::safety::RiskClass::Destructive,
            _ => unreachable!(),
        }
        assert!(f.pg.consume_approval(f.tenant, &f.lease, &wrong).await.is_err());
    }
    let mut stale = f.lease.clone();
    stale.fencing_token += 1;
    assert!(f.pg.consume_approval(f.tenant, &stale, &snapshot).await.is_err());
    assert!(f
        .pg
        .consume_approval(TenantId(uuid::Uuid::from_u128(999)), &f.lease, &snapshot)
        .await
        .is_err());
    let (left, right) = tokio::join!(
        f.pg.consume_approval(f.tenant, &f.lease, &snapshot),
        f.pg.consume_approval(f.tenant, &f.lease, &snapshot)
    );
    assert_eq!(u32::from(left.is_ok()) + u32::from(right.is_ok()), 1);
    assert!(f
        .pg
        .consume_approval(f.tenant, &f.lease, &snapshot)
        .await
        .is_err());
    let mut changed = f.request.binding.epoch;
    changed.mutation_seq += 1;
    assert!(f
        .pg
        .intend_approved(
            f.tenant,
            &f.lease,
            f.request.binding.action,
            changed,
            &f.allowed()
        )
        .await
        .is_err());
    f.pg.intend_approved(
        f.tenant,
        &f.lease,
        f.request.binding.action,
        f.request.binding.epoch,
        &f.allowed(),
    )
    .await
    .unwrap();
    let actions = ActionJournal::list(&f.pg, f.lease.session.run, None)
        .await
        .unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].id, f.request.binding.action);
    let linked: bool = sqlx::query_scalar("SELECT p.safety_decision_id=a.safety_decision_id AND p.consumed_at<=a.intended_at FROM approvals p JOIN actions a ON a.action_id=p.action_id WHERE p.approval_id=$1")
        .bind(f.request.id.0).fetch_one(f.pg.pool()).await.unwrap();
    assert!(linked);
    assert!(f
        .pg
        .intend_approved(
            f.tenant,
            &f.lease,
            f.request.binding.action,
            f.request.binding.epoch,
            &f.allowed()
        )
        .await
        .is_err());
    f.pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn durable_denial_expiry_revocation_and_lease_loss_refuse_consumption_and_intent() {
    for consumed_before_fault in [false, true] {
        for fault in [
            "denied",
            "expired",
            "revoked",
            "lease",
            "authorization",
            "cancelled",
        ] {
            let Some(f) = Fixture::new().await else { return };
            let snapshot = f
                .decide(if fault == "denied" {
                    ApprovalDecision::Denied
                } else {
                    ApprovalDecision::Approved
                })
                .await;
            if consumed_before_fault && fault != "denied" {
                f.pg.consume_approval(f.tenant, &f.lease, &snapshot)
                    .await
                    .unwrap();
            }
            match fault {
                "expired" => {
                    sqlx::query("UPDATE approvals SET expires_at=clock_timestamp() WHERE approval_id=$1")
                        .bind(f.request.id.0)
                        .execute(f.pg.pool())
                        .await
                        .unwrap();
                }
                "revoked" => {
                    sqlx::query("UPDATE approvals SET revoked_at=clock_timestamp() WHERE approval_id=$1")
                        .bind(f.request.id.0)
                        .execute(f.pg.pool())
                        .await
                        .unwrap();
                }
                "lease" => {
                    sqlx::query(
                        "UPDATE crawl_sessions SET fencing_token=fencing_token+1 WHERE session_id=$1",
                    )
                    .bind(f.lease.session.id.0)
                    .execute(f.pg.pool())
                    .await
                    .unwrap();
                }
                "authorization" => {
                    let now: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
                        .fetch_one(f.pg.pool())
                        .await
                        .unwrap();
                    let record = crawlx_core::AuthorizationRecordId(uuid::Uuid::from_u128(501));
                    let body = serde_json::json!({"profileCap": "test_environment"});
                    let digest = [2_u8; 32];
                    f.pg.ensure_authorization_record(&crawlx_storage::AuthorizationRow {
                        tenant: f.tenant,
                        record,
                        version: 1,
                        body: &body,
                        body_digest: &digest,
                        valid_from: now - Duration::hours(1),
                        valid_to: now + Duration::hours(1),
                    })
                    .await
                    .unwrap();
                    sqlx::query(
                        "UPDATE authorization_records SET verified_at=$2, revoked_at=$2 WHERE record_id=$1",
                    )
                    .bind(record.0)
                    .bind(now)
                    .execute(f.pg.pool())
                    .await
                    .unwrap();
                    sqlx::query("UPDATE crawl_runs SET authorization_record_id=$2, authorization_body_digest=$3 WHERE run_id=$1")
                    .bind(f.lease.session.run.0).bind(record.0).bind(digest.as_slice())
                    .execute(f.pg.pool()).await.unwrap();
                }
                "cancelled" => {
                    sqlx::query(
                        "UPDATE crawl_runs SET cancel_requested_at=clock_timestamp() WHERE run_id=$1",
                    )
                    .bind(f.lease.session.run.0)
                    .execute(f.pg.pool())
                    .await
                    .unwrap();
                }
                "denied" => {}
                _ => unreachable!(),
            }
            assert!(f
                .pg
                .consume_approval(f.tenant, &f.lease, &snapshot)
                .await
                .is_err());
            assert!(f
                .pg
                .intend_approved(
                    f.tenant,
                    &f.lease,
                    f.request.binding.action,
                    f.request.binding.epoch,
                    &f.allowed()
                )
                .await
                .is_err());
            f.pg.drop_schema().await.unwrap();
        }
    }
}

#[tokio::test]
async fn durable_reviewer_racing_exact_request_binding_cannot_execute_unbound() {
    let Some(f) = Fixture::new().await else { return };
    let p = proposal("role0", StateClusterId(uuid::Uuid::nil()), 2);
    let mut v = verdict(SafetyDecision::ApprovalRequired);
    v.approval = Some(ApprovalId(uuid::Uuid::from_u128(20)));
    let action =
        f.pg.propose(f.lease.session.run, f.lease.session.id, &p, &v)
            .await
            .unwrap();
    let now: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    let request = ApprovalRequestV1::new(
        v.approval.unwrap(),
        ApprovalBindingV1::new(
            f.tenant,
            &f.lease,
            action,
            p.key.id(),
            v.risk_class,
            f.request.binding.params_digest,
            p.epoch,
        ),
        "redacted raced review".into(),
        now,
        now + Duration::minutes(5),
    );
    f.api
        .approval_decide(
            f.lease.session.run,
            request.id,
            ApprovalDecision::Approved,
            f.reviewer,
            None,
            now,
        )
        .await
        .unwrap();
    let record = f
        .api
        .approval_get(f.lease.session.run, request.id)
        .await
        .unwrap()
        .unwrap();
    let snapshot = DurableApprovalV1::new(request.clone(), record);
    assert!(f
        .pg
        .consume_approval(f.tenant, &f.lease, &snapshot)
        .await
        .is_err());
    f.pg.persist_approval(f.tenant, &f.lease, &request).await.unwrap();
    assert!(f.pg.consume_approval(f.tenant, &f.lease, &snapshot).await.is_ok());
    f.pg.drop_schema().await.unwrap();
}
