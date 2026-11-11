//! Durable approval contract under injected time, including concurrent single use.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::safety::{SafetyDecision, SafetyVerdict};
use crawlx_core::time::{Clock, ManualClock};
use crawlx_core::{
    ActionId, ApprovalId, AuthorizationRecordId, CrawlRunId, StateClusterId, StoreError, TenantId, Timestamp,
    WorkerId,
};
use crawlx_storage::approvals::{
    ApprovalBindingV1, ApprovalRepository, ApprovalRequestV1, DurableApprovalV1,
};
use crawlx_storage::memory::HeadResponseAuthorizer;
use crawlx_storage::testkit::{crawl_run, create_crawl, proposal, sessions, verdict};
use crawlx_storage::{ApprovalDecision, LeaseRepo, MemoryStore, SessionLease};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct Fixture {
    store: Arc<MemoryStore>,
    clock: Arc<ManualClock>,
    tenant: TenantId,
    lease: SessionLease,
    request: ApprovalRequestV1,
}

struct LiveAuthority(AtomicBool);

#[async_trait]
impl HeadResponseAuthorizer for LiveAuthority {
    async fn authorize(
        &self,
        _: CrawlRunId,
        _: TenantId,
        _: AuthorizationRecordId,
        _: Timestamp,
    ) -> Result<(), StoreError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::AccessDenied("approval authorization revoked".into()))
        }
    }
}

impl Fixture {
    async fn new(authority: Option<Arc<LiveAuthority>>) -> Self {
        let clock = Arc::new(ManualClock::new(
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        ));
        let store = Arc::new(MemoryStore::with_clock(clock.clone()).with_ttls(
            std::time::Duration::from_secs(600),
            std::time::Duration::from_secs(600),
        ));
        let tenant = TenantId(uuid::Uuid::from_u128(1));
        let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        run.id = CrawlRunId(uuid::Uuid::from_u128(2));
        run.created_at = clock.now();
        if let Some(authority) = authority {
            run.config.safety.authorization_record_ref =
                Some(AuthorizationRecordId(uuid::Uuid::from_u128(3)));
            run.config_digest = run.config.digest().unwrap();
            store.set_head_response_authorizer(authority);
        }
        store.create(&run, None).await.unwrap();
        let mut slots = sessions(run.id, 1, 1);
        slots[0].id = crawlx_core::SessionId(uuid::Uuid::from_u128(4));
        store.create_sessions(&slots).await.unwrap();
        let lease = store
            .claim_session(run.id, WorkerId(uuid::Uuid::from_u128(5)), false)
            .await
            .unwrap()
            .unwrap();
        let p = proposal("role0", StateClusterId(uuid::Uuid::nil()), 1);
        let mut v = verdict(SafetyDecision::ApprovalRequired);
        v.approval = Some(ApprovalId(uuid::Uuid::from_u128(6)));
        let action = store.propose(run.id, lease.session.id, &p, &v).await.unwrap();
        let binding = ApprovalBindingV1::new(
            tenant,
            &lease,
            action,
            p.key.id(),
            v.risk_class,
            crawlx_core::hash::Digest::of("approval-test", b"params"),
            p.epoch,
        );
        let request = ApprovalRequestV1::new(
            v.approval.unwrap(),
            binding,
            "redacted test action".into(),
            clock.now(),
            clock.now() + Duration::seconds(60),
        );
        store.persist_approval(tenant, &lease, &request).await.unwrap();
        Self {
            store,
            clock,
            tenant,
            lease,
            request,
        }
    }

    fn decide(&self, decision: ApprovalDecision) -> DurableApprovalV1 {
        self.store
            .decide_approval_record(
                self.lease.session.run,
                self.request.id,
                decision,
                uuid::Uuid::from_u128(7),
                None,
            )
            .unwrap();
        DurableApprovalV1::new(
            self.request.clone(),
            self.store.approval_records(self.lease.session.run).remove(0),
        )
    }

    fn allowed(&self) -> SafetyVerdict {
        let mut v = verdict(SafetyDecision::Allow);
        v.approval = Some(self.request.id);
        v.risk_class = self.request.binding.risk;
        v
    }
}

#[tokio::test]
async fn approved_request_reuses_original_action_at_fenced_t1_and_replay_fails() {
    let f = Fixture::new(None).await;
    f.store
        .persist_approval(f.tenant, &f.lease, &f.request)
        .await
        .unwrap();
    let preview = f.decide(ApprovalDecision::Approved);
    assert!(
        f.store
            .intend(
                f.request.binding.action,
                f.lease.session.id,
                f.request.binding.epoch
            )
            .await
            .is_err(),
        "reviewer approval alone must not release the action hold"
    );
    let found = f
        .store
        .find_approval(
            f.tenant,
            &f.lease,
            f.request.binding.action_key,
            f.request.binding.risk,
            f.request.binding.params_digest,
            f.request.binding.epoch,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.request, f.request);
    let receipt = f
        .store
        .consume_approval(f.tenant, &f.lease, &preview)
        .await
        .unwrap();
    assert_eq!(receipt.request.binding.action, f.request.binding.action);
    assert_eq!(receipt.fence, f.lease.fencing_token);
    assert_eq!(receipt.consumed_at, f.clock.now());
    assert!(f
        .store
        .consume_approval(f.tenant, &f.lease, &preview)
        .await
        .is_err());
    let allowed = f.allowed();
    f.store
        .intend_approved(
            f.tenant,
            &f.lease,
            f.request.binding.action,
            f.request.binding.epoch,
            &allowed,
        )
        .await
        .unwrap();
    let rows = ActionJournal::list(f.store.as_ref(), f.lease.session.run, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, f.request.binding.action);
    assert_eq!(rows[0].status, crawlx_core::counters::ActionStatus::Intended);
    assert_eq!(rows[0].safety_decision, allowed.decision_id);
    assert!(f
        .store
        .intend_approved(
            f.tenant,
            &f.lease,
            f.request.binding.action,
            f.request.binding.epoch,
            &allowed
        )
        .await
        .is_err());
}

#[tokio::test]
async fn pending_denied_and_all_changed_bindings_fail_without_spending_real_request() {
    let f = Fixture::new(None).await;
    let pending = DurableApprovalV1::new(
        f.request.clone(),
        f.store.approval_records(f.lease.session.run).remove(0),
    );
    assert!(f
        .store
        .consume_approval(f.tenant, &f.lease, &pending)
        .await
        .is_err());
    let approved = f.decide(ApprovalDecision::Approved);
    for dimension in 0..7 {
        let mut changed = approved.clone();
        match dimension {
            0 => changed.request.binding.tenant = TenantId(uuid::Uuid::from_u128(11)),
            1 => changed.request.binding.run = CrawlRunId(uuid::Uuid::from_u128(12)),
            2 => changed.request.binding.action = ActionId(uuid::Uuid::from_u128(13)),
            3 => changed.request.binding.params_digest = crawlx_core::hash::Digest::of("test", b"wrong"),
            4 => changed.request.binding.epoch.mutation_seq += 1,
            5 => changed.request.binding.action_key.0[0] ^= 1,
            6 => changed.request.binding.risk = crawlx_core::safety::RiskClass::Destructive,
            _ => unreachable!(),
        }
        assert!(f
            .store
            .consume_approval(f.tenant, &f.lease, &changed)
            .await
            .is_err());
    }
    assert!(f
        .store
        .consume_approval(TenantId(uuid::Uuid::from_u128(99)), &f.lease, &approved)
        .await
        .is_err());
    assert!(f
        .store
        .consume_approval(f.tenant, &f.lease, &approved)
        .await
        .is_ok());
    let denied = Fixture::new(None).await;
    let snapshot = denied.decide(ApprovalDecision::Denied);
    assert!(denied
        .store
        .consume_approval(denied.tenant, &denied.lease, &snapshot)
        .await
        .is_err());
}

#[tokio::test]
async fn concurrent_consumers_have_exactly_one_winner() {
    let f = Fixture::new(None).await;
    let approved = f.decide(ApprovalDecision::Approved);
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let store = f.store.clone();
        let lease = f.lease.clone();
        let preview = approved.clone();
        let tenant = f.tenant;
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            store.consume_approval(tenant, &lease, &preview).await.is_ok()
        });
    }
    barrier.wait().await;
    let mut successes = 0;
    while let Some(result) = tasks.join_next().await {
        successes += u32::from(result.unwrap());
    }
    assert_eq!(successes, 1);
}

#[tokio::test]
async fn stale_fence_revocation_expiry_and_changed_epoch_fail_closed_at_consume_and_t1() {
    let authority = Arc::new(LiveAuthority(AtomicBool::new(true)));
    let f = Fixture::new(Some(authority.clone())).await;
    let approved = f.decide(ApprovalDecision::Approved);
    let mut stale = f.lease.clone();
    stale.fencing_token += 1;
    assert!(matches!(
        f.store.consume_approval(f.tenant, &stale, &approved).await,
        Err(StoreError::LeaseLost)
    ));
    authority.0.store(false, Ordering::SeqCst);
    assert!(f
        .store
        .consume_approval(f.tenant, &f.lease, &approved)
        .await
        .is_err());
    authority.0.store(true, Ordering::SeqCst);
    f.store
        .consume_approval(f.tenant, &f.lease, &approved)
        .await
        .unwrap();
    let mut changed = f.request.binding.epoch;
    changed.document_seq += 1;
    assert!(f
        .store
        .intend_approved(
            f.tenant,
            &f.lease,
            f.request.binding.action,
            changed,
            &f.allowed()
        )
        .await
        .is_err());
    assert!(f
        .store
        .intend_approved(
            f.tenant,
            &stale,
            f.request.binding.action,
            f.request.binding.epoch,
            &f.allowed()
        )
        .await
        .is_err());
    authority.0.store(false, Ordering::SeqCst);
    assert!(f
        .store
        .intend_approved(
            f.tenant,
            &f.lease,
            f.request.binding.action,
            f.request.binding.epoch,
            &f.allowed()
        )
        .await
        .is_err());
    authority.0.store(true, Ordering::SeqCst);
    f.clock.advance_ms(60_000);
    assert!(f
        .store
        .intend_approved(
            f.tenant,
            &f.lease,
            f.request.binding.action,
            f.request.binding.epoch,
            &f.allowed()
        )
        .await
        .is_err());
    let expired = Fixture::new(None).await;
    let approved = expired.decide(ApprovalDecision::Approved);
    expired.clock.advance_ms(60_000);
    assert!(expired
        .store
        .consume_approval(expired.tenant, &expired.lease, &approved)
        .await
        .is_err());
}

#[tokio::test]
async fn reviewer_racing_request_binding_is_preserved_but_cannot_execute_unbound() {
    let f = Fixture::new(None).await;
    let p = proposal("role0", StateClusterId(uuid::Uuid::nil()), 2);
    let mut v = verdict(SafetyDecision::ApprovalRequired);
    v.approval = Some(ApprovalId(uuid::Uuid::from_u128(20)));
    let action = f
        .store
        .propose(f.lease.session.run, f.lease.session.id, &p, &v)
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
        f.clock.now(),
        f.clock.now() + Duration::seconds(60),
    );
    f.store
        .decide_approval_record(
            f.lease.session.run,
            request.id,
            ApprovalDecision::Approved,
            uuid::Uuid::from_u128(7),
            None,
        )
        .unwrap();
    let record = f
        .store
        .approval_records(f.lease.session.run)
        .into_iter()
        .find(|record| record.id == request.id)
        .unwrap();
    let snapshot = DurableApprovalV1::new(request.clone(), record);
    assert!(f
        .store
        .consume_approval(f.tenant, &f.lease, &snapshot)
        .await
        .is_err());
    f.store
        .persist_approval(f.tenant, &f.lease, &request)
        .await
        .unwrap();
    assert!(f
        .store
        .consume_approval(f.tenant, &f.lease, &snapshot)
        .await
        .is_ok());
}
