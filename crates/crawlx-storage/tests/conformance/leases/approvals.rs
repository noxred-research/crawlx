#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Durable approvals under leases: a reviewer's decision is spent exactly once, under the
//! exact lease fence, and releases the hold of the original action only at the fenced T1.
//!
//! The reviewer side is the API repository (`approval_decide`, `approval_get`), the kernel
//! side is the [`ApprovalRepository`] of the store; both run over the same database. Faults
//! (expiry, revocation, a lost lease or authorization) are injected with raw SQL, because
//! durable expiry and authority are decided by the database clock and the stored rows, never
//! by an application clock.

use super::support::{tenant, Raw, StoreOf, V};
use crate::rig::Rig;
use chrono::Duration;
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::safety::{RiskClass, SafetyDecision, SafetyVerdict};
use crawlx_core::{
    ActionId, ApprovalId, AuthorizationRecordId, CrawlRunId, StateClusterId, TenantId, WorkerId,
};
use crawlx_storage::approvals::{
    ApprovalBindingV1, ApprovalRepository, ApprovalRequestV1, DurableApprovalV1,
};
use crawlx_storage::testkit::{proposal, sessions, verdict};
use crawlx_storage::{ApiKeyRow, ApiRepo, ApprovalDecision, LeaseRepo, SessionLease, Store};
use uuid::Uuid;

conformance! { databases:
    approved_request_reuses_original_action_at_fenced_t1_and_replay_fails,
    durable_reviewer_decision_consumes_once_and_links_original_action_at_t1,
    durable_denial_expiry_revocation_and_lease_loss_refuse_consumption_and_intent,
    durable_reviewer_racing_exact_request_binding_cannot_execute_unbound,
    pending_denied_and_all_changed_bindings_fail_without_spending_real_request,
    concurrent_consumers_have_exactly_one_winner,
    stale_fence_revocation_expiry_and_changed_epoch_fail_closed_at_consume_and_t1,
}

/// One tenant, one run with a single leased session, a reviewer key and one pending approval
/// bound to a parked (approval-required) action of that session.
struct Fixture<'a, B: StoreOf> {
    raw: Raw<'a>,
    store: Store<B>,
    api: ApiRepo<B>,
    tenant: TenantId,
    lease: SessionLease,
    request: ApprovalRequestV1,
    reviewer: Uuid,
}

impl<'a, B: StoreOf> Fixture<'a, B>
where
    Store<B>: ApprovalRepository + RunRepo + LeaseRepo + ActionJournal,
{
    async fn new(rig: &'a Rig, store: &Store<B>) -> Self {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let now = raw.now().await;
        let mut run = crawlx_storage::testkit::crawl_run(
            tenant,
            crawlx_storage::testkit::create_crawl("https://example.test/", &[], 1),
        );
        run.created_at = now;
        store.create(&run, None).await.unwrap();
        store.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
        let lease = store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        let api = ApiRepo::new(store.clone());
        let reviewer = Uuid::now_v7();
        api.key_insert(
            &ApiKeyRow {
                key_id: reviewer,
                tenant,
                prefix: format!("approval-{}", reviewer.simple()),
                hash: [1; 32],
                scopes: vec!["approvals:decide".into()],
                expires_at: None,
                revoked: false,
            },
            "approval-test",
        )
        .await
        .unwrap();
        let p = proposal("role0", StateClusterId(Uuid::nil()), 1);
        let mut v = verdict(SafetyDecision::ApprovalRequired);
        v.approval = Some(ApprovalId(Uuid::now_v7()));
        let action = store.propose(run.id, lease.session.id, &p, &v).await.unwrap();
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
        store.persist_approval(tenant, &lease, &request).await.unwrap();
        Self {
            raw,
            store: store.clone(),
            api,
            tenant,
            lease,
            request,
            reviewer,
        }
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
        self.snapshot().await
    }

    async fn snapshot(&self) -> DurableApprovalV1 {
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

    async fn consume(&self, snapshot: &DurableApprovalV1) -> bool {
        self.store
            .consume_approval(self.tenant, &self.lease, snapshot)
            .await
            .is_ok()
    }

    async fn intend_approved(&self, epoch: crawlx_core::epoch::ObservationEpoch) -> bool {
        self.store
            .intend_approved(
                self.tenant,
                &self.lease,
                self.request.binding.action,
                epoch,
                &self.allowed(),
            )
            .await
            .is_ok()
    }

    /// Register an authorization record of the tenant, verified and then revoked, and make the
    /// run depend on it: from then on the run has no live authorization.
    async fn revoke_authorization(&self) {
        let now = self.raw.now().await;
        let record = AuthorizationRecordId(Uuid::now_v7());
        let body = serde_json::json!({"profileCap": "test_environment"});
        let digest = [2_u8; 32];
        self.raw
            .run(
                "INSERT INTO authorization_records (record_id, tenant_id, version, body, body_digest, valid_from, valid_to, created_by) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    V::Uuid(record.0),
                    V::Uuid(self.tenant.0),
                    V::I32(1),
                    V::Json(&body),
                    V::Bytes(&digest),
                    V::Ts(now - Duration::hours(1)),
                    V::Ts(now + Duration::hours(1)),
                    V::Uuid(self.reviewer),
                ],
            )
            .await;
        self.raw
            .run(
                "UPDATE authorization_records SET verified_at = $1, revoked_at = $2 WHERE record_id = $3",
                &[V::Ts(now), V::Ts(now), V::Uuid(record.0)],
            )
            .await;
        self.raw
            .run(
                "UPDATE crawl_runs SET authorization_record_id = $1, authorization_body_digest = $2 WHERE run_id = $3",
                &[V::Uuid(record.0), V::Bytes(&digest), V::Uuid(self.lease.session.run.0)],
            )
            .await;
    }
}

db_case! {
    async fn durable_reviewer_decision_consumes_once_and_links_original_action_at_t1<B>(rig, store) {
        let f = Fixture::new(rig, store).await;
        let snapshot = f.decide(ApprovalDecision::Approved).await;
        assert_eq!(snapshot.record.decision, ApprovalDecision::Approved);
        let binding = &f.request.binding;
        let found = f
            .store
            .find_approval(
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
            .store
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
        assert!(
            f.store
                .intend(binding.action, f.lease.session.id, binding.epoch)
                .await
                .is_err(),
            "reviewer approval alone must not release the action hold"
        );
        for dimension in 0..7 {
            let mut wrong = snapshot.clone();
            match dimension {
                0 => wrong.request.binding.tenant = TenantId(Uuid::from_u128(101)),
                1 => wrong.request.binding.run = CrawlRunId(Uuid::from_u128(102)),
                2 => wrong.request.binding.action = ActionId(Uuid::from_u128(103)),
                3 => wrong.request.binding.params_digest.0[0] ^= 1,
                4 => wrong.request.binding.epoch.mutation_seq += 1,
                5 => wrong.request.binding.action_key.0[0] ^= 1,
                6 => wrong.request.binding.risk = RiskClass::Destructive,
                _ => unreachable!(),
            }
            assert!(!f.consume(&wrong).await, "dimension {dimension}");
        }
        let mut stale = f.lease.clone();
        stale.fencing_token += 1;
        assert!(f
            .store
            .consume_approval(f.tenant, &stale, &snapshot)
            .await
            .is_err());
        assert!(f
            .store
            .consume_approval(TenantId(Uuid::from_u128(999)), &f.lease, &snapshot)
            .await
            .is_err());
        let (left, right) = tokio::join!(f.consume(&snapshot), f.consume(&snapshot));
        assert_eq!(u32::from(left) + u32::from(right), 1);
        assert!(!f.consume(&snapshot).await);
        let mut changed = f.request.binding.epoch;
        changed.mutation_seq += 1;
        assert!(!f.intend_approved(changed).await);
        assert!(f.intend_approved(f.request.binding.epoch).await);
        let actions = ActionJournal::list(&f.store, f.lease.session.run, None)
            .await
            .unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].id, f.request.binding.action);
        let linked = f
            .raw
            .one(
                "SELECT p.safety_decision_id = a.safety_decision_id AS linked, p.consumed_at <= a.intended_at AS ordered \
                 FROM approvals p JOIN actions a ON a.action_id = p.action_id WHERE p.approval_id = $1",
                &[V::Uuid(f.request.id.0)],
            )
            .await;
        assert!(linked.flag("linked"));
        assert!(linked.flag("ordered"));
        assert!(!f.intend_approved(f.request.binding.epoch).await);
    }
}

db_case! {
    async fn durable_denial_expiry_revocation_and_lease_loss_refuse_consumption_and_intent<B>(rig, store) {
        for consumed_before_fault in [false, true] {
            for fault in [
                "denied",
                "expired",
                "revoked",
                "lease",
                "authorization",
                "cancelled",
            ] {
                let f = Fixture::new(rig, store).await;
                let snapshot = f
                    .decide(if fault == "denied" {
                        ApprovalDecision::Denied
                    } else {
                        ApprovalDecision::Approved
                    })
                    .await;
                if consumed_before_fault && fault != "denied" {
                    f.store
                        .consume_approval(f.tenant, &f.lease, &snapshot)
                        .await
                        .unwrap();
                }
                let now = f.raw.now().await;
                match fault {
                    "expired" => {
                        f.raw
                            .run(
                                "UPDATE approvals SET expires_at = $1 WHERE approval_id = $2",
                                &[V::Ts(now), V::Uuid(f.request.id.0)],
                            )
                            .await;
                    }
                    "revoked" => {
                        f.raw
                            .run(
                                "UPDATE approvals SET revoked_at = $1 WHERE approval_id = $2",
                                &[V::Ts(now), V::Uuid(f.request.id.0)],
                            )
                            .await;
                    }
                    "lease" => {
                        f.raw
                            .run(
                                "UPDATE crawl_sessions SET fencing_token = fencing_token + 1 WHERE session_id = $1",
                                &[V::Uuid(f.lease.session.id.0)],
                            )
                            .await;
                    }
                    "authorization" => f.revoke_authorization().await,
                    "cancelled" => {
                        f.raw
                            .run(
                                "UPDATE crawl_runs SET cancel_requested_at = $1 WHERE run_id = $2",
                                &[V::Ts(now), V::Uuid(f.lease.session.run.0)],
                            )
                            .await;
                    }
                    "denied" => {}
                    _ => unreachable!(),
                }
                assert!(
                    !f.consume(&snapshot).await,
                    "{fault}, consumed first: {consumed_before_fault}"
                );
                assert!(
                    !f.intend_approved(f.request.binding.epoch).await,
                    "{fault}, consumed first: {consumed_before_fault}"
                );
            }
        }
    }
}

db_case! {
    async fn durable_reviewer_racing_exact_request_binding_cannot_execute_unbound<B>(rig, store) {
        let f = Fixture::new(rig, store).await;
        let p = proposal("role0", StateClusterId(Uuid::nil()), 2);
        let mut v = verdict(SafetyDecision::ApprovalRequired);
        v.approval = Some(ApprovalId(Uuid::now_v7()));
        let action = f
            .store
            .propose(f.lease.session.run, f.lease.session.id, &p, &v)
            .await
            .unwrap();
        let now = f.raw.now().await;
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
        // the reviewer decides before the kernel has bound its exact request
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
            .store
            .consume_approval(f.tenant, &f.lease, &snapshot)
            .await
            .is_err());
        f.store.persist_approval(f.tenant, &f.lease, &request).await.unwrap();
        assert!(f
            .store
            .consume_approval(f.tenant, &f.lease, &snapshot)
            .await
            .is_ok());
    }
}

db_case! {
    async fn pending_denied_and_all_changed_bindings_fail_without_spending_real_request<B>(rig, store) {
        let f = Fixture::new(rig, store).await;
        let pending = f.snapshot().await;
        assert!(!f.consume(&pending).await, "a pending request is not spendable");
        let approved = f.decide(ApprovalDecision::Approved).await;
        for dimension in 0..7 {
            let mut changed = approved.clone();
            match dimension {
                0 => changed.request.binding.tenant = TenantId(Uuid::from_u128(11)),
                1 => changed.request.binding.run = CrawlRunId(Uuid::from_u128(12)),
                2 => changed.request.binding.action = ActionId(Uuid::from_u128(13)),
                3 => changed.request.binding.params_digest = crawlx_core::hash::Digest::of("test", b"wrong"),
                4 => changed.request.binding.epoch.mutation_seq += 1,
                5 => changed.request.binding.action_key.0[0] ^= 1,
                6 => changed.request.binding.risk = RiskClass::Destructive,
                _ => unreachable!(),
            }
            assert!(!f.consume(&changed).await, "dimension {dimension}");
        }
        assert!(f
            .store
            .consume_approval(TenantId(Uuid::from_u128(99)), &f.lease, &approved)
            .await
            .is_err());
        // none of the refusals spent the real request
        assert!(f.consume(&approved).await);

        let denied = Fixture::new(rig, store).await;
        let snapshot = denied.decide(ApprovalDecision::Denied).await;
        assert!(!denied.consume(&snapshot).await);
    }
}

db_case! {
    async fn concurrent_consumers_have_exactly_one_winner<B>(rig, store) {
        let f = Fixture::new(rig, store).await;
        let approved = f.decide(ApprovalDecision::Approved).await;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
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
}

db_case! {
    async fn stale_fence_revocation_expiry_and_changed_epoch_fail_closed_at_consume_and_t1<B>(rig, store) {
        let f = Fixture::new(rig, store).await;
        let approved = f.decide(ApprovalDecision::Approved).await;
        let mut stale = f.lease.clone();
        stale.fencing_token += 1;
        assert!(matches!(
            f.store.consume_approval(f.tenant, &stale, &approved).await,
            Err(crawlx_core::StoreError::LeaseLost)
        ));
        f.store
            .consume_approval(f.tenant, &f.lease, &approved)
            .await
            .unwrap();
        let mut changed = f.request.binding.epoch;
        changed.document_seq += 1;
        assert!(!f.intend_approved(changed).await, "a changed epoch");
        assert!(
            f.store
                .intend_approved(
                    f.tenant,
                    &stale,
                    f.request.binding.action,
                    f.request.binding.epoch,
                    &f.allowed()
                )
                .await
                .is_err(),
            "a stale fence"
        );
        // the run's authorization is revoked between consume and T1
        f.revoke_authorization().await;
        assert!(!f.intend_approved(f.request.binding.epoch).await, "a revoked authorization");

        // an approval whose durable expiry passed is not spendable
        let expired = Fixture::new(rig, store).await;
        let approved = expired.decide(ApprovalDecision::Approved).await;
        let now = expired.raw.now().await;
        expired
            .raw
            .run(
                "UPDATE approvals SET expires_at = $1 WHERE approval_id = $2",
                &[V::Ts(now), V::Uuid(expired.request.id.0)],
            )
            .await;
        assert!(!expired.consume(&approved).await, "an expired approval");

        // T1 is refused after durable expiry as well, even when consumption came first
        let late = Fixture::new(rig, store).await;
        let approved = late.decide(ApprovalDecision::Approved).await;
        assert!(late.consume(&approved).await);
        let now = late.raw.now().await;
        late.raw
            .run(
                "UPDATE approvals SET expires_at = $1 WHERE approval_id = $2",
                &[V::Ts(now), V::Uuid(late.request.id.0)],
            )
            .await;
        assert!(!late.intend_approved(late.request.binding.epoch).await, "T1 after expiry");
    }
}

db_case! {
    async fn approved_request_reuses_original_action_at_fenced_t1_and_replay_fails<B>(rig, store) {
        let f = Fixture::new(rig, store).await;
        f.store.persist_approval(f.tenant, &f.lease, &f.request).await.unwrap();
        let preview = f.decide(ApprovalDecision::Approved).await;
        assert!(f.store
            .intend(f.request.binding.action, f.lease.session.id, f.request.binding.epoch)
            .await.is_err(), "a reviewer decision alone preserves the hold");
        let binding = &f.request.binding;
        let found = f.store.find_approval(
            f.tenant, &f.lease, binding.action_key, binding.risk, binding.params_digest, binding.epoch,
        ).await.unwrap().unwrap();
        assert_eq!(found.request, f.request);
        let before = f.raw.now().await;
        let consumed = f.store.consume_approval(f.tenant, &f.lease, &preview).await.unwrap();
        let after = f.raw.now().await;
        assert_eq!(consumed.request.binding.action, binding.action);
        assert_eq!(consumed.fence, f.lease.fencing_token);
        assert!(consumed.consumed_at >= before && consumed.consumed_at <= after);
        assert!(!f.consume(&preview).await, "consumption cannot be replayed");
        let allowed = f.allowed();
        f.store.intend_approved(f.tenant, &f.lease, binding.action, binding.epoch, &allowed)
            .await.unwrap();
        let actions = ActionJournal::list(&f.store, f.lease.session.run, None).await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].id, binding.action);
        assert_eq!(actions[0].status, crawlx_core::counters::ActionStatus::Intended);
        assert_eq!(actions[0].safety_decision, allowed.decision_id);
        assert!(f.store.intend_approved(
            f.tenant, &f.lease, binding.action, binding.epoch, &allowed,
        ).await.is_err(), "T1 cannot be replayed");
    }
}
