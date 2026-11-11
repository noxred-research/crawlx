//! Durable approvals on every engine: the reviewer decision, the single-use consume and the T1
//! link, with the fence, expiry, revocation, authorization and cancellation refusals.
//! Ported from the PostgreSQL-only `durable_approvals_pg.rs`; the in-memory twin stays in
//! `durable_approvals.rs`.

use crate::rig::Rig;
use chrono::Duration;
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::safety::{SafetyDecision, SafetyVerdict};
use crawlx_core::{ApprovalId, CrawlRunId, StateClusterId, TenantId, WorkerId};
use crawlx_storage::approvals::{
    ApprovalBindingV1, ApprovalRepository, ApprovalRequestV1, DurableApprovalV1,
};
use crawlx_storage::tenant::Tenancy;
use crawlx_storage::testkit::tenancy::{Handle, Harness};
use crawlx_storage::testkit::{crawl_run, create_crawl, proposal, sessions, verdict};
use crawlx_storage::{with_handle, ApiKeyRow, ApiRepo, ApprovalDecision, LeaseRepo, SessionLease, Store};
use uuid::Uuid;

conformance! { databases:
    durable_reviewer_decision_consumes_once_and_links_original_action_at_t1,
    durable_denial_expiry_revocation_and_lease_loss_refuse_consumption_and_intent,
    durable_reviewer_racing_exact_request_binding_cannot_execute_unbound,
}

struct Fixture<B: Tenancy> {
    store: Store<B>,
    api: ApiRepo<B>,
    tenant: TenantId,
    lease: SessionLease,
    request: ApprovalRequestV1,
    reviewer: Uuid,
}

impl<B: Tenancy> Fixture<B>
where
    Store<B>: RunRepo + LeaseRepo + ActionJournal + ApprovalRepository,
{
    /// `salt` keeps the ids of several fixtures in one database apart.
    async fn new(store: Store<B>, handle: &Handle, salt: u128) -> Self {
        let tenant = TenantId(Uuid::from_u128(1 + salt * 1000));
        handle.ensure_tenant(tenant, "approval-test").await.unwrap();
        let now = store.now().await.unwrap();
        let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        run.created_at = now;
        store.create(&run, None).await.unwrap();
        store.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
        let lease = store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        let api = ApiRepo::new(store.clone());
        let reviewer = Uuid::from_u128(2 + salt * 1000);
        api.key_insert(
            &ApiKeyRow {
                key_id: reviewer,
                tenant,
                prefix: format!("approval-fixture-{salt}"),
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
        v.approval = Some(ApprovalId(Uuid::from_u128(3 + salt * 1000)));
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
            store,
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

async fn durable_reviewer_decision_consumes_once_and_links_original_action_at_t1(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    let op = &harness.operator;
    with_handle!(op, |store| {
        async {
        let f = Fixture::new(store.clone(), op, 0).await;
        let snapshot = f.decide(ApprovalDecision::Approved).await;
        assert_eq!(snapshot.record.decision, ApprovalDecision::Approved);
        let binding = &f.request.binding;
        let found = f
            .store
            .find_approval(f.tenant, &f.lease, binding.action_key, binding.risk, binding.params_digest, binding.epoch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.request, f.request);
        let mut wrong_params = binding.params_digest;
        wrong_params.0[0] ^= 1;
        assert!(f
            .store
            .find_approval(f.tenant, &f.lease, binding.action_key, binding.risk, wrong_params, binding.epoch)
            .await
            .unwrap()
            .is_none());
        assert!(f
            .store
            .intend(f.request.binding.action, f.lease.session.id, f.request.binding.epoch)
            .await
            .is_err());
        for dimension in 0..7 {
            let mut wrong = snapshot.clone();
            match dimension {
                0 => wrong.request.binding.tenant = TenantId(Uuid::from_u128(101)),
                1 => wrong.request.binding.run = CrawlRunId(Uuid::from_u128(102)),
                2 => wrong.request.binding.action = crawlx_core::ActionId(Uuid::from_u128(103)),
                3 => wrong.request.binding.params_digest.0[0] ^= 1,
                4 => wrong.request.binding.epoch.mutation_seq += 1,
                5 => wrong.request.binding.action_key.0[0] ^= 1,
                6 => wrong.request.binding.risk = crawlx_core::safety::RiskClass::Destructive,
                _ => unreachable!(),
            }
            assert!(f.store.consume_approval(f.tenant, &f.lease, &wrong).await.is_err());
        }
        let mut stale = f.lease.clone();
        stale.fencing_token += 1;
        assert!(f.store.consume_approval(f.tenant, &stale, &snapshot).await.is_err());
        assert!(f
            .store
            .consume_approval(TenantId(Uuid::from_u128(999)), &f.lease, &snapshot)
            .await
            .is_err());
        let (left, right) = tokio::join!(
            f.store.consume_approval(f.tenant, &f.lease, &snapshot),
            f.store.consume_approval(f.tenant, &f.lease, &snapshot)
        );
        assert_eq!(u32::from(left.is_ok()) + u32::from(right.is_ok()), 1);
        assert!(f.store.consume_approval(f.tenant, &f.lease, &snapshot).await.is_err());
        let mut changed = f.request.binding.epoch;
        changed.mutation_seq += 1;
        assert!(f
            .store
            .intend_approved(f.tenant, &f.lease, f.request.binding.action, changed, &f.allowed())
            .await
            .is_err());
        f.store
            .intend_approved(f.tenant, &f.lease, f.request.binding.action, f.request.binding.epoch, &f.allowed())
            .await
            .unwrap();
        let actions = ActionJournal::list(&f.store, f.lease.session.run, None).await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].id, f.request.binding.action);
        // the approval links the decision of the original action and was consumed before T1
        let linked = op
            .count(
                "approvals p JOIN actions a ON a.action_id = p.action_id",
                &format!(
                    "p.approval_id = {} AND p.safety_decision_id = a.safety_decision_id AND p.consumed_at <= a.intended_at",
                    op.id(f.request.id.0)
                ),
            )
            .await
            .unwrap();
        assert_eq!(linked, 1);
        assert!(f
            .store
            .intend_approved(f.tenant, &f.lease, f.request.binding.action, f.request.binding.epoch, &f.allowed())
            .await
            .is_err());
    }
    .await
    });
    harness.finish().await.unwrap();
}

async fn durable_denial_expiry_revocation_and_lease_loss_refuse_consumption_and_intent(rig: &Rig) {
    // each fault gets a fixture of its own (distinct ids) in the one migrated database
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    let op = &harness.operator;
    let mut salt = 10_u128;
    for consumed_before_fault in [false, true] {
        for fault in [
            "denied",
            "expired",
            "revoked",
            "lease",
            "authorization",
            "cancelled",
        ] {
            salt += 1;
            with_handle!(op, |store| {
                async {
                let f = Fixture::new(store.clone(), op, salt).await;
                let snapshot = f
                    .decide(if fault == "denied" {
                        ApprovalDecision::Denied
                    } else {
                        ApprovalDecision::Approved
                    })
                    .await;
                if consumed_before_fault && fault != "denied" {
                    f.store.consume_approval(f.tenant, &f.lease, &snapshot).await.unwrap();
                }
                let clock = op.clock_sql();
                match fault {
                    "expired" => {
                        op.run(&format!(
                            "UPDATE approvals SET expires_at = {clock} WHERE approval_id = {}",
                            op.id(f.request.id.0)
                        ))
                        .await
                        .unwrap();
                    }
                    "revoked" => {
                        op.run(&format!(
                            "UPDATE approvals SET revoked_at = {clock} WHERE approval_id = {}",
                            op.id(f.request.id.0)
                        ))
                        .await
                        .unwrap();
                    }
                    "lease" => {
                        op.run(&format!(
                            "UPDATE crawl_sessions SET fencing_token = fencing_token + 1 WHERE session_id = {}",
                            op.id(f.lease.session.id.0)
                        ))
                        .await
                        .unwrap();
                    }
                    "authorization" => {
                        let record = Uuid::from_u128(501 + salt * 1000);
                        let key = op.id(f.reviewer);
                        op.run(&format!(
                            "INSERT INTO authorization_records (record_id, tenant_id, version, body, body_digest, valid_from, valid_to, \
                             created_by, verified_at, revoked_at) VALUES ({rec}, {tenant}, 1, '{{\"profileCap\":\"test_environment\"}}', {digest}, \
                             {past}, {future}, {key}, {clock}, {clock})",
                            rec = op.id(record),
                            tenant = op.id(f.tenant.0),
                            digest = op.bytes(&[2_u8; 32]),
                            past = shifted(op, "-", 1),
                            future = shifted(op, "+", 1),
                        ))
                        .await
                        .unwrap();
                        op.run(&format!(
                            "UPDATE crawl_runs SET authorization_record_id = {rec}, authorization_body_digest = {digest} WHERE run_id = {run}",
                            rec = op.id(record),
                            digest = op.bytes(&[2_u8; 32]),
                            run = op.id(f.lease.session.run.0),
                        ))
                        .await
                        .unwrap();
                    }
                    "cancelled" => {
                        op.run(&format!(
                            "UPDATE crawl_runs SET cancel_requested_at = {clock} WHERE run_id = {}",
                            op.id(f.lease.session.run.0)
                        ))
                        .await
                        .unwrap();
                    }
                    "denied" => {}
                    _ => unreachable!(),
                }
                assert!(
                    f.store.consume_approval(f.tenant, &f.lease, &snapshot).await.is_err(),
                    "{fault} (consumed first: {consumed_before_fault}) still consumed"
                );
                assert!(
                    f.store
                        .intend_approved(f.tenant, &f.lease, f.request.binding.action, f.request.binding.epoch, &f.allowed())
                        .await
                        .is_err(),
                    "{fault} (consumed first: {consumed_before_fault}) still reached T1"
                );
            }
            .await
            });
        }
    }
    harness.finish().await.unwrap();
}

/// `now() +/- hours` in the dialect of `handle`.
fn shifted(handle: &Handle, sign: &str, hours: i64) -> String {
    match handle {
        Handle::Postgres(_) => format!("now() {sign} interval '{hours} hours'"),
        Handle::MariaDb(_) => format!("DATE_ADD(NOW(6), INTERVAL {sign}{hours} HOUR)"),
        Handle::Sqlite(_) => format!(
            "(CAST(unixepoch('subsec') * 1000000 AS INTEGER) {sign} {})",
            hours * 3_600_000_000
        ),
    }
}

async fn durable_reviewer_racing_exact_request_binding_cannot_execute_unbound(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    let op = &harness.operator;
    with_handle!(op, |store| async {
        let f = Fixture::new(store.clone(), op, 99).await;
        let p = proposal("role0", StateClusterId(Uuid::nil()), 2);
        let mut v = verdict(SafetyDecision::ApprovalRequired);
        v.approval = Some(ApprovalId(Uuid::from_u128(20 + 99 * 1000)));
        let action = f
            .store
            .propose(f.lease.session.run, f.lease.session.id, &p, &v)
            .await
            .unwrap();
        let now = f.store.now().await.unwrap();
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
        // the reviewer decides before the kernel has bound the request
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
    .await);
    harness.finish().await.unwrap();
}
