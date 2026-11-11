//! Reviewer HTTP decisions cross the same durable table used by the worker kernel bridge.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::StatusCode;
use chrono::{TimeZone, Utc};
use crawlx_api::{ApiConfig, Settings};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::config::{DestructiveActions, LaunchProfile, SafetyProfile};
use crawlx_core::observation::{LiveTargetFacts, RuntimeLocator};
use crawlx_core::repo::{ActionJournal, RunRepo, SafetyContext};
use crawlx_core::time::{Clock, ManualClock};
use crawlx_core::{BackendNodeId, FrameId, StateClusterId, TabId, WorkerId};
use crawlx_safety::approvals::{ApprovalAuthority, VerifiedApproval};
use crawlx_safety::{Adjudication, KernelConfig, SafetyKernel};
use crawlx_storage::approvals::{
    ApprovalBindingV1, ApprovalRepository, ApprovalRequestV1, DurableApprovalV1,
};
use crawlx_storage::testkit::{crawl_run, create_crawl, proposal, sessions};
use crawlx_storage::LeaseRepo;
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn reviewer_http_approved_action_reaches_kernel_and_original_journal_once() {
    for approved in [true, false] {
        let clock = Arc::new(ManualClock::new(
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        ));
        let e = common::env_with(ApiConfig::default(), Settings::default(), clock.clone());
        let mut run = crawl_run(e.tenant, create_crawl("https://example.test/", &[], 1));
        run.created_at = clock.now();
        run.config.safety.profile = SafetyProfile::TestEnvironment;
        run.config.safety.destructive_actions = DestructiveActions::Approval;
        run.config_digest = run.config.digest().unwrap();
        e.store.create(&run, None).await.unwrap();
        e.store.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
        let lease = e
            .store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        let kernel = SafetyKernel::new_with_clock(
            KernelConfig {
                profile: SafetyProfile::TestEnvironment,
                launch_profile: LaunchProfile::Standard,
                has_test_sinks: false,
                destructive_approval: DestructiveActions::Approval,
                seed_origin: "https://example.test".into(),
                policy_version: 1,
            },
            clock.clone(),
        )
        .unwrap()
        .with_run_deadline(clock.now() + chrono::Duration::minutes(5));
        let mut p = proposal("role0", StateClusterId(uuid::Uuid::nil()), 1);
        p.action = BrowserAction::Click {
            target: RuntimeLocator {
                tab: TabId("approval-tab".into()),
                frame: FrameId("main".into()),
                backend_node_id: BackendNodeId(1),
                object_id: None,
                ax_node_id: None,
                epoch: p.epoch,
            },
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        };
        p.key.action_kind = p.action.kind();
        let context = SafetyContext {
            profile: SafetyProfile::TestEnvironment,
            has_test_sinks: false,
            destructive_approval_allowed: true,
            principal: lease.session.role.clone(),
            seed_origin: "https://example.test".into(),
            in_scope: true,
            target: LiveTargetFacts {
                current_url: "https://example.test/projects".into(),
                role: Some("button".into()),
                name: Some("Delete project".into()),
                ..LiveTargetFacts::default()
            },
            form_hint: None,
        };
        let Adjudication::ApprovalRequired(verdict, request) = kernel.adjudicate(p.clone(), &context) else {
            panic!("destructive action must require approval");
        };
        assert_eq!(request.expires_at, clock.now() + chrono::Duration::minutes(5));
        let action = e
            .store
            .propose(run.id, lease.session.id, &p, &verdict)
            .await
            .unwrap();
        let durable = ApprovalRequestV1::new(
            request.approval_id,
            ApprovalBindingV1::new(
                e.tenant,
                &lease,
                action,
                request.action_key,
                request.risk,
                request.params_digest,
                p.epoch,
            ),
            request.summary.clone(),
            request.created_at,
            request.expires_at,
        );
        e.store
            .persist_approval(e.tenant, &lease, &durable)
            .await
            .unwrap();
        let path = format!(
            "/v1/crawls/{}/approvals/{}:{}",
            run.id,
            request.approval_id,
            if approved { "approve" } else { "deny" }
        );
        let foreign = e
            .key_for("other-approval-tenant", &[crawlx_api::Scope::ApprovalsDecide])
            .await;
        let (status, _, _) = e
            .send(
                axum::http::Method::POST,
                &path,
                Some(&foreign),
                &[],
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = e.post(&path, &json!({"reason":"reviewed fixture"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["consumed"], false);
        let record = e.store.approval_records(run.id).remove(0);
        let snapshot = DurableApprovalV1::new(durable, record);
        if !approved {
            assert!(e
                .store
                .consume_approval(e.tenant, &lease, &snapshot)
                .await
                .is_err());
            assert!(!matches!(kernel.adjudicate(p, &context), Adjudication::Allow(_)));
            continue;
        }
        // An HTTP decision is not itself an admission capability.
        assert!(!matches!(
            kernel.adjudicate(p.clone(), &context),
            Adjudication::Allow(_)
        ));
        let receipt = e
            .store
            .consume_approval(e.tenant, &lease, &snapshot)
            .await
            .unwrap();
        assert_eq!(receipt.request.binding.action, action);
        let authority =
            ApprovalAuthority::new(e.tenant, run.id, lease.session.id, action, receipt.fence, p.epoch);
        let mut verified = VerifiedApproval::from_consumed(request, authority);
        let Adjudication::Allow(admitted) =
            kernel.adjudicate_verified(p.clone(), &context, authority, &mut verified)
        else {
            panic!("verified reviewer decision must reach the kernel");
        };
        assert!(kernel.confirm(&admitted, &context.target).is_ok());
        e.store
            .intend_approved(e.tenant, &lease, action, p.epoch, admitted.verdict())
            .await
            .unwrap();
        assert!(e
            .store
            .consume_approval(e.tenant, &lease, &snapshot)
            .await
            .is_err());
        assert!(matches!(
            kernel.adjudicate_verified(p, &context, authority, &mut verified),
            Adjudication::Deny(_)
        ));
        let actions = ActionJournal::list(e.store.as_ref(), run.id, None).await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].id, action);
        let (status, _, body) = e.get(&format!("/v1/crawls/{}/approvals", run.id)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["consumed"], true);
    }
}
