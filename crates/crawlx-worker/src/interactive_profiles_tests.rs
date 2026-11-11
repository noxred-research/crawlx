//! Deterministic local interactive control and cleanup tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{CrawlSession, SessionKind, SessionStatus};
use crawlx_core::session_binding::SessionIdentityV1;
use crawlx_core::time::ManualClock;
use crawlx_core::PrincipalId;

fn fixture() -> (
    Arc<InteractiveProfiles>,
    InteractiveControl,
    InteractiveScope,
    Arc<ManualClock>,
) {
    let now = Timestamp::from_timestamp(1_700_000_000, 0).unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let registry = Arc::new(
        InteractiveProfiles::new(clock.clone(), url::Url::parse("http://127.0.0.1:8080/").unwrap()).unwrap(),
    );
    let tenant = TenantId(uuid::Uuid::from_u128(1));
    let session = CrawlSession {
        id: SessionId(uuid::Uuid::from_u128(2)),
        run: CrawlRunId(uuid::Uuid::from_u128(3)),
        kind: SessionKind::Browser,
        role: PrincipalId("operator".into()),
        run_index: 1,
        schedule_slot: 0,
        status: SessionStatus::Running,
        browser: None,
        action_seq: 0,
    };
    let digest = Digest::of("test/interactive", b"local");
    let identity = SessionIdentityV1::new(tenant, &session, digest, digest, digest, digest, None);
    let binding = SessionBindingV1::new(identity, 7, now + chrono::Duration::minutes(10));
    let scope = InteractiveScope::new(
        tenant,
        session.run,
        session.id,
        1,
        7,
        "api_key:local-owner".into(),
    );
    let control = registry.register(binding, CancellationToken::new()).unwrap();
    (registry, control, scope, clock)
}

fn request() -> InteractiveStart {
    InteractiveStart {
        profile_name: "interactive-session".into(),
        expected_generation: 0,
        ttl_seconds: 60,
        retained_profile_consent: true,
        capture_consent: true,
        privacy_consent: true,
    }
}

async fn accept_start(
    registry: &InteractiveProfiles,
    control: &mut InteractiveControl,
    scope: &InteractiveScope,
    request: InteractiveStart,
) -> InteractiveStatus {
    let (status, ()) = tokio::join!(registry.start(scope, request), async {
        let InteractiveCommand::Start { reply, .. } = control.recv().await.unwrap() else {
            panic!("start command required");
        };
        reply.send(Ok(InteractiveReply::Ready)).unwrap();
    });
    status.unwrap()
}

#[test]
fn local_origin_and_explicit_consent_are_required() {
    let now = Timestamp::from_timestamp(1_700_000_000, 0).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(now));
    for value in [
        "http://remote.test/",
        "http://localhost/",
        "http://127.0.0.1/path",
        "http://127.0.0.1/?token=x",
        "http://user@127.0.0.1/",
    ] {
        assert!(InteractiveProfiles::new(clock.clone(), url::Url::parse(value).unwrap()).is_err());
    }
    let mut missing = request();
    missing.retained_profile_consent = false;
    assert_eq!(missing.validate(), Err(InteractiveError::Invalid));
    missing = request();
    missing.privacy_consent = false;
    assert_eq!(missing.validate(), Err(InteractiveError::Invalid));
    for name in ["", ".", "..", "../profile", "a/b"] {
        let mut invalid = request();
        invalid.profile_name = name.into();
        assert_eq!(invalid.validate(), Err(InteractiveError::Invalid));
    }
}

#[tokio::test]
async fn authenticated_scope_checks_every_dimension_and_owner() {
    let (registry, mut control, scope, _) = fixture();
    accept_start(&registry, &mut control, &scope, request()).await;
    let mut cases = Vec::new();
    let mut altered = scope.clone();
    altered.tenant = TenantId(uuid::Uuid::from_u128(10));
    cases.push(altered);
    let mut altered = scope.clone();
    altered.run = CrawlRunId(uuid::Uuid::from_u128(10));
    cases.push(altered);
    let mut altered = scope.clone();
    altered.session = SessionId(uuid::Uuid::from_u128(10));
    cases.push(altered);
    let mut altered = scope.clone();
    altered.generation += 1;
    cases.push(altered);
    let mut altered = scope.clone();
    altered.lease_fence += 1;
    cases.push(altered);
    let mut altered = scope.clone();
    altered.owner = "api_key:other-owner".into();
    cases.push(altered);
    for altered in cases {
        assert!(matches!(
            registry.status(&altered).await,
            Err(InteractiveError::Unavailable)
        ));
    }
    assert!(control.rx.try_recv().is_err());
}

#[tokio::test]
async fn start_input_and_finish_wait_for_actual_actor_boundaries() {
    let (registry, mut control, scope, _) = fixture();
    assert_eq!(
        accept_start(&registry, &mut control, &scope, request())
            .await
            .state,
        InteractiveState::Active
    );
    let input = ProfileInput::Activate {
        selector: "button[data-action=login]".into(),
    };
    let (status, ()) = tokio::join!(registry.input(&scope, input), async {
        let InteractiveCommand::Input {
            scope: command_scope,
            input,
            reply,
        } = control.recv().await.unwrap()
        else {
            panic!("input required");
        };
        assert_eq!(command_scope, scope);
        assert_eq!(input.selector(), "button[data-action=login]");
        reply.send(Ok(InteractiveReply::Accepted)).unwrap();
    });
    assert_eq!(status.unwrap().state, InteractiveState::Active);
    let (status, ()) = tokio::join!(registry.finish(&scope), async {
        let InteractiveCommand::Finish { reply, .. } = control.recv().await.unwrap() else {
            panic!("finish required");
        };
        reply
            .send(Ok(InteractiveReply::Committed { generation: 1 }))
            .unwrap();
    });
    assert_eq!(status.unwrap().committed_generation, Some(1));
    drop(control);
    assert_eq!(
        registry.status(&scope).await.unwrap().state,
        InteractiveState::Finished
    );
}

#[tokio::test]
async fn wrong_commit_generation_never_reports_saved_profile() {
    let (registry, mut control, scope, _) = fixture();
    accept_start(&registry, &mut control, &scope, request()).await;
    let (status, ()) = tokio::join!(registry.finish(&scope), async {
        let InteractiveCommand::Finish { reply, .. } = control.recv().await.unwrap() else {
            panic!("finish required");
        };
        reply
            .send(Ok(InteractiveReply::Committed { generation: 2 }))
            .unwrap();
    });
    assert!(matches!(status, Err(InteractiveError::Refused)));
    assert!(control.cancellation().is_cancelled());
}

#[tokio::test]
async fn expiry_cancel_and_actor_drop_revoke_controls() {
    let (registry, mut control, scope, clock) = fixture();
    accept_start(&registry, &mut control, &scope, request()).await;
    clock.advance_ms(60_001);
    assert!(matches!(
        registry.status(&scope).await,
        Err(InteractiveError::Unavailable)
    ));
    assert!(control.recv().await.is_none());
    assert!(control.cancellation().is_cancelled());

    let (registry, mut control, scope, _) = fixture();
    accept_start(&registry, &mut control, &scope, request()).await;
    assert_eq!(registry.cancel(&scope).unwrap().state, InteractiveState::Closed);
    assert!(control.recv().await.is_none());

    let (registry, control, scope, _) = fixture();
    drop(control);
    assert!(matches!(
        registry.start(&scope, request()).await,
        Err(InteractiveError::Unavailable)
    ));
}

#[tokio::test]
async fn cancelled_api_operation_cancels_actor_instead_of_detaching_input() {
    let (registry, mut control, scope, _) = fixture();
    accept_start(&registry, &mut control, &scope, request()).await;
    let mut pending = Box::pin(registry.input(
        &scope,
        ProfileInput::Activate {
            selector: "button".into(),
        },
    ));
    let command = tokio::select! {
        result = &mut pending => panic!("input unexpectedly completed: {result:?}"),
        command = control.recv() => command.unwrap(),
    };
    drop(pending);
    let InteractiveCommand::Input { reply, .. } = command else {
        panic!("input required");
    };
    assert!(reply.is_closed());
    assert!(control.cancellation().is_cancelled());
    assert!(matches!(
        registry.status(&scope).await,
        Err(InteractiveError::Unavailable)
    ));
}

#[tokio::test]
async fn capture_requires_start_opt_in_and_suppresses_unproven_pixels() {
    let (registry, mut control, scope, _) = fixture();
    let mut no_capture = request();
    no_capture.capture_consent = false;
    accept_start(&registry, &mut control, &scope, no_capture).await;
    let (result, ()) = tokio::join!(registry.subscribe(&scope, true, true), async {
        let InteractiveCommand::Inspect { reply, .. } = control.recv().await.unwrap() else {
            panic!("inspect required");
        };
        reply.send(Ok(InteractiveReply::Accepted)).unwrap();
    });
    assert!(matches!(result, Err(InteractiveError::Refused)));

    let (registry, mut control, scope, _) = fixture();
    accept_start(&registry, &mut control, &scope, request()).await;
    let (result, ()) = tokio::join!(registry.subscribe(&scope, true, true), async {
        let InteractiveCommand::Inspect { reply, .. } = control.recv().await.unwrap() else {
            panic!("inspect required");
        };
        reply.send(Ok(InteractiveReply::Accepted)).unwrap();
    });
    let mut receiver = result.unwrap();
    assert_eq!(
        receiver.recv().await.unwrap().reason(),
        crawlx_browser::screencast::SuppressionReason::PrivacyUnproven
    );
    control.suppress_frame(true).unwrap();
    assert_eq!(
        receiver.recv().await.unwrap().reason(),
        crawlx_browser::screencast::SuppressionReason::SecretPresent
    );
    registry.cancel(&scope).unwrap();
    assert!(receiver.recv().await.is_none());
}

#[test]
fn input_accepts_only_bounded_reference_only_vocabulary() {
    assert!(
        serde_json::from_value::<ProfileInput>(serde_json::json!({"kind":"evaluate","script":"x"})).is_err()
    );
    assert!(serde_json::from_value::<ProfileInput>(serde_json::json!({"kind":"type_secret","selector":"#password","credential":"vault://role/password","value":"raw"})).is_err());
    assert!(ProfileInput::TypeSecret {
        selector: "#password".into(),
        credential: CredentialRef("raw-value".into())
    }
    .validate()
    .is_err());
    assert!(ProfileInput::Activate {
        selector: "a".repeat(2049)
    }
    .validate()
    .is_err());
}

#[tokio::test]
async fn concurrent_control_rejection_does_not_partially_change_workflow_state() {
    let (registry, mut control, scope, _) = fixture();
    accept_start(&registry, &mut control, &scope, request()).await;
    let mut pending = Box::pin(registry.status(&scope));
    let command = tokio::select! {
        result = &mut pending => panic!("status unexpectedly completed: {result:?}"),
        command = control.recv() => command.unwrap(),
    };
    assert!(matches!(
        registry.finish(&scope).await,
        Err(InteractiveError::Busy)
    ));
    assert_eq!(
        registry.entry(&scope).unwrap().status().state,
        InteractiveState::Active
    );
    let InteractiveCommand::Inspect { reply, .. } = command else {
        panic!("inspect required");
    };
    reply.send(Ok(InteractiveReply::Accepted)).unwrap();
    assert_eq!(pending.await.unwrap().state, InteractiveState::Active);
    assert!(!control.cancellation().is_cancelled());
}
