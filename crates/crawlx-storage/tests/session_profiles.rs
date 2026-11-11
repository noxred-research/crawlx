//! Real PostgreSQL session/profile consumer regressions. Skip without CRAWLX_TEST_DATABASE_URL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::counters::{ActionStatus, ReconcileResolution, RunStatus};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ActionJournal, EventRepo, Reconciliation, RunRepo, SessionStatus};
use crawlx_core::session_binding::{
    BindingState, RetirementReason, SessionBindingError, SessionBindingV1, SessionIdentityV1, SessionLimits,
};
use crawlx_core::{TenantId, WorkerId};
use crawlx_storage::leases::{LeaseRepo, SessionLease};
use crawlx_storage::profiles::{BrowserProfileRepo, ProfileCipher, ProfileFiles, ProfileScopeV1};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions};
use crawlx_storage::{Pg, PgConfig};
use std::collections::{BTreeMap, BTreeSet};

async fn fixture() -> Option<(Pg, Pg, TenantId, SessionLease, SessionLease)> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let config = PgConfig {
        schema: Some(format!("profile_{}", uuid::Uuid::now_v7().simple())),
        ..PgConfig::default()
    };
    let pg = Pg::connect(&url, config.clone()).await.unwrap();
    pg.migrate().await.unwrap();
    let other_process = Pg::connect(&url, config).await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "profile-regression").await.unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 2));
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 2)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let first = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let second = other_process
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    Some((pg, other_process, tenant, first, second))
}

fn scope(tenant: TenantId, lease: &SessionLease) -> ProfileScopeV1 {
    ProfileScopeV1::new(
        tenant,
        lease.session.role.clone(),
        "fixture".into(),
        BTreeSet::from(["https://example.test".into()]),
        Digest::of("build", b"pinned"),
        Digest::of("egress", b"approved"),
    )
    .unwrap()
}

#[tokio::test]
async fn two_connections_cannot_lease_one_profile_generation_or_reuse_a_stale_session_fence() {
    let Some((pg, peer, tenant, lease, other)) = fixture().await else {
        return;
    };
    let now = pg.now().await.unwrap();
    let digest = Digest::of("fixture", b"bound");
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let first_binding = pg
        .bind_session(&lease, identity.clone(), now + chrono::Duration::minutes(10))
        .await
        .unwrap();
    assert!(
        peer.bind_session(&lease, identity.clone(), now + chrono::Duration::minutes(10))
            .await
            .is_err(),
        "same lease cannot spawn two bound actors"
    );
    let cipher = ProfileCipher::new(&[9; 32]).unwrap();
    let scope = scope(tenant, &lease);
    let bytes = cipher
        .seal(
            &scope,
            1,
            now + chrono::Duration::minutes(5),
            ProfileFiles::new(
                BTreeMap::from([("Default/Cookies".into(), b"profile-secret-canary".to_vec())]),
                false,
            )
            .unwrap(),
        )
        .unwrap();
    let pinned = Digest::of("crawlx/profile-bundle/v1", &bytes);
    let service = BrowserProfileRepo::new(&pg, &cipher);
    service
        .import(&lease, &scope, &bytes, pinned, 0, true, false)
        .await
        .unwrap();
    assert!(
        BrowserProfileRepo::new(&peer, &cipher)
            .acquire(&other, &scope, false)
            .await
            .is_err(),
        "another live actor cannot acquire this generation"
    );
    assert!(
        service
            .import(&lease, &scope, &bytes, pinned, 0, true, false)
            .await
            .is_err(),
        "create replay is a generation conflict, not overwrite"
    );
    let stored: Vec<u8> = sqlx::query_scalar("SELECT encrypted_bundle FROM browser_profiles")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(stored, bytes);
    assert!(!stored
        .windows(b"profile-secret-canary".len())
        .any(|window| window == b"profile-secret-canary"));
    pg.release(&lease, SessionStatus::Recovering).await.unwrap();
    let replacement = peer
        .claim_session(lease.session.run, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replacement.session.id, lease.session.id);
    let renewed = peer
        .bind_session(&replacement, identity, now + chrono::Duration::minutes(10))
        .await
        .unwrap();
    assert_eq!(
        renewed.generation, first_binding.generation,
        "handover does not silently swap identity generation"
    );
    assert!(pg
        .update_session_binding(&lease, first_binding.state_version, &first_binding)
        .await
        .is_err());
    assert!(service.export(&lease, &scope, 1, false).await.is_err());
    assert!(BrowserProfileRepo::new(&peer, &cipher)
        .acquire(&replacement, &scope, false)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn binding_expiry_uses_only_durable_login_credit_and_a_bounded_reservation() {
    let Some((pg, _, tenant, lease, other)) = fixture().await else {
        return;
    };
    let run = RunRepo::get(&pg, lease.session.run).await.unwrap();
    let raw_deadline = run.started_at.unwrap_or(run.created_at)
        + chrono::Duration::seconds(i64::from(run.config.limits.duration_seconds));
    let digest = Digest::of("fixture", b"login-clock");
    let budget = |credit, allowance| {
        serde_json::json!({
            "session_id": lease.session.id,
            "login_credit_ms": credit,
            "login_allowance_ms": allowance,
        })
    };
    let first = EventRepo::append(&pg, run.id, "session.budget", budget(0, 0))
        .await
        .unwrap();
    // Model a completed measured login without a real-time sleep.
    sqlx::query("UPDATE crawl_events SET created_at=clock_timestamp()-interval '2 seconds' WHERE run_id=$1 AND seq=$2")
        .bind(run.id.0).bind(i64::try_from(first).unwrap()).execute(pg.pool()).await.unwrap();
    EventRepo::append(&pg, run.id, "session.budget", budget(1_000, 10_000))
        .await
        .unwrap();
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let binding = pg
        .bind_session(&lease, identity, raw_deadline + chrono::Duration::days(1))
        .await
        .unwrap();
    assert_eq!(
        binding.expires_at,
        raw_deadline + chrono::Duration::milliseconds(11_000)
    );
    // Another slot cannot borrow the first slot's active reservation.
    let identity = SessionIdentityV1::new(tenant, &other.session, digest, digest, digest, digest, None);
    let binding = pg
        .bind_session(&other, identity, raw_deadline + chrono::Duration::days(1))
        .await
        .unwrap();
    assert_eq!(
        binding.expires_at,
        raw_deadline + chrono::Duration::milliseconds(1_000)
    );
    EventRepo::append(
        &pg,
        run.id,
        "session.budget",
        budget(
            1_000,
            crawlx_storage::session_binding::MAX_LOGIN_RESERVATION_MS + 1,
        ),
    )
    .await
    .unwrap();
    let identity = SessionIdentityV1::new(tenant, &other.session, digest, digest, digest, digest, None);
    let error = pg
        .bind_session(&other, identity, raw_deadline + chrono::Duration::days(1))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("invalid durable login clock"));
}

#[tokio::test]
async fn fenced_recovery_can_reserve_relogin_past_the_previous_exploration_deadline() {
    let Some((pg, peer, tenant, lease, _)) = fixture().await else {
        return;
    };
    let run = RunRepo::get(&pg, lease.session.run).await.unwrap();
    let raw = pg.now().await.unwrap() + chrono::Duration::seconds(10);
    let started = raw - chrono::Duration::seconds(i64::from(run.config.limits.duration_seconds));
    sqlx::query("UPDATE crawl_runs SET started_at=$2 WHERE run_id=$1")
        .bind(run.id.0)
        .bind(started)
        .execute(pg.pool())
        .await
        .unwrap();
    let digest = Digest::of("fixture", b"recovery-login");
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let reservation = serde_json::json!({
        "session_id": lease.session.id,
        "login_credit_ms": 0,
        "login_allowance_ms": 20_000,
    });
    EventRepo::append(&pg, run.id, "session.budget", reservation.clone())
        .await
        .unwrap();
    let mut old = pg
        .bind_session(&lease, identity.clone(), raw + chrono::Duration::seconds(20))
        .await
        .unwrap();
    let version = old.state_version;
    old.state_version = old.state_version.checked_add(1).unwrap();
    old.expires_at = raw;
    pg.update_session_binding(&lease, version, &old).await.unwrap();
    assert_eq!(old.lifetime_expires_at, Some(raw + chrono::Duration::seconds(20)));
    // A later fenced holder reserves relogin after the previous actor narrowed to raw.
    EventRepo::append(&pg, run.id, "session.budget", reservation)
        .await
        .unwrap();
    pg.release(&lease, SessionStatus::Recovering).await.unwrap();
    let replacement = peer
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replacement.session.id, lease.session.id);
    assert_ne!(replacement.fencing_token, lease.fencing_token);
    let mut renewed = peer
        .bind_session(
            &replacement,
            identity.clone(),
            raw + chrono::Duration::seconds(20),
        )
        .await
        .unwrap();
    assert_eq!(renewed.generation, old.generation);
    assert_eq!(renewed.expires_at, raw + chrono::Duration::seconds(20));
    assert_eq!(renewed.lifetime_expires_at, old.lifetime_expires_at);
    assert!(
        renewed
            .eligible(
                &identity,
                replacement.fencing_token,
                raw + chrono::Duration::seconds(1),
                crawlx_core::session_binding::SessionLimits::default(),
            )
            .is_ok(),
        "the bounded relogin can outlast the remaining exploration time"
    );
    let version = renewed.state_version;
    renewed.state_version = renewed.state_version.checked_add(1).unwrap();
    renewed.expires_at = raw + chrono::Duration::seconds(5);
    peer.update_session_binding(&replacement, version, &renewed)
        .await
        .unwrap();
    let mut changed_cap = renewed.clone();
    changed_cap.state_version = changed_cap.state_version.checked_add(1).unwrap();
    changed_cap.lifetime_expires_at = Some(raw + chrono::Duration::seconds(21));
    assert!(
        peer.update_session_binding(&replacement, renewed.state_version, &changed_cap,)
            .await
            .is_err(),
        "fenced recovery cannot alter the lifetime ceiling"
    );
    assert!(
        pg.verify_session_binding(&lease, &old).await.is_err(),
        "old actor remains fenced"
    );
}

#[tokio::test]
async fn expired_binding_keeps_independent_lease_profile_and_repository_failures() {
    use crawlx_core::session_binding::SessionBindingError;
    use crawlx_core::StoreError;
    use crawlx_storage::session_binding::SessionBindingVerificationError;

    let Some((pg, peer, tenant, lease, other)) = fixture().await else {
        return;
    };
    let now = pg.now().await.unwrap();
    let digest = Digest::of("fixture", b"expiry-cause");
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let mut binding = pg
        .bind_session(&lease, identity, now + chrono::Duration::minutes(1))
        .await
        .unwrap();
    let version = binding.state_version;
    binding.state_version = binding.state_version.checked_add(1).unwrap();
    binding.expires_at = now - chrono::Duration::seconds(1);
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(matches!(
        pg.verify_session_binding(&lease, &binding).await,
        Err(SessionBindingVerificationError::Binding(
            SessionBindingError::Expired
        )),
    ));
    let mut fenced = lease.clone();
    fenced.fencing_token = fenced.fencing_token.checked_add(1).unwrap();
    assert!(matches!(
        pg.verify_session_binding(&fenced, &binding).await,
        Err(SessionBindingVerificationError::Store(StoreError::LeaseLost)),
    ));

    let cipher = ProfileCipher::new(&[7; 32]).unwrap();
    let profile_scope = scope(tenant, &other);
    let bytes = cipher
        .seal(
            &profile_scope,
            1,
            now + chrono::Duration::minutes(1),
            ProfileFiles::new(BTreeMap::new(), false).unwrap(),
        )
        .unwrap();
    BrowserProfileRepo::new(&pg, &cipher)
        .import(
            &other,
            &profile_scope,
            &bytes,
            Digest::of("crawlx/profile-bundle/v1", &bytes),
            0,
            true,
            false,
        )
        .await
        .unwrap();
    let profile = Digest::of_value("crawlx/profile-identity/v1", &(&profile_scope, 1_u64)).unwrap();
    let identity = SessionIdentityV1::new(
        tenant,
        &other.session,
        digest,
        digest,
        digest,
        digest,
        Some(profile),
    );
    let mut profiled = pg
        .bind_session(&other, identity, now + chrono::Duration::minutes(1))
        .await
        .unwrap();
    let version = profiled.state_version;
    profiled.state_version = profiled.state_version.checked_add(1).unwrap();
    profiled.expires_at = now - chrono::Duration::seconds(1);
    pg.update_session_binding(&other, version, &profiled)
        .await
        .unwrap();
    // Both ceilings elapsed. Profile loss is still an independent refusal, not budget exhaustion.
    sqlx::query("UPDATE browser_profiles SET expires_at=$2 WHERE session_id=$1")
        .bind(other.session.id.0)
        .bind(profiled.expires_at)
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        pg.verify_session_binding(&other, &profiled).await,
        Err(SessionBindingVerificationError::Store(StoreError::Conflict(_))),
    ));
    peer.pool().close().await;
    assert!(matches!(
        peer.verify_session_binding(&lease, &binding).await,
        Err(SessionBindingVerificationError::Store(_)),
    ));
}

#[tokio::test]
async fn cancellation_and_retention_sweep_erase_actual_encrypted_profile_objects() {
    let Some((pg, _, tenant, lease, _)) = fixture().await else {
        return;
    };
    let cipher = ProfileCipher::new(&[4; 32]).unwrap();
    let scope = scope(tenant, &lease);
    let now = pg.now().await.unwrap();
    let bytes = cipher
        .seal(
            &scope,
            1,
            now + chrono::Duration::minutes(5),
            ProfileFiles::new(BTreeMap::new(), false).unwrap(),
        )
        .unwrap();
    let service = BrowserProfileRepo::new(&pg, &cipher);
    service
        .import(
            &lease,
            &scope,
            &bytes,
            Digest::of("crawlx/profile-bundle/v1", &bytes),
            0,
            true,
            false,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE browser_profiles SET expires_at=clock_timestamp()-interval '1 second'")
        .execute(pg.pool())
        .await
        .unwrap();
    assert_eq!(pg.reap_profiles().await.unwrap(), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_profiles")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "retention removes ciphertext, not just catalog visibility"
    );
    service
        .import(
            &lease,
            &scope,
            &bytes,
            Digest::of("crawlx/profile-bundle/v1", &bytes),
            0,
            true,
            false,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE crawl_runs SET cancel_requested_at=clock_timestamp() WHERE run_id=$1")
        .bind(lease.session.run.0)
        .execute(pg.pool())
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_profiles")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "cancellation trigger erases secrets synchronously");
    assert!(service.inspect(&lease, &scope, 1, false).await.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn crashed_tmpfs_copy_is_reaped_only_by_its_database_authority_and_dead_fence() {
    use crawlx_storage::profiles::{ProfileRuntimeLease, PROFILE_RUNTIME_ROOT};
    let Some((pg, _, tenant, lease, _)) = fixture().await else {
        return;
    };
    let cipher = ProfileCipher::new(&[3; 32]).unwrap();
    let scope = scope(tenant, &lease);
    let now = pg.now().await.unwrap();
    let bytes = cipher
        .seal(
            &scope,
            1,
            now + chrono::Duration::minutes(5),
            ProfileFiles::new(BTreeMap::new(), false).unwrap(),
        )
        .unwrap();
    BrowserProfileRepo::new(&pg, &cipher)
        .import(
            &lease,
            &scope,
            &bytes,
            Digest::of("crawlx/profile-bundle/v1", &bytes),
            0,
            true,
            false,
        )
        .await
        .unwrap();
    let descriptor = ProfileRuntimeLease::new(pg.profile_authority().await.unwrap(), tenant, &lease);
    let files = ProfileFiles::new(
        BTreeMap::from([("Default/Cookies".into(), b"temporary-secret".to_vec())]),
        false,
    )
    .unwrap();
    let copy = files
        .materialize(std::path::Path::new(PROFILE_RUNTIME_ROOT), &descriptor, false)
        .unwrap();
    let path = copy.keep(); // Simulate a process crash: no TempDir destructor runs.
    pg.reap_profile_directories().await.unwrap();
    assert!(path.join("Default/Cookies").exists());
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").unwrap();
    let foreign = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("profile_foreign_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    foreign.migrate().await.unwrap();
    foreign.reap_profile_directories().await.unwrap();
    assert!(
        path.exists(),
        "another database/schema must not erase a live secret copy"
    );
    sqlx::query("UPDATE crawl_sessions SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE session_id=$1")
        .bind(lease.session.id.0).execute(pg.pool()).await.unwrap();
    assert!(
        pg.heartbeat(&lease).await.is_err(),
        "an expired fence cannot resurrect before the reaper"
    );
    assert!(pg.release(&lease, SessionStatus::Completed).await.is_err());
    assert!(pg.reap_profile_directories().await.unwrap() >= 1);
    assert!(!path.exists(), "crash reaping deletes the actual secret files");
}

#[tokio::test]
async fn render_children_start_fenced_and_never_enter_authenticated_role_claims() {
    let Some((pg, peer, _, first, _)) = fixture().await else {
        return;
    };
    let mut renderer = first.session.clone();
    renderer.id = crawlx_core::SessionId::new();
    renderer.role = crawlx_core::PrincipalId("scrape".into());
    renderer.run_index = 1;
    renderer.schedule_slot = crawlx_storage::leases::RENDER_SESSION_SLOT_BASE;
    renderer.status = SessionStatus::Pending;
    renderer.browser = None;
    renderer.action_seq = 0;
    let worker = WorkerId::new();
    let lease = pg.create_render_session(&renderer, worker).await.unwrap();
    assert_eq!(lease.session.status, SessionStatus::Running);
    assert_eq!(lease.worker, worker);
    assert!(lease.fencing_token > first.fencing_token);
    assert!(peer
        .claim_session_exact(renderer.run, renderer.id, WorkerId::new(), true)
        .await
        .unwrap()
        .is_none());
    pg.release(&lease, SessionStatus::Recovering).await.unwrap();
    assert!(
        peer.claim_session_exact(renderer.run, renderer.id, WorkerId::new(), true)
            .await
            .unwrap()
            .is_none(),
        "recovering render children must not become role actors"
    );
    assert!(
        pg.create_render_session(&renderer, WorkerId::new())
            .await
            .is_err(),
        "a second process cannot recreate the same render identity"
    );
    let mut successor = first.session.clone();
    successor.id = crawlx_core::SessionId::new();
    successor.run_index = 3;
    successor.schedule_slot = 2;
    successor.status = SessionStatus::Pending;
    successor.browser = None;
    successor.action_seq = 0;
    pg.create_sessions(&[successor.clone()]).await.unwrap();
    assert!(
        peer.claim_session_exact(successor.run, successor.id, WorkerId::new(), false)
            .await
            .unwrap()
            .is_none(),
        "render leases must not bypass the existing authenticated role barrier"
    );
}

async fn stored_profile(pg: &Pg) -> (i64, Vec<u8>, Vec<u8>, uuid::Uuid, uuid::Uuid, i64) {
    sqlx::query_as(
        "SELECT generation,encrypted_bundle,digest,owner_run,session_id,lease_fence FROM browser_profiles",
    )
    .fetch_one(pg.pool())
    .await
    .unwrap()
}

async fn unresolved_prior_owner_blocks_handover(replace_generation: bool) {
    let Some((pg, peer, tenant, prior, next)) = fixture().await else {
        return;
    };
    let cipher = ProfileCipher::new(&[7; 32]).unwrap();
    let scope = scope(tenant, &prior);
    let now = pg.now().await.unwrap();
    let seal = |generation| {
        cipher
            .seal(
                &scope,
                generation,
                now + chrono::Duration::minutes(5),
                ProfileFiles::new(
                    BTreeMap::from([("Default/Cookies".into(), b"prior-owner-secret".to_vec())]),
                    false,
                )
                .unwrap(),
            )
            .unwrap()
    };
    let original = seal(1);
    let replacement = seal(2);
    BrowserProfileRepo::new(&pg, &cipher)
        .import(
            &prior,
            &scope,
            &original,
            Digest::of("crawlx/profile-bundle/v1", &original),
            0,
            true,
            false,
        )
        .await
        .unwrap();
    let proposed = proposal(&prior.session.role.0, crawlx_core::StateClusterId::new(), 1);
    let action = pg
        .propose(prior.session.run, prior.session.id, &proposed, &allow_verdict())
        .await
        .unwrap();
    pg.intend(action, prior.session.id, proposed.epoch).await.unwrap();
    sqlx::query(
        "UPDATE crawl_sessions SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE session_id=$1",
    )
    .bind(prior.session.id.0)
    .execute(pg.pool())
    .await
    .unwrap();
    let unchanged = stored_profile(&pg).await;
    let service = BrowserProfileRepo::new(&peer, &cipher);
    for status in [ActionStatus::Intended, ActionStatus::Unknown] {
        if status == ActionStatus::Unknown {
            assert_eq!(
                pg.mark_unknown(pg.now().await.unwrap()).await.unwrap(),
                vec![action]
            );
        }
        assert_eq!(ActionJournal::get(&pg, action).await.unwrap().status, status);
        if replace_generation {
            assert!(
                service
                    .import(
                        &next,
                        &scope,
                        &replacement,
                        Digest::of("crawlx/profile-bundle/v1", &replacement),
                        1,
                        true,
                        false,
                    )
                    .await
                    .is_err(),
                "expired prior owner with {status:?} action must block replacement"
            );
        } else {
            assert!(
                service.acquire(&next, &scope, false).await.is_err(),
                "expired prior owner with {status:?} action must block cross-session acquisition"
            );
        }
        assert_eq!(
            stored_profile(&pg).await,
            unchanged,
            "refusal preserves encrypted bytes, generation, owner and fence"
        );
    }
    pg.reap(pg.now().await.unwrap()).await.unwrap();
    let recovery = peer
        .claim_session_exact(prior.session.run, prior.session.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovery.session.id, prior.session.id);
    assert!(recovery.fencing_token > prior.fencing_token);
    assert!(BrowserProfileRepo::new(&pg, &cipher)
        .acquire(&prior, &scope, false)
        .await
        .is_err());
    let (inspection, _) = service.acquire(&recovery, &scope, false).await.unwrap().unwrap();
    assert_eq!(
        inspection.generation, 1,
        "recovery restores the existing generation"
    );
    let recovered = stored_profile(&pg).await;
    assert_eq!(recovered.1, original);
    assert_eq!(recovered.4, recovery.session.id.0);
    assert_eq!(recovered.5, recovery.fencing_token);
    assert_eq!(
        ActionJournal::get(&pg, action).await.unwrap().status,
        ActionStatus::Unknown
    );
    assert!(
        service
            .import(
                &recovery,
                &scope,
                &replacement,
                Digest::of("crawlx/profile-bundle/v1", &replacement),
                1,
                true,
                false,
            )
            .await
            .is_err(),
        "same-session recovery may restore but cannot replace unresolved generation"
    );
    assert_eq!(stored_profile(&pg).await, recovered);
    peer.reconcile(
        action,
        Reconciliation {
            resolution: ReconcileResolution::NotApplied,
            evidence: serde_json::json!({"probe": "prior write absent"}),
            reconciled_at: peer.now().await.unwrap(),
        },
    )
    .await
    .unwrap();
    peer.release(&recovery, SessionStatus::Completed).await.unwrap();
    if replace_generation {
        let inspection = service
            .import(
                &next,
                &scope,
                &replacement,
                Digest::of("crawlx/profile-bundle/v1", &replacement),
                1,
                true,
                false,
            )
            .await
            .unwrap();
        assert_eq!(inspection.generation, 2);
    } else {
        let (inspection, _) = service.acquire(&next, &scope, false).await.unwrap().unwrap();
        assert_eq!(inspection.generation, 1);
    }
    let handed_over = stored_profile(&pg).await;
    assert_eq!(handed_over.4, next.session.id.0);
    assert_eq!(handed_over.5, next.fencing_token);
    assert_eq!(
        handed_over.1,
        if replace_generation { replacement } else { original }
    );
}

#[tokio::test]
async fn expired_prior_owner_unresolved_write_blocks_profile_acquire_until_reconciled() {
    unresolved_prior_owner_blocks_handover(false).await;
}

#[tokio::test]
async fn expired_prior_owner_unresolved_write_blocks_profile_import_until_reconciled() {
    unresolved_prior_owner_blocks_handover(true).await;
}

fn binding_limits(max_usage: u64, max_health_errors: u16) -> SessionLimits {
    let mut limits = SessionLimits::default();
    limits.max_usage = max_usage;
    limits.max_health_errors = max_health_errors;
    limits
}

async fn anonymous_binding_fixture(
    rotations: u32,
    login: bool,
) -> Option<(Pg, Pg, TenantId, SessionLease, SessionBindingV1)> {
    let (pg, peer, tenant, _, _) = fixture().await?;
    let mut config = create_crawl("https://example.test/", &["anonymous"], 1);
    if login {
        config.roles[0].login_plan = Some("builtin:form".into());
    }
    let mut orchestration = crawlx_core::orchestration::OrchestrationConfigV1::default();
    orchestration.attempts.max_session_rotations = rotations;
    config.orchestration = Some(orchestration);
    let run = crawl_run(tenant, config);
    pg.create(&run, None).await.unwrap();
    let mut roles = sessions(run.id, 1, 1);
    roles[0].role = crawlx_core::PrincipalId::anonymous();
    pg.create_sessions(&roles).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let lease = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let digest = Digest::of("fixture", b"binding-lifecycle");
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let binding = pg
        .bind_session(
            &lease,
            identity,
            pg.now().await.unwrap() + chrono::Duration::minutes(1),
        )
        .await
        .unwrap();
    Some((pg, peer, tenant, lease, binding))
}

#[tokio::test]
async fn binding_health_success_and_failed_cleanup_keep_monotone_fenced_metadata() {
    let Some((pg, peer, tenant, lease, mut binding)) = anonymous_binding_fixture(1, false).await else {
        return;
    };
    let now = pg.now().await.unwrap();
    let limits = binding_limits(10, 2);
    for (healthy, health) in [(false, 1), (true, 0), (false, 1)] {
        let version = binding.state_version;
        binding.record_use(healthy, now, limits).unwrap();
        pg.update_session_binding(&lease, version, &binding)
            .await
            .unwrap();
        assert_eq!(binding.health_errors, health);
    }
    let mut invalid = binding.clone();
    invalid.state_version += 1;
    invalid.usage = 0;
    assert!(peer
        .update_session_binding(&lease, binding.state_version, &invalid)
        .await
        .is_err());
    let mut invalid = binding.clone();
    invalid.state_version += 1;
    invalid.schema_version = 2;
    assert!(peer
        .update_session_binding(&lease, binding.state_version, &invalid)
        .await
        .is_err());
    assert_eq!(pg.load_session_binding(&lease, tenant).await.unwrap(), binding);
    let version = binding.state_version;
    binding.record_use(false, now, limits).unwrap();
    assert_eq!(binding.state, BindingState::Draining);
    assert_eq!(binding.retirement, Some(RetirementReason::Unhealthy));
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(matches!(
        peer.verify_session_binding(&lease, &binding).await,
        Err(
            crawlx_storage::session_binding::SessionBindingVerificationError::Binding(
                SessionBindingError::Draining {
                    reason: RetirementReason::Unhealthy
                }
            )
        ),
    ));
    // The final reserved use may report its outcome after entering drain.
    let version = binding.state_version;
    binding.state_version += 1;
    binding.health_errors -= 1;
    peer.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let mut invalid = binding.clone();
    invalid.state_version += 1;
    invalid.usage += 1;
    assert!(pg
        .update_session_binding(&lease, binding.state_version, &invalid)
        .await
        .is_err());
    let version = binding.state_version;
    binding.finish_cleanup(false).unwrap();
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert_eq!(peer.load_session_binding(&lease, tenant).await.unwrap(), binding);
    assert_eq!(binding.state, BindingState::Quarantined);
    assert!(peer
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at,)
        .await
        .is_err());
}

#[tokio::test]
async fn explicit_binding_replacement_requires_reconciled_write_exact_owner_and_live_fence() {
    let Some((pg, peer, tenant, lease, mut binding)) = anonymous_binding_fixture(1, false).await else {
        return;
    };
    let original = binding.clone();
    let proposed = proposal("anonymous", crawlx_core::StateClusterId::new(), 1);
    let action = pg
        .propose(lease.session.run, lease.session.id, &proposed, &allow_verdict())
        .await
        .unwrap();
    pg.intend(action, lease.session.id, proposed.epoch).await.unwrap();
    let now = pg.now().await.unwrap();
    let version = binding.state_version;
    binding.record_use(true, now, binding_limits(1, 5)).unwrap();
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(
        peer.replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at,)
            .await
            .is_err(),
        "draining is not confirmed cleanup"
    );
    let version = binding.state_version;
    binding.finish_cleanup(true).unwrap();
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert_eq!(peer.load_session_binding(&lease, tenant).await.unwrap(), binding);
    assert!(peer.replace_retired_session_binding(
        &lease, &original, binding.identity.clone(), binding.expires_at,
    ).await.is_err(), "stale state version cannot replace");
    let mut stale = lease.clone();
    stale.fencing_token -= 1;
    assert!(pg.load_session_binding(&stale, tenant).await.is_err());
    assert!(
        pg.replace_retired_session_binding(&stale, &binding, binding.identity.clone(), binding.expires_at,)
            .await
            .is_err(),
        "stale lease cannot replace"
    );
    assert!(
        peer.replace_retired_session_binding(
            &lease,
            &binding,
            binding.identity.clone(),
            binding.expires_at + chrono::Duration::seconds(1),
        )
        .await
        .is_err(),
        "replacement cannot extend expiry"
    );
    for status in [ActionStatus::Intended, ActionStatus::Unknown] {
        if status == ActionStatus::Unknown {
            assert_eq!(
                pg.mark_unknown(now + chrono::Duration::days(1)).await.unwrap(),
                vec![action]
            );
        }
        assert_eq!(ActionJournal::get(&pg, action).await.unwrap().status, status);
        assert!(
            peer.replace_retired_session_binding(
                &lease,
                &binding,
                binding.identity.clone(),
                binding.expires_at,
            )
            .await
            .is_err(),
            "unresolved {status:?} write blocks generation reset"
        );
        assert_eq!(pg.load_session_binding(&lease, tenant).await.unwrap(), binding);
    }
    pg.reconcile(
        action,
        Reconciliation {
            resolution: ReconcileResolution::NotApplied,
            evidence: serde_json::json!({"probe": "write absent"}),
            reconciled_at: pg.now().await.unwrap(),
        },
    )
    .await
    .unwrap();
    let mut wrong_tenant = binding.identity.clone();
    wrong_tenant.tenant = TenantId::new();
    let mut wrong_run = binding.identity.clone();
    wrong_run.run = crawlx_core::CrawlRunId::new();
    let mut wrong_session = binding.identity.clone();
    wrong_session.session = crawlx_core::SessionId::new();
    let mut wrong_principal = binding.identity.clone();
    wrong_principal.principal = crawlx_core::PrincipalId("reader".into());
    for identity in [wrong_tenant, wrong_run, wrong_session, wrong_principal] {
        assert!(peer
            .replace_retired_session_binding(&lease, &binding, identity, binding.expires_at)
            .await
            .is_err());
    }
    assert!(
        peer.replace_retired_session_binding(
            &lease,
            &binding,
            binding.identity.clone(),
            binding.expires_at + chrono::Duration::seconds(1),
        )
        .await
        .is_err(),
        "reconciled replacement cannot extend expiry"
    );
    let mut next = peer
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
        .await
        .unwrap();
    assert_eq!(next.generation, binding.generation + 1);
    assert_eq!(next.identity, binding.identity);
    assert_eq!(next.usage, 0);
    assert_eq!(next.health_errors, 0);
    assert_eq!(next.expires_at, original.expires_at);
    assert_eq!(next.lifetime_expires_at, original.lifetime_expires_at);
    peer.verify_session_binding(&lease, &next).await.unwrap();
    assert!(pg.verify_session_binding(&lease, &binding).await.is_err());
    assert!(
        pg.replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at,)
            .await
            .is_err(),
        "replacement compare-and-swap cannot replay"
    );
    let version = next.state_version;
    next.record_use(true, now, binding_limits(1, 5)).unwrap();
    pg.update_session_binding(&lease, version, &next).await.unwrap();
    let version = next.state_version;
    next.finish_cleanup(true).unwrap();
    pg.update_session_binding(&lease, version, &next).await.unwrap();
    assert!(
        pg.replace_retired_session_binding(&lease, &next, next.identity.clone(), next.expires_at,)
            .await
            .is_err(),
        "finite admitted rotation budget cannot reset"
    );
}

#[tokio::test]
async fn implicit_rotation_permission_and_configured_login_never_reset_retired_generation() {
    for (rotations, login) in [(0, false), (1, true)] {
        let Some((pg, peer, tenant, lease, mut binding)) = anonymous_binding_fixture(rotations, login).await
        else {
            return;
        };
        let now = pg.now().await.unwrap();
        let version = binding.state_version;
        binding.record_use(false, now, binding_limits(5, 1)).unwrap();
        pg.update_session_binding(&lease, version, &binding)
            .await
            .unwrap();
        let version = binding.state_version;
        binding.finish_cleanup(true).unwrap();
        pg.update_session_binding(&lease, version, &binding)
            .await
            .unwrap();
        assert!(peer
            .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at,)
            .await
            .is_err());
        assert_eq!(pg.load_session_binding(&lease, tenant).await.unwrap(), binding);
    }
}

#[tokio::test]
async fn observed_egress_pin_survives_peer_restart_without_mutating_binding_revision() {
    let Some((pg, peer, tenant, lease, mut binding)) = anonymous_binding_fixture(1, false).await else {
        return;
    };
    let pin = Digest::of("fixture", b"observed-target");
    let drift = Digest::of("fixture", b"changed-target");
    pg.check_session_egress_pin(&lease, tenant, binding.generation, pin)
        .await
        .unwrap();
    peer.check_session_egress_pin(&lease, tenant, binding.generation, pin)
        .await
        .unwrap();
    assert!(peer
        .check_session_egress_pin(&lease, tenant, binding.generation, drift)
        .await
        .is_err());
    assert!(peer
        .check_session_egress_pin(&lease, tenant, binding.generation + 1, pin)
        .await
        .is_err());
    assert!(peer
        .check_session_egress_pin(&lease, TenantId::new(), binding.generation, pin)
        .await
        .is_err());
    let mut stale = lease.clone();
    stale.fencing_token -= 1;
    assert!(peer
        .check_session_egress_pin(&stale, tenant, binding.generation, pin)
        .await
        .is_err());
    assert_eq!(pg.load_session_binding(&lease, tenant).await.unwrap(), binding);
    let now = pg.now().await.unwrap();
    let version = binding.state_version;
    binding.record_use(true, now, binding_limits(1, 5)).unwrap();
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let version = binding.state_version;
    binding.finish_cleanup(true).unwrap();
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let next = pg
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
        .await
        .unwrap();
    peer.check_session_egress_pin(&lease, tenant, next.generation, drift)
        .await
        .unwrap();
    assert!(peer
        .check_session_egress_pin(&lease, tenant, binding.generation, pin)
        .await
        .is_err());
    assert_eq!(pg.load_session_binding(&lease, tenant).await.unwrap(), next);
}

#[tokio::test]
async fn explicit_anonymous_rotation_never_erases_an_existing_encrypted_profile() {
    let Some((pg, peer, tenant, lease, mut binding)) = anonymous_binding_fixture(1, false).await else {
        return;
    };
    let now = pg.now().await.unwrap();
    let cipher = ProfileCipher::new(&[5; 32]).unwrap();
    let profile_scope = scope(tenant, &lease);
    let bytes = cipher
        .seal(
            &profile_scope,
            1,
            now + chrono::Duration::minutes(1),
            ProfileFiles::new(
                BTreeMap::from([("Default/Cookies".into(), b"strict-profile-secret".to_vec())]),
                false,
            )
            .unwrap(),
        )
        .unwrap();
    BrowserProfileRepo::new(&pg, &cipher)
        .import(
            &lease,
            &profile_scope,
            &bytes,
            Digest::of("crawlx/profile-bundle/v1", &bytes),
            0,
            true,
            false,
        )
        .await
        .unwrap();
    let original_profile = stored_profile(&pg).await;
    let version = binding.state_version;
    binding.record_use(true, now, binding_limits(1, 5)).unwrap();
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let version = binding.state_version;
    binding.finish_cleanup(true).unwrap();
    pg.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(peer
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at,)
        .await
        .is_err());
    assert_eq!(stored_profile(&pg).await, original_profile);
    assert_eq!(pg.load_session_binding(&lease, tenant).await.unwrap(), binding);
}
