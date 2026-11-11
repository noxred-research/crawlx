//! Conformance cases (session bindings): the generation rules of the metadata kept beneath
//! the session lease. A retired generation never resets implicitly, explicit replacement needs
//! a reconciled write, the exact owner and a live fence, health and usage move monotonically
//! under the fence, expiry follows only durable login credit, and an observed egress pin
//! outlives the process that recorded it.
//!
//! Binding metadata has no in-memory twin, so these cases run on the database engines.

use super::reports::{exec, on_zdr_db, scalar_bytes, scalar_i64, tenant_of, Bind};
use crate::rig::Rig;
use crawlx_core::counters::{ActionStatus, ReconcileResolution, RunStatus};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ActionJournal, EventRepo, Reconciliation, RunRepo, SessionStatus};
use crawlx_core::session_binding::{
    BindingState, RetirementReason, SessionBindingError, SessionBindingV1, SessionIdentityV1, SessionLimits,
};
use crawlx_core::{StoreError, TenantId, Timestamp, WorkerId};
use crawlx_storage::leases::{LeaseRepo, SessionLease};
use crawlx_storage::profiles::{BrowserProfileRepo, ProfileCipher, ProfileFiles, ProfileScopeV1};
use crawlx_storage::session_binding::SessionBindingVerificationError;
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions};
use std::collections::{BTreeMap, BTreeSet};

conformance! { databases:
    binding_expiry_uses_only_durable_login_credit_and_a_bounded_reservation,
    fenced_recovery_can_reserve_relogin_past_the_previous_exploration_deadline,
    expired_binding_keeps_independent_lease_profile_and_repository_failures,
    binding_health_success_and_failed_cleanup_keep_monotone_fenced_metadata,
    explicit_binding_replacement_requires_reconciled_write_exact_owner_and_live_fence,
    implicit_rotation_permission_and_configured_login_never_reset_retired_generation,
    observed_egress_pin_survives_a_new_handle_without_mutating_the_binding,
    explicit_anonymous_rotation_never_erases_an_existing_encrypted_profile,
}

/// What the cases need of a database store: the generic repositories plus the binding
/// operations, which are inherent methods of each `Store`.
trait Binder: RunRepo + LeaseRepo + EventRepo + ActionJournal + Sync {
    async fn bind_session(
        &self,
        lease: &SessionLease,
        identity: SessionIdentityV1,
        expires_at: Timestamp,
    ) -> Result<SessionBindingV1, StoreError>;
    async fn update_session_binding(
        &self,
        lease: &SessionLease,
        expected_version: u64,
        next: &SessionBindingV1,
    ) -> Result<(), StoreError>;
    async fn verify_session_binding(
        &self,
        lease: &SessionLease,
        binding: &SessionBindingV1,
    ) -> Result<(), SessionBindingVerificationError>;
    async fn load_session_binding(
        &self,
        lease: &SessionLease,
        tenant: TenantId,
    ) -> Result<SessionBindingV1, StoreError>;
    async fn check_session_egress_pin(
        &self,
        lease: &SessionLease,
        tenant: TenantId,
        generation: u64,
        pin: Digest,
    ) -> Result<(), StoreError>;
    async fn replace_retired_session_binding(
        &self,
        lease: &SessionLease,
        expected: &SessionBindingV1,
        identity: SessionIdentityV1,
        expires_at: Timestamp,
    ) -> Result<SessionBindingV1, SessionBindingVerificationError>;
    async fn import_profile(
        &self,
        cipher: &ProfileCipher,
        lease: &SessionLease,
        scope: &ProfileScopeV1,
        bytes: &[u8],
    ) -> Result<(), StoreError>;
}

macro_rules! impl_binder {
    ($($store:ty),+) => {$(
        impl Binder for $store {
            async fn bind_session(
                &self,
                lease: &SessionLease,
                identity: SessionIdentityV1,
                expires_at: Timestamp,
            ) -> Result<SessionBindingV1, StoreError> {
                <$store>::bind_session(self, lease, identity, expires_at).await
            }
            async fn update_session_binding(
                &self,
                lease: &SessionLease,
                expected_version: u64,
                next: &SessionBindingV1,
            ) -> Result<(), StoreError> {
                <$store>::update_session_binding(self, lease, expected_version, next).await
            }
            async fn verify_session_binding(
                &self,
                lease: &SessionLease,
                binding: &SessionBindingV1,
            ) -> Result<(), SessionBindingVerificationError> {
                <$store>::verify_session_binding(self, lease, binding).await
            }
            async fn load_session_binding(
                &self,
                lease: &SessionLease,
                tenant: TenantId,
            ) -> Result<SessionBindingV1, StoreError> {
                <$store>::load_session_binding(self, lease, tenant).await
            }
            async fn check_session_egress_pin(
                &self,
                lease: &SessionLease,
                tenant: TenantId,
                generation: u64,
                pin: Digest,
            ) -> Result<(), StoreError> {
                <$store>::check_session_egress_pin(self, lease, tenant, generation, pin).await
            }
            async fn replace_retired_session_binding(
                &self,
                lease: &SessionLease,
                expected: &SessionBindingV1,
                identity: SessionIdentityV1,
                expires_at: Timestamp,
            ) -> Result<SessionBindingV1, SessionBindingVerificationError> {
                <$store>::replace_retired_session_binding(self, lease, expected, identity, expires_at).await
            }
            async fn import_profile(
                &self,
                cipher: &ProfileCipher,
                lease: &SessionLease,
                scope: &ProfileScopeV1,
                bytes: &[u8],
            ) -> Result<(), StoreError> {
                BrowserProfileRepo::new(self, cipher)
                    .import(
                        lease,
                        scope,
                        bytes,
                        Digest::of("crawlx/profile-bundle/v1", bytes),
                        0,
                        true,
                        false,
                    )
                    .await
                    .map(drop)
            }
        }
    )+};
}
impl_binder!(
    crawlx_storage::Store<crawlx_storage::backend::SqliteBackend>,
    crawlx_storage::Store<crawlx_storage::backend::MariaBackend>,
    crawlx_storage::Pg
);

/// A running run of two sessions with one claimed lease each, held by different workers.
async fn fixture<R: Binder>(repo: &R, tenant: TenantId) -> (SessionLease, SessionLease) {
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 2));
    repo.create(&run, None).await.unwrap();
    repo.create_sessions(&sessions(run.id, 1, 2)).await.unwrap();
    repo.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let first = repo
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let second = repo
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    (first, second)
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

fn binding_limits(max_usage: u64, max_health_errors: u16) -> SessionLimits {
    let mut limits = SessionLimits::default();
    limits.max_usage = max_usage;
    limits.max_health_errors = max_health_errors;
    limits
}

/// An anonymous role with one session, leased and bound for a minute.
async fn anonymous_binding_fixture<R: Binder>(
    repo: &R,
    tenant: TenantId,
    rotations: u32,
    login: bool,
) -> (SessionLease, SessionBindingV1) {
    let mut config = create_crawl("https://example.test/", &["anonymous"], 1);
    if login {
        config.roles[0].login_plan = Some("builtin:form".into());
    }
    let mut orchestration = crawlx_core::orchestration::OrchestrationConfigV1::default();
    orchestration.attempts.max_session_rotations = rotations;
    config.orchestration = Some(orchestration);
    let run = crawl_run(tenant, config);
    repo.create(&run, None).await.unwrap();
    let mut roles = sessions(run.id, 1, 1);
    roles[0].role = crawlx_core::PrincipalId::anonymous();
    repo.create_sessions(&roles).await.unwrap();
    repo.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let lease = repo
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let digest = Digest::of("fixture", b"binding-lifecycle");
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let binding = repo
        .bind_session(
            &lease,
            identity,
            repo.now().await.unwrap() + chrono::Duration::minutes(1),
        )
        .await
        .unwrap();
    (lease, binding)
}

async fn binding_expiry_uses_only_durable_login_credit_and_a_bounded_reservation(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| login_credit(rig, repo, tenant).await);
}

async fn login_credit<R: Binder>(rig: &Rig, repo: &R, tenant: TenantId) {
    let (lease, other) = fixture(repo, tenant).await;
    let run = RunRepo::get(repo, lease.session.run).await.unwrap();
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
    let first = EventRepo::append(repo, run.id, "session.budget", budget(0, 0))
        .await
        .unwrap();
    // Model a completed measured login without a real-time sleep.
    exec(
        rig,
        "UPDATE crawl_events SET created_at=$1 WHERE run_id=$2 AND seq=$3",
        &[
            Bind::Ts(repo.now().await.unwrap() - chrono::Duration::seconds(2)),
            Bind::Uuid(run.id.0),
            Bind::I64(i64::try_from(first).unwrap()),
        ],
    )
    .await;
    EventRepo::append(repo, run.id, "session.budget", budget(1_000, 10_000))
        .await
        .unwrap();
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let binding = repo
        .bind_session(&lease, identity, raw_deadline + chrono::Duration::days(1))
        .await
        .unwrap();
    assert_eq!(
        binding.expires_at,
        raw_deadline + chrono::Duration::milliseconds(11_000)
    );
    // Another slot cannot borrow the first slot's active reservation.
    let identity = SessionIdentityV1::new(tenant, &other.session, digest, digest, digest, digest, None);
    let binding = repo
        .bind_session(&other, identity, raw_deadline + chrono::Duration::days(1))
        .await
        .unwrap();
    assert_eq!(
        binding.expires_at,
        raw_deadline + chrono::Duration::milliseconds(1_000)
    );
    EventRepo::append(
        repo,
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
    let error = repo
        .bind_session(&other, identity, raw_deadline + chrono::Duration::days(1))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("invalid durable login clock"));
}

async fn fenced_recovery_can_reserve_relogin_past_the_previous_exploration_deadline(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| recovery(rig, repo, tenant).await);
}

async fn recovery<R: Binder>(rig: &Rig, repo: &R, tenant: TenantId) {
    let (lease, _) = fixture(repo, tenant).await;
    let run = RunRepo::get(repo, lease.session.run).await.unwrap();
    let raw = repo.now().await.unwrap() + chrono::Duration::seconds(10);
    let started = raw - chrono::Duration::seconds(i64::from(run.config.limits.duration_seconds));
    exec(
        rig,
        "UPDATE crawl_runs SET started_at=$1 WHERE run_id=$2",
        &[Bind::Ts(started), Bind::Uuid(run.id.0)],
    )
    .await;
    let digest = Digest::of("fixture", b"recovery-login");
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let reservation = serde_json::json!({
        "session_id": lease.session.id,
        "login_credit_ms": 0,
        "login_allowance_ms": 20_000,
    });
    EventRepo::append(repo, run.id, "session.budget", reservation.clone())
        .await
        .unwrap();
    let mut old = repo
        .bind_session(&lease, identity.clone(), raw + chrono::Duration::seconds(20))
        .await
        .unwrap();
    let version = old.state_version;
    old.state_version = old.state_version.checked_add(1).unwrap();
    old.expires_at = raw;
    repo.update_session_binding(&lease, version, &old).await.unwrap();
    assert_eq!(old.lifetime_expires_at, Some(raw + chrono::Duration::seconds(20)));
    // A later fenced holder reserves relogin after the previous actor narrowed to raw.
    EventRepo::append(repo, run.id, "session.budget", reservation)
        .await
        .unwrap();
    repo.release(&lease, SessionStatus::Recovering).await.unwrap();
    let replacement = repo
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replacement.session.id, lease.session.id);
    assert_ne!(replacement.fencing_token, lease.fencing_token);
    let mut renewed = repo
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
                SessionLimits::default(),
            )
            .is_ok(),
        "the bounded relogin can outlast the remaining exploration time"
    );
    let version = renewed.state_version;
    renewed.state_version = renewed.state_version.checked_add(1).unwrap();
    renewed.expires_at = raw + chrono::Duration::seconds(5);
    repo.update_session_binding(&replacement, version, &renewed)
        .await
        .unwrap();
    let mut changed_cap = renewed.clone();
    changed_cap.state_version = changed_cap.state_version.checked_add(1).unwrap();
    changed_cap.lifetime_expires_at = Some(raw + chrono::Duration::seconds(21));
    assert!(
        repo.update_session_binding(&replacement, renewed.state_version, &changed_cap)
            .await
            .is_err(),
        "fenced recovery cannot alter the lifetime ceiling"
    );
    assert!(
        repo.verify_session_binding(&lease, &old).await.is_err(),
        "old actor remains fenced"
    );
}

async fn expired_binding_keeps_independent_lease_profile_and_repository_failures(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| independent_failures(rig, repo, tenant).await);
}

async fn independent_failures<R: Binder>(rig: &Rig, repo: &R, tenant: TenantId) {
    let (lease, other) = fixture(repo, tenant).await;
    let now = repo.now().await.unwrap();
    let digest = Digest::of("fixture", b"expiry-cause");
    let identity = SessionIdentityV1::new(tenant, &lease.session, digest, digest, digest, digest, None);
    let mut binding = repo
        .bind_session(&lease, identity, now + chrono::Duration::minutes(1))
        .await
        .unwrap();
    let version = binding.state_version;
    binding.state_version = binding.state_version.checked_add(1).unwrap();
    binding.expires_at = now - chrono::Duration::seconds(1);
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(matches!(
        repo.verify_session_binding(&lease, &binding).await,
        Err(SessionBindingVerificationError::Binding(
            SessionBindingError::Expired
        )),
    ));
    let mut fenced = lease.clone();
    fenced.fencing_token = fenced.fencing_token.checked_add(1).unwrap();
    assert!(matches!(
        repo.verify_session_binding(&fenced, &binding).await,
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
    repo.import_profile(&cipher, &other, &profile_scope, &bytes)
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
    let mut profiled = repo
        .bind_session(&other, identity, now + chrono::Duration::minutes(1))
        .await
        .unwrap();
    let version = profiled.state_version;
    profiled.state_version = profiled.state_version.checked_add(1).unwrap();
    profiled.expires_at = now - chrono::Duration::seconds(1);
    repo.update_session_binding(&other, version, &profiled)
        .await
        .unwrap();
    // Both ceilings elapsed. Profile loss is still an independent refusal, not budget exhaustion.
    exec(
        rig,
        "UPDATE browser_profiles SET expires_at=$1 WHERE session_id=$2",
        &[Bind::Ts(profiled.expires_at), Bind::Uuid(other.session.id.0)],
    )
    .await;
    assert!(matches!(
        repo.verify_session_binding(&other, &profiled).await,
        Err(SessionBindingVerificationError::Store(StoreError::Conflict(_))),
    ));
    // A repository failure after the lease checks is a store error, never a binding verdict.
    exec(
        rig,
        "ALTER TABLE session_bindings RENAME TO session_bindings_gone",
        &[],
    )
    .await;
    let failed = repo.verify_session_binding(&lease, &binding).await;
    exec(
        rig,
        "ALTER TABLE session_bindings_gone RENAME TO session_bindings",
        &[],
    )
    .await;
    assert!(matches!(failed, Err(SessionBindingVerificationError::Store(_))));
}

async fn binding_health_success_and_failed_cleanup_keep_monotone_fenced_metadata(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| health(repo, tenant).await);
}

async fn health<R: Binder>(repo: &R, tenant: TenantId) {
    let (lease, mut binding) = anonymous_binding_fixture(repo, tenant, 1, false).await;
    let now = repo.now().await.unwrap();
    let limits = binding_limits(10, 2);
    for (healthy, health) in [(false, 1), (true, 0), (false, 1)] {
        let version = binding.state_version;
        binding.record_use(healthy, now, limits).unwrap();
        repo.update_session_binding(&lease, version, &binding)
            .await
            .unwrap();
        assert_eq!(binding.health_errors, health);
    }
    let mut invalid = binding.clone();
    invalid.state_version += 1;
    invalid.usage = 0;
    assert!(repo
        .update_session_binding(&lease, binding.state_version, &invalid)
        .await
        .is_err());
    let mut invalid = binding.clone();
    invalid.state_version += 1;
    invalid.schema_version = 2;
    assert!(repo
        .update_session_binding(&lease, binding.state_version, &invalid)
        .await
        .is_err());
    assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), binding);
    let version = binding.state_version;
    binding.record_use(false, now, limits).unwrap();
    assert_eq!(binding.state, BindingState::Draining);
    assert_eq!(binding.retirement, Some(RetirementReason::Unhealthy));
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(matches!(
        repo.verify_session_binding(&lease, &binding).await,
        Err(SessionBindingVerificationError::Binding(
            SessionBindingError::Draining {
                reason: RetirementReason::Unhealthy
            }
        )),
    ));
    // The final reserved use may report its outcome after entering drain.
    let version = binding.state_version;
    binding.state_version += 1;
    binding.health_errors -= 1;
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let mut invalid = binding.clone();
    invalid.state_version += 1;
    invalid.usage += 1;
    assert!(repo
        .update_session_binding(&lease, binding.state_version, &invalid)
        .await
        .is_err());
    let version = binding.state_version;
    binding.finish_cleanup(false).unwrap();
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), binding);
    assert_eq!(binding.state, BindingState::Quarantined);
    assert!(repo
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
        .await
        .is_err());
}

async fn explicit_binding_replacement_requires_reconciled_write_exact_owner_and_live_fence(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| replacement(repo, tenant).await);
}

async fn replacement<R: Binder>(repo: &R, tenant: TenantId) {
    let (lease, mut binding) = anonymous_binding_fixture(repo, tenant, 1, false).await;
    let original = binding.clone();
    let proposed = proposal("anonymous", crawlx_core::StateClusterId::new(), 1);
    let action = repo
        .propose(lease.session.run, lease.session.id, &proposed, &allow_verdict())
        .await
        .unwrap();
    repo.intend(action, lease.session.id, proposed.epoch)
        .await
        .unwrap();
    let now = repo.now().await.unwrap();
    let version = binding.state_version;
    binding.record_use(true, now, binding_limits(1, 5)).unwrap();
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(
        repo.replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
            .await
            .is_err(),
        "draining is not confirmed cleanup"
    );
    let version = binding.state_version;
    binding.finish_cleanup(true).unwrap();
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), binding);
    assert!(
        repo.replace_retired_session_binding(&lease, &original, binding.identity.clone(), binding.expires_at)
            .await
            .is_err(),
        "stale state version cannot replace"
    );
    let mut stale = lease.clone();
    stale.fencing_token -= 1;
    assert!(repo.load_session_binding(&stale, tenant).await.is_err());
    assert!(
        repo.replace_retired_session_binding(&stale, &binding, binding.identity.clone(), binding.expires_at)
            .await
            .is_err(),
        "stale lease cannot replace"
    );
    let mut wrong_owner = lease.clone();
    wrong_owner.worker = WorkerId::new();
    assert!(matches!(
        repo.replace_retired_session_binding(
            &wrong_owner,
            &binding,
            binding.identity.clone(),
            binding.expires_at,
        )
        .await,
        Err(SessionBindingVerificationError::Store(StoreError::LeaseLost))
    ));
    assert!(
        repo.replace_retired_session_binding(
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
                repo.mark_unknown(now + chrono::Duration::days(1)).await.unwrap(),
                vec![action]
            );
        }
        assert_eq!(ActionJournal::get(repo, action).await.unwrap().status, status);
        assert!(
            repo.replace_retired_session_binding(
                &lease,
                &binding,
                binding.identity.clone(),
                binding.expires_at,
            )
            .await
            .is_err(),
            "unresolved {status:?} write blocks generation reset"
        );
        assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), binding);
    }
    repo.reconcile(
        action,
        Reconciliation {
            resolution: ReconcileResolution::NotApplied,
            evidence: serde_json::json!({"probe": "write absent"}),
            reconciled_at: repo.now().await.unwrap(),
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
        assert!(repo
            .replace_retired_session_binding(&lease, &binding, identity, binding.expires_at)
            .await
            .is_err());
    }
    assert!(
        repo.replace_retired_session_binding(
            &lease,
            &binding,
            binding.identity.clone(),
            binding.expires_at + chrono::Duration::seconds(1),
        )
        .await
        .is_err(),
        "reconciled replacement cannot extend expiry"
    );
    let mut next = repo
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
        .await
        .unwrap();
    assert_eq!(next.generation, binding.generation + 1);
    assert_eq!(next.identity, binding.identity);
    assert_eq!(next.usage, 0);
    assert_eq!(next.health_errors, 0);
    assert_eq!(next.expires_at, original.expires_at);
    assert_eq!(next.lifetime_expires_at, original.lifetime_expires_at);
    repo.verify_session_binding(&lease, &next).await.unwrap();
    assert!(repo.verify_session_binding(&lease, &binding).await.is_err());
    assert!(
        repo.replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
            .await
            .is_err(),
        "replacement compare-and-swap cannot replay"
    );
    let version = next.state_version;
    next.record_use(true, now, binding_limits(1, 5)).unwrap();
    repo.update_session_binding(&lease, version, &next).await.unwrap();
    let version = next.state_version;
    next.finish_cleanup(true).unwrap();
    repo.update_session_binding(&lease, version, &next).await.unwrap();
    assert!(
        repo.replace_retired_session_binding(&lease, &next, next.identity.clone(), next.expires_at)
            .await
            .is_err(),
        "finite admitted rotation budget cannot reset"
    );
}

async fn implicit_rotation_permission_and_configured_login_never_reset_retired_generation(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| implicit(repo, tenant).await);
}

async fn implicit<R: Binder>(repo: &R, tenant: TenantId) {
    for (rotations, login) in [(0, false), (1, true)] {
        let (lease, mut binding) = anonymous_binding_fixture(repo, tenant, rotations, login).await;
        let now = repo.now().await.unwrap();
        let version = binding.state_version;
        binding.record_use(false, now, binding_limits(5, 1)).unwrap();
        repo.update_session_binding(&lease, version, &binding)
            .await
            .unwrap();
        let version = binding.state_version;
        binding.finish_cleanup(true).unwrap();
        repo.update_session_binding(&lease, version, &binding)
            .await
            .unwrap();
        assert!(repo
            .bind_session(&lease, binding.identity.clone(), binding.expires_at)
            .await
            .is_err());
        assert!(repo
            .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
            .await
            .is_err());
        assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), binding);
    }
}

async fn observed_egress_pin_survives_a_new_handle_without_mutating_the_binding(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    let (lease, binding) = on_zdr_db!(rig, |repo| pins(repo, tenant).await);
    let database = super::reports::reopen(rig).await;
    super::reports::on_database!(database, |repo| restarted_pin(repo, &lease, tenant, &binding)
        .await);
    database.close().await;
}

async fn restarted_pin<R: Binder>(
    repo: &R,
    lease: &SessionLease,
    tenant: TenantId,
    binding: &SessionBindingV1,
) {
    let pin = Digest::of("fixture", b"observed-target");
    let drift = Digest::of("fixture", b"changed-target");
    repo.check_session_egress_pin(lease, tenant, binding.generation, drift)
        .await
        .unwrap();
    assert!(repo
        .check_session_egress_pin(lease, tenant, binding.generation, pin)
        .await
        .is_err());
    assert_eq!(repo.load_session_binding(lease, tenant).await.unwrap(), *binding);
}

async fn pins<R: Binder>(repo: &R, tenant: TenantId) -> (SessionLease, SessionBindingV1) {
    let (lease, mut binding) = anonymous_binding_fixture(repo, tenant, 1, false).await;
    let pin = Digest::of("fixture", b"observed-target");
    let drift = Digest::of("fixture", b"changed-target");
    repo.check_session_egress_pin(&lease, tenant, binding.generation, pin)
        .await
        .unwrap();
    repo.check_session_egress_pin(&lease, tenant, binding.generation, pin)
        .await
        .unwrap();
    assert!(repo
        .check_session_egress_pin(&lease, tenant, binding.generation, drift)
        .await
        .is_err());
    assert!(repo
        .check_session_egress_pin(&lease, tenant, binding.generation + 1, pin)
        .await
        .is_err());
    assert!(repo
        .check_session_egress_pin(&lease, TenantId::new(), binding.generation, pin)
        .await
        .is_err());
    let mut stale = lease.clone();
    stale.fencing_token -= 1;
    assert!(repo
        .check_session_egress_pin(&stale, tenant, binding.generation, pin)
        .await
        .is_err());
    assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), binding);
    let now = repo.now().await.unwrap();
    let version = binding.state_version;
    binding.record_use(true, now, binding_limits(1, 5)).unwrap();
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let version = binding.state_version;
    binding.finish_cleanup(true).unwrap();
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let next = repo
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
        .await
        .unwrap();
    // Each generation has its own pin: the new one accepts a different observation, and the
    // retired generation is no longer the live one.
    repo.check_session_egress_pin(&lease, tenant, next.generation, drift)
        .await
        .unwrap();
    assert!(repo
        .check_session_egress_pin(&lease, tenant, binding.generation, pin)
        .await
        .is_err());
    assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), next);
    (lease, next)
}

async fn explicit_anonymous_rotation_never_erases_an_existing_encrypted_profile(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| keeps_profile(rig, repo, tenant).await);
}

/// The stored profile as raw columns: generation, sealed bundle, digest and holder fence.
async fn stored_profile(rig: &Rig, lease: &SessionLease) -> (i64, Vec<u8>, Vec<u8>, i64) {
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM browser_profiles WHERE owner_run=$1 AND session_id=$2",
            &[Bind::Uuid(lease.session.run.0), Bind::Uuid(lease.session.id.0)],
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(rig, "SELECT count(*) FROM browser_profiles", &[]).await,
        1
    );
    (
        scalar_i64(rig, "SELECT generation FROM browser_profiles", &[]).await,
        scalar_bytes(rig, "SELECT encrypted_bundle FROM browser_profiles", &[]).await,
        scalar_bytes(rig, "SELECT digest FROM browser_profiles", &[]).await,
        scalar_i64(rig, "SELECT lease_fence FROM browser_profiles", &[]).await,
    )
}

async fn keeps_profile<R: Binder>(rig: &Rig, repo: &R, tenant: TenantId) {
    let (lease, mut binding) = anonymous_binding_fixture(repo, tenant, 1, false).await;
    let now = repo.now().await.unwrap();
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
    repo.import_profile(&cipher, &lease, &profile_scope, &bytes)
        .await
        .unwrap();
    let original_profile = stored_profile(rig, &lease).await;
    let version = binding.state_version;
    binding.record_use(true, now, binding_limits(1, 5)).unwrap();
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    let version = binding.state_version;
    binding.finish_cleanup(true).unwrap();
    repo.update_session_binding(&lease, version, &binding)
        .await
        .unwrap();
    assert!(repo
        .replace_retired_session_binding(&lease, &binding, binding.identity.clone(), binding.expires_at)
        .await
        .is_err());
    assert_eq!(stored_profile(rig, &lease).await, original_profile);
    assert_eq!(repo.load_session_binding(&lease, tenant).await.unwrap(), binding);
}
