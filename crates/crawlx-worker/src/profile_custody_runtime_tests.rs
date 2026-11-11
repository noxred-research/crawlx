#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crawlx_core::counters::RunStatus;
use crawlx_core::custody::RunSecretAuthority as _;
use crawlx_core::repo::RunRepo as _;
use crawlx_core::{PrincipalId, TenantId, WorkerId};
use crawlx_storage::artifact_key_crypto::FileArtifactKeys;
use crawlx_storage::custody::PgSecretAuthority;
use crawlx_storage::leases::LeaseRepo as _;
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{Pg, StoreConfig};
use serde_json::json;
use std::time::Duration;

const NOW: f64 = 1_000_000_000.0;

fn at() -> Timestamp {
    chrono::DateTime::from_timestamp(1_000_000_000, 0).unwrap()
}
const ORIGIN: &str = "https://example.test";

fn canary(label: &str) -> String {
    Digest::of("crawlx/profile-test-canary/v1", label.as_bytes()).to_string()
}

fn document() -> Value {
    json!({
        "version": 1,
        "cookies": [{
            "name": "sid", "value": canary("cookie"), "domain": "example.test", "path": "/",
            "expires": -1, "size": 70, "httpOnly": true, "secure": true, "session": true,
            "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443
        }],
        "origins": [{"origin": ORIGIN,
            "local": [["local-key", canary("local")]],
            "session": [["session-key", canary("session")]]}]
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn scope() -> ProfileScopeV1 {
    ProfileScopeV1::new(
        TenantId::new(),
        PrincipalId("role0".into()),
        "retained".into(),
        BTreeSet::from([ORIGIN.to_owned()]),
        Digest::of("test/browser", b"build-one"),
        Digest::of("test/egress", b"egress-one"),
    )
    .unwrap()
}

/// Browser double: cookies apply on import (host-only domains gain the leading dot a real
/// browser reports), web storage appears only once a document of its origin exists.
#[derive(Default)]
struct Memory {
    cookies: Vec<Value>,
    pending: Vec<Value>,
    origins: Vec<Value>,
    drop_cookies: bool,
    fail_import: bool,
    fail_export: bool,
}

impl Memory {
    fn login(&mut self, document: &Value) {
        self.cookies = document["cookies"].as_array().unwrap().clone();
        self.origins = document["origins"].as_array().unwrap().clone();
    }

    fn navigate(&mut self) {
        self.origins.append(&mut self.pending);
    }
}

#[async_trait]
impl StorageSurface for Memory {
    async fn import(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        if self.fail_import {
            return Err(BrowserError::Io("import refused".into()));
        }
        let document: Value = serde_json::from_slice(blob).map_err(|e| BrowserError::Io(e.to_string()))?;
        if !self.drop_cookies {
            self.cookies = document["cookies"]
                .as_array()
                .unwrap()
                .iter()
                .cloned()
                .map(|mut cookie| {
                    let domain = format!(".{}", cookie["domain"].as_str().unwrap());
                    cookie["domain"] = Value::from(domain);
                    cookie
                })
                .collect();
        }
        self.pending = document["origins"].as_array().unwrap().clone();
        Ok(())
    }

    async fn export_complete(&mut self) -> Result<Vec<u8>, BrowserError> {
        if self.fail_export {
            return Err(BrowserError::Unsupported(
                "complete profile export unavailable".into(),
            ));
        }
        Ok(bytes(
            &json!({"version": 1, "cookies": self.cookies, "origins": self.origins}),
        ))
    }
}

#[tokio::test]
async fn only_a_provably_empty_exportable_context_may_receive_a_profile() {
    ensure_fresh(&mut Memory::default()).await.unwrap();
    let mut with_cookie = Memory::default();
    with_cookie.login(&document());
    assert!(ensure_fresh(&mut with_cookie).await.is_err());
    let mut with_web = Memory {
        origins: document()["origins"].as_array().unwrap().clone(),
        ..Memory::default()
    };
    assert!(ensure_fresh(&mut with_web).await.is_err());
    let mut unexportable = Memory {
        fail_export: true,
        ..Memory::default()
    };
    assert!(ensure_fresh(&mut unexportable).await.is_err());
}

#[tokio::test]
async fn secrets_reach_the_local_registry_before_import_and_stay_registered_on_failure() {
    let secrets = CaptchaSecrets::default();
    let mut refusing = Memory {
        fail_import: true,
        ..Memory::default()
    };
    let expires = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
    assert!(
        apply_state(&secrets, &bytes(&document()), expires, NOW, &mut refusing)
            .await
            .is_err()
    );
    for label in ["cookie", "local", "session"] {
        assert_eq!(secrets.redact(&canary(label)).unwrap(), "[REDACTED]", "{label}");
    }
    assert_eq!(secrets.redact("local-key").unwrap(), "[REDACTED]");
}

#[tokio::test]
async fn restore_requires_cookie_readback_and_confirms_web_storage_after_navigation() {
    let secrets = CaptchaSecrets::default();
    let expires = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
    let mut browser = Memory::default();
    let restored = apply_state(&secrets, &bytes(&document()), expires, NOW, &mut browser)
        .await
        .unwrap();
    assert!(
        !restored.web_confirmed,
        "web storage is applied to documents, not yet observable"
    );
    let mut start = ProfileStart {
        scope: scope(),
        generation: 1,
        acquired: None,
        restored: Some(restored),
    };
    assert!(start.is_restored() && start.web_storage_pending());
    assert!(start
        .confirm_web_storage(&browser.export_complete().await.unwrap())
        .is_err());
    assert!(start.web_storage_pending());
    browser.navigate();
    start
        .confirm_web_storage(&browser.export_complete().await.unwrap())
        .unwrap();
    assert!(!start.web_storage_pending());
    assert_eq!(start.expires_at(), Some(expires));
    assert_eq!(
        start.profile_identity().unwrap(),
        Some(Digest::of_value("crawlx/profile-identity/v1", &(&start.scope, 1_u64)).unwrap())
    );
}

#[tokio::test]
async fn a_store_hit_alone_is_not_a_restore() {
    let secrets = CaptchaSecrets::default();
    let expires = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
    let mut dropping = Memory {
        drop_cookies: true,
        ..Memory::default()
    };
    assert!(
        apply_state(&secrets, &bytes(&document()), expires, NOW, &mut dropping)
            .await
            .is_err()
    );
    let mut unexportable = Memory {
        fail_export: true,
        ..Memory::default()
    };
    assert!(
        apply_state(&secrets, &bytes(&document()), expires, NOW, &mut unexportable)
            .await
            .is_err()
    );
    let fresh = ProfileStart {
        scope: scope(),
        generation: 0,
        acquired: None,
        restored: None,
    };
    assert!(!fresh.is_restored() && !fresh.web_storage_pending());
    assert_eq!(fresh.profile_identity().unwrap(), None);
    assert_eq!(fresh.expires_at(), None);
}

#[tokio::test]
async fn expired_persistent_cookies_are_not_required_to_read_back() {
    let mut state = document();
    state["cookies"][0]["session"] = Value::Bool(false);
    state["cookies"][0]["expires"] = Value::from(100.0);
    state["origins"] = json!([]);
    let mut dropping = Memory {
        drop_cookies: true,
        ..Memory::default()
    };
    let expires = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
    apply_state(
        &CaptchaSecrets::default(),
        &bytes(&state),
        expires,
        NOW,
        &mut dropping,
    )
    .await
    .unwrap();
    assert!(
        apply_state(
            &CaptchaSecrets::default(),
            &bytes(&state),
            expires,
            50.0,
            &mut Memory {
                drop_cookies: true,
                ..Memory::default()
            }
        )
        .await
        .is_err(),
        "a cookie still valid at `now` must read back"
    );
}

#[derive(Debug)]
struct Refuse;

#[async_trait]
impl NavigationGuard for Refuse {
    async fn check(&self, _: &url::Url) -> NavigationVerdict {
        NavigationVerdict::EgressDenied
    }
    async fn check_request(&self, _: &url::Url) -> NavigationVerdict {
        NavigationVerdict::EgressDenied
    }
    fn intercepts_subresources(&self) -> bool {
        true
    }
    async fn check_subresource(&self, _: &url::Url) -> NavigationVerdict {
        NavigationVerdict::EgressDenied
    }
}

#[tokio::test]
async fn origin_guard_confines_documents_requests_and_subresources() {
    let inside = url::Url::parse("https://example.test/a").unwrap();
    for outside in [
        "https://other.test/",
        "http://example.test/",
        "https://example.test:8443/",
    ] {
        let outside = url::Url::parse(outside).unwrap();
        let guard = origin_guard(BTreeSet::from([ORIGIN.to_owned()]), None);
        assert!(guard.intercepts_subresources());
        assert_eq!(guard.check(&inside).await.refusal(), None);
        assert_eq!(guard.check_request(&inside).await.refusal(), None);
        assert_eq!(guard.check_subresource(&inside).await.refusal(), None);
        for verdict in [
            guard.check(&outside).await,
            guard.check_request(&outside).await,
            guard.check_subresource(&outside).await,
        ] {
            assert_eq!(verdict.refusal(), Some("profile_origin_binding"), "{outside}");
        }
    }
    let wrapped = origin_guard(BTreeSet::from([ORIGIN.to_owned()]), Some(Arc::new(Refuse)));
    assert_eq!(wrapped.check(&inside).await.refusal(), Some("egress_denied"));
    assert_eq!(
        wrapped.check_subresource(&inside).await.refusal(),
        Some("egress_denied")
    );
}

/// The run's own retention (default days from creation) bounds every profile expiry used here.
fn profile_expiry() -> Timestamp {
    let later = chrono::Utc::now() + chrono::Duration::hours(1);
    chrono::DateTime::from_timestamp_millis(later.timestamp_millis()).unwrap()
}

async fn leased_run(
    pg: &Pg,
    tenant: TenantId,
    authority: &PgSecretAuthority,
) -> (SessionLease, CustodyLease) {
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 1));
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let lease = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let custody = CustodyLease::new(
        tenant,
        run.id,
        lease.session.id,
        lease.worker,
        lease.fencing_token,
    );
    authority.initialize(&custody).await.unwrap();
    (lease, custody)
}

/// Custody acquisition followed by application to a browser double.
trait Restore {
    async fn restore(
        &self,
        identity: &SessionIdentityV1,
        generation: u64,
        now: Timestamp,
        surface: &mut Memory,
    ) -> Result<ProfileStart, WorkerError>;
}

impl Restore for ProfileCustodyRuntime {
    async fn restore(
        &self,
        identity: &SessionIdentityV1,
        generation: u64,
        now: Timestamp,
        surface: &mut Memory,
    ) -> Result<ProfileStart, WorkerError> {
        let mut start = self.acquire(identity, generation).await?;
        start.apply(&self.inputs.secrets, now, surface).await?;
        Ok(start)
    }
}

fn identity(tenant: TenantId, lease: &SessionLease, build: &[u8]) -> SessionIdentityV1 {
    let digest = Digest::of("test/profile-runtime", b"identity");
    SessionIdentityV1::new(
        tenant,
        &lease.session,
        digest,
        Digest::of("test/browser", build),
        Digest::of("test/egress", b"egress-one"),
        digest,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn runtime(
    authority: &Arc<PgSecretAuthority>,
    keys: &Arc<dyn ArtifactKeys>,
    lease: &SessionLease,
    custody: CustodyLease,
    secrets: &CaptchaSecrets,
    fresh_expiry: Timestamp,
    save_changes: bool,
) -> ProfileCustodyRuntime {
    ProfileCustodyRuntime::new(ProfileCustodyInputs {
        authority: Arc::new(crate::durable::DurableAuthority::Postgres((**authority).clone())),
        keys: Arc::clone(keys),
        lease: lease.clone(),
        custody,
        secrets: secrets.clone(),
        name: "retained".to_owned(),
        origins: BTreeSet::from([ORIGIN.to_owned()]),
        save_changes,
        fresh_expiry,
    })
    .unwrap()
}

#[tokio::test]
async fn restart_restores_the_committed_generation_through_custody_and_refuses_everything_else() {
    let (Ok(database), Ok(redis)) = (
        std::env::var("CRAWLX_TEST_DATABASE_URL"),
        std::env::var("CRAWLX_TEST_SECRET_REDIS_URL"),
    ) else {
        return;
    };
    let pg = Pg::connect(
        &database,
        StoreConfig {
            schema: Some(format!(
                "profile_runtime_{}",
                crawlx_core::CrawlRunId::new().0.simple()
            )),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "profile-runtime-test").await.unwrap();
    let authority = Arc::new(
        PgSecretAuthority::open(pg.clone(), &redis, Duration::from_secs(120))
            .await
            .unwrap(),
    );
    let key_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(key_file.path(), canary("wrapping-root")).unwrap();
    let keys: Arc<dyn ArtifactKeys> = Arc::new(
        FileArtifactKeys::from_lookup(&|name| {
            (name == "CRAWLX_ARTIFACT_KEY_FILE").then(|| key_file.path().to_string_lossy().into_owned())
        })
        .unwrap()
        .unwrap(),
    );

    // First process: new namespace, the session logs in, its strict export becomes generation 1.
    let expiry_a = profile_expiry();
    let (lease_a, custody_a) = leased_run(&pg, tenant, &authority).await;
    let first = runtime(
        &authority,
        &keys,
        &lease_a,
        custody_a,
        &CaptchaSecrets::default(),
        expiry_a,
        true,
    );
    let identity_a = identity(tenant, &lease_a, b"build-one");
    let mut browser_a = Memory::default();
    let start_a = first.restore(&identity_a, 0, at(), &mut browser_a).await.unwrap();
    assert!(!start_a.is_restored() && start_a.generation() == 0);
    assert_eq!(start_a.profile_identity().unwrap(), None);
    assert!(
        first
            .restore(&identity_a, 1, at(), &mut Memory::default())
            .await
            .is_err(),
        "a missing non-zero generation never falls back to an empty profile"
    );
    browser_a.login(&document());
    let committed = first
        .finish(&start_a, &browser_a.export_complete().await.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.generation, 1);
    let unsaved = runtime(
        &authority,
        &keys,
        &lease_a,
        CustodyLease::new(
            tenant,
            lease_a.session.run,
            lease_a.session.id,
            lease_a.worker,
            lease_a.fencing_token,
        ),
        &CaptchaSecrets::default(),
        expiry_a,
        false,
    );
    assert!(unsaved.finish(&start_a, b"{}").await.unwrap().is_none());

    // Restart: the old holder releases its lease; a new worker, run and fence restore generation 1.
    pg.release(&lease_a, crawlx_core::repo::SessionStatus::Recovering)
        .await
        .unwrap();
    let (lease_b, custody_b) = leased_run(&pg, tenant, &authority).await;
    let secrets_b = CaptchaSecrets::default();
    let second = runtime(
        &authority,
        &keys,
        &lease_b,
        custody_b.clone(),
        &secrets_b,
        expiry_a,
        true,
    );
    let identity_b = identity(tenant, &lease_b, b"build-one");
    assert!(
        second
            .restore(&identity_b, 2, at(), &mut Memory::default())
            .await
            .is_err(),
        "wrong generation"
    );
    let mut dirty = Memory::default();
    dirty.login(&document());
    assert!(
        second.restore(&identity_b, 1, at(), &mut dirty).await.is_err(),
        "context not empty"
    );
    let other_build = identity(tenant, &lease_b, b"build-two");
    assert!(
        second
            .restore(&other_build, 1, at(), &mut Memory::default())
            .await
            .is_err(),
        "other build"
    );
    let mut foreign = identity_b.clone();
    foreign.principal = PrincipalId("someone-else".into());
    assert!(
        second
            .restore(&foreign, 1, at(), &mut Memory::default())
            .await
            .is_err(),
        "other principal"
    );
    let mut broken = Memory {
        drop_cookies: true,
        ..Memory::default()
    };
    assert!(
        second.restore(&identity_b, 1, at(), &mut broken).await.is_err(),
        "unapplied cookies"
    );

    // The claim precedes the browser: bindable identity and deadline exist before any import.
    let mut claimed = second.acquire(&identity_b, 1).await.unwrap();
    assert!(claimed.apply_pending() && !claimed.is_restored());
    assert!(claimed.profile_identity().unwrap().is_some());
    assert_eq!(claimed.expires_at(), Some(committed.expires_at));
    assert!(
        second.finish(&claimed, b"{}").await.is_err(),
        "an unapplied claim never commits"
    );
    claimed
        .apply(&secrets_b, at(), &mut Memory::default())
        .await
        .unwrap();
    assert!(claimed.is_restored());
    let mut browser_b = Memory::default();
    let mut start_b = second
        .restore(&identity_b, 1, at(), &mut browser_b)
        .await
        .unwrap();
    assert!(start_b.is_restored() && start_b.generation() == 1);
    assert_eq!(start_b.expires_at(), Some(committed.expires_at));
    assert_eq!(
        start_b.profile_identity().unwrap(),
        Some(Digest::of_value("crawlx/profile-identity/v1", &(start_b.scope(), 1_u64)).unwrap())
    );
    assert!(start_b.web_storage_pending());
    assert!(
        second
            .finish(&start_b, &browser_b.export_complete().await.unwrap())
            .await
            .is_err(),
        "a lineage whose restored web storage was never proven in the browser is not extended"
    );
    browser_b.navigate();
    start_b
        .confirm_web_storage(&browser_b.export_complete().await.unwrap())
        .unwrap();
    for label in ["cookie", "local", "session"] {
        assert_eq!(secrets_b.redact(&canary(label)).unwrap(), "[REDACTED]", "{label}");
        assert!(authority
            .snapshot(&custody_b)
            .await
            .unwrap()
            .secrets
            .contains_bytes(canary(label).as_bytes())
            .unwrap());
    }

    // The restarted session continues the same lineage.
    let next = second
        .finish(&start_b, &browser_b.export_complete().await.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.generation, 2);
    assert_eq!(
        next.expires_at, committed.expires_at,
        "retention is never extended"
    );
}
