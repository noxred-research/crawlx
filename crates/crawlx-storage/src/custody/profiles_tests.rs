//! Supported storage-state and real database/registry custody regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::artifact_key_crypto::{FileArtifactKeys, MemoryArtifactKeys};
use crate::codec::get;
use crate::custody::PgSecretAuthority;
use crate::leases::LeaseRepo as _;
use crate::testkit::{crawl_run, create_crawl, sessions};
use crate::{Pg, StoreConfig};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::RunRepo as _;
use crawlx_core::{PrincipalId, TenantId, WorkerId};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;

fn scope() -> ProfileScopeV1 {
    ProfileScopeV1::new(
        TenantId(Uuid::from_u128(1)),
        PrincipalId("role0".into()),
        "retained".into(),
        BTreeSet::from(["https://example.test".into()]),
        Digest::of("test/browser", b"build-one"),
        Digest::of("test/egress", b"egress-one"),
    )
    .unwrap()
}

fn canary(label: &str) -> String {
    Digest::of("crawlx/profile-test-canary/v1", label.as_bytes()).to_string()
}

fn document() -> Value {
    json!({
        "version": 1,
        "cookies": [{
            "name": "sid", "value": canary("cookie"), "domain": "example.test", "path": "/",
            "expires": -1, "size": canary("cookie").len() + 3, "httpOnly": true, "secure": true, "session": true,
            "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443
        }],
        "origins": [{"origin": "https://example.test",
            "local": [["local-key", canary("local")]],
            "session": [["session-key", canary("session")]]}]
    })
}

fn parse(value: &Value) -> Result<SupportedStorageState, StoreError> {
    SupportedStorageState::parse(&serde_json::to_vec(value).unwrap(), &scope())
}

#[test]
fn supported_state_preserves_all_cookies_local_and_session_values() {
    let bytes = serde_json::to_vec(&document()).unwrap();
    let state = SupportedStorageState::parse(&bytes, &scope()).unwrap();
    assert_eq!(state.as_bytes(), bytes);
    let expected_values = [canary("cookie"), canary("local"), canary("session")];
    let expected = ["sid", "local-key", "session-key"]
        .into_iter()
        .chain(expected_values.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    assert_eq!(state.opaque_values(), expected);
    let debug = format!("{state:?}");
    assert!(!debug.contains("secret"));
    for value in &expected_values {
        assert!(!debug.contains(value));
    }
    assert!(!debug.contains("example.test"));
}

#[test]
fn strict_state_rejects_unknown_missing_wrong_type_and_legacy_exports() {
    for candidate in [
        json!({}),
        json!({"sid":"opaque"}),
        json!({"version":1,"cookies":[]}),
        json!({"version":2,"cookies":[],"origins":[]}),
        json!({"version":1,"cookies":[],"origins":[],"directory":"opaque"}),
    ] {
        assert!(parse(&candidate).is_err());
    }
    for key in ["cookies", "origins"] {
        let mut value = document();
        value[key] = json!({});
        assert!(parse(&value).is_err());
    }
    for key in ["value", "domain", "session", "sourcePort", "priority"] {
        let mut value = document();
        value["cookies"][0].as_object_mut().unwrap().remove(key);
        assert!(parse(&value).is_err(), "missing {key}");
    }
    for key in ["local", "session"] {
        let mut value = document();
        value["origins"][0].as_object_mut().unwrap().remove(key);
        assert!(parse(&value).is_err());
    }
    let mut value = document();
    value["cookies"][0]["unknownAttribute"] = json!("not-supported");
    assert!(parse(&value).is_err());
    let mut value = document();
    value["origins"][0]["session"] = json!([["key", 3]]);
    assert!(parse(&value).is_err());
    let duplicate = br#"{"version":1,"version":1,"cookies":[],"origins":[]}"#;
    assert!(SupportedStorageState::parse(duplicate, &scope()).is_err());
}

#[test]
fn strict_state_rejects_ambiguous_origins_duplicate_keys_and_cookie_identities() {
    let mut value = document();
    let origin = value["origins"][0].clone();
    value["origins"].as_array_mut().unwrap().push(origin);
    assert!(parse(&value).is_err());
    let mut value = document();
    value["origins"][0]["local"] = json!([["same", "first"], ["same", "second"]]);
    assert!(parse(&value).is_err());
    let mut value = document();
    let cookie = value["cookies"][0].clone();
    value["cookies"].as_array_mut().unwrap().push(cookie);
    assert!(parse(&value).is_err());
    for origin in [
        "https://example.test/",
        "https://other.test",
        "null",
        "file:///tmp/state",
    ] {
        let mut value = document();
        value["origins"][0]["origin"] = json!(origin);
        assert!(parse(&value).is_err());
    }
    for domain in ["other.test", ".test", "example.test.evil", "example.test\n"] {
        let mut value = document();
        value["cookies"][0]["domain"] = json!(domain);
        assert!(parse(&value).is_err());
    }
}

#[test]
fn strict_state_supports_only_restorable_cookie_attributes() {
    for (key, val) in [
        ("priority", json!("Unknown")),
        ("sameSite", json!("Unknown")),
        ("sourceScheme", json!("Unknown")),
        ("sourcePort", json!(65536)),
        ("sourcePort", json!(0)),
        ("sameParty", json!(true)),
        ("partitionKeyOpaque", json!(true)),
        ("path", json!("relative")),
        ("name", json!("invalid name")),
        ("value", json!("invalid\ncookie")),
        ("sameSite", Value::Null),
        ("partitionKey", Value::Null),
    ] {
        let mut value = document();
        value["cookies"][0][key] = val;
        assert!(parse(&value).is_err(), "unsupported {key}");
    }
    let mut value = document();
    value["cookies"][0]["partitionKey"] = json!({
        "topLevelSite":"https://example.test", "hasCrossSiteAncestor":false,
    });
    assert!(parse(&value).is_ok());
    value["cookies"][0]["partitionKey"]["topLevelSite"] = json!("https://other.test");
    assert!(parse(&value).is_err());
    let mut value = document();
    value["cookies"][0]["session"] = json!(false);
    assert!(parse(&value).is_err());
    value["cookies"][0]["expires"] = json!(4_000_000_000_u64);
    assert!(parse(&value).is_ok());
    // Source scheme describes where a cookie was set, not its Secure attribute.
    let mut value = document();
    value["cookies"][0]["secure"] = json!(false);
    assert!(parse(&value).is_ok());
}

#[test]
fn strict_state_bounds_entire_json_each_opaque_value_and_distinct_registry_values() {
    assert!(SupportedStorageState::parse(
        &vec![b' '; crate::profiles::MAX_STORAGE_STATE_BYTES + 1],
        &scope()
    )
    .is_err());
    let mut value = document();
    value["cookies"][0]["value"] = json!("x".repeat(16 * 1024 + 1));
    assert!(parse(&value).is_err());
    let mut value = document();
    value["origins"][0]["local"] = Value::Array(
        (0..256)
            .map(|n| json!([format!("key-{n}"), format!("value-{n}")]))
            .collect(),
    );
    assert!(parse(&value).is_err());
    let state = parse(&json!({"version":1,"cookies":[],"origins":[]})).unwrap();
    assert!(state.opaque_values().is_empty());
}

#[test]
fn generation_conversion_never_wraps() {
    assert_eq!(generation(0).unwrap(), 0);
    assert_eq!(generation(u64::try_from(i64::MAX).unwrap()).unwrap(), i64::MAX);
    assert!(generation(u64::MAX).is_err());
}

fn file_keys() -> (tempfile::NamedTempFile, FileArtifactKeys) {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), canary("wrapping-root")).unwrap();
    let keys = FileArtifactKeys::from_lookup(&|name| {
        (name == "CRAWLX_ARTIFACT_KEY_FILE").then(|| file.path().to_string_lossy().into_owned())
    })
    .unwrap()
    .unwrap();
    (file, keys)
}

#[tokio::test]
async fn profiles_use_independent_durable_wrapped_keys_and_complete_authentication() {
    let (_file, keys) = file_keys();
    let owner = CrawlRunId(Uuid::from_u128(2));
    let bytes = serde_json::to_vec(&document()).unwrap();
    let length = u64::try_from(bytes.len()).unwrap();
    let first = ArtifactContext::new(scope().tenant, owner, ArtifactId(Uuid::from_u128(3)));
    let second = ArtifactContext::new(scope().tenant, owner, ArtifactId(Uuid::from_u128(4)));
    let a = keys.prepare(&first, length, length).await.unwrap();
    let b = keys.prepare(&second, length, length).await.unwrap();
    assert_ne!(a.envelope.wrapped_key, b.envelope.wrapped_key);
    assert!(keys.open(&second, &a.envelope).await.is_err());
    let mut encrypted = Vec::new();
    drop(a.encryption.seal(bytes.as_slice(), &mut encrypted).await.unwrap());
    let opaque = canary("cookie");
    assert!(!encrypted
        .windows(opaque.len())
        .any(|part| part == opaque.as_bytes()));
    let key = keys.open(&first, &a.envelope).await.unwrap();
    let mut reader = ArtifactDecryption::new(encrypted.as_slice(), first, key, length)
        .await
        .unwrap();
    let mut recovered = Zeroizing::new(Vec::new());
    while let Some(chunk) = reader.next_chunk().await.unwrap() {
        recovered.extend_from_slice(&chunk);
    }
    assert_eq!(reader.authenticated_len(), Some(length));
    assert_eq!(*recovered, bytes);
    let key = keys.open(&first, &a.envelope).await.unwrap();
    encrypted.pop();
    let mut reader = ArtifactDecryption::new(encrypted.as_slice(), first, key, length)
        .await
        .unwrap();
    assert!(reader.next_chunk().await.is_err());
}

struct Fixture {
    pg: Pg,
    authority: PgSecretAuthority,
    lease: SessionLease,
    custody: CustodyLease,
    scope: ProfileScopeV1,
    expiry: Timestamp,
}

async fn fixture() -> Option<Fixture> {
    let database = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let redis = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").ok()?;
    let pg = Pg::connect(
        &database,
        StoreConfig {
            schema: Some(format!("profile_custody_{}", Uuid::now_v7().simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "profile-custody-test").await.unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 1));
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let expiry: Timestamp = sqlx::query_scalar("UPDATE crawl_runs SET expires_at=clock_timestamp()+interval '1 hour' WHERE run_id=$1 RETURNING expires_at-interval '1 minute'")
        .bind(run.id.0).fetch_one(pg.pool()).await.unwrap();
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
    let authority = PgSecretAuthority::open(pg.clone(), &redis, Duration::from_secs(120))
        .await
        .unwrap();
    authority.initialize(&custody).await.unwrap();
    let mut scope = scope();
    scope.tenant = tenant;
    Some(Fixture {
        pg,
        authority,
        lease,
        custody,
        scope,
        expiry,
    })
}

#[tokio::test]
async fn postgres_profile_round_trip_registers_before_release_and_checks_generation_scope_and_fence() {
    let Some(f) = fixture().await else {
        return;
    };
    let (_file, keys) = file_keys();
    let profiles = CustodyProfiles::new(&f.authority, &keys);
    let bytes = serde_json::to_vec(&document()).unwrap();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 0, true)
        .await
        .unwrap()
        .is_none());
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 1, true)
        .await
        .is_err());
    let first = profiles
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
        .await
        .unwrap();
    assert_eq!(first.generation, 1);
    let registered = f.authority.snapshot(&f.custody).await.unwrap();
    for label in ["cookie", "local", "session"] {
        assert!(registered
            .secrets
            .contains_bytes(canary(label).as_bytes())
            .unwrap());
    }
    let row = sqlx::query(
        "SELECT encrypted_bundle,custody_envelope,custody_incarnation,custody_epoch FROM browser_profiles",
    )
    .fetch_one(f.pg.pool())
    .await
    .unwrap();
    let ciphertext: Vec<u8> = sqlx::Row::try_get(&row, "encrypted_bundle").unwrap();
    let opaque = canary("cookie");
    assert!(!ciphertext
        .windows(opaque.len())
        .any(|part| part == opaque.as_bytes()));
    assert_eq!(
        get::<Uuid>(&row, "custody_incarnation").unwrap(),
        registered.version.incarnation
    );
    assert_eq!(
        get::<i64>(&row, "custody_epoch").unwrap(),
        registered.version.epoch
    );
    let (_, restored) = profiles
        .acquire(&f.lease, &f.custody, &f.scope, 1, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.as_bytes(), bytes);
    assert!(profiles
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
        .await
        .is_err());
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 2, true)
        .await
        .is_err());
    let mut wrong = f.scope.clone();
    wrong.backend_build = Digest::of("test/browser", b"other-build");
    assert!(profiles
        .acquire(&f.lease, &f.custody, &wrong, 1, true)
        .await
        .is_err());
    wrong = f.scope.clone();
    wrong.egress = Digest::of("test/egress", b"other-egress");
    assert!(profiles
        .acquire(&f.lease, &f.custody, &wrong, 1, true)
        .await
        .is_err());
    wrong = f.scope.clone();
    wrong.tenant = TenantId::new();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &wrong, 1, true)
        .await
        .is_err());
    wrong = f.scope.clone();
    wrong.principal = PrincipalId("other-principal".into());
    assert!(profiles
        .acquire(&f.lease, &f.custody, &wrong, 1, true)
        .await
        .is_err());
    let mut stale = f.custody.clone();
    stale.fence += 1;
    assert!(profiles
        .acquire(&f.lease, &stale, &f.scope, 1, true)
        .await
        .is_err());
    let second = profiles
        .commit(&f.lease, &f.custody, &f.scope, 1, f.expiry, true, &bytes)
        .await
        .unwrap();
    assert_eq!(second.generation, 2);
    assert_ne!(first.digest, second.digest);
}

#[tokio::test]
async fn postgres_profile_policy_loss_corruption_and_legacy_directory_paths_fail_closed() {
    let Some(f) = fixture().await else {
        return;
    };
    let (_file, keys) = file_keys();
    let profiles = CustodyProfiles::new(&f.authority, &keys);
    let bytes = serde_json::to_vec(&document()).unwrap();
    assert!(profiles
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, false, &bytes)
        .await
        .is_err());
    assert!(profiles
        .commit(
            &f.lease,
            &f.custody,
            &f.scope,
            0,
            f.expiry + chrono::Duration::hours(2),
            true,
            &bytes
        )
        .await
        .is_err());
    assert!(profiles
        .commit(
            &f.lease,
            &f.custody,
            &f.scope,
            0,
            f.expiry - chrono::Duration::hours(2),
            true,
            &bytes
        )
        .await
        .is_err());
    let ephemeral = MemoryArtifactKeys::new().unwrap();
    assert!(CustodyProfiles::new(&f.authority, &ephemeral)
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
        .await
        .is_err());
    profiles
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
        .await
        .unwrap();
    let legacy_key = Digest::of("crawlx/profile-test-key/v1", b"legacy").0;
    let legacy = crate::profiles::ProfileCipher::new(&legacy_key).unwrap();
    let repo = crate::profiles::BrowserProfileRepo::new(&f.pg, &legacy);
    assert!(matches!(
        repo.acquire(&f.lease, &f.scope, false).await,
        Err(StoreError::Unavailable(_))
    ));
    sqlx::query("UPDATE browser_profiles SET encrypted_bundle=set_byte(encrypted_bundle,30,get_byte(encrypted_bundle,30)#1)")
        .execute(f.pg.pool()).await.unwrap();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 1, true)
        .await
        .is_err());
    sqlx::query("DELETE FROM browser_profiles")
        .execute(f.pg.pool())
        .await
        .unwrap();
    let mut metadata = f.pg.get_metadata(f.custody.run).await.unwrap();
    metadata.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    metadata.retention.days = 0;
    sqlx::query("UPDATE crawl_runs SET retention_mode='zdr',retention_days=0,config=jsonb_build_object('privacy','zdr','metadata',$2::jsonb) WHERE run_id=$1")
        .bind(f.custody.run.0)
        .bind(serde_json::to_value(metadata).unwrap())
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        profiles
            .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
            .await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 1, true)
        .await
        .is_err());
}

#[tokio::test]
async fn postgres_acquire_registers_complete_state_in_new_run_before_returning_any_bytes() {
    let Some(f) = fixture().await else {
        return;
    };
    let (_file, keys) = file_keys();
    let bytes = serde_json::to_vec(&document()).unwrap();
    CustodyProfiles::new(&f.authority, &keys)
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
        .await
        .unwrap();
    let run = crawl_run(
        f.scope.tenant,
        create_crawl("https://example.test/", &["role0"], 1),
    );
    f.pg.create(&run, None).await.unwrap();
    f.pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    f.pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    sqlx::query("UPDATE crawl_runs SET expires_at=clock_timestamp()+interval '2 hours' WHERE run_id=$1")
        .bind(run.id.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    let incoming =
        f.pg.claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .unwrap();
    let custody = CustodyLease::new(
        f.scope.tenant,
        run.id,
        incoming.session.id,
        incoming.worker,
        incoming.fencing_token,
    );
    f.authority.initialize(&custody).await.unwrap();
    assert!(!f
        .authority
        .snapshot(&custody)
        .await
        .unwrap()
        .secrets
        .has_values()
        .unwrap());
    let profiles = CustodyProfiles::new(&f.authority, &keys);
    // A live old holder cannot be detached, even by an otherwise authorized principal.
    assert!(profiles
        .acquire(&incoming, &custody, &f.scope, 1, true)
        .await
        .is_err());
    sqlx::query("UPDATE crawl_sessions SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE session_id=$1")
        .bind(f.lease.session.id.0).execute(f.pg.pool()).await.unwrap();
    let (_, restored) = profiles
        .acquire(&incoming, &custody, &f.scope, 1, true)
        .await
        .unwrap()
        .unwrap();
    let registered = f.authority.snapshot(&custody).await.unwrap();
    for value in restored.opaque_values() {
        assert!(registered.secrets.contains_bytes(value.as_bytes()).unwrap());
    }
    assert_eq!(restored.as_bytes(), bytes);
}

struct PausedKeys {
    inner: FileArtifactKeys,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl ArtifactKeys for PausedKeys {
    fn is_available(&self) -> bool {
        self.inner.is_available()
    }
    fn is_durable(&self) -> bool {
        self.inner.is_durable()
    }

    async fn prepare(
        &self,
        context: &ArtifactContext,
        plaintext_len: u64,
        max_plaintext_bytes: u64,
    ) -> Result<crate::artifact_key_crypto::PreparedArtifact, crate::artifact_key_crypto::ArtifactKeyError>
    {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        self.inner
            .prepare(context, plaintext_len, max_plaintext_bytes)
            .await
    }

    async fn open(
        &self,
        context: &ArtifactContext,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<crate::artifact_crypto::ArtifactDataKey, crate::artifact_key_crypto::ArtifactKeyError> {
        self.inner.open(context, envelope).await
    }
}

#[tokio::test]
async fn postgres_profile_publication_compares_authority_epoch_after_key_preparation() {
    let Some(f) = fixture().await else {
        return;
    };
    let (_file, inner) = file_keys();
    let keys = PausedKeys {
        inner,
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    };
    let profiles = CustodyProfiles::new(&f.authority, &keys);
    let bytes = serde_json::to_vec(&document()).unwrap();
    let writing = profiles.commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes);
    let racing = async {
        keys.entered.acquire().await.unwrap().forget();
        let current = f.authority.snapshot(&f.custody).await.unwrap();
        f.authority
            .register(
                &f.custody,
                current.version,
                Uuid::now_v7(),
                &SecretOr::secret(canary("racing")),
            )
            .await
            .unwrap();
        keys.release.add_permits(1);
    };
    let (result, ()) = tokio::join!(writing, racing);
    assert!(matches!(&result, Err(StoreError::Conflict(detail)) if detail == PUBLISH_STALE));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_profiles")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn postgres_registry_loss_never_releases_profile_or_recreates_empty_authority() {
    let Some(f) = fixture().await else {
        return;
    };
    let (_file, keys) = file_keys();
    let profiles = CustodyProfiles::new(&f.authority, &keys);
    let bytes = serde_json::to_vec(&document()).unwrap();
    profiles
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
        .await
        .unwrap();
    let redis = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").unwrap();
    let mut connection = redis::Client::open(redis.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(format!("crawlx:secrets:{{{}:{}}}", f.scope.tenant, f.custody.run))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 1, true)
        .await
        .is_err());
    assert!(f.authority.initialize(&f.custody).await.is_err());
}

#[tokio::test]
async fn postgres_profile_authenticates_catalog_scope_generation_and_expiry_against_ciphertext() {
    let Some(f) = fixture().await else {
        return;
    };
    let (_file, keys) = file_keys();
    let profiles = CustodyProfiles::new(&f.authority, &keys);
    let bytes = serde_json::to_vec(&document()).unwrap();
    profiles
        .commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes)
        .await
        .unwrap();
    let mut changed_scope = f.scope.clone();
    changed_scope.backend_build = Digest::of("test/browser", b"catalog-only-change");
    sqlx::query("UPDATE browser_profiles SET scope=$1")
        .bind(to_json(&changed_scope).unwrap())
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &changed_scope, 1, true)
        .await
        .is_err());
    sqlx::query("UPDATE browser_profiles SET scope=$1,generation=2")
        .bind(to_json(&f.scope).unwrap())
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 2, true)
        .await
        .is_err());
    sqlx::query("UPDATE browser_profiles SET generation=1,expires_at=expires_at-interval '1 second'")
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 1, true)
        .await
        .is_err());
    sqlx::query("UPDATE browser_profiles SET expires_at=clock_timestamp()-interval '1 second'")
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(profiles
        .acquire(&f.lease, &f.custody, &f.scope, 1, true)
        .await
        .is_err());
}

#[tokio::test]
async fn postgres_profile_publication_rejects_changed_authority_incarnation() {
    let Some(f) = fixture().await else {
        return;
    };
    let (_file, inner) = file_keys();
    let keys = PausedKeys {
        inner,
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    };
    let profiles = CustodyProfiles::new(&f.authority, &keys);
    let bytes = serde_json::to_vec(&document()).unwrap();
    let writing = profiles.commit(&f.lease, &f.custody, &f.scope, 0, f.expiry, true, &bytes);
    let racing = async {
        keys.entered.acquire().await.unwrap().forget();
        sqlx::query("UPDATE run_secret_authority SET incarnation=$3 WHERE tenant_id=$1 AND run_id=$2")
            .bind(f.scope.tenant.0)
            .bind(f.custody.run.0)
            .bind(Uuid::now_v7())
            .execute(f.pg.pool())
            .await
            .unwrap();
        keys.release.add_permits(1);
    };
    let (result, ()) = tokio::join!(writing, racing);
    assert!(matches!(result, Err(StoreError::Conflict(_))));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM browser_profiles")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
