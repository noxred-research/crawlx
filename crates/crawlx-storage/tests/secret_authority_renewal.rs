//! Real backend refusal and historical renewal-receipt recovery regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Duration as TimeDelta;
use crawlx_core::counters::RunStatus;
use crawlx_core::custody::{CustodyLease, RunSecretAuthority, SecretEpoch};
use crawlx_core::repo::RunRepo;
use crawlx_core::{SecretOr, TenantId, Timestamp, WorkerId};
use crawlx_storage::custody::{
    encrypted_object_key, CiphertextIdentity, PgSecretAuthority, CIPHERTEXT_DIGEST_DOMAIN,
};
use crawlx_storage::leases::LeaseRepo;
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{Pg, PgConfig};
use std::time::Duration;
use uuid::Uuid;

fn ciphertext() -> CiphertextIdentity {
    CiphertextIdentity::new(
        crawlx_core::hash::Digest::of(CIPHERTEXT_DIGEST_DOMAIN, &[7; 196]),
        196,
    )
    .unwrap()
}

struct Fixture {
    pg: Pg,
    authority: PgSecretAuthority,
    lease: CustodyLease,
    redis: redis::aio::MultiplexedConnection,
    key: String,
}

async fn fixture(ttl: Duration) -> Option<Fixture> {
    let database = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").ok()?;
    let pg = Pg::connect(
        &database,
        PgConfig {
            schema: Some(format!("renewal_{}", Uuid::now_v7().simple())),
            // Renewal clock samples must use the held transaction, not the pool.
            max_connections: 1,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "secret-renewal-regression")
        .await
        .unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 1));
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let session = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let lease = CustodyLease::new(
        tenant,
        run.id,
        session.session.id,
        session.worker,
        session.fencing_token,
    );
    let authority = PgSecretAuthority::open(pg.clone(), &redis_url, ttl)
        .await
        .unwrap();
    let redis = redis::Client::open(redis_url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    Some(Fixture {
        pg,
        authority,
        lease,
        redis,
        key: format!("crawlx:secrets:{{{}:{}}}", tenant, run.id),
    })
}

async fn expiry(f: &Fixture) -> Timestamp {
    sqlx::query_scalar("SELECT expires_at FROM run_secret_authority")
        .fetch_one(f.pg.pool())
        .await
        .unwrap()
}

fn target(previous: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_timestamp_millis(previous.timestamp_millis() + seconds * 1000).unwrap()
}

async fn pending(
    f: &Fixture,
    expected: SecretEpoch,
    operation: Uuid,
    previous: Timestamp,
    deadline: Timestamp,
) {
    // Reproduce a migrated historical authority, whose physical expiry was its
    // original use deadline. New authorities never send a Redis renewal command.
    sqlx::query("UPDATE run_secret_authority SET use_window_ms=NULL,retention_ceiling=expires_at")
        .execute(f.pg.pool())
        .await
        .unwrap();
    let mut connection = f.redis.clone();
    let _: bool = redis::cmd("PEXPIREAT")
        .arg(&f.key)
        .arg(previous.timestamp_millis() - 2000)
        .query_async(&mut connection)
        .await
        .unwrap();
    // Real durable pre-command boundary, not a mock or process-local authority.
    sqlx::query("INSERT INTO run_secret_authority_renewals(tenant_id,run_id,operation,incarnation,secret_epoch,previous_deadline,deadline) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(f.lease.tenant.0).bind(f.lease.run.0).bind(operation).bind(expected.incarnation)
        .bind(expected.epoch).bind(previous).bind(deadline)
        .execute(f.pg.pool()).await.unwrap();
    sqlx::query("UPDATE run_secret_authority SET pending_renewal_operation=$1,pending_renewal_deadline=$2")
        .bind(operation)
        .bind(deadline)
        .execute(f.pg.pool())
        .await
        .unwrap();
}

async fn remote_renew(
    f: &mut Fixture,
    expected: SecretEpoch,
    operation: Uuid,
    previous: Timestamp,
    deadline: Timestamp,
) -> Vec<String> {
    redis::Script::new(include_str!("../src/custody_redis.lua"))
        .key(&f.key)
        .arg("renew")
        .arg(expected.incarnation.to_string())
        .arg(expected.epoch)
        .arg(operation.to_string())
        .arg(previous.timestamp_millis() - 2000)
        .arg(deadline.timestamp_millis() - 2000)
        .invoke_async(&mut f.redis)
        .await
        .unwrap()
}

async fn historical_applied_receipt(
    f: &mut Fixture,
    operation: Uuid,
    previous: Timestamp,
    deadline: Timestamp,
) {
    // Fault-state fixture for a historical command that executed before its
    // durable completion reply was lost. Production cannot issue this mutation.
    let _: () = redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(&f.key)
        .arg("renewal_operation")
        .arg(operation.to_string())
        .arg("renewal_previous")
        .arg(previous.timestamp_millis() - 2000)
        .arg("renewal_deadline")
        .arg(deadline.timestamp_millis() - 2000)
        .ignore()
        .cmd("PEXPIREAT")
        .arg(&f.key)
        .arg(deadline.timestamp_millis() - 2000)
        .ignore()
        .query_async(&mut f.redis)
        .await
        .unwrap();
}

#[tokio::test]
async fn historical_recovery_preserves_registration_retry_and_exact_absolute_expiry() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let registration = Uuid::now_v7();
    let secret = SecretOr::secret("renewal-private-canary-719".into());
    let registered = f
        .authority
        .register(&f.lease, initial.version, registration, &secret)
        .await
        .unwrap();
    let durable_before: (Option<Uuid>, Option<Vec<u8>>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT last_operation,commitment,last_value_commitment FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    let volatile_before: (String, String, String) = redis::cmd("HMGET")
        .arg(&f.key)
        .arg(&["operation", "value", "salt"])
        .query_async(&mut f.redis)
        .await
        .unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 3600);
    let operation = Uuid::now_v7();
    pending(&f, registered.version, operation, previous, deadline).await;
    historical_applied_receipt(&mut f, operation, previous, deadline).await;
    let renewed = f
        .authority
        .renew_authority(&f.lease, registered.version, operation, deadline)
        .await
        .unwrap();
    assert_eq!(renewed.version, registered.version);
    assert!(renewed
        .secrets
        .contains_bytes(b"renewal-private-canary-719")
        .unwrap());
    let remote_deadline: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(remote_deadline, deadline.timestamp_millis() - 2000);
    let durable_after: (Option<Uuid>, Option<Vec<u8>>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT last_operation,commitment,last_value_commitment FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert_eq!(durable_before, durable_after);
    let volatile_after: (String, String, String) = redis::cmd("HMGET")
        .arg(&f.key)
        .arg(&["operation", "value", "salt"])
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(volatile_before, volatile_after);
    tokio::time::sleep(Duration::from_millis(25)).await;
    f.authority
        .renew_authority(&f.lease, registered.version, operation, deadline)
        .await
        .unwrap();
    assert_eq!(expiry(&f).await, deadline);
    let after_retry: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(after_retry, remote_deadline);
    assert!(f
        .authority
        .renew_authority(&f.lease, registered.version, operation, target(deadline, 1))
        .await
        .is_err());
    let retried = f
        .authority
        .register(&f.lease, initial.version, registration, &secret)
        .await
        .unwrap();
    assert_eq!(retried.version, registered.version);
    // Lost completion replies remain recoverable after another registration.
    let current = f
        .authority
        .register(
            &f.lease,
            registered.version,
            Uuid::now_v7(),
            &SecretOr::secret("later-secret".into()),
        )
        .await
        .unwrap();
    let recovered = f
        .authority
        .renew_authority(&f.lease, registered.version, operation, deadline)
        .await
        .unwrap();
    assert_eq!(recovered.version, current.version);
    // A later historical renewal cannot release an old operation id for reuse.
    let next = target(deadline, 1);
    let next_operation = Uuid::now_v7();
    pending(&f, current.version, next_operation, deadline, next).await;
    historical_applied_receipt(&mut f, next_operation, deadline, next).await;
    f.authority
        .renew_authority(&f.lease, current.version, next_operation, next)
        .await
        .unwrap();
    f.authority
        .renew_authority(&f.lease, registered.version, operation, deadline)
        .await
        .unwrap();
    assert_eq!(expiry(&f).await, next);
}

#[tokio::test]
async fn unapplied_pending_barrier_blocks_use_and_cannot_extend_retention() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let operation = Uuid::now_v7();
    pending(&f, initial.version, operation, previous, deadline).await;
    let effective: Timestamp =
        sqlx::query_scalar("SELECT GREATEST(expires_at,pending_renewal_deadline) FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert_eq!(effective, deadline);
    assert!(f.authority.snapshot(&f.lease).await.is_err());
    assert!(f.authority.initialize(&f.lease).await.is_err());
    assert!(f
        .authority
        .register(
            &f.lease,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("blocked".into())
        )
        .await
        .is_err());
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
        .await
        .is_err());
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, operation, target(deadline, 1))
        .await
        .is_err());
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .is_err());
    assert_eq!(expiry(&f).await, previous);
    let barrier: Option<Uuid> =
        sqlx::query_scalar("SELECT pending_renewal_operation FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert_eq!(barrier, Some(operation));
    let remote: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(remote, previous.timestamp_millis() - 2000);
}

#[tokio::test]
async fn old_deadline_recovery_requires_surviving_exact_remote_renewal_proof() {
    let Some(mut f) = fixture(Duration::from_secs(5)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let operation = Uuid::now_v7();
    pending(&f, initial.version, operation, previous, deadline).await;
    historical_applied_receipt(&mut f, operation, previous, deadline).await;
    let wait = (previous - f.pg.now().await.unwrap())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(wait + Duration::from_millis(25)).await;
    assert!(f.authority.snapshot(&f.lease).await.is_err());
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
        .await
        .is_err());
    let recovered = f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .unwrap();
    assert_eq!(recovered.version, initial.version);
    let remote_deadline: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(remote_deadline, deadline.timestamp_millis() - 2000);
}

#[tokio::test]
async fn old_deadline_without_applied_renewal_never_recreates_lost_registry() {
    let Some(mut f) = fixture(Duration::from_secs(5)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let operation = Uuid::now_v7();
    pending(&f, initial.version, operation, previous, deadline).await;
    let wait = (previous - f.pg.now().await.unwrap())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(wait + Duration::from_millis(25)).await;
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .is_err());
    assert!(f.authority.initialize(&f.lease).await.is_err());
    let exists: bool = redis::cmd("EXISTS")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(!exists);
    let effective: Timestamp =
        sqlx::query_scalar("SELECT GREATEST(expires_at,pending_renewal_deadline) FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert_eq!(effective, deadline);
}

#[tokio::test]
async fn delayed_remote_command_is_refused_and_corrupt_historical_receipt_denies_recovery() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let operation = Uuid::now_v7();
    pending(&f, initial.version, operation, previous, deadline).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        remote_renew(&mut f, initial.version, operation, previous, deadline).await[0],
        "denied"
    );
    let absolute: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(absolute, previous.timestamp_millis() - 2000);
    historical_applied_receipt(&mut f, operation, previous, deadline).await;
    let _: () = redis::cmd("HSET")
        .arg(&f.key)
        .arg("renewal_previous")
        .arg("corrupt")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .is_err());
    assert!(f.authority.snapshot(&f.lease).await.is_err());
    let _: () = redis::cmd("DEL")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .is_err());
    let exists: bool = redis::cmd("EXISTS")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(!exists);
}

#[tokio::test]
async fn queued_lifetime_mutation_cannot_execute_after_fence_loss_cancel_or_purge() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let operation = Uuid::now_v7();
    pending(&f, initial.version, operation, previous, deadline).await;
    // A queued Redis command must refuse independently of whether PostgreSQL
    // can still be reached. Redis itself cannot read the changed fence/state.
    sqlx::query("UPDATE crawl_sessions SET lease_expires_at=clock_timestamp()-interval '1 second'")
        .execute(f.pg.pool())
        .await
        .unwrap();
    for stopped in ["cancel", "purge"] {
        sqlx::query("UPDATE crawl_runs SET cancel_requested_at=CASE WHEN $1='cancel' THEN clock_timestamp() END,purge_requested_at=CASE WHEN $1='purge' THEN clock_timestamp() END")
            .bind(stopped).execute(f.pg.pool()).await.unwrap();
        assert_eq!(
            remote_renew(&mut f, initial.version, operation, previous, deadline).await,
            vec!["denied".to_string()],
        );
        let remote: i64 = redis::cmd("PEXPIRETIME")
            .arg(&f.key)
            .query_async(&mut f.redis)
            .await
            .unwrap();
        assert_eq!(remote, previous.timestamp_millis() - 2000);
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, operation, deadline)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn renewal_denies_stale_lease_nonpositive_extension_and_run_ceiling() {
    let Some(f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let exact = Timestamp::from_timestamp_millis(previous.timestamp_millis()).unwrap();
    for deadline in [exact, exact - TimeDelta::seconds(1), target(previous, 86401)] {
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .is_err());
    }
    let deadline = target(previous, 60);
    sqlx::query("UPDATE crawl_runs SET expires_at=$1")
        .bind(target(previous, 30))
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
        .await
        .is_err());
    sqlx::query("UPDATE crawl_runs SET expires_at=NULL")
        .execute(f.pg.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE crawl_sessions SET lease_expires_at=clock_timestamp()-interval '1 second'")
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
        .await
        .is_err());
    assert_eq!(expiry(&f).await, previous);
}

#[tokio::test]
async fn renewal_obeys_authorization_deadline_revocation_cancel_and_purge() {
    let Some(f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let key = Uuid::now_v7();
    sqlx::query("INSERT INTO api_keys(key_id,tenant_id,prefix,key_hash,scopes) VALUES($1,$2,$3,$4,ARRAY['crawl:write'])")
        .bind(key).bind(f.lease.tenant.0).bind(format!("renewal-{key}")).bind([9u8; 32].as_slice())
        .execute(f.pg.pool()).await.unwrap();
    let authorization = Uuid::now_v7();
    sqlx::query("INSERT INTO authorization_records(record_id,tenant_id,body,body_digest,valid_from,valid_to,created_by) VALUES($1,$2,'{}'::jsonb,$3,clock_timestamp()-interval '1 hour',$4,$5)")
        .bind(authorization).bind(f.lease.tenant.0).bind([5u8; 32].as_slice())
        .bind(target(previous, 30)).bind(key).execute(f.pg.pool()).await.unwrap();
    sqlx::query("UPDATE crawl_runs SET authorization_record_id=$1")
        .bind(authorization)
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
        .await
        .is_err());
    let allowed = target(previous, 10);
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), allowed)
        .await
        .is_err());
    sqlx::query("UPDATE authorization_records SET revoked_at=clock_timestamp()")
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(allowed, 1))
        .await
        .is_err());
    sqlx::query("UPDATE crawl_runs SET authorization_record_id=NULL,cancel_requested_at=clock_timestamp()")
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(allowed, 1))
        .await
        .is_err());
    sqlx::query("UPDATE crawl_runs SET cancel_requested_at=NULL,purge_requested_at=clock_timestamp()")
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(allowed, 1))
        .await
        .is_err());
}

#[tokio::test]
async fn pending_renewal_blocks_real_publication_reads_and_terminal_finalization() {
    let Some(f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let id = crawlx_core::ArtifactId::new();
    let artifact = crawlx_storage::ArtifactRow {
        id,
        tenant: f.lease.tenant,
        run: f.lease.run,
        kind: "html".into(),
        bucket: "encrypted-renewal".into(),
        object_key: encrypted_object_key(f.lease.tenant, f.lease.run, id, ciphertext().digest),
        size_bytes: 128,
        digest: crawlx_core::hash::Digest::of("crawlx/artifact/v1", &[7; 128]),
        content_type: "text/html".into(),
        sensitivity: crawlx_core::repo::Sensitivity::Content,
        created_at: f.pg.now().await.unwrap(),
        expires_at: None,
    };
    let envelope = crawlx_storage::custody::ArtifactKeyEnvelope::new(
        artifact.tenant,
        artifact.run,
        artifact.id,
        "renewal-test-kms-key".into(),
        vec![7; 256],
    )
    .unwrap();
    f.authority
        .publish(&f.lease, initial.version, &artifact, &ciphertext(), &envelope)
        .await
        .unwrap();
    f.authority
        .read_state(artifact.tenant, artifact.run, artifact.id)
        .await
        .unwrap();
    let previous = expiry(&f).await;
    pending(
        &f,
        initial.version,
        Uuid::now_v7(),
        previous,
        target(previous, 60),
    )
    .await;
    assert!(f
        .authority
        .publish(&f.lease, initial.version, &artifact, &ciphertext(), &envelope)
        .await
        .is_err());
    assert!(f
        .authority
        .read_state(artifact.tenant, artifact.run, artifact.id)
        .await
        .is_err());
    f.pg.set_status(
        f.lease.run,
        RunStatus::Completed,
        Some(crawlx_core::counters::TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    assert!(f.authority.finalize(initial.version).await.is_err());
}

#[tokio::test]
async fn surviving_key_without_exact_renewal_proof_cannot_recover_after_old_deadline() {
    let Some(mut f) = fixture(Duration::from_secs(5)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let operation = Uuid::now_v7();
    pending(&f, initial.version, operation, previous, deadline).await;
    // Adversarial surviving backend: a long TTL alone is not renewal proof.
    let _: bool = redis::cmd("PEXPIREAT")
        .arg(&f.key)
        .arg(deadline.timestamp_millis() - 2000)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    let wait = (previous - f.pg.now().await.unwrap())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(wait + Duration::from_millis(25)).await;
    let exists: bool = redis::cmd("EXISTS")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(exists);
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .is_err());
    assert_eq!(expiry(&f).await, previous);
}

#[tokio::test]
async fn changed_secret_set_never_receives_requested_renewal() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let registered = f
        .authority
        .register(
            &f.lease,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("first-secret".into()),
        )
        .await
        .unwrap();
    let previous = expiry(&f).await;
    let deadline = target(previous, 60);
    let operation = Uuid::now_v7();
    pending(&f, registered.version, operation, previous, deadline).await;
    // Same lengths pass structural validation, but not the complete commitment.
    let _: i64 = redis::cmd("HSET")
        .arg(&f.key)
        .arg("s1")
        .arg("other-secret")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, registered.version, operation, deadline)
        .await
        .is_err());
    let remote: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(remote, previous.timestamp_millis() - 2000);
    let metadata: bool = redis::cmd("HEXISTS")
        .arg(&f.key)
        .arg("renewal_operation")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(!metadata);
}

#[tokio::test]
async fn renewal_rejects_requests_larger_than_the_configured_use_window() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    sqlx::query("UPDATE crawl_runs SET created_at=clock_timestamp()-interval '1 hour',deadline_at=clock_timestamp()+interval '25 hours',expires_at=clock_timestamp()+interval '3 days' WHERE run_id=$1")
        .bind(f.lease.run.0).execute(f.pg.pool()).await.unwrap();
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let now = f.pg.now().await.unwrap();
    let deadline = target(now, 24 * 60 * 60);
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
        .await
        .is_err());
    let created: Timestamp = sqlx::query_scalar("SELECT created_at FROM crawl_runs WHERE run_id=$1")
        .bind(f.lease.run.0)
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert!(deadline > created + TimeDelta::hours(24));
    let physical: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(physical < deadline.timestamp_millis() - 2000);
    let barrier: Option<Uuid> =
        sqlx::query_scalar("SELECT pending_renewal_operation FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert!(barrier.is_none());
}

#[tokio::test]
async fn overlong_absolute_window_is_rejected_before_pending_barrier() {
    let Some(f) = fixture(crawlx_storage::custody::MAX_AUTHORITY_TTL).await else {
        return;
    };
    sqlx::query("UPDATE crawl_runs SET deadline_at=clock_timestamp()+interval '3 days',expires_at=clock_timestamp()+interval '3 days' WHERE run_id=$1")
        .bind(f.lease.run.0).execute(f.pg.pool()).await.unwrap();
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let previous = expiry(&f).await;
    let too_far = target(previous, 60 * 60);
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), too_far)
        .await
        .is_err());
    let pending: Option<Uuid> =
        sqlx::query_scalar("SELECT pending_renewal_operation FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert!(pending.is_none());
    assert_eq!(expiry(&f).await, previous);
}

async fn physical_expiry(f: &mut Fixture) -> i64 {
    redis::cmd("PEXPIRETIME")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap()
}

#[tokio::test]
async fn durable_renewal_commits_once_and_never_changes_redis_retention() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let ceiling: Timestamp = sqlx::query_scalar("SELECT retention_ceiling FROM run_secret_authority")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    let physical = physical_expiry(&mut f).await;
    assert_eq!(physical, ceiling.timestamp_millis() - 2000);
    let now = f.pg.now().await.unwrap();
    // Enter a shorter remaining use window without changing its original policy.
    sqlx::query("UPDATE run_secret_authority SET expires_at=$1")
        .bind(target(now, 10))
        .execute(f.pg.pool())
        .await
        .unwrap();
    let deadline = target(now, 50);
    let operation = Uuid::now_v7();
    let renewed = f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .unwrap();
    assert_eq!(renewed.version, initial.version);
    assert_eq!(expiry(&f).await, deadline);
    assert_eq!(physical_expiry(&mut f).await, physical);
    // Recover the durable receipt through a fresh authority, as after process loss.
    let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").unwrap();
    let recovered_authority = PgSecretAuthority::open(f.pg.clone(), &redis_url, Duration::from_secs(3600))
        .await
        .unwrap();
    recovered_authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .unwrap();
    assert!(recovered_authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(now, 120))
        .await
        .is_err());
    let registered = f
        .authority
        .register(
            &f.lease,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("renewed-registry-value".into()),
        )
        .await
        .unwrap();
    let recovered = f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .unwrap();
    assert_eq!(recovered.version, registered.version);
    assert_eq!(physical_expiry(&mut f).await, physical);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM run_secret_authority_renewals")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(receipts, 1);
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, operation, target(deadline, 1))
        .await
        .is_err());
    assert_eq!(expiry(&f).await, deadline);
}

#[tokio::test]
async fn frozen_ceiling_never_grows_after_run_policy_is_relaxed() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let now = f.pg.now().await.unwrap();
    sqlx::query("UPDATE crawl_runs SET expires_at=$1,deadline_at=$1")
        .bind(target(now, 45))
        .execute(f.pg.pool())
        .await
        .unwrap();
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let original: Timestamp = sqlx::query_scalar("SELECT retention_ceiling FROM run_secret_authority")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE crawl_runs SET expires_at=$1,deadline_at=$1")
        .bind(target(now, 3600))
        .execute(f.pg.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE run_secret_authority SET expires_at=$1")
        .bind(target(now, 10))
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(original, 1))
        .await
        .is_err());
    f.authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), original)
        .await
        .unwrap();
    assert_eq!(physical_expiry(&mut f).await, original.timestamp_millis() - 2000);
}

#[tokio::test]
async fn expired_use_authority_never_resurrects_even_with_surviving_redis_values() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let now = f.pg.now().await.unwrap();
    let physical = physical_expiry(&mut f).await;
    sqlx::query("UPDATE run_secret_authority SET expires_at=$1")
        .bind(target(now, -1))
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(now, 30))
        .await
        .is_err());
    assert!(f.authority.initialize(&f.lease).await.is_err());
    assert!(f.authority.snapshot(&f.lease).await.is_err());
    assert_eq!(physical_expiry(&mut f).await, physical);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM run_secret_authority_renewals")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(receipts, 0);
}

#[tokio::test]
async fn renewal_registration_race_requires_current_epoch_without_losing_retry_identity() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let now = f.pg.now().await.unwrap();
    sqlx::query("UPDATE run_secret_authority SET expires_at=$1")
        .bind(target(now, 10))
        .execute(f.pg.pool())
        .await
        .unwrap();
    let registered = f
        .authority
        .register(
            &f.lease,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("registration-race-value".into()),
        )
        .await
        .unwrap();
    let deadline = target(now, 50);
    let operation = Uuid::now_v7();
    let error = f
        .authority
        .renew_authority(&f.lease, initial.version, operation, deadline)
        .await
        .unwrap_err();
    assert!(crawlx_storage::is_stale_epoch(&error));
    let renewed = f
        .authority
        .renew_authority(&f.lease, registered.version, Uuid::now_v7(), deadline)
        .await
        .unwrap();
    assert_eq!(renewed.version, registered.version);
    let physical = physical_expiry(&mut f).await;
    sqlx::query("UPDATE crawl_sessions SET fencing_token=fencing_token+1")
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        f.authority
            .renew_authority(&f.lease, registered.version, Uuid::now_v7(), target(deadline, 1))
            .await,
        Err(crawlx_core::StoreError::LeaseLost)
    ));
    assert_eq!(physical_expiry(&mut f).await, physical);
}

#[tokio::test]
async fn lost_redis_registry_never_rebuilds_during_a_durable_renewal() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let now = f.pg.now().await.unwrap();
    sqlx::query("UPDATE run_secret_authority SET expires_at=$1")
        .bind(target(now, 10))
        .execute(f.pg.pool())
        .await
        .unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f
        .authority
        .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(now, 50))
        .await
        .is_err());
    let exists: bool = redis::cmd("EXISTS")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(!exists);
    assert_eq!(expiry(&f).await, target(now, 10));
}

#[tokio::test]
async fn paused_redis_response_cannot_renew_a_cancelled_producer_or_change_physical_expiry() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let now = f.pg.now().await.unwrap();
    let previous = target(now, 10);
    sqlx::query("UPDATE run_secret_authority SET expires_at=$1")
        .bind(previous)
        .execute(f.pg.pool())
        .await
        .unwrap();
    let physical = physical_expiry(&mut f).await;
    let source = url::Url::parse(&std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").unwrap()).unwrap();
    let host = source.host_str().unwrap().to_owned();
    let port = source.port().unwrap_or(6379);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut endpoint = source;
    endpoint.set_host(Some("127.0.0.1")).unwrap();
    endpoint.set_port(Some(address.port())).unwrap();
    let armed = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let proxy = {
        let armed = Arc::clone(&armed);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .unwrap();
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            let requests = tokio::io::copy(&mut client_read, &mut server_write);
            let responses = async {
                let mut buffer = [0u8; 8192];
                loop {
                    let count = server_read.read(&mut buffer).await?;
                    if count == 0 {
                        return Ok::<(), std::io::Error>(());
                    }
                    if armed.swap(false, Ordering::SeqCst) {
                        entered.add_permits(1);
                        release.acquire().await.unwrap().forget();
                    }
                    client_write.write_all(&buffer[..count]).await?;
                }
            };
            let _ = tokio::try_join!(requests, responses);
        })
    };
    let authority = PgSecretAuthority::open(f.pg.clone(), endpoint.as_str(), Duration::from_secs(60))
        .await
        .unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    let lease = f.lease.clone().with_cancellation(token.clone());
    armed.store(true, Ordering::SeqCst);
    let renewal = tokio::spawn(async move {
        authority
            .renew_authority(&lease, initial.version, Uuid::now_v7(), target(now, 50))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    token.cancel();
    release.add_permits(1);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), renewal)
            .await
            .unwrap()
            .unwrap(),
        Err(crawlx_core::StoreError::LeaseLost)
    ));
    assert_eq!(expiry(&f).await, previous);
    assert_eq!(physical_expiry(&mut f).await, physical);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM run_secret_authority_renewals")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(receipts, 0);
    proxy.abort();
    let _ = proxy.await;
}

#[tokio::test]
async fn original_retention_above_one_day_requires_both_explicit_permissions_and_operator_ceiling() {
    for (explicit_retention, explicit_authorization, maximum_hours, expected_hours) in [
        (false, false, 72, 24),
        (true, false, 72, 24),
        (false, true, 72, 24),
        (true, true, 72, 72),
        (true, true, 30, 30),
    ] {
        let Some(mut f) = fixture(Duration::from_secs(60)).await else {
            return;
        };
        let before = f.pg.now().await.unwrap();
        let permission = before + TimeDelta::hours(96);
        sqlx::query("UPDATE crawl_runs SET expires_at=$1,deadline_at=NULL")
            .bind(explicit_retention.then_some(permission))
            .execute(f.pg.pool())
            .await
            .unwrap();
        if explicit_authorization {
            let key = Uuid::now_v7();
            sqlx::query("INSERT INTO api_keys(key_id,tenant_id,prefix,key_hash,scopes) VALUES($1,$2,$3,$4,ARRAY['crawl:write'])")
                .bind(key).bind(f.lease.tenant.0).bind(format!("window-{key}")).bind([9u8; 32].as_slice())
                .execute(f.pg.pool()).await.unwrap();
            let authorization = Uuid::now_v7();
            sqlx::query("INSERT INTO authorization_records(record_id,tenant_id,body,body_digest,valid_from,valid_to,created_by) VALUES($1,$2,'{}'::jsonb,$3,$4,$5,$6)")
                .bind(authorization).bind(f.lease.tenant.0).bind([5u8; 32].as_slice())
                .bind(before-TimeDelta::hours(1)).bind(permission).bind(key)
                .execute(f.pg.pool()).await.unwrap();
            sqlx::query("UPDATE crawl_runs SET authorization_record_id=$1")
                .bind(authorization)
                .execute(f.pg.pool())
                .await
                .unwrap();
        }
        let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").unwrap();
        let authority = PgSecretAuthority::open_with_policy(
            f.pg.clone(),
            &redis_url,
            Duration::from_secs(60),
            Duration::from_secs(maximum_hours * 3600),
        )
        .await
        .unwrap();
        authority.initialize(&f.lease).await.unwrap();
        let after = f.pg.now().await.unwrap();
        let ceiling: Timestamp = sqlx::query_scalar("SELECT retention_ceiling FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
        let earliest = target(before + TimeDelta::hours(expected_hours), 0);
        assert!(ceiling >= earliest);
        assert!(ceiling <= after + TimeDelta::hours(expected_hours));
        assert_eq!(physical_expiry(&mut f).await, ceiling.timestamp_millis() - 2000);
    }
}

#[tokio::test]
async fn terminal_retained_projector_uses_only_surviving_original_secret_values() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let secret = SecretOr::secret(format!("retained-projector-{}", Uuid::now_v7()));
    let current = f
        .authority
        .register(&f.lease, initial.version, Uuid::now_v7(), &secret)
        .await
        .unwrap();
    assert!(f
        .authority
        .retained_snapshot(f.lease.tenant, f.lease.run, initial.version)
        .await
        .is_err());
    f.pg.set_status(
        f.lease.run,
        RunStatus::Completed,
        Some(crawlx_core::counters::TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    f.authority.finalize(current.version).await.unwrap();
    let snapshot = f
        .authority
        .retained_snapshot(f.lease.tenant, f.lease.run, current.version)
        .await
        .unwrap();
    assert_eq!(snapshot.version, current.version);
    assert!(snapshot
        .secrets
        .contains_bytes(secret.expose().as_bytes())
        .unwrap());
    let physical = physical_expiry(&mut f).await;
    assert!(f
        .authority
        .retained_snapshot(TenantId::new(), f.lease.run, current.version)
        .await
        .is_err());
    assert_eq!(physical_expiry(&mut f).await, physical);
    let _: i64 = redis::cmd("DEL")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f
        .authority
        .retained_snapshot(f.lease.tenant, f.lease.run, current.version)
        .await
        .is_err());
    let exists: bool = redis::cmd("EXISTS")
        .arg(&f.key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(!exists);
}

#[tokio::test]
async fn retained_source_projector_refuses_zdr_even_with_live_secret_values() {
    let Some(f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let mut metadata = f.pg.get_metadata(f.lease.run).await.unwrap();
    metadata.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    metadata.retention.days = 0;
    sqlx::query("UPDATE crawl_runs SET retention_mode='zdr',retention_days=0,config=jsonb_build_object('privacy','zdr','metadata',$2::jsonb) WHERE run_id=$1")
        .bind(f.lease.run.0)
        .bind(serde_json::to_value(metadata).unwrap())
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f
        .authority
        .retained_snapshot(f.lease.tenant, f.lease.run, initial.version)
        .await
        .is_err());
}

#[tokio::test]
async fn competing_live_renewals_request_refresh_instead_of_failing_valid_producer_work() {
    let Some(mut f) = fixture(Duration::from_secs(60)).await else {
        return;
    };
    let initial = f.authority.initialize(&f.lease).await.unwrap();
    let now = f.pg.now().await.unwrap();
    sqlx::query("UPDATE run_secret_authority SET expires_at=$1")
        .bind(target(now, 10))
        .execute(f.pg.pool())
        .await
        .unwrap();
    let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").unwrap();
    let peer = PgSecretAuthority::open(f.pg.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let deadline = target(now, 50);
    let physical = physical_expiry(&mut f).await;
    let (first, second) = tokio::join!(
        f.authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline),
        peer.renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let refused = first.err().or_else(|| second.err()).unwrap();
    assert!(crawlx_storage::is_stale_epoch(&refused));
    assert_eq!(expiry(&f).await, deadline);
    assert_eq!(physical_expiry(&mut f).await, physical);
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM run_secret_authority_renewals")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(receipts, 1);
}
