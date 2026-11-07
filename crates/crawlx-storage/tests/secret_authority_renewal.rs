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
async fn authorized_soak_renewal_stays_unavailable_without_atomic_revocation() {
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
