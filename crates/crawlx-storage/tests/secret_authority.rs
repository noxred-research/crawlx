//! Real PostgreSQL/volatile Redis custody regressions. Both backend URLs are required.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::custody::{ArtifactReadState, CustodyLease, RunSecretAuthority, SecretEpoch};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{RunRepo, Sensitivity, SessionStatus};
use crawlx_core::{ArtifactId, SecretOr, TenantId, WorkerId};
use crawlx_storage::custody::{
    encrypted_object_key, ArtifactKeyEnvelope, CiphertextIdentity, PgSecretAuthority,
    CIPHERTEXT_DIGEST_DOMAIN,
};
use crawlx_storage::leases::{LeaseRepo, SessionLease};
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{ArtifactRow, Pg, PgConfig};
use std::time::Duration;
use uuid::Uuid;

struct Fixture {
    pg: Pg,
    peer: Pg,
    first: PgSecretAuthority,
    second: PgSecretAuthority,
    lease: CustodyLease,
    other: CustodyLease,
    session: SessionLease,
    redis: redis::aio::MultiplexedConnection,
    redis_key: String,
}

async fn fixture() -> Option<Fixture> {
    let database = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    // Must point at a dedicated no-RDB/AOF/no-replica/noeviction Redis instance.
    let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").ok()?;
    let config = PgConfig {
        schema: Some(format!("custody_{}", Uuid::now_v7().simple())),
        ..PgConfig::default()
    };
    let pg = Pg::connect(&database, config.clone()).await.unwrap();
    pg.migrate().await.unwrap();
    let peer = Pg::connect(&database, config).await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "secret-authority-regression")
        .await
        .unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 2));
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 2)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let session = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let second_session = peer
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
    let other = CustodyLease::new(
        tenant,
        run.id,
        second_session.session.id,
        second_session.worker,
        second_session.fencing_token,
    );
    let first = PgSecretAuthority::open(pg.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let second = PgSecretAuthority::open(peer.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let redis = redis::Client::open(redis_url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    Some(Fixture {
        pg,
        peer,
        first,
        second,
        lease,
        other,
        session,
        redis,
        redis_key: format!("crawlx:secrets:{{{}:{}}}", tenant, run.id),
    })
}

async fn artifact(f: &Fixture) -> ArtifactRow {
    let id = ArtifactId::new();
    ArtifactRow {
        id,
        tenant: f.lease.tenant,
        run: f.lease.run,
        kind: "html".into(),
        bucket: "encrypted-artifacts".into(),
        object_key: encrypted_object_key(f.lease.tenant, f.lease.run, id, ciphertext().digest),
        size_bytes: 128,
        digest: Digest::of("crawlx/artifact/v1", &[7; 128]),
        content_type: "text/html".into(),
        sensitivity: Sensitivity::Content,
        created_at: f.pg.now().await.unwrap(),
        expires_at: None,
    }
}

fn envelope(row: &ArtifactRow) -> ArtifactKeyEnvelope {
    ArtifactKeyEnvelope::new(
        row.tenant,
        row.run,
        row.id,
        "arn:aws:kms:us-east-1:111122223333:key/custody-regression".into(),
        vec![7; 256],
    )
    .unwrap()
}

fn ciphertext() -> CiphertextIdentity {
    CiphertextIdentity::new(Digest::of(CIPHERTEXT_DIGEST_DOMAIN, &[7; 196]), 196).unwrap()
}

fn exact_value_commitment(salt: &str, version: SecretEpoch, operation: Uuid, value: &str) -> [u8; 32] {
    let key = blake3::derive_key("crawlx/registration-value-key/v1", salt.as_bytes());
    let mut hash = blake3::Hasher::new_keyed(&key);
    hash.update(version.tenant.0.as_bytes());
    hash.update(version.run.0.as_bytes());
    hash.update(version.incarnation.as_bytes());
    hash.update(operation.as_bytes());
    hash.update(&version.epoch.to_be_bytes());
    hash.update(&u64::try_from(value.len()).unwrap().to_be_bytes());
    hash.update(value.as_bytes());
    *hash.finalize().as_bytes()
}

#[tokio::test]
async fn independent_backends_share_all_secret_categories_and_atomic_publication_epoch() {
    let Some(f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let registered = f
        .second
        .register(
            &f.other,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("request-password-canary-591".into()),
        )
        .await
        .unwrap();
    let shared = f.first.snapshot(&f.lease).await.unwrap();
    assert_eq!(registered.version, shared.version);
    assert!(shared
        .secrets
        .contains_bytes(b"request-password-canary-591")
        .unwrap());
    let row = artifact(&f).await;
    let key = envelope(&row);
    assert!(f
        .first
        .publish(&f.lease, initial.version, &row, &ciphertext(), &key)
        .await
        .is_err());
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(before, 0);
    f.first
        .publish(&f.lease, shared.version, &row, &ciphertext(), &key)
        .await
        .unwrap();
    f.second
        .publish(&f.other, shared.version, &row, &ciphertext(), &key)
        .await
        .unwrap();
    let pair: (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM artifacts),(SELECT count(*) FROM artifact_key_custody)")
            .fetch_one(f.peer.pool())
            .await
            .unwrap();
    assert_eq!(pair, (1, 1));
    let custody = f.second.read_custody(row.tenant, row.run, row.id).await.unwrap();
    assert_eq!(custody.envelope, key);
    assert_eq!(custody.ciphertext, ciphertext());
    let durable: String = sqlx::query_scalar("SELECT row_to_json(a)::text FROM run_secret_authority a")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert!(!durable.contains("request-password-canary-591"));
    let mut secret_metadata = artifact(&f).await;
    secret_metadata.content_type = "application/request-password-canary-591".into();
    assert!(f
        .first
        .publish(
            &f.lease,
            shared.version,
            &secret_metadata,
            &ciphertext(),
            &envelope(&secret_metadata)
        )
        .await
        .is_err());
}

#[tokio::test]
async fn lost_registration_reply_blocks_publication_and_recovers_only_same_operation_and_value() {
    let Some(f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let previous: Vec<u8> = sqlx::query_scalar("SELECT commitment FROM run_secret_authority")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    let operation = Uuid::now_v7();
    let value = SecretOr::secret("solver-token-after-remote-write-591".into());
    let next = f
        .first
        .register(&f.lease, initial.version, operation, &value)
        .await
        .unwrap();
    let committed: Vec<u8> = sqlx::query_scalar("SELECT commitment FROM run_secret_authority")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    // Recreate the exact crash boundary: Redis mutation succeeded, but its caller
    // never finalized the pending PostgreSQL operation. No mock backend is involved.
    sqlx::query("UPDATE run_secret_authority SET epoch=$1,commitment=$2,pending_operation=$3,pending_commitment=$4,last_operation=$5,pending_value_commitment=last_value_commitment,last_value_commitment=NULL")
        .bind(initial.version.epoch).bind(previous).bind(operation).bind(committed).bind(initial.version.incarnation)
        .execute(f.pg.pool()).await.unwrap();
    assert!(f.second.snapshot(&f.other).await.is_err());
    let row = artifact(&f).await;
    assert!(f
        .second
        .publish(&f.other, next.version, &row, &ciphertext(), &envelope(&row))
        .await
        .is_err());
    assert!(f
        .second
        .register(&f.other, initial.version, Uuid::now_v7(), &value)
        .await
        .is_err());
    assert!(f
        .second
        .register(
            &f.other,
            initial.version,
            operation,
            &SecretOr::secret("changed-value".into())
        )
        .await
        .is_err());
    let recovered = f
        .second
        .register(&f.other, initial.version, operation, &value)
        .await
        .unwrap();
    assert_eq!(recovered.version, next.version);
    let replay = f
        .first
        .register(&f.lease, initial.version, operation, &value)
        .await
        .unwrap();
    assert_eq!(replay.version, next.version);
    f.second
        .publish(&f.other, recovered.version, &row, &ciphertext(), &envelope(&row))
        .await
        .unwrap();
}

#[tokio::test]
async fn same_length_corruption_loss_tenant_mismatch_and_dead_fences_never_become_empty_success() {
    let Some(mut f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let known = f
        .first
        .register(
            &f.lease,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("secret-value-a".into()),
        )
        .await
        .unwrap();
    let mut wrong = f.other.clone();
    wrong.tenant = TenantId::new();
    assert!(f.second.snapshot(&wrong).await.is_err());
    f.pg.release(&f.session, SessionStatus::Recovering).await.unwrap();
    assert!(f.first.snapshot(&f.lease).await.is_err());
    let _: i64 = redis::cmd("HSET")
        .arg(&f.redis_key)
        .arg("s1")
        .arg("secret-value-b")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f.second.snapshot(&f.other).await.is_err());
    assert!(f
        .second
        .register(
            &f.other,
            known.version,
            Uuid::now_v7(),
            &SecretOr::secret("next-secret".into())
        )
        .await
        .is_err());
    let _: i64 = redis::cmd("DEL")
        .arg(&f.redis_key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(
        f.second.initialize(&f.other).await.is_err(),
        "volatile loss cannot resurrect empty state"
    );
    let row = artifact(&f).await;
    assert!(f
        .second
        .publish(&f.other, known.version, &row, &ciphertext(), &envelope(&row))
        .await
        .is_err());
}

#[tokio::test]
async fn native_expiry_never_refreshes_and_registration_is_bounded() {
    let Some(mut f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let before: i64 = redis::cmd("PTTL")
        .arg(&f.redis_key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f
        .first
        .register(
            &f.lease,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("x".repeat(16385))
        )
        .await
        .is_err());
    let registered = f
        .second
        .register(
            &f.other,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("bounded-secret".into()),
        )
        .await
        .unwrap();
    let after: i64 = redis::cmd("PTTL")
        .arg(&f.redis_key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(
        after > 0 && after <= before,
        "registration never extends native expiry"
    );
    let _: i64 = redis::cmd("PEXPIRE")
        .arg(&f.redis_key)
        .arg(0)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(f.first.snapshot(&f.lease).await.is_err());
    assert!(f
        .first
        .register(
            &f.lease,
            registered.version,
            Uuid::now_v7(),
            &SecretOr::secret("late-value".into())
        )
        .await
        .is_err());
}

#[tokio::test]
async fn finalized_ciphertext_keeps_durable_read_custody_without_redis_and_blocks_catalog_growth() {
    let Some(mut f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let row = artifact(&f).await;
    let key = envelope(&row);
    f.first
        .publish(&f.lease, initial.version, &row, &ciphertext(), &key)
        .await
        .unwrap();
    assert!(
        f.first.finalize(initial.version).await.is_err(),
        "running runs cannot seal"
    );
    let next = f
        .second
        .register(
            &f.other,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("final-epoch-token-591".into()),
        )
        .await
        .unwrap();
    assert!(matches!(
        f.first.read_state(row.tenant, row.run, row.id).await.unwrap(),
        ArtifactReadState::Live(_)
    ));
    // A real content caller must fully rescan before renewing this exact immutable
    // object's validation epoch. This authority test exercises only the catalog.
    f.first
        .publish(&f.lease, next.version, &row, &ciphertext(), &key)
        .await
        .unwrap();
    f.pg.set_status(
        f.lease.run,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    f.second.finalize(next.version).await.unwrap();
    f.first.finalize(next.version).await.unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(&f.redis_key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    let durable = PgSecretAuthority::finalized_reads(f.peer.clone());
    assert!(
        matches!(durable.read_state(row.tenant, row.run, row.id).await.unwrap(), ArtifactReadState::Finalized(epoch) if epoch == next.version)
    );
    assert_eq!(
        durable
            .read_custody(row.tenant, row.run, row.id)
            .await
            .unwrap()
            .envelope,
        key
    );
    let another = artifact(&f).await;
    assert!(crawlx_storage::ArtifactIndex::record(&f.pg, &another)
        .await
        .is_err());
    assert!(
        sqlx::query("UPDATE artifacts SET object_key='changed-after-seal' WHERE artifact_id=$1")
            .bind(row.id.0)
            .execute(f.pg.pool())
            .await
            .is_err()
    );
    assert!(f
        .first
        .register(
            &f.lease,
            next.version,
            Uuid::now_v7(),
            &SecretOr::secret("late-secret".into())
        )
        .await
        .is_err());
}

#[tokio::test]
async fn finalization_refuses_a_historical_artifact_secret_epoch() {
    let Some(f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let row = artifact(&f).await;
    f.first
        .publish(&f.lease, initial.version, &row, &ciphertext(), &envelope(&row))
        .await
        .unwrap();
    let next = f
        .second
        .register(
            &f.other,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("unscanned-final-secret-591".into()),
        )
        .await
        .unwrap();
    f.pg.set_status(
        f.lease.run,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    assert!(f.first.finalize(next.version).await.is_err());
    assert!(PgSecretAuthority::finalized_reads(f.peer.clone())
        .read_state(row.tenant, row.run, row.id)
        .await
        .is_err());
    let sealed: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT sealed_at FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert!(sealed.is_none());
}

#[tokio::test]
async fn concurrent_workers_cannot_register_two_values_from_one_epoch() {
    let Some(f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let left = SecretOr::secret("worker-left-credential-591".into());
    let right = SecretOr::secret("worker-right-credential-591".into());
    let (left_result, right_result) = tokio::join!(
        f.first.register(&f.lease, initial.version, Uuid::now_v7(), &left),
        f.second
            .register(&f.other, initial.version, Uuid::now_v7(), &right),
    );
    assert_ne!(left_result.is_ok(), right_result.is_ok());
    let shared = f.first.snapshot(&f.lease).await.unwrap();
    assert_eq!(shared.version.epoch, initial.version.epoch + 1);
    assert_ne!(
        shared.secrets.contains_bytes(left.expose().as_bytes()).unwrap(),
        shared.secrets.contains_bytes(right.expose().as_bytes()).unwrap(),
    );
}

#[tokio::test]
async fn finalization_refuses_missing_custody_even_when_no_new_secret_epoch_exists() {
    let Some(f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let raw = artifact(&f).await;
    crawlx_storage::ArtifactIndex::record(&f.pg, &raw).await.unwrap();
    f.pg.set_status(
        f.lease.run,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    assert!(f.first.finalize(initial.version).await.is_err());
}

#[tokio::test]
async fn changed_retry_before_redis_mutation_cannot_poison_the_original_registration() {
    let Some(mut f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let operation = Uuid::now_v7();
    let original = SecretOr::secret("original-before-redis-write-591".to_owned());
    let salt: String = redis::cmd("HGET")
        .arg(&f.redis_key)
        .arg("salt")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    let mut hasher = blake3::Hasher::new_derive_key("crawlx/run-secret-snapshot/v1");
    hasher.update(salt.as_bytes());
    hasher.update(&u64::try_from(original.expose().len()).unwrap().to_be_bytes());
    hasher.update(original.expose().as_bytes());
    let exact_value = exact_value_commitment(&salt, initial.version, operation, original.expose());
    sqlx::query("UPDATE run_secret_authority SET pending_operation=$1,pending_commitment=$2,pending_value_commitment=$3")
        .bind(operation).bind(hasher.finalize().as_bytes().as_slice()).bind(exact_value.as_slice())
        .execute(f.pg.pool()).await.unwrap();
    assert!(f
        .second
        .register(
            &f.other,
            initial.version,
            operation,
            &SecretOr::secret("changed-before-redis-write-591".into())
        )
        .await
        .is_err());
    let redis_epoch: String = redis::cmd("HGET")
        .arg(&f.redis_key)
        .arg("epoch")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(redis_epoch, initial.version.epoch.to_string());
    let absent: Option<String> = redis::cmd("HGET")
        .arg(&f.redis_key)
        .arg("s1")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert!(absent.is_none());
    let recovered = f
        .first
        .register(&f.lease, initial.version, operation, &original)
        .await
        .unwrap();
    assert!(recovered
        .secrets
        .contains_bytes(original.expose().as_bytes())
        .unwrap());
}

#[tokio::test]
async fn native_deadline_is_absolute_and_earlier_than_the_durable_deadline() {
    let Some(mut f) = fixture().await else {
        return;
    };
    f.first.initialize(&f.lease).await.unwrap();
    let deadline: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT expires_at FROM run_secret_authority")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    let native: i64 = redis::cmd("PEXPIRETIME")
        .arg(&f.redis_key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(native, deadline.timestamp_millis() - 2000);
    let late_key = format!("{}:late-init", f.redis_key);
    let incarnation = Uuid::now_v7();
    let expired_deadline = f.pg.now().await.unwrap().timestamp_millis() - 1000;
    let result: Vec<String> = redis::Script::new(include_str!("../src/custody_redis.lua"))
        .key(&late_key)
        .arg("init")
        .arg(incarnation.to_string())
        .arg(0)
        .arg(incarnation.to_string())
        .arg("")
        .arg(expired_deadline)
        .arg(Uuid::now_v7().to_string())
        .invoke_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(result, vec!["denied".to_owned()]);
    let exists: i64 = redis::cmd("EXISTS")
        .arg(&late_key)
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(
        exists, 0,
        "delayed initialization cannot resurrect an expired absolute deadline"
    );
}

#[tokio::test]
async fn legacy_insert_before_initialization_serializes_with_initialization_and_sealing() {
    let Some(f) = fixture().await else {
        return;
    };
    let raw = artifact(&f).await;
    let mut pending = f.pg.pool().begin().await.unwrap();
    sqlx::query("INSERT INTO artifacts(artifact_id,tenant_id,run_id,kind,bucket,object_key,size_bytes,content_digest,content_type,sensitivity,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::sensitivity_class,$11,$12)")
        .bind(raw.id.0).bind(raw.tenant.0).bind(raw.run.0).bind(&raw.kind).bind(&raw.bucket).bind(&raw.object_key)
        .bind(i64::try_from(raw.size_bytes).unwrap()).bind(raw.digest.0.as_slice()).bind(&raw.content_type)
        .bind(raw.sensitivity.as_str()).bind(raw.created_at).bind(raw.expires_at).execute(&mut *pending).await.unwrap();
    let blocked = tokio::time::timeout(Duration::from_millis(100), f.second.initialize(&f.other)).await;
    assert!(
        blocked.is_err(),
        "initialization must wait for a pre-authority catalog insert"
    );
    pending.commit().await.unwrap();
    let initial = f.first.initialize(&f.lease).await.unwrap();
    f.pg.set_status(
        f.lease.run,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    assert!(
        f.first.finalize(initial.version).await.is_err(),
        "the previously invisible raw insert is now included in seal completeness"
    );
}

#[tokio::test]
async fn unresolved_exposure_ledger_denies_registration_and_finalization_without_public_cleanup() {
    let Some(f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let row = artifact(&f).await;
    f.first
        .publish(&f.lease, initial.version, &row, &ciphertext(), &envelope(&row))
        .await
        .unwrap();
    // Real durable crash state. No arbitrary successful task is accepted as proof
    // that a transport's producer and queues have stopped.
    sqlx::query("INSERT INTO run_artifact_exposures(tenant_id,run_id,operation,artifact_id,artifact_binding,incarnation,secret_epoch) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(row.tenant.0).bind(row.run.0).bind(Uuid::now_v7()).bind(row.id.0)
        .bind(row.digest.0.as_slice()).bind(initial.version.incarnation).bind(initial.version.epoch)
        .execute(f.pg.pool()).await.unwrap();
    assert!(f
        .second
        .register(
            &f.other,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("blocked-by-unresolved-output-591".into())
        )
        .await
        .is_err());
    f.pg.set_status(
        f.lease.run,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    assert!(f.second.finalize(initial.version).await.is_err());
    let open: i64 = sqlx::query_scalar("SELECT count(*) FROM run_artifact_exposures WHERE closed_at IS NULL")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(open, 1);
}

#[tokio::test]
async fn static_url_fence_does_not_require_a_browser_session_and_rejects_returned_leases() {
    use crawlx_core::repo::FrontierRepo as _;
    let Some(f) = fixture().await else {
        return;
    };
    sqlx::query("DELETE FROM crawl_sessions WHERE run_id=$1")
        .bind(f.lease.run.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    let url = crawlx_storage::testkit::canonical_url("https://example.test/static");
    f.pg.discover(f.lease.run, &url, 0, None, None).await.unwrap();
    let worker = WorkerId::new();
    let leased = f.pg.lease_batch_fenced(f.lease.run, worker, 1).await.unwrap();
    let (entry, fence) = &leased[0];
    let lease = CustodyLease::for_url(f.lease.tenant, f.lease.run, entry.id, worker, *fence);
    let initial = f.first.initialize(&lease).await.unwrap();
    let next = f
        .first
        .register(
            &lease,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("static-request-header-secret-591".into()),
        )
        .await
        .unwrap();
    let row = artifact(&f).await;
    f.first
        .publish(&lease, next.version, &row, &ciphertext(), &envelope(&row))
        .await
        .unwrap();
    f.pg.give_back(entry.id, *fence).await.unwrap();
    assert!(f.first.snapshot(&lease).await.is_err());
    let later = artifact(&f).await;
    assert!(f
        .first
        .publish(&lease, next.version, &later, &ciphertext(), &envelope(&later))
        .await
        .is_err());
}

struct TestProducerAuthorization {
    tenant: TenantId,
    run: crawlx_core::CrawlRunId,
    key: Uuid,
    allowed: bool,
}

#[async_trait::async_trait]
impl crawlx_storage::custody::ArtifactProducerAuthorizer for TestProducerAuthorization {
    async fn authorize(
        &self,
        tenant: TenantId,
        run: crawlx_core::CrawlRunId,
    ) -> Result<Uuid, crawlx_core::StoreError> {
        if self.allowed && self.tenant == tenant && self.run == run {
            Ok(self.key)
        } else {
            Err(crawlx_core::StoreError::AccessDenied(
                "test producer denied".into(),
            ))
        }
    }
}

#[tokio::test]
async fn authenticated_api_producer_requires_authorization_and_live_tenant_bound_key() {
    let Some(f) = fixture().await else {
        return;
    };
    sqlx::query("DELETE FROM crawl_sessions WHERE run_id=$1")
        .bind(f.lease.run.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    let key = Uuid::now_v7();
    sqlx::query("INSERT INTO api_keys(key_id,tenant_id,prefix,key_hash,scopes) VALUES($1,$2,$3,$4,ARRAY['crawl:write'])")
        .bind(key).bind(f.lease.tenant.0).bind(format!("custody-test-{key}")).bind([9u8;32].as_slice())
        .execute(f.pg.pool()).await.unwrap();
    let mut authorization = TestProducerAuthorization {
        tenant: f.lease.tenant,
        run: f.lease.run,
        key,
        allowed: false,
    };
    assert!(f
        .first
        .acquire_authenticated_producer(
            &authorization,
            f.lease.tenant,
            f.lease.run,
            Duration::from_secs(30)
        )
        .await
        .is_err());
    authorization.allowed = true;
    assert!(f
        .first
        .acquire_authenticated_producer(&authorization, f.lease.tenant, f.lease.run, Duration::ZERO)
        .await
        .is_err());
    let first = f
        .first
        .acquire_authenticated_producer(
            &authorization,
            f.lease.tenant,
            f.lease.run,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let second = f
        .second
        .acquire_authenticated_producer(
            &authorization,
            f.lease.tenant,
            f.lease.run,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    assert_ne!(first.worker, second.worker);
    assert!(second.fence > first.fence);
    let initial = f.first.initialize(&first).await.unwrap();
    let row = artifact(&f).await;
    f.first
        .publish(&first, initial.version, &row, &ciphertext(), &envelope(&row))
        .await
        .unwrap();
    let mut wrong_owner = first.clone();
    wrong_owner.worker = WorkerId::new();
    assert!(f.first.snapshot(&wrong_owner).await.is_err());
    let mut wrong_fence = first.clone();
    wrong_fence.fence += 1;
    assert!(f.first.snapshot(&wrong_fence).await.is_err());
    assert!(f
        .first
        .release_authenticated_producer(&wrong_fence)
        .await
        .is_err());
    let released = f
        .first
        .acquire_authenticated_producer(
            &authorization,
            f.lease.tenant,
            f.lease.run,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    f.first.release_authenticated_producer(&released).await.unwrap();
    f.first.release_authenticated_producer(&released).await.unwrap();
    assert!(f.first.snapshot(&released).await.is_err());
    sqlx::query("UPDATE run_custody_producers SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND run_id=$2 AND fence=$3")
        .bind(second.tenant.0).bind(second.run.0).bind(second.fence).execute(f.pg.pool()).await.unwrap();
    assert!(f.second.snapshot(&second).await.is_err());
    assert!(f.first.snapshot(&first).await.is_ok());
    sqlx::query("UPDATE api_keys SET revoked_at=clock_timestamp() WHERE key_id=$1")
        .bind(key)
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f.first.snapshot(&first).await.is_err());
    assert!(f
        .first
        .acquire_authenticated_producer(
            &authorization,
            f.lease.tenant,
            f.lease.run,
            Duration::from_secs(30)
        )
        .await
        .is_err());
}

#[tokio::test]
async fn zdr_registry_is_shared_without_creating_durable_content() {
    use crawlx_core::config::RetentionMode;
    use std::sync::Arc;
    let Some(f) = fixture().await else {
        return;
    };
    let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").unwrap();
    let delivery = Arc::new(
        crawlx_storage::DeliveryBuffer::open_redis(
            &redis_url,
            Arc::new(crawlx_core::SystemClock),
            crawlx_storage::BufferLimits::default(),
        )
        .await
        .unwrap(),
    );
    let pg = f.pg.clone().with_delivery_buffer(delivery.clone());
    let mut config = create_crawl("https://example.test/volatile", &["role0"], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let run = crawl_run(f.lease.tenant, config);
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let session = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let lease = CustodyLease::new(
        run.tenant,
        run.id,
        session.session.id,
        session.worker,
        session.fencing_token,
    );
    let authority = PgSecretAuthority::open(pg.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let initial = authority.initialize(&lease).await.unwrap();
    let artifact = delivery
        .insert(
            run.tenant,
            run.id,
            1,
            "markdown",
            "text/plain",
            b"fully validated volatile output",
        )
        .await
        .unwrap();
    let mut wrong = artifact.clone();
    wrong.digest = Digest::of("wrong", b"wrong");
    assert!(delivery
        .content_metadata(run.tenant, run.id, 1, &wrong)
        .await
        .unwrap()
        .is_none());
    assert!(delivery
        .content_metadata(run.tenant, run.id, 2, &artifact)
        .await
        .unwrap()
        .is_none());
    let token = SecretOr::secret("volatile-callback-secret-591".into());
    let next = authority
        .register(&lease, initial.version, Uuid::now_v7(), &token)
        .await
        .unwrap();
    let shared = f.first.snapshot(&lease).await.unwrap();
    assert_eq!(shared.version, next.version);
    assert!(shared.secrets.contains_bytes(token.expose().as_bytes()).unwrap());
    let durable: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE run_id=$1")
        .bind(run.id.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(durable, 0);
}

#[tokio::test]
async fn pending_retry_binds_exact_value_even_when_both_values_are_already_registered() {
    let Some(mut f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let a = SecretOr::secret("already-known-value-a-591".into());
    let b = SecretOr::secret("already-known-value-b-591".into());
    let first = f
        .first
        .register(&f.lease, initial.version, Uuid::now_v7(), &a)
        .await
        .unwrap();
    let current = f
        .first
        .register(&f.lease, first.version, Uuid::now_v7(), &b)
        .await
        .unwrap();
    let salt: String = redis::cmd("HGET")
        .arg(&f.redis_key)
        .arg("salt")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    let operation = Uuid::now_v7();
    let exact = exact_value_commitment(&salt, current.version, operation, a.expose());
    sqlx::query("UPDATE run_secret_authority SET pending_operation=$1,pending_commitment=commitment,pending_value_commitment=$2")
        .bind(operation).bind(exact.as_slice()).execute(f.pg.pool()).await.unwrap();
    assert!(f
        .second
        .register(&f.other, current.version, operation, &b)
        .await
        .is_err());
    let unchanged: String = redis::cmd("HGET")
        .arg(&f.redis_key)
        .arg("epoch")
        .query_async(&mut f.redis)
        .await
        .unwrap();
    assert_eq!(unchanged, current.version.epoch.to_string());
    let recovered = f
        .second
        .register(&f.other, current.version, operation, &a)
        .await
        .unwrap();
    assert_eq!(
        recovered.version.epoch,
        current.version.epoch.checked_add(1).unwrap()
    );
    assert!(recovered.secrets.contains_bytes(a.expose().as_bytes()).unwrap());
    assert!(recovered.secrets.contains_bytes(b.expose().as_bytes()).unwrap());
    assert!(f
        .first
        .register(&f.lease, current.version, operation, &b)
        .await
        .is_err());
    let same = f
        .first
        .register(&f.lease, current.version, operation, &a)
        .await
        .unwrap();
    assert_eq!(same.version, recovered.version);
}

#[tokio::test]
async fn plaintext_catalog_identity_and_ciphertext_fixity_remain_separate_and_immutable() {
    let Some(f) = fixture().await else {
        return;
    };
    let initial = f.first.initialize(&f.lease).await.unwrap();
    let row = artifact(&f).await;
    let encrypted = ciphertext();
    assert_ne!(row.digest, encrypted.digest);
    assert_ne!(row.size_bytes, encrypted.size_bytes);
    let envelope = envelope(&row);
    f.first
        .publish(&f.lease, initial.version, &row, &encrypted, &envelope)
        .await
        .unwrap();
    let stored: (Vec<u8>, i64) =
        sqlx::query_as("SELECT content_digest,size_bytes FROM artifacts WHERE artifact_id=$1")
            .bind(row.id.0)
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert_eq!(
        stored,
        (row.digest.0.to_vec(), i64::try_from(row.size_bytes).unwrap())
    );
    let custody = f.second.read_custody(row.tenant, row.run, row.id).await.unwrap();
    assert_eq!(custody.ciphertext, encrypted);
    assert_eq!(custody.envelope, envelope);
    let changed_ciphertext = CiphertextIdentity::new(
        Digest::of(CIPHERTEXT_DIGEST_DOMAIN, b"changed"),
        encrypted.size_bytes,
    )
    .unwrap();
    let mut changed_attempt = row.clone();
    changed_attempt.object_key = encrypted_object_key(row.tenant, row.run, row.id, changed_ciphertext.digest);
    assert_ne!(changed_attempt.object_key, row.object_key);
    assert!(f
        .second
        .publish(
            &f.other,
            initial.version,
            &changed_attempt,
            &changed_ciphertext,
            &envelope
        )
        .await
        .is_err());
    assert_eq!(
        f.second
            .read_custody(row.tenant, row.run, row.id)
            .await
            .unwrap()
            .ciphertext,
        encrypted
    );
    sqlx::query("UPDATE artifacts SET size_bytes=size_bytes+1 WHERE artifact_id=$1")
        .bind(row.id.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f.second.read_custody(row.tenant, row.run, row.id).await.is_err());
    assert!(f.second.read_state(row.tenant, row.run, row.id).await.is_err());
}

#[tokio::test]
async fn actual_provisioned_api_role_uses_only_owned_producer_sequence() {
    let Some(f) = fixture().await else {
        return;
    };
    let database = std::env::var("CRAWLX_TEST_DATABASE_URL").unwrap();
    let redis_url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL").unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    let role = format!("custody_api_{}", Uuid::now_v7().simple());
    let password = Uuid::now_v7().simple().to_string();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")))
        .execute(f.pg.pool()).await.unwrap();
    // Test-only actor probe proves acquisition actually used the restricted pool.
    sqlx::query(
        "ALTER TABLE run_custody_producers ADD COLUMN database_actor name NOT NULL DEFAULT current_user",
    )
    .execute(f.pg.pool())
    .await
    .unwrap();
    let production = include_str!("../../../docker/provision-api-role.sql");
    let marker = "REVOKE CREATE ON SCHEMA public FROM PUBLIC;";
    let (_, body) = production.split_once(marker).unwrap();
    let actual_provisioning = format!("{marker}{body}")
        .replace("public", &schema)
        .replace("crawlx_api", &role);
    // Execute the actual production grant logic, including its owned-column
    // sequence discovery. Deliberately never grant ALL SEQUENCES.
    sqlx::raw_sql(sqlx::AssertSqlSafe(actual_provisioning))
        .execute(f.pg.pool())
        .await
        .unwrap();
    let mut restricted_url = url::Url::parse(&database).unwrap();
    restricted_url.set_username(&role).unwrap();
    restricted_url.set_password(Some(&password)).unwrap();
    let restricted = Pg::connect_existing(
        restricted_url.as_str(),
        PgConfig {
            schema: Some(schema.clone()),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    let capabilities: (bool,bool) = sqlx::query_as("SELECT has_sequence_privilege(current_user,$1,'USAGE'),has_sequence_privilege(current_user,pg_get_serial_sequence($2,'fence'),'USAGE')")
        .bind(format!("{schema}.lease_fence_seq")).bind(format!("{schema}.run_custody_producers"))
        .fetch_one(restricted.pool()).await.unwrap();
    assert_eq!(capabilities, (false, true));
    let key = Uuid::now_v7();
    sqlx::query("INSERT INTO api_keys(key_id,tenant_id,prefix,key_hash,scopes) VALUES($1,$2,$3,$4,ARRAY['crawl:write'])")
        .bind(key).bind(f.lease.tenant.0).bind(format!("provisioned-{key}")).bind([9u8;32].as_slice())
        .execute(f.pg.pool()).await.unwrap();
    let authorization = TestProducerAuthorization {
        tenant: f.lease.tenant,
        run: f.lease.run,
        key,
        allowed: true,
    };
    let request_pg = f.pg.with_api_role(restricted_url.as_str()).await.unwrap();
    let authority = PgSecretAuthority::open(request_pg, &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let lease = crawlx_storage::tenant::scope(
        f.lease.tenant,
        authority.acquire_authenticated_producer(
            &authorization,
            f.lease.tenant,
            f.lease.run,
            Duration::from_secs(30),
        ),
    )
    .await
    .unwrap();
    let actor: String =
        sqlx::query_scalar("SELECT database_actor::text FROM run_custody_producers WHERE producer_id=$1")
            .bind(match lease.source {
                crawlx_core::custody::CustodySource::AuthenticatedProducer(id) => id,
                _ => panic!("wrong source"),
            })
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert_eq!(actor, role);
    crawlx_storage::tenant::scope(f.lease.tenant, authority.release_authenticated_producer(&lease))
        .await
        .unwrap();
    drop(authority);
    restricted.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role}")))
        .execute(f.pg.pool())
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
        .execute(f.pg.pool())
        .await
        .unwrap();
}
