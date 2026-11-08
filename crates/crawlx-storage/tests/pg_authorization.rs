//! Authorization record lifecycle on PostgreSQL (migration 0019): immutable creation
//! with the policy digest, the body-immutability trigger, idempotent revocation, the lifecycle merge
//! every reader sees, run digest binding and the `authorization_revoked` terminal reason. Each test
//! runs in its own schema on `CRAWLX_TEST_DATABASE_URL`; without that variable every test returns
//! early.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::repo::RunRepo;
use crawlx_core::{AuthorizationRecordId, CrawlRunId, StoreError, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::{AuthorizationRecord, AuthzFailure, OwnershipProof};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{
    ApiKeyRow, AuthorizationInsert, AuthorizationRow, NewAuthorization, Pg, PgApiRepo, PgConfig,
};
use serde_json::{json, Value};
use uuid::Uuid;

struct Env {
    pg: Pg,
    repo: PgApiRepo,
}

async fn setup() -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("t_{}", CrawlRunId::new().0.simple())),
            max_connections: 4,
            ..PgConfig::default()
        },
    )
    .await
    .expect("connect");
    pg.migrate().await.expect("migrate");
    Some(Env {
        repo: PgApiRepo::new(pg.clone()),
        pg,
    })
}

macro_rules! env {
    () => {
        match setup().await {
            Some(e) => e,
            None => {
                eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

/// PostgreSQL keeps microseconds; a test clock that already has only microseconds round-trips.
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
}

impl Env {
    async fn teardown(self) {
        self.pg.drop_schema().await.expect("drop schema");
    }

    /// A tenant with one API key (the creator of its records).
    async fn tenant(&self, name: &str) -> (TenantId, Uuid) {
        let tenant = TenantId::new();
        let key = AuthorizationRecordId::new().0;
        self.repo
            .key_insert(
                &ApiKeyRow {
                    key_id: key,
                    tenant,
                    prefix: format!("pfx{}", key.simple()),
                    hash: [7; 32],
                    scopes: vec!["authorizations:write".to_owned()],
                    expires_at: None,
                    revoked: false,
                },
                name,
            )
            .await
            .expect("key");
        (tenant, key)
    }
}

/// A record of `tenant` with a DNS TXT proof, as the API stores it (no lifecycle state).
fn record(tenant: TenantId) -> AuthorizationRecord {
    let mut r = sample_record(tenant, now(), &["https://app.example.test"]);
    r.ownership = Some(OwnershipProof::DnsTxt {});
    r
}

fn new_row<'a>(
    r: &AuthorizationRecord,
    body: &'a Value,
    digest: &'a Digest,
    by: Uuid,
    verification: &'a Value,
    verified_at: DateTime<Utc>,
) -> NewAuthorization<'a> {
    NewAuthorization {
        tenant: r.tenant,
        id: r.id,
        version: i32::try_from(r.version).unwrap(),
        body,
        body_digest: &digest.0,
        valid_from: r.valid_from,
        valid_to: r.valid_to,
        created_by: by,
        verified_at,
        verification,
    }
}

/// Create `r` verified at `at`; returns the digest stored.
async fn create(env: &Env, r: &AuthorizationRecord, by: Uuid, at: DateTime<Utc>) -> Digest {
    let body = serde_json::to_value(r).unwrap();
    let digest = r.body_digest().unwrap();
    let verification = json!({ "kind": "dns_txt", "checkedAt": at, "hosts": ["app.example.test"] });
    let outcome = env
        .repo
        .authorization_create(&new_row(r, &body, &digest, by, &verification, at))
        .await
        .unwrap();
    assert_eq!(outcome, AuthorizationInsert::Created);
    digest
}

#[tokio::test]
async fn create_round_trips_and_stores_the_policy_digest() {
    let env = env!();
    let (tenant, key) = env.tenant("acme").await;
    let r = record(tenant);
    let at = now();
    let digest = create(&env, &r, key, at).await;

    let stored = env
        .repo
        .authorization_stored(tenant, r.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(stored.body_digest, digest, "the column holds the policy digest");
    assert_eq!(
        stored.verification.as_ref().unwrap()["kind"],
        "dns_txt",
        "verification evidence is kept"
    );
    let back: AuthorizationRecord = serde_json::from_value(stored.body.clone()).unwrap();
    assert_eq!(back.verified_at, Some(at));
    assert_eq!(back.revoked_at, None);
    assert_eq!(
        back.body_digest().unwrap(),
        digest,
        "the digest of the stored record is the digest stored"
    );
    let body_without_lifecycle: Value =
        sqlx::query_scalar("SELECT body FROM authorization_records WHERE record_id = $1")
            .bind(r.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    for key in ["verifiedAt", "revokedAt", "revokedReason"] {
        assert!(
            body_without_lifecycle.get(key).is_none(),
            "{key} is a column, not body"
        );
    }
    // `authorization_get` is the same JSON
    assert_eq!(
        env.repo.authorization_get(tenant, r.id).await.unwrap(),
        Some(stored.body)
    );
    env.teardown().await;
}

#[tokio::test]
async fn create_is_idempotent_and_never_overwrites() {
    let env = env!();
    let (tenant, key) = env.tenant("acme").await;
    let (other, other_key) = env.tenant("globex").await;
    let r = record(tenant);
    let at = now();
    let digest = create(&env, &r, key, at).await;

    let body = serde_json::to_value(&r).unwrap();
    let verification = json!({ "kind": "dns_txt" });
    let replay = env
        .repo
        .authorization_create(&new_row(
            &r,
            &body,
            &digest,
            key,
            &verification,
            at + Duration::minutes(5),
        ))
        .await
        .unwrap();
    assert_eq!(replay, AuthorizationInsert::Replayed);

    // same id, another body
    let mut changed = r.clone();
    changed.title = "another engagement".to_owned();
    let changed_body = serde_json::to_value(&changed).unwrap();
    let changed_digest = changed.body_digest().unwrap();
    let taken = env
        .repo
        .authorization_create(&new_row(
            &changed,
            &changed_body,
            &changed_digest,
            key,
            &verification,
            at,
        ))
        .await
        .unwrap();
    assert_eq!(taken, AuthorizationInsert::Taken);

    // same id, another tenant, even with the same body
    let mut theirs = r.clone();
    theirs.tenant = other;
    let theirs_body = serde_json::to_value(&theirs).unwrap();
    let theirs_digest = theirs.body_digest().unwrap();
    let taken = env
        .repo
        .authorization_create(&new_row(
            &theirs,
            &theirs_body,
            &theirs_digest,
            other_key,
            &verification,
            at,
        ))
        .await
        .unwrap();
    assert_eq!(taken, AuthorizationInsert::Taken);

    let stored = env
        .repo
        .authorization_stored(tenant, r.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.body_digest, digest,
        "the first body is still the stored one"
    );
    let back: AuthorizationRecord = serde_json::from_value(stored.body).unwrap();
    assert_eq!(back.verified_at, Some(at), "a replay does not re-verify");
    assert!(
        env.repo
            .authorization_stored(other, r.id)
            .await
            .unwrap()
            .is_none(),
        "another tenant cannot read it"
    );
    env.teardown().await;
}

async fn update_error(env: &Env, set: &str, id: AuthorizationRecordId) -> Option<String> {
    let sql = format!("UPDATE authorization_records SET {set} WHERE record_id = $1");
    match sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id.0)
        .execute(env.pg.pool())
        .await
    {
        Ok(_) => None,
        Err(sqlx::Error::Database(d)) => Some(format!("{}: {}", d.code().unwrap_or_default(), d.message())),
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn the_body_columns_are_immutable_and_the_lifecycle_columns_are_not() {
    let env = env!();
    let (tenant, key) = env.tenant("acme").await;
    let (other, _) = env.tenant("globex").await;
    let r = record(tenant);
    create(&env, &r, key, now()).await;

    for set in [
        "body = '{\"tampered\":true}'::jsonb".to_owned(),
        "body_digest = '\\x00'::bytea".to_owned(),
        "version = version + 1".to_owned(),
        format!("tenant_id = '{}'", other.0),
        "valid_from = valid_from - interval '1 day'".to_owned(),
        "valid_to = valid_to + interval '1 day'".to_owned(),
        format!("record_id = '{}'", AuthorizationRecordId::new().0),
    ] {
        let err = update_error(&env, &set, r.id)
            .await
            .unwrap_or_else(|| panic!("`{set}` must be rejected"));
        assert!(
            err.starts_with("23514") && err.contains("immutable"),
            "`{set}` -> {err}"
        );
    }
    // a rejected update changed nothing
    let stored = env
        .repo
        .authorization_stored(tenant, r.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.body_digest, r.body_digest().unwrap());

    for set in [
        "revoked_at = now(), revoked_reason = 'x'",
        "verified_at = now()",
        "verification = '{\"kind\":\"dns_txt\"}'::jsonb",
        "evidence_artifact_id = NULL",
        "valid_to = valid_to",
    ] {
        assert_eq!(
            update_error(&env, set, r.id).await,
            None,
            "`{set}` is lifecycle state"
        );
    }
    env.teardown().await;
}

#[tokio::test]
async fn revoke_is_idempotent_and_returns_the_first_revocation() {
    let env = env!();
    let (tenant, key) = env.tenant("acme").await;
    let (other, other_key) = env.tenant("globex").await;
    let r = record(tenant);
    let digest = create(&env, &r, key, now()).await;

    let t1 = now();
    let first = env
        .repo
        .authorization_revoke(tenant, r.id, key, Some("engagement over"), t1)
        .await
        .unwrap()
        .expect("record exists");
    assert!(first.first);
    let rec: AuthorizationRecord = serde_json::from_value(first.stored.body.clone()).unwrap();
    assert_eq!(rec.revoked_at, Some(t1));
    assert_eq!(rec.revoked_reason.as_deref(), Some("engagement over"));
    assert_eq!(
        rec.check_active(t1 + Duration::seconds(1)),
        Err(AuthzFailure::Revoked)
    );
    assert_eq!(
        first.stored.body_digest, digest,
        "revoking does not change the body digest"
    );
    let by: Option<Uuid> =
        sqlx::query_scalar("SELECT revoked_by FROM authorization_records WHERE record_id = $1")
            .bind(r.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(by, Some(key));

    let second = env
        .repo
        .authorization_revoke(
            tenant,
            r.id,
            key,
            Some("a different reason"),
            t1 + Duration::hours(1),
        )
        .await
        .unwrap()
        .expect("record exists");
    assert!(!second.first, "already revoked");
    assert_eq!(second.stored, first.stored, "the first revocation stands");

    // another tenant's key cannot revoke it, an unknown id is absent
    assert!(env
        .repo
        .authorization_revoke(other, r.id, other_key, None, t1)
        .await
        .unwrap()
        .is_none());
    assert!(env
        .repo
        .authorization_revoke(tenant, AuthorizationRecordId::new(), key, None, t1)
        .await
        .unwrap()
        .is_none());
    env.teardown().await;
}

#[tokio::test]
async fn the_worker_reader_sees_the_lifecycle_like_the_api_reader() {
    let env = env!();
    let (tenant, key) = env.tenant("acme").await;
    let r = record(tenant);
    let at = now();
    create(&env, &r, key, at).await;

    let worker = env
        .pg
        .authorization_record_body(r.id)
        .await
        .unwrap()
        .expect("stored");
    let api = env
        .repo
        .authorization_get(tenant, r.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(worker, api);
    let live: AuthorizationRecord = serde_json::from_value(worker).unwrap();
    assert_eq!(live.verified_at, Some(at));
    assert_eq!(live.check_active(at), Ok(()));

    let t1 = at + Duration::seconds(30);
    env.repo
        .authorization_revoke(tenant, r.id, key, Some("stop"), t1)
        .await
        .unwrap();
    let worker = env
        .pg
        .authorization_record_body(r.id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(worker["revokedAt"], json!(t1));
    assert_eq!(worker["revokedReason"], "stop");
    let revoked: AuthorizationRecord = serde_json::from_value(worker.clone()).unwrap();
    assert_eq!(revoked.check_active(t1), Err(AuthzFailure::Revoked));
    assert_eq!(
        env.repo.authorization_get(tenant, r.id).await.unwrap(),
        Some(worker),
        "both readers agree after revocation"
    );
    assert!(env
        .pg
        .authorization_record_body(AuthorizationRecordId::new())
        .await
        .unwrap()
        .is_none());
    env.teardown().await;
}

#[tokio::test]
async fn mark_verified_replaces_the_proof_and_keeps_the_body() {
    let env = env!();
    let (tenant, key) = env.tenant("acme").await;
    let r = record(tenant);
    let at = now();
    let digest = create(&env, &r, key, at).await;

    let later = at + Duration::hours(2);
    let proof =
        json!({ "kind": "dns_txt", "checkedAt": later, "hosts": ["app.example.test"], "again": true });
    let stored = env
        .repo
        .authorization_mark_verified(tenant, r.id, &proof, later)
        .await
        .unwrap()
        .expect("record exists");
    assert_eq!(stored.verification, Some(proof));
    assert_eq!(stored.body_digest, digest);
    let rec: AuthorizationRecord = serde_json::from_value(stored.body).unwrap();
    assert_eq!(rec.verified_at, Some(later));
    assert_eq!(rec.body_digest().unwrap(), digest);

    let other = env.tenant("globex").await.0;
    assert!(env
        .repo
        .authorization_mark_verified(other, r.id, &json!({}), later)
        .await
        .unwrap()
        .is_none());
    env.teardown().await;
}

#[tokio::test]
async fn a_run_is_bound_to_the_body_digest_it_was_admitted_under() {
    let env = env!();
    let (tenant, key) = env.tenant("acme").await;
    let r = record(tenant);
    let digest = create(&env, &r, key, now()).await;

    let run = crawl_run(tenant, create_crawl("https://app.example.test/", &[], 1));
    env.pg.create(&run, None).await.unwrap();
    assert_eq!(env.repo.authorization_run_digest(run.id).await.unwrap(), None);
    env.repo.authorization_bind_run(run.id, digest).await.unwrap();
    assert_eq!(
        env.repo.authorization_run_digest(run.id).await.unwrap(),
        Some(digest)
    );

    let ghost = CrawlRunId::new();
    assert!(matches!(
        env.repo.authorization_bind_run(ghost, digest).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        env.repo.authorization_run_digest(ghost).await,
        Err(StoreError::NotFound { .. })
    ));
    env.teardown().await;
}

#[tokio::test]
async fn local_registration_stays_unverified_and_stores_no_lifecycle_state() {
    let env = env!();
    let tenant = TenantId::new();
    let mut r = record(tenant);
    // a caller that serializes a record with lifecycle state set must not leak it into the body
    r.revoked_at = Some(now());
    r.revoked_reason = Some("should not be stored".to_owned());
    r.verified_at = Some(now());
    let body = serde_json::to_value(&r).unwrap();
    let digest = r.body_digest().unwrap();
    env.pg
        .ensure_authorization_record(&AuthorizationRow {
            tenant,
            record: r.id,
            version: 1,
            body: &body,
            body_digest: &digest.0,
            valid_from: r.valid_from,
            valid_to: r.valid_to,
        })
        .await
        .unwrap();
    // registering again is a no-op
    env.pg
        .ensure_authorization_record(&AuthorizationRow {
            tenant,
            record: r.id,
            version: 1,
            body: &body,
            body_digest: &digest.0,
            valid_from: r.valid_from,
            valid_to: r.valid_to,
        })
        .await
        .unwrap();

    let stored = env
        .pg
        .authorization_record_body(r.id)
        .await
        .unwrap()
        .expect("stored");
    let back: AuthorizationRecord = serde_json::from_value(stored).unwrap();
    assert_eq!(back.verified_at, None, "no proof was checked");
    assert_eq!(back.revoked_at, None);
    assert_eq!(back.revoked_reason, None);
    assert_eq!(back.body_digest().unwrap(), digest);
    let stored_digest: Vec<u8> =
        sqlx::query_scalar("SELECT body_digest FROM authorization_records WHERE record_id = $1")
            .bind(r.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(stored_digest, digest.0.to_vec());
    env.teardown().await;
}

#[tokio::test]
async fn a_run_can_end_with_the_authorization_revoked_terminal_reason() {
    let env = env!();
    let tenant = TenantId::new();
    env.pg.ensure_tenant(tenant, "acme").await.unwrap();
    let run = crawl_run(tenant, create_crawl("https://app.example.test/", &[], 1));
    env.pg.create(&run, None).await.unwrap();
    env.pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    env.pg
        .set_status(
            run.id,
            RunStatus::Failed,
            Some(TerminalReason::AuthorizationRevoked),
        )
        .await
        .unwrap();
    let stored = env.pg.get(run.id).await.unwrap();
    assert_eq!(stored.status, RunStatus::Failed);
    assert_eq!(stored.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    env.teardown().await;
}

#[tokio::test]
async fn retention_preserves_bound_records_and_audit_chain_and_bounds_each_pass() {
    let env = env!();
    let (tenant, key) = env.tenant("retention").await;
    let at = now();
    let sweep_at = at + Duration::days(1_500);
    let sweeper = crawlx_storage::RetentionSweeper::new(env.pg.clone());
    let live = record(tenant);
    create(&env, &live, key, at).await;
    let terminal = record(tenant);
    create(&env, &terminal, key, at).await;
    for (record, finished) in [(&live, false), (&terminal, true)] {
        let mut config = create_crawl("https://app.example.test/", &[], 1);
        config.safety.authorization_record_ref = Some(record.id);
        let run = crawl_run(tenant, config);
        env.pg.create(&run, None).await.unwrap();
        if finished {
            env.pg
                .set_status(
                    run.id,
                    RunStatus::Completed,
                    Some(TerminalReason::FrontierExhausted),
                )
                .await
                .unwrap();
        }
    }
    let recent = record(tenant);
    create(&env, &recent, key, at + Duration::days(1_499)).await;
    let mut expired_ids = Vec::new();
    for _ in 0..103 {
        let expired = record(tenant);
        create(&env, &expired, key, at).await;
        expired_ids.push(expired.id);
    }
    assert_eq!(
        sweeper
            .sweep_authorizations(at + Duration::days(399))
            .await
            .unwrap(),
        0
    );
    assert_eq!(sweeper.sweep_authorizations(sweep_at).await.unwrap(), 100);
    assert_eq!(sweeper.sweep_authorizations(sweep_at).await.unwrap(), 3);
    assert_eq!(sweeper.sweep_authorizations(sweep_at).await.unwrap(), 0);
    for record in [&live, &terminal, &recent] {
        let stored = env
            .repo
            .authorization_stored(tenant, record.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.body_digest, record.body_digest().unwrap());
    }
    for id in expired_ids {
        assert!(env.repo.authorization_stored(tenant, id).await.unwrap().is_none());
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE event = 'authorization.purged'")
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(count, 103);
    let broken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT prev_hash, lag(entry_hash, 1, decode(repeat('00', 32), 'hex')) \
         OVER (ORDER BY audit_id) AS expected FROM audit_events) chain WHERE prev_hash <> expected",
    )
    .fetch_one(env.pg.pool())
    .await
    .unwrap();
    assert_eq!(broken, 0);
    env.teardown().await;
}
