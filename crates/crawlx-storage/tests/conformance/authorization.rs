//! Authorization records on every engine: create, immutability, lifecycle, the two readers and
//! the run binding. Ported from the PostgreSQL-only `pg_authorization.rs`.

use crate::rig::Rig;
use chrono::{DateTime, Duration, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::{AuthorizationRecordId, CrawlRunId, StoreError, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::{AuthorizationRecord, AuthzFailure, OwnershipProof};
use crawlx_storage::tenant::Tenancy;
use crawlx_storage::testkit::tenancy::{seed, Handle, Harness};
use crawlx_storage::{with_handle, ApiKeyRow, ApiRepo, AuthorizationInsert, NewAuthorization};
use serde_json::{json, Value};
use uuid::Uuid;

conformance! { databases:
    create_round_trips_and_stores_the_policy_digest,
    create_is_idempotent_and_never_overwrites,
    the_body_columns_are_immutable_and_the_lifecycle_columns_are_not,
    revoke_is_idempotent_and_returns_the_first_revocation,
    the_worker_reader_sees_the_lifecycle_like_the_api_reader,
    mark_verified_replaces_the_proof_and_keeps_the_body,
    a_run_is_bound_to_the_body_digest_it_was_admitted_under,
}

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap()
}

/// A record of `tenant` with a DNS TXT proof, as the API stores it (no lifecycle state).
fn record(tenant: TenantId) -> AuthorizationRecord {
    let mut r = sample_record(tenant, now(), &["https://app.example.test"]);
    r.ownership = Some(OwnershipProof::DnsTxt {});
    r
}

/// A tenant with one API key (the creator of its records).
async fn tenant_with_key<B: Tenancy>(repo: &ApiRepo<B>, name: &str) -> (TenantId, Uuid) {
    let tenant = TenantId::new();
    let key = AuthorizationRecordId::new().0;
    repo.key_insert(
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
    .unwrap();
    (tenant, key)
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
async fn create<B: Tenancy>(
    repo: &ApiRepo<B>,
    r: &AuthorizationRecord,
    by: Uuid,
    at: DateTime<Utc>,
) -> Digest {
    let body = serde_json::to_value(r).unwrap();
    let digest = r.body_digest().unwrap();
    let verification = json!({ "kind": "dns_txt", "checkedAt": at, "hosts": ["app.example.test"] });
    let outcome = repo
        .authorization_create(&new_row(r, &body, &digest, by, &verification, at))
        .await
        .unwrap();
    assert_eq!(outcome, AuthorizationInsert::Created);
    digest
}

fn filter(handle: &Handle, id: AuthorizationRecordId) -> String {
    format!("record_id = {}", handle.id(id.0))
}

async fn create_round_trips_and_stores_the_policy_digest(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    with_handle!(&harness.operator, |store| async {
        let repo = ApiRepo::new(store.clone());
        let (tenant, key) = tenant_with_key(&repo, "acme").await;
        let r = record(tenant);
        let at = now();
        let digest = create(&repo, &r, key, at).await;

        let stored = repo
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
        let raw = harness
            .operator
            .column(
                "authorization_records",
                "body",
                &filter(&harness.operator, r.id),
                false,
            )
            .await
            .unwrap()
            .unwrap();
        let body_without_lifecycle: Value = serde_json::from_str(&raw).unwrap();
        for key in ["verifiedAt", "revokedAt", "revokedReason"] {
            assert!(
                body_without_lifecycle.get(key).is_none(),
                "{key} is a column, not body"
            );
        }
        // `authorization_get` is the same JSON
        assert_eq!(
            repo.authorization_get(tenant, r.id).await.unwrap(),
            Some(stored.body)
        );
    }
    .await);
    harness.finish().await.unwrap();
}

async fn create_is_idempotent_and_never_overwrites(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    with_handle!(&harness.operator, |store| async {
        let repo = ApiRepo::new(store.clone());
        let (tenant, key) = tenant_with_key(&repo, "acme").await;
        let (other, other_key) = tenant_with_key(&repo, "globex").await;
        let r = record(tenant);
        let at = now();
        let digest = create(&repo, &r, key, at).await;

        let body = serde_json::to_value(&r).unwrap();
        let verification = json!({ "kind": "dns_txt" });
        let replay = repo
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
        let taken = repo
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
        let taken = repo
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

        let stored = repo.authorization_stored(tenant, r.id).await.unwrap().unwrap();
        assert_eq!(
            stored.body_digest, digest,
            "the first body is still the stored one"
        );
        let back: AuthorizationRecord = serde_json::from_value(stored.body).unwrap();
        assert_eq!(back.verified_at, Some(at), "a replay does not re-verify");
        assert!(
            repo.authorization_stored(other, r.id).await.unwrap().is_none(),
            "another tenant cannot read it"
        );
    }
    .await);
    harness.finish().await.unwrap();
}

/// The `SET` clauses that try to change the immutable body columns, in the dialect of `handle`.
fn tampering(handle: &Handle, other: TenantId) -> Vec<String> {
    let (body, valid_from, valid_to) = match handle {
        Handle::Postgres(_) => (
            "body = '{\"tampered\":true}'::jsonb",
            "valid_from = valid_from - interval '1 day'",
            "valid_to = valid_to + interval '1 day'",
        ),
        Handle::MariaDb(_) => (
            "body = '{\"tampered\":true}'",
            "valid_from = valid_from - INTERVAL 1 DAY",
            "valid_to = valid_to + INTERVAL 1 DAY",
        ),
        _ => (
            "body = '{\"tampered\":true}'",
            "valid_from = valid_from - 86400000000",
            "valid_to = valid_to + 86400000000",
        ),
    };
    vec![
        body.to_owned(),
        format!("body_digest = {}", handle.bytes(&[0])),
        "version = version + 1".to_owned(),
        format!("tenant_id = {}", handle.id(other.0)),
        valid_from.to_owned(),
        valid_to.to_owned(),
        format!("record_id = {}", handle.id(AuthorizationRecordId::new().0)),
    ]
}

/// The `SET` clauses that change lifecycle state, which stay allowed.
fn lifecycle(handle: &Handle) -> Vec<String> {
    let (now_sql, proof) = match handle {
        Handle::Postgres(_) => ("now()", "'{\"kind\":\"dns_txt\"}'::jsonb"),
        Handle::MariaDb(_) => ("NOW(6)", "'{\"kind\":\"dns_txt\"}'"),
        _ => (
            "CAST(unixepoch('subsec') * 1000000 AS INTEGER)",
            "'{\"kind\":\"dns_txt\"}'",
        ),
    };
    vec![
        format!("revoked_at = {now_sql}, revoked_reason = 'x'"),
        format!("verified_at = {now_sql}"),
        format!("verification = {proof}"),
        "evidence_artifact_id = NULL".to_owned(),
        "valid_to = valid_to".to_owned(),
    ]
}

async fn the_body_columns_are_immutable_and_the_lifecycle_columns_are_not(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    let op = &harness.operator;
    let (tenant, record_id, digest) = with_handle!(op, |store| async {
        let repo = ApiRepo::new(store.clone());
        let (tenant, key) = tenant_with_key(&repo, "acme").await;
        let r = record(tenant);
        create(&repo, &r, key, now()).await;
        (tenant, r.id, r.body_digest().unwrap())
    }
    .await);
    let other = TenantId::new();
    for set in tampering(op, other) {
        let sql = format!(
            "UPDATE authorization_records SET {set} WHERE record_id = {}",
            op.id(record_id.0)
        );
        let error = op
            .error_of(&sql)
            .await
            .unwrap_or_else(|| panic!("`{set}` must be rejected"));
        assert!(error.contains("immutable"), "`{set}` -> {error}");
    }
    // a rejected update changed nothing
    with_handle!(op, |store| async {
        let stored = ApiRepo::new(store.clone())
            .authorization_stored(tenant, record_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.body_digest, digest);
    }
    .await);
    for set in lifecycle(op) {
        let sql = format!(
            "UPDATE authorization_records SET {set} WHERE record_id = {}",
            op.id(record_id.0)
        );
        assert_eq!(op.error_of(&sql).await, None, "`{set}` is lifecycle state");
    }
    harness.finish().await.unwrap();
}

async fn revoke_is_idempotent_and_returns_the_first_revocation(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    let op = &harness.operator;
    let (r, key) = with_handle!(op, |store| async {
        let repo = ApiRepo::new(store.clone());
        let (tenant, key) = tenant_with_key(&repo, "acme").await;
        let (other, other_key) = tenant_with_key(&repo, "globex").await;
        let r = record(tenant);
        let digest = create(&repo, &r, key, now()).await;

        let t1 = now();
        let first = repo
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

        let second = repo
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
        assert!(repo
            .authorization_revoke(other, r.id, other_key, None, t1)
            .await
            .unwrap()
            .is_none());
        assert!(repo
            .authorization_revoke(tenant, AuthorizationRecordId::new(), key, None, t1)
            .await
            .unwrap()
            .is_none());
        (r, key)
    }
    .await);
    let by = op
        .column("authorization_records", "revoked_by", &filter(op, r.id), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        by.replace('-', "").to_lowercase(),
        key.simple().to_string(),
        "the revoking key is recorded"
    );
    harness.finish().await.unwrap();
}

async fn the_worker_reader_sees_the_lifecycle_like_the_api_reader(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    with_handle!(&harness.operator, |store| async {
        let repo = ApiRepo::new(store.clone());
        let (tenant, key) = tenant_with_key(&repo, "acme").await;
        let r = record(tenant);
        let at = now();
        create(&repo, &r, key, at).await;

        let worker = store
            .authorization_record_body(r.id)
            .await
            .unwrap()
            .expect("stored");
        let api = repo
            .authorization_get(tenant, r.id)
            .await
            .unwrap()
            .expect("stored");
        assert_eq!(worker, api);
        let live: AuthorizationRecord = serde_json::from_value(worker).unwrap();
        assert_eq!(live.verified_at, Some(at));
        assert_eq!(live.check_active(at), Ok(()));

        let t1 = at + Duration::seconds(30);
        repo.authorization_revoke(tenant, r.id, key, Some("stop"), t1)
            .await
            .unwrap();
        let worker = store
            .authorization_record_body(r.id)
            .await
            .unwrap()
            .expect("stored");
        assert_eq!(worker["revokedAt"], json!(t1));
        assert_eq!(worker["revokedReason"], "stop");
        let revoked: AuthorizationRecord = serde_json::from_value(worker.clone()).unwrap();
        assert_eq!(revoked.check_active(t1), Err(AuthzFailure::Revoked));
        assert_eq!(
            repo.authorization_get(tenant, r.id).await.unwrap(),
            Some(worker),
            "both readers agree after revocation"
        );
        assert!(store
            .authorization_record_body(AuthorizationRecordId::new())
            .await
            .unwrap()
            .is_none());
    }
    .await);
    harness.finish().await.unwrap();
}

async fn mark_verified_replaces_the_proof_and_keeps_the_body(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    with_handle!(&harness.operator, |store| async {
        let repo = ApiRepo::new(store.clone());
        let (tenant, key) = tenant_with_key(&repo, "acme").await;
        let r = record(tenant);
        let at = now();
        let digest = create(&repo, &r, key, at).await;

        let later = at + Duration::hours(2);
        let proof =
            json!({ "kind": "dns_txt", "checkedAt": later, "hosts": ["app.example.test"], "again": true });
        let stored = repo
            .authorization_mark_verified(tenant, r.id, &proof, later)
            .await
            .unwrap()
            .expect("record exists");
        assert_eq!(stored.verification, Some(proof));
        assert_eq!(stored.body_digest, digest);
        let rec: AuthorizationRecord = serde_json::from_value(stored.body).unwrap();
        assert_eq!(rec.verified_at, Some(later));
        assert_eq!(rec.body_digest().unwrap(), digest);

        let other = tenant_with_key(&repo, "globex").await.0;
        assert!(repo
            .authorization_mark_verified(other, r.id, &json!({}), later)
            .await
            .unwrap()
            .is_none());
    }
    .await);
    harness.finish().await.unwrap();
}

async fn a_run_is_bound_to_the_body_digest_it_was_admitted_under(rig: &Rig) {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    let rows = seed(&harness.operator, TenantId::new(), "bound").await.unwrap();
    with_handle!(&harness.operator, |store| async {
        let repo = ApiRepo::new(store.clone());
        let (tenant, key) = (rows.tenant, rows.key);
        let r = record(tenant);
        let digest = create(&repo, &r, key, now()).await;

        let run = rows.run;
        assert_eq!(repo.authorization_run_digest(run).await.unwrap(), None);
        repo.authorization_bind_run(run, digest).await.unwrap();
        assert_eq!(repo.authorization_run_digest(run).await.unwrap(), Some(digest));

        let ghost = CrawlRunId::new();
        assert!(matches!(
            repo.authorization_bind_run(ghost, digest).await,
            Err(StoreError::NotFound { .. })
        ));
        assert!(matches!(
            repo.authorization_run_digest(ghost).await,
            Err(StoreError::NotFound { .. })
        ));
    }
    .await);
    harness.finish().await.unwrap();
}
