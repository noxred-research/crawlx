//! Real PostgreSQL checkpoint encryption cutover; skips without CRAWLX_TEST_DATABASE_URL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Duration;
use crawlx_core::repo::{ArtifactStore, CheckpointRecord, CheckpointRepo, RunRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::{CheckpointId, ObservationEpoch, StoreError, TenantId};
use crawlx_storage::artifacts::{ArtifactReaper, FsArtifactStore, FsBlobs, ObjectArtifactStore};
use crawlx_storage::checkpoint_crypto::{CheckpointContext, CheckpointKeys, MemoryCheckpointKeys};
use crawlx_storage::retention::{append_audit, RetentionSweeper};
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{Pg, PgConfig};
use std::sync::Arc;
use zeroize::Zeroizing;

#[tokio::test]
async fn migration_0037_revokes_only_legacy_checkpoint_uses_and_sweeps_their_objects() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("checkpoint_cutover_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    let mut previous = sqlx::migrate!("./migrations");
    previous
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 36);
    previous.run(pg.pool()).await.unwrap();
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(version, 36);

    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "checkpoint cutover").await.unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    // Seed the historical schema directly: today's RunRepo also writes columns
    // introduced after migration 0036, which are deliberately absent here.
    sqlx::query(
        "INSERT INTO crawl_runs (run_id,tenant_id,mode,seed,safety_profile,policy_version, \
         identity_version,state_algo_version,query_classifier_version,config,config_digest, \
         retention_mode,retention_days,created_at,counters) \
         VALUES ($1,$2,($3->>'mode')::crawl_mode,$4,($3->'safety'->>'profile')::safety_profile, \
         $5,$6,$7,$8,$3,$9,($3->'retention'->>'mode')::retention_mode, \
         ($3->'retention'->>'days')::int,$10,$11)",
    )
    .bind(run.id.0)
    .bind(tenant.0)
    .bind(serde_json::to_value(&run.config).unwrap())
    .bind(i64::from_ne_bytes(run.seed.0.to_ne_bytes()))
    .bind(i32::try_from(run.policy_version).unwrap())
    .bind(i16::try_from(run.config.crawl.identity.version.decision_version()).unwrap())
    .bind(i16::try_from(crawlx_core::state::StateSignature::VERSION).unwrap())
    .bind(1_i16)
    .bind(run.config_digest.0.as_slice())
    .bind(run.created_at)
    .bind(serde_json::to_value(run.counters).unwrap())
    .execute(pg.pool())
    .await
    .unwrap();
    let sessions = sessions(run.id, 1, 2);
    pg.create_sessions(&sessions).await.unwrap();
    let now = pg.db_now().await.unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FsArtifactStore::open(directory.path(), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone()))
            .with_read_scope(tenant, run.id),
    );
    // This is the pre-cutover CheckpointPayload JSON shape, authored as a real
    // credential-bearing storage_state object, not a synthetic migration marker.
    let mut payload = serde_json::json!({
        "version": 2,
        "binding": null,
        "url": "https://example.test/",
        "epoch": ObservationEpoch::default(),
        "action_seq": 2,
        "storage_b64": "eyJjb29raWVzIjpbXX0="
    });
    let plaintext = serde_json::to_vec(&payload).unwrap();
    let legacy = store
        .put(
            run.id,
            Sensitivity::CredentialBearing,
            "application/json",
            &plaintext,
        )
        .await
        .unwrap();
    let encrypted_id = CheckpointId::new();
    let keys = MemoryCheckpointKeys::new().unwrap();
    let context = CheckpointContext::new(tenant, run.id, sessions[0].id, encrypted_id);
    payload["action_seq"] = serde_json::json!(1);
    let encrypted_plaintext = serde_json::to_vec(&payload).unwrap();
    let ciphertext = keys
        .seal(&context, Zeroizing::new(encrypted_plaintext.clone()))
        .await
        .unwrap();
    let ciphertext = ciphertext.as_ref().to_vec();
    let encrypted = store
        .put(
            run.id,
            Sensitivity::CredentialBearing,
            "application/vnd.crawlx.checkpoint-encrypted",
            &ciphertext,
        )
        .await
        .unwrap();
    let unlinked = store
        .put(
            run.id,
            Sensitivity::CredentialBearing,
            "application/json",
            b"{\"unlinked\":true}",
        )
        .await
        .unwrap();
    let export = store
        .put_kind(
            run.id,
            Sensitivity::Content,
            "manifest",
            "application/json",
            b"{\"export\":true}",
        )
        .await
        .unwrap();
    let checkpoint = CheckpointRecord {
        id: encrypted_id,
        run: run.id,
        session: sessions[0].id,
        epoch: ObservationEpoch::default(),
        action_seq: 1,
        reason: "pause".into(),
        storage: encrypted.clone(),
        url_hash: None,
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    pg.put(&checkpoint).await.unwrap();
    let legacy_checkpoint = CheckpointRecord {
        id: CheckpointId::new(),
        action_seq: 2,
        storage: legacy.clone(),
        ..checkpoint.clone()
    };
    pg.put(&legacy_checkpoint).await.unwrap();
    let legacy_only = CheckpointRecord {
        id: CheckpointId::new(),
        session: sessions[1].id,
        ..legacy_checkpoint.clone()
    };
    pg.put(&legacy_only).await.unwrap();
    assert_eq!(
        pg.latest(sessions[0].id).await.unwrap().unwrap().id,
        legacy_checkpoint.id
    );
    assert_eq!(store.get(&legacy).await.unwrap(), plaintext);
    let legacy_row = store.row(legacy.id).await.unwrap().unwrap();
    let encrypted_row = store.row(encrypted.id).await.unwrap().unwrap();
    let unlinked_row = store.row(unlinked.id).await.unwrap().unwrap();
    let export_row = store.row(export.id).await.unwrap().unwrap();
    let object_index = format!("_index/{}.json", legacy.id);
    let old_index = tokio::fs::read(directory.path().join(&object_index))
        .await
        .unwrap();
    append_audit(
        &pg,
        Some(tenant.0),
        Some(run.id.0),
        "migration_regression",
        "checkpoint.created",
        serde_json::json!({"checkpoint": legacy_checkpoint.id}),
    )
    .await
    .unwrap();
    let audit_before: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_events a ORDER BY audit_id")
            .fetch_all(pg.pool())
            .await
            .unwrap();
    assert!(!audit_before.is_empty());

    pg.migrate().await.unwrap();
    clock.advance_ms(
        (pg.db_now().await.unwrap() - now)
            .num_milliseconds()
            .saturating_add(2),
    );
    let deadlines: (chrono::DateTime<chrono::Utc>, bool) =
        sqlx::query_as("SELECT expires_at, deleted_at IS NULL FROM artifacts WHERE artifact_id=$1")
            .bind(legacy.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert!(deadlines.0 <= pg.db_now().await.unwrap());
    assert!(deadlines.1, "migration must leave physical deletion pending");
    assert!(matches!(
        store.get(&legacy).await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(pg.latest(sessions[0].id).await.unwrap().unwrap().id, encrypted_id);
    assert!(pg.latest(sessions[1].id).await.unwrap().is_none());
    assert_eq!(pg.list(sessions[0].id).await.unwrap().len(), 1);
    assert_eq!(store.row(encrypted.id).await.unwrap().unwrap(), encrypted_row);
    assert_eq!(store.row(unlinked.id).await.unwrap().unwrap(), unlinked_row);
    assert_eq!(store.row(export.id).await.unwrap().unwrap(), export_row);
    assert_eq!(store.get(&encrypted).await.unwrap(), ciphertext);
    assert_eq!(
        keys.open(&context, ciphertext.clone()).await.unwrap().as_slice(),
        encrypted_plaintext
    );
    // Neither the migration nor a successful retained read rewrites an object index.
    assert_eq!(
        tokio::fs::read(directory.path().join(&object_index))
            .await
            .unwrap(),
        old_index
    );
    assert_eq!(
        tokio::fs::read(directory.path().join(&legacy_row.object_key))
            .await
            .unwrap(),
        plaintext
    );

    let reopened = ObjectArtifactStore::new(
        FsBlobs::open(directory.path()).await.unwrap(),
        Arc::new(pg.clone()),
        clock.clone(),
    )
    .with_index(Arc::new(pg.clone()))
    .with_read_scope(tenant, run.id);
    assert!(matches!(
        reopened.get(&legacy).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(reopened
        .presign(&legacy, std::time::Duration::from_secs(60))
        .await
        .is_err());
    #[cfg(target_os = "linux")]
    assert!(store
        .get_bounded(&legacy, Sensitivity::CredentialBearing, 4096)
        .await
        .is_err());
    // An unavailable authoritative index must not expose still-readable object bytes.
    sqlx::raw_sql("ALTER TABLE artifacts RENAME TO artifacts_unavailable")
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        reopened.get(&encrypted).await,
        Err(StoreError::Database { .. })
    ));
    assert!(matches!(
        reopened.reap_expired(pg.db_now().await.unwrap()).await,
        Err(StoreError::Database { .. })
    ));
    sqlx::raw_sql("ALTER TABLE artifacts_unavailable RENAME TO artifacts")
        .execute(pg.pool())
        .await
        .unwrap();

    let report = RetentionSweeper::new(pg.clone())
        .with_artifacts(store.clone())
        .sweep(pg.db_now().await.unwrap())
        .await
        .unwrap();
    assert_eq!(report.artifacts_deleted, 1);
    assert!(!directory.path().join(&legacy_row.object_key).exists());
    assert!(!directory.path().join(&object_index).exists());
    assert_eq!(reopened.get(&encrypted).await.unwrap(), ciphertext);
    assert_eq!(reopened.get(&unlinked).await.unwrap(), b"{\"unlinked\":true}");
    assert_eq!(reopened.get(&export).await.unwrap(), b"{\"export\":true}");
    let structural_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM checkpoints WHERE run_id=$1")
        .bind(run.id.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(structural_rows, 3);
    let deleted: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM artifacts WHERE artifact_id=$1")
            .bind(legacy.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert!(deleted);
    assert!(
        sqlx::query("DELETE FROM artifacts WHERE artifact_id=$1")
            .bind(legacy.id.0)
            .execute(pg.pool())
            .await
            .is_err(),
        "checkpoint foreign key must survive physical erasure"
    );
    let audit_after: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_events a ORDER BY audit_id")
            .fetch_all(pg.pool())
            .await
            .unwrap();
    assert_eq!(audit_after, audit_before);
    pg.drop_schema().await.unwrap();
}
