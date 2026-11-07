//! Terminal checkpoint revocation preserves structural custody through physical erasure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{ArtifactStore, CheckpointRecord, CheckpointRepo, RunRepo, Sensitivity};
use crawlx_core::{CheckpointId, TenantId};
use crawlx_storage::artifacts::FsArtifactStore;
use crawlx_storage::checkpoint_crypto::{CheckpointContext, CheckpointKeys, MemoryCheckpointKeys};
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{Pg, PgConfig};
use std::sync::Arc;
use zeroize::Zeroizing;

#[tokio::test]
async fn terminal_postgres_recovery_erases_ciphertext_without_deleting_checkpoint_or_audit_rows() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("checkpoint_lifecycle_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "checkpoint lifecycle").await.unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    pg.create(&run, None).await.unwrap();
    let sessions = sessions(run.id, 1, 1);
    pg.create_sessions(&sessions).await.unwrap();
    let now = pg.db_now().await.unwrap();
    let clock = Arc::new(crawlx_core::time::ManualClock::new(now));
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let id = CheckpointId::new();
    let context = CheckpointContext::new(tenant, run.id, sessions[0].id, id);
    let keys = MemoryCheckpointKeys::new().unwrap();
    let plaintext = br#"{"cookies":[{"value":"terminal-pg-cookie-canary"}]}"#;
    let encrypted = keys
        .seal(&context, Zeroizing::new(plaintext.to_vec()))
        .await
        .unwrap();
    let deadline = now + chrono::Duration::minutes(1);
    let artifact = store
        .put_until(
            run.id,
            Sensitivity::CredentialBearing,
            "application/vnd.crawlx.checkpoint-encrypted",
            encrypted.as_ref(),
            deadline,
        )
        .await
        .unwrap();
    let checkpoint = CheckpointRecord {
        id,
        run: run.id,
        session: sessions[0].id,
        epoch: crawlx_core::ObservationEpoch::default(),
        action_seq: 1,
        reason: "shutdown".into(),
        storage: artifact.clone(),
        url_hash: None,
        created_at: now,
        expires_at: deadline,
    };
    pg.put(&checkpoint).await.unwrap();
    crawlx_storage::retention::append_audit(
        &pg,
        Some(tenant.0),
        Some(run.id.0),
        "lifecycle_fixture",
        "checkpoint.created",
        serde_json::json!({"checkpoint":id}),
    )
    .await
    .unwrap();
    let audit_before: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_events a ORDER BY audit_id")
            .fetch_all(pg.pool())
            .await
            .unwrap();
    let row = store.row(artifact.id).await.unwrap().unwrap();
    pg.set_status(
        run.id,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    let revoked: bool = sqlx::query_scalar(
        "SELECT a.expires_at<=r.finished_at AND c.expires_at<=r.finished_at \
         FROM artifacts a JOIN crawl_runs r ON r.run_id=a.run_id \
         JOIN checkpoints c ON c.storage_artifact_id=a.artifact_id WHERE c.checkpoint_id=$1",
    )
    .bind(id.0)
    .fetch_one(pg.pool())
    .await
    .unwrap();
    assert!(
        revoked,
        "terminal transaction must atomically revoke both recovery deadlines"
    );
    // Reopening cannot recover the stale, longer-lived filesystem index as authority.
    let reopened = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock)
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    assert!(matches!(
        reopened.get(&artifact).await,
        Err(crawlx_core::StoreError::NotFound { .. })
    ));
    assert_eq!(reopened.erase_run_credentials(run.id).await.unwrap(), 1);
    assert!(!dir.path().join(row.object_key).exists());
    assert!(!dir.path().join(format!("_index/{}.json", artifact.id)).exists());
    let structural: i64 = sqlx::query_scalar("SELECT count(*) FROM checkpoints WHERE checkpoint_id=$1")
        .bind(id.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(structural, 1);
    let deleted: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM artifacts WHERE artifact_id=$1")
            .bind(artifact.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert!(deleted);
    let audit_after: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_events a ORDER BY audit_id")
            .fetch_all(pg.pool())
            .await
            .unwrap();
    assert_eq!(audit_after, audit_before);
    pg.drop_schema().await.unwrap();
}
