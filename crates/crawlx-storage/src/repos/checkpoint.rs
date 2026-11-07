//! `CheckpointRepo` over `checkpoints` (the checkpoint transaction T3).

use crate::codec::{conv, digest, get, opt_digest};
use crate::error::db;
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::repo::{CheckpointRecord, CheckpointRepo};
use crawlx_core::{
    ArtifactId, ArtifactRef, CheckpointId, CrawlRunId, ObservationEpoch, SessionId, StoreError,
};
use sqlx::postgres::PgRow;

/// Checkpoints kept per session.
const KEEP: i64 = 3;

const COLS: &str = "c.checkpoint_id, c.run_id, c.session_id, c.epoch_navigation, c.epoch_document, c.epoch_mutation, \
    c.action_seq, c.reason, c.storage_artifact_id, a.content_digest AS storage_digest, c.url_hash, c.created_at, c.expires_at";

fn from_row(r: &PgRow) -> Result<CheckpointRecord, StoreError> {
    Ok(CheckpointRecord {
        id: CheckpointId(get(r, "checkpoint_id")?),
        run: CrawlRunId(get(r, "run_id")?),
        session: SessionId(get(r, "session_id")?),
        epoch: ObservationEpoch {
            navigation_seq: conv(get::<i64>(r, "epoch_navigation")?, "epoch_navigation")?,
            document_seq: conv(get::<i64>(r, "epoch_document")?, "epoch_document")?,
            mutation_seq: conv(get::<i64>(r, "epoch_mutation")?, "epoch_mutation")?,
        },
        action_seq: conv(get::<i64>(r, "action_seq")?, "action_seq")?,
        reason: get(r, "reason")?,
        storage: ArtifactRef {
            id: ArtifactId(get(r, "storage_artifact_id")?),
            digest: digest(&get::<Vec<u8>>(r, "storage_digest")?)?,
        },
        url_hash: opt_digest(get::<Option<Vec<u8>>>(r, "url_hash")?)?,
        created_at: get(r, "created_at")?,
        expires_at: get(r, "expires_at")?,
    })
}

#[async_trait]
impl CheckpointRepo for Pg {
    /// Inserts the row and prunes the session down to its newest three checkpoints in one transaction.
    async fn put(&self, c: &CheckpointRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("checkpoint.put");
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(
            "INSERT INTO checkpoints (checkpoint_id, run_id, session_id, epoch_navigation, epoch_document, epoch_mutation, \
               action_seq, reason, storage_artifact_id, url_hash, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(c.id.0)
        .bind(c.run.0)
        .bind(c.session.0)
        .bind(conv::<u64, i64>(c.epoch.navigation_seq, "epoch_navigation")?)
        .bind(conv::<u64, i64>(c.epoch.document_seq, "epoch_document")?)
        .bind(conv::<u64, i64>(c.epoch.mutation_seq, "epoch_mutation")?)
        .bind(conv::<u64, i64>(c.action_seq, "action_seq")?)
        .bind(&c.reason)
        .bind(c.storage.id.0)
        .bind(c.url_hash.map(|d| d.0.to_vec()))
        .bind(c.created_at)
        .bind(c.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query(
            "DELETE FROM checkpoints WHERE session_id = $1 AND checkpoint_id NOT IN ( \
               SELECT checkpoint_id FROM checkpoints WHERE session_id = $1 ORDER BY action_seq DESC, created_at DESC LIMIT $2)",
        )
        .bind(c.session.0)
        .bind(KEEP)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn latest(&self, session: SessionId) -> Result<Option<CheckpointRecord>, StoreError> {
        Ok(CheckpointRepo::list(self, session).await?.into_iter().next())
    }

    async fn list(&self, session: SessionId) -> Result<Vec<CheckpointRecord>, StoreError> {
        let _timer = self.query_timer("checkpoint.list");
        let rows = sqlx::query(&format!(
            "SELECT {COLS} FROM checkpoints c JOIN artifacts a ON a.artifact_id = c.storage_artifact_id \
             WHERE c.session_id = $1 AND c.expires_at > clock_timestamp() \
               AND a.deleted_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > clock_timestamp()) \
             ORDER BY c.action_seq DESC, c.created_at DESC"
        ))
        .bind(session.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(from_row).collect()
    }
}
