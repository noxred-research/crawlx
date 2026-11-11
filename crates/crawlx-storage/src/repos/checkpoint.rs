//! `CheckpointRepo` over `checkpoints` (the checkpoint transaction T3).

use crate::backend::strategy::Conn;
use crate::backend::{BackendKind, Dialect};
use crate::codec::{conv, digest, opt_digest};
use crate::sql::{in_list, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::repo::{CheckpointRecord, CheckpointRepo};
use crawlx_core::{
    ArtifactId, ArtifactRef, CheckpointId, CrawlRunId, ObservationEpoch, SessionId, StoreError,
};

/// Checkpoints kept per session.
const KEEP: i64 = 3;

const COLS: &str = "c.checkpoint_id, c.run_id, c.session_id, c.epoch_navigation, c.epoch_document, c.epoch_mutation, \
    c.action_seq, c.reason, c.storage_artifact_id, a.content_digest AS storage_digest, c.url_hash, c.created_at, c.expires_at";

fn from_row<R: SqlRow>(r: &R) -> Result<CheckpointRecord, StoreError> {
    Ok(CheckpointRecord {
        id: CheckpointId(r.uuid("checkpoint_id")?),
        run: CrawlRunId(r.uuid("run_id")?),
        session: SessionId(r.uuid("session_id")?),
        epoch: ObservationEpoch {
            navigation_seq: conv(r.i64("epoch_navigation")?, "epoch_navigation")?,
            document_seq: conv(r.i64("epoch_document")?, "epoch_document")?,
            mutation_seq: conv(r.i64("epoch_mutation")?, "epoch_mutation")?,
        },
        action_seq: conv(r.i64("action_seq")?, "action_seq")?,
        reason: r.text("reason")?,
        storage: ArtifactRef {
            id: ArtifactId(r.uuid("storage_artifact_id")?),
            digest: digest(&r.bytes("storage_digest")?)?,
        },
        url_hash: opt_digest(r.opt_bytes("url_hash")?)?,
        created_at: r.ts("created_at")?,
        expires_at: r.ts("expires_at")?,
    })
}

/// Delete every checkpoint of `session` but the newest [`KEEP`]. PostgreSQL does it in one
/// statement; MariaDB rejects `LIMIT` inside `IN` and a subquery on the table being deleted
/// from, so the other engines read the ids, drop the newest and delete the rest.
async fn prune<B: Sql>(conn: &mut Conn<B>, session: SessionId) -> Result<(), StoreError> {
    if B::KIND == BackendKind::Postgres {
        stmt!(
            B,
            "DELETE FROM checkpoints WHERE session_id = $1 AND checkpoint_id NOT IN ( \
               SELECT checkpoint_id FROM checkpoints WHERE session_id = $1 ORDER BY action_seq DESC, created_at DESC LIMIT $2)"
        )
        .uuid(session.0)
        .i64(KEEP)
        .execute(conn)
        .await?;
        return Ok(());
    }
    let stale: Vec<uuid::Uuid> = stmt!(
        B,
        "SELECT checkpoint_id FROM checkpoints WHERE session_id = $1 ORDER BY action_seq DESC, created_at DESC"
    )
    .uuid(session.0)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .skip(usize::try_from(KEEP).unwrap_or(usize::MAX))
    .map(|row| row.uuid("checkpoint_id"))
    .collect::<Result<_, _>>()?;
    if stale.is_empty() {
        return Ok(());
    }
    Stmt::<B>::dynamic(&format!(
        "DELETE FROM checkpoints WHERE checkpoint_id {}",
        in_list::<B>(1, stale.len())
    ))
    .uuid_list(&stale)
    .execute(conn)
    .await?;
    Ok(())
}

#[async_trait]
impl<B: Sql> CheckpointRepo for Store<B> {
    /// Inserts the row and prunes the session down to its newest three checkpoints in one transaction.
    async fn put(&self, c: &CheckpointRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("checkpoint.put");
        let mut tx = self.begin_write().await?;
        stmt!(
            B,
            "INSERT INTO checkpoints (checkpoint_id, run_id, session_id, epoch_navigation, epoch_document, epoch_mutation, \
               action_seq, reason, storage_artifact_id, url_hash, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
        )
        .uuid(c.id.0)
        .uuid(c.run.0)
        .uuid(c.session.0)
        .i64(conv::<u64, i64>(c.epoch.navigation_seq, "epoch_navigation")?)
        .i64(conv::<u64, i64>(c.epoch.document_seq, "epoch_document")?)
        .i64(conv::<u64, i64>(c.epoch.mutation_seq, "epoch_mutation")?)
        .i64(conv::<u64, i64>(c.action_seq, "action_seq")?)
        .text(&c.reason)
        .uuid(c.storage.id.0)
        .opt_bytes(c.url_hash.as_ref().map(|d| d.0.as_slice()))
        .ts(c.created_at)
        .ts(c.expires_at)
        .execute(tx.conn())
        .await?;
        prune::<B>(tx.conn(), c.session).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn latest(&self, session: SessionId) -> Result<Option<CheckpointRecord>, StoreError> {
        Ok(CheckpointRepo::list(self, session).await?.into_iter().next())
    }

    async fn list(&self, session: SessionId) -> Result<Vec<CheckpointRecord>, StoreError> {
        let _timer = self.query_timer("checkpoint.list");
        let clock = <B::Dialect as Dialect>::clock_timestamp();
        let rows = stmt!(
            B,
            format!(
                "SELECT {COLS} FROM checkpoints c JOIN artifacts a ON a.artifact_id = c.storage_artifact_id \
                 WHERE c.session_id = $1 AND c.expires_at > {clock} \
                   AND a.deleted_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > {clock}) \
                 ORDER BY c.action_seq DESC, c.created_at DESC"
            )
        )
        .uuid(session.0)
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter().map(from_row).collect()
    }
}
