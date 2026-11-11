//! PostgreSQL probes for archive race tests: crawlx-storage owns all SQL, so downstream
//! tests drive these instead of naming tables or advisory-lock keys.

use crate::error::db;
use crate::Pg;
use crawlx_core::{StoreError, TenantId};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Raise the stored sensitivity of `artifact` to `sensitive`, as a package class upgrade does.
///
/// # Errors
/// `StoreError::Database` when the update fails.
pub async fn mark_artifact_sensitive(pg: &Pg, artifact: Uuid) -> Result<(), StoreError> {
    sqlx::query("UPDATE artifacts SET sensitivity='sensitive' WHERE artifact_id=$1")
        .bind(artifact)
        .execute(pg.pool())
        .await
        .map_err(db)?;
    Ok(())
}

/// Number of sessions currently waiting on `tenant`'s archive advisory lock.
///
/// # Errors
/// `StoreError::Database` when the query fails.
pub async fn archive_lock_waiters(pg: &Pg, tenant: TenantId) -> Result<i64, StoreError> {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objsubid=1 \
         AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295::bigint) \
         AND objid::bigint=(hashtextextended($1,0)&4294967295::bigint)",
    )
    .bind(tenant.to_string())
    .fetch_one(pg.pool())
    .await
    .map_err(db)
}

/// A transaction holding `tenant`'s archive advisory lock until [`release`](Self::release).
#[derive(Debug)]
#[must_use = "the lock is released when the guard is dropped"]
pub struct HeldArchiveLock {
    tx: Transaction<'static, Postgres>,
}

impl HeldArchiveLock {
    /// Take `tenant`'s archive advisory lock in a fresh transaction.
    ///
    /// # Errors
    /// `StoreError::Database` when the transaction or lock statement fails.
    pub async fn acquire(pg: &Pg, tenant: TenantId) -> Result<Self, StoreError> {
        let mut tx = pg.pool().begin().await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        Ok(Self { tx })
    }

    /// Commit the holding transaction, letting queued lock waiters proceed.
    ///
    /// # Errors
    /// `StoreError::Database` when the commit fails.
    pub async fn release(self) -> Result<(), StoreError> {
        self.tx.commit().await.map_err(db)
    }
}

/// Source export of the dependency edge committed for `export`.
///
/// # Errors
/// `StoreError::Database` when the edge is absent or the query fails.
pub async fn archive_dependency_source(pg: &Pg, tenant: TenantId, export: Uuid) -> Result<Uuid, StoreError> {
    sqlx::query_scalar("SELECT source_export FROM archive_dependencies WHERE tenant_id=$1 AND export_id=$2")
        .bind(tenant.0)
        .bind(export)
        .fetch_one(pg.pool())
        .await
        .map_err(db)
}
